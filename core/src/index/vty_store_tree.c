/*
 * vty_store_tree.c — B+tree 读写、校验、统计与检查点
 */

#include "vty_store_internal.h"


/* 从段头读出子节点真实 level，而不是依赖父节点推断。 */
static int load_child_exact(VtyStore *s, uint64_t id,
                            const uint8_t expected_hash[VTY_HASH_BYTES],
                            uint8_t *level, VtyMemNode *child)
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    uint8_t actual[VTY_HASH_BYTES];
    VtySegmentHeader sh;
    int rc;

    if (id < VTY_DATA_OFFSET || id >= s->loc.data_end) return VTY_E_CORRUPT;
    rc = vty_st_read_at(s->h, id, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return VTY_E_IO;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != VTY_SEG_DIR || sh.seq != id) return VTY_E_CORRUPT;
    *level = sh.id;
    rc = vty_st_node_read(s, id, sh.id, child, actual);
    if (rc != VTY_OK) return rc;
    /* 父节点存的子 hash 必须与真实段 hash 一致；否则“父指向子”的
     * 完整性链条只是装饰，无法在 VerifyIntegrity 中审计。 */
    if (expected_hash != NULL &&
        vty_ct_equal(actual, expected_hash, VTY_HASH_BYTES) != 0) {
        vty_st_node_free(child);
        return VTY_E_CORRUPT;
    }
    return VTY_OK;
}

static int write_split_pair(VtyStore *s, VtyMemNode *work, uint32_t mid,
                            VtySplit *out)
{
    VtyMemNode *left = NULL;
    VtyMemNode *right = NULL;
    int rc;

    left = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode));
    right = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode));
    if (left == NULL || right == NULL) { rc = VTY_E_RESOURCE; goto out; }

    left->level = work->level;
    left->type = work->type;
    left->n = (uint16_t)mid;
    right->level = work->level;
    right->type = work->type;
    right->n = (uint16_t)(work->n - mid);

    memcpy(left->e, work->e, sizeof(VtyMemEntry) * mid);
    memcpy(right->e, work->e + mid, sizeof(VtyMemEntry) * right->n);
    /* 所有权转移：work 不再释放这些值。 */
    {
        uint32_t i;
        for (i = 0; i < work->n; i++) work->e[i].val = NULL;
    }

    rc = vty_st_node_write(s, left, &out->left);
    if (rc == VTY_OK) rc = vty_st_node_write(s, right, &out->right);
    if (rc == VTY_OK) out->split = 1;

out:
    if (left != NULL) { vty_st_node_free(left); vty_free(left, sizeof(VtyMemNode)); }
    if (right != NULL) { vty_st_node_free(right); vty_free(right, sizeof(VtyMemNode)); }
    return rc;
}

static int insert_rec(VtyStore *s, VtyMemNode *node,
                      const uint8_t *key, uint16_t key_len,
                      const uint8_t *val, uint32_t val_len,
                      VtySplit *out)
{
    size_t plain_len = 0;
    int rc;

    if (node->type == VTY_NODE_LEAF) {
        uint32_t i;
        int found = 0;
        for (i = 0; i < node->n; i++) {
            int c = vty_st_key_cmp(node->e[i].key, node->e[i].key_len, key, key_len);
            if (c == 0) { found = 1; break; }
            if (c > 0) break;
        }
        if (found) {
            VtyMemEntry *e = &node->e[i];
            if (e->val != NULL) {
                vty_secure_zero(e->val, e->val_len);
                vty_free(e->val, e->val_len);
                e->val = NULL;
            }
            e->val_len = val_len;
            if (val_len != 0) {
                e->val = (uint8_t *)vty_alloc(val_len);
                if (e->val == NULL) return VTY_E_RESOURCE;
                memcpy(e->val, val, val_len);
            }
        } else {
            /* 空值也是合法条目（索引存在性由键表达）；不能把“值为空”
             * 当成“无写入”，否则索引键永远不会落盘。 */
            if (node->n >= VTY_STORE_ENTRY_MAX) return VTY_E_RESOURCE;
            memmove(&node->e[i + 1], &node->e[i],
                    sizeof(VtyMemEntry) * (node->n - i));
            memset(&node->e[i], 0, sizeof(VtyMemEntry));
            node->e[i].key_len = key_len;
            memcpy(node->e[i].key, key, key_len);
            node->e[i].val_len = val_len;
            if (val_len != 0) {
                node->e[i].val = (uint8_t *)vty_alloc(val_len);
                if (node->e[i].val == NULL) return VTY_E_RESOURCE;
                memcpy(node->e[i].val, val, val_len);
            }
            node->n++;
        }

        rc = vty_st_node_plain_size(node, &plain_len);
        if (rc == VTY_OK) {
            out->split = 0;
            return vty_st_node_write(s, node, &out->left);
        }
        if (rc != VTY_E_RESOURCE) return rc;
        return write_split_pair(s, node, node->n / 2u, out);
    }

    /* 内部节点：找到第一个 >= key 的分隔键；没有则落到最后一个子节点，
     * 由叶节点扩展上界并回传新的最大键。 */
    {
        uint32_t i;
        VtyMemNode child;
        uint8_t child_level = 0;
        VtySplit sub;

        memset(&child, 0, sizeof(child));
        memset(&sub, 0, sizeof(sub));
        for (i = 0; i < node->n; i++) {
            if (vty_st_key_cmp(key, key_len, node->e[i].key, node->e[i].key_len) <= 0) break;
        }
        if (i == node->n) i = node->n - 1u;

        rc = load_child_exact(s, node->e[i].child_id,
                              node->e[i].child_hash, &child_level, &child);
        if (rc != VTY_OK) return rc;
        rc = insert_rec(s, &child, key, key_len, val, val_len, &sub);
        vty_st_node_free(&child);
        if (rc != VTY_OK) return rc;

        if (!sub.split) {
            node->e[i].child_id = sub.left.id;
            memcpy(node->e[i].child_hash, sub.left.hash, VTY_HASH_BYTES);
            node->e[i].key_len = sub.left.max_len;
            memcpy(node->e[i].key, sub.left.max_key, sub.left.max_len);
        } else {
            if (node->n >= VTY_STORE_ENTRY_MAX) return VTY_E_RESOURCE;
            node->e[i].child_id = sub.left.id;
            memcpy(node->e[i].child_hash, sub.left.hash, VTY_HASH_BYTES);
            node->e[i].key_len = sub.left.max_len;
            memcpy(node->e[i].key, sub.left.max_key, sub.left.max_len);

            memmove(&node->e[i + 2], &node->e[i + 1],
                    sizeof(VtyMemEntry) * (node->n - i - 1u));
            memset(&node->e[i + 1], 0, sizeof(VtyMemEntry));
            node->e[i + 1].child_id = sub.right.id;
            memcpy(node->e[i + 1].child_hash, sub.right.hash, VTY_HASH_BYTES);
            node->e[i + 1].key_len = sub.right.max_len;
            memcpy(node->e[i + 1].key, sub.right.max_key, sub.right.max_len);
            node->n++;
        }

        rc = vty_st_node_plain_size(node, &plain_len);
        if (rc == VTY_OK) {
            out->split = 0;
            return vty_st_node_write(s, node, &out->left);
        }
        if (rc != VTY_E_RESOURCE) return rc;
        return write_split_pair(s, node, node->n / 2u, out);
    }
}

static int find_leaf(VtyStore *s, const uint8_t *full_key, uint16_t full_len,
                     VtyMemNode *out_leaf, int *found)
{
    VtyMemNode node;
    uint64_t id = s->loc.root_node_id;
    uint8_t level = s->loc.level;
    int rc;

    memset(&node, 0, sizeof(node));
    *found = 0;
    if (id == 0u) return VTY_E_INVALID;

    for (;;) {
        rc = vty_st_node_read(s, id, level, &node, NULL);
        if (rc != VTY_OK) return rc;
        if (node.type == VTY_NODE_LEAF) {
            *out_leaf = node;
            return VTY_OK;
        }
        {
            uint32_t i;
            for (i = 0; i < node.n; i++) {
                if (vty_st_key_cmp(full_key, full_len, node.e[i].key, node.e[i].key_len) <= 0) {
                    break;
                }
            }
            if (i == node.n) {
                vty_st_node_free(&node);
                return VTY_E_INVALID;
            }
            id = node.e[i].child_id;
            level = (uint8_t)(level > 0 ? level - 1u : 0u);
            vty_st_node_free(&node);
        }
    }
}

int vty_store_put(VtyStore *s, uint8_t keyspace,
                  const uint8_t *key, size_t key_len,
                  const uint8_t *value, size_t value_len)
{
    uint8_t full_key[VTY_STORE_KEY_MAX];
    uint16_t full_len;
    VtyMemNode root;
    VtySplit split;
    int rc;

    if (s == NULL || (key == NULL && key_len != 0)) return VTY_E_INVALID;
    if (key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;
    if (value_len > VTY_STORE_VAL_MAX) return VTY_E_RESOURCE;
    if (value == NULL && value_len != 0) return VTY_E_INVALID;

    full_key[0] = keyspace;
    if (key_len != 0) memcpy(full_key + 1, key, key_len);
    full_len = (uint16_t)(key_len + 1u);

    if (s->loc.root_node_id == 0u) {
        memset(&root, 0, sizeof(root));
        root.level = 0;
        root.type = VTY_NODE_LEAF;
        root.n = 1;
        root.e[0].key_len = full_len;
        memcpy(root.e[0].key, full_key, full_len);
        root.e[0].val_len = (uint32_t)value_len;
        if (value_len != 0) {
            root.e[0].val = (uint8_t *)vty_alloc(value_len);
            if (root.e[0].val == NULL) return VTY_E_RESOURCE;
            memcpy(root.e[0].val, value, value_len);
        }

        memset(&split, 0, sizeof(split));
        rc = vty_st_node_write(s, &root, &split.left);
        vty_st_node_free(&root);
        if (rc != VTY_OK) return rc;
        s->loc.root_node_id = split.left.id;
        s->loc.root_offset = split.left.id;
        s->loc.root_len = (uint32_t)(s->loc.data_end - split.left.id);
        s->loc.level = split.left.level;
        memcpy(s->root_hash, split.left.hash, VTY_HASH_BYTES);
        return VTY_OK;
    }

    memset(&root, 0, sizeof(root));
    rc = vty_st_node_read(s, s->loc.root_node_id, s->loc.level, &root, NULL);
    if (rc != VTY_OK) return rc;
    rc = insert_rec(s, &root, full_key, full_len, value, (uint32_t)value_len, &split);
    vty_st_node_free(&root);
    if (rc != VTY_OK) return rc;

    if (split.split) {
        VtyMemNode newroot;
        VtyNodeRef nr;
        if (s->loc.level >= VTY_STORE_MAX_LEVEL) return VTY_E_RESOURCE;
        memset(&newroot, 0, sizeof(newroot));
        newroot.level = (uint8_t)(s->loc.level + 1u);
        newroot.type = VTY_NODE_INTERNAL;
        newroot.n = 2;
        newroot.e[0].key_len = split.left.max_len;
        memcpy(newroot.e[0].key, split.left.max_key, split.left.max_len);
        newroot.e[0].child_id = split.left.id;
        memcpy(newroot.e[0].child_hash, split.left.hash, VTY_HASH_BYTES);
        newroot.e[1].key_len = split.right.max_len;
        memcpy(newroot.e[1].key, split.right.max_key, split.right.max_len);
        newroot.e[1].child_id = split.right.id;
        memcpy(newroot.e[1].child_hash, split.right.hash, VTY_HASH_BYTES);
        rc = vty_st_node_write(s, &newroot, &nr);
        vty_st_node_free(&newroot);
        if (rc != VTY_OK) return rc;
        s->loc.root_node_id = nr.id;
        s->loc.root_offset = nr.id;
        s->loc.root_len = (uint32_t)(s->loc.data_end - nr.id);
        s->loc.level = nr.level;
        memcpy(s->root_hash, nr.hash, VTY_HASH_BYTES);
        return VTY_OK;
    }

    s->loc.root_node_id = split.left.id;
    s->loc.root_offset = split.left.id;
    s->loc.root_len = (uint32_t)(s->loc.data_end - split.left.id);
    s->loc.level = split.left.level;
    memcpy(s->root_hash, split.left.hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_store_get(VtyStore *s, uint8_t keyspace,
                  const uint8_t *key, size_t key_len,
                  uint8_t **value, size_t *value_len)
{
    uint8_t full_key[VTY_STORE_KEY_MAX];
    uint16_t full_len;
    VtyMemNode leaf;
    int rc;
    uint32_t i;

    if (s == NULL || key == NULL || value == NULL || value_len == NULL) {
        return VTY_E_INVALID;
    }
    if (key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;
    *value = NULL;
    *value_len = 0;
    full_key[0] = keyspace;
    memcpy(full_key + 1, key, key_len);
    full_len = (uint16_t)(key_len + 1u);

    memset(&leaf, 0, sizeof(leaf));
    {
        int found = 0;
        rc = find_leaf(s, full_key, full_len, &leaf, &found);
        if (rc != VTY_OK) return rc;
    }

    for (i = 0; i < leaf.n; i++) {
        if (vty_st_key_cmp(leaf.e[i].key, leaf.e[i].key_len, full_key, full_len) == 0) {
            /* 空值 = 键存在（索引条目）；返回 OK 且 value=NULL，调用方
             * 据此区分“存在但无值”和“键不存在”。 */
            if (leaf.e[i].val_len != 0) {
                *value = (uint8_t *)vty_alloc(leaf.e[i].val_len);
                if (*value == NULL) {
                    vty_st_node_free(&leaf);
                    return VTY_E_RESOURCE;
                }
                memcpy(*value, leaf.e[i].val, leaf.e[i].val_len);
            }
            *value_len = leaf.e[i].val_len;
            vty_st_node_free(&leaf);
            return VTY_OK;
        }
        if (vty_st_key_cmp(leaf.e[i].key, leaf.e[i].key_len, full_key, full_len) > 0) break;
    }
    vty_st_node_free(&leaf);
    return VTY_E_INVALID;
}

int vty_store_commit(VtyStore *s, VtyDataRootLocator *out,
                     uint8_t data_root_hash[VTY_HASH_BYTES])
{
    int rc;

    if (s == NULL || out == NULL || data_root_hash == NULL) return VTY_E_INVALID;
    if (s->dirty) {
        rc = FlushFileBuffers(s->h);
        if (!rc) return VTY_E_IO;
        s->dirty = 0;
    }
    rc = vty_store_data_root(s->vault_uuid, s->epoch, s->root_hash, data_root_hash);
    if (rc != VTY_OK) return rc;
    *out = s->loc;
    return VTY_OK;
}

static int verify_node(VtyStore *s, uint64_t id, uint8_t level, uint8_t depth)
{
    VtyMemNode n;
    int rc;
    uint32_t i;

    if (depth > VTY_STORE_MAX_LEVEL) return VTY_E_CORRUPT;
    memset(&n, 0, sizeof(n));
    rc = vty_st_node_read(s, id, level, &n, NULL);
    if (rc != VTY_OK) return rc;

    if (n.type == VTY_NODE_INTERNAL) {
        for (i = 0; i < n.n; i++) {
            VtyMemNode child;
            uint8_t child_level = 0;
            memset(&child, 0, sizeof(child));
            rc = load_child_exact(s, n.e[i].child_id, n.e[i].child_hash,
                                  &child_level, &child);
            if (rc != VTY_OK) { vty_st_node_free(&n); return rc; }
            if (child_level + 1u != n.level) { vty_st_node_free(&child); vty_st_node_free(&n); return VTY_E_CORRUPT; }
            if (vty_st_key_cmp(child.e[child.n - 1].key, child.e[child.n - 1].key_len,
                        n.e[i].key, n.e[i].key_len) != 0) {
                vty_st_node_free(&child);
                vty_st_node_free(&n);
                return VTY_E_CORRUPT;
            }
            vty_st_node_free(&child);
            rc = verify_node(s, n.e[i].child_id, (uint8_t)(n.level - 1u),
                             (uint8_t)(depth + 1u));
            if (rc != VTY_OK) { vty_st_node_free(&n); return rc; }
        }
    }
    vty_st_node_free(&n);
    return VTY_OK;
}

int vty_store_verify(VtyStore *s)
{
    uint64_t size = 0;
    int rc;

    if (s == NULL) return VTY_E_INVALID;
    rc = vty_st_file_size_of(s->h, &size);
    if (rc != VTY_OK) return rc;
    if (size < s->loc.data_end) return VTY_E_CORRUPT;
    if (s->loc.root_node_id == 0u) {
        uint8_t empty[VTY_HASH_BYTES];
        rc = vty_store_empty_root(s->vault_uuid, s->epoch, empty);
        if (rc != VTY_OK) return rc;
        return vty_ct_equal(empty, s->root_hash, VTY_HASH_BYTES) == 0 ? VTY_OK
                                                                     : VTY_E_CORRUPT;
    }
    return verify_node(s, s->loc.root_node_id, s->loc.level, 0);
}

/* ------------------------------------------------------------------ *
 * 存储统计与紧凑批量构建
 *
 * 统计只走当前 DataRoot 可达的活节点；批量构建只用于新建空 store，
 * 直接自底向上写节点，避免在压缩产物中再次产生 COW 旧节点。
 * ------------------------------------------------------------------ */

static int measure_dir_node(VtyStore *s, uint64_t id, uint8_t level,
                            const uint8_t expected_hash[VTY_HASH_BYTES],
                            uint8_t depth, uint64_t *bytes, uint64_t *nodes)
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    VtySegmentHeader sh;
    VtyMemNode n;
    uint8_t actual[VTY_HASH_BYTES];
    uint64_t total;
    int rc;

    if (s == NULL || bytes == NULL || nodes == NULL) return VTY_E_INVALID;
    if (depth > VTY_STORE_MAX_LEVEL) return VTY_E_CORRUPT;
    if (id < VTY_DATA_OFFSET || id >= s->loc.data_end) return VTY_E_CORRUPT;
    rc = vty_st_read_at(s->h, id, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return rc;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != VTY_SEG_DIR || sh.seq != id || sh.id != level) {
        return VTY_E_CORRUPT;
    }
    total = VTY_SEG_HEADER_BYTES + (uint64_t)sh.payload_len;
    if (total > s->loc.data_end - id) return VTY_E_CORRUPT;

    memset(&n, 0, sizeof(n));
    rc = vty_st_node_read(s, id, level, &n, actual);
    if (rc != VTY_OK) return rc;
    if (expected_hash != NULL &&
        vty_ct_equal(actual, expected_hash, VTY_HASH_BYTES) != 0) {
        vty_st_node_free(&n);
        return VTY_E_CORRUPT;
    }
    *bytes += total;
    (*nodes)++;

    if (n.type == VTY_NODE_INTERNAL) {
        uint32_t i;
        for (i = 0; i < n.n; i++) {
            rc = measure_dir_node(s, n.e[i].child_id,
                                  (uint8_t)(level > 0u ? level - 1u : 0u),
                                  n.e[i].child_hash,
                                  (uint8_t)(depth + 1u), bytes, nodes);
            if (rc != VTY_OK) {
                vty_st_node_free(&n);
                return rc;
            }
        }
    }
    vty_st_node_free(&n);
    return VTY_OK;
}

int vty_store_storage_stats(VtyStore *s, VtyStoreStats *out)
{
    uint64_t size = 0;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    rc = vty_st_file_size_of(s->h, &size);
    if (rc != VTY_OK) return rc;
    if (size < s->loc.data_end) return VTY_E_CORRUPT;
    out->file_size = size;
    out->data_end = s->loc.data_end;
    if (s->loc.root_node_id != 0u) {
        rc = measure_dir_node(s, s->loc.root_node_id, s->loc.level,
                              s->root_hash, 0u, &out->tree_bytes,
                              &out->node_count);
        if (rc != VTY_OK) return rc;
    }
    return VTY_OK;
}

int vty_store_delete(VtyStore *s, uint8_t keyspace,
                     const uint8_t *key, size_t key_len)
{
    uint8_t tomb = VTY_STORE_TOMBSTONE_BYTE;

    return vty_store_put(s, keyspace, key, key_len, &tomb, 1u);
}

int vty_store_checkpoint(VtyStore *s, VtyStoreCheckpoint *out)
{
    if (s == NULL || out == NULL) return VTY_E_INVALID;
    out->loc = s->loc;
    memcpy(out->hash, s->root_hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_store_restore(VtyStore *s, const VtyStoreCheckpoint *cp)
{
    if (s == NULL || cp == NULL) return VTY_E_INVALID;
    s->loc = cp->loc;
    memcpy(s->root_hash, cp->hash, VTY_HASH_BYTES);
    return VTY_OK;
}

/* ------------------------------------------------------------------ *
 * 升序游标
 *
 * 只保存路径上的节点 id/下标，每次推进重新读取节点；数据区只追加，
 * 旧节点不会被覆盖，因此游标天然处于打开瞬间的快照。
 * ------------------------------------------------------------------ */

int vty_store_is_empty(VtyStore *s)
{
    return (s != NULL && s->loc.root_node_id == 0u) ? 1 : 0;
}

int vty_store_count(VtyStore *s, uint8_t keyspace, uint64_t *out_count)
{
    VtyStoreCursor *c = NULL;
    uint64_t n = 0;
    int rc;

    if (s == NULL || out_count == NULL) return VTY_E_INVALID;
    rc = vty_store_cursor_open(s, keyspace, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *v = NULL;
        size_t klen = 0, vlen = 0;
        rc = vty_store_cursor_next(c, &done, &k, &klen, &v, &vlen);
        if (rc != VTY_OK) {
            vty_store_cursor_close(c);
            return rc;
        }
        if (done) break;
        n++;
        if (k != NULL) vty_free(k, klen);
        if (v != NULL) vty_free(v, vlen);
    }
    vty_store_cursor_close(c);
    *out_count = n;
    return VTY_OK;
}
