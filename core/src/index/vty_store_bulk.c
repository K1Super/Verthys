/*
 * vty_store_bulk.c — 空库批量构建
 */

#include "vty_store_internal.h"

struct VtyStoreBulk {
    VtyStore *s;
    VtyMemNode *nodes;                /* [0, VTY_STORE_MAX_LEVEL] */
    uint8_t last_key[VTY_STORE_KEY_MAX];
    size_t last_len;
    uint64_t entries;
    VtyNodeRef root;
    int has_last;
    int has_root;
};


static void bulk_reset_node(VtyMemNode *n, uint8_t level, uint8_t type)
{
    vty_st_node_free(n);
    memset(n, 0, sizeof(*n));
    n->level = level;
    n->type = type;
}

static int bulk_leaf_append(VtyMemNode *leaf, const uint8_t *key,
                            uint16_t key_len, const uint8_t *value,
                            uint32_t value_len)
{
    VtyMemEntry *e;
    size_t plain_len = 0;
    int rc;

    if (leaf == NULL || leaf->type != VTY_NODE_LEAF) return VTY_E_INVALID;
    if (leaf->n >= VTY_STORE_ENTRY_MAX) return VTY_E_RESOURCE;
    e = &leaf->e[leaf->n];
    memset(e, 0, sizeof(*e));
    e->key_len = key_len;
    memcpy(e->key, key, key_len);
    e->val_len = value_len;
    if (value_len != 0) {
        e->val = (uint8_t *)vty_alloc(value_len);
        if (e->val == NULL) {
            memset(e, 0, sizeof(*e));
            return VTY_E_RESOURCE;
        }
        memcpy(e->val, value, value_len);
    }
    leaf->n++;

    rc = vty_st_node_plain_size(leaf, &plain_len);
    if (rc == VTY_OK) return VTY_OK;
    if (rc != VTY_E_RESOURCE) return rc;

    /* 溢出：撤销本次追加，交由调用方先落盘当前叶。 */
    leaf->n--;
    if (e->val != NULL) {
        vty_secure_zero(e->val, e->val_len);
        vty_free(e->val, e->val_len);
    }
    memset(e, 0, sizeof(*e));
    return VTY_E_RESOURCE;
}

static int bulk_internal_append(VtyMemNode *node, const VtyNodeRef *ref)
{
    VtyMemEntry *e;
    size_t plain_len = 0;
    int rc;

    if (node == NULL || ref == NULL) return VTY_E_INVALID;
    if (node->n >= VTY_STORE_ENTRY_MAX) return VTY_E_RESOURCE;
    if (node->n > 0u &&
        vty_st_key_cmp(node->e[node->n - 1u].key, node->e[node->n - 1u].key_len,
                ref->max_key, ref->max_len) >= 0) {
        return VTY_E_INVALID;
    }
    e = &node->e[node->n];
    memset(e, 0, sizeof(*e));
    e->key_len = ref->max_len;
    memcpy(e->key, ref->max_key, ref->max_len);
    e->child_id = ref->id;
    memcpy(e->child_hash, ref->hash, VTY_HASH_BYTES);
    node->n++;

    rc = vty_st_node_plain_size(node, &plain_len);
    if (rc == VTY_OK) return VTY_OK;
    if (rc != VTY_E_RESOURCE) return rc;
    node->n--;
    memset(e, 0, sizeof(*e));
    return VTY_E_RESOURCE;
}

static int bulk_flush_node(VtyStoreBulk *b, uint8_t level, int as_root);

static int bulk_add_ref(VtyStoreBulk *b, uint8_t level, const VtyNodeRef *ref)
{
    VtyMemNode *node;
    int rc;

    if (b == NULL || ref == NULL) return VTY_E_INVALID;
    if (level > VTY_STORE_MAX_LEVEL) return VTY_E_RESOURCE;
    node = &b->nodes[level];
    if (node->n == 0u) bulk_reset_node(node, level, VTY_NODE_INTERNAL);

    rc = bulk_internal_append(node, ref);
    if (rc == VTY_OK) return VTY_OK;
    if (rc != VTY_E_RESOURCE) return rc;

    /* 当前内节点已满：先落盘并上推，再在空节点中重试。 */
    if (level >= VTY_STORE_MAX_LEVEL) return VTY_E_RESOURCE;
    rc = bulk_flush_node(b, level, 0);
    if (rc != VTY_OK) return rc;
    return bulk_add_ref(b, level, ref);
}

static int bulk_flush_node(VtyStoreBulk *b, uint8_t level, int as_root)
{
    VtyMemNode *node;
    VtyNodeRef ref;
    int rc;

    if (b == NULL || level > VTY_STORE_MAX_LEVEL) return VTY_E_INVALID;
    node = &b->nodes[level];
    if (node->n == 0u) return VTY_OK;

    memset(&ref, 0, sizeof(ref));
    rc = vty_st_node_write(b->s, node, &ref);
    if (rc != VTY_OK) return rc;
    bulk_reset_node(node, level, node->type == VTY_NODE_LEAF
                                     ? VTY_NODE_LEAF : VTY_NODE_INTERNAL);

    if (as_root) {
        b->root = ref;
        b->has_root = 1;
        return VTY_OK;
    }
    return bulk_add_ref(b, (uint8_t)(level + 1u), &ref);
}

int vty_store_bulk_begin(VtyStore *s, VtyStoreBulk **out)
{
    VtyStoreBulk *b;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    *out = NULL;
    if (s->loc.root_node_id != 0u || s->loc.data_end != VTY_DATA_OFFSET) {
        return VTY_E_POLICY;
    }
    b = (VtyStoreBulk *)vty_alloc(sizeof(*b));
    if (b == NULL) return VTY_E_RESOURCE;
    b->nodes = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode) *
                                       (VTY_STORE_MAX_LEVEL + 1u));
    if (b->nodes == NULL) {
        vty_free(b, sizeof(*b));
        return VTY_E_RESOURCE;
    }
    memset(b->nodes, 0, sizeof(VtyMemNode) * (VTY_STORE_MAX_LEVEL + 1u));
    b->s = s;
    b->has_last = 0;
    b->has_root = 0;
    b->entries = 0;
    *out = b;
    return VTY_OK;
}

int vty_store_bulk_add(VtyStoreBulk *b, uint8_t keyspace,
                       const uint8_t *key, size_t key_len,
                       const uint8_t *value, size_t value_len)
{
    uint8_t full_key[VTY_STORE_KEY_MAX];
    uint16_t full_len;
    VtyMemNode *leaf;
    int rc;

    if (b == NULL) return VTY_E_INVALID;
    if (key == NULL && key_len != 0) return VTY_E_INVALID;
    if (value == NULL && value_len != 0) return VTY_E_INVALID;
    if (key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;
    if (value_len > VTY_STORE_VAL_MAX) return VTY_E_RESOURCE;

    full_key[0] = keyspace;
    if (key_len != 0) memcpy(full_key + 1, key, key_len);
    full_len = (uint16_t)(key_len + 1u);
    if (b->has_last &&
        vty_st_key_cmp(b->last_key, b->last_len, full_key, full_len) >= 0) {
        return VTY_E_INVALID;
    }

    leaf = &b->nodes[0];
    if (leaf->n == 0u) bulk_reset_node(leaf, 0u, VTY_NODE_LEAF);
    rc = bulk_leaf_append(leaf, full_key, full_len, value, (uint32_t)value_len);
    if (rc == VTY_E_RESOURCE && leaf->n > 0u) {
        rc = bulk_flush_node(b, 0u, 0);
        if (rc != VTY_OK) return rc;
        leaf = &b->nodes[0];
        bulk_reset_node(leaf, 0u, VTY_NODE_LEAF);
        rc = bulk_leaf_append(leaf, full_key, full_len, value,
                              (uint32_t)value_len);
    }
    if (rc != VTY_OK) return rc;

    memcpy(b->last_key, full_key, full_len);
    b->last_len = full_len;
    b->has_last = 1;
    b->entries++;
    return VTY_OK;
}

int vty_store_bulk_finish(VtyStoreBulk *b)
{
    uint8_t level;
    int rc;

    if (b == NULL) return VTY_E_INVALID;

    /* 自底向上落盘；当更高层为空时，当前节点就是根，必须最后写。 */
    for (level = 0; level <= VTY_STORE_MAX_LEVEL; level++) {
        uint8_t j;
        int higher_empty = 1;

        if (b->nodes[level].n == 0u) continue;
        for (j = (uint8_t)(level + 1u); j <= VTY_STORE_MAX_LEVEL; j++) {
            if (b->nodes[j].n != 0u) { higher_empty = 0; break; }
        }
        rc = bulk_flush_node(b, level, higher_empty);
        if (rc != VTY_OK) return rc;
        if (higher_empty) break;
    }

    if (!b->has_root) {
        uint8_t empty[VTY_HASH_BYTES];
        rc = vty_store_empty_root(b->s->vault_uuid, b->s->epoch, empty);
        if (rc != VTY_OK) return rc;
        b->s->loc.root_node_id = 0u;
        b->s->loc.root_offset = 0u;
        b->s->loc.root_len = 0u;
        b->s->loc.level = 0u;
        memcpy(b->s->root_hash, empty, VTY_HASH_BYTES);
        return VTY_OK;
    }

    b->s->loc.root_node_id = b->root.id;
    b->s->loc.root_offset = b->root.id;
    b->s->loc.root_len = (uint32_t)(b->s->loc.data_end - b->root.id);
    b->s->loc.level = b->root.level;
    memcpy(b->s->root_hash, b->root.hash, VTY_HASH_BYTES);
    return VTY_OK;
}

void vty_store_bulk_abort(VtyStoreBulk *b)
{
    uint32_t i;

    if (b == NULL) return;
    if (b->nodes != NULL) {
        for (i = 0; i <= VTY_STORE_MAX_LEVEL; i++) {
            vty_st_node_free(&b->nodes[i]);
        }
        vty_free(b->nodes, sizeof(VtyMemNode) * (VTY_STORE_MAX_LEVEL + 1u));
        b->nodes = NULL;
    }
    vty_free(b, sizeof(*b));
}
