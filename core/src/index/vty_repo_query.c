/*
 * vty_repo_query.c — 类型/名称盲索引查询与记录迭代
 */

#include "vty_repo_internal.h"

struct VtyRepoIter {
    VtyVault *v;
    VtyStoreCursor *cur;
    uint64_t start_id;
};


int vty_repo_count(VtyVault *v, uint64_t *out_count)
{
    VtyStoreCursor *c = NULL;
    uint64_t n = 0;
    int rc;

    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    if (out_count == NULL) return VTY_E_INVALID;

    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) return rc;

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        VtyRepoLeaf leaf;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;

        if (klen != 8u) { rc = VTY_E_CORRUPT; }
        else if (repo_get_be64(k) == 0u) {
            /* 分配器条目：8 字节 next_id，不是记录叶 */
            if (vlen != 8u) rc = VTY_E_CORRUPT;
        } else if (vlen != VTY_REPO_LEAF_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            rc = repo_leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0) {
                n++;
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }

    vty_store_cursor_close(c);
    if (rc != VTY_OK) return rc;
    *out_count = n;
    return VTY_OK;
}

/* 按类型令牌扫描类型索引：命中返回首个非墓碑记录 ID。 */
static int repo_find_by_token(VtyVault *v, const uint8_t token[VTY_HASH_BYTES],
                              uint8_t *out_found, uint64_t *out_id)
{
    VtyStoreCursor *c = NULL;
    int rc;

    rc = vty_store_cursor_open(v->store, VTY_KS_TYPE, token, VTY_HASH_BYTES, &c);
    if (rc != VTY_OK) return rc;

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc == VTY_OK && !done) {
            if (klen < VTY_HASH_BYTES || memcmp(k, token, VTY_HASH_BYTES) != 0) {
                rc = VTY_OK;
                done = 1;
            } else if (klen != VTY_HASH_BYTES + 8u) {
                rc = VTY_E_CORRUPT;
            } else if (vlen != 0u) {
                /* 墓碑值必须恰好是单字节标记；其他长度说明索引被写坏。 */
                if (vlen != 1u || val[0] != VTY_STORE_TOMBSTONE_BYTE) {
                    rc = VTY_E_CORRUPT;
                }
            } else {
                *out_found = 1;
                if (out_id != NULL) *out_id = repo_get_be64(k + VTY_HASH_BYTES);
                done = 1;
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK || done) break;
    }

    vty_store_cursor_close(c);
    return rc;
}

int vty_repo_find_by_type(VtyVault *v, uint8_t type,
                          uint8_t *out_found, uint64_t *out_id)
{
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t token[VTY_HASH_BYTES];
    uint32_t i;
    int rc;

    if (out_found == NULL) return VTY_E_INVALID;
    *out_found = 0;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;

    if (repo_is_system_type(type)) {
        rc = vty_vault_system_key(v, mdek);
        if (rc != VTY_OK) return rc;
        memcpy(module_uuid, vty_system_module_uuid, VTY_UUID_BYTES);
        rc = vty_type_token(mdek, module_uuid, v->header.epoch, type, token);
        vty_secure_zero(mdek, sizeof(mdek));
        if (rc != VTY_OK) return rc;
        rc = repo_find_by_token(v, token, out_found, out_id);
        if (rc != VTY_OK || *out_found) return rc;

        /* 旧布局回退：升级前安全记录仍按所属模块 MDEK 建索引。
         * 模块已启用且未解锁时取不到 MDEK，跳过该模块。 */
        for (i = 0; i < VTY_MODULE_COUNT; i++) {
            rc = vty_vault_module_key_index(v, i, mdek);
            if (rc == VTY_E_POLICY) {
                vty_secure_zero(mdek, sizeof(mdek));
                continue;
            }
            if (rc != VTY_OK) {
                vty_secure_zero(mdek, sizeof(mdek));
                return rc;
            }
            memcpy(module_uuid, v->modules[i].uuid, VTY_UUID_BYTES);
            rc = vty_type_token(mdek, module_uuid, v->header.epoch, type, token);
            vty_secure_zero(mdek, sizeof(mdek));
            if (rc != VTY_OK) return rc;
            rc = repo_find_by_token(v, token, out_found, out_id);
            if (rc != VTY_OK) return rc;
            if (*out_found) return VTY_OK;
        }
        return VTY_OK;
    }

    rc = repo_module_for_type(v, type, module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = vty_type_token(mdek, module_uuid, v->header.epoch, type, token);
    vty_secure_zero(mdek, sizeof(mdek));
    if (rc != VTY_OK) return rc;
    return repo_find_by_token(v, token, out_found, out_id);
}

int vty_repo_find_by_name(VtyVault *v, uint8_t type,
                          const uint8_t *name, size_t name_len,
                          uint8_t *out_found, uint64_t *out_id)
{
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t token[VTY_HASH_BYTES];
    VtyStoreCursor *c = NULL;
    int rc;

    if (out_found == NULL || name == NULL || name_len == 0u) {
        return VTY_E_INVALID;
    }
    *out_found = 0;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;

    rc = repo_module_for_type(v, type, module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = vty_name_index(mdek, module_uuid, name, name_len, token);
    vty_secure_zero(mdek, sizeof(mdek));
    if (rc != VTY_OK) return rc;

    /* 名称索引键 = token(32) || id(8)，游标从 token 前缀起点顺序扫描；
     * 前缀不匹配即说明该名称已无更多候选。 */
    rc = vty_store_cursor_open(v->store, VTY_KS_NAME, token, VTY_HASH_BYTES, &c);
    if (rc != VTY_OK) {
        vty_secure_zero(token, sizeof(token));
        return rc;
    }

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc == VTY_OK && !done) {
            if (klen < VTY_HASH_BYTES || memcmp(k, token, VTY_HASH_BYTES) != 0) {
                rc = VTY_OK;
                done = 1;
            } else if (klen != VTY_HASH_BYTES + 8u) {
                rc = VTY_E_CORRUPT;
            } else if (vlen != 0u) {
                if (vlen != 1u || val == NULL ||
                    val[0] != VTY_STORE_TOMBSTONE_BYTE) {
                    rc = VTY_E_CORRUPT;
                }
            } else {
                *out_found = 1;
                if (out_id != NULL) *out_id = repo_get_be64(k + VTY_HASH_BYTES);
                done = 1;
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK || done) break;
    }

    vty_store_cursor_close(c);
    vty_secure_zero(token, sizeof(token));
    return rc;
}

int vty_repo_list_ids_by_type(VtyVault *v, uint8_t type,
                              uint64_t after_id, uint64_t max_count,
                              uint64_t *out_ids, uint64_t *out_count,
                              uint8_t *out_exhausted)
{
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t token[VTY_HASH_BYTES];
    uint8_t start[VTY_HASH_BYTES + 8u];
    size_t start_len;
    VtyStoreCursor *cursor = NULL;
    uint64_t count = 0;
    int rc;

    if (out_ids == NULL || out_count == NULL || out_exhausted == NULL) {
        return VTY_E_INVALID;
    }
    *out_count = 0;
    *out_exhausted = 1;
    if (max_count == 0u || max_count > VTY_REPO_TYPE_ID_BATCH_MAX) {
        return VTY_E_INVALID;
    }
    if (after_id == UINT64_MAX) return VTY_E_INVALID;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;

    rc = repo_module_for_type(v, type, module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = vty_type_token(mdek, module_uuid, v->header.epoch, type, token);
    vty_secure_zero(mdek, sizeof(mdek));
    if (rc != VTY_OK) return rc;

    /* 游标起点 = 类型 token；after_id 非零时后移一个 ID，保证严格升序
     * 分页不重复。类型键固定为 token(32) + id(8, 大端)。 */
    memcpy(start, token, VTY_HASH_BYTES);
    if (after_id != 0u) {
        repo_be64(start + VTY_HASH_BYTES, after_id + 1u);
        start_len = sizeof(start);
    } else {
        start_len = VTY_HASH_BYTES;
    }
    rc = vty_store_cursor_open(v->store, VTY_KS_TYPE, start, start_len,
                               &cursor);
    if (rc != VTY_OK) {
        vty_secure_zero(token, sizeof(token));
        return rc;
    }

    *out_exhausted = 1;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL;
        uint8_t *val = NULL;
        size_t klen = 0;
        size_t vlen = 0;

        rc = vty_store_cursor_next(cursor, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) {
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            break;
        }
        if (done) {
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            break;
        }
        if (klen < VTY_HASH_BYTES || memcmp(k, token, VTY_HASH_BYTES) != 0) {
            /* 已越过本类型 token 前缀：后续键不属于该类型。 */
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            break;
        }
        if (klen != VTY_HASH_BYTES + 8u) {
            rc = VTY_E_CORRUPT;
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            break;
        }
        if (vlen == 0u) {
            uint64_t id = repo_get_be64(k + VTY_HASH_BYTES);
            if (id > after_id) {
                out_ids[count++] = id;
                if (count == max_count) {
                    /* 本页已满：是否还有下一条由下一次调用判定。 */
                    *out_exhausted = 0;
                    if (k != NULL) vty_free(k, klen);
                    if (val != NULL) vty_free(val, vlen);
                    break;
                }
            }
        } else if (vlen != 1u || val == NULL ||
                   val[0] != VTY_STORE_TOMBSTONE_BYTE) {
            rc = VTY_E_CORRUPT;
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            break;
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
    }

    vty_store_cursor_close(cursor);
    vty_secure_zero(token, sizeof(token));
    *out_count = count;
    return rc;
}

int vty_repo_iter_open(VtyVault *v, uint64_t start_id, VtyRepoIter **out)
{
    VtyRepoIter *it;
    uint8_t start[8];
    int rc;

    if (out == NULL) return VTY_E_INVALID;
    *out = NULL;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;

    it = (VtyRepoIter *)vty_alloc(sizeof(VtyRepoIter));
    if (it == NULL) return VTY_E_RESOURCE;
    it->v = v;
    it->start_id = start_id;
    if (start_id != 0u) repo_be64(start, start_id);
    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD,
                               start_id != 0u ? start : NULL,
                               start_id != 0u ? sizeof(start) : 0u,
                               &it->cur);
    if (rc != VTY_OK) {
        vty_free(it, sizeof(VtyRepoIter));
        return rc;
    }
    *out = it;
    return VTY_OK;
}

int vty_repo_iter_next(VtyRepoIter *it, VtyRepoLeaf *leaf, int *done)
{
    if (it == NULL || leaf == NULL || done == NULL) return VTY_E_INVALID;
    *done = 0;

    for (;;) {
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        int rc;

        rc = vty_store_cursor_next(it->cur, done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) return rc;
        if (*done) return VTY_OK;

        if (klen != 8u) {
            rc = VTY_E_CORRUPT;
            goto next_out;
        }
        {
            uint64_t id = repo_get_be64(k);
            if (id == 0u) { rc = VTY_OK; goto next_out; }   /* 分配器 */
            if (id < it->start_id) { rc = VTY_OK; goto next_out; }
            if (vlen != VTY_REPO_LEAF_BYTES) { rc = VTY_E_CORRUPT; goto next_out; }
            rc = repo_leaf_decode(val, vlen, leaf);
            if (rc != VTY_OK) goto next_out;
            if ((leaf->flags & VTY_REPO_FLAG_TOMBSTONE) != 0) {
                rc = VTY_OK;
                goto next_out;
            }
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            return VTY_OK;
        }

next_out:
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) return rc;
    }
}

void vty_repo_iter_close(VtyRepoIter *it)
{
    if (it == NULL) return;
    vty_store_cursor_close(it->cur);
    vty_free(it, sizeof(VtyRepoIter));
}
