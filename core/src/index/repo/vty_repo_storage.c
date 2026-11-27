/*
 * vty_repo_storage.c — 存储统计与解锁期空闲区重建
 */

#include "vty_repo_internal.h"

/* ------------------------------------------------------------------ *
 * 存储统计
 * ------------------------------------------------------------------ */

static int repo_key_is_allocator(const uint8_t *key, size_t key_len)
{
    size_t i;

    if (key == NULL || key_len != 8u) return 0;
    for (i = 0; i < key_len; i++) {
        if (key[i] != 0u) return 0;
    }
    return 1;
}

/* 活段边界校验：任何越界都按 CORRUPT 拒绝，不把未验证的偏移带进统计/重建。 */
static int repo_segment_bounds(const VtyVault *v, uint64_t offset,
                               uint32_t len, int allow_zero)
{
    if (v == NULL || v->store == NULL) return VTY_E_INVALID;
    if (!allow_zero && len == 0u) return VTY_E_CORRUPT;
    if (offset < VTY_DATA_OFFSET) return VTY_E_CORRUPT;
    if (offset > v->data_root.data_end) return VTY_E_CORRUPT;
    if ((uint64_t)len > v->data_root.data_end - offset) return VTY_E_CORRUPT;
    return VTY_OK;
}

int vty_repo_storage_stats(VtyVault *v, VtyStorageStats *out)
{
    VtyStoreStats st;
    VtyStoreCursor *c = NULL;
    uint64_t segment_bytes = 0;
    uint64_t records = 0, files = 0, chunks = 0;
    int rc;

    if (v == NULL || out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_storage_stats(v->store, &st);
    if (rc != VTY_OK) return rc;
    if (st.file_size < st.data_end) return VTY_E_CORRUPT;

    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (!repo_key_is_allocator(k, klen)) {
            VtyRepoLeaf leaf;

            if (repo_value_is_tombstone(vlen, val)) {
                /* 记录叶的墓碑是 148B 带标志的叶，不是 1B 值；这里只兜底。 */
                rc = VTY_OK;
            } else if (klen != 8u || vlen != VTY_REPO_LEAF_BYTES) {
                rc = VTY_E_CORRUPT;
            } else {
                memset(&leaf, 0, sizeof(leaf));
                rc = repo_leaf_decode(val, vlen, &leaf);
                if (rc == VTY_OK &&
                    (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0) {
                    rc = repo_segment_bounds(v, leaf.data_offset,
                                             leaf.data_len, 0);
                    if (rc == VTY_OK) {
                        segment_bytes += (uint64_t)leaf.data_len;
                        records++;
                    }
                }
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    c = NULL;
    if (rc != VTY_OK) return rc;

    rc = vty_store_cursor_open(v->store, VTY_KS_CHUNK, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (repo_value_is_tombstone(vlen, val)) {
            rc = VTY_OK;
        } else if (klen != VTY_UUID_BYTES + 4u ||
                   vlen != VTY_REPO_CHUNK_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            VtyRepoChunkEntry e;
            memset(&e, 0, sizeof(e));
            rc = repo_chunk_leaf_decode(val, vlen, &e);
            if (rc == VTY_OK) {
                rc = repo_segment_bounds(v, e.offset, e.len, 0);
                if (rc == VTY_OK) {
                    segment_bytes += (uint64_t)e.len;
                    chunks++;
                }
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    c = NULL;
    if (rc != VTY_OK) return rc;

    rc = vty_store_cursor_open(v->store, VTY_KS_FILE, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (repo_value_is_tombstone(vlen, val)) {
            rc = VTY_OK;
        } else if (klen != VTY_UUID_BYTES || vlen != VTY_REPO_FILE_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            files++;
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    if (rc != VTY_OK) return rc;

    out->file_size = st.file_size;
    out->data_end = st.data_end;
    out->live_tree_bytes = st.tree_bytes;
    out->live_segment_bytes = segment_bytes;
    out->live_bytes = st.tree_bytes + segment_bytes;
    if (out->live_bytes > st.file_size - VTY_DATA_OFFSET) return VTY_E_CORRUPT;
    out->reclaimable_bytes =
        st.file_size - VTY_DATA_OFFSET - out->live_bytes;
    out->record_count = records;
    out->file_count = files;
    out->chunk_count = chunks;
    return VTY_OK;
}

/* ------------------------------------------------------------------ *
 * 解锁期空闲区重建
 *
 * DataRoot 是唯一事实源：目录树可达节点、活记录/分片段、以及仍带
 * 定位符的墓碑（擦除完成前不得复用）全部登记为占用，剩余字节标为
 * 空闲。重建只读不写；失败时关闭复用，退回追加模式。
 * ------------------------------------------------------------------ */

static int space_reserve_leaf_segment(VtyVault *v, const VtyRepoLeaf *leaf)
{
    int rc;

    if (leaf->data_offset == 0u || leaf->data_len == 0u) return VTY_OK;
    rc = repo_segment_bounds(v, leaf->data_offset, leaf->data_len, 0);
    if (rc != VTY_OK) return rc;
    return vty_store_space_reserve(v->store, leaf->data_offset,
                                   (uint64_t)leaf->data_len);
}

int vty_repo_space_sync(VtyVault *v)
{
    VtyStoreCursor *c = NULL;
    int rc;

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;

    rc = vty_store_space_begin(v->store);
    if (rc != VTY_OK) return rc;

    rc = vty_store_space_scan_nodes(v->store);
    if (rc != VTY_OK) goto fail;

    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) goto fail;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) {
            vty_free(k, klen);
            vty_free(val, vlen);
            break;
        }
        if (done) {
            vty_free(k, klen);
            vty_free(val, vlen);
            break;
        }
        if (repo_key_is_allocator(k, klen)) {
            if (vlen != 8u) rc = VTY_E_CORRUPT;
        } else if (repo_value_is_tombstone(vlen, val)) {
            rc = VTY_OK;
        } else if (klen != 8u || vlen != VTY_REPO_LEAF_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            VtyRepoLeaf leaf;

            memset(&leaf, 0, sizeof(leaf));
            rc = repo_leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK) {
                /* 墓碑仍可能带定位符：擦除完成前必须保持占用。 */
                rc = space_reserve_leaf_segment(v, &leaf);
            }
        }
        vty_free(k, klen);
        vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    c = NULL;
    if (rc != VTY_OK) goto fail;

    rc = vty_store_cursor_open(v->store, VTY_KS_CHUNK, NULL, 0, &c);
    if (rc != VTY_OK) goto fail;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) {
            vty_free(k, klen);
            vty_free(val, vlen);
            break;
        }
        if (done) {
            vty_free(k, klen);
            vty_free(val, vlen);
            break;
        }
        if (repo_value_is_tombstone(vlen, val)) {
            rc = VTY_OK;
        } else if (klen != VTY_UUID_BYTES + 4u ||
                   vlen != VTY_REPO_CHUNK_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            VtyRepoChunkEntry e;

            memset(&e, 0, sizeof(e));
            rc = repo_chunk_leaf_decode(val, vlen, &e);
            if (rc == VTY_OK) {
                rc = repo_segment_bounds(v, e.offset, e.len, 0);
            }
            if (rc == VTY_OK) {
                rc = vty_store_space_reserve(v->store, e.offset,
                                             (uint64_t)e.len);
            }
        }
        vty_free(k, klen);
        vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    c = NULL;
    if (rc != VTY_OK) goto fail;

    return vty_store_space_finish(v->store);

fail:
    if (c != NULL) vty_store_cursor_close(c);
    vty_store_space_disable(v->store);
    return rc;
}
