/*
 * vty_repo_storage.c — 存储统计与压缩复制
 */

#include "vty_repo_internal.h"

/* ------------------------------------------------------------------ *
 * 存储统计与压缩复制
 * ------------------------------------------------------------------ */

typedef struct {
    VtyStoreBulk *bulk;
    VtyVault *dst;
    uint64_t records;
    uint64_t chunks;
    uint64_t bytes;
    uint64_t max_id;
    uint64_t next_id;
    int saw_allocator;
} CompactCtx;


static int repo_key_is_allocator(const uint8_t *key, size_t key_len)
{
    size_t i;

    if (key == NULL || key_len != 8u) return 0;
    for (i = 0; i < key_len; i++) {
        if (key[i] != 0u) return 0;
    }
    return 1;
}

/* 活段边界校验：任何越界都按 CORRUPT 拒绝，不把未验证的偏移带进统计/复制。 */
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

/* 读取旧段原始密文并追加到新 store；返回的新 locator 必须与旧叶的
 * 长度/哈希完全一致，否则说明源段被替换或搬移，拒绝继续。 */
static int compact_copy_segment(VtyVault *src, VtyVault *dst,
                                uint8_t type, uint64_t seq, uint64_t id,
                                uint64_t offset, uint32_t len,
                                const uint8_t hash[VTY_HASH_BYTES],
                                VtySegmentLocator *out)
{
    VtySegmentLocator loc;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    int rc;

    if (src == NULL || dst == NULL || out == NULL || hash == NULL) {
        return VTY_E_INVALID;
    }
    if (type != VTY_SEG_RECORD && type != VTY_SEG_CHUNK) {
        return VTY_E_INVALID;
    }
    rc = repo_segment_bounds(src, offset, len, 0);
    if (rc != VTY_OK) return rc;
    if (len < VTY_SEG_HEADER_BYTES) return VTY_E_CORRUPT;

    memset(&loc, 0, sizeof(loc));
    loc.type = type;
    loc.seq = seq;
    loc.id = id;
    loc.offset = offset;
    loc.total_len = len;
    memcpy(loc.hash, hash, VTY_HASH_BYTES);
    rc = vty_store_read_segment(src->store, &loc, &payload, &payload_len);
    if (rc != VTY_OK) return rc;

    memset(out, 0, sizeof(*out));
    rc = vty_store_append_segment(dst->store, type, seq, id,
                                  payload, payload_len, out);
    if (payload != NULL) {
        vty_secure_zero(payload, payload_len != 0 ? payload_len : 1u);
        vty_free(payload, payload_len != 0 ? payload_len : 1u);
    }
    if (rc != VTY_OK) return rc;
    if (out->total_len != len ||
        vty_ct_equal(out->hash, hash, VTY_HASH_BYTES) != 0) {
        return VTY_E_VERIFY;
    }
    return VTY_OK;
}

static int compact_add(CompactCtx *ctx, uint8_t keyspace,
                       const uint8_t *key, size_t key_len,
                       const uint8_t *value, size_t value_len)
{
    return vty_store_bulk_add(ctx->bulk, keyspace, key, key_len,
                              value, value_len);
}

static int compact_records(CompactCtx *ctx, VtyVault *src,
                           VtyRepoCompactProgressFn cb, void *user)
{
    VtyStoreCursor *c = NULL;
    int rc;

    rc = vty_store_cursor_open(src->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;

        if (repo_key_is_allocator(k, klen)) {
            if (vlen != 8u) {
                rc = VTY_E_CORRUPT;
            } else {
                uint64_t nid = vty_get_u64(val);
                if (nid == 0u) {
                    rc = VTY_E_CORRUPT;
                } else {
                    ctx->next_id = nid;
                    ctx->saw_allocator = 1;
                    rc = compact_add(ctx, VTY_KS_RECORD, k, klen, val, vlen);
                }
            }
        } else if (repo_value_is_tombstone(vlen, val)) {
            rc = VTY_OK;
        } else if (klen != 8u || vlen != VTY_REPO_LEAF_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            VtyRepoLeaf leaf;
            RepoLeafRaw raw;
            uint8_t leaf_buf[VTY_REPO_LEAF_BYTES];
            VtySegmentLocator loc;

            memset(&leaf, 0, sizeof(leaf));
            rc = repo_leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0) {
                rc = VTY_OK;
            } else if (rc == VTY_OK) {
                rc = compact_copy_segment(src, ctx->dst, VTY_SEG_RECORD,
                                          leaf.record_id, 0u,
                                          leaf.data_offset, leaf.data_len,
                                          leaf.data_hash, &loc);
                if (rc == VTY_OK) {
                    memset(&raw, 0, sizeof(raw));
                    raw.record_id = leaf.record_id;
                    memcpy(raw.module_uuid, leaf.module_uuid,
                           VTY_UUID_BYTES);
                    raw.flags = leaf.flags;
                    memcpy(raw.name_index, leaf.name_index,
                           VTY_HASH_BYTES);
                    memcpy(raw.type_token, leaf.type_token,
                           VTY_HASH_BYTES);
                    raw.created_time = leaf.created_time;
                    raw.data_offset = loc.offset;
                    raw.data_len = loc.total_len;
                    raw.plain_size = leaf.plain_size;
                    memcpy(raw.data_hash, loc.hash, VTY_HASH_BYTES);
                    rc = repo_leaf_encode(&raw, leaf_buf);
                    if (rc == VTY_OK) {
                        rc = compact_add(ctx, VTY_KS_RECORD, k, klen,
                                         leaf_buf, sizeof(leaf_buf));
                    }
                    if (rc == VTY_OK) {
                        ctx->records++;
                        ctx->bytes += (uint64_t)loc.total_len;
                        if (leaf.record_id > ctx->max_id) {
                            ctx->max_id = leaf.record_id;
                        }
                    }
                }
            }
        }

        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
        if (cb != NULL &&
            cb(user, ctx->records, ctx->chunks, ctx->bytes) != 0) {
            rc = VTY_E_POLICY;
            break;
        }
    }
    vty_store_cursor_close(c);
    return rc;
}

static int compact_index_or_file(CompactCtx *ctx, VtyVault *src,
                                 uint8_t keyspace)
{
    VtyStoreCursor *c = NULL;
    int rc;

    rc = vty_store_cursor_open(src->store, keyspace, NULL, 0, &c);
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
        } else if (keyspace == VTY_KS_FILE &&
                   (klen != VTY_UUID_BYTES || vlen != VTY_REPO_FILE_BYTES)) {
            rc = VTY_E_CORRUPT;
        } else {
            rc = compact_add(ctx, keyspace, k, klen, val, vlen);
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    return rc;
}

static int compact_chunks(CompactCtx *ctx, VtyVault *src,
                          VtyRepoCompactProgressFn cb, void *user)
{
    VtyStoreCursor *c = NULL;
    int rc;

    rc = vty_store_cursor_open(src->store, VTY_KS_CHUNK, NULL, 0, &c);
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
            uint8_t leaf[VTY_REPO_CHUNK_BYTES];
            VtySegmentLocator loc;
            uint32_t seq = repo_get_be32(k + VTY_UUID_BYTES);

            memset(&e, 0, sizeof(e));
            rc = repo_chunk_leaf_decode(val, vlen, &e);
            if (rc == VTY_OK) {
                e.seq = seq;
                rc = compact_copy_segment(src, ctx->dst, VTY_SEG_CHUNK,
                                          seq, 0u, e.offset, e.len,
                                          e.hash, &loc);
            }
            if (rc == VTY_OK) {
                e.offset = loc.offset;
                e.len = loc.total_len;
                memcpy(e.hash, loc.hash, VTY_HASH_BYTES);
                rc = repo_chunk_leaf_encode(&e, leaf);
                if (rc == VTY_OK) {
                    rc = compact_add(ctx, VTY_KS_CHUNK, k, klen,
                                     leaf, sizeof(leaf));
                }
                if (rc == VTY_OK) {
                    ctx->chunks++;
                    ctx->bytes += (uint64_t)loc.total_len;
                }
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
        if (cb != NULL &&
            cb(user, ctx->records, ctx->chunks, ctx->bytes) != 0) {
            rc = VTY_E_POLICY;
            break;
        }
    }
    vty_store_cursor_close(c);
    return rc;
}

static int compact_modules(CompactCtx *ctx, VtyVault *src)
{
    VtyStoreCursor *c = NULL;
    int rc;

    rc = vty_store_cursor_open(src->store, VTY_KS_MODULE, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (klen != 1u || repo_value_is_tombstone(vlen, val)) {
            rc = VTY_E_CORRUPT;
        } else {
            rc = compact_add(ctx, VTY_KS_MODULE, k, klen, val, vlen);
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    return rc;
}

int vty_repo_compact_copy(VtyVault *src, VtyVault *dst,
                          VtyRepoCompactProgressFn cb, void *user,
                          uint64_t *out_records, uint64_t *out_chunks,
                          uint64_t *out_bytes)
{
    CompactCtx ctx;
    int rc;

    if (out_records != NULL) *out_records = 0;
    if (out_chunks != NULL) *out_chunks = 0;
    if (out_bytes != NULL) *out_bytes = 0;
    if (src == NULL || dst == NULL) return VTY_E_INVALID;
    rc = repo_ready(src);
    if (rc != VTY_OK) return rc;
    rc = repo_ready(dst);
    if (rc != VTY_OK) return rc;
    if (src->rotate_pending || dst->rotate_pending) return VTY_E_ROTATE_PENDING;

    memset(&ctx, 0, sizeof(ctx));
    ctx.dst = dst;
    rc = vty_store_bulk_begin(dst->store, &ctx.bulk);
    if (rc != VTY_OK) return rc;

    rc = compact_records(&ctx, src, cb, user);
    if (rc == VTY_OK) rc = compact_index_or_file(&ctx, src, VTY_KS_NAME);
    if (rc == VTY_OK) rc = compact_index_or_file(&ctx, src, VTY_KS_TYPE);
    if (rc == VTY_OK) rc = compact_index_or_file(&ctx, src, VTY_KS_FILE);
    if (rc == VTY_OK) rc = compact_chunks(&ctx, src, cb, user);
    if (rc == VTY_OK) rc = compact_modules(&ctx, src);
    /* 维护队列与一次性迁移标记随库搬运：新库继续补偿未完成的擦除，
     * 且不会因压缩而重跑旧墓碑全量扫描。 */
    if (rc == VTY_OK) rc = compact_index_or_file(&ctx, src, VTY_KS_SCRUB);
    if (rc == VTY_OK) rc = compact_index_or_file(&ctx, src, VTY_KS_MAINT);
    if (rc == VTY_OK) {
        if (!ctx.saw_allocator || ctx.next_id <= ctx.max_id) {
            rc = VTY_E_CORRUPT;
        }
    }
    if (rc == VTY_OK) rc = vty_store_bulk_finish(ctx.bulk);
    vty_store_bulk_abort(ctx.bulk);
    if (rc != VTY_OK) return rc;

    if (out_records != NULL) *out_records = ctx.records;
    if (out_chunks != NULL) *out_chunks = ctx.chunks;
    if (out_bytes != NULL) *out_bytes = ctx.bytes;
    return VTY_OK;
}
