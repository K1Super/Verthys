/*
 * vty_repo_file.c — 文件叶与分片叶
 */

#include "vty_repo_internal.h"


static int file_leaf_encode(const VtyRepoFile *f,
                            uint8_t out[VTY_REPO_FILE_BYTES])
{
    size_t off = 0;

    if (f == NULL || out == NULL) return VTY_E_INVALID;
    memcpy(out + off, f->pt_hash, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    vty_put_u32(out + off, f->total); off += 4;
    vty_put_u64(out + off, f->created_time); off += 8;
    return off == VTY_REPO_FILE_BYTES ? VTY_OK : VTY_E_INVALID;
}

static int file_leaf_decode(const uint8_t *in, size_t len, VtyRepoFile *out)
{
    size_t off = 0;

    if (in == NULL || out == NULL) return VTY_E_INVALID;
    if (len != VTY_REPO_FILE_BYTES) return VTY_E_CORRUPT;
    memcpy(out->pt_hash, in + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    out->total = vty_get_u32(in + off); off += 4;
    out->created_time = vty_get_u64(in + off); off += 8;
    return off == VTY_REPO_FILE_BYTES ? VTY_OK : VTY_E_CORRUPT;
}

int repo_chunk_leaf_encode(const VtyRepoChunkEntry *e,
                             uint8_t out[VTY_REPO_CHUNK_BYTES])
{
    size_t off = 0;

    if (e == NULL || out == NULL) return VTY_E_INVALID;
    memcpy(out + off, e->chunk_id, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    vty_put_u64(out + off, e->offset); off += 8;
    vty_put_u32(out + off, e->len); off += 4;
    memcpy(out + off, e->hash, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    return off == VTY_REPO_CHUNK_BYTES ? VTY_OK : VTY_E_INVALID;
}

int repo_chunk_leaf_decode(const uint8_t *in, size_t len,
                             VtyRepoChunkEntry *out)
{
    size_t off = 0;

    if (in == NULL || out == NULL) return VTY_E_INVALID;
    if (len != VTY_REPO_CHUNK_BYTES) return VTY_E_CORRUPT;
    memcpy(out->chunk_id, in + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    out->offset = vty_get_u64(in + off); off += 8;
    out->len = vty_get_u32(in + off); off += 4;
    memcpy(out->hash, in + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    return off == VTY_REPO_CHUNK_BYTES ? VTY_OK : VTY_E_CORRUPT;
}

void repo_chunk_key(uint8_t out[VTY_UUID_BYTES + 4u],
                      const uint8_t file_uuid[VTY_UUID_BYTES], uint32_t seq)
{
    memcpy(out, file_uuid, VTY_UUID_BYTES);
    repo_be32(out + VTY_UUID_BYTES, seq);
}

int repo_file_get_raw(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                        VtyRepoFile *out)
{
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    rc = vty_store_get(v->store, VTY_KS_FILE, file_uuid, VTY_UUID_BYTES,
                       &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen == 1u && val[0] == VTY_STORE_TOMBSTONE_BYTE) {
        vty_free(val, vlen);
        return VTY_E_INVALID;
    }
    rc = file_leaf_decode(val, vlen, out);
    vty_free(val, vlen);
    return rc;
}

static int chunk_get_raw(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                         uint32_t seq, VtyRepoChunkEntry *out)
{
    uint8_t key[VTY_UUID_BYTES + 4u];
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    repo_chunk_key(key, file_uuid, seq);
    rc = vty_store_get(v->store, VTY_KS_CHUNK, key, sizeof(key), &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen == 1u && val[0] == VTY_STORE_TOMBSTONE_BYTE) {
        vty_free(val, vlen);
        return VTY_E_INVALID;
    }
    memset(out, 0, sizeof(*out));
    rc = repo_chunk_leaf_decode(val, vlen, out);
    vty_free(val, vlen);
    if (rc == VTY_OK) out->seq = seq;
    return rc;
}

static int file_put_ex(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                       const uint8_t pt_hash[VTY_HASH_BYTES], uint32_t total,
                       uint64_t created_time)
{
    VtyStoreCheckpoint cp;
    VtyRepoFile f;
    uint8_t leaf[VTY_REPO_FILE_BYTES];
    int rc;

    if (file_uuid == NULL || pt_hash == NULL) return VTY_E_INVALID;
    if (total > VTY_MANIFEST_MAX_CHUNKS) return VTY_E_RESOURCE;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    rc = repo_require_file_module(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;

    memset(&f, 0, sizeof(f));
    memcpy(f.pt_hash, pt_hash, VTY_HASH_BYTES);
    f.total = total;
    f.created_time = (created_time == UINT64_MAX)
                         ? (uint64_t)time(NULL)
                         : created_time;
    rc = file_leaf_encode(&f, leaf);
    if (rc != VTY_OK) goto fail;
    rc = vty_store_put(v->store, VTY_KS_FILE, file_uuid, VTY_UUID_BYTES,
                       leaf, sizeof(leaf));
    if (rc != VTY_OK) goto fail;
    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    return VTY_OK;

fail:
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_file_put(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                      const uint8_t pt_hash[VTY_HASH_BYTES], uint32_t total)
{
    return file_put_ex(v, file_uuid, pt_hash, total, UINT64_MAX);
}

int vty_repo_file_put_ex(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                         const uint8_t pt_hash[VTY_HASH_BYTES], uint32_t total,
                         uint64_t created_time)
{
    return file_put_ex(v, file_uuid, pt_hash, total, created_time);
}

int vty_repo_file_list(VtyVault *v, VtyRepoFileVisitor visitor, void *user,
                       uint64_t *out_count)
{
    VtyStoreCursor *c = NULL;
    uint64_t count = 0;
    int rc;

    if (out_count != NULL) *out_count = 0;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    rc = repo_require_file_module(v);
    if (rc != VTY_OK) return rc;

    rc = vty_store_cursor_open(v->store, VTY_KS_FILE, NULL, 0, &c);
    if (rc != VTY_OK) return rc;

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        VtyRepoFile f;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc == VTY_OK && !done) {
            if (klen != VTY_UUID_BYTES) {
                rc = VTY_E_CORRUPT;
            } else if (vlen == 1u) {
                /* 墓碑：文件已删除，不进入轮换复制范围。 */
                if (val[0] != VTY_STORE_TOMBSTONE_BYTE) rc = VTY_E_CORRUPT;
            } else {
                memset(&f, 0, sizeof(f));
                rc = file_leaf_decode(val, vlen, &f);
                if (rc == VTY_OK && visitor != NULL) {
                    rc = visitor(user, k, &f);
                }
                if (rc == VTY_OK) count++;
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK || done) break;
    }

    vty_store_cursor_close(c);
    if (rc == VTY_OK && out_count != NULL) *out_count = count;
    return rc;
}

/* 轮换专用：不依赖 file 模块密钥统计存活文件叶。fileverthys 模块被删除后，
 * 键空间只剩墓碑；出现存活叶说明删除未清空数据，轮换必须 fail-closed。 */
int vty_repo_file_count_live(VtyVault *v, uint64_t *out_count)
{
    VtyStoreCursor *c = NULL;
    uint64_t count = 0;
    int rc;

    if (v == NULL || out_count == NULL) return VTY_E_INVALID;
    *out_count = 0;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_cursor_open(v->store, VTY_KS_FILE, NULL, 0, &c);
    if (rc != VTY_OK) return rc;

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc == VTY_OK && !done) {
            if (klen != VTY_UUID_BYTES) {
                rc = VTY_E_CORRUPT;
            } else if (repo_value_is_tombstone(vlen, val)) {
                rc = VTY_OK;
            } else if (vlen != VTY_REPO_FILE_BYTES) {
                rc = VTY_E_CORRUPT;
            } else {
                VtyRepoFile f;
                memset(&f, 0, sizeof(f));
                rc = file_leaf_decode(val, vlen, &f);
                if (rc == VTY_OK) count++;
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK || done) break;
    }

    vty_store_cursor_close(c);
    if (rc == VTY_OK) *out_count = count;
    return rc;
}

int vty_repo_file_get(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                      VtyRepoFile *out)
{
    int rc;

    if (file_uuid == NULL || out == NULL) return VTY_E_INVALID;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    rc = repo_require_file_module(v);
    if (rc != VTY_OK) return rc;
    return repo_file_get_raw(v, file_uuid, out);
}

int vty_repo_chunk_add(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                       uint32_t seq, const uint8_t *pt, size_t pt_len)
{
    VtyStoreCheckpoint cp;
    VtyRepoFile f;
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    VtySegmentLocator loc;
    VtyRepoChunkEntry e;
    uint8_t key[VTY_UUID_BYTES + 4u];
    uint8_t leaf[VTY_REPO_CHUNK_BYTES];
    int rc;

    if (file_uuid == NULL) return VTY_E_INVALID;
    if (pt == NULL && pt_len != 0) return VTY_E_INVALID;
    if (pt_len > VTY_CHUNK_MAX_PT) return VTY_E_INVALID;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    /* 先做模块策略检查，锁定态不读取文件叶元数据 */
    rc = repo_module_index(v, 2u, module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = repo_file_get_raw(v, file_uuid, &f);
    if (rc != VTY_OK || seq >= f.total) {
        vty_secure_zero(mdek, sizeof(mdek));
        return (rc != VTY_OK) ? rc : VTY_E_INVALID;
    }
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }

    rc = vty_chunk_seal(mdek, file_uuid, seq, f.total, v->header.epoch,
                        pt, pt_len, &sealed, &sealed_len);
    if (rc != VTY_OK) goto fail;
    rc = vty_store_append_segment(v->store, VTY_SEG_CHUNK, seq, 0u,
                                  sealed, sealed_len, &loc);
    if (rc != VTY_OK) goto fail;

    memset(&e, 0, sizeof(e));
    e.seq = seq;
    rc = vty_chunk_id(mdek, file_uuid, seq, e.chunk_id);
    if (rc != VTY_OK) goto fail;
    e.offset = loc.offset;
    e.len = loc.total_len;
    memcpy(e.hash, loc.hash, VTY_HASH_BYTES);
    rc = repo_chunk_leaf_encode(&e, leaf);
    if (rc != VTY_OK) goto fail;
    repo_chunk_key(key, file_uuid, seq);
    rc = vty_store_put(v->store, VTY_KS_CHUNK, key, sizeof(key),
                       leaf, sizeof(leaf));
    if (rc != VTY_OK) goto fail;

    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    if (sealed != NULL) {
        vty_secure_zero(sealed, sealed_len);
        vty_free(sealed, sealed_len);
    }
    vty_secure_zero(mdek, sizeof(mdek));
    return VTY_OK;

fail:
    if (sealed != NULL) {
        vty_secure_zero(sealed, sealed_len);
        vty_free(sealed, sealed_len);
    }
    vty_secure_zero(mdek, sizeof(mdek));
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_chunk_get(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                       uint32_t seq, uint8_t **pt, size_t *pt_len)
{
    VtyRepoFile f;
    VtyRepoChunkEntry e;
    VtySegmentLocator loc;
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    int rc;

    if (file_uuid == NULL || pt == NULL || pt_len == NULL) return VTY_E_INVALID;
    *pt = NULL;
    *pt_len = 0;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    rc = repo_module_index(v, 2u, module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = repo_file_get_raw(v, file_uuid, &f);
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }
    rc = chunk_get_raw(v, file_uuid, seq, &e);
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }

    memset(&loc, 0, sizeof(loc));
    loc.type = VTY_SEG_CHUNK;
    loc.seq = seq;
    loc.id = 0u;
    loc.offset = e.offset;
    loc.total_len = e.len;
    memcpy(loc.hash, e.hash, VTY_HASH_BYTES);
    rc = vty_store_read_segment(v->store, &loc, &payload, &payload_len);
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }
    rc = vty_chunk_open(mdek, file_uuid, seq, f.total, v->header.epoch,
                        payload, payload_len, pt, pt_len);
    vty_free(payload, payload_len);
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

int vty_repo_file_manifest(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                           VtyRepoChunkEntry **out, uint32_t *out_count)
{
    VtyRepoFile f;
    VtyRepoChunkEntry *entries = NULL;
    VtyStoreCursor *c = NULL;
    uint32_t filled = 0;
    int rc;

    if (file_uuid == NULL || out == NULL || out_count == NULL) {
        return VTY_E_INVALID;
    }
    *out = NULL;
    *out_count = 0;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    rc = repo_require_file_module(v);
    if (rc != VTY_OK) return rc;
    rc = repo_file_get_raw(v, file_uuid, &f);
    if (rc != VTY_OK) return rc;
    if (f.total == 0u) return VTY_OK;
    if (f.total > VTY_MANIFEST_MAX_CHUNKS) return VTY_E_CORRUPT;

    entries = (VtyRepoChunkEntry *)vty_alloc(sizeof(VtyRepoChunkEntry) * f.total);
    if (entries == NULL) return VTY_E_RESOURCE;
    rc = vty_store_cursor_open(v->store, VTY_KS_CHUNK, file_uuid,
                               VTY_UUID_BYTES, &c);
    if (rc != VTY_OK) goto fail;

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        VtyRepoChunkEntry e;
        uint32_t seq;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (klen != VTY_UUID_BYTES + 4u ||
            memcmp(k, file_uuid, VTY_UUID_BYTES) != 0) {
            /* 下一个文件 UUID 表示本文件范围结束，不是损坏 */
            done = 1;
        } else if (repo_value_is_tombstone(vlen, val)) {
            /* 已删除文件的墓碑分片：不属于本文件清单，跳过。 */
            rc = VTY_OK;
        } else if (vlen != VTY_REPO_CHUNK_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            seq = repo_get_be32(k + VTY_UUID_BYTES);
            memset(&e, 0, sizeof(e));
            rc = repo_chunk_leaf_decode(val, vlen, &e);
            if (rc == VTY_OK) {
                if (seq >= f.total || entries[seq].len != 0u) {
                    /* 空洞/越界/重复：清单无法重建 */
                    rc = VTY_E_CORRUPT;
                } else {
                    e.seq = seq;
                    entries[seq] = e;
                    filled++;
                }
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK || done) break;
    }

    vty_store_cursor_close(c);
    if (rc == VTY_OK && filled != f.total) rc = VTY_E_CORRUPT;
    if (rc != VTY_OK) {
        vty_free(entries, sizeof(VtyRepoChunkEntry) * f.total);
        return rc;
    }
    *out = entries;
    *out_count = f.total;
    return VTY_OK;

fail:
    if (c != NULL) vty_store_cursor_close(c);
    if (entries != NULL) vty_free(entries, sizeof(VtyRepoChunkEntry) * f.total);
    return rc;
}
