/*
 * vty_repo_rekey.c — 模块重写、内容信封换封与模块清除
 */

#include "vty_repo_internal.h"


/* 用显式 MDEK 读取记录：模块启用重写时旧 Keyring 仍在，但调用方
 * 不应依赖策略入口，避免重写过程中被模块锁定状态拦截。 */
static int repo_read_with_mdek(VtyVault *v, const VtyRepoLeaf *leaf,
                               const uint8_t mdek[VTY_KEY_BYTES],
                               VtyRepoRecord *out)
{
    VtySegmentLocator loc;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint8_t *name = NULL, *data = NULL;
    size_t name_len = 0, data_len = 0;
    uint8_t *copy = NULL;
    int rc;

    if (v == NULL || leaf == NULL || mdek == NULL || out == NULL) {
        return VTY_E_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if ((leaf->flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;

    memset(&loc, 0, sizeof(loc));
    loc.type = VTY_SEG_RECORD;
    loc.seq = leaf->record_id;
    loc.offset = leaf->data_offset;
    loc.total_len = leaf->data_len;
    memcpy(loc.hash, leaf->data_hash, VTY_HASH_BYTES);
    rc = vty_store_read_segment(v->store, &loc, &payload, &payload_len);
    if (rc != VTY_OK) return rc;

    if ((leaf->flags & VTY_REPO_FLAG_KEYED) != 0) {
        rc = vty_record_open_keyed(mdek, leaf->module_uuid, v->header.epoch,
                                   payload, payload_len, &name, &name_len,
                                   &data, &data_len);
    } else {
        rc = vty_record_open(mdek, leaf->module_uuid, v->header.epoch,
                             payload, payload_len, &name, &name_len,
                             &data, &data_len);
    }
    vty_free(payload, payload_len);
    if (rc != VTY_OK) return rc;

    if (data_len == 0u) { rc = VTY_E_CORRUPT; goto out; }
    if ((size_t)leaf->plain_size != data_len - 1u) {
        rc = VTY_E_CORRUPT;
        goto out;
    }
    copy = (uint8_t *)vty_alloc(data_len - 1u);
    if (data_len > 1u && copy == NULL) { rc = VTY_E_RESOURCE; goto out; }
    if (data_len > 1u) memcpy(copy, data + 1, data_len - 1u);

    out->id = leaf->record_id;
    out->type = data[0];
    out->name = name;
    out->name_len = name_len;
    out->data = copy;
    out->data_len = data_len - 1u;
    name = NULL;
    copy = NULL;
    rc = VTY_OK;

out:
    if (name != NULL) vty_free(name, name_len != 0 ? name_len : 1u);
    if (copy != NULL) vty_free(copy, data_len - 1u);
    if (data != NULL) {
        vty_secure_zero(data, data_len);
        vty_free(data, data_len);
    }
    return rc;
}

int vty_repo_module_rekey_bytes(VtyVault *v, uint32_t index, uint64_t *out)
{
    VtyStoreCursor *c = NULL;
    uint64_t total = 0;
    int rc;

    if (v == NULL || out == NULL) return VTY_E_INVALID;
    if (!v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        VtyRepoLeaf leaf;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc == VTY_OK && !done && klen == 8u && repo_get_be64(k) != 0u &&
            vlen == VTY_REPO_LEAF_BYTES) {
            rc = repo_leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0 &&
                memcmp(leaf.module_uuid, v->modules[index].uuid,
                       VTY_UUID_BYTES) == 0) {
                total += (uint64_t)leaf.data_len + VTY_REPO_LEAF_BYTES +
                         VTY_RECORD_KEY_HEADER_BYTES +
                         (VTY_HASH_BYTES + 8u) * 2u;
            }
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK || done) break;
    }
    vty_store_cursor_close(c);
    if (rc != VTY_OK) return rc;

    if (index == 2u) {
        rc = vty_store_cursor_open(v->store, VTY_KS_CHUNK, NULL, 0, &c);
        if (rc != VTY_OK) return rc;
        for (;;) {
            int done = 0;
            uint8_t *k = NULL, *val = NULL;
            size_t klen = 0, vlen = 0;

            rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
            if (rc == VTY_OK && !done && vlen == VTY_REPO_CHUNK_BYTES) {
                VtyRepoChunkEntry e;
                rc = repo_chunk_leaf_decode(val, vlen, &e);
                if (rc == VTY_OK) {
                    total += (uint64_t)e.len + VTY_REPO_CHUNK_BYTES;
                }
            }
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            if (rc != VTY_OK || done) break;
        }
        vty_store_cursor_close(c);
        if (rc != VTY_OK) return rc;
    }

    *out = total + VTY_MODULE_DESC_MAX;
    return VTY_OK;
}

static int index_key_expect_empty(VtyVault *v, uint8_t keyspace,
                                  const uint8_t key[VTY_HASH_BYTES + 8u])
{
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc = vty_store_get(v->store, keyspace, key, VTY_HASH_BYTES + 8u,
                           &val, &vlen);
    if (rc != VTY_OK) return VTY_E_CORRUPT;
    if (vlen != 0u) {
        vty_free(val, vlen);
        return VTY_E_CORRUPT;
    }
    if (val != NULL) vty_free(val, 0u);
    return VTY_OK;
}

/* 内容记录内层信封换封。
 *
 * 照片/清藏内容在落库前先由内容层以模块 MDEK 做分片封装，随后记录层
 * 又以同一 MDEK 加密外层。模块启用轮换 MDEK 时若只重写外层，内层仍
 * 绑定旧 MDEK，启用后全部内容认证失败（表现为照片损坏、文件块不可读）。
 *
 * 判据以内层信封可认证为准：结构自洽且能以旧 MDEK 打开才换封；普通
 * 记录载荷（账户明文、文件索引等）无法通过认证，原样保留。
 * allow_embedded 仅对 meta 记录开启：旧版 meta 的 chunkDataB64 内还嵌着
 * 一层分片信封，需要递归换封；普通数据块载荷禁止扫描，避免误改内容。
 */
static int rewrap_content_envelope(const uint8_t old_mdek[VTY_KEY_BYTES],
                                   const uint8_t new_mdek[VTY_KEY_BYTES],
                                   uint64_t old_epoch,
                                   uint64_t new_epoch,
                                   int allow_embedded,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len,
                                   int *rewrapped)
{
    const size_t prefix = VTY_UUID_BYTES + 4u + 4u + 4u;
    const size_t min_len = prefix + VTY_NONCE_BYTES + VTY_TAG_BYTES;
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint32_t seq, total, pt_len;
    uint8_t *pt = NULL;
    uint8_t *embedded = NULL;
    size_t pt_bytes = 0;
    size_t embedded_len = 0;
    int embedded_rewrapped = 0;
    int rc;

    *out = NULL;
    *out_len = 0;
    *rewrapped = 0;
    if (in == NULL || in_len < min_len) return VTY_OK;

    memcpy(file_uuid, in, VTY_UUID_BYTES);
    seq = vty_get_u32(in + VTY_UUID_BYTES);
    total = vty_get_u32(in + VTY_UUID_BYTES + 4u);
    pt_len = vty_get_u32(in + VTY_UUID_BYTES + 8u);
    if (total == 0u || seq >= total || (size_t)pt_len > VTY_CHUNK_MAX_PT) {
        return VTY_OK;
    }
    if (in_len != prefix + VTY_NONCE_BYTES + (size_t)pt_len + VTY_TAG_BYTES) {
        return VTY_OK;
    }

    rc = vty_chunk_open(old_mdek, file_uuid, seq, total, old_epoch, in, in_len,
                        &pt, &pt_bytes);
    if (rc == VTY_E_AEAD || rc == VTY_E_KEY_INVALID || rc == VTY_E_INVALID) {
        return VTY_OK; /* 不是分片信封：按普通记录载荷处理 */
    }
    if (rc != VTY_OK) return rc; /* 资源/IO 故障：不得静默跳过换封 */

    /* 旧版内联布局：meta JSON 的 chunkDataB64 内还嵌着一层分片信封，
     * 顶层的 vty_chunk_open 无法触达。这里在重封 meta 明文前把其中
     * 能以旧 MDEK 认证的内联分片一并换成新 MDEK。 */
    if (allow_embedded && pt_bytes > 0u && pt[0] == (uint8_t)'{') {
        rc = vty_chunk_rewrap_embedded(old_mdek, new_mdek, old_epoch, new_epoch,
                                       pt, pt_bytes,
                                       &embedded, &embedded_len,
                                       &embedded_rewrapped);
        if (rc != VTY_OK) {
            vty_secure_zero(pt, pt_bytes);
            vty_free(pt, pt_bytes);
            return rc;
        }
        if (embedded_rewrapped) {
            vty_secure_zero(pt, pt_bytes);
            vty_free(pt, pt_bytes);
            pt = embedded;
            pt_bytes = embedded_len;
            embedded = NULL;
        }
    }

    rc = vty_chunk_seal(new_mdek, file_uuid, seq, total, new_epoch, pt, pt_bytes,
                        out, out_len);
    vty_secure_zero(pt, pt_bytes);
    vty_free(pt, pt_bytes != 0 ? pt_bytes : 1u);
    if (embedded != NULL) {
        vty_free(embedded, embedded_len);
    }
    if (rc != VTY_OK) return rc;
    *rewrapped = 1;
    return VTY_OK;
}

/* 全库轮换专用：按模块上下文换封单条内容记录的内层信封。
 *
 * 与 rekey_one_record 共用同一判定：仅非系统记录、且模块为 0/2 时尝试；
 * allow_embedded 的模块/类型门槛保持一致。old_epoch/new_epoch 分离，
 * 供全库轮换跨代使用（模块启用时二者相同）。 */
int vty_repo_rewrap_content(uint8_t type, int module_index,
                            const uint8_t old_mdek[VTY_KEY_BYTES],
                            uint64_t old_epoch,
                            const uint8_t new_mdek[VTY_KEY_BYTES],
                            uint64_t new_epoch,
                            const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t *out_len,
                            int *rewrapped)
{
    int allow_embedded;

    if (out == NULL || out_len == NULL || rewrapped == NULL) {
        return VTY_E_INVALID;
    }
    *out = NULL;
    *out_len = 0;
    *rewrapped = 0;
    if (repo_is_system_type(type)) return VTY_OK;
    if (module_index != 0 && module_index != 2) return VTY_OK;
    allow_embedded = (module_index == 0 && type == 0x01)
                  || (module_index == 2 && (type == 0x08 || type == 0x05));
    return rewrap_content_envelope(old_mdek, new_mdek, old_epoch, new_epoch,
                                   allow_embedded, in, in_len, out, out_len,
                                   rewrapped);
}

/* 内容信封自检：按给定 MDEK/epoch 尝试解封。
 * 结构不符/认证失败返回 VTY_OK 且 *openable=0；资源或内部故障返回错误码，
 * 避免把“无法判断”误当成“不可解封”而静默通过。 */
int vty_repo_content_envelope_check(const uint8_t mdek[VTY_KEY_BYTES],
                                    uint64_t epoch,
                                    const uint8_t *in, size_t in_len,
                                    int *openable)
{
    const size_t prefix = VTY_UUID_BYTES + 4u + 4u + 4u;
    const size_t min_len = prefix + VTY_NONCE_BYTES + VTY_TAG_BYTES;
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint32_t seq, total, pt_len;
    uint8_t *pt = NULL;
    size_t pt_bytes = 0;
    int rc;

    if (openable == NULL) return VTY_E_INVALID;
    *openable = 0;
    if (mdek == NULL || in == NULL || in_len < min_len) return VTY_OK;

    seq = vty_get_u32(in + VTY_UUID_BYTES);
    total = vty_get_u32(in + VTY_UUID_BYTES + 4u);
    pt_len = vty_get_u32(in + VTY_UUID_BYTES + 8u);
    if (total == 0u || seq >= total || (size_t)pt_len > VTY_CHUNK_MAX_PT) {
        return VTY_OK;
    }
    if (in_len != prefix + VTY_NONCE_BYTES + (size_t)pt_len + VTY_TAG_BYTES) {
        return VTY_OK;
    }
    memcpy(file_uuid, in, VTY_UUID_BYTES);
    rc = vty_chunk_open(mdek, file_uuid, seq, total, epoch, in, in_len,
                        &pt, &pt_bytes);
    if (rc == VTY_E_AEAD || rc == VTY_E_KEY_INVALID || rc == VTY_E_INVALID) {
        return VTY_OK;
    }
    if (rc != VTY_OK) return rc;
    vty_secure_zero(pt, pt_bytes != 0 ? pt_bytes : 1u);
    vty_free(pt, pt_bytes != 0 ? pt_bytes : 1u);
    *openable = 1;
    return VTY_OK;
}

/* 记录重写：保留 record_id/created_time/flags，按重写后的真实长度更新
 * plain_size，换 MDEK 与名称/类型盲索引；旧索引键必须存在，缺失即说明
 * 库已不一致。内联分片换封会改变记录明文长度，plain_size 必须同步。 */
static int rekey_one_record(VtyVault *v, const VtyRepoLeaf *leaf,
                            const uint8_t old_mdek[VTY_KEY_BYTES],
                            const uint8_t new_mdek[VTY_KEY_BYTES],
                            const uint8_t module_uuid[VTY_UUID_BYTES],
                            int module_index,
                            int rewrap_content)
{
    VtyRepoRecord rec;
    RepoLeafRaw raw;
    VtySegmentLocator loc;
    uint8_t *plain = NULL;
    uint8_t *sealed = NULL;
    uint8_t *inner = NULL;
    size_t inner_len = 0;
    size_t sealed_len = 0;
    int rewrapped = 0;
    uint8_t name_index[VTY_HASH_BYTES];
    uint8_t type_token[VTY_HASH_BYTES];
    uint8_t ikey[VTY_HASH_BYTES + 8u];
    uint8_t key[8];
    uint8_t leaf_buf[VTY_REPO_LEAF_BYTES];
    uint8_t system_key[VTY_KEY_BYTES];
    const uint8_t *seal_key = new_mdek;
    const uint8_t *seal_uuid = module_uuid;
    int rc;

    memset(system_key, 0, sizeof(system_key));
    memset(&rec, 0, sizeof(rec));
    rc = repo_read_with_mdek(v, leaf, old_mdek, &rec);
    if (rc != VTY_OK) return rc;

    /* 内容模块记录：内层分片信封必须随 MDEK 一并换封。内联分片只存在于
     * meta 类型（照片 0x01；文件元数据 0x08/旧 0x05），按模块限定类型，
     * 避免把照片/文件块载荷中偶然出现的字节序列误当作内联分片。 */
    if (rewrap_content && !repo_is_system_type(rec.type)) {
        int allow_embedded = (module_index == 0 && rec.type == 0x01)
                          || (module_index == 2 && (rec.type == 0x08 || rec.type == 0x05));
        rc = rewrap_content_envelope(old_mdek, new_mdek,
                                     v->header.epoch, v->header.epoch,
                                     allow_embedded,
                                     rec.data, rec.data_len, &inner, &inner_len,
                                     &rewrapped);
        if (rc != VTY_OK) goto out;
        if (rewrapped) {
            vty_secure_zero(rec.data, rec.data_len);
            vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
            rec.data = inner;
            rec.data_len = inner_len;
            inner = NULL;
        }
    }

    /* 安全/密钥管理记录在启用事务中原位迁入系统记录域：
     * 保留 record_id/创建时间/标志位，换系统密钥与保留 UUID，
     * 使记录不再随该模块锁定而不可读。 */
    if (repo_is_system_type(rec.type)) {
        rc = vty_vault_system_key(v, system_key);
        if (rc != VTY_OK) goto out;
        seal_key = system_key;
        seal_uuid = vty_system_module_uuid;
    }

    plain = (uint8_t *)vty_alloc(rec.data_len + 1u);
    if (plain == NULL) { rc = VTY_E_RESOURCE; goto out; }
    plain[0] = rec.type;
    if (rec.data_len != 0u) memcpy(plain + 1, rec.data, rec.data_len);

    rc = vty_record_seal_keyed(seal_key, seal_uuid, leaf->record_id,
                               v->header.epoch, 0u,
                               rec.name, rec.name_len,
                               plain, rec.data_len + 1u, &sealed, &sealed_len);
    vty_secure_zero(plain, rec.data_len + 1u);
    vty_free(plain, rec.data_len + 1u);
    plain = NULL;
    if (rc != VTY_OK) goto out;

    rc = vty_store_append_segment(v->store, VTY_SEG_RECORD,
                                  leaf->record_id, 0u, sealed, sealed_len, &loc);
    vty_secure_zero(sealed, sealed_len);
    vty_free(sealed, sealed_len);
    sealed = NULL;
    if (rc != VTY_OK) goto out;

    rc = vty_name_index(seal_key, seal_uuid, rec.name, rec.name_len,
                        name_index);
    if (rc != VTY_OK) goto out;
    rc = vty_type_token(seal_key, seal_uuid, v->header.epoch, rec.type,
                        type_token);
    if (rc != VTY_OK) goto out;

    memset(&raw, 0, sizeof(raw));
    raw.record_id = leaf->record_id;
    memcpy(raw.module_uuid, seal_uuid, VTY_UUID_BYTES);
    raw.flags = (uint8_t)((leaf->flags | VTY_REPO_FLAG_KEYED) &
                          (uint8_t)~VTY_REPO_FLAG_SCRUB_PENDING);
    memcpy(raw.name_index, name_index, VTY_HASH_BYTES);
    memcpy(raw.type_token, type_token, VTY_HASH_BYTES);
    raw.created_time = leaf->created_time;
    raw.data_offset = loc.offset;
    raw.data_len = loc.total_len;
    raw.plain_size = (uint32_t)rec.data_len;
    memcpy(raw.data_hash, loc.hash, VTY_HASH_BYTES);
    rc = repo_leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) goto out;

    repo_index_key(ikey, leaf->name_index, leaf->record_id);
    rc = index_key_expect_empty(v, VTY_KS_NAME, ikey);
    if (rc != VTY_OK) goto out;
    rc = vty_store_delete(v->store, VTY_KS_NAME, ikey, sizeof(ikey));
    if (rc != VTY_OK) goto out;
    repo_index_key(ikey, leaf->type_token, leaf->record_id);
    rc = index_key_expect_empty(v, VTY_KS_TYPE, ikey);
    if (rc != VTY_OK) goto out;
    rc = vty_store_delete(v->store, VTY_KS_TYPE, ikey, sizeof(ikey));
    if (rc != VTY_OK) goto out;

    repo_index_key(ikey, name_index, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_NAME, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto out;
    repo_index_key(ikey, type_token, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_TYPE, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto out;

    repo_record_key(key, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf_buf, sizeof(leaf_buf));

out:
    if (plain != NULL) {
        vty_secure_zero(plain, rec.data_len + 1u);
        vty_free(plain, rec.data_len + 1u);
    }
    if (sealed != NULL) {
        vty_secure_zero(sealed, sealed_len);
        vty_free(sealed, sealed_len);
    }
    if (inner != NULL) {
        vty_secure_zero(inner, inner_len);
        vty_free(inner, inner_len != 0 ? inner_len : 1u);
    }
    if (rec.name != NULL) vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    if (rec.data != NULL) {
        vty_secure_zero(rec.data, rec.data_len);
        vty_free(rec.data, rec.data_len);
    }
    vty_secure_zero(system_key, sizeof(system_key));
    return rc;
}

/* 分片重写：文件叶不变，只换分片段 CK 与分片叶 chunk_id/locator。 */
static int rekey_chunks(VtyVault *v, const uint8_t old_mdek[VTY_KEY_BYTES],
                        const uint8_t new_mdek[VTY_KEY_BYTES])
{
    VtyStoreCursor *c = NULL;
    uint8_t cur_file[VTY_UUID_BYTES];
    uint32_t cur_total = 0;
    uint32_t seen = 0;
    int have_file = 0;
    int rc;

    memset(cur_file, 0, sizeof(cur_file));
    rc = vty_store_cursor_open(v->store, VTY_KS_CHUNK, NULL, 0, &c);
    if (rc != VTY_OK) return rc;

    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        VtyRepoChunkEntry e;
        VtyRepoFile f;
        uint8_t *payload = NULL;
        size_t payload_len = 0;
        uint8_t *sealed = NULL;
        size_t sealed_len = 0;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        VtySegmentLocator loc;
        uint8_t key[VTY_UUID_BYTES + 4u];
        uint8_t leaf[VTY_REPO_CHUNK_BYTES];
        uint32_t seq;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (klen != VTY_UUID_BYTES + 4u) {
            rc = VTY_E_CORRUPT;
            goto item_out;
        }
        if (repo_value_is_tombstone(vlen, val)) {
            /* 模块删除遗留的墓碑分片：跳过，不参与重写与计数。 */
            rc = VTY_OK;
            goto item_out;
        }
        if (vlen != VTY_REPO_CHUNK_BYTES) {
            rc = VTY_E_CORRUPT;
            goto item_out;
        }
        if (!have_file || memcmp(k, cur_file, VTY_UUID_BYTES) != 0) {
            if (have_file && seen != cur_total) { rc = VTY_E_CORRUPT; goto item_out; }
            memcpy(cur_file, k, VTY_UUID_BYTES);
            memset(&f, 0, sizeof(f));
            rc = repo_file_get_raw(v, cur_file, &f);
            if (rc != VTY_OK) goto item_out;
            cur_total = f.total;
            seen = 0;
            have_file = 1;
        }
        seq = repo_get_be32(k + VTY_UUID_BYTES);
        if (seq >= cur_total) { rc = VTY_E_CORRUPT; goto item_out; }
        rc = repo_chunk_leaf_decode(val, vlen, &e);
        if (rc != VTY_OK) goto item_out;

        {
            VtySegmentLocator rloc;
            memset(&rloc, 0, sizeof(rloc));
            rloc.type = VTY_SEG_CHUNK;
            rloc.seq = seq;
            rloc.offset = e.offset;
            rloc.total_len = e.len;
            memcpy(rloc.hash, e.hash, VTY_HASH_BYTES);
            rc = vty_store_read_segment(v->store, &rloc, &payload, &payload_len);
            if (rc != VTY_OK) goto item_out;
        }
        rc = vty_chunk_open(old_mdek, cur_file, seq, cur_total, v->header.epoch,
                            payload, payload_len, &pt, &pt_len);
        vty_free(payload, payload_len);
        payload = NULL;
        if (rc != VTY_OK) goto item_out;

        rc = vty_chunk_seal(new_mdek, cur_file, seq, cur_total, v->header.epoch,
                            pt, pt_len, &sealed, &sealed_len);
        vty_secure_zero(pt, pt_len);
        vty_free(pt, pt_len);
        pt = NULL;
        if (rc != VTY_OK) goto item_out;

        rc = vty_store_append_segment(v->store, VTY_SEG_CHUNK, seq, 0u,
                                      sealed, sealed_len, &loc);
        vty_secure_zero(sealed, sealed_len);
        vty_free(sealed, sealed_len);
        sealed = NULL;
        if (rc != VTY_OK) goto item_out;

        memset(&e, 0, sizeof(e));
        e.seq = seq;
        rc = vty_chunk_id(new_mdek, cur_file, seq, e.chunk_id);
        if (rc != VTY_OK) goto item_out;
        e.offset = loc.offset;
        e.len = loc.total_len;
        memcpy(e.hash, loc.hash, VTY_HASH_BYTES);
        rc = repo_chunk_leaf_encode(&e, leaf);
        if (rc != VTY_OK) goto item_out;
        repo_chunk_key(key, cur_file, seq);
        rc = vty_store_put(v->store, VTY_KS_CHUNK, key, sizeof(key),
                           leaf, sizeof(leaf));
        if (rc != VTY_OK) goto item_out;
        seen++;

item_out:
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (payload != NULL) vty_free(payload, payload_len);
        if (sealed != NULL) {
            vty_secure_zero(sealed, sealed_len);
            vty_free(sealed, sealed_len);
        }
        if (pt != NULL) {
            vty_secure_zero(pt, pt_len);
            vty_free(pt, pt_len);
        }
        if (rc != VTY_OK) break;
    }

    vty_store_cursor_close(c);
    if (rc != VTY_OK) return rc;
    if (have_file && seen != cur_total) return VTY_E_CORRUPT;
    return VTY_OK;
}

int vty_repo_module_rekey(VtyVault *v, uint32_t index,
                          const uint8_t old_mdek[VTY_KEY_BYTES],
                          const uint8_t new_mdek[VTY_KEY_BYTES])
{
    VtyRepoIter *it = NULL;
    uint8_t module_uuid[VTY_UUID_BYTES];
    int rc;

    if (v == NULL || old_mdek == NULL || new_mdek == NULL) return VTY_E_INVALID;
    if (!v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    memcpy(module_uuid, v->modules[index].uuid, VTY_UUID_BYTES);
    rc = vty_repo_iter_open(v, 0u, &it);
    if (rc != VTY_OK) return rc;

    for (;;) {
        VtyRepoLeaf leaf;
        int done = 0;
        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK) break;
        if (done) break;
        if (memcmp(leaf.module_uuid, module_uuid, VTY_UUID_BYTES) != 0) continue;
        rc = rekey_one_record(v, &leaf, old_mdek, new_mdek, module_uuid, index,
                              index == 0u || index == 2u);
        if (rc != VTY_OK) break;
    }
    vty_repo_iter_close(it);
    if (rc != VTY_OK) return rc;

    if (index == 2u) rc = rekey_chunks(v, old_mdek, new_mdek);
    return rc;
}

/* 删除模块：记录叶/名称/类型索引写墓碑；fileverthys 额外清空文件/分片叶。
 * 与普通删除共用 repo_delete_one，保持索引与叶一致。 */
int vty_repo_module_purge(VtyVault *v, uint32_t index,
                          const uint8_t module_uuid[VTY_UUID_BYTES],
                          uint64_t *out_records,
                          uint64_t *out_files,
                          uint64_t *out_chunks)
{
    VtyStoreCursor *c = NULL;
    uint64_t records = 0, files = 0, chunks = 0;
    int rc;

    if (out_records != NULL) *out_records = 0;
    if (out_files != NULL) *out_files = 0;
    if (out_chunks != NULL) *out_chunks = 0;
    if (v == NULL || module_uuid == NULL) return VTY_E_INVALID;
    if (!v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;
        VtyRepoLeaf leaf;
        int is_allocator = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) break;
        if (done) break;
        if (klen == 8u) {
            size_t i;
            is_allocator = 1;
            for (i = 0; i < 8u; i++) {
                if (k[i] != 0u) { is_allocator = 0; break; }
            }
        }
        if (is_allocator) {
            if (vlen != 8u) { rc = VTY_E_CORRUPT; }
        } else if (klen == 8u && vlen == VTY_REPO_LEAF_BYTES) {
            rc = repo_leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0 &&
                memcmp(leaf.module_uuid, module_uuid, VTY_UUID_BYTES) == 0) {
                rc = repo_delete_one(v, &leaf);
                if (rc == VTY_OK) records++;
            }
        } else {
            rc = VTY_E_CORRUPT;
        }
        if (k != NULL) vty_free(k, klen);
        if (val != NULL) vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    c = NULL;
    if (rc != VTY_OK) return rc;

    if (index == 2u) {
        rc = vty_store_cursor_open(v->store, VTY_KS_CHUNK, NULL, 0, &c);
        if (rc != VTY_OK) return rc;
        for (;;) {
            int done = 0;
            uint8_t *k = NULL, *val = NULL;
            size_t klen = 0, vlen = 0;

            rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
            if (rc != VTY_OK) break;
            if (done) break;
            if (klen != VTY_UUID_BYTES + 4u) {
                rc = VTY_E_CORRUPT;
            } else if (repo_value_is_tombstone(vlen, val)) {
                /* 已删除分片：跳过，不重复计数。 */
                rc = VTY_OK;
            } else if (vlen != VTY_REPO_CHUNK_BYTES) {
                rc = VTY_E_CORRUPT;
            } else {
                rc = vty_store_delete(v->store, VTY_KS_CHUNK, k, klen);
                if (rc == VTY_OK) chunks++;
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
            if (klen != VTY_UUID_BYTES) {
                rc = VTY_E_CORRUPT;
            } else if (repo_value_is_tombstone(vlen, val)) {
                /* 已删除文件：跳过，不重复计数。 */
                rc = VTY_OK;
            } else if (vlen != VTY_REPO_FILE_BYTES) {
                rc = VTY_E_CORRUPT;
            } else {
                rc = vty_store_delete(v->store, VTY_KS_FILE, k, klen);
                if (rc == VTY_OK) files++;
            }
            if (k != NULL) vty_free(k, klen);
            if (val != NULL) vty_free(val, vlen);
            if (rc != VTY_OK) break;
        }
        vty_store_cursor_close(c);
        if (rc != VTY_OK) return rc;
    }

    if (out_records != NULL) *out_records = records;
    if (out_files != NULL) *out_files = files;
    if (out_chunks != NULL) *out_chunks = chunks;
    return VTY_OK;
}
