/*
 * vty_repo_record.c — 记录写入、读取与原子替换
 */

#include "vty_repo_internal.h"


static int repo_add_one_ex(VtyVault *v, uint8_t type,
                           const uint8_t *name, size_t name_len,
                           const uint8_t *data, size_t data_len,
                           uint64_t forced_id, uint64_t created_time,
                           uint64_t prev_id, uint64_t *out_id)
{
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t name_index[VTY_HASH_BYTES];
    uint8_t type_token[VTY_HASH_BYTES];
    uint8_t *plain = NULL;
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    RepoLeafRaw raw;
    VtySegmentLocator loc;
    uint8_t key[8];
    uint8_t ikey[VTY_HASH_BYTES + 8u];
    uint8_t leaf_buf[VTY_REPO_LEAF_BYTES];
    uint64_t id = 0, next_id = 0;
    const char *empty = "";
    int rc;

    rc = repo_module_for_type(v, type, module_uuid, mdek);
    if (rc != VTY_OK) goto fail;

    rc = repo_get_next_id(v, &next_id);
    if (rc != VTY_OK) goto fail;
    if (forced_id != 0u) {
        /* 复制顺序按旧 ID 升序；回退到已消费 ID 会让分配器失去单调性。 */
        if (forced_id < next_id) { rc = VTY_E_INVALID; goto fail; }
        id = forced_id;
    } else {
        id = next_id;
    }
    if (id == UINT64_MAX) { rc = VTY_E_RESOURCE; goto fail; }

    /* 数据明文首字节是记录类型；真实长度仍由 AEAD 内层长度字段保护。 */
    plain = (uint8_t *)vty_alloc(data_len + 1u);
    if (plain == NULL) { rc = VTY_E_RESOURCE; goto fail; }
    plain[0] = type;
    if (data_len != 0) memcpy(plain + 1, data, data_len);

    rc = vty_record_seal_keyed(mdek, module_uuid, id, v->header.epoch, prev_id,
                               name != NULL ? name : (const uint8_t *)empty,
                               name_len, plain, data_len + 1u,
                               &sealed, &sealed_len);
    vty_secure_zero(plain, data_len + 1u);
    vty_free(plain, data_len + 1u);
    plain = NULL;
    if (rc != VTY_OK) goto fail;

    rc = vty_store_append_segment(v->store, VTY_SEG_RECORD, id, 0u,
                                  sealed, sealed_len, &loc);
    vty_secure_zero(sealed, sealed_len);
    vty_free(sealed, sealed_len);
    sealed = NULL;
    if (rc != VTY_OK) goto fail;

    rc = vty_name_index(mdek, module_uuid,
                        name != NULL ? name : (const uint8_t *)empty, name_len,
                        name_index);
    if (rc != VTY_OK) goto fail;
    rc = vty_type_token(mdek, module_uuid, v->header.epoch, type, type_token);
    if (rc != VTY_OK) goto fail;

    memset(&raw, 0, sizeof(raw));
    raw.record_id = id;
    memcpy(raw.module_uuid, module_uuid, VTY_UUID_BYTES);
    raw.flags = VTY_REPO_FLAG_KEYED;
    memcpy(raw.name_index, name_index, VTY_HASH_BYTES);
    memcpy(raw.type_token, type_token, VTY_HASH_BYTES);
    /* UINT64_MAX = 由本次写入取当前时间；其余值原样保留（含 0），
     * 保证轮换复制不篡改历史创建时间。 */
    raw.created_time = (created_time == UINT64_MAX)
                           ? (uint64_t)time(NULL)
                           : created_time;
    raw.data_offset = loc.offset;
    raw.data_len = loc.total_len;
    raw.plain_size = (uint32_t)data_len;
    memcpy(raw.data_hash, loc.hash, VTY_HASH_BYTES);
    rc = repo_leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) goto fail;

    repo_record_key(key, id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf_buf, sizeof(leaf_buf));
    if (rc != VTY_OK) goto fail;

    repo_index_key(ikey, name_index, id);
    rc = vty_store_put(v->store, VTY_KS_NAME, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto fail;
    repo_index_key(ikey, type_token, id);
    rc = vty_store_put(v->store, VTY_KS_TYPE, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto fail;

    /* 分配器与记录同一次提交：崩溃时不会出现“ID 已用但记录不存在”
     * 或“记录存在但计数回退”。 */
    rc = repo_put_next_id(v, id + 1u);
    if (rc != VTY_OK) goto fail;

    *out_id = id;
    vty_secure_zero(mdek, sizeof(mdek));
    return VTY_OK;

fail:
    if (plain != NULL) {
        vty_secure_zero(plain, data_len + 1u);
        vty_free(plain, data_len + 1u);
    }
    if (sealed != NULL) {
        vty_secure_zero(sealed, sealed_len);
        vty_free(sealed, sealed_len);
    }
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

static int repo_add_one(VtyVault *v, uint8_t type,
                        const uint8_t *name, size_t name_len,
                        const uint8_t *data, size_t data_len,
                        uint64_t forced_id, uint64_t created_time,
                        uint64_t *out_id)
{
    return repo_add_one_ex(v, type, name, name_len, data, data_len,
                           forced_id, created_time, 0u, out_id);
}

static int repo_add_check(uint8_t type, const uint8_t *name, size_t name_len,
                          const uint8_t *data, size_t data_len)
{
    (void)type;
    if (name == NULL && name_len != 0) return VTY_E_INVALID;
    if (data == NULL && data_len != 0) return VTY_E_INVALID;
    if (name_len > VTY_RECORD_MAX_NAME) return VTY_E_INVALID;
    /* 数据明文首字节为类型，因此原始数据上界比记录层少 1 字节。 */
    if (data_len >= (size_t)VTY_RECORD_MAX_DATA) return VTY_E_INVALID;
    return VTY_OK;
}

int vty_repo_add(VtyVault *v, uint8_t type,
                 const uint8_t *name, size_t name_len,
                 const uint8_t *data, size_t data_len,
                 uint64_t *out_id)
{
    VtyStoreCheckpoint cp;
    int rc;

    if (out_id == NULL) return VTY_E_INVALID;
    rc = repo_add_check(type, name, name_len, data, data_len);
    if (rc != VTY_OK) return rc;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;

    rc = repo_add_one(v, type, name, name_len, data, data_len, 0u,
                      UINT64_MAX, out_id);
    if (rc != VTY_OK) goto fail;
    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    return VTY_OK;

fail:
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_add_ex(VtyVault *v, uint8_t type,
                    const uint8_t *name, size_t name_len,
                    const uint8_t *data, size_t data_len,
                    uint64_t forced_id, uint64_t created_time,
                    uint64_t *out_id)
{
    VtyStoreCheckpoint cp;
    int rc;

    if (out_id == NULL || forced_id == 0u) return VTY_E_INVALID;
    *out_id = 0u;
    rc = repo_add_check(type, name, name_len, data, data_len);
    if (rc != VTY_OK) return rc;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;

    rc = repo_add_one(v, type, name, name_len, data, data_len,
                      forced_id, created_time, out_id);
    if (rc != VTY_OK) goto fail;
    if (*out_id != forced_id) { rc = VTY_E_VERIFY; goto fail; }
    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    return VTY_OK;

fail:
    *out_id = 0u;
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_add_many(VtyVault *v, const VtyRepoInput *in, size_t count,
                      uint64_t *out_ids)
{
    VtyStoreCheckpoint cp;
    size_t i;
    int rc;

    if (in == NULL && count != 0) return VTY_E_INVALID;
    if (count == 0) return VTY_OK;
    for (i = 0; i < count; i++) {
        rc = repo_add_check(in[i].type, in[i].name, in[i].name_len,
                            in[i].data, in[i].data_len);
        if (rc != VTY_OK) return rc;
    }
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;

    for (i = 0; i < count; i++) {
        uint64_t id = 0;
        rc = repo_add_one(v, in[i].type, in[i].name, in[i].name_len,
                          in[i].data, in[i].data_len, 0u, UINT64_MAX, &id);
        if (rc != VTY_OK) goto fail;
        if (out_ids != NULL) out_ids[i] = id;
    }

    /* 批量导入只在末尾提交一次：中途失败整体恢复到导入前的根，
     * 未提交的记录段保持不可达。 */
    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    return VTY_OK;

fail:
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_read(VtyVault *v, const VtyRepoLeaf *leaf, VtyRepoRecord *out)
{
    uint8_t mdek[VTY_KEY_BYTES];
    VtySegmentLocator loc;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint8_t *name = NULL;
    uint8_t *data = NULL;
    size_t name_len = 0;
    size_t data_len = 0;
    uint8_t *copy = NULL;
    int rc;

    if (v == NULL || leaf == NULL || out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    if ((leaf->flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;

    rc = vty_vault_module_key(v, leaf->module_uuid, mdek);
    if (rc != VTY_OK) return rc;

    memset(&loc, 0, sizeof(loc));
    loc.type = VTY_SEG_RECORD;
    loc.seq = leaf->record_id;
    loc.id = 0u;
    loc.offset = leaf->data_offset;
    loc.total_len = leaf->data_len;
    memcpy(loc.hash, leaf->data_hash, VTY_HASH_BYTES);
    rc = vty_store_read_segment(v->store, &loc, &payload, &payload_len);
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }

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
    vty_secure_zero(mdek, sizeof(mdek));
    if (rc != VTY_OK) return rc;

    if (data_len == 0u) {
        rc = VTY_E_CORRUPT;
        goto out;
    }
    /* 索引 plain_size 与 AEAD 内层真实长度必须一致；任何背离都是
     * 目录/记录段交叉损坏，不能向调用方返回猜测值。 */
    if ((size_t)(leaf->plain_size) != data_len - 1u) {
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

int vty_repo_read_name(VtyVault *v, const VtyRepoLeaf *leaf,
                       uint8_t **name, size_t *name_len)
{
    uint8_t mdek[VTY_KEY_BYTES];
    VtySegmentLocator loc;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    int rc;

    if (v == NULL || leaf == NULL || name == NULL || name_len == NULL) {
        return VTY_E_INVALID;
    }
    *name = NULL;
    *name_len = 0;
    if ((leaf->flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;

    rc = vty_vault_module_key(v, leaf->module_uuid, mdek);
    if (rc != VTY_OK) return rc;

    memset(&loc, 0, sizeof(loc));
    loc.type = VTY_SEG_RECORD;
    loc.seq = leaf->record_id;
    loc.id = 0u;
    loc.offset = leaf->data_offset;
    loc.total_len = leaf->data_len;
    memcpy(loc.hash, leaf->data_hash, VTY_HASH_BYTES);
    rc = vty_store_read_segment(v->store, &loc, &payload, &payload_len);
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }

    if ((leaf->flags & VTY_REPO_FLAG_KEYED) != 0) {
        rc = vty_record_open_name_keyed(mdek, leaf->module_uuid,
                                        v->header.epoch, payload, payload_len,
                                        name, name_len);
    } else {
        rc = vty_record_open_name(mdek, leaf->module_uuid, v->header.epoch,
                                  payload, payload_len, name, name_len);
    }
    vty_free(payload, payload_len);
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

int vty_repo_get(VtyVault *v, uint64_t id, VtyRepoRecord *out)
{
    VtyRepoLeaf leaf;
    int found = 0;
    int rc;

    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    if (id == 0u || out == NULL) return VTY_E_INVALID;
    rc = repo_get_leaf_raw(v, id, &leaf, &found);
    if (rc != VTY_OK) return rc;
    if (!found || (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;
    return vty_repo_read(v, &leaf, out);
}

int vty_repo_replace(VtyVault *v, uint64_t old_id, uint8_t type,
                     const uint8_t *name, size_t name_len,
                     const uint8_t *data, size_t data_len,
                     uint64_t *out_new_id)
{
    VtyStoreCheckpoint cp;
    VtyRepoLeaf old_leaf;
    int found = 0;
    int rc;
    uint64_t new_id = 0;

    if (out_new_id == NULL || old_id == 0u) return VTY_E_INVALID;
    *out_new_id = 0u;
    rc = repo_add_check(type, name, name_len, data, data_len);
    if (rc != VTY_OK) return rc;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;

    /* 先定位并校验旧记录：不存在/已墓碑/模块不可用 → 零副作用拒绝 */
    rc = repo_get_leaf_raw(v, old_id, &old_leaf, &found);
    if (rc != VTY_OK) goto fail;
    if (!found || (old_leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0) {
        rc = VTY_E_INVALID;
        goto fail;
    }
    rc = repo_require_leaf_module(v, &old_leaf);
    if (rc != VTY_OK) goto fail;

    /* 新记录追加（含分配器推进），随后墓碑化旧记录；两者共用一次提交。
     * 新记录密钥头指向上一个版本，删除时沿链擦除全部历史密钥。 */
    rc = repo_add_one_ex(v, type, name, name_len, data, data_len, 0u,
                         UINT64_MAX, old_id, &new_id);
    if (rc != VTY_OK) goto fail;
    if (new_id <= old_id) {
        rc = VTY_E_VERIFY;
        goto fail;
    }
    rc = repo_delete_one(v, &old_leaf);
    if (rc != VTY_OK) goto fail;

    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    *out_new_id = new_id;

    if (!repo_skip_scrub()) {
        int cleared = 0;
        repo_finish_scrub(v, &old_leaf, &cleared);
        (void)vty_store_flush(v->store);
        if (cleared) (void)repo_commit(v);
    }
    return VTY_OK;

fail:
    vty_store_restore(v->store, &cp);
    return rc;
}
