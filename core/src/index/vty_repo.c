/*
 * vty_repo.c — 记录仓库实现
 *
 * 写入顺序固定为：分配器/记录段/叶/索引 → store_commit → Keyring
 * DataRoot → 元数据保存。任何一步失败都恢复到本次写入前的根指针，
 * 未提交的追加段保持不可达（COW 不覆盖旧节点）。
 */
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_record.h"
#include "vty_chunk.h"
#include "vty_module.h"
#include "vty_util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t record_id;
    uint8_t  module_uuid[VTY_UUID_BYTES];
    uint8_t  flags;
    uint8_t  name_index[VTY_HASH_BYTES];
    uint8_t  type_token[VTY_HASH_BYTES];
    uint64_t created_time;
    uint64_t data_offset;
    uint32_t data_len;
    uint32_t plain_size;
    uint8_t  data_hash[VTY_HASH_BYTES];
} RepoLeafRaw;

struct VtyRepoIter {
    VtyVault *v;
    VtyStoreCursor *cur;
    uint64_t start_id;
};

static void be64(uint8_t out[8], uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_be64(const uint8_t in[8])
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | (uint64_t)in[i];
    return v;
}

static void be32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static int repo_ready(VtyVault *v)
{
    if (v == NULL || !v->unlocked) return VTY_E_POLICY;
    if (v->store == NULL) return VTY_E_POLICY;
    return VTY_OK;
}

/* 轮换：源库在轮换作业期间只读。所有写入口经本函数拒绝，避免复制
 * 快照之外的变更在提交时被静默丢弃。 */
static int repo_write_ready(VtyVault *v)
{
    int rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    return VTY_OK;
}

/* 键空间删除以单字节墓碑表示；所有范围扫描都必须把它当作“已删除”跳过，
 * 否则模块删除/重建后的 rekey、purge、清单重建会把合法墓碑误判为损坏。 */
static int repo_value_is_tombstone(size_t vlen, const uint8_t *val)
{
    return vlen == 1u && val != NULL && val[0] == VTY_STORE_TOMBSTONE_BYTE;
}

/* 记录按类型路由到模块；MDEK 取用统一受模块策略位约束。 */
static int repo_module_index(VtyVault *v, uint32_t index,
                             uint8_t uuid[VTY_UUID_BYTES],
                             uint8_t mdek[VTY_KEY_BYTES])
{
    int rc;

    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    memcpy(uuid, v->modules[index].uuid, VTY_UUID_BYTES);
    rc = vty_vault_module_key_index(v, index, mdek);
    if (rc != VTY_OK) vty_secure_zero(mdek, VTY_KEY_BYTES);
    return rc;
}

/* 安全/密钥管理记录的类型白名单：不归属任何可启用模块，使用系统记录域。
 * 0x11 为退役证书记录，仍按业务类型路由，避免其机密性下降。 */
static int repo_is_system_type(uint8_t type)
{
    return type == 0x10u || type == 0x12u || type == 0x13u;
}

static int repo_module_for_type(VtyVault *v, uint8_t type,
                                uint8_t uuid[VTY_UUID_BYTES],
                                uint8_t mdek[VTY_KEY_BYTES])
{
    if (repo_is_system_type(type)) {
        memcpy(uuid, vty_system_module_uuid, VTY_UUID_BYTES);
        return vty_vault_system_key(v, mdek);
    }
    return repo_module_index(v, vty_module_index_for_type(type), uuid, mdek);
}

/* 文件/分片固定归 fileverthys；仅做策略检查并丢弃取出的密钥。 */
static int repo_require_file_module(VtyVault *v)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc = repo_module_index(v, 2u, uuid, mdek);
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

/* 删除也必须遵守模块策略：锁定模块的记录不可被无声删除。 */
static int repo_require_leaf_module(VtyVault *v, const VtyRepoLeaf *leaf)
{
    uint8_t key[VTY_KEY_BYTES];
    int rc;

    memset(key, 0, sizeof(key));
    rc = vty_vault_module_key(v, leaf->module_uuid, key);
    vty_secure_zero(key, sizeof(key));
    return rc;
}

static int repo_commit(VtyVault *v)
{
    int rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) return rc;
    return vty_vault_save_meta(v);
}

/* 叶子固定 148B；任何未知标志位都拒绝，避免未来字段被旧代码误解。 */
static int leaf_encode(const RepoLeafRaw *r, uint8_t out[VTY_REPO_LEAF_BYTES])
{
    size_t off = 0;

    if (r == NULL || out == NULL) return VTY_E_INVALID;
    if ((r->flags & (uint8_t)~VTY_REPO_FLAG_KNOWN) != 0) return VTY_E_INVALID;
    out[off++] = 1u;
    out[off++] = r->flags;
    vty_put_u16(out + off, 0); off += 2;
    vty_put_u64(out + off, r->record_id); off += 8;
    memcpy(out + off, r->module_uuid, VTY_UUID_BYTES); off += VTY_UUID_BYTES;
    memcpy(out + off, r->name_index, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    memcpy(out + off, r->type_token, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    vty_put_u64(out + off, r->created_time); off += 8;
    vty_put_u64(out + off, r->data_offset); off += 8;
    vty_put_u32(out + off, r->data_len); off += 4;
    vty_put_u32(out + off, r->plain_size); off += 4;
    memcpy(out + off, r->data_hash, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    return off == VTY_REPO_LEAF_BYTES ? VTY_OK : VTY_E_INVALID;
}

static int leaf_decode(const uint8_t *in, size_t in_len, VtyRepoLeaf *out)
{
    size_t off = 0;

    if (in == NULL || out == NULL) return VTY_E_INVALID;
    if (in_len != VTY_REPO_LEAF_BYTES) return VTY_E_CORRUPT;
    if (in[off++] != 1u) return VTY_E_CORRUPT;
    out->flags = in[off++];
    if ((out->flags & (uint8_t)~VTY_REPO_FLAG_KNOWN) != 0) return VTY_E_CORRUPT;
    if (vty_get_u16(in + off) != 0u) return VTY_E_CORRUPT;
    off += 2;
    out->record_id = vty_get_u64(in + off); off += 8;
    memcpy(out->module_uuid, in + off, VTY_UUID_BYTES); off += VTY_UUID_BYTES;
    memcpy(out->name_index, in + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    memcpy(out->type_token, in + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    out->created_time = vty_get_u64(in + off); off += 8;
    out->data_offset = vty_get_u64(in + off); off += 8;
    out->data_len = vty_get_u32(in + off); off += 4;
    out->plain_size = vty_get_u32(in + off); off += 4;
    memcpy(out->data_hash, in + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    if (off != VTY_REPO_LEAF_BYTES) return VTY_E_CORRUPT;
    if (out->record_id == 0u) return VTY_E_CORRUPT;
    return VTY_OK;
}

static void record_key(uint8_t out[8], uint64_t id)
{
    be64(out, id);
}

static void index_key(uint8_t out[VTY_HASH_BYTES + 8u],
                      const uint8_t token[VTY_HASH_BYTES], uint64_t id)
{
    memcpy(out, token, VTY_HASH_BYTES);
    be64(out + VTY_HASH_BYTES, id);
}

static int get_leaf_raw(VtyVault *v, uint64_t id, VtyRepoLeaf *out, int *found)
{
    uint8_t key[8];
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    *found = 0;
    record_key(key, id);
    rc = vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key), &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen != VTY_REPO_LEAF_BYTES) {
        vty_free(val, vlen);
        return VTY_E_CORRUPT;
    }
    rc = leaf_decode(val, vlen, out);
    vty_free(val, vlen);
    if (rc != VTY_OK) return rc;
    if (out->record_id != id) return VTY_E_CORRUPT;
    *found = 1;
    return VTY_OK;
}

static int get_next_id(VtyVault *v, uint64_t *out)
{
    uint8_t zero[8] = {0};
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    rc = vty_store_get(v->store, VTY_KS_RECORD, zero, sizeof(zero), &val, &vlen);
    if (rc == VTY_OK) {
        if (vlen != 8u) {
            vty_free(val, vlen);
            return VTY_E_CORRUPT;
        }
        *out = vty_get_u64(val);
        vty_free(val, vlen);
        if (*out == 0u || *out == UINT64_MAX) return VTY_E_CORRUPT;
        return VTY_OK;
    }
    /* 空树首次写入：分配器由本次 Add 建立（next=2，返回 1）。 */
    if (vty_store_is_empty(v->store)) {
        *out = 1u;
        return VTY_OK;
    }
    return VTY_E_CORRUPT;
}

static int put_next_id(VtyVault *v, uint64_t next_id)
{
    uint8_t zero[8] = {0};
    uint8_t val[8];

    vty_put_u64(val, next_id);
    return vty_store_put(v->store, VTY_KS_RECORD, zero, sizeof(zero),
                         val, sizeof(val));
}

static int repo_add_one(VtyVault *v, uint8_t type,
                        const uint8_t *name, size_t name_len,
                        const uint8_t *data, size_t data_len,
                        uint64_t forced_id, uint64_t created_time,
                        uint64_t *out_id)
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

    rc = get_next_id(v, &next_id);
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

    rc = vty_record_seal(mdek, module_uuid, id, v->header.epoch,
                         name != NULL ? name : (const uint8_t *)empty, name_len,
                         plain, data_len + 1u, &sealed, &sealed_len);
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
    raw.flags = 0u;
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
    rc = leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) goto fail;

    record_key(key, id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf_buf, sizeof(leaf_buf));
    if (rc != VTY_OK) goto fail;

    index_key(ikey, name_index, id);
    rc = vty_store_put(v->store, VTY_KS_NAME, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto fail;
    index_key(ikey, type_token, id);
    rc = vty_store_put(v->store, VTY_KS_TYPE, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto fail;

    /* 分配器与记录同一次提交：崩溃时不会出现“ID 已用但记录不存在”
     * 或“记录存在但计数回退”。 */
    rc = put_next_id(v, id + 1u);
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

int vty_repo_init_allocator(VtyVault *v)
{
    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    return put_next_id(v, 1u);
}

int vty_repo_next_id(VtyVault *v, uint64_t *out)
{
    int rc;

    if (v == NULL || out == NULL) return VTY_E_INVALID;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    return get_next_id(v, out);
}

int vty_repo_set_next_id(VtyVault *v, uint64_t next)
{
    int rc;

    if (v == NULL || next == 0u) return VTY_E_INVALID;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    return put_next_id(v, next);
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

    rc = vty_record_open(mdek, leaf->module_uuid, v->header.epoch,
                         payload, payload_len, &name, &name_len,
                         &data, &data_len);
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

    rc = vty_record_open_name(mdek, leaf->module_uuid, v->header.epoch,
                              payload, payload_len, name, name_len);
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
    rc = get_leaf_raw(v, id, &leaf, &found);
    if (rc != VTY_OK) return rc;
    if (!found || (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;
    return vty_repo_read(v, &leaf, out);
}

static int delete_one(VtyVault *v, const VtyRepoLeaf *leaf)
{
    RepoLeafRaw raw;
    uint8_t leaf_buf[VTY_REPO_LEAF_BYTES];
    uint8_t key[8];
    uint8_t ikey[VTY_HASH_BYTES + 8u];
    int rc;

    memset(&raw, 0, sizeof(raw));
    raw.record_id = leaf->record_id;
    memcpy(raw.module_uuid, leaf->module_uuid, VTY_UUID_BYTES);
    raw.flags = (uint8_t)(leaf->flags | VTY_REPO_FLAG_TOMBSTONE);
    memcpy(raw.name_index, leaf->name_index, VTY_HASH_BYTES);
    memcpy(raw.type_token, leaf->type_token, VTY_HASH_BYTES);
    raw.created_time = leaf->created_time;
    raw.data_offset = leaf->data_offset;
    raw.data_len = leaf->data_len;
    raw.plain_size = leaf->plain_size;
    memcpy(raw.data_hash, leaf->data_hash, VTY_HASH_BYTES);
    rc = leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) return rc;

    record_key(key, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf_buf, sizeof(leaf_buf));
    if (rc != VTY_OK) return rc;

    index_key(ikey, leaf->name_index, leaf->record_id);
    rc = vty_store_delete(v->store, VTY_KS_NAME, ikey, sizeof(ikey));
    if (rc != VTY_OK) return rc;
    index_key(ikey, leaf->type_token, leaf->record_id);
    return vty_store_delete(v->store, VTY_KS_TYPE, ikey, sizeof(ikey));
}

int vty_repo_delete(VtyVault *v, uint64_t id)
{
    VtyStoreCheckpoint cp;
    VtyRepoLeaf leaf;
    int found = 0;
    int rc;

    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    if (id == 0u) return VTY_E_INVALID;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;
    rc = get_leaf_raw(v, id, &leaf, &found);
    if (rc != VTY_OK) return rc;
    if (!found || (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;
    rc = repo_require_leaf_module(v, &leaf);
    if (rc != VTY_OK) return rc;

    rc = delete_one(v, &leaf);
    if (rc != VTY_OK) goto fail;
    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    return VTY_OK;

fail:
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_delete_many(VtyVault *v, const uint64_t *ids, size_t count)
{
    VtyStoreCheckpoint cp;
    VtyRepoLeaf *leaves = NULL;
    size_t i;
    int rc;

    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    if (ids == NULL && count != 0) return VTY_E_INVALID;
    if (count == 0) return VTY_OK;

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;
    leaves = (VtyRepoLeaf *)vty_alloc(sizeof(VtyRepoLeaf) * count);
    if (leaves == NULL) return VTY_E_RESOURCE;

    /* 先全量探测：任一不存在整体 NOTFOUND（零副作用）。 */
    for (i = 0; i < count; i++) {
        int found = 0;
        if (ids[i] == 0u) { rc = VTY_E_INVALID; goto fail; }
        rc = get_leaf_raw(v, ids[i], &leaves[i], &found);
        if (rc != VTY_OK) goto fail;
        if (!found || (leaves[i].flags & VTY_REPO_FLAG_TOMBSTONE) != 0) {
            rc = VTY_E_INVALID;
            goto fail;
        }
        rc = repo_require_leaf_module(v, &leaves[i]);
        if (rc != VTY_OK) goto fail;
    }

    for (i = 0; i < count; i++) {
        rc = delete_one(v, &leaves[i]);
        if (rc != VTY_OK) goto fail;
    }

    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;
    vty_free(leaves, sizeof(VtyRepoLeaf) * count);
    return VTY_OK;

fail:
    if (leaves != NULL) vty_free(leaves, sizeof(VtyRepoLeaf) * count);
    vty_store_restore(v->store, &cp);
    return rc;
}

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

static int chunk_leaf_encode(const VtyRepoChunkEntry *e,
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

static int chunk_leaf_decode(const uint8_t *in, size_t len,
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

static void chunk_key(uint8_t out[VTY_UUID_BYTES + 4u],
                      const uint8_t file_uuid[VTY_UUID_BYTES], uint32_t seq)
{
    memcpy(out, file_uuid, VTY_UUID_BYTES);
    be32(out + VTY_UUID_BYTES, seq);
}

static int file_get_raw(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
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

    chunk_key(key, file_uuid, seq);
    rc = vty_store_get(v->store, VTY_KS_CHUNK, key, sizeof(key), &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen == 1u && val[0] == VTY_STORE_TOMBSTONE_BYTE) {
        vty_free(val, vlen);
        return VTY_E_INVALID;
    }
    memset(out, 0, sizeof(*out));
    rc = chunk_leaf_decode(val, vlen, out);
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
    return file_get_raw(v, file_uuid, out);
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
    rc = file_get_raw(v, file_uuid, &f);
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
    rc = chunk_leaf_encode(&e, leaf);
    if (rc != VTY_OK) goto fail;
    chunk_key(key, file_uuid, seq);
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
    rc = file_get_raw(v, file_uuid, &f);
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
    rc = file_get_raw(v, file_uuid, &f);
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
            seq = get_be32(k + VTY_UUID_BYTES);
            memset(&e, 0, sizeof(e));
            rc = chunk_leaf_decode(val, vlen, &e);
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
        else if (get_be64(k) == 0u) {
            /* 分配器条目：8 字节 next_id，不是记录叶 */
            if (vlen != 8u) rc = VTY_E_CORRUPT;
        } else if (vlen != VTY_REPO_LEAF_BYTES) {
            rc = VTY_E_CORRUPT;
        } else {
            rc = leaf_decode(val, vlen, &leaf);
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
                if (out_id != NULL) *out_id = get_be64(k + VTY_HASH_BYTES);
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
        be64(start + VTY_HASH_BYTES, after_id + 1u);
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
            uint64_t id = get_be64(k + VTY_HASH_BYTES);
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
    if (start_id != 0u) be64(start, start_id);
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
            uint64_t id = get_be64(k);
            if (id == 0u) { rc = VTY_OK; goto next_out; }   /* 分配器 */
            if (id < it->start_id) { rc = VTY_OK; goto next_out; }
            if (vlen != VTY_REPO_LEAF_BYTES) { rc = VTY_E_CORRUPT; goto next_out; }
            rc = leaf_decode(val, vlen, leaf);
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

    rc = vty_record_open(mdek, leaf->module_uuid, v->header.epoch,
                         payload, payload_len, &name, &name_len,
                         &data, &data_len);
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
        if (rc == VTY_OK && !done && klen == 8u && get_be64(k) != 0u &&
            vlen == VTY_REPO_LEAF_BYTES) {
            rc = leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0 &&
                memcmp(leaf.module_uuid, v->modules[index].uuid,
                       VTY_UUID_BYTES) == 0) {
                total += (uint64_t)leaf.data_len + VTY_REPO_LEAF_BYTES +
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
                rc = chunk_leaf_decode(val, vlen, &e);
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
 */
static int rewrap_content_envelope(const uint8_t old_mdek[VTY_KEY_BYTES],
                                   const uint8_t new_mdek[VTY_KEY_BYTES],
                                   uint64_t epoch,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len,
                                   int *rewrapped)
{
    const size_t prefix = VTY_UUID_BYTES + 4u + 4u + 4u;
    const size_t min_len = prefix + VTY_NONCE_BYTES + VTY_TAG_BYTES;
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint32_t seq, total, pt_len;
    uint8_t *pt = NULL;
    size_t pt_bytes = 0;
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

    rc = vty_chunk_open(old_mdek, file_uuid, seq, total, epoch, in, in_len,
                        &pt, &pt_bytes);
    if (rc == VTY_E_AEAD || rc == VTY_E_KEY_INVALID || rc == VTY_E_INVALID) {
        return VTY_OK; /* 不是分片信封：按普通记录载荷处理 */
    }
    if (rc != VTY_OK) return rc; /* 资源/IO 故障：不得静默跳过换封 */

    rc = vty_chunk_seal(new_mdek, file_uuid, seq, total, epoch, pt, pt_bytes,
                        out, out_len);
    vty_secure_zero(pt, pt_bytes);
    vty_free(pt, pt_bytes != 0 ? pt_bytes : 1u);
    if (rc != VTY_OK) return rc;
    *rewrapped = 1;
    return VTY_OK;
}

/* 记录重写：保留 record_id/created_time/flags/plain_size，换 MDEK 与
 * 名称/类型盲索引；旧索引键必须存在，缺失即说明库已不一致。 */
static int rekey_one_record(VtyVault *v, const VtyRepoLeaf *leaf,
                            const uint8_t old_mdek[VTY_KEY_BYTES],
                            const uint8_t new_mdek[VTY_KEY_BYTES],
                            const uint8_t module_uuid[VTY_UUID_BYTES],
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

    /* 内容模块记录：内层分片信封必须随 MDEK 一并换封。 */
    if (rewrap_content && !repo_is_system_type(rec.type)) {
        rc = rewrap_content_envelope(old_mdek, new_mdek, v->header.epoch,
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

    rc = vty_record_seal(seal_key, seal_uuid, leaf->record_id,
                         v->header.epoch, rec.name, rec.name_len,
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
    raw.flags = leaf->flags;
    memcpy(raw.name_index, name_index, VTY_HASH_BYTES);
    memcpy(raw.type_token, type_token, VTY_HASH_BYTES);
    raw.created_time = leaf->created_time;
    raw.data_offset = loc.offset;
    raw.data_len = loc.total_len;
    raw.plain_size = leaf->plain_size;
    memcpy(raw.data_hash, loc.hash, VTY_HASH_BYTES);
    rc = leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) goto out;

    index_key(ikey, leaf->name_index, leaf->record_id);
    rc = index_key_expect_empty(v, VTY_KS_NAME, ikey);
    if (rc != VTY_OK) goto out;
    rc = vty_store_delete(v->store, VTY_KS_NAME, ikey, sizeof(ikey));
    if (rc != VTY_OK) goto out;
    index_key(ikey, leaf->type_token, leaf->record_id);
    rc = index_key_expect_empty(v, VTY_KS_TYPE, ikey);
    if (rc != VTY_OK) goto out;
    rc = vty_store_delete(v->store, VTY_KS_TYPE, ikey, sizeof(ikey));
    if (rc != VTY_OK) goto out;

    index_key(ikey, name_index, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_NAME, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto out;
    index_key(ikey, type_token, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_TYPE, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) goto out;

    record_key(key, leaf->record_id);
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
            rc = file_get_raw(v, cur_file, &f);
            if (rc != VTY_OK) goto item_out;
            cur_total = f.total;
            seen = 0;
            have_file = 1;
        }
        seq = get_be32(k + VTY_UUID_BYTES);
        if (seq >= cur_total) { rc = VTY_E_CORRUPT; goto item_out; }
        rc = chunk_leaf_decode(val, vlen, &e);
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
        rc = chunk_leaf_encode(&e, leaf);
        if (rc != VTY_OK) goto item_out;
        chunk_key(key, cur_file, seq);
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
        rc = rekey_one_record(v, &leaf, old_mdek, new_mdek, module_uuid,
                              index == 0u || index == 2u);
        if (rc != VTY_OK) break;
    }
    vty_repo_iter_close(it);
    if (rc != VTY_OK) return rc;

    if (index == 2u) rc = rekey_chunks(v, old_mdek, new_mdek);
    return rc;
}

/* 删除模块：记录叶/名称/类型索引写墓碑；fileverthys 额外清空文件/分片叶。
 * 与普通删除共用 delete_one，保持索引与叶一致。 */
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
            rc = leaf_decode(val, vlen, &leaf);
            if (rc == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0 &&
                memcmp(leaf.module_uuid, module_uuid, VTY_UUID_BYTES) == 0) {
                rc = delete_one(v, &leaf);
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
