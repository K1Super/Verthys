/*
 * vty_repo_leaf.c — 记录仓库基础契约：就绪与轮转守卫、模块路由、叶编解码、ID 分配器
 */

#include "vty_repo_internal.h"

#ifdef VERTHYS_TEST_HOOKS
static int g_skip_scrub_for_test = 0;

void vty_repo_set_skip_scrub_for_test(int skip)
{
    g_skip_scrub_for_test = skip;
}

int repo_skip_scrub(void)
{
    return g_skip_scrub_for_test;
}
#else
/* 生产构建保留符号但为无操作：测试目标会链接本符号，生产 DLL 不导出它，
 * 也不存在可切换的跳过擦除路径。 */
void vty_repo_set_skip_scrub_for_test(int skip)
{
    (void)skip;
}

int repo_skip_scrub(void)
{
    return 0;
}
#endif


void repo_be64(uint8_t out[8], uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}

uint64_t repo_get_be64(const uint8_t in[8])
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | (uint64_t)in[i];
    return v;
}

void repo_be32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

uint32_t repo_get_be32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

int repo_ready(VtyVault *v)
{
    if (v == NULL || !v->unlocked) return VTY_E_POLICY;
    if (v->store == NULL) return VTY_E_POLICY;
    return VTY_OK;
}

/* 轮换：源库在轮换作业期间只读。所有写入口经本函数拒绝，避免复制
 * 快照之外的变更在提交时被静默丢弃。 */
int repo_write_ready(VtyVault *v)
{
    int rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    return VTY_OK;
}

/* 键空间删除以单字节墓碑表示；所有范围扫描都必须把它当作“已删除”跳过，
 * 否则模块删除/重建后的 rekey、purge、清单重建会把合法墓碑误判为损坏。 */
int repo_value_is_tombstone(size_t vlen, const uint8_t *val)
{
    return vlen == 1u && val != NULL && val[0] == VTY_STORE_TOMBSTONE_BYTE;
}

/* 记录按类型路由到模块；MDEK 取用统一受模块策略位约束。 */
int repo_module_index(VtyVault *v, uint32_t index,
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
int repo_is_system_type(uint8_t type)
{
    return type == 0x10u || type == 0x12u || type == 0x13u;
}

int repo_module_for_type(VtyVault *v, uint8_t type,
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
int repo_require_file_module(VtyVault *v)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc = repo_module_index(v, 2u, uuid, mdek);
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

/* 删除也必须遵守模块策略：锁定模块的记录不可被无声删除。 */
int repo_require_leaf_module(VtyVault *v, const VtyRepoLeaf *leaf)
{
    uint8_t key[VTY_KEY_BYTES];
    int rc;

    memset(key, 0, sizeof(key));
    rc = vty_vault_module_key(v, leaf->module_uuid, key);
    vty_secure_zero(key, sizeof(key));
    return rc;
}

int repo_commit(VtyVault *v)
{
    int rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) return rc;
    return vty_vault_save_meta(v);
}

/* 叶子固定 148B；任何未知标志位都拒绝，避免未来字段被旧代码误解。 */
int repo_leaf_encode(const RepoLeafRaw *r, uint8_t out[VTY_REPO_LEAF_BYTES])
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

int repo_leaf_decode(const uint8_t *in, size_t in_len, VtyRepoLeaf *out)
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

void repo_record_key(uint8_t out[8], uint64_t id)
{
    repo_be64(out, id);
}

void repo_index_key(uint8_t out[VTY_HASH_BYTES + 8u],
                      const uint8_t token[VTY_HASH_BYTES], uint64_t id)
{
    memcpy(out, token, VTY_HASH_BYTES);
    repo_be64(out + VTY_HASH_BYTES, id);
}

int repo_get_leaf_raw(VtyVault *v, uint64_t id, VtyRepoLeaf *out, int *found)
{
    uint8_t key[8];
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    *found = 0;
    repo_record_key(key, id);
    rc = vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key), &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen != VTY_REPO_LEAF_BYTES) {
        vty_free(val, vlen);
        return VTY_E_CORRUPT;
    }
    rc = repo_leaf_decode(val, vlen, out);
    vty_free(val, vlen);
    if (rc != VTY_OK) return rc;
    if (out->record_id != id) return VTY_E_CORRUPT;
    *found = 1;
    return VTY_OK;
}

int repo_get_next_id(VtyVault *v, uint64_t *out)
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

int repo_put_next_id(VtyVault *v, uint64_t next_id)
{
    uint8_t zero[8] = {0};
    uint8_t val[8];

    vty_put_u64(val, next_id);
    return vty_store_put(v->store, VTY_KS_RECORD, zero, sizeof(zero),
                         val, sizeof(val));
}

/* ------------------------------------------------------------------ *
 * 删除擦除：密钥头（RKH）与版本链
 *
 * 每个新格式记录的段载荷最前固定 64B RKH；RKH 包裹随机 RDK，AAD 绑定
 * 模块 UUID / 记录 ID / epoch / 上一版本 ID。删除时只擦 RKH，载荷（含
 * 名称、数据与外层文件分片信封）永久不可解。
 *
 * 旧格式记录没有 RKH，删除时整段零写；旧版本链上的 legacy 目标同样
 * 整段零写。擦除失败保留 SCRUB_PENDING，由解锁维护补偿，删除结论不回滚。
 * ------------------------------------------------------------------ */

int vty_repo_init_allocator(VtyVault *v)
{
    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    return repo_put_next_id(v, 1u);
}

int vty_repo_next_id(VtyVault *v, uint64_t *out)
{
    int rc;

    if (v == NULL || out == NULL) return VTY_E_INVALID;
    rc = repo_ready(v);
    if (rc != VTY_OK) return rc;
    return repo_get_next_id(v, out);
}

int vty_repo_set_next_id(VtyVault *v, uint64_t next)
{
    int rc;

    if (v == NULL || next == 0u) return VTY_E_INVALID;
    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    return repo_put_next_id(v, next);
}
