/*
 * verthys_api_container.c — 记录 CRUD/校验/改密的 API 适配
 *
 * 所有函数要求调用方已持有 api_mutex（公共入口负责），内部不再加锁；
 * GetRecord 的借用指针缓存规则：下次查询/写/Lock 前有效。
 */
#include "verthys_api_container.h"
#include "verthys_api_utils.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_module.h"
#include "vty_tpm_pcr.h"
#include "vty_chunk.h"
#include "vty_rotate.h"
#include "vty_lockout.h"

#include <stdlib.h>
#include <string.h>

VerthysResult verthys_api_container_map(int vty_rc)
{
    switch (vty_rc) {
    case VTY_OK:               return VERTHYS_OK;
    case VTY_E_INVALID:        return VERTHYS_ERR_NOTFOUND;
    case VTY_E_VERSION:        return VERTHYS_ERR_FORMAT;
    case VTY_E_SLOT_UNKNOWN:   return VERTHYS_ERR_FORMAT;
    case VTY_E_SLOT_MISSING:   return VERTHYS_ERR_FORMAT;
    case VTY_E_KDF_WEAK:       return VERTHYS_ERR_FORMAT;
    case VTY_E_KEY_INVALID:    return VERTHYS_ERR_AUTH;
    case VTY_E_AEAD:           return VERTHYS_ERR_AUTH;
    case VTY_E_POLICY:         return VERTHYS_ERR_POLICY;
    case VTY_E_TPM:            return VERTHYS_ERR_TPM;
    case VTY_E_LOCKED:         return VERTHYS_ERR_RATE;
    case VTY_E_CORRUPT:        return VERTHYS_ERR_CORRUPT;
    case VTY_E_ROLLBACK:       return VERTHYS_ERR_ROLLBACK;
    case VTY_E_IO:             return VERTHYS_ERR_IO;
    case VTY_E_RESOURCE:       return VERTHYS_ERR_RESOURCE_LIMIT;
    case VTY_E_KEYFILE_REQUIRED: return VERTHYS_ERR_KEYFILE_REQUIRED;
    case VTY_E_KEYFILE_INVALID:  return VERTHYS_ERR_KEYFILE_INVALID;
    case VTY_E_EXISTS:         return VERTHYS_ERR_EXISTS;
    case VTY_E_ROTATE_PENDING: return VERTHYS_ERR_ROTATE_PENDING;
    case VTY_E_MODULE_LOCKED:  return VERTHYS_ERR_MODULE_LOCKED;
    case VTY_E_NO_SPACE:       return VERTHYS_ERR_NO_SPACE;
    case VTY_E_VERIFY:         return VERTHYS_ERR_VERIFY;
    default:                   return VERTHYS_ERR_INVALID;
    }
}

static int vault_ready(struct VerthysContext *ctx, VtyVault **out)
{
    if (ctx == NULL) return 0;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER || ctx->vault == NULL) return 0;
    if (!ctx->vault->unlocked || ctx->vault->store == NULL) return 0;
    *out = ctx->vault;
    return 1;
}

static uint8_t *dup_bytes(const uint8_t *src, size_t n)
{
    uint8_t *p;

    if (n == 0) return NULL;
    p = (uint8_t *)malloc(n);
    if (p != NULL) memcpy(p, src, n);
    return p;
}

VerthysResult verthys_api_container_add(struct VerthysContext *ctx,
                                 const VerthysRecord *record,
                                 uint64_t *out_id)
{
    VtyVault *v;
    int rc;

    if (record == NULL || out_id == NULL) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    rc = vty_repo_add(v, (uint8_t)record->type,
                      (const uint8_t *)record->name, record->name_len,
                      record->data, record->data_len, out_id);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_add_many(struct VerthysContext *ctx,
                                      const VerthysRecord *records,
                                      uint32_t count,
                                      uint64_t *out_ids)
{
    VtyVault *v;
    VtyRepoInput *in;
    uint32_t i;
    int rc;

    if (records == NULL || out_ids == NULL) return VERTHYS_ERR_INVALID;
    if (count == 0u || count > VERTHYS_ADD_RECORDS_MAX) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    in = (VtyRepoInput *)calloc((size_t)count, sizeof(*in));
    if (in == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    /* out_ids 先归零：批量失败时不向调用方暴露部分分配结果。 */
    memset(out_ids, 0, (size_t)count * sizeof(uint64_t));
    for (i = 0u; i < count; i++) {
        in[i].type = (uint8_t)records[i].type;
        in[i].name = (const uint8_t *)records[i].name;
        in[i].name_len = records[i].name_len;
        in[i].data = records[i].data;
        in[i].data_len = records[i].data_len;
    }

    rc = vty_repo_add_many(v, in, (size_t)count, out_ids);
    free(in);
    if (rc != VTY_OK) {
        memset(out_ids, 0, (size_t)count * sizeof(uint64_t));
    }
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_get(struct VerthysContext *ctx, uint64_t id,
                                 VerthysRecord *out_record)
{
    VtyVault *v;
    VtyRepoRecord rec;
    uint8_t *name = NULL;
    uint8_t *data = NULL;
    int rc;

    if (out_record == NULL) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    memset(&rec, 0, sizeof(rec));
    rc = vty_repo_get(v, id, &rec);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    /* 仓库返回 vty_alloc 缓冲；借用缓存统一用 malloc/free，必须复制
     * 后再按各自分配器释放，避免跨分配器 free。 */
    name = dup_bytes(rec.name, rec.name_len);
    data = dup_bytes(rec.data, rec.data_len);
    if ((rec.name_len != 0 && name == NULL) ||
        (rec.data_len != 0 && data == NULL)) {
        free(name);
        free(data);
        if (rec.name != NULL) vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
        return VERTHYS_ERR_INTERNAL;
    }
    if (rec.name != NULL) vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);

    ctx_free_getrecord_cache(ctx);
    ctx->last_getrecord_name = name;
    ctx->last_getrecord_name_len = rec.name_len;
    ctx->last_getrecord_data = data;
    ctx->last_getrecord_data_size = rec.data_len;

    out_record->type = (VerthysRecordType)rec.type;
    out_record->name = (const char *)name;
    out_record->name_len = rec.name_len;
    out_record->data = data;
    out_record->data_len = rec.data_len;
    return VERTHYS_OK;
}

VerthysResult verthys_api_container_delete(struct VerthysContext *ctx, uint64_t id)
{
    VtyVault *v;
    int rc;

    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;
    rc = vty_repo_delete(v, id);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_delete_many(struct VerthysContext *ctx,
                                         const uint64_t *ids, size_t count)
{
    VtyVault *v;
    int rc;

    if (ids == NULL && count != 0) return VERTHYS_ERR_INVALID;
    if (count == 0) return VERTHYS_OK;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;
    rc = vty_repo_delete_many(v, ids, count);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_count(struct VerthysContext *ctx,
                                   uint64_t *out_count)
{
    VtyVault *v;
    int rc;

    if (out_count == NULL) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;
    rc = vty_repo_count(v, out_count);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_verify(struct VerthysContext *ctx,
                                    uint64_t *out_failed_lids,
                                    uint64_t max_failed,
                                    uint64_t *out_failed_count)
{
    VtyVault *v;
    VtyRepoIter *it = NULL;
    uint64_t failed = 0;
    int rc;

    if (out_failed_count == NULL) return VERTHYS_ERR_INVALID;
    *out_failed_count = 0;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    /* 目录结构/DataRoot 级损坏无法逐条报告，整体拒绝（与既有迭代器
     * 中途损坏同纪律）。记录级解密失败记入 failed_lids 并继续。 */
    rc = vty_store_verify(v->store);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    rc = vty_repo_iter_open(v, 0, &it);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    for (;;) {
        VtyRepoLeaf leaf;
        VtyRepoRecord rec;
        int done = 0;

        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK) break;
        if (done) break;

        memset(&rec, 0, sizeof(rec));
        if (vty_repo_read(v, &leaf, &rec) != VTY_OK) {
            if (out_failed_lids != NULL && failed < max_failed) {
                out_failed_lids[failed] = leaf.record_id;
            }
            failed++;
            continue;
        }
        if (rec.name != NULL) {
            vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        }
        if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
    }

    vty_repo_iter_close(it);
    if (rc != VTY_OK) return verthys_api_container_map(rc);
    *out_failed_count = failed;
    return VERTHYS_OK;
}

/* 公共入口接受显式长度；本层按 NUL 终结串取口令，长度不符时复制
 * （不把调用方内存当作 C 字符串直接读取）。 */
static char *pw_copy(const char *pw, size_t len)
{
    char *copy;

    if (pw == NULL || len == 0) return NULL;
    copy = (char *)malloc(len + 1u);
    if (copy == NULL) return NULL;
    memcpy(copy, pw, len);
    copy[len] = '\0';
    return copy;
}

VerthysResult verthys_api_container_change_password(struct VerthysContext *ctx,
                                             const char *old_pw, size_t old_len,
                                             const char *new_pw, size_t new_len)
{
    VtyVault *v;
    char *old_copy = NULL;
    char *new_copy = NULL;
    int rc;

    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    old_copy = pw_copy(old_pw, old_len);
    new_copy = pw_copy(new_pw, new_len);
    if (old_copy == NULL || new_copy == NULL) {
        free(old_copy);
        free(new_copy);
        return VERTHYS_ERR_INVALID;
    }

    /* 旧口令先验证：会话已解锁并不代表调用方知道当前口令。 */
    rc = vty_vault_verify_password(v, old_copy);
    if (rc != VTY_OK) {
        verthys_secure_zero(old_copy, old_len);
        verthys_secure_zero(new_copy, new_len);
        free(old_copy);
        free(new_copy);
        return verthys_api_container_map(rc);
    }

    /* 改密只轮换口令/设备槽；恢复码是独立凭据，由 RecoveryRotate 管理。 */
    rc = vty_vault_rotate_password(v, new_copy);
    verthys_secure_zero(old_copy, old_len);
    verthys_secure_zero(new_copy, new_len);
    free(old_copy);
    free(new_copy);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_flush(struct VerthysContext *ctx)
{
    VtyVault *v;
    int rc;

    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    /* Flush 的持久化对象是“尚无记录变更但目录可能脏”的会话；仓库
     * 每次写已提交，此处再走一次 DataRoot/元数据保存保证幂等落盘。 */
    rc = vty_vault_save(v);
    return verthys_api_container_map(rc);
}

/* ------------------------------------------------------------------ *
 * PCR 策略公共入口                                                     *
 * ------------------------------------------------------------------ */

static struct VerthysContext *module_ctx(VerthysHandle handle);
static void module_lock_ctx(struct VerthysContext *ctx);
static void module_unlock_ctx(struct VerthysContext *ctx);

/* 恢复会话已由恢复码根认证；普通会话必须提供当前恢复码。 */
static int pcr_recovery_ok(const struct VerthysContext *ctx,
                           const char *recovery_code)
{
    if (ctx == NULL || ctx->vault == NULL) return 0;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        return strlen(recovery_code) <= 256u;
    }
    return ctx->vault->recovery_mode;
}

VerthysResult Verthys_V4PcrStatus(VerthysHandle handle,
                                  uint32_t *out_enabled,
                                  uint32_t *out_select)
{
    struct VerthysContext *ctx = module_ctx(handle);
    uint32_t enabled = 0;
    uint32_t select = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (out_enabled == NULL || out_select == NULL) return VERTHYS_ERR_INVALID;

    module_lock_ctx(ctx);
    rc = vty_vault_pcr_info(ctx->vault, &enabled, &select);
    module_unlock_ctx(ctx);

    if (rc == VTY_OK) {
        *out_enabled = enabled;
        *out_select = select;
    }
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4PcrEnable(VerthysHandle handle,
                                  uint32_t pcr_select,
                                  const char *recovery_code)
{
    struct VerthysContext *ctx = module_ctx(handle);
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!pcr_recovery_ok(ctx, recovery_code)) return VERTHYS_ERR_INVALID;
    /* 内部 map 把 E_INVALID 归为 NOTFOUND；位图非法必须在公共入口
     * 先返回 INVALID，避免调用方误判为记录不存在。 */
    if (vty_tpm_pcr_select_valid(pcr_select) != VTY_OK) {
        return VERTHYS_ERR_INVALID;
    }

    module_lock_ctx(ctx);
    rc = VTY_OK;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(ctx->vault, recovery_code);
    }
    if (rc == VTY_OK) {
        rc = vty_vault_pcr_enable(ctx->vault, pcr_select);
    }
    module_unlock_ctx(ctx);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4PcrDisable(VerthysHandle handle,
                                   const char *recovery_code)
{
    struct VerthysContext *ctx = module_ctx(handle);
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!pcr_recovery_ok(ctx, recovery_code)) return VERTHYS_ERR_INVALID;

    module_lock_ctx(ctx);
    rc = VTY_OK;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(ctx->vault, recovery_code);
    }
    if (rc == VTY_OK) {
        rc = vty_vault_pcr_disable(ctx->vault);
    }
    module_unlock_ctx(ctx);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4PcrReseal(VerthysHandle handle,
                                  const char *recovery_code)
{
    struct VerthysContext *ctx = module_ctx(handle);
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!pcr_recovery_ok(ctx, recovery_code)) return VERTHYS_ERR_INVALID;

    module_lock_ctx(ctx);
    rc = VTY_OK;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(ctx->vault, recovery_code);
    }
    if (rc == VTY_OK) {
        rc = vty_vault_pcr_reseal(ctx->vault);
    }
    module_unlock_ctx(ctx);
    return verthys_api_container_map(rc);
}

/* ------------------------------------------------------------------ *
 * keyfile 因子公共入口                                           *
 * ------------------------------------------------------------------ */

VerthysResult Verthys_V4KeyfileEnable(VerthysHandle handle,
                                      const char *password,
                                      size_t password_len,
                                      const char *new_keyfile_path)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (password == NULL || password_len == 0 || new_keyfile_path == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_vault_keyfile_enable_file(ctx->vault, pw, new_keyfile_path);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4KeyfileDisable(VerthysHandle handle,
                                       const char *password,
                                       size_t password_len,
                                       const char *keyfile_path)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    /* keyfile_path 允许为空串：仅恢复码会话可用（keyfile 丢失逃生），
     * 由 C 层按会话模式判定；普通会话空路径返回 KEYFILE_REQUIRED。 */
    if (password == NULL || password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_vault_keyfile_disable(ctx->vault, pw,
                                   (keyfile_path != NULL && keyfile_path[0] != '\0')
                                       ? keyfile_path : NULL);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4KeyfileStatus(VerthysHandle handle,
                                      uint32_t *out_enabled,
                                      uint32_t *out_recovery_mode)
{
    struct VerthysContext *ctx = module_ctx(handle);

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (out_enabled == NULL || out_recovery_mode == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    module_lock_ctx(ctx);
    *out_enabled = (ctx->vault->header.flags & VTY_FLAG_KEYFILE) != 0 ? 1u : 0u;
    *out_recovery_mode = ctx->vault->recovery_mode ? 1u : 0u;
    module_unlock_ctx(ctx);
    return VERTHYS_OK;
}

VerthysResult Verthys_V4ResealDevice(VerthysHandle handle,
                                     const char *password,
                                     size_t password_len,
                                     const char *keyfile_path)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (password_len > 512u) return VERTHYS_ERR_INVALID;
    if (keyfile_path != NULL && strlen(keyfile_path) > 1024u) {
        return VERTHYS_ERR_INVALID;
    }

    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_vault_reseal_device_file(
        ctx->vault, pw,
        (keyfile_path != NULL && keyfile_path[0] != '\0') ? keyfile_path : NULL);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

/* ------------------------------------------------------------------ *
 * 内容分片 / 清单公共入口                                              *
 * ------------------------------------------------------------------ */

static int content_out_ok(const uint8_t *out, size_t out_cap, size_t need)
{
    if (out == NULL || out_cap < need) return VTY_E_RESOURCE;
    return VTY_OK;
}

static int content_args_ok(uint32_t module_id, const uint8_t file_uuid[16],
                           uint32_t seq, uint32_t total)
{
    static const uint8_t zero_uuid[16] = { 0 };
    uint32_t i;
    uint8_t acc = 0;

    if (module_id >= VTY_MODULE_COUNT) return 0;
    if (file_uuid == NULL || total == 0 || seq >= total) return 0;
    for (i = 0; i < 16u; i++) acc |= file_uuid[i];
    return acc != 0 && memcmp(file_uuid, zero_uuid, 16) != 0 ? 1 : 0;
}

VerthysResult Verthys_V4ChunkSeal(VerthysHandle handle,
                                  uint32_t module_id,
                                  const uint8_t file_uuid[16],
                                  uint32_t seq,
                                  uint32_t total,
                                  const uint8_t *plain,
                                  size_t plain_len,
                                  uint8_t *out,
                                  size_t out_cap,
                                  size_t *out_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (out_len == NULL || !content_args_ok(module_id, file_uuid, seq, total)) {
        return VERTHYS_ERR_INVALID;
    }
    if (plain_len > VTY_CHUNK_MAX_PT || (plain_len != 0 && plain == NULL)) {
        return VERTHYS_ERR_INVALID;
    }
    *out_len = 0;
    memset(mdek, 0, sizeof(mdek));

    module_lock_ctx(ctx);
    rc = vty_vault_module_key_index(ctx->vault, module_id, mdek);
    if (rc == VTY_OK) {
        rc = vty_chunk_seal(mdek, file_uuid, seq, total,
                            ctx->vault->header.epoch, plain, plain_len,
                            &ct, &ct_len);
    }
    if (rc == VTY_OK) {
        *out_len = ct_len;
        rc = content_out_ok(out, out_cap, ct_len);
        if (rc == VTY_OK) memcpy(out, ct, ct_len);
    }
    module_unlock_ctx(ctx);

    if (ct != NULL) {
        vty_secure_zero(ct, ct_len);
        vty_free(ct, ct_len);
    }
    vty_secure_zero(mdek, sizeof(mdek));
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ChunkOpen(VerthysHandle handle,
                                  uint32_t module_id,
                                  const uint8_t file_uuid[16],
                                  uint32_t seq,
                                  uint32_t total,
                                  const uint8_t *in,
                                  size_t in_len,
                                  uint8_t *out,
                                  size_t out_cap,
                                  size_t *out_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (out_len == NULL || in == NULL || in_len == 0 ||
        !content_args_ok(module_id, file_uuid, seq, total)) {
        return VERTHYS_ERR_INVALID;
    }
    *out_len = 0;
    memset(mdek, 0, sizeof(mdek));

    module_lock_ctx(ctx);
    rc = vty_vault_module_key_index(ctx->vault, module_id, mdek);
    if (rc == VTY_OK) {
        rc = vty_chunk_open(mdek, file_uuid, seq, total,
                            ctx->vault->header.epoch, in, in_len, &pt, &pt_len);
    }
    if (rc == VTY_OK) {
        *out_len = pt_len;
        rc = content_out_ok(out, out_cap, pt_len);
        if (rc == VTY_OK) memcpy(out, pt, pt_len);
    }
    module_unlock_ctx(ctx);

    if (pt != NULL) {
        vty_secure_zero(pt, pt_len);
        vty_free(pt, pt_len);
    }
    vty_secure_zero(mdek, sizeof(mdek));
    return verthys_api_container_map(rc);
}

/* ------------------------------------------------------------------ *
 * 模块 M1 公共入口                                                      *
 * ------------------------------------------------------------------ */

static struct VerthysContext *module_ctx(VerthysHandle handle)
{
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    if (ctx == NULL) return NULL;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return NULL;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER || ctx->vault == NULL) return NULL;
    if (!ctx->vault->unlocked) return NULL;
    return ctx;
}

static void module_lock_ctx(struct VerthysContext *ctx)
{
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#else
    (void)ctx;
#endif
}

static void module_unlock_ctx(struct VerthysContext *ctx)
{
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#else
    (void)ctx;
#endif
}

static int recovery_arg_ok(const char *text, int required)
{
    if (text == NULL || text[0] == '\0') return required ? 0 : 1;
    return strlen(text) <= 256u;
}

static int module_id_ok(uint32_t module_id)
{
    return module_id < VTY_MODULE_COUNT;
}

VerthysResult Verthys_V4ModuleEnable(VerthysHandle handle,
                                     uint32_t module_id,
                                     const char *password,
                                     size_t password_len,
                                     const char *recovery_code)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (!recovery_arg_ok(recovery_code, 0)) return VERTHYS_ERR_INVALID;
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_module_enable(ctx->vault, module_id, pw, recovery_code);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleUnlock(VerthysHandle handle,
                                     uint32_t module_id,
                                     const char *password,
                                     size_t password_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_module_unlock(ctx->vault, module_id, pw);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleLock(VerthysHandle handle, uint32_t module_id)
{
    struct VerthysContext *ctx = module_ctx(handle);

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (module_id != VERTHYS_MODULE_ALL && module_id >= VTY_MODULE_COUNT) {
        return VERTHYS_ERR_INVALID;
    }
    module_lock_ctx(ctx);
    vty_module_lock(ctx->vault, module_id);
    module_unlock_ctx(ctx);
    return VERTHYS_OK;
}

VerthysResult Verthys_V4ModuleRotatePassword(VerthysHandle handle,
                                             uint32_t module_id,
                                             const char *old_password,
                                             size_t old_len,
                                             const char *new_password,
                                             size_t new_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *old_pw = NULL;
    char *new_pw = NULL;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (old_password == NULL || old_len == 0 ||
        new_password == NULL || new_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    old_pw = pw_copy(old_password, old_len);
    new_pw = pw_copy(new_password, new_len);
    if (old_pw == NULL || new_pw == NULL) {
        if (old_pw != NULL) { verthys_secure_zero(old_pw, old_len); free(old_pw); }
        if (new_pw != NULL) { verthys_secure_zero(new_pw, new_len); free(new_pw); }
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }

    module_lock_ctx(ctx);
    rc = vty_module_rotate_password(ctx->vault, module_id, old_pw, new_pw);
    module_unlock_ctx(ctx);

    verthys_secure_zero(old_pw, old_len);
    verthys_secure_zero(new_pw, new_len);
    free(old_pw);
    free(new_pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleDisable(VerthysHandle handle,
                                      uint32_t module_id,
                                      const char *password,
                                      size_t password_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_module_disable(ctx->vault, module_id, pw);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleDelete(VerthysHandle handle,
                                     uint32_t module_id,
                                     const char *password,
                                     size_t password_len,
                                     const char *confirm)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw = NULL;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (confirm == NULL || strcmp(confirm, "DELETE") != 0) {
        return VERTHYS_ERR_INVALID;
    }
    if (password != NULL && password_len != 0) {
        pw = pw_copy(password, password_len);
        if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    } else if (password_len != 0) {
        return VERTHYS_ERR_INVALID;
    }

    module_lock_ctx(ctx);
    rc = vty_module_delete(ctx->vault, module_id, pw, confirm);
    module_unlock_ctx(ctx);

    if (pw != NULL) {
        verthys_secure_zero(pw, password_len);
        free(pw);
    }
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleBindRecovery(VerthysHandle handle,
                                           uint32_t module_id,
                                           const char *password,
                                           size_t password_len,
                                           const char *recovery_code)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (!recovery_arg_ok(recovery_code, 1)) return VERTHYS_ERR_INVALID;
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_module_bind_recovery(ctx->vault, module_id, pw, recovery_code);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleResealDevice(VerthysHandle handle,
                                           uint32_t module_id,
                                           const char *password,
                                           size_t password_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_module_reseal_device(ctx->vault, module_id, pw);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleStatus(VerthysHandle handle,
                                     uint32_t module_id,
                                     VerthysModuleStatus *out_status)
{
    struct VerthysContext *ctx = module_ctx(handle);
    VtyModuleStatus st;
    int rc;

    if (out_status == NULL) return VERTHYS_ERR_INVALID;
    memset(out_status, 0, sizeof(*out_status));
    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;

    module_lock_ctx(ctx);
    rc = vty_module_status(ctx->vault, module_id, &st);
    module_unlock_ctx(ctx);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    out_status->enabled = st.enabled;
    out_status->unlocked = st.unlocked;
    out_status->has_recovery = st.has_recovery;
    out_status->deleted = st.deleted;
    return VERTHYS_OK;
}

VerthysResult Verthys_V4ModuleLockoutRemaining(VerthysHandle handle,
                                               uint32_t module_id,
                                               uint32_t *out_secs)
{
    struct VerthysContext *ctx;
    int rc;

    if (out_secs == NULL) return VERTHYS_ERR_INVALID;
    *out_secs = 0;
    ctx = module_ctx(handle);
    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;

    rc = vty_lockout_module_remaining_secs(ctx->vault->header.vault_uuid,
                                           module_id, out_secs);
    return (rc == VTY_OK) ? VERTHYS_OK : VERTHYS_ERR_MODULE_LOCKED;
}

VerthysResult Verthys_V4RecoveryRotate(VerthysHandle handle,
                                       const char *password,
                                       size_t password_len,
                                       const char *old_recovery,
                                       char *out_recovery,
                                       size_t out_cap)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (!recovery_arg_ok(old_recovery, 1)) return VERTHYS_ERR_INVALID;
    if (out_recovery == NULL || out_cap < 80u) return VERTHYS_ERR_INVALID;

    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    memset(out_recovery, 0, out_cap);
    module_lock_ctx(ctx);
    rc = vty_vault_recovery_rotate(ctx->vault, pw, old_recovery,
                                   out_recovery, out_cap);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    if (rc != VTY_OK) verthys_secure_zero(out_recovery, out_cap);
    return verthys_api_container_map(rc);
}

/* ------------------------------------------------------------------ *
 * 全库 DEK 轮换公共入口                                             *
 * ------------------------------------------------------------------ */

/* 轮换入口的 E_INVALID 表示参数/路径策略非法，不能沿用记录链路的
 * “INVALID→NOTFOUND”映射，否则调用方会误判为记录不存在。 */
static VerthysResult rotate_map(int rc)
{
    if (rc == VTY_E_INVALID) return VERTHYS_ERR_INVALID;
    return verthys_api_container_map(rc);
}

static void rotate_fill_info(const VtyRotateStats *s, VerthysRotateInfo *out)
{
    memset(out, 0, sizeof(*out));
    if (s == NULL) return;
    out->stage = s->stage;
    out->modules_ready = s->modules_ready;
    out->records = s->records;
    out->files = s->files;
    out->chunks = s->chunks;
    out->bytes = s->bytes;
}

typedef struct {
    VerthysRotateProgress cb;
    void *user;
} RotateCallbackBridge;

static int rotate_progress_bridge(void *user, const VtyRotateStats *stats)
{
    RotateCallbackBridge *b = (RotateCallbackBridge *)user;
    VerthysRotateInfo info;

    if (b == NULL || b->cb == NULL) return 0;
    rotate_fill_info(stats, &info);
    return b->cb(b->user, &info);
}

VerthysResult Verthys_V4RotateBegin(VerthysHandle handle,
                                    const char *new_path,
                                    const char *password,
                                    size_t password_len,
                                    uint32_t flags,
                                    VerthysRotateInfo *out_info)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    VtyRotateJob *job = NULL;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (new_path == NULL || password == NULL || password_len == 0 ||
        out_info == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    memset(out_info, 0, sizeof(*out_info));

    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    if (ctx->rotate != NULL) {
        rc = VTY_E_ROTATE_PENDING;
    } else {
        rc = vty_rotate_begin(ctx->vault, new_path, pw, flags, &job);
        if (rc == VTY_OK) ctx->rotate = job;
    }
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    if (rc != VTY_OK) return rotate_map(rc);

    rotate_fill_info(vty_rotate_stats(job), out_info);
    return VERTHYS_OK;
}

VerthysResult Verthys_V4RotateAttachKeyfile(VerthysHandle handle,
                                            const char *keyfile_path,
                                            const char *password,
                                            size_t password_len)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (keyfile_path == NULL || keyfile_path[0] == '\0' ||
        password == NULL || password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }

    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    rc = vty_vault_attach_keyfile(ctx->vault, keyfile_path, pw);
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return rotate_map(rc);
}

VerthysResult Verthys_V4RotateUnlockModule(VerthysHandle handle,
                                           uint32_t module_id,
                                           const char *password,
                                           size_t password_len,
                                           const char *recovery_code)
{
    struct VerthysContext *ctx = module_ctx(handle);
    char *pw;
    int no_job = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0 ||
        password_len > VTY_MODULE_PASSWORD_MAX) {
        return VERTHYS_ERR_INVALID;
    }
    if (!recovery_arg_ok(recovery_code, 0)) return VERTHYS_ERR_INVALID;

    pw = pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    module_lock_ctx(ctx);
    if (ctx->rotate == NULL) {
        rc = VTY_OK;
        no_job = 1;
    } else {
        rc = vty_rotate_unlock_module(ctx->rotate, module_id, pw,
                                      recovery_code);
    }
    module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}

VerthysResult Verthys_V4RotateRun(VerthysHandle handle,
                                  VerthysRotateProgress progress,
                                  void *user)
{
    struct VerthysContext *ctx = module_ctx(handle);
    RotateCallbackBridge bridge;
    int no_job = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    bridge.cb = progress;
    bridge.user = user;
    module_lock_ctx(ctx);
    if (ctx->rotate == NULL) {
        rc = VTY_OK;
        no_job = 1;
    } else {
        rc = vty_rotate_run(ctx->rotate, rotate_progress_bridge,
                            progress != NULL ? &bridge : NULL);
    }
    module_unlock_ctx(ctx);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}

VerthysResult Verthys_V4RotateCommit(VerthysHandle handle,
                                     uint32_t keep_old)
{
    struct VerthysContext *ctx = module_ctx(handle);
    VtyVault *newv = NULL;
    int no_job = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    module_lock_ctx(ctx);
    if (ctx->rotate == NULL) {
        rc = VTY_OK;
        no_job = 1;
    } else {
        rc = vty_rotate_commit(ctx->rotate, keep_old != 0u ? 1 : 0, &newv);
        if (rc == VTY_OK) {
            ctx->rotate = NULL;
            /* vty_rotate_commit 已清零释放旧库并返回新库：只接管指针，
             * 驻留计数保持 1。禁止在此处再释放旧库或计数 +1。 */
            vault_session_replace_externally_freed(ctx, newv);
        }
    }
    module_unlock_ctx(ctx);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}

VerthysResult Verthys_V4RotateAbort(VerthysHandle handle)
{
    struct VerthysContext *ctx = module_ctx(handle);
    int no_job = 0;
    int rc = VTY_OK;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    module_lock_ctx(ctx);
    if (ctx->rotate == NULL) {
        no_job = 1;
    } else {
        rc = vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    module_unlock_ctx(ctx);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}
