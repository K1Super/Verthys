/*
 * verthys_api_container_module.c — 模块 M1 管理与模块密钥内容分片
 *
 * 模块生命周期入口统一在锁区内完成；内容分片按模块密钥封装/解封，
 * 明文与中间密钥用后擦除。
 */
#include "verthys_api_container_internal.h"

#include "vty_chunk.h"
#include "vty_lockout.h"
#include "vty_module.h"
#include "vty_util.h"

#include <stdlib.h>
#include <string.h>

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
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

    vty_api_module_lock_ctx(ctx);
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
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
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

    vty_api_module_lock_ctx(ctx);
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
    vty_api_module_unlock_ctx(ctx);

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

VerthysResult Verthys_V4ModuleEnable(VerthysHandle handle,
                                     uint32_t module_id,
                                     const char *password,
                                     size_t password_len,
                                     const char *recovery_code)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (!vty_api_recovery_arg_ok(recovery_code, 0)) return VERTHYS_ERR_INVALID;
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_module_enable(ctx->vault, module_id, pw, recovery_code);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleUnlock(VerthysHandle handle,
                                     uint32_t module_id,
                                     const char *password,
                                     size_t password_len)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    rc = vty_module_unlock(ctx->vault, module_id, pw);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleLock(VerthysHandle handle, uint32_t module_id)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (module_id != VERTHYS_MODULE_ALL && module_id >= VTY_MODULE_COUNT) {
        return VERTHYS_ERR_INVALID;
    }
    vty_api_module_lock_ctx(ctx);
    vty_module_lock(ctx->vault, module_id);
    vty_api_module_unlock_ctx(ctx);
    return VERTHYS_OK;
}

VerthysResult Verthys_V4ModuleRotatePassword(VerthysHandle handle,
                                             uint32_t module_id,
                                             const char *old_password,
                                             size_t old_len,
                                             const char *new_password,
                                             size_t new_len)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *old_pw = NULL;
    char *new_pw = NULL;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (old_password == NULL || old_len == 0 ||
        new_password == NULL || new_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    old_pw = vty_api_pw_copy(old_password, old_len);
    new_pw = vty_api_pw_copy(new_password, new_len);
    if (old_pw == NULL || new_pw == NULL) {
        if (old_pw != NULL) { verthys_secure_zero(old_pw, old_len); free(old_pw); }
        if (new_pw != NULL) { verthys_secure_zero(new_pw, new_len); free(new_pw); }
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(old_pw, old_len);
        verthys_secure_zero(new_pw, new_len);
        free(old_pw);
        free(new_pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_module_rotate_password(ctx->vault, module_id, old_pw, new_pw);
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_module_disable(ctx->vault, module_id, pw);
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw = NULL;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (confirm == NULL || strcmp(confirm, "DELETE") != 0) {
        return VERTHYS_ERR_INVALID;
    }
    if (password != NULL && password_len != 0) {
        pw = vty_api_pw_copy(password, password_len);
        if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    } else if (password_len != 0) {
        return VERTHYS_ERR_INVALID;
    }

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        if (pw != NULL) {
            verthys_secure_zero(pw, password_len);
            free(pw);
        }
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_module_delete(ctx->vault, module_id, pw, confirm);
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (!vty_api_recovery_arg_ok(recovery_code, 1)) return VERTHYS_ERR_INVALID;
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_module_bind_recovery(ctx->vault, module_id, pw, recovery_code);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleResealDevice(VerthysHandle handle,
                                           uint32_t module_id,
                                           const char *password,
                                           size_t password_len)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_module_reseal_device(ctx->vault, module_id, pw);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4ModuleStatus(VerthysHandle handle,
                                     uint32_t module_id,
                                     VerthysModuleStatus *out_status)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    VtyModuleStatus st;
    int rc;

    if (out_status == NULL) return VERTHYS_ERR_INVALID;
    memset(out_status, 0, sizeof(*out_status));
    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;

    vty_api_module_lock_ctx(ctx);
    rc = vty_module_status(ctx->vault, module_id, &st);
    vty_api_module_unlock_ctx(ctx);
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
    ctx = vty_api_module_ctx(handle);
    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (!vty_api_recovery_arg_ok(old_recovery, 1)) return VERTHYS_ERR_INVALID;
    if (out_recovery == NULL || out_cap < 80u) return VERTHYS_ERR_INVALID;

    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    memset(out_recovery, 0, out_cap);
    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        verthys_secure_zero(out_recovery, out_cap);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_vault_recovery_rotate(ctx->vault, pw, old_recovery,
                                   out_recovery, out_cap);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    if (rc != VTY_OK) verthys_secure_zero(out_recovery, out_cap);
    return verthys_api_container_map(rc);
}
