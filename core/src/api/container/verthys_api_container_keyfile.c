/*
 * verthys_api_container_keyfile.c — keyfile 因子与设备重封的公共入口
 *
 * 口令按显式长度复制后进入锁区，退出时统一擦除；空 keyfile 路径表示
 * 恢复码会话下的 keyfile 丢失逃生路径。
 */
#include "verthys_api_container_internal.h"

#include "vty_keymanager.h"
#include "vty_util.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ *
 * keyfile 因子公共入口                                           *
 * ------------------------------------------------------------------ */

VerthysResult Verthys_V4KeyfileEnable(VerthysHandle handle,
                                      const char *password,
                                      size_t password_len,
                                      const char *new_keyfile_path)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (password == NULL || password_len == 0 || new_keyfile_path == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_vault_keyfile_enable_file(ctx->vault, pw, new_keyfile_path);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4KeyfileDisable(VerthysHandle handle,
                                       const char *password,
                                       size_t password_len,
                                       const char *keyfile_path)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    /* keyfile_path 允许为空串：仅恢复码会话可用（keyfile 丢失逃生），
     * 由 C 层按会话模式判定；普通会话空路径返回 KEYFILE_REQUIRED。 */
    if (password == NULL || password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_vault_keyfile_disable(ctx->vault, pw,
                                   (keyfile_path != NULL && keyfile_path[0] != '\0')
                                       ? keyfile_path : NULL);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4KeyfileStatus(VerthysHandle handle,
                                      uint32_t *out_enabled,
                                      uint32_t *out_recovery_mode)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (out_enabled == NULL || out_recovery_mode == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    vty_api_module_lock_ctx(ctx);
    *out_enabled = (ctx->vault->header.flags & VTY_FLAG_KEYFILE) != 0 ? 1u : 0u;
    *out_recovery_mode = ctx->vault->recovery_mode ? 1u : 0u;
    vty_api_module_unlock_ctx(ctx);
    return VERTHYS_OK;
}

VerthysResult Verthys_V4ResealDevice(VerthysHandle handle,
                                     const char *password,
                                     size_t password_len,
                                     const char *keyfile_path)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (password == NULL || password_len == 0) return VERTHYS_ERR_INVALID;
    if (password_len > 512u) return VERTHYS_ERR_INVALID;
    if (keyfile_path != NULL && strlen(keyfile_path) > 1024u) {
        return VERTHYS_ERR_INVALID;
    }

    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    rc = vty_vault_reseal_device_file(
        ctx->vault, pw,
        (keyfile_path != NULL && keyfile_path[0] != '\0') ? keyfile_path : NULL);
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return verthys_api_container_map(rc);
}
