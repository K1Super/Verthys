/*
 * verthys_api_container_pcr.c — PCR 策略公共入口
 *
 * 位图合法性在进入锁区前判定；恢复码校验与会话模式判定集中于此。
 */
#include "verthys_api_container_internal.h"

#include "vty_keymanager.h"
#include "vty_tpm_pcr.h"

#include <string.h>

/* ------------------------------------------------------------------ *
 * PCR 策略公共入口                                                     *
 * ------------------------------------------------------------------ */

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    uint32_t enabled = 0;
    uint32_t select = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (out_enabled == NULL || out_select == NULL) return VERTHYS_ERR_INVALID;

    vty_api_module_lock_ctx(ctx);
    rc = vty_vault_pcr_info(ctx->vault, &enabled, &select);
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!pcr_recovery_ok(ctx, recovery_code)) return VERTHYS_ERR_INVALID;
    /* 内部 map 把 E_INVALID 归为 NOTFOUND；位图非法必须在公共入口
     * 先返回 INVALID，避免调用方误判为记录不存在。 */
    if (vty_tpm_pcr_select_valid(pcr_select) != VTY_OK) {
        return VERTHYS_ERR_INVALID;
    }

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_POLICY;
    }
    rc = VTY_OK;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(ctx->vault, recovery_code);
    }
    if (rc == VTY_OK) {
        rc = vty_vault_pcr_enable(ctx->vault, pcr_select);
    }
    vty_api_module_unlock_ctx(ctx);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4PcrDisable(VerthysHandle handle,
                                   const char *recovery_code)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!pcr_recovery_ok(ctx, recovery_code)) return VERTHYS_ERR_INVALID;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_POLICY;
    }
    rc = VTY_OK;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(ctx->vault, recovery_code);
    }
    if (rc == VTY_OK) {
        rc = vty_vault_pcr_disable(ctx->vault);
    }
    vty_api_module_unlock_ctx(ctx);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_V4PcrReseal(VerthysHandle handle,
                                  const char *recovery_code)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!pcr_recovery_ok(ctx, recovery_code)) return VERTHYS_ERR_INVALID;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_POLICY;
    }
    rc = VTY_OK;
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(ctx->vault, recovery_code);
    }
    if (rc == VTY_OK) {
        rc = vty_vault_pcr_reseal(ctx->vault);
    }
    vty_api_module_unlock_ctx(ctx);
    return verthys_api_container_map(rc);
}
