/*
 * verthys_api_rollback.c — 回退锚点维护门面（内部实现，不新增导出）
 *
 * 只做参数/句柄/调用方签名边界与内部类型到公共 ABI 的转换；状态判定、
 * 回收与释放全部在 vty_rollback 内完成。任何自动回收都只处理 DEAD
 * 条目，ACTIVE/TAMPERED/UNKNOWN 绝不会被本组接口删除（Release 是
 * 用户显式确认的单独路径）。
 */
#include "verthys_api_utils.h"
#include "verthys_security_runtime.h"   /* 句柄在册校验 */
#include "vty_caller_auth.h"
#include "vty_rollback.h"
#include "vty_util.h"                   /* vty_secure_zero */

#include <string.h>

static VerthysResult verthys_anchor_map(int rc)
{
    switch (rc) {
    case VTY_OK:               return VERTHYS_OK;
    case VTY_E_INVALID:        return VERTHYS_ERR_INVALID;
    case VTY_E_ANCHOR_FULL:    return VERTHYS_ERR_ANCHOR_FULL;
    case VTY_E_CORRUPT:        return VERTHYS_ERR_CORRUPT;
    case VTY_E_IO:             return VERTHYS_ERR_IO;
    case VTY_E_TPM:            return VERTHYS_ERR_TPM;
    case VTY_E_POLICY:         return VERTHYS_ERR_POLICY;
    case VTY_E_RESOURCE:       return VERTHYS_ERR_RESOURCE_LIMIT;
    case VTY_E_CALLER:         return VERTHYS_ERR_UNAUTHORIZED;
    default:                   return VERTHYS_ERR_INTERNAL;
    }
}

static uint32_t verthys_anchor_state_of(uint32_t internal)
{
    switch (internal) {
    case VTY_ANCHOR_ACTIVE:   return VERTHYS_ANCHOR_WITNESS_ACTIVE;
    case VTY_ANCHOR_DEAD:     return VERTHYS_ANCHOR_WITNESS_DEAD;
    case VTY_ANCHOR_TAMPERED: return VERTHYS_ANCHOR_WITNESS_TAMPERED;
    default:                  return VERTHYS_ANCHOR_WITNESS_UNKNOWN;
    }
}

VerthysResult Verthys_RollbackAnchorList(VerthysHandle handle,
                                         VerthysAnchorInfo *out_anchors,
                                         uint32_t capacity,
                                         uint32_t *out_count,
                                         uint32_t *out_state)
{
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    VtyAnchorInfo tmp[VTY_ROLLBACK_MAX_ENTRIES];
    uint32_t needed = 0;
    uint32_t i;
    int missing = 0;
    int rc;

    if (handle == NULL || out_count == NULL || out_state == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (!verthys_ctx_registry_contains(ctx)) return VERTHYS_ERR_INVALID;
    if (capacity > 0 && out_anchors == NULL) return VERTHYS_ERR_INVALID;
    if (vty_caller_auth_check() != VTY_OK) return VERTHYS_ERR_UNAUTHORIZED;

    *out_count = 0;
    *out_state = VERTHYS_ANCHOR_STATE_CORRUPT;

    /* 先只查数量（不触发 64 次 TPM 探测），再按调用方容量决定是否
     * 填充明细。 */
    rc = vty_rollback_anchor_list(NULL, 0, &needed, &missing);
    if (rc != VTY_OK) {
        *out_state = (rc == VTY_E_CORRUPT)
                         ? VERTHYS_ANCHOR_STATE_CORRUPT
                         : (missing ? VERTHYS_ANCHOR_STATE_ABSENT
                                    : VERTHYS_ANCHOR_STATE_UNKNOWN);
        return verthys_anchor_map(rc);
    }
    *out_count = needed;
    *out_state = missing ? VERTHYS_ANCHOR_STATE_ABSENT
                         : VERTHYS_ANCHOR_STATE_OK;
    if (needed == 0 || out_anchors == NULL || capacity == 0) {
        return VERTHYS_OK;
    }
    if (capacity < needed) return VERTHYS_ERR_RESOURCE_LIMIT;

    memset(tmp, 0, sizeof(tmp));
    rc = vty_rollback_anchor_list(tmp, VTY_ROLLBACK_MAX_ENTRIES,
                                  &needed, &missing);
    if (rc != VTY_OK) return verthys_anchor_map(rc);
    if (needed > capacity) {
        *out_count = needed;
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }
    memset(out_anchors, 0, (size_t)needed * sizeof(*out_anchors));
    for (i = 0; i < needed; i++) {
        out_anchors[i].struct_size = (uint32_t)sizeof(VerthysAnchorInfo);
        memcpy(out_anchors[i].uuid, tmp[i].uuid, VERTHYS_ANCHOR_UUID_BYTES);
        out_anchors[i].generation = tmp[i].generation;
        out_anchors[i].witness_state = verthys_anchor_state_of(tmp[i].state);
    }
    *out_count = needed;
    *out_state = missing ? VERTHYS_ANCHOR_STATE_ABSENT
                         : VERTHYS_ANCHOR_STATE_OK;
    vty_secure_zero(tmp, sizeof(tmp));
    return VERTHYS_OK;
}

VerthysResult Verthys_RollbackAnchorReclaim(VerthysHandle handle,
                                            uint32_t flags,
                                            uint32_t *out_removed,
                                            uint32_t *out_cleanup_failed)
{
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    int rc;

    if (handle == NULL || out_removed == NULL ||
        out_cleanup_failed == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (!verthys_ctx_registry_contains(ctx)) return VERTHYS_ERR_INVALID;
    if (vty_caller_auth_check() != VTY_OK) return VERTHYS_ERR_UNAUTHORIZED;
    *out_removed = 0;
    *out_cleanup_failed = 0;
    rc = vty_rollback_anchor_reclaim(flags, out_removed, out_cleanup_failed);
    return verthys_anchor_map(rc);
}

VerthysResult Verthys_RollbackAnchorRelease(
    VerthysHandle handle,
    const uint8_t uuid[VERTHYS_ANCHOR_UUID_BYTES],
    uint32_t flags,
    uint32_t *out_released,
    uint32_t *out_cleanup_failed)
{
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    int rc;

    if (handle == NULL || uuid == NULL || out_released == NULL ||
        out_cleanup_failed == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (!verthys_ctx_registry_contains(ctx)) return VERTHYS_ERR_INVALID;
    if (vty_caller_auth_check() != VTY_OK) return VERTHYS_ERR_UNAUTHORIZED;
    *out_released = 0;
    *out_cleanup_failed = 0;
    rc = vty_rollback_anchor_release(uuid, flags, out_released,
                                     out_cleanup_failed);
    return verthys_anchor_map(rc);
}
