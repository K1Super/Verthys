/*
 * verthys_api_container_rotate.c — 全库 DEK 轮换的公共入口
 *
 * 轮换作业挂在会话上；入口的 E_INVALID 表示参数/路径策略非法，
 * 不沿用记录链路的 INVALID→NOTFOUND 映射。
 */
#include "verthys_api_container_internal.h"

#include "vty_rotate.h"
#include "vty_util.h"

#include <stdlib.h>
#include <string.h>

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    VtyRotateJob *job = NULL;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (new_path == NULL || password == NULL || password_len == 0 ||
        out_info == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    memset(out_info, 0, sizeof(*out_info));

    pw = vty_api_pw_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        verthys_secure_zero(pw, password_len);
        free(pw);
        return VERTHYS_ERR_POLICY;
    }
    if (ctx->rotate != NULL) {
        rc = VTY_E_ROTATE_PENDING;
    } else {
        rc = vty_rotate_begin(ctx->vault, new_path, pw, flags, &job);
        if (rc == VTY_OK) ctx->rotate = job;
    }
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (keyfile_path == NULL || keyfile_path[0] == '\0' ||
        password == NULL || password_len == 0) {
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
    rc = vty_vault_attach_keyfile(ctx->vault, keyfile_path, pw);
    vty_api_module_unlock_ctx(ctx);

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
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    char *pw;
    int no_job = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (!vty_api_module_id_ok(module_id)) return VERTHYS_ERR_INVALID;
    if (password == NULL || password_len == 0 ||
        password_len > VTY_MODULE_PASSWORD_MAX) {
        return VERTHYS_ERR_INVALID;
    }
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
    if (ctx->rotate == NULL) {
        rc = VTY_OK;
        no_job = 1;
    } else {
        rc = vty_rotate_unlock_module(ctx->rotate, module_id, pw,
                                      recovery_code);
    }
    vty_api_module_unlock_ctx(ctx);

    verthys_secure_zero(pw, password_len);
    free(pw);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}

VerthysResult Verthys_V4RotateRun(VerthysHandle handle,
                                  VerthysRotateProgress progress,
                                  void *user)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    RotateCallbackBridge bridge;
    int no_job = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    bridge.cb = progress;
    bridge.user = user;
    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_POLICY;
    }
    if (ctx->rotate == NULL) {
        rc = VTY_OK;
        no_job = 1;
    } else {
        rc = vty_rotate_run(ctx->rotate, rotate_progress_bridge,
                            progress != NULL ? &bridge : NULL);
    }
    vty_api_module_unlock_ctx(ctx);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}

VerthysResult Verthys_V4RotateCommit(VerthysHandle handle,
                                     uint32_t keep_old)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    VtyVault *newv = NULL;
    int no_job = 0;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_POLICY;
    }
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
            /* 轮换目标由批量构建生成，空闲区尚未登记；立即重建，
             * 让后续删除/写入复用空间，而不是退化为追加直到下次解锁。 */
            (void)vty_repo_space_sync(ctx->vault);
        }
    }
    vty_api_module_unlock_ctx(ctx);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}

VerthysResult Verthys_V4RotateAbort(VerthysHandle handle)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    int no_job = 0;
    int rc = VTY_OK;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    vty_api_module_lock_ctx(ctx);
    if (ctx->rotate == NULL) {
        no_job = 1;
    } else {
        rc = vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    vty_api_module_unlock_ctx(ctx);
    return no_job ? VERTHYS_ERR_INVALID : rotate_map(rc);
}
