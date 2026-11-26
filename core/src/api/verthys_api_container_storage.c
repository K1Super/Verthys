/*
 * verthys_api_container_storage.c — 存储统计与空间压缩的公共入口
 *
 * 统计字段按仓库快照如实上报；压缩使用同目录临时文件并在提交后
 * 接管新库，旧库释放由压缩层负责。
 */
#include "verthys_api_container_internal.h"

#include "vty_compact.h"
#include "vty_repo.h"

#include <string.h>

/* ------------------------------------------------------------------ *
 * 存储统计与空间压缩                                                  *
 * ------------------------------------------------------------------ */

typedef struct {
    VerthysCompactProgress cb;
    void *user;
} CompactApiBridge;

static int compact_api_progress(void *user, const VtyCompactStats *src)
{
    CompactApiBridge *bridge = (CompactApiBridge *)user;
    VerthysCompactStats out;

    if (bridge == NULL || bridge->cb == NULL || src == NULL) return 0;
    memset(&out, 0, sizeof(out));
    out.stage = src->stage;
    out.before_bytes = src->before_bytes;
    out.after_bytes = src->after_bytes;
    out.reclaimed_bytes = src->reclaimed_bytes;
    out.records = src->records;
    out.chunks = src->chunks;
    out.bytes = src->bytes;
    out.live_bytes = src->live_bytes;
    return bridge->cb(bridge->user, &out);
}

VerthysResult Verthys_GetStorageStats(VerthysHandle handle,
                                      VerthysStorageStats *out_stats)
{
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    VtyStorageStats st;
    int rc;

    if (out_stats == NULL) return VERTHYS_ERR_INVALID;
    memset(out_stats, 0, sizeof(*out_stats));
    if (ctx == NULL) return VERTHYS_ERR_LOCKED;

    vty_api_module_lock_ctx(ctx);
    memset(&st, 0, sizeof(st));
    rc = vty_repo_storage_stats(ctx->vault, &st);
    vty_api_module_unlock_ctx(ctx);
    if (rc != VTY_OK) {
        return (rc == VTY_E_INVALID) ? VERTHYS_ERR_INVALID
                                     : verthys_api_container_map(rc);
    }
    out_stats->file_size = st.file_size;
    out_stats->data_end = st.data_end;
    out_stats->live_tree_bytes = st.live_tree_bytes;
    out_stats->live_segment_bytes = st.live_segment_bytes;
    out_stats->live_bytes = st.live_bytes;
    out_stats->reclaimable_bytes = st.reclaimable_bytes;
    out_stats->record_count = st.record_count;
    out_stats->file_count = st.file_count;
    out_stats->chunk_count = st.chunk_count;
    return VERTHYS_OK;
}

VerthysResult Verthys_CompactStorage(VerthysHandle handle,
                                     VerthysCompactProgress progress,
                                     void *user)
{
    static const char suffix[] = ".vtycompact.tmp";
    struct VerthysContext *ctx = vty_api_module_ctx(handle);
    CompactApiBridge bridge;
    VtyCompactJob *job = NULL;
    VtyVault *newv = NULL;
    char tmp_path[1400];
    size_t path_len;
    int rc;

    if (ctx == NULL) return VERTHYS_ERR_LOCKED;
    if (ctx->vault == NULL || !ctx->vault->unlocked ||
        ctx->vault->store == NULL) {
        return VERTHYS_ERR_LOCKED;
    }

    vty_api_module_lock_ctx(ctx);
    if (verthys_bulk_defer_active(ctx)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_POLICY;
    }
    path_len = strlen(ctx->vault->path);
    if (path_len + sizeof(suffix) > sizeof(tmp_path)) {
        vty_api_module_unlock_ctx(ctx);
        return VERTHYS_ERR_INVALID;
    }
    memcpy(tmp_path, ctx->vault->path, path_len);
    memcpy(tmp_path + path_len, suffix, sizeof(suffix));

    rc = vty_compact_cleanup_stale(ctx->vault->path);
    if (rc != VTY_OK) {
        vty_api_module_unlock_ctx(ctx);
        return verthys_api_container_map(rc);
    }
    rc = vty_compact_begin(ctx->vault, tmp_path, &job);
    if (rc != VTY_OK) {
        vty_api_module_unlock_ctx(ctx);
        return verthys_api_container_map(rc);
    }

    bridge.cb = progress;
    bridge.user = user;
    rc = vty_compact_run(job, progress != NULL ? compact_api_progress : NULL,
                         progress != NULL ? &bridge : NULL);
    if (rc != VTY_OK) {
        (void)vty_compact_abort(job);
        vty_api_module_unlock_ctx(ctx);
        return verthys_api_container_map(rc);
    }
    rc = vty_compact_commit(job, &newv);
    if (rc != VTY_OK) {
        (void)vty_compact_abort(job);
        vty_api_module_unlock_ctx(ctx);
        return verthys_api_container_map(rc);
    }

    /* vty_compact_commit 已释放旧库：只接管新库，驻留计数保持 1。 */
    vault_session_replace_externally_freed(ctx, newv);
    vty_api_module_unlock_ctx(ctx);
    return VERTHYS_OK;
}
