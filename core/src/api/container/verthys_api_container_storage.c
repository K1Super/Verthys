/*
 * verthys_api_container_storage.c — 存储统计的公共入口
 *
 * 删除后的空间回收由存储引擎在提交时自动完成，本层只提供只读统计。
 */
#include "verthys_api_container_internal.h"

#include "vty_repo.h"

#include <string.h>

/* ------------------------------------------------------------------ *
 * 存储统计                                                            *
 * ------------------------------------------------------------------ */

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


