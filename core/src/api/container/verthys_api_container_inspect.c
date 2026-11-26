/*
 * verthys_api_container_inspect.c — 容器只读检查的 API 适配层
 *
 * 唯一允许读取 VtyVault 内部字段的 API 侧文件：容器信息与落盘自查的
 * 字段组装、错误映射全部在此完成，状态门面只持锁与转发。
 *
 * 前置条件：调用方已持有 ctx->api_mutex 共享锁，且 ctx 非 NULL。
 */
#include "verthys_api_container.h"

#include "vty_keymanager.h"
#include "vty_types.h"

#include <string.h>

VerthysResult verthys_api_container_info(struct VerthysContext *ctx,
                                         VerthysContainerInfo *out_info)
{
    memset(out_info, 0, sizeof(*out_info));
    out_info->api_version = VERTHYS_API_VERSION;
    /* 编译期能力：本实现唯一支持的容器格式版本。 */
    out_info->fmt_version = (uint16_t)VERTHYS_CONTAINER_FORMAT_VERSION;
    out_info->preset = (uint16_t)ctx->preset;
    out_info->last_fullscan_time = ctx->last_fullscan_time;
    out_info->warm_cache_enabled = (uint8_t)ctx->warm_cache_enabled;

    /* 未解锁态：仅版本头部有意义，统计字段全部如实归零并提前返回
     * （不伪造数据；容器未打开时不存在可报告的运行时统计） */
    if (ctx->state != VERTHYS_STATE_UNLOCKED) {
        return VERTHYS_OK;
    }

    /* 数据区尚未提交记录（当前只交付格式与会话），统计字段按
     * DataRoot 高水位如实报告，不伪造 record_count。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        uint64_t live = 0;
        VerthysResult cr;

        if (ctx->vault == NULL) return VERTHYS_ERR_INTERNAL;

        out_info->txid = ctx->vault->header.generation;
        out_info->data_region_size =
            ctx->vault->data_root.data_end - VTY_DATA_OFFSET;
        out_info->data_used_bytes = out_info->data_region_size;

        cr = verthys_api_container_count(ctx, &live);
        if (cr != VERTHYS_OK) return cr;
        out_info->record_count = live;

        out_info->index_region_size = 0;
        out_info->mount_count = 0;
        out_info->cumulative_write_bytes = 0;
        out_info->merkle_pending = 0;
        out_info->has_keyfile =
            (uint8_t)((ctx->vault->header.flags & VTY_FLAG_KEYFILE) != 0);
        memcpy(out_info->container_id, ctx->vault->header.vault_uuid,
               VTY_UUID_BYTES);
        return VERTHYS_OK;
    }

    return VERTHYS_ERR_FORMAT;
}

/* 写入静态错误文案：last_error 仅承载稳定短文案（不引入 printf 族——
 * 数值细节由结构体的 header_magic / header_version / file_size /
 * wal_offset 字段承载） */
static void ver_persist_set_error(VerPersistVerifyResult *out, const char *msg)
{
    size_t n;
    if (out == NULL || msg == NULL) return;
    n = strlen(msg);
    if (n >= sizeof(out->last_error)) n = sizeof(out->last_error) - 1u;
    memcpy(out->last_error, msg, n);
    out->last_error[n] = '\0';
}

VerPersistStatus verthys_api_container_verify_persist(
    struct VerthysContext *ctx, VerPersistVerifyResult *out_result)
{
    /* 校验会话 DataRoot 指向的根段仍在盘上且摘要一致。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VtyPersistCheck chk;
        int rc;

        memset(&chk, 0, sizeof(chk));
        if (ctx->vault == NULL || !ctx->vault->unlocked ||
            ctx->vault->store == NULL) {
            out_result->status = VERTHYS_PERSIST_E_INTERNAL;
            ver_persist_set_error(out_result, "no active session");
            return out_result->status;
        }

        rc = vty_vault_verify_persist(ctx->vault, &chk);
        out_result->file_size = chk.file_size;
        out_result->mtime_ms = chk.mtime_ms;
        out_result->header_magic = chk.header_magic;
        out_result->header_version = chk.header_version;
        out_result->wal_offset = 0u;
        if (rc == VTY_OK) {
            out_result->status = VERTHYS_PERSIST_OK;
        } else if (rc == VTY_E_IO) {
            out_result->status = VERTHYS_PERSIST_E_IO;
            ver_persist_set_error(out_result, "data root read io failed");
        } else if (rc == VTY_E_CORRUPT) {
            out_result->status =
                (chk.file_size < ctx->vault->data_root.data_end)
                    ? VERTHYS_PERSIST_E_SIZE_MISMATCH
                    : VERTHYS_PERSIST_E_HEADER_INVALID;
            ver_persist_set_error(out_result, "data root verification failed");
        } else {
            out_result->status = VERTHYS_PERSIST_E_INTERNAL;
            ver_persist_set_error(out_result, "data root verification internal error");
        }
        return out_result->status;
    }

    /* 非容器格式无持久化自查路径 */
    out_result->status = VERTHYS_PERSIST_E_INTERNAL;
    ver_persist_set_error(out_result, "no active unlocked session");
    return out_result->status;
}
