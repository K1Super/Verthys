/*
 * verthys_api_status.c — 容器只读检查门面
 *
 * 只负责句柄/参数校验与共享锁；容器字段组装、完整性遍历与落盘自查
 * 全部委托容器适配层，门面不读取 VtyVault 内部字段。
 */
#include "verthys_api_utils.h"
#include "verthys_api_container.h"

#include <string.h>

/* ================================================================== *
 * Verthys_GetContainerInfo 诊断接口
 *
 * 获取容器元数据（只读，不暴露密钥），供安全中心/状态指示器使用。
 *
 * 版本探测语义（worker 启动预检）：api_version/fmt_version/preset
 * 三个头部字段在任何状态（含 LOCKED/未解锁）均可读——供加载方在
 * 首个解锁操作前校准 ABI/格式兼容性，早于任何布局敏感调用。
 *
 * 线程安全：MT-Const（只读操作，可与其它只读操作并发）
 * ================================================================== */
VerthysResult Verthys_GetContainerInfo(VerthysHandle handle,
                                       VerthysContainerInfo *out_info)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL || out_info == NULL) return VERTHYS_ERR_INVALID;
    ctx = (struct VerthysContext *)handle;

    verthys_ctx_lock_shared(ctx);
    rc = verthys_api_container_info(ctx, out_info);
    verthys_ctx_unlock_shared(ctx);
    return rc;
}

/* ================================================================== *
 * Verthys_VerifyIntegrity 独立完整性校验接口
 *
 * 执行全量 Merkle 树校验 + 数据块 AEAD 标签验证，
 * 返回校验结果与损坏 LID 列表。
 *
 * 标准化错误模型
 *   采用"检查类 API 惯例"：
 *   - 校验操作成功完成 → 返回 VERTHYS_OK（无论是否发现损坏）
 *   - 发现损坏记录 → 通过 out_failed_count > 0 表明，out_failed_lids
 *     输出对应 LID 列表，前端据此标记损坏条目并支持跳过/修复
 *   - 仅当参数非法、库未解锁、内部状态错误时返回错误码
 *   VERTHYS_ERR_CORRUPT 保留给读取类接口（GetRecord/ScanFetch）在
 *   单条记录遭遇损坏时使用，本接口不返回此码。
 *
 * 耗时较长（万级记录约数秒），建议在后台线程调用。
 *
 * 线程安全：MT-Unsafe（遍历期间不可并发写操作）
 * ================================================================== */
VerthysResult Verthys_VerifyIntegrity(VerthysHandle handle,
                                      uint64_t *out_failed_lids,
                                      uint64_t max_failed,
                                      uint64_t *out_failed_count)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (out_failed_count == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    /* 状态机不变量：UNLOCKED ⇒ CONTAINER。先校验格式再进入锁区，
     * 保证任何返回路径都不会遗留未释放的锁。 */
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 共享锁：遍历期间阻止并发写 */
    verthys_ctx_lock_shared(ctx);
    rc = verthys_api_container_verify(ctx, out_failed_lids, max_failed,
                                      out_failed_count);
    verthys_ctx_unlock_shared(ctx);
    return rc;
}

/* ================================================================== *
 * Verthys_VerifyPersist 落盘自查接口
 *
 * 会话在解锁态持有库句柄；自查读取 DataRoot 指向的根段并复核摘要，
 * 不改会话状态、不写盘、无副作用。
 * ================================================================== */
VerPersistStatus Verthys_VerifyPersist(VerthysHandle handle,
                                       VerPersistVerifyResult *out_result)
{
    struct VerthysContext *ctx;
    VerPersistStatus status;

    if (out_result == NULL) return VERTHYS_PERSIST_E_INTERNAL;
    memset(out_result, 0, sizeof(*out_result));

    /* 无可用会话（未解锁 / 锁定态 / 句柄为空）→ INTERNAL：
     * 此时不存在持锁句柄，外部读路径才是唯一选择，本接口无从自查。 */
    ctx = (struct VerthysContext *)handle;
    if (ctx == NULL || ctx->state != VERTHYS_STATE_UNLOCKED) {
        out_result->status = VERTHYS_PERSIST_E_INTERNAL;
        strncpy(out_result->last_error, "no active unlocked session",
                sizeof(out_result->last_error) - 1u);
        return out_result->status;
    }

    verthys_ctx_lock_shared(ctx);
    status = verthys_api_container_verify_persist(ctx, out_result);
    verthys_ctx_unlock_shared(ctx);
    return status;
}
