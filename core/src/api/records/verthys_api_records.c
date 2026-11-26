/*
 * verthys_api_records.c — 记录读写门面
 *
 * 记录新增/批量新增/导入锚点推迟/读取/删除/替换/计数/刷盘全部在此收口。
 * 锁纪律：先完成句柄状态与格式校验，再进入 api_mutex；进入锁区后只有
 * 单一出口，任何分支都不得绕过解锁。
 */
#include "verthys_api_utils.h"
#include "verthys_api_container.h"
#include "verthys_security_runtime.h"   /* 句柄在册校验 */

#include "anti_debug.h"
#include "runtime_hash.h"
#include "vty_keymanager.h"   /* vty_vault_bulk_begin/commit */

#include <string.h>

/* 记录写入的统一入口校验（AddRecord / AddRecords 共用）。
 *
 * 名称长度在 API 边界钳制：索引条目 name_len 为 uint16 存储，超 4096
 * 字节的名称会导致"块以全名派生记录密钥、索引以截断名存储"的分裂 →
 * 重载后记录不可解。数据长度同时受导出格式 32 位容量与单条 IPC 预算
 * （12MiB base64 的 4/3 解码上界 9MiB）约束。 */
static VerthysResult validate_record_write(const VerthysRecord *record)
{
    if (record == NULL) return VERTHYS_ERR_INVALID;
    if (record->name == NULL && record->name_len != 0) return VERTHYS_ERR_INVALID;
    if (record->data == NULL && record->data_len != 0) return VERTHYS_ERR_INVALID;
    if (record->name_len > VERTHYS_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (record->data_len > VERTHYS_RECORD_DATA_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (record->data_len > (9u * 1024u * 1024u)) return VERTHYS_ERR_RESOURCE_LIMIT;
    return VERTHYS_OK;
}

/* 5. 新增记录 */
VerthysResult Verthys_AddRecord(VerthysHandle handle,
                            const VerthysRecord *record,
                            uint64_t *out_id)
{
    VerthysResult vrc;
    VerthysResult rc;
    struct VerthysContext *ctx;

    if (handle == NULL || record == NULL || out_id == NULL) return VERTHYS_ERR_INVALID;
    vrc = validate_record_write(record);
    if (vrc != VERTHYS_OK) return vrc;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    /* 状态机不变量：UNLOCKED ⇒ CONTAINER；先校验格式再进锁区。 */
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 写路径入口反调试复检（60s 周期之外的高价值动作补点）。
     * check 内部命中高置信度调试器时已上报 KILL；此处不改变返回语义。 */
    (void)anti_debug_check();

    verthys_ctx_lock_exclusive(ctx);

    /* 写操作入口统一失效查询缓存，防止 UAF
     * 所有写入操作（增/删/改/导入/改密/刷盘）在持锁后立即清空 getrecord_cache，
     * 消除外部借用指针在缓存销毁后变为野指针的 UAF 窗口。
     * 统一收口缓存销毁，写入事务提交前强制清空历史查询缓存。 */
    ctx_free_getrecord_cache(ctx);

    /* 写路径周期重算关键函数
     * 运行时哈希（时间门控，距上次全量 <30min 直接返回；首调立即全量）。 */
    runtime_hash_verify_periodic();

    /* 仓库写入 + 单次 DataRoot/元数据提交（api_mutex 已持有） */
    rc = verthys_api_container_add(ctx, record, out_id);

    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 5.1 批量新增记录（API 版本 0x0013）：单次事务提交，全有或全无 */
VerthysResult Verthys_AddRecords(VerthysHandle handle,
                            const VerthysRecord *records,
                            uint32_t count,
                            uint64_t *out_ids)
{
    struct VerthysContext *ctx;
    uint32_t i;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (records == NULL || out_ids == NULL) return VERTHYS_ERR_INVALID;
    if (count == 0u || count > VERTHYS_ADD_RECORDS_MAX) return VERTHYS_ERR_INVALID;

    /* IDs 先归零：任何失败路径（含逐条校验拒绝）都不向调用方暴露
     * 未初始化或部分分配结果。 */
    memset(out_ids, 0, (size_t)count * sizeof(uint64_t));

    /* 逐条边界校验：任一非法即整批拒绝，避免部分写入与事务半成品 */
    for (i = 0u; i < count; i++) {
        VerthysResult vrc = validate_record_write(&records[i]);
        if (vrc != VERTHYS_OK) return vrc;
    }

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    verthys_ctx_lock_exclusive(ctx);

    /* 写操作入口统一失效查询缓存（与 AddRecord 同一 UAF 纪律） */
    ctx_free_getrecord_cache(ctx);
    runtime_hash_verify_periodic();

    {
        VerthysResult rc = verthys_api_container_add_many(ctx, records, count, out_ids);
        verthys_ctx_unlock_exclusive(ctx);
        return rc;
    }
}

/* 5.2 批量导入锚点推迟（API 版本 0x0015）
 *
 * Begin/Commit 自身不做数据写入，但会改变会话的锚点提交策略，
 * 因此与写路径同锁串行，并使既有 GetRecord 借用指针失效
 * （避免调用方把跨会话的借用指针当作仍然有效）。 */
VerthysResult Verthys_BulkImportBegin(VerthysHandle handle)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER || ctx->vault == NULL) {
        return VERTHYS_ERR_FORMAT;
    }

    verthys_ctx_lock_exclusive(ctx);
    ctx_free_getrecord_cache(ctx);
    if (ctx->rotate != NULL) {
        /* 轮换作业持有源库只读语义，推迟窗口不能与轮换叠加。 */
        rc = VERTHYS_ERR_POLICY;
    } else {
        rc = verthys_api_map_vty(vty_vault_bulk_begin(ctx->vault));
    }
    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

VerthysResult Verthys_BulkImportCommit(VerthysHandle handle)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER || ctx->vault == NULL) {
        return VERTHYS_ERR_FORMAT;
    }

    verthys_ctx_lock_exclusive(ctx);
    ctx_free_getrecord_cache(ctx);
    rc = verthys_api_map_vty(vty_vault_bulk_commit(ctx->vault));
    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 6. 读取记录 */
VerthysResult Verthys_GetRecord(VerthysHandle handle,
                            uint64_t id,
                            VerthysRecord *out_record)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL || out_record == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 独占锁：借用指针缓存受锁保护 */
    verthys_ctx_lock_exclusive(ctx);

    /* 目录叶查找 + 记录段校验/AEAD 解密，结果复制进借用缓存 */
    rc = verthys_api_container_get(ctx, id, out_record);

    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 6.1 显式释放 GetRecord 借用缓存
 *
 * 借用指针契约要求调用方在使用完返回记录后主动释放缓存；worker 在把
 * 记录复制到自有缓冲并完成 base64 后调用本接口，避免 C 层明文跨请求驻留。 */
VerthysResult Verthys_ClearRecordCache(VerthysHandle handle)
{
    struct VerthysContext *ctx;

    if (handle == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (!verthys_ctx_registry_contains(ctx)) return VERTHYS_ERR_INVALID;

    verthys_ctx_lock_exclusive(ctx);
    ctx_free_getrecord_cache(ctx);
    verthys_ctx_unlock_exclusive(ctx);
    return VERTHYS_OK;
}

/* 7. 删除记录 */
VerthysResult Verthys_DeleteRecord(VerthysHandle handle, uint64_t id)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    verthys_ctx_lock_exclusive(ctx);

    /* 推迟窗口只覆盖新增记录：删除会把“数据复活”纳入回退影响。 */
    if (verthys_bulk_defer_active(ctx)) {
        rc = VERTHYS_ERR_POLICY;
    } else {
        /* 写操作入口统一失效查询缓存，防止 UAF */
        ctx_free_getrecord_cache(ctx);
        /* 写路径周期运行时哈希校验（30min 门控） */
        runtime_hash_verify_periodic();

        /* 记录叶/名称/类型三处墓碑 + 单次提交 */
        rc = verthys_api_container_delete(ctx, id);
    }

    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 7b. 原子替换记录（API 版本 0x0017）
 *
 * 同一次事务提交内墓碑化 old_id 并写入新记录；任一失败恢复到调用前的根。
 * 适用于系统单例记录的换钥，避免"写新/删旧"跨两次事务的崩溃窗口。 */
VerthysResult Verthys_ReplaceRecord(VerthysHandle handle, uint64_t old_id,
                                    const VerthysRecord *record,
                                    uint64_t *out_new_id)
{
    VerthysResult vrc;
    VerthysResult rc;
    struct VerthysContext *ctx;

    if (handle == NULL || record == NULL || out_new_id == NULL || old_id == 0u) {
        return VERTHYS_ERR_INVALID;
    }
    *out_new_id = 0u;
    vrc = validate_record_write(record);
    if (vrc != VERTHYS_OK) return vrc;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    (void)anti_debug_check();

    verthys_ctx_lock_exclusive(ctx);

    /* 推迟窗口只覆盖新增：替换含删除语义，必须先 Commit（与 DeleteRecord 同策略）。 */
    if (verthys_bulk_defer_active(ctx)) {
        rc = VERTHYS_ERR_POLICY;
    } else {
        ctx_free_getrecord_cache(ctx);
        runtime_hash_verify_periodic();

        rc = verthys_api_container_replace(ctx, old_id, record, out_new_id);
    }

    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 7a. 批量删除记录（单次提交刚性要求）
 *
 * 本函数在单事务内统一写墓碑，末尾一次 DataRoot/元数据提交收口，
 * 磁盘写入量与条目数解耦。
 *
 * @param handle  Verthys 句柄
 * @param ids     待删除记录 ID 数组
 * @param count   数组长度
 * @returns VERTHYS_OK 全部成功；VERTHYS_ERR_NOTFOUND 任一 ID 不存在（整体回滚）
 */
VerthysResult Verthys_DeleteRecords(VerthysHandle handle, const uint64_t *ids, size_t count)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (ids == NULL && count != 0) return VERTHYS_ERR_INVALID;
    if (count == 0) return VERTHYS_OK;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    verthys_ctx_lock_exclusive(ctx);

    if (verthys_bulk_defer_active(ctx)) {
        rc = VERTHYS_ERR_POLICY;
    } else {
        /* 写操作入口统一失效查询缓存，防止 UAF */
        ctx_free_getrecord_cache(ctx);
        /* 写路径周期运行时哈希校验（30min 门控） */
        runtime_hash_verify_periodic();

        /* 先全量探测再统一写墓碑，一次提交收口 */
        rc = verthys_api_container_delete_many(ctx, ids, count);
    }

    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 获取存活记录总数
 *
 * 语义：目录叶全量遍历精确计数（跳过分配器与墓碑）。
 */
VerthysResult Verthys_GetSummaryCount(VerthysHandle handle, uint64_t *out_count)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL || out_count == NULL) return VERTHYS_ERR_INVALID;
    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 目录叶全量遍历精确计数（跳过分配器与墓碑） */
    verthys_ctx_lock_shared(ctx);
    rc = verthys_api_container_count(ctx, out_count);
    verthys_ctx_unlock_shared(ctx);
    return rc;
}

/* ================================================================== *
 * Verthys_Flush 显式刷盘接口
 *
 * 在不锁定的情况下主动将内存中的索引变更刷写到磁盘，
 * 保证崩溃恢复一致性。
 *
 * 提交 DataRoot/元数据变更并物理落盘。
 *
 * 线程安全：MT-Safe（内部递归互斥锁保护）
 * ================================================================== */
VerthysResult Verthys_Flush(VerthysHandle handle)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    verthys_ctx_lock_exclusive(ctx);

    /* 写操作入口统一失效查询缓存，防止 UAF */
    ctx_free_getrecord_cache(ctx);
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* 刷盘：DataRoot/元数据提交（api_mutex 已持有）。 */
    rc = verthys_api_container_flush(ctx);

    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}
