/*
 * verthys_scan.c — 游标式批量数据扫描底层实现模块
 *
 * 三段式标准游标调用范式：打开游标 Open → 循环批量拉取 Fetch →
 * 关闭释放 Close。彻底规避单条记录循环查询带来的 LSM 重复查找开销，
 * 大幅提升大批量列表遍历性能。
 *
 * 内置全链路安全防护体系：
 * 1. 游标绑定打开瞬间 LSM 快照（open 时深拷贝 MemTable 编码流 +
 *    SSTable 元数据/块迭代器），遍历过程不受并发写入事务数据变更干扰
 *    （快照隔离由 LSM 结构性保证）
 * 2. 每次数据拉取执行全局应急熔断状态检测，触发安全紧急机制时直接停止对外服务
 * 3. 游标内存对象托管至内存防护管理器，系统紧急清零指令下发时自动覆写销毁敏感内容
 * 4. 通过内存页锁定API将游标常驻物理内存，防止页面置换交换至磁盘引发内存数据泄露
 * 5. 堆上深拷贝的字符串与二进制数据，释放前执行多轮交替字节安全擦除再执行内存释放
 */
#include "verthys_internal.h"
#include "memory_guard.h"
#include "emergency.h"
#include "verthys_diag.h"
/* 扫描：目录叶游标 + 记录段解密/名称解密。 */
#include "vty_repo.h"
#include "verthys_api_container.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

/* ------------------------------------------------------------------ *
 * 扫描游标内部结构体定义                                              *
 * ------------------------------------------------------------------ */
struct VerthysScanCursor {
    uint64_t            start_lid;       /* 遍历起始逻辑记录ID（迭代器 lid 升序，
                                            Fetch 中过滤 < start_lid 的条目） */
    uint64_t            batch_size;      /* 单次批量拉取建议条数 */
    int                 exhausted;       /* 全局遍历完成标记，置1后不再继续读取数据 */

    /* 扫描投影与取批预算（Verthys_ScanOpenEx 设定；ScanOpen 按 FULL/不限 设定） */
    uint32_t            project;         /* VerthysScanProject 取值 */
    uint64_t            index_inline_max_bytes; /* INDEX 投影的内联数据阈值 */
    uint64_t            max_batch_bytes; /* 单次 Fetch 输出字节预算，0=不限 */

    /* 安全管控状态字段 */
    int                 mem_locked;      /* 标记游标结构体内存是否已执行页锁定 */
    int                 invalidated;     /* 标记游标是否被应急熔断机制强制作废 */


    /* === 目录叶游标（COW 快照） === */
    struct VerthysContext *vault_ctx;          /* 借用句柄（共享锁/存活性检测） */
    struct VtyVault     *vault_owner;          /* 借用实例身份锚点，Lock 后失配 */
    VtyRepoIter         *vault_iter;
};


/* ------------------------------------------------------------------ *
 * 扫描游标辅助段
 *
 * 目录叶在打开瞬间固定根节点（store COW 快照）；游标借用 VtyVault
 * 实例，Lock/再解锁后实例失配即作废，杜绝悬挂 store 句柄。
 * ------------------------------------------------------------------ */
static int scan_alive(const VerthysScanCursor *cursor)
{
    const struct VerthysContext *ctx;

    if (cursor == NULL || cursor->vault_owner == NULL) return 0;
    ctx = cursor->vault_ctx;
    return ctx != NULL &&
           ctx->fmt_version == VERTHYS_FMT_CONTAINER &&
           ctx->vault == cursor->vault_owner &&
           ctx->vault->unlocked &&
           ctx->vault->store != NULL;
}

static uint8_t *scan_dup_bytes(const uint8_t *src, size_t n)
{
    uint8_t *p;

    if (n == 0) return NULL;
    p = (uint8_t *)malloc(n);
    if (p != NULL) memcpy(p, src, n);
    return p;
}

static VerthysResult scan_open(struct VerthysContext *ctx,
                                  uint64_t start_lid,
                                  uint64_t batch_size,
                                  uint32_t project,
                                  uint64_t index_inline_max_bytes,
                                  uint64_t max_batch_bytes,
                                  const char *guard_label,
                                  VerthysScanCursor **out_cursor)
{
    VerthysScanCursor *cursor;
    int rc;

    *out_cursor = NULL;
    if (ctx->vault == NULL || !ctx->vault->unlocked || ctx->vault->store == NULL) {
        return VERTHYS_ERR_LOCKED;
    }

    cursor = (VerthysScanCursor *)calloc(1, sizeof(VerthysScanCursor));
    if (cursor == NULL) return VERTHYS_ERR_INTERNAL;

    cursor->vault_ctx = ctx;
    cursor->vault_owner = ctx->vault;
    cursor->start_lid = start_lid;
    cursor->batch_size = (batch_size > 0) ? batch_size : 500;
    cursor->project = project;
    cursor->index_inline_max_bytes = index_inline_max_bytes;
    cursor->max_batch_bytes = max_batch_bytes;

    rc = vty_repo_iter_open(ctx->vault, start_lid, &cursor->vault_iter);
    if (rc != VTY_OK) {
        free(cursor);
        return verthys_api_container_map(rc);
    }

    if (verthys_lock_memory(cursor, sizeof(*cursor)) == 0) {
        cursor->mem_locked = 1;
    }
    memory_guard_register(cursor, sizeof(*cursor), guard_label);

    *out_cursor = cursor;
    return VERTHYS_OK;
}

static VerthysResult scan_fetch(VerthysScanCursor *cursor,
                                   VerthysRecord *out_records,
                                   uint64_t *out_lids,
                                   uint64_t max_count,
                                   uint64_t *out_count,
                                   uint64_t *out_failed_lids,
                                   uint64_t *out_failed_count)
{
    uint64_t count = 0;
    uint64_t failed = 0;
    uint64_t batch_bytes = 0;

    if (!scan_alive(cursor)) {
        cursor->invalidated = 1;
        return VERTHYS_ERR_LOCKED;
    }

    *out_count = 0;
    if (out_failed_count != NULL) *out_failed_count = 0;
    if (cursor->exhausted || max_count == 0) return VERTHYS_OK;

    while (count < max_count) {
        VtyRepoLeaf leaf;
        VtyRepoRecord rec;
        int done = 0;
        int rc;

        rc = vty_repo_iter_next(cursor->vault_iter, &leaf, &done);
        if (rc != VTY_OK) return verthys_api_container_map(rc);
        if (done) { cursor->exhausted = 1; break; }
        if (leaf.record_id < cursor->start_lid) continue;

        {
            int inline_data = (cursor->project == VERTHYS_SCAN_PROJECT_FULL) ||
                              ((uint64_t)leaf.plain_size <= cursor->index_inline_max_bytes);
            uint8_t *name = NULL;
            uint8_t *data = NULL;
            size_t name_len = 0;
            size_t data_len = 0;

            memset(&rec, 0, sizeof(rec));
            if (inline_data) {
                rc = vty_repo_read(cursor->vault_owner, &leaf, &rec);
                if (rc != VTY_OK) {
                    if (out_failed_lids != NULL && failed < max_count) {
                        out_failed_lids[failed] = leaf.record_id;
                    }
                    failed++;
                    continue;
                }
                name = rec.name;
                name_len = rec.name_len;
                data = rec.data;
                data_len = rec.data_len;
            } else {
                rc = vty_repo_read_name(cursor->vault_owner, &leaf, &name, &name_len);
                if (rc != VTY_OK) {
                    if (out_failed_lids != NULL && failed < max_count) {
                        out_failed_lids[failed] = leaf.record_id;
                    }
                    failed++;
                    continue;
                }
            }

            {
                uint8_t *name_copy = scan_dup_bytes(name, name_len);
                uint8_t *data_copy = scan_dup_bytes(data, data_len);
                if ((name_len != 0 && name_copy == NULL) ||
                    (data_len != 0 && data_copy == NULL)) {
                    free(name_copy);
                    free(data_copy);
                    if (name != NULL) vty_free(name, name_len != 0 ? name_len : 1u);
                    if (data != NULL) vty_free(data, data_len != 0 ? data_len : 1u);
                    *out_count = count;
                    if (out_failed_count != NULL) *out_failed_count = failed;
                    return VERTHYS_ERR_INTERNAL;
                }
                if (name != NULL) vty_free(name, name_len != 0 ? name_len : 1u);
                if (data != NULL) vty_free(data, data_len != 0 ? data_len : 1u);

                out_lids[count] = leaf.record_id;
                out_records[count].type = (VerthysRecordType)(inline_data ? rec.type : 0);
                out_records[count].name = (const char *)name_copy;
                out_records[count].name_len = name_len;
                out_records[count].data = data_copy;
                out_records[count].data_len = data_len;
                batch_bytes += (uint64_t)name_len + (uint64_t)data_len;
                count++;
            }
        }

        if (cursor->max_batch_bytes > 0 && batch_bytes > cursor->max_batch_bytes) break;
    }

    *out_count = count;
    if (out_failed_count != NULL) *out_failed_count = failed;
    return VERTHYS_OK;
}

static VerthysResult scan_summary_fetch(VerthysScanCursor *cursor,
                                           VerthysSummaryRecord *out_records,
                                           uint64_t *out_lids,
                                           uint64_t max_count,
                                           uint64_t *out_count)
{
    uint64_t count = 0;

    if (!scan_alive(cursor)) {
        cursor->invalidated = 1;
        return VERTHYS_ERR_LOCKED;
    }
    *out_count = 0;
    if (cursor->exhausted || max_count == 0) return VERTHYS_OK;

    while (count < max_count) {
        VtyRepoLeaf leaf;
        uint8_t *name = NULL;
        size_t name_len = 0;
        int done = 0;
        int rc;

        rc = vty_repo_iter_next(cursor->vault_iter, &leaf, &done);
        if (rc != VTY_OK) return verthys_api_container_map(rc);
        if (done) { cursor->exhausted = 1; break; }
        if (leaf.record_id < cursor->start_lid) continue;

        rc = vty_repo_read_name(cursor->vault_owner, &leaf, &name, &name_len);
        if (rc != VTY_OK) {
            /* 单条不可读（模块未解锁 / 记录段损坏）不得中止整个摘要扫描：
             * 摘要只负责名称与索引元数据，类型由类型盲索引提供。跳过名称
             * 解密但保留 lid/大小/偏移/哈希，列表仍能靠 ID 渲染并由按需
             * 解密补齐名称。 */
            name = NULL;
            name_len = 0;
            rc = VTY_OK;
        }
        /* 空名称在记录层带 1 字节占位分配；摘要输出用 NULL/0 表示
         * （释放接口按 name_len>0 判定）。 */
        if (name_len == 0 && name != NULL) {
            vty_free(name, 1u);
            name = NULL;
        }

        out_lids[count] = leaf.record_id;
        out_records[count].lid = leaf.record_id;
        /* 摘要不读数据：类型在记录密文内（首字节），不可在不解密数据
         * 的前提下得出；如实返回未知类型，而不是猜测。 */
        out_records[count].type = 0;
        out_records[count].name = (const char *)name;
        out_records[count].name_len = name_len;
        out_records[count].data_size = leaf.plain_size;
        out_records[count].physical_offset = leaf.data_offset;
        memcpy(out_records[count].merkle_leaf, leaf.data_hash,
               sizeof(out_records[count].merkle_leaf));
        out_records[count].created_time = leaf.created_time;
        out_records[count].slot_state = VERTHYS_SLOT_VALID;
        count++;
    }

    *out_count = count;
    return VERTHYS_OK;
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：打开全量解密扫描游标                                   *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanOpen(VerthysHandle handle,
                           uint64_t start_lid,
                           uint64_t batch_size,
                           VerthysScanCursor **out_cursor)
{
    /* 既有入口语义保持：FULL 投影、无内联阈值、无取批预算 */
    return Verthys_ScanOpenEx(handle, start_lid, batch_size,
                              VERTHYS_SCAN_PROJECT_FULL, 0, 0, out_cursor);
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：打开带投影与取批预算的扫描游标                         *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanOpenEx(VerthysHandle handle,
                           uint64_t start_lid,
                           uint64_t batch_size,
                           VerthysScanProject project,
                           uint64_t index_inline_max_bytes,
                           uint64_t max_batch_bytes,
                           VerthysScanCursor **out_cursor)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL || out_cursor == NULL) return VERTHYS_ERR_INVALID;

    /* 投影取值白名单：未知投影拒绝，避免调用方以为拿到索引却得到未定义行为 */
    if (project != VERTHYS_SCAN_PROJECT_FULL &&
        project != VERTHYS_SCAN_PROJECT_INDEX) {
        return VERTHYS_ERR_INVALID;
    }

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 非容器格式一律拒绝（无扫描语义） */
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 全局应急安全机制触发时拒绝创建游标 */
    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 共享锁覆盖：会话实例解引用（并发 Lock 换实例的 TOCTOU）+
     * 目录叶快照打开。锁内单出口，与写路径（独占锁）互斥。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    /* 统计全量解密扫描调用次数，用于监控不合理调用场景：
     * 列表渲染应使用索引投影或仅元数据的摘要扫描接口，FULL 投影才是
     * "为读索引而解密全部数据"的不合理调用（原子递增——共享锁允许多个
     * 扫描并发，计数不丢失） */
    if (project == VERTHYS_SCAN_PROJECT_FULL) {
#ifdef _WIN32
        InterlockedIncrement64((LONG64 *)&ctx->diag_scan_open_count);
#else
        ctx->diag_scan_open_count++;
#endif
#ifdef _WIN32
        /* 仅首次打开时告警一次：全量解密扫描的代价与记录体积成正比，
         * 列表/索引场景应改用索引投影或摘要扫描；累计次数由诊断计数器
         * 承担，重复告警只会淹没诊断通道。 */
        if (ctx->diag_scan_open_count == 1) {
            VERTHYS_DIAG_LOG("[VERTHYS] WARNING: full (decrypt-all) scan opened; "
                             "index/list rendering should use index projection or summary scan");
        }
#endif
    }

    rc = scan_open(ctx, start_lid, batch_size,
                      (uint32_t)project, index_inline_max_bytes,
                      max_batch_bytes, "scan_cursor", out_cursor);

#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return rc;
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：批量拉取完整解密记录数据                               *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanFetch(VerthysScanCursor *cursor,
                            VerthysRecord *out_records,
                            uint64_t *out_lids,
                            uint64_t max_count,
                            uint64_t *out_count,
                            uint64_t *out_failed_lids,
                            uint64_t *out_failed_count)
{
    VerthysResult rc;
    struct VerthysContext *ctx;

    if (cursor == NULL || out_records == NULL || out_lids == NULL || out_count == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    *out_count = 0;
    if (out_failed_count != NULL) *out_failed_count = 0;

    /* 熔断状态检测，已作废游标或全局应急触发直接终止 */
    if (cursor->invalidated || emergency_is_triggered()) {
        cursor->invalidated = 1;
        return VERTHYS_ERR_LOCKED;
    }

    /* 共享锁覆盖核心读路径：记录段解密 + 目录叶游标推进 +
     * 实例存活性检测（并发 Lock 换实例的 TOCTOU）。锁内单出口。 */
    ctx = cursor->vault_ctx;
#ifdef _WIN32
    if (ctx != NULL && ctx->api_mutex != NULL) {
        AcquireSRWLockShared(ctx->api_mutex);
    }
#endif
    if (cursor->vault_owner != NULL) {
        rc = scan_fetch(cursor, out_records, out_lids, max_count,
                           out_count, out_failed_lids, out_failed_count);
    } else {
        rc = VERTHYS_ERR_FORMAT;
    }
#ifdef _WIN32
    if (ctx != NULL && ctx->api_mutex != NULL) {
        ReleaseSRWLockShared(ctx->api_mutex);
    }
#endif
    return rc;
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：安全释放批量扫描深拷贝记录内存                          *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanRecordFree(VerthysRecord *record)
{
    if (record == NULL) return VERTHYS_ERR_INVALID;

    /* 名称缓冲区先安全多轮字节擦除再释放堆内存 */
    if (record->name != NULL && record->name_len > 0) {
        memory_guard_secure_zero((void *)record->name, record->name_len);
        free((void *)record->name);
        record->name     = NULL;
        record->name_len = 0;
    }

    /* 二进制数据缓冲区安全擦除释放 */
    if (record->data != NULL && record->data_len > 0) {
        memory_guard_secure_zero((void *)record->data, record->data_len);
        free((void *)record->data);
        record->data     = NULL;
        record->data_len = 0;
    }

    return VERTHYS_OK;
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：关闭并销毁扫描游标，回收所有附属资源                    *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanClose(VerthysScanCursor *cursor)
{
    if (cursor == NULL) return VERTHYS_ERR_INVALID;

    /* 先释放 目录叶游标快照迭代器，再清零游标本身 */
    if (cursor->vault_iter != NULL) {
        vty_repo_iter_close(cursor->vault_iter);
        cursor->vault_iter = NULL;
    }

    /* 从内存防护管理器注销注册 */
    memory_guard_unregister(cursor);

    /* 解除虚拟内存页锁定 */
    if (cursor->mem_locked) {
        verthys_unlock_memory(cursor, sizeof(*cursor));
    }

    /* 游标结构体内存安全覆写清零后释放 */
    memory_guard_secure_zero(cursor, sizeof(*cursor));
    free(cursor);

    return VERTHYS_OK;
}

/* ================================================================== *
 * 轻量摘要扫描子模块（仅读取索引元数据，不加载解密实际文件数据块）      *
 *
 * 与全量扫描核心差异：
 * 1. 游标创建逻辑完全复用同一套 LSM 快照迭代器骨架，仅Fetch拉取实现不同
 * 2. 仅读取 LSM 条目元数据 + Extent 索引内存回查，不触发数据块 IO 与
 *    解密函数，遍历性能大幅提升
 * 3. 仅拷贝名称字符串做堆深拷贝，其余数值字段直接赋值，内存开销极低
 * 4. 槽位状态完整透传给上层，用于前端区分正常、待回收、写入中条目展示样式
 * ================================================================== */

/* ------------------------------------------------------------------ *
 * 对外导出接口：打开摘要轻量扫描游标                                    *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanSummaryOpen(VerthysHandle handle,
                                   uint64_t start_lid,
                                   uint64_t batch_size,
                                   VerthysScanCursor **out_cursor)
{
    struct VerthysContext *ctx;

    if (handle == NULL || out_cursor == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 共享锁覆盖：实例解引用（并发 Lock 换实例的 TOCTOU）+
     * 目录叶快照打开（与 Verthys_ScanOpen 同一纪律，锁内单出口）。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
    /* 摘要/全量差异仅在 Fetch 路径：元数据直读 vs 记录段解密。
     * 摘要只解密名称，不读数据段。 */
    {
        VerthysResult rc;
        rc = scan_open(ctx, start_lid, batch_size,
                          VERTHYS_SCAN_PROJECT_FULL, 0, 0,
                          "scan_summary_cursor", out_cursor);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc;
    }
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：批量拉取摘要元数据记录，不解密文件实体数据              *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanSummaryFetch(VerthysScanCursor *cursor,
                                    VerthysSummaryRecord *out_records,
                                    uint64_t *out_lids,
                                    uint64_t max_count,
                                    uint64_t *out_count)
{
    if (cursor == NULL || out_records == NULL || out_lids == NULL || out_count == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    *out_count = 0;

    /* 应急熔断校验 */
    if (cursor->invalidated || emergency_is_triggered()) {
        cursor->invalidated = 1;
        return VERTHYS_ERR_LOCKED;
    }

    /* 共享锁覆盖核心读路径：目录叶游标推进 + 实例存活性检测。
     * 与 Verthys_ScanFetch 同一纪律，锁内单出口。 */
    {
        struct VerthysContext *ctx = cursor->vault_ctx;
        VerthysResult rc;
#ifdef _WIN32
        if (ctx != NULL && ctx->api_mutex != NULL) {
            AcquireSRWLockShared(ctx->api_mutex);
        }
#endif
        rc = (cursor->vault_owner != NULL)
            ? scan_summary_fetch(cursor, out_records, out_lids,
                                    max_count, out_count)
            : VERTHYS_ERR_FORMAT;
#ifdef _WIN32
        if (ctx != NULL && ctx->api_mutex != NULL) {
            ReleaseSRWLockShared(ctx->api_mutex);
        }
#endif
        return rc;
    }
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：释放摘要记录深拷贝名称内存                              *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanSummaryRecordFree(VerthysSummaryRecord *record)
{
    if (record == NULL) return VERTHYS_ERR_INVALID;

    /* 名称缓冲区安全擦除后释放 */
    if (record->name != NULL && record->name_len > 0) {
        memory_guard_secure_zero((void *)record->name, record->name_len);
        free((void *)record->name);
        record->name     = NULL;
        record->name_len = 0;
    }

    /* Merkle哈希数组做一致性清零处理 */
    memory_guard_secure_zero(record->merkle_leaf, sizeof(record->merkle_leaf));

    return VERTHYS_OK;
}

/* ------------------------------------------------------------------ *
 * 轻量级记录类型存在性检查                                             *
 *                                                                    *
 * LSM 快照迭代器仅检查 type 字段，不分配 name 堆内存，不访问数据区块。  *
 *                                                                    *
 * 相比 ScanSummaryOpen+Fetch 循环：                                    *
 *   - 消除多次 IPC 往返开销（C 层一次调用完成）                        *
 *   - 消除 name 字符串堆分配/释放开销                                  *
 *   - 消除 VerthysSummaryRecord 结构体拷贝开销                           *
 *   - 找到匹配即早停返回（无需遍历全部记录）                            *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_HasRecordByType(VerthysHandle handle,
                                   uint8_t rtype,
                                   uint8_t *out_found)
{
    struct VerthysContext *ctx;

    if (handle == NULL || out_found == NULL) return VERTHYS_ERR_INVALID;

    *out_found = 0;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    if (ctx->vault == NULL || !ctx->vault->unlocked || ctx->vault->store == NULL) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 应急熔断校验 */
    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 共享锁覆盖：类型索引游标 + 实例解引用。
     * 锁内单出口，与写路径互斥。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
    {
        VerthysResult rc;
        rc = verthys_api_container_map(
            vty_repo_find_by_type(ctx->vault, rtype, out_found, NULL));
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc;
    }
}

/* ------------------------------------------------------------------ *
 * 按类型查找首条记录的逻辑 ID（lid）                                   *
 *                                                                    *
 * 与 Verthys_HasRecordByType 的关键差异：                                *
 *   同时返回 found 标志与匹配记录的 lid（单次遍历，轻量探测无解密 IO）  *
 *                                                                    *
 * 历史背景：unlock 后 UI 卡死根因为早期容器调用                         *
 * Verthys_HasRecordByType 返回 VERTHYS_ERR_FORMAT → 前端 probe 抛异常 →   *
 * 进异步确认 loading 视图 → viewMode 永久卡 "loading"。本函数将       *
 * "是否存在全局密钥记录 + lid"下沉到 worker 进程内执行，彻底消除      *
 * unlock 后 probe IPC 链。未找到返回 VERTHYS_OK + out_found=0          *
 * （不报 FORMAT，避免前端 probe 抛异常）。                            *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_FindFirstLidByType(VerthysHandle handle,
                                     uint8_t rtype,
                                     uint8_t *out_found,
                                     uint64_t *out_lid)
{
    struct VerthysContext *ctx;

    if (handle == NULL || out_found == NULL || out_lid == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    *out_found = 0;
    *out_lid   = 0;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 应急熔断校验 */
    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    if (ctx->vault == NULL || !ctx->vault->unlocked || ctx->vault->store == NULL) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 共享锁覆盖：类型索引游标 + 实例解引用
     * （与 Verthys_HasRecordByType 同一纪律，锁内单出口）。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
    {
        VerthysResult rc;
        rc = verthys_api_container_map(
            vty_repo_find_by_type(ctx->vault, rtype, out_found, out_lid));
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc;
    }
}

/* ------------------------------------------------------------------ *
 * 按类型分页枚举记录 ID（类型盲索引，API 版本 0x0012）
 *
 * 为什么不复用摘要扫描：摘要不读记录密文，type 恒为未知 0；
 * 业务类型在写入时已进入 VTY_KS_TYPE 盲索引，枚举该索引既准确
 * 又不需要解密记录段，且对历史 容器天然兼容。
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ListIdsByType(VerthysHandle handle,
                                    uint8_t rtype,
                                    uint64_t after_id,
                                    uint64_t max_count,
                                    uint64_t *out_ids,
                                    uint64_t *out_count,
                                    uint8_t *out_exhausted)
{
    struct VerthysContext *ctx;

    if (handle == NULL || out_ids == NULL || out_count == NULL ||
        out_exhausted == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    *out_count = 0;
    *out_exhausted = 1;
    if (max_count == 0u || max_count > VERTHYS_TYPE_ID_BATCH_MAX) {
        return VERTHYS_ERR_INVALID;
    }
    if (after_id == UINT64_MAX) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (emergency_is_triggered()) return VERTHYS_ERR_LOCKED;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;
    if (ctx->vault == NULL || !ctx->vault->unlocked || ctx->vault->store == NULL) {
        return VERTHYS_ERR_LOCKED;
    }

#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
    {
        /* 锁内复检会话存活性：检查与取锁之间可能发生 Lock/Deinit 或应急
         * 熔断，ctx->vault 会被释放；在共享锁下重新读取实例再调用，避免把
         * 已释放的 VtyVault 交给仓库层（UAF）。 */
        VtyVault *vault = (ctx->state == VERTHYS_STATE_UNLOCKED &&
                        ctx->fmt_version == VERTHYS_FMT_CONTAINER)
            ? ctx->vault : NULL;
        VerthysResult rc;
        if (emergency_is_triggered() || vault == NULL ||
            !vault->unlocked || vault->store == NULL) {
            rc = VERTHYS_ERR_LOCKED;
        } else {
            rc = verthys_api_container_map(
                vty_repo_list_ids_by_type(vault, rtype, after_id, max_count,
                                          out_ids, out_count, out_exhausted));
        }
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc;
    }
}
