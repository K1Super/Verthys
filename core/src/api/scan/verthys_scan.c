/*
 * verthys_scan.c — 游标式批量数据扫描底层实现模块（V3-only）
 *
 * ★ §1.4 V2 退役重写：数据通路统一为 LSM 全量快照迭代器 + Extent
 * 内核态按需解密（原 v2 B+ 树叶子链表遍历路径随 §1.4 删除清单退役）。
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
/* V3 扫描游标（LSM 快照迭代器 + Extent 解密）。
 * verthys_v3_lifecycle.h 传递包含 verthys_lsm.h（scan_open/next/close）/
 * verthys_extent.h（extent_get / extent_index_find）/ VerthysContextV3 全套接口。 */
#include "verthys_v3_lifecycle.h"

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
 * 扫描游标内部结构体定义（V3-only）                                    *
 * ------------------------------------------------------------------ */
struct VerthysScanCursor {
    uint64_t            start_lid;       /* 遍历起始逻辑记录ID（迭代器 lid 升序，
                                            Fetch 中过滤 < start_lid 的条目） */
    uint64_t            batch_size;      /* 单次批量拉取建议条数 */
    int                 exhausted;       /* 全局遍历完成标记，置1后不再继续读取数据 */

    /* 安全管控状态字段 */
    int                 mem_locked;      /* 标记游标结构体内存是否已执行页锁定 */
    int                 invalidated;     /* 标记游标是否被应急熔断机制强制作废 */

    /* === V3 LSM 快照迭代上下文 === */
    VerthysLsmScanIter   *v3_iter;          /* LSM 全量快照迭代器（open 时深拷贝，
                                             并发 put/flush/compaction 不影响，
                                             快照隔离由 LSM 结构性保证） */
    struct VerthysContext *v3_ctx;          /* 借用：VerthysContext（Fetch 时经
                                             ctx->v3 取 f/ext_idx/extent 分区） */
    VerthysContextV3     *v3_owner;         /* 借用实例身份锚点：容器 Lock/再解锁
                                             后 ctx->v3 更换实例 → 本游标即刻
                                             失效（借用的 f/分区不可再用） */
};

/* ------------------------------------------------------------------ *
 * V3 扫描游标辅助段                                                    *
 *                                                                    *
 * 数据通路：VerthysLsmScanIter（lid 升序全量快照——open 时深拷贝        *
 * MemTable 编码流 + SSTable 元数据/块迭代器，跨层归并去重 + 墓碑     *
 * 跳过）→ ScanFetch 经 verthys_extent_get 内核态解密（AEAD + BLAKE2b  *
 * 双重校验）→ 深拷贝输出（借用契约，调用方 ScanRecordFree 释放）。   *
 *                                                                    *
 * 实例身份锚点（v3_owner）：容器 Lock/再解锁后 ctx->v3 更换堆实例，   *
 * 游标借用的 f/分区/索引即刻悬挂——Fetch 入口经 scan_v3_alive 检测    *
 * 实例一致性，失配即作废游标（invalidated），杜绝悬挂引用解引用。    *
 *                                                                    *
 * 并发纪律：游标生命周期内禁止并发 Lock/容器循环；迭代器内部逐条持   *
 * lsm 独占锁推进（vio_pread64 定位互斥），长扫描不阻塞写者。应急熔断：*
 * Fetch 入口 emergency_is_triggered 检测 + 游标结构体托管内存防护     *
 * 管理器（紧急清零后 Fetch 拒绝服务）。                              *
 * ------------------------------------------------------------------ */

/*
 * V3 游标存活性校验：容器实例未循环（ctx->v3 == v3_owner）且子系统
 * 在位。0 = 存活可继续；非 0 = 已失效（调用方置 invalidated 并拒绝）。
 */
static int scan_v3_alive(const VerthysScanCursor *cursor)
{
    const struct VerthysContext *ctx;

    if (cursor == NULL) return 0;
    ctx = cursor->v3_ctx;
    return ctx != NULL &&
           ctx->fmt_version == VERTHYS_FMT_V3 &&
           ctx->v3 != NULL &&
           ctx->v3 == cursor->v3_owner &&
           ctx->v3->subsystems_open;
}

/*
 * V3 游标创建（ScanOpen / ScanSummaryOpen 共用骨架）：
 * 分配 + LSM 快照迭代器打开 + 内存防护三件套（页锁定 / 内存防护
 * 管理器注册 / 零初始化）。
 * label 传入内存防护注册标识（区分全量/摘要游标）。
 */
static VerthysResult scan_v3_open(struct VerthysContext *ctx,
                                uint64_t start_lid,
                                uint64_t batch_size,
                                const char *guard_label,
                                VerthysScanCursor **out_cursor)
{
    VerthysScanCursor *cursor = NULL;
    VerthysResult rc;

    *out_cursor = NULL;

    if (ctx->v3 == NULL || !ctx->v3->subsystems_open) return VERTHYS_ERR_LOCKED;

    cursor = (VerthysScanCursor *)calloc(1, sizeof(VerthysScanCursor));
    if (cursor == NULL) return VERTHYS_ERR_INTERNAL;

    cursor->v3_ctx     = ctx;
    cursor->v3_owner   = ctx->v3;
    cursor->start_lid  = start_lid;
    cursor->batch_size = (batch_size > 0) ? batch_size : 500;
    cursor->exhausted  = 0;
    cursor->invalidated = 0;

    rc = verthys_lsm_scan_open(ctx->v3->lsm, &cursor->v3_iter);
    if (rc != VERTHYS_OK) {
        free(cursor);
        return rc;
    }

    /* 内存页锁定，避免游标结构体被交换至磁盘文件 */
    if (verthys_lock_memory(cursor, sizeof(*cursor)) == 0) {
        cursor->mem_locked = 1;
    }

    /* 注册至内存防护管理器，紧急清零时自动覆写游标内存 */
    memory_guard_register(cursor, sizeof(*cursor), guard_label);

    *out_cursor = cursor;
    return VERTHYS_OK;
}

/*
 * V3 全量拉取（ScanFetch 路径）：
 * LSM 快照迭代器逐条（lid 升序，墓碑已被迭代器跳过）→ start_lid 定位
 * → 有效槽位过滤 → Extent 内核态解密（AEAD + BLAKE2b 双重完整性）→
 * 深拷贝输出（借用契约，调用方 ScanRecordFree 释放）。
 *
 * 失败语义：单条解密/索引不变量背离不中止整体扫描，记入 failed
 * 清单输出 lid（上层可做损坏条目提示与修复）；迭代器自身损坏
 * （INTERNAL）为不可恢复错误，直接上抛。
 */
static VerthysResult scan_v3_fetch(VerthysScanCursor *cursor,
                                 VerthysRecord *out_records,
                                 uint64_t *out_lids,
                                 uint64_t max_count,
                                 uint64_t *out_count,
                                 uint64_t *out_failed_lids,
                                 uint64_t *out_failed_count)
{
    VerthysContextV3 *v;
    VerthysLsmEntry e;
    uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
    uint64_t count = 0;
    uint64_t failed = 0;
    size_t name_len = 0;
    VerthysResult rc;

    /* 实例存活性：容器 Lock/再解锁后 ctx->v3 更换实例 → 游标即刻作废 */
    if (!scan_v3_alive(cursor)) {
        cursor->invalidated = 1;
        return VERTHYS_ERR_LOCKED;
    }
    v = cursor->v3_ctx->v3;

    if (cursor->exhausted || max_count == 0) {
        *out_count = 0;
        if (out_failed_count != NULL) *out_failed_count = 0;
        return VERTHYS_OK;
    }

    while (count < max_count) {
        uint8_t *data;
        uint8_t *name = NULL;
        size_t cap;

        rc = verthys_lsm_scan_next(cursor->v3_iter, &e, name_buf,
                                 sizeof(name_buf), &name_len);
        if (rc == VERTHYS_ERR_NOTFOUND) {
            cursor->exhausted = 1;
            break;
        }
        if (rc != VERTHYS_OK) {
            /* INTERNAL：迭代器失效（块解码失败等），后续 Fetch 持续同错 */
            *out_count = count;
            if (out_failed_count != NULL) *out_failed_count = failed;
            return rc;
        }

        /* start_lid 定位（迭代器 lid 升序）：未达起始点条目直接跳过 */
        if (e.lid < cursor->start_lid) continue;

        /* 仅读取有效槽位（跳过空闲/待回收/写入中/损坏） */
        if (e.slot_state != VERTHYS_SLOT_VALID) continue;

        /* 索引不变量（与 verthys_api_v3_get 同源）：Extent 明文长度 ==
         * 记录数据长度；背离 = LSM/Extent 索引交叉损坏 → 记入 failed */
        if (e.data_size != (uint64_t)e.plaintext_size) {
            if (out_failed_lids != NULL && failed < max_count) {
                out_failed_lids[failed] = e.lid;
            }
            failed++;
            continue;
        }

        /* Extent 解密缓冲（契约要求 pt 非 NULL：空数据走 1 字节哑缓冲，
         * 成功后清零丢弃，输出 data=NULL / data_len=0） */
        cap = (e.plaintext_size > 0) ? (size_t)e.plaintext_size : 1u;
        data = (uint8_t *)malloc(cap);
        if (data == NULL) {
            *out_count = count;
            if (out_failed_count != NULL) *out_failed_count = failed;
            return VERTHYS_ERR_INTERNAL;
        }

        rc = verthys_extent_get(v->f, v->txn.extent_part, v->ext_idx, e.hash,
                              data, &cap);
        if (rc != VERTHYS_OK || cap != (size_t)e.plaintext_size) {
            /* 解密失败（AUTH/CORRUPT/IO）或长度背离：failed 记账，扫描继续 */
            verthys_secure_zero(data, cap);
            free(data);
            if (out_failed_lids != NULL && failed < max_count) {
                out_failed_lids[failed] = e.lid;
            }
            failed++;
            continue;
        }

        /* 名称深拷贝（e.name/name_buf 为迭代器内借用缓冲，跨迭代复用） */
        if (e.name_len > 0) {
            name = (uint8_t *)malloc(e.name_len);
            if (name == NULL) {
                verthys_secure_zero(data, cap);
                free(data);
                *out_count = count;
                if (out_failed_count != NULL) *out_failed_count = failed;
                return VERTHYS_ERR_INTERNAL;
            }
            memcpy(name, name_buf, e.name_len);
        }

        out_lids[count]             = e.lid;
        out_records[count].type     = (VerthysRecordType)e.type;
        out_records[count].name     = (const char *)name;
        out_records[count].name_len = e.name_len;
        if (e.plaintext_size > 0) {
            out_records[count].data     = data;
            out_records[count].data_len = cap;
        } else {
            /* 空数据语义（与 verthys_api_v3_get 一致）：哑缓冲即刻回收 */
            verthys_secure_zero(data, cap);
            free(data);
            out_records[count].data     = NULL;
            out_records[count].data_len = 0;
        }
        count++;
    }

    *out_count = count;
    if (out_failed_count != NULL) *out_failed_count = failed;
    return VERTHYS_OK;
}

/*
 * V3 摘要拉取（ScanSummaryFetch 路径）：
 * 仅读取 LSM 条目元数据 + Extent 索引内存回查（无数据块 IO 与解密），
 * 遍历性能为内存索引直读级。
 *
 * 字段映射（语义对等）：
 *   - merkle_leaf   ← BLAKE2b-256 内容寻址哈希（单记录完整性锚点）
 *   - physical_offset ← Extent 分区数据区内绝对偏移（分区基址 +
 *                    索引帧区 + 条目数据区相对偏移）
 *   - slot_state    ← LSM 条目槽位状态原样透传（前端展示样式用）
 *
 * 交叉异常（LSM 有键但 Extent 索引无对应哈希）= 索引结构不一致，
 * 坦诚直报 INTERNAL，不静默填 0 掩盖数据损坏。
 */
static VerthysResult scan_v3_summary_fetch(VerthysScanCursor *cursor,
                                         VerthysSummaryRecord *out_records,
                                         uint64_t *out_lids,
                                         uint64_t max_count,
                                         uint64_t *out_count)
{
    VerthysContextV3 *v;
    VerthysLsmEntry e;
    uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
    uint64_t count = 0;
    size_t name_len = 0;
    VerthysResult rc;

    if (!scan_v3_alive(cursor)) {
        cursor->invalidated = 1;
        return VERTHYS_ERR_LOCKED;
    }
    v = cursor->v3_ctx->v3;

    if (cursor->exhausted || max_count == 0) {
        *out_count = 0;
        return VERTHYS_OK;
    }

    while (count < max_count) {
        uint8_t *name = NULL;
        VerthysExtent ext;

        rc = verthys_lsm_scan_next(cursor->v3_iter, &e, name_buf,
                                 sizeof(name_buf), &name_len);
        if (rc == VERTHYS_ERR_NOTFOUND) {
            cursor->exhausted = 1;
            break;
        }
        if (rc != VERTHYS_OK) {
            *out_count = count;
            return rc;
        }

        if (e.lid < cursor->start_lid) continue;

        /* 摘要透传全部非空闲槽位（待删除、写入中条目均返回并透传
         * 状态给前端展示；墓碑已被迭代器跳过） */
        if (e.slot_state == VERTHYS_SLOT_FREE) continue;

        /* 权威 Extent 索引回查：物理偏移定位（纯内存查找，无 IO）。
         * 去重命中时多条记录共用同一 Extent 条目（内容寻址语义） */
        rc = verthys_extent_index_find(v->ext_idx, e.hash, &ext);
        if (rc != VERTHYS_OK) {
            *out_count = count;
            return VERTHYS_ERR_INTERNAL;
        }

        if (e.name_len > 0) {
            name = (uint8_t *)malloc(e.name_len);
            if (name == NULL) {
                *out_count = count;
                return VERTHYS_ERR_INTERNAL;
            }
            memcpy(name, name_buf, e.name_len);
        }

        out_lids[count]                    = e.lid;
        out_records[count].lid             = e.lid;
        out_records[count].type            = e.type;
        out_records[count].name            = name;
        out_records[count].name_len        = e.name_len;
        out_records[count].data_size       = e.data_size;
        out_records[count].physical_offset = v->txn.extent_part->offset
                                           + VERTHYS_EXTENT_INDEX_REGION_BYTES
                                           + ext.offset;
        memcpy(out_records[count].merkle_leaf, e.hash, sizeof(e.hash));
        out_records[count].created_time    = e.created_time;
        out_records[count].slot_state      = e.slot_state;
        count++;
    }

    *out_count = count;
    return VERTHYS_OK;
}

/*
 * V3 按类型查找（HasRecordByType / FindFirstLidByType 共用骨架）：
 * LSM 快照迭代器全量扫描，type 匹配即早停（轻量路径：仅元数据读取，
 * 无数据块 IO 与解密，无 name 堆分配）。
 * out_lid 可为 NULL（仅存在性探测）。found=0 时 *out_lid 不变更。
 */
static VerthysResult scan_v3_find_by_type(struct VerthysContext *ctx,
                                         uint8_t rtype,
                                         uint8_t *out_found,
                                         uint64_t *out_lid)
{
    VerthysLsmScanIter *it = NULL;
    VerthysLsmEntry e;
    uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
    size_t name_len = 0;
    VerthysResult rc;

    *out_found = 0;

    rc = verthys_lsm_scan_open(ctx->v3->lsm, &it);
    if (rc != VERTHYS_OK) return rc;

    for (;;) {
        rc = verthys_lsm_scan_next(it, &e, name_buf, sizeof(name_buf), &name_len);
        if (rc == VERTHYS_ERR_NOTFOUND) {
            rc = VERTHYS_OK;    /* 全量遍历完成，未找到匹配类型 */
            break;
        }
        if (rc != VERTHYS_OK) break;

        /* 非空闲槽位均参与匹配（待回收/写入中条目仍存在） */
        if (e.slot_state == VERTHYS_SLOT_FREE) continue;

        if (e.type == rtype) {
            *out_found = 1;
            if (out_lid != NULL) *out_lid = e.lid;
            break;
        }
    }

    verthys_lsm_scan_close(it);
    return rc;
}

/* ------------------------------------------------------------------ *
 * 对外导出接口：打开全量解密扫描游标                                   *
 * ------------------------------------------------------------------ */
VerthysResult Verthys_ScanOpen(VerthysHandle handle,
                           uint64_t start_lid,
                           uint64_t batch_size,
                           VerthysScanCursor **out_cursor)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL || out_cursor == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* V3-only：非 V3 容器一律拒绝（VERTHYS_ERR_V3_REQUIRED 语义由
     * §1.4 删除清单自然实现——V1/V2 路径已退役） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

    /* 全局应急安全机制触发时拒绝创建游标 */
    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 统计全量解密扫描调用次数，用于监控不合理调用场景：
     * 列表渲染优先使用仅元数据的摘要扫描接口 */
    ctx->diag_scan_open_count++;
#ifdef _WIN32
    {
        char _warn[256];
        snprintf(_warn, sizeof(_warn),
                 "[VERTHYS] WARNING: Verthys_ScanOpen called (full-scan, v3). "
                 "List rendering should use Verthys_ScanSummaryOpen instead. "
                 "count=%llu",
                 (unsigned long long)ctx->diag_scan_open_count);
        VERTHYS_DIAG_LOG(_warn);
    }
#endif

    rc = scan_v3_open(ctx, start_lid, batch_size, "scan_cursor", out_cursor);
    if (rc != VERTHYS_OK) return rc;
    return VERTHYS_OK;
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

    /* LSM 快照迭代器 + Extent 解密路径（快照隔离由 LSM 结构性保证） */
    return scan_v3_fetch(cursor, out_records, out_lids, max_count,
                         out_count, out_failed_lids, out_failed_count);
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

    /* 先释放 LSM 快照迭代器堆实例（其借用 cursor 字段定位，必须先于
     * 游标内存清零与释放执行；幂等） */
    verthys_lsm_scan_close(cursor->v3_iter);
    cursor->v3_iter = NULL;

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

    /* V3-only：非 V3 容器一律拒绝（§1.4 V2 退役） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 与全量扫描共用 scan_v3_open 骨架；摘要/全量差异仅在 Fetch 路径
     * ——元数据直读 vs Extent 解密。guard_label 区分内存防护注册标识。 */
    return scan_v3_open(ctx, start_lid, batch_size,
                        "scan_summary_cursor", out_cursor);
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

    /* LSM 元数据直读路径（无解密开销，快照隔离由 LSM 结构性保证） */
    return scan_v3_summary_fetch(cursor, out_records, out_lids,
                                 max_count, out_count);
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

    /* V3-only：非 V3 容器一律拒绝（§1.4 V2 退役） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

    if (ctx->v3 == NULL || !ctx->v3->subsystems_open) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 应急熔断校验 */
    if (emergency_is_triggered()) {
        return VERTHYS_ERR_LOCKED;
    }

    return scan_v3_find_by_type(ctx, rtype, out_found, NULL);
}

/* ------------------------------------------------------------------ *
 * 按类型查找首条记录的逻辑 ID（lid）                                   *
 *                                                                    *
 * 与 Verthys_HasRecordByType 的关键差异：                                *
 *   同时返回 found 标志与匹配记录的 lid（单次遍历，轻量探测无解密 IO）  *
 *                                                                    *
 * 历史背景（v1 时代）：unlock 后 UI 卡死根因为 v1 容器调用             *
 * Verthys_HasRecordByType 返回 VERTHYS_ERR_FORMAT → 前端 probe 抛异常 →   *
 * 进异步确认 loading 视图 → viewMode 永久卡 "loading"。本函数将       *
 * "是否存在全局密钥记录 + lid"下沉到 worker 进程内执行，彻底消除      *
 * unlock 后 probe IPC 链。V3-only 时代语义保持：未找到返回 VERTHYS_OK    *
 * + out_found=0（不报 FORMAT，避免前端 probe 抛异常）。               *
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

    /* V3-only：非 V3 容器一律拒绝（§1.4 V2 退役） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

    if (ctx->v3 == NULL || !ctx->v3->subsystems_open) {
        return VERTHYS_ERR_LOCKED;
    }

    return scan_v3_find_by_type(ctx, rtype, out_found, out_lid);
}
