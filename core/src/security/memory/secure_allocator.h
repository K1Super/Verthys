/*
 * secure_allocator.h — 密钥相关结构专用安全分配器 + 全局内存预算记账
 *
 * 设计依据：
 *   - docs/PERFORMANCE_ARCHITECTURE.md §4.1（内存预算：512MB 硬上限，
 *     80% 触发回收，95% 拒绝新操作返回 VERTHYS_ERR_RESOURCE_LIMIT）
 *   - docs/PERFORMANCE_ARCHITECTURE.md §4.2（安全分配器：VirtualAlloc 区段
 *     + PAGE_GUARD 边界页 + VirtualLock 锁页 + 释放前清零 + 元数据独立存储）
 *   - docs/TARGET_ARCHITECTURE_V5.md §5.2（VerthysContext 挂 SecureAllocator*）
 *   - docs/V3_UPGRADE_PLAYBOOK.md WP-7
 *
 * 威胁模型（安全设计规则）：
 *   1. 堆相邻溢出读写：密钥材料不在普通堆上与业务数据混布——每次分配
 *      独立 VirtualAlloc 区段，前后各一页 PAGE_NOACCESS 边界页，
 *      越界访问立即触发访问违例（永久语义，可观测、可测试。
 *      实现注记：PAGE_GUARD 修饰符与 PAGE_NOACCESS 互斥（gle=87），
 *      且 READONLY|GUARD 为一次性触发后转可读；纯 NOACCESS 每次访问
 *      均违例，安全性严格强于一次性 GUARD 页）；
 *   2. 换出残留（磁盘取证）：数据页 VirtualLock 锁定于物理内存；
 *   3. 释放后残留：释放前 SecureZeroMemory 清零，随后 VirtualFree 归还
 *      内核（页表项销毁，零页合并前物理页已被覆写清零）；
 *   4. 元数据伪造/溢出改写：分配元数据（基址/长度/魔数）存于独立普通堆
 *      注册表，与安全区段物理隔离，边界页不保护它，但元数据被毁仅导致
 *      该分配不可释放（DoS），不会泄露密钥材料。
 *
 * 并发模型：
 *   - 全局预算计数：Interlocked 64 位原子加减（多 ctx 并发安全）；
 *   - 实例注册表：SRWLOCK 独占写/共享读；
 *   - 回收回调在锁外同步调用（调用方线程），回调内禁止再进入本模块
 *     （防递归死锁——契约级约束）。
 */
#ifndef VERTHYS_SECURE_ALLOCATOR_H
#define VERTHYS_SECURE_ALLOCATOR_H

#include <stdint.h>
#include <stddef.h>
#include "verthys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 全局内存预算（性能架构 §4.1） ---------- */

/* DLL 内部总内存硬上限默认值：512MB（可配置，见 budget_init） */
#define SECURE_ALLOC_DEFAULT_BUDGET_BYTES ((size_t)512u * 1024u * 1024u)

/* 预算阈值（百分比）：
 *   ≥ RECLAIM_PCT（80%）：触发回收回调（清缓存/刷 MemTable 等）；
 *   ≥ REJECT_PCT（95%）：拒绝新分配，返回 VERTHYS_ERR_RESOURCE_LIMIT。 */
#define SECURE_ALLOC_RECLAIM_PCT 80u
#define SECURE_ALLOC_REJECT_PCT  95u

/*
 * 内存回收回调：用量首次达到预算 80% 时触发一次（用量回落至 80% 以下
 * 重新武装）。在触发 alloc 的调用线程内同步执行——回调内禁止调用本模块
 * 任何接口（防递归）。
 *   user_ctx      : budget_init 注册的用户上下文
 *   current_bytes : 当前全局用量
 *   budget_bytes  : 当前预算上限
 */
typedef void (*SecureAllocatorReclaimFn)(void *user_ctx,
                                         size_t current_bytes,
                                         size_t budget_bytes);

/*
 * 配置进程级全局预算与回收回调（Verthys_Init 时机调用一次）。
 * budget_bytes 为 0 时采用默认 512MB；reclaim_fn 可为 NULL（不回收）。
 * 重复调用：更新预算与回调（运行时已用量保持不变；新预算小于当前用量
 * 时后续分配直接按 95% 拒绝规则处理）。
 */
VerthysResult secure_allocator_budget_init(size_t budget_bytes,
                                         SecureAllocatorReclaimFn reclaim_fn,
                                         void *reclaim_ctx);

/* 当前全局用量（字节，原子读取） */
size_t secure_allocator_budget_usage(void);

/* 当前预算上限（字节） */
size_t secure_allocator_budget_limit(void);

/* 回调累计触发次数（诊断/测试观测） */
uint32_t secure_allocator_budget_reclaim_count(void);

/* ---------- 隔离堆分配器（每 VerthysContext 实例） ---------- */

/*
 * 创建分配器实例（内部注册表为空）。失败返回 NULL。
 * 单个实例非线程安全面向注册表读侧（统计查询），alloc/free 内部以
 * SRWLOCK 串行化——多线程并发 alloc/free 安全。
 */
typedef struct SecureAllocator SecureAllocator;

SecureAllocator *secure_allocator_create(void);

/*
 * 销毁分配器：全部活跃区段清零 + 解锁 + 释放，注册表与实例一并销毁。
 * 幂等：NULL 直接返回。
 */
void secure_allocator_destroy(SecureAllocator *alloc);

/*
 * 安全分配：
 *   布局 [边界页 PAGE_NOACCESS][数据页 RW+VirtualLock][边界页 NOACCESS]
 *   out_ptr 返回数据页基址（页对齐）；size 向上取整到页粒度。
 * 失败路径：
 *   VERTHYS_ERR_INVALID       — 参数非法 / size 为 0 / 溢出
 *   VERTHYS_ERR_RESOURCE_LIMIT— 预算 95% 拒绝
 *   VERTHYS_ERR_INTERNAL      — VirtualAlloc/VirtualProtect/VirtualLock 失败
 * 成功后全局用量按（数据页 + 边界页）提交字节数累加。
 */
VerthysResult secure_allocator_alloc(SecureAllocator *alloc, size_t size,
                                   void **out_ptr);

/*
 * 安全释放：数据页 SecureZeroMemory → VirtualUnlock → VirtualFree，
 * 全局用量原子递减，注册表条目移除。
 *   VERTHYS_ERR_INVALID — 参数非法 / 指针非本分配器数据页基址（含魔数
 *   校验失败——元数据独立存储，双重防伪造）。
 */
VerthysResult secure_allocator_free(SecureAllocator *alloc, void *ptr);

/* ---------- 可观测性统计 ---------- */

typedef struct SecureAllocatorStats {
    size_t   live_bytes;      /* 活跃数据页字节数（不含边界页） */
    size_t   live_count;      /* 活跃分配数 */
    uint64_t total_allocs;    /* 累计分配成功次数 */
    uint64_t total_frees;     /* 累计释放成功次数 */
    uint32_t lock_failures;   /* VirtualLock 失败次数（诊断） */
} SecureAllocatorStats;

/* 填充统计快照（out 为 NULL 时无操作） */
void secure_allocator_get_stats(const SecureAllocator *alloc,
                                SecureAllocatorStats *out);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_SECURE_ALLOCATOR_H */
