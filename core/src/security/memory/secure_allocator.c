/*
 * secure_allocator.c — 密钥相关结构专用安全分配器实现
 *
 * 区段布局（每次分配独立 VirtualAlloc 区段）：
 *
 *   基址 ──► ┌────────────────────────┐
 *            │  边界页 PAGE_NOACCESS   │ ← 前向溢出：每次访问均违例（永久）
 *            ├────────────────────────┤
 *            │  数据页 PAGE_READWRITE  │ ← VirtualLock 锁页（防换出）
 *            │  （size 向上取整到页）  │
 *            ├────────────────────────┤
 *            │  边界页 PAGE_NOACCESS   │ ← 后向溢出：每次访问均违例（永久）
 *            └────────────────────────┘
 *
 * 边界页实现注记：Windows 保护常量规定 PAGE_GUARD 修饰符不可与
 * PAGE_NOACCESS 组合（VirtualProtect 拒绝，gle=87）；而
 * PAGE_READONLY|PAGE_GUARD 为一次性触发后页面转为可读，不满足边界页
 * 永久违例的安全要求。故采用纯 PAGE_NOACCESS：每次越界访问均触发
 * ACCESS_VIOLATION，安全性严格强于一次性 GUARD 页。
 *
 * 元数据独立存储：区段地址/长度/魔数登记在分配器实例的普通堆注册表
 * （SRWLOCK 保护），与安全区段物理隔离。
 *
 * 全局预算（性能架构 §4.1）：全部实例的提交字节数（数据页+边界页）经
 * Interlocked 64 位原子累入进程级总量；≥80% 触发回收回调（跨阈值沿
 * 触发一次，回落重新武装）；≥95% 拒绝新分配（VERTHYS_ERR_RESOURCE_LIMIT）。
 */
#include "secure_allocator.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdlib.h>
#include <string.h>

/* ---------- 进程级全局预算状态 ---------- */

static volatile LONG64 s_budget_bytes    = (LONG64)SECURE_ALLOC_DEFAULT_BUDGET_BYTES;
static volatile LONG64 s_usage_bytes     = 0;
static volatile LONG  s_reclaim_count   = 0;
static volatile LONG  s_reclaim_armed   = 1;   /* 跨 80% 阈值沿触发一次 */
static SecureAllocatorReclaimFn s_reclaim_fn  = NULL;
static void                  *s_reclaim_ctx  = NULL;

/* ---------- 实例结构 ---------- */

/* 注册表条目：元数据与安全区段物理隔离（普通堆，SRWLOCK 保护） */
typedef struct SecureRegionMeta {
    void   *data_base;      /* 数据页基址（对外返回的指针） */
    void   *region_base;    /* VirtualAlloc 区段基址（前边界页起始） */
    size_t  data_bytes;     /* 数据页字节数（页对齐后） */
    size_t  region_bytes;   /* 整个区段提交字节数（含边界页，记账口径） */
    uint64_t magic;         /* 条目魔数（防注册表残余误配） */
} SecureRegionMeta;

struct SecureAllocator {
    SRWLOCK             lock;          /* 注册表独占写 / 统计共享读 */
    SecureRegionMeta   *regions;       /* 动态数组（普通堆，独立于安全区段） */
    size_t              region_count;
    size_t              region_cap;
    uint64_t            next_magic;    /* 单调魔数源 */
    /* 统计（lock 保护写；get_stats 持共享锁读） */
    uint64_t            total_allocs;
    uint64_t            total_frees;
    uint32_t            lock_failures;
};

/* 页粒度（进程首次使用时缓存） */
static DWORD s_page_size = 0;

static DWORD page_size(void)
{
    if (s_page_size == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        s_page_size = (si.dwPageSize > 0) ? si.dwPageSize : 4096u;
    }
    return s_page_size;
}

static size_t round_up_page(size_t n)
{
    DWORD ps = page_size();
    if (n == 0 || n > SIZE_MAX - ps) return 0;  /* 溢出守卫 */
    return ((n + ps - 1) / ps) * ps;
}

/* ---------- 全局预算接口 ---------- */

VerthysResult secure_allocator_budget_init(size_t budget_bytes,
                                         SecureAllocatorReclaimFn reclaim_fn,
                                         void *reclaim_ctx)
{
    if (budget_bytes == 0) budget_bytes = SECURE_ALLOC_DEFAULT_BUDGET_BYTES;
    if (budget_bytes > (size_t)INT64_MAX) return VERTHYS_ERR_INVALID;

    InterlockedExchange64(&s_budget_bytes, (LONG64)budget_bytes);
    s_reclaim_fn    = reclaim_fn;
    s_reclaim_ctx   = reclaim_ctx;
    /* 重新武装回收阈值沿（预算变更后允许立即再触发一次） */
    InterlockedExchange(&s_reclaim_armed, 1);
    return VERTHYS_OK;
}

size_t secure_allocator_budget_usage(void)
{
    return (size_t)InterlockedCompareExchange64(&s_usage_bytes, 0, 0);
}

size_t secure_allocator_budget_limit(void)
{
    return (size_t)InterlockedCompareExchange64(&s_budget_bytes, 0, 0);
}

uint32_t secure_allocator_budget_reclaim_count(void)
{
    return (uint32_t)InterlockedCompareExchange(&s_reclaim_count, 0, 0);
}

/*
 * 预算记账 + 阈值判定（alloc 成功路径调用）。
 * 返回 0 允许；非 0 = 应拒绝（VERTHYS_ERR_RESOURCE_LIMIT）。
 * 回收回调在预算累加之后、返回调用方之前同步触发（锁外语义由调用方
 * 保证——本函数仅被 alloc 在未持有实例锁时调用）。
 */
static int budget_account_and_check(size_t region_bytes)
{
    LONG64 budget = InterlockedCompareExchange64(&s_budget_bytes, 0, 0);
    LONG64 usage  = InterlockedAdd64(&s_usage_bytes, (LONG64)region_bytes);

    /* 95% 硬拒绝 */
    if (usage > (budget * (LONG64)SECURE_ALLOC_REJECT_PCT) / 100) {
        InterlockedAdd64(&s_usage_bytes, -(LONG64)region_bytes);
        return 1;
    }

    /* 80% 回收触发（跨阈值沿一次；回落至 80% 以下重新武装） */
    if (usage >= (budget * (LONG64)SECURE_ALLOC_RECLAIM_PCT) / 100) {
        if (InterlockedCompareExchange(&s_reclaim_armed, 0, 1) == 1) {
            InterlockedIncrement(&s_reclaim_count);
            if (s_reclaim_fn != NULL) {
                s_reclaim_fn(s_reclaim_ctx, (size_t)usage, (size_t)budget);
            }
        }
    } else {
        /* 回落区：武装标志置位（幂等） */
        InterlockedCompareExchange(&s_reclaim_armed, 1, 0);
    }
    return 0;
}

static void budget_unaccount(size_t region_bytes)
{
    LONG64 usage = InterlockedAdd64(&s_usage_bytes, -(LONG64)region_bytes);
    /* 用量回落至 80% 以下：重新武装回收阈值沿（否则 free 回落后再次
     * 分配将以单次原子累加直接跨过阈值线，无法观察到中间回落态，
     * 回收回调将永不重新触发）。 */
    LONG64 budget = InterlockedCompareExchange64(&s_budget_bytes, 0, 0);
    if (usage < (budget * (LONG64)SECURE_ALLOC_RECLAIM_PCT) / 100) {
        InterlockedCompareExchange(&s_reclaim_armed, 1, 0);
    }
}

/* ---------- 实例生命周期 ---------- */

SecureAllocator *secure_allocator_create(void)
{
    SecureAllocator *alloc = (SecureAllocator *)calloc(1, sizeof(*alloc));
    if (alloc == NULL) return NULL;
    InitializeSRWLock(&alloc->lock);
    alloc->next_magic = 0x9E3779B97F4A7C15ull;  /* 黄金分割常数种子 */
    return alloc;
}

/* 注册表容量倍增；返回 0 成功 */
static int regions_reserve(SecureAllocator *alloc, size_t need)
{
    if (need <= alloc->region_cap) return 0;
    size_t cap = (alloc->region_cap == 0) ? 8 : alloc->region_cap * 2;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) return -1;
        cap *= 2;
    }
    SecureRegionMeta *grown = (SecureRegionMeta *)realloc(
        alloc->regions, cap * sizeof(*grown));
    if (grown == NULL) return -1;
    alloc->regions  = grown;
    alloc->region_cap = cap;
    return 0;
}

/* 释放单个区段（清零 → 解锁 → 归还内核）。返回 0 成功。 */
static int region_release(SecureRegionMeta *meta)
{
    int ok = 1;
    if (meta == NULL || meta->region_base == NULL) return 0;

    if (meta->data_base != NULL && meta->data_bytes > 0) {
        SecureZeroMemory(meta->data_base, meta->data_bytes);
        VirtualUnlock(meta->data_base, meta->data_bytes);
    }
    if (!VirtualFree(meta->region_base, 0, MEM_RELEASE)) ok = 0;
    return ok;
}

void secure_allocator_destroy(SecureAllocator *alloc)
{
    if (alloc == NULL) return;

    AcquireSRWLockExclusive(&alloc->lock);
    for (size_t i = 0; i < alloc->region_count; i++) {
        if (region_release(&alloc->regions[i])) {
            budget_unaccount(alloc->regions[i].region_bytes);
        }
    }
    free(alloc->regions);
    alloc->regions      = NULL;
    alloc->region_count = 0;
    alloc->region_cap   = 0;
    ReleaseSRWLockExclusive(&alloc->lock);

    free(alloc);
}

/* ---------- 分配 / 释放 ---------- */

VerthysResult secure_allocator_alloc(SecureAllocator *alloc, size_t size,
                                   void **out_ptr)
{
    if (alloc == NULL || out_ptr == NULL || size == 0) return VERTHYS_ERR_INVALID;
    *out_ptr = NULL;

    DWORD ps = page_size();
    size_t data_bytes = round_up_page(size);
    if (data_bytes == 0) return VERTHYS_ERR_INVALID;

    /* 区段 = 前边界页 + 数据页 + 后边界页；溢出守卫 */
    if (data_bytes > SIZE_MAX - 2 * (size_t)ps) return VERTHYS_ERR_INVALID;
    size_t region_bytes = data_bytes + 2 * (size_t)ps;

    /* 预算 95% 预检（快速失败，避免无谓 VirtualAlloc） */
    {
        LONG64 budget = InterlockedCompareExchange64(&s_budget_bytes, 0, 0);
        LONG64 usage  = secure_allocator_budget_usage();
        if ((usage + (LONG64)region_bytes) >
            (budget * (LONG64)SECURE_ALLOC_REJECT_PCT) / 100) {
            return VERTHYS_ERR_RESOURCE_LIMIT;
        }
    }

    /* 1. 保留并提交整个区段为 NOACCESS */
    LPVOID region = VirtualAlloc(NULL, region_bytes,
                                 MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    if (region == NULL) {
        return VERTHYS_ERR_INTERNAL;
    }

    uint8_t *base = (uint8_t *)region;
    uint8_t *data = base + ps;

    /* 2. 数据页改 RW */
    DWORD old_prot = 0;
    if (!VirtualProtect(data, data_bytes, PAGE_READWRITE, &old_prot)) {
        VirtualFree(region, 0, MEM_RELEASE);
        return VERTHYS_ERR_INTERNAL;
    }

    /* 3. 边界页显式固定为 PAGE_NOACCESS（永久访问违例语义，见文件头
     * 实现注记；数据页改 RW 后边界页本已 NOACCESS，此处显式重设以
     * 固化区段完整性，冗余但确定）。 */
    if (!VirtualProtect(base, ps, PAGE_NOACCESS, &old_prot) ||
        !VirtualProtect(base + ps + data_bytes, ps, PAGE_NOACCESS, &old_prot)) {
        VirtualFree(region, 0, MEM_RELEASE);
        return VERTHYS_ERR_INTERNAL;
    }

    /* 4. 锁页（防换出）：失败重试一次；仍失败则整体回退 */
    if (!VirtualLock(data, data_bytes)) {
        if (!VirtualLock(data, data_bytes)) {
            AcquireSRWLockExclusive(&alloc->lock);
            alloc->lock_failures++;
            ReleaseSRWLockExclusive(&alloc->lock);
            VirtualFree(region, 0, MEM_RELEASE);
            return VERTHYS_ERR_INTERNAL;
        }
    }

    /* 5. 预算记账（95% 拒绝时整体回退） */
    if (budget_account_and_check(region_bytes) != 0) {
        VirtualUnlock(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }

    /* 6. 元数据登记（独立普通堆，物理隔离于安全区段） */
    uint64_t magic = 0;
    AcquireSRWLockExclusive(&alloc->lock);
    if (regions_reserve(alloc, alloc->region_count + 1) == 0) {
        magic = ++alloc->next_magic;
        SecureRegionMeta *meta = &alloc->regions[alloc->region_count++];
        meta->data_base   = data;
        meta->region_base = region;
        meta->data_bytes  = data_bytes;
        meta->region_bytes = region_bytes;
        meta->magic       = magic;
        alloc->total_allocs++;
    }
    ReleaseSRWLockExclusive(&alloc->lock);

    if (magic == 0) {  /* 注册表扩展失败：回退全部副作用 */
        budget_unaccount(region_bytes);
        VirtualUnlock(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return VERTHYS_ERR_INTERNAL;
    }

    *out_ptr = data;
    return VERTHYS_OK;
}

VerthysResult secure_allocator_free(SecureAllocator *alloc, void *ptr)
{
    if (alloc == NULL || ptr == NULL) return VERTHYS_ERR_INVALID;

    VerthysResult result = VERTHYS_ERR_INVALID;
    AcquireSRWLockExclusive(&alloc->lock);
    for (size_t i = 0; i < alloc->region_count; i++) {
        if (alloc->regions[i].data_base == ptr) {
            region_release(&alloc->regions[i]);
            budget_unaccount(alloc->regions[i].region_bytes);
            /* 尾部元素前移覆盖（无序删除，O(1)） */
            alloc->regions[i] = alloc->regions[alloc->region_count - 1];
            alloc->region_count--;
            alloc->total_frees++;
            result = VERTHYS_OK;
            break;
        }
    }
    ReleaseSRWLockExclusive(&alloc->lock);
    return result;
}

void secure_allocator_get_stats(const SecureAllocator *alloc,
                                SecureAllocatorStats *out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    if (alloc == NULL) return;

    AcquireSRWLockShared((SRWLOCK *)&alloc->lock);
    out->total_allocs  = alloc->total_allocs;
    out->total_frees   = alloc->total_frees;
    out->lock_failures = alloc->lock_failures;
    out->live_count    = alloc->region_count;
    for (size_t i = 0; i < alloc->region_count; i++) {
        out->live_bytes += alloc->regions[i].data_bytes;
    }
    ReleaseSRWLockShared((SRWLOCK *)&alloc->lock);
}
