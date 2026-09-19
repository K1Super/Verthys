/*
 * test_secure_allocator.c — 验收：安全分配器 + 全局内存预算记账
 *
 * 覆盖（分配/释放/边界页触发/锁页/预算上限拒绝）：
 *   1. 基础分配/释放 roundtrip（页对齐、数据读写、统计一致性、用量回落）
 *   2. 边界页触发（SEH 捕获：前后 PAGE_GUARD 页访问均引发 ACCESS_VIOLATION）
 *   3. 锁页（VirtualLock 成功路径：lock_failures==0；引用计数验证）
 *   4. 预算上限拒绝（95% VERTHYS_ERR_RESOURCE_LIMIT）+ 80% 回收回调触发/
 *      重新武装 + 跨实例共享记账
 *   5. 错误路径（NULL/0 尺寸/野指针/重复释放/非本分配器指针拒绝）
 *   6. destroy 语义（活跃区段全量释放、用量精确回落）
 */
#include "verthys_test.h"
#include "secure_allocator.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string.h>

/* ---------- 测试辅助 ---------- */

static DWORD test_page_size(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (si.dwPageSize > 0) ? si.dwPageSize : 4096u;
}

static size_t round_up_ps(size_t n)
{
    DWORD ps = test_page_size();
    return ((n + ps - 1) / ps) * ps;
}

/* SEH：探测地址访问是否引发 ACCESS_VIOLATION（1=违例，0=正常访问） */
static int access_raises_av(const volatile void *p)
{
    __try {
        volatile uint8_t v = *(const volatile uint8_t *)p;
        (void)v;
        return 0;
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH) {
        return 1;
    }
}

/* 80% 回收回调记录器 */
static volatile LONG g_reclaim_hits = 0;
static size_t g_reclaim_last_current = 0;
static size_t g_reclaim_last_budget = 0;

static void test_reclaim_cb(void *user_ctx, size_t current_bytes, size_t budget_bytes)
{
    (void)user_ctx;
    InterlockedIncrement(&g_reclaim_hits);
    g_reclaim_last_current = current_bytes;
    g_reclaim_last_budget  = budget_bytes;
}

/* ---------- 1. 基础分配/释放 ---------- */

TEST(sec_alloc_basic_roundtrip)
{
    SecureAllocator *alloc = secure_allocator_create();
    SecureAllocatorStats st;
    void *p = NULL;
    uint8_t pattern[256];
    size_t base_usage = secure_allocator_budget_usage();
    unsigned i;

    CHECK(alloc != NULL);
    secure_allocator_get_stats(alloc, &st);
    CHECK(st.live_count == 0 && st.live_bytes == 0);

    CHECK(secure_allocator_alloc(alloc, 256, &p) == VERTHYS_OK);
    CHECK(p != NULL);
    /* 数据页基址页对齐 */
    CHECK(((uintptr_t)p % test_page_size()) == 0);

    /* 数据读写 roundtrip */
    for (i = 0; i < sizeof(pattern); i++) pattern[i] = (uint8_t)(i * 31 + 7);
    memcpy(p, pattern, sizeof(pattern));
    CHECK(memcmp(p, pattern, sizeof(pattern)) == 0);

    /* 统计 + 全局用量（数据页 + 2 边界页） */
    secure_allocator_get_stats(alloc, &st);
    CHECK(st.live_count == 1);
    CHECK(st.live_bytes == round_up_ps(256));
    CHECK(st.total_allocs == 1);
    CHECK(secure_allocator_budget_usage() ==
          base_usage + round_up_ps(256) + 2 * test_page_size());

    /* 释放：用量精确回落 */
    CHECK(secure_allocator_free(alloc, p) == VERTHYS_OK);
    secure_allocator_get_stats(alloc, &st);
    CHECK(st.live_count == 0 && st.live_bytes == 0);
    CHECK(st.total_frees == 1);
    CHECK(secure_allocator_budget_usage() == base_usage);

    secure_allocator_destroy(alloc);
    return 0;
}

/* ---------- 2. 边界页触发 ---------- */

TEST(sec_alloc_guard_pages)
{
    SecureAllocator *alloc = secure_allocator_create();
    void *p = NULL;
    DWORD ps = test_page_size();

    CHECK(alloc != NULL);
    /* 单页数据：数据页 [p, p+ps)，前后各一页边界 */
    CHECK(secure_allocator_alloc(alloc, ps, &p) == VERTHYS_OK);
    CHECK(p != NULL);

    /* 前边界页（p-1 与 p-ps）：必须访问违例 */
    CHECK(access_raises_av((const volatile uint8_t *)p - 1) == 1);
    CHECK(access_raises_av((const volatile uint8_t *)p - ps) == 1);

    /* 后边界页（p+ps 起始）：必须访问违例 */
    CHECK(access_raises_av((const volatile uint8_t *)p + ps) == 1);
    CHECK(access_raises_av((const volatile uint8_t *)p + 2 * ps - 1) == 1);

    /* 数据页内首尾字节正常可访问（边界精确，无误伤） */
    CHECK(access_raises_av((const volatile uint8_t *)p) == 0);
    CHECK(access_raises_av((const volatile uint8_t *)p + ps - 1) == 0);

    CHECK(secure_allocator_free(alloc, p) == VERTHYS_OK);
    secure_allocator_destroy(alloc);
    return 0;
}

/* ---------- 3. 锁页 ---------- */

TEST(sec_alloc_locked)
{
    SecureAllocator *alloc = secure_allocator_create();
    SecureAllocatorStats st;
    void *p = NULL;
    DWORD ps = test_page_size();

    CHECK(alloc != NULL);
    CHECK(secure_allocator_alloc(alloc, 2 * ps, &p) == VERTHYS_OK);
    CHECK(p != NULL);

    /* 分配路径 VirtualLock 成功（失败会计入 lock_failures） */
    secure_allocator_get_stats(alloc, &st);
    CHECK(st.lock_failures == 0);

    /* 锁引用计数验证：外部再 Lock 一次（计数 2）→ Unlock 一次（计数 1）
     * → 模块 free 路径仍需 Unlock 成功（计数归零），不应报错 */
    CHECK(VirtualLock(p, 2 * ps) != 0);
    CHECK(VirtualUnlock(p, 2 * ps) != 0);

    CHECK(secure_allocator_free(alloc, p) == VERTHYS_OK);

    /* 释放后 Unlock 已由模块完成：再次 Unlock 必须失败（证明已解锁） */
    CHECK(VirtualUnlock(p, 2 * ps) == 0);

    secure_allocator_destroy(alloc);
    return 0;
}

/* ---------- 4. 预算上限拒绝 + 回收回调 ---------- */

TEST(sec_alloc_budget_reject_and_reclaim)
{
    SecureAllocator *a1 = secure_allocator_create();
    SecureAllocator *a2 = secure_allocator_create();
    DWORD ps = test_page_size();
    size_t base_usage = secure_allocator_budget_usage();
    size_t base_budget = secure_allocator_budget_limit();
    uint32_t base_reclaims = secure_allocator_budget_reclaim_count();

    /* 区域 = 1 数据页 + 2 边界页 = 3 页；预算 10 页：
     *   95% 拒绝线 = 9.5 页 → 第 4 次分配（累计 12 页）被拒；
     *   80% 回收线 = 8 页 → 第 3 次分配后（累计 9 页）触发回调。 */
    size_t budget = 10 * ps;
    void *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;

    CHECK(a1 != NULL && a2 != NULL);
    g_reclaim_hits = 0;
    CHECK(secure_allocator_budget_init(budget, test_reclaim_cb, NULL)
          == VERTHYS_OK);
    CHECK(secure_allocator_budget_limit() == budget);

    /* 前三次成功（跨实例共享记账：a1×2 + a2×1） */
    CHECK(secure_allocator_alloc(a1, ps, &p1) == VERTHYS_OK);
    CHECK(secure_allocator_alloc(a1, ps, &p2) == VERTHYS_OK);
    CHECK(secure_allocator_alloc(a2, ps, &p3) == VERTHYS_OK);
    CHECK(p1 != NULL && p2 != NULL && p3 != NULL);

    /* 80% 回收已触发（9 页 ≥ 8 页），且仅一次（阈值沿语义） */
    CHECK(g_reclaim_hits == 1);
    CHECK(g_reclaim_last_current == base_usage + 9 * ps);
    CHECK(g_reclaim_last_budget == budget);

    /* 第 4 次分配：累计将达 12 页 > 9.5 页 → 预算拒绝 */
    CHECK(secure_allocator_alloc(a1, ps, &p4) == VERTHYS_ERR_RESOURCE_LIMIT);
    CHECK(p4 == NULL);
    CHECK(secure_allocator_budget_usage() == base_usage + 9 * ps);

    /* 释放一个区段（9 → 6 页，回落 80% 以下 → 回收重新武装） */
    CHECK(secure_allocator_free(a1, p1) == VERTHYS_OK);
    CHECK(secure_allocator_budget_usage() == base_usage + 6 * ps);

    /* 再分配（6 → 9 页，重新跨 80%）→ 回调第二次触发 */
    CHECK(secure_allocator_alloc(a2, ps, &p1) == VERTHYS_OK);
    CHECK(g_reclaim_hits == 2);

    /* 清场：全部释放，用量精确回落基线（p1 当前归属 a2） */
    CHECK(secure_allocator_free(a2, p1) == VERTHYS_OK);
    CHECK(secure_allocator_free(a1, p2) == VERTHYS_OK);
    CHECK(secure_allocator_free(a2, p3) == VERTHYS_OK);
    CHECK(secure_allocator_budget_usage() == base_usage);
    CHECK(secure_allocator_budget_reclaim_count() >= base_reclaims + 2);

    /* 恢复全局默认预算 + 清空回调（测试环境还原纪律） */
    CHECK(secure_allocator_budget_init(SECURE_ALLOC_DEFAULT_BUDGET_BYTES,
                                       NULL, NULL) == VERTHYS_OK);

    secure_allocator_destroy(a1);
    secure_allocator_destroy(a2);
    return 0;
}

/* ---------- 5. 错误路径 ---------- */

TEST(sec_alloc_error_paths)
{
    SecureAllocator *alloc = secure_allocator_create();
    SecureAllocator *other = secure_allocator_create();
    void *p = NULL, *q = NULL;
    int stack_var = 0;

    CHECK(alloc != NULL && other != NULL);

    /* 参数校验 */
    CHECK(secure_allocator_alloc(NULL, 16, &p) == VERTHYS_ERR_INVALID);
    CHECK(secure_allocator_alloc(alloc, 0, &p) == VERTHYS_ERR_INVALID);
    CHECK(secure_allocator_alloc(alloc, 16, NULL) == VERTHYS_ERR_INVALID);
    /* 尺寸溢出（round_up 页对齐溢出守卫） */
    CHECK(secure_allocator_alloc(alloc, (size_t)-1, &p) == VERTHYS_ERR_INVALID);

    CHECK(secure_allocator_free(NULL, p) == VERTHYS_ERR_INVALID);
    CHECK(secure_allocator_free(alloc, NULL) == VERTHYS_ERR_INVALID);

    /* 正常分配后：重复释放第二次拒绝 */
    CHECK(secure_allocator_alloc(alloc, 64, &p) == VERTHYS_OK);
    CHECK(secure_allocator_free(alloc, p) == VERTHYS_OK);
    CHECK(secure_allocator_free(alloc, p) == VERTHYS_ERR_INVALID);

    /* 野指针/外部指针拒绝（元数据独立存储 + 注册表校验） */
    CHECK(secure_allocator_free(alloc, &stack_var) == VERTHYS_ERR_INVALID);
    CHECK(secure_allocator_alloc(other, 64, &q) == VERTHYS_OK);
    CHECK(secure_allocator_free(alloc, q) == VERTHYS_ERR_INVALID);  /* 跨实例 */
    CHECK(secure_allocator_free(other, q) == VERTHYS_OK);           /* 归属正确 */

    /* 统计查询：NULL 安全 */
    secure_allocator_get_stats(alloc, NULL);
    secure_allocator_get_stats(NULL, NULL);

    secure_allocator_destroy(alloc);
    secure_allocator_destroy(other);
    return 0;
}

/* ---------- 6. destroy 语义 + 多区段一致性 ---------- */

TEST(sec_alloc_destroy_releases_all)
{
    SecureAllocator *alloc = secure_allocator_create();
    SecureAllocatorStats st;
    size_t base_usage = secure_allocator_budget_usage();
    void *ptrs[32];
    DWORD ps = test_page_size();
    int i;

    CHECK(alloc != NULL);

    /* 混合尺寸 × 32 区段（含子页与多页） */
    for (i = 0; i < 32; i++) {
        size_t sz = (i % 4 == 0) ? 100 : (size_t)(i + 1) * 100;
        ptrs[i] = NULL;
        CHECK(secure_allocator_alloc(alloc, sz, &ptrs[i]) == VERTHYS_OK);
        CHECK(ptrs[i] != NULL);
        memset(ptrs[i], (uint8_t)i, sz);  /* 全幅写入验证页边界内可用 */
    }
    secure_allocator_get_stats(alloc, &st);
    CHECK(st.live_count == 32);
    CHECK(st.total_allocs == 32);

    /* 乱序释放一半 */
    for (i = 1; i < 32; i += 2) {
        CHECK(secure_allocator_free(alloc, ptrs[i]) == VERTHYS_OK);
    }
    secure_allocator_get_stats(alloc, &st);
    CHECK(st.live_count == 16);
    CHECK(st.total_frees == 16);

    /* destroy：剩余 16 区段全量释放，用量精确回落基线 */
    secure_allocator_destroy(alloc);
    CHECK(secure_allocator_budget_usage() == base_usage);

    /* 边界尺寸再验证：1 字节分配仍占满一整数据页 */
    {
        SecureAllocator *a = secure_allocator_create();
        void *one = NULL;
        CHECK(secure_allocator_alloc(a, 1, &one) == VERTHYS_OK);
        secure_allocator_get_stats(a, &st);
        CHECK(st.live_bytes == ps);
        secure_allocator_destroy(a);
    }
    CHECK(secure_allocator_budget_usage() == base_usage);
    return 0;
}
