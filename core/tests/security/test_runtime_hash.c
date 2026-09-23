/*
 * test_runtime_hash.c — 验收：运行时函数级哈希校验
 *
 * 前提（构建接线硬依赖）：verthys_tests.exe 经 CMake POST_BUILD 步骤由
 * rhash_gen 补丁 .rhat 真表（/MAP + /INCREMENTAL:NO + POST_BUILD，
 * 构建注册于 core/tests/CMakeLists.txt）。本文件验收四层：
 *   1. 表已配置（configured）——POST_BUILD 链路断裂即失败（禁静默降级）；
 *   2. 真表全量通过（scan==0）——构建期文件哈希 ≡ 运行期内存哈希，
 *      含重定位槽位掩码归一的正确性（跨 ASLR 基稳定性的核心验收）；
 *   3. 真表条目 VirtualProtect 改字节 → 检出；还原 → 恢复干净；
 *   4. 白盒 overlay 自基线机制（安装/检出/清空/参数校验）。
 *
 * KILL 语义纪律（与 test_emergency.c 一致）：KILL 级应急触发
 * TerminateProcess，不在测试进程内验证失配→KILL 路径；verify 系列
 * 仅在干净态执行（无失配 → 无应急副作用，进程存活到达断言）。
 */
#include "verthys_test.h"
#include "runtime_hash.h"
#include "verthys_crypto.h"      /* verthys_random_bytes（X 清单函数） */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>             /* uintptr_t（_beginthreadex 返回值的句柄强转） */
#include <string.h>
#include <stdlib.h>

/* overlay 白盒目标：本翻译单元私有函数（不入 X 清单，仅经 overlay 覆盖）。
 * volatile 防优化内联消解（地址被取用即必然实体化，双保险）。 */
static int rhat_dummy_target(int x)
{
    volatile int v = x * 3 + 7;
    return v;
}

/* 1. POST_BUILD 链路验收：真表已配置 */
TEST(rhat_table_configured)
{
    /* .rhat 全零（未补丁）= 构建接线断裂 → 失败显性化 */
    CHECK_EQ(runtime_hash_configured(), 1);
    return 0;
}

/* 2. 真表全量通过：构建期文件哈希 ≡ 运行期内存哈希（掩码归一正确性） */
TEST(rhat_real_table_scan_clean)
{
    CHECK_EQ(runtime_hash_scan(), 0);
    return 0;
}

/* 3. X 清单函数被真表覆盖；未入表符号不误命中 */
TEST(rhat_lookup_covered)
{
    const void *base = NULL;
    size_t len = 0;

    /* verthys_random_bytes 在 X 清单 → .rhat 真表条目 */
    CHECK_EQ(runtime_hash_lookup(verthys_random_bytes, &base, &len), 1);
    CHECK(base != NULL);
    CHECK(len > 0 && len <= VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES);

    /* NULL 与未入表函数（本文件私有符号）不命中 */
    CHECK_EQ(runtime_hash_lookup(NULL, &base, &len), 0);
    CHECK_EQ(runtime_hash_lookup((const void *)&rhat_dummy_target,
                                &base, &len), 0);
    return 0;
}

/* 4. 真表条目篡改检出：VirtualProtect + 改字节 → scan 失配；还原 → 干净 */
TEST(rhat_virtualprotect_patch_detected)
{
    const void *base = NULL;
    size_t len = 0;
    CHECK_EQ(runtime_hash_lookup(verthys_random_bytes, &base, &len), 1);
    CHECK(base != NULL);
    CHECK(len > 0 && len <= VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES);

    unsigned char *saved = (unsigned char *)malloc(len);
    CHECK(saved != NULL);
    memcpy(saved, base, len);

    DWORD oldp = 0;
    CHECK(VirtualProtect((LPVOID)base, (SIZE_T)len,
                         PAGE_EXECUTE_READWRITE, &oldp) != 0);

    /* 3 个不同偏移各翻 1 字节：x64 .text 以 RIP 相对寻址为主、重定位
     * 槽位稀疏，三处同时落入掩码槽的概率可忽略；任一未掩码差异即检出 */
    ((unsigned char *)base)[0]         ^= 0xA5;
    ((unsigned char *)base)[len / 4]   ^= 0xA5;
    ((unsigned char *)base)[len / 2]   ^= 0xA5;

    int bad = runtime_hash_scan();

    /* 无论后续断言结果，先还原（防篡改态泄漏到后续测试）再判定 */
    memcpy((void *)base, saved, len);
    DWORD tmp = 0;
    (void)VirtualProtect((LPVOID)base, (SIZE_T)len, oldp, &tmp);
    free(saved);

    CHECK(bad > 0);                    /* 至少一条真表条目检出失配 */
    CHECK_EQ(runtime_hash_scan(), 0);  /* 还原后恢复干净态 */
    return 0;
}

/* 5. 白盒 overlay：参数校验 + 自基线一致 + 篡改检出 + 清空 */
TEST(rhat_overlay_install_detect_clear)
{
    const unsigned char *target = (const unsigned char *)&rhat_dummy_target;
    const size_t span = 24;  /* 覆盖函数前 24 字节（部分覆盖即合法） */

    /* 非法参数拒绝 */
    CHECK(runtime_hash_test_install(NULL, span) != 0);
    CHECK(runtime_hash_test_install(target, 0) != 0);

    /* 安装自基线（以当前内存内容掩码哈希为基准） */
    CHECK_EQ(runtime_hash_test_install(target, span), 0);
    CHECK_EQ(runtime_hash_scan(), 0);   /* 基线与当前内容一致 */

    unsigned char saved[24];
    memcpy(saved, target, span);
    DWORD oldp = 0;
    CHECK(VirtualProtect((LPVOID)target, (SIZE_T)span,
                         PAGE_EXECUTE_READWRITE, &oldp) != 0);
    ((unsigned char *)target)[span / 2] ^= 0x5A;
    int bad = runtime_hash_scan();
    memcpy((void *)target, saved, span);
    DWORD tmp = 0;
    (void)VirtualProtect((LPVOID)target, (SIZE_T)span, oldp, &tmp);

    CHECK(bad > 0);                    /* overlay 覆盖区篡改检出 */
    CHECK_EQ(runtime_hash_scan(), 0);  /* 还原后干净 */

    runtime_hash_test_clear();
    CHECK_EQ(runtime_hash_scan(), 0);  /* overlay 清空后不再参与 */
    return 0;
}

/* 6. 干净态 verify / 周期门控：无失配 → 无 KILL 副作用（存活即通过） */
TEST(rhat_verify_periodic_clean_state)
{
    CHECK_EQ(runtime_hash_scan(), 0);       /* 前提：干净 */

    runtime_hash_verify();                  /* 全量（无失配 → 无应急） */
    runtime_hash_verify_periodic();         /* 首调：立即全量 */
    runtime_hash_verify_periodic();         /* 窗口内：时间门控直接返回 */
    return 0;
}

/* ===================================================================== *
 *  7. overlay 并发安装 + 扫描单飞互斥                                   *
 * ===================================================================== */

/* 并发段目标：8 个行为各异的私有点函数（编译期防 ICF 合并），
 * 内容恒定——scan 对任一已安装条目的期望失配恒为 0。 */
static int rhat_conc_t0(int x) { volatile int v = x * 3 + 11;  return v; }
static int rhat_conc_t1(int x) { volatile int v = x * 5 + 17;  return v; }
static int rhat_conc_t2(int x) { volatile int v = x * 7 + 23;  return v; }
static int rhat_conc_t3(int x) { volatile int v = x * 11 + 29; return v; }
static int rhat_conc_t4(int x) { volatile int v = x * 13 + 31; return v; }
static int rhat_conc_t5(int x) { volatile int v = x * 17 + 37; return v; }
static int rhat_conc_t6(int x) { volatile int v = x * 19 + 41; return v; }
static int rhat_conc_t7(int x) { volatile int v = x * 23 + 43; return v; }

#define RH_CONC_TARGETS  8u
#define RH_CONC_SPAN     32u   /* 覆盖函数体（超出即读同节相邻字节，无碍） */
#define RH_CONC_NEED     3u    /* 单安装线程最低成功次数（成功后提前退出） */
#define RH_CONC_MAX_TRY  400   /* 单安装线程尝试上限（防扫描长窗口饿死） */
#define RH_CONC_SCANS    150   /* 扫描线程周期数 */

/*
 * 跨线程共享状态：错误仅原子累计（多线程下禁用 CHECK 立即返回），
 * 安装返回码三分：0=成功、-1=单飞忙碌（调用方重试语义，合法）、
 * 其余=未预期错误。扫描恒期望 0 失配（锁纪律下表不撕裂）。
 */
typedef struct RhConcState {
    volatile LONG scan_errs;    /* 扫描非零失配次数（撕裂/误报证据） */
    volatile LONG install_ok;   /* 安装成功次数 */
    volatile LONG install_busy; /* 安装返回 -1 次数（单飞竞争） */
    volatile LONG install_err;  /* 安装异常返回次数 */
} RhConcState;

static const unsigned char *rh_conc_target_addr(unsigned i)
{
    static const unsigned char *targets[RH_CONC_TARGETS] = {
        (const unsigned char *)&rhat_conc_t0, (const unsigned char *)&rhat_conc_t1,
        (const unsigned char *)&rhat_conc_t2, (const unsigned char *)&rhat_conc_t3,
        (const unsigned char *)&rhat_conc_t4, (const unsigned char *)&rhat_conc_t5,
        (const unsigned char *)&rhat_conc_t6, (const unsigned char *)&rhat_conc_t7,
    };
    return targets[i % RH_CONC_TARGETS];
}

/* 安装线程：循环安装轮换目标（与扫描线程竞争 s_hbuf / s_overlay 共享区）。
 * 扫描单次耗时长（重定位收集 + 排序），失败尝试开销极小——纯固定次数
 * 尝试会全部落入同一段扫描独占窗口（饿死）。改为"成功计数 + 尝试上限 +
 * 交替短让出"：长窗口内等待，扫描排空间隙即获锁。 */
static unsigned __stdcall rh_conc_installer(void *arg)
{
    RhConcState *st = (RhConcState *)arg;
    unsigned i;
    LONG got = 0;

    for (i = 0; i < RH_CONC_MAX_TRY; i++) {
        int rc = runtime_hash_test_install(rh_conc_target_addr(i), RH_CONC_SPAN);
        if (rc == 0) {
            InterlockedIncrement(&st->install_ok);
            if (InterlockedIncrement(&got) >= (LONG)RH_CONC_NEED) break;
        } else if (rc < 0) {
            InterlockedIncrement(&st->install_busy);
        } else {
            InterlockedIncrement(&st->install_err);
        }
        Sleep((i & 1u) ? 1 : 0);   /* 交替 0/1ms 让出，给扫描留排空窗口 */
    }
    return 0;
}

/* 扫描线程：循环全量扫描断言零失配（并发安装不得致表撕裂） */
static unsigned __stdcall rh_conc_scanner(void *arg)
{
    RhConcState *st = (RhConcState *)arg;
    unsigned i;

    for (i = 0; i < RH_CONC_SCANS; i++) {
        int mm = runtime_hash_scan();
        if (mm != 0) InterlockedIncrement(&st->scan_errs);
        Sleep(0);
    }
    return 0;
}

/*
 * 主测试：串行预装 8 条自基线 → 两安装线程 + 一扫描线程并发 →
 * join → 表清空 → 统一断言（先完成全部操作与清理，再判定）。
 * 绿态：扫描零失配、安装仅 0/-1、至少一次成功；红态（无单飞锁）：
 * s_hbuf 双写撕裂使存储基线失真，扫描间歇性非零失配（概率性，多轮缓解）。
 */
TEST(rhat_overlay_concurrent_install_scan)
{
    RhConcState st;
    HANDLE threads[3];
    DWORD wr;
    int pre_fail = 0;
    int final_mm = 0;
    int post_mm = 0;
    unsigned i;

    memset(&st, 0, sizeof(st));

    for (i = 0; i < RH_CONC_TARGETS; i++) {
        if (runtime_hash_test_install(rh_conc_target_addr(i), RH_CONC_SPAN) != 0) {
            pre_fail = 1;
        }
    }

    threads[0] = (HANDLE)(uintptr_t)_beginthreadex(NULL, 0, rh_conc_installer, &st, 0, NULL);
    threads[1] = (HANDLE)(uintptr_t)_beginthreadex(NULL, 0, rh_conc_installer, &st, 0, NULL);
    threads[2] = (HANDLE)(uintptr_t)_beginthreadex(NULL, 0, rh_conc_scanner, &st, 0, NULL);
    if (threads[0] == NULL || threads[1] == NULL || threads[2] == NULL) {
        /* 收口：关闭已创建句柄并清表（线程未创建即无残存） */
        for (i = 0; i < 3; i++) {
            if (threads[i] != NULL) CloseHandle(threads[i]);
        }
        runtime_hash_test_clear();
        printf("  [FAIL] thread creation failed\n");
        return 1;
    }

    wr = WaitForMultipleObjects(3, threads, TRUE, INFINITE);
    CloseHandle(threads[0]);
    CloseHandle(threads[1]);
    CloseHandle(threads[2]);

    final_mm = runtime_hash_scan();
    runtime_hash_test_clear();
    post_mm = runtime_hash_scan();

    /* ---- 收口后统一断言 ---- */
    CHECK_EQ(pre_fail, 0);
    CHECK_EQ(wr, WAIT_OBJECT_0);
    CHECK_EQ((long)st.install_err, 0);
    CHECK((long)st.install_ok >= (long)RH_CONC_NEED);   /* 并发下安装可达 */
    CHECK_EQ((long)st.scan_errs, 0);
    CHECK_EQ(final_mm, 0);
    CHECK_EQ(post_mm, 0);
    return 0;
}
