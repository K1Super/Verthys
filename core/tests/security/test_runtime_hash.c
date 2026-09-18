/*
 * test_runtime_hash.c — ★ V3 升级 WP-8 验收：运行时函数级哈希校验
 *
 * 前提（构建接线硬依赖）：verthys_tests.exe 经 CMake POST_BUILD 步骤由
 * rhash_gen 补丁 .rhat 真表（/MAP + /INCREMENTAL:NO + POST_BUILD，
 * 见 core/tests/CMakeLists.txt）。本文件验收四层：
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
