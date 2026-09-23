/*
 * test_integrity_verify.c — 配套测试：构建期签名验签
 *
 * 覆盖：
 *   - 开发/测试构建（.vsec 全零未配置）：integrity_verify_startup 空操作通过
 *   - integrity_init 幂等就绪（defense_closure HOOK 路径判据）
 *
 * Release 构建的 .vsec 注入由 build_core.release.ps1 完成并在生产链路
 * 验证（Verthys_Unlock 入口）；测试进程的 .vsec 恒为未配置态，验签必须
 * 返回 0（跳过），此行为本身即是契约的一部分。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "integrity.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>   /* 自身文件时间戳指纹变更（SetFileTime 路径） */

TEST(integrity_verify_unconfigured_passes)
{
    /* 测试构建无基准注入 → 跳过校验返回 0（不得误报） */
    CHECK_EQ(integrity_verify_startup(), 0);
    return 0;
}

TEST(integrity_init_idempotent)
{
    CHECK_EQ(integrity_init(), 0);
    CHECK_EQ(integrity_init(), 0);  /* 幂等 */
    return 0;
}

/* 三态可区分：HMAC 计算失败（测试注入）→ INCOMPLETE 而非 PASS，且计数递增。
 * 验证基础设施异常不再被静默当作"通过"，且与"哈希不匹配"可区分。 */
TEST(integrity_anchor_incomplete_not_pass)
{
    long before = integrity_incomplete_count();

    integrity_test_force_fail(1);
    int r = integrity_check_anchor(ANCHOR_OPEN_SETTINGS);
    integrity_test_force_fail(0);   /* 先复位注入，再统一断言 */

    long after = integrity_incomplete_count();

    CHECK_EQ(r, INTEGRITY_RESULT_INCOMPLETE);   /* 未完成，非通过 */
    CHECK(after >= before + 1);                  /* 计数证据：异常被观测 */

    /* 复位后同锚点（基准未配置）恢复为 PASS，且非 MISMATCH */
    CHECK_EQ(integrity_check_anchor(ANCHOR_OPEN_SETTINGS), INTEGRITY_RESULT_PASS);
    return 0;
}

/* 自身文件验签缓存（解锁热路径）：
 *   - 缓存回放：指纹不变时重复验签不触发重算（重算计数不动——
 *     以计数证据替代计时对比，避免 CI 计时抖动）；
 *   - 指纹失效重算：修改自身文件最后写入时间戳 → 重算计数必增。
 * 白盒钩子（重算计数/清缓存）仅测试使用。 */
TEST(integrity_verify_startup_cache_replay_invalidate)
{
    long c0, c1;

    /* 冷启动基态：清缓存 + 记录基线计数 */
    integrity_verify_cache_reset();
    c0 = integrity_verify_recompute_count();

    /* 首次：缓存空 → 冷路径重算一次 */
    CHECK_EQ(integrity_verify_startup(), 0);
    c1 = integrity_verify_recompute_count();
    CHECK(c1 == c0 + 1);

    /* 二次：指纹命中 → 回放，重算计数不动 */
    CHECK_EQ(integrity_verify_startup(), 0);
    CHECK_EQ(integrity_verify_recompute_count(), c1);

    /* 修改自身文件最后写入时间（+1s，跨过文件系统时间戳粒度） */
    {
        wchar_t self_path[MAX_PATH];
        CHECK(GetModuleFileNameW(NULL, self_path, MAX_PATH) != 0);
        HANDLE hf = CreateFileW(self_path, FILE_WRITE_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE |
                                FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        CHECK(hf != INVALID_HANDLE_VALUE);
        FILETIME ft_now;
        GetSystemTimeAsFileTime(&ft_now);
        ULARGE_INTEGER u;
        u.LowPart  = ft_now.dwLowDateTime;
        u.HighPart = ft_now.dwHighDateTime;
        u.QuadPart += UINT64_C(10000000);   /* +1s（100ns 刻度） */
        FILETIME ft_later;
        ft_later.dwLowDateTime  = u.LowPart;
        ft_later.dwHighDateTime = u.HighPart;
        CHECK(SetFileTime(hf, NULL, NULL, &ft_later) != 0);
        CloseHandle(hf);
    }

    /* 指纹失效 → 触发重算一次 */
    CHECK_EQ(integrity_verify_startup(), 0);
    CHECK_EQ(integrity_verify_recompute_count(), c1 + 1);

    /* 新指纹下回放恢复生效 */
    CHECK_EQ(integrity_verify_startup(), 0);
    CHECK_EQ(integrity_verify_recompute_count(), c1 + 1);

    return 0;
}
