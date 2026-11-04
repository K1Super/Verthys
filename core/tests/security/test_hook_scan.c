/*
 * test_hook_scan.c — Hook 扫描状态机与真实基线冒烟
 *
 * 覆盖：
 *   - 纯判定：干净 / 全部基线缺失 / 标准 stub 与磁盘不一致（STALE）/
 *     首次 Hook 特征仅遥测 / 连续两次 Hook 特征才终止 / IAT 槽异常两级
 *   - 真实 ntdll 基线：init + run_once 完成，结论不得为 ANOMALY（干净
 *     环境无 Hook）；允许 CLEAN/STALE/UNAVAILABLE（热补丁按过期处理）
 *   - 周期定时器启停幂等，不留下悬挂队列
 */
#include "verthys_test.h"
#include "hook_scan.h"

#include <string.h>

TEST(hook_scan_evaluate_clean)
{
    HookScanTargetObs obs[2];
    uint32_t ms[2] = { 3, 3 };
    uint32_t is[2] = { 2, 2 };
    int kill = 9;

    memset(obs, 0, sizeof(obs));
    obs[0].baseline_ok = 1;
    obs[0].mem_matches = 1;
    obs[0].iat_matches = 1;
    obs[1].baseline_ok = 1;
    obs[1].mem_matches = 1;
    obs[1].iat_matches = 1;

    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_CLEAN);
    CHECK_EQ(kill, 0);
    CHECK_EQ(ms[0], 0u);
    CHECK_EQ(is[0], 0u);
    return 0;
}

TEST(hook_scan_evaluate_baseline_unavailable)
{
    HookScanTargetObs obs[2];
    uint32_t ms[2] = { 0, 0 };
    uint32_t is[2] = { 0, 0 };
    int kill = 0;

    memset(obs, 0, sizeof(obs));   /* 全部 baseline_ok=0 */
    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill),
             HOOK_SCAN_UNAVAILABLE);
    CHECK_EQ(kill, 0);

    /* 部分基线可用：只用可用目标判定，不因缺失项整体不可用。 */
    obs[0].baseline_ok = 1;
    obs[0].mem_matches = 1;
    obs[0].iat_matches = 1;
    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_CLEAN);
    return 0;
}

TEST(hook_scan_evaluate_stale_stub)
{
    HookScanTargetObs obs[2];
    uint32_t ms[2] = { 0, 0 };
    uint32_t is[2] = { 0, 0 };
    int kill = 0;

    memset(obs, 0, sizeof(obs));
    obs[0].baseline_ok = 1;
    obs[0].mem_matches = 0;
    obs[0].mem_hook_shaped = 0;   /* 仍是标准 stub，仅与磁盘基线不一致 */
    obs[0].iat_matches = 1;

    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_STALE);
    CHECK_EQ(kill, 0);
    return 0;
}

TEST(hook_scan_evaluate_hook_two_strikes)
{
    HookScanTargetObs obs[2];
    uint32_t ms[2] = { 0, 0 };
    uint32_t is[2] = { 0, 0 };
    int kill = 0;

    memset(obs, 0, sizeof(obs));
    obs[0].baseline_ok = 1;
    obs[0].mem_matches = 0;
    obs[0].mem_hook_shaped = 1;
    obs[0].iat_matches = 1;

    /* 首次异常：状态异常但不得终止。 */
    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_ANOMALY);
    CHECK_EQ(kill, 0);
    CHECK_EQ(ms[0], 1u);

    /* 连续第二次：高置信度，终止。 */
    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_ANOMALY);
    CHECK_EQ(kill, 1);

    /* 恢复正常后连续计数清零。 */
    obs[0].mem_matches = 1;
    obs[0].mem_hook_shaped = 0;
    kill = 0;
    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_CLEAN);
    CHECK_EQ(ms[0], 0u);
    return 0;
}

TEST(hook_scan_evaluate_iat_two_strikes)
{
    HookScanTargetObs obs[2];
    uint32_t ms[2] = { 0, 0 };
    uint32_t is[2] = { 0, 0 };
    int kill = 0;

    memset(obs, 0, sizeof(obs));
    obs[0].baseline_ok = 1;
    obs[0].mem_matches = 1;
    obs[0].iat_matches = 0;

    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_ANOMALY);
    CHECK_EQ(kill, 0);
    CHECK_EQ(is[0], 1u);

    CHECK_EQ(hook_scan_evaluate(obs, 2, ms, is, &kill), HOOK_SCAN_ANOMALY);
    CHECK_EQ(kill, 1);
    return 0;
}

TEST(hook_scan_real_baseline_smoke)
{
    uint32_t state;

    CHECK_EQ(hook_scan_init(), 0);
    CHECK_EQ(hook_scan_run_once(), 0);
    state = hook_scan_get_state();
    TEST_LOG("[hook_scan] real state=%u last=%llu ms\n",
             (unsigned)state,
             (unsigned long long)hook_scan_get_last_scan_ms());
    /* 干净环境不得出现 Hook 特征；CLEAN/STALE/UNAVAILABLE 均属可接受证据。 */
    CHECK(state != HOOK_SCAN_ANOMALY);
    CHECK(hook_scan_get_last_scan_ms() > 0u);

    /* 定时器启停幂等（不等待 60s 周期）。 */
    CHECK_EQ(hook_scan_start_periodic(), 0);
    CHECK_EQ(hook_scan_start_periodic(), 0);
    hook_scan_stop_periodic();
    hook_scan_stop_periodic();
    return 0;
}
