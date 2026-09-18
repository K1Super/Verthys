/*
 * test_emergency.c — 方案 §6.1 配套测试：应急响应分级模型
 *
 * 覆盖（方案 §8.2 新增测试清单）：
 *   - TELEMETRY 级仅记录、无处置
 *   - DEGRADE 级需窗口内同信号累计 ≥2 才触发降级处理器
 *   - 降级处理器回调 + 熔断闩锁（幂等）
 *   - emergency_clear_signals 解除降级态（解锁成功恢复路径）
 *   - 信号窗口查询
 * （KILL 级触发 TerminateProcess，不在测试进程内验证）
 */
#include "verthys_test.h"
#include "verthys.h"
#include "emergency.h"

static int g_handler_calls = 0;
static void test_degrade_handler(void)
{
    g_handler_calls++;
}

TEST(emergency_telemetry_no_trigger)
{
    CHECK_EQ(emergency_init(), 0);
    emergency_set_degrade_handler(test_degrade_handler);
    g_handler_calls = 0;
    emergency_clear_signals();

    emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_UNKNOWN_DLL);
    emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_UNKNOWN_DLL);
    emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_UNKNOWN_DLL);

    /* 遥测只记录：无处置、无熔断 */
    CHECK_EQ(g_handler_calls, 0);
    CHECK_EQ(emergency_is_triggered(), 0);
    CHECK((emergency_get_signals() & EMERG_SIG_UNKNOWN_DLL) != 0);

    emergency_clear_signals();
    return 0;
}

TEST(emergency_degrade_requires_window_threshold)
{
    CHECK_EQ(emergency_init(), 0);
    emergency_set_degrade_handler(test_degrade_handler);
    g_handler_calls = 0;
    emergency_clear_signals();

    /* 单次中置信度信号：不触发（防单次误报） */
    emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_REMOTE_MEM_READ);
    CHECK_EQ(g_handler_calls, 0);
    CHECK_EQ(emergency_is_triggered(), 0);

    /* 窗口内第二次同信号：达到阈值 → 降级处理器恰好回调一次 */
    emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_REMOTE_MEM_READ);
    CHECK_EQ(g_handler_calls, 1);
    CHECK_EQ(emergency_is_triggered(), 1);
    CHECK_EQ(emergency_is_degraded(), 1);

    /* 闩锁：后续重复信号不再重复处置 */
    emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_REMOTE_MEM_READ);
    CHECK_EQ(g_handler_calls, 1);

    /* 解锁成功恢复路径：清除后熔断解除 */
    emergency_clear_signals();
    CHECK_EQ(emergency_is_triggered(), 0);
    CHECK_EQ(emergency_is_degraded(), 0);
    CHECK_EQ(emergency_get_signals(), 0);

    /* 清除后重新计数（窗口重置生效） */
    emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_REMOTE_MEM_READ);
    CHECK_EQ(g_handler_calls, 1);  /* 未达阈值，仍不触发 */

    emergency_clear_signals();
    return 0;
}

TEST(emergency_handler_swap_and_null)
{
    CHECK_EQ(emergency_init(), 0);
    emergency_set_degrade_handler(NULL);
    g_handler_calls = 0;
    emergency_clear_signals();

    /* 无处理器时 DEGRADE 仅置闩锁（IO 门控仍然生效），不崩溃 */
    emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_PROCESS_TAMPER);
    emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_PROCESS_TAMPER);
    CHECK_EQ(emergency_is_triggered(), 1);
    CHECK_EQ(g_handler_calls, 0);

    emergency_clear_signals();
    emergency_set_degrade_handler(test_degrade_handler);
    return 0;
}
