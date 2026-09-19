/*
 * fuzz_common.h — fuzz 目标共享初始化
 *
 * MSVC Debug CRT 陷阱：堆完整性断言 / _ASSERTE 默认弹模态对话框等待
 * 人工点击（中止/重试/忽略）——libFuzzer/ctest/CI 无人工介入 → 进程
 * 挂死在对话框上（本地实测：fuzz_partition 触发 HEAP CORRUPTION
 * 对话框挂起 1 小时+，ctest 无 TIMEOUT 即 CI 挂死）。
 *
 * 纪律：每个 LLVMFuzzerTestOneInput 首行调用 fuzz_msvc_prepare()：
 *   - 报告重定向到调试器通道（_CRTDBG_MODE_DEBUG，无对话框）；
 *   - abort 关闭 _WRITE_ABORT_MSG / _CALL_REPORTFAULT 弹窗；
 *   - 幂等（重复调用无副作用），非 MSVC 平台为空操作。
 */
#ifndef VERTHYS_FUZZ_COMMON_H
#define VERTHYS_FUZZ_COMMON_H

#ifdef _MSC_VER
#include <crtdbg.h>
#include <stdlib.h>
#endif

static void fuzz_msvc_prepare(void)
{
#ifdef _MSC_VER
    static int done = 0;
    if (done) return;
    done = 1;
    /* CRT 断言/错误报告 → 调试器输出通道，禁用交互对话框 */
    _CrtSetReportMode(_CRT_WARN,   _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ERROR,  _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
    /* abort()：仅终止进程，不弹运行时错误对话框 */
    _set_abort_behavior(0, _CALL_REPORTFAULT | _WRITE_ABORT_MSG);
#endif
}

#endif /* VERTHYS_FUZZ_COMMON_H */
