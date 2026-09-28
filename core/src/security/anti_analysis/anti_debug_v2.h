/*
 * anti_debug_v2.h — 反调试检测（内部模块，不导出）
 *
 * 检测面（全部为本进程内高置信度信号，无系统级进程扫描）：
 *   - IsDebuggerPresent（PEB.BeingDebugged）
 *   - NtQueryInformationProcess 三重探测（DebugPort/DebugFlags/DebugObject）
 *   - 硬件断点 DR0-DR3（GetThreadContext）
 *
 * 响应：任一命中 → EMERG_LEVEL_KILL（调试器确认属于高置信度信号）；
 * 高安全档（anti_debug_aggressive）下可疑及以上直接零化退出。
 */
#ifndef VERTHYS_ANTI_DEBUG_V2_H
#define VERTHYS_ANTI_DEBUG_V2_H

/* 威胁等级 */
typedef enum {
    DBG_THREAT_NONE        = 0,  /* 未检测到威胁 */
    DBG_THREAT_SUSPICIOUS  = 1,  /* 软件调试器命中（IsDebuggerPresent/NtQuery 探测） */
    DBG_THREAT_HARDWARE_BP = 2,  /* 硬件断点 DR0-DR3 被设置 */
    DBG_THREAT_CRITICAL    = 3,  /* 多重威胁叠加 */
} DebugThreatLevel;

/*
 * 初始化反调试模块（幂等）。
 * 确保密码库就绪；NtQueryInformationProcess 经 syscall_direct
 * （直接系统调用，stub 优先 / 降级回退）传输。
 */
int anti_debug_v2_init(void);

/*
 * 综合检测：软件调试器探测 + DR 寄存器检测。
 * 受档位开关 anti_debug 门控；任一命中即上报 KILL 级应急信号。
 * 返回威胁等级。
 */
DebugThreatLevel anti_debug_v2_check(void);

/*
 * 触发立即清零退出（本模块内部使用的高置信度退出路径）。
 * 清零本模块内部状态后 TerminateProcess（不留 dump、不弹窗）。
 */
void anti_debug_v2_emergency_exit(void);

#endif /* VERTHYS_ANTI_DEBUG_V2_H */