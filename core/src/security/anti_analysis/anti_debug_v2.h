/*
 * anti_debug_v2.h — 反调试检测（内部模块，不导出）
 *

 * 原实现缺陷：
 *   1. 进程名黑名单（windbg/ida/ProcessHacker 等全系统扫描）——开发机上
 *      常驻无关工具即命中，产生永久惩罚 + 应急信号累积，结构性误报。
 *   2. should_corrupt_data 的 0.5% 比特反转"行为误导"——任何触碰真实
 *      用户数据的路径上都等于故意损坏数据。已删除。
 *
 * 修复后检测面（全部为本进程内高置信度信号）：
 *   - IsDebuggerPresent（PEB.BeingDebugged）
 *   - NtQueryInformationProcess 三重探测（DebugPort/DebugFlags/DebugObject）
 *   - 硬件断点 DR0-DR3（GetThreadContext）
 * 响应：任一命中 → EMERG_LEVEL_KILL（调试器确认属于高置信度信号）；punish 模式仅保留 KDF 迭代提升语义。
 */
#ifndef VERTHYS_ANTI_DEBUG_V2_H
#define VERTHYS_ANTI_DEBUG_V2_H

#include <stdint.h>

/* 威胁等级 */
typedef enum {
    DBG_THREAT_NONE        = 0,  /* 未检测到威胁 */
    DBG_THREAT_SUSPICIOUS  = 1,  /* 软件调试器命中（IsDebuggerPresent/NtQuery 探测） */
    DBG_THREAT_HARDWARE_BP = 2,  /* 硬件断点 DR0-DR3 被设置 */
    DBG_THREAT_CRITICAL    = 3,  /* 多重威胁叠加 */
} DebugThreatLevel;

/*
 * 初始化反调试模块（幂等）。
 * 确保密码库与安全配置就绪；NtQueryInformationProcess 经
 * syscall_direct（直接系统调用，stub 优先 / 降级回退）传输。
 */
int anti_debug_v2_init(void);

/*
 * 综合检测：软件调试器探测 + DR 寄存器检测。
 * 任一命中即上报 KILL 级应急信号（高置信度）。
 * 返回威胁等级。
 */
DebugThreatLevel anti_debug_v2_check(void);

/*
 * 查询当前是否处于"惩罚模式"（曾检测到威胁，本会话持续）。
 * 调用方据此提升 KDF 迭代轮次（anti_debug_v2_get_kdf_iters）。
 * 返回 0=正常模式，1=惩罚模式。
 */
int anti_debug_v2_is_punish_mode(void);

/*
 * 获取当前生效的 KDF 迭代轮次。
 * 正常模式返回 kdf_iters_normal，惩罚模式返回 kdf_iters_punish。
 */
uint32_t anti_debug_v2_get_kdf_iters(void);

/*
 * 触发立即清零退出（本模块内部使用的高置信度退出路径）。
 * 清零本模块内部状态后 TerminateProcess（不留 dump、不弹窗）。
 */
void anti_debug_v2_emergency_exit(void);

#endif /* VERTHYS_ANTI_DEBUG_V2_H */
