/*
 * anti_debug_v2.c — 反调试检测模块实现
 *

 * 检测层（全部为本进程内高置信度信号，无系统级进程扫描）：
 *   1. IsDebuggerPresent（PEB.BeingDebugged）
 *   2. NtQueryInformationProcess 三重探测
 *      （ProcessDebugPort / ProcessDebugFlags / ProcessDebugObjectHandle）
 *   3. 硬件断点检测（GetThreadContext 检查 DR0-DR3 寄存器——
 *      调用瞬间的入口点快照检查，非持续监控）
 *
 * 响应层（分级模型）：
 *   - 任一命中 → emergency_report(EMERG_LEVEL_KILL, ...)：调试器确认属于
 *     高置信度信号（软件探测与 DR 寄存器无法被正常执行流置位）。
 *   - 高安全档（anti_debug_aggressive=1）：可疑及以上由本模块直接零化退出。
 *   - 档位开关 anti_debug 为总门控（矩阵中全档恒开，保留门控语义）。
 *
 * 调用时机：Verthys_Init、Verthys_ChangePassword、Verthys_Export
 * 各一次——高频路径零开销。
 */
#include "anti_debug_v2.h"
#include "verthys_internal.h"    /* verthys_secure_zero */
#include "verthys_crypto.h"      /* verthys_crypto_init */
#include "security_preset.h"     /* security_config_snapshot */
#include "emergency.h"         /* emergency_report */
/* NtQueryInformationProcess 改走直接系统调用包装
 * （stub 优先 / GetProcAddress 回退），绕过用户态 API Hook。 */
#include "syscall_direct.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

/* NTSTATUS 成功值 */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((LONG)0x00000000)
#endif

/* ---------- 模块内部状态 ---------- */
static int s_initialized = 0;                 /* 幂等初始化标志 */

/* ===================================================================== *
 *                        检测层：软件调试器探测                          *
 * ===================================================================== */

/* 检测 IsDebuggerPresent + NtQueryInformationProcess 三重探测。
 * 命中任一即返回 1（调试器活跃）。全部为本进程内可验证信号。 */
static int check_software_debugger(void)
{
    /* 1. IsDebuggerPresent：读取 PEB.BeingDebugged 标志 */
    if (IsDebuggerPresent()) {
        return 1;
    }

    /* 2. NtQueryInformationProcess：三种调试器探测
     * 经 syscall_direct 包装——优先直接 stub（绕过
     * 用户态 Hook），降级时回退 GetProcAddress（行为与旧版一致）；
     * 包装内部彻底失联返回非 SUCCESS，各探测按"无信号"跳过。 */
    HANDLE proc = GetCurrentProcess();

    /* ProcessDebugPort (0x07)：非零表示存在调试端口（被调试） */
    DWORD_PTR debug_port = 0;
    if (syscall_NtQueryInformationProcess(
            proc, 0x07, &debug_port, sizeof(debug_port), NULL) == STATUS_SUCCESS) {
        if (debug_port != 0) {
            return 1;
        }
    }

    /* ProcessDebugFlags (0x1F)：0 表示被调试（注意：与 DebugPort 语义相反） */
    DWORD debug_flags = 0;
    if (syscall_NtQueryInformationProcess(
            proc, 0x1F, &debug_flags, sizeof(debug_flags), NULL) == STATUS_SUCCESS) {
        if (debug_flags == 0) {
            return 1;
        }
    }

    /* ProcessDebugObjectHandle (0x1E)：调用返回 STATUS_SUCCESS 即表示
     * 调试对象存在（进程正被调试） */
    HANDLE debug_obj = NULL;
    if (syscall_NtQueryInformationProcess(
            proc, 0x1E, &debug_obj, sizeof(debug_obj), NULL) == STATUS_SUCCESS) {
        return 1;
    }

    return 0;
}

/* ===================================================================== *
 *                     检测层：硬件断点 DR0-DR3 探测                      *
 * ===================================================================== */

/* 检查当前线程上下文的 DR0-DR3 寄存器是否被显式设置（非零）。
 * DR0-DR3 是硬件断点地址寄存器，正常进程全为零；
 * 任一非零 = 调试器设置了硬件断点 → 高置信度入侵信号。
 * 语义边界：本函数为调用瞬间的"入口点瞬时快照检查"（当前线程
 * 调试寄存器），非持续监控——检查通过后调试器仍可事后设置
 * 断点，该窗口风险由锚点校验与运行时哈希检测纵深兜底。
 * 返回 1=检测到硬件断点，0=未检测到。 */
static int check_hardware_breakpoints(void)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    /* GetThreadContext 读取当前线程的调试寄存器 */
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return 0;  /* 无法获取上下文，不阻断（保守放行） */
    }

    int detected = 0;
    /* 遍历全部四个调试地址寄存器 DR0/DR1/DR2/DR3 */
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 ||
        ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        detected = 1;
    }

    /* 上下文含寄存器敏感信息，用毕清零（单轮覆写足够） */
    verthys_secure_zero(&ctx, sizeof(ctx));
    return detected;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int anti_debug_v2_init(void)
{
    if (s_initialized) {
        return 0;  /* 幂等 */
    }

    /* 确保密码库可用 */
    if (verthys_crypto_init() != 0) {
        return -1;
    }

    /* 直接系统调用传输就绪（stub 提取或 GetProcAddress 降级） */
    (void)syscall_direct_init();

    s_initialized = 1;
    return 0;
}

DebugThreatLevel anti_debug_v2_check(void)
{
    if (!s_initialized) {
        if (anti_debug_v2_init() != 0) {
            /* 初始化失败（密码库不可用）：按严重威胁处理，触发应急熔断 */
            return DBG_THREAT_CRITICAL;
        }
    }

    /* 档位开关：调试器检测总门控（每次取配置快照，禁止跨调用持有指针） */
    SecurityConfig cfg;
    (void)security_config_snapshot(&cfg);
    if (!cfg.anti_debug) {
        return DBG_THREAT_NONE;
    }

    /* 多层特征检测（本进程内信号，全量启用） */
    int sw_debugger  = check_software_debugger();    /* IsDebuggerPresent + NtQuery */
    int hw_bp        = check_hardware_breakpoints(); /* DR0-DR3 硬件断点 */

    /* 威胁等级判定 */
    DebugThreatLevel level;
    if (hw_bp && sw_debugger) {
        level = DBG_THREAT_CRITICAL;
    } else if (hw_bp) {
        level = DBG_THREAT_HARDWARE_BP;
    } else if (sw_debugger) {
        level = DBG_THREAT_SUSPICIOUS;
    } else {
        level = DBG_THREAT_NONE;
    }

    /* 调试器确认 = 高置信度信号 → KILL 级上报 */
    if (hw_bp) {
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_HARDWARE_BP);
    }
    if (sw_debugger) {
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_DEBUGGER_ACTIVE);
    }

    /* 高安全档：可疑及以上直接零化退出（替代常规应急处置） */
    if (cfg.anti_debug_aggressive && level >= DBG_THREAT_SUSPICIOUS) {
        anti_debug_v2_emergency_exit();  /* 不返回 */
    }

    return level;
}

void anti_debug_v2_emergency_exit(void)
{
    /* 清零本模块内部状态（单轮覆写足够，废除多轮民俗） */
    verthys_secure_zero(&s_initialized, sizeof(s_initialized));

    /* 终止进程：不生成 dump、不弹窗 */
    TerminateProcess(GetCurrentProcess(), 1);
}
