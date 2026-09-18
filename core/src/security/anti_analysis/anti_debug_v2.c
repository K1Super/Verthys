/*
 * anti_debug_v2.c — 反调试检测模块实现
 *
 * ★ 方案 §6.2.1（P1-O 治理）：检测器修复（缺陷依据见头注）。
 *
 * 检测层（全部为本进程内高置信度信号，无系统级进程扫描）：
 *   1. IsDebuggerPresent（PEB.BeingDebugged）
 *   2. NtQueryInformationProcess 三重探测
 *      （ProcessDebugPort / ProcessDebugFlags / ProcessDebugObjectHandle）
 *   3. 硬件断点检测（GetThreadContext 检查 DR0-DR3 寄存器）
 *
 * 响应层（方案 §6.1 分级模型）：
 *   - 任一命中 → emergency_report(EMERG_LEVEL_KILL, ...)：调试器确认属于
 *     高置信度信号（软件探测与 DR 寄存器无法被正常执行流置位）。
 *   - 惩罚模式：检测到威胁后激活，KDF 迭代提升（延迟惩罚语义保留，
 *     与比特反转"行为误导"彻底切割）。
 *   - 高安全模式（anti_debug_aggressive=1）：检测即本模块直接退出。
 *
 * 调用时机（方案 §6.2.1）：Verthys_Init、Verthys_ChangePassword、Verthys_Export
 * 各一次——高频路径零开销。
 */
#include "anti_debug_v2.h"
#include "verthys_internal.h"    /* verthys_secure_zero */
#include "verthys_crypto.h"      /* verthys_crypto_init */
#include "security_preset.h"   /* security_get_config */
#include "emergency.h"         /* emergency_report */
/* ★ WP-9：NtQueryInformationProcess 改走直接系统调用包装
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
static int s_punish_mode = 0;                 /* 惩罚模式标志（检测到威胁后置1） */
static const SecurityConfig *s_config = NULL;  /* 安全配置缓存（只读） */

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
     * ★ WP-9：经 syscall_direct 包装——优先直接 stub（绕过
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

    /* 上下文含寄存器敏感信息，用毕清零（单轮覆写足够，方案 P2-G） */
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

    /* 读取安全配置（决定是否启用激进策略与 KDF 迭代轮次） */
    s_config = security_get_config();

    /* ★ WP-9：直接系统调用传输就绪（stub 提取或 GetProcAddress 降级） */
    (void)syscall_direct_init();

    s_initialized = 1;
    return 0;
}

DebugThreatLevel anti_debug_v2_check(void)
{
    if (!s_initialized) {
        if (anti_debug_v2_init() != 0) {
            /* 初始化失败（密码库不可用）：按严重威胁处理，触发应急熔断 */
            s_punish_mode = 1;
            return DBG_THREAT_CRITICAL;
        }
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

    /* 检测到威胁后激活惩罚模式（一次激活，本会话不撤销） */
    if (level >= DBG_THREAT_SUSPICIOUS) {
        s_punish_mode = 1;
    }

    /* ★ 方案 §6.1：调试器确认 = 高置信度信号 → KILL 级上报 */
    if (hw_bp) {
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_HARDWARE_BP);
    }
    if (sw_debugger) {
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_DEBUGGER_ACTIVE);
    }

    /* 高安全模式：SUSPICIOUS 及以上直接退出（替代延迟惩罚） */
    if (s_config != NULL && s_config->anti_debug_aggressive) {
        if (level >= DBG_THREAT_SUSPICIOUS) {
            anti_debug_v2_emergency_exit();  /* 不返回 */
        }
    }

    return level;
}

int anti_debug_v2_is_punish_mode(void)
{
    return s_punish_mode ? 1 : 0;
}

uint32_t anti_debug_v2_get_kdf_iters(void)
{
    const SecurityConfig *cfg = s_config;
    if (cfg == NULL) {
        /* 未初始化时回退到默认配置 */
        cfg = security_get_config();
    }
    if (s_punish_mode) {
        return cfg->kdf_iters_punish;
    }
    return cfg->kdf_iters_normal;
}

void anti_debug_v2_emergency_exit(void)
{
    /* 清零本模块内部状态（单轮覆写足够，方案 P2-G：废除多轮民俗） */
    verthys_secure_zero(&s_initialized, sizeof(s_initialized));
    verthys_secure_zero(&s_punish_mode, sizeof(s_punish_mode));
    verthys_secure_zero(&s_config, sizeof(s_config));

    /* 终止进程：不生成 dump、不弹窗 */
    TerminateProcess(GetCurrentProcess(), 1);
}
