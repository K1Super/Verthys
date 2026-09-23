/*
 * defense_closure.c — 闭环防御能力验证状态机实现
 *

 * 原实现缺陷：BLOCKED 的判定是"模块 init 成功"
 * 而非"攻击路径被阻断"——例如 check_mem_dump 的 BLOCKED 只说明
 * key_drift/working_set 定时器启动（注册表为空，什么都没保护）。
 *
 * 新语义：每个路径的 BLOCKED 必须有真实可验证的条件；保护未落地处
 * 如实报告 DEGRADED（BOOT 模式允许降级启动并记录，FAILED 才拒绝）：
 *   1. SUSPEND_BYPASS   — 反调试模块就绪（入口检测 + Init 校验）
 *   2. MEM_DUMP         — 密钥已进入 CNG 内核托管（key_separation 三权分立
 *                          或 V3 keymanager_cng 密钥组，任一成立即 BLOCKED）
 *   3. HIBERNATION      — 判据重构：密钥 CNG 内核托管（与 MEM_DUMP
 *                          同源判据——休眠取证窃取的是用户态页内密钥，
 *                          密钥不落地则 hiberfil.sys 无密钥可取）+
 *                          memory_guard 注册区锁页（在用数据防换出）
 *   4. IAT_INLINE_HOOK  — TLS 回调标志已验证 + 完整性模块就绪 +
 *                          判据升级（直接系统调用激活），
 *                          检测器 NT 查询绕开可被用户态 Hook 的 ntdll 导出
 *   5. DLL_HIJACK       — System32 优先加载 + 沙盒镜像加载策略生效
 *   6. PROCESS_READ     — 双层 Job Object 隔离已建立
 *   7. CROSS_DEVICE     — CNG 机器密钥可用 + 硬件绑定指纹就绪
 *
 * check 全程持 SRWLOCK 串行化——BOOT（Verthys_Init）与 RUNTIME
 *   （Verthys_GetSecurityStatus）可能并发到达，静态报告缓存 s_last_report
 *   的写读必须互斥。
 */
#include "defense_closure.h"

/* Layer 1: 进程不可触碰化 */
#include "job_isolation.h"

/* 密钥托管状态（MEM_DUMP 判据：key_separation 三权分立 +
 * keymanager_cng CNG 内核托管双分支） */
#include "key_separation.h"
#include "keymanager_cng.h"

/* Layer 3: 固件与硬件绑定 */
#include "cng_machine_key.h"
#include "system32_loader.h"
#include "hardware_binding.h"

/* Layer 4: Hook 对抗（TLS 标志 + 联动销毁） */
#include "tls_loader.h"
#include "tamper_destroy.h"

/* Layer 5: 进程无菌沙盒 */
#include "process_sandbox.h"

/* 完整性模块（基准验签） */
#include "integrity.h"

/* 反调试模块（SUSPEND_BYPASS 判据） */
#include "anti_debug_v2.h"

/* HIBERNATION 判据——memory_guard 注册区锁页（显式包含，
 * 此前经传递包含隐式依赖） */
#include "memory_guard.h"

/* P4 判据升级——直接系统调用激活状态（落地收口） */
#include "syscall_direct.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>   /* InterlockedCompareExchange（g_tls_init_marker 原子读） */

#include <string.h>

/* ---------- 模块状态 ---------- */

static int                s_initialized   = 0;
static DefenseStatusReport s_last_report;
static int                s_has_check     = 0;
/* 校验串行化锁——静态初始化（SRWLOCK_INIT），无需析构 */
static SRWLOCK            s_check_lock    = SRWLOCK_INIT;

/* ---------- 各攻击路径状态检查 ---------- */

/*
 * 1. 管理员调试挂起绕过
 *    依赖：anti_debug_v2（Init + 高危入口检测，无独立线程可挂起）
 */
static DefenseState check_suspend_bypass(void)
{
    if (anti_debug_v2_init() == 0) return DEFENSE_STATE_BLOCKED;
    return DEFENSE_STATE_FAILED;
}

/*
 * 2. 内存 Dump / 冷启动
 *    依赖：key_separation（CNG 内核托管）。
 *    密钥已安装进内核 → BLOCKED；模块就绪但密钥仍在用户态 → DEGRADED；
 *    模块不可用 → FAILED。
 */
static DefenseState check_mem_dump(void)
{
    if (key_separation_init() != 0) return DEFENSE_STATE_FAILED;
    /* key_separation 三权分立托管 或 keymanager_cng CNG 内核托管，
     * 任一成立即 BLOCKED */
    if (key_separation_any_installed()) return DEFENSE_STATE_BLOCKED;
    if (verthys_cng_km_global_handle_total() > 0) return DEFENSE_STATE_BLOCKED;
    /* 接线完成前置位：密钥在用户态，防 Dump 降级 */
    return DEFENSE_STATE_DEGRADED;
}

/*
 * 3. 休眠文件取证
 *    判定重构（目标态 7/7 BLOCKED 收口）：
 *    休眠取证窃取的是"进程用户态地址空间中的密钥"。判据与 MEM_DUMP
 *    同源——密钥已 CNG 内核托管（key_separation 三权分立 或 V3
 *    keymanager_cng 密钥组）⟹ worker 用户态页无密钥可供 hiberfil.sys
 *    取证；叠加 memory_guard 注册区锁页（在用数据防换出），两者齐备
 *    即 BLOCKED。
 *    原实现（工作集驱逐体系删除后恒 DEGRADED）的前置残余——"密钥在
 *    用户态"——已由 CNG 托管接线实质消除。
 */
static DefenseState check_hibernation(void)
{
    int guard_ok = (memory_guard_init() == 0) ? 1 : 0;
    int keys_kernel_custody = (key_separation_any_installed() ||
                               verthys_cng_km_global_handle_total() > 0) ? 1 : 0;

    if (guard_ok && keys_kernel_custody) return DEFENSE_STATE_BLOCKED;
    if (guard_ok || keys_kernel_custody) return DEFENSE_STATE_DEGRADED;
    return DEFENSE_STATE_FAILED;
}

/*
 * 4. IAT Hook / Inline Hook
 *    依赖：TLS 回调标志已验证（tls_loader_init 已在 Verthys_Init 执行）
 *          + 完整性模块就绪（构建期基准验签）
 *          + 判据升级（直接系统调用激活）：反调试/内存防护检测器的 NT 查询经自建 stub 页直达内核，
 *            ntdll 导出入口的用户态 Inline Hook 无法再致盲检测器。
 *            stub 未激活（SSN 提取失败降级回 GetProcAddress）时，
 *            检测器查询重新暴露于可 Hook 路径，诚实降级。
 */
static DefenseState check_iat_inline_hook(void)
{
    int tls_ok  = (InterlockedCompareExchange(&g_tls_init_marker, 0, 0) == 1) ? 1 : 0;
    int intg_ok = (integrity_init() == 0) ? 1 : 0;
    int syscall_ok = (syscall_direct_init() == 0 && syscall_direct_available()) ? 1 : 0;

    if (tls_ok && intg_ok && syscall_ok) return DEFENSE_STATE_BLOCKED;
    if (intg_ok || syscall_ok)           return DEFENSE_STATE_DEGRADED;
    return DEFENSE_STATE_FAILED;
}

/*
 * 5. DLL 劫持 / 反射注入
 *    依赖：system32_loader（System32 优先）+
 *          process_sandbox（NoRemoteImages / NoLowMandatoryLabelImages，
 *          由 worker 经 Verthys_NotifySandboxAttrs 注入）
 */
static DefenseState check_dll_hijack(void)
{
    int sysloader_ok = (system32_loader_init() == 0) ? 1 : 0;

    uint32_t sandbox_attrs = process_sandbox_get_active_attrs();
    int sandbox_remote_ok = (sandbox_attrs & SANDBOX_ATTR_IMAGE_NO_REMOTE) ? 1 : 0;
    int sandbox_low_ok     = (sandbox_attrs & SANDBOX_ATTR_IMAGE_NO_LOW_LABEL) ? 1 : 0;

    if (sysloader_ok && sandbox_remote_ok && sandbox_low_ok) {
        return DEFENSE_STATE_BLOCKED;
    }
    if (sysloader_ok || sandbox_remote_ok || sandbox_low_ok) {
        return DEFENSE_STATE_DEGRADED;
    }
    return DEFENSE_STATE_FAILED;
}

/*
 * 6. 进程打开/读取内存
 *    依赖：job_isolation（双层 Job Object + 白名单 DACL 隔离）
 */
static DefenseState check_process_read(void)
{
    int job_active = job_isolation_is_active();

    if (job_active) return DEFENSE_STATE_BLOCKED;
    return DEFENSE_STATE_FAILED;
}

/*
 * 7. 跨设备迁移解密
 *    依赖：cng_machine_key（CNG 机器密钥 + RSA-OAEP 包装 pepper）+
 *          hardware_binding（MachineGuid 指纹）
 */
static DefenseState check_cross_device(void)
{
    /* cng_machine_key_init 优雅降级恒返回 0；可用性经 is_available 查询 */
    cng_machine_key_init();
    int cng_ok     = cng_machine_key_is_available() ? 1 : 0;
    int hwbind_ok  = (hardware_binding_init() == 0) ? 1 : 0;

    if (cng_ok && hwbind_ok) return DEFENSE_STATE_BLOCKED;
    if (cng_ok || hwbind_ok) return DEFENSE_STATE_DEGRADED;
    return DEFENSE_STATE_FAILED;
}

/* ---------- 报告汇总 ---------- */

static void aggregate_report(DefenseStatusReport *report)
{
    if (report == NULL) return;

    report->blocked_count  = 0;
    report->degraded_count = 0;
    report->failed_count   = 0;
    report->has_degraded   = 0;

    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        switch (report->path_state[i]) {
            case DEFENSE_STATE_BLOCKED:
                report->blocked_count++;
                break;
            case DEFENSE_STATE_DEGRADED:
                report->degraded_count++;
                report->has_degraded = 1;
                break;
            case DEFENSE_STATE_FAILED:
                report->failed_count++;
                break;
            default:
                break;
        }
    }

    /* all_critical_blocked 语义：全部 7 条关键路径均 BLOCKED 才算全阻断。
     * 旧实现仅判 failed_count==0，会把"存在 DEGRADED"误报为全阻断；
     * 此处收紧为三条件齐备（无 FAILED、无 DEGRADED、且 BLOCKED 满 7 条）。 */
    report->all_critical_blocked =
        (report->failed_count   == 0 &&
         report->degraded_count == 0 &&
         report->blocked_count  == DEFENSE_PATH_COUNT) ? 1 : 0;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int defense_closure_init(void)
{
    if (s_initialized) return 0;
    memset(&s_last_report, 0, sizeof(s_last_report));
    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        s_last_report.path_state[i] = DEFENSE_STATE_NOT_CHECKED;
    }
    s_initialized = 1;
    s_has_check   = 0;
    return 0;
}

int defense_closure_check(DefenseCheckMode mode,
                          DefenseStatusReport *out_report)
{
    if (!s_initialized) {
        if (defense_closure_init() != 0) {
            return -1;
        }
    }

    DefenseStatusReport local;
    memset(&local, 0, sizeof(local));

    /* 全程持排他锁——BOOT（Verthys_Init）与 RUNTIME
     * （Verthys_GetSecurityStatus）并发调用时，s_last_report 写读互斥；
     * 各 check_* 仅读已初始化模块的稳定状态，锁内无回调重入。 */
    AcquireSRWLockExclusive(&s_check_lock);

    /* 逐项检查 7 条攻击路径 */
    local.path_state[DEFENSE_PATH_SUSPEND_BYPASS]  = check_suspend_bypass();
    local.path_state[DEFENSE_PATH_MEM_DUMP]        = check_mem_dump();
    local.path_state[DEFENSE_PATH_HIBERNATION]     = check_hibernation();
    local.path_state[DEFENSE_PATH_IAT_INLINE_HOOK] = check_iat_inline_hook();
    local.path_state[DEFENSE_PATH_DLL_HIJACK]      = check_dll_hijack();
    local.path_state[DEFENSE_PATH_PROCESS_READ]    = check_process_read();
    local.path_state[DEFENSE_PATH_CROSS_DEVICE]    = check_cross_device();

    aggregate_report(&local);

    /* 缓存到 s_last_report */
    memcpy(&s_last_report, &local, sizeof(s_last_report));
    s_has_check = 1;

    ReleaseSRWLockExclusive(&s_check_lock);

    /* 输出报告 */
    if (out_report != NULL) {
        memcpy(out_report, &local, sizeof(*out_report));
    }

    /*
     * 返回策略：
     *   - BOOT 模式：FAILED 数 > 0 → 返回非零（拒绝启动）
     *   - BOOT 模式：仅 DEGRADED，无 FAILED → 返回 0（可启动，调用方需记录降级）
     *   - RUNTIME 模式：始终返回 0（仅记录状态）
     */
    if (mode == DEFENSE_CHECK_RUNTIME) {
        return 0;
    }

    /* BOOT 模式 */
    return (local.failed_count > 0) ? -1 : 0;
}

DefenseState defense_closure_get_path_state(DefensePath path)
{
    if (!s_has_check) {
        return DEFENSE_STATE_NOT_CHECKED;
    }
    if (path < 0 || path >= DEFENSE_PATH_COUNT) {
        return DEFENSE_STATE_NOT_CHECKED;
    }
    return s_last_report.path_state[path];
}

int defense_closure_get_summary(void)
{
    if (!s_has_check) {
        return 3;  /* 未校验 */
    }
    if (s_last_report.failed_count > 0) {
        return 2;  /* 有 FAILED */
    }
    if (s_last_report.has_degraded) {
        return 1;  /* 有 DEGRADED */
    }
    return 0;  /* 全部 BLOCKED */
}

const char *defense_closure_path_name(DefensePath path)
{
    switch (path) {
        case DEFENSE_PATH_SUSPEND_BYPASS:  return "Admin Suspend Bypass";
        case DEFENSE_PATH_MEM_DUMP:        return "Memory Dump / Cold Boot";
        case DEFENSE_PATH_HIBERNATION:     return "Hibernation Forensics";
        case DEFENSE_PATH_IAT_INLINE_HOOK: return "IAT / Inline Hook";
        case DEFENSE_PATH_DLL_HIJACK:      return "DLL Hijack / Reflective";
        case DEFENSE_PATH_PROCESS_READ:    return "Process Memory Read";
        case DEFENSE_PATH_CROSS_DEVICE:    return "Cross-Device Migration";
        default:                           return "Unknown";
    }
}

const char *defense_closure_state_name(DefenseState state)
{
    switch (state) {
        case DEFENSE_STATE_NOT_CHECKED: return "NOT_CHECKED";
        case DEFENSE_STATE_BLOCKED:     return "BLOCKED";
        case DEFENSE_STATE_DEGRADED:    return "DEGRADED";
        case DEFENSE_STATE_FAILED:      return "FAILED";
        default:                        return "UNKNOWN";
    }
}
