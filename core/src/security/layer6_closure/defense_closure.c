/*
 * defense_closure.c — 闭环防御能力验证状态机实现
 *
 * 判据来源（全部为当前进程 / 当前会话的可验证事实）：
 *   0 挂起绕过 — 无驻留密钥时 BLOCKED；有密钥时 DEGRADED，看门狗未接线
 *                 记 SUSPEND_GUARD_INACTIVE（可修复），接线后仅剩管理员
 *                 挂起这一架构限制（SUSPEND_UNPREVENTABLE）。
 *   1 内存转储 — 无驻留密钥时 BLOCKED；V4 密钥驻留用户态时 DEGRADED。
 *   2 休眠取证 — 无驻留密钥或系统休眠关闭时 BLOCKED；休眠启用/状态未知
 *                 且有驻留密钥时 DEGRADED。
 *   3 接口挂钩 — TLS 加载标志缺失为 FAILED；扫描异常为 FAILED；扫描
 *                 不可用/过期或直连系统调用未激活为 DEGRADED；扫描干净
 *                 且直连可用为 BLOCKED。
 *   4 动态劫持 — 只采信 OS 回读的 mitigation 位：核心位齐备 BLOCKED，
 *                 部分/无法确认 DEGRADED。
 *   5 进程读取 — 双层 Job Object 生效时 BLOCKED，否则 FAILED。
 *   6 跨设备迁移 — 被查询会话已解锁、绑定槽存在、机器密钥可用且硬件
 *                 指纹就绪时 BLOCKED；否则 DEGRADED（无事实/不可用）。
 *
 * 检查全程持 SRWLOCK 串行化——BOOT（Verthys_Init）与 RUNTIME
 * （Verthys_GetSecurityStatus）可能并发到达，静态报告缓存 s_last_report
 * 的写读必须互斥。检查过程不调用任何 *_init，不创建句柄与定时器。
 */
#include "defense_closure.h"

/* Layer 1: 进程不可触碰化 */
#include "job_isolation.h"

/* Layer 3: 固件与硬件绑定（只读可用性查询） */
#include "cng_machine_key.h"
#include "hardware_binding.h"

/* Layer 4: Hook 对抗（TLS 加载标志） */
#include "tls_loader.h"

/* Layer 5: 进程无菌沙盒（事实位由 fill_process_facts 写入） */
#include "process_sandbox.h"

/* 预设策略（anti_dump 开关进入 policy_flags，仅用于 UI 提示） */
#include "security_preset.h"

/* 休眠状态（hiberfil 取证判据） */
#include "hibernation_state.h"

/* Inline Hook / IAT 基线扫描结论 */
#include "hook_scan.h"

/* P4 判据——直接系统调用激活状态（只读查询） */
#include "syscall_direct.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>   /* InterlockedCompareExchange / FILETIME / SRWLOCK */

#include <string.h>

/* ---------- 模块状态 ---------- */

static INIT_ONCE         s_init_once     = INIT_ONCE_STATIC_INIT;
static DefenseStatusReport s_last_report;
static int               s_has_check     = 0;
/* 校验串行化锁——静态初始化（SRWLOCK_INIT），无需析构 */
static SRWLOCK           s_check_lock    = SRWLOCK_INIT;
/* 运行时守卫位：bit0=心跳运行 bit1=挂起守卫接线；完整掩码语义 */
static volatile LONG     s_runtime_guards = 0;

static BOOL CALLBACK dcl_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once;
    (void)param;
    (void)ctx;

    memset(&s_last_report, 0, sizeof(s_last_report));
    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        s_last_report.path_state[i]  = DEFENSE_STATE_NOT_CHECKED;
        s_last_report.path_reason[i] = DEFENSE_REASON_NONE;
    }
    s_has_check = 0;
    return TRUE;
}

/* 沙盒核心 mitigation 位：仅接受 OS 可回读确认的项——子进程创建 /
 * 远程与低完整性镜像 / ACG。System32 优先由 worker 在加载 DLL 之前
 * 固定，Windows 不提供回读接口，故不把不可证明的项塞进核心位。
 * 判定只接受 OS 回读结果（sandbox_verified_mask），worker 自报位不参与。 */
#define DCL_SANDBOX_CORE_MASK (SANDBOX_ATTR_PROCESS_CREATE_DISABLE | \
                               SANDBOX_ATTR_IMAGE_NO_REMOTE | \
                               SANDBOX_ATTR_IMAGE_NO_LOW_LABEL | \
                               SANDBOX_ATTR_ACG)

/* ---------- 各攻击路径状态检查 ---------- */

/*
 * 0. 管理员调试挂起绕过
 *    无驻留密钥时没有可窃取资产，按 BLOCKED；有密钥时管理员挂起无法
 *    从根本上阻止，只能靠看门狗缩短暴露窗口，故恒为 DEGRADED。
 */
static DefenseState check_suspend_bypass(const DefenseFacts *facts,
                                         DefenseReason *reason)
{
    if (facts->any_unlocked_v4 == 0) {
        *reason = DEFENSE_REASON_NO_RESIDENT_KEY;
        return DEFENSE_STATE_BLOCKED;
    }
    /* 心跳与挂起守卫必须同时接线才认为看门狗生效；只接一半等于没有
     * 处置路径，仍按可修复缺口报告。 */
    if ((facts->policy_flags &
         (DEFENSE_GUARD_HEARTBEAT | DEFENSE_GUARD_SUSPEND_LOCK)) ==
        (DEFENSE_GUARD_HEARTBEAT | DEFENSE_GUARD_SUSPEND_LOCK)) {
        *reason = DEFENSE_REASON_SUSPEND_UNPREVENTABLE;
    } else {
        *reason = DEFENSE_REASON_SUSPEND_GUARD_INACTIVE;
    }
    return DEFENSE_STATE_DEGRADED;
}

/*
 * 1. 内存 Dump / 冷启动
 *    V4 内容密钥驻留用户态堆，解锁进程可被完整转储；内核托管暂缓前
 *    该路径只能诚实报告降级。policy_flags 中的 anti_dump 仅用于 UI
 *    提示，不改变判据。
 */
static DefenseState check_mem_dump(const DefenseFacts *facts,
                                   DefenseReason *reason)
{
    if (facts->any_unlocked_v4 == 0) {
        *reason = DEFENSE_REASON_NO_RESIDENT_KEY;
        return DEFENSE_STATE_BLOCKED;
    }
    *reason = DEFENSE_REASON_V4_KEYS_USER_RESIDENT;
    return DEFENSE_STATE_DEGRADED;
}

/*
 * 2. 休眠文件取证
 *    休眠文件保存的是物理内存镜像。无驻留密钥时无可取证资产；系统休眠
 *    已禁用时 hiberfil 不存在，同样无可取证资产——两种情况均按 BLOCKED。
 *    休眠启用或状态无法证明且存在驻留密钥时，按降级如实上报。
 */
static DefenseState check_hibernation(const DefenseFacts *facts,
                                      DefenseReason *reason)
{
    if (facts->any_unlocked_v4 == 0) {
        *reason = DEFENSE_REASON_NO_RESIDENT_KEY;
        return DEFENSE_STATE_BLOCKED;
    }
    if (facts->hibernation_state == 0) {
        *reason = DEFENSE_REASON_HIBERNATION_DISABLED;
        return DEFENSE_STATE_BLOCKED;
    }
    if (facts->hibernation_state == 1) {
        *reason = DEFENSE_REASON_HIBERNATION_ENABLED;
        return DEFENSE_STATE_DEGRADED;
    }
    *reason = DEFENSE_REASON_HIBERNATION_UNKNOWN;
    return DEFENSE_STATE_DEGRADED;
}

/*
 * 3. IAT Hook / Inline Hook
 *    TLS 加载标志缺失说明 DLL 加载路径被改写（可能被剥除 TLS 目录重打包），
 *    按 FAILED。扫描结果分三档：异常 FAILED、过期/不可用 DEGRADED、
 *    干净且直连系统调用激活 BLOCKED。直连未激活时检测器的 NT 查询重新
 *    暴露于可 Hook 的 ntdll 导出，不能算闭合。
 */
static DefenseState check_iat_inline_hook(const DefenseFacts *facts,
                                          DefenseReason *reason)
{
    int tls_ok = (InterlockedCompareExchange(&g_tls_init_marker, 0, 0) == 1)
                     ? 1 : 0;
    int syscall_ok = syscall_direct_available() ? 1 : 0;

    if (!tls_ok) {
        *reason = DEFENSE_REASON_MODULE_INIT_FAILED;
        return DEFENSE_STATE_FAILED;
    }

    switch (facts->hook_scan_state) {
        case 2:  /* 扫描发现 Hook 特征 */
            *reason = DEFENSE_REASON_HOOK_DETECTED;
            return DEFENSE_STATE_FAILED;
        case 3:  /* 证据超过有效期 */
            *reason = DEFENSE_REASON_EVIDENCE_STALE;
            return DEFENSE_STATE_DEGRADED;
        case 1:  /* 最近一次扫描干净 */
            if (syscall_ok) {
                *reason = DEFENSE_REASON_HOOK_SCAN_CLEAN;
                return DEFENSE_STATE_BLOCKED;
            }
            *reason = DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE;
            return DEFENSE_STATE_DEGRADED;
        default: /* 0=不可用 / 未知值按不可用处理 */
            *reason = DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE;
            return DEFENSE_STATE_DEGRADED;
    }
}

/*
 * 4. DLL 劫持 / 反射注入
 *    mitigation 位只能由 OS 回读确认；worker 自报位可能被伪造或过时，
 *    不进入判据。核心位齐备 BLOCKED，缺位或无法回读 DEGRADED。
 */
static DefenseState check_dll_hijack(const DefenseFacts *facts,
                                     DefenseReason *reason)
{
    uint32_t verified = facts->sandbox_verified_mask;

    if (verified == 0) {
        *reason = DEFENSE_REASON_SANDBOX_UNVERIFIED;
        return DEFENSE_STATE_DEGRADED;
    }
    if ((verified & DCL_SANDBOX_CORE_MASK) == DCL_SANDBOX_CORE_MASK) {
        *reason = DEFENSE_REASON_SANDBOX_VERIFIED;
        return DEFENSE_STATE_BLOCKED;
    }
    *reason = DEFENSE_REASON_SANDBOX_PARTIAL;
    return DEFENSE_STATE_DEGRADED;
}

/*
 * 5. 进程打开/读取内存
 *    双层 Job Object + 白名单 DACL 是真实的内核级隔离；未生效说明关键
 *    防御缺失，按 FAILED（BOOT 模式拒绝启动）。
 */
static DefenseState check_process_read(const DefenseFacts *facts,
                                       DefenseReason *reason)
{
    (void)facts;

    if (job_isolation_is_active()) {
        *reason = DEFENSE_REASON_JOB_ACTIVE;
        return DEFENSE_STATE_BLOCKED;
    }
    *reason = DEFENSE_REASON_MODULE_INIT_FAILED;
    return DEFENSE_STATE_FAILED;
}

/*
 * 6. 跨设备迁移解密
 *    只有被查询会话已解锁且设备根/PCR 槽存在时，绑定事实才成立；机器
 *    密钥与硬件指纹是绑定能落地的先决条件。硬件指纹不可用说明初始化
 *    失败（FAILED）；机器密钥不可用或没有绑定事实按 DEGRADED。
 */
static DefenseState check_cross_device(const DefenseFacts *facts,
                                       DefenseReason *reason)
{
    if (facts->queried_unlocked_v4 == 0) {
        *reason = DEFENSE_REASON_NO_SESSION_FACTS;
        return DEFENSE_STATE_DEGRADED;
    }
    if (!hardware_binding_is_ready()) {
        *reason = DEFENSE_REASON_MODULE_INIT_FAILED;
        return DEFENSE_STATE_FAILED;
    }
    if (!cng_machine_key_is_available()) {
        *reason = DEFENSE_REASON_NO_SESSION_FACTS;
        return DEFENSE_STATE_DEGRADED;
    }
    if (facts->queried_device_bound || facts->queried_pcr_bound) {
        *reason = DEFENSE_REASON_DEVICE_BOUND;
        return DEFENSE_STATE_BLOCKED;
    }
    *reason = DEFENSE_REASON_NO_SESSION_FACTS;
    return DEFENSE_STATE_DEGRADED;
}

/* ---------- 报告汇总 ---------- */

static void aggregate_report(DefenseStatusReport *report)
{
    if (report == NULL) return;

    report->blocked_count  = 0;
    report->degraded_count = 0;
    report->failed_count   = 0;
    report->limited_count  = 0;
    report->has_degraded   = 0;

    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        switch (report->path_state[i]) {
            case DEFENSE_STATE_BLOCKED:
                report->blocked_count++;
                break;
            case DEFENSE_STATE_DEGRADED:
                report->degraded_count++;
                report->has_degraded = 1;
                /* 架构限制只统计两项：内核托管暂缓（密钥驻留用户态）与
                 * 管理员挂起不可阻止。其余降级属于可修复缺口，不得混入
                 * "受架构限制"口径。 */
                if (report->path_reason[i] ==
                        DEFENSE_REASON_V4_KEYS_USER_RESIDENT ||
                    report->path_reason[i] ==
                        DEFENSE_REASON_SUSPEND_UNPREVENTABLE) {
                    report->limited_count++;
                }
                break;
            case DEFENSE_STATE_FAILED:
                report->failed_count++;
                break;
            default:
                break;
        }
    }

    /* all_critical_blocked 语义：全部 7 条关键路径均 BLOCKED 才算全阻断。
     * 存在 DEGRADED 一律为 0——未实施内核托管前解锁态必然为 0，这是
     * 诚实结果，不得为面板好看放宽语义。 */
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
    InitOnceExecuteOnce(&s_init_once, dcl_init_once, NULL, NULL);
    return 0;
}

void defense_closure_set_runtime_guards(uint32_t flags)
{
    LONG masked = (LONG)(flags &
                        (DEFENSE_GUARD_HEARTBEAT | DEFENSE_GUARD_SUSPEND_LOCK));
    InterlockedExchange(&s_runtime_guards, masked);
}

uint32_t defense_closure_get_runtime_guards(void)
{
    return (uint32_t)InterlockedCompareExchange(&s_runtime_guards, 0, 0);
}

void defense_closure_fill_process_facts(DefenseFacts *facts)
{
    SecurityConfig cfg;
    FILETIME ft;
    uint64_t filetime;

    if (facts == NULL) return;

    /* 休眠状态从注册表读取（禁用/启用/未知三态）；读取失败按未知降级。
     * Hook 扫描结论来自最近一次有效扫描（超过 120s 自动转 STALE）。 */
    facts->hibernation_state = hibernation_state_query();
    facts->hook_scan_state   = hook_scan_get_state();

    /* mitigation 只能由 OS 回读确认：查询失败按“无法确认”置 0，
     * 查询成功则使用系统返回的实际生效位；自报位不进入事实。 */
    {
        uint32_t verified = 0;
        if (process_sandbox_verify_os(&verified) == 0) {
            facts->sandbox_verified_mask = verified;
        } else {
            facts->sandbox_verified_mask = 0;
        }
    }

    memset(&cfg, 0, sizeof(cfg));
    (void)security_config_snapshot(&cfg);
    facts->policy_flags = defense_closure_get_runtime_guards();
    if (cfg.anti_dump) {
        facts->policy_flags |= DEFENSE_POLICY_ANTI_DUMP;
    }

    /* FILETIME（1601 纪元，100ns）→ Unix 毫秒 */
    GetSystemTimeAsFileTime(&ft);
    filetime = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    facts->now_ms = filetime / 10000u - 11644473600000ull;
}

int defense_closure_check_facts(DefenseCheckMode mode,
                                const DefenseFacts *facts,
                                DefenseStatusReport *out_report)
{
    DefenseStatusReport local;

    if (facts == NULL) return -1;
    (void)defense_closure_init();

    memset(&local, 0, sizeof(local));

    /* 全程持排他锁——BOOT（Verthys_Init）与 RUNTIME
     * （Verthys_GetSecurityStatus）并发调用时，s_last_report 写读互斥；
     * 各 check_* 仅读调用方已复制的 facts 与只读模块状态，锁内无回调重入。 */
    AcquireSRWLockExclusive(&s_check_lock);

    local.path_state[DEFENSE_PATH_SUSPEND_BYPASS] =
        check_suspend_bypass(facts, &local.path_reason[DEFENSE_PATH_SUSPEND_BYPASS]);
    local.path_state[DEFENSE_PATH_MEM_DUMP] =
        check_mem_dump(facts, &local.path_reason[DEFENSE_PATH_MEM_DUMP]);
    local.path_state[DEFENSE_PATH_HIBERNATION] =
        check_hibernation(facts, &local.path_reason[DEFENSE_PATH_HIBERNATION]);
    local.path_state[DEFENSE_PATH_IAT_INLINE_HOOK] =
        check_iat_inline_hook(facts, &local.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK]);
    local.path_state[DEFENSE_PATH_DLL_HIJACK] =
        check_dll_hijack(facts, &local.path_reason[DEFENSE_PATH_DLL_HIJACK]);
    local.path_state[DEFENSE_PATH_PROCESS_READ] =
        check_process_read(facts, &local.path_reason[DEFENSE_PATH_PROCESS_READ]);
    local.path_state[DEFENSE_PATH_CROSS_DEVICE] =
        check_cross_device(facts, &local.path_reason[DEFENSE_PATH_CROSS_DEVICE]);

    local.checked_at_unix_ms = facts->now_ms;
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

int defense_closure_check(DefenseCheckMode mode,
                          DefenseStatusReport *out_report)
{
    DefenseFacts facts;

    memset(&facts, 0, sizeof(facts));
    defense_closure_fill_process_facts(&facts);
    /* 兼容包装不持有句柄：会话事实全部为 0（BOOT 语义）。 */
    return defense_closure_check_facts(mode, &facts, out_report);
}

DefenseState defense_closure_get_path_state(DefensePath path)
{
    DefenseState state = DEFENSE_STATE_NOT_CHECKED;

    if (path < 0 || path >= DEFENSE_PATH_COUNT) {
        return DEFENSE_STATE_NOT_CHECKED;
    }

    AcquireSRWLockShared(&s_check_lock);
    if (s_has_check) {
        state = s_last_report.path_state[path];
    }
    ReleaseSRWLockShared(&s_check_lock);
    return state;
}

int defense_closure_get_summary(void)
{
    int summary = 3;  /* 未校验 */

    AcquireSRWLockShared(&s_check_lock);
    if (s_has_check) {
        if (s_last_report.failed_count > 0) {
            summary = 2;  /* 有 FAILED */
        } else if (s_last_report.has_degraded) {
            summary = 1;  /* 有 DEGRADED */
        } else {
            summary = 0;  /* 全部 BLOCKED */
        }
    }
    ReleaseSRWLockShared(&s_check_lock);
    return summary;
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

const char *defense_closure_reason_name(DefenseReason reason)
{
    switch (reason) {
        case DEFENSE_REASON_NONE:                      return "NONE";
        case DEFENSE_REASON_NO_RESIDENT_KEY:           return "NO_RESIDENT_KEY";
        case DEFENSE_REASON_V4_KEYS_USER_RESIDENT:     return "V4_KEYS_USER_RESIDENT";
        case DEFENSE_REASON_HIBERNATION_ENABLED:       return "HIBERNATION_ENABLED";
        case DEFENSE_REASON_HIBERNATION_UNKNOWN:       return "HIBERNATION_UNKNOWN";
        case DEFENSE_REASON_SUSPEND_UNPREVENTABLE:     return "SUSPEND_UNPREVENTABLE";
        case DEFENSE_REASON_SUSPEND_GUARD_INACTIVE:    return "SUSPEND_GUARD_INACTIVE";
        case DEFENSE_REASON_HOOK_SCAN_CLEAN:           return "HOOK_SCAN_CLEAN";
        case DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE:     return "HOOK_SCAN_UNAVAILABLE";
        case DEFENSE_REASON_HOOK_DETECTED:             return "HOOK_DETECTED";
        case DEFENSE_REASON_SANDBOX_VERIFIED:          return "SANDBOX_VERIFIED";
        case DEFENSE_REASON_SANDBOX_PARTIAL:           return "SANDBOX_PARTIAL";
        case DEFENSE_REASON_SANDBOX_UNVERIFIED:        return "SANDBOX_UNVERIFIED";
        case DEFENSE_REASON_JOB_ACTIVE:                return "JOB_ACTIVE";
        case DEFENSE_REASON_DEVICE_BOUND:              return "DEVICE_BOUND";
        case DEFENSE_REASON_NO_SESSION_FACTS:          return "NO_SESSION_FACTS";
        case DEFENSE_REASON_MODULE_INIT_FAILED:        return "MODULE_INIT_FAILED";
        case DEFENSE_REASON_POLICY_DISABLED:            return "POLICY_DISABLED";
        case DEFENSE_REASON_EVIDENCE_STALE:            return "EVIDENCE_STALE";
        case DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED: return "ARCH_LIMIT_KERNEL_DEFERRED";
        case DEFENSE_REASON_HIBERNATION_DISABLED:      return "HIBERNATION_DISABLED";
        default:                                       return "UNKNOWN";
    }
}
