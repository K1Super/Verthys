/*
 * verthys_api_security.c — 进程级安全姿态与只读状态门面
 *
 * 只承载与句柄生命周期无关的进程级安全控制与状态查询：沙盒/守卫通知、
 * 预设切档与特性位、库级熔断、动态防护状态、内核状态、内建诊断。
 * 公共枚举与内部枚举的编译期对齐契约随本文件锁定。
 */
#include "verthys_api_utils.h"
#include "verthys_security_runtime.h"

#include "vty_keymanager.h"        /* vty_vault_binding_info */
#include "vty_machine_limiter.h"
#include "vty_lockout.h"
#include "process_sandbox.h"
#include "defense_closure.h"
#include "anti_inject.h"
#include "security_preset.h"
#include "verthys_pepper.h"

#include <stddef.h>
#include <string.h>

/*
 * 通知 DLL 当前 Worker 进程已应用的沙盒属性
 *
 * Worker（Rust 端）在加载本 DLL 之前已通过 apply_process_sandbox()
 * 应用进程级 mitigation policy（ProcessSystemCallDisablePolicy、
 * ProcessChildProcessPolicy、SetDefaultDllDirectories、ProcessImageLoadPolicy）。
 *
 * Worker 在加载本 DLL 后、调用 Verthys_Init 之前调用本函数，
 * 将已应用的属性位掩码注入本模块，使后续 defense_closure_check
 * 能正确识别已生效的防御策略。
 *
 *   attrs: 已应用的属性位掩码（与 process_sandbox.h 中的 SANDBOX_ATTR_* 对齐）
 */
VerthysResult Verthys_NotifySandboxAttrs(uint32_t attrs)
{
    process_sandbox_set_active_attrs(attrs);
    return VERTHYS_OK;
}

/*
 * 通知运行时守卫状态（API 版本 0x0014）
 *
 * 完整掩码写入（非累加 OR）：worker 每次心跳/守卫变更都提交当前全量
 * 掩码，停止守卫时提交 0。未知位在 C 层丢弃，防止调用方污染判据。
 */
VerthysResult Verthys_NotifyRuntimeGuards(uint32_t flags)
{
    uint32_t before = defense_closure_get_runtime_guards();
    defense_closure_set_runtime_guards(flags);
    uint32_t after = defense_closure_get_runtime_guards();

    /* 心跳位首次置位：worker 心跳线程晚于 anti_inject_init 创建，
     * 必须刷新外部线程基线，否则 300s 周期巡检会把常驻心跳线程
     * 误判为远程注入。 */
    if ((before & DEFENSE_GUARD_HEARTBEAT) == 0 &&
        (after & DEFENSE_GUARD_HEARTBEAT) != 0) {
        anti_inject_refresh_baseline();
    }
    return VERTHYS_OK;
}

/* 运行时切换安全预设档位。
 *
 * SecurityPreset 与 VerthysPreset 数值一致（0=BALANCED/1=SECURE/
 * 2=PERFORMANCE），此处显式映射不依赖枚举值巧合。
 * security_preset_switch 内部以双缓冲填充 + InterlockedExchangePointer
 * 原子发布：任何时刻读者看到的都是完整配置快照，无全零窗口。
 * 本接口不触碰容器句柄状态（仅校验非 NULL），切换为进程级运行时
 * 配置变更，不要求容器已解锁——应用层在此之前完成会话授权裁决。 */
VerthysResult Verthys_SwitchSecurityPreset(VerthysHandle handle, VerthysPreset preset)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;

    SecurityPreset sp;
    switch (preset) {
        case VERTHYS_PRESET_BALANCED:    sp = SEC_PRESET_BALANCED;    break;
        case VERTHYS_PRESET_SECURE:      sp = SEC_PRESET_SECURE;      break;
        case VERTHYS_PRESET_PERFORMANCE: sp = SEC_PRESET_PERFORMANCE; break;
        /* CUSTOM 无 C 层档位定义，由应用层组合各子系统开关实现 */
        default: return VERTHYS_ERR_INVALID;
    }

    if (security_preset_switch(sp) != 0) {
        return VERTHYS_ERR_INVALID;
    }
    /* 切到 SECURE 立即尝试保护本进程；切出 SECURE 解除保护。 */
    vty_machine_limiter_kernel_guard_apply_preset();
    return VERTHYS_OK;
}

/* 运行时查询活跃安全预设档位。
 *
 * 取自活跃配置快照，供调用方做切档回读校验：切档后读回值与请求值
 * 不一致即可判定切换未生效（宿主据此回滚持久化并报错）。
 * 线程安全：MT-Safe（快照读取，无锁）。 */
VerthysResult Verthys_GetSecurityPreset(VerthysHandle handle, uint32_t *out_preset)
{
    if (handle == NULL || out_preset == NULL) return VERTHYS_ERR_INVALID;

    SecurityPreset sp = security_runtime_preset();
    if (sp != SEC_PRESET_BALANCED && sp != SEC_PRESET_SECURE &&
        sp != SEC_PRESET_PERFORMANCE) {
        return VERTHYS_ERR_INVALID;
    }
    *out_preset = (uint32_t)sp;
    return VERTHYS_OK;
}

/* 只读查询库级熔断剩余秒数：供宿主在 VERTHYS_ERR_RATE 响应后展示
 * “已锁定 X 秒”。不消耗尝试额度、不改变计数；查询失败按 0 返回，不
 * 改变既有错误链。 */
VerthysResult Verthys_GetLibLockoutRemaining(uint32_t *out_secs)
{
    if (out_secs == NULL) return VERTHYS_ERR_INVALID;
    *out_secs = 0;
    if (!vty_lockout_enabled()) return VERTHYS_OK;
    if (vty_lockout_init() != VTY_OK) return VERTHYS_ERR_TPM;
    (void)vty_lockout_remaining_secs(out_secs);
    return VERTHYS_OK;
}

/* 运行时查询指定预设档位的特性位投影（11 位跨层特性契约）。
 *
 * 投影是档位矩阵的唯一权威输出：宿主展示与执行均以此为准，
 * 消除多端各自维护特性表导致的语义漂移。
 * 线程安全：MT-Safe。 */
VerthysResult Verthys_GetPresetFeatureBits(VerthysHandle handle,
                                           VerthysPreset preset,
                                           uint32_t *out_bits)
{
    if (handle == NULL || out_bits == NULL) return VERTHYS_ERR_INVALID;

    SecurityPreset sp;
    switch (preset) {
        case VERTHYS_PRESET_BALANCED:    sp = SEC_PRESET_BALANCED;    break;
        case VERTHYS_PRESET_SECURE:      sp = SEC_PRESET_SECURE;      break;
        case VERTHYS_PRESET_PERFORMANCE: sp = SEC_PRESET_PERFORMANCE; break;
        default: return VERTHYS_ERR_INVALID;
    }

    if (security_preset_feature_bits(sp, out_bits) != 0) {
        return VERTHYS_ERR_INVALID;
    }
    return VERTHYS_OK;
}

/* ================================================================== *
 * 内建诊断接口
 *
 * 返回运行时采集的结构化状态指标（扫描游标打开次数/锁等待/胡椒来源），
 * 供安全中心展示和问题定位。所有指标均为非敏感数据。
 *
 * 线程安全：MT-Const（只读操作，可与其它只读操作并发）
 * ================================================================== */
VerthysResult Verthys_GetDiagnostics(VerthysHandle handle, VerthysDiagnostics *out_diag)
{
    if (handle == NULL || out_diag == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    /* 读操作使用共享锁，允许多个读取并发执行：诊断数据为非敏感指标，
     * 可与 GetRecord/GetContainerInfo/VerifyIntegrity/Export 并发。 */
    verthys_ctx_lock_shared(ctx);

    memset(out_diag, 0, sizeof(*out_diag));

    /* 扫描指标 */
    out_diag->scan_open_count       = ctx->diag_scan_open_count;
    /* 胡椒来源（诊断，不暴露胡椒值） */
    out_diag->pepper_source         = (uint8_t)verthys_pepper_get_source();
    /* 可观测性指标 */
    out_diag->lock_wait_ms          = ctx->diag_lock_wait_ms;
    /* preheat_status 保留 ABI 字段；当前容器格式无预热状态，保持 0。 */

    verthys_ctx_unlock_shared(ctx);
    return VERTHYS_OK;
}

/* ================================================================== *
 * 动态防护状态查询（API 版本 0x000B）：
 *
 * 每次调用执行 RUNTIME 级实时复检（defense_closure_check 内部
 * SRWLOCK 串行化，并发调用安全）；防御状态为进程级事实，不依赖
 * 容器解锁状态，锁定态/未挂载态均可查询。
 *
 * 线程安全：MT-Safe
 * ================================================================== */

/* 公共枚举镜像与内部枚举值域对齐的编译期契约
 * （Verthys_GetSecurityStatus 逐字段映射的正确性依赖此对齐） */
_Static_assert((int)VERTHYS_DEFENSE_NOT_CHECKED == (int)DEFENSE_STATE_NOT_CHECKED &&
               (int)VERTHYS_DEFENSE_BLOCKED     == (int)DEFENSE_STATE_BLOCKED &&
               (int)VERTHYS_DEFENSE_DEGRADED    == (int)DEFENSE_STATE_DEGRADED &&
               (int)VERTHYS_DEFENSE_FAILED      == (int)DEFENSE_STATE_FAILED,
               "public VerthysDefenseState out of sync with internal DefenseState");
_Static_assert((int)VERTHYS_DEFENSE_PATH_COUNT == (int)DEFENSE_PATH_COUNT,
               "public VerthysDefensePath count out of sync with internal DefensePath");
_Static_assert((int)VERTHYS_DEFENSE_REASON_NONE == (int)DEFENSE_REASON_NONE &&
               (int)VERTHYS_DEFENSE_REASON_NO_RESIDENT_KEY ==
                   (int)DEFENSE_REASON_NO_RESIDENT_KEY &&
               (int)VERTHYS_DEFENSE_REASON_V4_KEYS_USER_RESIDENT ==
                   (int)DEFENSE_REASON_KEYS_USER_RESIDENT &&
               (int)VERTHYS_DEFENSE_REASON_HIBERNATION_ENABLED ==
                   (int)DEFENSE_REASON_HIBERNATION_ENABLED &&
               (int)VERTHYS_DEFENSE_REASON_HIBERNATION_UNKNOWN ==
                   (int)DEFENSE_REASON_HIBERNATION_UNKNOWN &&
               (int)VERTHYS_DEFENSE_REASON_SUSPEND_UNPREVENTABLE ==
                   (int)DEFENSE_REASON_SUSPEND_UNPREVENTABLE &&
               (int)VERTHYS_DEFENSE_REASON_SUSPEND_GUARD_INACTIVE ==
                   (int)DEFENSE_REASON_SUSPEND_GUARD_INACTIVE &&
               (int)VERTHYS_DEFENSE_REASON_HOOK_SCAN_CLEAN ==
                   (int)DEFENSE_REASON_HOOK_SCAN_CLEAN &&
               (int)VERTHYS_DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE ==
                   (int)DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE &&
               (int)VERTHYS_DEFENSE_REASON_HOOK_DETECTED ==
                   (int)DEFENSE_REASON_HOOK_DETECTED &&
               (int)VERTHYS_DEFENSE_REASON_SANDBOX_VERIFIED ==
                   (int)DEFENSE_REASON_SANDBOX_VERIFIED &&
               (int)VERTHYS_DEFENSE_REASON_SANDBOX_PARTIAL ==
                   (int)DEFENSE_REASON_SANDBOX_PARTIAL &&
               (int)VERTHYS_DEFENSE_REASON_SANDBOX_UNVERIFIED ==
                   (int)DEFENSE_REASON_SANDBOX_UNVERIFIED &&
               (int)VERTHYS_DEFENSE_REASON_JOB_ACTIVE ==
                   (int)DEFENSE_REASON_JOB_ACTIVE &&
               (int)VERTHYS_DEFENSE_REASON_DEVICE_BOUND ==
                   (int)DEFENSE_REASON_DEVICE_BOUND &&
               (int)VERTHYS_DEFENSE_REASON_NO_SESSION_FACTS ==
                   (int)DEFENSE_REASON_NO_SESSION_FACTS &&
               (int)VERTHYS_DEFENSE_REASON_MODULE_INIT_FAILED ==
                   (int)DEFENSE_REASON_MODULE_INIT_FAILED &&
               (int)VERTHYS_DEFENSE_REASON_POLICY_DISABLED ==
                   (int)DEFENSE_REASON_POLICY_DISABLED &&
               (int)VERTHYS_DEFENSE_REASON_EVIDENCE_STALE ==
                   (int)DEFENSE_REASON_EVIDENCE_STALE &&
               (int)VERTHYS_DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED ==
                   (int)DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED &&
               (int)VERTHYS_DEFENSE_REASON_HIBERNATION_DISABLED ==
                   (int)DEFENSE_REASON_HIBERNATION_DISABLED,
               "public VerthysDefenseReason out of sync with internal DefenseReason");

/* 追加式 ABI：既有 48 字节前缀保持不变；新字段偏移与总大小锁定，
 * 防止 C/Rust/TS 三方布局漂移。 */
_Static_assert(offsetof(VerthysSecurityStatus, path_reason) == 48u,
               "VerthysSecurityStatus.path_reason offset drift");
_Static_assert(offsetof(VerthysSecurityStatus, limited_count) == 76u,
               "VerthysSecurityStatus.limited_count offset drift");
_Static_assert(offsetof(VerthysSecurityStatus, policy_flags) == 80u,
               "VerthysSecurityStatus.policy_flags offset drift");
_Static_assert(offsetof(VerthysSecurityStatus, checked_at_unix_ms) == 88u,
               "VerthysSecurityStatus.checked_at_unix_ms offset drift");
_Static_assert(sizeof(VerthysSecurityStatus) == 104u,
               "VerthysSecurityStatus size drift");

VerthysResult Verthys_GetSecurityStatus(VerthysHandle handle,
                                    VerthysSecurityStatus *out_status)
{
    struct VerthysContext *ctx;
    DefenseFacts facts;
    DefenseStatusReport report;

    if (handle == NULL || out_status == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;

    memset(&facts, 0, sizeof(facts));
    defense_closure_fill_process_facts(&facts);

    /* 快照锁序：registry → ctx。
     *
     * pin 持有注册表共享锁，保证 Verthys_Deinit 的注销与释放不会发生在
     * 复制期间（注销本身持 registry 独占锁）；ctx 共享锁保证会话指针与
     * 绑定事实一致。复制完成后立即释放两把锁，随后才获取 defense_closure
     * 的检查锁——禁止嵌套 ctx 锁与检查锁。
     *
     * 状态查询无副作用：不调用任何 *_init、不创建句柄、不启动定时器；
     * 仅读取已初始化模块与 OS 查询结果。 */
    if (!verthys_ctx_registry_pin(ctx)) return VERTHYS_ERR_INVALID;

    verthys_ctx_lock_shared(ctx);

    facts.any_unlocked_session = vault_session_resident_count();
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER && ctx->vault != NULL) {
        VtyVaultBindingInfo binding;
        if (vty_vault_binding_info(ctx->vault, &binding) == VTY_OK) {
            facts.queried_unlocked_session  = binding.unlocked;
            facts.queried_device_bound = binding.device_bound;
            facts.queried_pcr_bound    = binding.pcr_bound;
        }
    }

    verthys_ctx_unlock_shared(ctx);
    verthys_ctx_registry_unpin();

    if (defense_closure_check_facts(DEFENSE_CHECK_RUNTIME,
                                    &facts, &report) != 0) {
        /* RUNTIME 模式契约恒返回 0；此分支为防御性顶层错误映射 */
        return VERTHYS_ERR_INTERNAL;
    }

    memset(out_status, 0, sizeof(*out_status));
    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        out_status->path_state[i]  = (VerthysDefenseState)report.path_state[i];
        out_status->path_reason[i] = (uint32_t)report.path_reason[i];
    }
    out_status->blocked_count        = report.blocked_count;
    out_status->degraded_count       = report.degraded_count;
    out_status->failed_count         = report.failed_count;
    out_status->all_critical_blocked = (uint8_t)report.all_critical_blocked;
    out_status->has_degraded         = (uint8_t)report.has_degraded;
    out_status->limited_count        = report.limited_count;
    out_status->policy_flags         = facts.policy_flags;
    out_status->reserved2            = 0;
    out_status->checked_at_unix_ms   = report.checked_at_unix_ms;
    out_status->reserved3[0]         = 0;
    out_status->reserved3[1]         = 0;
    return VERTHYS_OK;
}

VerthysResult Verthys_GetKernelStatus(VerthysHandle handle,
                                      VerthysKernelStatus *out_status)
{
    VtyKernelStatus status;
    int rc;

    if (handle == NULL || out_status == NULL) return VERTHYS_ERR_INVALID;

    memset(out_status, 0, sizeof(*out_status));
    memset(&status, 0, sizeof(status));
    rc = vty_machine_limiter_kernel_status(&status);
    if (rc != VTY_OK) return VERTHYS_ERR_INTERNAL;

    out_status->state = status.state;
    out_status->reason = status.reason;
    out_status->capabilities = status.capabilities;
    out_status->protocol_major = status.protocol_major;
    out_status->protocol_minor = status.protocol_minor;
    out_status->reserved = 0;
    return VERTHYS_OK;
}
