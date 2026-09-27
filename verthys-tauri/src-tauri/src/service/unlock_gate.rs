/*
 * service/unlock_gate.rs — 口令类入口暴力熔断的服务层契约
 *
 * 为什么契约放在 service 层：口令闸门被多个控制器命令共用（解锁、GMK 验证、
 * 密钥派生），而控制器按单向依赖规则只允许引用 service / repository / util /
 * constants。控制器若直接引用 security_commands 的实现模块，即形成
 * controller → security_commands 的反向依赖（CI 分层红线）。
 *
 * 依赖反转：本模块只声明契约（判定结果 + 函数注册位），不依赖任何安全实现；
 * 具体实现（守卫读写、审计、DPAPI 持久化）由 security_commands 侧在应用
 * 启动阶段注册（install）。未注册时按 fail-closed 语义拒绝放行，与既有
 * 「守卫不可用」的安全语义一致。
 *
 * 线程安全：注册位为一次性写入（OnceLock，启动阶段完成后只读）；判定与记账
 * 为无状态转发，可并发调用。
 */

use std::sync::OnceLock;
use tauri::AppHandle;

/// worker 错误码统一化后的认证域错误标识（口令错误/认证数据损坏）。
///
/// 仅此错误码构成暴破证据并计数；通信层失败、格式错误与功能性状态码不计数，
/// 防止非口令因素被误判为暴破。
pub(crate) const AUTH_DOMAIN_ERROR: &str = "ERR_00000002";

/// 口令类命令入口的熔断判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnlockGate {
    /// 允许发起本次尝试
    Allowed,
    /// 熔断锁定中，携带剩余秒数
    Locked(u64),
    /// 失败次数已达清空阈值，要求先执行索引清空与完整性校验
    PurgeRequired,
    /// 守卫状态不可用（锁中毒等内部异常）：fail-closed，拒绝放行
    Unavailable,
}

/// 闸门判定实现签名（由 security_commands 在启动阶段注册）
pub(crate) type GateFn = fn(&AppHandle) -> UnlockGate;

/// 认证失败/成功记账实现签名
pub(crate) type AuthRecordFn = fn(&AppHandle);

static GATE_IMPL: OnceLock<GateFn> = OnceLock::new();
static AUTH_FAILURE_IMPL: OnceLock<AuthRecordFn> = OnceLock::new();
static AUTH_SUCCESS_IMPL: OnceLock<AuthRecordFn> = OnceLock::new();

/// 注册熔断闸门实现（应用启动阶段调用一次；重复注册忽略，保持首个实现）。
pub(crate) fn install(gate: GateFn, on_failure: AuthRecordFn, on_success: AuthRecordFn) {
    let _ = GATE_IMPL.set(gate);
    let _ = AUTH_FAILURE_IMPL.set(on_failure);
    let _ = AUTH_SUCCESS_IMPL.set(on_success);
}

/// 口令类命令入口熔断检查（在口令进入任何业务逻辑之前调用）。
///
/// fail-closed：实现未注册（启动异常）时返回 [`UnlockGate::Unavailable`]。
pub(crate) fn gate_check(app: &AppHandle) -> UnlockGate {
    match GATE_IMPL.get() {
        Some(f) => f(app),
        None => UnlockGate::Unavailable,
    }
}

/// 记录一次认证域失败（口令错误等）。
///
/// 记账属非关键路径：实现未注册时静默跳过，不阻断主流程（与实现内部
/// 「获取守卫失败即跳过计数」的既有语义一致）。
pub(crate) fn record_auth_failure(app: &AppHandle) {
    if let Some(f) = AUTH_FAILURE_IMPL.get() {
        f(app);
    }
}

/// 记录一次口令验证成功：重置连续失败计数。
pub(crate) fn record_auth_success(app: &AppHandle) {
    if let Some(f) = AUTH_SUCCESS_IMPL.get() {
        f(app);
    }
}