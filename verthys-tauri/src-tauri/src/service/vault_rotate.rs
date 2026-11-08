/*
 * service/vault_rotate.rs — 全库 DEK 轮换的服务层契约
 *
 * 为什么契约放在 service 层：轮换控制器按单向依赖规则只允许引用
 * service / repository / util / constants；而口令注入、路径授权、
 * worker 会话与流式进度都依赖横切模块（state / worker）。控制器若直接
 * 引用这些模块即形成 controller → state/worker 的反向依赖（分层红线）。
 *
 * 依赖反转：本模块只声明轮换所需的宿主能力（函数指针表），具体实现由
 * security_commands 侧在应用启动阶段注册（install）。未注册时 fail-closed，
 * 所有入口返回 Err，禁止在宿主能力不完整时触碰轮换流程。
 *
 * 线程安全：注册位一次性写入（OnceLock，启动阶段完成后只读）；函数为
 * 无状态转发，可并发调用。
 */

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use zeroize::Zeroizing;

/// 全库轮换取消信号（父进程创建的命名事件）。
///
/// 句柄以 isize 持有以便跨线程存储；实际 Win32 类型由宿主桥接层转换。
#[derive(Debug, Clone)]
pub(crate) struct RotateCancelSignal {
    pub(crate) name: String,
    pub(crate) handle: isize,
}

/// 全库轮换进度视图（与 worker RotateProgress 字段一一对应）
///
/// 只承载统计计数，不含记录名/明文/密钥；直接作为 Tauri Channel 载荷。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateProgress {
    pub stage: u32,
    pub modules_ready: u32,
    pub records: u64,
    pub files: u64,
    pub chunks: u64,
    pub bytes: u64,
}

/// Begin 超时：Argon2id + 临时容器创建；SECURE 预设极端机器留足余量。
const ROTATE_BEGIN_TIMEOUT: Duration = Duration::from_secs(120);
/// 模块口令登记：解封 user 槽 + （可选）恢复码二次校验。
const ROTATE_MODULE_UNLOCK_TIMEOUT: Duration = Duration::from_secs(60);
/// 提交：同卷改名 + PCR 重封 + 回退锚点推进，不复制数据。
const ROTATE_COMMIT_TIMEOUT: Duration = Duration::from_secs(120);
/// 丢弃临时库：删除新文件与作业状态。
const ROTATE_ABORT_TIMEOUT: Duration = Duration::from_secs(60);
/// keyfile 补录：读取 + Argon2id 验证 user 槽。
const ROTATE_ATTACH_KEYFILE_TIMEOUT: Duration = Duration::from_secs(60);

/// Begin flags 合法位：仅允许显式移除 PCR 绑定（C 层 VERTHYS_V4_ROTATE_FLAG_DROP_PCR）。
pub const ROTATE_FLAG_DROP_PCR: u32 = 0x0000_0001;
/// 模块索引上限（C 层 VTY_V4_MODULE_COUNT = 3）。
const MODULE_COUNT: u32 = 3;
/// 模块口令上限（C 层 VTY_MODULE_PASSWORD_MAX = 4096 字节）。
const MAX_MODULE_PASSWORD_BYTES: usize = 4096;
/// 恢复码字符上限（C 层 recovery_arg_ok 限制 256 字符）。
const MAX_RECOVERY_CODE_CHARS: usize = 256;

/// 宿主能力实现签名（由 security_commands 在启动阶段注册）
pub(crate) type RequireUnlockedFn = fn(&AppHandle, &str) -> Result<(), String>;
pub(crate) type LoadPasswordFn = fn(&AppHandle) -> Result<Zeroizing<String>, String>;
pub(crate) type AuthorizePathFn = fn(&AppHandle, &str, &str, &str) -> Result<(), String>;
pub(crate) type SessionPathFn = fn(&AppHandle) -> Option<String>;
pub(crate) type SendFn = fn(&AppHandle, &str, Duration) -> Result<String, String>;
pub(crate) type SendWithProgressFn =
    fn(&AppHandle, &str, &dyn Fn(&RotateProgress)) -> Result<String, String>;
pub(crate) type RefreshSessionFn = fn(&AppHandle) -> Result<(), String>;
pub(crate) type CreateCancelFn = fn() -> Result<RotateCancelSignal, String>;
pub(crate) type SignalCancelFn = fn(&RotateCancelSignal) -> Result<(), String>;
pub(crate) type CloseCancelFn = fn(RotateCancelSignal);

/// 宿主能力表
pub(crate) struct HostHooks {
    pub require_unlocked: RequireUnlockedFn,
    pub load_password: LoadPasswordFn,
    pub authorize_path: AuthorizePathFn,
    pub session_path: SessionPathFn,
    pub send: SendFn,
    pub send_with_progress: SendWithProgressFn,
    /// 提交成功后重建会话哨兵锁（文件被原子替换，旧句柄已指向退役文件）
    pub refresh_session: RefreshSessionFn,
    /// 创建 Run 取消信号（命名事件）
    pub create_cancel: CreateCancelFn,
    /// 置位取消信号（SetEvent）
    pub signal_cancel: SignalCancelFn,
    /// 关闭取消事件句柄
    pub close_cancel: CloseCancelFn,
}

static HOST: OnceLock<HostHooks> = OnceLock::new();

/// 当前作业的取消信号（Begin 创建，Commit/Abort 释放）
static RUN_CANCEL: Mutex<Option<RotateCancelSignal>> = Mutex::new(None);
/// 仅解锁模块与复制阶段允许取消；Run 返回后置 false
static CANCEL_ENABLED: AtomicBool = AtomicBool::new(false);
/// 轮换在途操作数：Begin/解锁模块/Run/补录 keyfile/Commit/Abort 全覆盖。
/// 锁定与销毁只能在这些操作全部收敛后执行；仅等待 Run 会漏掉“Commit
/// 换名/重封 PCR 期间销毁 worker”的窗口。
static INFLIGHT: Mutex<usize> = Mutex::new(0);
static INFLIGHT_DONE: Condvar = Condvar::new();

/// 在途计数的锁中毒按“计数仍可用”处理：计数只做加减，不存在半更新状态；
/// 若一次 panic 后永久拒绝访问，锁定链会被永久封死。
fn lock_inflight() -> std::sync::MutexGuard<'static, usize> {
    INFLIGHT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 轮换 IPC 在途守卫：进入即计数 +1，任何返回路径（含 panic 展开）都会
/// 减计数并唤醒锁定闸门。
struct RotateInflightGuard;

impl RotateInflightGuard {
    fn enter() -> Self {
        *lock_inflight() += 1;
        Self
    }
}

impl Drop for RotateInflightGuard {
    fn drop(&mut self) {
        let mut count = lock_inflight();
        *count = count.saturating_sub(1);
        INFLIGHT_DONE.notify_all();
    }
}

/// Run 阶段的取消开关守卫：Run 退出后不得再把“取消已生效”报告给 UI。
struct RunCancelGuard;

impl RunCancelGuard {
    fn enter() -> Self {
        CANCEL_ENABLED.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for RunCancelGuard {
    fn drop(&mut self) {
        CANCEL_ENABLED.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) fn test_set_inflight(count: usize) {
    let mut guard = lock_inflight();
    *guard = count;
    if count == 0 {
        INFLIGHT_DONE.notify_all();
    }
}

/// 注册宿主能力实现（应用启动阶段调用一次；重复注册忽略，保持首个实现）。
pub(crate) fn install(hooks: HostHooks) {
    let _ = HOST.set(hooks);
}

fn hooks() -> Result<&'static HostHooks, String> {
    HOST.get()
        .ok_or_else(|| "全库轮换模块不可用，请重启应用后重试".to_string())
}

/// 解析 worker 响应是否成功（只读取 ok 字段，不消费业务内容）。
fn response_ok(raw: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("ok").and_then(|ok| ok.as_bool()))
        .unwrap_or(false)
}

/// 释放当前取消信号（关闭命名事件句柄并禁用取消）。
fn clear_cancel_signal() {
    CANCEL_ENABLED.store(false, Ordering::SeqCst);
    let signal = RUN_CANCEL
        .lock()
        .ok()
        .and_then(|mut guard| guard.take());
    if let (Some(signal), Ok(host)) = (signal, hooks()) {
        (host.close_cancel)(signal);
    }
}

/// 会话锁定/销毁时释放取消信号：C 层的作业已随会话释放，宿主侧不得
/// 保留可置位的事件句柄或“可取消”状态。
pub(crate) fn reset_on_lock() {
    clear_cancel_signal();
}

/// Begin flags 只能是已定义的位（未知位按非法参数拒绝）。
pub(crate) fn flags_ok(flags: u32) -> bool {
    flags & !ROTATE_FLAG_DROP_PCR == 0
}

pub(crate) fn module_id_ok(module_id: u32) -> bool {
    module_id < MODULE_COUNT
}

pub(crate) fn module_password_ok(password: &str) -> bool {
    !password.is_empty() && password.len() <= MAX_MODULE_PASSWORD_BYTES
}

pub(crate) fn recovery_code_ok(code: &str) -> bool {
    code.len() <= MAX_RECOVERY_CODE_CHARS
}

/// 开始轮换：校验会话与容器口令，创建临时新库。
///
/// new_path 的写授权必须在口令进入请求前签发；load_password 取自本机
/// 容器口令保管（前端不传口令）。
pub(crate) fn begin(app: &AppHandle, new_path: &str, flags: u32) -> Result<String, String> {
    let _inflight = RotateInflightGuard::enter();
    let host = hooks()?;
    (host.require_unlocked)(app, "v4_rotate_begin")?;
    (host.authorize_path)(app, "v4_rotate_begin", "write", new_path)?;
    let password = (host.load_password)(app)?;
    /* 直接序列化到 Zeroizing<String>：避免先构造 serde_json::Value 再转
     * 字符串，口令在堆上只保留一份可清零的副本。 */
    #[derive(serde::Serialize)]
    struct BeginReq<'a> {
        op: &'a str,
        new_path: &'a str,
        password: &'a str,
        flags: u32,
    }
    let req = BeginReq {
        op: "v4_rotate_begin",
        new_path,
        password: password.as_str(),
        flags,
    };
    let json = Zeroizing::new(
        serde_json::to_string(&req).map_err(|e| format!("轮换请求序列化失败: {}", e))?,
    );
    let result = (host.send)(app, json.as_str(), ROTATE_BEGIN_TIMEOUT);
    if result.as_deref().map(response_ok).unwrap_or(false) {
        /* Begin 成功说明不存在其他活动作业：此时才释放上一轮残留信号，
         * 避免重复 Begin（IPC 直调/未来 UI 改动）误关活动作业的取消事件。 */
        clear_cancel_signal();
        match (host.create_cancel)() {
            Ok(signal) => {
                if let Ok(mut slot) = RUN_CANCEL.lock() {
                    *slot = Some(signal);
                    CANCEL_ENABLED.store(true, Ordering::SeqCst);
                }
            }
            Err(e) => {
                /* 解耦降级：取消通道不可用不应阻断轮换，但必须留痕。 */
                log::warn!("[vault_rotate] 取消事件创建失败，本次作业不可取消: {}", e);
            }
        }
    }
    result
}

/// 登记一个已启用模块的口令（并解锁源模块）。
pub(crate) fn unlock_module(
    app: &AppHandle,
    module_id: u32,
    password: &str,
    recovery_code: Option<&str>,
) -> Result<String, String> {
    let _inflight = RotateInflightGuard::enter();
    let host = hooks()?;
    (host.require_unlocked)(app, "v4_rotate_unlock_module")?;
    #[derive(serde::Serialize)]
    struct UnlockReq<'a> {
        op: &'a str,
        module_id: u32,
        password: &'a str,
        recovery_code: &'a str,
    }
    let req = UnlockReq {
        op: "v4_rotate_unlock_module",
        module_id,
        password,
        recovery_code: recovery_code.unwrap_or(""),
    };
    let json = Zeroizing::new(
        serde_json::to_string(&req).map_err(|e| format!("轮换请求序列化失败: {}", e))?,
    );
    (host.send)(app, json.as_str(), ROTATE_MODULE_UNLOCK_TIMEOUT)
}

/// 全量复制并提供进度（长任务，进度感知超时由 worker 会话层控制）。
///
/// Run 期间父进程创建的命名事件随请求下发；Run 返回即禁用取消（剩余阶段
/// 只能 Commit 或 Abort）。
pub(crate) fn run(
    app: &AppHandle,
    progress_cb: &dyn Fn(&RotateProgress),
) -> Result<String, String> {
    let _inflight = RotateInflightGuard::enter();
    let host = hooks()?;
    (host.require_unlocked)(app, "v4_rotate_run")?;
    let cancel_event = RUN_CANCEL
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|signal| signal.name.clone()))
        .unwrap_or_default();
    let json = Zeroizing::new(
        serde_json::json!({
            "op": "v4_rotate_run",
            "cancel_event": cancel_event,
        })
        .to_string(),
    );
    // 在途计数与取消开关由 RAII 守卫收口：正常返回与 panic 展开都保证复位。
    let _cancel = RunCancelGuard::enter();
    (host.send_with_progress)(app, json.as_str(), progress_cb)
}

/// 锁定/销毁前等待轮换操作全部收敛。
///
/// 锁库请求在 worker 忙时只能排队，不能保证在操作返回前生效；如果直接
/// 销毁会话，worker 会继续持有 GMK 并执行轮换。此处在宿主侧先置位取消
/// （仅 Run 阶段有效）并等待在途计数归零（有界），超时则拒绝锁定而不是
/// 留下“已锁定但密钥仍驻留”的假象。覆盖 Begin/解锁模块/Run/补录/Commit/
/// Abort 全部阶段：只等 Run 会漏掉换名与 PCR 重封窗口。
///
/// 进程级硬退出路径（窗口关闭超时、ExitRequested 直接 set_session(None)）
/// 无法被本闸门拦截；那条路径的崩溃窗口由 C 层轮换恢复日志兜底。
pub(crate) fn prepare_for_lock(timeout: Duration) -> Result<(), String> {
    let mut inflight = lock_inflight();
    if *inflight == 0 {
        return Ok(());
    }
    /* 取消不可用时仍需等待；若 Run 已接近完成，等待会立即返回。 */
    drop(inflight);
    let _ = cancel();
    inflight = lock_inflight();
    let deadline = Instant::now() + timeout;
    loop {
        if *inflight == 0 {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("轮换操作仍在执行：已请求取消，等待收敛超时，请稍后重试锁定".to_string());
        }
        /* Condvar 与计数共用中毒语义：panic 后继续等待，而不是把
         * 锁定链永久判为不可用。 */
        let (guard, wait) = match INFLIGHT_DONE.wait_timeout(inflight, remaining) {
            Ok(result) => result,
            Err(poisoned) => poisoned.into_inner(),
        };
        inflight = guard;
        if wait.timed_out() && *inflight != 0 {
            return Err("轮换操作仍在执行：已请求取消，等待收敛超时，请稍后重试锁定".to_string());
        }
    }
}

/// 请求取消正在进行的 Run：置位父进程命名事件。
///
/// 仅 Begin 成功到 Run 返回之间有效；Run 返回后调用返回错误，由 UI 引导
/// 使用 Commit/Abort。
pub(crate) fn cancel() -> Result<String, String> {
    if !CANCEL_ENABLED.load(Ordering::SeqCst) {
        return Err("当前阶段不可取消轮换（仅解锁模块与复制阶段可取消）".to_string());
    }
    let host = hooks()?;
    /* 在持有 RUN_CANCEL 锁期间置位：clear_cancel_signal 也持同一把锁，
     * 避免 SetEvent 与 CloseHandle 并发导致对已关闭句柄的置位。 */
    let signal = RUN_CANCEL
        .lock()
        .map_err(|_| "轮换取消状态不可用".to_string())?;
    let signal = signal
        .as_ref()
        .ok_or_else(|| "轮换取消信号不可用".to_string())?;
    (host.signal_cancel)(signal)?;
    Ok(serde_json::json!({
        "ok": true,
        "op": "v4_rotate_cancel",
    })
    .to_string())
}

/// 恢复会话补录 keyfile（容器启用 KEYFILE 且会话未持有摘要时）。
pub(crate) fn attach_keyfile(app: &AppHandle, keyfile_path: &str) -> Result<String, String> {
    let _inflight = RotateInflightGuard::enter();
    let host = hooks()?;
    (host.require_unlocked)(app, "v4_rotate_attach_keyfile")?;
    (host.authorize_path)(app, "v4_rotate_attach_keyfile", "read", keyfile_path)?;
    let password = (host.load_password)(app)?;
    #[derive(serde::Serialize)]
    struct AttachReq<'a> {
        op: &'a str,
        keyfile_path: &'a str,
        password: &'a str,
    }
    let req = AttachReq {
        op: "v4_rotate_attach_keyfile",
        keyfile_path,
        password: password.as_str(),
    };
    let json = Zeroizing::new(
        serde_json::to_string(&req).map_err(|e| format!("轮换请求序列化失败: {}", e))?,
    );
    (host.send)(app, json.as_str(), ROTATE_ATTACH_KEYFILE_TIMEOUT)
}

/// 原子替换源库并推进回退锚点。
pub(crate) fn commit(app: &AppHandle, keep_old: bool) -> Result<String, String> {
    let _inflight = RotateInflightGuard::enter();
    let host = hooks()?;
    (host.require_unlocked)(app, "v4_rotate_commit")?;
    let json = Zeroizing::new(
        serde_json::json!({
            "op": "v4_rotate_commit",
            "keep_old": keep_old,
        })
        .to_string(),
    );
    let result = (host.send)(app, json.as_str(), ROTATE_COMMIT_TIMEOUT);
    if result.as_deref().map(response_ok).unwrap_or(false) {
        clear_cancel_signal();
    }
    result
}

/// 提交成功后重建会话哨兵锁；失败返回原因，由调用方记录审计降级。
pub(crate) fn refresh_session_after_commit(app: &AppHandle) -> Result<(), String> {
    match hooks() {
        Ok(host) => (host.refresh_session)(app),
        Err(e) => Err(e),
    }
}

/// 丢弃临时库；成功后句柄仍指向原库。
pub(crate) fn abort(app: &AppHandle) -> Result<String, String> {
    let _inflight = RotateInflightGuard::enter();
    let host = hooks()?;
    (host.require_unlocked)(app, "v4_rotate_abort")?;
    let json = Zeroizing::new(serde_json::json!({ "op": "v4_rotate_abort" }).to_string());
    let result = (host.send)(app, json.as_str(), ROTATE_ABORT_TIMEOUT);
    if result.as_deref().map(response_ok).unwrap_or(false) {
        clear_cancel_signal();
    }
    result
}

/// 当前会话绑定的源库路径（审计资源哈希用）
pub(crate) fn session_path(app: &AppHandle) -> Option<String> {
    hooks().ok().and_then(|h| (h.session_path)(app))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 在途计数是进程级全局状态：涉及它的用例必须串行执行，避免用例间
    /// 互相改写计数造成伪失败。
    static RUN_STATE_SERIAL: Mutex<()> = Mutex::new(());

    fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
        RUN_STATE_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn flags_only_accept_drop_pcr_bit() {
        assert!(flags_ok(0));
        assert!(flags_ok(ROTATE_FLAG_DROP_PCR));
        assert!(!flags_ok(0x0000_0002));
        assert!(!flags_ok(u32::MAX));
    }

    #[test]
    fn module_and_secret_bounds() {
        assert!(module_id_ok(0));
        assert!(module_id_ok(2));
        assert!(!module_id_ok(3));

        assert!(!module_password_ok(""));
        assert!(module_password_ok("pw"));
        assert!(module_password_ok(&"a".repeat(MAX_MODULE_PASSWORD_BYTES)));
        assert!(!module_password_ok(&"a".repeat(MAX_MODULE_PASSWORD_BYTES + 1)));

        assert!(recovery_code_ok(""));
        assert!(recovery_code_ok(&"R".repeat(MAX_RECOVERY_CODE_CHARS)));
        assert!(!recovery_code_ok(&"R".repeat(MAX_RECOVERY_CODE_CHARS + 1)));
    }

    #[test]
    fn missing_host_fails_closed() {
        // 测试进程未安装宿主实现：契约查询必须返回 Err，禁止空实现静默放行。
        assert!(hooks().is_err(), "未注册实现时必须 fail-closed");
    }

    #[test]
    fn lock_gate_waits_for_inflight_job_and_times_out() {
        let _serial = serial_guard();
        test_set_inflight(1);
        assert!(
            prepare_for_lock(Duration::from_millis(30)).is_err(),
            "轮换操作未收敛时锁定必须超时失败"
        );
        test_set_inflight(0);
        assert!(
            prepare_for_lock(Duration::from_millis(30)).is_ok(),
            "在途操作为零时锁定闸门必须立即放行"
        );
    }

    #[test]
    fn inflight_guard_resets_state_even_on_panic() {
        let _serial = serial_guard();
        let outcome = std::panic::catch_unwind(|| {
            let _guard = RotateInflightGuard::enter();
            let _cancel = RunCancelGuard::enter();
            assert_eq!(*lock_inflight(), 1, "进入守卫后在途计数必须为 1");
            panic!("模拟轮换操作内的 panic");
        });
        assert!(outcome.is_err(), "用例前提：轮换操作内发生 panic");
        assert_eq!(*lock_inflight(), 0, "panic 展开后在途计数必须归零");
        assert!(
            prepare_for_lock(Duration::from_millis(30)).is_ok(),
            "panic 展开后锁定闸门不得被永久封死"
        );
        assert!(
            !CANCEL_ENABLED.load(Ordering::SeqCst),
            "操作退出（含 panic）后必须关闭取消开关"
        );
    }
}
