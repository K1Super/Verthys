/* progress_cb.rs — 全库 DEK 轮换进度回调（C → Rust → stdout 流式推送）
 *
 * 职责：vty_rotate_progress_cb（unsafe extern "C"）。
 * 依赖：std::io、std::os::raw::c_void、ffi_types 中的轮换进度 C 结构体。
 * 被引用方：worker.rs（在轮换 Run 前注册）。
 */

use std::io::{self, Write};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use zeroize::Zeroize;

use super::ffi_types::VerthysRotateInfoC;

/* 全库 DEK 轮换进度回调（C → Rust → stdout JSON 行）
 *
 * C 层在 Run 内按记录/文件/模块粒度同步调用本回调（大库可达数十万次），
 * 直接逐次写 stdout 会把轮换拖成 IO 瓶颈。此处在 worker 侧做节流：
 * 阶段变化或距上次输出超过 200ms 才写一行，前端仍能获得连续进度。
 *
 * 格式：
 *   {"ok":true,"op":"v4_rotate_progress","stage":N,"modules_ready":N,
 *    "records":N,"files":N,"chunks":N,"bytes":N}
 *
 * 安全边界：仅统计计数与阶段编号，不含记录名/明文/密钥；返回值在收到
 * 父进程取消事件时返回 1（C 层据此取消 Run 并进入 FAILED，只能 Abort）。 */
const ROTATE_PROGRESS_MIN_INTERVAL_MS: u64 = 200;

static ROTATE_PROGRESS_LAST_MS: AtomicU64 = AtomicU64::new(0);
static ROTATE_PROGRESS_LAST_STAGE: AtomicU32 = AtomicU32::new(0);
static ROTATE_PROGRESS_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
/// 取消事件句柄（null=未提供）。由 call_rotate_run 在 Run 前设置、返回后清零。
#[cfg(windows)]
static ROTATE_CANCEL_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
/// 取消检查节流（每 200ms 最多一次 WaitForSingleObject）
#[cfg(windows)]
static ROTATE_CANCEL_LAST_CHECK_MS: AtomicU64 = AtomicU64::new(0);

/// 设置本次 Run 的取消事件句柄（Windows）。
#[cfg(windows)]
pub(crate) fn set_rotate_cancel_handle(handle: *mut c_void) {
    ROTATE_CANCEL_LAST_CHECK_MS.store(0, Ordering::Relaxed);
    ROTATE_CANCEL_HANDLE.store(handle, Ordering::Relaxed);
}

/// 清除取消事件句柄（Run 返回后必须调用）。
pub(crate) fn clear_rotate_cancel_handle() {
    #[cfg(windows)]
    ROTATE_CANCEL_HANDLE.store(std::ptr::null_mut(), Ordering::Relaxed);
}

#[cfg(windows)]
fn rotate_cancel_requested() -> bool {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let handle = ROTATE_CANCEL_HANDLE.load(Ordering::Relaxed);
    if handle.is_null() {
        return false;
    }
    /* 进度回调按记录粒度触发（大库可达数十万次）；取消检查节流到 200ms，
     * 避免把 WaitForSingleObject 加进每次复制的热路径。 */
    let now = rotate_now_ms();
    let last = ROTATE_CANCEL_LAST_CHECK_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < ROTATE_PROGRESS_MIN_INTERVAL_MS {
        return false;
    }
    ROTATE_CANCEL_LAST_CHECK_MS.store(now, Ordering::Relaxed);
    unsafe { WaitForSingleObject(handle, 0) == 0 }
}

fn rotate_now_ms() -> u64 {
    ROTATE_PROGRESS_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis() as u64
}

pub(crate) unsafe extern "C" fn vty_rotate_progress_cb(
    _user: *mut c_void,
    info: *const VerthysRotateInfoC,
) -> i32 {
    /* FFI 边界纪律：panic 不得展开穿过 extern "C" 边界。轮换进度只是
     * 观测通道，序列化异常不应取消整个轮换事务，故捕获后返回 0 继续。 */
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vty_rotate_progress_cb_inner(info)
    }));
    match result {
        Ok(rc) => rc,
        Err(_) => {
            crate::log::mark_panic_flag();
            crate::log::init_diag!(
                "[worker] vty_rotate_progress_cb 内部 panic 已捕获（绝不让其展开跨 FFI 边界）"
            );
            0
        }
    }
}

unsafe fn vty_rotate_progress_cb_inner(info: *const VerthysRotateInfoC) -> i32 {
    if info.is_null() {
        return 0;
    }
    let i = &*info;

    /* 取消检查先于节流输出：即使本次不写进度行，也要观察取消信号。 */
    #[cfg(windows)]
    if rotate_cancel_requested() {
        crate::log::init_diag!("[worker] 轮换收到取消信号，终止本次 Run");
        return 1;
    }

    let now = rotate_now_ms();
    let last_stage = ROTATE_PROGRESS_LAST_STAGE.load(Ordering::Relaxed);
    let last_ms = ROTATE_PROGRESS_LAST_MS.load(Ordering::Relaxed);
    if i.stage == last_stage && now.saturating_sub(last_ms) < ROTATE_PROGRESS_MIN_INTERVAL_MS {
        return 0;
    }
    ROTATE_PROGRESS_LAST_STAGE.store(i.stage, Ordering::Relaxed);
    ROTATE_PROGRESS_LAST_MS.store(now, Ordering::Relaxed);

    let json = format!(
        r#"{{"ok":true,"op":"v4_rotate_progress","stage":{},"modules_ready":{},"records":{},"files":{},"chunks":{},"bytes":{}}}"#,
        i.stage, i.modules_ready, i.records, i.files, i.chunks, i.bytes,
    );
    /* 进度行必须带会话签名；签名失败时不写出，由宿主空闲超时收敛。 */
    let mut sealed = match super::ipc_auth::seal_progress(&json) {
        Ok(line) => line,
        Err(e) => {
            crate::log::init_diag!("[worker] 轮换进度签名失败，丢弃本条进度: {}", e);
            return 0;
        }
    };
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", sealed);
    let _ = lock.flush();
    sealed.zeroize();
    0
}
