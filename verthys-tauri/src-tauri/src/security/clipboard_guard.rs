/*
 * clipboard_guard.rs — 剪贴板保护升级模块
 *
 * 修复要点：
 *   1. 分离写入与清空策略，使用延迟清空模式
 *      - SetClipboardData 后绝不清空，敏感内容正常驻留供用户粘贴
 *      - 清空仅在以下条件触发：30 秒自动过期、高安全模式下检测到外部
 *        SetClipboardData（而非读取）、显式调用 clear/transactional_clear
 *   2. 废弃序列号检测读取，改用外部 SetClipboardData 检测
 *      - GetClipboardSequenceNumber 仅在 SetClipboardData 成功时递增
 *      - OpenClipboard / GetClipboardData 不改变序列号
 *      - 因此"序列号递增 = 外部写入"才是正确判定
 *   3. 窗口过程仅标记事件，所有剪贴板操作在消息循环中异步处理
 *      - clipboard_window_proc 收到 WM_CLIPBOARDUPDATE 时仅设置 AtomicBool
 *      - 消息循环轮询检测到标志后在主循环上下文执行检查和处理
 *      - 完全避免窗口过程内的重入风险
 *   4. 将分散的原子变量重构为单一的状态枚举与锁保护
 *      - 用 Mutex<ClipboardStateData> 替换所有松散原子变量
 *      - 状态结构体包含 stage、last_seq、expire_at 等字段
 *      - 所有状态读取和修改都在获取锁后原子完成
 *   5. 清空操作优先使用 EmptyClipboard，放弃无意义的垃圾覆写
 *      - 移除"写入随机数据再清空"逻辑
 *      - 直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD
 *      - 写入敏感内容时通过 CF_PRIVATEFIRST 标记防止进入历史记录
 *   6. 监听线程内进行 OLE 初始化与剪贴板能力检查
 *      - 隐藏窗口与消息循环由同一线程创建，保证 WM_CLIPBOARDUPDATE 可达
 *      - 监听线程启动时调用 OleInitialize，退出前调用 OleUninitialize
 *   7. 启动幂等：窗口类进程内仅注册一次；重复下发硬化开关直接成功，
 *      不得因 ERROR_CLASS_ALREADY_EXISTS 误报“剪贴板监听启动失败”
 */

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

/* ---------- Windows 消息常量 ---------- */
/// WM_CLIPBOARDUPDATE = 0x031D：AddClipboardFormatListener 注册后由系统投递
const WM_CLIPBOARDUPDATE: u32 = 0x031D;
/// WM_DESTROYCLIPBOARD = 0x030D：EmptyClipboard 时系统发送给剪贴板所有者
const WM_DESTROYCLIPBOARD: u32 = 0x030D;
const WM_DESTROY: u32 = 0x0002;

/// 监听窗口类名（进程内仅注册一次）
#[cfg(target_os = "windows")]
const LISTENER_CLASS_NAME: &str = "VerthysClipGuard";
/// ERROR_INVALID_WINDOW_HANDLE：窗口句柄失效（重建窗口重试一次）
#[cfg(target_os = "windows")]
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1401;
/// ERROR_CLASS_ALREADY_EXISTS：窗口类已注册（幂等复用，不视为失败）
#[cfg(target_os = "windows")]
const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;

/// PeekMessage 移除标志 PM_REMOVE = 0x0001
const PM_REMOVE: u32 = 0x0001;

/// 剪贴板格式
const CF_UNICODETEXT: u32 = 13;
/// CF_PRIVATEFIRST = 0x0200：私有格式范围起始，剪贴板历史工具通常不缓存
const CF_PRIVATEFIRST: u32 = 0x0200;

/// HWND_BROADCAST = 0xFFFF：向所有顶层窗口广播
const HWND_BROADCAST: isize = 0xFFFF;

/// GMEM_DDESHARE = 0x2000（windows crate 0.58 未导出此命名常量，以原始位构造）
const GMEM_DDESHARE_RAW: u32 = 0x2000;
/// GMEM_MOVEABLE = 0x0002
const GMEM_MOVEABLE_RAW: u32 = 0x0002;

/// 敏感内容自动过期时长（写入后 30 秒自动清空）
const SENSITIVE_EXPIRE_SECS: u64 = 30;
/// 序列号轮询间隔（毫秒）
const POLL_INTERVAL_MS: u64 = 200;
/// OpenClipboard 重试次数（剪贴板被占用时等待重试）
const OPEN_RETRIES: usize = 3;
/// 重试间隔（50ms）
const RETRY_INTERVAL_MS: u64 = 50;

/* ==================================================================== *
 *  统一状态枚举与锁保护                               *
 *                                                                        *
 *  用单一 Mutex<ClipboardStateData> 替换所有松散原子变量。                *
 *  所有状态读取和修改都在获取锁后原子完成，消除瞬时不一致窗口。            *
 * ==================================================================== */

/// 剪贴板状态阶段枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClipboardStage {
    /// 空闲：无敏感内容驻留
    Idle,
    /// 本进程正在写入剪贴板（忽略自身写入链产生的通知）
    Writing,
    /// 敏感内容已驻留剪贴板，等待清空触发（过期 / 外部写入 / 显式清空）
    SensitivePresent,
}

/// 统一剪贴板状态（受 CLIPBOARD_STATE Mutex 保护）
struct ClipboardStateData {
    /// 当前阶段
    stage: ClipboardStage,
    /// 上次记录的剪贴板序列号（基线）
    last_seq: u32,
    /// 敏感内容过期时间戳（毫秒，UNIX_EPOCH 起）
    expire_at_ms: u64,
    /// 高安全模式：启用时外部写入即触发清空
    high_security: bool,
    /// 监听是否运行
    monitoring: bool,
}

/// 全局统一剪贴板状态（替代所有松散原子变量）
static CLIPBOARD_STATE: Mutex<ClipboardStateData> = Mutex::new(ClipboardStateData {
    stage: ClipboardStage::Idle,
    last_seq: 0,
    expire_at_ms: 0,
    high_security: false,
    monitoring: false,
});

/// 窗口过程仅设置此标志，消息循环中异步处理
static PENDING_UPDATE: AtomicBool = AtomicBool::new(false);

/// 剪贴板写入串行化锁（跨线程互斥访问剪贴板物理 API）
static CLIPBOARD_LOCK: Mutex<()> = Mutex::new(());

/// 辅助：安全获取状态锁（处理 poison）
fn lock_state() -> std::sync::MutexGuard<'static, ClipboardStateData> {
    CLIPBOARD_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/* ==================================================================== *
 *                  windows crate 导入（剪贴板与随机数 API）              *
 * ==================================================================== */
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{HANDLE, HWND};
#[cfg(target_os = "windows")]
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber,
    OpenClipboard, RemoveClipboardFormatListener, SetClipboardData,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Ole::{OleInitialize, OleUninitialize};

/* ==================================================================== *
 *                        Windows 原始 FFI 声明                           *
 * ==================================================================== */
#[cfg(target_os = "windows")]
#[link(name = "user32")]
extern "system" {
    fn CreateWindowExW(
        dwExStyle: u32,
        lpClassName: *const u16,
        lpWindowName: *const u16,
        dwStyle: u32,
        x: i32,
        y: i32,
        nWidth: i32,
        nHeight: i32,
        hWndParent: isize,
        hMenu: isize,
        hInstance: isize,
        lpParam: *const u8,
    ) -> isize;

    fn DefWindowProcW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> isize;

    fn DestroyWindow(hWnd: isize) -> i32;

    /// PostMessageW：向指定窗口消息队列投递消息（线程安全），用于 stop 时唤醒循环
    fn PostMessageW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> i32;

    fn PeekMessageW(
        lpMsg: *mut Msg,
        hWnd: isize,
        wMsgFilterMin: u32,
        wMsgFilterMax: u32,
        wRemoveMsg: u32,
    ) -> i32;

    fn TranslateMessage(lpMsg: *const Msg) -> i32;

    fn DispatchMessageW(lpMsg: *const Msg) -> isize;

    fn RegisterClassExW(lpWndClass: *const WndClassExW) -> u16;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetModuleHandleW(lpModuleName: *const u16) -> isize;
    fn Sleep(dwMilliseconds: u32);

    /// GlobalAlloc（原始 FFI）：分配可移动/共享内存，返回 HGLOBAL（isize 形式）。
    fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> isize;

    /// GlobalLock（原始 FFI）：锁定 HGLOBAL 内存并返回可写指针。
    fn GlobalLock(h_mem: isize) -> *mut u8;

    /// GlobalUnlock（原始 FFI）：解锁 HGLOBAL 内存。
    fn GlobalUnlock(h_mem: isize) -> i32;
}

/* ---------- FFI 结构体 ---------- */
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Default)]
#[allow(non_snake_case)]
struct WndClassExW {
    cbSize: u32,
    style: u32,
    lpfnWndProc: Option<unsafe extern "system" fn(isize, u32, usize, isize) -> isize>,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: isize,
    hIcon: isize,
    hCursor: isize,
    hbrBackground: isize,
    lpszMenuName: *const u16,
    lpszClassName: *const u16,
    hIconSm: isize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Default)]
struct Msg {
    hwnd: isize,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
}

/* ---------- 辅助：字符串转宽字符（含 NUL） ---------- */
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    if v.last() != Some(&0) {
        v.push(0);
    }
    v
}

/* ---------- 辅助：当前毫秒时间戳 ---------- */
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/* ==================================================================== *
 *  窗口过程仅标记事件                                *
 *                                                                        *
 *  clipboard_window_proc 中不再直接调用任何剪贴板 API。                   *
 *  收到 WM_CLIPBOARDUPDATE / WM_DESTROYCLIPBOARD 时，仅设置 PENDING_UPDATE *
 *  标志。消息循环中的轮询检测到该标志后，在主循环上下文中执行检查和处理。  *
 *  这完全避免了窗口过程内的重入风险。                                     *
 * ==================================================================== */
#[cfg(target_os = "windows")]
unsafe extern "system" fn clipboard_window_proc(
    hwnd: isize,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        WM_CLIPBOARDUPDATE | WM_DESTROYCLIPBOARD => {
            // 仅设置标志，不在窗口过程中执行任何剪贴板操作
            PENDING_UPDATE.store(true, Ordering::SeqCst);
            0
        }
        WM_DESTROY => 0,
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/* ==================================================================== *
 *  异步处理待处理的剪贴板事件              *
 *                                                                        *
 *  在消息循环上下文中调用（非窗口过程），安全地执行剪贴板检查和处理。      *
 *  外部 SetClipboardData（序列号递增）而非读取才是正确的触发条件。        *
 * ==================================================================== */
#[cfg(target_os = "windows")]
fn process_clipboard_update() {
    // 获取当前序列号（不需要打开剪贴板）
    let current = unsafe { GetClipboardSequenceNumber() };

    // 在锁内原子地读取状态并决定操作
    let action = {
        let mut state = lock_state();

        match state.stage {
            ClipboardStage::Writing => {
                // 本进程写入链中：仅刷新基线，不反应
                state.last_seq = current;
                return;
            }
            ClipboardStage::SensitivePresent => {
                if current > state.last_seq {
                    // 序列号递增 = 外部调用了 SetClipboardData（写入，非读取）
                    // 这才是正确的触发条件
                    if state.high_security {
                        // 高安全模式：立即清空
                        log::warn!(
                            "[clipboard_guard] 检测到外部剪贴板写入（seq {}→{}），\
                             高安全模式立即清空",
                            state.last_seq,
                            current
                        );
                        // 标记为 Writing 以忽略清空操作自身产生的通知
                        state.stage = ClipboardStage::Writing;
                        ClearAction::ClearAndReset
                    } else {
                        // 非高安全模式：外部已替换内容，更新基线，状态回归空闲
                        state.last_seq = current;
                        state.stage = ClipboardStage::Idle;
                        ClearAction::None
                    }
                } else {
                    // 序列号未变化（可能是 WM_DESTROYCLIPBOARD 通知），仅更新基线
                    state.last_seq = current;
                    ClearAction::None
                }
            }
            ClipboardStage::Idle => {
                // 空闲状态：仅更新基线
                state.last_seq = current;
                ClearAction::None
            }
        }
    };
    // 状态锁已释放

    if action == ClearAction::ClearAndReset {
        // 执行清空（获取 CLIPBOARD_LOCK 串行化剪贴板 API）
        let clear_result = do_clear_internal();

        // 更新状态
        let mut state = lock_state();
        state.stage = ClipboardStage::Idle;
        state.last_seq = unsafe { GetClipboardSequenceNumber() };

        if let Err(ref e) = clear_result {
            log::error!("[clipboard_guard] 外部写入触发清空失败: {}", e);
        }
    }
}

/// 清空动作枚举（process_clipboard_update 的决策结果）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearAction {
    None,
    ClearAndReset,
}

/// 轮询敏感内容自动过期（30 秒后清空）
#[cfg(target_os = "windows")]
fn check_sensitive_expire() {
    let action = {
        let state = lock_state();
        if state.stage != ClipboardStage::SensitivePresent {
            return;
        }
        if state.expire_at_ms == 0 {
            return;
        }
        if now_ms() >= state.expire_at_ms {
            log::info!(
                "[clipboard_guard] 敏感内容已超时（{} 秒），自动清空",
                SENSITIVE_EXPIRE_SECS
            );
            true
        } else {
            false
        }
    };

    if action {
        // 标记为 Writing 以忽略清空操作自身产生的通知
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Writing;
        }

        let clear_result = do_clear_internal();

        let mut state = lock_state();
        state.stage = ClipboardStage::Idle;
        state.last_seq = unsafe { GetClipboardSequenceNumber() };
        state.expire_at_ms = 0;

        if let Err(ref e) = clear_result {
            log::error!("[clipboard_guard] 超时触发清空失败: {}", e);
        }
    }
}

/* ==================================================================== *
 *  统一剪贴板清空入口（公共接口）                    *
 *                                                                        *
 *  所有剪贴板清空操作均通过此入口，包括：                                 *
 *    - mod.rs 的 clear_clipboard() 向后兼容封装                          *
 *    - ClipboardGuard 的 clear() 方法                                    *
 *    - 审计日志的 clear_clipboard 命令                                   *
 *                                                                        *
 *  直接调用 EmptyClipboard + 广播 WM_DESTROYCLIPBOARD。                   *
 *  移除"写入随机数据再清空"的无意义逻辑。                                 *
 * ==================================================================== */

/// 统一剪贴板清空入口
///
/// 直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD，
/// 强制系统清除云剪贴板缓存。
/// 移除了旧版"写入随机数据再清空"的自相矛盾逻辑。
pub fn clear() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        do_clear_internal()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("clear_clipboard: 非 Windows 平台不支持".into())
    }
}

/* ==================================================================== *
 *  内部清空实现                                      *
 *                                                                        *
 *  直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD。                   *
 *  移除"写入随机数据再清空"的无意义逻辑。                                 *
 *  EmptyClipboard 本身已足够保护残留。                                    *
 * ==================================================================== */
#[cfg(target_os = "windows")]
fn do_clear_internal() -> Result<(), String> {
    let _lock = CLIPBOARD_LOCK
        .lock()
        .map_err(|e| format!("CLIPBOARD_LOCK poisoned: {}", e))?;

    let mut last_err = String::new();

    unsafe {
        let _ = OleInitialize(None);

        // 重试 OpenClipboard（剪贴板被占用时等待 50ms × OPEN_RETRIES）
        let mut opened = false;
        for attempt in 0..OPEN_RETRIES {
            let hwnd = HWND(std::ptr::null_mut());
            match OpenClipboard(hwnd) {
                Ok(_) => {
                    opened = true;
                    break;
                }
                Err(e) => {
                    last_err = format!("OpenClipboard 失败（第 {} 次）: {}", attempt + 1, e);
                    if attempt + 1 < OPEN_RETRIES {
                        Sleep(RETRY_INTERVAL_MS as u32);
                    }
                }
            }
        }

        if !opened {
            return Err(last_err);
        }

        // 直接 EmptyClipboard，放弃无意义的垃圾覆写
        let empty_ok = EmptyClipboard().is_ok();

        // 广播 WM_DESTROYCLIPBOARD，强制系统清除云剪贴板缓存
        let post_ok = PostMessageW(HWND_BROADCAST, WM_DESTROYCLIPBOARD, 0, 0) != 0;

        let _ = CloseClipboard();

        log::info!(
            "[clipboard_guard] do_clear: EmptyClipboard={} WM_DESTROYCLIPBOARD 广播={}",
            empty_ok,
            post_ok
        );

        if empty_ok {
            Ok(())
        } else {
            Err("EmptyClipboard 失败".into())
        }
    }
}

/* ---------- 创建隐藏监听窗口 ---------- */
/// 创建隐藏监听窗口（窗口归属调用线程，即监听线程）。
///
/// 必须先确保窗口类已注册；窗口类为进程级资源，进程内只注册一次。
#[cfg(target_os = "windows")]
fn create_listener_window() -> Result<isize, String> {
    ensure_listener_class()?;

    unsafe {
        let class_name = to_wide(LISTENER_CLASS_NAME);
        let hinst = GetModuleHandleW(std::ptr::null());

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            hinst,
            std::ptr::null(),
        );

        if hwnd == 0 {
            return Err(format!(
                "CreateWindowExW 失败: GetLastError={}",
                GetLastError()
            ));
        }
        Ok(hwnd)
    }
}

/// 注册监听窗口类（进程内严格一次）。
///
/// 旧实现每次 `start_monitoring` 都调用 `RegisterClassExW`，第二次返回 1410
/// （ERROR_CLASS_ALREADY_EXISTS）并被误判为启动失败，导致安全档位恢复链重复
/// 下发开关时误报“会话硬化未完全生效”。此处以 `OnceLock` 保证仅注册一次；
/// 并发或历史注册返回 1410 时按“同名同类已存在”处理，不视为失败。
#[cfg(target_os = "windows")]
fn ensure_listener_class() -> Result<(), String> {
    static CLASS_READY: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if CLASS_READY.get().is_some() {
        return Ok(());
    }

    unsafe {
        let class_name = to_wide(LISTENER_CLASS_NAME);
        let hinst = GetModuleHandleW(std::ptr::null());

        let wc = WndClassExW {
            cbSize: std::mem::size_of::<WndClassExW>() as u32,
            lpfnWndProc: Some(clipboard_window_proc),
            hInstance: hinst,
            lpszClassName: class_name.as_ptr(),
            ..Default::default()
        };

        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            let err_code = GetLastError();
            if err_code != ERROR_CLASS_ALREADY_EXISTS {
                return Err(format!("RegisterClassExW 失败: GetLastError={}", err_code));
            }
        }

        let _ = CLASS_READY.set(());
        Ok(())
    }
}

/* ==================================================================== *
 *  监听线程（窗口创建 + 监听注册 + 消息泵 / 序列号轮询）                 *
 *                                                                        *
 *  关键约束：隐藏窗口必须由运行消息循环的线程创建。Win32 窗口消息只投递  *
 *  到创建该窗口的线程队列；旧实现在命令线程创建窗口、在另一线程跑消息    *
 *  循环，WM_CLIPBOARDUPDATE 永远无法被监听线程读取，外部写入检测形同虚设。*
 * ==================================================================== */

/// 创建窗口并注册剪贴板格式监听。
///
/// 返回 `(hwnd, format_listener)`：
///   - `format_listener=true`：WM_CLIPBOARDUPDATE 事件通道可用；
///   - `format_listener=false`：降级为序列号轮询（窗口已销毁，hwnd=0）。
#[cfg(target_os = "windows")]
fn setup_listener() -> Result<(isize, bool), String> {
    unsafe {
        let mut hwnd = create_listener_window()?;

        if AddClipboardFormatListener(HWND(hwnd as *mut _)).is_ok() {
            return Ok((hwnd, true));
        }

        let err_code = GetLastError();
        if err_code == ERROR_INVALID_WINDOW_HANDLE {
            log::warn!(
                "[clipboard_guard] AddClipboardFormatListener 失败 \
                 (ERROR_INVALID_WINDOW_HANDLE)，重新创建窗口重试"
            );
            let _ = DestroyWindow(hwnd);
            hwnd = create_listener_window()?;
            if AddClipboardFormatListener(HWND(hwnd as *mut _)).is_ok() {
                return Ok((hwnd, true));
            }
            let retry_err = GetLastError();
            let _ = DestroyWindow(hwnd);
            return Err(format!(
                "AddClipboardFormatListener 重试仍失败: GetLastError={}",
                retry_err
            ));
        }

        // 权限拒绝或其他错误：降级为定时轮询（序列号变化仍可检测外部写入）
        log::warn!(
            "[clipboard_guard] AddClipboardFormatListener 失败: GetLastError={}，\
             降级为定时轮询模式（仅序列号轮询，无 WM_CLIPBOARDUPDATE）",
            err_code
        );
        let _ = DestroyWindow(hwnd);
        Ok((0, false))
    }
}

/// 监听线程退出前的资源回收（窗口句柄归属本线程，跨线程销毁会失败）
#[cfg(target_os = "windows")]
fn cleanup_listener(hwnd: isize, format_listener: bool) {
    if hwnd == 0 {
        return;
    }
    unsafe {
        if format_listener {
            let _ = RemoveClipboardFormatListener(HWND(hwnd as *mut _));
        }
        let _ = DestroyWindow(hwnd);
    }
}

/// 监听线程主体：创建窗口、上报启动结果、泵消息并轮询剪贴板序列号。
///
/// 启动结果通过 `ready` 同步回传：窗口创建/监听注册失败必须返回 Err，
/// 调用方据此如实上报，绝不制造“已启动”假象。
#[cfg(target_os = "windows")]
fn run_listener_thread(
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
    stop: Arc<AtomicBool>,
) {
    unsafe {
        let ole_result = OleInitialize(None);
        if ole_result.is_err() {
            log::warn!(
                "[clipboard_guard] 监听线程 OleInitialize 失败: {:?}，剪贴板操作可能异常",
                ole_result
            );
        }

        let (hwnd, format_listener) = match setup_listener() {
            Ok(v) => v,
            Err(e) => {
                let _ = ready.send(Err(e));
                OleUninitialize();
                return;
            }
        };

        // 原子重置监听状态基线；停止信号与状态写入共用一把锁，
        // 与 stop 的“先置停止信号、后置 monitoring=false”形成串行化，
        // 避免停止与启动竞争时把 monitoring 重新置回 true。
        {
            let mut state = lock_state();
            if stop.load(Ordering::SeqCst) {
                drop(state);
                cleanup_listener(hwnd, format_listener);
                OleUninitialize();
                return;
            }
            state.stage = ClipboardStage::Idle;
            state.last_seq = GetClipboardSequenceNumber();
            state.expire_at_ms = 0;
            state.monitoring = true;
        }
        PENDING_UPDATE.store(false, Ordering::SeqCst);

        if ready.send(Ok(())).is_err() {
            // 调用方已放弃本次启动：立即清理退出，避免留下无主监听线程
            cleanup_listener(hwnd, format_listener);
            OleUninitialize();
            return;
        }

        log::info!(
            "[clipboard_guard] 剪贴板监听已启动 (hwnd={}, mode={})",
            hwnd,
            if format_listener {
                "format_listener"
            } else {
                "polling_only"
            }
        );

        let mut last_polled_seq = GetClipboardSequenceNumber();
        loop {
            // 1. 排干窗口消息（WM_CLIPBOARDUPDATE 仅置位 PENDING_UPDATE）
            loop {
                let mut msg = Msg::default();
                if PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) == 0 {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // 2. 停止信号：主动停止 或 监听状态被置为关闭
            if stop.load(Ordering::SeqCst) || !lock_state().monitoring {
                break;
            }

            // 3. 外部写入检测：窗口消息 + 序列号轮询双通道。
            //    轮询通道同时覆盖 AddClipboardFormatListener 降级场景，
            //    保证“外部写入即清空”不依赖窗口消息是否可用。
            let pending = PENDING_UPDATE.swap(false, Ordering::SeqCst);
            let current = GetClipboardSequenceNumber();
            let seq_changed = current != last_polled_seq;
            last_polled_seq = current;
            if pending || seq_changed {
                process_clipboard_update();
            }

            // 4. 轮询敏感内容自动过期
            check_sensitive_expire();

            // 5. 阻塞式小睡，避免空转烧 CPU
            Sleep(POLL_INTERVAL_MS as u32);
        }

        // 线程退出前回收窗口与监听注册，再反初始化 OLE
        cleanup_listener(hwnd, format_listener);
        OleUninitialize();
        log::info!("[clipboard_guard] 剪贴板监听线程已退出");
    }
}

/* ==================================================================== *
 *                        ClipboardGuard 结构体                          *
 * ==================================================================== */
pub struct ClipboardGuard {
    /// 监听线程句柄（窗口由该线程创建并销毁）
    join_handle: Option<JoinHandle<()>>,
    /// 当前监听轮次的停止信号（每轮启动独立创建，避免跨轮串扰）
    stop_flag: Option<Arc<AtomicBool>>,
}

impl ClipboardGuard {
    pub fn new() -> Self {
        ClipboardGuard {
            join_handle: None,
            stop_flag: None,
        }
    }

    /// 停止并回收当前监听线程（有界等待，超时 detach 由进程退出回收）。
    ///
    /// 先置停止信号、再置 `monitoring=false`：监听线程在状态锁内检查停止
    /// 信号后才写入 `monitoring=true`，因此不会出现“停止后又被置回运行”的竞态。
    #[cfg(target_os = "windows")]
    fn stop_listener_thread(&mut self) {
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, Ordering::SeqCst);
        }
        {
            let mut state = lock_state();
            state.monitoring = false;
        }
        PENDING_UPDATE.store(false, Ordering::SeqCst);

        if let Some(handle) = self.join_handle.take() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !handle.is_finished() {
                if std::time::Instant::now() >= deadline {
                    // 丢弃 JoinHandle 即 detach：线程持有独立停止信号，不会
                    // 再改写全局监听状态；其窗口资源随线程退出自行回收。
                    log::warn!("[clipboard_guard] 监听线程 3 秒内未退出，detach（随进程退出回收）");
                    return;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = handle.join();
        }
    }

    /* ---------------- 延迟清空写入 ---------------- */
    /// 写入敏感内容（延迟清空模式）：
    ///
    /// SetClipboardData 后绝不清空。
    /// 敏感内容正常驻留剪贴板中，供用户粘贴。
    /// 清空动作仅在以下条件触发时执行：
    ///   - 30 秒自动过期（check_sensitive_expire 轮询）
    ///   - 高安全模式下检测到外部 SetClipboardData（process_clipboard_update）
    ///   - 显式调用 clear / transactional_clear
    ///
    /// 写入时通过 CF_PRIVATEFIRST 标记，
    /// 从源头防止进入剪贴板历史记录。
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    pub fn write_sensitive(content: &str) -> Result<(), String> {
        // 串行化剪贴板物理 API 访问
        let _lock = CLIPBOARD_LOCK
            .lock()
            .map_err(|e| format!("CLIPBOARD_LOCK poisoned: {}", e))?;

        // 准备 CF_UNICODETEXT 内容：UTF-16 编码 + NUL 终止符
        let mut utf16: Vec<u16> = content.encode_utf16().collect();
        utf16.push(0u16);
        let size = utf16.len() * 2; // 字节数

        // 原子设置 Writing 阶段 + 过期时间
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Writing;
            state.expire_at_ms = now_ms() + SENSITIVE_EXPIRE_SECS * 1000;
        }

        let result: Result<(), String> = unsafe {
            let _ = OleInitialize(None);
            let hwnd = HWND(std::ptr::null_mut());
            if OpenClipboard(hwnd).is_err() {
                Err(format!(
                    "OpenClipboard 失败: GetLastError={}",
                    GetLastError()
                ))
            } else {
                // 先清空既有内容
                let _ = EmptyClipboard();

                // 1. GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE) 分配共享可移动内存
                let h_mem_raw = GlobalAlloc(GMEM_DDESHARE_RAW | GMEM_MOVEABLE_RAW, size);
                if h_mem_raw == 0 {
                    let _ = CloseClipboard();
                    Err(format!(
                        "GlobalAlloc(GMEM_DDESHARE|GMEM_MOVEABLE) 失败: GetLastError={}",
                        GetLastError()
                    ))
                } else {
                    // 2. GlobalLock → 拷贝 → GlobalUnlock
                    let ptr = GlobalLock(h_mem_raw);
                    if ptr.is_null() {
                        let _ = CloseClipboard();
                        Err(format!("GlobalLock 失败: GetLastError={}", GetLastError()))
                    } else {
                        std::ptr::copy_nonoverlapping(utf16.as_ptr() as *const u8, ptr, size);
                        let _ = GlobalUnlock(h_mem_raw);

                        // 3. SetClipboardData(CF_UNICODETEXT, handle)
                        //    SetClipboardData 接管内存所有权，不可 GlobalFree
                        match SetClipboardData(CF_UNICODETEXT, HANDLE(h_mem_raw as *mut _)) {
                            Ok(_) => {
                                // 写入 CF_PRIVATEFIRST 标记，
                                // 防止进入剪贴板历史记录（best-effort）
                                let h_priv = GlobalAlloc(GMEM_MOVEABLE_RAW, 1);
                                if h_priv != 0 {
                                    let priv_ptr = GlobalLock(h_priv);
                                    if !priv_ptr.is_null() {
                                        *priv_ptr = 1u8; // 标记字节
                                        let _ = GlobalUnlock(h_priv);
                                        let _ = SetClipboardData(
                                            CF_PRIVATEFIRST,
                                            HANDLE(h_priv as *mut _),
                                        );
                                    }
                                }

                                let _ = CloseClipboard();

                                // 绝不清空！敏感内容驻留供用户粘贴
                                log::info!(
                                    "[clipboard_guard] write_sensitive: 写入 {} 字符，\
                                     延迟清空模式（{} 秒后自动清空 / 外部写入触发清空）",
                                    content.chars().count(),
                                    SENSITIVE_EXPIRE_SECS
                                );
                                Ok(())
                            }
                            Err(e) => {
                                let _ = CloseClipboard();
                                Err(format!("SetClipboardData 失败: {}", e))
                            }
                        }
                    }
                }
            }
        };

        // 显式清零本地敏感缓冲区
        for w in utf16.iter_mut() {
            *w = 0;
        }

        // 原子更新状态
        {
            let mut state = lock_state();
            match &result {
                Ok(()) => {
                    state.stage = ClipboardStage::SensitivePresent;
                    state.last_seq = unsafe { GetClipboardSequenceNumber() };
                }
                Err(e) => {
                    state.stage = ClipboardStage::Idle;
                    log::error!("[clipboard_guard] write_sensitive 失败: {}", e);
                }
            }
        }

        result
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    pub fn write_sensitive(_content: &str) -> Result<(), String> {
        Err("clipboard_guard: 非 Windows 平台不支持".into())
    }

    /* ---------------- 事务式剪贴板安全清空 ---------------- */
    /// 事务式剪贴板安全清空
    ///
    /// 移除垃圾覆写轮次，改为直接 EmptyClipboard。
    /// 事务性体现在 OpenClipboard 重试 + 最终广播 WM_DESTROYCLIPBOARD。
    ///
    /// 完整事务序列：
    ///   1. OpenClipboard 获取所有权（重试 3 次，每次间隔 50ms）
    ///   2. EmptyClipboard 清空所有格式
    ///   3. 广播 WM_DESTROYCLIPBOARD 强制系统清除云剪贴板缓存
    ///   4. CloseClipboard
    ///
    /// 重试机制：OpenClipboard 失败（剪贴板被占用）时等待 50ms 重试，最多 3 次。
    /// 全部失败返回 Err（不再静默返回 Ok）。
    #[cfg(target_os = "windows")]
    pub fn transactional_clear() -> Result<(), String> {
        // 标记为 Writing 以忽略清空操作自身产生的通知
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Writing;
        }

        let result = do_clear_internal();

        // 原子更新状态
        let mut state = lock_state();
        state.stage = ClipboardStage::Idle;
        state.last_seq = unsafe { GetClipboardSequenceNumber() };
        state.expire_at_ms = 0;

        if let Err(ref e) = result {
            log::error!("[clipboard_guard] transactional_clear 失败: {}", e);
        }
        result
    }

    #[cfg(not(target_os = "windows"))]
    pub fn transactional_clear() -> Result<(), String> {
        Err("clipboard_guard: 非 Windows 平台不支持".into())
    }

    /* ---------------- 启动监听 ---------------- */
    /// 启动剪贴板格式监听器（AddClipboardFormatListener）+ 监听线程。
    ///
    /// 幂等语义：监听已在运行时重复启动直接成功。安全档位恢复链会在每次
    /// 进入中枢时重复下发同一开关，重复启动不得被当作失败上报。
    ///
    /// 启动握手：监听线程完成窗口创建与监听注册后回传 Ok/Err；
    /// 失败必须如实返回，绝不制造“已启动”假象。
    #[cfg(target_os = "windows")]
    pub fn start_monitoring(&mut self) -> Result<(), String> {
        // 1. 幂等判定：线程仍存活且状态为监听中 → 直接成功
        if lock_state().monitoring
            && self
                .join_handle
                .as_ref()
                .is_some_and(|handle| !handle.is_finished())
        {
            log::info!("[clipboard_guard] 监听已在运行，重复启动按幂等成功处理");
            return Ok(());
        }

        // 2. 回收上一轮残留（线程已退出但句柄未回收 / 状态残留）
        self.stop_listener_thread();

        // 3. 启动监听线程（窗口归属该线程，消息循环与本线程同源）
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = stop_flag.clone();

        let handle = thread::Builder::new()
            .name("verthys-clipboard-guard".into())
            .spawn(move || run_listener_thread(ready_tx, thread_stop))
            .map_err(|e| format!("启动剪贴板监听线程失败: {}", e))?;

        self.join_handle = Some(handle);
        self.stop_flag = Some(stop_flag);

        // 4. 有界等待启动结果：超时按失败上报并回收线程
        match ready_rx.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                self.stop_listener_thread();
                Err(e)
            }
            Err(_) => {
                self.stop_listener_thread();
                Err("剪贴板监听线程启动超时".into())
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start_monitoring(&mut self) -> Result<(), String> {
        Err("clipboard_guard: 非 Windows 平台不支持".into())
    }

    /* ---------------- 停止监听 ---------------- */
    /// 停止监听：置停止信号 → 有界等待线程自行销毁窗口并退出。
    ///
    /// 窗口由监听线程创建，必须由其自身销毁（Win32 跨线程 DestroyWindow 会
    /// 失败），因此这里不再持有或操作窗口句柄。
    #[cfg(target_os = "windows")]
    pub fn stop_monitoring(&mut self) {
        let was_monitoring = lock_state().monitoring;
        self.stop_listener_thread();

        // 清除敏感内容状态
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Idle;
            state.expire_at_ms = 0;
        }

        if was_monitoring {
            log::info!("[clipboard_guard] 剪贴板监听已停止");
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn stop_monitoring(&mut self) {}

    /* ---------------- 高安全模式开关 ---------------- */
    /// 启用 / 禁用「外部写入即清空」行为。
    /// 高安全标志仅作为状态字段，不再依赖全局原子变量。
    pub fn set_high_security_mode(&mut self, enabled: bool) {
        let mut state = lock_state();
        state.high_security = enabled;
        log::info!(
            "[clipboard_guard] 高安全模式: {}",
            if enabled { "启用" } else { "禁用" }
        );
    }
}

impl Default for ClipboardGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}

/* ==================================================================== *
 *  单元测试                                                             *
 * ==================================================================== */
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    /// 回归：重复启动必须幂等成功，停止后重启必须成功。
    ///
    /// 旧实现每次启动都重复 RegisterClassExW，第二次返回 1410
    /// （ERROR_CLASS_ALREADY_EXISTS）被误判为“剪贴板监听启动失败”，
    /// 导致中枢误报“会话硬化未完全生效”。
    #[test]
    fn clipboard_monitor_start_is_idempotent_and_restartable() {
        let mut guard = ClipboardGuard::new();

        guard.start_monitoring().expect("首次启动剪贴板监听失败");
        guard
            .start_monitoring()
            .expect("重复启动必须幂等成功（不得因窗口类已注册而失败）");
        guard.stop_monitoring();

        guard
            .start_monitoring()
            .expect("停止后重新启动剪贴板监听失败");
        guard.stop_monitoring();

        assert!(!lock_state().monitoring, "停止后监听状态必须为关闭");
    }
}
