/*
 * clipboard_guard/win32.rs — Windows 常量、FFI 结构体、原始 FFI 与宽字符辅助
 */

/* ---------- Windows 消息常量 ---------- */
/// WM_CLIPBOARDUPDATE = 0x031D：AddClipboardFormatListener 注册后由系统投递
pub(super) const WM_CLIPBOARDUPDATE: u32 = 0x031D;
/// WM_DESTROYCLIPBOARD = 0x030D：EmptyClipboard 时系统发送给剪贴板所有者
pub(super) const WM_DESTROYCLIPBOARD: u32 = 0x030D;
pub(super) const WM_DESTROY: u32 = 0x0002;

/// 监听窗口类名（进程内仅注册一次）
pub(super) const LISTENER_CLASS_NAME: &str = "VerthysClipGuard";
/// ERROR_INVALID_WINDOW_HANDLE：窗口句柄失效（重建窗口重试一次）
pub(super) const ERROR_INVALID_WINDOW_HANDLE: u32 = 1401;
/// ERROR_CLASS_ALREADY_EXISTS：窗口类已注册（幂等复用，不视为失败）
pub(super) const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;

/// 剪贴板格式
pub(super) const CF_UNICODETEXT: u32 = 13;
/// CF_PRIVATEFIRST = 0x0200：私有格式范围起始，剪贴板历史工具通常不缓存
pub(super) const CF_PRIVATEFIRST: u32 = 0x0200;

/// HWND_BROADCAST = 0xFFFF：向所有顶层窗口广播
pub(super) const HWND_BROADCAST: isize = 0xFFFF;

/// GMEM_DDESHARE = 0x2000（windows crate 0.58 未导出此命名常量，以原始位构造）
pub(super) const GMEM_DDESHARE_RAW: u32 = 0x2000;
/// GMEM_MOVEABLE = 0x0002
pub(super) const GMEM_MOVEABLE_RAW: u32 = 0x0002;

/* ---------- Windows 原始 FFI 声明 ---------- */
#[link(name = "user32")]
extern "system" {
    pub(super) fn CreateWindowExW(
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

    pub(super) fn DefWindowProcW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> isize;

    pub(super) fn DestroyWindow(hWnd: isize) -> i32;

    /// PostMessageW：向指定窗口消息队列投递消息（线程安全），用于 stop 时唤醒循环
    pub(super) fn PostMessageW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> i32;

    pub(super) fn PeekMessageW(
        lpMsg: *mut Msg,
        hWnd: isize,
        wMsgFilterMin: u32,
        wMsgFilterMax: u32,
        wRemoveMsg: u32,
    ) -> i32;

    pub(super) fn TranslateMessage(lpMsg: *const Msg) -> i32;

    pub(super) fn DispatchMessageW(lpMsg: *const Msg) -> isize;

    pub(super) fn RegisterClassExW(lpWndClass: *const WndClassExW) -> u16;
}

#[link(name = "kernel32")]
extern "system" {
    pub(super) fn GetLastError() -> u32;
    pub(super) fn GetModuleHandleW(lpModuleName: *const u16) -> isize;
    pub(super) fn Sleep(dwMilliseconds: u32);

    /// GlobalAlloc（原始 FFI）：分配可移动/共享内存，返回 HGLOBAL（isize 形式）。
    pub(super) fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> isize;

    /// GlobalLock（原始 FFI）：锁定 HGLOBAL 内存并返回可写指针。
    pub(super) fn GlobalLock(h_mem: isize) -> *mut u8;

    /// GlobalUnlock（原始 FFI）：解锁 HGLOBAL 内存。
    pub(super) fn GlobalUnlock(h_mem: isize) -> i32;
}

/* ---------- FFI 结构体 ---------- */
#[repr(C)]
#[derive(Default)]
#[allow(non_snake_case)]
pub(super) struct WndClassExW {
    pub(super) cbSize: u32,
    pub(super) style: u32,
    pub(super) lpfnWndProc: Option<unsafe extern "system" fn(isize, u32, usize, isize) -> isize>,
    pub(super) cbClsExtra: i32,
    pub(super) cbWndExtra: i32,
    pub(super) hInstance: isize,
    pub(super) hIcon: isize,
    pub(super) hCursor: isize,
    pub(super) hbrBackground: isize,
    pub(super) lpszMenuName: *const u16,
    pub(super) lpszClassName: *const u16,
    pub(super) hIconSm: isize,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct Msg {
    hwnd: isize,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
}

/* ---------- 辅助：字符串转宽字符（含 NUL） ---------- */
pub(super) fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    if v.last() != Some(&0) {
        v.push(0);
    }
    v
}
