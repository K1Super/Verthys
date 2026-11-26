use libloading::Symbol;
use std::os::raw::c_char;

#[cfg(windows)]
use crate::log::diag;
use crate::runtime::ffi_types::*;
use crate::runtime::progress_cb::vty_rotate_progress_cb;
#[cfg(windows)]
use crate::runtime::progress_cb::{clear_rotate_cancel_handle, set_rotate_cancel_handle};

use super::{ffi_call, Worker};

/* ------------------------------------------------------------------ *
 * 轮换取消命名事件（Windows）                                         *
 *                                                                    *
 * 父进程（Tauri 主进程）创建命名事件，Run 请求只携带事件名；worker   *
 * 打开事件并在进度回调中节流检查。事件为 auto-reset：一次置位只被    *
 * 消费一次，不会影响后续轮换。                                       *
 * ------------------------------------------------------------------ */

#[cfg(windows)]
pub(super) fn open_rotate_cancel_event(name: &str) -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::System::Threading::OpenEventW;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0u16)).collect();
    let handle = unsafe { OpenEventW(SYNCHRONIZE, 0, wide.as_ptr()) };
    if handle.is_null() { None } else { Some(handle) }
}

#[cfg(windows)]
pub(super) fn rotate_cancel_signaled(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    unsafe { WaitForSingleObject(handle, 0) == 0 }
}

#[cfg(windows)]
pub(super) fn close_rotate_cancel_event(handle: windows_sys::Win32::Foundation::HANDLE) {
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
}

impl Worker {

    /* ================================================================ *
     * 全库 DEK 轮换（作业式五段入口）                            *
     *                                                                *
     * 口令/恢复码只在本次调用内以字节切片透传，worker 不缓存、不写日志； *
     * Run 通过同步进度回调写 stdout 进度行，主线程在 FFI 期间不持锁。   *
     * ================================================================ */

    pub(crate) fn call_rotate_begin(
        &self,
        new_path: &str,
        password: &str,
        flags: u32,
    ) -> Result<VerthysRotateInfoC, u32> {
        let mut info: VerthysRotateInfoC = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4RotateBeginFn> =
                match lib.get(b"Verthys_V4RotateBegin") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let path_c = match std::ffi::CString::new(new_path) {
                Ok(c) => c,
                Err(_) => return Err(0x00000001u32),
            };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    path_c.as_ptr(),
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    flags,
                    &mut info,
                )
            })
            .unwrap_or(0xFFFFFFFF)
        };
        if rc == VERTHYS_OK { Ok(info) } else { Err(rc) }
    }

    pub(crate) fn call_rotate_attach_keyfile(
        &self,
        keyfile_path: &str,
        password: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4RotateAttachKeyfileFn> =
                match lib.get(b"Verthys_V4RotateAttachKeyfile") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let path_c = match std::ffi::CString::new(keyfile_path) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    path_c.as_ptr(),
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_rotate_unlock_module(
        &self,
        module_id: u32,
        password: &str,
        recovery_code: Option<&str>,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4RotateUnlockModuleFn> =
                match lib.get(b"Verthys_V4RotateUnlockModule") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.as_bytes();
            /* 恢复码可选：C 层按 NULL/空串跳过二次校验。 */
            let rec = match recovery_code {
                Some(code) => match std::ffi::CString::new(code) {
                    Ok(c) => Some(c),
                    Err(_) => return 0x00000001u32,
                },
                None => None,
            };
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    rec.as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(std::ptr::null()),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_rotate_run(&self, cancel_event: Option<&str>) -> u32 {
        /* 取消信号：父进程创建命名事件并把名称放进 Run 请求；worker 在此
         * 打开事件，进度回调按 200ms 节流检查。Run 返回即关闭句柄。 */
        #[cfg(windows)]
        let mut cancel_handle: Option<windows_sys::Win32::Foundation::HANDLE> = None;
        #[cfg(windows)]
        if let Some(name) = cancel_event {
            let handle = match open_rotate_cancel_event(name) {
                Some(h) => h,
                None => {
                    diag!("[worker] 轮换取消事件打开失败，拒绝 Run（fail-closed）");
                    return 0x00000001u32;
                }
            };
            /* Run 前已置位：直接按取消返回，避免空库无进度回调时取消失效。 */
            if rotate_cancel_signaled(handle) {
                close_rotate_cancel_event(handle);
                diag!("[worker] 轮换在 Run 前收到取消信号");
                return 0x00000017u32;
            }
            set_rotate_cancel_handle(handle);
            cancel_handle = Some(handle);
        }
        #[cfg(not(windows))]
        let _ = cancel_event;

        let rc = unsafe {
            let lib = &self._lib;
            /* 符号查找失败也必须走统一清理出口：否则取消句柄泄漏到全局，
             * 下一次无取消事件的 Run 可能读到残留的置位状态。 */
            match lib.get::<VerthysV4RotateRunFn>(b"Verthys_V4RotateRun") {
                Ok(func) => ffi_call(|| {
                    func(
                        self.handle,
                        Some(vty_rotate_progress_cb),
                        std::ptr::null_mut(),
                    )
                })
                .unwrap_or(0xFFFFFFFF),
                Err(_) => 0xFFFFFFFF,
            }
        };

        #[cfg(windows)]
        {
            clear_rotate_cancel_handle();
            if let Some(handle) = cancel_handle.take() {
                close_rotate_cancel_event(handle);
            }
        }
        rc
    }

    pub(crate) fn call_rotate_commit(&self, keep_old: bool) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4RotateCommitFn> =
                match lib.get(b"Verthys_V4RotateCommit") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| func(self.handle, u32::from(keep_old))).unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_rotate_abort(&self) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4RotateAbortFn> =
                match lib.get(b"Verthys_V4RotateAbort") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| func(self.handle)).unwrap_or(0xFFFFFFFF)
        }
    }
}
