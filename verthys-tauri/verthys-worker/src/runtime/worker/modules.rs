use libloading::Symbol;
use std::ffi::CStr;
use std::os::raw::c_char;

use zeroize::Zeroize;

use crate::runtime::ffi_types::*;

use super::{ffi_call, Worker};

impl Worker {

    /* ================================================================ *
     * 模块 M1 会话 FFI                                              *
     *                                                                *
     * 只转发模块索引与口令/恢复码；MDEK 与任何派生密钥都由 C 层持有，   *
     * worker 不缓存模块口令，也不在响应中返回密钥。                    *
     * ================================================================ */

    pub(crate) fn call_module_enable(
        &self,
        module_id: u32,
        password: &str,
        recovery_code: Option<&str>,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleEnableFn> =
                match lib.get(b"Verthys_V4ModuleEnable") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.as_bytes();
            /* C 层按 NUL 结尾读取恢复码（strlen）；Rust &str 不带 NUL，
             * 直接把 as_ptr 交给 C 会越过字符串末尾读取，导致随机拒绝。 */
            let rec = match recovery_code {
                Some(text) => match std::ffi::CString::new(text) {
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
                        .map_or(std::ptr::null(), |c| c.as_ptr()),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_unlock(&self, module_id: u32, password: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleUnlockFn> =
                match lib.get(b"Verthys_V4ModuleUnlock") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_lock(&self, module_id: u32) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleLockFn> =
                match lib.get(b"Verthys_V4ModuleLock") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| func(self.handle, module_id)).unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_rotate_password(
        &self,
        module_id: u32,
        old_password: &str,
        new_password: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleRotatePasswordFn> =
                match lib.get(b"Verthys_V4ModuleRotatePassword") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let old = old_password.as_bytes();
            let new = new_password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    old.as_ptr() as *const c_char,
                    old.len(),
                    new.as_ptr() as *const c_char,
                    new.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_disable(&self, module_id: u32, password: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleDisableFn> =
                match lib.get(b"Verthys_V4ModuleDisable") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_delete(
        &self,
        module_id: u32,
        password: Option<&str>,
        confirm: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleDeleteFn> =
                match lib.get(b"Verthys_V4ModuleDelete") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.map(|s| s.as_bytes());
            let pw_ptr = pw.map(|b| b.as_ptr() as *const c_char);
            let pw_len = pw.map(|b| b.len()).unwrap_or(0);
            /* confirm 由 C 层 strcmp 校验，必须 NUL 结尾。 */
            let confirm_c = match std::ffi::CString::new(confirm) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    pw_ptr.unwrap_or(std::ptr::null()),
                    pw_len,
                    confirm_c.as_ptr(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_bind_recovery(
        &self,
        module_id: u32,
        password: &str,
        recovery_code: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleBindRecoveryFn> =
                match lib.get(b"Verthys_V4ModuleBindRecovery") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.as_bytes();
            /* C 层按 NUL 结尾读取恢复码；Rust &str 不含 NUL。 */
            let rec = match std::ffi::CString::new(recovery_code) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    rec.as_ptr(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_reseal_device(&self, module_id: u32, password: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleResealDeviceFn> =
                match lib.get(b"Verthys_V4ModuleResealDevice") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_module_status(
        &self,
        module_id: u32,
    ) -> Result<VerthysModuleStatusC, u32> {
        let mut st: VerthysModuleStatusC = unsafe { std::mem::zeroed() };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleStatusFn> =
                match lib.get(b"Verthys_V4ModuleStatus") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| func(self.handle, module_id, &mut st)).unwrap_or(0xFFFFFFFF);
            if rc == VERTHYS_OK { Ok(st) } else { Err(rc) }
        }
    }

    /// 只读查询模块锁剩余秒数；查询不可用时返回 None（不改变错误链）。
    pub(crate) fn call_module_lockout_remaining(&self, module_id: u32) -> Option<u64> {
        let mut secs: u32 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ModuleLockoutRemainingFn> = lib
                .get(b"Verthys_V4ModuleLockoutRemaining")
                .ok()?;
            let rc = ffi_call(|| func(self.handle, module_id, &mut secs)).unwrap_or(0xFFFFFFFF);
            if rc == VERTHYS_OK { Some(secs as u64) } else { None }
        }
    }

    /// 只读查询库级熔断剩余秒数；查询不可用时返回 None（不改变错误链）。
    pub(crate) fn call_get_lib_lockout_remaining(&self) -> Option<u64> {
        let mut secs: u32 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetLibLockoutRemainingFn> = lib
                .get(b"Verthys_GetLibLockoutRemaining")
                .ok()?;
            let rc = ffi_call(|| func(&mut secs)).unwrap_or(0xFFFFFFFF);
            if rc == VERTHYS_OK { Some(secs as u64) } else { None }
        }
    }

    pub(crate) fn call_recovery_rotate(
        &self,
        password: &str,
        old_recovery: &str,
    ) -> Result<String, u32> {
        let mut out = [0u8; 80];
        let rc = unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4RecoveryRotateFn> =
                match lib.get(b"Verthys_V4RecoveryRotate") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let pw = password.as_bytes();
            /* C 层按 NUL 结尾读取旧恢复码（strlen）；Rust &str 不含 NUL。 */
            let old = match std::ffi::CString::new(old_recovery) {
                Ok(c) => c,
                Err(_) => return Err(0x00000001u32),
            };
            ffi_call(|| {
                func(
                    self.handle,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    old.as_ptr(),
                    out.as_mut_ptr() as *mut c_char,
                    out.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        };
        if rc != VERTHYS_OK {
            out.zeroize();
            return Err(rc);
        }
        let text = unsafe { CStr::from_ptr(out.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned();
        out.zeroize();
        Ok(text)
    }
}
