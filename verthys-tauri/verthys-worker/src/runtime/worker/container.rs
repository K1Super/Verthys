use libloading::Symbol;
use std::ffi::CStr;
use std::io::Read;
use std::os::raw::c_char;

use zeroize::Zeroize;

use crate::log::diag;
use crate::runtime::ffi_types::*;

use super::{ffi_call, Worker};

/* ------------------------------------------------------------------ *
 * 容器入口白名单                                                   *
 * ------------------------------------------------------------------ */

/// 只接受 VRTY 容器 magic。
///
/// 产品解锁入口不依赖 C 层按文件头分发，非 VRTY magic 的容器必须在
/// 进入 C 层前被拒绝。
/// 返回错误码与 C 层一致：0x05=FORMAT，0x08=IO。
pub(crate) fn check_container_magic(path: &str) -> Result<(), u32> {
    const VERTHYS_ERR_IO: u32 = 0x00000008;
    const VERTHYS_ERR_FORMAT: u32 = 0x00000005;
    const CONTAINER_MAGIC: &[u8; 4] = b"VRTY";

    let mut file = std::fs::File::open(path).map_err(|_| VERTHYS_ERR_IO)?;
    let mut header = [0u8; 8];
    let read = file.read(&mut header).map_err(|_| VERTHYS_ERR_IO)?;
    if read < CONTAINER_MAGIC.len() || &header[..CONTAINER_MAGIC.len()] != CONTAINER_MAGIC {
        return Err(VERTHYS_ERR_FORMAT);
    }
    Ok(())
}

impl Worker {
    /// 专用解锁入口：先做 magic 白名单，再调用容器解锁入口。
    /// C 层路径始终重新读取元数据。
    pub(crate) fn call_unlock(&self, path: &str, password: &str) -> u32 {
        if let Err(rc) = super::check_container_magic(path) {
            return rc;
        }
        unsafe {
            let lib = &self._lib;

            let func: Symbol<VerthysV4UnlockFn> = match lib.get(b"Verthys_V4Unlock") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return 0xFFFFFFFF,
            };
            let pw_bytes = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    path_c.as_ptr(),
                    pw_bytes.as_ptr() as *const c_char,
                    pw_bytes.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_lock(&self) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysLockFn> = match lib.get(b"Verthys_Lock") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 修复：调用 Verthys_Flush 显式刷盘
    ///
    /// 替代旧 verthys_flush 的 lock+unlock 模式（有 worker 卡在 LOCKED 状态的风险）。
    /// Verthys_Flush 语义：
    ///   - MemTable 强制 flush（冻结落盘 L0 SSTable → Manifest 原子提交 → WAL 复位）
    ///   - 空 MemTable 为 no-op，不清零密钥、不改 state
    ///
    /// 安全性：不改变 worker 状态（始终保持 UNLOCKED），不清零密钥，不重新加载索引
    pub(crate) fn call_flush(&self) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysFlushFn> = match lib.get(b"Verthys_Flush") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle) }).unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_deinit(&self) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysDeinitFn> = match lib.get(b"Verthys_Deinit") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle) }).unwrap_or(0xFFFFFFFF)
        }
    }


    pub(crate) fn call_change_password(&self, old_pw: &str, new_pw: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysChangePasswordFn> = match lib.get(b"Verthys_ChangePassword") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            let old_bytes = old_pw.as_bytes();
            let new_bytes = new_pw.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    old_bytes.as_ptr() as *const c_char,
                    old_bytes.len(),
                    new_bytes.as_ptr() as *const c_char,
                    new_bytes.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    /* ================================================================ *
     * 容器创建/恢复与 PCR 策略 FFI                                  *
     *                                                                *
     * 恢复码只经本次调用返回给宿主，worker 不落盘、不写日志；            *
     * PCR 入口只传位图与恢复码，密钥仍全部由 C 层持有。                 *
     * ================================================================ */

    pub(crate) fn call_create(
        &self,
        path: &str,
        password: &str,
    ) -> Result<String, u32> {
        let mut rec = [0u8; 80];
        let rc = unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4CreateFn> =
                match lib.get(b"Verthys_V4Create") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => {
                    diag!("[worker] v4_create: 路径含内嵌 NUL，length={}", path.len());
                    return Err(0x00000001u32);
                }
            };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    path_c.as_ptr(),
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    rec.as_mut_ptr() as *mut c_char,
                    rec.len(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        };
        if rc != VERTHYS_OK {
            rec.zeroize();
            return Err(rc);
        }
        let text = unsafe { CStr::from_ptr(rec.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned();
        rec.zeroize();
        Ok(text)
    }

    pub(crate) fn call_unlock_recovery(&self, path: &str, recovery_code: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4UnlockRecoveryFn> =
                match lib.get(b"Verthys_V4UnlockRecovery") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            let rec_c = match std::ffi::CString::new(recovery_code) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            ffi_call(|| func(self.handle, path_c.as_ptr(), rec_c.as_ptr()))
                .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_pcr_status(&self) -> Result<(u32, u32), u32> {
        let mut enabled: u32 = 0;
        let mut select: u32 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4PcrStatusFn> =
                match lib.get(b"Verthys_V4PcrStatus") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| func(self.handle, &mut enabled, &mut select))
                .unwrap_or(0xFFFFFFFF);
            if rc == VERTHYS_OK { Ok((enabled, select)) } else { Err(rc) }
        }
    }

    pub(crate) fn call_pcr_enable(&self, pcr_select: u32, recovery_code: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4PcrEnableFn> =
                match lib.get(b"Verthys_V4PcrEnable") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let rec = match std::ffi::CString::new(recovery_code) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            ffi_call(|| func(self.handle, pcr_select, rec.as_ptr())).unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_pcr_disable(&self, recovery_code: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4PcrDisableFn> =
                match lib.get(b"Verthys_V4PcrDisable") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let rec = match std::ffi::CString::new(recovery_code) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            ffi_call(|| func(self.handle, rec.as_ptr())).unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_pcr_reseal(&self, recovery_code: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4PcrResealFn> =
                match lib.get(b"Verthys_V4PcrReseal") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let rec = match std::ffi::CString::new(recovery_code) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            ffi_call(|| func(self.handle, rec.as_ptr())).unwrap_or(0xFFFFFFFF)
        }
    }
}
