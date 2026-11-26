use libloading::Symbol;
use std::ffi::CStr;
use std::os::raw::c_char;

use zeroize::Zeroize;

use crate::runtime::ffi_types::*;

use super::{ffi_call, Worker};

impl Worker {
    /* ================================================================ *
     * keyfile 因子 FFI                                               *
     *                                                                *
     * keyfile 路径经 IPC 传入，文件内容只在 C 层读取/生成；worker 不   *
     * 持有 keyfile 字节，也不缓存其摘要。                              *
     * ================================================================ */

    pub(crate) fn call_create_keyfile(
        &self,
        path: &str,
        password: &str,
        keyfile_path: &str,
    ) -> Result<String, u32> {
        let mut rec = [0u8; 80];
        let rc = unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4CreateKeyfileFn> =
                match lib.get(b"Verthys_V4CreateKeyfile") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return Err(0x00000001u32),
            };
            let kf_c = match std::ffi::CString::new(keyfile_path) {
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
                    kf_c.as_ptr(),
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

    pub(crate) fn call_unlock_keyfile(
        &self,
        path: &str,
        password: &str,
        keyfile_path: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4UnlockKeyfileFn> =
                match lib.get(b"Verthys_V4UnlockKeyfile") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            let kf_c = match std::ffi::CString::new(keyfile_path) {
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
                    kf_c.as_ptr(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_keyfile_enable(
        &self,
        password: &str,
        new_keyfile_path: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4KeyfileEnableFn> =
                match lib.get(b"Verthys_V4KeyfileEnable") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let kf_c = match std::ffi::CString::new(new_keyfile_path) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    kf_c.as_ptr(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_keyfile_disable(
        &self,
        password: &str,
        keyfile_path: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4KeyfileDisableFn> =
                match lib.get(b"Verthys_V4KeyfileDisable") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let kf_c = match std::ffi::CString::new(keyfile_path) {
                Ok(c) => c,
                Err(_) => return 0x00000001u32,
            };
            let pw = password.as_bytes();
            ffi_call(|| {
                func(
                    self.handle,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    kf_c.as_ptr(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    pub(crate) fn call_keyfile_status(&self) -> Result<(bool, bool), u32> {
        let mut enabled: u32 = 0;
        let mut recovery_mode: u32 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4KeyfileStatusFn> =
                match lib.get(b"Verthys_V4KeyfileStatus") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| func(self.handle, &mut enabled, &mut recovery_mode))
                .unwrap_or(0xFFFFFFFF);
            if rc == VERTHYS_OK {
                Ok((enabled != 0, recovery_mode != 0))
            } else {
                Err(rc)
            }
        }
    }

    /// 恢复会话重绑容器 user/device 槽。keyfile_path 为空表示容器未启用
    /// keyfile；启用但未提供时由 C 层返回 KEYFILE_REQUIRED。
    pub(crate) fn call_reseal_device(
        &self,
        password: &str,
        keyfile_path: &str,
    ) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ResealDeviceFn> =
                match lib.get(b"Verthys_V4ResealDevice") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let pw = zeroize::Zeroizing::new(password.as_bytes().to_vec());
            let kf_c = match std::ffi::CString::new(keyfile_path) {
                Ok(c) => c,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| {
                func(
                    self.handle,
                    pw.as_ptr() as *const c_char,
                    pw.len(),
                    kf_c.as_ptr(),
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    /* ================================================================ *
     * 内容分片/清单 FFI                                             *
     *                                                                *
     * 密钥只由 C 层用模块 MDEK 派生；worker 只持有密文/明文缓冲，       *
     * 调用返回后立即清零。                                             *
     * ================================================================ */

    pub(crate) fn call_chunk_seal(
        &self,
        module_id: u32,
        file_uuid: &[u8; 16],
        seq: u32,
        total: u32,
        plain: &[u8],
    ) -> Result<Vec<u8>, u32> {
        let cap = plain.len() + 128;
        let mut out = vec![0u8; cap];
        let mut out_len: usize = 0;
        let rc = unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ChunkSealFn> =
                match lib.get(b"Verthys_V4ChunkSeal") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    file_uuid.as_ptr(),
                    seq,
                    total,
                    plain.as_ptr(),
                    plain.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                )
            })
            .unwrap_or(0xFFFFFFFF)
        };
        if rc != VERTHYS_OK {
            out.zeroize();
            return Err(rc);
        }
        out.truncate(out_len);
        Ok(out)
    }

    pub(crate) fn call_chunk_open(
        &self,
        module_id: u32,
        file_uuid: &[u8; 16],
        seq: u32,
        total: u32,
        cipher: &[u8],
    ) -> Result<Vec<u8>, u32> {
        let mut out = vec![0u8; cipher.len()];
        let mut out_len: usize = 0;
        let rc = unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysV4ChunkOpenFn> =
                match lib.get(b"Verthys_V4ChunkOpen") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            ffi_call(|| {
                func(
                    self.handle,
                    module_id,
                    file_uuid.as_ptr(),
                    seq,
                    total,
                    cipher.as_ptr(),
                    cipher.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                )
            })
            .unwrap_or(0xFFFFFFFF)
        };
        if rc != VERTHYS_OK {
            out.zeroize();
            return Err(rc);
        }
        out.truncate(out_len);
        Ok(out)
    }
}
