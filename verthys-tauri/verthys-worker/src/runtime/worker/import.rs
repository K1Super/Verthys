use libloading::Symbol;
use std::os::raw::c_char;

use crate::log::diag;
use crate::runtime::ffi_types::*;

use super::{ffi_call, Worker};

impl Worker {
    /// 批量导入锚点推迟（API 0x0015）：旧 DLL 缺符号时返回
    /// `VERTHYS_SYMBOL_UNSUPPORTED`，由宿主回退逐次提交。
    pub(crate) fn call_bulk_import_begin(&self) -> Result<(), u32> {
        self.call_bulk_import_symbol(b"Verthys_BulkImportBegin")
    }

    pub(crate) fn call_bulk_import_commit(&self) -> Result<(), u32> {
        self.call_bulk_import_symbol(b"Verthys_BulkImportCommit")
    }

    fn call_bulk_import_symbol(&self, name: &[u8]) -> Result<(), u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysBulkImportFn> = match lib.get(name) {
                Ok(f) => f,
                Err(_) => return Err(VERTHYS_SYMBOL_UNSUPPORTED),
            };
            let r = ffi_call(|| { func(self.handle) }).unwrap_or(0xFFFFFFFF);
            if r == VERTHYS_OK { Ok(()) } else { Err(r) }
        }
    }


    pub(crate) fn call_export(&self, path: &str, password: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysExportFn> = match lib.get(b"Verthys_Export") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => {
                    // 嵌入 NUL 的路径：日志只记字节长度，不回显原始内容（防日志注入）
                    diag!("[worker] export: 路径含内嵌 NUL，length={}", path.len());
                    return 0xFFFFFFFF;
                }
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

    pub(crate) fn call_import(&self, path: &str, password: &str) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysImportFn> = match lib.get(b"Verthys_Import") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => {
                    // 嵌入 NUL 的路径：日志只记字节长度，不回显原始内容（防日志注入）
                    diag!("[worker] import: 路径含内嵌 NUL，length={}", path.len());
                    return 0xFFFFFFFF;
                }
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
}
