use libloading::Symbol;

use crate::runtime::ffi_types::*;

use super::{ffi_call, VerifyPersistOutcome, Worker};

impl Worker {
    pub(crate) fn call_get_storage_stats(&self) -> Result<VerthysStorageStatsC, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetStorageStatsFn> =
                match lib.get(b"Verthys_GetStorageStats") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFFu32),
                };
            let mut out = VerthysStorageStatsC::default();
            let rc = ffi_call(|| func(self.handle, &mut out)).unwrap_or(0xFFFFFFFF);
            if rc == VERTHYS_OK {
                Ok(out)
            } else {
                Err(rc)
            }
        }
    }

    /* ----------------------------------------------------------------
     * 落盘自查（Verthys_VerifyPersist）
     *
     * 由 worker 进程内用 C 层持锁句柄自查盘面结构：容器会话以独占方式
     * 持有超级块区 [0,64KB) 字节范围锁，主进程外部读必失败（os error
     * 33），只有持锁进程持锁句柄能读。Err(0xFFFFFFFF) 仅表示符号缺失或
     * FFI panic；C 层返回的非 OK 状态经 Ok(outcome.status_code) 原样透传。
     * ---------------------------------------------------------------- */
    pub(crate) fn call_verify_persist(&self) -> Result<VerifyPersistOutcome, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysVerifyPersistFn> =
                match lib.get(b"Verthys_VerifyPersist") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFFu32),
                };
            let mut out: VerPersistVerifyResultC = std::mem::zeroed();
            let status = ffi_call(|| { func(self.handle, &mut out as *mut VerPersistVerifyResultC) })
                .map_err(|_| 0xFFFFFFFFu32)?;

            // last_error 为 C 端 NULL 终结的 UTF-8 缓冲：按首个 NUL 截断
            let mut len = 0usize;
            while len < out.last_error.len() && out.last_error[len] != 0 {
                len += 1;
            }
            let bytes: Vec<u8> = out.last_error[..len].iter().map(|c| *c as u8).collect();

            Ok(VerifyPersistOutcome {
                status_code: status,
                file_size: out.file_size,
                mtime_ms: out.mtime_ms,
                header_magic: out.header_magic,
                header_version: out.header_version,
                wal_offset: out.wal_offset,
                last_error: String::from_utf8_lossy(&bytes).into_owned(),
            })
        }
    }
}
