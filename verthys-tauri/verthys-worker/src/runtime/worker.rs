/* worker.rs — Worker：持有 DLL + 句柄
 *
 * 职责：
 *   - struct Worker（持有 Library / VerthysHandle / scan_cursor / scan_shm）
 *   - impl Worker：new + 所有 call_xxx 方法（FFI 调用封装）
 *   - impl Drop（清理游标 + 共享内存 + Lock → Deinit + 清零 GMK）
 *
 * 依赖：libloading、std::os::raw::c_char、crate::log::init_diag、
 *       crate::defense、ffi_types（大量函数指针类型）、scan_shm（windows）、
 *       progress_cb（注册回调）、gmk::GMK（Drop 清零）、diagnostics::format_os_error。
 */

mod container;
mod dll;
mod ffi_guards;
mod import;
mod keyfile;
mod modules;
mod records;
mod rotate;
mod scan;
mod security;
mod storage;

use libloading::Library;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::runtime::ffi_types::{VerthysHandle, VerthysScanCursorPtr};
use crate::runtime::gmk::GMK;
#[cfg(windows)]
use crate::runtime::scan_shm;

pub(crate) use container::check_container_magic;
pub(crate) use ffi_guards::{clamp_enum_count, ffi_call, VerifyPersistOutcome};

pub(crate) struct Worker {
    _lib: Library,
    handle: VerthysHandle,
    /// 游标批量扫描状态
    scan_cursor: Option<VerthysScanCursorPtr>,
    /// 共享内存传输段（游标扫描专用）
    #[cfg(windows)]
    scan_shm: Option<scan_shm::ScanShm>,
    /// 运行时守卫完整掩码（bit0=心跳运行 bit1=挂起守卫接线）。
    /// 心跳位由心跳线程启动后置位；挂起位由主进程经 runtime_guards op 下发。
    runtime_guards: AtomicU32,
    /// 旧 DLL 缺少 Verthys_NotifyRuntimeGuards 时只记录一次诊断，不阻断主循环。
    guards_symbol_warned: AtomicBool,
    /// 心跳线程停止标志与句柄（arm_heartbeat 成功后存在）。
    heartbeat_stop: Option<Arc<AtomicBool>>,
    heartbeat_thread: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // 先停心跳线程，避免其在锁库/析构期间继续脉冲
        if let Some(stop) = self.heartbeat_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(thread) = self.heartbeat_thread.take() {
            let _ = thread.join();
        }
        // 清理扫描游标 + 共享内存
        let _ = self.call_scan_close();
        // 安全清理：Lock → Deinit + 清零 GMK
        let _ = self.call_lock();
        let _ = self.call_deinit();
        GMK.with(|g| *g.borrow_mut() = None);
    }
}

/* ------------------------------------------------------------------ *
 * 守卫擦除测试（Windows）                                             *
 *                                                                    *
 * Drop 擦除无法在释放后观测，改为直接验证 scrub() 覆写效果；          *
 * Drop → scrub 委托为单行实现，由代码审查保证。                       *
 * ------------------------------------------------------------------ */

#[cfg(all(test, windows))]
mod tests {
    use super::ffi_guards::{PlainBatchGuard, SummaryBatchGuard, MAX_ENUM_COUNT};
    use super::*;

    #[test]
    fn clamp_enum_count_caps_huge_values() {
        // 恶意超大 id（1e8）必须被截断到硬上限，防巨大分配
        assert_eq!(clamp_enum_count(100_000_000), MAX_ENUM_COUNT);
        assert_eq!(clamp_enum_count(MAX_ENUM_COUNT + 1), MAX_ENUM_COUNT);
    }

    #[test]
    fn clamp_enum_count_preserves_small_values() {
        assert_eq!(clamp_enum_count(0), 0);
        assert_eq!(clamp_enum_count(1), 1);
        assert_eq!(clamp_enum_count(500), 500);
        assert_eq!(clamp_enum_count(MAX_ENUM_COUNT), MAX_ENUM_COUNT);
    }

    #[test]
    fn ffi_call_captures_panic_and_returns_err() {
        // 人为 panic：断言不向外传播，而是返回 Err + 置位进程级标记，
        // 调用方据此返回失败码——panic 绝不展开跨 FFI 边界
        let result = ffi_call(|| -> u32 { panic!("人为注入 panic"); });
        assert!(result.is_err(), "panic 应被 ffi_call 捕获并转为 Err");
        assert!(
            crate::log::panic_flag_is_set(),
            "捕获 panic 后应置位进程级标记"
        );
    }

    #[test]
    fn ffi_call_passes_through_normal_return() {
        let result = ffi_call(|| -> u32 { 0x22 });
        assert_eq!(result, Ok(0x22));
    }

    #[test]
    fn plain_batch_guard_scrub_overwrites_name_and_data() {
        let mut g = PlainBatchGuard::with_capacity(2);
        g.push((1, 2, "记录名明文".to_string(), b"data-plaintext".to_vec()));
        g.push((3, 4, String::new(), Vec::new()));

        let (name_ptr, name_len, data_ptr, data_len) = {
            let r = &g.rows[0];
            (r.2.as_ptr(), r.2.len(), r.3.as_ptr(), r.3.len())
        };
        assert!(name_len > 0 && data_len > 0);

        g.scrub();

        unsafe {
            let name_bytes = std::slice::from_raw_parts(name_ptr, name_len);
            assert!(name_bytes.iter().all(|&b| b == 0), "name 应被三轮覆写清零");
            let data_bytes = std::slice::from_raw_parts(data_ptr, data_len);
            assert!(data_bytes.iter().all(|&b| b == 0), "data 应被三轮覆写清零");
        }

        // 幂等：scrub 后行数据已被覆写，再次调用不崩溃不改变全零状态
        g.scrub();
        unsafe {
            let name_bytes = std::slice::from_raw_parts(name_ptr, name_len);
            assert!(name_bytes.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn summary_batch_guard_scrub_overwrites_name_and_merkle() {
        let mut g = SummaryBatchGuard::with_capacity(1);
        g.push((
            7,
            8,
            "摘要记录名".to_string(),
            128,
            4096,
            [0xABu8; 32],
            1_700_000_000,
        ));

        let (name_ptr, name_len, merkle_ptr) = {
            let r = &g.rows[0];
            (r.2.as_ptr(), r.2.len(), r.5.as_ptr())
        };

        g.scrub();

        unsafe {
            let name_bytes = std::slice::from_raw_parts(name_ptr, name_len);
            assert!(name_bytes.iter().all(|&b| b == 0), "name 应被三轮覆写清零");
            let merkle_bytes = std::slice::from_raw_parts(merkle_ptr, 32);
            assert!(
                merkle_bytes.iter().all(|&b| b == 0),
                "merkle_leaf 应被三轮覆写清零"
            );
        }
    }

    #[test]
    fn plain_batch_guard_rows_pass_through_slice_view() {
        // rows() 返回的切片必须与写入行数一致（write_records 直传契约）
        let mut g = PlainBatchGuard::with_capacity(4);
        assert_eq!(g.rows().len(), 0);
        g.push((1, 2, "a".to_string(), vec![1u8]));
        g.push((2, 3, "b".to_string(), vec![2u8, 3u8]));
        assert_eq!(g.rows().len(), 2);
        assert_eq!(g.rows()[1].0, 2);
        assert_eq!(g.rows()[1].3.len(), 2);
    }

    /* ------------------------------------------------------------------ *
     * 产品入口只接受 magic                                           *
     * ------------------------------------------------------------------ */

    fn write_magic_file(case: &str, magic: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "verthys_worker_magic_{}_{}_{}.bin",
            std::process::id(),
            case,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, magic).expect("写 magic 样本失败");
        path
    }

    #[test]
    fn check_magic_rejects_foreign_format() {
        let path = write_magic_file("foreign", &[0x46, 0x4D, 0x54, 0x58]);
        let rc = check_container_magic(path.to_str().unwrap()).expect_err("异种格式必须被拒绝");
        assert_eq!(rc, 0x00000005, "异种格式应返回 FORMAT");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_magic_accepts_vrty() {
        let path = write_magic_file("vrty", &[0x56, 0x52, 0x54, 0x59]);
        check_container_magic(path.to_str().unwrap()).expect("容器应通过 magic 白名单");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_magic_rejects_truncated_header() {
        let path = write_magic_file("short", &[0x56, 0x52]);
        let rc = check_container_magic(path.to_str().unwrap()).expect_err("截断头必须被拒绝");
        assert_eq!(rc, 0x00000005, "截断头应返回 FORMAT");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_magic_missing_file_is_io() {
        let path = std::env::temp_dir().join(format!(
            "verthys_worker_magic_missing_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let rc = check_container_magic(path.to_str().unwrap()).expect_err("不存在文件必须失败");
        assert_eq!(rc, 0x00000008, "读取失败应返回 IO");
    }
}
