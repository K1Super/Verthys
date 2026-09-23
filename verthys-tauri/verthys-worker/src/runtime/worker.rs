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

use libloading::{Library, Symbol};
use std::os::raw::c_char;

use crate::log::{diag, init_diag};
use crate::runtime::ffi_types::*;
use crate::runtime::format_os_error;
#[cfg(windows)]
use crate::runtime::scan_shm;
use crate::runtime::progress_cb::unlock_progress_cb;
use crate::runtime::protocol::SecurityStatusReport;
use crate::runtime::gmk::GMK;

/* ------------------------------------------------------------------ *
 * 扫描临时缓冲 RAII 守卫（Windows）                                    *
 *                                                                    *
 * 原实现：写入共享内存成功后手工循环三轮覆写临时缓冲；                  *
 * 写入失败（? 提前返回）时擦除循环被整体跳过，明文残留。               *
 *                                                                    *
 * 守卫化：Drop 时统一三轮覆写（0x00 → 0xFF → 0x00），                  *
 * 任何提前返回路径（含 ? 传播/panic）均被覆盖。                        *
 * ------------------------------------------------------------------ */

/// 三轮覆写擦除（len=0 时为空操作，避免对空缓冲取悬垂指针）
#[cfg(windows)]
fn overwrite_3rounds(p: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        std::ptr::write_bytes(p, 0x00, len);
        std::ptr::write_bytes(p, 0xFF, len);
        std::ptr::write_bytes(p, 0x00, len);
    }
}

/// 全量扫描临时缓冲守卫：(lid, rtype, name, data)
#[cfg(windows)]
struct PlainBatchGuard {
    rows: Vec<(u64, u32, String, Vec<u8>)>,
}

#[cfg(windows)]
impl PlainBatchGuard {
    fn with_capacity(n: usize) -> Self {
        Self { rows: Vec::with_capacity(n) }
    }

    fn push(&mut self, row: (u64, u32, String, Vec<u8>)) {
        self.rows.push(row);
    }

    /// 只读访问行数据（直传 write_records 的切片签名）
    fn rows(&self) -> &[(u64, u32, String, Vec<u8>)] {
        &self.rows
    }

    /// 立即擦除全部明文行（幂等：覆写后再次调用无害）
    fn scrub(&mut self) {
        for (_, _, name, data) in self.rows.iter_mut() {
            overwrite_3rounds(name.as_mut_ptr(), name.len());
            overwrite_3rounds(data.as_mut_ptr(), data.len());
        }
    }
}

#[cfg(windows)]
impl Drop for PlainBatchGuard {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// 摘要扫描临时缓冲守卫：(lid, rtype, name, data_size, physical_offset, merkle_leaf, created_time)
#[cfg(windows)]
struct SummaryBatchGuard {
    rows: Vec<scan_shm::SummaryRecord>,
}

#[cfg(windows)]
impl SummaryBatchGuard {
    fn with_capacity(n: usize) -> Self {
        Self { rows: Vec::with_capacity(n) }
    }

    fn push(&mut self, row: scan_shm::SummaryRecord) {
        self.rows.push(row);
    }

    fn rows(&self) -> &[scan_shm::SummaryRecord] {
        &self.rows
    }

    /// 立即擦除全部摘要行（name 明文 + merkle_leaf 哈希）
    fn scrub(&mut self) {
        for (_, _, name, _, _, merkle, _) in self.rows.iter_mut() {
            overwrite_3rounds(name.as_mut_ptr(), name.len());
            overwrite_3rounds(merkle.as_mut_ptr(), merkle.len());
        }
    }
}

#[cfg(windows)]
impl Drop for SummaryBatchGuard {
    fn drop(&mut self) {
        self.scrub();
    }
}

/* ------------------------------------------------------------------ *
 * Worker：持有 DLL + 句柄                                             *
 * ------------------------------------------------------------------ */

/// 批量枚举单批条数硬上限
///
/// 游标批量扫描（全量/摘要）按 max_count 预分配记录数组与 lid 数组，
/// 前端可控的 id 字段直达此处；无上限时超大 id 直接触发巨大分配。
/// 上限值按单批内存预算选取（5000 × 全量记录结构 ≈ 数百 KB 级），
/// 与本进程单请求内存宽度匹配。调用点须始终经 clamp_enum_count，
/// 超限请求被静默截断（截断语义对游标无害：后续批次继续拉取）。
pub(crate) const MAX_ENUM_COUNT: u64 = 5000;

/// 将外部可控的批量条数限制到硬上限以内
pub(crate) fn clamp_enum_count(v: u64) -> u64 {
    v.min(MAX_ENUM_COUNT)
}

/// 统一 FFI 调用收口：所有对 C 导出函数的调用必须经此函数
///
/// Rust panic 展开穿过 extern "C" 边界属于未定义行为。
/// catch_unwind 捕获 panic 后：置位进程级标记（主循环检测后安全退出）
/// 并返回 Err，调用方转换为 0xFFFFFFFF 失败码——panic 绝不展开进 C。
pub(crate) fn ffi_call<R, F: FnOnce() -> R>(invoke: F) -> Result<R, ()> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(invoke)) {
        Ok(v) => Ok(v),
        Err(_) => {
            crate::log::mark_panic_flag();
            init_diag!("[worker] FFI 调用捕获到 panic（已阻断跨边界展开，返回失败码）");
            Err(())
        }
    }
}

pub(crate) struct Worker {
    _lib: Library,
    handle: VerthysHandle,
    /// 游标批量扫描状态
    scan_cursor: Option<VerthysScanCursorPtr>,
    /// 共享内存传输段（游标扫描专用）
    #[cfg(windows)]
    scan_shm: Option<scan_shm::ScanShm>,
}

impl Worker {
    pub(crate) fn new(dll_path: &str) -> Result<Self, String> {
        init_diag!("[worker] 开始加载 DLL: {}", dll_path);
        /*
         * Windows 加密 Worker 最终完整版安全设计 — 进程无菌沙盒
         *
         * 必须在加载 verthys.dll 之前应用进程级 mitigation policy：
         *   1. WIN32K_SYSTEM_CALL_DISABLE：免疫所有窗口注入
         *   2. PROCESS_CREATION_DISABLED：绝杀进程镂空、子进程注入
         *   3. IMAGE_LOAD_PREFER_SYSTEM32：防本地 DLL 劫持
         *   4. IMAGE_LOAD_NO_REMOTE：防反射注入、内存 PE 加载
         *
         * 这些 mitigation policy 是进程级策略，一旦应用不可撤销。
         * 必须在加载任何业务 DLL 之前完成沙盒包装，否则后续 DLL 加载行为
         * 可能已被攻击者篡改（如本地目录 DLL 劫持）。
         *
         * 失败降级：旧版 Windows 不支持某些 policy（Win10 1709+ 才有），
         * 失败不阻断启动，仅记录降级状态。实际状态由 verthys.dll 内的
         * defense_closure_check 在 BOOT 模式查询。
         */
        let sandbox_attrs = crate::defense::apply_process_sandbox();
        init_diag!("[worker] 进程级沙盒 mitigation 已应用: attrs=0x{:02X}", sandbox_attrs);

        unsafe {
            // 诊断：在加载 DLL 前先打印路径和文件存在性，便于排查
            let path_exists = std::path::Path::new(dll_path).exists();
            init_diag!("[worker] DLL 路径: {} | 文件存在: {}", dll_path, path_exists);

            let lib = Library::new(dll_path).map_err(|e| {
                // 使用 {:?} 输出 Debug 格式，包含底层 WindowsError(io::Error) 的原始错误码
                // 这是诊断 "LoadLibraryExW failed" 但 Display 不显示错误码的关键手段
                init_diag!("[worker] DLL 加载失败 (Display): {}", e);
                init_diag!("[worker] DLL 加载失败 (Debug): {:?}", e);

                // 进一步通过 FFI 获取 GetLastError，覆盖 libloading 内部已被其他调用清空的情况
                let last_err = crate::runtime::ffi_get_last_error();
                init_diag!("[worker] DLL 加载失败 GetLastError={:08X} (0x{} = {})",
                    last_err, last_err, format_os_error(last_err));

                format!("load dll: {}", e)
            })?;
            init_diag!("[worker] DLL 加载成功，获取 Verthys_Init 符号");

            /*
             * 在调用 Verthys_Init 之前，先通知 DLL 当前 Worker 进程已应用的
             * 沙盒属性位掩码。Verthys_Init 内部的 defense_closure_check(BOOT)
             * 会通过 process_sandbox_get_active_attrs() 查询此状态，
             * 据此判断 DLL_HIJACK 攻击路径是否已阻断。
             */
            let notify_sandbox: Symbol<VerthysNotifySandboxAttrsFn> =
                lib.get(b"Verthys_NotifySandboxAttrs").map_err(|e| {
                    init_diag!("[worker] 获取 Verthys_NotifySandboxAttrs 符号失败: {}", e);
                    format!("get Verthys_NotifySandboxAttrs: {}", e)
                })?;
            let notify_r = ffi_call(|| { notify_sandbox(sandbox_attrs) }).unwrap_or(0xFFFFFFFF);
            if notify_r != VERTHYS_OK {
                init_diag!("[worker] Verthys_NotifySandboxAttrs 失败: code={:08X}", notify_r);
                return Err(format!("Verthys_NotifySandboxAttrs failed: {:08X}", notify_r));
            }
            init_diag!("[worker] 已通知 DLL 沙盒属性: 0x{:02X}", sandbox_attrs);

            let init: Symbol<VerthysInitFn> =
                lib.get(b"Verthys_Init").map_err(|e| {
                    init_diag!("[worker] 获取 Verthys_Init 符号失败: {}", e);
                    format!("get Verthys_Init: {}", e)
                })?;
            let mut handle: VerthysHandle = std::ptr::null_mut();
            init_diag!("[worker] 调用 Verthys_Init（含 anti_debug_check + 六层动态防护初始化）");
            let r = ffi_call(|| { init(&mut handle) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK || handle.is_null() {
                init_diag!("[worker] Verthys_Init 失败: code={:08X}, handle_null={}", r, handle.is_null());
                return Err(format!("Verthys_Init failed: {:08X}", r));
            }
            init_diag!("[worker] Verthys_Init 成功（六层动态防护已就绪），进入主循环");
            Ok(Worker { _lib: lib, handle, scan_cursor: None, #[cfg(windows)] scan_shm: None })
        }
    }

    pub(crate) fn call_unlock(&self, path: &str, password: &str, flags: u32) -> u32 {
        unsafe {
            let lib = &self._lib;

            /* 在 Verthys_Unlock 之前注册进度回调
             *
             * unlock_progress_cb 在 C DLL 各阶段被同步调用，向 stdout 写入
             * {"ok":true,"op":"unlock_progress",...} 进度行。父进程
             * send_json_with_unlock_progress 识别进度行并转发前端。
             *
             * 兼容性：若 DLL 未导出 Verthys_RegisterUnlockProgressCallback（旧 DLL），
             * 静默跳过注册，解锁仍正常执行（仅无进度反馈）。 */
            if let Ok(register_fn) = lib.get::<VerthysRegisterUnlockProgressFn>(
                b"Verthys_RegisterUnlockProgressCallback\0",
            ) {
                let _ = ffi_call(|| {
                    register_fn(
                        self.handle,
                        Some(unlock_progress_cb),
                        std::ptr::null_mut(),
                    )
                });
            }

            let func: Symbol<VerthysUnlockFn> = match lib.get(b"Verthys_Unlock") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return 0xFFFFFFFF,
            };
            let pw_bytes = password.as_bytes();
            /* 透传 flags 参数（预热状态位域）给 C 层 Verthys_Unlock */
            ffi_call(|| {
                func(
                    self.handle,
                    path_c.as_ptr(),
                    pw_bytes.as_ptr() as *const c_char,
                    pw_bytes.len(),
                    flags,
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    /// 显式创建新 verthys（V3，可选预设）
    /// preset: 0=BALANCED, 1=SECURE
    pub(crate) fn call_create_with_preset(&self, path: &str, password: &str, preset: u32) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysCreateWithPresetFn> =
                match lib.get(b"Verthys_CreateWithPreset") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            let path_c = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => {
                    // 嵌入 NUL 的路径：日志只记字节长度，不回显原始内容（防日志注入）
                    diag!("[worker] create_with_preset: 路径含内嵌 NUL，length={}", path.len());
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
                    preset,
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

    /// 运行时切换安全预设档位（0=BALANCED / 1=SECURE / 2=PERFORMANCE）
    ///
    /// 双缓冲原子发布，切换立即生效；重复切到当前档为幂等 no-op。
    /// 失败回退：DLL 导出缺失（旧版核心）返回 0xFFFFFFFF，由上层可见报告。
    pub(crate) fn call_switch_security_preset(&self, preset: u32) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysSwitchSecurityPresetFn> =
                match lib.get(b"Verthys_SwitchSecurityPreset") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| { func(self.handle, preset) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 修复：调用 Verthys_Flush 显式刷盘
    ///
    /// 替代旧 verthys_flush 的 lock+unlock 模式（有 worker 卡在 LOCKED 状态的风险）。
    /// Verthys_Flush 语义（V3-only）：
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

    pub(crate) fn call_add_record(&self, rtype: u32, name: &str, data: &[u8]) -> Result<u64, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysAddRecordFn> = match lib.get(b"Verthys_AddRecord") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let name_c = match std::ffi::CString::new(name) {
                Ok(c) => c,
                Err(_) => {
                    // 嵌入 NUL 的记录名：日志只记字节长度，不回显原始内容（防日志注入）
                    diag!("[worker] add_record: 名称含内嵌 NUL，length={}", name.len());
                    return Err(0xFFFFFFFF);
                }
            };
            let rec = VerthysRecordC {
                rtype,
                name: name_c.as_ptr(),
                name_len: name.len(),
                data: data.as_ptr(),
                data_len: data.len(),
            };
            let mut id: u64 = 0;
            let r = ffi_call(|| { func(self.handle, &rec, &mut id) }).unwrap_or(0xFFFFFFFF);
            if r == VERTHYS_OK {
                Ok(id)
            } else {
                Err(r)
            }
        }
    }

    pub(crate) fn call_get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetRecordFn> = match lib.get(b"Verthys_GetRecord") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let mut rec = VerthysRecordC {
                rtype: 0,
                name: std::ptr::null(),
                name_len: 0,
                data: std::ptr::null(),
                data_len: 0,
            };
            let r = ffi_call(|| { func(self.handle, id, &mut rec) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                return Err(r);
            }
            // 借用指针：立即拷贝数据（下次调用或 Lock 前有效）
            let name = if !rec.name.is_null() && rec.name_len > 0 {
                let slice = std::slice::from_raw_parts(rec.name as *const u8, rec.name_len);
                String::from_utf8_lossy(slice).into_owned()
            } else {
                String::new()
            };
            let data = if !rec.data.is_null() && rec.data_len > 0 {
                let slice = std::slice::from_raw_parts(rec.data, rec.data_len);
                slice.to_vec()
            } else {
                Vec::new()
            };
            Ok((rec.rtype, name, data))
        }
    }

    /* ----------------------------------------------------------------
     * 游标批量扫描（共享内存零拷贝传输）
     * ---------------------------------------------------------------- */

    /// 打开扫描游标 + 创建共享内存 + 首批预加载
    /// 返回 (shm_name, shm_size, record_count, exhausted)
    #[cfg(windows)]
    pub(crate) fn call_scan_open(&mut self, start_lid: u64, batch_size: u64)
        -> Result<(String, usize, usize, bool), u32>
    {
        // 1. 创建共享内存段（VirtualLock + 随机名称）
        let shm = scan_shm::ScanShm::create(scan_shm::SHM_DEFAULT_SIZE)
            .map_err(|_| 0xFFFFFFFFu32)?;
        let shm_name = shm.name().to_string();
        let shm_size = shm.size();

        // 2. 打开 C 游标（复用 vbtree_scan_all，绑定瞬时只读快照）
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanOpenFn> = match lib.get(b"Verthys_ScanOpen") {
                Ok(f) => f,
                Err(_) => { shm.destroy(); return Err(0xFFFFFFFF); }
            };
            let mut cursor: VerthysScanCursorPtr = std::ptr::null_mut();
            // 传 C 前同样 clamp：batch_size 进入游标状态，保持与预分配上限一致
            let r = ffi_call(|| { func(self.handle, start_lid, clamp_enum_count(batch_size), &mut cursor) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                shm.destroy();
                return Err(r);
            }
            self.scan_cursor = Some(cursor);
        }

        // 3. 销毁旧共享内存段（如有），存入新段
        if let Some(old) = self.scan_shm.take() {
            old.destroy();
        }
        self.scan_shm = Some(shm);

        // 4. 首批预加载：驱动遍历器填充共享内存
        let (count, exhausted) = self.fetch_into_shm(batch_size)?;
        Ok((shm_name, shm_size, count, exhausted))
    }

    /// 批量拉取记录写入共享内存
    /// 返回 (record_count, exhausted)
    #[cfg(windows)]
    pub(crate) fn call_scan_fetch(&mut self, max_count: u64) -> Result<(usize, bool), u32> {
        self.fetch_into_shm(max_count)
    }

    /// 内部：调用 C Verthys_ScanFetch → 拷贝到共享内存 → 释放 C 深拷贝 → 安全擦除临时缓冲
    /// 紧急熔断响应：ScanFetch 返回 VERTHYS_ERR_LOCKED 时立即吊销游标 + 销毁 SHM
    #[cfg(windows)]
    fn fetch_into_shm(&mut self, max_count: u64) -> Result<(usize, bool), u32> {
        const VERTHYS_ERR_LOCKED: u32 = 0x00000007;
        let cursor = match self.scan_cursor {
            Some(c) => c,
            None => return Err(0xFFFFFFFF),
        };
        let shm = match self.scan_shm.as_mut() {
            Some(s) => s,
            None => return Err(0xFFFFFFFF),
        };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanFetchFn> = match lib.get(b"Verthys_ScanFetch") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let free_fn: Symbol<VerthysScanRecordFreeFn> = match lib.get(b"Verthys_ScanRecordFree") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };

            // 上限截断后以同一值驱动预分配与 FFI：两者尺寸必须一致，
            // C 端按传入条数写入 out_count 条，缓冲过小即溢出
            let mc = clamp_enum_count(max_count) as usize;
            let mut records: Vec<VerthysRecordC> = (0..mc).map(|_| VerthysRecordC {
                rtype: 0, name: std::ptr::null(), name_len: 0,
                data: std::ptr::null(), data_len: 0,
            }).collect();
            let mut lids: Vec<u64> = vec![0u64; mc];
            let mut out_count: u64 = 0;
            /* 根治：传递 out_failed_lids=NULL, out_failed_count=NULL
             *   与 C 端 Verthys_ScanFetch 7 参数签名严格对齐（verthys.h:574-580）
             *   原缺陷：FFI 仅传 5 参数，C 从栈读取垃圾值作为 out_failed_count，
             *   执行 *out_failed_count=0 向垃圾地址写入 → 0xC0000005 崩溃 */
            let r = ffi_call(|| { func(cursor, records.as_mut_ptr(), lids.as_mut_ptr(), mc as u64, &mut out_count, std::ptr::null_mut(), std::ptr::null_mut()) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                // 紧急熔断吊销：ScanFetch 返回 LOCKED 表示 emergency_is_triggered
                // 或游标已被标记 invalidated，立即销毁 SHM 缓冲区 + 关闭游标
                if r == VERTHYS_ERR_LOCKED {
                    self.revoke_scan_cursor();
                }
                return Err(r);
            }

            // 从 C 深拷贝收集到守卫化临时缓冲（Drop 三轮覆写，含写 SHM 失败的提前返回路径）
            let mut result = PlainBatchGuard::with_capacity(out_count as usize);
            for i in 0..out_count as usize {
                let rec = &records[i];
                let name = if !rec.name.is_null() && rec.name_len > 0 {
                    let slice = std::slice::from_raw_parts(rec.name as *const u8, rec.name_len);
                    String::from_utf8_lossy(slice).into_owned()
                } else { String::new() };
                let data = if !rec.data.is_null() && rec.data_len > 0 {
                    let slice = std::slice::from_raw_parts(rec.data, rec.data_len);
                    slice.to_vec()
                } else { Vec::new() };
                result.push((lids[i], rec.rtype, name, data));

                // 释放 C 深拷贝（含安全擦除）
                let _ = ffi_call(|| { free_fn(&mut records[i] as *mut VerthysRecordC) }).unwrap_or(0xFFFFFFFF);
            }

            let exhausted = out_count == 0;

            // 写入共享内存（内部先 3 轮擦除旧数据）
            // 失败时 ? 提前返回 → 守卫 Drop 仍三轮覆写全部明文行
            let count = shm.write_records(result.rows(), exhausted).map_err(|_| 0xFFFFFFFFu32)?;

            // 成功路径由守卫 Drop 在函数返回时统一擦除
            Ok((count, exhausted))
        }
    }

    /// 紧急熔断吊销：擦除存储进程侧 SHM 缓冲区 + 关闭游标 + 标记句柄无效
    /// 安全模块通知存储进程立即吊销所有活跃游标，
    /// 吊销动作包括擦除缓冲区、关闭游标、标记句柄无效
    #[cfg(windows)]
    fn revoke_scan_cursor(&mut self) {
        // 1. 销毁共享内存缓冲区（随机字节覆写 → 解锁 → 取消映射 → 关闭句柄）
        if let Some(shm) = self.scan_shm.take() {
            shm.destroy();
        }
        // 2. 关闭 C 游标（注销 memory_guard → 解锁 → 安全擦除 → 释放）
        if let Some(cursor) = self.scan_cursor.take() {
            unsafe {
                let lib = &self._lib;
                if let Ok(func) = lib.get(b"Verthys_ScanClose") {
                    let func: Symbol<VerthysScanCloseFn> = func;
                    let _ = ffi_call(|| { func(cursor) });
                }
            }
        }
    }

    /// 关闭扫描游标 + 销毁共享内存
    #[cfg(windows)]
    pub(crate) fn call_scan_close(&mut self) -> u32 {
        // 销毁共享内存（擦除 → 解锁 → 取消映射 → 关闭句柄）
        if let Some(shm) = self.scan_shm.take() {
            shm.destroy();
        }
        // 关闭 C 游标（注销 memory_guard → 解锁 → 擦除 → 释放）
        let cursor = match self.scan_cursor.take() {
            Some(c) => c,
            None => return 0,
        };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanCloseFn> = match lib.get(b"Verthys_ScanClose") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(cursor) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /* 非 Windows 平台：游标扫描不支持，返回错误 */
    #[cfg(not(windows))]
    pub(crate) fn call_scan_open(&mut self, _start_lid: u64, _batch_size: u64)
        -> Result<(String, usize, usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_fetch(&mut self, _max_count: u64) -> Result<(usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_close(&mut self) -> u32 { 0xFFFFFFFF }

    /* ================================================================ *
     * 摘要扫描（轻量元数据，不读数据块）                       *
     *                                                                  *
     * 与全量扫描的区别：                                                *
     *   - 复用 VerthysScanCursor 游标结构（Open 逻辑相同）               *
     *   - Fetch 调用 Verthys_ScanSummaryFetch，仅提取索引元数据           *
     *   - SHM 写入 write_summary_records（72B 条目，无数据块）          *
     *   - Close 复用 call_scan_close（Verthys_ScanClose 不区分摘要/全量） *
     * ================================================================ */

    /// 打开摘要扫描游标 + 创建共享内存 + 首批预加载
    /// 返回 (shm_name, shm_size, record_count, exhausted)
    ///
    /// 摘要扫描使用更小的 SHM（4MB），因为元数据体积极小。
    /// 游标复用 self.scan_cursor 字段（与全量扫描互斥，不会并发）。
    #[cfg(windows)]
    pub(crate) fn call_scan_summary_open(&mut self, start_lid: u64, batch_size: u64)
        -> Result<(String, usize, usize, bool), u32>
    {
        // 1. 创建摘要专用共享内存段（4MB，VirtualLock + 随机名称）
        let shm = scan_shm::ScanShm::create(scan_shm::SHM_SUMMARY_DEFAULT_SIZE)
            .map_err(|_| 0xFFFFFFFFu32)?;
        let shm_name = shm.name().to_string();
        let shm_size = shm.size();

        // 2. 打开 C 摘要扫描游标（Verthys_ScanSummaryOpen，复用 VerthysScanCursor 结构）
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanSummaryOpenFn> = match lib.get(b"Verthys_ScanSummaryOpen") {
                Ok(f) => f,
                Err(_) => { shm.destroy(); return Err(0xFFFFFFFF); }
            };
            let mut cursor: VerthysScanCursorPtr = std::ptr::null_mut();
            // 传 C 前同样 clamp：与全量扫描同纪律
            let r = ffi_call(|| { func(self.handle, start_lid, clamp_enum_count(batch_size), &mut cursor) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                shm.destroy();
                return Err(r);
            }
            self.scan_cursor = Some(cursor);
        }

        // 3. 销毁旧共享内存段（如有），存入新段
        if let Some(old) = self.scan_shm.take() {
            old.destroy();
        }
        self.scan_shm = Some(shm);

        // 4. 首批预加载：驱动摘要遍历器填充共享内存
        let (count, exhausted) = self.fetch_summary_into_shm(batch_size)?;
        Ok((shm_name, shm_size, count, exhausted))
    }

    /// 批量拉取摘要记录写入共享内存
    /// 返回 (record_count, exhausted)
    #[cfg(windows)]
    pub(crate) fn call_scan_summary_fetch(&mut self, max_count: u64) -> Result<(usize, bool), u32> {
        self.fetch_summary_into_shm(max_count)
    }

    /// 内部：调用 C Verthys_ScanSummaryFetch → 拷贝到共享内存 → 释放 C 深拷贝 → 安全擦除临时缓冲
    /// 紧急熔断响应：ScanSummaryFetch 返回 VERTHYS_ERR_LOCKED 时立即吊销游标 + 销毁 SHM
    #[cfg(windows)]
    fn fetch_summary_into_shm(&mut self, max_count: u64) -> Result<(usize, bool), u32> {
        const VERTHYS_ERR_LOCKED: u32 = 0x00000007;
        let cursor = match self.scan_cursor {
            Some(c) => c,
            None => return Err(0xFFFFFFFF),
        };
        let shm = match self.scan_shm.as_mut() {
            Some(s) => s,
            None => return Err(0xFFFFFFFF),
        };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanSummaryFetchFn> = match lib.get(b"Verthys_ScanSummaryFetch") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let free_fn: Symbol<VerthysScanSummaryRecordFreeFn> =
                match lib.get(b"Verthys_ScanSummaryRecordFree") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };

            // 上限截断后以同一值驱动预分配与 FFI（与全量扫描同纪律）
            let mc = clamp_enum_count(max_count) as usize;
            let mut records: Vec<VerthysSummaryRecordC> = (0..mc).map(|_| VerthysSummaryRecordC {
                lid: 0,
                rtype: 0,
                name_len: 0,
                name: std::ptr::null(),
                data_size: 0,
                physical_offset: 0,
                merkle_leaf: [0u8; 32],
                created_time: 0,
                slot_state: 0,    /* 根治：与 C 端对齐 */
            }).collect();
            let mut lids: Vec<u64> = vec![0u64; mc];
            let mut out_count: u64 = 0;

            let r = ffi_call(|| { func(cursor, records.as_mut_ptr(), lids.as_mut_ptr(), mc as u64, &mut out_count) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                // 紧急熔断吊销：ScanSummaryFetch 返回 LOCKED 表示 emergency_is_triggered
                // 或游标已被标记 invalidated，立即销毁 SHM 缓冲区 + 关闭游标
                if r == VERTHYS_ERR_LOCKED {
                    self.revoke_scan_cursor();
                }
                return Err(r);
            }

            // 从 C 深拷贝收集到守卫化临时缓冲（摘要元组：无数据块，含 created_time 字段）
            // Drop 三轮覆写（name 明文 + merkle_leaf 哈希），含写 SHM 失败的提前返回路径
            let mut result = SummaryBatchGuard::with_capacity(out_count as usize);
            for rec in records.iter_mut().take(out_count as usize) {
                let name = if !rec.name.is_null() && rec.name_len > 0 {
                    let slice = std::slice::from_raw_parts(rec.name, rec.name_len as usize);
                    String::from_utf8_lossy(slice).into_owned()
                } else {
                    String::new()
                };
                result.push((
                    rec.lid,
                    rec.rtype,
                    name,
                    rec.data_size,
                    rec.physical_offset,
                    rec.merkle_leaf,
                    rec.created_time,
                ));

                // 释放 C 深拷贝（name 被安全擦除并释放，merkle_leaf 擦除）
                let _ = ffi_call(|| { free_fn(rec as *mut VerthysSummaryRecordC) }).unwrap_or(0xFFFFFFFF);
            }

            let exhausted = out_count == 0;

            // 写入共享内存（内部先随机覆写旧数据）
            // 失败时 ? 提前返回 → 守卫 Drop 仍三轮覆写全部摘要行
            let count = shm.write_summary_records(result.rows(), exhausted).map_err(|_| 0xFFFFFFFFu32)?;

            // 成功路径由守卫 Drop 在函数返回时统一擦除
            Ok((count, exhausted))
        }
    }

    /* 非 Windows 平台：摘要扫描不支持，返回错误 */
    #[cfg(not(windows))]
    pub(crate) fn call_scan_summary_open(&mut self, _start_lid: u64, _batch_size: u64)
        -> Result<(String, usize, usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_summary_fetch(&mut self, _max_count: u64) -> Result<(usize, bool), u32> { Err(0xFFFFFFFF) }

    pub(crate) fn call_delete_record(&self, id: u64) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysDeleteRecordFn> = match lib.get(b"Verthys_DeleteRecord") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle, id) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 批量删除记录（单次事务，合并为单次 flush）
    /// C 层在单事务内逐条删除，最后一次收口（一次 PREPARE → COMMIT → CONFIRM），
    /// 磁盘写入量与条目数解耦；任一 ID 不存在则整体回滚为 NOTFOUND。
    pub(crate) fn call_delete_records(&self, ids: &[u64]) -> u32 {
        if ids.is_empty() {
            return 0; /* VERTHYS_OK */
        }
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysDeleteRecordsFn> = match lib.get(b"Verthys_DeleteRecords") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle, ids.as_ptr(), ids.len()) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 获取已加载的轻量摘要记录数
    /// 返回解锁时从 summary_index_off 加载的摘要记录数（0=无摘要索引）
    pub(crate) fn call_get_summary_count(&self) -> (u32, u64) {
        let mut count: u64 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetSummaryCountFn> = match lib.get(b"Verthys_GetSummaryCount") {
                Ok(f) => f,
                Err(_) => return (0xFFFFFFFF, 0),
            };
            let rc = ffi_call(|| { func(self.handle, &mut count as *mut u64) }).unwrap_or(0xFFFFFFFF);
            (rc, count)
        }
    }

    /// ：轻量级记录类型存在性检查
    /// 仅遍历 B+ 树索引节点检查 type 字段，不读数据块，典型 < 100ms
    /// 返回 (rc, found)：rc=0 成功（found=0/1），rc!=0 失败
    pub(crate) fn call_has_record_by_type(&self, rtype: u8) -> (u32, bool) {
        let mut found: u8 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysHasRecordByTypeFn> = match lib.get(b"Verthys_HasRecordByType") {
                Ok(f) => f,
                Err(_) => return (0xFFFFFFFF, false),
            };
            let rc = ffi_call(|| { func(self.handle, rtype, &mut found as *mut u8) }).unwrap_or(0xFFFFFFFF);
            (rc, found != 0)
        }
    }

    /// 进程内查找指定类型的首条记录 lid
    /// 返回 (rc, found, lid)：rc=0 成功（found=0/1），rc!=0 失败
    /// 与 call_has_record_by_type 的关键差异：
    ///   1. 同时返回 lid，省去二次 find_lid IPC 往返
    ///   2. V3-only：fmt!=V3 时 C 层返回 FORMAT（无旧格式兼容分支）
    pub(crate) fn call_find_first_lid_by_type(&self, rtype: u8) -> (u32, bool, u64) {
        let mut found: u8 = 0;
        let mut lid: u64 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysFindFirstLidByTypeFn> =
                match lib.get(b"Verthys_FindFirstLidByType") {
                    Ok(f) => f,
                    Err(_) => return (0xFFFFFFFF, false, 0),
                };
            let rc = ffi_call(|| { func(self.handle, rtype, &mut found as *mut u8, &mut lid as *mut u64) }).unwrap_or(0xFFFFFFFF);
            (rc, found != 0, lid)
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
     * 动态防护 7 路径状态实时查询               *
     *                                                                *
     * FFI 调用 Verthys_GetSecurityStatus（RUNTIME 级实时复检，非 BOOT     *
     * 缓存快照）。防御状态为进程级事实：worker 启动即持有 handle，      *
     * 锁定态/未挂载态均可查询（verthys.h 行为契约）。                  *
     * ================================================================ */

    /// 查询动态防护状态。Err(错误码)：INVALID（参数异常）/ INTERNAL（复检管线异常）
    pub(crate) fn call_security_status(&self) -> Result<SecurityStatusReport, u32> {
        /* C 契约：reserved 必须置零传递（zeroed 全量置零，满足契约） */
        let mut st: VerthysSecurityStatusC = unsafe { std::mem::zeroed() };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetSecurityStatusFn> =
                match lib.get(b"Verthys_GetSecurityStatus") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| { func(self.handle, &mut st as *mut VerthysSecurityStatusC) }).unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
        }
        Ok(SecurityStatusReport {
            path_state: st.path_state,
            blocked_count: st.blocked_count,
            degraded_count: st.degraded_count,
            failed_count: st.failed_count,
            all_critical_blocked: st.all_critical_blocked != 0,
            has_degraded: st.has_degraded != 0,
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
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
}
