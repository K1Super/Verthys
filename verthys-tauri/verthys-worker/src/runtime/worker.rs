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
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::io::Read;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use zeroize::Zeroize;

use crate::log::{diag, init_diag};
use crate::runtime::ffi_types::*;
use crate::runtime::format_os_error;
use crate::runtime::progress_cb::vty_rotate_progress_cb;
#[cfg(windows)]
use crate::runtime::scan_shm;
use crate::runtime::protocol::SecurityStatusReport;

#[cfg(windows)]
extern "system" {
    /// 仅用于父进程注入的匿名事件脉冲；句柄值来自签名 IPC 下发。
    fn SetEvent(h_event: *mut std::ffi::c_void) -> i32;
}
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

/* ------------------------------------------------------------------ *
 * 轮换取消命名事件（Windows）                                         *
 *                                                                    *
 * 父进程（Tauri 主进程）创建命名事件，Run 请求只携带事件名；worker   *
 * 打开事件并在进度回调中节流检查。事件为 auto-reset：一次置位只被    *
 * 消费一次，不会影响后续轮换。                                       *
 * ------------------------------------------------------------------ */

#[cfg(windows)]
fn open_rotate_cancel_event(name: &str) -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::System::Threading::OpenEventW;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0u16)).collect();
    let handle = unsafe { OpenEventW(SYNCHRONIZE, 0, wide.as_ptr()) };
    if handle.is_null() { None } else { Some(handle) }
}

#[cfg(windows)]
fn rotate_cancel_signaled(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    unsafe { WaitForSingleObject(handle, 0) == 0 }
}

#[cfg(windows)]
fn close_rotate_cancel_event(handle: windows_sys::Win32::Foundation::HANDLE) {
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
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

/// 落盘自查结构化结果（Verthys_VerifyPersist 出参的 Rust 侧投影）
///
/// status_code 语义（对齐 C 端 VerPersistStatus）：
///   0=OK / 1=HEADER_INVALID / 2=SIZE_MISMATCH / 3=WAL_REGION
///   / 4=IO / 5=INTERNAL
pub(crate) struct VerifyPersistOutcome {
    pub(crate) status_code: i32,
    pub(crate) file_size: u64,
    pub(crate) mtime_ms: u64,
    pub(crate) header_magic: u32,
    pub(crate) header_version: u32,
    pub(crate) wal_offset: u64,
    pub(crate) last_error: String,
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
    /// 运行时守卫完整掩码（bit0=心跳运行 bit1=挂起守卫接线）。
    /// 心跳位由心跳线程启动后置位；挂起位由主进程经 runtime_guards op 下发。
    runtime_guards: AtomicU32,
    /// 旧 DLL 缺少 Verthys_NotifyRuntimeGuards 时只记录一次诊断，不阻断主循环。
    guards_symbol_warned: AtomicBool,
    /// 心跳线程停止标志与句柄（arm_heartbeat 成功后存在）。
    heartbeat_stop: Option<Arc<AtomicBool>>,
    heartbeat_thread: Option<JoinHandle<()>>,
}

// 构建期生成的 DLL 完整性基线（Release 必存在，Debug 允许占位）
include!(concat!(env!("OUT_DIR"), "/expected_dll_hash.rs"));

/// 常数时间比较两组 32 字节摘要。
///
/// 逐字节异或累加，不做提前返回，避免摘要比较环节泄露前导匹配长度。
fn digest_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for index in 0..32 {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

/// 摘要转十六进制文本（仅用于诊断日志）
fn digest_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// 在 `Library::new` 之前校验 DLL 的路径归属与全文件摘要。
///
/// 契约：
///   - Release：DLL 必须位于 worker 可执行文件所在目录内，且 SHA-256 与
///     构建期基线一致；任一条件不满足即拒绝加载，防止宿主传入路径被替换
///     后加载被篡改的模块。
///   - Debug：构建期无稳定基线，跳过哈希比对，仅记录摘要。
///
/// 返回值为规范化后的绝对路径，后续加载必须使用该路径，避免相对路径重解析。
/// 副作用：完整读取一次 DLL 字节；不回写、不修改文件。
fn verify_dll_integrity(dll_path: &str) -> Result<std::path::PathBuf, String> {
    let canonical_dll = std::fs::canonicalize(dll_path)
        .map_err(|e| format!("规范化 DLL 路径失败: {}", e))?;

    #[cfg(not(debug_assertions))]
    {
        let exe = std::env::current_exe().map_err(|e| format!("获取 worker 路径失败: {}", e))?;
        let exe_dir = exe
            .parent()
            .ok_or_else(|| "worker 路径缺少父目录".to_string())?;
        let canonical_dir = std::fs::canonicalize(exe_dir)
            .map_err(|e| format!("规范化 worker 目录失败: {}", e))?;
        // 未打包的 release 开发树（target/release）中 worker 与 DLL 分处不同目录，
        // 该布局不是部署形态；打包安装目录中两者必须同根。
        let dir_text = canonical_dir.display().to_string().to_lowercase();
        let is_dev_layout = dir_text.ends_with("\\target\\release");
        if !is_dev_layout && !canonical_dll.starts_with(&canonical_dir) {
            return Err(format!(
                "DLL 路径越界: {} 不在 {} 内",
                canonical_dll.display(),
                canonical_dir.display()
            ));
        }
    }

    let mut file = std::fs::File::open(&canonical_dll)
        .map_err(|e| format!("打开 DLL 失败: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("读取 DLL 失败: {}", e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut actual = [0u8; 32];
    actual.copy_from_slice(&hasher.finalize());

    if HAS_EXPECTED_DLL_HASH && !digest_equal(&actual, &EXPECTED_DLL_SHA256) {
        return Err(format!(
            "DLL 摘要不匹配: actual={} expected={}",
            digest_hex(&actual),
            digest_hex(&EXPECTED_DLL_SHA256)
        ));
    }
    init_diag!("[worker] DLL 完整性校验通过: {}", digest_hex(&actual));
    Ok(canonical_dll)
}

impl Worker {
    pub(crate) fn new(dll_path: &str) -> Result<Self, String> {
        init_diag!("[worker] 开始加载 DLL: {}", dll_path);
        /* 加载前先完成路径归属与全文件摘要校验：宿主传入的路径不可信，
         * 必须在任何符号解析之前拒绝越界路径与内容被替换的模块。 */
        let verified_dll = verify_dll_integrity(dll_path).map_err(|e| {
            init_diag!("[worker] DLL 完整性校验失败，拒绝加载: {}", e);
            e
        })?;

        /*
         * Windows 进程级沙盒
         *
         * 必须在加载 verthys.dll 之前应用进程级 mitigation policy：
         *   1. WIN32K_SYSTEM_CALL_DISABLE：阻断窗口站/桌面相关注入面
         *   2. PROCESS_CREATION_DISABLED：阻断子进程创建与镂空链
         *   3. IMAGE_LOAD_NO_REMOTE / NO_LOW_LABEL：阻断远程与低完整性镜像
         *   4. ACG：阻断运行期动态代码生成
         *   5. StrictHandle：阻断句柄引用违规
         *
         * System32-only DLL 搜索已由入口处的 apply_early_dll_policy 固定，
         * 此处失败必须失败关闭：降级启动会让后续所有加固建立在不可信基线上。
         */
        let sandbox_attrs = crate::defense::apply_process_sandbox().map_err(|e| {
            init_diag!("[worker] 进程级沙盒 mitigation 失败，拒绝加载 DLL: {}", e);
            e
        })?;
        init_diag!("[worker] 进程级沙盒 mitigation 已应用: attrs=0x{:02X}", sandbox_attrs);

        unsafe {
            // 诊断：在加载 DLL 前先打印路径和文件存在性，便于排查
            let path_exists = std::path::Path::new(dll_path).exists();
            init_diag!("[worker] DLL 路径: {} | 文件存在: {}", dll_path, path_exists);

            let lib = Library::new(&verified_dll).map_err(|e| {
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

            /* DLL 版本预检：布局敏感调用（Unlock/Scan 系列携带跨边界结构体）
             * 之前校准 DLL 接口版本。版本错位的旧 DLL 在此被显式拒绝，
             * 而不是在后续 FFI 结构体解析时以栈损坏形式崩溃。预检读取的是
             * VerthysContainerInfo 前 8 字节——该头部在任何容器状态均可读，
             * stateless 且无副作用。预检失败时进程随即退出，已初始化句柄
             * 由进程回收，无驻留窗口。 */
            const WORKER_KNOWN_API_VERSION: u32 = 0x0014;
            let get_info: Symbol<VerthysGetContainerInfoFn> =
                lib.get(b"Verthys_GetContainerInfo").map_err(|e| {
                    init_diag!("[worker] DLL 缺少 Verthys_GetContainerInfo 导出（版本过旧），拒绝加载: {}", e);
                    format!("get Verthys_GetContainerInfo: {}", e)
                })?;
            let mut probe = VerthysContainerInfoProbeC {
                api_version: 0,
                fmt_version: 0,
                preset: 0,
            };
            let probe_r = ffi_call(|| { get_info(handle, &mut probe) }).unwrap_or(0xFFFFFFFF);
            if probe_r != VERTHYS_OK {
                init_diag!("[worker] DLL 版本预检调用失败: code={:08X}", probe_r);
                return Err(format!("Verthys_GetContainerInfo failed: {:08X}", probe_r));
            }
            if probe.api_version > WORKER_KNOWN_API_VERSION {
                init_diag!(
                    "[worker] DLL 接口版本超前于 worker: dll_api={:04X}, worker={:04X}，拒绝加载",
                    probe.api_version,
                    WORKER_KNOWN_API_VERSION
                );
                return Err(format!(
                    "DLL API version {:04X} is newer than worker-known {:04X}",
                    probe.api_version, WORKER_KNOWN_API_VERSION
                ));
            }
            /* 容器格式版本由 C 层编译期能力上报（当前 4）；worker 不在加载期
             * 与固定字面量比较——避免把“单一格式”版本演进绑死在 worker 侧。 */
            init_diag!(
                "[worker] DLL 版本预检通过: api={:04X}, fmt={}",
                probe.api_version,
                probe.fmt_version
            );

            Ok(Worker {
                _lib: lib,
                handle,
                scan_cursor: None,
                #[cfg(windows)]
                scan_shm: None,
                runtime_guards: AtomicU32::new(0),
                guards_symbol_warned: AtomicBool::new(false),
                heartbeat_stop: None,
                heartbeat_thread: None,
            })
        }
    }

    /// 专用解锁入口：先做 magic 白名单，再调用容器解锁入口。
    /// C 层路径始终重新读取元数据。
    pub(crate) fn call_unlock(&self, path: &str, password: &str) -> u32 {
        if let Err(rc) = check_container_magic(path) {
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

    /// 查询活跃安全预设档位（快照读取）
    ///
    /// 返回 Ok(档位代号 0/1/2)；失败返回 Err(错误码/0xFFFFFFFF)，
    /// 由上层据此做切档回读校验（不一致即判定切换未生效）。
    pub(crate) fn call_get_security_preset(&self) -> Result<u32, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetSecurityPresetFn> =
                match lib.get(b"Verthys_GetSecurityPreset") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let mut preset: u32 = 0;
            let rc = ffi_call(|| { func(self.handle, &mut preset as *mut u32) })
                .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
            Ok(preset)
        }
    }

    /// 查询指定档位的特性位投影（跨层特性契约）
    ///
    /// 返回 Ok(特性位)；失败返回 Err(错误码/0xFFFFFFFF)。
    pub(crate) fn call_get_preset_feature_bits(&self, preset: u32) -> Result<u32, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetPresetFeatureBitsFn> =
                match lib.get(b"Verthys_GetPresetFeatureBits") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let mut bits: u32 = 0;
            let rc = ffi_call(|| { func(self.handle, preset, &mut bits as *mut u32) })
                .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
            Ok(bits)
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

    /// 批量新增记录（API 0x0013）：单次 C 层事务提交，返回与输入等长的 ID 列表。
    ///
    /// 调用方（dispatch）负责构造稳定的 CString 与数据缓冲，并保证切片内的
    /// 指针在调用期间有效；本方法只负责 FFI 调用与错误码转换。
    pub(crate) fn call_add_records(&self, records: &[VerthysRecordC]) -> Result<Vec<u64>, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysAddRecordsFn> = match lib.get(b"Verthys_AddRecords") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let mut ids = vec![0u64; records.len()];
            let r = ffi_call(|| {
                func(self.handle, records.as_ptr(), records.len() as u32, ids.as_mut_ptr())
            })
            .unwrap_or(0xFFFFFFFF);
            if r == VERTHYS_OK {
                Ok(ids)
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
            /* 借用指针已深拷贝到自有缓冲，立即清零 C 层缓存，
             * 缩短明文在 DLL 堆中的驻留窗口。旧 DLL 不导出该符号时
             * 保持原行为，由 next GetRecord/Lock 失效缓存。 */
            if let Ok(clear) = lib.get::<VerthysClearRecordCacheFn>(b"Verthys_ClearRecordCache") {
                let _ = ffi_call(|| { clear(self.handle) });
            }
            Ok((rec.rtype, name, data))
        }
    }

    /* ----------------------------------------------------------------
     * 游标批量扫描（共享内存零拷贝传输）
     * ---------------------------------------------------------------- */

    /// 打开扫描游标 + 创建共享内存 + 首批预加载
    /// 返回 (shm_name, shm_size, record_count, exhausted, failed_lids)
    ///
    /// project / index_inline_max_bytes 为投影参数（FULL=全部记录解密；
    /// INDEX=仅对不超过内联阈值的记录解密取数），取批预算恒取 SHM 水位线
    /// SCAN_BATCH_MAX_BYTES：单批载荷因此恒落在段容量内（取满即返回本批），
    /// 大记录数据集不再出现"单批超容 → 整批失败"。
    #[cfg(windows)]
    pub(crate) fn call_scan_open(&mut self, start_lid: u64, batch_size: u64,
                                 project: u32, index_inline_max_bytes: u64,
                                 auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool, Vec<u64>), u32>
    {
        // 1. 创建共享内存段（VirtualLock + 随机名称）
        let shm = scan_shm::ScanShm::create(scan_shm::SHM_DEFAULT_SIZE)
            .map_err(|_| 0xFFFFFFFFu32)?;
        let shm_name = shm.name().to_string();
        let shm_size = shm.size();

        // 2. 打开 C 游标（复用 vbtree_scan_all，绑定瞬时只读快照）
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanOpenExFn> = match lib.get(b"Verthys_ScanOpenEx") {
                Ok(f) => f,
                Err(_) => { shm.destroy(); return Err(0xFFFFFFFF); }
            };
            let mut cursor: VerthysScanCursorPtr = std::ptr::null_mut();
            // 传 C 前同样 clamp：batch_size 进入游标状态，保持与预分配上限一致
            let r = ffi_call(|| { func(self.handle, start_lid, clamp_enum_count(batch_size),
                                      project, index_inline_max_bytes,
                                      scan_shm::SCAN_BATCH_MAX_BYTES, &mut cursor) }).unwrap_or(0xFFFFFFFF);
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

        // 4. 首批预加载：驱动遍历器填充共享内存（同样携带 SHM 认证密钥）
        let (count, exhausted, failed_ids) = self.fetch_into_shm(batch_size, auth_key)?;
        Ok((shm_name, shm_size, count, exhausted, failed_ids))
    }

    /// 批量拉取记录写入共享内存
    /// 返回 (record_count, exhausted, failed_lids)
    #[cfg(windows)]
    pub(crate) fn call_scan_fetch(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool, Vec<u64>), u32> {
        self.fetch_into_shm(max_count, auth_key)
    }

    /// 内部：调用 C Verthys_ScanFetch → 拷贝到共享内存 → 释放 C 深拷贝 → 安全擦除临时缓冲
    /// 紧急熔断响应：ScanFetch 返回 VERTHYS_ERR_LOCKED 时立即吊销游标 + 销毁 SHM
    #[cfg(windows)]
    fn fetch_into_shm(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool, Vec<u64>), u32> {
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
            /* 失败条目清单：C 端按 lid 记账解密失败/索引不一致的条目
             * （不静默丢弃），此处必须传入真实缓冲——传 NULL 会让上层
             * 完全看不到损坏条目，把"损坏"误当"不存在"。
             * 缓冲按本批条数上限分配，超出部分 C 端不再写（计数仍报总数）。 */
            let mut failed_lids: Vec<u64> = vec![0u64; mc];
            let mut out_failed_count: u64 = 0;
            let r = ffi_call(|| { func(cursor, records.as_mut_ptr(), lids.as_mut_ptr(), mc as u64,
                                      &mut out_count, failed_lids.as_mut_ptr(),
                                      &mut out_failed_count) }).unwrap_or(0xFFFFFFFF);
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

            // 失败条目：仅取缓冲范围内已写入的 lid（计数可能大于缓冲容量）
            let failed: Vec<u64> = failed_lids
                .iter()
                .take((out_failed_count as usize).min(mc))
                .copied()
                .collect();

            let exhausted = out_count == 0;

            // 写入共享内存（内部先 3 轮擦除旧数据）
            // 失败时 ? 提前返回 → 守卫 Drop 仍三轮覆写全部明文行
            let count = shm.write_records(result.rows(), exhausted, auth_key).map_err(|_| 0xFFFFFFFFu32)?;

            // 成功路径由守卫 Drop 在函数返回时统一擦除
            Ok((count, exhausted, failed))
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
    pub(crate) fn call_scan_open(&mut self, _start_lid: u64, _batch_size: u64, _auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_fetch(&mut self, _max_count: u64, _auth_key: Option<&[u8]>) -> Result<(usize, bool), u32> { Err(0xFFFFFFFF) }
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
    pub(crate) fn call_scan_summary_open(&mut self, start_lid: u64, batch_size: u64,
                                         auth_key: Option<&[u8]>)
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

        // 4. 首批预加载：驱动摘要遍历器填充共享内存（同样携带 SHM 认证密钥）
        let (count, exhausted) = self.fetch_summary_into_shm(batch_size, auth_key)?;
        Ok((shm_name, shm_size, count, exhausted))
    }

    /// 批量拉取摘要记录写入共享内存
    /// 返回 (record_count, exhausted)
    #[cfg(windows)]
    pub(crate) fn call_scan_summary_fetch(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool), u32> {
        self.fetch_summary_into_shm(max_count, auth_key)
    }

    /// 内部：调用 C Verthys_ScanSummaryFetch → 拷贝到共享内存 → 释放 C 深拷贝 → 安全擦除临时缓冲
    /// 紧急熔断响应：ScanSummaryFetch 返回 VERTHYS_ERR_LOCKED 时立即吊销游标 + 销毁 SHM
    #[cfg(windows)]
    fn fetch_summary_into_shm(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool), u32> {
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
            let count = shm.write_summary_records(result.rows(), exhausted, auth_key).map_err(|_| 0xFFFFFFFFu32)?;

            // 成功路径由守卫 Drop 在函数返回时统一擦除
            Ok((count, exhausted))
        }
    }

    /* 非 Windows 平台：摘要扫描不支持，返回错误 */
    #[cfg(not(windows))]
    pub(crate) fn call_scan_summary_open(&mut self, _start_lid: u64, _batch_size: u64, _auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_summary_fetch(&mut self, _max_count: u64, _auth_key: Option<&[u8]>) -> Result<(usize, bool), u32> { Err(0xFFFFFFFF) }

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
    ///   2. 格式不符时 C 层返回 FORMAT（无旧格式兼容分支）
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

    /// 按类型分页枚举记录 ID（类型盲索引，API 0x0012）。
    /// 不读取记录密文；out_ids 长度必须 >= max_count。
    pub(crate) fn call_list_ids_by_type(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
        out_ids: &mut [u64],
        out_count: &mut u64,
        out_exhausted: &mut u8,
    ) -> u32 {
        if max_count == 0u64 || (out_ids.len() as u64) < max_count {
            return 0xFFFFFFFF;
        }
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysListIdsByTypeFn> =
                match lib.get(b"Verthys_ListIdsByType") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| {
                func(
                    self.handle,
                    rtype,
                    after_id,
                    max_count,
                    out_ids.as_mut_ptr(),
                    out_count as *mut u64,
                    out_exhausted as *mut u8,
                )
            })
            .unwrap_or(0xFFFFFFFF)
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
            super::progress_cb::set_rotate_cancel_handle(handle);
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
            super::progress_cb::clear_rotate_cancel_handle();
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
            path_reason: st.path_reason,
            limited_count: st.limited_count,
            policy_flags: st.policy_flags,
            checked_at_unix_ms: st.checked_at_unix_ms,
        })
    }

    /// 合并并下发运行时守卫位（完整掩码语义）。
    ///
    /// 心跳位一旦由心跳线程置位便保持；挂起位跟随主进程下发值（停止守卫
    /// 下发 0）。合并结果写入进程级原子并立即通知 C 层，状态查询据此
    /// 区分"看门狗已接线"与"可修复缺口"。
    pub(crate) fn update_runtime_guards(&self, suspend_lock: bool) -> Result<(), u32> {
        let heartbeat = self.runtime_guards.load(Ordering::Relaxed) & 0x01;
        let next = heartbeat | if suspend_lock { 0x02 } else { 0 };
        self.runtime_guards.store(next, Ordering::Relaxed);
        self.push_runtime_guards()
    }

    /// 启用心跳线程（句柄由父进程 DuplicateHandle 注入本进程）。
    ///
    /// 独立线程每 500ms SetEvent，与 IPC 主循环解耦：即使主循环在执行长
    /// FFI（导入/轮换），脉冲仍持续，父进程可区分"忙"与"被挂起"。
    /// 成功后置 bit0 并通知 C 层；C 首次看到心跳位时刷新反注入线程基线
    ///（心跳线程起始地址在 worker EXE，不在 verthys.dll，必须纳入基线）。
    pub(crate) fn arm_heartbeat(&mut self, handle: u64) -> Result<(), u32> {
        if handle == 0 {
            return Err(VERTHYS_ERR_INVALID);
        }
        if self.heartbeat_thread.is_some() {
            return Ok(());
        }

        #[cfg(windows)]
        {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_for_thread = stop.clone();
            let thread = std::thread::Builder::new()
                .name("verthys-heartbeat".into())
                .spawn(move || {
                    let h = handle as *mut std::ffi::c_void;
                    while !stop_for_thread.load(Ordering::Relaxed) {
                        unsafe {
                            let _ = SetEvent(h);
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                })
                .map_err(|_| 0xFFFFFFFFu32)?;
            self.heartbeat_stop = Some(stop);
            self.heartbeat_thread = Some(thread);
        }
        #[cfg(not(windows))]
        {
            return Err(0xFFFFFFFFu32);
        }

        let flags = self.runtime_guards.load(Ordering::Relaxed) | 0x01;
        self.runtime_guards.store(flags, Ordering::Relaxed);
        self.push_runtime_guards()
    }

    /// 将当前完整掩码推送到 C 层；旧 DLL 缺少该导出时仅诊断一次。
    fn push_runtime_guards(&self) -> Result<(), u32> {
        let flags = self.runtime_guards.load(Ordering::Relaxed);
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysNotifyRuntimeGuardsFn> =
                match lib.get(b"Verthys_NotifyRuntimeGuards") {
                    Ok(f) => f,
                    Err(_) => {
                        if !self.guards_symbol_warned.swap(true, Ordering::Relaxed) {
                            init_diag!(
                                "[worker] DLL 缺少 Verthys_NotifyRuntimeGuards（旧版），守卫位仅本地记录"
                            );
                        }
                        return Ok(());
                    }
                };
            let rc = ffi_call(|| { func(flags) }).unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
        }
        Ok(())
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
                    Err(_) => return Err(0xFFFFFFFF),
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
