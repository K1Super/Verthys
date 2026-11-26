use libloading::{Library, Symbol};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU32};

use crate::log::init_diag;
use crate::runtime::ffi_types::*;
use crate::runtime::format_os_error;

use super::{ffi_call, Worker};

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
             * 由进程回收，无驻留窗口。
             * 版本常量由 build.rs 生成：默认 0x0017，可用
             * VERTHYS_WORKER_API_VERSION 显式抬高。 */
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
}
