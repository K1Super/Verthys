/*
 * trace_cleanup.rs — 应用自身痕迹清理（痕迹清理能力的执行路径）
 *
 * 职责：
 *   承载 11 位特性契约中 FEAT_TRACE_CLEANUP 位的应用侧执行路径：
 *   锁定 / 退出时枚举系统最近记录目录（%APPDATA%\Microsoft\Windows\Recent）
 *   中的 .lnk 条目，仅删除指向本应用文件的记录，绝不触碰无关系统记录。
 *
 * 应用自身痕迹域（判定收口，唯一口径）：
 *   - 目标文件扩展名为本应用专属容器格式（.verthys 密钥容器 /
 *     .venc 加密导出容器）；扩展名通配格式（如 .bin）不纳入，防止
 *     误删用户无关文件；
 *   - 或目标路径位于应用自有目录（配置 / 数据目录，由调用方传入
 *     受信目录前缀，后端解析，前端不可注入）。
 *
 * COM 线程模型约束：
 *   .lnk 目标解析经 IShellLink/IPersistFile（COM）。清理整体运行在
 *   调用方提供的专用阻塞线程上；线程内自行 CoInitializeEx，正常路径
 *   配对 CoUninitialize。若线程复用导致已被以其他 apartment 模型初始
 *   化（RPC_E_CHANGED_MODE），沿用现有模型且不调用 CoUninitialize，
 *   不破坏他方初始化状态。
 *
 * 失败语义：整体失败返回 Err 由调用方写审计；单条 .lnk 解析或删除
 * 失败不中断批量，逐条跳过。删除对象是 .lnk 记录本身，永不触碰
 * 目标文件。
 */

/// 应用专属容器扩展名（小写）。仅此集合内的目标按扩展名纳入痕迹域。
const APP_OWNED_EXTENSIONS: [&str; 2] = [".verthys", ".venc"];

/// 应用自身痕迹域判定（纯函数，可测）
///
/// - `target_lower`：.lnk 指向的目标路径（已转小写、统一反斜杠）；
/// - `owned_dirs_lower`：应用自有目录前缀（已转小写、统一反斜杠、
///   去尾部反斜杠）。
///
/// 命中规则：目标以应用自有目录前缀开头（按路径边界匹配，`verthys`
/// 前缀不得命中 `verthys2` 等同名前缀目录），或扩展名属于应用专属
/// 容器格式。空目标 / 空前缀一律不命中。
fn is_app_owned_target(target_lower: &str, owned_dirs_lower: &[String]) -> bool {
    if target_lower.is_empty() {
        return false;
    }
    if owned_dirs_lower.iter().any(|d| {
        !d.is_empty()
            && target_lower.starts_with(d.as_str())
            && (target_lower.len() == d.len()
                || target_lower.as_bytes()[d.len()] == b'\\')
    }) {
        return true;
    }
    APP_OWNED_EXTENSIONS
        .iter()
        .any(|ext| target_lower.ends_with(ext))
}

/// 执行应用自身痕迹清理，返回删除的 .lnk 条目数
///
/// 调用方必须在专用阻塞线程上调用（spawn_blocking 等），本函数在该
/// 线程内完成 COM 初始化与逐条解析。Windows 以外平台返回 0。
///
/// `owned_dirs`：应用自有目录前缀（配置 / 数据目录），用于
/// 路径前缀判定；扩展名判定与该参数无关。
pub fn cleanup_app_recent_links(owned_dirs: &[std::path::PathBuf]) -> Result<usize, String> {
    #[cfg(target_os = "windows")]
    {
        win_impl::cleanup_app_recent_links(owned_dirs)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = owned_dirs;
        Ok(0)
    }
}

/// 锁定 / 退出时机的痕迹清理入口（fire-and-forget，不阻塞锁定响应）
///
/// 门控：仅 FEAT_TRACE_CLEANUP 开启时执行（策略位未应用时保守执行，
/// 与门控模块失败方向一致）。清理在专用阻塞线程上运行（COM 初始化
/// 在任务内完成，与调用方线程模型隔离）；结果写审计事件
/// （TRACE_CLEANUP）：
///   - 删除数 > 0：审计 Success（清理为状态变更动作，必须留痕）；
///   - 删除数 = 0：仅 debug 日志（无痕可清为常态，不制造审计噪音）；
///   - 失败：审计 Failure + 告警日志（失败可见，不静默吞掉）。
pub fn run_locked_cleanup_async(app: tauri::AppHandle) {
    if !crate::security::app_feature_gate::enabled(
        crate::security::app_feature_gate::FEAT_TRACE_CLEANUP,
    ) {
        return;
    }

    // 任务在阻塞线程池执行（运行时关闭等极端场景下任务被丢弃，不影响锁定主流程）
    let handle = tokio::task::spawn_blocking(move || {
        let owned_dirs = collect_owned_dirs(&app);
        let result = cleanup_app_recent_links(&owned_dirs);
        report_cleanup_result(&app, &result);
    });
    // 显式丢弃句柄：fire-and-forget 契约，锁定主流程不等待清理结果
    drop(handle);
}

/// 收集应用自有目录前缀（痕迹域判定的路径输入）
///
/// 覆盖配置目录与数据目录（应用自身文件所在）；用户选择的容器 /
/// 导出文件可能位于任意位置，由扩展名规则（.verthys / .venc）覆盖。
fn collect_owned_dirs(app: &tauri::AppHandle) -> Vec<std::path::PathBuf> {
    use tauri::Manager;
    let mut dirs = Vec::new();
    if let Ok(d) = app.path().app_config_dir() {
        dirs.push(d);
    }
    if let Ok(d) = app.path().app_local_data_dir() {
        dirs.push(d);
    }
    if let Ok(d) = app.path().app_data_dir() {
        dirs.push(d);
    }
    dirs
}

/// 上报清理结果（应用日志 + 审计事件）
fn report_cleanup_result(app: &tauri::AppHandle, result: &Result<usize, String>) {
    use crate::security_commands::audit::write_audit_with_extensions;
    use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};

    let session_id = format!("pid-{}", std::process::id());
    match result {
        Ok(0) => {
            log::debug!("[trace_cleanup] 系统最近记录中无应用痕迹");
        }
        Ok(n) => {
            log::info!("[trace_cleanup] 已清理 {} 条应用痕迹记录", n);
            write_audit_with_extensions(
                app,
                &session_id,
                AuditEventType::TraceCleanup,
                AuditResult::Success,
                None,
                Some(format!("已清理 {} 条应用痕迹记录", n)),
                AuditExtensions::default(),
            );
        }
        Err(e) => {
            log::warn!("[trace_cleanup] 痕迹清理失败（不阻塞锁定）: {}", e);
            write_audit_with_extensions(
                app,
                &session_id,
                AuditEventType::TraceCleanup,
                AuditResult::Failure,
                None,
                Some(format!("痕迹清理失败: {}", e)),
                AuditExtensions::default(),
            );
        }
    }
}

#[cfg(target_os = "windows")]
mod win_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use windows::core::{Interface, GUID};
    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE};
    use windows::Win32::Storage::FileSystem::DeleteFileW;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED, IPersistFile, STGM_READ,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, SLGP_RAWPATH};

    use super::is_app_owned_target;

    /// CLSID_ShellLink（Shell 链接对象，系统级稳定标识，crate 未导出故本地定义）
    const CLSID_SHELL_LINK: GUID = GUID {
        data1: 0x00021401,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    /// 本线程 COM 初始化作用域（RAII）
    ///
    /// owned = true 表示本函数完成了初始化，Drop 时配对 CoUninitialize；
    /// owned = false 表示线程已被以其他 apartment 模型初始化，沿用现状
    /// 且不解除初始化。
    struct ComScope {
        owned: bool,
    }

    impl ComScope {
        fn init() -> Result<ComScope, String> {
            let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            if hr.is_ok() || hr == S_FALSE {
                Ok(ComScope { owned: true })
            } else if hr == RPC_E_CHANGED_MODE {
                // 线程池复用：COM 已按其他模型初始化，直接沿用
                Ok(ComScope { owned: false })
            } else {
                Err(format!("CoInitializeEx 失败: {:#x}", hr.0 as u32))
            }
        }
    }

    impl Drop for ComScope {
        fn drop(&mut self) {
            if self.owned {
                unsafe { CoUninitialize() };
            }
        }
    }

    /// Path → 以 null 结尾的 UTF-16 序列
    fn path_to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// 解析单个 .lnk 指向的本地目标路径（无法解析返回 None）
    ///
    /// SLGP_RAWPATH：取链接内记录的原始本地路径，不要求目标存在、
    /// 不触发网络解析（避免清理动作被慢速/离线目标拖住）。
    fn resolve_lnk_target(lnk_path: &Path) -> Option<String> {
        let wide = path_to_wide(lnk_path);

        // SAFETY：COM 已在本线程初始化（ComScope）；接口调用均按
        // COM 契约传参，缓冲区长度显式传递，无跨线程共享。
        unsafe {
            let shell_link: IShellLinkW =
                CoCreateInstance(&CLSID_SHELL_LINK, None::<&windows::core::IUnknown>, CLSCTX_INPROC_SERVER)
                    .ok()?;
            let persist: IPersistFile = shell_link.cast().ok()?;
            persist
                .Load(windows::core::PCWSTR::from_raw(wide.as_ptr()), STGM_READ)
                .ok()?;

            let mut buf = [0u16; 520]; // MAX_PATH * 2 + 余量
            let mut find_data = windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW::default();
            shell_link
                .GetPath(&mut buf, &mut find_data as *mut _, SLGP_RAWPATH.0 as u32)
                .ok()?;

            let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            if len == 0 {
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..len]))
        }
    }

    /// 路径规范化为小写反斜杠形态（痕迹域判定的统一口径）
    ///
    /// 统一正反斜杠后转小写，去尾部分隔符；保证与前缀判定及扩展名
    /// 判定的输入契约一致（兼容个别链接目标使用正斜杠的形态）。
    fn normalize_lower(path: &str) -> String {
        let mut s = path.to_lowercase().replace('/', "\\");
        while s.len() > 1 && s.ends_with('\\') {
            s.pop();
        }
        s
    }

    pub(super) fn cleanup_app_recent_links(owned_dirs: &[PathBuf]) -> Result<usize, String> {
        // COM 初始化必须先于任何 COM 调用；作用域 Drop 时按归属解除
        let _com = ComScope::init()?;

        let owned_dirs_lower: Vec<String> = owned_dirs
            .iter()
            .map(|d| normalize_lower(&d.to_string_lossy()))
            .collect();

        let appdata = std::env::var("APPDATA")
            .map_err(|_| "无法读取 %APPDATA% 环境变量".to_string())?;
        let recent_dir = Path::new(&appdata).join(r"Microsoft\Windows\Recent");
        let entries = match std::fs::read_dir(&recent_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 最近记录目录不存在：无可清理项，非错误
                return Ok(0);
            }
            Err(e) => {
                return Err(format!("读取最近记录目录失败: {}", e));
            }
        };

        let mut deleted: usize = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let is_lnk = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("lnk"))
                .unwrap_or(false);
            if !is_lnk {
                continue;
            }

            // 仅处理常规文件（子目录不该出现在 Recent，防御性跳过）
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }

            let target = match resolve_lnk_target(&path) {
                Some(t) => t,
                None => continue, // 无法解析目标（非本地路径/损坏）：跳过不删
            };

            let target_lower = normalize_lower(&target);
            if !is_app_owned_target(&target_lower, &owned_dirs_lower) {
                continue; // 无关系统记录：绝不触碰
            }

            let wide = path_to_wide(&path);
            // SAFETY：wide 为以 null 结尾的合法 UTF-16 路径
            if unsafe { DeleteFileW(windows::core::PCWSTR::from_raw(wide.as_ptr())) }.is_ok() {
                deleted += 1;
            }
            // 单条删除失败（被占用等）：跳过，不中断批量
        }

        Ok(deleted)
    }
}

/* ====================================================================== *
 *  单元测试（判定口径为跨调用契约，防回退）                                *
 * ====================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_owned_by_extension() {
        let dirs: Vec<String> = vec![];
        assert!(is_app_owned_target(
            r"c:\users\x\docs\秘密.verthys",
            &dirs
        ));
        // 契约：输入已由调用方统一为小写反斜杠（normalize_lower）
        assert!(is_app_owned_target(r"d:\backup\照片.venc", &dirs));
        assert!(is_app_owned_target(
            r"c:\users\x\docs\photo.venc",
            &dirs
        ));
    }

    #[test]
    fn test_app_owned_by_directory_prefix() {
        let dirs = vec![r"c:\users\x\appdata\roaming\verthys".to_string()];
        assert!(is_app_owned_target(
            r"c:\users\x\appdata\roaming\verthys\cache\thumb.png",
            &dirs
        ));
        // 目录自身前缀命中（目标即目录本身，防御性覆盖）
        assert!(is_app_owned_target(
            r"c:\users\x\appdata\roaming\verthys",
            &dirs
        ));
        // 同名前缀目录（verthys2）必须按路径边界排除，防止误删
        assert!(!is_app_owned_target(
            r"c:\users\x\appdata\roaming\verthys2\other.png",
            &dirs
        ));
    }

    #[test]
    fn test_unrelated_records_never_matched() {
        let dirs: Vec<String> = vec![];
        // 通用扩展名（.bin 等）不属于应用专属痕迹域，绝不按扩展名删除
        assert!(!is_app_owned_target(r"c:\tools\firmware.bin", &dirs));
        assert!(!is_app_owned_target(r"c:\users\x\docs\报告.docx", &dirs));
        assert!(!is_app_owned_target(r"c:\windows\system32\drivers\etc\hosts", &dirs));
    }

    #[test]
    fn test_empty_inputs_never_match() {
        let dirs: Vec<String> = vec![];
        assert!(!is_app_owned_target("", &dirs));
        // 空目录前缀只对前缀规则无效；扩展名规则独立生效（.verthys 仍命中）
        let dirs_with_empty = vec![String::new()];
        assert!(!is_app_owned_target(r"c:\anything.bin", &dirs_with_empty));
        assert!(is_app_owned_target(r"c:\anything.verthys", &dirs_with_empty));
    }
}
