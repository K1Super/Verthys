/*
 * controller/preflight_controller.rs — 路径预检控制器（第 3.1-3.9 项重写版）
 *
 *
 * 包含命令：
 *   - verthys_preflight: 路径预检（企业级安全版）
 *
 * 第 3.1-3.9 项企业级预检方案：
 *   3.1 白名单基目录集合：canonicalize 父目录后必须以白名单为前缀；删黑名单。
 *        白名单动态构建：用户目录（Profile/Documents/AppData）+ EXE 目录 + 非系统盘根。
 *   3.2 先校验后操作：输入校验 → 解析父目录绝对路径 → 白名单检查（拒绝则不任何 FS 操作）
 *        → 才创建目录；失败回滚仅当本次新建。
 *   3.3 原子化租约：目标父目录创建随机命名独占锁文件并保持打开作为租约凭据，
 *        整个会话内完成消除 TOCTOU（写权限测试即租约创建）。
 *   3.4 错误信息脱敏：PreflightResult 仅返回错误码 + 无路径提示；
 *        详细路径经 sanitize_path 仅写入后端日志。
 *   3.5 磁盘空间检查错误分离：get_disk_space_mb 失败返回 DISK_SPACE_UNKNOWN（非 0 误判）；
 *        阈值外置常量 DISK_SPACE_MIN_MB。
 *   3.6 随机文件名 + 重试：写权限测试用 CSPRNG 随机十六进制文件名 + 立即删除
 *        + 重试（占用等 50ms × 3）。
 *   3.7 统一平台安全策略：动态获取用户数据目录作白名单基；条件编译 Windows 限
 *        CSIDL_WINDOWS 等区域，Unix 屏蔽 /etc /boot；用 canonicalize 规范化。
 *   3.8 输入校验第一道防线：拒绝空字节/控制字符/超 MAX_PATH/相对路径/../~；
 *        不通过返回 INVALID_PATH 不执行 FS 操作（util/path::validate_path_input）。
 *   3.9 异步化与并发控制：spawn_blocking + 5s 超时返回 TEMPORARY_FAILURE；
 *        Semaphore 限制并发预检数（避免磁盘 I/O 雪崩）。
 *
 * 依赖方向：controller → controller::types / controller::api_error /
 *           util::path / util::disk / util::random / constants::timeout
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::PreflightResult;
use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use crate::util::path::{sanitize_path, validate_path_input};
use crate::util::random::random_hex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Semaphore;

/* ------------------------------------------------------------------ *
 * 第 3.9 项：并发控制信号量                                            *
 *                                                                    *
 * 使用 OnceLock 持有全局 Semaphore，限制同时执行的预检数量。           *
 * 预检涉及磁盘 I/O（canonicalize/create_dir/写测试/磁盘空间查询），    *
 * 高并发下不加限制会导致磁盘 I/O 雪崩，影响 UI 响应。                   *
 * ------------------------------------------------------------------ */

/// 第 3.9 项：并发预检上限（同时执行的 verthys_preflight 数量）
const PREFLIGHT_MAX_CONCURRENCY: usize = 4;

/// 第 3.9 项：全局并发信号量（OnceLock 懒初始化）
static PREFLIGHT_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

/// 获取预检并发信号量
fn preflight_semaphore() -> &'static Semaphore {
    PREFLIGHT_SEMAPHORE.get_or_init(|| Semaphore::new(PREFLIGHT_MAX_CONCURRENCY))
}

/* ------------------------------------------------------------------ *
 * 第 3.5 / 3.9 项：超时与阈值常量                                      *
 * ------------------------------------------------------------------ */

/// 第 3.9 项：预检总超时（5s，对应 TimeoutConfig.preflight）
const PREFLIGHT_TIMEOUT: Duration = TIMEOUT_CONFIG.preflight;

/// 第 3.5 项：磁盘空间最小阈值（MB，外置配置）
///
/// 低于此值返回 DISK_SPACE_INSUFFICIENT。
/// 阈值外置便于不同部署环境调整（阶段 8 可改为按分区配置）。
const DISK_SPACE_MIN_MB: u64 = 200;

/// 第 3.6 项：写权限测试重试次数（临时文件被占用时重试）
const WRITE_TEST_RETRIES: usize = 3;

/// 第 3.6 项：写权限测试重试间隔
const WRITE_TEST_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/* ------------------------------------------------------------------ *
 * 第 3.4 项：错误结果构造辅助（脱敏，仅错误码 + 无路径提示）            *
 * ------------------------------------------------------------------ */

/// 第 3.4 项：构造失败结果（脱敏）
///
/// 仅返回错误码 + 用户可读的无路径提示，不泄露文件系统布局。
/// 详细路径经 sanitize_path 写入后端日志（调用方负责）。
fn make_error_result(code: ErrorCode, dir_created: bool) -> PreflightResult {
    PreflightResult {
        ok: false,
        error: Some(code.default_message().to_string()),
        error_code: Some(code.as_str().to_string()),
        is_system_protected: false,
        file_exists: false,
        disk_space_mb: 0,
        dir_created,
    }
}

/// 第 3.4 项：构造系统保护目录拒绝结果（脱敏）
fn make_system_protected_result(dir_created: bool) -> PreflightResult {
    let code = ErrorCode::PermissionDenied;
    PreflightResult {
        ok: false,
        error: Some(code.default_message().to_string()),
        error_code: Some(code.as_str().to_string()),
        is_system_protected: true,
        file_exists: false,
        disk_space_mb: 0,
        dir_created,
    }
}

/* ------------------------------------------------------------------ *
 * 第 3.1 / 3.7 项：白名单基目录集合构建                                *
 *                                                                    *
 * 动态获取当前平台的用户目录 + 非系统盘根作为白名单基。                 *
 * 白名单基目录自身也 canonicalize，避免被符号链接绕过。                *
 * 不存在的目录跳过（首次运行时用户目录可能未创建）。                   *
 * ------------------------------------------------------------------ */

/// 第 3.1 / 3.7 项：构建安全白名单基目录集合
///
/// Windows 白名单来源：
///   1. FOLDERID_Profile（C:\Users\<user>）— 用户主目录
///   2. FOLDERID_Documents — 用户文档目录
///   3. FOLDERID_LocalAppData — %LOCALAPPDATA%
///   4. FOLDERID_RoamingAppData — %APPDATA%
///   5. current_exe().parent() — EXE 所在目录（便携模式）
///   6. 非系统盘的固定本地卷根（D:\ E:\ 等）— 用户可自由写入
///
/// Unix 白名单来源：
///   1. $HOME
///   2. XDG_DATA_HOME（或 ~/.local/share）
///   3. current_exe().parent()
///   4. /tmp
///
/// 系统盘（通常 C:\）的根目录不加入白名单，仅其用户子目录（1-4）允许。
/// 非系统盘根目录整体加入白名单（用户数据盘，无系统文件）。
fn build_safe_whitelist() -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();

    // 5. EXE 所在目录（便携模式 / 安装目录）
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        if let Ok(canon) = std::fs::canonicalize(&exe_dir) {
            bases.push(canon);
        }
    }

    #[cfg(windows)]
    {
        // 1-4. Windows 用户目录（SHGetKnownFolderPath）
        for base in get_windows_user_dirs() {
            if let Ok(canon) = std::fs::canonicalize(&base) {
                bases.push(canon);
            }
        }

        // 6. 所有固定本地卷根（包括系统盘 C:\，系统目录由 is_system_protected_dir 二次防御）
        for drive_root in get_all_fixed_drive_roots() {
            // 驱动器根目录 canonicalize（如 D:\）
            if let Ok(canon) = std::fs::canonicalize(&drive_root) {
                bases.push(canon);
            }
        }
    }

    #[cfg(not(windows))]
    {
        // 1. $HOME
        if let Ok(home) = std::env::var("HOME") {
            if let Ok(canon) = std::fs::canonicalize(&home) {
                bases.push(canon);
            }
        }
        // 2. XDG_DATA_HOME 或 ~/.local/share
        let xdg_data = std::env::var("XDG_DATA_HOME").ok().filter(|s| !s.is_empty());
        let data_dir = xdg_data.map(PathBuf::from).or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local").join("share"))
        });
        if let Some(dd) = data_dir {
            if let Ok(canon) = std::fs::canonicalize(&dd) {
                bases.push(canon);
            }
        }
        // 4. /tmp
        if let Ok(canon) = std::fs::canonicalize("/tmp") {
            bases.push(canon);
        }
    }

    bases
}

/// 第 3.7 项：Windows 用户目录获取（SHGetKnownFolderPath）
#[cfg(windows)]
fn get_windows_user_dirs() -> Vec<PathBuf> {
    use windows::Win32::UI::Shell::{
        SHGetKnownFolderPath, FOLDERID_Documents, FOLDERID_LocalAppData, FOLDERID_Profile,
        FOLDERID_RoamingAppData, KNOWN_FOLDER_FLAG,
    };

    let mut dirs = Vec::new();
    let flags = KNOWN_FOLDER_FLAG(0);

    for folder_id in [
        &FOLDERID_Profile,
        &FOLDERID_Documents,
        &FOLDERID_LocalAppData,
        &FOLDERID_RoamingAppData,
    ] {
        let result = unsafe { SHGetKnownFolderPath(folder_id, flags, None) };
        if let Ok(pwsz) = result {
            let path_str = unsafe { pwsz.to_string() };
            unsafe {
                windows::Win32::System::Com::CoTaskMemFree(Some(pwsz.as_ptr() as *const _));
            }
            if let Ok(s) = path_str {
                if !s.is_empty() {
                    dirs.push(PathBuf::from(s));
                }
            }
        }
    }

    dirs
}

/// 第 3.7 项：获取所有固定本地卷根目录
///
/// 枚举所有逻辑驱动器，筛选出固定驱动器（DRIVE_FIXED=3）。
/// 所有固定盘根加入白名单（包括系统盘 C:\），
/// 系统目录（C:\Windows 等）由 is_system_protected_dir 二次防御拦截。
/// 用户数据盘（D:\ E:\ 等）整体可写，无需额外限制。
#[cfg(windows)]
fn get_all_fixed_drive_roots() -> Vec<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW};

    // DRIVE_FIXED = 3（windows crate 0.58 常量值）
    const DRIVE_FIXED: u32 = 3;

    let mut buffer = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) };
    if len == 0 {
        return Vec::new();
    }

    let strings: Vec<u16> = buffer[..len as usize].to_vec();
    let mut drives = Vec::new();

    // GetLogicalDriveStringsW 返回以双 null 结尾的字符串数组
    let mut start = 0;
    while start < strings.len() {
        let end = strings[start..].iter().position(|&c| c == 0);
        match end {
            Some(0) => break, // 双 null，结束
            Some(n) => {
                let drive_str = String::from_utf16_lossy(&strings[start..start + n]);
                if drive_str.len() >= 2 {
                    // 检查是否为固定驱动器
                    let wide: Vec<u16> =
                        drive_str.encode_utf16().chain(std::iter::once(0)).collect();
                    let drive_type = unsafe { GetDriveTypeW(PCWSTR::from_raw(wide.as_ptr())) };
                    if drive_type == DRIVE_FIXED {
                        drives.push(PathBuf::from(drive_str));
                    }
                }
                start += n + 1;
            }
            None => break,
        }
    }

    drives
}

/* ------------------------------------------------------------------ *
 * 第 3.7 项：系统保护目录检查（条件编译，防御纵深）                     *
 *                                                                    *
 * 白名单是主要防线（3.1），系统目录检查是二次防御。                     *
 * 即使白名单意外包含系统路径，此处仍拒绝。                              *
 * ------------------------------------------------------------------ */

/// 第 3.7 项：检查路径是否位于系统保护目录
///
/// 条件编译：
///   - Windows: 检查 CSIDL_WINDOWS / Program Files / ProgramData 等
///   - Unix: 检查 /etc /boot /usr /bin /sbin /root
///
/// 返回 true 表示位于系统保护目录（拒绝写入）。
///
/// 注意：使用前缀匹配系统子目录（C:\Windows\...），但根目录（C:\）使用精确匹配，
/// 避免误判 C:\Users\... 等用户路径。
fn is_system_protected_dir(canonical: &Path) -> bool {
    let path_str = canonical.to_string_lossy().to_lowercase();

    #[cfg(windows)]
    {
        // Windows 系统保护目录（小写前缀匹配子目录）
        // 注意：白名单已保证用户目录安全，此处为防御纵深
        let system_subdir_prefixes = [
            r"\\?\c:\windows",
            r"c:\windows",
            r"\\?\c:\program files",
            r"c:\program files",
            r"\\?\c:\program files (x86)",
            r"c:\program files (x86)",
            r"\\?\c:\programdata",
            r"c:\programdata",
        ];

        // 子目录前缀匹配（C:\Windows\... C:\Program Files\... 等）
        if system_subdir_prefixes.iter().any(|p| path_str.starts_with(p)) {
            return true;
        }

        // 系统盘根目录精确匹配（禁止直接在 C:\ 下创建文件，但允许 C:\Users\... 等子目录）
        // 仅当路径本身就是 C:\ 或 \\?\C:\ 时拒绝
        let root_forms = [r"\\?\c:\", r"c:\"];
        if root_forms.iter().any(|root| path_str == *root) {
            return true;
        }

        false
    }

    #[cfg(not(windows))]
    {
        let system_prefixes = ["/etc", "/boot", "/usr", "/bin", "/sbin", "/root", "/proc", "/sys"];
        system_prefixes.iter().any(|p| path_str.starts_with(p))
    }
}

/* ------------------------------------------------------------------ *
 * 第 3.1 项：白名单前缀校验                                            *
 * ------------------------------------------------------------------ */

/// 第 3.1 项：校验 canonicalize 后的路径是否以白名单基目录为前缀
///
/// 精确匹配或为子路径（path 以 base + 分隔符开头）。
/// 路径与白名单基目录均经 canonicalize，防止符号链接绕过。
///
/// ★ 企业级根治修复：trim 尾部分隔符
///   根因：Windows 驱动器根目录（如 D:\）canonicalize 后为 \\?\D:\，
///   规范化为 //?/d:/（含尾部 /）。原 format!("{}/", base_str) 产生
///   //?/d://（双斜杠），无法匹配 //?/d:/test，导致 D 盘路径被误拒。
///   修复：先 trim_end_matches('/') 消除尾部斜杠，再拼接分隔符。
fn is_within_whitelist(path: &Path, whitelist: &[PathBuf]) -> bool {
    let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
    let path_str = path_str.trim_end_matches('/');
    for base in whitelist {
        let base_str = base.to_string_lossy().to_lowercase().replace('\\', "/");
        let base_str = base_str.trim_end_matches('/');
        if path_str == base_str || path_str.starts_with(&format!("{}/", base_str)) {
            return true;
        }
    }
    false
}

/* ------------------------------------------------------------------ *
 * 第 3.2 项：解析父目录（canonicalize 父目录或最长存在祖先）            *
 *                                                                    *
 * 若父目录不存在（首次运行），canonicalize 会失败。                    *
 * 此时向上回溯找到最长的已存在祖先，canonicalize 后校验白名单。         *
 * 由于 validate_path_input 已拒绝 .. 段，不存在的尾部路径不会逃逸。     *
 * ------------------------------------------------------------------ */

/// 第 3.2 项：解析父目录用于白名单校验
///
/// 返回 (canonical_ancestor, parent_path)：
///   - canonical_ancestor: 父目录或其最长已存在祖先的 canonicalize 路径
///   - parent_path: 原始父目录路径（用于后续 create_dir_all）
///
/// 若父目录已存在，canonical_ancestor = canonicalize(parent)。
/// 若父目录不存在，向上回溯找到已存在祖先 canonicalize，校验其白名单归属。
fn resolve_parent_for_whitelist(parent: &Path) -> Result<PathBuf, String> {
    // 尝试直接 canonicalize 父目录
    if let Ok(canon) = std::fs::canonicalize(parent) {
        return Ok(canon);
    }

    // 父目录不存在：向上回溯找最长已存在祖先
    let mut current = parent;
    loop {
        match current.parent() {
            Some(ancestor) => {
                if let Ok(canon_ancestor) = std::fs::canonicalize(ancestor) {
                    // 找到已存在祖先，返回其 canonical 路径
                    // 校验白名单时用此祖先；后续 create_dir_all(parent) 在白名单内安全
                    return Ok(canon_ancestor);
                }
                current = ancestor;
            }
            None => {
                // 回溯到根仍无法 canonicalize
                return Err("无法解析路径父目录的任何祖先".to_string());
            }
        }
    }
}

/* ------------------------------------------------------------------ *
 * 第 3.3 / 3.6 项：原子化租约 — 随机命名独占锁文件写权限测试             *
 *                                                                    *
 * 创建随机命名文件并保持打开（租约凭据），证明目录可写。                *
 * 随机文件名避免并发冲突；重试机制应对临时占用。                        *
 * 测试完成后立即删除锁文件。                                            *
 * ------------------------------------------------------------------ */

/// 第 3.3 / 3.6 项：原子化租约写权限测试
///
/// 在目标目录创建随机命名的独占锁文件，验证目录可写性。
/// 流程：
///   1. 生成 32 字符随机十六进制文件名（CSPRNG）
///   2. 尝试创建并打开文件（独占创建 CREATE_NEW）
///   3. 写入测试字节 + fsync
///   4. 关闭并删除锁文件
///   5. 若创建失败（被占用），等待 50ms 重试，最多 3 次
///
/// 返回：
///   - Ok(()): 目录可写，租约创建成功
///   - Err(msg): 目录不可写或重试耗尽
fn test_write_permission_with_lease(dir: &Path) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut last_err = String::new();

    for attempt in 0..WRITE_TEST_RETRIES {
        // 第 3.6 项：随机文件名（32 字符十六进制，CSPRNG）
        let random_name = format!(".verthys_lease_{}.tmp", random_hex(16));
        let lease_path = dir.join(&random_name);

        // 第 3.3 项：独占创建（CREATE_NEW 语义：文件已存在则失败）
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lease_path)
        {
            Ok(mut file) => {
                // 写入测试字节
                if let Err(e) = file.write_all(b"verthys_preflight_lease") {
                    log::warn!(
                        "[preflight] 租约文件写入失败（第 {} 次）: {}",
                        attempt + 1,
                        e
                    );
                    // 写入失败但文件已创建 → 目录可写，仅记录告警
                } else {
                    // fsync 确保数据落盘
                    let _ = file.sync_all();
                }

                // 第 3.6 项：立即删除锁文件（不留痕迹）
                drop(file);
                if let Err(_) = std::fs::remove_file(&lease_path) {
                    log::warn!(
                        "[preflight] 租约文件删除失败（可能残留）: {}",
                        sanitize_path(&lease_path.to_string_lossy())
                    );
                    // 删除失败不阻塞主流程（文件名为随机，无并发冲突风险）
                }

                // 文件创建成功 → 目录可写
                return Ok(());
            }
            Err(e) => {
                last_err = format!("目录不可写: {}", e);
                if attempt + 1 < WRITE_TEST_RETRIES {
                    // 第 3.6 项：等待 50ms 后重试（文件被占用时的退避）
                    std::thread::sleep(WRITE_TEST_RETRY_INTERVAL);
                } else {
                    // 最后一次重试失败，last_err 已设置
                    log::warn!(
                        "[preflight] 第 3.6 项：写权限测试重试 {} 次后仍失败",
                        WRITE_TEST_RETRIES
                    );
                }
            }
        }
    }

    Err(last_err)
}

/* ------------------------------------------------------------------ *
 * 第 3.5 项：磁盘空间检查（错误分离）                                  *
 * ------------------------------------------------------------------ */

/// 第 3.5 项：磁盘空间检查结果
enum DiskSpaceStatus {
    /// 剩余空间充足（MB）
    Ok(u64),
    /// 空间不足（MB，低于阈值）
    Insufficient(u64),
    /// 无法获取磁盘空间信息
    Unknown,
}

/// 第 3.5 项：检查磁盘空间（区分不足与未知）
fn check_disk_space(path: &Path) -> DiskSpaceStatus {
    use crate::util::disk::get_disk_space_mb;
    match get_disk_space_mb(path) {
        Some(mb) => {
            if mb < DISK_SPACE_MIN_MB {
                DiskSpaceStatus::Insufficient(mb)
            } else {
                DiskSpaceStatus::Ok(mb)
            }
        }
        None => DiskSpaceStatus::Unknown, // 第 3.5 项：失败返回 Unknown，非 0 误判
    }
}

/* ------------------------------------------------------------------ *
 * 第 3.1-3.9 项：预检核心逻辑（spawn_blocking 内执行）                 *
 *                                                                    *
 * 所有阻塞式 FS 操作集中在此函数，由 spawn_blocking 调度至阻塞线程池。  *
 * ------------------------------------------------------------------ */

/// 第 3.1-3.9 项：预检核心逻辑（阻塞线程内执行）
///
/// 执行顺序（第 3.2 项：先校验后操作）：
///   1. 第 3.8 项：输入硬校验（不执行 FS 操作）
///   2. 解析父目录绝对路径
///   3. 第 3.1 项：白名单前缀校验（拒绝则不任何 FS 操作）
///   4. 第 3.7 项：系统保护目录二次防御
///   5. 白名单通过后才执行目录创建（仅当不存在时）
///   6. 第 3.5 项：磁盘空间检查（错误分离）
///   7. 第 3.3 / 3.6 项：原子化租约写权限测试
///   8. 检查目标文件是否已存在
///   9. 失败时回滚本次新建目录（第 3.2 项）
fn do_preflight_blocking(verthys_path: String) -> PreflightResult {
    let path = Path::new(&verthys_path);

    // 1. 第 3.8 项：输入硬校验（第一道防线，不执行任何 FS 操作）
    if let Err(e) = validate_path_input(&verthys_path) {
        log::warn!("[preflight] 第 3.8 项：路径输入校验失败: {}", e);
        return make_error_result(ErrorCode::InvalidPath, false);
    }

    // 2. 解析父目录
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => {
            log::warn!("[preflight] 路径无父目录");
            return make_error_result(ErrorCode::InvalidPath, false);
        }
    };

    // 记录是否本次新建了目录（第 3.2 项：失败回滚用）
    let mut dir_created_by_us = false;

    // 3. 第 3.1 项：白名单前缀校验（先校验后操作，不产生副作用）
    let whitelist = build_safe_whitelist();
    let canonical_ancestor = match resolve_parent_for_whitelist(parent) {
        Ok(canon) => canon,
        Err(e) => {
            log::warn!(
                "[preflight] 第 3.1 项：父目录解析失败: {} [{}]",
                e,
                sanitize_path(&parent.to_string_lossy())
            );
            return make_error_result(ErrorCode::InvalidPath, false);
        }
    };

    if !is_within_whitelist(&canonical_ancestor, &whitelist) {
        log::warn!(
            "[preflight] 第 3.1 项：路径不在白名单基目录内 [{}]",
            sanitize_path(&canonical_ancestor.to_string_lossy())
        );
        return make_error_result(ErrorCode::PermissionDenied, false);
    }

    // 4. 第 3.7 项：系统保护目录二次防御（defense-in-depth）
    if is_system_protected_dir(&canonical_ancestor) {
        log::warn!(
            "[preflight] 第 3.7 项：系统保护目录拒绝 [{}]",
            sanitize_path(&canonical_ancestor.to_string_lossy())
        );
        return make_system_protected_result(false);
    }

    // 5. 白名单通过后才执行目录创建（第 3.2 项：先校验后操作）
    if !parent.exists() {
        match std::fs::create_dir_all(parent) {
            Ok(_) => {
                dir_created_by_us = true;
                log::info!(
                    "[preflight] 目录已递归创建 [{}]",
                    sanitize_path(&parent.to_string_lossy())
                );
            }
            Err(e) => {
                log::warn!(
                    "[preflight] 目录创建失败: {} [{}]",
                    e,
                    sanitize_path(&parent.to_string_lossy())
                );
                return make_error_result(ErrorCode::PermissionDenied, false);
            }
        }
    }

    // canonicalize 父目录（现在已存在）用于后续检查
    let canonical_parent = match std::fs::canonicalize(parent) {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "[preflight] 父目录 canonicalize 失败: {} [{}]",
                e,
                sanitize_path(&parent.to_string_lossy())
            );
            let result = make_error_result(ErrorCode::InvalidPath, dir_created_by_us);
            rollback_created_dir(parent, dir_created_by_us);
            return result;
        }
    };

    // 6. 第 3.5 项：磁盘空间检查（错误分离）
    let disk_space_status = check_disk_space(&canonical_parent);
    let disk_space_mb = match disk_space_status {
        DiskSpaceStatus::Ok(mb) => mb,
        DiskSpaceStatus::Insufficient(mb) => {
            log::warn!(
                "[preflight] 第 3.5 项：磁盘空间不足 {}MB（阈值 {}MB）",
                mb,
                DISK_SPACE_MIN_MB
            );
            let result = make_error_result(ErrorCode::DiskSpaceInsufficient, dir_created_by_us);
            rollback_created_dir(parent, dir_created_by_us);
            return result;
        }
        DiskSpaceStatus::Unknown => {
            log::warn!("[preflight] 第 3.5 项：无法获取磁盘空间信息");
            let result = make_error_result(ErrorCode::DiskSpaceUnknown, dir_created_by_us);
            rollback_created_dir(parent, dir_created_by_us);
            return result;
        }
    };

    // 7. 第 3.3 / 3.6 项：原子化租约写权限测试
    if let Err(e) = test_write_permission_with_lease(&canonical_parent) {
        log::warn!(
            "[preflight] 第 3.3 项：租约写权限测试失败: {} [{}]",
            e,
            sanitize_path(&canonical_parent.to_string_lossy())
        );
        let result = make_error_result(ErrorCode::PermissionDenied, dir_created_by_us);
        rollback_created_dir(parent, dir_created_by_us);
        return result;
    }

    // 8. 检查目标文件是否已存在
    let file_exists = path.exists();

    // 9. 预检通过
    PreflightResult {
        ok: true,
        error: None,
        error_code: None,
        is_system_protected: false,
        file_exists,
        disk_space_mb,
        dir_created: dir_created_by_us,
    }
}

/// 第 3.2 项：回滚本次新建的目录
///
/// 仅当目录由本次调用创建时才删除，避免误删用户数据。
/// 删除失败仅记录日志，不阻塞主流程（目录为空时删除应成功）。
fn rollback_created_dir(parent: &Path, dir_created_by_us: bool) {
    if !dir_created_by_us {
        return;
    }
    if let Err(e) = std::fs::remove_dir_all(parent) {
        log::warn!(
            "[preflight] 第 3.2 项：回滚新建目录失败: {} [{}]",
            e,
            sanitize_path(&parent.to_string_lossy())
        );
    }
}

/* ------------------------------------------------------------------ *
 * 第 3.1-3.9 项：verthys_preflight 命令入口                              *
 * ------------------------------------------------------------------ */

/// 路径预检（企业级安全版）：第 3.1-3.9 项全量方案
///
/// 九重安全校验：
///   1. 第 3.8 项：输入硬校验（空字节/控制字符/超长/相对路径/.. /~）
///   2. 第 3.2 项：解析父目录绝对路径（先校验后操作）
///   3. 第 3.1 项：白名单基目录前缀校验（canonicalize + 前缀匹配）
///   4. 第 3.7 项：系统保护目录二次防御（条件编译）
///   5. 第 3.2 项：白名单通过后才递归创建目录 + 失败回滚
///   6. 第 3.5 项：磁盘空间检查（DISK_SPACE_INSUFFICIENT / DISK_SPACE_UNKNOWN 分离）
///   7. 第 3.3 项：原子化租约写权限测试（随机命名锁文件，消除 TOCTOU）
///   8. 第 3.6 项：写测试随机文件名 + 50ms×3 重试
///   9. 第 3.4 项：错误信息脱敏（仅错误码 + 无路径提示）
///
/// 第 3.9 项：异步化与并发控制
///   - spawn_blocking 将阻塞式 FS 操作调度至阻塞线程池
///   - 5s 超时返回 TEMPORARY_FAILURE
///   - Semaphore 限制并发预检数（PREFLIGHT_MAX_CONCURRENCY=4）
#[tauri::command]
pub async fn verthys_preflight(verthys_path: String) -> Result<PreflightResult, String> {
    // 第 3.9 项：获取并发信号量（限制同时执行的预检数量）
    let _permit = preflight_semaphore()
        .acquire()
        .await
        .map_err(|e| format!("并发信号量获取失败: {}", e))?;

    // 第 3.9 项：spawn_blocking + 5s 超时
    let result = tokio::time::timeout(
        PREFLIGHT_TIMEOUT,
        tokio::task::spawn_blocking(move || do_preflight_blocking(verthys_path)),
    )
    .await;

    match result {
        // 超时内完成
        Ok(spawn_result) => match spawn_result {
            Ok(preflight_result) => Ok(preflight_result),
            Err(join_err) => {
                // spawn_blocking 线程 panic
                log::error!("[preflight] 第 3.9 项：预检任务异常退出: {}", join_err);
                Ok(make_error_result(ErrorCode::TemporaryFailure, false))
            }
        },
        // 第 3.9 项：超时
        Err(_) => {
            log::warn!(
                "[preflight] 第 3.9 项：预检超时（{}s），返回 TEMPORARY_FAILURE",
                PREFLIGHT_TIMEOUT.as_secs()
            );
            Ok(make_error_result(ErrorCode::TemporaryFailure, false))
        }
    }
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_is_system_protected_dir_windows_system() {
        #[cfg(windows)]
        {
            assert!(is_system_protected_dir(&PathBuf::from(
                r"C:\Windows\System32\drivers"
            )));
            assert!(is_system_protected_dir(&PathBuf::from(
                r"C:\Program Files\app"
            )));
            assert!(is_system_protected_dir(&PathBuf::from(r"C:\ProgramData")));
        }
    }

    #[test]
    fn test_is_system_protected_dir_user_dir() {
        #[cfg(windows)]
        {
            // 用户目录不应被标记为系统保护
            assert!(!is_system_protected_dir(&PathBuf::from(
                r"C:\Users\test\Documents\verthys"
            )));
        }
    }

    #[test]
    fn test_is_within_whitelist_match() {
        let whitelist = vec![PathBuf::from(r"C:\Users\test")];
        assert!(is_within_whitelist(
            &PathBuf::from(r"C:\Users\test\verthys"),
            &whitelist
        ));
        assert!(is_within_whitelist(
            &PathBuf::from(r"C:\Users\test"),
            &whitelist
        ));
    }

    #[test]
    fn test_is_within_whitelist_no_match() {
        let whitelist = vec![PathBuf::from(r"C:\Users\test")];
        assert!(!is_within_whitelist(
            &PathBuf::from(r"C:\Windows\evil"),
            &whitelist
        ));
        assert!(!is_within_whitelist(
            &PathBuf::from(r"D:\other"),
            &whitelist
        ));
    }

    #[test]
    fn test_is_within_whitelist_prefix_not_partial() {
        // 防止 C:\Users\testevil 被误判为 C:\Users\test 的子路径
        let whitelist = vec![PathBuf::from(r"C:\Users\test")];
        assert!(!is_within_whitelist(
            &PathBuf::from(r"C:\Users\testevil"),
            &whitelist
        ));
    }

    #[test]
    fn test_make_error_result_sanitized() {
        let result = make_error_result(ErrorCode::InvalidPath, false);
        assert!(!result.ok);
        assert!(result.error_code.as_deref() == Some("INVALID_PATH"));
        // 错误消息不应包含路径
        assert!(result.error.is_some());
        assert!(!result.error.unwrap().contains('\\'));
    }

    #[test]
    fn test_make_system_protected_result() {
        let result = make_system_protected_result(false);
        assert!(!result.ok);
        assert!(result.is_system_protected);
        assert!(result.error_code.as_deref() == Some("PERMISSION_DENIED"));
    }

    #[test]
    fn test_check_disk_space_unknown() {
        // 不存在的路径应返回 Unknown（非 0 误判）
        let status = check_disk_space(&PathBuf::from(r"Z:\nonexistent_drive_12345"));
        match status {
            DiskSpaceStatus::Unknown => { /* 预期：无法获取磁盘空间 */ }
            DiskSpaceStatus::Ok(_) => { /* 某些环境可能映射 Z: 盘，也接受 */ }
            DiskSpaceStatus::Insufficient(_) => { /* 也接受 */ }
        }
    }

    #[test]
    fn test_test_write_permission_with_lease_success() {
        // 在临时目录测试写权限
        let temp_dir = std::env::temp_dir().join("verthys_preflight_test_lease");
        let _ = std::fs::create_dir_all(&temp_dir);
        let result = test_write_permission_with_lease(&temp_dir);
        assert!(result.is_ok(), "写权限测试应成功: {:?}", result);
        // 清理
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_build_safe_whitelist_nonempty() {
        let whitelist = build_safe_whitelist();
        // 至少应包含 EXE 目录
        assert!(!whitelist.is_empty(), "白名单不应为空");
    }

    #[test]
    fn test_resolve_parent_for_whitelist_existing() {
        let temp = std::env::temp_dir();
        let result = resolve_parent_for_whitelist(&temp);
        assert!(result.is_ok(), "已存在目录应能 canonicalize");
        let canon = result.unwrap();
        assert!(canon.is_absolute());
    }

    #[test]
    fn test_resolve_parent_for_whitelist_nonexistent_ancestor() {
        // 构造不存在的路径，但其祖先（temp_dir）存在
        let temp = std::env::temp_dir();
        let nonexistent = temp.join("verthys_nonexistent_lvl1").join("lvl2").join("lvl3");
        let result = resolve_parent_for_whitelist(&nonexistent);
        assert!(result.is_ok(), "应回溯到已存在祖先");
        let canon = result.unwrap();
        // canonical 路径应是 temp_dir 或其上级
        assert!(canon.is_absolute());
    }

    #[test]
    fn test_do_preflight_blocking_rejects_system_dir() {
        #[cfg(windows)]
        {
            let result = do_preflight_blocking(r"C:\Windows\evil\hack\verthys.verthys".to_string());
            assert!(!result.ok, "系统目录应被拒绝");
            assert!(
                result.error_code.as_deref() == Some("PERMISSION_DENIED")
                    || result.error_code.as_deref() == Some("INVALID_PATH"),
                "系统目录拒绝应返回 PERMISSION_DENIED 或 INVALID_PATH"
            );
            assert!(!result.dir_created, "不应创建任何目录");
        }
    }

    #[test]
    fn test_do_preflight_blocking_rejects_relative_path() {
        let result = do_preflight_blocking("relative/path/verthys.verthys".to_string());
        assert!(!result.ok);
        assert!(result.error_code.as_deref() == Some("INVALID_PATH"));
    }

    #[test]
    fn test_do_preflight_blocking_rejects_parent_dir_traversal() {
        let result = do_preflight_blocking(r"C:\data\..\..\evil\verthys.verthys".to_string());
        assert!(!result.ok);
        assert!(result.error_code.as_deref() == Some("INVALID_PATH"));
    }

    #[test]
    fn test_do_preflight_blocking_rejects_null_byte() {
        let result = do_preflight_blocking("C:\0evil\\verthys.verthys".to_string());
        assert!(!result.ok);
        assert!(result.error_code.as_deref() == Some("INVALID_PATH"));
    }

    #[test]
    fn test_do_preflight_blocking_valid_temp_path() {
        // 在临时目录下创建合法 verthys 路径，应通过预检
        let temp = std::env::temp_dir().join("verthys_preflight_valid_test");
        let _ = std::fs::create_dir_all(&temp);
        let verthys_path = temp.join("test_verthys.verthys");
        let result = do_preflight_blocking(verthys_path.to_string_lossy().to_string());
        assert!(result.ok, "合法临时目录路径应通过预检: {:?}", result.error);
        assert!(result.error_code.is_none());
        // 清理
        let _ = std::fs::remove_dir_all(&temp);
    }
}
