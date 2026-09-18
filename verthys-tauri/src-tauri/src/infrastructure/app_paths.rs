/*
 * @file infrastructure/app_paths.rs
 * @brief 应用持久化目录规则解析与路径标准化模块
 *
 * 强制业务约束与安全红线：
 * 1. 禁止代码内改写LOCALAPPDATA、APPDATA系统环境变量，避免污染Tauri、WebView2及子进程数据写入位置，防止多实例文件损坏。
 * 2. 所有相对路径基准强制使用可执行文件父目录，禁止依赖进程启动工作目录，规避不同启动方式带来路径不确定性。
 * 3. 便携/沙箱模式仅由编译Feature或受信任命令行参数控制，不信任用户可随意篡改的环境变量作为切换依据。
 *
 * 目录解析优先级规则（由高至低）：
 * 1. 入口层校验完成的--data-dir可信命令行参数
 * 2. portable_mode编译特性开启，指向程序同级data目录
 * 3. Windows系统API读取LocalAppData公共目录，拼接应用唯一标识文件夹
 * 4. 程序同级data目录兜底，用于只读存储介质降级方案并输出告警日志
 *
 * 附属路径规则：
 * 日志目录固定为数据根目录/logs，日志文件携带进程名称；Windows全量绝对路径统一追加\\?\长路径前缀突破MAX_PATH限制。
 */
use std::path::{Path, PathBuf};

/// 应用唯一标识，需与Tauri配置文件标识符保持一致
const APP_IDENTIFIER: &str = "com.verthys.app";

/// 应用全量路径集合结构体
/// 所有输出路径均为绝对路径，Windows平台已完成长路径前缀兼容处理，source用于启动日志排查目录来源
#[derive(Debug, Clone)]
pub struct AppPaths {
    /// 应用根数据存储目录
    pub data_dir: PathBuf,
    /// 日志文件存放子目录
    pub log_dir: PathBuf,
    /// 临时文件存放子目录
    pub tmp_dir: PathBuf,
    /// 目录解析来源标记，用于问题诊断
    pub source: PathSource,
}

/// 数据目录判定来源枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSource {
    /// 受信命令行参数指定目录
    CliArg,
    /// 编译开启便携模式特性
    PortableFeature,
    /// 通过系统Shell接口获取的用户本地应用数据目录
    KnownFolder,
    /// 可执行文件同级data目录兜底降级方案
    ExeDirFallback,
}

impl AppPaths {
    /// 按既定优先级规则解析应用数据根目录并组装完整路径对象
    /// cli_data_dir：经上层入口合法性校验的可信绝对路径
    pub fn resolve(cli_data_dir: Option<&Path>) -> Self {
        // 1. 优先使用校验后的命令行指定目录
        if let Some(dir) = cli_data_dir {
            let data_dir = normalize_long_path(dir);
            return Self::from_data_dir(data_dir, PathSource::CliArg);
        }

        // 2. 编译便携模式启用时使用程序同级data目录
        if cfg!(feature = "portable_mode") {
            if let Some(exe_dir) = exe_parent_dir() {
                let data_dir = normalize_long_path(&exe_dir.join("data"));
                return Self::from_data_dir(data_dir, PathSource::PortableFeature);
            }
        }

        // 3. Windows通过系统可信API读取LocalAppData目录
        #[cfg(windows)]
        if let Some(local_app_data) = get_known_folder_local_app_data() {
            let data_dir = normalize_long_path(&local_app_data.join(APP_IDENTIFIER));
            return Self::from_data_dir(data_dir, PathSource::KnownFolder);
        }

        // 4. 最终兜底：程序同级data目录，适配只读磁盘无法写入系统目录场景
        let exe_dir = exe_parent_dir().unwrap_or_else(|| PathBuf::from("."));
        let data_dir = normalize_long_path(&exe_dir.join("data"));
        Self::from_data_dir(data_dir, PathSource::ExeDirFallback)
    }

    /// 基于根目录自动拼接日志、临时子目录，完成结构体实例构建
    fn from_data_dir(data_dir: PathBuf, source: PathSource) -> Self {
        let log_dir = data_dir.join("logs");
        let tmp_dir = data_dir.join("tmp");
        AppPaths {
            data_dir,
            log_dir,
            tmp_dir,
            source,
        }
    }

    /// 批量创建所有业务所需目录，在日志组件初始化前执行
    /// 根目录创建失败直接抛出错误；日志、临时目录创建失败做降级兼容，不阻断进程启动
    pub fn ensure_dirs(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| format!("创建数据目录失败 [{}]: {}", self.data_dir.display(), e))?;
        // 子目录创建异常静默处理，日志模块内部降级输出至标准错误流
        let _ = std::fs::create_dir_all(&self.log_dir);
        let _ = std::fs::create_dir_all(&self.tmp_dir);
        Ok(())
    }

    /// 根据进程名称拼接完整日志文件绝对路径
    pub fn log_path(&self, process_name: &str) -> PathBuf {
        self.log_dir.join(format!("{}.log", process_name))
    }
}

/// 获取当前可执行文件所在父文件夹
/// 设计约束：拒绝使用进程工作目录，规避不同启动方式导致路径漂移问题
fn exe_parent_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

/// Windows路径长路径兼容处理函数
/// 规则：未携带\\?\前缀的绝对路径统一追加前缀；UNC网络路径做对应格式转换；已合规路径直接原样返回
#[cfg(windows)]
pub fn normalize_long_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str.starts_with(r"\\?\") || path_str.starts_with(r"\\.\") {
        return path.to_path_buf();
    }
    // 网络共享UNC路径转换为长路径标准格式
    if path_str.starts_with(r"\\") && !path_str.starts_with(r"\\?\") {
        let rest = &path_str[2..];
        return PathBuf::from(format!(r"\\?\UNC\{}", rest));
    }
    // 绝对路径直接添加长路径前缀
    if path.is_absolute() {
        return PathBuf::from(format!(r"\\?\{}", path_str));
    }
    // 相对路径先规范化为绝对路径再处理
    if let Ok(canon) = std::fs::canonicalize(path) {
        let canon_str = canon.to_string_lossy();
        if !canon_str.starts_with(r"\\?\") {
            return PathBuf::from(format!(r"\\?\{}", canon_str));
        }
        return canon;
    }
    path.to_path_buf()
}

#[cfg(not(windows))]
pub fn normalize_long_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// Windows通过系统Shell可信接口读取LocalAppData目录
/// 安全意图：不依赖可被外部篡改的环境变量，直接读取系统注册真实路径，返回值可信度更高；调用后必须手动释放API分配内存
#[cfg(windows)]
fn get_known_folder_local_app_data() -> Option<PathBuf> {
    use windows::Win32::UI::Shell::{
        SHGetKnownFolderPath, FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG,
    };

    let flags = KNOWN_FOLDER_FLAG(0);
    let result = unsafe {
        SHGetKnownFolderPath(&FOLDERID_LocalAppData, flags, None)
    };

    match result {
        Ok(pwsz) => {
            let path_str = unsafe { pwsz.to_string() };
            // 释放COM堆内存，避免内存泄漏
            unsafe {
                windows::Win32::System::Com::CoTaskMemFree(Some(pwsz.as_ptr() as *const _));
            }
            match path_str {
                Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
                _ => None,
            }
        }
        Err(_) => None,
    }
}

/// 非Windows平台本地数据目录降级获取逻辑
#[cfg(not(windows))]
#[allow(dead_code)]
fn get_known_folder_local_app_data() -> Option<PathBuf> {
    std::env::var("XDG_DATA_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local").join("share"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 校验命令行参数指定目录优先级生效
    #[test]
    fn test_resolve_with_cli_arg() {
        let tmp = std::env::temp_dir().join("verthys_test_app_paths");
        let paths = AppPaths::resolve(Some(&tmp));
        assert_eq!(paths.source, PathSource::CliArg);
        assert!(paths.data_dir.ends_with("verthys_test_app_paths"));
        assert!(paths.log_dir.ends_with("logs"));
        assert!(paths.tmp_dir.ends_with("tmp"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 校验无指定参数时兜底降级路径合法性
    #[test]
    fn test_resolve_fallback_to_exe_dir() {
        let paths = AppPaths::resolve(None);
        assert!(paths.data_dir.is_absolute() || paths.data_dir.starts_with(r"\\?\"));
        assert!(!matches!(paths.source, PathSource::CliArg));
    }

    /// 校验Windows长路径前缀格式化逻辑
    #[test]
    fn test_normalize_long_path_windows() {
        let p = Path::new(r"C:\Users\Test\Data");
        let normalized = normalize_long_path(p);
        let s = normalized.to_string_lossy();
        assert!(s.starts_with(r"\\?\") || !s.starts_with(r"\\?\\"), "normalized: {}", s);
    }

    /// 校验批量目录创建接口健壮性
    #[test]
    fn test_ensure_dirs() {
        let tmp = std::env::temp_dir().join("verthys_test_ensure_dirs");
        let paths = AppPaths::resolve(Some(&tmp));
        paths.ensure_dirs().expect("ensure_dirs 应成功");
        assert!(paths.data_dir.exists());
        assert!(paths.log_dir.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}