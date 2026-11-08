/*
 * @file infrastructure/log_pipe.rs
 * @brief 异步结构化日志管道与后台守护线程封装
 *
 * 强制架构规则（代码评审准入约束）
 * 1. 单队列唯一实例：单个进程仅创建一条有界消息队列承载全部日志，统一由单一线程消费落地磁盘；
 * 2. 业务线程零阻塞：日志写入IO全部交由独立后台线程处理，生产端仅做入队操作，不阻塞主业务流程；
 * 3. 禁止全局静态变量：日志发送句柄不做全局静态单例，必须在程序入口实例化后存入上下文，逐层参数注入传递；
 * 4. 禁止内存缓存日志：日志产生时立即投递至队列，任何层级不做内存暂存、批量拼接、延迟发送。
 *
 * 分层日志调用权限约束
 * - 底层工具层、数据持久层：无直接打印日志权限，仅通过Result错误载体向上返回异常信息；
 * - 服务层、控制器层：不直接调用日志发送接口，仅封装错误上下文继续向上抛出；
 * - 程序入口、全局异常捕获处理器：唯一允许调用日志发送接口的代码层级。
 *
 * 投递策略规则
 * 1. 普通级别日志（Trace/Debug/Info/Warn）：非阻塞投递，队列满载直接丢弃，优先保证业务吞吐量；
 * 2. 严重级别日志（Error/Fatal）：可靠投递，队列拥堵时短时阻塞等待，超时无法入队则降级输出兜底，保证关键错误不丢失；
 * 文件容错降级规则
 * 主日志路径文件无法打开/写入时，自动切换至系统临时目录备用日志文件，避免日志完全丢失。
 */
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

/// 应用日志大小轮转策略
///
/// 审计日志（`audit.log`）是 HMAC 链式防篡改文件，不在本策略范围内；
/// 本策略只约束 `logs/<process>.log` 的结构化应用日志。
#[derive(Debug, Clone, Copy)]
pub struct LogRotation {
    /// 单个日志文件达到该字节数后轮转
    pub max_bytes: u64,
    /// 保留的历史文件数量（不含当前文件）
    pub keep_files: usize,
}

impl Default for LogRotation {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            keep_files: 4,
        }
    }
}

/// 日志等级，JSON序列化为大写字符串，区分不同投递策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

impl LogLevel {
    /// 等级字符串标识
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        }
    }

    /// 是否为需要可靠投递的严重日志
    #[cfg(test)]
    fn is_critical(&self) -> bool {
        matches!(self, LogLevel::Error | LogLevel::Fatal)
    }
}

/// 单条结构化日志条目，最终以单行JSON格式写入日志文件
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    /// ISO 8601 UTC时间戳
    pub timestamp: String,
    /// 日志等级
    pub level: LogLevel,
    /// 当前进程PID
    pub pid: u32,
    /// 日志来源模块名
    pub module: String,
    /// 日志内容
    pub message: String,
}

impl LogEntry {
    /// 快速构建日志条目，自动填充时间戳与进程号
    pub fn new(level: LogLevel, module: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level,
            pid: std::process::id(),
            module: module.into(),
            message: message.into(),
        }
    }
}

/// 守护器内部共享状态，通过Arc实现多线程安全克隆
struct LogDaemonInner {
    sender: Sender<LogEntry>,
    /// 防止重复执行关闭流程
    shutdown_called: AtomicBool,
}

/// 日志守护器顶层对象，管理队列与后台写入线程生命周期
/// 生命周期规范：入口创建 -> 发送句柄注入上下文 -> 退出前主动排空队列关闭
pub struct LogDaemon {
    inner: Arc<LogDaemonInner>,
}

impl LogDaemon {
    /// 创建日志守护器并启动后台IO消费线程
    /// capacity：有界队列容量；log_path：日志最终落盘路径
    pub fn new(capacity: usize, log_path: PathBuf) -> Self {
        Self::new_with_rotation(capacity, log_path, LogRotation::default())
    }

    /// 创建日志守护器并指定轮转策略（测试注入小阈值，生产使用默认值）
    pub(crate) fn new_with_rotation(
        capacity: usize,
        log_path: PathBuf,
        rotation: LogRotation,
    ) -> Self {
        let (sender, receiver) = bounded::<LogEntry>(capacity);

        thread::Builder::new()
            .name("log-consumer".to_string())
            .spawn(move || Self::consumer_loop(receiver, log_path, rotation))
            .expect("启动日志消费后台线程失败");

        let inner = LogDaemonInner {
            sender,
            shutdown_called: AtomicBool::new(false),
        };

        Self {
            inner: Arc::new(inner),
        }
    }

    /// 获取可克隆的日志发送端，用于注入上下文向下传递
    pub fn sender(&self) -> LogSender {
        LogSender {
            sender: self.inner.sender.clone(),
        }
    }

    /// 刷新队列并安全关闭，等待积压日志全部消费完毕
    /// 因队列通道需所有发送端销毁才会关闭，此处采用轮询判断队列为空作为排空依据
    /// 超时未消费完成则做兜底告警输出，返回true代表正常排空
    pub fn flush_and_shutdown(&self, timeout: Duration) -> bool {
        if self.inner.shutdown_called.swap(true, Ordering::SeqCst) {
            return true;
        }

        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.inner.sender.is_empty() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }

        #[cfg(windows)]
        {
            let remain = self.inner.sender.len();
            output_debug_string(&format!("日志刷新超时，仍有{}条日志未完成写入", remain));
        }
        false
    }

    /// 后台消费循环：持续读取队列、序列化JSON、追加写入文件
    /// 文件写入失败会尝试重新打开句柄，主路径失效自动降级临时目录文件；
    /// 达到轮转阈值时关闭句柄、滚动历史文件后重新打开当前文件。
    fn consumer_loop(receiver: Receiver<LogEntry>, log_path: PathBuf, rotation: LogRotation) {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut active_path = log_path.clone();
        let mut file = open_append(&active_path);
        let mut written = file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|m| m.len())
            .unwrap_or(0);

        // 主文件打开失败，降级到系统临时目录备用日志
        if file.is_none() {
            active_path = fallback_log_path(&log_path);
            file = open_append(&active_path);
            written = file
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .map(|m| m.len())
                .unwrap_or(0);

            #[cfg(windows)]
            output_debug_string(&format!(
                "主日志文件打开失败，降级路径：{}",
                active_path.display()
            ));
        }

        while let Ok(entry) = receiver.recv() {
            let Ok(json_str) = serde_json::to_string(&entry) else {
                continue;
            };
            let line = format!("{}\n", json_str);

            // 写入前轮转：保留当前文件历史，避免单文件无限增长
            if rotation.max_bytes > 0
                && written > 0
                && written.saturating_add(line.len() as u64) > rotation.max_bytes
            {
                // 先释放当前句柄：Windows 不允许重命名打开中的文件
                drop(file.take());
                if rotate_log(&active_path, rotation.keep_files) {
                    written = 0;
                }
                file = open_append(&active_path);
            }

            if file.is_none() {
                file = open_append(&active_path);
                if file.is_none() && active_path != log_path {
                    file = open_append(&log_path);
                    if file.is_some() {
                        active_path = log_path.clone();
                        written = file
                            .as_ref()
                            .and_then(|f| f.metadata().ok())
                            .map(|m| m.len())
                            .unwrap_or(0);
                    }
                }
                if file.is_none() {
                    let fallback = fallback_log_path(&log_path);
                    file = open_append(&fallback);
                    if file.is_some() {
                        active_path = fallback;
                        written = file
                            .as_ref()
                            .and_then(|f| f.metadata().ok())
                            .map(|m| m.len())
                            .unwrap_or(0);
                    }
                }
            }

            if let Some(f) = &mut file {
                if f.write_all(line.as_bytes()).is_ok() {
                    written = written.saturating_add(line.len() as u64);
                } else {
                    file = None;
                }
            }
        }

        // 通道关闭，强制刷盘
        if let Some(f) = &mut file {
            let _ = f.flush();
        }
    }
}

/// 打开追加写日志文件；失败返回 None 由调用方降级
fn open_append(path: &Path) -> Option<std::fs::File> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// 主路径不可写时的临时目录备用文件
fn fallback_log_path(log_path: &Path) -> PathBuf {
    std::env::temp_dir().join(
        log_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("verthys_fallback.log")),
    )
}

/// 滚动日志文件：`app.log` → `app.1.log` → `app.2.log` …
///
/// 调用方必须先关闭当前文件句柄（Windows 不允许重命名打开中的文件）。
/// 返回 true 表示当前文件已成功转为历史文件；失败时调用方应继续追加当前文件，
/// 不因轮转失败丢失任何日志。
fn rotate_log(path: &Path, keep_files: usize) -> bool {
    if !path.exists() {
        return false;
    }
    if keep_files == 0 {
        return std::fs::remove_file(path).is_ok();
    }

    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("log");
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("log");
    let rotated = |index: usize| {
        path.with_file_name(format!("{}.{}.{}", stem, index, ext))
    };

    let _ = std::fs::remove_file(rotated(keep_files));
    for index in (1..keep_files).rev() {
        let from = rotated(index);
        if from.exists() {
            let _ = std::fs::rename(from, rotated(index + 1));
        }
    }
    std::fs::rename(path, rotated(1)).is_ok()
}

impl Clone for LogDaemon {
    fn clone(&self) -> Self {
        LogDaemon {
            inner: self.inner.clone(),
        }
    }
}

/// 日志发送句柄，对外唯一投递入口，遵循注入式传递原则
#[derive(Clone)]
pub struct LogSender {
    sender: Sender<LogEntry>,
}

impl LogSender {
    /// 可丢弃非阻塞发送：普通级别日志使用，队列满直接丢弃不阻塞业务
    pub fn send_allow_drop(&self, entry: LogEntry) -> Result<(), TrySendError<LogEntry>> {
        self.sender.try_send(entry)
    }

    /// 旧接口兼容别名
    pub fn try_send(&self, entry: LogEntry) -> Result<(), TrySendError<LogEntry>> {
        self.send_allow_drop(entry)
    }

    /// 可靠不丢失发送：Error/Fatal级别专用
    /// 队列拥堵时异步线程阻塞投递，1秒超时未完成则降级兜底输出，杜绝关键日志丢失
    pub fn send_guaranteed(&self, entry: LogEntry) {
        match self.sender.try_send(entry.clone()) {
            Ok(()) => return,
            Err(TrySendError::Disconnected(_)) => {
                output_debug_string_fallback(&entry);
                return;
            }
            Err(TrySendError::Full(_)) => {}
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let s_clone = self.sender.clone();
        let e_clone = entry.clone();
        let _ = thread::Builder::new()
            .name("log-reliable-worker".to_string())
            .spawn(move || {
                let _ = s_clone.send(e_clone);
                let _ = tx.send(());
            });

        if rx.recv_timeout(Duration::from_secs(1)).is_err() {
            output_debug_string_fallback(&entry);
        }
    }

    /// 旧版阻塞发送兼容方法，用于panic钩子等存量调用点
    pub fn send(&self, entry: LogEntry) -> Result<(), crossbeam_channel::SendError<LogEntry>> {
        match self.sender.try_send(entry.clone()) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => self.sender.send(entry),
            Err(TrySendError::Disconnected(_)) => {
                output_debug_string_fallback(&entry);
                Err(crossbeam_channel::SendError(entry))
            }
        }
    }

    // 各等级快捷封装方法
    pub fn info(&self, module: &str, message: impl Into<String>) {
        let _ = self.send_allow_drop(LogEntry::new(LogLevel::Info, module, message));
    }

    pub fn error(&self, module: &str, message: impl Into<String>) {
        self.send_guaranteed(LogEntry::new(LogLevel::Error, module, message));
    }

    pub fn warn(&self, module: &str, message: impl Into<String>) {
        let _ = self.send_allow_drop(LogEntry::new(LogLevel::Warn, module, message));
    }

    pub fn debug(&self, module: &str, message: impl Into<String>) {
        let _ = self.send_allow_drop(LogEntry::new(LogLevel::Debug, module, message));
    }

    pub fn fatal(&self, module: &str, message: impl Into<String>) {
        self.send_guaranteed(LogEntry::new(LogLevel::Fatal, module, message));
    }
}

// 底层调试输出兼容函数
#[cfg(windows)]
fn output_debug_string(msg: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;

    let wide: Vec<u16> = std::ffi::OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe { OutputDebugStringW(PCWSTR(wide.as_ptr())) };
}

#[cfg(not(windows))]
fn output_debug_string(msg: &str) {
    eprintln!("{}", msg);
}

/// 队列不可用时，严重日志格式化后降级输出
fn output_debug_string_fallback(entry: &LogEntry) {
    let text = format!(
        "[{}][{}] pid:{} | {} | {}",
        entry.timestamp,
        entry.level.as_str(),
        entry.pid,
        entry.module,
        entry.message
    );
    output_debug_string(&text);
}

// 过渡期兼容别名，后续迭代可整体删除
pub struct LogPipe {
    daemon: LogDaemon,
}

impl LogPipe {
    pub fn new(capacity: usize, log_path: PathBuf) -> Self {
        Self {
            daemon: LogDaemon::new(capacity, log_path),
        }
    }

    pub fn sender(&self) -> LogSender {
        self.daemon.sender()
    }

    pub fn join(self) {
        let _ = self.daemon.flush_and_shutdown(Duration::from_secs(5));
    }

    pub fn flush_and_shutdown(&self, timeout: Duration) -> bool {
        self.daemon.flush_and_shutdown(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_log_write() {
        let tmp = std::env::temp_dir().join(format!("log_test_{}.log", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let daemon = LogDaemon::new(64, tmp.clone());
        let sender = daemon.sender();

        sender.info("test_mod", "正常信息日志");
        sender.error("test_mod", "错误级别日志");

        thread::sleep(Duration::from_millis(200));
        assert!(daemon.flush_and_shutdown(Duration::from_secs(2)));

        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        assert!(content.contains("正常信息日志"));
        assert!(content.contains("错误级别日志"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_critical_level_mark() {
        assert!(!LogLevel::Warn.is_critical());
        assert!(LogLevel::Error.is_critical());
        assert!(LogLevel::Fatal.is_critical());
    }

    #[test]
    fn test_log_entry_build() {
        let e = LogEntry::new(LogLevel::Debug, "core", "test msg");
        assert_eq!(e.level, LogLevel::Debug);
        assert_eq!(e.module, "core");
    }

    #[test]
    fn test_log_rotation_bounds_file_count() {
        let dir = std::env::temp_dir().join(format!(
            "verthys_log_rotation_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("main.log");
        let rotation = LogRotation {
            max_bytes: 200,
            keep_files: 2,
        };
        let daemon = LogDaemon::new_with_rotation(128, log_path.clone(), rotation);
        let sender = daemon.sender();

        for index in 0..20 {
            sender.info("rotation", format!("message-{index}-{}", "x".repeat(40)));
        }
        thread::sleep(Duration::from_millis(200));
        assert!(daemon.flush_and_shutdown(Duration::from_secs(2)));
        // 队列清空不代表消费线程已写完最后一行；留出落盘窗口
        thread::sleep(Duration::from_millis(100));

        let logs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("log"))
            .collect();
        // 当前文件 + 两个历史文件；更老的已删除
        assert_eq!(logs.len(), 3, "轮转后文件数应受 keep_files 约束: {logs:?}");
        assert!(log_path.exists(), "当前文件必须继续存在");
        assert!(dir.join("main.1.log").exists(), "最近历史文件必须存在");
        assert!(dir.join("main.2.log").exists(), "第二历史文件必须存在");
        assert!(
            !dir.join("main.3.log").exists(),
            "超出 keep_files 的历史文件必须被删除"
        );

        let current = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            current.lines().all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()),
            "轮转不得破坏 JSON 行结构"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_rotate_log_keep_zero_truncates() {
        let dir = std::env::temp_dir().join(format!(
            "verthys_log_rotation_zero_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        std::fs::write(&path, b"payload").unwrap();
        assert!(rotate_log(&path, 0));
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
