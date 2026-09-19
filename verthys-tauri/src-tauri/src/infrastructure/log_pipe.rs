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
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

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
    /// 后台消费线程句柄
    consumer_handle: std::sync::Mutex<Option<thread::JoinHandle<()>>>,
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
        let (sender, receiver) = bounded::<LogEntry>(capacity);

        let handle = thread::Builder::new()
            .name("log-consumer".to_string())
            .spawn(move || Self::consumer_loop(receiver, log_path))
            .expect("启动日志消费后台线程失败");

        let inner = LogDaemonInner {
            sender,
            shutdown_called: AtomicBool::new(false),
            consumer_handle: std::sync::Mutex::new(Some(handle)),
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
    /// 文件写入失败会尝试重新打开句柄，主路径失效自动降级临时目录文件
    fn consumer_loop(receiver: Receiver<LogEntry>, log_path: PathBuf) {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        // 主文件打开失败，降级到系统临时目录备用日志
        if file.is_none() {
            let fallback = std::env::temp_dir().join(
                log_path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("verthys_fallback.log")),
            );
            let _ = std::fs::create_dir_all(fallback.parent().unwrap());
            file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&fallback)
                .ok();

            #[cfg(windows)]
            output_debug_string(&format!("主日志文件打开失败，降级路径：{}", fallback.display()));
        }

        while let Ok(entry) = receiver.recv() {
            let Ok(json_str) = serde_json::to_string(&entry) else {
                continue;
            };
            let line = format!("{}\n", json_str);

            match &mut file {
                Some(f) => {
                    if f.write_all(line.as_bytes()).is_err() {
                        file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&log_path)
                            .ok();
                    }
                }
                None => {
                    file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                        .ok();
                    if let Some(f) = &mut file {
                        let _ = f.write_all(line.as_bytes());
                    }
                }
            }
        }

        // 通道关闭，强制刷盘
        if let Some(f) = &mut file {
            let _ = f.flush();
        }
    }
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
    pub(crate) fn new(sender: Sender<LogEntry>) -> Self {
        Self { sender }
    }

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
        entry.timestamp, entry.level.as_str(), entry.pid, entry.module, entry.message
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
}