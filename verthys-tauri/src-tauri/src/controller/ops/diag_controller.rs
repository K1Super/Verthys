/*
 * @file controller/diag_controller.rs
 * @brief 诊断信息控制器 - 前端致命错误上报、日志导出与开发期日志尾部读取
 *
 * 本模块提供前端致命错误上报接收端，以及开发悬浮球的诊断入口。
 * 日志尾部读取只在调试构建开放：- 发布态命令存在但直接拒绝，
 * 避免复制整张命令表带来的漂移风险。
 */

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// 单次尾部读取的字节上限：只取文件末尾窗口，避免日志膨胀时整文件读入。
const LOG_TAIL_WINDOW_BYTES: u64 = 256 * 1024;
/// 前端一次最多获取的行数；超出部分按时间截断。
const LOG_TAIL_MAX_LINES: usize = 500;
/// 允许读取的日志来源（与 ProcessMode::process_name 的文件名一致）。
const LOG_PROCESS_NAMES: [&str; 3] = ["main_ui", "worker", "inspector"];

/// 前端致命错误上报通道。
///
/// 生产构建中前端 console 输出被混淆器关闭，未捕获异常只能经本命令
/// 落入后端日志文件；负载为前端组装的结构化 JSON 字符串。
///
/// 约束：入口只做长度截断（按 UTF-8 字符边界对齐），不解析、不改写内容，
/// 防止超长异常堆栈撑爆日志文件；命令不返回错误——上报通道自身失败
/// 由前端调用侧的兜底处理，此处静默尽力而为。
#[tauri::command]
pub fn log_fatal(entry: String) {
    const HARD_MAX_BYTES: usize = 16 * 1024;
    let snippet: String = if entry.len() > HARD_MAX_BYTES {
        let mut end = HARD_MAX_BYTES;
        while end > 0 && !entry.is_char_boundary(end) {
            end -= 1;
        }
        entry[..end].to_string()
    } else {
        entry
    };
    log::error!("[frontend-fatal] {}", snippet);
}

/// 导出应用诊断日志（脱敏 zip）
///
/// 仅打包 `AppPaths.log_dir` 下的普通 `.log` 文件（含轮转历史），导出前
/// 统一脱敏路径与长哈希。审计日志 `audit.log` 是 HMAC 链式文件，不在导出
/// 范围内，也不做轮转。
#[tauri::command]
pub fn diagnostics_export_logs(
    app: tauri::AppHandle,
    target_path: String,
) -> Result<String, String> {
    /* 该入口只服务开发悬浮球；发布态直接拒绝，避免用户侧或外部 IPC 调用。
       采用编译期常量而非条件注册，避免复制整张命令表带来的漂移风险。 */
    if !cfg!(debug_assertions) {
        return Err("诊断导出仅在开发构建可用".to_string());
    }

    use tauri::Manager;
    let paths = app
        .try_state::<crate::infrastructure::app_paths::AppPaths>()
        .ok_or_else(|| "应用数据目录未初始化".to_string())?;
    let audit_log = app
        .path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join("audit.log"));
    crate::infrastructure::log_export::export(
        &paths.log_dir,
        audit_log.as_deref(),
        &target_path,
    )
}

/// 一条展示用日志；时间戳保持写入时的 RFC3339 原文，由前端按本地时区格式化。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevLogLine {
    pub timestamp: String,
    pub level: String,
    pub pid: u32,
    pub module: String,
    pub message: String,
    pub process_name: String,
}

/// 日志尾部读取结果：附日志目录，便于开发面板直接展示与复制。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevLogTail {
    pub log_dir: String,
    pub lines: Vec<DevLogLine>,
}

/// 读取当前构建最近的应用日志尾部。
///
/// process：main_ui / worker / inspector / all；all 会合并三个来源后按时间排序。
/// 只读取每个文件末尾的固定窗口，日志轮转文件不在本入口范围内。
#[tauri::command]
pub fn diagnostics_tail_logs(
    app: tauri::AppHandle,
    process: String,
    max_lines: usize,
) -> Result<DevLogTail, String> {
    /* 与导出入口同一约束：发布态直接拒绝，避免用户侧或外部 IPC 调用。 */
    if !cfg!(debug_assertions) {
        return Err("日志读取仅在开发构建可用".to_string());
    }

    use tauri::Manager;
    let paths = app
        .try_state::<crate::infrastructure::app_paths::AppPaths>()
        .ok_or_else(|| "应用数据目录未初始化".to_string())?;
    tail_logs(&paths.log_dir, &process, max_lines)
}

fn tail_logs(log_dir: &Path, process: &str, max_lines: usize) -> Result<DevLogTail, String> {
    let names: Vec<&str> = match process {
        "all" => LOG_PROCESS_NAMES.to_vec(),
        name if LOG_PROCESS_NAMES.contains(&name) => vec![name],
        other => return Err(format!("未知日志来源: {other}")),
    };
    let limit = max_lines.clamp(1, LOG_TAIL_MAX_LINES);
    let mut lines = Vec::new();

    for name in names {
        let path = log_dir.join(format!("{name}.log"));
        for raw in read_tail_lines(&path)? {
            if let Some(line) = parse_log_line(&raw, name) {
                lines.push(line);
            }
        }
    }

    /* 合并多来源时按写入时间排序；时间戳损坏的记录排到最后。 */
    lines.sort_by_cached_key(|line| timestamp_key(&line.timestamp));
    if lines.len() > limit {
        lines.drain(0..lines.len() - limit);
    }

    Ok(DevLogTail {
        log_dir: log_dir.to_string_lossy().to_string(),
        lines,
    })
}

/// 读取文件末尾窗口并按行切分；文件不存在视为空来源。
fn read_tail_lines(path: &Path) -> Result<Vec<String>, String> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("读取日志失败: {error}")),
    };

    let length = file
        .metadata()
        .map_err(|error| format!("读取日志元数据失败: {error}"))?
        .len();
    let start = length.saturating_sub(LOG_TAIL_WINDOW_BYTES);
    if start > 0 {
        file.seek(SeekFrom::Start(start))
            .map_err(|error| format!("定位日志失败: {error}"))?;
    }

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|error| format!("读取日志内容失败: {error}"))?;
    let text = String::from_utf8_lossy(&buffer);
    let mut lines: Vec<&str> = text.split('\n').collect();
    /* 从窗口中间切入时，首行可能是半条 JSON，直接丢弃。 */
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    lines.retain(|line| !line.trim().is_empty());
    Ok(lines.into_iter().map(str::to_string).collect())
}

#[derive(serde::Deserialize)]
struct RawLogLine {
    timestamp: String,
    level: String,
    pid: u32,
    #[serde(default)]
    module: String,
    message: String,
}

/// 结构化日志为单行 JSON；损坏行（例如进程崩溃时的半行）跳过而不中断读取。
fn parse_log_line(raw: &str, process_name: &str) -> Option<DevLogLine> {
    let parsed: RawLogLine = serde_json::from_str(raw).ok()?;
    Some(DevLogLine {
        timestamp: parsed.timestamp,
        level: parsed.level,
        pid: parsed.pid,
        module: parsed.module,
        message: parsed.message,
        process_name: process_name.to_string(),
    })
}

fn timestamp_key(value: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp_millis())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    fn log_line(timestamp: &str, level: &str, message: &str) -> String {
        format!(
            r#"{{"timestamp":"{timestamp}","level":"{level}","pid":42,"module":"test","message":"{message}"}}"#
        )
    }

    #[test]
    fn tail_reads_valid_lines_and_orders_by_time() {
        let dir = unique_temp_dir("verthys-log-tail");
        std::fs::create_dir_all(&dir).expect("create log dir");
        let late = log_line("2026-11-26T10:00:02Z", "ERROR", "late");
        let early = log_line("2026-11-26T10:00:01Z", "INFO", "early");
        std::fs::write(dir.join("main_ui.log"), format!("{late}\n{early}\n")).expect("write log");

        let tail = tail_logs(&dir, "main_ui", 10).expect("tail logs");
        assert_eq!(tail.lines.len(), 2);
        assert_eq!(tail.lines[0].message, "early");
        assert_eq!(tail.lines[1].level, "ERROR");
        assert_eq!(tail.lines[1].process_name, "main_ui");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_skips_malformed_lines_and_missing_files() {
        let dir = unique_temp_dir("verthys-log-tail-skip");
        std::fs::create_dir_all(&dir).expect("create log dir");
        let valid = log_line("2026-11-26T10:00:00Z", "INFO", "valid");
        std::fs::write(dir.join("worker.log"), format!("{valid}\nnot-json\n")).expect("write log");

        let tail = tail_logs(&dir, "worker", 10).expect("tail logs");
        assert_eq!(tail.lines.len(), 1);
        assert_eq!(tail.lines[0].message, "valid");

        let empty = tail_logs(&dir, "inspector", 10).expect("missing file is empty");
        assert!(empty.lines.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_clamps_lines_and_rejects_unknown_source() {
        let dir = unique_temp_dir("verthys-log-tail-clamp");
        std::fs::create_dir_all(&dir).expect("create log dir");
        let mut content = String::new();
        for index in 0..5 {
            content.push_str(&log_line(
                &format!("2026-11-26T10:00:0{index}Z"),
                "INFO",
                &format!("line-{index}"),
            ));
            content.push('\n');
        }
        std::fs::write(dir.join("main_ui.log"), content).expect("write log");

        let tail = tail_logs(&dir, "main_ui", 2).expect("tail logs");
        assert_eq!(tail.lines.len(), 2);
        assert_eq!(tail.lines[1].message, "line-4");

        assert!(tail_logs(&dir, "unknown", 10).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
