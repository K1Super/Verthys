/*
 * @file controller/diag_controller.rs
 * @brief 诊断信息控制器 - 前端致命错误上报通道
 *
 * 本模块提供前端致命错误上报接收端。
 */

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
