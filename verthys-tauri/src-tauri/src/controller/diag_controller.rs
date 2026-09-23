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