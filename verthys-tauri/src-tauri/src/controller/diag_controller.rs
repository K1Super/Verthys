/*
 * @file controller/diag_controller.rs
 * @brief 诊断信息控制器 - 提供系统运行状态摘要
 *
 * 本模块提供轻量级诊断接口，用于健康检查或故障排查，返回关键组件存在性
 * 和运行状态，但不暴露具体路径等敏感信息。
 *
 * =============================================================================
 * 设计意图
 * =============================================================================
 * - 诊断信息用于判断 worker 可执行文件、加密库 DLL 是否可访问，以及
 *   worker 子进程是否存活。
 * - 为避免信息泄露，不返回任何绝对路径或工作目录，仅以布尔值和哈希
 *   前缀替代完整路径内容。
 * - DLL 哈希返回前 16 个字符，足以区分版本差异，但不提供完整哈希值，
 *   降低被用于碰撞攻击的风险。
 *
 * =============================================================================
 * 安全约束
 * =============================================================================
 * - 不返回路径、进程 ID 以外的任何具体标识（worker_pid 可被外部感知，
 *   属于正常诊断范畴）。
 * - 所有路径解析失败均静默转换为 false，不暴露解析过程的具体错误。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → state / infrastructure::path_resolver / controller::types
 */

use crate::controller::types::DiagInfo;
use crate::infrastructure::path_resolver::{
    get_dll_hash_prefix, resolve_dll_path, resolve_worker_path,
};
use crate::state::AppState;
use tauri::State;

/// 返回诊断摘要，包括 worker 和 DLL 是否存在、worker 是否运行、
/// 以及 DLL 哈希前缀（仅前 16 字符）。
///
/// 路径解析仅用于判断存在性，不返回路径本身。
/// DLL 哈希前缀用于版本识别，不提供完整哈希。
/// worker_pid 当前为占位，后续由状态填充。
#[tauri::command]
pub fn diag_info(app: tauri::AppHandle, state: State<AppState>) -> Result<DiagInfo, String> {
    let worker_exists = resolve_worker_path(&app)
        .map(|p| std::path::Path::new(&p).exists())
        .unwrap_or(false);
    let dll_exists = resolve_dll_path(&app)
        .map(|p| std::path::Path::new(&p).exists())
        .unwrap_or(false);
    let worker_running = state.has_session();

    Ok(DiagInfo {
        worker_exists,
        dll_exists,
        worker_running,
        dll_hash: get_dll_hash_prefix(),
        worker_pid: None,
    })
}

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