/*
 * 扫描共享辅助
 *
 * 职责边界：游标安全存回、审计写入、shm_name 与批次计数校验、批次密钥生成。
 * 全量扫描与摘要扫描共用，禁止各自复制校验逻辑。
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::{VerthysRecordEntry, VerthysSummaryEntry};
use crate::infrastructure::audit::get_audit_hmac_key;
use crate::state::{
    AppState, ScanPipelineState,
};
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};

/// 存回扫描游标：仅当槽位为空时恢复。
///
/// next 处理期间槽位被 take() 为空；若此时并发 scan_open 已安装新会话，
/// 直接写回旧游标会覆盖新 shm_name 导致串台。此处丢弃过期游标，
/// 由旧游标的 Drop 释放其缓冲与预取任务。
pub(super) fn restore_scan_pipeline(state: &AppState, scan: ScanPipelineState<VerthysRecordEntry>) {
    let mut guard = state.lock_scan_state();
    if guard.is_none() {
        *guard = Some(scan);
    } else {
        log::warn!("[scan] 丢弃过期游标恢复：已有新的扫描会话");
    }
}

pub(super) fn restore_summary_scan_pipeline(state: &AppState, scan: ScanPipelineState<VerthysSummaryEntry>) {
    let mut guard = state.lock_scan_summary_state();
    if guard.is_none() {
        *guard = Some(scan);
    } else {
        log::warn!("[scan] 丢弃过期摘要游标恢复：已有新的扫描会话");
    }
}

/* ------------------------------------------------------------------ *
 * shm_name 校验 + 批次校验 + 审计               *
 *                                                                    *
 * 与 key_controller / file_controller 中的审计实现同模式。            *
 * 资源标识哈希化，HMAC 密钥由设备指纹派生，失败不阻塞业务。           *
 * ------------------------------------------------------------------ */

/// 获取审计日志文件路径
pub(super) fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败，跳过审计写入: {}", e);
            None
        }
    }
}

/// 写入扫描操作审计事件（不阻塞业务流程）
///
/// 封装 audit_log::append_audit 的错误处理：
///   - 获取审计日志路径失败 → 跳过
///   - 获取 HMAC 密钥失败 → 跳过
///   - append_audit 失败 → 记录 warning，不传播错误
pub(super) fn write_scan_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    let log_path = match get_audit_log_path(app) {
        Some(p) => p,
        None => return,
    };

    let hmac_key = match get_audit_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let session_id = format!("pid-{}", std::process::id());

    let mut event = AuditEvent::new(event_type, &session_id, "user", result);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入扫描审计事件失败（不阻塞业务）: {}", e);
    }
}

/// shm_name 白名单校验
///
/// 校验 shm_name 匹配 `^[a-zA-Z0-9_\-]{1,64}$`，防止路径注入。
/// 委托到 `constants::shm::is_valid_shm_name`（与 worker 同源定义）。
///
/// 校验失败返回 SHM_CORRUPTED 错误码的 VerthysResponse。
pub(super) fn validate_shm_name(shm_name: &str) -> Result<(), String> {
    use crate::constants::is_valid_shm_name;
    if !is_valid_shm_name(shm_name) {
        log::warn!("[scan] shm_name 校验失败（仅字母/数字/下划线/连字符，1-64 字符）");
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }
    Ok(())
}

/// 批次记录数校验
///
/// 校验实际解析的记录数与 worker 报告的 record_count 一致。
/// 不一致表示共享内存数据损坏（部分记录因边界校验被跳过），
/// 触发熔断：审计 + 通知 worker 重置。
///
/// # 参数
/// - `actual_count`: read_from_shm 返回的 records.len()
/// - `expected_count`: SHM 头部 worker 写入的 record_count
///
/// # 返回
/// - Ok(()): 记录数一致
/// - Err(msg): 不一致，调用方应触发熔断清理
pub(super) fn validate_batch_count(actual_count: usize, expected_count: usize) -> Result<(), String> {
    if actual_count != expected_count {
        log::error!(
            "[scan] 第 2.7 项：批次记录数不一致 actual={} expected={}，触发熔断",
            actual_count,
            expected_count
        );
        return Err(format!(
            "批次记录数不一致（actual={}, expected={}），共享内存数据可能损坏",
            actual_count, expected_count
        ));
    }
    Ok(())
}

/// 生成单批随机 SHM 认证密钥（32 字节 CSPRNG，base64 入 IPC 载荷）
///
/// 每批（open 首批与每轮 fetch）一把独立密钥：请求经匿名父子管道传入
/// worker，worker 以该密钥对 SHM 使用区计算 HMAC 并写尾部认证块；主进程
/// 以同一密钥验签后解析。密钥随批即弃（Zeroizing），无跨批重放面。
pub(super) fn gen_shm_batch_key() -> (zeroize::Zeroizing<[u8; 32]>, String) {
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    crate::util::random::fill_random_bytes(&mut key[..]);
    let encoded = crate::util::base64::base64_encode(&key[..]);
    (key, encoded)
}
