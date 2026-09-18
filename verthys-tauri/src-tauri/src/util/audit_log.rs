/*
 * util/audit_log.rs — HMAC 链式防篡改审计日志
 *
 *    "" 第 5.8 项 / 第 6.6 项 / 第 7.6 项 / 第 9.8 项 / 第 13.7 项 / 第 16.5 项
 *
 * 架构定位：工具层（util）审计日志模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 仅依赖 util::crypto（HMAC）与 std::fs（追加写入）
 *   - 每条审计事件独立写入文件，HMAC 链式校验防篡改
 *
 * 设计原则：
 *   - 追加写入：审计日志只追加，不修改/删除已写入条目
 *   - HMAC 链式：每条记录的 HMAC 包含前一条的 HMAC，形成链式结构
 *     篡改任意一条记录将导致后续所有记录的 HMAC 校验失败
 *   - 资源标识哈希化：路径/名称等敏感标识以 SHA-256 哈希形式记录
 *     不存原始路径，防止日志泄露用户隐私
 *   - 不含敏感数据：密码/密钥/明文内容不写入审计日志
 *
 * 审计事件覆盖范围：
 *   - 第 5.8 项：密钥操作（派生/验证/清空）
 *   - 第 6.6 项：文件读写操作
 *   - 第 7.6 项：剪贴板模式变更/清空/监听事件
 *   - 第 9.8 项：状态文件创建/修改/修复/删除
 *   - 第 13.7 项：安全命令执行
 *   - 第 16.5 项：verthys 解锁/锁定/container_id 不匹配
 *
 * CI 红线：
 *   - 本文件不输出 log::* 调用（审计日志独立于应用日志）
 *   - 失败时返回 Err，不静默丢弃审计事件
 *   - HMAC 密钥由调用方管理，本模块不存储密钥
 */

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

// ===== 审计事件类型 =====

/// 审计事件类型
///
/// 覆盖所有需要审计的安全相关操作。
/// 前端不直接消费此枚举，仅用于后端日志记录。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AuditEventType {
    // 密钥操作（第 5.8 项）
    KeyDerive,
    KeyVerify,
    KeyClear,
    // 文件操作（第 6.6 项）
    FileRead,
    FileWrite,
    FileDelete,
    // 剪贴板操作（第 7.6 项）
    ClipboardClear,
    ClipboardModeChange,
    ClipboardMonitorEvent,
    // 状态文件操作（第 9.8 项）
    StateCreate,
    StateModify,
    StateRepair,
    StateDelete,
    // 安全命令（第 13.7 项）
    SecurityCommand,
    SecureDelete,
    HardenPrivateDir,
    CleanupCrashResidue,
    // Verthys 操作（第 16.5 项）
    VerthysUnlock,
    VerthysLock,
    ContainerIdMismatch,
    // 设备绑定（第 4.4 项）
    DeviceBind,
    DeviceUnbind,
    DeviceRebind,
    // 爆破防护（第 5.3 项）
    BruteForceLockout,
    BruteForceReset,
    // 扫描操作（第 2.7 项）
    ScanOpen,
    ScanNext,
    ScanClose,
    ScanAbort,
    ScanCircuitBreaker,
    // 后台巡检（SECURITY.md 第 429-483 项：企业级巡检改进）
    /// 巡检测到威胁（未知模块连续达到阈值）
    PatrolThreat,
    /// 巡检触发应急熔断（直接销毁 worker 会话）
    PatrolEmergency,
    /// 巡检看门狗事件（线程重启 / 重启失败强制熔断）
    PatrolWatchdog,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::KeyDerive => "KEY_DERIVE",
            AuditEventType::KeyVerify => "KEY_VERIFY",
            AuditEventType::KeyClear => "KEY_CLEAR",
            AuditEventType::FileRead => "FILE_READ",
            AuditEventType::FileWrite => "FILE_WRITE",
            AuditEventType::FileDelete => "FILE_DELETE",
            AuditEventType::ClipboardClear => "CLIPBOARD_CLEAR",
            AuditEventType::ClipboardModeChange => "CLIPBOARD_MODE_CHANGE",
            AuditEventType::ClipboardMonitorEvent => "CLIPBOARD_MONITOR_EVENT",
            AuditEventType::StateCreate => "STATE_CREATE",
            AuditEventType::StateModify => "STATE_MODIFY",
            AuditEventType::StateRepair => "STATE_REPAIR",
            AuditEventType::StateDelete => "STATE_DELETE",
            AuditEventType::SecurityCommand => "SECURITY_COMMAND",
            AuditEventType::SecureDelete => "SECURE_DELETE",
            AuditEventType::HardenPrivateDir => "HARDEN_PRIVATE_DIR",
            AuditEventType::CleanupCrashResidue => "CLEANUP_CRASH_RESIDUE",
            AuditEventType::VerthysUnlock => "VERTHYS_UNLOCK",
            AuditEventType::VerthysLock => "VERTHYS_LOCK",
            AuditEventType::ContainerIdMismatch => "CONTAINER_ID_MISMATCH",
            AuditEventType::DeviceBind => "DEVICE_BIND",
            AuditEventType::DeviceUnbind => "DEVICE_UNBIND",
            AuditEventType::DeviceRebind => "DEVICE_REBIND",
            AuditEventType::BruteForceLockout => "BRUTE_FORCE_LOCKOUT",
            AuditEventType::BruteForceReset => "BRUTE_FORCE_RESET",
            AuditEventType::ScanOpen => "SCAN_OPEN",
            AuditEventType::ScanNext => "SCAN_NEXT",
            AuditEventType::ScanClose => "SCAN_CLOSE",
            AuditEventType::ScanAbort => "SCAN_ABORT",
            AuditEventType::ScanCircuitBreaker => "SCAN_CIRCUIT_BREAKER",
            AuditEventType::PatrolThreat => "PATROL_THREAT",
            AuditEventType::PatrolEmergency => "PATROL_EMERGENCY",
            AuditEventType::PatrolWatchdog => "PATROL_WATCHDOG",
        }
    }
}

/// 审计事件结果
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
}

impl AuditResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditResult::Success => "success",
            AuditResult::Failure => "failure",
            AuditResult::Denied => "denied",
        }
    }
}

/// 审计事件
///
/// 一条完整的审计日志记录，包含：
///   - 事件类型、时间戳、会话 ID
///   - 资源标识哈希（路径/名称的 SHA-256，不存明文）
///   - 操作结果（成功/失败/拒绝）
///   - 可选详情（错误码、参数摘要，不含敏感数据）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// 事件类型
    pub event_type: AuditEventType,
    /// ISO 8601 时间戳
    pub timestamp: String,
    /// 会话 ID（进程启动时生成，用于关联同一会话的事件）
    pub session_id: String,
    /// 操作来源（用户/系统/自动巡检）
    pub source: String,
    /// 资源标识哈希（SHA-256 前 16 字符，hex）
    ///
    /// 路径/文件名/记录名等敏感标识哈希化，不存明文。
    /// 空字符串表示无特定资源（如全局操作）。
    pub resource_hash: String,
    /// 操作结果
    pub result: AuditResult,
    /// 可选详情（错误码、参数摘要，不含密码/密钥/明文）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditEvent {
    /// 创建新审计事件
    pub fn new(
        event_type: AuditEventType,
        session_id: &str,
        source: &str,
        result: AuditResult,
    ) -> Self {
        AuditEvent {
            event_type,
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            source: source.to_string(),
            resource_hash: String::new(),
            result,
            detail: None,
        }
    }

    /// 设置资源标识哈希（从原始路径/名称计算）
    pub fn with_resource(mut self, resource: &str) -> Self {
        self.resource_hash = hash_resource(resource);
        self
    }

    /// 设置详情
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// 计算资源标识的 SHA-256 哈希（前 16 字符，hex）
///
/// 用于审计日志中的路径/名称脱敏。
/// 返回前 16 字符（64 位碰撞空间，足够区分不同资源）。
pub fn hash_resource(resource: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(resource.as_bytes());
    let hash = hasher.finalize();
    hash.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

// ===== HMAC 链式防篡改 =====

/// 审计日志条目（含 HMAC 链式标签）
///
/// 文件中每行一个 JSON 序列化的 AuditLogEntry：
///   {"event": {...}, "prev_hmac": "...", "hmac": "..."}
///
/// HMAC 链式结构：
///   hmac_n = HMAC(key, serialize(event_n) || prev_hmac_{n-1})
///
/// 篡改第 n 条记录的 event 将导致 hmac_n 校验失败，
/// 进而 hmac_{n+1} 因输入变化也失败，链式传播。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditLogEntry {
    /// 审计事件
    pub event: AuditEvent,
    /// 前一条记录的 HMAC（首条为全零）
    pub prev_hmac: String,
    /// 本条记录的 HMAC（hex 编码）
    pub hmac: String,
}

/// 追加写入审计事件到日志文件
///
/// 流程：
///   1. 读取日志文件最后一条记录的 HMAC（链式前驱）
///   2. 计算当前事件的 HMAC（包含前驱 HMAC）
///   3. 追加写入日志文件（JSON 单行）
///
/// 参数：
///   - log_path: 审计日志文件路径
///   - hmac_key: HMAC 密钥（由调用方管理，应从设备指纹派生）
///   - event: 审计事件
///
/// 失败：I/O 错误或序列化失败返回 Err
pub fn append_audit(log_path: &Path, hmac_key: &[u8], event: AuditEvent) -> Result<(), String> {
    // 1. 读取最后一条记录的 HMAC（链式前驱）
    let prev_hmac = read_last_hmac(log_path).unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

    // 2. 序列化事件
    let event_json = serde_json::to_string(&event)
        .map_err(|e| format!("serialize audit event failed: {}", e))?;

    // 3. 计算当前记录的 HMAC（包含前驱 HMAC）
    //    hmac = HMAC(key, event_json || prev_hmac)
    let mut hmac_input = Vec::with_capacity(event_json.len() + prev_hmac.len());
    hmac_input.extend_from_slice(event_json.as_bytes());
    hmac_input.extend_from_slice(prev_hmac.as_bytes());
    let hmac = crate::util::crypto::hmac_sign(hmac_key, &hmac_input);
    let hmac_hex: String = hmac.iter().map(|b| format!("{:02x}", b)).collect();

    // 4. 构造日志条目
    let entry = AuditLogEntry {
        event,
        prev_hmac,
        hmac: hmac_hex,
    };
    let entry_json = serde_json::to_string(&entry)
        .map_err(|e| format!("serialize audit log entry failed: {}", e))?;

    // 5. 追加写入文件
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create audit log dir failed: {}", e))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("open audit log file failed: {}", e))?;

    writeln!(file, "{}", entry_json)
        .map_err(|e| format!("write audit log entry failed: {}", e))?;

    Ok(())
}

/// 读取审计日志文件中最后一条记录的 HMAC
///
/// 用于链式 HMAC 的前驱获取。
/// 空文件或读取失败返回 None（首条记录使用全零 HMAC）。
fn read_last_hmac(log_path: &Path) -> Option<String> {
    if !log_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(log_path).ok()?;
    let last_line = content.lines().rfind(|l| !l.trim().is_empty())?;
    let entry: AuditLogEntry = serde_json::from_str(last_line).ok()?;
    Some(entry.hmac)
}

// ===== 审计日志校验 =====

/// 校验审计日志文件的 HMAC 链式完整性
///
/// 逐行验证每条记录的 HMAC，检测篡改。
/// 任一记录校验失败返回该行号，全部通过返回 Ok(())。
///
/// 参数：
///   - log_path: 审计日志文件路径
///   - hmac_key: HMAC 密钥
///
/// 返回：
///   - Ok(()): 全部记录校验通过
///   - Err(line_number): 第 line_number 行校验失败（1-based）
pub fn verify_audit_chain(log_path: &Path, hmac_key: &[u8]) -> Result<(), usize> {
    if !log_path.exists() {
        return Ok(()); // 空文件视为有效
    }

    let content = std::fs::read_to_string(log_path).map_err(|_| 0usize)?;
    let mut prev_hmac = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    for (idx, line) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let line_no = idx + 1;
        let entry: AuditLogEntry = serde_json::from_str(line).map_err(|_| line_no)?;

        // 验证 prev_hmac 链式关系
        if entry.prev_hmac != prev_hmac {
            return Err(line_no);
        }

        // 重新计算 HMAC 验证
        let event_json = serde_json::to_string(&entry.event).map_err(|_| line_no)?;
        let mut hmac_input = Vec::with_capacity(event_json.len() + entry.prev_hmac.len());
        hmac_input.extend_from_slice(event_json.as_bytes());
        hmac_input.extend_from_slice(entry.prev_hmac.as_bytes());
        let expected_hmac = crate::util::crypto::hmac_sign(hmac_key, &hmac_input);
        let expected_hex: String = expected_hmac.iter().map(|b| format!("{:02x}", b)).collect();

        if !crate::util::crypto::ct_eq(entry.hmac.as_bytes(), expected_hex.as_bytes()) {
            return Err(line_no);
        }

        prev_hmac = entry.hmac;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_resource() {
        let h1 = hash_resource("C:/Users/test/verthys.verthys");
        let h2 = hash_resource("C:/Users/test/verthys.verthys");
        let h3 = hash_resource("C:/Users/other/verthys.verthys");

        assert_eq!(h1, h2); // 相同输入相同哈希
        assert_ne!(h1, h3); // 不同输入不同哈希
        assert_eq!(h1.len(), 16); // 前 16 字符
    }

    #[test]
    fn test_audit_event_new() {
        let event = AuditEvent::new(
            AuditEventType::VerthysUnlock,
            "session_abc",
            "user",
            AuditResult::Success,
        )
        .with_resource("C:/Users/test/verthys.verthys")
        .with_detail("unlock succeeded");

        assert_eq!(event.event_type.as_str(), "VERTHYS_UNLOCK");
        assert_eq!(event.result.as_str(), "success");
        assert!(!event.resource_hash.is_empty());
        assert!(event.detail.is_some());
    }

    #[test]
    fn test_append_and_verify_chain() {
        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join(format!("verthys_audit_test_{}.log", std::process::id()));
        let _ = std::fs::remove_file(&log_path);

        let hmac_key = b"test_hmac_key_for_audit_log";

        // 写入 3 条审计事件
        for i in 0..3 {
            let event = AuditEvent::new(
                AuditEventType::KeyDerive,
                "session_test",
                "user",
                AuditResult::Success,
            )
            .with_detail(format!("derive #{}", i));
            append_audit(&log_path, hmac_key, event).unwrap();
        }

        // 验证链式完整性
        assert!(verify_audit_chain(&log_path, hmac_key).is_ok());

        // 篡改日志文件（修改中间一条记录）
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        let tampered_line = lines[1].replace("derive #1", "derive #TAMPERED");
        let tampered_content = format!(
            "{}\n{}\n{}\n",
            lines[0], tampered_line, lines[2]
        );
        std::fs::write(&log_path, tampered_content).unwrap();

        // 篡改后应校验失败
        assert!(verify_audit_chain(&log_path, hmac_key).is_err());

        // 清理
        let _ = std::fs::remove_file(&log_path);
    }
}
