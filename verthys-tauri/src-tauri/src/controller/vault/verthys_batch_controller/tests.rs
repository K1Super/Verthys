/*
 * verthys_batch_controller 单元测试
 *
 * 覆盖会话冲突码稳定性、导入 ID 唯一性与批量 DTO 序列化契约。
 */
use super::support::{generate_import_id, import_session_busy_response};
use crate::constants::command_names::cmd;
use crate::controller::types::{BatchRecordInput, ImportBatchProgress};

#[test]
fn test_import_session_busy_response_carries_stable_code() {
    // 会话冲突码为前端控制流契约（清藏冲突确认 / 照片引导文案）：
    // 码值与序列化形态必须稳定，文案仅作展示
    let resp = import_session_busy_response();
    assert!(!resp.ok);
    assert_eq!(resp.error_code.as_deref(), Some("E_IMPORT_SESSION_BUSY"));
    assert_eq!(
        resp.error.as_deref(),
        Some("已有导入会话进行中，请先结束当前会话")
    );
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"error_code\":\"E_IMPORT_SESSION_BUSY\""));
}

#[test]
fn test_generate_import_id_unique() {
    let id1 = generate_import_id();
    let id2 = generate_import_id();
    assert!(id1.starts_with("imp-"));
    assert!(id2.starts_with("imp-"));
    // 即使同一毫秒，随机后缀也应使两者不同
    assert_ne!(id1, id2, "import_id 应全局唯一");
}

#[test]
fn test_batch_record_input_deserialize() {
    let json = r#"{"rtype":1,"name":"meta_a.jpg","entry_key":"abcd1234","data_b64":"base64data"}"#;
    let rec: BatchRecordInput = serde_json::from_str(json).unwrap();
    assert_eq!(rec.rtype, 1);
    assert_eq!(rec.name, "meta_a.jpg");
    assert_eq!(rec.entry_key, "abcd1234");
    assert_eq!(rec.data_b64, "base64data");
}

#[test]
fn test_import_batch_progress_serialize() {
    let p = ImportBatchProgress {
        batch_id: 1,
        processed_in_batch: 5,
        total_in_batch: 10,
        total_committed: 100,
        total_skipped: 3,
        elapsed_ms: 1234,
    };
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"batch_id\":1"));
    assert!(json.contains("\"total_committed\":100"));
}

#[test]
fn test_command_name_constants_match_registered_commands() {
    // 命令名常量必须与 Tauri 命令注册名逐字一致（授权闸门审计口径依赖）。
    assert_eq!(cmd::IMPORT_BEGIN, "verthys_import_begin");
    assert_eq!(cmd::ADD_RECORDS_BATCH, "verthys_add_records_batch");
    assert_eq!(cmd::IMPORT_CHECKPOINT, "verthys_import_checkpoint");
    assert_eq!(cmd::IMPORT_END, "verthys_import_end");
}
