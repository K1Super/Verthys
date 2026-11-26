/* tests.rs — protocol 模块单元测试
 *
 * 覆盖：Response 序列化、请求字段缺省值、base64 编解码契约、
 *       响应行长度约束、错误码折叠规则与敏感字段清零。
 */

use super::{
    base64_decode, base64_encode, bound_response_line, KernelStatusReport, Request, Response,
    MAX_RESPONSE_LINE_BYTES,
};

#[test]
fn kernel_status_response_serializes_state() {
    let mut resp = Response::ok("kernel_status");
    resp.kernel_status = Some(KernelStatusReport {
        state: 3,
        reason: 0,
        capabilities: 3,
        protocol_major: 1,
        protocol_minor: 0,
    });
    let value = serde_json::to_value(&resp).expect("序列化响应");
    assert_eq!(value["op"], "kernel_status");
    assert_eq!(value["kernel_status"]["state"], 3);
    assert_eq!(value["kernel_status"]["protocol_major"], 1);
}

// 扫描投影请求字段：缺省（不传该字段的既有调用方）必须等价于
// FULL 投影 + 无内联阈值，语义与历史行为一致
#[test]
fn request_scan_projection_defaults_to_full() {
    let req: Request = serde_json::from_str(r#"{"op":"scan_open"}"#)
        .expect("无投影字段的请求必须可解析");
    assert_eq!(req.project, "");
    assert_eq!(req.inline_max_bytes, 0);

    let req2: Request = serde_json::from_str(
        r#"{"op":"scan_open","project":"index","inline_max_bytes":65536}"#,
    )
    .expect("显式投影字段必须可解析");
    assert_eq!(req2.project, "index");
    assert_eq!(req2.inline_max_bytes, 65536);
}

// 全局密钥读回验证依赖的编码契约：decode(encode(x)) == x 且
// encode 为无换行标准字母表——AddRecord 写入的 record base64 与
// GetRecord 读回重编码结果必须逐字节相等，否则落盘读回验证恒失败。
#[test]
fn base64_roundtrip_idempotent() {
    let samples: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        &[0u8, 1, 2, 3, 4, 5, 6, 7],
        &[0xFFu8; 10],
        &[0u8; 124], // 全局密钥 record 长度
    ];
    for s in samples {
        let enc = base64_encode(s);
        assert!(!enc.contains('\n'), "输出不得含换行");
        let dec = base64_decode(&enc).expect("decode(encode(x)) 必须成功");
        assert_eq!(dec.as_slice(), *s, "roundtrip 字节相等");
        assert_eq!(base64_encode(&dec), enc, "encode 幂等：重编码逐字节相等");
    }
}

// 传输层容错：decode 宽容 CR/LF/空格（SHM/管道拼接场景）
#[test]
fn base64_decode_tolerates_whitespace() {
    let enc = base64_encode(&[0xABu8; 13]);
    let with_crlf = format!("{}\r\n{}", &enc[..8], &enc[8..]);
    let dec = base64_decode(&with_crlf).expect("CR/LF 容错");
    assert_eq!(dec, vec![0xABu8; 13]);
}

// 写侧约束：上限内原样透传
#[test]
fn bound_response_line_passes_through_within_limit() {
    let json = r#"{"ok":true,"op":"get_record","data":"AAAA"}"#.to_string();
    assert_eq!(bound_response_line(json.clone(), "get_record"), json);
}

// 写侧约束：超限响应被替换为受控错误行（保留 op 便于定位失败操作）
#[test]
fn bound_response_line_replaces_oversized_payload() {
    let oversized = format!(
        r#"{{"ok":true,"op":"get_record","data":"{}"}}"#,
        "A".repeat(MAX_RESPONSE_LINE_BYTES),
    );
    assert!(oversized.len() > MAX_RESPONSE_LINE_BYTES);

    let bounded = bound_response_line(oversized, "get_record");
    assert!(bounded.len() < 4096, "受控错误行必须是固定量级的小体积");
    let v: serde_json::Value =
        serde_json::from_str(&bounded).expect("受控错误行必须是合法 JSON");
    assert_eq!(v["ok"], serde_json::Value::Bool(false));
    assert_eq!(v["op"], serde_json::Value::String("get_record".into()));
    assert!(
        v["error"]
            .as_str()
            .unwrap_or_default()
            .contains("too large")
    );
}

// 跨层预算：导入侧允许的最大记录取回后仍落在写侧上限内
#[test]
fn max_legal_record_response_fits_writer_limit() {
    // 与导入守卫一致：单条记录的 base64 载荷上限取自跨层预算常量
    let payload = crate::runtime::budget::PB_IPC_MAX_PAYLOAD_BYTES as usize;
    let worst_case = payload / 3 * 4 + 64 * 1024;
    assert!(
        worst_case < MAX_RESPONSE_LINE_BYTES,
        "最大合法响应行 {} 字节必须落在写侧上限 {} 字节内",
        worst_case,
        MAX_RESPONSE_LINE_BYTES
    );
}

// 模块策略拒绝必须保留 0x17，不得折叠为 AUTH：调用方需要区分
// “模块未解锁/未绑定恢复码”和“口令错误”。
#[test]
fn policy_error_not_collapsed_to_auth() {
    let resp = Response::err("v4_module_unlock", 0x00000017);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000017"));
    let auth = Response::err("v4_module_unlock", 0x00000002);
    assert_eq!(auth.error.as_deref(), Some("ERR_00000002"));
}

// 恢复码轮换响应只能存活到序列化完成；scrub 后不得残留。
#[test]
fn recovery_code_response_is_scrubbed() {
    let mut resp = Response::ok("v4_recovery_rotate");
    resp.recovery_code = Some("ABCD-EFGH".into());
    resp.scrub();
    let code = resp.recovery_code.as_deref().unwrap_or("");
    assert!(code.chars().all(|c| c == '\0'), "恢复码必须被清零");
}

// TPM/回滚错误必须保留 0x18/0x19：UI 需要引导恢复码重密封或提示文件回退，
// 折叠为 AUTH 会让这两类可行动错误退化成“口令错误”。
#[test]
fn tpm_and_rollback_errors_not_collapsed_to_auth() {
    let tpm = Response::err("v4_pcr_enable", 0x00000018);
    assert_eq!(tpm.error.as_deref(), Some("ERR_00000018"));
    let rollback = Response::err("unlock", 0x00000019);
    assert_eq!(rollback.error.as_deref(), Some("ERR_00000019"));
}

// 锚点表满必须保留 0x21：UI 需要展示容量与维护入口，不能误报为回退。
#[test]
fn anchor_full_error_not_collapsed_to_auth() {
    let full = Response::err("v4_create", 0x00000021);
    assert_eq!(full.error.as_deref(), Some("ERR_00000021"));
}

// 锚点维护接口的可行动错误（IO/损坏/未授权/TPM/容量）必须原样透传。
#[test]
fn anchor_admin_errors_preserve_actionable_codes() {
    for code in [0x00000008u32, 0x00000009, 0x00000016, 0x00000018, 0x00000021] {
        let resp = Response::err_raw("rollback_anchor_list", code);
        let expected = format!("ERR_{:08X}", code);
        assert_eq!(resp.error.as_deref(), Some(expected.as_str()));
    }
}

// 轮换作业错误必须保留原码：调用方需要区分“作业进行中/模块未解锁/
// 空间不足/完整性复核失败”，折叠为 AUTH 会使这四类可行动错误退化。
#[test]
fn rotate_errors_not_collapsed_to_auth() {
    for code in [0x0000001Cu32, 0x0000001D, 0x0000001E, 0x0000001F] {
        let resp = Response::err("v4_rotate_run", code);
        let expected = format!("ERR_{:08X}", code);
        assert_eq!(resp.error.as_deref(), Some(expected.as_str()));
    }
}

// 模块请求字段：缺省值必须兼容既有调用方，显式字段可解析。
#[test]
fn request_module_fields_parse() {
    let req: Request = serde_json::from_str(r#"{"op":"v4_module_unlock"}"#)
        .expect("无模块字段的请求必须可解析");
    assert_eq!(req.module_id, 0);
    assert!(req.recovery_code.is_empty());
    assert!(req.old_recovery.is_empty());

    let req2: Request = serde_json::from_str(
        r#"{"op":"v4_module_enable","module_id":2,"password":"pw","recovery_code":"CODE"}"#,
    )
    .expect("模块请求必须可解析");
    assert_eq!(req2.module_id, 2);
    assert_eq!(req2.recovery_code.as_str(), "CODE");

    let pcr: Request =
        serde_json::from_str(r#"{"op":"v4_pcr_enable","pcr_select":2176}"#)
            .expect("PCR 请求必须可解析");
    assert_eq!(pcr.pcr_select, 2176);
}
