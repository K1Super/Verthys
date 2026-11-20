/*
 * rollback_anchor_controller.rs — 回退锚点维护命令（前端 → 主进程 → worker → C）
 *
 * 职责边界：
 *   - List/Release/Reclaim 只做参数边界、转发与审计；状态判定与“只回收
 *     DEAD”由 C 层保证。
 *   - Scan 是宿主侧只读文件扫描：只读容器固定头 76 字节，不打开容器、
 *     不修改任何文件；结果仅用于向用户展示证据，不作为自动删除依据。
 *   - 释放必须由前端二次确认后传入 confirm=true；宿主不提供静默调用路径。
 *
 * 安全约束：
 *   - 审计只记录 UUID 哈希与计数，不记录容器路径、指纹或任何密钥材料。
 *   - 扫描跳过符号链接/重解析点，限制深度与文件数，权限错误单独计数。
 */
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use tauri::State;

use crate::controller::types::{
    AnchorScanEntry, AnchorScanResult, VerthysResponse,
};
use crate::infrastructure::audit::write_audit_with_extensions;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};

/// 单次维护命令的 worker 超时：64 条 TPM 探测 + 少量删除，留足余量。
const ANCHOR_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// 单次扫描的硬上限：防止用户误选整盘导致长时间占用。
const SCAN_MAX_FILES: u64 = 200_000;
const SCAN_MAX_DEPTH: usize = 8;
const SCAN_MAX_ROOTS: usize = 32;
const SCAN_MAX_PATHS_PER_UUID: usize = 32;

/// 容器固定头长度（与 C 层 VTY_HEADER_FIXED_BYTES 对齐）。
const CONTAINER_HEADER_BYTES: usize = 76;
/// 容器主版本（与 VERTHYS_CONTAINER_FORMAT_VERSION 对齐）。
const CONTAINER_VERSION_MAJOR: u16 = 4;
const CONTAINER_MAGIC: [u8; 4] = *b"VRTY";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

fn session_id() -> String {
    format!("pid-{}", std::process::id())
}

fn audit_anchor(
    app: &tauri::AppHandle,
    event: AuditEventType,
    result: AuditResult,
    resource: Option<&str>,
    detail: Option<String>,
) {
    write_audit_with_extensions(
        app,
        &session_id(),
        event,
        result,
        resource,
        detail,
        AuditExtensions::default(),
    );
}

fn forward(
    state: &AppState,
    req: &serde_json::Value,
) -> Result<VerthysResponse, String> {
    let line = req.to_string();
    let resp_json = state.send_with_timeout(&line, ANCHOR_OP_TIMEOUT)?;
    let mut resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    resp.adopt_worker_error_code();
    Ok(resp)
}

fn is_uuid_hex(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 读取容器固定头并提取 UUID；任何字段不合法返回 None。
///
/// 只依赖 76 字节固定头：magic、主版本、header_len 与 UUID 偏移 12。
/// 不校验尾哈希/槽区，因为扫描阶段不打开容器、也不需要证明其可解锁。
pub(crate) fn header_uuid(header: &[u8; CONTAINER_HEADER_BYTES]) -> Option<[u8; 16]> {
    if header[0..4] != CONTAINER_MAGIC {
        return None;
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != CONTAINER_VERSION_MAJOR {
        return None;
    }
    let header_len = u16::from_le_bytes([header[8], header[9]]);
    if header_len < CONTAINER_HEADER_BYTES as u16 {
        return None;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&header[12..28]);
    Some(uuid)
}

fn uuid_hex(uuid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in uuid {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn is_container_candidate(path: &Path) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return false,
    };
    ext == "vty" || ext == "verthys"
}

#[derive(Default)]
struct ScanState {
    entries: HashMap<String, Vec<String>>,
    files_seen: u64,
    matched_count: u64,
    truncated: bool,
    permission_errors: u64,
}

fn scan_error(state: &mut ScanState, err: &std::io::Error) {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        state.permission_errors += 1;
    }
}

fn inspect_file(path: &Path, state: &mut ScanState) {
    if !is_container_candidate(path) {
        return;
    }
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            scan_error(state, &e);
            return;
        }
    };
    let mut header = [0u8; CONTAINER_HEADER_BYTES];
    let mut read = 0usize;
    while read < header.len() {
        match file.read(&mut header[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) => {
                scan_error(state, &e);
                return;
            }
        }
    }
    if read < header.len() {
        return;
    }
    let uuid = match header_uuid(&header) {
        Some(u) => u,
        None => return,
    };
    state.matched_count += 1;
    let key = uuid_hex(&uuid);
    let paths = state.entries.entry(key).or_default();
    if paths.len() < SCAN_MAX_PATHS_PER_UUID {
        paths.push(path.to_string_lossy().to_string());
    }
}

fn walk_dir(dir: &Path, depth: usize, state: &mut ScanState) {
    if state.files_seen >= SCAN_MAX_FILES {
        state.truncated = true;
        return;
    }
    if depth > SCAN_MAX_DEPTH {
        state.truncated = true;
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            scan_error(state, &e);
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                scan_error(state, &e);
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                scan_error(state, &e);
                continue;
            }
        };
        /* DirEntry::metadata 在部分平台会跟随链接；先用 file_type 拦住符号链接，
         * 再由 metadata 属性拦截 Windows 重解析点（junction）。 */
        if file_type.is_symlink() {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                scan_error(state, &e);
                continue;
            }
        };
        if is_reparse_or_symlink(&metadata) {
            continue;
        }
        if metadata.is_dir() {
            walk_dir(&path, depth + 1, state);
        } else if metadata.is_file() {
            state.files_seen += 1;
            inspect_file(&path, state);
        }
        if state.files_seen >= SCAN_MAX_FILES {
            state.truncated = true;
            return;
        }
    }
}

fn scan_roots(roots: &[String]) -> AnchorScanResult {
    let mut state = ScanState::default();
    for root in roots {
        let path = PathBuf::from(root);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                scan_error(&mut state, &e);
                continue;
            }
        };
        if is_reparse_or_symlink(&metadata) {
            continue;
        }
        if metadata.is_dir() {
            walk_dir(&path, 0, &mut state);
        } else if metadata.is_file() {
            state.files_seen += 1;
            inspect_file(&path, &mut state);
        }
    }
    let mut entries: Vec<AnchorScanEntry> = state
        .entries
        .into_iter()
        .map(|(uuid, mut paths)| {
            paths.sort();
            AnchorScanEntry { uuid, paths }
        })
        .collect();
    entries.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    AnchorScanResult {
        entries,
        files_seen: state.files_seen,
        matched_count: state.matched_count,
        truncated: state.truncated,
        permission_errors: state.permission_errors,
    }
}

/// 列出本机回退锚点（不要求容器已解锁）。
#[tauri::command]
pub async fn verthys_rollback_anchor_list(
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    forward(&state, &json!({ "op": "rollback_anchor_list" }))
}

/// 回收所有“见证确定不存在”的锚点。ACTIVE/TAMPERED/UNKNOWN 保留。
#[tauri::command]
pub async fn verthys_rollback_anchor_reclaim(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    confirm: bool,
) -> Result<VerthysResponse, String> {
    if !confirm {
        let mut resp = VerthysResponse::err("rollback_anchor_reclaim", "缺少显式确认");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    let resp = forward(
        &state,
        &json!({ "op": "rollback_anchor_reclaim", "anchor_confirm": true }),
    )?;
    let result = if resp.ok {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    audit_anchor(
        &app,
        AuditEventType::RollbackAnchorReclaim,
        result,
        None,
        Some(format!(
            "removed={} cleanup_failed={}",
            resp.anchor_removed.unwrap_or(0),
            resp.anchor_cleanup_failed.unwrap_or(0)
        )),
    );
    Ok(resp)
}

/// 显式释放指定 UUID 的锚点并删除两槽见证。
///
/// 该操作会使仍存在的容器在下次打开时 fail-closed，只能使用恢复码
/// 重设锚点；前端必须完成二次确认后才可传入 confirm=true。
#[tauri::command]
pub async fn verthys_rollback_anchor_release(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    uuid: String,
    confirm: bool,
) -> Result<VerthysResponse, String> {
    if !confirm {
        let mut resp = VerthysResponse::err("rollback_anchor_release", "缺少显式确认");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    if !is_uuid_hex(&uuid) {
        let mut resp = VerthysResponse::err("rollback_anchor_release", "UUID 格式非法");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    let resp = forward(
        &state,
        &json!({
            "op": "rollback_anchor_release",
            "uuid": uuid,
            "anchor_confirm": true,
        }),
    )?;
    let result = if resp.ok {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    audit_anchor(
        &app,
        AuditEventType::RollbackAnchorRelease,
        result,
        Some(&uuid),
        Some(format!(
            "released={} cleanup_failed={}",
            resp.anchor_released.unwrap_or(0),
            resp.anchor_cleanup_failed.unwrap_or(0)
        )),
    );
    Ok(resp)
}

/// 扫描用户选择的根目录，返回 UUID → 路径证据。
///
/// 只读、有界、跳过重解析点；权限错误单独计数，不视为“文件不存在”。
#[tauri::command]
pub async fn verthys_rollback_anchor_scan(
    app: tauri::AppHandle,
    roots: Vec<String>,
) -> Result<VerthysResponse, String> {
    let roots: Vec<String> = roots
        .into_iter()
        .filter(|r| !r.trim().is_empty())
        .take(SCAN_MAX_ROOTS)
        .collect();
    if roots.is_empty() {
        let mut resp = VerthysResponse::err("rollback_anchor_scan", "未选择扫描目录");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    let scan = tokio::task::spawn_blocking(move || scan_roots(&roots))
        .await
        .map_err(|e| format!("scan task join: {}", e))?;
    audit_anchor(
        &app,
        AuditEventType::RollbackAnchorScan,
        AuditResult::Success,
        None,
        Some(format!(
            "files_seen={} matched={} truncated={} permission_errors={}",
            scan.files_seen, scan.matched_count, scan.truncated, scan.permission_errors
        )),
    );
    let mut resp = VerthysResponse::ok("rollback_anchor_scan");
    resp.anchor_scan = Some(scan);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn uuid_hex_validation() {
        assert!(is_uuid_hex("0123456789abcdef0123456789abcdef"));
        assert!(is_uuid_hex("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_uuid_hex(""));
        assert!(!is_uuid_hex("0011"));
        assert!(!is_uuid_hex("zz23456789abcdef0123456789abcdef"));
    }

    fn sample_header(uuid: [u8; 16]) -> [u8; CONTAINER_HEADER_BYTES] {
        let mut header = [0u8; CONTAINER_HEADER_BYTES];
        header[0..4].copy_from_slice(&CONTAINER_MAGIC);
        header[4..6].copy_from_slice(&CONTAINER_VERSION_MAJOR.to_le_bytes());
        header[8..10].copy_from_slice(&(CONTAINER_HEADER_BYTES as u16).to_le_bytes());
        header[12..28].copy_from_slice(&uuid);
        header
    }

    #[test]
    fn header_uuid_accepts_valid_and_rejects_bad() {
        let uuid = [0xABu8; 16];
        let header = sample_header(uuid);
        assert_eq!(header_uuid(&header), Some(uuid));

        let mut bad_magic = header;
        bad_magic[0] = b'X';
        assert_eq!(header_uuid(&bad_magic), None);

        let mut bad_version = header;
        bad_version[4] = 3;
        assert_eq!(header_uuid(&bad_version), None);

        let mut bad_len = header;
        bad_len[8..10].copy_from_slice(&10u16.to_le_bytes());
        assert_eq!(header_uuid(&bad_len), None);
    }

    #[test]
    fn scan_finds_container_and_reports_counts() {
        let uuid = [0x5Au8; 16];
        let root = std::env::temp_dir().join(format!(
            "verthys-anchor-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&root).expect("create temp dir");
        let container = root.join("sample.verthys");
        {
            let mut file = File::create(&container).expect("create container");
            file.write_all(&sample_header(uuid)).expect("write header");
        }
        let junk = root.join("junk.txt");
        {
            let mut file = File::create(&junk).expect("create junk");
            file.write_all(b"not a container").expect("write junk");
        }

        let result = scan_roots(&[root.to_string_lossy().to_string()]);
        assert_eq!(result.matched_count, 1);
        assert_eq!(result.files_seen, 2);
        assert!(!result.truncated);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].uuid, uuid_hex(&uuid));
        assert_eq!(result.entries[0].paths.len(), 1);

        let _ = fs::remove_dir_all(&root);
    }
}
