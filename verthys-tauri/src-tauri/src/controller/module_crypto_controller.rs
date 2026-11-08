/* module_crypto_controller.rs — 内容层加密命令（前端 → 主进程 → worker）
 *
 * 职责：校验模块、布局与尺寸边界，把请求转发给 worker 的 module_* 操作，
 * 并把公开参数透传前端。分片密钥（MDEK）只存在于 C 层句柄内；本层
 * 请求/响应不含任何原始密钥。
 *
 * 模块解锁/锁定在 语义下是 C 层 M1 状态机操作：
 *   - 模块未启用 → MDEK 在 Keyring，内容路径可用，解锁为幂等空操作；
 *   - 模块已启用 → 必须把模块口令交给 C 层解锁 user 槽；
 *   - 锁定 → 清空 C 层模块会话缓存（不涉及口令）。
 *
 * 安全约束：
 *   - 仅接受白名单模块与布局，未知取值直接拒绝；
 *   - 消耗模块密钥的操作要求容器已解锁；
 *   - 锁定命令不设解锁闸门，保证锁定态下仍能清理 C 层驻留密钥；
 *   - 请求载荷按跨层预算上限前置拒绝，避免超限请求打断 worker 行协议。
 *
 * 依赖方向：controller → state / worker 会话（经 AppState::send）。
 */

use std::time::Duration;

use serde_json::json;
use tauri::State;
use zeroize::Zeroizing;

use crate::controller::types::VerthysResponse;
use crate::controller::verthys_controller::require_unlocked;
use crate::infrastructure::shm_schema::PB_IPC_MAX_PAYLOAD_BYTES;
use crate::state::AppState;

/// 模块口令上限（UTF-8 字节）：模块密钥是短口令，超长输入按非法处理
const MAX_MODULE_SECRET_BYTES: usize = 4096;
/// 包裹态文件密钥上限（字符）：正常值约 120 字符，留出编码余量
const MAX_WRAPPED_KEY_CHARS: usize = 4096;
/// 盐字段上限（字符）：base64(16B) 为 24 字符
const MAX_SALT_CHARS: usize = 64;
/// 单次内容载荷的 base64 字符上限：跨层预算常量即字符口径，直接对齐
const MAX_DATA_CHARS: usize = PB_IPC_MAX_PAYLOAD_BYTES as usize;

/// 模块索引通配值（C 层 VERTHYS_MODULE_ALL）：仅锁定命令接受
const MODULE_ALL: u32 = 0xFFFF_FFFF;
/// 模块解锁/锁定是 C 层槽位操作，按短操作预算
const KEY_OP_TIMEOUT: Duration = Duration::from_secs(30);
/// 内容加解密超时：单块上限 1MiB，30 秒覆盖极端机器抖动
const CRYPT_OP_TIMEOUT: Duration = Duration::from_secs(30);

const CRYPT_KINDS: [&str; 8] = [
    "meta",
    "chunk",
    "slim_meta",
    "slim_chunk",
    "thumb",
    "chunkset",
    "v2_chunk",
    "v2_check",
];

/// 内容模块 → 模块索引（0=photo，2=fileverthys）。
/// 内容层只承载照片与文件保险箱两类数据；accounts 的记录由 C 层记录层
/// 直接管理，不经过内容加解密命令。
fn content_module_index(module: &str) -> Result<u32, String> {
    match module {
        "photo" => Ok(0),
        "file" => Ok(2),
        _ => Err("模块标识非法".into()),
    }
}

/// 会话模块（解锁/锁定）→ 模块索引：0=photo，1=accounts，2=fileverthys。
fn module_index(module: &str) -> Result<u32, String> {
    match module {
        "photo" => Ok(0),
        "accounts" => Ok(1),
        "file" | "fileverthys" => Ok(2),
        _ => Err("模块标识非法".into()),
    }
}

fn ensure_module(module: &str) -> Result<(), String> {
    content_module_index(module).map(|_| ())
}

fn ensure_kind(kind: &str, allowed: &[&str]) -> Result<(), String> {
    if allowed.contains(&kind) {
        Ok(())
    } else {
        Err("加密布局非法".into())
    }
}

fn ensure_hex_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("文件哈希格式非法".into());
    }
    Ok(())
}

fn ensure_position(seq: u32, total: u32) -> Result<(), String> {
    if total == 0 || seq >= total {
        return Err("块序号或总数非法".into());
    }
    Ok(())
}

fn ensure_data_len(data: &str, allow_empty: bool) -> Result<(), String> {
    if !allow_empty && data.is_empty() {
        return Err("内容载荷不能为空".into());
    }
    if data.len() > MAX_DATA_CHARS {
        return Err("内容载荷超出单次上限".into());
    }
    Ok(())
}

/// 序列化并转发请求；请求与响应缓冲在离开作用域时清零。
///
/// 响应 JSON 含解密后的内容明文（base64），必须与请求同等对待：
/// 解析完成后立即由 Zeroizing 清零，避免 MB 级明文驻留主进程堆。
fn forward(
    state: &AppState,
    req: &serde_json::Value,
    timeout: Duration,
) -> Result<VerthysResponse, String> {
    let line = Zeroizing::new(req.to_string());
    let resp_json = Zeroizing::new(state.send_with_timeout(line.as_str(), timeout)?);
    let mut resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    resp.adopt_worker_error_code();
    Ok(resp)
}

/// 解锁模块：把模块口令一次性交付 C 层，解封该模块 MDEK 的 user 槽。
///
/// 模块未启用时 MDEK 在 Keyring，本命令返回幂等成功（enabled=false）：
/// 调用方据此知道内容路径无需口令，但不得据此关闭模块保护。
/// 已删除模块直接拒绝：删除后的数据叶已清除，解锁无意义。
#[tauri::command]
pub async fn verthys_module_key_unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module: String,
    password: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "module_key_unlock") {
        return Ok(VerthysResponse::err("module_key_unlock", &msg));
    }
    if password.is_empty() || password.len() > MAX_MODULE_SECRET_BYTES {
        return Ok(VerthysResponse::err("module_key_unlock", "模块口令长度非法"));
    }
    let module_id = module_index(&module)?;

    let status = forward(
        &state,
        &json!({ "op": "v4_module_status", "module_id": module_id }),
        KEY_OP_TIMEOUT,
    )?;
    if !status.ok {
        /* 状态查询失败按解锁失败返回：不把 v4_module_status 的 op 名透出，
         * 保持调用方只看到 module_key_unlock 的结果语义。 */
        return Ok(VerthysResponse::err(
            "module_key_unlock",
            status.error.as_deref().unwrap_or("模块状态查询失败"),
        ));
    }
    if status.deleted == Some(true) {
        return Ok(VerthysResponse::err("module_key_unlock", "模块已删除"));
    }
    if status.enabled != Some(true) {
        /* 未启用：MDEK 在 Keyring，内容加解密不依赖模块口令。 */
        let mut ok = VerthysResponse::ok("module_key_unlock");
        ok.enabled = Some(false);
        ok.unlocked = Some(false);
        ok.deleted = Some(false);
        return Ok(ok);
    }

    let password = Zeroizing::new(password);
    let req = json!({
        "op": "v4_module_unlock",
        "module_id": module_id,
        "password": password.as_str(),
    });
    forward(&state, &req, KEY_OP_TIMEOUT)
}

/// 清除模块会话密钥；module 为空表示全部模块。
///
/// 不设解锁闸门：锁定态必须先清空 C 层模块会话缓存，闸门会阻断清理。
#[tauri::command]
pub async fn verthys_module_key_lock(
    state: State<'_, AppState>,
    module: Option<String>,
) -> Result<VerthysResponse, String> {
    let module = module.unwrap_or_default();
    let module_id = if module.is_empty() {
        MODULE_ALL
    } else {
        module_index(&module)?
    };
    let req = json!({
        "op": "v4_module_lock",
        "module_id": module_id,
    });
    forward(&state, &req, KEY_OP_TIMEOUT)
}

/// 加密内容记录；密钥来自 worker 内的模块会话密钥。
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn verthys_module_seal(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module: String,
    kind: String,
    data: Option<String>,
    salt: Option<String>,
    file_hash: Option<String>,
    seq: Option<u32>,
    total: Option<u32>,
    wrapped_key: Option<String>,
    password: Option<String>,
) -> Result<VerthysResponse, String> {
    module_seal_open(
        app, state, module, kind, data, salt, file_hash, seq, total, wrapped_key, password, true,
    )
}

/// 解密内容记录；返回明文与（记录型块）密文内嵌的 seq/total。
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn verthys_module_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module: String,
    kind: String,
    data: Option<String>,
    salt: Option<String>,
    file_hash: Option<String>,
    seq: Option<u32>,
    total: Option<u32>,
    wrapped_key: Option<String>,
    password: Option<String>,
) -> Result<VerthysResponse, String> {
    module_seal_open(
        app, state, module, kind, data, salt, file_hash, seq, total, wrapped_key, password, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn module_seal_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module: String,
    kind: String,
    data: Option<String>,
    salt: Option<String>,
    file_hash: Option<String>,
    seq: Option<u32>,
    total: Option<u32>,
    wrapped_key: Option<String>,
    password: Option<String>,
    sealing: bool,
) -> Result<VerthysResponse, String> {
    let op = if sealing { "module_seal" } else { "module_open" };
    if let Err(msg) = require_unlocked(&app, &state, op) {
        return Ok(VerthysResponse::err(op, &msg));
    }
    ensure_module(&module)?;
    ensure_kind(&kind, &CRYPT_KINDS)?;

    let data = data.unwrap_or_default();
    let password = Zeroizing::new(password.unwrap_or_default());
    if password.len() > MAX_MODULE_SECRET_BYTES {
        return Ok(VerthysResponse::err(op, "文件口令超长"));
    }
    /* v2_check 的明文由 worker 固定，写入侧不接收调用方数据；其余布局
     * 无论加解密都必须携带非空载荷。 */
    ensure_data_len(&data, sealing && kind == "v2_check")?;

    let file_hash = file_hash.unwrap_or_default();
    let seq_value = seq.unwrap_or(0);
    let total_value = total.unwrap_or(0);
    let salt = salt.unwrap_or_default();
    let wrapped_key = wrapped_key.unwrap_or_default();
    if salt.len() > MAX_SALT_CHARS || wrapped_key.len() > MAX_WRAPPED_KEY_CHARS {
        return Ok(VerthysResponse::err(op, "文件盐或包裹密钥超出上限"));
    }

    if matches!(kind.as_str(), "slim_chunk" | "thumb" | "chunkset") && wrapped_key.is_empty() {
        return Ok(VerthysResponse::err(op, "包裹态文件密钥不能为空"));
    }
    if matches!(kind.as_str(), "v2_chunk" | "v2_check") && salt.is_empty() {
        return Ok(VerthysResponse::err(op, "文件盐不能为空"));
    }
    if matches!(kind.as_str(), "v2_chunk" | "v2_check") && password.is_empty() {
        return Ok(VerthysResponse::err(op, "文件口令不能为空"));
    }
    if matches!(
        kind.as_str(),
        "chunk" | "slim_chunk" | "thumb" | "chunkset"
    ) {
        ensure_hex_hash(&file_hash)?;
    }
    /* 记录型块的 seq/total 在写入时随密文落盘；瘦身块不携带位置，
     * 读写两侧都依赖调用方给出的位置。既有块解密时由密文内嵌值
     * 参与 AD，调用方无需提供。 */
    if sealing && matches!(kind.as_str(), "chunk" | "slim_chunk") {
        ensure_position(seq_value, total_value)?;
    }
    if kind == "slim_chunk" && !sealing {
        ensure_position(seq_value, total_value)?;
    }

    let req = json!({
        "op": op,
        "module": module,
        "kind": kind,
        "data": data,
        "salt": salt,
        "file_hash": file_hash,
        "seq": seq_value,
        "total": total_value,
        "wrapped_key": wrapped_key,
        "password": password.as_str(),
    });
    forward(&state, &req, CRYPT_OP_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_module_index_accepts_all_session_modules() {
        assert_eq!(module_index("photo").unwrap(), 0);
        assert_eq!(module_index("accounts").unwrap(), 1);
        assert_eq!(module_index("file").unwrap(), 2);
        assert_eq!(module_index("fileverthys").unwrap(), 2);
        assert!(module_index("").is_err());
        assert!(module_index("unknown").is_err());
    }

    #[test]
    fn content_module_and_kind_whitelists_reject_unknown_values() {
        assert!(ensure_module("photo").is_ok());
        assert!(ensure_module("file").is_ok());
        assert!(ensure_module("accounts").is_err());
        assert!(ensure_module("").is_err());

        assert!(ensure_kind("meta", &CRYPT_KINDS).is_ok());
        assert!(ensure_kind("v2_check", &CRYPT_KINDS).is_ok());
        assert!(ensure_kind("plaintext", &CRYPT_KINDS).is_err());
        assert!(ensure_kind("", &CRYPT_KINDS).is_err());
    }

    #[test]
    fn hash_and_position_validation_cover_boundaries() {
        let valid = "a".repeat(64);
        assert!(ensure_hex_hash(&valid).is_ok());
        assert!(ensure_hex_hash(&"g".repeat(64)).is_err());
        assert!(ensure_hex_hash(&"a".repeat(63)).is_err());
        assert!(ensure_hex_hash("").is_err());

        assert!(ensure_position(0, 1).is_ok());
        assert!(ensure_position(2, 3).is_ok());
        assert!(ensure_position(3, 3).is_err());
        assert!(ensure_position(0, 0).is_err());
    }

    #[test]
    fn payload_length_gate_rejects_empty_and_oversize() {
        assert!(ensure_data_len("YQ==", false).is_ok());
        assert!(ensure_data_len("", false).is_err());
        assert!(ensure_data_len("", true).is_ok());

        let oversize = "a".repeat(MAX_DATA_CHARS + 1);
        assert!(ensure_data_len(&oversize, false).is_err());
        let at_limit = "a".repeat(MAX_DATA_CHARS);
        assert!(ensure_data_len(&at_limit, false).is_ok());
    }
}
