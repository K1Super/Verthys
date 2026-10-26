/* module_crypto_controller.rs — 内容层加密命令（前端 → 主进程 → worker）
 *
 * 职责：校验模块、布局与尺寸边界，把请求转发给 worker 的 module_* 操作，
 * 并把句柄与公开参数透传前端。模块密钥与文件密钥始终只存在于 worker
 * 进程内；本层请求/响应不含原始密钥。
 *
 * 安全约束：
 *   - 仅接受白名单模块与布局，未知取值直接拒绝；
 *   - 消耗模块密钥的操作要求容器已解锁；
 *   - 锁定命令不设解锁闸门，保证锁定态下仍能清理 worker 驻留密钥；
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
/// 文件块 v2 迭代次数下限：低于此值视为参数被篡改
const V2_MIN_ITERATIONS: u32 = 10_000;
/// 文件块 v2 迭代次数上限：拒绝超长派生拖垮 worker
const V2_MAX_ITERATIONS: u32 = 10_000_000;
/// 首次派生需要 PBKDF2 150000 轮，留出冷启动余量
const KEY_OP_TIMEOUT: Duration = Duration::from_secs(30);
/// 内容加解密超时：单块上限 1MiB，30 秒覆盖极端机器抖动
const CRYPT_OP_TIMEOUT: Duration = Duration::from_secs(30);

const MODULE_WHITELIST: [&str; 2] = ["photo", "file"];
const FILE_KEY_KINDS: [&str; 1] = ["slim_create"];
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

fn ensure_module(module: &str) -> Result<(), String> {
    if MODULE_WHITELIST.contains(&module) {
        Ok(())
    } else {
        Err("模块标识非法".into())
    }
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
    serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))
}

/// 解锁模块密钥：把模块口令一次性交付 worker 托管。
///
/// 口令正确性由模块解锁链路判定；本命令不引入可离线验证的校验块。
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
    ensure_module(&module)?;
    if password.is_empty() || password.len() > MAX_MODULE_SECRET_BYTES {
        return Ok(VerthysResponse::err("module_key_unlock", "模块口令长度非法"));
    }
    let password = Zeroizing::new(password);
    let req = json!({
        "op": "module_key_unlock",
        "module": module,
        "password": password.as_str(),
    });
    forward(&state, &req, KEY_OP_TIMEOUT)
}

/// 清除模块密钥；module 为空表示全部清除。
///
/// 不设解锁闸门：锁定态必须先清空 worker 驻留密钥，闸门会阻断清理。
#[tauri::command]
pub async fn verthys_module_key_lock(
    state: State<'_, AppState>,
    module: Option<String>,
) -> Result<VerthysResponse, String> {
    let module = module.unwrap_or_default();
    if !module.is_empty() {
        ensure_module(&module)?;
    }
    let req = json!({
        "op": "module_key_lock",
        "module": module,
    });
    forward(&state, &req, KEY_OP_TIMEOUT)
}

/// 创建瘦身布局的文件密钥组。
///
/// 返回文件盐与包裹态文件密钥（均为可落盘的公开参数）；随机文件密钥由
/// worker 生成并立即包裹，不经响应返回，调用方后续只用包裹态密钥引用。
#[tauri::command]
pub async fn verthys_module_file_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module: String,
    kind: String,
    wrapped_key: Option<String>,
    salt: Option<String>,
    iterations: Option<u32>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "module_file_key") {
        return Ok(VerthysResponse::err("module_file_key", &msg));
    }
    ensure_module(&module)?;
    ensure_kind(&kind, &FILE_KEY_KINDS)?;

    let wrapped_key = wrapped_key.unwrap_or_default();
    let salt = salt.unwrap_or_default();
    if wrapped_key.len() > MAX_WRAPPED_KEY_CHARS || salt.len() > MAX_SALT_CHARS {
        return Ok(VerthysResponse::err("module_file_key", "密钥参数超出上限"));
    }
    if kind == "slim_create" && (!wrapped_key.is_empty() || !salt.is_empty()) {
        return Ok(VerthysResponse::err("module_file_key", "创建文件密钥不需要外部密钥参数"));
    }
    let iterations = iterations.unwrap_or(0);
    if iterations != 0 && !(V2_MIN_ITERATIONS..=V2_MAX_ITERATIONS).contains(&iterations) {
        return Ok(VerthysResponse::err("module_file_key", "迭代次数非法"));
    }

    let req = json!({
        "op": "module_file_key",
        "module": module,
        "kind": kind,
        "wrapped_key": wrapped_key,
        "salt": salt,
        "iterations": iterations,
    });
    forward(&state, &req, KEY_OP_TIMEOUT)
}

/// 加密内容记录；密钥来自 worker 内的模块密钥或包裹态文件密钥。
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
    fn module_and_kind_whitelists_reject_unknown_values() {
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
