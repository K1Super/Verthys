//! e2e_measure 公共辅助：环境变量解析、尺寸矩阵、JSON 判定、原生协议发送与 E2E 状态隔离。

use std::time::Duration;

use crate::worker::budget::PB_PHOTO_CHUNK_SIZE_BYTES;
use crate::worker::WorkerSession;

/// 照片分块大小：取跨层预算单一权威值，不再保留本地副本。
pub(super) const PHOTO_CHUNK_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
/// 照片数据块记录类型。
pub(super) const TYPE_PHOTO_CHUNK: u32 = 5;
/// 照片 meta 记录类型。
pub(super) const TYPE_PHOTO_META: u32 = 1;

pub(super) fn env_usize(name: &str, default: usize) -> usize
{
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// 解析待测照片尺寸（字节）。
///
/// 优先级：精确字节 > 小数 MB 列表 > 单值 MB > 缺省矩阵 10/17.73/24.43。
/// 支持 17.73、24.43 这类真实文件大小；10MB 只是最小样本，不是上限。
pub(super) fn env_photo_sizes_bytes() -> Vec<usize>
{
    let mut sizes: Vec<usize> = Vec::new();

    if let Ok(raw) = std::env::var("VERTHYS_WORKER_E2E_PHOTO_BYTES") {
        if let Ok(v) = raw.trim().parse::<usize>() {
            if v > 0 {
                sizes.push(v);
            }
        }
    }
    if sizes.is_empty() {
        if let Ok(raw) = std::env::var("VERTHYS_WORKER_E2E_PHOTO_SIZES_MB") {
            for token in raw.split(',') {
                if let Ok(mb) = token.trim().parse::<f64>() {
                    if mb.is_finite() && mb > 0.0 {
                        sizes.push((mb * 1024.0 * 1024.0).round() as usize);
                    }
                }
            }
        }
    }
    if sizes.is_empty() {
        if let Ok(raw) = std::env::var("VERTHYS_WORKER_E2E_PHOTO_MB") {
            if let Ok(mb) = raw.trim().parse::<f64>() {
                if mb.is_finite() && mb > 0.0 {
                    sizes.push((mb * 1024.0 * 1024.0).round() as usize);
                }
            }
        }
    }
    if sizes.is_empty() {
        /* 缺省跑小矩阵：10MiB 只是最小样本，缺省也覆盖实拍大图尺寸。 */
        for mb in [10.0_f64, 17.73, 24.43] {
            sizes.push((mb * 1024.0 * 1024.0).round() as usize);
        }
    }
    sizes.dedup();
    sizes
}

/// 以 MiB（1024²）展示尺寸；与 Windows 资源管理器显示的“MB”口径一致。
pub(super) fn mib_text(bytes: usize) -> String
{
    format!("{:.2}", bytes as f64 / (1024.0 * 1024.0))
}

pub(super) fn json_ok(resp: &str) -> bool
{
    serde_json::from_str::<serde_json::Value>(resp)
        .ok()
        .and_then(|v| v.get("ok").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// 单次 add_records 的 base64 载荷上限（与 worker/IPC 预算一致，留出余量）。
pub(super) const ADD_RECORDS_PAYLOAD_BUDGET: usize = 12 * 1024 * 1024;

pub(super) const NATIVE_MIB: u64 = 1024 * 1024;
pub(super) const NATIVE_CHUNK_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
/// 单个协议请求的超时：一次 next/add_records 可能承载整块 4MiB 密文。
const NATIVE_OP_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) fn native_chunk_total(size: u64) -> usize
{
    size.div_ceil(NATIVE_CHUNK_BYTES as u64) as usize
}

pub(super) fn native_mb_label(mb: f64) -> String
{
    if mb.fract() == 0.0 {
        format!("{}", mb as u64)
    } else {
        format!("{}", mb)
    }
}

pub(super) fn native_send(
    session: &WorkerSession,
    request: serde_json::Value,
) -> Result<serde_json::Value, String>
{
    let op = request
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let raw = session
        .send_json_with_timeout(&request.to_string(), NATIVE_OP_TIMEOUT)
        .map_err(|e| format!("{op} 请求失败: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{op} 响应解析失败: {e}"))
}

pub(super) fn native_send_ok(
    session: &WorkerSession,
    request: serde_json::Value,
) -> Result<serde_json::Value, String>
{
    let op = request
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let value = native_send(session, request)?;
    if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        return Ok(value);
    }
    let detail = value
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("无错误信息");
    Err(format!("{op} 失败: {detail}"))
}

/// 写入单条记录并返回 C 层分配的 ID；ID=0 视为失败（finish 明确拒绝 0）。
pub(super) fn native_add_record(
    session: &WorkerSession,
    rtype: u32,
    name: &str,
    data_b64: &str,
) -> Result<u64, String>
{
    let value = native_send_ok(
        session,
        serde_json::json!({
            "op": "add_records",
            "records": [{"rtype": rtype, "name": name, "data": data_b64}],
        }),
    )?;
    let ids = value
        .get("ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("add_records 响应缺少 ids: name={name}"))?;
    if ids.len() != 1 {
        return Err(format!(
            "add_records 返回 {} 个 id（期望 1）: name={name}",
            ids.len()
        ));
    }
    let id = ids[0]
        .as_u64()
        .ok_or_else(|| format!("add_records id 非法: name={name}"))?;
    if id == 0 {
        return Err(format!("add_records 返回 id=0: name={name}"));
    }
    Ok(id)
}

/// 提交一块 worker 暂存密文（引用提交，不携带密文）。
pub(super) fn native_add_staged(
    session: &WorkerSession,
    job_id: &str,
    rtype: u32,
    name: &str,
    chunk_key: &str,
    chunk_hash: &str,
) -> Result<u64, String>
{
    let value = native_send_ok(
        session,
        serde_json::json!({
            "op": "add_records_staged",
            "staged_records": [{
                "rtype": rtype,
                "name": name,
                "job_id": job_id,
                "chunk_key": chunk_key,
                "chunk_hash": chunk_hash,
            }],
        }),
    )?;
    let ids = value
        .get("ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("add_records_staged 响应缺少 ids: name={name}"))?;
    if ids.len() != 1 {
        return Err(format!(
            "add_records_staged 返回 {} 个 id（期望 1）: name={name}",
            ids.len()
        ));
    }
    let id = ids[0]
        .as_u64()
        .ok_or_else(|| format!("add_records_staged id 非法: name={name}"))?;
    if id == 0 {
        return Err(format!("add_records_staged 返回 id=0: name={name}"));
    }
    Ok(id)
}

#[derive(Default)]
pub(super) struct NativeTotals {
    pub(super) files: usize,
    pub(super) chunks: usize,
    pub(super) bytes: u64,
}

/// E2E 安全状态隔离：把 rollback/lockout 状态写入临时目录，避免消耗
/// 真实环境有限的 rollback.state 槽位。仅测试构建的 DLL 识别该变量。
static E2E_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) struct E2eStateGuard {
    dir: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl E2eStateGuard {
    pub(super) fn new() -> Self {
        let lock = E2E_STATE_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = tempfile::tempdir().expect("创建 E2E 状态目录失败");
        let previous = std::env::var_os("VERTHYS_TEST_STATE_DIR");
        std::env::set_var("VERTHYS_TEST_STATE_DIR", dir.path());
        Self {
            dir,
            previous,
            _lock: lock,
        }
    }

    /// 隔离目录中的回退状态文件路径；用于断言测试构建确实使用了该目录。
    pub(super) fn rollback_state_path(&self) -> std::path::PathBuf {
        self.dir.path().join("rollback.state")
    }
}

impl Drop for E2eStateGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var("VERTHYS_TEST_STATE_DIR", value),
            None => std::env::remove_var("VERTHYS_TEST_STATE_DIR"),
        }
    }
}

#[test]
fn e2e_state_guard_sets_and_restores_isolated_dir() {
    let previous = std::env::var_os("VERTHYS_TEST_STATE_DIR");
    let isolated;
    {
        let guard = E2eStateGuard::new();
        isolated = guard.dir.path().to_path_buf();
        assert_eq!(
            std::env::var_os("VERTHYS_TEST_STATE_DIR"),
            Some(isolated.clone().into_os_string())
        );
        assert!(!guard.rollback_state_path().exists());
    }
    assert_eq!(std::env::var_os("VERTHYS_TEST_STATE_DIR"), previous);
}
