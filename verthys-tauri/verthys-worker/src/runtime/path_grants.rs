/*
 * runtime/path_grants.rs — worker 侧路径授权表
 *
 * 职责边界：保存宿主签发的一次性路径能力，并在路径型操作执行前消费。
 * 不执行文件 I/O 以外的业务逻辑，不访问容器内容。
 *
 * 安全约束：
 *   - 授权与 target_op、mode、规范化路径三元组严格绑定；
 *   - 授权 30 秒过期，最多 32 条，消费即删除；
 *   - 只接受绝对路径，拒绝 NUL、设备命名空间与全局根前缀；
 *   - 授权表只在内存中存在，不落盘、不日志输出路径。
 *
 * 线程安全：Mutex 保护；路径规范化在锁外完成，避免持锁做文件系统调用。
 */

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const GRANT_TTL: Duration = Duration::from_secs(30);
const MAX_GRANTS: usize = 32;
const MODE_READ: &str = "read";
const MODE_WRITE: &str = "write";

struct Grant {
    target_op: String,
    mode: String,
    path: String,
    expires_at: Instant,
}

static GRANTS: Mutex<Vec<Grant>> = Mutex::new(Vec::new());

/// 签发一次性路径授权。
///
/// `target_op` 与 `mode` 必须是预定义组合，拒绝任意配对扩大权限面。
pub(crate) fn authorize(target_op: &str, mode: &str, raw_path: &str) -> Result<(), String> {
    if !is_allowed_pair(target_op, mode) {
        return Err("路径授权的操作与模式组合非法".to_string());
    }
    let path = normalize_path(raw_path)?;
    let now = Instant::now();

    let mut grants = GRANTS.lock().unwrap_or_else(|poison| poison.into_inner());
    grants.retain(|grant| grant.expires_at > now);
    grants.retain(|grant| {
        !(grant.target_op == target_op && grant.mode == mode && grant.path == path)
    });
    if grants.len() >= MAX_GRANTS {
        return Err("路径授权表已满".to_string());
    }
    grants.push(Grant {
        target_op: target_op.to_string(),
        mode: mode.to_string(),
        path,
        expires_at: now + GRANT_TTL,
    });
    Ok(())
}

/// 消费完全匹配的路径授权；过期、跨操作、跨模式均视为未授权。
pub(crate) fn consume(target_op: &str, mode: &str, raw_path: &str) -> bool {
    let path = match normalize_path(raw_path) {
        Ok(path) => path,
        Err(_) => return false,
    };
    let now = Instant::now();

    let mut grants = GRANTS.lock().unwrap_or_else(|poison| poison.into_inner());
    grants.retain(|grant| grant.expires_at > now);
    if let Some(index) = grants.iter().position(|grant| {
        grant.target_op == target_op && grant.mode == mode && grant.path == path
    }) {
        grants.remove(index);
        true
    } else {
        false
    }
}

/// 预定义操作与模式组合。
fn is_allowed_pair(target_op: &str, mode: &str) -> bool {
    match target_op {
        "unlock" | "import" => mode == MODE_READ,
        "create_with_preset" | "export" => mode == MODE_WRITE,
        _ => false,
    }
}

/// 规范化路径：存在路径完整规范化；不存在路径规范化父目录后拼接文件名。
fn normalize_path(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.contains('\0') {
        return Err("路径为空或含非法字符".to_string());
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err("路径必须是绝对路径".to_string());
    }

    let upper = raw.replace('/', "\\").to_ascii_uppercase();
    if upper.starts_with("\\\\.\\") || upper.starts_with("\\\\?\\GLOBALROOT") {
        return Err("路径命名空间非法".to_string());
    }

    if path.exists() {
        let canonical =
            std::fs::canonicalize(path).map_err(|e| format!("路径规范化失败: {}", e))?;
        return Ok(canonical.to_string_lossy().to_string());
    }

    let parent = path
        .parent()
        .ok_or_else(|| "路径缺少父目录".to_string())?;
    let name = path
        .file_name()
        .ok_or_else(|| "路径缺少文件名".to_string())?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|e| format!("父目录规范化失败: {}", e))?;
    Ok(canonical_parent.join(name).to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_target(name: &str) -> String {
        let dir = std::env::temp_dir();
        dir.join(name).to_string_lossy().to_string()
    }

    #[test]
    fn grant_consumed_once() {
        let path = temp_target("verthys-grant-once.tmp");
        authorize("unlock", MODE_READ, &path).unwrap();
        assert!(consume("unlock", MODE_READ, &path));
        assert!(!consume("unlock", MODE_READ, &path));
    }

    #[test]
    fn grant_rejects_op_mode_mismatch() {
        let path = temp_target("verthys-grant-mismatch.tmp");
        authorize("unlock", MODE_READ, &path).unwrap();
        assert!(!consume("export", MODE_READ, &path));
        assert!(!consume("unlock", MODE_WRITE, &path));
    }

    #[test]
    fn grant_rejects_invalid_pairs_and_relative_paths() {
        assert!(authorize("unlock", MODE_WRITE, &temp_target("x.tmp")).is_err());
        assert!(authorize("export", MODE_READ, &temp_target("x.tmp")).is_err());
        assert!(authorize("unlock", MODE_READ, "relative.tmp").is_err());
        assert!(authorize("unlock", MODE_READ, "").is_err());
    }
}
