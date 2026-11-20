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

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const GRANT_TTL: Duration = Duration::from_secs(30);
const MAX_GRANTS: usize = 32;
/// 批量导入 job 授权：与单路径授权分离，避免把 10,000 条路径塞进 32 条表。
const JOB_GRANT_TTL: Duration = Duration::from_secs(600);
const MAX_JOB_PATHS: usize = 10_000;
const MODE_READ: &str = "read";
const MODE_WRITE: &str = "write";

struct Grant {
    target_op: String,
    mode: String,
    path: String,
    expires_at: Instant,
}

struct JobGrant {
    target_op: String,
    paths: HashSet<String>,
    expires_at: Instant,
}

static GRANTS: Mutex<Vec<Grant>> = Mutex::new(Vec::new());
static JOB_GRANTS: Mutex<Vec<(String, JobGrant)>> = Mutex::new(Vec::new());

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

/// 按目标操作签发批量 job 授权（照片导入 / 备份还原）。
pub(crate) fn authorize_job_target(
    target_op: &str,
    job_id: &str,
    raw_paths: &[String],
) -> Result<(), String> {
    if job_id.is_empty() {
        return Err("job_id 不能为空".to_string());
    }
    if !is_allowed_pair(target_op, MODE_READ) {
        return Err("照片导入授权组合非法".to_string());
    }
    if raw_paths.is_empty() {
        return Err("路径列表为空".to_string());
    }
    if raw_paths.len() > MAX_JOB_PATHS {
        return Err(format!(
            "单 job 路径数超过上限: {} > {}",
            raw_paths.len(),
            MAX_JOB_PATHS
        ));
    }

    let mut paths = HashSet::with_capacity(raw_paths.len());
    for raw in raw_paths {
        paths.insert(normalize_path(raw)?);
    }

    let now = Instant::now();
    let mut grants = JOB_GRANTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    grants.retain(|(_, grant)| grant.expires_at > now);
    grants.retain(|(id, _)| id != job_id);
    grants.push((
        job_id.to_string(),
        JobGrant {
            target_op: target_op.to_string(),
            paths,
            expires_at: now + JOB_GRANT_TTL,
        },
    ));
    Ok(())
}

/// 成员校验：只判断路径是否属于该 job 且操作匹配，不消费授权。
pub(crate) fn job_contains_for(target_op: &str, job_id: &str, raw_path: &str) -> bool {
    let path = match normalize_path(raw_path) {
        Ok(path) => path,
        Err(_) => return false,
    };
    let now = Instant::now();
    let mut grants = JOB_GRANTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    grants.retain(|(_, grant)| grant.expires_at > now);
    grants.iter().any(|(id, grant)| {
        id == job_id && grant.target_op == target_op && grant.paths.contains(&path)
    })
}

/// 成员校验：只判断路径是否属于该 job，不消费授权（测试用）。
#[cfg(test)]
pub(crate) fn job_contains(job_id: &str, raw_path: &str) -> bool {
    let path = match normalize_path(raw_path) {
        Ok(path) => path,
        Err(_) => return false,
    };
    let now = Instant::now();
    let mut grants = JOB_GRANTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    grants.retain(|(_, grant)| grant.expires_at > now);
    grants
        .iter()
        .find(|(id, _)| id == job_id)
        .map(|(_, grant)| grant.paths.contains(&path))
        .unwrap_or(false)
}

/// job 结束/取消时立即销毁授权。
pub(crate) fn revoke_job(job_id: &str) {
    let mut grants = JOB_GRANTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    grants.retain(|(id, _)| id != job_id);
}

/// 预定义操作与模式组合。
fn is_allowed_pair(target_op: &str, mode: &str) -> bool {
    match target_op {
        "unlock" | "import" | "v4_unlock_recovery" | "v4_unlock_keyfile"
        | "v4_keyfile_disable" | "v4_reseal_device"
        | "v4_rotate_attach_keyfile" | "photo_import" | "photo_restore"
        | "photo_parse" => mode == MODE_READ,
        "v4_create" | "v4_create_keyfile"
        | "v4_keyfile_enable" | "export"
        | "v4_rotate_begin" => mode == MODE_WRITE,
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

    /// 全库轮换临时库路径只允许写授权；读授权必须被拒绝。
    #[test]
    fn grant_rotate_begin_only_accepts_write() {
        let path = temp_target("verthys-rotate-grant.tmp");
        authorize("v4_rotate_begin", MODE_WRITE, &path).unwrap();
        assert!(consume("v4_rotate_begin", MODE_WRITE, &path));
        assert!(authorize("v4_rotate_begin", MODE_READ, &path).is_err());
    }

    /// 轮换 keyfile 补录只接受读授权。
    #[test]
    fn grant_rotate_attach_keyfile_only_accepts_read() {
        let path = temp_target("verthys-rotate-keyfile-grant.tmp");
        authorize("v4_rotate_attach_keyfile", MODE_READ, &path).unwrap();
        assert!(consume("v4_rotate_attach_keyfile", MODE_READ, &path));
        assert!(authorize("v4_rotate_attach_keyfile", MODE_WRITE, &path).is_err());
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

    #[test]
    fn job_grant_is_bound_to_job_and_not_consumed() {
        let a = temp_target("verthys-job-a.jpg");
        let b = temp_target("verthys-job-b.jpg");
        authorize_job_target("photo_import", "job-1", &[a.clone(), b.clone()]).unwrap();

        assert!(job_contains("job-1", &a));
        assert!(job_contains("job-1", &a), "成员校验不得消费授权");
        assert!(!job_contains("job-2", &a), "跨 job 必须拒绝");
        assert!(!job_contains("job-1", &temp_target("other.jpg")));

        revoke_job("job-1");
        assert!(!job_contains("job-1", &a), "结束后授权必须销毁");
    }

    #[test]
    fn job_grant_rejects_empty_oversize_and_relative_paths() {
        assert!(authorize_job_target("photo_import", "", &[temp_target("x.jpg")]).is_err());
        assert!(authorize_job_target("photo_import", "job-empty", &[]).is_err());
        assert!(
            authorize_job_target("photo_import", "job-rel", &["relative.jpg".to_string()]).is_err()
        );

        let too_many: Vec<String> = (0..10_001)
            .map(|i| temp_target(&format!("verthys-many-{}.jpg", i)))
            .collect();
        assert!(authorize_job_target("photo_import", "job-many", &too_many).is_err());
    }

    /// 备份还原使用同一 job 授权通道，但只允许读模式。
    #[test]
    fn restore_and_parse_grants_are_read_only() {
        let path = temp_target("verthys-restore.venc");
        authorize_job_target("photo_restore", "job-restore", std::slice::from_ref(&path)).unwrap();
        assert!(job_contains("job-restore", &path));
        assert!(authorize_job_target("photo_restore", "job-x", &["rel.venc".to_string()]).is_err());

        authorize_job_target("photo_parse", "job-parse", std::slice::from_ref(&path)).unwrap();
        assert!(job_contains("job-parse", &path));
        assert!(!job_contains_for("photo_restore", "job-parse", &path), "跨操作不得复用授权");
        assert!(!job_contains_for("photo_import", "job-parse", &path), "跨操作不得复用授权");
        assert!(authorize_job_target("photo_parse", "job-y", &["rel.venc".to_string()]).is_err());
    }

    /// 大批量导入的常规规模必须被接受：1,000 条路径一次授权，成员校验可用。
    #[test]
    fn job_grant_accepts_thousand_paths() {
        let paths: Vec<String> = (0..1_000)
            .map(|i| temp_target(&format!("verthys-bulk-{}.jpg", i)))
            .collect();
        authorize_job_target("photo_import", "job-bulk", &paths).expect("1,000 条路径应被接受");
        assert!(job_contains("job-bulk", &paths[0]));
        assert!(job_contains("job-bulk", &paths[999]));
        revoke_job("job-bulk");
    }
}
