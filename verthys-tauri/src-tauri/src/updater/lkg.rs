/*
 * updater/lkg.rs — 上一已知良好安装包
 *
 * 新版本健康自检失败时，唯一可执行的恢复动作是用上一个已确认版本的安装包
 * 重新覆盖。回退物料必须在安装前复制到应用数据目录，并在使用前重新校验
 * 签名、哈希与 PE 版本；缺失或校验失败时只能如实报告不可用。
 */

use super::log;
use super::manifest::ValidatedManifest;
use super::marker::{self, LkgRecord};
use super::pe;
use super::verify;
use super::PreparedBytes;
use super::UpdaterError;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tauri::AppHandle;

/// 已知良好物料指针文件名。
const CURRENT_FILE: &str = "current.json";
/// 候选物料最长保留时间；未被标记引用的候选属于异常残留。
const CANDIDATE_RETENTION_HOURS: i64 = 24 * 7;
/// 已知良好物料保留份数。
const KNOWN_GOOD_KEEP: usize = 2;

pub(crate) fn lkg_dir(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    let dir = marker::updater_dir(app)?.join("lkg");
    std::fs::create_dir_all(&dir).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法创建回退物料目录: {error}"),
            true,
        )
    })?;
    Ok(dir)
}

fn current_path(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    Ok(lkg_dir(app)?.join(CURRENT_FILE))
}

/// 读取当前已知良好物料；文件不存在或内容非法均视为无可用物料。
pub fn current(app: &AppHandle) -> Result<Option<LkgRecord>, UpdaterError> {
    let path = current_path(app)?;
    let payload = match std::fs::read(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(UpdaterError::new(
                "E_UPDATER_INTERNAL",
                format!("无法读取回退物料指针: {error}"),
                true,
            ))
        }
    };
    match serde_json::from_slice::<LkgRecord>(&payload) {
        Ok(record) => Ok(Some(record)),
        Err(_) => {
            // 指针损坏不应阻断新的更新；隔离后按“无已知良好物料”处理。
            let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
            let _ = std::fs::rename(
                &path,
                path.with_file_name(format!("current.corrupt-{stamp}.json")),
            );
            log::append(
                app,
                "repair_failed",
                "Lkg",
                Some("E_UPDATER_MARKER_INVALID"),
                "warn",
                serde_json::json!({ "stage": "current_pointer" }),
            );
            Ok(None)
        }
    }
}

/// 将本次安装包复制为候选物料；返回的记录写入标记，健康确认后晋升。
pub fn stage_candidate(
    app: &AppHandle,
    manifest: &ValidatedManifest,
    prepared: &PreparedBytes,
    signature: &str,
) -> Result<LkgRecord, UpdaterError> {
    let dir = lkg_dir(app)?;
    let exe = dir.join(format!("candidate-{}.exe", manifest.release_id));
    marker::write_atomic(&exe, &prepared.bytes)?;
    let record = LkgRecord {
        path: exe.to_string_lossy().to_string(),
        sha256: prepared.sha256.clone(),
        version: manifest.version.clone(),
        file_version: prepared.file_version.clone(),
        release_id: manifest.release_id.clone(),
        signature: signature.to_string(),
    };
    let meta = dir.join(format!("candidate-{}.json", manifest.release_id));
    let payload = serde_json::to_vec_pretty(&record).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("候选物料记录序列化失败: {error}"),
            true,
        )
    })?;
    marker::write_atomic(&meta, &payload)?;
    Ok(record)
}

/// 健康确认后把候选物料晋升为已知良好物料，并清理过期候选。
pub fn promote(app: &AppHandle, candidate: &LkgRecord) -> Result<(), UpdaterError> {
    let dir = lkg_dir(app)?;
    let source = PathBuf::from(&candidate.path);
    if !source.exists() {
        return Err(UpdaterError::new(
            "E_UPDATER_ROLLBACK_MATERIAL_MISSING",
            "候选回退物料不存在",
            false,
        ));
    }
    let target = dir.join(format!("known-good-{}.exe", candidate.version));
    let bytes = std::fs::read(&source).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法读取候选回退物料: {error}"),
            true,
        )
    })?;
    marker::write_atomic(&target, &bytes)?;

    let mut record = candidate.clone();
    record.path = target.to_string_lossy().to_string();
    let payload = serde_json::to_vec_pretty(&record).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("回退物料指针序列化失败: {error}"),
            true,
        )
    })?;
    marker::write_atomic(&current_path(app)?, &payload)?;

    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(dir.join(format!("candidate-{}.json", candidate.release_id)));
    prune_known_good(&dir);
    let _ = cleanup_candidates(app, Some(&candidate.release_id));
    Ok(())
}

/// 校验回退物料：签名、哈希与 PE 版本必须全部一致。
pub fn verify(app: &AppHandle, record: &LkgRecord) -> Result<(), UpdaterError> {
    let path = PathBuf::from(&record.path);
    let bytes = std::fs::read(&path).map_err(|_| material_missing("无法读取回退安装包"))?;
    if bytes.is_empty() || format!("{:x}", Sha256::digest(&bytes)) != record.sha256 {
        return Err(material_missing("回退安装包校验失败"));
    }
    verify::verify_installer(app, &bytes, &record.signature)
        .map_err(|_| material_missing("回退安装包签名不受信任"))?;
    let file_version = pe::file_version_from_bytes(&bytes)
        .map_err(|_| material_missing("回退安装包缺少版本资源"))?;
    if file_version != record.file_version || file_version != record.version {
        return Err(material_missing("回退安装包版本与记录不一致"));
    }
    Ok(())
}

/// 清理超过保留期的候选物料；被当前标记引用的候选不删除。
pub fn cleanup_candidates(app: &AppHandle, keep_release: Option<&str>) -> Result<(), UpdaterError> {
    let dir = lkg_dir(app)?;
    let cutoff = Utc::now() - chrono::Duration::hours(CANDIDATE_RETENTION_HOURS);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("candidate-") {
            continue;
        }
        if keep_release.is_some_and(|release| name.contains(release)) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let modified: chrono::DateTime<Utc> = modified.into();
        if modified < cutoff {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}

fn prune_known_good(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !name.starts_with("known-good-") || !name.ends_with(".exe") {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect();
    files.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, path) in files.into_iter().skip(KNOWN_GOOD_KEEP) {
        let _ = std::fs::remove_file(path);
    }
}

fn material_missing(detail: &str) -> UpdaterError {
    UpdaterError::new("E_UPDATER_ROLLBACK_MATERIAL_MISSING", detail, false)
}

#[cfg(test)]
mod tests {
    use super::KNOWN_GOOD_KEEP;

    #[test]
    fn known_good_retention_is_bounded() {
        assert_eq!(KNOWN_GOOD_KEEP, 2);
    }
}
