/*
 * 文件收尾与结果组装
 *
 * 职责边界：放弃当前文件、磁盘空间校验、finish 参数校验、条目回填与
 * job 失效识别。
 */

use crate::constants::import_writer::MAX_RECORD_NAME_LEN;


use super::*;
/// 放弃当前文件：丢弃宿主缓冲，并让 worker 消费游标（错误忽略）。
///
/// worker 在下次 next 看到无当前文件时会清空该 job 的暂存，因此这里不需要
/// 逐块补偿删除；已提交的块由会话台账与孤儿回收结算。
pub(super) async fn abandon_file(app: &tauri::AppHandle, job_id: &str, file: &mut FileProgress) {
    file.buffer.clear();
    file.abandoned = true;
    let _ = finish_job(app, job_id, &[]).await;
}

/// 容器卷可用空间（读数不可得返回 None，调用方按“未知”处置）。
pub(super) fn container_free_bytes(path: Option<&str>) -> Option<u64> {
    path.and_then(|p| crate::util::disk::get_disk_space_bytes(std::path::Path::new(p)))
}

pub(super) fn required_space(size: u64) -> u64 {
    size.saturating_mul(DISK_HEADROOM_NUM) / DISK_HEADROOM_DEN
}

/// 收尾字段预校验：不完整就不写 meta，避免产生“已落盘但进不了列表”的孤条目。
pub(super) fn validate_finish(finish: &FileFinish) -> Result<(), String> {
    if finish.record_name.len() > MAX_RECORD_NAME_LEN {
        return Err("元数据记录名超长".to_string());
    }
    if finish.meta_b64.is_empty() {
        return Err("元数据载荷为空".to_string());
    }
    if finish.entry_key.len() != 64
        || !finish
            .entry_key
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("条目键格式非法".to_string());
    }
    if finish.encrypted
        && (finish.salt_b64.is_none()
            || finish.iterations.is_none()
            || finish.password_check.is_none())
    {
        return Err("加密条目的 KDF 参数或口令校验块缺失".to_string());
    }
    Ok(())
}

pub(super) fn build_entry(
    meta_id: u64,
    file: &FileProgress,
    finish: &FileFinish,
) -> Result<FileImportEntry, String> {
    if finish.record_name.len() > MAX_RECORD_NAME_LEN {
        return Err("元数据记录名超长".to_string());
    }
    let kdf = if finish.encrypted {
        let (Some(salt_b64), Some(iterations)) = (finish.salt_b64.clone(), finish.iterations)
        else {
            return Err("加密条目的 KDF 参数缺失".to_string());
        };
        if finish.password_check.is_none() {
            return Err("加密条目的口令校验块缺失".to_string());
        }
        Some(FileKdfOut {
            version: 2,
            salt_b64,
            iterations,
        })
    } else {
        None
    };
    Ok(FileImportEntry {
        meta_id,
        name: file.file_name.clone(),
        mime: file.mime.clone(),
        size: finish.size,
        total_chunks: finish.total_chunks,
        encrypted: finish.encrypted,
        meta_name: finish.record_name.clone(),
        meta_b64: finish.meta_b64.clone(),
        chunk_ids: file.chunk_ids.clone(),
        chunk_hashes: finish.chunk_hashes.clone(),
        chunk_size: crate::infrastructure::shm_schema::PB_MAX_FILE_CHUNK_SIZE_BYTES,
        file_hash: finish.file_hash.clone(),
        entry_key: finish.entry_key.clone(),
        kdf,
        password_check: finish.password_check.clone(),
    })
}

pub(super) fn is_job_gone(err: &str) -> bool {
    err.contains("job 不存在") || err.contains("已结束")
}
