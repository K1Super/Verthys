/*
 * 网格元数据、损坏探测与备份预览
 *
 * 职责边界：批量读取网格展示元数据与缩略图、损坏探测以及备份文件解析
 * 预览。解密与缩略图生成在 worker 内完成，宿主只转发与校验参数。
 */

use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::AppState;
use serde::Serialize;
use std::time::Duration;
use tauri::State;

use super::*;
/* ------------------------------------------------------------------ *
 * Phase 4：网格元数据、损坏探测与备份预览                             *
 * ------------------------------------------------------------------ */

const META_BATCH_MAX: usize = 32;
const META_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_BATCH_MAX: usize = 512;
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);
const PARSE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoMetaItem {
    pub meta_id: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub file_hash: String,
    pub entry_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub animated: Option<bool>,
    pub created_at: i64,
    pub slim: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoMetaBatch {
    pub items: Vec<PhotoMetaItem>,
    pub failed_ids: Vec<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoDamageScan {
    pub checked: u64,
    pub damaged: Vec<u64>,
    pub inconclusive: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoParsePreview {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub file_hash: String,
    pub thumb_b64: String,
    pub chunk_count: u32,
    pub created_at: i64,
}

/// 批量读取网格展示元数据与缩略图（worker 内解密，前端不再接触记录密文）。
#[tauri::command]
pub async fn photo_meta_get(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_ids: Vec<u64>,
) -> Result<PhotoMetaBatch, String> {
    require_unlocked(&app, &state, "photo_meta_get")?;
    let mut items = Vec::with_capacity(meta_ids.len());
    let mut failed_ids = Vec::new();
    for batch in meta_ids.chunks(META_BATCH_MAX) {
        let raw = send_worker(
            &app,
            serde_json::json!({"op": "photo_meta_get", "ids": batch}),
            META_TIMEOUT,
        )
        .await?;
        let reply = parse_reply("photo_meta_get", &raw)?;
        if !reply.ok {
            return Err(reply
                .error
                .unwrap_or_else(|| "照片元数据读取失败".to_string()));
        }
        for item in reply.photo_meta.unwrap_or_default() {
            items.push(PhotoMetaItem {
                meta_id: item.meta_id,
                name: item.name,
                mime: item.mime,
                size: item.size,
                file_hash: item.file_hash,
                entry_key: item.entry_key,
                thumb_b64: item.thumb_b64,
                animated: item.animated,
                created_at: item.created_at,
                slim: item.slim,
            });
        }
        failed_ids.extend(reply.failed_ids.unwrap_or_default());
    }
    Ok(PhotoMetaBatch { items, failed_ids })
}

/// 损坏扫描：只把内容层认证失败且非历史明文的记录判为确定损坏。
#[tauri::command]
pub async fn photo_meta_probe(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_ids: Vec<u64>,
) -> Result<PhotoDamageScan, String> {
    require_unlocked(&app, &state, "photo_meta_probe")?;
    let mut scan = PhotoDamageScan {
        checked: 0,
        damaged: Vec::new(),
        inconclusive: 0,
    };
    for batch in meta_ids.chunks(PROBE_BATCH_MAX) {
        let raw = send_worker(
            &app,
            serde_json::json!({"op": "photo_meta_probe", "ids": batch}),
            PROBE_TIMEOUT,
        )
        .await?;
        let reply = parse_reply("photo_meta_probe", &raw)?;
        if !reply.ok {
            return Err(reply
                .error
                .unwrap_or_else(|| "照片损坏扫描失败".to_string()));
        }
        let Some(part) = reply.photo_damage else {
            return Err("损坏扫描响应缺少结果".to_string());
        };
        scan.checked += part.checked;
        scan.damaged.extend(part.damaged);
        scan.inconclusive += part.inconclusive;
    }
    Ok(scan)
}

/// 备份预览：worker 流式解析 .venc 清单，不把容器读入前端。
#[tauri::command]
pub async fn photo_parse_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
    token: String,
) -> Result<Vec<PhotoParsePreview>, String> {
    require_unlocked(&app, &state, "photo_parse_start")?;
    if path.trim().is_empty() {
        return Err("未选择备份文件".to_string());
    }
    ensure_source_allowed(&path)?;
    let token = token.trim().to_string();
    if token.len() < 8 {
        return Err("令牌格式不正确（至少 8 位字符）".to_string());
    }
    let job_id = format!("parse-{}", generate_job_id());
    authorize_batch_for(&app, &job_id, std::slice::from_ref(&path), "photo_parse").await?;
    let result = send_worker(
        &app,
        serde_json::json!({
            "op": "photo_venc_inspect",
            "job_id": job_id,
            "path": path,
            "token": token,
        }),
        PARSE_TIMEOUT,
    )
    .await;
    // 预览不保留 worker job；end 幂等清理并撤销路径授权
    end_restore_job(&app, &job_id).await;
    let raw = result?;
    let reply = parse_reply("photo_venc_inspect", &raw)?;
    if !reply.ok {
        return Err(reply
            .error
            .unwrap_or_else(|| "备份文件解析失败".to_string()));
    }
    Ok(reply
        .photo_previews
        .unwrap_or_default()
        .into_iter()
        .map(|p| PhotoParsePreview {
            name: p.name,
            mime: p.mime,
            size: p.size,
            file_hash: p.file_hash,
            thumb_b64: p.thumb_b64,
            chunk_count: p.chunk_count,
            created_at: p.created_at,
        })
        .collect())
}
