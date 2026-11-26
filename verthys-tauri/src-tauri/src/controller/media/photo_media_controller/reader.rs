/*
 * 预览与原图分块读取
 *
 * 职责边界：预览首屏懒生成与缓存命中、原图分块读取协议与一致性校验、
 * 读取作业取消。块序号/总数/结束标志/载荷长度任一不自洽即拒绝。
 */

use crate::constants::is_valid_shm_name;
use crate::constants::record_types::TYPE_PHOTO_PREVIEW;
use crate::infrastructure::shared_memory::read_shm_blob;
use crate::controller::vault::verthys_batch_controller::submit_writer_cmd;
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::import_writer::{self, WriterCommand};
use crate::state::AppState;
use crate::util::contracts::BatchRecordInput;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use std::time::{Duration, Instant};
use tauri::ipc::Response as IpcResponse;
use tauri::State;
use zeroize::Zeroizing;

use super::*;
/* ------------------------------------------------------------------ *
 * Phase 2：预览与原图读取                                             *
 * ------------------------------------------------------------------ */

/// 预览首屏预算：历史照片首次懒生成需要读块/解码/编码，给足余量
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(120);
const READ_BEGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// 单块解密超时：4MiB 块 + AEAD 在低端机也有充足余量
const READ_NEXT_TIMEOUT: Duration = Duration::from_secs(60);
const READ_END_TIMEOUT: Duration = Duration::from_secs(10);
/// 预览派生记录写入（单条 add_record，含 TPM 锚点提交）
const DERIVED_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// 布局不支持原生读取：前端据此回退旧 JS 查看链路。
pub const PHOTO_LAYOUT_UNSUPPORTED: &str = "E_PHOTO_LAYOUT_UNSUPPORTED";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPreviewResult {
    pub data_b64: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// true=命中已落库预览记录；false=本次懒生成
    pub cached: bool,
    pub elapsed_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoFullBegin {
    pub job_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunk_total: u32,
}

/// 原图块一致性校验：序号/总数/结束标志/载荷长度任一不自洽即拒绝。
///
/// 前端按 begin.chunkTotal 精确拉取，最后一块必须且只能由 worker 标记 done；
/// 空块在本协议中不合法（照片明文大小为 0 的元数据在 begin 阶段已被拒绝）。
fn validate_full_chunk(
    done: bool,
    chunk_index: u32,
    chunk_total: u32,
    payload_len: usize,
) -> Result<(), &'static str> {
    if chunk_total == 0 {
        return Err("chunk_total is zero");
    }
    if chunk_index >= chunk_total {
        return Err("chunk_index out of range");
    }
    if done != (chunk_index + 1 == chunk_total) {
        return Err("done flag inconsistent with chunk index/total");
    }
    if payload_len == 0 {
        return Err("empty chunk payload");
    }
    Ok(())
}

fn read_error(reply: &WorkerReply) -> String {
    if let Some(code) = reply.error_code.as_deref() {
        return format!("{}: {}", code, reply.error.clone().unwrap_or_default());
    }
    reply
        .error
        .clone()
        .unwrap_or_else(|| "照片读取失败".to_string())
}

async fn end_read_job(app: &tauri::AppHandle, job_id: &str) {
    let _ = send_worker(
        app,
        serde_json::json!({"op": "photo_read_job_end", "job_id": job_id}),
        READ_END_TIMEOUT,
    )
    .await;
}

/// 读取预览：命中预览记录直接返回；缺失时 worker 懒生成并回传待写记录。
#[tauri::command]
pub async fn photo_preview_get(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_id: u64,
) -> Result<PhotoPreviewResult, String> {
    let started = Instant::now();
    require_unlocked(&app, &state, "photo_preview_get")?;
    if meta_id == 0 {
        return Err("照片 ID 非法".to_string());
    }

    let job_id = format!("preview-{}", generate_job_id());
    let raw = send_worker(
        &app,
        serde_json::json!({
            "op": "photo_read_job_begin",
            "job_id": job_id,
            "mode": "preview",
            "meta_id": meta_id,
        }),
        PREVIEW_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_read_job_begin", &raw)?;
    if !reply.ok {
        return Err(read_error(&reply));
    }
    let read = reply
        .photo_read
        .ok_or_else(|| "预览响应缺少结果".to_string())?;
    if read.status != "preview" {
        return Err(format!("预览状态异常: {}", read.status));
    }
    let data_b64 = read
        .data_b64
        .ok_or_else(|| "预览响应缺少图像数据".to_string())?;

    // 懒生成的预览：经单写者落库；失败只告警，本次仍返回已生成字节
    if let Some(record) = reply.photo_record {
        let write = async {
            let writer = import_writer::ensure(&app)?;
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<Result<u64, String>>();
            let cmd = WriterCommand::AppendDerived {
                record: BatchRecordInput {
                    rtype: TYPE_PHOTO_PREVIEW,
                    name: record.name,
                    entry_key: String::new(),
                    data_b64: record.data_b64,
                    chunk_ids: None,
                    chunk_hashes: None,
                },
                reply: reply_tx,
            };
            submit_writer_cmd(&writer, cmd, reply_rx).await
        };
        match tokio::time::timeout(DERIVED_WRITE_TIMEOUT, write).await {
            Ok(Ok(_id)) => {}
            Ok(Err(e)) => log::warn!("[photo_preview] 预览记录写入失败（不影响本次显示）: {}", e),
            Err(_) => log::warn!("[photo_preview] 预览记录写入超时（不影响本次显示）"),
        }
    }

    // 预览为一次性操作，begin 不保留 worker job；end 幂等清理
    end_read_job(&app, &job_id).await;

    Ok(PhotoPreviewResult {
        data_b64,
        name: read.name.unwrap_or_default(),
        mime: read.mime.unwrap_or_default(),
        size: read.size.unwrap_or(0),
        cached: read.preview_cached.unwrap_or(false),
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// 打开原图读取 job；返回块数与显示字段。
#[tauri::command]
pub async fn photo_full_begin(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_id: u64,
) -> Result<PhotoFullBegin, String> {
    require_unlocked(&app, &state, "photo_full_begin")?;
    if meta_id == 0 {
        return Err("照片 ID 非法".to_string());
    }
    let job_id = format!("full-{}", generate_job_id());
    /* 每 job 一次性 SHM 认证密钥：随 begin 请求经签名 IPC 下发 worker，
     * 仅用于校验原图明文块，不落盘、不返回前端。 */
    let mut shm_key = Zeroizing::new(vec![0u8; 32]);
    crate::util::random::fill_random_bytes(&mut shm_key[..]);
    let shm_key_b64 = crate::util::base64::base64_encode(&shm_key);
    let raw = send_worker(
        &app,
        serde_json::json!({
            "op": "photo_read_job_begin",
            "job_id": job_id,
            "mode": "full",
            "meta_id": meta_id,
            "shm_key": shm_key_b64,
        }),
        READ_BEGIN_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_read_job_begin", &raw)?;
    if !reply.ok {
        return Err(read_error(&reply));
    }
    let read = reply
        .photo_read
        .ok_or_else(|| "原图读取响应缺少结果".to_string())?;
    let chunk_total = read.chunk_total.unwrap_or(0);
    if chunk_total == 0 {
        end_read_job(&app, &job_id).await;
        return Err("原图分块数量非法".to_string());
    }
    state.set_photo_read_key(&job_id, shm_key);
    Ok(PhotoFullBegin {
        job_id,
        name: read.name.unwrap_or_default(),
        mime: read.mime.unwrap_or_default(),
        size: read.size.unwrap_or(0),
        chunk_total,
    })
}

/// 拉取下一块原图明文。
///
/// 返回 `tauri::ipc::Response` 裸载荷：没有帧头、没有 base64 编解码、
/// 没有 1.33× 体积放大。前端按 `photo_full_begin` 返回的 `chunkTotal`
/// 精确拉取；宿主校验块序号/总数/done 一致性。worker 明文块经共享内存
/// 传递，宿主读取后立即验签并覆写使用区。done=true 时 worker job 已自动结束。
#[tauri::command]
pub async fn photo_full_next(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    job_id: String,
) -> Result<IpcResponse, String> {
    let result = photo_full_next_inner(&app, &state, &job_id).await;
    /* 任一错误路径都必须结束 worker 读取 job：仅清宿主密钥会让 job 占满
     * 并发读取槽位直到 TTL，累计后原图查看整体不可用。 */
    if result.is_err() {
        state.remove_photo_read_key(&job_id);
        end_read_job(&app, &job_id).await;
    }
    result
}

async fn photo_full_next_inner(
    app: &tauri::AppHandle,
    state: &State<'_, AppState>,
    job_id: &str,
) -> Result<IpcResponse, String> {
    require_unlocked(app, state, "photo_full_next")?;
    if job_id.is_empty() {
        return Err("读取 job 非法".to_string());
    }
    let raw = send_worker(
        &app,
        serde_json::json!({"op": "photo_read_job_next", "job_id": job_id}),
        READ_NEXT_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_read_job_next", &raw)?;
    if !reply.ok {
        state.remove_photo_read_key(&job_id);
        return Err(read_error(&reply));
    }
    let read = reply
        .photo_read
        .ok_or_else(|| "原图读取响应缺少结果".to_string())?;
    let done = match read.status.as_str() {
        "chunk" => false,
        "done" => true,
        "cancelled" => {
            state.remove_photo_read_key(&job_id);
            return Err("E_PHOTO_READ_CANCELLED".to_string());
        }
        other => {
            state.remove_photo_read_key(&job_id);
            return Err(format!("原图读取状态异常: {}", other));
        }
    };

    let payload: Vec<u8> = match (read.shm_name.as_deref(), read.shm_len) {
        (Some(shm_name), Some(shm_len)) => {
            if !is_valid_shm_name(shm_name) || shm_len == 0 {
                state.remove_photo_read_key(&job_id);
                return Err("原图共享内存参数非法".to_string());
            }
            let key = state
                .photo_read_key(&job_id)
                .ok_or_else(|| "原图读取密钥缺失".to_string())?;
            match read_shm_blob(shm_name, shm_len as usize, Some(&key[..])) {
                Ok((bytes, shm_done)) => {
                    if shm_done != done {
                        state.remove_photo_read_key(&job_id);
                        return Err("原图共享内存状态不一致".to_string());
                    }
                    bytes
                }
                Err(e) => {
                    state.remove_photo_read_key(&job_id);
                    return Err(e);
                }
            }
        }
        _ => match read.data_b64.as_deref() {
            Some(data_b64) => BASE64
                .decode(data_b64.as_bytes())
                .map_err(|_| "原图块编码非法".to_string())?,
            None => {
                state.remove_photo_read_key(&job_id);
                return Err("原图读取响应缺少数据".to_string());
            }
        },
    };

    let Some(chunk_index) = read.chunk_index else {
        state.remove_photo_read_key(&job_id);
        return Err("原图读取响应缺少块序号".to_string());
    };
    let Some(chunk_total) = read.chunk_total else {
        state.remove_photo_read_key(&job_id);
        return Err("原图读取响应缺少块总数".to_string());
    };
    if let Err(e) = validate_full_chunk(done, chunk_index, chunk_total, payload.len()) {
        state.remove_photo_read_key(&job_id);
        return Err(format!("原图分块状态非法: {}", e));
    }
    if done {
        state.remove_photo_read_key(&job_id);
        end_read_job(&app, &job_id).await;
    }
    Ok(IpcResponse::new(payload))
}

/// 取消原图读取：worker 停止后续产出并清理 job。
#[tauri::command]
pub async fn photo_full_cancel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    job_id: String,
) -> Result<(), String> {
    if job_id.is_empty() {
        return Ok(());
    }
    let _ = send_worker(
        &app,
        serde_json::json!({"op": "photo_read_job_cancel", "job_id": job_id}),
        READ_END_TIMEOUT,
    )
    .await;
    state.remove_photo_read_key(&job_id);
    end_read_job(&app, &job_id).await;
    Ok(())
}

#[cfg(test)]
mod phase2_tests {
    use super::*;

    #[test]
    fn full_chunk_consistency_rules() {
        assert!(validate_full_chunk(false, 0, 3, 1024).is_ok());
        assert!(validate_full_chunk(true, 2, 3, 1024).is_ok());
        assert!(validate_full_chunk(true, 0, 1, 1024).is_ok());

        assert!(validate_full_chunk(false, 0, 0, 1024).is_err());
        assert!(validate_full_chunk(false, 3, 3, 1024).is_err());
        assert!(validate_full_chunk(true, 0, 3, 1024).is_err());
        assert!(validate_full_chunk(false, 2, 3, 1024).is_err());
        assert!(validate_full_chunk(true, 2, 3, 0).is_err());
    }
}
