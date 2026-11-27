/*
 * dispatch/routes_media.rs — 媒体与文件导入作业路由
 */

use super::*;

pub(super) fn handle(worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        "file_import_job_begin" => file_import::handle_begin(req),
        "file_import_job_next" => file_import::handle_next(worker, req),
        "file_import_job_finish" => file_import::handle_finish(req),
        "file_import_job_cancel" => file_import::handle_cancel(req),
        "file_import_job_end" => file_import::handle_end(req),
        "photo_import_job_begin" => media::handle_begin(req),
        "photo_import_job_next" => media::handle_next(worker, req),
        "photo_import_job_finish" => media::handle_finish(worker, req),
        "photo_import_job_cancel" => media::handle_cancel(req),
        "photo_import_job_end" => media::handle_end(req),
        "photo_read_job_begin" => {
            /* 原图模式随 begin 下发一次性 SHM 认证密钥；预览不需要。 */
            let auth_key = if req.mode == "full" {
                match parse_shm_auth_key("photo_read_job_begin", &req.shm_key) {
                    Ok(key) => key,
                    Err(resp) => return Some(*resp),
                }
            } else {
                None
            };
            media::handle_read_begin(worker, req, auth_key)
        }
        "photo_read_job_next" => media::handle_read_next(worker, req),
        "photo_read_job_cancel" => media::handle_read_cancel(req),
        "photo_read_job_end" => media::handle_read_end(req),
        "photo_preview_ids" => media::handle_preview_ids(worker, req),
        "photo_meta_get" => media::handle_meta_get(worker, req),
        "photo_meta_probe" => media::handle_meta_probe(worker, req),
        "photo_venc_inspect" => media::handle_restore_inspect(req),
        "photo_export_job_begin" => media::handle_export_begin(req),
        "photo_export_job_next" => media::handle_export_next(worker, req),
        "photo_export_job_cancel" => media::handle_export_cancel(req),
        "photo_export_job_end" => media::handle_export_end(req),
        "photo_restore_job_begin" => media::handle_restore_begin(req),
        "photo_restore_job_next" => media::handle_restore_next(worker, req),
        "photo_restore_photo_finish" => media::handle_restore_finish(worker, req),
        "photo_restore_job_cancel" => media::handle_restore_cancel(req),
        "photo_restore_job_end" => media::handle_restore_end(req),
        /* 暂存块提交：照片导入块密文不出 worker，本分支只按引用取密文写入。 */
        "add_records_staged" => media::handle_add_staged(worker, req),
        _ => return None,
    };
    Some(resp)
}
