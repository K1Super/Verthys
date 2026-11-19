/*
 * media/mod.rs — 原生媒体数据面
 *
 * 导入：文件读取、格式判定、缩略图/预览、动图探测、分块封装。
 * 读取：预览命中/懒生成、原图分块解密。
 * 导出：原始/.venc/PNG 字节流（宿主写盘）。
 * 还原：VENC 流式解析、重封装、meta 收尾。
 * 各 job 独立状态，不共享明文缓冲。
 */

pub(crate) mod animated;
pub(crate) mod decoder;
pub(crate) mod export_job;
pub(crate) mod import_job;
pub(crate) mod meta_job;
pub(crate) mod mime;
pub(crate) mod preview;
pub(crate) mod read_job;
pub(crate) mod restore_job;
pub(crate) mod source;
pub(crate) mod venc;

pub(crate) use export_job::{
    handle_begin as handle_export_begin,
    handle_cancel as handle_export_cancel,
    handle_end as handle_export_end,
    handle_next as handle_export_next,
};
pub(crate) use import_job::{
    handle_begin, handle_cancel, handle_end, handle_finish, handle_next,
};
pub(crate) use meta_job::{
    handle_meta_get, handle_meta_probe,
};
pub(crate) use read_job::{
    handle_begin as handle_read_begin,
    handle_cancel as handle_read_cancel,
    handle_end as handle_read_end,
    handle_next as handle_read_next,
    handle_preview_ids,
};
pub(crate) use restore_job::{
    handle_begin as handle_restore_begin,
    handle_cancel as handle_restore_cancel,
    handle_end as handle_restore_end,
    handle_finish as handle_restore_finish,
    handle_inspect as handle_restore_inspect,
    handle_next as handle_restore_next,
};
