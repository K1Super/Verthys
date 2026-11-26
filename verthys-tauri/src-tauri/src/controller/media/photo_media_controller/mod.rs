/*
 * controller/media/photo_media_controller — 照片数据面
 *
 * 子模块边界：
 *   types   前端契约 DTO 与 worker 回包结构
 *   worker  worker IPC 桥接、路径授权、job 生命周期与进度推送
 *   import  原生导入流水线（命令入口 / 分批 / 落库 / 取消）
 *   meta    网格元数据、损坏探测与备份预览
 *   reader  预览与原图分块读取协议
 *   export  原生导出流水线
 *   restore 原生备份还原流水线
 *
 * 关键约束：
 *   - 同一时刻只允许一个数据面任务（槽位由 AppState 保证）；
 *   - worker 侧 job 按路径批切分，每批独立 job_id，共享同一导入会话；
 *   - 单文件失败必须继续后续文件，绝不因单张照片中止整批；
 *   - 源文件只读，不删除、不移动。
 *
 * 依赖方向：controller → state / util / controller::vault / controller::files。
 */
mod types;
mod worker;
mod import;
mod meta;
mod reader;
mod export;
mod restore;

use restore::*;
use types::*;
use worker::*;

use std::time::Duration;

pub use export::{photo_export_cancel, photo_export_start};
pub use import::{photo_import_cancel, photo_import_start};
pub use meta::{photo_meta_get, photo_meta_probe, photo_parse_start};
pub use reader::{
    photo_full_begin, photo_full_cancel, photo_full_next, photo_preview_get,
    PHOTO_LAYOUT_UNSUPPORTED,
};
pub use restore::{photo_restore_cancel, photo_restore_start};
/// 单个 worker job 的路径上限（与 worker 侧 MAX_JOB_PATHS 一致）
const MAX_JOB_PATHS: usize = 10_000;

/// 路径授权 / job 建立超时
const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(60);
const BEGIN_TIMEOUT: Duration = Duration::from_secs(60);
/// 单次 next / finish 的超时：首次 next 会触发 100MiB 文件的整文件哈希与缩略图
const NEXT_TIMEOUT: Duration = Duration::from_secs(300);
const FINISH_TIMEOUT: Duration = Duration::from_secs(300);
/// 子批 job 结束超时
const END_TIMEOUT: Duration = Duration::from_secs(30);

/// 路径授权续期阈值：worker TTL 为 600s，取一半时间滚动续期
const GRANT_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// 块缓冲上限：凑满 16 块（约 64MiB 明文）提交一组。
///
/// 块密文驻留 worker 暂存区，宿主只持有引用；分组上限与 worker 暂存
/// 块数上限同源，字节上限按单块密文上界推导，不放大宿主 base64/JSON 峰值。
const CHUNK_BUFFER_LIMIT: usize = 16;

/// 照片 meta 记录类型（与前端 TYPE_PHOTO_META 同值）
const PHOTO_META_RTYPE: u32 = 0x01;

const PHASE_SCANNING: &str = "scanning";
const PHASE_IMPORTING: &str = "importing";
const PHASE_FINISHING: &str = "finishing";
const PHASE_DONE: &str = "done";
const PHASE_CANCELLED: &str = "cancelled";

/// 结构化错误码：并发导入被拒绝（前端据此提示已有任务进行中）
const ERROR_CODE_BUSY: &str = "E_PHOTO_IMPORT_BUSY";
/// 结构化错误码：容器会话未就绪
const ERROR_CODE_NOT_READY: &str = "E_VERTHYS_NOT_READY";
