/*
 * controller/filevault/file_import_controller — 清藏（文件保险箱）原生导入
 *
 * 子模块边界：
 *   types    前端契约 DTO 与 worker 回包结构
 *   worker   worker IPC 桥接、路径授权、job 生命周期与进度推送
 *   start    导入命令入口与入参/路径校验
 *   import   逐文件导入主流水线（取块 → 缓冲 → 提交 → 收尾）
 *   finish   放弃文件、空间校验、finish 参数与条目回填
 *   cancel   仅针对 file-* job 的取消
 *   tests    单元测试（仅测试构建）
 *
 * 安全约束：源文件只读；系统关键目录拒绝；密码以 Zeroizing 传递；
 * 单文件失败必须继续后续文件。
 *
 * 依赖方向：controller → state / util / controller::vault / controller::files。
 *//// 结构化错误码：并发数据面任务被拒绝
const ERROR_CODE_BUSY: &str = "E_FILE_IMPORT_BUSY";
/// 结构化错误码：容器会话未就绪
const ERROR_CODE_NOT_READY: &str = "E_VERTHYS_NOT_READY";
/// 单 job 文件数上限（与 worker 侧 MAX_JOB_FILES 一致）
const MAX_FILES: usize = 10_000;
/// 路径授权 / job 建立超时
const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(60);
const BEGIN_TIMEOUT: Duration = Duration::from_secs(60);
/// 单次 next / finish 超时：单块读取 + 加密在低端机也有充足余量
const NEXT_TIMEOUT: Duration = Duration::from_secs(300);
const FINISH_TIMEOUT: Duration = Duration::from_secs(120);
const END_TIMEOUT: Duration = Duration::from_secs(30);
/// 路径授权续期阈值：worker job 授权 TTL 为 600s，取一半滚动续期
const GRANT_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
/// 块缓冲上限：凑满 16 块提交一组（worker 暂存区同容量）
const CHUNK_BUFFER_LIMIT: usize = 16;
/// 容器卷空间余量：除块数据外还有索引与日志开销
const DISK_HEADROOM_NUM: u64 = 105;
const DISK_HEADROOM_DEN: u64 = 100;

const PHASE_SCANNING: &str = "scanning";
const PHASE_IMPORTING: &str = "importing";
const PHASE_FINISHING: &str = "finishing";
const PHASE_DONE: &str = "done";
const PHASE_CANCELLED: &str = "cancelled";
use std::time::Duration;

mod cancel;
mod finish;
mod import;
mod start;
mod types;
mod worker;

#[cfg(test)]
mod tests;

use finish::*;
use import::*;
use start::*;
use types::*;
use worker::*;

pub use cancel::file_import_cancel;
pub use start::file_import_start;
