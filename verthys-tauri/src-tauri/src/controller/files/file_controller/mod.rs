/*
 * controller/files/file_controller — 文件读写（沙箱隔离、流式传输与原子写入）
 *
 * 子模块边界：
 *   audit    文件操作审计写入（路径哈希化，不含内容）
 *   sandbox  白名单沙箱读写与二进制 IPC 命令
 *   user_io  用户授权路径读写、文件统计与磁盘空间查询
 *   stream   单文件导出的流式落盘（暂存 + fsync + 原子替换）
 *   tests    单元测试（仅测试构建）
 *
 * 安全约束：沙箱路径必须落在白名单内；用户授权路径跳过白名单但拒绝系统
 * 关键目录；文件大小与超时按导出常量统一约束；审计不记录内容或明文路径。
 *
 * 依赖方向：controller → state / infrastructure / util / constants / api_error。
 */
use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use std::sync::Mutex;
use std::time::Duration;

mod audit;
mod sandbox;
mod stream;
mod user_io;

#[cfg(test)]
mod tests;

use audit::*;
// sandbox 的自由函数只供单元测试经 super::* 调用；生产路径使用下方
// 显式重导出的命令入口，故按测试构建门控
#[cfg(test)]
use sandbox::*;
use user_io::*;

pub use sandbox::{read_file_bytes, write_file_bytes};
pub use stream::{
    abort_user_file_stream, append_user_file_chunk, finalize_user_file_stream,
    write_user_file_stream,
};
pub use user_io::{
    check_disk_space, read_user_file, user_file_stat, write_user_file, DiskSpaceInfo,
    UserFileStat,
};

pub(crate) use stream::{
    audit_export_event, stream_abort_blocking, stream_append_blocking, stream_create_blocking,
    stream_finalize_blocking,
};
pub(crate) use user_io::is_system_critical_path;
// ===== 文件大小与块大小 =====

/// 允许读取/写入的最大文件大小（50MB），防止内存耗尽。
const FILE_SIZE_LIMIT: u64 = 50 * 1024 * 1024;

/// 流式读写的分块大小（64KB），平衡内存与性能。
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// 文件操作超时（10 秒），源自全局 IPC 超时配置。
const FILE_OP_TIMEOUT: Duration = TIMEOUT_CONFIG.ipc;

/// 用户授权文件操作超时（120 秒）。
///
/// 大文件（数百 MB ~ 2GB）的读取/写入需要更长时间，
/// 10 秒超时会误杀合法的大文件传输。此超时仅用于 read_user_file /
/// write_user_file，与沙箱白名单操作的 FILE_OP_TIMEOUT 隔离。
const USER_FILE_OP_TIMEOUT: Duration = Duration::from_secs(120);

/// 用户授权文件分片操作的调用超时（15 秒）。
///
/// 分片读取单次只搬运一个分片（≤ 流式写入分片上界），正常耗时远低于
/// 整文件读取；独立短超时用于快速暴露卡在慢速介质上的源文件，避免单次
/// 读取长期占用导入流水线。整文件读取仍沿用 120 秒语义。
const USER_FILE_CHUNK_OP_TIMEOUT: Duration = Duration::from_secs(15);

// ===== 写操作互斥锁 =====

/// 全局写互斥锁，序列化所有文件写入，防止并发写操作交叉破坏文件。
static WRITE_MUTEX: Mutex<()> = Mutex::new(());
