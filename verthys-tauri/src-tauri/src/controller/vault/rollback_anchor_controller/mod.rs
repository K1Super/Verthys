/*
 * controller/vault/rollback_anchor_controller — 回退锚点维护
 *
 * 子模块边界：
 *   support   扫描取消、UUID 识别、审计与 worker 转发
 *   targets   扫描目标来源合并、去重与排序
 *   scan      有界预算遍历与容器头只读识别
 *   merge     按 UUID 合并多路径证据并保留历史快照
 *   deep      深度扫描根与自定义位置校验
 *   pass      扫描轮次、快照持久化与结果组装
 *   commands  Tauri 命令入口
 *   tests     单元测试（仅测试构建）
 *
 * 安全约束：扫描只读容器固定头，不打开容器、不修改文件；跳过符号链接/
 * 重解析点；审计只记录 UUID 哈希与计数，不记录容器路径或密钥材料。
 */
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// 单次维护命令的 worker 超时：64 条 TPM 探测 + 少量删除，留足余量。
const ANCHOR_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// 单次自动扫描的硬上限：防止误选大目录导致长时间占用。
const SCAN_MAX_FILES: u64 = 200_000;
const SCAN_MAX_DEPTH: usize = 8;
const DEEP_MAX_DEPTH: usize = 24;
const SCAN_MAX_TARGETS: usize = 128;
const SCAN_MAX_CUSTOM_ROOTS: usize = 16;
const SCAN_MAX_STORED_ROOTS: usize = 256;
const SCAN_MAX_PATHS_PER_UUID: usize = 32;
const SCAN_CACHE_TTL_SECS: u64 = 300;

/// 自动扫描预算：单次总时长与单根目录时长分别限制，避免一个大目录吞掉全部时间。
const SCAN_BUDGET: Duration = Duration::from_secs(15);
const SCAN_ROOT_SLICE: Duration = Duration::from_secs(6);
/// 深度扫描预算：仅在用户显式触发时使用。
const DEEP_BUDGET: Duration = Duration::from_secs(60);
const DEEP_ROOT_SLICE: Duration = Duration::from_secs(6);

/// 容器固定头长度（与 C 层 VTY_HEADER_FIXED_BYTES 对齐）。
const CONTAINER_HEADER_BYTES: usize = 76;
/// 容器主版本（与 VERTHYS_CONTAINER_FORMAT_VERSION 对齐）。
const CONTAINER_VERSION_MAJOR: u16 = 4;
const CONTAINER_MAGIC: [u8; 4] = *b"VRTY";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// 深度扫描时跳过的系统目录名（不区分大小写）。
const DEEP_SKIP_DIRS: &[&str] = &[
    "Windows",
    "$Recycle.Bin",
    "System Volume Information",
    "Recovery",
    "PerfLogs",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "Config.Msi",
    "$WinREAgent",
    "Windows.old",
];

/// 扫描单飞：同一进程内并发调用等待前一次完成，避免重复遍历与证据互相覆盖。
static SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 用户显式停止扫描：扫描线程在下一个目录项边界退出，已完成的证据照常落盘。
static SCAN_CANCEL: AtomicBool = AtomicBool::new(false);
mod commands;
mod deep;
mod merge;
mod pass;
mod scan;
mod support;
mod targets;

#[cfg(test)]
mod tests;

use deep::*;
use merge::*;
use pass::*;
use scan::*;
use support::*;
use targets::*;

pub use commands::{
    verthys_rollback_anchor_list, verthys_rollback_anchor_reclaim,
    verthys_rollback_anchor_release, verthys_rollback_anchor_scan,
    verthys_rollback_anchor_scan_cancel, verthys_rollback_anchor_scan_forget_root,
};
