/*
 * controller/vault/rollback_anchor_controller — 回退锚点维护
 *
 * 子模块边界：
 *   support   扫描取消、UUID 识别、审计与 worker 转发
 *   targets   扫描目标来源合并、去重与排序
 *   scope     本地磁盘枚举与自定义位置校验
 *   scan      并行遍历与容器头只读识别
 *   merge     按 UUID 合并多路径证据并保留历史快照
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

/// 单次全量扫描的硬上限：覆盖多盘大目录，同时防止极端规模长时间占用。
const SCAN_MAX_FILES: u64 = 2_000_000;
/// 全盘扫描的目录深度：从盘符根算起，容器文件所在目录到第 8 层。
///
/// 8 层覆盖桌面、文档、下载与常见项目层级；更深层通常是缓存、依赖与
/// 构建产物，继续遍历只会耗尽预算。该边界属于声明的覆盖范围，不视为
/// 扫描失败。
const VOLUME_SCAN_MAX_DEPTH: usize = 8;
/// 自定义位置由用户显式指定，允许扫得更深。
const CUSTOM_SCAN_MAX_DEPTH: usize = 32;
/// 目标上限：最多 26 个盘符 + 16 个最近探针 + 1 个当前探针 + 16 个自定义位置。
const SCAN_MAX_TARGETS: usize = 64;
const SCAN_MAX_CUSTOM_ROOTS: usize = 16;
const SCAN_MAX_STORED_ROOTS: usize = 256;
const SCAN_MAX_PATHS_PER_UUID: usize = 32;
const SCAN_CACHE_TTL_SECS: u64 = 300;

/// 全量扫描总预算：并行遍历下覆盖普通多盘桌面环境；超时即标记不完整。
const SCAN_BUDGET: Duration = Duration::from_secs(150);
/// 并行遍历线程上限：机械盘随机读放大明显，超过该值收益有限。
const SCAN_MAX_WORKERS: usize = 8;

/// 容器固定头长度（与 C 层 VTY_HEADER_FIXED_BYTES 对齐）。
const CONTAINER_HEADER_BYTES: usize = 76;
/// 容器主版本（与 VERTHYS_CONTAINER_FORMAT_VERSION 对齐）。
const CONTAINER_VERSION_MAJOR: u16 = 4;
const CONTAINER_MAGIC: [u8; 4] = *b"VRTY";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// 磁盘根目录下直接跳过的系统目录名（不区分大小写）。
///
/// 只跳过操作系统与安装器独占管理的顶级目录；用户目录与自定义位置一律
/// 参与扫描。这些目录默认拒绝读取（如 WindowsApps），纳入遍历只会制造
/// 权限错误与无效证据。
const VOLUME_SKIP_DIRS: &[&str] = &[
    "Windows",
    "$Recycle.Bin",
    "System Volume Information",
    "Recovery",
    "PerfLogs",
    "Config.Msi",
    "$WinREAgent",
    "Windows.old",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
];

/// 任意深度跳过的依赖/构建缓存目录（不区分大小写）。
///
/// 这些目录只保存第三方依赖与构建产物，规模可达数十万文件，纳入遍历会
/// 耗尽预算并使真正需要覆盖的用户目录变成“不完整”。
const NESTED_SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "target",
    "__pycache__",
    ".venv",
    "venv",
];

/// 全盘扫描额外跳过的应用数据目录（仅 Volume 来源，不区分大小写）。
///
/// AppData 只保存应用缓存与配置，用户容器不会放在这里；纳入遍历会产生
/// 数十万无关文件，是整盘扫描被预算截断的主要来源。
const VOLUME_NESTED_SKIP_DIRS: &[&str] = &["AppData"];

/// 扫描单飞：同一进程内并发调用等待前一次完成，避免重复遍历与证据互相覆盖。
static SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 用户显式停止扫描：扫描线程在下一个目录项边界退出，已完成的证据照常落盘。
static SCAN_CANCEL: AtomicBool = AtomicBool::new(false);
mod commands;
mod merge;
mod pass;
mod scan;
mod scope;
mod support;
mod targets;

#[cfg(test)]
mod tests;

use merge::*;
use pass::*;
use scan::*;
use scope::*;
use support::*;
use targets::*;

pub use commands::{
    verthys_rollback_anchor_list, verthys_rollback_anchor_reclaim, verthys_rollback_anchor_release,
    verthys_rollback_anchor_scan, verthys_rollback_anchor_scan_cancel,
    verthys_rollback_anchor_scan_forget_root,
};
