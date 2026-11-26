/*
 * 用户授权文件操作
 *
 * 职责边界：用户经原生对话框显式选择的路径可跳过白名单，但仍必须拒绝
 * 系统关键目录、限制大小、控制超时并写审计。本模块提供整文件/分片读取、
 * 文件统计、磁盘空间查询与原子写入。
 */

mod disk;
mod path_guard;
mod read;
mod stat;
mod write;

// ===== 用户授权文件操作（跳过白名单，拒绝系统关键目录） =====
//
// 用户通过原生文件对话框 open() 显式选择的文件已获得明确授权，白名单
// 不适用于这类路径（可能位于 D:\、E:\ 或网络位置）。read_user_file /
// write_user_file 的校验链：
//   - 跳过白名单校验（用户已通过对话框授权）
//   - validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）
//   - canonicalize（解析符号链接，确保路径真实）
//   - 系统关键目录拒绝（C:\Windows、C:\Program Files 等）
//   - 文件大小限制（2GB）
//   - 超时控制（整文件读取 120s；分片读取按分片超时）
//   - 审计日志

pub(crate) use path_guard::is_system_critical_path;

pub use disk::{check_disk_space, DiskSpaceInfo};
pub use read::read_user_file;
pub use stat::{user_file_stat, UserFileStat};
pub use write::write_user_file;

pub(super) use disk::{check_disk_space_blocking, nearest_existing_ancestor};
pub(super) use path_guard::resolve_user_file_target;
pub(super) use read::read_user_file_range_blocking;
pub(super) use stat::user_file_stat_blocking;
pub(super) use write::write_user_file_blocking;
