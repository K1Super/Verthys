/*
 * updater/mod.rs — 本机更新服务入口
 *
 * 职责：检查清单、预检环境、下载安装包、复验签名与哈希、读取 PE 版本、
 * 校验锁库结果、写入更新标记、安装并记录事件。
 *
 * 安全边界：所有准入判定都在 Rust 侧完成；前端只消费结果与展示状态。
 * 检查、准备、安装由操作锁串行化；取消通过令牌与代际号中断在途下载，不排队。
 * 安装只接受与当前会话绑定的有效回执；准备后的字节保存在内存，移交后进程退出。
 */

#[path = "checks/authenticode.rs"]
mod authenticode;
#[path = "flow/check.rs"]
mod check;
#[path = "infra/error.rs"]
mod error;
#[path = "apply/gate.rs"]
mod gate;
#[path = "apply/health.rs"]
mod health;
#[path = "flow/lifecycle.rs"]
mod lifecycle;
#[path = "apply/lkg.rs"]
mod lkg;
#[path = "infra/log.rs"]
mod log;
#[path = "checks/manifest.rs"]
mod manifest;
#[path = "apply/marker.rs"]
mod marker;
#[path = "apply/native.rs"]
mod native;
#[path = "checks/pe.rs"]
mod pe;
#[path = "apply/precheck.rs"]
mod precheck;
#[path = "apply/repair.rs"]
mod repair;
#[path = "flow/startup.rs"]
mod startup;
#[path = "infra/transport.rs"]
mod transport;
#[path = "flow/types.rs"]
mod types;
#[path = "checks/verify.rs"]
mod verify;

#[cfg(test)]
#[path = "flow/tests.rs"]
mod tests;

// 命令宏由 #[tauri::command] 生成并在子模块内以 pub use 暴露；glob 重导出
// 同时覆盖命令函数与命令宏，保证 `updater::<命令>` 路径可被 generate_handler 解析。
pub use check::*;
pub use lifecycle::*;
pub use startup::*;
pub use types::{UpdaterError, UpdaterState};

use types::PreparedBytes;
