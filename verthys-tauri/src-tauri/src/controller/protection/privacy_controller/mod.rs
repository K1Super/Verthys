/*
 * controller/protection/privacy_controller — 防截屏隐私保护
 *
 * 子模块边界：
 *   error       错误分类与稳定错误码
 *   model       凭证槽位、亲和性/审计出口与状态机定义
 *   coordinator 模式切换、凭证签发/消费、隔离与对账收敛
 *   startup     启动序列、窗口目标收集与恢复对话框
 *   commands    Tauri 命令入口与限流
 *   tests       单元测试（仅测试构建）
 *
 * 设计约束：单一真相源（状态与凭证同锁）；系统调用在锁外或阻塞池执行；
 * 过渡身份单调递增，过期任务不得覆盖新状态；隔离只存在于运行时。
 *
 * 依赖方向：controller → security / security_commands / util。
 */
use std::time::Duration;


mod commands;
mod coordinator;
mod error;
mod model;
mod startup;

#[cfg(test)]
mod tests;

use model::*;

pub use commands::{
    adopt_privacy_session, get_privacy_status, reconcile_privacy, set_privacy_mode,
};
pub use coordinator::PrivacyCoordinator;
pub use error::PrivacyError;
pub use model::{
    AppAuditSink, AuditSink, Lease, PrivacyModeOutcome, PrivacyStatusSnapshot, TokenSlot,
    WindowSnapshot, WindowTarget,
};
pub use startup::{collect_targets, run_startup_recovery_dialog, startup_engage, StartupOutcome};
/* ====================================================================== *
 *  常量与错误分类                                                         *
 * ====================================================================== */

/// 过渡卡死判定阈值：过渡任务跑在阻塞池，正常耗时为毫秒级；
/// 超过该阈值仍停在过渡态视为任务异常终止，由下一次状态读取收尸转入隔离
const STUCK_THRESHOLD: Duration = Duration::from_secs(30);

/// 限流：开启较严（防连点与前端缺陷），关闭宽松（不得卡住用户关闭操作），
/// 采纳与对账低频；状态查询只读幂等，不限流。
const ENABLE_MAX_PER_MINUTE: usize = 10;
const DISABLE_MAX_PER_MINUTE: usize = 60;
const ADOPT_MAX_PER_MINUTE: usize = 10;
const RECONCILE_MAX_PER_MINUTE: usize = 5;
