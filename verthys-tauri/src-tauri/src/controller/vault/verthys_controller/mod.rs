/*
 * controller/vault/verthys_controller — 加密库生命周期与记录数据面
 *
 * 子模块边界：
 *   password        本机容器口令材料读取策略、口令与 keyfile 目标校验
 *   audit           数据域会话闸门与审计写入（解锁态判定的唯一入口）
 *   init            初始化状态判定与主动修复
 *   unlock          口令 / keyfile 解锁
 *   recovery        恢复码解锁与恢复码轮换
 *   create          新库创建（create → lock → 哨兵锁 → unlock 自检）
 *   session         落盘、锁定、刷盘、落盘自查与导入会话强制关闭
 *   records         单条与批量记录 CRUD、流式枚举
 *   transfer        容器导出 / 导入
 *   security_status 动态防护状态透传
 *   preheat         解锁前页缓存预热
 *
 * 依赖方向：controller → state / repository / infrastructure / util / worker。
 * 共享的解锁态判定与审计必须经由 audit 子模块，禁止各命令复制实现。
 */
mod audit;
mod create;
mod init;
mod password;
mod preheat;
mod records;
mod recovery;
mod security_status;
mod session;
mod transfer;
mod unlock;

#[cfg(test)]
mod test_support;

use password::*;

/* 命令与跨模块复用入口：对外名称与原单文件模块保持一致 */
pub use create::verthys_create;
pub use init::verthys_init_status;
pub use preheat::verthys_preheat;
pub use records::{
    verthys_add_record, verthys_delete_record, verthys_delete_records,
    verthys_enumerate_records, verthys_enumerate_records_stream, verthys_get_record,
    verthys_get_summary_count, verthys_has_record_by_type,
};
pub use recovery::verthys_recovery_rotate;
pub(crate) use recovery::verthys_unlock_recovery;
pub use security_status::verthys_security_status;
pub use session::{
    verthys_flush, verthys_force_close_import_session, verthys_lock, verthys_lock_persist,
    verthys_prepare_lock, verthys_verify_disk_persist,
};
pub use transfer::{verthys_export, verthys_import};
pub use unlock::verthys_unlock;

pub(crate) use audit::{require_unlocked, write_verthys_audit};
pub(crate) use password::{
    load_existing_container_password, load_or_create_container_password,
    KEY_MATERIAL_MISSING_CODE, KEY_MATERIAL_MISSING_MESSAGE,
};
pub(crate) use records::delete_batch_timeout;
// ===== 借用式请求构造 =====

// 以下结构体把口令/记录明文以 &str 借用序列化进输出字符串，
// 不产生 serde_json::Value 的 owned 明文拷贝；序列化结果立即进入
// Zeroizing 容器，随敏感原件在发送后统一擦除。

/// unlock 请求体
#[derive(serde::Serialize)]
struct UnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

/// recovery 解锁请求体
#[derive(serde::Serialize)]
struct RecoveryUnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    recovery_code: &'a str,
}

/// 恢复码轮换请求体（当前容器口令由宿主注入）
#[derive(serde::Serialize)]
struct RecoveryRotateReq<'a> {
    op: &'static str,
    password: &'a str,
    old_recovery: &'a str,
}

/// v4_create 请求体
#[derive(serde::Serialize)]
struct V4CreateReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

/// keyfile 解锁请求体（库路径 + keyfile 路径）
#[derive(serde::Serialize)]
struct KeyfileUnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
    keyfile_path: &'a str,
}

/// keyfile 创建请求体（库路径 + keyfile 路径）
#[derive(serde::Serialize)]
struct KeyfileCreateReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
    keyfile_path: &'a str,
}
