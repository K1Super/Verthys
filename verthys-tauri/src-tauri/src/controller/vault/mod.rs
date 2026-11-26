/*
 * controller/vault — 加密库核心域
 *
 * 职责边界：Verthys 容器的完整生命周期与数据面，包括初始化判定、解锁/锁定/
 * 落盘、记录 CRUD 与分页读取、批量导入会话、模块密钥托管、全库 DEK 轮换、
 * 存储压实与回退锚点维护。密钥派生与记录明文运算都在 worker 内完成，
 * 本域只做指令转发、状态编排与审计。
 *
 * 组内依赖：各控制器可依赖同域内其它控制器；共享的解锁态校验与审计入口
 * 由 verthys_controller 统一导出，禁止复制实现。
 */
pub mod module_controller;
pub mod module_crypto_controller;
pub mod preflight_controller;
pub mod rollback_anchor_controller;
pub mod scan_controller;
pub mod storage_controller;
pub mod vault_rotate_controller;
pub mod verthys_batch_controller;
pub mod verthys_controller;
pub mod worker_controller;
