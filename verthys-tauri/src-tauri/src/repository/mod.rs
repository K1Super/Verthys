/*
 * repository/mod.rs — 持久层模块入口
 *
 * 持久层职责：
 *   - 不主动捕获任何异常（除必须处理的系统级信号外）
 *   - 遇到错误时，立即将原始错误包装为 VerthysError 并向上传播（? 操作符）
 *   - 绝对不允许在底层代码中吞掉异常而不重新抛出
 *   - 无日志权限，仅通过返回 Result 的 Err 变体携带错误描述
 *
 * 依赖方向：repository → util（单向，禁止引用 service / controller / entry）
 */
pub mod verthys_repository;
pub mod verthys_state;
/// 照片导入 Write-Ahead Log（断点续传持久层）
///
/// 追加式 JSON-lines 日志 + 已提交哈希集合 + 检查点 + 启动恢复 + fsync + 压缩。
/// 由 verthys_batch_controller 调用，AppState 持有 ImportSession 贯穿导入生命周期。
pub mod verthys_wal;
