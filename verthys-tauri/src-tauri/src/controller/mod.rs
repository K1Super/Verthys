/*
 * controller/mod.rs — 控制器层模块入口
 *
 *
 * 控制器层职责：
 *   - 接收上下文，调用服务层，将错误向上转换
 *   - 允许捕获特定业务异常，转换为具有业务语义的统一错误结构
 *   - 转换后必须立即向上抛出，不得隐式返回空值或默认值掩盖故障
 *   - 禁止直接调用日志发送接口（仅顶层入口层允许）
 *   - 禁止直接访问持久层具体实现，应通过服务层
 *
 * 依赖方向：controller → service（单向，禁止反向）
 */
pub mod types;
/// API 错误码与响应信封（ApiResponse<T> / ApiError / ErrorCode）
pub mod api_error;
pub mod verthys_controller;
/// 照片导入异步批处理流水线 — 批量控制器
///
/// verthys_import_begin / verthys_add_records_batch / verthys_import_end /
/// verthys_import_checkpoint / verthys_wal_recover（WAL + 串行 worker 插入 + 进度 Channel）
pub mod verthys_batch_controller;
pub mod scan_controller;
pub mod worker_controller;
pub mod key_controller;
pub mod device_controller;
pub mod clipboard_controller;
pub mod file_controller;
pub mod diag_controller;
pub mod preflight_controller;
