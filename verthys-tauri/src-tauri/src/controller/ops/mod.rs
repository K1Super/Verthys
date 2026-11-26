/*
 * controller/ops — 运维面
 *
 * 职责边界：诊断日志导出/尾部读取与开发夹具配置。诊断日志必须脱敏且不包含
 * 审计 HMAC 链；开发夹具仅在开发构建可用。
 */
pub mod devfixture_controller;
pub mod diag_controller;
