/*
 * controller/files — 通用文件 I/O 域
 *
 * 职责边界：文件沙箱白名单读写、用户授权的任意路径读写与统计、磁盘空间查询、
 * 流式导出落盘（暂存 + 原子替换）。本域不接触密钥与容器格式。
 */
pub mod file_controller;
