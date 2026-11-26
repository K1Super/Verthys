/*
 * controller/filevault — 清藏（文件保险箱）导入域
 *
 * 职责边界：文件保险箱的 native 导入流水线。worker 侧完成读取、哈希与加密，
 * 宿主侧负责源校验、作业生命周期、空间预检、分块提交与进度推送。
 */
pub mod file_import_controller;
