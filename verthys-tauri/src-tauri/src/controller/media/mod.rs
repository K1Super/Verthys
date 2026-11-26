/*
 * controller/media — 照片数据面
 *
 * 职责边界：照片库的 native 导入、网格元数据、损坏探测、预览与原图分块读取、
 * 导出与备份还原。读取、加密与哈希在 worker 内完成，本域负责作业生命周期、
 * 单写者落库、进度推送与原子写盘。
 */
pub mod photo_media_controller;
