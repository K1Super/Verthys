/*
 * security/command_names.rs — 数据域 IPC 命令名常量
 *
 * 职责：verthys 数据域命令名的唯一权威来源，供授权闸门与审计日志引用，
 * 禁止在命令入口与审计点散落字符串字面量（防止命令名漂移导致审计口径不一致）。
 *
 * 依赖方向：纯常量模块，零依赖。
 */

/// verthys 数据域 IPC 命令名常量
pub mod cmd {
    /// 批量导入：创建导入会话
    pub const IMPORT_BEGIN: &str = "verthys_import_begin";
    /// 批量导入：写入加密记录
    pub const ADD_RECORDS_BATCH: &str = "verthys_add_records_batch";
    /// 批量导入：上传外置加密块
    pub const ADD_CHUNK_BATCH: &str = "verthys_add_chunk_batch";
    /// 批量导入：查询检查点
    pub const IMPORT_CHECKPOINT: &str = "verthys_import_checkpoint";
    /// 批量导入：结束导入会话
    pub const IMPORT_END: &str = "verthys_import_end";
    /// 删除后释放去重锁（WAL 删除墓碑）
    pub const FORGET_HASHES: &str = "verthys_forget_hashes";
    /// 孤儿外置块 GC：删除台账中未被任何 meta 引用（owner=0）的块记录
    pub const GC_ORPHAN_CHUNKS: &str = "verthys_gc_orphan_chunks";
    /// 开发用：重置 WAL 与快照（清空续传去重状态）
    pub const DEV_RESET_WAL: &str = "dev_reset_wal";
    /// 流式导出：创建写入会话（暂存文件）
    pub const WRITE_USER_FILE_STREAM: &str = "write_user_file_stream";
    /// 流式导出：追加原始数据块
    pub const APPEND_USER_FILE_CHUNK: &str = "append_user_file_chunk";
    /// 流式导出：同步落盘并原子替换目标
    pub const FINALIZE_USER_FILE_STREAM: &str = "finalize_user_file_stream";
    /// 流式导出：中止会话并清理暂存
    pub const ABORT_USER_FILE_STREAM: &str = "abort_user_file_stream";
}
