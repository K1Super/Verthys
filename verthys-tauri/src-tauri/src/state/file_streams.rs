/*
 * state/file_streams.rs — 文件流式写入会话表
 *
 * 职责：托管进行中的流式文件写入会话（暂存文件句柄 + 路径 + 累计字节），
 * 为 file_controller 的流式写入命令提供进程内生命周期管理。
 *
 * 设计约束：
 * - 每个会话以 Arc<Mutex<FileStreamState>> 托管：命令层可克隆指针后在
 *   spawn_blocking 中执行磁盘 IO，避免阻塞异步运行时线程。
 * - 单会话状态锁仅覆盖「该流的写句柄与计数」，全局表锁仅覆盖「指针的
 *   增删查」，两者不嵌套持有，避免锁竞争与死锁。
 * - 会话不自动终结：finalize / abort 由命令显式触发；崩溃遗留的暂存
 *   文件由下一次创建流时的按龄清理兜底（暂存永远不会被 rename 到目标）。
 */

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// 单个流式写入会话的运行状态
///
/// 生命周期：write_user_file_stream 创建并注册 → append 递增写入 →
/// finalize 同步落盘并原子替换目标后注销；abort 直接注销并清理暂存。
/// `file` 为 Some 表示会话活跃，finalize / abort 消费时置 None 关闭句柄。
#[derive(Debug)]
pub struct FileStreamState {
    /// 暂存文件句柄（写入目标为临时文件，finalize 时原子替换到目标路径）
    file: Option<std::fs::File>,
    /// 暂存文件绝对路径（清理残留时使用）
    temp_path: PathBuf,
    /// 最终目标文件绝对路径（finalize 时 rename 到此位置）
    target_path: PathBuf,
    /// 已接受写入的累计字节数（用于总量上限校验与审计）
    bytes_written: u64,
}

impl FileStreamState {
    /// 构造会话状态（暂存文件由调用方以 create_new 独占创建）
    pub fn new(file: std::fs::File, temp_path: PathBuf, target_path: PathBuf) -> Self {
        FileStreamState {
            file: Some(file),
            temp_path,
            target_path,
            bytes_written: 0,
        }
    }

    /// 追加原始字节并更新累计计数
    ///
    /// 调用方须在写入前完成总量上限校验；会话已终结（句柄为 None）时
    /// 返回 BrokenPipe 错误——正常流程中外层已注销会话，此分支仅在
    /// 状态不变量被破坏时可达。
    pub fn append(&mut self, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "会话已终结"))?;
        file.write_all(data)?;
        self.bytes_written += data.len() as u64;
        Ok(())
    }

    /// 累计已写入字节（总量上限校验与审计用）
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// 暂存文件路径（清理残留时使用）
    pub fn temp_path(&self) -> &PathBuf {
        &self.temp_path
    }

    /// 最终目标文件路径
    pub fn target_path(&self) -> &PathBuf {
        &self.target_path
    }

    /// 同步落盘暂存文件（finalize 在 rename 前调用，保证数据持久）
    pub fn sync_all(&self) -> std::io::Result<()> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "会话已终结"))?;
        file.sync_all()
    }

    /// 关闭暂存文件句柄（Drop 关闭；Windows 上先关句柄再做 rename 是
    /// 最保守的兼容路径）
    pub fn close_handle(&mut self) {
        self.file = None;
    }

    /// 会话是否仍持有活跃句柄（中毒恢复时区分「未终结」与「已终结」）
    pub fn is_active(&self) -> bool {
        self.file.is_some()
    }
}

/// 流式写入会话表（注册于 AppState，索引为会话标识）
pub type FileStreamTable = Mutex<HashMap<String, Arc<Mutex<FileStreamState>>>>;

/// 尽力清理单会话残留（关闭句柄 + 删除暂存文件）
///
/// 用于会话表中毒恢复与进程退出兜底：会话对应的导出已不可能完成，
/// 暂存文件不会被 rename 到目标，删除仅回收磁盘空间，失败仅告警。
pub fn cleanup_stream_residue(entry: Arc<Mutex<FileStreamState>>) {
    let state = match entry.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };
    let temp = state.temp_path().clone();
    drop(state); // 先关闭句柄再删除，避免 Windows 打开句柄干扰
    if let Err(e) = std::fs::remove_file(&temp) {
        log::warn!("[file_streams] 清理会话暂存失败: {}", e);
    }
}
