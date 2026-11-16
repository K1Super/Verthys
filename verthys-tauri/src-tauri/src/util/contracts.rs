/*
 * util/contracts.rs — 跨层共享数据契约
 *
 * 存放同时被 controller、state、infrastructure 引用的记录与批量协议类型，
 * 避免共享结构落在某一业务分层后形成反向依赖。
 * 本模块只依赖 util 内的安全字符串与 serde/ts-rs，不包含业务逻辑。
 */

use crate::util::secured_string::SecuredString;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use zeroize::Zeroize;

// ===== 记录条目类型 =====

/// 批量枚举返回的单条记录（与 worker RecordEntry 对齐）
///
/// Base64 字段附 original_size:u64（原始字节数，base64 解码后长度）
///
/// name / data 使用 SecuredString（Zeroizing<String>）：
///   - Drop 时自动 zeroize 堆内存
///   - 透明 serde（序列化为普通 JSON 字符串），前端契约无感
///   - Deref<Target=str> 兼容 as_str()/len()/is_empty()/as_ptr() 调用
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct VerthysRecordEntry {
    #[ts(type = "number")]
    pub id: u64,
    /// 记录类型
    pub rtype: u32,
    /// 记录名称（SecuredString，Drop 时零化擦除）
    pub name: SecuredString,
    /// Base64 编码的记录数据（SecuredString，Drop 时零化擦除）
    pub data: SecuredString,
    /// 原始数据大小（字节，base64 解码后长度）
    ///
    /// 前端据此预分配解码缓冲区，避免 base64 解码后才知道大小。
    /// 向后兼容：旧响应无此字段时为 None，前端按 data.len() * 3 / 4 估算。
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub original_size: Option<u64>,
}

/// VerthysRecordEntry 的 Zeroize 实现
///
/// 仅擦除敏感字段 name / data（SecuredString::zeroize 以 volatile 写零覆盖堆字节后 clear）。
/// id / rtype / original_size 非敏感，不擦除（保留以便崩溃诊断）。
///
/// 支持泛型 `ScanRecord: Zeroize` 约束，使 `<[VerthysRecordEntry]>::zeroize()`
/// 可直接对整批记录就地擦除。
impl Zeroize for VerthysRecordEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.data.zeroize();
    }
}

/// 摘要扫描返回的单条记录（轻量元数据，不含数据块）
///
/// 与 VerthysRecordEntry 的区别：
///   - 无 data 字段（不解密数据块，解锁后 1-2 秒内完成列表渲染）
///   - 携带 data_size / physical_offset / merkle_leaf（供按需加载定位 + 完整性校验）
///   - 携带 created_time（创建时间戳，解锁后立即展示在列表中）
///
/// merkle_leaf 以 base64 传输（32 字节 → 44 字符），前端用于全盘完整性巡检。
///
/// name / merkle_leaf 使用 SecuredString（Zeroizing<String>）：Drop 时自动零化堆内存。
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct VerthysSummaryEntry {
    #[ts(type = "number")]
    pub id: u64,
    pub rtype: u32,
    /// 记录名称（SecuredString，Drop 时零化擦除）
    pub name: SecuredString,
    /// 原始数据大小（字节，用于显示"大小"列）
    #[ts(type = "number")]
    pub data_size: u64,
    /// 物理槽位偏移（按需加载时直接定位磁盘位置，跳过 B+ 树查找）
    #[ts(type = "number")]
    pub physical_offset: u64,
    /// Merkle 叶子哈希 base64（SecuredString，完整性校验码，Drop 时零化）
    pub merkle_leaf: SecuredString,
    /// 创建时间戳（Unix 秒，列表展示用）
    #[ts(type = "number")]
    pub created_time: u64,
}

/// VerthysSummaryEntry 的 Zeroize 实现
///
/// 仅擦除敏感字段 name / merkle_leaf。其余字段非敏感。
impl Zeroize for VerthysSummaryEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.merkle_leaf.zeroize();
    }
}

// ===== 照片导入批量协议类型 =====
//
// verthys_add_records_batch 的输入/进度契约，与前端 verthys.ts 对齐。
// 定义于本模块供控制器命令入口与单写者通道（state::import_writer）共享，
// 避免跨分层重复定义同一批处理数据类型。

/// 单条已加密记录输入（前端 Worker 池加密后产出）
///
/// 字段语义：
///   - rtype：记录类型（与 verthys_add_record 一致）
///   - name：记录名称（如 `meta_xxx.jpg`）
///   - entry_key：调用方生成的非内容身份键（用于会话内幂等/WAL 续传）
///   - data_b64：已加密的记录数据 base64（前端 XChaCha20-Poly1305 加密产物）
///   - chunk_ids / chunk_hashes：外置块引用（仅大文件外置模式携带；
///     导入时校验块在本会话已成功上传，防止悬空引用）
#[derive(Debug, Clone, Deserialize)]
pub struct BatchRecordInput {
    pub rtype: u32,
    pub name: String,
    #[serde(default)]
    pub entry_key: String,
    pub data_b64: String,
    #[serde(default)]
    pub chunk_ids: Option<Vec<u64>>,
    #[serde(default)]
    pub chunk_hashes: Option<Vec<String>>,
}

/// 单条外置加密块输入（verthys_add_chunk_batch 载荷元素）
///
/// 字段语义：
///   - chunk_key：调用方生成的非内容块键（记录名与会话内幂等依据；
///     不得由内容哈希派生）
///   - data_b64：块密文 base64（前端 XChaCha20-Poly1305 加密产物）
///   - rtype：记录类型（外置载荷角色）。缺省为照片数据块；索引瘦身布局的
///     缩略图记录显式指定缩略图类型，写者据此分配记录名与类型，二者共用
///     同一上传通道、台账与幂等映射
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkBlob {
    #[serde(default)]
    pub chunk_key: String,
    pub data_b64: String,
    #[serde(default)]
    pub rtype: Option<u32>,
}

/// 批量写入进度（通过 Tauri Channel 流式推送到前端）
///
/// 前端在 requestAnimationFrame 内接收并绘制进度条，保证任何时刻最多一帧间隔更新，
/// 绝不参与数据处理热路径。
#[derive(Debug, Clone, Serialize)]
pub struct ImportBatchProgress {
    /// 本批次 ID（从 1 递增，前端据此对齐检查点）
    pub batch_id: u64,
    /// 本批次已处理记录数（含幂等跳过 + 失败）
    pub processed_in_batch: u64,
    /// 本批次总记录数
    pub total_in_batch: u64,
    /// 导入会话累计已 committed 记录数（检查点）
    pub total_committed: u64,
    /// 导入会话累计因条目键幂等跳过的记录数
    pub total_skipped: u64,
    /// 本批次已耗时（毫秒，自批次开始累计）
    pub elapsed_ms: u64,
}
