//! WAL 条目与恢复快照的数据类型

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// WAL 单条记录类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum WalEntry {
    /// 导入会话开始
    #[serde(rename = "begin")]
    Begin { import_id: String, ts: u64 },
    /// 记录已加密，待入库（写入缓存缓冲器之前）
    #[serde(rename = "pending")]
    Pending {
        import_id: String,
        batch_id: u64,
        /// 非内容键：调用方生成的导入项身份键（用于会话内幂等/WAL 续传）
        #[serde(default)]
        entry_key: String,
        name: String,
        idx: u64,
    },
    /// 记录已入库并落盘（缓存刷新 + worker add_record 完成）
    ///
    /// `chunk_ids` 承载本条记录引用的外置块记录 ID：
    ///   - `Some([...])`：本条目显式声明引用集合（空集合表示无外置块）；
    ///   - `None`：字段缺省的历史条目，引用集合不可推断。
    #[serde(rename = "committed")]
    Committed {
        import_id: String,
        batch_id: u64,
        /// 非内容键：与 Pending 同源的导入项身份键
        #[serde(default)]
        entry_key: String,
        verthys_id: u64,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_ids: Option<Vec<u64>>,
    },
    /// 检查点：标记某批次完整提交
    #[serde(rename = "checkpoint")]
    Checkpoint {
        import_id: String,
        batch_id: u64,
        committed_count: u64,
    },
    /// 删除墓碑：照片删除后释放去重锁（删除后可重新导入）
    #[serde(rename = "removed")]
    Removed {
        /// 被删除条目的非内容身份键（释放续传幂等锁）
        keys: Vec<String>,
        /// 写入时刻（Unix 毫秒）
        at: u64,
    },
    /// 导入会话结束
    #[serde(rename = "end")]
    End { import_id: String, success: bool },
}

/// WAL 恢复后的快照
#[derive(Debug, Clone, Default)]
pub struct WalSnapshot {
    /// 所有已 committed 的非内容条目键 — 续传幂等依据
    pub committed_keys: HashSet<String>,
    /// 最后一个检查点已提交计数
    pub last_committed_count: u64,
    /// 最后一个检查点的批次 ID
    pub last_batch_id: u64,
    /// 当前活跃的 import_id（若 WAL 未 end）
    pub active_import_id: Option<String>,
    /// 已 committed 的 {entry_key → verthys_id} 映射（供调试/审计）
    pub committed_ids: std::collections::HashMap<String, u64>,
    /// 已 committed 条目显式声明的外置块归属：{块记录 ID → 拥有者记录 ID}
    ///
    /// 仅由携带引用集合的条目累积；删除墓碑会撤销对应拥有者的声明。
    pub committed_chunk_owners: HashMap<u64, u64>,
    /// WAL 中是否存在引用集合不可推断的历史 committed 条目
    ///
    /// 为真时，台账中仍为孤儿候选的条目无法证明归属，结算路径须将其冻结，
    /// 宁可永久保留也不得回收。
    pub has_unsettleable_commits: bool,
}

/// 快照文件内容：compacted committed 集合的持久化镜像
///
/// 快照承载「压缩时点的去重集合 + ID 映射」，WAL 只保留快照之后的
/// 增量条目；恢复 = 快照基线 + WAL 增量重放，加载成本 O(1) + O(增量)。
#[derive(Serialize, Deserialize, Default)]
pub(super) struct WalSetSnapshot {
    /// 快照中的额外字段由 serde 忽略：内容哈希不得作为去重键。
    #[serde(default)]
    pub(super) committed_keys: Vec<String>,
    #[serde(default)]
    pub(super) committed_ids: Vec<(String, u64)>,
}
