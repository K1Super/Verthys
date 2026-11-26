//! WAL 恢复重放、块归属结算与去重键维护

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::repository::container_layout;

use super::wal_io::{now_ms, resolve_wal_path, snapshot_path_for};
use super::wal_types::{WalEntry, WalSetSnapshot, WalSnapshot};
use super::wal_writer::WalWriter;

/// 从指定 WAL 文件路径加载快照（快照文件基线 + WAL 增量重放）
pub(super) fn load_from_path(path: &Path) -> Result<WalSnapshot, String> {
    let mut snapshot = WalSnapshot::default();

    // 1. 快照文件基线（compacted committed 集合，O(1) 载入）
    let snap_path = snapshot_path_for(path);
    if snap_path.exists() {
        let text =
            std::fs::read_to_string(&snap_path).map_err(|e| format!("WAL 快照读取失败: {}", e))?;
        let base: WalSetSnapshot =
            serde_json::from_str(&text).map_err(|e| format!("WAL 快照解析失败: {}", e))?;
        for key in base.committed_keys {
            if !key.is_empty() {
                snapshot.committed_keys.insert(key);
            }
        }
        for (key, id) in base.committed_ids {
            snapshot.committed_ids.insert(key, id);
        }
        snapshot.last_committed_count = snapshot.committed_keys.len() as u64;
    }

    // 2. 增量重放（快照之后追加的 WAL 条目；无 WAL 则仅快照有效）
    if !path.exists() {
        return Ok(snapshot);
    }

    let file = File::open(path).map_err(|e| format!("WAL 打开失败: {}", e))?;
    let reader = BufReader::new(file);

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("WAL 读取失败 (行 {}): {}", line_no + 1, e))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: WalEntry = serde_json::from_str(line)
            .map_err(|e| format!("WAL 反序列化失败 (行 {}): {}", line_no + 1, e))?;

        match entry {
            WalEntry::Begin { import_id, .. } => {
                // 仅标记活跃会话，不清空已累积的去重集合：WAL 每次会话创建前
                // 会被截断，重放到的 Begin 必为当前历史的起点；存在快照基线时
                // （上次压缩的哈希全集）基线必须跨会话保留，清空会永久丢失
                // 既有照片的去重键，导致重新入库产生重复记录。
                snapshot.active_import_id = Some(import_id);
                snapshot.last_committed_count = 0;
                snapshot.last_batch_id = 0;
            }
            WalEntry::Pending { .. } => {
                // pending 不进入 committed_keys，续传时重新处理
            }
            WalEntry::Committed {
                entry_key,
                verthys_id,
                import_id,
                chunk_ids,
                ..
            } => {
                if !entry_key.is_empty() {
                    snapshot.committed_keys.insert(entry_key.clone());
                    /* 同一批次可写入共用条目键的多条记录（照片 meta 与预览）：
                     * ID 映射只认首条索引记录，重放时不得让后写记录覆盖，
                     * 否则删除流程按 meta ID 反查条目键会落空，去重锁永久残留。 */
                    snapshot
                        .committed_ids
                        .entry(entry_key)
                        .or_insert(verthys_id);
                }
                match chunk_ids {
                    Some(ids) => {
                        for chunk_id in ids {
                            snapshot.committed_chunk_owners.insert(chunk_id, verthys_id);
                        }
                    }
                    // 历史条目未携带引用集合：归属无从推断，标记为不可结算，
                    // 由结算路径对台账孤儿候选执行冻结
                    None => snapshot.has_unsettleable_commits = true,
                }
                snapshot.active_import_id = Some(import_id);
            }
            WalEntry::Checkpoint {
                batch_id,
                committed_count,
                import_id,
            } => {
                snapshot.last_batch_id = batch_id;
                snapshot.last_committed_count = committed_count;
                snapshot.active_import_id = Some(import_id);
            }
            WalEntry::Removed { keys, .. } => {
                // 删除墓碑：从续传幂等集合移除（删除后可重新导入语义），并撤销
                // 该记录声明过的块归属，避免把已删除记录的块结算成有效归属
                for key in &keys {
                    if let Some(owner_id) = snapshot.committed_ids.remove(key) {
                        snapshot
                            .committed_chunk_owners
                            .retain(|_, owner| *owner != owner_id);
                    }
                    snapshot.committed_keys.remove(key);
                }
            }
            WalEntry::End { .. } => {
                // 会话结束：保留已构建的 committed_keys 供下次去重
                snapshot.active_import_id = None;
            }
        }
    }

    Ok(snapshot)
}

/// 加载给定 verthys 路径对应的 WAL 快照（恢复入口）
pub fn load(verthys_path: &str) -> Result<WalSnapshot, String> {
    let path = resolve_wal_path(verthys_path);
    load_from_path(&path)
}

/// 台账结算统计（用于日志与断言，不参与分支判定）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SettlementOutcome {
    /// 本次真正改写归属的块记录数
    pub settled: u64,
    /// 本次被冻结（归属不可证明）的块记录数
    pub frozen: u64,
}

impl SettlementOutcome {
    /// 是否产生了台账变更；无变更时调用方无需重写台账文件
    pub fn changed(&self) -> bool {
        self.settled > 0 || self.frozen > 0
    }
}

/// 把 WAL 快照中的块归属声明应用到台账（纯内存变换，不落盘）
///
/// 两条规则：
///   1. 显式声明过引用集合的条目：把其块记录的归属改写为对应记录 ID；
///   2. 存在引用集合不可推断的历史条目时：台账中仍为孤儿候选的条目一律冻结
///      —— 它们可能被已提交记录引用，只是无从证明，宁可永久保留也不误删。
pub(super) fn apply_settlement(
    snapshot: &WalSnapshot,
    ledger: &mut crate::repository::verthys_chunks::ChunkLedger,
) -> SettlementOutcome {
    let mut outcome = SettlementOutcome::default();

    for (chunk_id, owner_id) in &snapshot.committed_chunk_owners {
        if ledger.owner_of(*chunk_id) != Some(*owner_id) {
            ledger.set_owner(*chunk_id, *owner_id);
            outcome.settled += 1;
        }
    }

    if snapshot.has_unsettleable_commits {
        for chunk_id in ledger.garbage_ids() {
            ledger.set_owner(
                chunk_id,
                crate::repository::verthys_chunks::UNVERIFIABLE_OWNER,
            );
            outcome.frozen += 1;
        }
    }

    outcome
}

/// 结算块归属并落盘（孤儿回收前的守卫入口）
///
/// 存在这样的崩溃窗口：记录已提交，而台账尚未把块归属从「孤儿候选」改写
/// 为拥有者；此时直接按台账回收，会删掉仍被已提交记录引用的块。本函数以
/// WAL 中的归属声明为权威重建台账，对无法证明归属的历史条目执行冻结，
/// 保证回收面绝不扩大。
///
/// 台账落盘失败向上传播为 Err：调用方必须放弃本次回收（保守不删）。
pub fn settle_chunk_owners(verthys_path: &str) -> Result<SettlementOutcome, String> {
    let snapshot = load(verthys_path)?;
    let mut ledger = crate::repository::verthys_chunks::load_chunk_ledger(verthys_path)?;
    let outcome = apply_settlement(&snapshot, &mut ledger);
    if outcome.changed() {
        crate::repository::verthys_chunks::save_chunk_ledger(verthys_path, &ledger)?;
    }
    Ok(outcome)
}

/// 追加删除墓碑（照片删除后释放续传幂等锁，删除后可重新导入）。
///
/// 以 append 模式写入既有 WAL（含 fsync）；WAL 与快照均不存在时为无操作
/// （幂等集合本为空，无可释放）。墓碑独立于导入会话：恢复重放时
/// 与条目位置无关地从 committed 集合移除条目键，且下一次会话创建在
/// 截断 WAL 前先完成重放，移除效果在截断后由内存集合继续承载。
/// 仅快照存在（WAL 已被清理）时创建最小 WAL 承载墓碑，避免快照基线
/// 在下次会话创建时复活已删除条目键。
pub fn append_removed(verthys_path: &str, keys: &[String]) -> Result<(), String> {
    if keys.is_empty() {
        return Ok(());
    }
    let path = resolve_wal_path(verthys_path);
    if !path.exists() {
        /* 无 WAL 但存在快照基线：去重集合仍可由快照承载，墓碑必须持久化。
         * 否则下次会话创建会把「快照 + 无增量」的旧集合重新固化，已删除
         * 条目键复活，重新导入被静默跳过。 */
        if !snapshot_path_for(&path).exists() {
            return Ok(());
        }
        container_layout::ensure_sidecar_dir(verthys_path)?;
        let mut writer = WalWriter::create(verthys_path, "prune")?;
        return writer.append(&WalEntry::Removed {
            keys: keys.to_vec(),
            at: now_ms(),
        });
    }
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|e| format!("WAL 追加打开失败: {}", e))?;
    let entry = WalEntry::Removed {
        keys: keys.to_vec(),
        at: now_ms(),
    };
    let line = serde_json::to_string(&entry).map_err(|e| format!("WAL 序列化失败: {}", e))?;
    writeln!(file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
    file.flush().map_err(|e| format!("WAL flush 失败: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("WAL fsync 失败: {}", e))?;
    Ok(())
}

/// 按记录 ID 解析已 committed 的条目键（只读映射，不改变去重集合）。
///
/// 删除流程即使无法解密 meta（模块密钥轮换/历史损坏），也能凭记录 ID
/// 释放续传幂等锁：WAL committed 行同时记录 `entry_key` 与 `verthys_id`。
pub fn keys_for_ids(verthys_path: &str, ids: &[u64]) -> Result<Vec<String>, String> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let snapshot = load(verthys_path)?;
    let wanted: HashSet<u64> = ids.iter().copied().filter(|id| *id != 0).collect();
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    Ok(snapshot
        .committed_ids
        .into_iter()
        .filter(|(_, id)| wanted.contains(id))
        .map(|(key, _)| key)
        .collect())
}

/// 收敛失效去重键：已 committed 记录 ID 不再存在于容器时移除对应条目键。
///
/// 删除墓碑可能因历史缺陷或崩溃缺失（例如删除时 meta 已不可解密，前端
/// 拿不到条目键）。已删除记录不再有 ID，其去重键必须视为失效，否则同一
/// 来源文件重新导入会被静默全部跳过。
pub fn prune_missing_commits(verthys_path: &str, live_ids: &HashSet<u64>) -> Result<u64, String> {
    let snapshot = load(verthys_path)?;
    if snapshot.committed_ids.is_empty() {
        return Ok(0);
    }
    let stale: Vec<String> = snapshot
        .committed_ids
        .into_iter()
        .filter(|(_, id)| !live_ids.contains(id))
        .map(|(key, _)| key)
        .collect();
    if stale.is_empty() {
        return Ok(0);
    }
    append_removed(verthys_path, &stale)?;
    Ok(stale.len() as u64)
}
