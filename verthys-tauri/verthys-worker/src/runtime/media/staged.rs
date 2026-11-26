/*
 * media/staged.rs — 外置块密文暂存区（拾光 / 清藏共用）
 *
 * 拾光导入、备份还原与清藏导入都在 worker 内生成块载荷；本模块按
 * job_id 暂存，宿主只持 chunk_key/chunk_hash 引用并按组提交。载荷不经过
 * IPC，提交成功后立即释放，失败时保留以便宿主逐条重试。
 *
 * 角色隔离由 job_id 命名空间与记录角色值共同保证：不同模块的 job 不共享
 * 暂存集合，块角色（照片块 / 文件块）由宿主提交时显式携带。
 *
 * 安全约束：
 *   - 单 job 最多 16 块 / 64MiB，条目 TTL 120s，超限或过期显式失败；
 *   - 密钥由调用方传入，块键/哈希严格校验；
 *   - 提交幂等：同一 chunk_key 返回既有记录 ID，不重复写库；
 *   - 暂存仅为密文，Drop 时清零。
 */

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::runtime::budget::{PB_MAX_FILE_CHUNK_SIZE_BYTES, PB_PHOTO_CHUNK_SIZE_BYTES};
use crate::runtime::ffi_types::VerthysRecordC;
use crate::runtime::protocol::{Request, Response, StagedAddRecord};
use crate::runtime::worker::Worker;

/// 单 job 暂存块上限：正常分组提交（16 块/组）不会触顶。
const STAGED_MAX_CHUNKS: usize = 16;
/// 两类内容分块口径的较大值：暂存上限必须同时覆盖照片块与文件块，
/// 任一常量上调都不会让满批的最后一块被上限拒绝。
const STAGED_CHUNK_PLAINTEXT: usize = if PB_PHOTO_CHUNK_SIZE_BYTES > PB_MAX_FILE_CHUNK_SIZE_BYTES {
    PB_PHOTO_CHUNK_SIZE_BYTES as usize
} else {
    PB_MAX_FILE_CHUNK_SIZE_BYTES as usize
};
/// 暂存字节上限按最大块数 × 单块密文上界推导，避免块数上限与字节上限
/// 互相矛盾。
const STAGED_MAX_BYTES: usize = STAGED_MAX_CHUNKS * (STAGED_CHUNK_PLAINTEXT + 128);
/// 暂存块存活窗口：提交延迟超过该值视为异常，拒绝继续。
const STAGED_TTL: Duration = Duration::from_secs(120);
/// 单次暂存提交的块数上限（与 add_records 对齐）。
const MAX_ADD_STAGED: usize = 512;

struct StagedChunk {
    sealed: Zeroizing<Vec<u8>>,
    hash: String,
    created_at: Instant,
}

#[derive(Default)]
struct StagedSet {
    chunks: HashMap<String, StagedChunk>,
    bytes: usize,
    /// 已提交块键 → 记录 ID：宿主重试时幂等返回。
    committed: HashMap<String, u64>,
}

impl StagedSet {
    fn prune(&mut self) {
        let now = Instant::now();
        let before = self.chunks.len();
        self.chunks
            .retain(|_, chunk| now.saturating_duration_since(chunk.created_at) < STAGED_TTL);
        if self.chunks.len() != before {
            self.bytes = self.chunks.values().map(|c| c.sealed.len()).sum();
        }
    }

    /// 校验引用并区分「已提交（幂等复用）」与「本次待写」。
    fn resolve(&self, records: &[StagedAddRecord], ids: &mut [u64]) -> Result<Vec<usize>, String> {
        let mut pending = Vec::with_capacity(records.len());
        for (index, record) in records.iter().enumerate() {
            if let Some(existing) = self.committed.get(&record.chunk_key) {
                ids[index] = *existing;
                continue;
            }
            let Some(staged) = self.chunks.get(&record.chunk_key) else {
                return Err("暂存块不存在或已过期".to_string());
            };
            if staged.hash != record.chunk_hash {
                return Err("暂存块哈希不一致".to_string());
            }
            pending.push(index);
        }
        Ok(pending)
    }

    /// C 层提交成功后的记账：写回 ID、释放暂存、更新字节计数。
    fn commit(
        &mut self,
        records: &[StagedAddRecord],
        pending: &[usize],
        new_ids: &[u64],
        ids: &mut [u64],
    ) -> Result<(), String> {
        if new_ids.len() != pending.len() || new_ids.contains(&0) {
            return Err("worker 返回 ID 列表非法".to_string());
        }
        for (offset, &index) in pending.iter().enumerate() {
            ids[index] = new_ids[offset];
            self.committed
                .insert(records[index].chunk_key.clone(), new_ids[offset]);
            self.chunks.remove(&records[index].chunk_key);
        }
        self.bytes = self.chunks.values().map(|c| c.sealed.len()).sum();
        Ok(())
    }
}

static REGISTRY: LazyLock<Mutex<HashMap<String, StagedSet>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock_registry() -> MutexGuard<'static, HashMap<String, StagedSet>> {
    REGISTRY
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/* ------------------------------------------------------------------ *
 * 生产者入口                                                          *
 * ------------------------------------------------------------------ */

/// 暂存一块密文；超块数/字节上限或重复键即显式失败。
pub(crate) fn stage(
    job_id: &str,
    key: &str,
    hash: String,
    sealed: Zeroizing<Vec<u8>>,
) -> Result<(), String> {
    let mut registry = lock_registry();
    let set = registry.entry(job_id.to_string()).or_default();
    set.prune();
    if set.chunks.len() >= STAGED_MAX_CHUNKS
        || set.bytes.saturating_add(sealed.len()) > STAGED_MAX_BYTES
    {
        return Err("块暂存超出上限".to_string());
    }
    if set.chunks.contains_key(key) {
        return Err("块键重复暂存".to_string());
    }
    set.bytes += sealed.len();
    set.chunks.insert(
        key.to_string(),
        StagedChunk {
            sealed,
            hash,
            created_at: Instant::now(),
        },
    );
    Ok(())
}

/// 清空一个 job 的全部暂存与幂等映射（新文件、收尾、取消、结束）。
pub(crate) fn clear(job_id: &str) {
    lock_registry().remove(job_id);
}

/// 清理全部 job 的超时暂存；空集合一并移除，防止孤儿驻留。
pub(crate) fn prune_all() {
    let mut registry = lock_registry();
    registry.retain(|_, set| {
        set.prune();
        !set.chunks.is_empty() || !set.committed.is_empty()
    });
}

/* ------------------------------------------------------------------ *
 * 宿主提交入口                                                        *
 * ------------------------------------------------------------------ */

/// 暂存块提交：按 job_id + chunk_key 取回 worker 内密文并写入容器。
///
/// 请求只携带引用，成功后才释放暂存并记录块键→ID 映射；失败时暂存
/// 保持原样，宿主逐条重试可继续。重复提交同一块键直接返回既有 ID。
pub(crate) fn handle_add_staged(worker: &Worker, req: &Request) -> Response {
    const OP: &str = "add_records_staged";
    let records = &req.staged_records;
    let count = records.len();
    if count == 0 || count > MAX_ADD_STAGED {
        return error(OP, "暂存块数量超出范围");
    }
    let job_id = records[0].job_id.as_str();
    if job_id.is_empty()
        || job_id.len() > 128
        || records.iter().any(|record| record.job_id != job_id)
    {
        return error(OP, "暂存块 job_id 非法或不一致");
    }
    if records.iter().any(|record| {
        !is_valid_chunk_key(&record.chunk_key)
            || !is_valid_chunk_hash(&record.chunk_hash)
            || std::ffi::CString::new(record.name.as_str()).is_err()
    }) {
        return error(OP, "暂存块引用字段非法");
    }

    let mut registry = lock_registry();
    let Some(set) = registry.get_mut(job_id) else {
        return error(OP, "job 不存在或已结束");
    };
    set.prune();

    let mut ids = vec![0u64; count];
    let pending = match set.resolve(records, &mut ids) {
        Ok(pending) => pending,
        Err(e) => return error(OP, &e),
    };

    if !pending.is_empty() {
        let result = {
            let mut names: Vec<std::ffi::CString> = Vec::with_capacity(pending.len());
            let mut c_records: Vec<VerthysRecordC> = Vec::with_capacity(pending.len());
            for &index in &pending {
                let record = &records[index];
                let name = std::ffi::CString::new(record.name.as_str())
                    .expect("暂存块记录名已校验");
                let staged = set
                    .chunks
                    .get(&record.chunk_key)
                    .expect("暂存块已校验");
                c_records.push(VerthysRecordC {
                    rtype: record.rtype,
                    name: name.as_ptr(),
                    name_len: name.as_bytes().len(),
                    data: staged.sealed.as_ptr(),
                    data_len: staged.sealed.len(),
                });
                names.push(name);
            }
            worker.call_add_records(&c_records)
        };

        match result {
            Ok(new_ids) => {
                if let Err(e) = set.commit(records, &pending, &new_ids, &mut ids) {
                    return error(OP, &e);
                }
            }
            Err(code) => return Response::err(OP, code),
        }
    }

    let mut resp = Response::ok(OP);
    resp.ids = ids;
    resp
}

/* ------------------------------------------------------------------ *
 * 校验                                                                *
 * ------------------------------------------------------------------ */

/// 暂存块键：16–64 位小写十六进制（与宿主记录名规则同源）。
fn is_valid_chunk_key(key: &str) -> bool {
    (16..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 暂存块内容哈希：固定 64 位小写十六进制 BLAKE3。
fn is_valid_chunk_hash(hash: &str) -> bool {
    hash.len() == 64 && is_valid_chunk_key(hash)
}

fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

/* ------------------------------------------------------------------ *
 * 测试                                                                *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    fn record(key: &str, hash: &str) -> StagedAddRecord {
        StagedAddRecord {
            rtype: 0x10,
            name: format!("chunk_{}", key),
            job_id: "job-1".to_string(),
            chunk_key: key.to_string(),
            chunk_hash: hash.to_string(),
        }
    }

    #[test]
    fn staged_capacity_covers_full_batch() {
        /* 16 块 × (最大分块明文 + 分片头 28B + nonce 24B + tag 16B)
         * 必须落在暂存字节上限内；否则凑满一批时最后一块会被拒绝。 */
        let sealed_max = STAGED_CHUNK_PLAINTEXT + 28 + 24 + 16;
        assert!(STAGED_MAX_CHUNKS * sealed_max <= STAGED_MAX_BYTES);
    }

    #[test]
    fn stage_caps_and_rejects_duplicate_key() {
        let job_id = "stage-caps";
        clear(job_id);
        let key = "a".repeat(64);
        stage(job_id, &key, "b".repeat(64), Zeroizing::new(vec![1u8; 4])).unwrap();
        assert!(stage(job_id, &key, "b".repeat(64), Zeroizing::new(vec![1u8; 4])).is_err());
        for i in 1..STAGED_MAX_CHUNKS {
            let key = format!("{:064x}", i);
            stage(job_id, &key, key.clone(), Zeroizing::new(vec![1u8; 4])).unwrap();
        }
        let overflow = format!("{:064x}", STAGED_MAX_CHUNKS);
        assert!(stage(job_id, &overflow, overflow.clone(), Zeroizing::new(vec![1u8; 4]))
            .is_err());
        clear(job_id);
    }

    #[test]
    fn stage_rejects_over_byte_limit() {
        let job_id = "stage-bytes";
        clear(job_id);
        let key = "a".repeat(64);
        stage(
            job_id,
            &key,
            "b".repeat(64),
            Zeroizing::new(vec![0u8; STAGED_MAX_BYTES]),
        )
        .unwrap();
        let next = "c".repeat(64);
        assert!(stage(job_id, &next, next.clone(), Zeroizing::new(vec![1u8; 1])).is_err());
        clear(job_id);
    }

    #[test]
    fn expired_chunks_are_pruned() {
        let mut set = StagedSet::default();
        let key = "a".repeat(64);
        set.chunks.insert(
            key,
            StagedChunk {
                sealed: Zeroizing::new(vec![1u8; 3]),
                hash: "b".repeat(64),
                created_at: Instant::now() - STAGED_TTL - Duration::from_secs(1),
            },
        );
        set.bytes = 3;
        set.prune();
        assert!(set.chunks.is_empty());
        assert_eq!(set.bytes, 0);
    }

    #[test]
    fn committed_chunk_returns_existing_id_without_repending() {
        let mut set = StagedSet::default();
        let key = "a".repeat(64);
        set.committed.insert(key.clone(), 42);
        let records = vec![record(&key, &"b".repeat(64))];
        let mut ids = vec![0u64; 1];

        let pending = set.resolve(&records, &mut ids).unwrap();
        assert!(pending.is_empty());
        assert_eq!(ids[0], 42);
    }

    #[test]
    fn missing_or_mismatched_chunk_is_rejected() {
        let mut set = StagedSet::default();
        let key = "a".repeat(64);
        let records = vec![record(&key, &"b".repeat(64))];
        let mut ids = vec![0u64; 1];
        assert!(set.resolve(&records, &mut ids).is_err());

        set.chunks.insert(
            key.clone(),
            StagedChunk {
                sealed: Zeroizing::new(vec![1u8, 2, 3]),
                hash: "c".repeat(64),
                created_at: Instant::now(),
            },
        );
        set.bytes = 3;
        assert!(set.resolve(&records, &mut ids).is_err());

        let matched = vec![record(&key, &"c".repeat(64))];
        assert_eq!(set.resolve(&matched, &mut ids).unwrap(), vec![0]);
    }

    #[test]
    fn commit_releases_ciphertext_and_is_idempotent() {
        let mut set = StagedSet::default();
        let key = "a".repeat(64);
        let hash = "c".repeat(64);
        set.chunks.insert(
            key.clone(),
            StagedChunk {
                sealed: Zeroizing::new(vec![1u8, 2, 3]),
                hash: hash.clone(),
                created_at: Instant::now(),
            },
        );
        set.bytes = 3;
        let records = vec![record(&key, &hash)];
        let mut ids = vec![0u64; 1];
        let pending = set.resolve(&records, &mut ids).unwrap();
        set.commit(&records, &pending, &[7], &mut ids).unwrap();
        assert_eq!(ids[0], 7);
        assert!(set.chunks.is_empty());
        assert_eq!(set.bytes, 0);

        let mut retry_ids = vec![0u64; 1];
        assert!(set.resolve(&records, &mut retry_ids).unwrap().is_empty());
        assert_eq!(retry_ids[0], 7);
    }

    #[test]
    fn validators_are_strict() {
        assert!(is_valid_chunk_key(&"a".repeat(16)));
        assert!(is_valid_chunk_key(&"0".repeat(64)));
        assert!(!is_valid_chunk_key(&"A".repeat(64)));
        assert!(!is_valid_chunk_key(&"a".repeat(15)));
        assert!(is_valid_chunk_hash(&"f".repeat(64)));
        assert!(!is_valid_chunk_hash(&"f".repeat(63)));
    }
}
