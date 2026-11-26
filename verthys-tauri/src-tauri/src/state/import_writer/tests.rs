use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tempfile::tempdir;

use crate::constants::import_writer as wconst;
use crate::constants::record_types::{
    TYPE_FILEVERTHYS_CHUNK, TYPE_PHOTO_CHUNK, TYPE_PHOTO_CHUNK_SET, TYPE_PHOTO_THUMB,
};
use crate::repository::verthys_wal::{self, ImportSession, WalEntry};
use crate::state::AppState;
use crate::util::contracts::{BatchRecordInput, ChunkBlob};

use super::append_chunks::{
    chunk_record_name, is_supported_chunk_rtype, is_valid_chunk_key, process_append_chunks,
};
use super::append_records::process_append_pending;
use super::end_progress::process_end;
use super::writer_actor::append_ledger_changes;

/// 构造带活跃会话的 AppState（WAL 落于临时目录），返回时保留目录存活性
fn state_with_session() -> (AppState, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let verthys_path = dir
        .path()
        .join("test.verthys")
        .to_string_lossy()
        .to_string();
    let state = AppState::new();
    let session = ImportSession::new(&verthys_path, "imp-test").unwrap();
    *state.lock_import_session() = Some(session);
    (state, verthys_path, dir)
}

fn hb() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(0))
}

fn rec(name: &str, entry_key: &str) -> BatchRecordInput {
    BatchRecordInput {
        rtype: 1,
        name: name.to_string(),
        entry_key: entry_key.to_string(),
        data_b64: "encoded".to_string(),
        chunk_ids: None,
        chunk_hashes: None,
    }
}

/// 台账落盘临时文件路径；把该路径占为目录即可令落盘确定性失败
fn ledger_tmp_path(verthys_path: &str) -> std::path::PathBuf {
    let mut p = crate::repository::container_layout::chunk_ledger_file_for(verthys_path);
    let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    p.set_file_name(name);
    p
}

#[test]
fn test_process_end_success_compacts_and_clears_session() {
    let (state, verthys_path, _dir) = state_with_session();
    {
        let mut guard = state.lock_import_session();
        let session = guard.as_mut().unwrap();
        session.mark_committed("h1", 42);
        session
            .writer
            .append(&WalEntry::Committed {
                import_id: "imp-test".into(),
                batch_id: 1,
                entry_key: "h1".into(),
                verthys_id: 42,
                name: "a.jpg".into(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
    }

    let outcome = process_end(&state, true).unwrap();
    assert_eq!(outcome.total_committed, 1);
    assert_eq!(outcome.import_id, "imp-test");
    assert!(state.lock_import_session().is_none());

    let snap = verthys_wal::load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("h1"));
    assert!(snap.active_import_id.is_none(), "end 后应无活跃会话");
}

#[test]
fn test_process_end_missing_session_errors() {
    let state = AppState::new();
    assert!(process_end(&state, true).is_err());
    assert!(process_end(&state, false).is_err());
}

#[test]
fn test_process_end_rejects_when_ledger_persist_fails() {
    // 成功结束以减少 WAL 为前提：台账落盘失败必须拒绝结束并保留会话，
    // 否则归属声明随压缩消失，之后只能按过期台账回收
    let (state, verthys_path, _dir) = state_with_session();
    let tmp_dir = ledger_tmp_path(&verthys_path);
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let err = process_end(&state, true).unwrap_err();
    assert!(
        err.contains("台账落盘失败"),
        "错误应说明台账落盘失败: {}",
        err
    );
    assert!(
        state.lock_import_session().is_some(),
        "落盘失败必须保留会话以支持重试"
    );

    std::fs::remove_dir_all(&tmp_dir).unwrap();
    let outcome = process_end(&state, true).unwrap();
    assert_eq!(outcome.import_id, "imp-test");
    assert!(state.lock_import_session().is_none());
}

#[test]
fn test_ledger_journal_append_failure_marks_dirty_and_end_compacts() {
    let (state, verthys_path, _dir) = state_with_session();
    let journal =
        crate::repository::container_layout::chunk_ledger_journal_file_for(&verthys_path);
    // 台账日志路径被同名目录占用 → 追加打开确定性失败
    std::fs::create_dir_all(&journal).unwrap();

    {
        let mut guard = state.lock_import_session();
        let session = guard.as_mut().unwrap();
        session.chunk_ledger.set_owner(7, 0);
        append_ledger_changes(session, &[(7, 0)]);
    }
    {
        let guard = state.lock_import_session();
        assert!(
            guard.as_ref().unwrap().ledger_dirty,
            "日志追加失败应置脏标记"
        );
    }

    // 排除障碍后，结束路径全量压缩写入内存台账并清理日志
    std::fs::remove_dir_all(&journal).unwrap();
    process_end(&state, true).unwrap();

    let loaded = crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
    assert_eq!(loaded.owner_of(7), Some(0));
    assert!(!journal.exists(), "全量压缩后日志必须被清理");
}

#[test]
fn test_process_append_pending_worker_down_fails_batch_for_retry() {
    let (state, _verthys_path, _dir) = state_with_session();
    let records = vec![rec("a.jpg", "h1"), rec("b.jpg", "h2")];

    /* worker 不可达属传输级失败：整批上抛供调用方按幂等条目键重试，
     * 避免把一次超时放大成逐条 N 次超时。 */
    let err = process_append_pending(&state, records, None, &hb()).unwrap_err();
    assert!(err.contains("worker"), "错误应标注 worker 不可用: {err}");
}

#[test]
fn test_process_append_pending_dedup_skips_committed() {
    let (state, _verthys_path, _dir) = state_with_session();
    {
        let mut guard = state.lock_import_session();
        guard.as_mut().unwrap().mark_committed("h1", 1);
    }

    let outcome =
        process_append_pending(&state, vec![rec("a.jpg", "h1")], None, &hb()).unwrap();
    assert_eq!(outcome.skipped_in_batch, 1);
    assert_eq!(outcome.committed_in_batch, 0);
    assert!(outcome.failed_indices.is_empty());
    assert_eq!(outcome.ids, vec![0]);
}

#[test]
fn test_process_append_pending_rejects_empty_and_oversize() {
    let (state, _verthys_path, _dir) = state_with_session();
    assert!(process_append_pending(&state, vec![], None, &hb()).is_err());

    let many: Vec<BatchRecordInput> = (0..wconst::MAX_BATCH_RECORDS + 1)
        .map(|i| rec(&format!("f{}", i), &format!("h{}", i)))
        .collect();
    assert!(process_append_pending(&state, many, None, &hb()).is_err());
}

#[test]
fn test_process_append_pending_rejects_malformed_per_item() {
    let (state, _verthys_path, _dir) = state_with_session();

    // 畸形条目：空名称 / 超长载荷 / 超长名称；逐条拒绝而不中止整批
    //（空条目键由会话内稳定键兜底，属合法输入，不作为畸形样例）
    let empty_name = rec("", "h1");
    let mut oversize = rec("b.jpg", "h2");
    oversize.data_b64 = "A".repeat(wconst::MAX_IPC_PAYLOAD_BYTES + 1);
    let long_name = rec(&"n".repeat(wconst::MAX_RECORD_NAME_LEN + 1), "h3");

    let outcome =
        process_append_pending(&state, vec![empty_name, oversize, long_name], None, &hb())
            .unwrap();

    assert_eq!(outcome.failed_indices, vec![0, 1, 2]);
    assert_eq!(outcome.ids, vec![0, 0, 0]);
    assert_eq!(outcome.committed_in_batch, 0);
    assert_eq!(outcome.skipped_in_batch, 0);
    assert_eq!(outcome.processed_in_batch, 3);
}

#[test]
fn test_process_append_pending_rejects_oversize_name() {
    let (state, _verthys_path, _dir) = state_with_session();
    let long_name = "n".repeat(wconst::MAX_RECORD_NAME_LEN + 1);

    let outcome =
        process_append_pending(&state, vec![rec(&long_name, "h1")], None, &hb()).unwrap();

    assert_eq!(outcome.failed_indices, vec![0]);
    assert_eq!(outcome.ids, vec![0]);
}

#[test]
fn test_process_append_pending_missing_session_errors() {
    let state = AppState::new();
    let err =
        process_append_pending(&state, vec![rec("a.jpg", "h1")], None, &hb()).unwrap_err();
    assert!(err.contains("无活跃导入会话"));
}

#[test]
fn test_process_append_chunks_worker_down_fails_batch_for_retry() {
    let (state, _verthys_path, _dir) = state_with_session();
    let chunks = vec![
        ChunkBlob {
            chunk_key: "a".repeat(64),
            data_b64: "x".into(),
            rtype: None,
            ..Default::default()
        },
        ChunkBlob {
            chunk_key: "b".repeat(64),
            data_b64: "y".into(),
            rtype: None,
            ..Default::default()
        },
    ];
    /* 传输级失败整批上抛，由协调器重试（块键幂等，不会产生重复语义） */
    let err = process_append_chunks(&state, chunks, &hb()).unwrap_err();
    assert!(err.contains("worker"), "错误应标注 worker 不可用: {err}");
}

fn staged_chunk(key: &str, hash: &str) -> ChunkBlob {
    ChunkBlob {
        chunk_key: key.to_string(),
        data_b64: String::new(),
        rtype: Some(TYPE_PHOTO_CHUNK),
        staged: true,
        job_id: "job-1".to_string(),
        chunk_hash: hash.to_string(),
    }
}

#[test]
fn test_process_append_chunks_accepts_staged_reference() {
    let (state, _verthys_path, _dir) = state_with_session();
    let key = "a".repeat(64);
    let chunks = vec![staged_chunk(&key, &"b".repeat(64))];
    let err = process_append_chunks(&state, chunks, &hb()).unwrap_err();
    assert!(err.contains("暂存块"), "应进入暂存提交路径: {err}");
}

#[test]
fn test_process_append_chunks_rejects_mixed_modes() {
    let (state, _verthys_path, _dir) = state_with_session();
    let chunks = vec![
        ChunkBlob {
            chunk_key: "a".repeat(64),
            data_b64: "x".into(),
            rtype: None,
            ..Default::default()
        },
        staged_chunk(&"b".repeat(64), &"c".repeat(64)),
    ];
    let err = process_append_chunks(&state, chunks, &hb()).unwrap_err();
    assert!(err.contains("混合"), "{err}");
}

#[test]
fn test_process_append_chunks_rejects_invalid_staged_reference() {
    let (state, _verthys_path, _dir) = state_with_session();
    let key = "a".repeat(64);
    let with_data = ChunkBlob {
        data_b64: "x".into(),
        ..staged_chunk(&key, &"b".repeat(64))
    };
    let bad_hash = staged_chunk(&key, "b");
    let outcome = process_append_chunks(&state, vec![with_data, bad_hash], &hb()).unwrap();
    assert_eq!(outcome.failed_indices, vec![0, 1]);
    assert_eq!(outcome.ids, vec![0, 0]);
}

#[test]
fn test_process_append_chunks_rejects_empty_oversize_malformed() {
    let (state, _verthys_path, _dir) = state_with_session();
    assert!(process_append_chunks(&state, vec![], &hb()).is_err());

    let many: Vec<ChunkBlob> = (0..wconst::MAX_CHUNKS_PER_IPC + 1)
        .map(|i| ChunkBlob {
            chunk_key: format!("{i:064x}"),
            data_b64: "x".into(),
            rtype: None,
            ..Default::default()
        })
        .collect();
    assert!(process_append_chunks(&state, many, &hb()).is_err());

    // 畸形输入按条失败，不中止整批（全部条目均在本地被拒绝时批次正常返回）
    let mixed = vec![
        ChunkBlob {
            chunk_key: "a".repeat(64),
            data_b64: "x".into(),
            rtype: Some(0x30), // 未知角色类型
            ..Default::default()
        },
        ChunkBlob {
            chunk_key: String::new(), // 空块键
            data_b64: "y".into(),
            rtype: None,
            ..Default::default()
        },
    ];
    let outcome = process_append_chunks(&state, mixed, &hb()).unwrap();
    assert_eq!(outcome.failed_indices, vec![0, 1], "畸形块必须入失败集");
    assert_eq!(outcome.ids, vec![0, 0]);
}

#[test]
fn test_process_append_chunks_rejects_unknown_role_type() {
    let (state, _verthys_path, _dir) = state_with_session();
    // 未知角色类型（既非块也非缩略图）：按条拒绝，不写入越界类型
    let chunks = vec![ChunkBlob {
        chunk_key: "c".repeat(64),
        data_b64: "z".into(),
        rtype: Some(0x30),
        ..Default::default()
    }];
    let outcome = process_append_chunks(&state, chunks, &hb()).unwrap();
    assert_eq!(outcome.failed_indices, vec![0]);
    assert_eq!(outcome.ids, vec![0]);
}

#[test]
fn test_chunk_rtype_whitelist_covers_fileverthys_and_rejects_others() {
    // 受支持角色：照片数据块 / 缩略图 / 块集 + 清藏文件块
    assert!(is_supported_chunk_rtype(TYPE_FILEVERTHYS_CHUNK));
    assert!(is_supported_chunk_rtype(TYPE_PHOTO_CHUNK));
    assert!(is_supported_chunk_rtype(TYPE_PHOTO_THUMB));
    assert!(is_supported_chunk_rtype(TYPE_PHOTO_CHUNK_SET));

    // 非外置载荷角色（元数据类型 / 加密根记录 / 越界值）一律拒收
    assert!(!is_supported_chunk_rtype(0));
    assert!(!is_supported_chunk_rtype(0x08));
    assert!(!is_supported_chunk_rtype(0x10));
    assert!(!is_supported_chunk_rtype(0x30));
}

#[test]
fn test_chunk_record_name_derivation_by_role() {
    let key = "d".repeat(64);
    let other = "f".repeat(64);

    // 清藏文件块与照片数据块共用默认前缀；缩略图与块集各有专属前缀
    assert_eq!(
        chunk_record_name(TYPE_FILEVERTHYS_CHUNK, &key),
        format!("chunk_{key}")
    );
    assert_eq!(
        chunk_record_name(TYPE_PHOTO_CHUNK, &key),
        format!("chunk_{key}")
    );
    assert_eq!(
        chunk_record_name(TYPE_PHOTO_THUMB, &key),
        format!("thumb_{key}")
    );
    assert_eq!(
        chunk_record_name(TYPE_PHOTO_CHUNK_SET, &key),
        format!("cset_{key}")
    );

    // 不同块键必须产生不同记录名（不是内容哈希，不跨文件复用）
    assert_ne!(
        chunk_record_name(TYPE_PHOTO_CHUNK, &key),
        chunk_record_name(TYPE_PHOTO_CHUNK, &other)
    );
    assert!(!chunk_record_name(TYPE_FILEVERTHYS_CHUNK, "e").contains("bin"));
}

#[test]
fn test_chunk_key_format_validation() {
    // 合法：16–64 位小写十六进制
    assert!(is_valid_chunk_key(&"a".repeat(16)));
    assert!(is_valid_chunk_key(&"0f".repeat(32)));
    assert!(is_valid_chunk_key(&"a".repeat(64)));
    // 非法：过短 / 过长 / 大写 / 非十六进制字符
    assert!(!is_valid_chunk_key(&"a".repeat(15)));
    assert!(!is_valid_chunk_key(&"a".repeat(65)));
    assert!(!is_valid_chunk_key(&"A".repeat(64)));
    assert!(!is_valid_chunk_key(&"z".repeat(64)));
    assert!(!is_valid_chunk_key("chunk-0000-0000"));
    assert!(!is_valid_chunk_key(""));
}

#[test]
fn test_process_append_chunks_rejects_malformed_key_format() {
    let (state, _verthys_path, _dir) = state_with_session();
    let chunks = vec![
        ChunkBlob {
            chunk_key: "A".repeat(64),
            data_b64: "x".into(),
            rtype: None,
            ..Default::default()
        },
        ChunkBlob {
            chunk_key: "c".repeat(15),
            data_b64: "y".into(),
            rtype: None,
            ..Default::default()
        },
    ];
    let outcome = process_append_chunks(&state, chunks, &hb()).unwrap();
    assert_eq!(outcome.failed_indices, vec![0, 1]);
    assert_eq!(outcome.ids, vec![0, 0]);
}

#[test]
fn test_process_append_pending_dangling_chunk_ref_rejected() {
    let (state, _verthys_path, _dir) = state_with_session();
    // 引用未上传的块 ID：按条拒绝，不进入 WAL pending
    let mut record = rec("a.jpg", "h1");
    record.chunk_ids = Some(vec![999]);
    let outcome = process_append_pending(&state, vec![record], None, &hb()).unwrap();
    assert_eq!(outcome.failed_indices, vec![0]);
    assert_eq!(outcome.ids, vec![0]);
    assert_eq!(outcome.committed_in_batch, 0);
}

#[test]
fn test_import_session_chunk_bookkeeping() {
    let (state, _verthys_path, _dir) = state_with_session();
    {
        let mut guard = state.lock_import_session();
        let session = guard.as_mut().unwrap();
        assert!(!session.chunk_refs_known(&[1]));
        session.remember_chunk("aa", 1);
        session.remember_chunk("bb", 2);
        assert_eq!(session.lookup_chunk("aa"), Some(1));
        assert!(session.chunk_refs_known(&[1, 2]));
        assert!(!session.chunk_refs_known(&[1, 3]));
    }
}
