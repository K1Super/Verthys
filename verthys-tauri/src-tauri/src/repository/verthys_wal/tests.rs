//! WAL 写入、重放、压缩与去重键维护的单元测试

use super::*;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::repository::container_layout;

pub(super) fn make_verthys_path(dir: &Path) -> String {
    dir.join("test.verthys").to_string_lossy().to_string()
}

/// WAL 路径（测试直读写用；先确保附属目录存在）
pub(super) fn wal_file(verthys_path: &str) -> PathBuf {
    let _ = container_layout::ensure_sidecar_dir(verthys_path);
    container_layout::wal_file_for(verthys_path)
}

#[test]
fn test_wal_create_append_commit() {
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-1").unwrap();
    writer
        .append(&WalEntry::Pending {
            import_id: "imp-1".into(),
            batch_id: 1,
            entry_key: "abc".into(),
            name: "a.jpg".into(),
            idx: 0,
        })
        .unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-1".into(),
            batch_id: 1,
            entry_key: "abc".into(),
            verthys_id: 42,
            name: "a.jpg".into(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer.finish("imp-1", true).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("abc"));
    assert_eq!(snap.committed_ids.get("abc"), Some(&42));
    assert!(snap.active_import_id.is_none(), "end 后应无活跃会话");
}

#[test]
fn test_wal_crash_recovery_pending_not_committed() {
    // 模拟崩溃：写入 pending 但未 committed，未 end
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-2").unwrap();
    writer
        .append(&WalEntry::Pending {
            import_id: "imp-2".into(),
            batch_id: 1,
            entry_key: "dup".into(),
            name: "b.jpg".into(),
            idx: 0,
        })
        .unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-2".into(),
            batch_id: 1,
            entry_key: "ok".into(),
            verthys_id: 7,
            name: "c.jpg".into(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    // 不调用 finish，模拟崩溃
    drop(writer);

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("ok"));
    assert!(
        !snap.committed_keys.contains("dup"),
        "pending 未 committed 不应进入去重集合"
    );
    assert!(snap.active_import_id.is_some(), "未 end 应保留活跃会话");
}

#[test]
fn test_wal_dedup_idempotent() {
    // 续传场景：已 committed 的哈希在去重集合中，重新导入应跳过
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-3").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-3".into(),
            batch_id: 1,
            entry_key: "h1".into(),
            verthys_id: 1,
            name: "x".into(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer.finish("imp-3", true).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("h1"));
}

#[test]
fn test_mark_committed_keeps_first_index_id() {
    // 照片 meta 与预览共用条目键：ID 映射必须指向首条索引记录，
    // 删除流程按 meta 记录 ID 反查条目键才能释放续传幂等锁。
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());
    let mut session = ImportSession::new(&verthys_path, "imp-dup").unwrap();

    session.mark_committed("k1", 100);
    session.mark_committed("k1", 101);

    assert_eq!(session.committed_ids.get("k1"), Some(&100));
    assert_eq!(session.total_committed, 1);
    assert_eq!(session.key_for_id(100), Some("k1"));
    assert_eq!(session.key_for_id(101), None);
}

#[test]
fn test_wal_replay_keeps_first_index_id_for_shared_key() {
    // 历史 WAL 可能对同一条目键写入 meta 与预览两条 committed 行；
    // 重放必须保留首条索引记录 ID，删除流程才能按 meta ID 释放去重锁。
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());
    let mut writer = WalWriter::create(&verthys_path, "imp-shared").unwrap();
    for (name, verthys_id) in [("meta_a.jpg", 100u64), ("preview_a", 101u64)] {
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-shared".into(),
                batch_id: 1,
                entry_key: "k-shared".into(),
                verthys_id,
                name: name.into(),
                chunk_ids: None,
            })
            .unwrap();
    }
    writer.finish("imp-shared", true).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert_eq!(snap.committed_ids.get("k-shared"), Some(&100));
    let by_meta = keys_for_ids(&verthys_path, &[100]).unwrap();
    assert_eq!(by_meta, vec!["k-shared".to_string()]);
    let by_preview = keys_for_ids(&verthys_path, &[101]).unwrap();
    assert!(by_preview.is_empty());
}

#[test]
fn test_wal_compact_preserves_committed() {
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-4").unwrap();
    for i in 0..50 {
        writer
            .append(&WalEntry::Pending {
                import_id: "imp-4".into(),
                batch_id: 1,
                entry_key: format!("h{}", i),
                name: format!("f{}", i),
                idx: i,
            })
            .unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-4".into(),
                batch_id: 1,
                entry_key: format!("h{}", i),
                verthys_id: 100 + i,
                name: format!("f{}", i),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
    }
    writer.finish("imp-4", true).unwrap();

    // compact 后重新加载，所有 committed 哈希应保留
    let snap = load(&verthys_path).unwrap();
    for i in 0..50 {
        assert!(
            snap.committed_keys.contains(&format!("h{}", i)),
            "compact 后哈希 h{} 应保留",
            i
        );
    }
}

#[test]
fn test_wal_load_nonexistent() {
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());
    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.is_empty());
}

#[test]
fn test_wal_append_deferred_batched_flush() {
    // 批量 pending 走 deferred 追加 + 一次 flush_sync：行完整可重放，
    // 且 pending 语义不变（不进入 committed 集合）
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-d").unwrap();
    writer
        .append_deferred(&WalEntry::Pending {
            import_id: "imp-d".into(),
            batch_id: 1,
            entry_key: "p1".into(),
            name: "a.jpg".into(),
            idx: 0,
        })
        .unwrap();
    writer
        .append_deferred(&WalEntry::Pending {
            import_id: "imp-d".into(),
            batch_id: 1,
            entry_key: "p2".into(),
            name: "b.jpg".into(),
            idx: 1,
        })
        .unwrap();
    writer.flush_sync().unwrap();
    drop(writer);

    let text = std::fs::read_to_string(wal_file(&verthys_path)).unwrap();
    assert_eq!(text.lines().count(), 3, "begin + 2 条 pending 应全部落盘");

    let snap = load(&verthys_path).unwrap();
    assert!(!snap.committed_keys.contains("p1"));
    assert!(!snap.committed_keys.contains("p2"));
}

#[test]
fn test_wal_removed_tombstone_releases_dedup() {
    // 删除墓碑：恢复重放后哈希从去重集合移除（删除后可重新导入）
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-r").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-r".into(),
            batch_id: 1,
            entry_key: "h1".into(),
            verthys_id: 5,
            name: "a.jpg".into(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer.finish("imp-r", true).unwrap();

    append_removed(&verthys_path, &["h1".to_string()]).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(!snap.committed_keys.contains("h1"), "墓碑应释放去重锁");
    assert!(!snap.committed_ids.contains_key("h1"));
}

#[test]
fn test_append_removed_noop_without_wal() {
    // WAL 不存在：墓碑为无操作（去重集合本就为空），且不创建 WAL 文件
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());
    append_removed(&verthys_path, &["h1".to_string()]).unwrap();
    assert!(!exists(&verthys_path), "无 WAL 时不得创建文件");
}

#[test]
fn test_append_removed_by_ids_releases_keys() {
    // 删除流程按记录 ID 释放去重键（meta 不可解密时仍可闭环）
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-id").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-id".into(),
            batch_id: 1,
            entry_key: "old".into(),
            verthys_id: 77,
            name: "a.jpg".into(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer.finish("imp-id", true).unwrap();

    let released = keys_for_ids(&verthys_path, &[77]).unwrap();
    assert_eq!(released.len(), 1);
    append_removed(&verthys_path, &released).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(!snap.committed_keys.contains("old"));
    assert!(!snap.committed_ids.contains_key("old"));
}

#[test]
fn test_prune_missing_commits_drops_only_absent_ids() {
    // 记录仍存活时保留去重键；记录已删除（ID 不存在）时键失效
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-prune").unwrap();
    for (key, id) in [("keep", 11u64), ("gone", 22u64)] {
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-prune".into(),
                batch_id: 1,
                entry_key: key.into(),
                verthys_id: id,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
    }
    writer.finish("imp-prune", true).unwrap();

    let live: HashSet<u64> = [11u64].into_iter().collect();
    let pruned = prune_missing_commits(&verthys_path, &live).unwrap();
    assert_eq!(pruned, 1);

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("keep"));
    assert!(!snap.committed_keys.contains("gone"));
}

#[test]
fn test_append_removed_with_snapshot_but_no_wal_persists() {
    // WAL 已被清理但快照仍承载去重集合：墓碑必须落盘，否则下次会话
    // 创建会从快照基线复活已删除条目键
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-snap").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-snap".into(),
            batch_id: 1,
            entry_key: "h1".into(),
            verthys_id: 5,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer.finish("imp-snap", true).unwrap();
    std::fs::remove_file(wal_file(&verthys_path)).unwrap();

    append_removed(&verthys_path, &["h1".to_string()]).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(!snap.committed_keys.contains("h1"), "墓碑必须跨快照生效");
}

#[test]
fn test_snapshot_survives_wal_absence() {
    // 快照文件独立承载 committed 集合：WAL 文件缺失时仍可恢复去重
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-s").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-s".into(),
            batch_id: 1,
            entry_key: "hs".into(),
            verthys_id: 9,
            name: "s.jpg".into(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer.finish("imp-s", true).unwrap();

    // WAL 文件被移除（模拟外部清理/损坏），快照仍提供去重集合
    std::fs::remove_file(wal_file(&verthys_path)).unwrap();
    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("hs"));
    assert_eq!(snap.committed_ids.get("hs"), Some(&9));
}

#[test]
fn test_import_session_loads_existing_chunk_ledger() {
    // 预写台账文件后新建会话：会话字段应载入既有映射（且不触碰台账文件本身）
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
    ledger.set_owner(101, 0);
    ledger.set_owner(202, 77);
    crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

    let session = ImportSession::new(&verthys_path, "imp-ledger").unwrap();
    assert_eq!(session.chunk_ledger.garbage_ids(), vec![101]);

    // 台账文件应保持原样（会话 new 只读台账，不重写）：两条映射均可在
    // 重载后的台账中命中移除，且仅有 101 是 owner==0 的孤儿候选
    let mut reloaded =
        crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
    assert_eq!(reloaded.garbage_ids(), vec![101]);
    assert!(reloaded.remove(&101));
    assert!(reloaded.remove(&202));
}

#[test]
fn test_import_session_forget_committed() {
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut session = ImportSession::new(&verthys_path, "imp-f").unwrap();
    session.mark_committed("h1", 42);
    session.mark_committed("h2", 43);
    assert_eq!(session.total_committed, 2);

    assert!(session.forget_committed("h1"));
    assert!(!session.forget_committed("h1"), "重复释放不重复计数");
    assert_eq!(session.total_committed, 1);
    assert!(!session.is_committed("h1"));
    assert!(session.is_committed("h2"));
}

#[test]
fn test_snapshot_baseline_survives_new_session() {
    // 回归：新会话 WAL 重放时 Begin 不得清空快照基线，
    // 否则上一会话压缩固化到快照的去重键将全部丢失，
    // 重启后重新导入同一批照片会产生重复记录
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    // 会话 A：入库 2 张并成功结束（compact 生成快照 + 最小 WAL）
    let mut writer = WalWriter::create(&verthys_path, "imp-a").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-a".into(),
            batch_id: 1,
            entry_key: "h1".into(),
            verthys_id: 1,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-a".into(),
            batch_id: 1,
            entry_key: "h2".into(),
            verthys_id: 2,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Checkpoint {
            import_id: "imp-a".into(),
            batch_id: 1,
            committed_count: 2,
        })
        .unwrap();
    writer.finish("imp-a", true).unwrap();

    // 会话 B：截断 WAL 写新 begin + 新记录，随后模拟崩溃（无 end）
    let mut writer = WalWriter::create(&verthys_path, "imp-b").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-b".into(),
            batch_id: 1,
            entry_key: "h3".into(),
            verthys_id: 3,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Checkpoint {
            import_id: "imp-b".into(),
            batch_id: 1,
            committed_count: 3,
        })
        .unwrap();
    drop(writer);

    let snap = load(&verthys_path).unwrap();
    assert!(
        snap.committed_keys.contains("h1"),
        "快照基线哈希 h1 跨会话必须保留"
    );
    assert!(snap.committed_keys.contains("h2"));
    assert!(snap.committed_keys.contains("h3"));
    assert_eq!(snap.committed_keys.len(), 3);
}

#[test]
fn test_compact_wal_is_minimal_skeleton() {
    // compact 后 WAL 仅保留会话骨架（begin/checkpoint/end），
    // 哈希全集由快照承载；重放成本与存活记录数解耦
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-m").unwrap();
    for i in 0..50 {
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-m".into(),
                batch_id: 1,
                entry_key: format!("h{}", i),
                verthys_id: 100 + i,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
    }
    writer
        .append(&WalEntry::Checkpoint {
            import_id: "imp-m".into(),
            batch_id: 1,
            committed_count: 50,
        })
        .unwrap();
    writer.finish("imp-m", true).unwrap();

    let wal_text = std::fs::read_to_string(wal_file(&verthys_path)).unwrap();
    let line_count = wal_text.lines().count();
    assert!(
        line_count < 10,
        "compact 后 WAL 应为会话骨架，实际 {} 行",
        line_count
    );

    let snap = load(&verthys_path).unwrap();
    assert_eq!(snap.committed_keys.len(), 50, "快照承载全部 50 个哈希");
    assert!(snap.committed_keys.contains("h49"));
}

#[test]
fn test_tombstone_after_compact_releases_snapshot_hash() {
    // 墓碑追加在 compact 之后的 WAL 尾部，重放必须能移除快照基线内的哈希
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut writer = WalWriter::create(&verthys_path, "imp-t").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-t".into(),
            batch_id: 1,
            entry_key: "keep".into(),
            verthys_id: 1,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-t".into(),
            batch_id: 1,
            entry_key: "gone".into(),
            verthys_id: 2,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Checkpoint {
            import_id: "imp-t".into(),
            batch_id: 1,
            committed_count: 2,
        })
        .unwrap();
    writer.finish("imp-t", true).unwrap();

    append_removed(&verthys_path, &["gone".to_string()]).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("keep"));
    assert!(
        !snap.committed_keys.contains("gone"),
        "墓碑须移除快照基线内的哈希"
    );
}

#[test]
fn test_tombstone_survives_session_creation_and_ends() {
    // 回归（去重锁复活缺陷）：删除墓碑仅落在 WAL 尾部；会话创建会截断
    // WAL，若未把「快照基线 + WAL 重放」后的权威集合固化为新基线，墓碑
    // 随截断消失，失败结束（不 compact）后下次载入即复活已删除哈希，
    // 表现为删除后重新导入同一文件被静默全部跳过。
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    // 会话 A：入库 2 条并成功结束（compact 固化快照 + 最小骨架 WAL）
    let mut writer = WalWriter::create(&verthys_path, "imp-a").unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-a".into(),
            batch_id: 1,
            entry_key: "keep".into(),
            verthys_id: 1,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Committed {
            import_id: "imp-a".into(),
            batch_id: 1,
            entry_key: "gone".into(),
            verthys_id: 2,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    writer
        .append(&WalEntry::Checkpoint {
            import_id: "imp-a".into(),
            batch_id: 1,
            committed_count: 2,
        })
        .unwrap();
    writer.finish("imp-a", true).unwrap();

    // 删除墓碑：释放 gone 的去重锁
    append_removed(&verthys_path, &["gone".to_string()]).unwrap();
    assert!(!load(&verthys_path)
        .unwrap()
        .committed_keys
        .contains("gone"));

    // 会话 B：创建（截断 WAL）→ 以失败结束（不 compact，原样保留 WAL）
    let session = ImportSession::new(&verthys_path, "imp-b").unwrap();
    assert!(
        !session.is_committed("gone"),
        "会话内集合须等于墓碑后的权威集合"
    );
    assert!(session.is_committed("keep"));
    session.writer.finish("imp-b", false).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("keep"));
    assert!(
        !snap.committed_keys.contains("gone"),
        "墓碑必须跨会话创建持久化（失败结束路径）"
    );

    // 会话 C：再次创建 → 以成功结束（compact 重写快照）
    let mut session = ImportSession::new(&verthys_path, "imp-c").unwrap();
    session.mark_committed("fresh", 3);
    session
        .writer
        .append(&WalEntry::Committed {
            import_id: "imp-c".into(),
            batch_id: 1,
            entry_key: "fresh".into(),
            verthys_id: 3,
            name: String::new(),
            chunk_ids: Some(Vec::new()),
        })
        .unwrap();
    session.writer.finish("imp-c", true).unwrap();

    let snap = load(&verthys_path).unwrap();
    assert!(snap.committed_keys.contains("keep"));
    assert!(snap.committed_keys.contains("fresh"));
    assert!(
        !snap.committed_keys.contains("gone"),
        "墓碑必须跨会话创建持久化（成功压缩路径）"
    );
}
