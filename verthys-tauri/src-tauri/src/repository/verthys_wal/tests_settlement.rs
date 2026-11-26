//! 块归属结算与建会话结算时机的单元测试

use super::tests::{make_verthys_path, wal_file};
use super::*;
use std::path::PathBuf;

use tempfile::tempdir;

use crate::repository::container_layout;

/// 台账落盘临时文件路径；把该路径占为目录即可令落盘确定性失败
fn ledger_tmp_path(verthys_path: &str) -> PathBuf {
    let mut p = container_layout::chunk_ledger_file_for(verthys_path);
    let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    p.set_file_name(name);
    p
}

/// 手写 WAL 文本（用于构造携带/缺省引用集合的历史条目）
fn write_wal_text(verthys_path: &str, text: &str) {
    std::fs::write(wal_file(verthys_path), text).unwrap();
}

#[test]
fn test_committed_chunk_ids_accumulate_and_legacy_marked() {
    // 显式声明引用集合的条目累积归属；字段缺省的历史条目标记为不可结算
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());
    write_wal_text(
        &verthys_path,
        concat!(
            "{\"kind\":\"begin\",\"import_id\":\"imp-x\",\"ts\":1}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-x\",\"batch_id\":1,",
            "\"hash\":\"legacy\",\"verthys_id\":11,\"name\":\"a.jpg\"}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-x\",\"batch_id\":1,",
            "\"hash\":\"fresh\",\"verthys_id\":22,\"name\":\"b.jpg\",\"chunk_ids\":[7,8]}\n"
        ),
    );

    let snap = load(&verthys_path).unwrap();
    assert_eq!(snap.committed_chunk_owners.get(&7), Some(&22));
    assert_eq!(snap.committed_chunk_owners.get(&8), Some(&22));
    assert!(snap.has_unsettleable_commits, "历史条目应标记为不可结算");
}

#[test]
fn test_settle_chunk_owners_applies_and_freezes() {
    // 已被声明的块归属改写为记录 ID；无法证明归属的孤儿候选冻结
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
    ledger.set_owner(7, 0);
    ledger.set_owner(9, 0);
    crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

    write_wal_text(
        &verthys_path,
        concat!(
            "{\"kind\":\"begin\",\"import_id\":\"imp-y\",\"ts\":1}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-y\",\"batch_id\":1,",
            "\"hash\":\"legacy\",\"verthys_id\":11,\"name\":\"a.jpg\"}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-y\",\"batch_id\":1,",
            "\"hash\":\"fresh\",\"verthys_id\":33,\"name\":\"b.jpg\",\"chunk_ids\":[7]}\n"
        ),
    );

    let outcome = settle_chunk_owners(&verthys_path).unwrap();
    assert_eq!(outcome.settled, 1, "块 7 的归属应被改写");
    assert_eq!(outcome.frozen, 1, "块 9 应被冻结");

    let reloaded = crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
    assert_eq!(reloaded.owner_of(7), Some(33));
    assert_eq!(
        reloaded.owner_of(9),
        Some(crate::repository::verthys_chunks::UNVERIFIABLE_OWNER)
    );
    assert!(reloaded.garbage_ids().is_empty(), "结算后不得再有回收候选");

    let again = settle_chunk_owners(&verthys_path).unwrap();
    assert!(!again.changed(), "重复结算应为无变更");
}

#[test]
fn test_settle_chunk_owners_failure_propagates() {
    // 台账落盘通道被占时结算必须失败，不得静默跳过
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
    ledger.set_owner(7, 0);
    crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

    write_wal_text(
        &verthys_path,
        concat!(
            "{\"kind\":\"begin\",\"import_id\":\"imp-z\",\"ts\":1}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-z\",\"batch_id\":1,",
            "\"hash\":\"fresh\",\"verthys_id\":44,\"name\":\"c.jpg\",\"chunk_ids\":[7]}\n"
        ),
    );

    let tmp_dir = ledger_tmp_path(&verthys_path);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    assert!(
        settle_chunk_owners(&verthys_path).is_err(),
        "落盘失败必须向上传播"
    );
    std::fs::remove_dir_all(&tmp_dir).unwrap();
}

#[test]
fn test_import_session_settles_before_wal_truncation() {
    // 建会话先结算并落盘，随后才截断 WAL；归属不会因截断而失去证明
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
    ledger.set_owner(7, 0);
    crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

    write_wal_text(
        &verthys_path,
        concat!(
            "{\"kind\":\"begin\",\"import_id\":\"imp-s1\",\"ts\":1}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-s1\",\"batch_id\":1,",
            "\"hash\":\"h\",\"verthys_id\":55,\"name\":\"d.jpg\",\"chunk_ids\":[7]}\n"
        ),
    );

    let session = ImportSession::new(&verthys_path, "imp-s2").unwrap();
    assert_eq!(session.chunk_ledger.owner_of(7), Some(55));
    drop(session);

    let reloaded = crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
    assert_eq!(reloaded.owner_of(7), Some(55), "结算结果必须落盘");
}

#[test]
fn test_import_session_refuses_when_settlement_persist_fails() {
    // 结算落盘失败时会话创建失败，且不得截断 WAL（归属声明不可丢）
    let dir = tempdir().unwrap();
    let verthys_path = make_verthys_path(dir.path());

    let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
    ledger.set_owner(7, 0);
    crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

    write_wal_text(
        &verthys_path,
        concat!(
            "{\"kind\":\"begin\",\"import_id\":\"imp-s3\",\"ts\":1}\n",
            "{\"kind\":\"committed\",\"import_id\":\"imp-s3\",\"batch_id\":1,",
            "\"hash\":\"h\",\"verthys_id\":66,\"name\":\"e.jpg\",\"chunk_ids\":[7]}\n"
        ),
    );

    let tmp_dir = ledger_tmp_path(&verthys_path);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    assert!(ImportSession::new(&verthys_path, "imp-s4").is_err());
    std::fs::remove_dir_all(&tmp_dir).unwrap();

    let wal_after = std::fs::read_to_string(wal_file(&verthys_path)).unwrap();
    assert!(
        wal_after.contains("imp-s3"),
        "会话创建失败时 WAL 必须保持原样（含归属声明）"
    );
}
