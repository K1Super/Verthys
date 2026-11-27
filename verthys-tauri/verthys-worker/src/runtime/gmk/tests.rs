/* 单元测试
 *
 * GMK 为 thread_local：cargo test 每个测试独占线程，
 * 各测试间的 GMK 状态互不干扰。
 */

use super::*;
use zeroize::Zeroizing;

use super::gmk_handlers::handle_change_global_key_with;
use super::gmk_material::{derive_gmk_material, verify_gmk_material};
use super::gmk_records::GmkRecordIo;
use super::gmk_state::{
    CODE_IO, CODE_NOTFOUND, GLOBAL_KEY_NAME, GLOBAL_KEY_RECORD_LEN, TYPE_GLOBAL_KEY,
};
use crate::runtime::protocol::{Request, base64_decode, base64_encode};

/// 构造派生/验证/子密钥测试请求（record 为 GMK 记录 base64）
fn make_request(op: &str, password: &str, bin_password: &str, bin_data: &[u8], record: &str) -> Request {
    Request {
        op: op.to_string(),
        path: String::new(),
        new_path: String::new(),
        keep_old: false,
        cancel_event: String::new(),
        keyfile_path: String::new(),
        mode: String::new(),
        target_op: String::new(),
        password: Zeroizing::new(password.to_string()),
        id: 0,
        rtype: 0,
        max_count: 0,
        name: String::new(),
        data: Zeroizing::new(record.to_string()),
        records: Vec::new(),
        staged_records: Vec::new(),
        old_password: Zeroizing::new(String::new()),
        new_password: Zeroizing::new(String::new()),
        bin_data: Zeroizing::new(base64_encode(bin_data)),
        bin_password: Zeroizing::new(bin_password.to_string()),
        new_bin_data: Zeroizing::new(String::new()),
        new_bin_password: Zeroizing::new(String::new()),
        preset: 0,
        ids: Vec::new(),
        flags: 0,
        uuids: Vec::new(),
        anchor_confirm: false,
        hb_handle: 0,
        shm_key: String::new(),
        project: String::new(),
        inline_max_bytes: 0,
        module_id: 0,
        pcr_select: 0,
        recovery_code: Zeroizing::new(String::new()),
        old_recovery: Zeroizing::new(String::new()),
        confirm: String::new(),
        module: String::new(),
        kind: String::new(),
        salt: String::new(),
        file_hash: String::new(),
        job_id: String::new(),
        meta_id: 0,
        paths: Vec::new(),
        committed_entry_keys: Vec::new(),
        chunk_ids: Vec::new(),
        format: String::new(),
        token: Zeroizing::new(String::new()),
        expected_hashes: Vec::new(),
        skip_photo: false,
        seq: 0,
        total: 0,
        iterations: 0,
        files: Vec::new(),
    }
}

#[test]
fn test_derive_verify_roundtrip() {
    let bin_data = b"test bin file content 0123456789abcdef";
    let record_bytes = derive_record("master-password-123", "bin-pass-456", bin_data);
    assert_eq!(record_bytes.len(), GLOBAL_KEY_RECORD_LEN);
    let record = base64_encode(&record_bytes);

    // 同参数验证必须通过（PRK 拷贝/清零重构后派生路径功能回归）
    let verify_req = make_request(
        "verify_global_key",
        "master-password-123",
        "bin-pass-456",
        bin_data,
        &record,
    );
    let verify_resp = handle_verify_global_key(&verify_req);
    assert!(verify_resp.ok, "同参数 verify 应通过: {:?}", verify_resp.error);
}

#[test]
fn test_verify_wrong_password_rejected() {
    let bin_data = b"another bin payload";
    let record = base64_encode(&derive_record("correct-horse-battery", "bin-pw", bin_data));

    let verify_req = make_request(
        "verify_global_key",
        "wrong-password",
        "bin-pw",
        bin_data,
        &record,
    );
    let verify_resp = handle_verify_global_key(&verify_req);
    assert!(!verify_resp.ok, "错误口令必须被拒绝");
}

#[test]
fn test_verify_record_from_other_derive_rejected() {
    // 不同派生产生的 record（随机 salt/nonce）解密必然失败 → AUTH
    let record_a = base64_encode(&derive_record("pw-a", "bin-a", b"bin-a-data"));
    let _record_b = derive_record("pw-b", "bin-b", b"bin-b-data");

    let verify_req = make_request(
        "verify_global_key", "pw-b", "bin-b", b"bin-b-data", &record_a,
    );
    let verify_resp = handle_verify_global_key(&verify_req);
    assert!(!verify_resp.ok, "跨派生的 record 必须验证失败");
}

/* ===== 改钥编排：以内存 fake 覆盖全部失败分支 ===== */

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};

fn derive_record(password: &str, bin_password: &str, bin: &[u8]) -> Vec<u8> {
    derive_gmk_material(password, &base64_encode(bin), bin_password, "test")
        .unwrap_or_else(|resp| panic!("测试派生应成功: {:?}", resp.error))
        .record
}

fn make_change_request(
    old_password: &str,
    old_bin_password: &str,
    old_bin: &[u8],
    new_password: &str,
    new_bin_password: &str,
    new_bin: &[u8],
) -> Request {
    let mut req = make_request("change_global_key", old_password, old_bin_password, old_bin, "");
    req.new_password = Zeroizing::new(new_password.to_string());
    req.new_bin_data = Zeroizing::new(base64_encode(new_bin));
    req.new_bin_password = Zeroizing::new(new_bin_password.to_string());
    req
}

/// 内存记录仓库：模拟 type 索引分页、读写与可控故障
struct FakeIo {
    records: RefCell<BTreeMap<u64, (u32, String, Vec<u8>)>>,
    next_id: RefCell<u64>,
    fail_add: bool,
    fail_delete: RefCell<HashSet<u64>>,
    corrupt_readback: bool,
    last_added: RefCell<Option<u64>>,
    /// false 模拟旧核心未导出 Verthys_ReplaceRecord → 走回退路径
    replace_supported: bool,
}

impl FakeIo {
    fn new() -> Self {
        Self {
            records: RefCell::new(BTreeMap::new()),
            next_id: RefCell::new(1),
            fail_add: false,
            fail_delete: RefCell::new(HashSet::new()),
            corrupt_readback: false,
            last_added: RefCell::new(None),
            replace_supported: true,
        }
    }

    fn insert(&self, id: u64, rtype: u32, name: &str, data: Vec<u8>) {
        self.records
            .borrow_mut()
            .insert(id, (rtype, name.to_string(), data));
        if id >= *self.next_id.borrow() {
            *self.next_id.borrow_mut() = id + 1;
        }
    }

    fn count(&self) -> usize {
        self.records.borrow().len()
    }

    fn has(&self, id: u64) -> bool {
        self.records.borrow().contains_key(&id)
    }
}

impl GmkRecordIo for FakeIo {
    fn list_ids_page(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
    ) -> Result<(Vec<u64>, bool), u32> {
        let records = self.records.borrow();
        let mut ids: Vec<u64> = records
            .iter()
            .filter(|(_, (t, _, _))| *t == rtype as u32)
            .map(|(id, _)| *id)
            .filter(|id| *id > after_id)
            .collect();
        ids.sort_unstable();
        let total = ids.len();
        ids.truncate(max_count as usize);
        let exhausted = ids.len() >= total;
        Ok((ids, exhausted))
    }

    fn get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32> {
        let records = self.records.borrow();
        match records.get(&id) {
            Some((rtype, name, data)) => {
                let mut data = data.clone();
                if self.corrupt_readback && *self.last_added.borrow() == Some(id) {
                    if let Some(first) = data.first_mut() {
                        *first ^= 0xFF;
                    }
                }
                Ok((*rtype, name.clone(), data))
            }
            None => Err(CODE_NOTFOUND),
        }
    }

    fn add_record(&self, rtype: u8, name: &str, data: &[u8]) -> Result<u64, u32> {
        if self.fail_add {
            return Err(CODE_IO);
        }
        let mut next = self.next_id.borrow_mut();
        let id = *next;
        *next += 1;
        self.records
            .borrow_mut()
            .insert(id, (rtype as u32, name.to_string(), data.to_vec()));
        *self.last_added.borrow_mut() = Some(id);
        Ok(id)
    }

    fn replace_record(
        &self,
        old_id: u64,
        rtype: u8,
        name: &str,
        data: &[u8],
    ) -> Result<u64, u32> {
        if !self.replace_supported {
            return Err(crate::runtime::ffi_types::VERTHYS_SYMBOL_UNSUPPORTED);
        }
        // 原子语义：任一失败都不得改变仓库
        if self.fail_add || self.fail_delete.borrow().contains(&old_id) {
            return Err(CODE_IO);
        }
        let mut records = self.records.borrow_mut();
        if !records.contains_key(&old_id) {
            return Err(CODE_NOTFOUND);
        }
        let mut next = self.next_id.borrow_mut();
        let id = *next;
        *next += 1;
        records.remove(&old_id);
        records.insert(id, (rtype as u32, name.to_string(), data.to_vec()));
        *self.last_added.borrow_mut() = Some(id);
        Ok(id)
    }

    fn delete_record(&self, id: u64) -> Result<(), u32> {
        if self.fail_delete.borrow().contains(&id) {
            return Err(CODE_IO);
        }
        if self.records.borrow_mut().remove(&id).is_some() {
            Ok(())
        } else {
            Err(CODE_NOTFOUND)
        }
    }
}

#[test]
fn test_change_global_key_success_replaces_record_and_swaps_gmk() {
    wipe_thread_gmk();
    let old_bin = b"old-bin-data";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let io = FakeIo::new();
    io.insert(5, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record.clone());
    // 无关记录：同名的账户记录、同类型的其他名称记录都不得被删除
    io.insert(6, 0x02, GLOBAL_KEY_NAME, vec![1, 2, 3]);
    io.insert(7, TYPE_GLOBAL_KEY as u32, "other", old_record);

    let req = make_change_request(
        "old-password-123",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin-data",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(resp.ok, "改钥应成功: {:?}", resp.error);
    assert_eq!(resp.cleanup_pending, Some(false));

    let new_record_b64 = resp.data.expect("应返回新记录");
    let new_record = base64_decode(&new_record_b64).expect("新记录应可解码");
    assert_eq!(new_record.len(), GLOBAL_KEY_RECORD_LEN);
    let new_id = resp.id.expect("应返回新 id");
    assert!(new_id > 7);

    // 旧记录删除；无关记录保留；新记录存在
    assert!(!io.has(5));
    assert!(io.has(6));
    assert!(io.has(7));
    assert!(io.has(new_id));

    // 旧钥对新记录验证失败，新钥通过
    assert!(verify_gmk_material(
        "old-password-123",
        &base64_encode(old_bin),
        "old-bin-pass",
        &new_record_b64,
        "test",
    )
    .is_err());
    let derived_new = verify_gmk_material(
        "new-password-456",
        &base64_encode(b"new-bin-data"),
        "new-bin-pass",
        &new_record_b64,
        "test",
    )
    .unwrap_or_else(|resp| panic!("新钥应通过: {:?}", resp.error));
    // 槽内 GMK 必须与新钥派生结果一致
    GMK.with(|g| {
        let slot = g.borrow();
        let stored = slot.as_ref().expect("槽应持有新 GMK");
        assert_eq!(&stored[..], &derived_new[..]);
    });
    wipe_thread_gmk();
}

#[test]
fn test_change_global_key_wrong_old_password_keeps_state() {
    wipe_thread_gmk();
    let old_bin = b"old-bin";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record);

    let req = make_change_request(
        "wrong-password",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000002"));
    assert_eq!(io.count(), 1);
    GMK.with(|g| assert!(g.borrow().is_none(), "失败不得写 GMK 槽"));
}

#[test]
fn test_change_global_key_add_failure_keeps_old() {
    wipe_thread_gmk();
    let old_bin = b"old-bin";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let mut io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record);
    io.fail_add = true;

    let req = make_change_request(
        "old-password-123",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000008"));
    assert!(io.has(1));
    GMK.with(|g| assert!(g.borrow().is_none()));
}

#[test]
fn test_change_global_key_atomic_replace_failure_keeps_old() {
    wipe_thread_gmk();
    let old_bin = b"old-bin";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record);
    // 原子替换整体失败：旧记录不得被墓碑，仓库保持单条旧记录
    io.fail_delete.borrow_mut().insert(1);

    let req = make_change_request(
        "old-password-123",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000008"));
    assert_eq!(io.count(), 1);
    assert!(io.has(1));
    GMK.with(|g| assert!(g.borrow().is_none(), "失败不得换槽"));
}

#[test]
fn test_change_global_key_fallback_delete_failure_sets_cleanup_pending() {
    wipe_thread_gmk();
    let old_bin = b"old-bin";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let mut io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record);
    // 模拟旧核心：无原子替换符号，回退写新/删旧；删旧失败仍视为成功
    io.replace_supported = false;
    io.fail_delete.borrow_mut().insert(1);

    let req = make_change_request(
        "old-password-123",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(resp.ok, "新记录已落盘即视为成功: {:?}", resp.error);
    assert_eq!(resp.cleanup_pending, Some(true));
    assert!(io.has(1), "删旧失败时旧记录保留，由下次解锁收敛");
    assert_eq!(io.count(), 2);
    GMK.with(|g| assert!(g.borrow().is_some(), "成功路径应换槽"));
    wipe_thread_gmk();
}

#[test]
fn test_change_global_key_atomic_readback_mismatch_fails_closed() {
    wipe_thread_gmk();
    let old_bin = b"old-bin";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let mut io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record);
    io.corrupt_readback = true;

    let req = make_change_request(
        "old-password-123",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000009"));
    // 原子替换已提交：旧记录已墓碑，仓库只剩新记录（读回异常）
    assert_eq!(io.count(), 1);
    assert!(!io.has(1));
    GMK.with(|g| assert!(g.borrow().is_none(), "读回异常不得换槽"));
}

#[test]
fn test_change_global_key_fallback_readback_mismatch_rolls_back_new() {
    wipe_thread_gmk();
    let old_bin = b"old-bin";
    let old_record = derive_record("old-password-123", "old-bin-pass", old_bin);
    let mut io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, old_record);
    io.replace_supported = false;
    io.corrupt_readback = true;

    let req = make_change_request(
        "old-password-123",
        "old-bin-pass",
        old_bin,
        "new-password-456",
        "new-bin-pass",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000009"));
    assert_eq!(io.count(), 1, "回退路径新记录应被回收");
    assert!(io.has(1));
    GMK.with(|g| assert!(g.borrow().is_none()));
}

#[test]
fn test_change_global_key_uses_latest_record_and_converges() {
    wipe_thread_gmk();
    let bin_a = b"bin-a";
    let bin_b = b"bin-b";
    let record_a = derive_record("pw-a-123456", "bp-a", bin_a);
    let record_b = derive_record("pw-b-123456", "bp-b", bin_b);
    let io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, record_a);
    io.insert(2, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, record_b);

    // 旧记录 A 的凭据不得通过（权威记录是最新的 B）
    let req_a = make_change_request(
        "pw-a-123456",
        "bp-a",
        bin_a,
        "new-password-456",
        "new-bp",
        b"new-bin",
    );
    let resp_a = handle_change_global_key_with(&req_a, &io);
    assert!(!resp_a.ok);
    assert_eq!(resp_a.error.as_deref(), Some("ERR_00000002"));

    // B 的凭据成功，且两条旧记录都被收敛删除
    let req_b = make_change_request(
        "pw-b-123456",
        "bp-b",
        bin_b,
        "new-password-456",
        "new-bp",
        b"new-bin",
    );
    let resp_b = handle_change_global_key_with(&req_b, &io);
    assert!(resp_b.ok, "最新记录凭据应成功: {:?}", resp_b.error);
    assert!(!io.has(1));
    assert!(!io.has(2));
    assert_eq!(io.count(), 1);
    wipe_thread_gmk();
}

#[test]
fn test_change_global_key_ignores_non_global_key_records() {
    wipe_thread_gmk();
    let bin = b"bin";
    let record = derive_record("pw-123456", "bp-123456", bin);
    let io = FakeIo::new();
    io.insert(1, TYPE_GLOBAL_KEY as u32, "account", record.clone());
    io.insert(2, TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, vec![0u8; 123]);
    io.insert(3, 0x02, GLOBAL_KEY_NAME, record);

    let req = make_change_request(
        "pw-123456",
        "bp-123456",
        bin,
        "new-password-456",
        "new-bp",
        b"new-bin",
    );
    let resp = handle_change_global_key_with(&req, &io);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("ERR_00000003"));
    assert_eq!(io.count(), 3, "非全局密钥记录不得被删除");
}
