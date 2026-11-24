/* gmk.rs — GMK 全局主密钥状态与派生命令
 *
 * 职责：
 *   - GMK thread_local 内存持有（Zeroizing 自动清零）
 *   - VERIFIER_PLAIN / VERIFIER_AD 常量
 *   - handle_derive_and_store_global_key / handle_verify_global_key
 *     / handle_change_global_key / handle_clear_global_key
 *
 * 依赖：std::cell::RefCell、zeroize、protocol（Request/Response/base64）。
 * 被引用方：dispatch.rs（handle_*）、worker.rs（GMK，Drop 时清零）。
 */

use std::cell::RefCell;
use zeroize::Zeroize;

use super::protocol::{Request, Response, base64_encode, base64_decode};
use crate::runtime::worker::Worker;

/* ------------------------------------------------------------------ *
 * GMK 全局主密钥状态（会话级，worker 内存中持有）                     *
 *                                                                    *
 * 设计：                                                             *
 *   - GMK 永不出 worker 子进程                                       *
 *   - 前端通过 IPC 请求派生子密钥                                    *
 *   - worker 退出（Drop）或 clear_global_key 时自动清零              *
 * ------------------------------------------------------------------ */

/// 验证器明文常量（32 字节，AES-GCM 加密后 = 48 字节含 tag）
/// 以版本标识 + 尾下划线补齐定长 32 字节
const VERIFIER_PLAIN: &[u8; 32] = b"VERTHYS_GLOBAL_KEY_VERIFIER_v2__";
/// 验证器 AES-GCM 附加数据
#[allow(dead_code)]
const VERIFIER_AD: &[u8] = b"VERTHYS_GLOBAL_VERIFIER_v1";

/* ------------------------------------------------------------------ *
 * 全局密钥记录契约                                                    *
 * ------------------------------------------------------------------ */

/// 全局密钥记录类型与名称（与前端 TYPE_GLOBAL_KEY / "global-key" 对齐）
const TYPE_GLOBAL_KEY: u8 = 0x10;
const GLOBAL_KEY_NAME: &str = "global-key";
/// 记录固定长度：salt(32) + nonce(12) + verifierCt(48) + binHash(32)
const GLOBAL_KEY_RECORD_LEN: usize = 124;
/// 类型索引分页大小（记录数极少，单页即可覆盖）
const GLOBAL_KEY_PAGE_SIZE: u64 = 64;
/// 候选记录上限：超过视为容器异常，拒绝改钥，避免无界遍历
const GLOBAL_KEY_MAX_CANDIDATES: usize = 256;

/// 本地错误码（与 verthys.h 对齐；避免跨模块常量耦合）
const CODE_OK: u32 = 0x00000000;
const CODE_AUTH: u32 = 0x00000002;
const CODE_NOTFOUND: u32 = 0x00000003;
#[cfg(test)]
const CODE_IO: u32 = 0x00000008;
const CODE_CORRUPT: u32 = 0x00000009;
const CODE_RESOURCE_LIMIT: u32 = 0x0000000F;

/// 派生结果：GMK 与待落盘记录（均未写入 thread_local 槽）
struct GmkMaterial {
    gmk: zeroize::Zeroizing<[u8; 32]>,
    record: Vec<u8>,
}

/// 写入 GMK 槽（唯一入口：派生/验证/改钥成功后调用）
fn store_gmk(gmk: zeroize::Zeroizing<[u8; 32]>) {
    GMK.with(|g| *g.borrow_mut() = Some(gmk));
}

thread_local! {
    /// GMK 内存持有（Zeroizing 保证清零）
    pub(crate) static GMK: RefCell<Option<zeroize::Zeroizing<[u8; 32]>>> = const { RefCell::new(None) };
}

/* ------------------------------------------------------------------ *
 * GMK 派生命令（敏感操作下沉）                                          *
 *                                                                    *
 * 所有密钥派生在 worker 子进程内完成，主进程/前端仅传递参数。          *
 * 任何响应都不得携带原始密钥字节：GMK 与派生密钥只以密文记录或          *
 * worker 内部状态存在。                                                *
 * ------------------------------------------------------------------ */

/// 派生全局主密钥 GMK（首次设置）
/// 输入：password + bin_data + bin_password
/// 输出：record(base64) = salt(32) + nonce(12) + verifierCt(48) + binHash(32)
/// 副作用：GMK 存入 thread_local 内存
/// 派生 GMK 核心：完整派生链（binKey → GMK → verifier → 124B record）。
/// 成功时 GMK 驻留 thread_local 并返回记录字节；失败返回已构造的
/// 错误响应（op 由调用方指定），GMK 不驻留。
/// derive_gmk_material 与 handle_derive_and_store_global_key / 改钥共用。
fn derive_gmk_material(
    password: &str,
    bin_data_b64: &str,
    bin_password: &str,
    op: &str,
) -> Result<GmkMaterial, Box<Response>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let bin_data = match base64_decode(bin_data_b64) {
        Ok(d) => d,
        Err(_) => {
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("base64 decode bin_data failed".into()),
                ..Response::ok(op)
            }))
        }
    };

    // 1. binMaterial = SHA-256(bin_data)
    let bin_material = Sha256::digest(&bin_data);

    // 2. binPasswordKey = PBKDF2(bin_password, salt=bin_material[:16], 150000)
    let mut bin_password_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        bin_password.as_bytes(),
        &bin_material[..16],
        150_000,
        &mut bin_password_key,
    );

    // 3. binKey = HKDF-Extract(salt=bin_material, IKM=bin_password_key)
    //    PRK 拷入 Zeroizing 后立即 volatile 清零 extract 输出缓冲
    let (mut bin_key_prk, _) = Hkdf::<Sha256>::extract(Some(&bin_material), &bin_password_key);
    let bin_key = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bin_key_prk[..]);
        arr
    });
    bin_key_prk[..].zeroize();

    // 4. globalSalt = random(32)
    let mut global_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut global_salt);

    // 5. IKM = password || binKey
    let pw_bytes = password.as_bytes();
    let mut ikm = Vec::with_capacity(pw_bytes.len() + bin_key.len());
    ikm.extend_from_slice(pw_bytes);
    ikm.extend_from_slice(&bin_key[..]);

    // 6. GMK = HKDF-Extract(salt=global_salt, IKM=password||binKey)
    //    PRK 处理同 binKey：拷入 Zeroizing 后立即清零中间量
    let (mut gmk_prk, _) = Hkdf::<Sha256>::extract(Some(&global_salt), &ikm);
    let gmk = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&gmk_prk[..]);
        arr
    });
    gmk_prk[..].zeroize();

    // 7. verifier: AES-GCM encrypt known constant
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&gmk[..]));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let verifier_ct = match cipher.encrypt(nonce, VERIFIER_PLAIN.as_ref()) {
        Ok(c) => c,
        Err(_) => {
            bin_password_key.zeroize();
            ikm.zeroize();
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("AES-GCM encrypt verifier failed".into()),
                ..Response::ok(op)
            }));
        }
    };

    // 8. binFileHash = SHA-256(bin_data)
    let bin_file_hash = Sha256::digest(&bin_data);

    // 9. 序列化 record: salt(32) + nonce(12) + verifierCt(48) + binHash(32) = 124B
    let mut record = Vec::with_capacity(32 + 12 + 48 + 32);
    record.extend_from_slice(&global_salt);
    record.extend_from_slice(&nonce_bytes);
    record.extend_from_slice(&verifier_ct);
    record.extend_from_slice(&bin_file_hash);

    // 10. 清零临时敏感变量（GMK 由调用方决定何时写入槽）
    bin_password_key.zeroize();
    ikm.zeroize();

    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk[..]);
    Ok(GmkMaterial {
        gmk: zeroize::Zeroizing::new(gmk_arr),
        record,
    })
}

/// 派生并持久化全局密钥（首次初始化专用，敏感操作下沉）
///
/// 时序：派生 GMK → 收敛残留 global-key 记录 → 写入新记录 →
/// 读回逐字节验证 → 成功后才写入 GMK 槽。任一失败都不触碰槽，
/// 避免"记录未落盘但内存已换钥"的中间态。
pub(crate) fn handle_derive_and_store_global_key(req: &Request, worker: &Worker) -> Response {
    use crate::runtime::ffi_types::VERTHYS_OK;

    let GmkMaterial { gmk, record } = match derive_gmk_material(
        req.password.as_str(),
        req.bin_data.as_str(),
        req.bin_password.as_str(),
        "derive_and_store_global_key",
    ) {
        Ok(m) => m,
        Err(resp) => return *resp,
    };
    let mut gmk_slot = Some(gmk);

    // 失败统一补偿：尽力回收半成品记录（GMK 未写槽，无需清理）
    let mut written_id: Option<u64> = None;
    let cleanup = |written: &mut Option<u64>| {
        if let Some(id) = written.take() {
            let _ = worker.call_delete_record(id);
        }
    };

    // 1. 收敛残留：历史中断可能遗留多条 global-key 记录，先清后写保证单条
    loop {
        let (rc, found, lid) = worker.call_find_first_lid_by_type(TYPE_GLOBAL_KEY);
        if rc != VERTHYS_OK {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", rc);
        }
        if !found {
            break;
        }
        let del_rc = worker.call_delete_record(lid);
        if del_rc != VERTHYS_OK {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", del_rc);
        }
    }

    // 2. 写入新记录（单调用原子写入）
    let id = match worker.call_add_record(TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, &record) {
        Ok(id) => id,
        Err(code) => {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", code);
        }
    };
    written_id = Some(id);

    // 3. 内容级读回验证：GetRecord 读回必须与写入逐字节一致
    match worker.call_get_record(id) {
        Ok((_rtype, _name, data)) if data == record => {
            // 4. 记录已确认落盘，才允许写 GMK 槽
            if let Some(gmk) = gmk_slot.take() {
                store_gmk(gmk);
            }
            Response {
                ok: true,
                op: "derive_and_store_global_key".into(),
                id: Some(id),
                data: Some(base64_encode(&record)),
                ..Response::ok("derive_and_store_global_key")
            }
        }
        Ok(_) => {
            cleanup(&mut written_id);
            Response::err_raw("derive_and_store_global_key", CODE_CORRUPT)
        }
        Err(code) => {
            cleanup(&mut written_id);
            Response::err_raw("derive_and_store_global_key", code)
        }
    }
}

/// 核验全局密钥三要素（不写 GMK 槽）
///
/// 返回派生出的 GMK 供调用方决定用途：verify 命令写入槽；
/// change 命令仅用于旧钥核验，用后立即 drop（Zeroizing）。
fn verify_gmk_material(
    password: &str,
    bin_data_b64: &str,
    bin_password: &str,
    record_b64: &str,
    op: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, Box<Response>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use sha2::{Digest, Sha256};

    let bin_data = match base64_decode(bin_data_b64) {
        Ok(d) => d,
        Err(_) => {
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("base64 decode bin_data failed".into()),
                ..Response::ok(op)
            }))
        }
    };
    let record = match base64_decode(record_b64) {
        Ok(d) => d,
        Err(_) => {
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("base64 decode record failed".into()),
                ..Response::ok(op)
            }))
        }
    };

    // 1. 解析 record: salt(32) + nonce(12) + verifierCt(48) + binHash(32) = 124B
    if record.len() != GLOBAL_KEY_RECORD_LEN {
        return Err(Box::new(Response::err(op, CODE_AUTH)));
    }
    let global_salt = &record[..32];
    let verifier_nonce = &record[32..44];
    let verifier_ct = &record[44..92];
    let bin_file_hash = &record[92..124];

    // 2. 校验 binFileHash
    let computed_hash = Sha256::digest(&bin_data);
    if computed_hash.as_slice() != bin_file_hash {
        return Err(Box::new(Response::err(op, CODE_AUTH)));
    }

    // 3. 派生 binKey + GMK
    let bin_material = Sha256::digest(&bin_data);
    let mut bin_password_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        bin_password.as_bytes(),
        &bin_material[..16],
        150_000,
        &mut bin_password_key,
    );
    // PRK 拷入 Zeroizing 后立即 volatile 清零 extract 输出缓冲
    let (mut bin_key_prk, _) = Hkdf::<Sha256>::extract(Some(&bin_material), &bin_password_key);
    let bin_key = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bin_key_prk[..]);
        arr
    });
    bin_key_prk[..].zeroize();

    let pw_bytes = password.as_bytes();
    let mut ikm = Vec::with_capacity(pw_bytes.len() + bin_key.len());
    ikm.extend_from_slice(pw_bytes);
    ikm.extend_from_slice(&bin_key[..]);

    // GMK 处理同 binKey：拷入 Zeroizing 后立即清零中间量
    let (mut gmk_prk, _) = Hkdf::<Sha256>::extract(Some(global_salt), &ikm);
    let gmk = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&gmk_prk[..]);
        arr
    });
    gmk_prk[..].zeroize();

    // 4. 解密 verifier
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&gmk[..]));
    let nonce = Nonce::from_slice(verifier_nonce);
    match cipher.decrypt(nonce, verifier_ct) {
        Ok(plain) => {
            if plain != VERIFIER_PLAIN.as_ref() {
                bin_password_key.zeroize();
                ikm.zeroize();
                return Err(Box::new(Response::err(op, CODE_AUTH)));
            }
        }
        Err(_) => {
            bin_password_key.zeroize();
            ikm.zeroize();
            return Err(Box::new(Response::err(op, CODE_AUTH)));
        }
    }

    // 5. 清零临时量，返回 GMK（由调用方决定何时入槽）
    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk[..]);
    bin_password_key.zeroize();
    ikm.zeroize();

    Ok(zeroize::Zeroizing::new(gmk_arr))
}

/// 验证全局密钥（后续进入时 / 中枢重认证）
/// 输入：password + bin_data + bin_password + record(base64)
/// 输出：ok=true 验证成功，GMK 存入内存
pub(crate) fn handle_verify_global_key(req: &Request) -> Response {
    match verify_gmk_material(
        req.password.as_str(),
        req.bin_data.as_str(),
        req.bin_password.as_str(),
        req.data.as_str(),
        "verify_global_key",
    ) {
        Ok(gmk) => {
            store_gmk(gmk);
            Response::ok("verify_global_key")
        }
        Err(resp) => *resp,
    }
}

/* ------------------------------------------------------------------ *
 * 改钥：记录 I/O 抽象与编排                                          *
 * ------------------------------------------------------------------ */

/// 全局密钥记录 I/O 抽象：真实实现走 Worker FFI，测试用内存 fake。
///
/// 把记录读写与 GMK 编排分离，使"旧钥错误 / 写失败 / 读回不一致 /
/// 删旧失败 / 成功换槽"等分支可在无 DLL 环境下被真实覆盖。
pub(crate) trait GmkRecordIo {
    fn list_ids_page(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
    ) -> Result<(Vec<u64>, bool), u32>;
    fn get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32>;
    fn add_record(&self, rtype: u8, name: &str, data: &[u8]) -> Result<u64, u32>;
    /// 原子替换（API 0x0017）；未导出时返回 VERTHYS_SYMBOL_UNSUPPORTED
    fn replace_record(
        &self,
        old_id: u64,
        rtype: u8,
        name: &str,
        data: &[u8],
    ) -> Result<u64, u32>;
    fn delete_record(&self, id: u64) -> Result<(), u32>;
}

struct WorkerRecordIo<'a>(&'a Worker);

impl GmkRecordIo for WorkerRecordIo<'_> {
    fn list_ids_page(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
    ) -> Result<(Vec<u64>, bool), u32> {
        let mut ids = vec![0u64; max_count as usize];
        let mut count = 0u64;
        let mut exhausted = 0u8;
        let rc = self.0.call_list_ids_by_type(
            rtype,
            after_id,
            max_count,
            &mut ids,
            &mut count,
            &mut exhausted,
        );
        if rc != CODE_OK {
            return Err(rc);
        }
        ids.truncate(count as usize);
        Ok((ids, exhausted != 0))
    }

    fn get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32> {
        self.0.call_get_record(id)
    }

    fn add_record(&self, rtype: u8, name: &str, data: &[u8]) -> Result<u64, u32> {
        self.0.call_add_record(rtype as u32, name, data)
    }

    fn replace_record(
        &self,
        old_id: u64,
        rtype: u8,
        name: &str,
        data: &[u8],
    ) -> Result<u64, u32> {
        self.0.call_replace_record(old_id, rtype as u32, name, data)
    }

    fn delete_record(&self, id: u64) -> Result<(), u32> {
        let rc = self.0.call_delete_record(id);
        if rc == CODE_OK {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

/// 分页枚举 type 索引中的全部 ID（升序；跳过墓碑）
fn list_all_global_key_ids(io: &dyn GmkRecordIo) -> Result<Vec<u64>, u32> {
    let mut all = Vec::new();
    let mut after = 0u64;
    loop {
        let (page, exhausted) = io.list_ids_page(TYPE_GLOBAL_KEY, after, GLOBAL_KEY_PAGE_SIZE)?;
        if page.is_empty() {
            break;
        }
        if let Some(&last) = page.last() {
            after = last;
        }
        all.extend(page);
        if all.len() > GLOBAL_KEY_MAX_CANDIDATES {
            return Err(CODE_RESOURCE_LIMIT);
        }
        if exhausted {
            break;
        }
    }
    Ok(all)
}

/// 解析全部有效全局密钥记录（type/name/长度三要素），按 id 升序返回
fn resolve_valid_global_key_records(
    io: &dyn GmkRecordIo,
) -> Result<Vec<(u64, Vec<u8>)>, u32> {
    let ids = list_all_global_key_ids(io)?;
    let mut out = Vec::new();
    for id in ids {
        match io.get_record(id) {
            Ok((rtype, name, data))
                if rtype == TYPE_GLOBAL_KEY as u32
                    && name == GLOBAL_KEY_NAME
                    && data.len() == GLOBAL_KEY_RECORD_LEN =>
            {
                out.push((id, data));
            }
            Ok(_) => {}
            Err(CODE_NOTFOUND) => {}
            Err(rc) => return Err(rc),
        }
    }
    out.sort_by_key(|(id, _)| *id);
    Ok(out)
}

/// 修改全局密钥（后端单命令的 worker 侧编排）
///
/// 顺序与失败语义（见记录不变量 R5/R6）：
///   1. 解析最新有效记录（max id）
///   2. 核验旧三要素（旧 GMK 仅内存，不入槽）
///   3. 派生新三要素（新 GMK 暂存，不入槽）
///   4. 写入新记录 + 逐字节读回
///   5. 删除旧记录与历史残留 + 读回确认
///   6. 成功后才把新 GMK 写入槽
///
/// 任何早于第 6 步的失败都不触碰 GMK 槽；删旧失败不判失败：新记录
/// 已是最新权威，残留由下次解锁收敛清除（cleanup_pending=true）。
pub(crate) fn handle_change_global_key(req: &Request, worker: &Worker) -> Response {
    handle_change_global_key_with(req, &WorkerRecordIo(worker))
}

fn handle_change_global_key_with(req: &Request, io: &dyn GmkRecordIo) -> Response {
    // 1. 解析权威记录：最新有效记录（max id）
    let records = match resolve_valid_global_key_records(io) {
        Ok(r) => r,
        Err(rc) => return Response::err_raw("change_global_key", rc),
    };
    let (old_id, old_record) = match records.last() {
        Some((id, data)) => (*id, data.clone()),
        None => return Response::err("change_global_key", CODE_NOTFOUND),
    };

    // 2. 核验旧三要素（旧 GMK 仅用于解密验证，不写槽）
    let old_record_b64 = base64_encode(&old_record);
    match verify_gmk_material(
        req.password.as_str(),
        req.bin_data.as_str(),
        req.bin_password.as_str(),
        &old_record_b64,
        "change_global_key",
    ) {
        Ok(old_gmk) => drop(old_gmk),
        Err(resp) => return *resp,
    }

    // 3. 派生新三要素（新 GMK 暂存，不写槽）
    let GmkMaterial {
        gmk: new_gmk,
        record: new_record,
    } = match derive_gmk_material(
        req.new_password.as_str(),
        req.new_bin_data.as_str(),
        req.new_bin_password.as_str(),
        "change_global_key",
    ) {
        Ok(m) => m,
        Err(resp) => return *resp,
    };

    // 4. 提交新记录：
    //    - 核心支持原子替换（API 0x0017）→ 单次事务内"写新 + 墓碑旧"，
    //      崩溃不会出现两条并存；
    //    - 旧核心未导出该符号 → 回退"写新 + 读回 + 删旧"（下方收敛处理旧记录）。
    //    原子路径读回不一致属于提交后完整性异常：旧记录已墓碑，不能再
    //    回滚，返回 CORRUPT 且不换槽（fail-closed，等待完整性巡检介入）。
    let new_id = match io.replace_record(old_id, TYPE_GLOBAL_KEY, GLOBAL_KEY_NAME, &new_record) {
        Ok(id) => {
            if id <= old_id {
                return Response::err_raw("change_global_key", CODE_CORRUPT);
            }
            match io.get_record(id) {
                Ok((rtype, name, data))
                    if rtype == TYPE_GLOBAL_KEY as u32
                        && name == GLOBAL_KEY_NAME
                        && data == new_record => {}
                _ => return Response::err_raw("change_global_key", CODE_CORRUPT),
            }
            id
        }
        Err(rc) if rc == crate::runtime::ffi_types::VERTHYS_SYMBOL_UNSUPPORTED => {
            // 兼容旧核心：写新 + 读回；失败回收新记录，旧记录与旧 GMK 保持不变
            let id = match io.add_record(TYPE_GLOBAL_KEY, GLOBAL_KEY_NAME, &new_record) {
                Ok(id) => id,
                Err(rc) => return Response::err_raw("change_global_key", rc),
            };
            if id <= old_id {
                let _ = io.delete_record(id);
                return Response::err_raw("change_global_key", CODE_CORRUPT);
            }
            match io.get_record(id) {
                Ok((rtype, name, data))
                    if rtype == TYPE_GLOBAL_KEY as u32
                        && name == GLOBAL_KEY_NAME
                        && data == new_record => {}
                Ok(_) => {
                    let _ = io.delete_record(id);
                    return Response::err_raw("change_global_key", CODE_CORRUPT);
                }
                Err(rc) => {
                    let _ = io.delete_record(id);
                    return Response::err_raw("change_global_key", rc);
                }
            }
            id
        }
        Err(rc) => return Response::err_raw("change_global_key", rc),
    };

    // 5. 删除旧记录与历史残留：新记录已落盘，清理失败不再判失败——
    //    最新记录为权威，残留由下次解锁收敛清除。
    //    原子替换已墓碑旧记录，此处的 NOTFOUND 视为"已删除"。
    let mut deleted = Vec::new();
    let mut cleanup_pending = false;
    for (id, _) in records.iter() {
        if *id == new_id {
            continue;
        }
        match io.delete_record(*id) {
            Ok(()) => match io.get_record(*id) {
                Err(CODE_NOTFOUND) => deleted.push(*id),
                _ => cleanup_pending = true,
            },
            Err(CODE_NOTFOUND) => deleted.push(*id),
            Err(_) => cleanup_pending = true,
        }
    }

    // 7. 新记录确认落盘后才换槽
    store_gmk(new_gmk);

    let mut resp = Response::ok("change_global_key");
    resp.id = Some(new_id);
    resp.data = Some(base64_encode(&new_record));
    resp.ids = deleted;
    resp.cleanup_pending = Some(cleanup_pending);
    resp
}

/// 清零 GMK 内存（lockAll 时调用）
pub(crate) fn handle_clear_global_key() -> Response {
    GMK.with(|g| *g.borrow_mut() = None);
    Response::ok("clear_global_key")
}

/// panic 清零器：清除当前线程 GMK TLS 驻留。
/// Zeroizing 的 Drop 在正常展开时同样会清零，此处为 panic hook 内
/// 的显式前置清零——hook 早于栈展开执行，清零先于任何诊断/转储输出。
pub(crate) fn wipe_thread_gmk() {
    GMK.with(|g| *g.borrow_mut() = None);
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 *                                                                    *
 * GMK 为 thread_local：cargo test 每个测试独占线程，                *
 * 各测试间的 GMK 状态互不干扰。                                       *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

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
            uuid: String::new(),
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
}
