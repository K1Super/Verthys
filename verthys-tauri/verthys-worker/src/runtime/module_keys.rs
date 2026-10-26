/* module_keys.rs — 模块密钥托管与内容加解密操作
 *
 * 职责边界：持有本进程内的模块密钥与按盐派生缓存；对外只暴露
 * “模块名 + 公开参数/包裹密钥 + 密文”形态的操作。原始模块密钥、
 * 派生密钥与解封后的文件密钥都不进入请求/响应载荷，也不写日志。
 *
 * 无句柄设计：所有文件密钥在使用点由包裹态密钥一次性解封并立即丢弃。
 * 句柄表需要随文件数量增长并依赖调用方释放，长批量导入会耗尽容量；
 * 解封成本被按盐派生缓存吸收（每文件一次 PBKDF2），逐块只做一次
 * XChaCha 解封，代价可忽略，换来无容量上限与无释放时序缺陷。
 *
 * 生命周期约束：库锁定、进程退出、panic 三类事件必须清空全部模块密钥
 * 与派生缓存。并发：worker 主循环单线程消费请求，状态放 thread_local；
 * 若未来改为多线程消费，必须替换为带锁结构并保持同一清零语义。
 */

use std::cell::RefCell;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::budget::PB_IPC_MAX_PAYLOAD_BYTES;
use super::content_crypto::{
    self, VencError, CHUNK_SET_AD, FILE_HASH_LEN, KEY_LEN, NONCE_LEN, PBKDF2_ITER, SALT_LEN,
    THUMB_AD, V2_IV_LEN, V2_MAX_ITERATIONS, V2_MIN_ITERATIONS,
};
use super::protocol::{base64_decode, base64_encode, Request, Response};

/// 单次内容载荷的 base64 字符上限（跨层预算常量为字符口径）
const MAX_PAYLOAD_CHARS: usize = PB_IPC_MAX_PAYLOAD_BYTES as usize;
/// 与字符上限对应的解码后字节上限（base64 每 4 字符解出 3 字节）
const MAX_PAYLOAD_DECODED_BYTES: usize = MAX_PAYLOAD_CHARS / 4 * 3;

/// 派生缓存容量：覆盖一次相册翻页的活跃文件，同时限制密钥常驻面
const CACHE_CAPACITY: usize = 8;
/// 模块密钥长度上限：模块口令是短文本，超长输入按非法处理
const MAX_MODULE_SECRET_BYTES: usize = 4096;

/* ------------------------------------------------------------------ *
 * 模块与派生方式                                                      *
 * ------------------------------------------------------------------ */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleId {
    Photo,
    File,
}

impl ModuleId {
    fn parse(text: &str) -> Result<Self, VencError> {
        match text {
            "photo" => Ok(Self::Photo),
            "file" => Ok(Self::File),
            _ => Err(VencError::Invalid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Derivation {
    /// 照片：PBKDF2 主密钥 → HKDF 文件子密钥（包裹密钥）
    PhotoFileKey,
    /// 文件块 v2：PBKDF2 直接作为 AES-256-GCM 密钥
    V2Raw,
}

/* ------------------------------------------------------------------ *
 * 会话状态                                                            *
 * ------------------------------------------------------------------ */

struct CacheEntry {
    module: ModuleId,
    salt: [u8; SALT_LEN],
    derivation: Derivation,
    iterations: u32,
    /// 文件块 v2 的口令指纹；照片派生为 None
    fingerprint: Option<[u8; 32]>,
    key: Zeroizing<[u8; KEY_LEN]>,
}

struct Session {
    photo_secret: Option<Zeroizing<Vec<u8>>>,
    file_secret: Option<Zeroizing<Vec<u8>>>,
    cache: Vec<CacheEntry>,
}

impl Session {
    const fn new() -> Self {
        Self {
            photo_secret: None,
            file_secret: None,
            cache: Vec::new(),
        }
    }

    fn clear_module(&mut self, module: ModuleId) {
        match module {
            ModuleId::Photo => self.photo_secret = None,
            ModuleId::File => self.file_secret = None,
        }
        self.cache.retain(|entry| entry.module != module);
    }

    fn clear_all(&mut self) {
        self.photo_secret = None;
        self.file_secret = None;
        self.cache.clear();
    }

    fn set_secret(&mut self, module: ModuleId, secret: Vec<u8>) {
        /* 旧密钥与旧缓存必须同时失效：否则换口令后仍可能用旧派生密钥
         * 解新数据。 */
        self.clear_module(module);
        let secret = Zeroizing::new(secret);
        match module {
            ModuleId::Photo => self.photo_secret = Some(secret),
            ModuleId::File => self.file_secret = Some(secret),
        }
    }

    fn derive(
        &mut self,
        module: ModuleId,
        salt: &[u8; SALT_LEN],
        derivation: Derivation,
        iterations: u32,
        password: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
        /* 文件块 v2 的密钥由文件口令派生而非模块密钥；缓存必须按口令指纹区分，
         * 否则同一盐下的不同文件口令会命中彼此的派生结果。 */
        let fingerprint = match derivation {
            Derivation::V2Raw => {
                let password = password.ok_or(VencError::Invalid)?;
                if password.is_empty() {
                    return Err(VencError::Invalid);
                }
                Some(password_fingerprint(salt, iterations, password))
            }
            Derivation::PhotoFileKey => None,
        };

        if let Some(pos) = self.cache.iter().position(|e| {
            e.module == module
                && e.salt == *salt
                && e.derivation == derivation
                && e.iterations == iterations
                && e.fingerprint == fingerprint
        }) {
            let entry = self.cache.remove(pos);
            let key = entry.key.clone();
            self.cache.insert(0, entry);
            return Ok(key);
        }

        let key = match derivation {
            Derivation::PhotoFileKey => {
                let secret = match module {
                    ModuleId::Photo => self.photo_secret.as_ref(),
                    ModuleId::File => self.file_secret.as_ref(),
                }
                .ok_or(VencError::Locked)?;
                let master = content_crypto::derive_master_key(secret, salt, PBKDF2_ITER)?;
                content_crypto::derive_file_key(&master, salt)?
            }
            Derivation::V2Raw => {
                if !(V2_MIN_ITERATIONS..=V2_MAX_ITERATIONS).contains(&iterations) {
                    return Err(VencError::Invalid);
                }
                let password = password.ok_or(VencError::Invalid)?;
                content_crypto::derive_master_key(password, salt, iterations)?
            }
        };

        if self.cache.len() >= CACHE_CAPACITY {
            /* 容量满时淘汰最久未用项；被淘汰条目的 Zeroizing 字段即时清零。 */
            self.cache.pop();
        }
        self.cache.insert(
            0,
            CacheEntry {
                module,
                salt: *salt,
                derivation,
                iterations,
                fingerprint,
                key: key.clone(),
            },
        );
        Ok(key)
    }
}

/// 口令指纹：盐、迭代次数与口令的 SHA-256，仅用于缓存索引，不可逆。
fn password_fingerprint(
    salt: &[u8; SALT_LEN],
    iterations: u32,
    password: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"VERTHYS-V2-PW\0");
    hasher.update(salt);
    hasher.update(iterations.to_be_bytes());
    hasher.update(password);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

thread_local! {
    static SESSION: RefCell<Session> = const { RefCell::new(Session::new()) };
}

fn with_session<R>(f: impl FnOnce(&mut Session) -> R) -> R {
    SESSION.with(|cell| f(&mut cell.borrow_mut()))
}

/// 栈区残留擦除。
///
/// Why：AEAD/KDF 第三方实现会在自己的调用帧里构造含密钥的临时结构
/// （AES 轮密钥、HMAC 键控状态等），这些结构没有清零接口；返回值与
/// 移动语义还可能留下源槽位副本。每次内容操作返回后，以零初始化的
/// 大缓冲占用同一深度的栈区，覆盖刚返回帧的残留。属于纵深防御：
/// 语言层无法保证栈槽位一定被覆盖，但可消除转储中最常见的残留位置。
#[inline(never)]
fn scrub_stack() {
    const SCRUB_BYTES: usize = 32 * 1024;
    let mut scratch = [0u8; SCRUB_BYTES];
    /* black_box 阻止编译器把未使用的全零数组优化掉；数组本身在帧内
     * 占位即完成覆盖，无需再次清零。 */
    std::hint::black_box(&mut scratch);
}

/* ------------------------------------------------------------------ *
 * 对外生命周期接口                                                    *
 * ------------------------------------------------------------------ */

/// 清空全部模块密钥与派生缓存。
///
/// 库锁定与进程退出必须调用；调用后任何加密操作返回 Locked。
pub(crate) fn lock_all() {
    with_session(|session| session.clear_all());
}

/// panic 钩子使用的清零入口；与 lock_all 同义，单独命名以表达触发场景。
pub(crate) fn wipe_thread_keys() {
    lock_all();
}

/* ------------------------------------------------------------------ *
 * 操作实现                                                            *
 * ------------------------------------------------------------------ */

pub(crate) fn handle_key_unlock(req: &Request) -> Response {
    let result = (|| -> Result<(), VencError> {
        let module = ModuleId::parse(&req.module)?;
        let secret = req.password.as_bytes();
        if secret.is_empty() || secret.len() > MAX_MODULE_SECRET_BYTES {
            return Err(VencError::Invalid);
        }
        /* 模块口令的正确性由宿主在模块解锁链路中判定；此处只做保管，
         * 不引入可被离线猜测的校验块，避免多一个口令验证预言机。 */
        with_session(|session| session.set_secret(module, secret.to_vec()));
        Ok(())
    })();
    result.map_or_else(|e| fail("module_key_unlock", e), |_| Response::ok("module_key_unlock"))
}

pub(crate) fn handle_key_lock(req: &Request) -> Response {
    let result = (|| -> Result<(), VencError> {
        if req.module.is_empty() {
            lock_all();
            return Ok(());
        }
        let module = ModuleId::parse(&req.module)?;
        with_session(|session| session.clear_module(module));
        Ok(())
    })();
    result.map_or_else(|e| fail("module_key_lock", e), |_| Response::ok("module_key_lock"))
}

pub(crate) fn handle_seal(req: &Request) -> Response {
    let resp = match seal_inner(req) {
        Ok(out) => {
            let mut resp = Response::ok("module_seal");
            resp.data = Some(base64_encode(&out));
            resp
        }
        Err(e) => fail("module_seal", e),
    };
    scrub_stack();
    resp
}

pub(crate) fn handle_open(req: &Request) -> Response {
    let resp = match open_inner(req) {
        Ok((plaintext, seq_total)) => {
            let mut resp = Response::ok("module_open");
            /* v2_check 只返回判定结果，空明文不写入 data，避免调用方把
             * “校验通过”误判为“解出空内容”。 */
            if !plaintext.is_empty() {
                resp.data = Some(base64_encode(&plaintext));
            }
            if let Some((seq, total)) = seq_total {
                resp.seq = Some(seq);
                resp.total = Some(total);
            }
            resp
        }
        Err(e) => fail("module_open", e),
    };
    scrub_stack();
    resp
}

/// 文件级密钥操作：只返回可落盘的公开参数与包裹态密钥。
pub(crate) fn handle_file_key(req: &Request) -> Response {
    let resp = match file_key_inner(req) {
        Ok(resp) => resp,
        Err(e) => fail("module_file_key", e),
    };
    scrub_stack();
    resp
}

fn file_key_inner(req: &Request) -> Result<Response, VencError> {
    let module = ModuleId::parse(&req.module)?;
    match req.kind.as_str() {
        "slim_create" => {
            let salt: [u8; SALT_LEN] = content_crypto::random_bytes()?;
            let nonce: [u8; NONCE_LEN] = content_crypto::random_bytes()?;
            let wrap_key = with_session(|session| {
                session.derive(module, &salt, Derivation::PhotoFileKey, PBKDF2_ITER, None)
            })?;
            let file_key = Zeroizing::new(content_crypto::random_bytes::<KEY_LEN>()?);
            let wrapped =
                content_crypto::seal_wrapped_file_key(&wrap_key[..], &salt, &nonce, &file_key)?;
            let mut resp = Response::ok("module_file_key");
            resp.salt = Some(base64_encode(&salt));
            resp.wrapped_key = Some(base64_encode(&wrapped));
            Ok(resp)
        }
        /* 文件块 v2 不需要服务端句柄：盐与迭代次数是公开参数，调用方在
         * 每次加解密时随请求携带，派生结果由缓存命中。 */
        _ => Err(VencError::Invalid),
    }
}

fn seal_inner(req: &Request) -> Result<Vec<u8>, VencError> {
    let module = ModuleId::parse(&req.module)?;
    let kind = req.kind.as_str();
    /* v2_check 的输入是固定明文，不接收调用方数据；其余布局必须携带
     * 非空明文，避免把“空记录”写盘后无法区分读取失败与零长度。 */
    let plaintext = if kind == "v2_check" {
        Zeroizing::new(Vec::new())
    } else {
        let payload = decode_payload(&req.data)?;
        if payload.is_empty() {
            return Err(VencError::Invalid);
        }
        payload
    };

    match kind {
        "meta" => {
            let salt = optional_salt(&req.salt)?;
            let nonce: [u8; NONCE_LEN] = content_crypto::random_bytes()?;
            let key = derive_photo_key(module, &salt)?;
            content_crypto::seal_meta(&key[..], &salt, &nonce, &plaintext)
        }
        "chunk" => {
            let salt = optional_salt(&req.salt)?;
            let nonce: [u8; NONCE_LEN] = content_crypto::random_bytes()?;
            let hash = required_hash(&req.file_hash)?;
            validate_position(req.seq, req.total)?;
            let key = derive_photo_key(module, &salt)?;
            content_crypto::seal_chunk(
                &key[..], &salt, &nonce, req.seq, req.total, &hash, &plaintext,
            )
        }
        "slim_meta" => {
            let salt = required_salt(&req.salt)?;
            let nonce: [u8; NONCE_LEN] = content_crypto::random_bytes()?;
            let key = derive_photo_key(module, &salt)?;
            content_crypto::seal_slim_meta(&key[..], &salt, &nonce, &plaintext)
        }
        "slim_chunk" => {
            let hash = required_hash(&req.file_hash)?;
            validate_position(req.seq, req.total)?;
            let file_key = resolve_slim_file_key(module, &req.wrapped_key)?;
            let nonce: [u8; NONCE_LEN] = content_crypto::random_bytes()?;
            content_crypto::seal_slim_chunk(
                &file_key[..], &nonce, req.seq, req.total, &hash, &plaintext,
            )
        }
        "thumb" | "chunkset" => {
            let hash = required_hash(&req.file_hash)?;
            let prefix = if kind == "thumb" { THUMB_AD } else { CHUNK_SET_AD };
            let wrap_key = resolve_wrap_key(module, &req.wrapped_key)?;
            let nonce: [u8; NONCE_LEN] = content_crypto::random_bytes()?;
            content_crypto::seal_bound_record(&wrap_key[..], &nonce, prefix, &hash, &plaintext)
        }
        "v2_chunk" => {
            let iv: [u8; V2_IV_LEN] = content_crypto::random_bytes()?;
            let key = derive_v2_key(module, req)?;
            content_crypto::seal_v2_chunk(&key[..], &iv, &plaintext)
        }
        "v2_check" => {
            let iv: [u8; V2_IV_LEN] = content_crypto::random_bytes()?;
            let key = derive_v2_key(module, req)?;
            content_crypto::build_v2_check(&key[..], &iv)
        }
        _ => Err(VencError::Invalid),
    }
}

/// 解密产物：明文，以及记录型块密文内嵌的 (seq, total)。
type OpenedRecord = (Zeroizing<Vec<u8>>, Option<(u32, u32)>);

fn open_inner(req: &Request) -> Result<OpenedRecord, VencError> {
    let module = ModuleId::parse(&req.module)?;
    let combined = decode_payload(&req.data)?;
    if combined.is_empty() {
        return Err(VencError::Invalid);
    }
    let kind = req.kind.as_str();

    match kind {
        "meta" => {
            let salt = content_crypto::extract_meta_salt(&combined)?;
            let key = derive_photo_key(module, &salt)?;
            Ok((content_crypto::open_meta(&key[..], &combined)?, None))
        }
        "chunk" => {
            let salt = content_crypto::extract_meta_salt(&combined)?;
            let hash = required_hash(&req.file_hash)?;
            let key = derive_photo_key(module, &salt)?;
            let (seq, total, plaintext) = content_crypto::open_chunk(&key[..], &combined, &hash)?;
            Ok((plaintext, Some((seq, total))))
        }
        "slim_meta" => {
            let salt = content_crypto::extract_meta_salt(&combined)?;
            let key = derive_photo_key(module, &salt)?;
            Ok((content_crypto::open_slim_meta(&key[..], &combined)?, None))
        }
        "slim_chunk" => {
            let hash = required_hash(&req.file_hash)?;
            validate_position(req.seq, req.total)?;
            let file_key = resolve_slim_file_key(module, &req.wrapped_key)?;
            Ok((
                content_crypto::open_slim_chunk(
                    &file_key[..], &combined, req.seq, req.total, &hash,
                )?,
                None,
            ))
        }
        "thumb" | "chunkset" => {
            let hash = required_hash(&req.file_hash)?;
            let prefix = if kind == "thumb" { THUMB_AD } else { CHUNK_SET_AD };
            let wrap_key = resolve_wrap_key(module, &req.wrapped_key)?;
            Ok((
                content_crypto::open_bound_record(&wrap_key[..], &combined, prefix, &hash)?,
                None,
            ))
        }
        "v2_chunk" => {
            let key = derive_v2_key(module, req)?;
            Ok((content_crypto::open_v2_chunk(&key[..], &combined)?, None))
        }
        "v2_check" => {
            let key = derive_v2_key(module, req)?;
            if !content_crypto::verify_v2_check(&key[..], &combined)? {
                return Err(VencError::Auth);
            }
            Ok((Zeroizing::new(Vec::new()), None))
        }
        _ => Err(VencError::Invalid),
    }
}

/* ------------------------------------------------------------------ *
 * 密钥解析辅助                                                        *
 * ------------------------------------------------------------------ */

fn derive_photo_key(
    module: ModuleId,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    with_session(|session| {
        session.derive(module, salt, Derivation::PhotoFileKey, PBKDF2_ITER, None)
    })
}

/// 由包裹态文件密钥解出块级文件密钥；解封结果只在本函数调用期内驻留。
fn resolve_slim_file_key(
    module: ModuleId,
    wrapped_b64: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    let wrapped = decode_wrapped(wrapped_b64)?;
    let salt = content_crypto::extract_wrapped_salt(&wrapped)?;
    let wrap_key = derive_photo_key(module, &salt)?;
    content_crypto::open_wrapped_file_key(&wrap_key[..], &wrapped)
}

/// 由包裹态文件密钥的盐派生记录级包裹密钥（缩略图 / 块集）。
fn resolve_wrap_key(
    module: ModuleId,
    wrapped_b64: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    let wrapped = decode_wrapped(wrapped_b64)?;
    let salt = content_crypto::extract_wrapped_salt(&wrapped)?;
    derive_photo_key(module, &salt)
}

fn derive_v2_key(
    module: ModuleId,
    req: &Request,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    let salt = required_salt(&req.salt)?;
    let iterations = if req.iterations == 0 {
        PBKDF2_ITER
    } else {
        req.iterations
    };
    let password = req.password.as_bytes();
    if password.is_empty() || password.len() > MAX_MODULE_SECRET_BYTES {
        return Err(VencError::Invalid);
    }
    with_session(|session| {
        session.derive(module, &salt, Derivation::V2Raw, iterations, Some(password))
    })
}

/* ------------------------------------------------------------------ *
 * 入参辅助                                                            *
 * ------------------------------------------------------------------ */

fn decode_payload(text: &str) -> Result<Zeroizing<Vec<u8>>, VencError> {
    /* 字符数先于解码校验：解码后字节上限可由字符上限精确推算，
     * 避免超预算请求在解码阶段产生大块临时分配。 */
    if text.len() > MAX_PAYLOAD_CHARS {
        return Err(VencError::Invalid);
    }
    let bytes = decode_b64(text)?;
    if bytes.len() > MAX_PAYLOAD_DECODED_BYTES {
        return Err(VencError::Invalid);
    }
    Ok(Zeroizing::new(bytes))
}

fn decode_wrapped(text: &str) -> Result<Vec<u8>, VencError> {
    if text.len() > MAX_PAYLOAD_CHARS {
        return Err(VencError::Invalid);
    }
    let bytes = decode_b64(text)?;
    if bytes.len() > MAX_PAYLOAD_DECODED_BYTES {
        return Err(VencError::Invalid);
    }
    Ok(bytes)
}

fn decode_b64(text: &str) -> Result<Vec<u8>, VencError> {
    if text.is_empty() {
        return Err(VencError::Invalid);
    }
    base64_decode(text).map_err(|_| VencError::Invalid)
}

fn optional_salt(text: &str) -> Result<[u8; SALT_LEN], VencError> {
    if text.is_empty() {
        return content_crypto::random_bytes();
    }
    required_salt(text)
}

fn required_salt(text: &str) -> Result<[u8; SALT_LEN], VencError> {
    let bytes = decode_b64(text)?;
    if bytes.len() != SALT_LEN {
        return Err(VencError::Invalid);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes);
    Ok(salt)
}

fn required_hash(text: &str) -> Result<[u8; FILE_HASH_LEN], VencError> {
    if text.is_empty() {
        return Err(VencError::Invalid);
    }
    content_crypto::parse_hash_hex(text)
}

fn validate_position(seq: u32, total: u32) -> Result<(), VencError> {
    if total == 0 || seq >= total {
        return Err(VencError::Invalid);
    }
    Ok(())
}

fn fail(op: &str, err: VencError) -> Response {
    let code = match err {
        VencError::Invalid => 0x01,
        VencError::Locked => 0x07,
        /* Auth / Corrupt / Internal 一律映射为 AUTH：对外不可区分
         * 口令错误、数据篡改与内部异常。 */
        _ => 0x02,
    };
    Response::err(op, code)
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: serde_json::Value) -> Request {
        serde_json::from_value(value).expect("测试请求必须可反序列化")
    }

    fn unlocked(module: &str, secret: &str) {
        let resp = handle_key_unlock(&request(serde_json::json!({
            "op": "module_key_unlock",
            "module": module,
            "password": secret,
        })));
        assert!(resp.ok, "模块解锁失败: {:?}", resp.error);
    }

    fn data_of(resp: &Response) -> Vec<u8> {
        base64_decode(resp.data.as_deref().expect("响应缺少 data")).expect("data 必须是 base64")
    }

    fn hash_of(data: &[u8]) -> String {
        content_crypto::hex_encode(&content_crypto::file_hash(data).expect("哈希输入非空"))
    }

    #[test]
    fn unlock_required_and_lock_clears() {
        lock_all();
        let resp = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "meta", "data": "YWJj",
        })));
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("ERR_00000007"));

        unlocked("photo", "photo-pass");
        let ok = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "meta", "data": "YWJj",
        })));
        assert!(ok.ok);

        let locked = handle_key_lock(&request(serde_json::json!({
            "op": "module_key_lock", "module": "photo",
        })));
        assert!(locked.ok);
        let after = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "meta", "data": "YWJj",
        })));
        assert_eq!(after.error.as_deref(), Some("ERR_00000007"));
        lock_all();
    }

    #[test]
    fn meta_roundtrip_and_salt_binding() {
        lock_all();
        unlocked("photo", "module-secret");
        let sealed = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "meta",
            "data": base64_encode(b"{\"name\":\"a.jpg\"}"),
        })));
        assert!(sealed.ok);
        let cipher = data_of(&sealed);

        let opened = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "meta",
            "data": base64_encode(&cipher),
        })));
        assert!(opened.ok);
        assert_eq!(data_of(&opened), b"{\"name\":\"a.jpg\"}");

        // 篡改必须认证失败，且错误码不区分篡改与口令错误
        let mut tampered = cipher.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let bad = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "meta",
            "data": base64_encode(&tampered),
        })));
        assert_eq!(bad.error.as_deref(), Some("ERR_00000002"));
        lock_all();
    }

    #[test]
    fn chunk_roundtrip_binds_position_and_hash() {
        lock_all();
        unlocked("photo", "module-secret");
        let hash = hash_of(b"chunk");
        let sealed = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "chunk",
            "data": base64_encode(b"chunk"), "seq": 1, "total": 3, "file_hash": hash,
        })));
        assert!(sealed.ok);

        let opened = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "chunk",
            "data": sealed.data, "file_hash": hash,
        })));
        assert!(opened.ok);
        assert_eq!((opened.seq, opened.total), (Some(1), Some(3)));
        assert_eq!(data_of(&opened), b"chunk");

        let bad = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "chunk",
            "data": sealed.data, "file_hash": hash_of(b"other"),
        })));
        assert_eq!(bad.error.as_deref(), Some("ERR_00000002"));
        lock_all();
    }

    #[test]
    fn slim_flow_keeps_keys_inside_worker_without_handles() {
        lock_all();
        unlocked("photo", "module-secret");
        let created = handle_file_key(&request(serde_json::json!({
            "op": "module_file_key", "module": "photo", "kind": "slim_create",
        })));
        assert!(created.ok);
        let wrapped = created.wrapped_key.clone().expect("必须返回包裹密钥");
        assert!(created.salt.is_some());

        let hash = hash_of(b"block");
        let sealed = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "slim_chunk",
            "wrapped_key": wrapped, "seq": 0, "total": 2, "file_hash": hash,
            "data": base64_encode(b"block"),
        })));
        assert!(sealed.ok);

        let opened = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "slim_chunk",
            "wrapped_key": wrapped, "seq": 0, "total": 2, "file_hash": hash,
            "data": sealed.data,
        })));
        assert!(opened.ok);
        assert_eq!(data_of(&opened), b"block");

        // 缩略图与块集只要求包裹密钥，不要求文件密钥句柄
        let thumb = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "thumb",
            "wrapped_key": wrapped, "file_hash": hash, "data": base64_encode(b"thumb"),
        })));
        assert!(thumb.ok);
        let thumb_open = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "thumb",
            "wrapped_key": wrapped, "file_hash": hash, "data": thumb.data,
        })));
        assert!(thumb_open.ok);
        assert_eq!(data_of(&thumb_open), b"thumb");

        // 错误模块口令不得解封
        lock_all();
        unlocked("photo", "wrong-secret");
        let bad = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "photo", "kind": "slim_chunk",
            "wrapped_key": wrapped, "seq": 0, "total": 2, "file_hash": hash,
            "data": sealed.data,
        })));
        assert_eq!(bad.error.as_deref(), Some("ERR_00000002"));
        lock_all();
    }

    #[test]
    fn v2_flow_derives_from_per_file_password_without_module_secret() {
        lock_all();
        /* 文件块 v2 的口令是每个文件独立的用户输入，与模块密钥无关：
         * 未解锁任何模块也必须能加密/解密与校验。 */
        let salt_b64 = base64_encode(&[0x11u8; SALT_LEN]);
        let password = "file-pass-一号";

        let sealed = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "file", "kind": "v2_chunk",
            "salt": salt_b64, "password": password, "data": base64_encode(b"file-block"),
        })));
        assert!(sealed.ok);
        let opened = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "file", "kind": "v2_chunk",
            "salt": salt_b64, "password": password, "data": sealed.data,
        })));
        assert!(opened.ok);
        assert_eq!(data_of(&opened), b"file-block");

        let check = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "file", "kind": "v2_check",
            "salt": salt_b64, "password": password,
        })));
        assert!(check.ok);
        let verified = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "file", "kind": "v2_check",
            "salt": salt_b64, "password": password, "data": check.data,
        })));
        assert!(verified.ok);

        // 另一个文件口令派生结果不得通过校验（同盐不同口令不得命中共缓存）
        let bad = handle_open(&request(serde_json::json!({
            "op": "module_open", "module": "file", "kind": "v2_check",
            "salt": salt_b64, "password": "another-pass", "data": check.data,
        })));
        assert_eq!(bad.error.as_deref(), Some("ERR_00000002"));

        // 缺少口令即非法：不允许退回模块密钥派生
        let missing = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "file", "kind": "v2_chunk",
            "salt": salt_b64, "data": base64_encode(b"x"),
        })));
        assert_eq!(missing.error.as_deref(), Some("ERR_00000001"));
        lock_all();
    }

    #[test]
    fn cache_is_bounded_and_evicts_oldest() {
        lock_all();
        unlocked("photo", "photo-secret");
        with_session(|session| {
            let mut salts = Vec::new();
            for i in 0..(CACHE_CAPACITY + 3) {
                let mut salt = [0u8; SALT_LEN];
                salt[0] = i as u8;
                session
                    .derive(ModuleId::Photo, &salt, Derivation::PhotoFileKey, PBKDF2_ITER, None)
                    .expect("派生必须成功");
                salts.push(salt);
            }
            assert_eq!(session.cache.len(), CACHE_CAPACITY);
            session
                .derive(ModuleId::Photo, &salts[0], Derivation::PhotoFileKey, PBKDF2_ITER, None)
                .expect("重新派生必须成功");
            assert_eq!(session.cache.len(), CACHE_CAPACITY);
        });
        lock_all();
    }

    #[test]
    fn invalid_positions_and_bad_hashes_are_rejected() {
        lock_all();
        unlocked("photo", "photo-secret");
        let bad_pos = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "chunk",
            "data": base64_encode(b"x"), "seq": 3, "total": 3, "file_hash": "00".repeat(32),
        })));
        assert_eq!(bad_pos.error.as_deref(), Some("ERR_00000001"));

        let bad_hash = handle_seal(&request(serde_json::json!({
            "op": "module_seal", "module": "photo", "kind": "chunk",
            "data": base64_encode(b"x"), "seq": 0, "total": 1, "file_hash": "xyz",
        })));
        assert_eq!(bad_hash.error.as_deref(), Some("ERR_00000001"));
        lock_all();
    }
}
