/* module_keys.rs — 内容层加解密入口（照片 / 文件）
 *
 * 职责边界：把前端的“模块名 + 布局 + 公开参数 + 载荷”映射到 C 层的
 * 分片接口（`Verthys_V4ChunkSeal/Open`）。分片密钥（MDEK）只在 C 层
 * 持有：worker 不保存模块口令、不派生模块密钥、不缓存任何文件密钥，
 * 内容路径的密钥面完全由 C 层 M1 状态机约束（未启用→Keyring，
 * 启用未解锁→POLICY/LOCKED，解锁后→可用）。
 *
 * 文件块 v2 保持每文件口令语义：内层 AES-256-GCM 由文件口令派生，
 * 外层仍由模块 MDEK 封装；口令只在本函数调用期内驻留。
 *
 * 布局种类（kind）在 外层明文中绑定（域标签 + 种类码）：
 * C 分片的 AAD 只覆盖 module/uuid/seq/total/pt_len，不区分内容种类；
 * 若不做绑定，具备记录写权限的攻击者可在同模块内互换 meta / thumb /
 * chunk 密文，把一种记录当作另一种记录解出。域标签让种类错配在
 * 外层认证通过后立即失败。
 *
 * 清单（manifest）：产品内容不使用独立清单记录。分片集合由 meta 内的
 * BLAKE3 逐块哈希表与 chunkset 记录共同认证，二者本身已被 分片
 * 封装；C 层清单仅服务于模块重写事务，不进入内容路径。
 */

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::budget::PB_IPC_MAX_PAYLOAD_BYTES;
use super::content_crypto::{
    self, VencError, KEY_LEN, PBKDF2_ITER, SALT_LEN, V2_MAX_ITERATIONS, V2_MIN_ITERATIONS,
};
use super::protocol::{base64_decode, base64_encode, Request, Response};
use super::worker::Worker;

/// 单次内容载荷的 base64 字符上限（跨层预算常量为字符口径）
const MAX_PAYLOAD_CHARS: usize = PB_IPC_MAX_PAYLOAD_BYTES as usize;
/// 与字符上限对应的解码后字节上限（base64 每 4 字符解出 3 字节）
const MAX_PAYLOAD_DECODED_BYTES: usize = MAX_PAYLOAD_CHARS / 4 * 3;
/// 文件口令长度上限：超长输入按非法处理
const MAX_SECRET_BYTES: usize = 4096;

/// 分片头长度：file_uuid(16) + seq(4) + total(4) + pt_len(4)
const CHUNK_PREFIX_LEN: usize = 16 + 4 + 4 + 4;
/// 分片 nonce 长度（C 层 VTY_NONCE_BYTES）
const CHUNK_NONCE_LEN: usize = 24;
/// 分片认证标签长度（C 层 VTY_TAG_BYTES）
const CHUNK_TAG_LEN: usize = 16;

/// 内容种类域标签：`VT4C` + 版本 + 种类码
const CONTENT_TAG_MAGIC: &[u8; 5] = b"VT4C\x01";
const CONTENT_TAG_LEN: usize = CONTENT_TAG_MAGIC.len() + 1;

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

fn module_index(module: ModuleId) -> u32 {
    match module {
        ModuleId::Photo => 0,
        ModuleId::File => 2,
    }
}

/// 内容种类码：与前端布局一一对应；未知种类直接拒绝。
fn kind_code(kind: &str) -> Option<u8> {
    match kind {
        "meta" => Some(1),
        "slim_meta" => Some(2),
        "chunk" => Some(3),
        "slim_chunk" => Some(4),
        "thumb" => Some(5),
        "chunkset" => Some(6),
        "v2_chunk" => Some(7),
        "v2_check" => Some(8),
        _ => None,
    }
}

fn tag_content(kind: u8, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(CONTENT_TAG_LEN + payload.len());
    out.extend_from_slice(CONTENT_TAG_MAGIC);
    out.push(kind);
    out.extend_from_slice(payload);
    Zeroizing::new(out)
}

/// 校验并剥离域标签；种类错配与标签篡改一律按认证失败处理。
fn untag_content(kind: u8, opened: &mut Zeroizing<Vec<u8>>) -> Result<(), VencError> {
    if opened.len() < CONTENT_TAG_LEN
        || &opened[..CONTENT_TAG_MAGIC.len()] != CONTENT_TAG_MAGIC
        || opened[CONTENT_TAG_MAGIC.len()] != kind
    {
        return Err(VencError::Auth);
    }
    let rest = opened.len() - CONTENT_TAG_LEN;
    opened.copy_within(CONTENT_TAG_LEN.., 0);
    opened.truncate(rest);
    Ok(())
}

/// 解析并预检 分片头：结构不自洽的输入在进入 FFI 之前拒绝。
fn parse_chunk_header(bytes: &[u8]) -> Result<([u8; 16], u32, u32), VencError> {
    const MIN_LEN: usize = CHUNK_PREFIX_LEN + CHUNK_NONCE_LEN + CHUNK_TAG_LEN;
    if bytes.len() < MIN_LEN {
        return Err(VencError::Corrupt);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[..16]);
    let seq = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let total = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let pt_len = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if total == 0 || seq >= total {
        return Err(VencError::Corrupt);
    }
    let expected = CHUNK_PREFIX_LEN
        .checked_add(CHUNK_NONCE_LEN)
        .and_then(|v| v.checked_add(pt_len as usize))
        .and_then(|v| v.checked_add(CHUNK_TAG_LEN));
    if expected != Some(bytes.len()) {
        return Err(VencError::Corrupt);
    }
    Ok((uuid, seq, total))
}

/// 照片内容的分片域标识：优先键控文件哈希，其次文件盐，最后随机。
/// 域标识不是寻址键；读取侧从 分片头解析，不依赖调用方重复提供。
fn photo_file_uuid(req: &Request) -> Result<[u8; 16], VencError> {
    if !req.file_hash.is_empty() {
        let hash = content_crypto::parse_hash_hex(&req.file_hash)?;
        let mut h = Sha256::new();
        h.update(b"verthys/v4/file-uuid/photo");
        h.update(hash);
        let d = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        return Ok(out);
    }
    if !req.salt.is_empty() {
        return required_salt(&req.salt);
    }
    content_crypto::random_bytes()
}

/// 文件块 v2 的分片域标识：文件盐即域标识（公开参数）。
fn v2_password_key(req: &Request) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    let salt = required_salt(&req.salt)?;
    let iterations = if req.iterations == 0 {
        PBKDF2_ITER
    } else {
        req.iterations
    };
    if !(V2_MIN_ITERATIONS..=V2_MAX_ITERATIONS).contains(&iterations) {
        return Err(VencError::Invalid);
    }
    let password = req.password.as_bytes();
    if password.is_empty() || password.len() > MAX_SECRET_BYTES {
        return Err(VencError::Invalid);
    }
    content_crypto::derive_master_key(password, &salt, iterations)
        .map_err(|_| VencError::Invalid)
}

fn module_position(kind: &str, req: &Request) -> Result<(u32, u32), VencError> {
    match kind {
        "chunk" | "slim_chunk" => {
            validate_position(req.seq, req.total)?;
            Ok((req.seq, req.total))
        }
        _ => Ok((0, 1)),
    }
}

/* ------------------------------------------------------------------ *
 * 栈区残留擦除                                                        *
 * ------------------------------------------------------------------ */

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
 * 生产加密入口                                                        *
 * ------------------------------------------------------------------ */

/// 加密入口：文件块 v2 先做每文件口令内层封装，再统一由 C 层以模块
/// MDEK 封装为 分片。
pub(crate) fn handle_seal_v4(req: &Request, worker: &Worker) -> Response {
    let resp = match seal_inner(req, worker) {
        Ok(out) => {
            let mut r = Response::ok("module_seal");
            r.data = Some(base64_encode(&out));
            r
        }
        Err(e) => fail("module_seal", e),
    };
    scrub_stack();
    resp
}

fn seal_inner(req: &Request, worker: &Worker) -> Result<Vec<u8>, VencError> {
    let module = ModuleId::parse(&req.module)?;
    let kind = req.kind.as_str();
    let code = kind_code(kind).ok_or(VencError::Invalid)?;

    /* v2_check 的明文由 worker 固定，不接收调用方数据；其余布局必须携带
     * 非空明文，避免把“空记录”写盘后无法区分读取失败与零长度。 */
    let payload = if kind == "v2_check" {
        Zeroizing::new(Vec::new())
    } else {
        let data = decode_payload(&req.data)?;
        if data.is_empty() {
            return Err(VencError::Invalid);
        }
        data
    };

    let (uuid, seq, total, inner) = if kind.starts_with("v2_") {
        let uuid = required_salt(&req.salt)?;
        let key = v2_password_key(req)?;
        let sealed = if kind == "v2_check" {
            content_crypto::build_v2_check(&key[..], &content_crypto::random_bytes()?)?
        } else {
            content_crypto::seal_v2_chunk(&key[..], &content_crypto::random_bytes()?, &payload)?
        };
        (uuid, 0, 1, tag_content(code, &sealed))
    } else {
        let uuid = photo_file_uuid(req)?;
        let (seq, total) = module_position(kind, req)?;
        (uuid, seq, total, tag_content(code, &payload))
    };

    worker
        .call_chunk_seal(module_index(module), &uuid, seq, total, &inner)
        .map_err(map_ffi_error)
}

/// 解密入口：从 分片头解析域标识与位置，由 C 层解封后校验种类标签；
/// v2 内容继续用每文件口令校验内层。
pub(crate) fn handle_open_v4(req: &Request, worker: &Worker) -> Response {
    let resp = match open_inner(req, worker) {
        Ok((plaintext, seq_total)) => {
            let mut r = Response::ok("module_open");
            if !plaintext.is_empty() {
                r.data = Some(base64_encode(&plaintext));
            }
            if let Some((seq, total)) = seq_total {
                r.seq = Some(seq);
                r.total = Some(total);
            }
            r
        }
        Err(e) => fail("module_open", e),
    };
    scrub_stack();
    resp
}

/// 解密结果：明文与（分块布局）密文内嵌的位置。
type OpenedContent = (Zeroizing<Vec<u8>>, Option<(u32, u32)>);

fn open_inner(req: &Request, worker: &Worker) -> Result<OpenedContent, VencError> {
    let module = ModuleId::parse(&req.module)?;
    let kind = req.kind.as_str();
    let code = kind_code(kind).ok_or(VencError::Invalid)?;

    let combined = decode_payload(&req.data)?;
    let (uuid, seq, total) = parse_chunk_header(&combined)?;
    let opened = worker
        .call_chunk_open(module_index(module), &uuid, seq, total, &combined)
        .map_err(map_ffi_error)?;
    let mut opened = Zeroizing::new(opened);
    untag_content(code, &mut opened)?;

    match kind {
        "chunk" => Ok((opened, Some((seq, total)))),
        "v2_chunk" => {
            let key = v2_password_key(req)?;
            Ok((content_crypto::open_v2_chunk(&key[..], &opened)?, None))
        }
        "v2_check" => {
            let key = v2_password_key(req)?;
            if !content_crypto::verify_v2_check(&key[..], &opened)? {
                return Err(VencError::Auth);
            }
            Ok((Zeroizing::new(Vec::new()), None))
        }
        "meta" | "slim_meta" | "slim_chunk" | "thumb" | "chunkset" => Ok((opened, None)),
        _ => Err(VencError::Invalid),
    }
}

fn map_ffi_error(rc: u32) -> VencError {
    match rc {
        /* AUTH 与 KEY_INVALID 统一为认证失败：不区分口令错误、密钥不匹配
         * 与密文篡改。 */
        0x00000002 => VencError::Auth,
        /* FORMAT / CORRUPT：结构或完整性损坏，对外仍归入 AUTH。 */
        0x00000005 | 0x00000009 => VencError::Corrupt,
        /* LOCKED / POLICY：容器锁定或策略拒绝。 */
        0x00000007 | 0x00000017 => VencError::Locked,
        /* 轮换作业期间源库只读。 */
        0x0000001C => VencError::RotatePending,
        /* 模块已启用但本会话未解锁：需要先输入模块口令。 */
        0x0000001D => VencError::ModuleLocked,
        _ => VencError::Invalid,
    }
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

fn decode_b64(text: &str) -> Result<Vec<u8>, VencError> {
    if text.is_empty() {
        return Err(VencError::Invalid);
    }
    base64_decode(text).map_err(|_| VencError::Invalid)
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
        VencError::RotatePending => 0x1C,
        VencError::ModuleLocked => 0x1D,
        /* Auth / Corrupt / Internal 一律映射为 AUTH：对外不可区分
         * 口令错误、数据篡改与内部异常。 */
        _ => 0x02,
    };
    Response::err(op, code)
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 *
 * 分片的真实加解密由 C 层承担，worker 单测覆盖不依赖 FFI 的
 * 编排与边界：分片头预检、种类标签绑定、参数校验、错误码映射。
 * 端到端往返（真实 MDEK、锁定/解锁、v2 口令）由
 * tests/e2e/worker-smoke.ps1 覆盖。
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mut value: serde_json::Value) -> Request {
        // op 字段只用于路由，参数级测试不需要逐条重复书写
        if value.get("op").is_none() {
            value["op"] = serde_json::json!("test");
        }
        serde_json::from_value(value).expect("测试请求必须可反序列化")
    }

    fn chunk_bytes(uuid: [u8; 16], seq: u32, total: u32, pt_len: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&uuid);
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&pt_len.to_le_bytes());
        out.resize(CHUNK_PREFIX_LEN + CHUNK_NONCE_LEN + pt_len as usize + CHUNK_TAG_LEN, 0xAA);
        out
    }

    #[test]
    fn rotate_and_module_locked_codes_are_preserved() {
        assert_eq!(map_ffi_error(0x0000001C), VencError::RotatePending);
        assert_eq!(map_ffi_error(0x0000001D), VencError::ModuleLocked);
        let rotate = fail("module_seal", VencError::RotatePending);
        assert_eq!(rotate.error.as_deref(), Some("ERR_0000001C"));
        let locked = fail("module_open", VencError::ModuleLocked);
        assert_eq!(locked.error.as_deref(), Some("ERR_0000001D"));
    }

    #[test]
    fn kind_codes_cover_every_layout_once() {
        let kinds = [
            "meta", "slim_meta", "chunk", "slim_chunk", "thumb", "chunkset", "v2_chunk",
            "v2_check",
        ];
        let mut codes = Vec::new();
        for kind in kinds {
            codes.push(kind_code(kind).expect("已知布局必须有种类码"));
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), kinds.len(), "种类码不得重复");
        assert_eq!(kind_code("plaintext"), None);
        assert_eq!(kind_code(""), None);
    }

    #[test]
    fn content_tag_binds_kind_and_strips_cleanly() {
        let tagged = tag_content(3, b"payload");
        assert_eq!(&tagged[..CONTENT_TAG_MAGIC.len()], CONTENT_TAG_MAGIC);

        let mut opened = tagged.clone();
        untag_content(3, &mut opened).expect("匹配种类必须解出");
        assert_eq!(opened.as_slice(), b"payload");

        // 种类错配 → 认证失败（在 FFI 之后仍不可跨布局解释）
        let mut mismatch = tagged.clone();
        assert_eq!(
            untag_content(5, &mut mismatch).unwrap_err(),
            VencError::Auth
        );

        // 标签篡改 → 认证失败
        let mut tampered = tagged.clone();
        tampered[0] ^= 0x01;
        assert_eq!(untag_content(3, &mut tampered).unwrap_err(), VencError::Auth);

        // 短于标签长度 → 认证失败（不得越界切片）
        let mut short = Zeroizing::new(vec![0u8; CONTENT_TAG_LEN - 1]);
        assert_eq!(untag_content(1, &mut short).unwrap_err(), VencError::Auth);

        // 空载荷（v2_check）标签剥离后长度为 0
        let mut empty = tag_content(8, b"");
        untag_content(8, &mut empty).expect("空载荷必须可剥离");
        assert!(empty.is_empty());
    }

    #[test]
    fn chunk_header_rejects_truncated_and_inconsistent_input() {
        let uuid = [0x11u8; 16];
        let ok = chunk_bytes(uuid, 1, 3, 8);
        assert_eq!(parse_chunk_header(&ok).unwrap(), (uuid, 1, 3));

        // 短输入
        assert_eq!(
            parse_chunk_header(&[0u8; CHUNK_PREFIX_LEN]).unwrap_err(),
            VencError::Corrupt
        );
        // seq 越界 / total 为 0
        let bad_seq = chunk_bytes(uuid, 3, 3, 8);
        assert_eq!(parse_chunk_header(&bad_seq).unwrap_err(), VencError::Corrupt);
        let zero_total = chunk_bytes(uuid, 0, 0, 8);
        assert_eq!(parse_chunk_header(&zero_total).unwrap_err(), VencError::Corrupt);
        // 长度与头内 pt_len 不一致（截断/追加都必须检出）
        let mut truncated = chunk_bytes(uuid, 0, 1, 8);
        truncated.pop();
        assert_eq!(parse_chunk_header(&truncated).unwrap_err(), VencError::Corrupt);
        let mut extended = chunk_bytes(uuid, 0, 1, 8);
        extended.push(0);
        assert_eq!(parse_chunk_header(&extended).unwrap_err(), VencError::Corrupt);
        // pt_len 极大（溢出检查）
        let huge = chunk_bytes(uuid, 0, 1, 0);
        let mut huge = huge;
        huge[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_chunk_header(&huge).unwrap_err(), VencError::Corrupt);
    }

    #[test]
    fn photo_uuid_is_stable_per_hash_and_rejects_bad_input() {
        let hash = content_crypto::hex_encode(&content_crypto::file_hash(b"x").unwrap());
        let a = photo_file_uuid(&request(serde_json::json!({ "file_hash": hash }))).unwrap();
        let b = photo_file_uuid(&request(serde_json::json!({ "file_hash": hash }))).unwrap();
        assert_eq!(a, b, "同一文件哈希必须稳定映射到同一域标识");
        assert_ne!(a, [0u8; 16], "域标识不得全零");

        assert!(photo_file_uuid(&request(serde_json::json!({ "file_hash": "xyz" }))).is_err());

        let salt = base64_encode(&[0x22u8; SALT_LEN]);
        let from_salt =
            photo_file_uuid(&request(serde_json::json!({ "salt": salt }))).unwrap();
        assert_eq!(from_salt, [0x22u8; 16]);

        // 无哈希且无盐：随机域标识，但必须非零且两次不同
        let r1 = photo_file_uuid(&request(serde_json::json!({}))).unwrap();
        let r2 = photo_file_uuid(&request(serde_json::json!({}))).unwrap();
        assert_ne!(r1, [0u8; 16]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn v2_password_requires_salt_password_and_sane_iterations() {
        let salt = base64_encode(&[0x33u8; SALT_LEN]);
        let ok = request(serde_json::json!({
            "salt": salt, "password": "file-pass", "iterations": V2_MIN_ITERATIONS,
        }));
        assert!(v2_password_key(&ok).is_ok());

        let no_password = request(serde_json::json!({ "salt": salt, "password": "" }));
        assert_eq!(v2_password_key(&no_password).unwrap_err(), VencError::Invalid);
        let no_salt = request(serde_json::json!({ "password": "file-pass" }));
        assert_eq!(v2_password_key(&no_salt).unwrap_err(), VencError::Invalid);
        let weak = request(serde_json::json!({
            "salt": salt, "password": "file-pass", "iterations": V2_MIN_ITERATIONS - 1,
        }));
        assert_eq!(v2_password_key(&weak).unwrap_err(), VencError::Invalid);
        let huge = request(serde_json::json!({
            "salt": salt, "password": "file-pass", "iterations": V2_MAX_ITERATIONS + 1,
        }));
        assert_eq!(v2_password_key(&huge).unwrap_err(), VencError::Invalid);
        let overlong = request(serde_json::json!({
            "salt": salt, "password": "a".repeat(MAX_SECRET_BYTES + 1),
        }));
        assert_eq!(v2_password_key(&overlong).unwrap_err(), VencError::Invalid);
    }

    #[test]
    fn ffi_error_mapping_keeps_lock_and_policy_distinct() {
        assert_eq!(map_ffi_error(0x02), VencError::Auth);
        assert_eq!(map_ffi_error(0x05), VencError::Corrupt);
        assert_eq!(map_ffi_error(0x09), VencError::Corrupt);
        assert_eq!(map_ffi_error(0x07), VencError::Locked);
        assert_eq!(map_ffi_error(0x17), VencError::Locked);
        assert_eq!(map_ffi_error(0x01), VencError::Invalid);

        assert_eq!(fail("x", VencError::Locked).error.as_deref(), Some("ERR_00000007"));
        assert_eq!(fail("x", VencError::Invalid).error.as_deref(), Some("ERR_00000001"));
        assert_eq!(fail("x", VencError::Auth).error.as_deref(), Some("ERR_00000002"));
        assert_eq!(fail("x", VencError::Corrupt).error.as_deref(), Some("ERR_00000002"));
    }

    #[test]
    fn payload_gate_rejects_empty_oversize_and_invalid_base64() {
        assert!(decode_payload("YWJj").is_ok());
        assert_eq!(decode_payload("").unwrap_err(), VencError::Invalid);
        assert_eq!(decode_payload("!!!").unwrap_err(), VencError::Invalid);
        let oversize = "a".repeat(MAX_PAYLOAD_CHARS + 1);
        assert_eq!(decode_payload(&oversize).unwrap_err(), VencError::Invalid);
    }

    #[test]
    fn positions_are_validated_before_sealing() {
        assert_eq!(module_position("chunk", &request(serde_json::json!({ "seq": 0, "total": 1 }))).unwrap(), (0, 1));
        assert!(module_position("chunk", &request(serde_json::json!({ "seq": 1, "total": 1 }))).is_err());
        assert!(module_position("slim_chunk", &request(serde_json::json!({ "seq": 0, "total": 0 }))).is_err());
        // 非分块布局固定 (0,1)：meta/thumb 不占用位置
        assert_eq!(module_position("meta", &request(serde_json::json!({}))).unwrap(), (0, 1));
    }
}
