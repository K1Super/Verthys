/* content_crypto.rs — 内容记录加密原语（与既有落盘布局逐字节兼容）
 *
 * 职责边界：只承载无状态的密码学运算与布局编解码；模块密钥、派生缓存
 * 与文件密钥解封由 module_keys 独占负责。本模块不持有任何长期密钥，
 * 也不访问磁盘。
 *
 * 布局（字节数）：
 *   记录型元数据：salt(16) | nonce(24) | 密文+tag
 *   记录型块：salt(16) | seq(4 大端) | total(4 大端) | nonce(24) | 密文+tag
 *   瘦身索引：salt(16) | nonce(24) | 密文+tag
 *   瘦身块 / 缩略图 / 块集：nonce(24) | 密文+tag
 *   包裹文件密钥：salt(16) | nonce(24) | 密文+tag
 *   文件块 v2：iv(12) | 密文+tag（AES-256-GCM，无附加数据）
 *
 * 附加数据绑定：
 *   块 AD = 前缀 ‖ seq ‖ total ‖ BLAKE3(明文块)
 *   缩略图 / 块集 AD = 前缀 ‖ BLAKE3(明文块)
 *
 * 错误语义：认证失败与结构不自洽使用不同变体，但调用方不得把差异
 * 透出给用户——口令错误与数据篡改必须不可区分。
 */

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/* ------------------------------------------------------------------ *
 * 布局常量                                                            *
 * ------------------------------------------------------------------ */

/// 文件盐长度（128 位）
pub(crate) const SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce 长度（192 位）
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 认证标签长度
pub(crate) const TAG_LEN: usize = 16;
/// 对称密钥长度（256 位）
pub(crate) const KEY_LEN: usize = 32;
/// BLAKE3 文件哈希长度
pub(crate) const FILE_HASH_LEN: usize = 32;
/// 文件块 v2 的 iv 长度（AES-GCM 96 位）
pub(crate) const V2_IV_LEN: usize = 12;
/// 照片文件密钥派生迭代次数（与既有写入面一致）
pub(crate) const PBKDF2_ITER: u32 = 150_000;
/// 文件块 v2 的最小可接受迭代次数：低于此值视为头部被篡改
pub(crate) const V2_MIN_ITERATIONS: u32 = 10_000;
/// 文件块 v2 迭代次数上限：拒绝恶意参数导致的超长派生
pub(crate) const V2_MAX_ITERATIONS: u32 = 10_000_000;
/// 文件级密码校验固定明文
pub(crate) const FILE_CHECK_PLAINTEXT: &[u8] = b"verthys-filecheck-v1";

/// 元数据 AEAD 附加数据
pub(crate) const META_AD: &[u8] = b"VERTHYSPHOTO_META_v1";
/// 块 AEAD 附加数据前缀（后接 seq / total / 文件哈希）
pub(crate) const CHUNK_AD_PREFIX: &[u8] = b"VERTHYSPHOTO_CHUNK_v1";
/// 照片文件子密钥 HKDF info
pub(crate) const FILE_KEY_INFO: &[u8] = b"VERTHYSPHOTO_FILE_KEY_v1";
/// 缩略图记录 AEAD 附加数据前缀（后接文件哈希）
pub(crate) const THUMB_AD: &[u8] = b"VERTHYSPHOTO_THUMB_v1";
/// 块集记录 AEAD 附加数据前缀（后接文件哈希）
pub(crate) const CHUNK_SET_AD: &[u8] = b"VERTHYSPHOTO_CHUNKSET_v1";
/// 包裹文件密钥 AEAD 附加数据
pub(crate) const FILE_KEY_WRAP_AD: &[u8] = b"VERTHYSPHOTO_FILEKEY_v1";

/* ------------------------------------------------------------------ *
 * 错误                                                                *
 * ------------------------------------------------------------------ */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VencError {
    /// 入参缺失或长度/取值不合法
    Invalid,
    /// AEAD 认证失败：口令或密钥不匹配、数据被篡改
    Auth,
    /// 结构不自洽：长度不足、字段非法
    Corrupt,
    /// 模块密钥未解锁或已被清除
    Locked,
    /// 随机源或密码学后端不可用
    Internal,
}

/* ------------------------------------------------------------------ *
 * 随机与哈希                                                          *
 * ------------------------------------------------------------------ */

/// 取密码学安全随机字节。
///
/// 随机源不可用时返回 Internal 而非回退到弱随机：任何可预测 nonce
/// 都会直接破坏 AEAD 的机密性。
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], VencError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| VencError::Internal)?;
    Ok(out)
}

/// 计算 BLAKE3 文件哈希；空输入视为非法（不存在零长度内容块）。
///
/// 当前仅在测试与向量校验中直接调用：生产路径的哈希由前端计算后随请求
/// 传入，worker 负责校验绑定关系，不重复做全文件读取。
#[cfg(test)]
pub(crate) fn file_hash(data: &[u8]) -> Result<[u8; FILE_HASH_LEN], VencError> {
    if data.is_empty() {
        return Err(VencError::Invalid);
    }
    let digest = blake3::hash(data);
    Ok(*digest.as_bytes())
}

/// 小写十六进制编码（哈希与诊断标识使用，不含密钥材料）。
#[cfg(test)]
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

/// 解析 64 字符十六进制哈希；长度或字符集不符即拒绝。
pub(crate) fn parse_hash_hex(text: &str) -> Result<[u8; FILE_HASH_LEN], VencError> {
    if text.len() != FILE_HASH_LEN * 2 || !text.is_ascii() {
        return Err(VencError::Invalid);
    }
    let mut out = [0u8; FILE_HASH_LEN];
    let raw = text.as_bytes();
    for i in 0..FILE_HASH_LEN {
        let hi = hex_nibble(raw[i * 2])?;
        let lo = hex_nibble(raw[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, VencError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(VencError::Invalid),
    }
}

/* ------------------------------------------------------------------ *
 * 密钥派生                                                            *
 * ------------------------------------------------------------------ */

/// PBKDF2-SHA256 主密钥派生。
///
/// iterations 由调用方给出：读取侧必须按头部携带的历史值执行，
/// 否则提升默认值会使既有数据永久不可解。
pub(crate) fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    if password.is_empty() || salt.len() != SALT_LEN || iterations == 0 {
        return Err(VencError::Invalid);
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out[..]);
    Ok(out)
}

/// 由主密钥与文件盐派生文件子密钥（HKDF-SHA256）。
///
/// 每个文件独立子密钥，限制单文件密钥泄露的影响面。
pub(crate) fn derive_file_key(
    master: &[u8; KEY_LEN],
    file_salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(file_salt), master);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(FILE_KEY_INFO, &mut out[..])
        .map_err(|_| VencError::Internal)?;
    Ok(out)
}

/* ------------------------------------------------------------------ *
 * AEAD 基元                                                            *
 * ------------------------------------------------------------------ */

fn xchacha(key: &[u8]) -> Result<XChaCha20Poly1305, VencError> {
    if key.len() != KEY_LEN {
        return Err(VencError::Invalid);
    }
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| VencError::Invalid)
}

/// XChaCha20-Poly1305 加密（输出含 16 字节认证标签）。
pub(crate) fn seal_x(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    if nonce.len() != NONCE_LEN {
        return Err(VencError::Invalid);
    }
    xchacha(key)?
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| VencError::Internal)
}

/// XChaCha20-Poly1305 解密；认证失败统一返回 Auth。
pub(crate) fn open_x(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VencError> {
    if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
        return Err(VencError::Corrupt);
    }
    xchacha(key)?
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VencError::Auth)
}

/// 块附加数据：前缀 ‖ seq(4 大端) ‖ total(4 大端) ‖ 文件哈希(32)。
pub(crate) fn build_chunk_ad(seq: u32, total: u32, file_hash: &[u8; FILE_HASH_LEN]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(CHUNK_AD_PREFIX.len() + 4 + 4 + FILE_HASH_LEN);
    ad.extend_from_slice(CHUNK_AD_PREFIX);
    ad.extend_from_slice(&seq.to_be_bytes());
    ad.extend_from_slice(&total.to_be_bytes());
    ad.extend_from_slice(file_hash);
    ad
}

/// 文件绑定附加数据：前缀 ‖ 文件哈希(32)。
pub(crate) fn build_file_bound_ad(prefix: &[u8], file_hash: &[u8; FILE_HASH_LEN]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(prefix.len() + FILE_HASH_LEN);
    ad.extend_from_slice(prefix);
    ad.extend_from_slice(file_hash);
    ad
}

/* ------------------------------------------------------------------ *
 * 记录型布局                                                          *
 * ------------------------------------------------------------------ */

/// 加密元数据：salt(16) ‖ nonce(24) ‖ 密文+tag。
pub(crate) fn seal_meta(
    file_key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    let ct = seal_x(file_key, nonce, META_AD, plaintext)?;
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密元数据；salt 由调用方从密文头部读取后先行派生密钥。
pub(crate) fn open_meta(
    file_key: &[u8],
    combined: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VencError> {
    if combined.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let nonce = &combined[SALT_LEN..SALT_LEN + NONCE_LEN];
    open_x(file_key, nonce, META_AD, &combined[SALT_LEN + NONCE_LEN..])
}

/// 从记录型密文头部取出盐；长度不足即判损坏。
pub(crate) fn extract_meta_salt(combined: &[u8]) -> Result<[u8; SALT_LEN], VencError> {
    if combined.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&combined[..SALT_LEN]);
    Ok(salt)
}

/// 加密记录型块：salt(16) ‖ seq(4) ‖ total(4) ‖ nonce(24) ‖ 密文+tag。
pub(crate) fn seal_chunk(
    file_key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    seq: u32,
    total: u32,
    file_hash: &[u8; FILE_HASH_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    if total == 0 || plaintext.is_empty() {
        return Err(VencError::Invalid);
    }
    let ad = build_chunk_ad(seq, total, file_hash);
    let ct = seal_x(file_key, nonce, &ad, plaintext)?;
    let mut out = Vec::with_capacity(SALT_LEN + 8 + NONCE_LEN + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密记录型块，返回密文自带的 seq/total 与明文。
///
/// seq/total 在解密前先做长度与取值校验，再参与 AD 认证：调用方应把
/// 返回值与自己持有的位置信息比对，拒绝跨位置拼接。
pub(crate) fn open_chunk(
    file_key: &[u8],
    combined: &[u8],
    file_hash: &[u8; FILE_HASH_LEN],
) -> Result<(u32, u32, Zeroizing<Vec<u8>>), VencError> {
    const HEADER: usize = SALT_LEN + 4 + 4 + NONCE_LEN;
    if combined.len() < HEADER + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let mut seq_bytes = [0u8; 4];
    seq_bytes.copy_from_slice(&combined[SALT_LEN..SALT_LEN + 4]);
    let mut total_bytes = [0u8; 4];
    total_bytes.copy_from_slice(&combined[SALT_LEN + 4..SALT_LEN + 8]);
    let seq = u32::from_be_bytes(seq_bytes);
    let total = u32::from_be_bytes(total_bytes);
    if total == 0 {
        return Err(VencError::Corrupt);
    }
    let nonce = &combined[SALT_LEN + 8..HEADER];
    let ad = build_chunk_ad(seq, total, file_hash);
    let plaintext = open_x(file_key, nonce, &ad, &combined[HEADER..])?;
    Ok((seq, total, plaintext))
}

/* ------------------------------------------------------------------ *
 * 索引瘦身布局                                                        *
 * ------------------------------------------------------------------ */

/// 加密瘦身索引：salt(16) ‖ nonce(24) ‖ 密文+tag。
///
/// 盐由调用方给定且必须与包裹态文件密钥同盐：读取侧一次派生即可
/// 同时覆盖索引、缩略图与文件密钥解封。
pub(crate) fn seal_slim_meta(
    file_key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    seal_meta(file_key, salt, nonce, plaintext)
}

/// 解密瘦身索引（布局与记录型元数据一致）。
pub(crate) fn open_slim_meta(
    file_key: &[u8],
    combined: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VencError> {
    open_meta(file_key, combined)
}

/// 加密瘦身块：nonce(24) ‖ 密文+tag，AD 绑定 seq/total/文件哈希。
pub(crate) fn seal_slim_chunk(
    file_key: &[u8],
    nonce: &[u8; NONCE_LEN],
    seq: u32,
    total: u32,
    file_hash: &[u8; FILE_HASH_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    if total == 0 || plaintext.is_empty() {
        return Err(VencError::Invalid);
    }
    let ad = build_chunk_ad(seq, total, file_hash);
    let ct = seal_x(file_key, nonce, &ad, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密瘦身块；seq/total 由调用方按块位置给出，与 AD 绑定值一致才通过。
pub(crate) fn open_slim_chunk(
    file_key: &[u8],
    combined: &[u8],
    seq: u32,
    total: u32,
    file_hash: &[u8; FILE_HASH_LEN],
) -> Result<Zeroizing<Vec<u8>>, VencError> {
    if total == 0 || combined.len() < NONCE_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let ad = build_chunk_ad(seq, total, file_hash);
    open_x(file_key, &combined[..NONCE_LEN], &ad, &combined[NONCE_LEN..])
}

/// 加密文件绑定记录（缩略图 / 块集）：nonce(24) ‖ 密文+tag。
pub(crate) fn seal_bound_record(
    wrap_key: &[u8],
    nonce: &[u8; NONCE_LEN],
    prefix: &[u8],
    file_hash: &[u8; FILE_HASH_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    if plaintext.is_empty() {
        return Err(VencError::Invalid);
    }
    let ad = build_file_bound_ad(prefix, file_hash);
    let ct = seal_x(wrap_key, nonce, &ad, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密文件绑定记录（缩略图 / 块集）。
pub(crate) fn open_bound_record(
    wrap_key: &[u8],
    combined: &[u8],
    prefix: &[u8],
    file_hash: &[u8; FILE_HASH_LEN],
) -> Result<Zeroizing<Vec<u8>>, VencError> {
    if combined.len() < NONCE_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let ad = build_file_bound_ad(prefix, file_hash);
    open_x(wrap_key, &combined[..NONCE_LEN], &ad, &combined[NONCE_LEN..])
}

/* ------------------------------------------------------------------ *
 * 包裹文件密钥                                                        *
 * ------------------------------------------------------------------ */

/// 包裹随机文件密钥：salt(16) ‖ nonce(24) ‖ 密文+tag。
///
/// 盐与包裹 nonce 随密文落盘；文件密钥本身只在解封后驻留内存。
pub(crate) fn seal_wrapped_file_key(
    wrap_key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    file_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, VencError> {
    let ct = seal_x(wrap_key, nonce, FILE_KEY_WRAP_AD, file_key)?;
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解封包裹态文件密钥；长度必须恰为 32 字节。
pub(crate) fn open_wrapped_file_key(
    wrap_key: &[u8],
    combined: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VencError> {
    if combined.len() < SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let nonce = &combined[SALT_LEN..SALT_LEN + NONCE_LEN];
    let plaintext = open_x(wrap_key, nonce, FILE_KEY_WRAP_AD, &combined[SALT_LEN + NONCE_LEN..])?;
    if plaintext.len() != KEY_LEN {
        return Err(VencError::Corrupt);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// 取出包裹态文件密钥内的盐（结构校验后返回）。
pub(crate) fn extract_wrapped_salt(combined: &[u8]) -> Result<[u8; SALT_LEN], VencError> {
    if combined.len() < SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&combined[..SALT_LEN]);
    Ok(salt)
}

/* ------------------------------------------------------------------ *
 * 文件块 v2（AES-256-GCM）                                            *
 * ------------------------------------------------------------------ */

fn aes_gcm(key: &[u8]) -> Result<Aes256Gcm, VencError> {
    if key.len() != KEY_LEN {
        return Err(VencError::Invalid);
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| VencError::Invalid)
}

/// 加密文件块 v2：iv(12) ‖ 密文+tag。
pub(crate) fn seal_v2_chunk(
    key: &[u8],
    iv: &[u8; V2_IV_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VencError> {
    let ct = aes_gcm(key)?
        .encrypt(Nonce::from_slice(iv), Payload { msg: plaintext, aad: &[] })
        .map_err(|_| VencError::Internal)?;
    let mut out = Vec::with_capacity(V2_IV_LEN + ct.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密文件块 v2。
pub(crate) fn open_v2_chunk(
    key: &[u8],
    combined: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VencError> {
    if combined.len() <= V2_IV_LEN + TAG_LEN {
        return Err(VencError::Corrupt);
    }
    let (iv, ct) = combined.split_at(V2_IV_LEN);
    aes_gcm(key)?
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad: &[] })
        .map(Zeroizing::new)
        .map_err(|_| VencError::Auth)
}

/// 生成密码校验块（固定明文的一次 AEAD）。
pub(crate) fn build_v2_check(
    key: &[u8],
    iv: &[u8; V2_IV_LEN],
) -> Result<Vec<u8>, VencError> {
    seal_v2_chunk(key, iv, FILE_CHECK_PLAINTEXT)
}

/// 校验密码校验块；解密失败与明文不符一律返回 false。
///
/// 明文比较使用常量时间实现：避免通过比较耗时推断前缀匹配长度。
pub(crate) fn verify_v2_check(key: &[u8], combined: &[u8]) -> Result<bool, VencError> {
    match open_v2_chunk(key, combined) {
        Ok(plaintext) => Ok(plaintext.len() == FILE_CHECK_PLAINTEXT.len()
            && bool::from(plaintext.as_slice().ct_eq(FILE_CHECK_PLAINTEXT))),
        /* 认证失败与结构损坏都是“校验不通过”的同类事实：调用方只需
         * 一个布尔结论，不应据错误分支推断口令是否接近正确。 */
        Err(VencError::Auth) | Err(VencError::Corrupt) => Ok(false),
        Err(other) => Err(other),
    }
}

/* ------------------------------------------------------------------ *
 * 单元测试：与前端加密实现的确定性向量双向校验                        *
 *
 * 向量由前端同源原语生成：同一 (口令, 盐, nonce, 明文) 下本模块的
 * 密文必须逐字节相同，且能解回同一明文。因此单向向量同时覆盖
 * “前端加密 → worker 解密”与“worker 加密 → 前端解密”。
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::protocol::base64_decode;

    const PASSWORD: &str = "photo-module-pass-测试";
    const SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const NONCE_HEX: &str = "202122232425262728292a2b2c2d2e2f3031323334353637";
    const WRAP_NONCE_HEX: &str = "606162636465666768696a6b6c6d6e6f7071727374757677";
    const FILE_KEY_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const MASTER_KEY_HEX: &str = "edffbddcb3290af05eabd593b6366a8d421af28e5d0ffe41dfe0ee885fcdf9ba";
    const WRAP_KEY_HEX: &str = "a663774919bf2431533def05d8ed9cf9bd071449c31a99f515d318216fa4c533";
    const FILE_HASH_HEX: &str = "e4542a4b9329829805e7bd66fa7f09dd9fe1eb65e1b9bdde770dca628b6199b0";
    const META_PLAIN_HEX: &str = "7b226e616d65223a2270686f746f2e6a7067222c226d696d65223a22696d6167652f6a706567222c2273697a65223a313032347d";
    const CHUNK_PLAIN_HEX: &str = "4348554e4b2d504c41494e544558542d303132333435363738392d414243444546";
    const THUMB_PLAIN_HEX: &str = "ffd8ffe000104a464946ffd9";
    const CHUNKSET_PLAIN_HEX: &str = "7b22696473223a5b312c325d2c22686173686573223a5b226161222c226262225d7d";
    const SLIM_META_PLAIN_HEX: &str = "7b226e616d65223a22736c696d2e6a7067222c22666d74223a322c227772617070656446696c654b6579223a2278227d";
    const V2_PLAIN_HEX: &str = "66696c652d626c6f636b2d76322d706c61696e746578742d303031";
    const V2_IV_HEX: &str = "808182838485868788898a8b";
    const LEGACY_META_B64: &str = "AAECAwQFBgcICQoLDA0ODyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2N+ZB2aCnunnmgE6Boaws931WqaThOenuI9gORM3oAQ4V+klQxEJN41YzeXLREwI4PiPCq91kXxwLU5EQzPUBC1/3bwbG";
    const LEGACY_CHUNK_B64: &str = "AAECAwQFBgcICQoLDA0ODwAAAAEAAAADICEiIyQlJicoKSorLC0uLzAxMjM0NTY33ivij4HyC5Djd6eanRuNOhb/tP4vsbF5hRVTrsMvKzfZi3voKWzdjcahV3IEQ61pYw==";
    const SLIM_META_B64: &str = "AAECAwQFBgcICQoLDA0ODyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2N+ZB2aCnunnmgE2Fp7Vts2dB7KrvfenzbIceUs32Hg4C7wNe8k5GpDF0czmRVFggcn7t4Pwn36C7C+oDXSRfpFs=";
    const SLIM_CHUNK_B64: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3YTxLfd1Ak1Tqo3rezST7KF3qPNvs4hy/pDkTpbK5LY6Gj5TaGch+WkGk1O8WYmtCrQ==";
    const THUMB_B64: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3YrtIIcrPEZrreBYXl0+pDvNP1zxBz0LNxnIPTA==";
    const CHUNKSET_B64: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY35kHepbn9YYeTEtuT9GGxdlWm4745vtxs3E1cw6MODVDCG6eQiRCjSJpqVPnDj41kcA0=";
    const WRAPPED_FILE_KEY_B64: &str = "AAECAwQFBgcICQoLDA0OD2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d0blpfAzOExRYCxMPH9RLaiOH3O7tDiWtDlGSYI3ELKtUuO2ViDLVlZHg7BtrPB4Pw==";
    const V2_CHUNK_B64: &str = "gIGCg4SFhoeIiYqLHSkAOcbXJ2Lj23sFmHJs5s6zUSwsQP7PkiGuPcQWLP8Ze98S+LZEmKHpvg==";
    const V2_CHECK_B64: &str = "gIGCg4SFhoeIiYqLDSUeKIPMOCDm2ToWyTd56cT3SWkVDdz8hN5rEOcWXeHdv6Oq";

    fn h(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2));
        let mut out = Vec::with_capacity(text.len() / 2);
        let raw = text.as_bytes();
        for i in 0..text.len() / 2 {
            let hi = hex_nibble(raw[i * 2]).unwrap();
            let lo = hex_nibble(raw[i * 2 + 1]).unwrap();
            out.push((hi << 4) | lo);
        }
        out
    }

    fn b64(text: &str) -> Vec<u8> {
        base64_decode(text).expect("测试向量必须是合法 base64")
    }

    fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        out
    }

    /// 派生链与前端一致：PBKDF2 → HKDF → BLAKE3
    #[test]
    fn kat_derivation_chain_matches_frontend() {
        let salt = arr::<SALT_LEN>(&h(SALT_HEX));
        let master = derive_master_key(PASSWORD.as_bytes(), &salt, PBKDF2_ITER).unwrap();
        assert_eq!(hex_encode(&master[..]), MASTER_KEY_HEX, "PBKDF2 输出必须逐字节一致");

        let wrap_key = derive_file_key(&master, &salt).unwrap();
        assert_eq!(hex_encode(&wrap_key[..]), WRAP_KEY_HEX, "HKDF 输出必须逐字节一致");

        let hash = file_hash(&h(CHUNK_PLAIN_HEX)).unwrap();
        assert_eq!(hex_encode(&hash), FILE_HASH_HEX, "BLAKE3 输出必须逐字节一致");
    }

    /// 记录型元数据：密文逐字节一致且可解回
    #[test]
    fn kat_legacy_meta_matches_frontend() {
        let salt = arr::<SALT_LEN>(&h(SALT_HEX));
        let nonce = arr::<NONCE_LEN>(&h(NONCE_HEX));
        let key = h(WRAP_KEY_HEX);
        let plain = h(META_PLAIN_HEX);

        let sealed = seal_meta(&key, &salt, &nonce, &plain).unwrap();
        assert_eq!(sealed, b64(LEGACY_META_B64));

        let opened = open_meta(&key, &sealed).unwrap();
        assert_eq!(opened.as_slice(), plain.as_slice());
        assert_eq!(extract_meta_salt(&sealed).unwrap(), salt);
    }

    /// 记录型块：布局、AD 绑定与明文往返
    #[test]
    fn kat_legacy_chunk_matches_frontend() {
        let salt = arr::<SALT_LEN>(&h(SALT_HEX));
        let nonce = arr::<NONCE_LEN>(&h(NONCE_HEX));
        let key = h(WRAP_KEY_HEX);
        let hash = arr::<FILE_HASH_LEN>(&h(FILE_HASH_HEX));
        let plain = h(CHUNK_PLAIN_HEX);

        let sealed = seal_chunk(&key, &salt, &nonce, 1, 3, &hash, &plain).unwrap();
        assert_eq!(sealed, b64(LEGACY_CHUNK_B64));

        let (seq, total, opened) = open_chunk(&key, &sealed, &hash).unwrap();
        assert_eq!((seq, total), (1, 3));
        assert_eq!(opened.as_slice(), plain.as_slice());

        // 位置或哈希不符必须认证失败
        assert!(matches!(
            open_chunk(&key, &sealed, &[0u8; FILE_HASH_LEN]),
            Err(VencError::Auth)
        ));
        assert!(matches!(
            open_slim_chunk(&key, &sealed[16 + 8..], 2, 3, &hash),
            Err(VencError::Auth)
        ));
    }

    /// 瘦身索引与瘦身块
    #[test]
    fn kat_slim_layouts_match_frontend() {
        let salt = arr::<SALT_LEN>(&h(SALT_HEX));
        let nonce = arr::<NONCE_LEN>(&h(NONCE_HEX));
        let wrap_key = h(WRAP_KEY_HEX);
        let file_key = h(FILE_KEY_HEX);
        let hash = arr::<FILE_HASH_LEN>(&h(FILE_HASH_HEX));
        let plain = h(CHUNK_PLAIN_HEX);

        let slim_meta = seal_slim_meta(&wrap_key, &salt, &nonce, &h(SLIM_META_PLAIN_HEX)).unwrap();
        assert_eq!(slim_meta, b64(SLIM_META_B64));
        assert_eq!(
            open_slim_meta(&wrap_key, &slim_meta).unwrap().as_slice(),
            h(SLIM_META_PLAIN_HEX).as_slice()
        );

        let slim_chunk = seal_slim_chunk(&file_key, &nonce, 0, 2, &hash, &plain).unwrap();
        assert_eq!(slim_chunk, b64(SLIM_CHUNK_B64));
        assert_eq!(
            open_slim_chunk(&file_key, &slim_chunk, 0, 2, &hash).unwrap().as_slice(),
            plain.as_slice()
        );
        // 换块位置必须拒绝
        assert!(matches!(
            open_slim_chunk(&file_key, &slim_chunk, 1, 2, &hash),
            Err(VencError::Auth)
        ));
    }

    /// 缩略图与块集：文件绑定 AD
    #[test]
    fn kat_bound_records_match_frontend() {
        let nonce = arr::<NONCE_LEN>(&h(NONCE_HEX));
        let wrap_key = h(WRAP_KEY_HEX);
        let hash = arr::<FILE_HASH_LEN>(&h(FILE_HASH_HEX));

        let thumb = seal_bound_record(&wrap_key, &nonce, THUMB_AD, &hash, &h(THUMB_PLAIN_HEX)).unwrap();
        assert_eq!(thumb, b64(THUMB_B64));
        assert_eq!(
            open_bound_record(&wrap_key, &thumb, THUMB_AD, &hash).unwrap().as_slice(),
            h(THUMB_PLAIN_HEX).as_slice()
        );
        // 跨记录类型换用必须失败（同一文件的不同记录不可互换）
        assert!(matches!(
            open_bound_record(&wrap_key, &thumb, CHUNK_SET_AD, &hash),
            Err(VencError::Auth)
        ));

        let set = seal_bound_record(&wrap_key, &nonce, CHUNK_SET_AD, &hash, &h(CHUNKSET_PLAIN_HEX)).unwrap();
        assert_eq!(set, b64(CHUNKSET_B64));
        assert_eq!(
            open_bound_record(&wrap_key, &set, CHUNK_SET_AD, &hash).unwrap().as_slice(),
            h(CHUNKSET_PLAIN_HEX).as_slice()
        );
    }

    /// 包裹文件密钥：解封结果与随机密钥逐字节一致
    #[test]
    fn kat_wrapped_file_key_matches_frontend() {
        let salt = arr::<SALT_LEN>(&h(SALT_HEX));
        let nonce = arr::<NONCE_LEN>(&h(WRAP_NONCE_HEX));
        let wrap_key = h(WRAP_KEY_HEX);
        let file_key = arr::<KEY_LEN>(&h(FILE_KEY_HEX));

        let wrapped = seal_wrapped_file_key(&wrap_key, &salt, &nonce, &file_key).unwrap();
        assert_eq!(wrapped, b64(WRAPPED_FILE_KEY_B64));
        assert_eq!(extract_wrapped_salt(&wrapped).unwrap(), salt);

        let opened = open_wrapped_file_key(&wrap_key, &wrapped).unwrap();
        assert_eq!(&opened[..], &file_key[..]);

        // 不同包裹密钥不得解封
        assert!(matches!(
            open_wrapped_file_key(&[0x11u8; KEY_LEN], &wrapped),
            Err(VencError::Auth)
        ));
    }

    /// 文件块 v2 与密码校验块
    #[test]
    fn kat_v2_file_chunks_match_frontend() {
        let master = h(MASTER_KEY_HEX);
        let iv = arr::<V2_IV_LEN>(&h(V2_IV_HEX));

        let sealed = seal_v2_chunk(&master, &iv, &h(V2_PLAIN_HEX)).unwrap();
        assert_eq!(sealed, b64(V2_CHUNK_B64));
        assert_eq!(
            open_v2_chunk(&master, &sealed).unwrap().as_slice(),
            h(V2_PLAIN_HEX).as_slice()
        );

        let check = build_v2_check(&master, &iv).unwrap();
        assert_eq!(check, b64(V2_CHECK_B64));
        assert!(verify_v2_check(&master, &check).unwrap());
        assert!(!verify_v2_check(&[0x22u8; KEY_LEN], &check).unwrap());
    }

    /// 解密侧结构防线：长度不足、空载荷、非法哈希
    #[test]
    fn structural_guards_reject_malformed_inputs() {
        let key = [0x33u8; KEY_LEN];
        assert!(matches!(open_meta(&key, &[]), Err(VencError::Corrupt)));
        assert!(matches!(
            open_chunk(&key, &[0u8; 32], &[0u8; FILE_HASH_LEN]),
            Err(VencError::Corrupt)
        ));
        assert!(matches!(open_v2_chunk(&key, &[0u8; 28]), Err(VencError::Corrupt)));
        assert_eq!(parse_hash_hex("zz").unwrap_err(), VencError::Invalid);
        assert_eq!(parse_hash_hex(&"a".repeat(63)).unwrap_err(), VencError::Invalid);
        assert_eq!(file_hash(&[]).unwrap_err(), VencError::Invalid);
        assert_eq!(
            derive_master_key(b"", &[0u8; SALT_LEN], PBKDF2_ITER).unwrap_err(),
            VencError::Invalid
        );
        assert_eq!(
            derive_master_key(b"pw", &[0u8; SALT_LEN], 0).unwrap_err(),
            VencError::Invalid
        );
    }
}
