/* content_crypto.rs — 文件块 v2 的密码学原语（AES-256-GCM + PBKDF2）
 *
 * 职责边界：只承载无状态的密码学运算与布局编解码。照片/文件内容的外层
 * 加密由 C 层 v4 分片（Verthys_V4ChunkSeal/Open）承担，本模块只保留
 * "每个文件独立口令"的内层封装：
 *   - 派生：PBKDF2-SHA256(文件口令, 文件盐, iterations) → 32 字节 AES 密钥
 *   - 布局：iv(12) ‖ 密文+tag（AES-256-GCM，无附加数据）
 *   - 校验：固定明文的一次 AEAD（v2_check），常量时间比较
 *
 * 本模块不持有任何长期密钥，也不访问磁盘。
 *
 * 错误语义：认证失败与结构不自洽使用不同变体，但调用方不得把差异
 * 透出给用户——口令错误与数据篡改必须不可区分。
 */

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/* ------------------------------------------------------------------ *
 * 布局常量                                                            *
 * ------------------------------------------------------------------ */

/// 文件盐长度（128 位）
pub(crate) const SALT_LEN: usize = 16;
/// AES-GCM 认证标签长度
pub(crate) const TAG_LEN: usize = 16;
/// 对称密钥长度（256 位）
pub(crate) const KEY_LEN: usize = 32;
/// BLAKE3 文件哈希长度
pub(crate) const FILE_HASH_LEN: usize = 32;
/// 文件块 v2 的 iv 长度（AES-GCM 96 位）
pub(crate) const V2_IV_LEN: usize = 12;
/// 文件口令派生的缺省迭代次数（调用方未指定时使用）
pub(crate) const PBKDF2_ITER: u32 = 150_000;
/// 文件块 v2 的最小可接受迭代次数：低于此值视为头部被篡改
pub(crate) const V2_MIN_ITERATIONS: u32 = 10_000;
/// 文件块 v2 迭代次数上限：拒绝恶意参数导致的超长派生
pub(crate) const V2_MAX_ITERATIONS: u32 = 10_000_000;
/// 文件级密码校验固定明文
pub(crate) const FILE_CHECK_PLAINTEXT: &[u8] = b"verthys-filecheck-v1";

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
    /// 全库轮换作业进行中：源库只读
    RotatePending,
    /// 模块未解锁（与 Locked 区分：调用方需要先输入模块口令）
    ModuleLocked,
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
/// 生产路径的文件哈希由前端计算后随请求传入，worker 只校验格式与绑定
/// 关系；本函数仅用于测试与向量校验。
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
/// iterations 由调用方给出：读取侧必须按记录携带的历史值执行，
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
 * 向量由前端同源原语生成：同一 (口令, 盐, iv, 明文) 下本模块的密文
 * 必须逐字节相同，且能解回同一明文。因此单向向量同时覆盖
 * “前端加密 → worker 解密”与“worker 加密 → 前端解密”。
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::protocol::base64_decode;

    const PASSWORD: &str = "photo-module-pass-测试";
    const SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const FILE_HASH_HEX: &str = "e4542a4b9329829805e7bd66fa7f09dd9fe1eb65e1b9bdde770dca628b6199b0";
    const CHUNK_PLAIN_HEX: &str = "4348554e4b2d504c41494e544558542d303132333435363738392d414243444546";
    const MASTER_KEY_HEX: &str = "edffbddcb3290af05eabd593b6366a8d421af28e5d0ffe41dfe0ee885fcdf9ba";
    const V2_PLAIN_HEX: &str = "66696c652d626c6f636b2d76322d706c61696e746578742d303031";
    const V2_IV_HEX: &str = "808182838485868788898a8b";
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

    /// PBKDF2 与 BLAKE3 的确定性向量：与前端实现逐字节一致
    #[test]
    fn kat_derivation_chain_matches_frontend() {
        let salt = arr::<SALT_LEN>(&h(SALT_HEX));
        let master = derive_master_key(PASSWORD.as_bytes(), &salt, PBKDF2_ITER).unwrap();
        assert_eq!(hex_encode(&master[..]), MASTER_KEY_HEX, "PBKDF2 输出必须逐字节一致");

        let hash = file_hash(&h(CHUNK_PLAIN_HEX)).unwrap();
        assert_eq!(hex_encode(&hash), FILE_HASH_HEX, "BLAKE3 输出必须逐字节一致");
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
