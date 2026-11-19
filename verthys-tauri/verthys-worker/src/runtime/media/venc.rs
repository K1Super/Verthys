/*
 * media/venc.rs — VENC 可移植备份容器（原生实现）
 *
 * 布局与前端 `src/lib/crypto.ts` 逐字节一致：
 *   [Outer Header 42B 明文] magic(4) version(2 BE) flags(2 BE) kdf_id(2 BE)
 *                           iterations(4 BE) salt(16) iv(12)
 *   [Wrapped Content Key 48B] AES-256-GCM(content_key, nonce=iv, AD=header)
 *   [Frame]* 帧头 type(1) seq(4 BE) len(4 BE) + nonce(24) + ciphertext+tag(16)
 *            帧密钥 XChaCha20-Poly1305，AD = 帧头(9B) || salt(16B)
 *   [Trailer 帧] frame_count(4 BE) + body_bytes(8 BE)
 *
 * 本模块只做格式与密码学，不访问容器记录；导出与还原 job 负责数据来源。
 * 令牌与内容密钥只在本次调用/本次 job 内驻留，随 Zeroizing 释放清零。
 */

use std::io::Read;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::runtime::budget::PB_PHOTO_MAX_BYTES;
use crate::runtime::content_crypto;

/* ------------------------------------------------------------------ *
 * 格式常量                                                            *
 * ------------------------------------------------------------------ */

pub(crate) const VENC_MAGIC: &[u8; 4] = b"VENC";
pub(crate) const VENC_VERSION: u16 = 3;
pub(crate) const VENC_KDF_ID_PBKDF2_SHA256: u16 = 1;
pub(crate) const VENC_KDF_ITERATIONS: u32 = 600_000;
pub(crate) const VENC_OUTER_HEADER_BYTES: usize = 42;
pub(crate) const VENC_WRAPPED_KEY_BYTES: usize = 48;
pub(crate) const VENC_FRAME_HEADER_BYTES: usize = 9;
pub(crate) const VENC_NONCE_LEN: usize = 24;
pub(crate) const VENC_TAG_LEN: usize = 16;
pub(crate) const VENC_SALT_LEN: usize = 16;
pub(crate) const VENC_IV_LEN: usize = 12;
pub(crate) const VENC_KEY_LEN: usize = 32;
pub(crate) const VENC_TRAILER_PAYLOAD_BYTES: usize = 12;

pub(crate) const VENC_FRAME_TYPE_LIGHT_META: u8 = 1;
pub(crate) const VENC_FRAME_TYPE_CHUNK: u8 = 2;
pub(crate) const VENC_FRAME_TYPE_TRAILER: u8 = 3;

/// 单帧负载上限（与前端 PARSE_MAX_FRAME_BYTES 一致）
pub(crate) const VENC_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// 帧数上限（清单帧 + 块帧，不含尾部帧）
pub(crate) const VENC_MAX_FRAME_COUNT: u32 = 100_000;
/// 容器总字节上限（与 MAX_EXPORT_SINGLE_BYTES 一致）
pub(crate) const VENC_MAX_CONTAINER_BYTES: u64 = 2_147_483_648;
/// 容器前缀（外层头 + 包裹密钥）
pub(crate) const VENC_PREFIX_BYTES: usize = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
/// 单帧固定开销
pub(crate) const VENC_FRAME_OVERHEAD: usize = VENC_FRAME_HEADER_BYTES + VENC_NONCE_LEN + VENC_TAG_LEN;
/// 清单名称/类型/缩略图边界
const LIGHT_META_NAME_MAX_BYTES: usize = 1024;
const LIGHT_META_MIME_MAX_BYTES: usize = 128;
const LIGHT_META_THUMB_MAX_BYTES: usize = 2 * 1024 * 1024;

/* ------------------------------------------------------------------ *
 * 错误                                                                *
 * ------------------------------------------------------------------ */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VencError {
    /// 入参缺失或取值非法
    Invalid,
    /// AEAD 认证失败：令牌错误或数据被篡改
    Auth,
    /// 结构不自洽：长度、序号、字段集合非法
    Corrupt,
    /// 版本或 KDF 标识不支持
    Unsupported,
    /// 容器超过单文件上限
    TooLarge,
    /// 随机源或密码学后端不可用
    Internal,
}

/* ------------------------------------------------------------------ *
 * 清单                                                                *
 * ------------------------------------------------------------------ */

/// 容器清单：字段集合严格为 7 个，未知字段一律拒绝。
///
/// 字段声明顺序与前端 `toLightMeta` 的对象键顺序一致，序列化产物与
/// `JSON.stringify` 同序（便于诊断与测试向量比对）。
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LightMeta {
    pub(crate) name: String,
    pub(crate) mime: String,
    pub(crate) size: u64,
    pub(crate) thumb_b64: String,
    pub(crate) file_hash: String,
    pub(crate) created_at: i64,
    pub(crate) chunk_count: u32,
}

impl LightMeta {
    /// 清单业务校验：与前端 `assertLightMetaShape` 同一契约。
    pub(crate) fn validate(&self) -> Result<(), VencError> {
        if self.name.is_empty() || self.name.len() > LIGHT_META_NAME_MAX_BYTES {
            return Err(VencError::Corrupt);
        }
        if self.mime.len() > LIGHT_META_MIME_MAX_BYTES {
            return Err(VencError::Corrupt);
        }
        if self.size == 0 || self.size > PB_PHOTO_MAX_BYTES {
            return Err(VencError::Corrupt);
        }
        if self.created_at < 0 {
            return Err(VencError::Corrupt);
        }
        if self.chunk_count == 0 || self.chunk_count > VENC_MAX_FRAME_COUNT {
            return Err(VencError::Corrupt);
        }
        if !is_hex64(&self.file_hash) {
            return Err(VencError::Corrupt);
        }
        if !self.thumb_b64.is_empty() {
            let bytes = crate::runtime::protocol::base64_decode(&self.thumb_b64)
                .map_err(|_| VencError::Corrupt)?;
            if bytes.len() > LIGHT_META_THUMB_MAX_BYTES {
                return Err(VencError::Corrupt);
            }
        }
        Ok(())
    }

    pub(crate) fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, VencError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| VencError::Internal)
    }

    pub(crate) fn from_json(payload: &[u8]) -> Result<Self, VencError> {
        let meta: LightMeta =
            serde_json::from_slice(payload).map_err(|_| VencError::Corrupt)?;
        meta.validate()?;
        Ok(meta)
    }
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/* ------------------------------------------------------------------ *
 * 打包                                                                *
 * ------------------------------------------------------------------ */

/// 流式打包器：外层头/包裹密钥一次产出，帧逐段产出。
///
/// 容器总字节在每次产出前累计校验；超限返回 `TooLarge`，调用方中止
/// 暂存文件，不会留下超限产物。
pub(crate) struct VencWriter {
    content_key: Zeroizing<[u8; VENC_KEY_LEN]>,
    salt: [u8; VENC_SALT_LEN],
    seq: u32,
    frame_count: u32,
    body_bytes: u64,
    produced: u64,
    max_bytes: u64,
}

impl VencWriter {
    /// 创建打包器：派生 KEK、生成内容密钥并封装，返回 (writer, 前缀字节)。
    pub(crate) fn new(token: &str) -> Result<(Self, Vec<u8>), VencError> {
        if token.is_empty() {
            return Err(VencError::Invalid);
        }
        let salt: [u8; VENC_SALT_LEN] =
            content_crypto::random_bytes().map_err(|_| VencError::Internal)?;
        let iv: [u8; VENC_IV_LEN] =
            content_crypto::random_bytes().map_err(|_| VencError::Internal)?;
        let content_key: Zeroizing<[u8; VENC_KEY_LEN]> =
            Zeroizing::new(content_crypto::random_bytes().map_err(|_| VencError::Internal)?);

        let header = build_header(&salt, &iv);
        let kek = derive_kek(token, &salt, VENC_KDF_ITERATIONS)?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| VencError::Internal)?;
        let wrapped = cipher
            .encrypt(
                AesNonce::from_slice(&iv),
                Payload {
                    msg: &content_key[..],
                    aad: &header,
                },
            )
            .map_err(|_| VencError::Internal)?;
        if wrapped.len() != VENC_WRAPPED_KEY_BYTES {
            return Err(VencError::Internal);
        }

        let mut prefix = Vec::with_capacity(VENC_PREFIX_BYTES);
        prefix.extend_from_slice(&header);
        prefix.extend_from_slice(&wrapped);

        Ok((
            VencWriter {
                content_key,
                salt,
                seq: 0,
                frame_count: 0,
                body_bytes: 0,
                produced: VENC_PREFIX_BYTES as u64,
                max_bytes: VENC_MAX_CONTAINER_BYTES,
            },
            prefix,
        ))
    }

    /// 写出清单帧。
    pub(crate) fn write_manifest(&mut self, meta: &LightMeta) -> Result<Vec<u8>, VencError> {
        let payload = meta.to_json()?;
        self.write_frame(VENC_FRAME_TYPE_LIGHT_META, &payload)
    }

    /// 写出数据块帧。
    pub(crate) fn write_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, VencError> {
        if chunk.is_empty() {
            return Err(VencError::Invalid);
        }
        self.write_frame(VENC_FRAME_TYPE_CHUNK, chunk)
    }

    /// 写出尾部校验帧；返回的字节必须是容器最后一段。
    pub(crate) fn finish(&mut self) -> Result<Vec<u8>, VencError> {
        let mut payload = Zeroizing::new([0u8; VENC_TRAILER_PAYLOAD_BYTES]);
        payload[..4].copy_from_slice(&self.frame_count.to_be_bytes());
        payload[4..].copy_from_slice(&self.body_bytes.to_be_bytes());
        let frame = encrypt_frame(
            &self.content_key,
            &self.salt,
            VENC_FRAME_TYPE_TRAILER,
            self.seq,
            &payload[..],
        )?;
        self.reserve(frame.len() as u64)?;
        self.seq = self.seq.wrapping_add(1);
        Ok(frame)
    }

    fn write_frame(&mut self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, VencError> {
        if payload.len() > VENC_MAX_FRAME_BYTES {
            return Err(VencError::TooLarge);
        }
        if self.frame_count >= VENC_MAX_FRAME_COUNT {
            return Err(VencError::Invalid);
        }
        let frame = encrypt_frame(
            &self.content_key,
            &self.salt,
            frame_type,
            self.seq,
            payload,
        )?;
        self.reserve(frame.len() as u64)?;
        self.seq = self.seq.wrapping_add(1);
        self.frame_count += 1;
        self.body_bytes = self
            .body_bytes
            .checked_add(payload.len() as u64)
            .ok_or(VencError::TooLarge)?;
        Ok(frame)
    }

    fn reserve(&mut self, bytes: u64) -> Result<(), VencError> {
        let next = self
            .produced
            .checked_add(bytes)
            .ok_or(VencError::TooLarge)?;
        if next > self.max_bytes {
            return Err(VencError::TooLarge);
        }
        self.produced = next;
        Ok(())
    }

    #[cfg(test)]
    fn set_max_bytes(&mut self, max: u64) {
        self.max_bytes = max;
    }
}

fn build_header(salt: &[u8; VENC_SALT_LEN], iv: &[u8; VENC_IV_LEN]) -> [u8; VENC_OUTER_HEADER_BYTES] {
    let mut header = [0u8; VENC_OUTER_HEADER_BYTES];
    header[..4].copy_from_slice(VENC_MAGIC);
    header[4..6].copy_from_slice(&VENC_VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&0u16.to_be_bytes());
    header[8..10].copy_from_slice(&VENC_KDF_ID_PBKDF2_SHA256.to_be_bytes());
    header[10..14].copy_from_slice(&VENC_KDF_ITERATIONS.to_be_bytes());
    header[14..30].copy_from_slice(salt);
    header[30..42].copy_from_slice(iv);
    header
}

fn derive_kek(
    token: &str,
    salt: &[u8; VENC_SALT_LEN],
    iterations: u32,
) -> Result<Zeroizing<[u8; VENC_KEY_LEN]>, VencError> {
    if token.is_empty() || iterations == 0 {
        return Err(VencError::Invalid);
    }
    let mut out = Zeroizing::new([0u8; VENC_KEY_LEN]);
    pbkdf2_hmac::<Sha256>(token.as_bytes(), salt, iterations, &mut out[..]);
    Ok(out)
}

fn frame_header(frame_type: u8, seq: u32, len: u32) -> [u8; VENC_FRAME_HEADER_BYTES] {
    let mut out = [0u8; VENC_FRAME_HEADER_BYTES];
    out[0] = frame_type;
    out[1..5].copy_from_slice(&seq.to_be_bytes());
    out[5..9].copy_from_slice(&len.to_be_bytes());
    out
}

fn frame_ad(frame_type: u8, seq: u32, len: u32, salt: &[u8; VENC_SALT_LEN]) -> [u8; VENC_FRAME_HEADER_BYTES + VENC_SALT_LEN] {
    let mut ad = [0u8; VENC_FRAME_HEADER_BYTES + VENC_SALT_LEN];
    ad[..VENC_FRAME_HEADER_BYTES].copy_from_slice(&frame_header(frame_type, seq, len));
    ad[VENC_FRAME_HEADER_BYTES..].copy_from_slice(salt);
    ad
}

fn encrypt_frame(
    content_key: &[u8; VENC_KEY_LEN],
    salt: &[u8; VENC_SALT_LEN],
    frame_type: u8,
    seq: u32,
    payload: &[u8],
) -> Result<Vec<u8>, VencError> {
    if payload.len() > u32::MAX as usize {
        return Err(VencError::TooLarge);
    }
    let nonce: [u8; VENC_NONCE_LEN] =
        content_crypto::random_bytes().map_err(|_| VencError::Internal)?;
    let ad = frame_ad(frame_type, seq, payload.len() as u32, salt);
    let cipher = XChaCha20Poly1305::new_from_slice(content_key).map_err(|_| VencError::Internal)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &ad,
            },
        )
        .map_err(|_| VencError::Internal)?;

    let mut out = Vec::with_capacity(VENC_FRAME_OVERHEAD + ciphertext.len());
    out.extend_from_slice(&frame_header(frame_type, seq, payload.len() as u32));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/* ------------------------------------------------------------------ *
 * 解析                                                                *
 * ------------------------------------------------------------------ */

/// 解析产出的单帧。
pub(crate) enum VencFrame {
    Manifest(LightMeta),
    Chunk(Zeroizing<Vec<u8>>),
    Trailer { frame_count: u32, body_bytes: u64 },
}

/// 流式解析器：只驻留当前帧，不把整包读入内存。
pub(crate) struct VencReader<R: Read> {
    reader: R,
    content_key: Zeroizing<[u8; VENC_KEY_LEN]>,
    salt: [u8; VENC_SALT_LEN],
    seq: u32,
    bytes_read: u64,
    total_bytes: u64,
    frame_count: u32,
    body_bytes: u64,
    trailer_seen: bool,
}

impl<R: Read> VencReader<R> {
    /// 打开容器：校验头部/封装密钥并解封内容密钥。
    pub(crate) fn open(mut reader: R, total_bytes: u64, token: &str) -> Result<Self, VencError> {
        if token.is_empty() {
            return Err(VencError::Invalid);
        }
        if total_bytes < (VENC_PREFIX_BYTES + VENC_FRAME_OVERHEAD) as u64 {
            return Err(VencError::Corrupt);
        }
        if total_bytes > VENC_MAX_CONTAINER_BYTES {
            return Err(VencError::TooLarge);
        }

        let mut header = [0u8; VENC_OUTER_HEADER_BYTES];
        reader.read_exact(&mut header).map_err(|_| VencError::Corrupt)?;
        if &header[..4] != VENC_MAGIC {
            return Err(VencError::Corrupt);
        }
        let version = u16::from_be_bytes([header[4], header[5]]);
        if version != VENC_VERSION {
            return Err(VencError::Unsupported);
        }
        let flags = u16::from_be_bytes([header[6], header[7]]);
        if flags != 0 {
            return Err(VencError::Corrupt);
        }
        let kdf_id = u16::from_be_bytes([header[8], header[9]]);
        if kdf_id != VENC_KDF_ID_PBKDF2_SHA256 {
            return Err(VencError::Unsupported);
        }
        let iterations = u32::from_be_bytes([header[10], header[11], header[12], header[13]]);
        if !(100_000..=10_000_000).contains(&iterations) {
            return Err(VencError::Corrupt);
        }

        let mut salt = [0u8; VENC_SALT_LEN];
        salt.copy_from_slice(&header[14..30]);
        let iv = &header[30..42];

        let mut wrapped = [0u8; VENC_WRAPPED_KEY_BYTES];
        reader.read_exact(&mut wrapped).map_err(|_| VencError::Corrupt)?;

        let kek = derive_kek(token, &salt, iterations)?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| VencError::Internal)?;
        let plain = cipher
            .decrypt(
                AesNonce::from_slice(iv),
                Payload {
                    msg: &wrapped,
                    aad: &header,
                },
            )
            .map_err(|_| VencError::Auth)?;
        if plain.len() != VENC_KEY_LEN {
            return Err(VencError::Corrupt);
        }
        let mut content_key = Zeroizing::new([0u8; VENC_KEY_LEN]);
        content_key.copy_from_slice(&plain);

        Ok(VencReader {
            reader,
            content_key,
            salt,
            seq: 0,
            bytes_read: VENC_PREFIX_BYTES as u64,
            total_bytes,
            frame_count: 0,
            body_bytes: 0,
            trailer_seen: false,
        })
    }

    /// 读取下一帧；尾部帧之后返回 None。
    pub(crate) fn next_frame(&mut self) -> Result<Option<VencFrame>, VencError> {
        if self.trailer_seen {
            // 尾部帧必须是最后一帧：任何尾随字节都视为结构损坏
            let mut probe = [0u8; 1];
            return match self.reader.read(&mut probe) {
                Ok(0) => Ok(None),
                Ok(_) => Err(VencError::Corrupt),
                Err(_) => Err(VencError::Corrupt),
            };
        }
        if self.bytes_read >= self.total_bytes {
            return Err(VencError::Corrupt);
        }

        let mut header = [0u8; VENC_FRAME_HEADER_BYTES];
        self.reader
            .read_exact(&mut header)
            .map_err(|_| VencError::Corrupt)?;
        self.bytes_read += VENC_FRAME_HEADER_BYTES as u64;

        let frame_type = header[0];
        let seq = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        if !matches!(
            frame_type,
            VENC_FRAME_TYPE_LIGHT_META | VENC_FRAME_TYPE_CHUNK | VENC_FRAME_TYPE_TRAILER
        ) {
            return Err(VencError::Corrupt);
        }
        if seq != self.seq {
            return Err(VencError::Corrupt);
        }
        if len as usize > VENC_MAX_FRAME_BYTES {
            return Err(VencError::Corrupt);
        }
        let frame_body = (VENC_NONCE_LEN + VENC_TAG_LEN) as u64 + len as u64;
        if self
            .bytes_read
            .checked_add(frame_body)
            .map(|end| end > self.total_bytes)
            .unwrap_or(true)
        {
            return Err(VencError::Corrupt);
        }

        let mut nonce = [0u8; VENC_NONCE_LEN];
        self.reader
            .read_exact(&mut nonce)
            .map_err(|_| VencError::Corrupt)?;
        let mut ciphertext = vec![0u8; len as usize + VENC_TAG_LEN];
        self.reader
            .read_exact(&mut ciphertext)
            .map_err(|_| VencError::Corrupt)?;
        self.bytes_read += (VENC_NONCE_LEN + VENC_TAG_LEN) as u64 + len as u64;

        let ad = frame_ad(frame_type, seq, len, &self.salt);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.content_key[..])
            .map_err(|_| VencError::Internal)?;
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &ad,
                },
            )
            .map_err(|_| VencError::Auth)?;
        if plain.len() != len as usize {
            return Err(VencError::Corrupt);
        }

        if frame_type == VENC_FRAME_TYPE_TRAILER {
            if plain.len() != VENC_TRAILER_PAYLOAD_BYTES {
                return Err(VencError::Corrupt);
            }
            self.seq = self.seq.wrapping_add(1);
            self.trailer_seen = true;
            let frame_count = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]);
            let body_bytes = u64::from_be_bytes([
                plain[4], plain[5], plain[6], plain[7], plain[8], plain[9], plain[10], plain[11],
            ]);
            return Ok(Some(VencFrame::Trailer {
                frame_count,
                body_bytes,
            }));
        }

        self.frame_count = self
            .frame_count
            .checked_add(1)
            .ok_or(VencError::Corrupt)?;
        if self.frame_count > VENC_MAX_FRAME_COUNT {
            return Err(VencError::Corrupt);
        }
        self.body_bytes = self
            .body_bytes
            .checked_add(len as u64)
            .ok_or(VencError::Corrupt)?;
        self.seq = self.seq.wrapping_add(1);

        match frame_type {
            VENC_FRAME_TYPE_LIGHT_META => {
                let plain = Zeroizing::new(plain);
                Ok(Some(VencFrame::Manifest(LightMeta::from_json(&plain)?)))
            }
            _ => Ok(Some(VencFrame::Chunk(Zeroizing::new(plain)))),
        }
    }

    /// 尾部帧声明的计数与实际累计值必须一致。
    pub(crate) fn verify_trailer(&self, frame_count: u32, body_bytes: u64) -> Result<(), VencError> {
        if frame_count != self.frame_count || body_bytes != self.body_bytes {
            return Err(VencError::Corrupt);
        }
        if !self.trailer_seen {
            return Err(VencError::Corrupt);
        }
        Ok(())
    }
}

/* ------------------------------------------------------------------ *
 * 单测                                                                *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::protocol::base64_decode;
    use std::io::Cursor;

    const TOKEN: &str = "phase3-venc-test-token";

    fn meta(name: &str, chunk_count: u32, thumb: &str) -> LightMeta {
        LightMeta {
            name: name.to_string(),
            mime: "image/jpeg".to_string(),
            size: 10,
            thumb_b64: thumb.to_string(),
            file_hash: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
                .to_string(),
            created_at: 1_763_500_000_000,
            chunk_count,
        }
    }

    fn pack() -> Vec<u8> {
        let (mut w, prefix) = VencWriter::new(TOKEN).unwrap();
        let mut out = prefix;
        out.extend_from_slice(&w.write_manifest(&meta("a.jpg", 2, "")).unwrap());
        out.extend_from_slice(&w.write_chunk(b"hello-").unwrap());
        out.extend_from_slice(&w.write_chunk(b"world").unwrap());
        out.extend_from_slice(&w.finish().unwrap());
        out
    }

    fn read_all(bytes: &[u8], token: &str) -> Result<(Vec<LightMeta>, Vec<Vec<u8>>), VencError> {
        let mut reader = VencReader::open(Cursor::new(bytes), bytes.len() as u64, token)?;
        let mut metas = Vec::new();
        let mut chunks = Vec::new();
        loop {
            match reader.next_frame()? {
                Some(VencFrame::Manifest(m)) => metas.push(m),
                Some(VencFrame::Chunk(c)) => chunks.push(c.to_vec()),
                Some(VencFrame::Trailer {
                    frame_count,
                    body_bytes,
                }) => {
                    reader.verify_trailer(frame_count, body_bytes)?;
                    assert!(reader.next_frame()?.is_none());
                    break;
                }
                None => break,
            }
        }
        Ok((metas, chunks))
    }

    #[test]
    fn header_layout_matches_frontend_contract() {
        let bytes = pack();
        assert_eq!(&bytes[..4], VENC_MAGIC);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), VENC_VERSION);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0);
        assert_eq!(
            u16::from_be_bytes([bytes[8], bytes[9]]),
            VENC_KDF_ID_PBKDF2_SHA256
        );
        assert_eq!(
            u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            VENC_KDF_ITERATIONS
        );
        assert_eq!(bytes.len() > VENC_PREFIX_BYTES, true);

        // 第一帧头：type=1、seq=0、len=清单 JSON 长度
        let frame = &bytes[VENC_PREFIX_BYTES..];
        assert_eq!(frame[0], VENC_FRAME_TYPE_LIGHT_META);
        assert_eq!(u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]), 0);
        let len = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]) as usize;
        let json = &frame[VENC_FRAME_HEADER_BYTES + VENC_NONCE_LEN
            ..VENC_FRAME_HEADER_BYTES + VENC_NONCE_LEN + len];
        assert!(!json.is_empty());
    }

    #[test]
    fn roundtrip_returns_manifest_and_chunks() {
        let bytes = pack();
        let (metas, chunks) = read_all(&bytes, TOKEN).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "a.jpg");
        assert_eq!(chunks, vec![b"hello-".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn wrong_token_fails_authentication() {
        let bytes = pack();
        assert_eq!(read_all(&bytes, "wrong-token").unwrap_err(), VencError::Auth);
    }

    #[test]
    fn tampering_any_frame_byte_fails_authentication() {
        let mut bytes = pack();
        let index = VENC_PREFIX_BYTES + VENC_FRAME_HEADER_BYTES + VENC_NONCE_LEN + 2;
        bytes[index] ^= 0x01;
        assert_eq!(read_all(&bytes, TOKEN).unwrap_err(), VencError::Auth);
    }

    #[test]
    fn truncated_and_trailing_bytes_are_rejected() {
        let mut bytes = pack();
        bytes.pop();
        assert!(read_all(&bytes, TOKEN).is_err());

        let mut appended = pack();
        appended.push(0);
        assert_eq!(read_all(&appended, TOKEN).unwrap_err(), VencError::Corrupt);
    }

    #[test]
    fn trailer_counts_mismatch_is_rejected() {
        let bytes = pack();
        let mut reader = VencReader::open(Cursor::new(&bytes), bytes.len() as u64, TOKEN).unwrap();
        let mut trailer = None;
        while let Some(frame) = reader.next_frame().unwrap() {
            if let VencFrame::Trailer {
                frame_count,
                body_bytes,
            } = frame
            {
                trailer = Some((frame_count, body_bytes));
            }
        }
        let (count, body) = trailer.expect("必须有尾部帧");
        assert!(reader.verify_trailer(count + 1, body).is_err());
        assert!(reader.verify_trailer(count, body + 1).is_err());
    }

    #[test]
    fn manifest_shape_rejects_unknown_or_missing_fields() {
        let mut value = serde_json::json!({
            "name": "a.jpg",
            "mime": "image/jpeg",
            "size": 10,
            "thumbB64": "",
            "fileHash": "a".repeat(64),
            "createdAt": 1,
            "chunkCount": 1,
        });
        assert!(LightMeta::from_json(value.to_string().as_bytes()).is_ok());

        value["extra"] = serde_json::json!(1);
        assert_eq!(
            LightMeta::from_json(value.to_string().as_bytes()).unwrap_err(),
            VencError::Corrupt
        );
        value.as_object_mut().unwrap().remove("extra");
        value.as_object_mut().unwrap().remove("mime");
        assert_eq!(
            LightMeta::from_json(value.to_string().as_bytes()).unwrap_err(),
            VencError::Corrupt
        );
    }

    #[test]
    fn manifest_limits_match_frontend_contract() {
        let mut m = meta("a.jpg", 1, "");
        assert!(m.validate().is_ok());

        m.name = String::new();
        assert_eq!(m.validate().unwrap_err(), VencError::Corrupt);
        m = meta("a.jpg", 1, "");
        m.mime = "m".repeat(129);
        assert_eq!(m.validate().unwrap_err(), VencError::Corrupt);
        m = meta("a.jpg", 1, "");
        m.size = 0;
        assert_eq!(m.validate().unwrap_err(), VencError::Corrupt);
        m = meta("a.jpg", 1, "");
        m.file_hash = "zz".repeat(32);
        assert_eq!(m.validate().unwrap_err(), VencError::Corrupt);
        m = meta("a.jpg", 0, "");
        assert_eq!(m.validate().unwrap_err(), VencError::Corrupt);
        m = meta("a.jpg", 1, "not-base64!");
        assert_eq!(m.validate().unwrap_err(), VencError::Corrupt);
    }

    #[test]
    fn chunk_and_whitespace_thumbnail_are_accepted() {
        let thumb = crate::runtime::protocol::base64_encode(b"thumb");
        let m = meta("a.jpg", 1, &thumb);
        assert!(m.validate().is_ok());
        assert_eq!(base64_decode(&m.thumb_b64).unwrap(), b"thumb");
    }

    #[test]
    fn sequential_frame_sequence_is_enforced() {
        let bytes = pack();
        let mut corrupted = bytes.clone();
        // 第二帧（第一个块帧）的 seq 改为 9：帧头在 AD 内，必然认证失败
        let first_frame_len = {
            let f = &bytes[VENC_PREFIX_BYTES..];
            let len = u32::from_be_bytes([f[5], f[6], f[7], f[8]]) as usize;
            VENC_FRAME_OVERHEAD + len
        };
        let second = VENC_PREFIX_BYTES + first_frame_len;
        corrupted[second + 1..second + 5].copy_from_slice(&9u32.to_be_bytes());
        assert_eq!(read_all(&corrupted, TOKEN).unwrap_err(), VencError::Corrupt);
    }

    #[test]
    fn container_limit_is_enforced_before_emitting() {
        let (mut w, _prefix) = VencWriter::new(TOKEN).unwrap();
        w.set_max_bytes(VENC_PREFIX_BYTES as u64 + 10);
        assert_eq!(
            w.write_manifest(&meta("a.jpg", 1, "")).unwrap_err(),
            VencError::TooLarge
        );
    }

    #[test]
    fn unsupported_version_and_kdf_are_rejected() {
        let bytes = pack();
        let mut version = bytes.clone();
        version[4..6].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            read_all(&version, TOKEN).unwrap_err(),
            VencError::Unsupported
        );

        let mut kdf = bytes.clone();
        kdf[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(read_all(&kdf, TOKEN).unwrap_err(), VencError::Unsupported);

        let mut iterations = bytes.clone();
        iterations[10..14].copy_from_slice(&99_999u32.to_be_bytes());
        assert_eq!(
            read_all(&iterations, TOKEN).unwrap_err(),
            VencError::Corrupt
        );
    }

    #[test]
    fn oversized_container_is_rejected_before_parsing() {
        let bytes = pack();
        assert!(matches!(
            VencReader::open(
                Cursor::new(&bytes),
                VENC_MAX_CONTAINER_BYTES + 1,
                TOKEN
            ),
            Err(VencError::TooLarge)
        ));
    }
}
