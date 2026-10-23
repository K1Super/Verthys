/*
 * infrastructure/ipc_secure.rs — 主进程 ↔ worker 认证信道
 *
 * 职责边界：
 *   - 生成会话主密钥，派生请求/响应/进度三个方向子密钥；
 *   - 封装/校验带序号、关联号与随机 nonce 的 HMAC-SHA256 信封；
 *   - 提供共享内存载荷的认证原语。
 *
 * 安全约束：
 *   - 信封校验失败必须失败关闭，禁止回退到明文透传；
 *   - 序号在通道内严格连续，关联号必须匹配当前请求；
 *   - 密钥不进入日志、错误文本或进程命令行。
 *
 * 线程安全：
 *   - 序号使用原子变量；本模块无共享可变映射。
 */

use crate::util::crypto::{ct_eq, hmac_sign};
use serde_json::value::RawValue;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// 会话主密钥长度（字节）
pub const SESSION_KEY_LEN: usize = 32;

/// 宿主向 worker 传递主密钥的环境变量名
pub const ENV_SESSION_KEY: &str = "VERTHYS_IPC_KEY";

/// 每条消息的随机 nonce 长度（字节）
const NONCE_LEN: usize = 16;

/// 信封协议版本
const PROTOCOL_VERSION: u8 = 1;

/// 签名原文固定前缀，隔离其他协议的 HMAC 输入
const MAC_PREFIX: &[u8] = b"VERTHYS-IPC\x00";

const CH_REQUEST: &str = "q";
const CH_RESPONSE: &str = "r";
const CH_PROGRESS: &str = "p";

/// 入站信封所属通道
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Response,
    Progress,
}

/// 已通过签名与序号校验的信封
#[derive(Debug)]
pub struct OpenedLine {
    pub channel: Channel,
    pub seq: u64,
    pub reply_to: u64,
    pub payload: String,
}

/// 出站信封。`payload` 以原始 JSON 片段嵌入，避免二次编码膨胀。
#[derive(serde::Serialize)]
struct OutEnvelope<'a> {
    v: u8,
    ch: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    mac: &'a str,
    payload: &'a RawValue,
}

/// 入站信封。`payload` 借用原始字节，签名校验使用未重编码的内容。
#[derive(serde::Deserialize)]
struct InEnvelope<'a> {
    v: u8,
    ch: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    mac: &'a str,
    payload: &'a RawValue,
}

/// 安全 IPC 信道：持有主密钥、方向子密钥与收发序号。
pub struct IpcSecureChannel {
    master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    request_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    response_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    progress_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    send_seq: AtomicU64,
    last_response_seq: AtomicU64,
    last_progress_seq: AtomicU64,
}

impl IpcSecureChannel {
    /// 创建新会话：CSPRNG 生成主密钥并派生子密钥。
    pub fn new() -> Result<Self, String> {
        let mut master = [0u8; SESSION_KEY_LEN];
        /* 密钥生成失败不得降级为可预测材料，必须失败关闭。 */
        getrandom::getrandom(&mut master).map_err(|e| format!("生成 IPC 会话密钥失败: {}", e))?;
        Self::from_master(master)
    }

    /// 使用给定主密钥构造信道。
    ///
    /// 仅用于测试与恢复场景；调用方负责不在日志中输出密钥。
    pub fn from_master(mut master: [u8; SESSION_KEY_LEN]) -> Result<Self, String> {
        let request_key = derive_key(&master, b"verthys/ipc/request")?;
        let response_key = derive_key(&master, b"verthys/ipc/response")?;
        let progress_key = derive_key(&master, b"verthys/ipc/progress")?;
        let channel = Self {
            master: Zeroizing::new(master),
            request_key: Zeroizing::new(request_key),
            response_key: Zeroizing::new(response_key),
            progress_key: Zeroizing::new(progress_key),
            send_seq: AtomicU64::new(0),
            last_response_seq: AtomicU64::new(0),
            last_progress_seq: AtomicU64::new(0),
        };
        master.zeroize();
        Ok(channel)
    }

    /// 主密钥十六进制文本，用于通过子进程环境变量传递。
    ///
    /// 调用方必须用可清零容器持有返回值。
    pub fn master_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex_encode(&*self.master))
    }

    /// 封装并签名一条请求，返回分配到的序号与线文本。
    pub fn sign_request(&self, payload: &str) -> Result<(u64, String), String> {
        let seq = self.send_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let line = self.seal(CH_REQUEST, &self.request_key[..], seq, 0, payload)?;
        Ok((seq, line))
    }

    /// 校验一条响应或进度消息。
    ///
    /// 校验顺序：字段合法性 → 签名 → 序号连续性。签名先于序号判断，
    /// 避免伪造消息推进接收窗口。
    pub fn open_line(&self, line: &str) -> Result<OpenedLine, String> {
        let envelope: InEnvelope<'_> =
            serde_json::from_str(line).map_err(|e| format!("IPC 信封解析失败: {}", e))?;
        if envelope.v != PROTOCOL_VERSION {
            return Err("IPC 信封版本不匹配".to_string());
        }

        let (channel, key, counter) = match envelope.ch {
            CH_RESPONSE => (
                Channel::Response,
                &self.response_key,
                &self.last_response_seq,
            ),
            CH_PROGRESS => (
                Channel::Progress,
                &self.progress_key,
                &self.last_progress_seq,
            ),
            _ => return Err("IPC 信封通道非法".to_string()),
        };

        let nonce = hex_decode_fixed::<NONCE_LEN>(envelope.nonce, "nonce")?;
        let received_mac = hex_decode_fixed::<32>(envelope.mac, "mac")?;
        let payload_bytes = envelope.payload.get().as_bytes();
        let expected_mac = mac_input(
            channel_byte(channel),
            envelope.seq,
            envelope.re,
            &nonce,
            payload_bytes,
        );
        let actual = hmac_sign(&key[..], &expected_mac)?;
        if !ct_eq(&actual, &received_mac) {
            return Err("IPC 签名校验失败".to_string());
        }

        if !accept_sequence(counter, envelope.seq) {
            return Err(format!("IPC 序号失配: {}", envelope.seq));
        }

        Ok(OpenedLine {
            channel,
            seq: envelope.seq,
            reply_to: envelope.re,
            payload: envelope.payload.get().to_string(),
        })
    }

    /// 构造并签名一条出站信封。
    fn seal(
        &self,
        channel: &str,
        key: &[u8],
        seq: u64,
        reply_to: u64,
        payload: &str,
    ) -> Result<String, String> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| format!("生成 IPC nonce 失败: {}", e))?;
        let nonce_hex = hex_encode(&nonce);
        let mac_bytes = hmac_sign(
            key,
            &mac_input(
                channel_byte_of(channel)?,
                seq,
                reply_to,
                &nonce,
                payload.as_bytes(),
            ),
        )?;
        let mac_hex = hex_encode(&mac_bytes);

        let raw = RawValue::from_string(payload.to_string())
            .map_err(|e| format!("IPC 载荷封装失败: {}", e))?;
        let envelope = OutEnvelope {
            v: PROTOCOL_VERSION,
            ch: channel,
            seq,
            re: reply_to,
            nonce: &nonce_hex,
            mac: &mac_hex,
            payload: &raw,
        };
        serde_json::to_string(&envelope).map_err(|e| format!("IPC 信封序列化失败: {}", e))
    }
}

impl Drop for IpcSecureChannel {
    fn drop(&mut self) {
        self.master.zeroize();
        self.request_key.zeroize();
        self.response_key.zeroize();
        self.progress_key.zeroize();
    }
}

/// 派生方向子密钥。
fn derive_key(
    master: &[u8; SESSION_KEY_LEN],
    label: &[u8],
) -> Result<[u8; SESSION_KEY_LEN], String> {
    let tag = hmac_sign(master, label)?;
    let mut key = [0u8; SESSION_KEY_LEN];
    key.copy_from_slice(&tag);
    Ok(key)
}

/// 签名原文拼接。
fn mac_input(channel: u8, seq: u64, reply_to: u64, nonce: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(MAC_PREFIX.len() + 1 + 8 + 8 + nonce.len() + payload.len());
    data.extend_from_slice(MAC_PREFIX);
    data.push(channel);
    data.extend_from_slice(&seq.to_be_bytes());
    data.extend_from_slice(&reply_to.to_be_bytes());
    data.extend_from_slice(nonce);
    data.extend_from_slice(payload);
    data
}

fn channel_byte(channel: Channel) -> u8 {
    match channel {
        Channel::Response => 2,
        Channel::Progress => 3,
    }
}

fn channel_byte_of(channel: &str) -> Result<u8, String> {
    match channel {
        CH_REQUEST => Ok(1),
        CH_RESPONSE => Ok(2),
        CH_PROGRESS => Ok(3),
        _ => Err("IPC 信封通道非法".to_string()),
    }
}

/// 严格序号推进：只接受上一序号加一。
fn accept_sequence(counter: &AtomicU64, seq: u64) -> bool {
    let mut current = counter.load(Ordering::SeqCst);
    loop {
        if seq != current + 1 {
            return false;
        }
        match counter.compare_exchange(current, seq, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn hex_decode_fixed<const N: usize>(text: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex_decode(text)?;
    if bytes.len() != N {
        return Err(format!("IPC 信封字段长度非法: {}", field));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub(crate) fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    hex::decode(text)
}

// =============================================================================
// SHM 载荷认证原语
// =============================================================================
//
// 命名共享内存仅绑定当前用户可读写，但同用户下其他进程仍可能打开并篡改
// 映射内容。worker 写入数据后在数据区尾部追加 HMAC-SHA256 标签，主进程
// 读回时用同一密钥核验。

/// SHM 载荷认证块长度（与 worker 端共用同一契约常量）
pub use super::shm_schema::SHM_AUTH_BLOCK_LEN;

/// 计算 SHM 载荷的 HMAC-SHA256 标签。
pub fn shm_auth_compute(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let tag = hmac_sign(key, data)?;
    Ok(tag.to_vec())
}

/// 常量时间校验 SHM 载荷标签；长度不符直接拒绝。
pub fn shm_auth_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    if tag.len() != SHM_AUTH_BLOCK_LEN {
        return false;
    }
    match hmac_sign(key, data) {
        Ok(expected) => ct_eq(&expected, tag),
        Err(_) => false,
    }
}

/// 内部十六进制编解码，避免为常量转换引入额外依赖。
mod hex {
    const HEX_TABLE: &[u8] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut buf = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            buf.push(HEX_TABLE[(byte >> 4) as usize] as char);
            buf.push(HEX_TABLE[(byte & 0x0F) as usize] as char);
        }
        buf
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("十六进制字符串长度必须为偶数".to_string());
        }
        let mut output = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let (pairs, _) = bytes.as_chunks::<2>();
        for pair in pairs {
            let high = (pair[0] as char).to_digit(16).ok_or("非法十六进制字符")?;
            let low = (pair[1] as char).to_digit(16).ok_or("非法十六进制字符")?;
            output.push((high * 16 + low) as u8);
        }
        Ok(output)
    }
}

// =============================================================================
// 单元测试
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_for(channel: &str, key: &[u8], seq: u64, reply_to: u64, payload: &str) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("CSPRNG 不可用");
        let nonce_hex = hex_encode(&nonce);
        let mac = hmac_sign(
            key,
            &mac_input(
                channel_byte_of(channel).unwrap(),
                seq,
                reply_to,
                &nonce,
                payload.as_bytes(),
            ),
        )
        .unwrap();
        let raw = RawValue::from_string(payload.to_string()).unwrap();
        serde_json::to_string(&OutEnvelope {
            v: PROTOCOL_VERSION,
            ch: channel,
            seq,
            re: reply_to,
            nonce: &nonce_hex,
            mac: &hex_encode(&mac),
            payload: &raw,
        })
        .unwrap()
    }

    #[test]
    fn test_request_sign_and_response_verify() {
        let host = IpcSecureChannel::new().unwrap();
        let (seq, request) = host.sign_request(r#"{"op":"ping"}"#).unwrap();
        assert_eq!(seq, 1);

        let parsed: InEnvelope<'_> = serde_json::from_str(&request).unwrap();
        assert_eq!(parsed.ch, "q");
        assert_eq!(parsed.re, 0);

        let response = envelope_for("r", &host.response_key[..], 1, seq, r#"{"ok":true}"#);
        let opened = host.open_line(&response).unwrap();
        assert_eq!(opened.channel, Channel::Response);
        assert_eq!(opened.reply_to, seq);
        assert_eq!(opened.payload, r#"{"ok":true}"#);
    }

    #[test]
    fn test_reject_tampered_payload() {
        let host = IpcSecureChannel::new().unwrap();
        let response = envelope_for("r", &host.response_key[..], 1, 1, r#"{"ok":true}"#);
        let mut value: serde_json::Value = serde_json::from_str(&response).unwrap();
        value["payload"] = serde_json::json!({"ok": false});
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(host.open_line(&tampered).is_err());
    }

    #[test]
    fn test_reject_wrong_key() {
        let host = IpcSecureChannel::new().unwrap();
        let other = IpcSecureChannel::new().unwrap();
        let response = envelope_for("r", &other.response_key[..], 1, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_reject_replayed_sequence() {
        let host = IpcSecureChannel::new().unwrap();
        let response = envelope_for("r", &host.response_key[..], 1, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_ok());
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_reject_out_of_order_sequence() {
        let host = IpcSecureChannel::new().unwrap();
        let response = envelope_for("r", &host.response_key[..], 3, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_progress_channel_independent_sequence() {
        let host = IpcSecureChannel::new().unwrap();
        let progress = envelope_for(
            "p",
            &host.progress_key[..],
            1,
            7,
            r#"{"op":"unlock_progress"}"#,
        );
        let response = envelope_for("r", &host.response_key[..], 1, 7, r#"{"ok":true}"#);
        let opened_progress = host.open_line(&progress).unwrap();
        let opened_response = host.open_line(&response).unwrap();
        assert_eq!(opened_progress.channel, Channel::Progress);
        assert_eq!(opened_response.channel, Channel::Response);
    }

    #[test]
    fn test_reject_wrong_direction_channel() {
        let host = IpcSecureChannel::new().unwrap();
        let request = envelope_for("q", &host.request_key[..], 1, 0, r#"{"op":"ping"}"#);
        assert!(host.open_line(&request).is_err());
    }

    #[test]
    fn test_reject_foreign_protocol_version() {
        let host = IpcSecureChannel::new().unwrap();
        let line = envelope_for("r", &host.response_key[..], 1, 1, r#"{"ok":true}"#);
        let mut value: serde_json::Value = serde_json::from_str(&line).unwrap();
        value["v"] = serde_json::json!(2);
        let mutated = serde_json::to_string(&value).unwrap();
        assert!(host.open_line(&mutated).is_err());
    }

    #[test]
    fn test_hex_codec_consistency() {
        let raw_bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex_str = hex_encode(&raw_bytes);
        assert_eq!(hex_str, "0123456789abcdef");
        assert_eq!(hex_decode(&hex_str).unwrap(), raw_bytes.to_vec());
    }

    #[test]
    fn test_shm_auth_roundtrip() {
        let key = [0x5Au8; SHM_AUTH_BLOCK_LEN];
        let data = b"shared memory payload bytes";
        let tag = shm_auth_compute(&key, data).unwrap();
        assert_eq!(tag.len(), SHM_AUTH_BLOCK_LEN);
        assert!(shm_auth_verify(&key, data, &tag));
    }

    #[test]
    fn test_shm_auth_reject_single_byte_tamper() {
        let key = [0x11u8; SHM_AUTH_BLOCK_LEN];
        let mut data = b"original payload".to_vec();
        let tag = shm_auth_compute(&key, &data).unwrap();
        data[0] ^= 0xFF;
        assert!(!shm_auth_verify(&key, &data, &tag));
    }

    #[test]
    fn test_shm_auth_reject_wrong_key() {
        let key = [0x22u8; SHM_AUTH_BLOCK_LEN];
        let wrong = [0x33u8; SHM_AUTH_BLOCK_LEN];
        let data = b"payload";
        let tag = shm_auth_compute(&key, data).unwrap();
        assert!(!shm_auth_verify(&wrong, data, &tag));
    }

    #[test]
    fn test_shm_auth_reject_bad_tag_len() {
        let key = [0x44u8; SHM_AUTH_BLOCK_LEN];
        assert!(!shm_auth_verify(&key, b"payload", b"short"));
        assert!(!shm_auth_verify(&key, b"payload", b""));
    }
}
