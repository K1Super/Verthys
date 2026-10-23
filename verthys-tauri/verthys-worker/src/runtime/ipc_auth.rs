/*
 * runtime/ipc_auth.rs — worker 侧 IPC 认证
 *
 * 职责边界：读取宿主下发的会话主密钥，派生方向子密钥，校验入站请求信封，
 * 为就绪、响应与进度消息生成签名信封。不接触业务数据与密钥内容。
 *
 * 关键约束：
 *   - 缺失或非法会话密钥必须失败关闭，禁止以无认证模式启动；
 *   - 签名校验收到的原始 JSON 字节，禁止先解析再重编码；
 *   - 各通道序号严格连续，请求关联号必须与当前请求一致；
 *   - 密钥与签名缓冲使用可清零容器，不进入日志。
 *
 * 线程安全：序号使用原子变量；进度回调线程与主循环共享同一实例。
 */

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

/// 宿主传入会话主密钥的环境变量名
pub(crate) const ENV_SESSION_KEY: &str = "VERTHYS_IPC_KEY";

const NONCE_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PROTOCOL_VERSION: u8 = 1;
const MAC_PREFIX: &[u8] = b"VERTHYS-IPC\x00";
const CH_REQUEST: &str = "q";
const CH_RESPONSE: &str = "r";
const CH_PROGRESS: &str = "p";

#[derive(Serialize)]
struct OutEnvelope<'a> {
    v: u8,
    ch: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    mac: &'a str,
    payload: &'a RawValue,
}

#[derive(Deserialize)]
struct InEnvelope<'a> {
    v: u8,
    ch: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    mac: &'a str,
    payload: &'a RawValue,
}

struct WorkerIpc {
    request_key: Zeroizing<[u8; KEY_LEN]>,
    response_key: Zeroizing<[u8; KEY_LEN]>,
    progress_key: Zeroizing<[u8; KEY_LEN]>,
    last_request_seq: AtomicU64,
    response_seq: AtomicU64,
    progress_seq: AtomicU64,
    current_request: AtomicU64,
}

static IPC: OnceLock<WorkerIpc> = OnceLock::new();

impl WorkerIpc {
    fn from_master(mut master: [u8; KEY_LEN]) -> Result<Self, String> {
        let request_key = derive_key(&master, b"verthys/ipc/request")?;
        let response_key = derive_key(&master, b"verthys/ipc/response")?;
        let progress_key = derive_key(&master, b"verthys/ipc/progress")?;
        let state = Self {
            request_key: Zeroizing::new(request_key),
            response_key: Zeroizing::new(response_key),
            progress_key: Zeroizing::new(progress_key),
            last_request_seq: AtomicU64::new(0),
            response_seq: AtomicU64::new(0),
            progress_seq: AtomicU64::new(0),
            current_request: AtomicU64::new(0),
        };
        master.zeroize();
        Ok(state)
    }

    fn verify_request(&self, line: &str) -> Result<(u64, String), String> {
        let envelope: InEnvelope<'_> =
            serde_json::from_str(line).map_err(|e| format!("IPC 请求信封解析失败: {}", e))?;
        if envelope.v != PROTOCOL_VERSION {
            return Err("IPC 请求信封版本不匹配".to_string());
        }
        if envelope.ch != CH_REQUEST || envelope.re != 0 {
            return Err("IPC 请求通道或关联号非法".to_string());
        }

        let nonce = hex_decode_fixed::<NONCE_LEN>(envelope.nonce, "nonce")?;
        let received_mac = hex_decode_fixed::<32>(envelope.mac, "mac")?;
        let signed = mac_input(
            1,
            envelope.seq,
            envelope.re,
            &nonce,
            envelope.payload.get().as_bytes(),
        );
        if !hmac_verify(&self.request_key[..], &signed, &received_mac) {
            return Err("IPC 请求签名校验失败".to_string());
        }
        if !accept_sequence(&self.last_request_seq, envelope.seq) {
            return Err(format!("IPC 请求序号失配: {}", envelope.seq));
        }

        Ok((envelope.seq, envelope.payload.get().to_string()))
    }

    fn seal(&self, channel: &str, reply_to: u64, payload: &str) -> Result<String, String> {
        let (key, seq, channel_byte): (&[u8], u64, u8) = match channel {
            CH_RESPONSE => (
                &self.response_key[..],
                self.response_seq.fetch_add(1, Ordering::SeqCst) + 1,
                2,
            ),
            CH_PROGRESS => (
                &self.progress_key[..],
                self.progress_seq.fetch_add(1, Ordering::SeqCst) + 1,
                3,
            ),
            _ => return Err("IPC 出站通道非法".to_string()),
        };

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| format!("IPC nonce 生成失败: {}", e))?;
        let nonce_hex = hex_encode(&nonce);
        let mac = hmac_sign(
            key,
            &mac_input(channel_byte, seq, reply_to, &nonce, payload.as_bytes()),
        )?;
        let mac_hex = hex_encode(&mac);
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

/// 从环境变量读取主密钥并初始化认证状态。
///
/// 必须在加载业务 DLL 之前调用；成功返回后环境变量已删除。
pub(crate) fn init_from_env() -> Result<(), String> {
    let key_text = Zeroizing::new(
        std::env::var(ENV_SESSION_KEY).map_err(|_| "缺少 IPC 会话密钥".to_string())?,
    );
    std::env::remove_var(ENV_SESSION_KEY);

    let decoded = hex_decode(&key_text)?;
    if decoded.len() != KEY_LEN {
        return Err("IPC 会话密钥长度非法".to_string());
    }
    let mut master = [0u8; KEY_LEN];
    master.copy_from_slice(&decoded);
    let state = WorkerIpc::from_master(master)?;
    master.zeroize();

    IPC.set(state)
        .map_err(|_| "IPC 认证状态重复初始化".to_string())
}

fn ipc() -> Result<&'static WorkerIpc, String> {
    IPC.get().ok_or_else(|| "IPC 认证状态未初始化".to_string())
}

/// 校验请求信封并返回请求序号与原始载荷 JSON。
pub(crate) fn verify_request(line: &str) -> Result<(u64, String), String> {
    ipc()?.verify_request(line)
}

/// 记录当前正在处理的请求序号，供进度消息填写关联号。
pub(crate) fn set_current_request(seq: u64) {
    if let Ok(state) = ipc() {
        state.current_request.store(seq, Ordering::SeqCst);
    }
}

/// 签署就绪信号（响应通道，关联号 0）。
pub(crate) fn seal_ready(payload: &str) -> Result<String, String> {
    ipc()?.seal(CH_RESPONSE, 0, payload)
}

/// 签署普通响应；`reply_to` 为对应请求序号。
pub(crate) fn seal_response(payload: &str, reply_to: u64) -> Result<String, String> {
    ipc()?.seal(CH_RESPONSE, reply_to, payload)
}

/// 签署解锁进度；关联号取当前请求序号。
pub(crate) fn seal_progress(payload: &str) -> Result<String, String> {
    let state = ipc()?;
    let reply_to = state.current_request.load(Ordering::SeqCst);
    state.seal(CH_PROGRESS, reply_to, payload)
}

fn derive_key(master: &[u8; KEY_LEN], label: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let tag = hmac_sign(master, label)?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&tag);
    Ok(key)
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "HMAC 密钥被拒绝".to_string())?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_TABLE: &[u8] = b"0123456789abcdef";
    let mut buf = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        buf.push(HEX_TABLE[(byte >> 4) as usize] as char);
        buf.push(HEX_TABLE[(byte & 0x0F) as usize] as char);
    }
    buf
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("十六进制字符串长度必须为偶数".to_string());
    }
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16).ok_or("非法十六进制字符")?;
        let low = (pair[1] as char).to_digit(16).ok_or("非法十六进制字符")?;
        output.push((high * 16 + low) as u8);
    }
    Ok(output)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_envelope(key: &[u8], ch: &str, seq: u64, re: u64, payload: &str) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).unwrap();
        let nonce_hex = hex_encode(&nonce);
        let channel_byte = match ch {
            CH_REQUEST => 1,
            CH_RESPONSE => 2,
            CH_PROGRESS => 3,
            _ => 0,
        };
        let mac = hmac_sign(
            key,
            &mac_input(channel_byte, seq, re, &nonce, payload.as_bytes()),
        )
        .unwrap();
        let raw = RawValue::from_string(payload.to_string()).unwrap();
        serde_json::to_string(&OutEnvelope {
            v: PROTOCOL_VERSION,
            ch,
            seq,
            re,
            nonce: &nonce_hex,
            mac: &hex_encode(&mac),
            payload: &raw,
        })
        .unwrap()
    }

    #[test]
    fn ipc_request_roundtrip_and_replay_rejected() {
        let state = WorkerIpc::from_master([0x11; KEY_LEN]).unwrap();
        let line = peer_envelope(&state.request_key[..], CH_REQUEST, 1, 0, r#"{"op":"ping"}"#);
        let (seq, payload) = state.verify_request(&line).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(payload, r#"{"op":"ping"}"#);
        assert!(state.verify_request(&line).is_err());
    }

    #[test]
    fn ipc_rejects_tampered_request() {
        let state = WorkerIpc::from_master([0x22; KEY_LEN]).unwrap();
        let line = peer_envelope(&state.request_key[..], CH_REQUEST, 1, 0, r#"{"op":"ping"}"#);
        let mut value: serde_json::Value = serde_json::from_str(&line).unwrap();
        value["payload"] = serde_json::json!({"op":"shutdown"});
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(state.verify_request(&tampered).is_err());
    }

    #[test]
    fn ipc_rejects_wrong_direction_and_gap() {
        let state = WorkerIpc::from_master([0x44; KEY_LEN]).unwrap();
        let wrong_channel =
            peer_envelope(&state.response_key[..], CH_RESPONSE, 1, 0, r#"{"ok":true}"#);
        assert!(state.verify_request(&wrong_channel).is_err());

        let gap = peer_envelope(&state.request_key[..], CH_REQUEST, 2, 0, r#"{"op":"ping"}"#);
        assert!(state.verify_request(&gap).is_err());
    }

    #[test]
    fn ipc_response_and_progress_are_sealed() {
        let state = WorkerIpc::from_master([0x33; KEY_LEN]).unwrap();
        state.current_request.store(9, Ordering::SeqCst);
        let response = state.seal(CH_RESPONSE, 9, r#"{"ok":true}"#).unwrap();
        let progress = state.seal(CH_PROGRESS, 9, r#"{"op":"unlock_progress"}"#).unwrap();
        assert!(response.contains("\"ch\":\"r\""));
        assert!(progress.contains("\"ch\":\"p\""));
        assert!(progress.contains("\"re\":9"));
    }

    #[test]
    fn ipc_hex_roundtrip() {
        let bytes = [0x00, 0x0F, 0xA5, 0xFF];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes.to_vec());
    }
}
