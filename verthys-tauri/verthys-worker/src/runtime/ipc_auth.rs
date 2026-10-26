/*
 * runtime/ipc_auth.rs — worker 侧 IPC 认证加密
 *
 * 职责边界：从 stdin 首行读取宿主下发的会话主密钥、会话标识与挑战值，
 * 派生方向子密钥，解密校验入站请求信封，为就绪、响应与进度消息
 * 生成加密信封并给出持有证明。不接触业务数据与密钥内容。
 *
 * 关键约束：
 *   - 首行缺失或非法必须失败关闭，禁止以无认证模式启动；
 *   - 会话标识不匹配即拒绝，杜绝跨会话重放；
 *   - 首行必须最先读取：引导行之后才允许出现业务信封；
 *   - 各通道序号严格连续，请求关联号必须与当前请求一致；
 *   - 密钥与明文缓冲使用可清零容器，不进入日志。
 *
 * 线程安全：序号使用原子变量；进度回调线程与主循环共享同一实例。
 */

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::protocol::{base64_decode, base64_encode};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SESSION_ID_LEN: usize = 16;
const CHALLENGE_LEN: usize = 32;
const PROTOCOL_VERSION: u8 = 2;
const AAD_PREFIX: &[u8] = b"VERTHYS-IPC-V2\x00";
const READY_PROOF_PREFIX: &[u8] = b"verthys/ipc/ready-proof\x00";
const CH_REQUEST: &str = "q";
const CH_RESPONSE: &str = "r";
const CH_PROGRESS: &str = "p";
const CH_BOOTSTRAP: &str = "b";

/// 引导行单行上限：仅承载会话材料，正常长度约 250 字节。
const BOOTSTRAP_MAX_BYTES: usize = 4096;

#[derive(Serialize)]
struct OutEnvelope<'a> {
    v: u8,
    ch: &'a str,
    sid: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    ct: &'a str,
}

#[derive(Deserialize)]
struct InEnvelope<'a> {
    v: u8,
    ch: &'a str,
    sid: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    ct: &'a str,
}

#[derive(Deserialize)]
struct Bootstrap<'a> {
    v: u8,
    ch: &'a str,
    sid: &'a str,
    key: &'a str,
    challenge: &'a str,
}

struct WorkerIpc {
    session_id: [u8; SESSION_ID_LEN],
    challenge: Zeroizing<[u8; CHALLENGE_LEN]>,
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
    fn from_parts(
        mut master: [u8; KEY_LEN],
        session_id: [u8; SESSION_ID_LEN],
        mut challenge: [u8; CHALLENGE_LEN],
    ) -> Result<Self, String> {
        let request_key = derive_key(&master, b"verthys/ipc/request")?;
        let response_key = derive_key(&master, b"verthys/ipc/response")?;
        let progress_key = derive_key(&master, b"verthys/ipc/progress")?;
        let state = Self {
            session_id,
            challenge: Zeroizing::new(challenge),
            request_key: Zeroizing::new(request_key),
            response_key: Zeroizing::new(response_key),
            progress_key: Zeroizing::new(progress_key),
            last_request_seq: AtomicU64::new(0),
            response_seq: AtomicU64::new(0),
            progress_seq: AtomicU64::new(0),
            current_request: AtomicU64::new(0),
        };
        master.zeroize();
        challenge.zeroize();
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
        let sid = hex_decode_fixed::<SESSION_ID_LEN>(envelope.sid, "sid")?;
        if !ct_eq(&sid, &self.session_id) {
            return Err("IPC 会话标识不匹配".to_string());
        }
        let nonce = hex_decode_fixed::<NONCE_LEN>(envelope.nonce, "nonce")?;
        if nonce[4..] != envelope.seq.to_be_bytes() {
            return Err("IPC nonce 与序号不匹配".to_string());
        }
        let ciphertext = decode_b64(envelope.ct)?;
        let aad = aad_bytes(1, &sid, envelope.seq, envelope.re);
        let payload = decrypt(&self.request_key[..], &nonce, &aad, &ciphertext)
            .map_err(|_| "IPC 请求解密认证失败".to_string())?;

        if !accept_sequence(&self.last_request_seq, envelope.seq) {
            return Err(format!("IPC 请求序号失配: {}", envelope.seq));
        }

        Ok((envelope.seq, payload))
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

        let nonce = build_nonce(seq)?;
        let aad = aad_bytes(channel_byte, &self.session_id, seq, reply_to);
        let ciphertext = encrypt(key, &nonce, &aad, payload.as_bytes())?;
        let sid_hex = hex_encode(&self.session_id);
        let nonce_hex = hex_encode(&nonce);
        let ct_b64 = base64_encode(&ciphertext);
        let envelope = OutEnvelope {
            v: PROTOCOL_VERSION,
            ch: channel,
            sid: &sid_hex,
            seq,
            re: reply_to,
            nonce: &nonce_hex,
            ct: &ct_b64,
        };
        serde_json::to_string(&envelope).map_err(|e| format!("IPC 信封序列化失败: {}", e))
    }

    /// 就绪证明：绑定会话标识与宿主本会话新生成的挑战值。
    fn ready_proof(&self) -> Result<[u8; 32], String> {
        let mut data =
            Vec::with_capacity(READY_PROOF_PREFIX.len() + self.session_id.len() + CHALLENGE_LEN);
        data.extend_from_slice(READY_PROOF_PREFIX);
        data.extend_from_slice(&self.session_id);
        data.extend_from_slice(&self.challenge[..]);
        let tag = hmac_sign(&self.response_key[..], &data)?;
        data.zeroize();
        Ok(tag)
    }
}

/// 从 stdin 首行读取引导材料并初始化认证状态。
///
/// 必须在加载业务 DLL 之前调用；成功后引导行立即清零。
/// 读取失败、长度超限或字段非法一律返回错误，由入口进程退出。
pub(crate) fn init_from_stdin() -> Result<(), String> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    let mut guard = stdin.lock();
    let mut line = Zeroizing::new(String::new());
    let read = guard
        .read_line(&mut line)
        .map_err(|e| format!("读取 IPC 引导行失败: {}", e))?;
    if read == 0 {
        return Err("缺少 IPC 引导行".to_string());
    }
    if read > BOOTSTRAP_MAX_BYTES {
        return Err("IPC 引导行超长".to_string());
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);

    let bootstrap: Bootstrap<'_> =
        serde_json::from_str(trimmed).map_err(|_| "IPC 引导行格式非法".to_string())?;
    if bootstrap.v != PROTOCOL_VERSION || bootstrap.ch != CH_BOOTSTRAP {
        return Err("IPC 引导行版本或通道非法".to_string());
    }
    let session_id = hex_decode_fixed::<SESSION_ID_LEN>(bootstrap.sid, "sid")?;
    let challenge = hex_decode_fixed::<CHALLENGE_LEN>(bootstrap.challenge, "challenge")?;
    let decoded = hex_decode(bootstrap.key)?;
    if decoded.len() != KEY_LEN {
        return Err("IPC 会话密钥长度非法".to_string());
    }
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    master.copy_from_slice(&decoded);
    let mut decoded = Zeroizing::new(decoded);

    let state = WorkerIpc::from_parts(*master, session_id, challenge)?;
    decoded.zeroize();
    master.zeroize();

    IPC.set(state)
        .map_err(|_| "IPC 认证状态重复初始化".to_string())
}

fn ipc() -> Result<&'static WorkerIpc, String> {
    IPC.get().ok_or_else(|| "IPC 认证状态未初始化".to_string())
}

/// 解密校验请求信封并返回请求序号与原始载荷 JSON。
pub(crate) fn verify_request(line: &str) -> Result<(u64, String), String> {
    ipc()?.verify_request(line)
}

/// 记录当前正在处理的请求序号，供进度消息填写关联号。
pub(crate) fn set_current_request(seq: u64) {
    if let Ok(state) = ipc() {
        state.current_request.store(seq, Ordering::SeqCst);
    }
}

/// 签署就绪信号（响应通道，关联号 0），载荷内附带持有证明。
pub(crate) fn seal_ready(payload: &str) -> Result<String, String> {
    let state = ipc()?;
    let mut value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| format!("IPC 就绪载荷解析失败: {}", e))?;
    let proof = state.ready_proof()?;
    value["proof"] = serde_json::Value::String(hex_encode(&proof));
    let body = serde_json::to_string(&value).map_err(|e| format!("IPC 就绪载荷封装失败: {}", e))?;
    state.seal(CH_RESPONSE, 0, &body)
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
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| "HMAC 密钥被拒绝".to_string())?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn aad_bytes(channel: u8, session_id: &[u8], seq: u64, reply_to: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(AAD_PREFIX.len() + 1 + session_id.len() + 16);
    data.extend_from_slice(AAD_PREFIX);
    data.push(channel);
    data.extend_from_slice(session_id);
    data.extend_from_slice(&seq.to_be_bytes());
    data.extend_from_slice(&reply_to.to_be_bytes());
    data
}

/// nonce 构造：4 字节随机前缀 + 8 字节大端序号。
///
/// 同一会话内序号严格递增，nonce 因此在 (密钥, nonce) 维度上唯一。
fn build_nonce(seq: u64) -> Result<[u8; NONCE_LEN], String> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce[..4]).map_err(|e| format!("IPC nonce 生成失败: {}", e))?;
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    Ok(nonce)
}

fn encrypt(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "IPC 密钥长度非法".to_string())?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "IPC 载荷加密失败".to_string())
}

fn decrypt(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "IPC 密钥长度非法".to_string())?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "IPC 载荷解密失败".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "IPC 载荷不是合法 UTF-8".to_string())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
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

fn decode_b64(text: &str) -> Result<Vec<u8>, String> {
    base64_decode(text).map_err(|_| "IPC 信封字段不是合法 base64".to_string())
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

    const TEST_MASTER: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const TEST_SID: [u8; SESSION_ID_LEN] = [0x22; SESSION_ID_LEN];
    const TEST_CHALLENGE: [u8; CHALLENGE_LEN] = [0x33; CHALLENGE_LEN];

    fn state() -> WorkerIpc {
        WorkerIpc::from_parts(TEST_MASTER, TEST_SID, TEST_CHALLENGE).unwrap()
    }

    /// 模拟宿主生成请求信封（仅测试）。
    fn host_request(state: &WorkerIpc, seq: u64, payload: &str) -> String {
        let nonce = build_nonce(seq).unwrap();
        let aad = aad_bytes(1, &state.session_id, seq, 0);
        let ct = encrypt(&state.request_key[..], &nonce, &aad, payload.as_bytes()).unwrap();
        serde_json::to_string(&OutEnvelope {
            v: PROTOCOL_VERSION,
            ch: CH_REQUEST,
            sid: &hex_encode(&state.session_id),
            seq,
            re: 0,
            nonce: &hex_encode(&nonce),
            ct: &base64_encode(&ct),
        })
        .unwrap()
    }

    /// 模拟宿主解密响应信封（仅测试）。
    fn host_open(state: &WorkerIpc, line: &str) -> Result<(u64, u64, String), String> {
        let envelope: InEnvelope<'_> =
            serde_json::from_str(line).map_err(|e| format!("解析失败: {}", e))?;
        let sid = hex_decode_fixed::<SESSION_ID_LEN>(envelope.sid, "sid")?;
        if !ct_eq(&sid, &state.session_id) {
            return Err("会话标识不匹配".to_string());
        }
        let channel = match envelope.ch {
            CH_RESPONSE => 2u8,
            CH_PROGRESS => 3u8,
            _ => return Err("通道非法".to_string()),
        };
        let key: &[u8] = if channel == 2 {
            &state.response_key[..]
        } else {
            &state.progress_key[..]
        };
        let nonce = hex_decode_fixed::<NONCE_LEN>(envelope.nonce, "nonce")?;
        let ct = decode_b64(envelope.ct)?;
        let aad = aad_bytes(channel, &sid, envelope.seq, envelope.re);
        let payload = decrypt(key, &nonce, &aad, &ct)?;
        Ok((envelope.seq, envelope.re, payload))
    }

    #[test]
    fn ipc_request_roundtrip_and_replay_rejected() {
        let state = state();
        let line = host_request(&state, 1, r#"{"op":"ping"}"#);
        let (seq, payload) = state.verify_request(&line).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(payload, r#"{"op":"ping"}"#);
        assert!(state.verify_request(&line).is_err());
    }

    #[test]
    fn ipc_rejects_tampered_request() {
        let state = state();
        let line = host_request(&state, 1, r#"{"op":"ping"}"#);
        let mut value: serde_json::Value = serde_json::from_str(&line).unwrap();
        let mut ct = value["ct"].as_str().unwrap().to_string();
        let last = ct.pop().unwrap();
        ct.push(if last == 'A' { 'B' } else { 'A' });
        value["ct"] = serde_json::json!(ct);
        assert!(state
            .verify_request(&serde_json::to_string(&value).unwrap())
            .is_err());
    }

    #[test]
    fn ipc_rejects_wrong_direction_and_gap() {
        let state = state();
        let response = state.seal(CH_RESPONSE, 0, r#"{"ok":true}"#).unwrap();
        assert!(state.verify_request(&response).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&host_request(&state, 1, r#"{"op":"ping"}"#)).unwrap();
        assert!(state
            .verify_request(&serde_json::to_string(&value).unwrap())
            .is_ok());
        value["seq"] = serde_json::json!(3);
        assert!(state
            .verify_request(&serde_json::to_string(&value).unwrap())
            .is_err());
    }

    #[test]
    fn ipc_rejects_foreign_session() {
        let state = state();
        let mut sid = TEST_SID;
        sid[0] ^= 0xFF;
        let foreign = WorkerIpc::from_parts(TEST_MASTER, sid, TEST_CHALLENGE).unwrap();
        let line = host_request(&foreign, 1, r#"{"op":"ping"}"#);
        assert!(state.verify_request(&line).is_err());
    }

    #[test]
    fn ipc_rejects_payload_sequence_mismatch_to_nonce() {
        let state = state();
        let line = host_request(&state, 1, r#"{"op":"ping"}"#);
        let mut value: serde_json::Value = serde_json::from_str(&line).unwrap();
        let nonce = value["nonce"].as_str().unwrap().to_string();
        let mut bytes = hex_decode(&nonce).unwrap();
        bytes[7] ^= 0x01;
        value["nonce"] = serde_json::json!(hex_encode(&bytes));
        assert!(state
            .verify_request(&serde_json::to_string(&value).unwrap())
            .is_err());
    }

    #[test]
    fn ipc_response_and_progress_are_sealed() {
        let state = state();
        state.current_request.store(9, Ordering::SeqCst);
        let response = state.seal(CH_RESPONSE, 9, r#"{"ok":true}"#).unwrap();
        let progress = state.seal(CH_PROGRESS, 9, r#"{"op":"unlock_progress"}"#).unwrap();
        assert!(!response.contains(r#""ok":true"#), "响应明文不得出现在线协议中");
        let (seq, re, payload) = host_open(&state, &response).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(re, 9);
        assert_eq!(payload, r#"{"ok":true}"#);
        let (_, re, payload) = host_open(&state, &progress).unwrap();
        assert_eq!(re, 9);
        assert_eq!(payload, r#"{"op":"unlock_progress"}"#);
    }

    #[test]
    fn ipc_ready_proof_matches_host_expectation() {
        let state = state();
        let line = state
            .seal(CH_RESPONSE, 0, r#"{"ok":true,"op":"ready"}"#)
            .unwrap();
        let (seq, re, payload) = host_open(&state, &line).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(re, 0);
        /* 证明算法与宿主一致：HMAC(响应密钥, 前缀||会话标识||挑战值)。 */
        let mut data = Vec::new();
        data.extend_from_slice(READY_PROOF_PREFIX);
        data.extend_from_slice(&TEST_SID);
        data.extend_from_slice(&TEST_CHALLENGE);
        let expected = hmac_sign(&state.response_key[..], &data).unwrap();
        assert_eq!(state.ready_proof().unwrap(), expected);
        assert!(payload.contains("ready"));
    }

    #[test]
    fn ipc_hex_roundtrip() {
        let bytes = [0x00, 0x0F, 0xA5, 0xFF];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes.to_vec());
    }
}
