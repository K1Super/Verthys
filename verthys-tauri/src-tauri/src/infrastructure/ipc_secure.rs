/*
 * infrastructure/ipc_secure.rs — 主进程 ↔ worker 认证加密信道
 *
 * 职责边界：
 *   - 生成会话主密钥、会话标识与握手挑战值，派生请求/响应/进度三个方向子密钥；
 *   - 生成引导行（密钥经匿名管道交付 worker，不进入进程环境块）；
 *   - 封装/校验 AES-256-GCM 信封：通道、序号、关联号与会话标识全部进入 AAD；
 *   - 校验 worker 就无法预知的新鲜挑战给出的持有证明；
 *   - 提供共享内存载荷的认证原语。
 *
 * 安全约束：
 *   - 信封校验失败必须失败关闭，禁止回退到明文透传；
 *   - 未完成就绪握手前不得发送任何业务请求，避免向未认证对端泄露口令；
 *   - 序号在通道内严格连续，关联号必须匹配当前请求；
 *   - 会话标识不匹配即拒绝，杜绝跨会话重放；
 *   - 密钥不进入日志、错误文本或进程命令行。
 *
 * 线程安全：
 *   - 序号与握手标志使用原子变量；本模块无共享可变映射。
 */

use crate::util::crypto::{ct_eq, hmac_sign};
use base64::Engine as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// 会话主密钥长度（字节）
pub const SESSION_KEY_LEN: usize = 32;

/// 会话标识长度（字节）
pub const SESSION_ID_LEN: usize = 16;

/// 握手挑战值长度（字节）
const CHALLENGE_LEN: usize = 32;

/// AES-GCM nonce 长度（字节）
const NONCE_LEN: usize = 12;

/// 信封协议版本
const PROTOCOL_VERSION: u8 = 2;

/// AAD 固定前缀，隔离其他协议的 AEAD 输入
const AAD_PREFIX: &[u8] = b"VERTHYS-IPC-V2\x00";

/// 就绪证明固定前缀，隔离其他协议的 HMAC 输入
const READY_PROOF_PREFIX: &[u8] = b"verthys/ipc/ready-proof\x00";

const CH_REQUEST: &str = "q";
const CH_RESPONSE: &str = "r";
const CH_PROGRESS: &str = "p";

/// 引导行通道标识（仅首次写入 stdin 使用）
const CH_BOOTSTRAP: &str = "b";

/// 入站信封所属通道
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Response,
    Progress,
}

/// 已通过解密与序号校验的信封
#[derive(Debug)]
pub struct OpenedLine {
    pub channel: Channel,
    pub seq: u64,
    pub reply_to: u64,
    pub payload: String,
}

/// 出站信封。载荷为 AES-256-GCM 密文，明文不落在管道上。
#[derive(serde::Serialize)]
struct OutEnvelope<'a> {
    v: u8,
    ch: &'a str,
    sid: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    ct: &'a str,
}

/// 入站信封。密文与 nonce 以文本形式进入，解密前不做任何业务解析。
#[derive(serde::Deserialize)]
struct InEnvelope<'a> {
    v: u8,
    ch: &'a str,
    sid: &'a str,
    seq: u64,
    re: u64,
    nonce: &'a str,
    ct: &'a str,
}

/// 就绪证明载荷（worker → 宿主）。
#[derive(serde::Deserialize)]
struct ReadyPayload<'a> {
    ok: bool,
    op: &'a str,
    proof: &'a str,
}

/// 安全 IPC 信道：持有主密钥、方向子密钥、会话标识与收发序号。
pub struct IpcSecureChannel {
    master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    session_id: [u8; SESSION_ID_LEN],
    challenge: Zeroizing<[u8; CHALLENGE_LEN]>,
    request_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    response_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    progress_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    send_seq: AtomicU64,
    last_response_seq: AtomicU64,
    last_progress_seq: AtomicU64,
    ready_verified: AtomicBool,
}

impl IpcSecureChannel {
    /// 创建新会话：CSPRNG 生成主密钥、会话标识与挑战值。
    pub fn new() -> Result<Self, String> {
        let mut master = [0u8; SESSION_KEY_LEN];
        let mut session_id = [0u8; SESSION_ID_LEN];
        let mut challenge = [0u8; CHALLENGE_LEN];
        /* 随机源失败不得降级为可预测材料，必须失败关闭。 */
        getrandom::getrandom(&mut master).map_err(|e| format!("生成 IPC 会话密钥失败: {}", e))?;
        getrandom::getrandom(&mut session_id).map_err(|e| format!("生成 IPC 会话标识失败: {}", e))?;
        getrandom::getrandom(&mut challenge).map_err(|e| format!("生成 IPC 挑战值失败: {}", e))?;
        Self::from_parts(master, session_id, challenge)
    }

    fn from_parts(
        mut master: [u8; SESSION_KEY_LEN],
        session_id: [u8; SESSION_ID_LEN],
        mut challenge: [u8; CHALLENGE_LEN],
    ) -> Result<Self, String> {
        let request_key = derive_key(&master, b"verthys/ipc/request")?;
        let response_key = derive_key(&master, b"verthys/ipc/response")?;
        let progress_key = derive_key(&master, b"verthys/ipc/progress")?;
        let channel = Self {
            master: Zeroizing::new(master),
            session_id,
            challenge: Zeroizing::new(challenge),
            request_key: Zeroizing::new(request_key),
            response_key: Zeroizing::new(response_key),
            progress_key: Zeroizing::new(progress_key),
            send_seq: AtomicU64::new(0),
            last_response_seq: AtomicU64::new(0),
            last_progress_seq: AtomicU64::new(0),
            ready_verified: AtomicBool::new(false),
        };
        master.zeroize();
        challenge.zeroize();
        Ok(channel)
    }

    /// 生成引导行：密钥、会话标识与挑战值经匿名管道交付 worker。
    ///
    /// 仅可写入一次，且必须先于任何业务信封。返回值必须由调用方清零。
    pub fn bootstrap_line(&self) -> Result<Zeroizing<String>, String> {
        let line = serde_json::json!({
            "v": PROTOCOL_VERSION,
            "ch": CH_BOOTSTRAP,
            "sid": hex_encode(&self.session_id),
            "key": hex_encode(&*self.master),
            "challenge": hex_encode(&*self.challenge),
        })
        .to_string();
        Ok(Zeroizing::new(line))
    }

    /// 封装并签名一条请求，返回分配到的序号与线文本。
    ///
    /// 未完成就绪握手时拒绝发送，防止业务口令进入未认证对端。
    pub fn sign_request(&self, payload: &str) -> Result<(u64, String), String> {
        if !self.ready_verified.load(Ordering::SeqCst) {
            return Err("IPC 握手未完成，拒绝发送业务请求".to_string());
        }
        let seq = self.send_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let line = self.seal(CH_REQUEST, &self.request_key[..], seq, 0, payload)?;
        Ok((seq, line))
    }

    /// 校验就绪响应并验证 worker 的密钥持有证明。
    ///
    /// 证明覆盖本会话新生成的挑战值：会话开始前录制的就绪行无法通过。
    /// 校验通过后置位握手标志，业务请求方可发送。
    pub fn verify_ready(&self, opened: &OpenedLine) -> Result<(), String> {
        if opened.channel != Channel::Response || opened.reply_to != 0 {
            return Err("IPC 就绪信号通道或关联号非法".to_string());
        }
        let ready: ReadyPayload<'_> =
            serde_json::from_str(&opened.payload).map_err(|e| format!("IPC 就绪载荷解析失败: {}", e))?;
        if !ready.ok || ready.op != "ready" {
            return Err("IPC 就绪载荷语义非法".to_string());
        }
        let received = hex_decode_fixed::<32>(ready.proof, "proof")?;
        let expected = ready_proof(&self.response_key[..], &self.session_id, &self.challenge[..])?;
        if !ct_eq(&expected, &received) {
            return Err("IPC 就绪证明校验失败".to_string());
        }
        self.ready_verified.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// 校验一条响应或进度消息。
    ///
    /// 校验顺序：字段合法性 → 会话标识 → 解密认证 → 序号连续性。
    /// 解密先于序号判断，避免伪造消息推进接收窗口。
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

        let sid = hex_decode_fixed::<SESSION_ID_LEN>(envelope.sid, "sid")?;
        if !ct_eq(&sid, &self.session_id) {
            return Err("IPC 会话标识不匹配".to_string());
        }
        /* 关联号为 0 的响应只允许作为就绪信号出现一次。 */
        if channel == Channel::Response
            && envelope.re == 0
            && self.ready_verified.load(Ordering::SeqCst)
        {
            return Err("IPC 就绪信号重复出现".to_string());
        }
        if channel == Channel::Response
            && envelope.re != 0
            && !self.ready_verified.load(Ordering::SeqCst)
        {
            return Err("IPC 握手未完成，拒绝业务响应".to_string());
        }

        let nonce = hex_decode_fixed::<NONCE_LEN>(envelope.nonce, "nonce")?;
        if nonce[4..] != envelope.seq.to_be_bytes() {
            return Err("IPC nonce 与序号不匹配".to_string());
        }
        let ciphertext = decode_b64(envelope.ct, "ct")?;
        let aad = aad_bytes(channel_byte(channel), &sid, envelope.seq, envelope.re);
        let payload = decrypt(&key[..], &nonce, &aad, &ciphertext)
            .map_err(|_| "IPC 信封解密认证失败".to_string())?;

        if !accept_sequence(counter, envelope.seq) {
            return Err(format!("IPC 序号失配: {}", envelope.seq));
        }

        Ok(OpenedLine {
            channel,
            seq: envelope.seq,
            reply_to: envelope.re,
            payload,
        })
    }

    /// 构造并加密一条出站信封。
    fn seal(
        &self,
        channel: &str,
        key: &[u8],
        seq: u64,
        reply_to: u64,
        payload: &str,
    ) -> Result<String, String> {
        let nonce = build_nonce(seq)?;
        let aad = aad_bytes(channel_byte_of(channel)?, &self.session_id, seq, reply_to);
        let ciphertext = encrypt(key, &nonce, &aad, payload.as_bytes())?;
        let sid_hex = hex_encode(&self.session_id);
        let nonce_hex = hex_encode(&nonce);
        let ct_b64 = encode_b64(&ciphertext);
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
}

impl Drop for IpcSecureChannel {
    fn drop(&mut self) {
        self.master.zeroize();
        self.challenge.zeroize();
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

/// 就绪证明：绑定会话标识与本会话挑战值。
fn ready_proof(key: &[u8], session_id: &[u8], challenge: &[u8]) -> Result<[u8; 32], String> {
    let mut data = Vec::with_capacity(READY_PROOF_PREFIX.len() + session_id.len() + challenge.len());
    data.extend_from_slice(READY_PROOF_PREFIX);
    data.extend_from_slice(session_id);
    data.extend_from_slice(challenge);
    let tag = hmac_sign(key, &data)?;
    data.zeroize();
    Ok(tag)
}

/// AEAD 附加认证数据：通道、会话标识、序号与关联号。
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
/// 同一会话内序号严格递增，nonce 因此在 (密钥, nonce) 维度上唯一，
/// 不依赖随机碰撞概率。
fn build_nonce(seq: u64) -> Result<[u8; NONCE_LEN], String> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce[..4]).map_err(|e| format!("生成 IPC nonce 失败: {}", e))?;
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    Ok(nonce)
}

fn encrypt(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
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
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
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

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(text: &str, field: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| format!("IPC 信封字段不是合法 base64: {}", field))
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
        for pair in bytes.as_chunks::<2>().0 {
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

    /// 测试用对端（模拟 worker）：共享同一主密钥/会话标识/挑战值。
    impl IpcSecureChannel {
        fn test_peer(&self) -> Self {
            Self::from_parts(
                *self.master,
                self.session_id,
                *self.challenge,
            )
            .expect("测试对端构造失败")
        }

        /// 模拟 worker 解密请求信封（仅测试）。
        fn open_request_for_test(&self, line: &str) -> Result<(u64, String), String> {
            let envelope: InEnvelope<'_> =
                serde_json::from_str(line).map_err(|e| format!("解析失败: {}", e))?;
            if envelope.ch != CH_REQUEST || envelope.re != 0 || envelope.v != PROTOCOL_VERSION {
                return Err("请求信封字段非法".to_string());
            }
            let sid = hex_decode_fixed::<SESSION_ID_LEN>(envelope.sid, "sid")?;
            if !ct_eq(&sid, &self.session_id) {
                return Err("会话标识不匹配".to_string());
            }
            let nonce = hex_decode_fixed::<NONCE_LEN>(envelope.nonce, "nonce")?;
            let ciphertext = decode_b64(envelope.ct, "ct")?;
            let aad = aad_bytes(1, &sid, envelope.seq, envelope.re);
            let payload = decrypt(&self.request_key[..], &nonce, &aad, &ciphertext)?;
            Ok((envelope.seq, payload))
        }

        /// 模拟 worker 生成就绪行（仅测试）。
        fn ready_line_for_test(&self, proof_challenge: &[u8; CHALLENGE_LEN]) -> String {
            let proof = ready_proof(&self.response_key[..], &self.session_id, proof_challenge)
                .expect("证明计算失败");
            let payload = serde_json::json!({
                "ok": true,
                "op": "ready",
                "proof": hex_encode(&proof),
            })
            .to_string();
            self.seal(CH_RESPONSE, &self.response_key[..], 1, 0, &payload)
                .expect("就绪行封装失败")
        }

        /// 模拟 worker 生成一条响应（仅测试）。
        fn response_for_test(&self, seq: u64, reply_to: u64, payload: &str) -> String {
            self.seal(CH_RESPONSE, &self.response_key[..], seq, reply_to, payload)
                .expect("响应封装失败")
        }

        /// 模拟 worker 生成一条进度（仅测试）。
        fn progress_for_test(&self, seq: u64, reply_to: u64, payload: &str) -> String {
            self.seal(CH_PROGRESS, &self.progress_key[..], seq, reply_to, payload)
                .expect("进度封装失败")
        }
    }

    /// 构造已完成握手的宿主信道与对端。
    fn handshaken() -> (IpcSecureChannel, IpcSecureChannel) {
        let host = IpcSecureChannel::new().unwrap();
        let peer = host.test_peer();
        let ready = peer.ready_line_for_test(&host.challenge);
        let opened = host.open_line(&ready).unwrap();
        host.verify_ready(&opened).unwrap();
        (host, peer)
    }

    #[test]
    fn test_ready_handshake_and_verified() {
        let (host, peer) = handshaken();
        assert!(host.ready_verified.load(Ordering::SeqCst));

        let (seq, request) = host.sign_request(r#"{"op":"ping"}"#).unwrap();
        assert_eq!(seq, 1);
        let (peer_seq, payload) = peer.open_request_for_test(&request).unwrap();
        assert_eq!(peer_seq, seq);
        assert_eq!(payload, r#"{"op":"ping"}"#);
    }

    #[test]
    fn test_ready_rejects_stale_challenge() {
        let host = IpcSecureChannel::new().unwrap();
        let peer = host.test_peer();
        /* 用会话开始前就固定的挑战值伪造就绪：必须拒绝。 */
        let stale = [0xAAu8; CHALLENGE_LEN];
        let ready = peer.ready_line_for_test(&stale);
        let opened = host.open_line(&ready).unwrap();
        assert!(host.verify_ready(&opened).is_err());
        assert!(!host.ready_verified.load(Ordering::SeqCst));
    }

    #[test]
    fn test_ready_rejects_tampered_proof() {
        let host = IpcSecureChannel::new().unwrap();
        let peer = host.test_peer();
        let proof = ready_proof(&peer.response_key[..], &peer.session_id, &host.challenge[..]).unwrap();
        let mut bad = proof;
        bad[0] ^= 0xFF;
        let payload = serde_json::json!({
            "ok": true,
            "op": "ready",
            "proof": hex_encode(&bad),
        })
        .to_string();
        let ready = peer.response_for_test(1, 0, &payload);
        let opened = host.open_line(&ready).unwrap();
        assert!(host.verify_ready(&opened).is_err());
    }

    #[test]
    fn test_request_refused_before_handshake() {
        let host = IpcSecureChannel::new().unwrap();
        assert!(host.sign_request(r#"{"op":"unlock"}"#).is_err());
    }

    #[test]
    fn test_business_response_refused_before_handshake() {
        let host = IpcSecureChannel::new().unwrap();
        let peer = host.test_peer();
        let response = peer.response_for_test(1, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_payload_absent_from_wire() {
        let (host, peer) = handshaken();
        let (_seq, request) = host.sign_request(r#"{"op":"unlock","password":"TopSecret"}"#).unwrap();
        assert!(!request.contains("TopSecret"), "请求明文不得出现在线协议中");
        let (_, payload) = peer.open_request_for_test(&request).unwrap();
        assert!(payload.contains("TopSecret"));
    }

    #[test]
    fn test_reject_replayed_response() {
        let (host, peer) = handshaken();
        let (seq, _) = host.sign_request(r#"{"op":"ping"}"#).unwrap();
        /* 就绪已占用响应序号 1，业务响应从 2 开始。 */
        let response = peer.response_for_test(2, seq, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_ok());
        /* 同一字节序列重放：序号已推进，必须拒绝。 */
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_reject_out_of_order_sequence() {
        let (host, peer) = handshaken();
        let response = peer.response_for_test(3, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_reject_tampered_ciphertext() {
        let (host, peer) = handshaken();
        let response = peer.response_for_test(2, 1, r#"{"ok":true}"#);
        let mut value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let mut ct = value["ct"].as_str().unwrap().to_string();
        let last = ct.pop().unwrap();
        ct.push(if last == 'A' { 'B' } else { 'A' });
        value["ct"] = serde_json::json!(ct);
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(host.open_line(&tampered).is_err());
    }

    #[test]
    fn test_reject_cross_session_envelope() {
        let (host, _peer) = handshaken();
        /* 另一会话（不同主密钥/会话标识）的响应不得被接受。 */
        let other = IpcSecureChannel::new().unwrap();
        let response = other.test_peer().response_for_test(1, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_err());

        /* 相同主密钥但会话标识不同：仍拒绝（会话绑定）。 */
        let mut sid = host.session_id;
        sid[0] ^= 0x01;
        let foreign = IpcSecureChannel::from_parts(*host.master, sid, *host.challenge).unwrap();
        let response = foreign.test_peer().response_for_test(1, 1, r#"{"ok":true}"#);
        assert!(host.open_line(&response).is_err());
    }

    #[test]
    fn test_reject_wrong_channel_and_version() {
        let (host, peer) = handshaken();
        let progress = peer.progress_for_test(1, 1, r#"{"op":"v4_rotate_progress"}"#);
        let opened = host.open_line(&progress).unwrap();
        assert_eq!(opened.channel, Channel::Progress);

        let request = peer
            .seal(CH_REQUEST, &peer.request_key[..], 1, 0, r#"{"op":"ping"}"#)
            .unwrap();
        assert!(host.open_line(&request).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&peer.response_for_test(2, 1, r#"{"ok":true}"#)).unwrap();
        value["v"] = serde_json::json!(1);
        assert!(host.open_line(&serde_json::to_string(&value).unwrap()).is_err());
    }

    #[test]
    fn test_progress_channel_independent_sequence() {
        let (host, peer) = handshaken();
        let progress = peer.progress_for_test(1, 7, r#"{"op":"v4_rotate_progress"}"#);
        let response = peer.response_for_test(2, 7, r#"{"ok":true}"#);
        assert!(host.open_line(&progress).is_ok());
        assert!(host.open_line(&response).is_ok());
    }

    #[test]
    fn test_reject_duplicate_ready() {
        let host = IpcSecureChannel::new().unwrap();
        let peer = host.test_peer();
        let ready = peer.ready_line_for_test(&host.challenge);
        let opened = host.open_line(&ready).unwrap();
        host.verify_ready(&opened).unwrap();
        /* 就绪行重复出现：不得再次推进握手状态。 */
        assert!(host.open_line(&ready).is_err());
    }

    #[test]
    fn test_reject_bad_nonce_binding() {
        let (host, peer) = handshaken();
        let response = peer.response_for_test(2, 1, r#"{"ok":true}"#);
        let mut value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let nonce = value["nonce"].as_str().unwrap().to_string();
        let mut nonce_bytes = hex_decode(&nonce).unwrap();
        nonce_bytes[11] ^= 0x01;
        value["nonce"] = serde_json::json!(hex_encode(&nonce_bytes));
        assert!(host.open_line(&serde_json::to_string(&value).unwrap()).is_err());
    }

    #[test]
    fn test_bootstrap_carries_session_material() {
        let host = IpcSecureChannel::new().unwrap();
        let line = host.bootstrap_line().unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["v"], serde_json::json!(2));
        assert_eq!(value["ch"], serde_json::json!("b"));
        assert_eq!(value["key"].as_str().unwrap().len(), 64);
        assert_eq!(value["sid"].as_str().unwrap().len(), 32);
        assert_eq!(value["challenge"].as_str().unwrap().len(), 64);
        assert!(!host.bootstrap_line().unwrap().is_empty());
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
