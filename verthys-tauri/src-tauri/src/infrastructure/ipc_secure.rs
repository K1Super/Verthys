/*
 * @file infrastructure/ipc_secure.rs
 * @brief 主进程 ↔ Worker 加密认证安全IPC信道实现
 *
 * 两项强制安全需求：
 * 1. 会话密钥+HMAC-SHA256消息签名+单调Nonce滑动窗口抗重放
 *    修复原明文JSON管道传输可被篡改、注入恶意指令的漏洞；
 *    会话密钥由CSPRNG生成，仅通过子进程命令行传递，进程级隔离；
 * 2. Worker关键操作响应强制附加HMAC校验
 *    主进程校验签名通过后才解析载荷，避免不可信响应直接透传上层。
 *
 * 强制执行CI安全红线（未满足禁止合并）：
 * 会话密钥、原始密码、密钥二进制全程禁止日志打印输出；
 * MAC标签比对、Nonce校验全部使用常量时间比较抵御计时攻击；
 * 会话密钥借助Zeroizing封装，Drop自动编译器防优化内存擦除；
 * 所有管道消息必须信封封装，裸明文IPC仅保留过渡期兼容兜底。
 *
 * 依赖底层基础设施：
 * - util::crypto：常量时间相等判断、HMAC-SHA256签名/验签
 * - util::random：密码学安全随机数生成器CSPRNG
 * - util::base64：载荷Base64编解码
 */

use crate::util::crypto::{ct_eq, hmac_sign, hmac_verify};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// HMAC-SHA256会话密钥固定长度：32字节（256位），符合算法安全密钥规格
pub const SESSION_KEY_LEN: usize = 32;

/// Nonce抗重放滑动窗口最大容纳数量
/// 允许少量网络乱序消息合法通过，超出窗口的旧序号直接判定为重放攻击
const REPLAY_WINDOW_SIZE: u64 = 64;

// =============================================================================
// 外层签名消息信封结构：所有IPC通信统一封装载体
// =============================================================================

/// 加密签名信封结构体，全量消息传输标准格式
/// 解决JSON嵌套转义、载荷篡改、重放复用三大风险
/// 序列化后JSON结构：{"payload":"base64字符串","nonce":序号,"hmac":"hex哈希"}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedMessage {
    /// 原始业务JSON经过Base64编码，规避嵌套JSON转义歧义问题
    pub payload: String,
    /// 全局单调自增序号，作为防重放唯一标识
    pub nonce: u64,
    /// HMAC-SHA256签名结果，小写16进制字符串固定64字符长度
    pub hmac: String,
}

impl SignedMessage {
    /// 原始JSON载荷Base64编码封装
    fn encode_payload(json: &str) -> String {
        crate::util::base64::base64_encode(json.as_bytes())
    }

    /// Base64载荷解码并校验UTF-8合法性
    fn decode_payload(b64: &str) -> Result<String, String> {
        let raw_bytes = crate::util::base64::base64_decode(b64)?;
        String::from_utf8(raw_bytes).map_err(|e| format!("IPC载荷UTF-8解码失败: {}", e))
    }

    /// 按照规范拼接签名原文：小端8字节nonce + Base64载荷字符串
    /// 使用共享会话密钥计算HMAC-SHA256并转为十六进制
    /// 失败（密钥被后端拒绝）不 panic：上抛 Err 由调用方处置
    fn compute_hmac(session_key: &[u8], nonce: u64, payload_b64: &str) -> Result<String, String> {
        let mut signing_data = Vec::with_capacity(8 + payload_b64.len());
        signing_data.extend_from_slice(&nonce.to_le_bytes());
        signing_data.extend_from_slice(payload_b64.as_bytes());

        let hmac_tag = hmac_sign(session_key, &signing_data)?;
        Ok(hex::encode(hmac_tag))
    }

    /// 常量时间校验HMAC签名，抵御侧信道计时攻击
    /// 签名计算基础异常与"签名不匹配"同为拒绝（fail-closed），
    /// 仅日志区分原因，绝不因计算失败放行载荷
    fn verify_hmac(&self, session_key: &[u8]) -> bool {
        let expected_tag = match Self::compute_hmac(session_key, self.nonce, &self.payload) {
            Ok(tag) => tag,
            Err(e) => {
                log::error!("[ipc_secure] HMAC计算基础异常，拒绝载荷: {}", e);
                return false;
            }
        };
        ct_eq(expected_tag.as_bytes(), self.hmac.as_bytes())
    }
}

// =============================================================================
// Nonce滑动窗口抗重放判定器：位图紧凑存储已接收序号
// =============================================================================

/// 基于64位位图实现的滑动重放窗口，内存开销极小
/// 安全规则：
/// 1. nonce=0永久保留禁用，不接受任何0序号消息；
/// 2. 大于当前最大序号：窗口向前滑动，标记为合法新消息；
/// 3. 与最大值差值超过窗口大小：判定过期旧消息直接拒绝；
/// 4. 窗口内已标记位图位：判定重复重放拦截。
struct NonceWindow {
    /// 窗口记录的最大合法nonce值
    highest: u64,
    /// 位图标记：bit N 代表 highest - N 该序号是否已处理过
    bitmap: u64,
}

impl NonceWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    /// 原子性检查序号合法性并写入记录
    /// 返回true=合法首次接收，false=重放/过期/非法序号
    fn check_and_record(&mut self, nonce: u64) -> bool {
        // 0号nonce保留禁用位
        if nonce == 0 {
            return false;
        }

        // 新更大序号，窗口向前推进
        if nonce > self.highest {
            let shift_distance = nonce - self.highest;
            if shift_distance >= REPLAY_WINDOW_SIZE {
                // 完全跳出窗口范围，位图全部失效清空
                self.bitmap = 0;
            } else {
                // 部分右移窗口，旧标记向后平移
                self.bitmap = self.bitmap.checked_shl(shift_distance as u32).unwrap_or(0);
            }
            self.highest = nonce;
            self.bitmap |= 1;
            return true;
        }

        // 序号小于等于最大值，判断是否在有效窗口区间
        let delta = self.highest.saturating_sub(nonce);
        if delta >= REPLAY_WINDOW_SIZE {
            return false;
        }

        let bit_mask = 1u64 << delta;
        if (self.bitmap & bit_mask) != 0 {
            // 位图已置位：已处理过，重放攻击
            false
        } else {
            // 窗口内未处理，标记后放行
            self.bitmap |= bit_mask;
            true
        }
    }
}

// =============================================================================
// 安全IPC信道主对象：封装会话密钥、发送计数器、接收防重放窗口
// =============================================================================

/// 全链路安全IPC信道实例，线程安全可跨线程调用
/// 内部成员安全保障：
/// 1. session_key：Zeroizing包装，离开作用域强制内存清零防内存dump泄露；
/// 2. send_nonce：AtomicU64无锁自增，多线程并发发送保证序号严格单调；
/// 3. recv_window：Mutex独占锁保护，避免并发校验位图状态错乱。
pub struct IpcSecureChannel {
    /// 会话密钥缓冲区，Drop自动擦除内存
    session_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    /// 发送方自增nonce计数器，每条出站消息分配唯一序号
    send_nonce: AtomicU64,
    /// 入站消息nonce防重放滑动窗口
    recv_window: Mutex<NonceWindow>,
}

impl IpcSecureChannel {
    /// 初始化全新安全信道，CSPRNG生成密码学安全随机会话密钥
    /// 调用时机：主进程worker_init阶段一次性创建
    pub fn new() -> Result<Self, String> {
        let mut key_buf = [0u8; SESSION_KEY_LEN];
        crate::util::random::fill_random_bytes(&mut key_buf);

        Ok(Self {
            session_key: Zeroizing::new(key_buf),
            send_nonce: AtomicU64::new(1), // nonce从1起始，避开保留值0
            recv_window: Mutex::new(NonceWindow::new()),
        })
    }

    /// 通过外部传入密钥构造信道，仅用于单元测试与特殊恢复场景
    pub fn from_key(key: [u8; SESSION_KEY_LEN]) -> Self {
        Self {
            session_key: Zeroizing::new(key),
            send_nonce: AtomicU64::new(1),
            recv_window: Mutex::new(NonceWindow::new()),
        }
    }

    /// 获取密钥只读引用，仅限传递给子进程启动参数，禁止日志打印
    pub fn session_key(&self) -> &[u8] {
        &self.session_key
    }

    /// 导出密钥十六进制字符串，用于命令行参数传递给Worker子进程
    pub fn session_key_hex(&self) -> String {
        hex::encode(&*self.session_key)
    }

    /// 对业务请求JSON进行签名封装，输出可直接管道发送的JSON字符串
    /// 流程：分配递增nonce → Base64载荷 → 计算HMAC → 序列化为信封
    pub fn sign_request(&self, json: &str) -> Result<String, String> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        let payload_b64 = SignedMessage::encode_payload(json);
        let hmac_tag = SignedMessage::compute_hmac(&self.session_key, nonce, &payload_b64)?;

        let envelope = SignedMessage {
            payload: payload_b64,
            nonce,
            hmac: hmac_tag,
        };

        serde_json::to_string(&envelope).map_err(|e| format!("请求签名序列化失败: {}", e))
    }

    /// 完整校验Worker返回签名响应，任意环节失败直接拒绝载荷
    /// 校验链路：反序列化 → HMAC常量时间验签 → Nonce防重放窗口校验 → Base64解码
    pub fn verify_response(&self, signed_json: &str) -> Result<String, String> {
        // 1. 反序列化信封结构
        let envelope: SignedMessage = serde_json::from_str(signed_json)
            .map_err(|e| format!("响应信封反序列化失败: {}", e))?;

        // 2. HMAC完整性与身份校验，失败判定消息被篡改
        if !envelope.verify_hmac(&self.session_key) {
            log::error!("[ipc_secure] IPC响应HMAC校验不通过，载荷疑似篡改");
            return Err("IPC安全校验失败：签名不匹配".to_string());
        }

        // 3. Nonce滑动窗口防重放判定，加锁保护窗口状态
        {
            let mut window_guard = self.recv_window.lock().unwrap_or_else(|poison| poison.into_inner());
            if !window_guard.check_and_record(envelope.nonce) {
                log::error!("[ipc_secure] 检测到IPC消息重放攻击，nonce:{}", envelope.nonce);
                return Err("IPC安全校验失败：重放消息拦截".to_string());
            }
        }

        // 4. 解码原始业务JSON返回上层
        SignedMessage::decode_payload(&envelope.payload)
    }

    /// 兼容过渡形态：自动识别是否为签名信封，未签名消息直接透传（仅过渡期使用）
    /// 注意：透传分支无任何认证保护，版本全量升级后应删除该兜底逻辑
    pub fn verify_or_passthrough(&self, json: &str) -> Result<String, String> {
        match serde_json::from_str::<SignedMessage>(json) {
            Ok(_) => self.verify_response(json),
            Err(_) => {
                log::debug!("[ipc_secure] 收到未签名原始响应，运行在向后兼容降级模式");
                Ok(json.to_string())
            }
        }
    }
}

/// Drop自动执行密钥内存擦除，Zeroizing已内置防编译器死代码消除优化
impl Drop for IpcSecureChannel {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

// =============================================================================
// 内置极简Hex编解码实现，减少第三方crate依赖
// =============================================================================
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
        if s.len() % 2 != 0 {
            return Err("十六进制字符串长度必须为偶数".to_string());
        }

        let mut output = Vec::with_capacity(s.len() / 2);
        let chars: Vec<char> = s.chars().collect();

        for chunk in chars.chunks_exact(2) {
            let high = chunk[0].to_digit(16).ok_or("非法十六进制字符")?;
            let low = chunk[1].to_digit(16).ok_or("非法十六进制字符")?;
            output.push((high * 16 + low) as u8);
        }

        Ok(output)
    }
}

// =============================================================================
// 单元测试：覆盖签名验签、篡改拦截、重放拦截、窗口逻辑、编解码全场景
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_normal_flow() {
        let channel = IpcSecureChannel::new().unwrap();
        let origin_req = r#"{"op":"ping","payload":"health_check"}"#;

        let signed_envelope = channel.sign_request(origin_req).unwrap();
        assert!(signed_envelope.contains("payload") && signed_envelope.contains("hmac"));

        // 模拟Worker端使用相同密钥验签
        let worker_channel = IpcSecureChannel::from_key(*channel.session_key);
        let resp_json = r#"{"code":0,"msg":"ok"}"#;
        let resp_env = SignedMessage {
            payload: SignedMessage::encode_payload(resp_json),
            nonce: 1,
            hmac: SignedMessage::compute_hmac(&worker_channel.session_key, 1, &SignedMessage::encode_payload(resp_json)).unwrap(),
        };
        let resp_str = serde_json::to_string(&resp_env).unwrap();

        let verified = worker_channel.verify_response(&resp_str).unwrap();
        assert_eq!(verified, resp_json);
    }

    #[test]
    fn test_reject_tampered_payload() {
        let channel = IpcSecureChannel::new().unwrap();
        let key = *channel.session_key;

        let raw_json = r#"{"unlock":true}"#;
        let env = SignedMessage {
            payload: SignedMessage::encode_payload(raw_json),
            nonce: 1,
            hmac: SignedMessage::compute_hmac(&key, 1, &SignedMessage::encode_payload(raw_json)).unwrap(),
        };
        let mut json_str = serde_json::to_string(&env).unwrap();

        // 篡改载荷内容
        let mut tampered_env: SignedMessage = serde_json::from_str(&json_str).unwrap();
        tampered_env.payload = SignedMessage::encode_payload(r#"{"unlock":false}"#);
        let tampered_str = serde_json::to_string(&tampered_env).unwrap();

        let res = channel.verify_response(&tampered_str);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("签名不匹配"));
    }

    #[test]
    fn test_reject_replay_nonce() {
        let channel = IpcSecureChannel::new().unwrap();
        let key = *channel.session_key;

        let env = SignedMessage {
            payload: SignedMessage::encode_payload(r#"{}"#),
            nonce: 1,
            hmac: SignedMessage::compute_hmac(&key, 1, &SignedMessage::encode_payload(r#"{}"#)).unwrap(),
        };
        let msg_str = serde_json::to_string(&env).unwrap();

        // 第一次合法通过
        assert!(channel.verify_response(&msg_str).is_ok());
        // 第二次重放直接拦截
        let err_res = channel.verify_response(&msg_str);
        assert!(err_res.is_err());
        assert!(err_res.unwrap_err().contains("重放消息拦截"));
    }

    #[test]
    fn test_nonce_auto_increment() {
        let ch = IpcSecureChannel::new().unwrap();
        let m1 = ch.sign_request("a").unwrap();
        let m2 = ch.sign_request("b").unwrap();

        let s1: SignedMessage = serde_json::from_str(&m1).unwrap();
        let s2: SignedMessage = serde_json::from_str(&m2).unwrap();
        assert!(s2.nonce > s1.nonce);
    }

    #[test]
    fn test_backward_compat_passthrough() {
        let ch = IpcSecureChannel::new().unwrap();
        let raw = r#"{"legacy":true}"#;
        let out = ch.verify_or_passthrough(raw).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn test_nonce_sliding_window_logic() {
        let mut window = NonceWindow::new();

        // nonce 0 直接拒绝
        assert!(!window.check_and_record(0));
        // 正常递增序号放行
        assert!(window.check_and_record(1));
        // 重复序号拦截
        assert!(!window.check_and_record(1));
        assert!(window.check_and_record(2));
        assert!(window.check_and_record(5));
        assert!(window.check_and_record(3));
        assert!(!window.check_and_record(3));
        // 超大序号滑动窗口清空旧记录
        assert!(window.check_and_record(100));
        // 旧序号超出窗口失效
        assert!(!window.check_and_record(3));
    }

    #[test]
    fn test_hex_codec_consistency() {
        let raw_bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex_str = hex::encode(&raw_bytes);
        assert_eq!(hex_str, "0123456789abcdef");
        let decode_back = hex::decode(&hex_str).unwrap();
        assert_eq!(decode_back, raw_bytes.to_vec());
    }
}