/*
 * auth.rs — 权限令牌（抗重放保护）
 *
 *
 * 职责：
 *   敏感操作（record_success / clear_purge / set_high_security）要求
 *   携带一次性 auth_token。令牌由 security_generate_auth_token 生成，
 *   验证后立即消费（一次性使用），防止重放攻击。
 *
 *   - generate_auth_token：密码学安全随机数生成（BCryptGenRandom，回退 SHA-256）
 *   - store_auth_token：存储令牌，限制数量防止内存泄漏
 *   - verify_and_consume_auth_token：验证并消费令牌（一次性使用）
 */

use super::state::SecurityState;

/* ====================================================================== *
 *  第 13.2.5 项：权限令牌（抗重放保护）                                   *
 *                                                                        *
 *  敏感操作（record_success / clear_purge / set_high_security）要求      *
 *  携带一次性 auth_token。令牌由 security_generate_auth_token 生成，     *
 *  验证后立即消费（一次性使用），防止重放攻击。                           *
 * ====================================================================== */

/// 第 13.2.5 项：生成一次性权限令牌（32 字节 hex = 64 字符）
pub(super) fn generate_auth_token() -> String {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };

        let mut buf = [0u8; 32];
        let status = unsafe {
            BCryptGenRandom(None, &mut buf[..], BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
        if status.0 >= 0 {
            return buf.iter().map(|b| format!("{:02x}", b)).collect();
        }
        log::warn!(
            "[security_auth] BCryptGenRandom 失败 (NTSTATUS=0x{:08X})，回退到 SHA-256",
            status.0 as u32
        );
    }

    // 回退：SHA-256(进程ID + 纳秒时间戳 + 线程ID)
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = format!("{:?}", std::thread::current().id());

    let mut hasher = Sha256::new();
    hasher.update(b"verthys_security_auth_token_v1");
    hasher.update(pid.to_le_bytes());
    hasher.update(ts.to_le_bytes());
    hasher.update(tid.as_bytes());
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 第 13.2.5 项：存储权限令牌
pub(super) fn store_auth_token(state: &SecurityState, token: String) {
    if let Ok(mut tokens) = state.auth_tokens.lock() {
        tokens.push(token);
        // 限制令牌数量，防止内存泄漏
        if tokens.len() > 16 {
            tokens.remove(0);
        }
    }
}

/// 第 13.2.5 项：验证并消费权限令牌（一次性使用）
///
/// 返回 true=令牌有效且已消费，false=令牌无效或不存在
pub(super) fn verify_and_consume_auth_token(state: &SecurityState, token: Option<&str>) -> bool {
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return false,
    };

    if let Ok(mut tokens) = state.auth_tokens.lock() {
        if let Some(pos) = tokens.iter().position(|t| t == token) {
            tokens.remove(pos);
            return true;
        }
    }
    false
}
