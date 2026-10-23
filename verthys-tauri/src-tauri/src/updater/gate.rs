/*
 * updater/gate.rs — 锁库闸门的一次性凭据
 *
 * 闸门必须绑定到具体会话、发布与已校验字节，并只在短窗口内有效。仅凭前端
 * 提交的 clean 布尔值即可安装，会让任何能调用命令的代码绕过落盘检查；因此
 * 解锁前先签发 challenge，锁库完成后凭 challenge 换取一次性 receipt，安装
 * 时只认 receipt。
 */

use serde::Serialize;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// 锁库挑战的有效期：覆盖锁库各步骤的超时上限，又不会让旧挑战长期可兑换。
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// 安装回执的有效期：只用于紧接着的安装移交，超时即要求重新锁库。
const RECEIPT_TTL: Duration = Duration::from_secs(120);

/// 锁库挑战：证明“该会话在某一时刻已准备完成，允许开始锁库”。
#[derive(Debug, Clone)]
pub struct Challenge {
    id: String,
    session_id: String,
    release_id: String,
    sha256: String,
    issued_at: Instant,
}

/// 安装回执：证明“该会话已完成干净锁库”，只能兑换一次安装。
#[derive(Debug, Clone)]
pub struct Receipt {
    id: String,
    session_id: String,
    release_id: String,
    sha256: String,
    issued_at: Instant,
}

/// 前端可见的挑战视图；不包含内部过期时间点，只给出剩余毫秒。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeView {
    pub challenge: String,
    pub release_id: String,
    pub sha256: String,
    pub expires_in_ms: u64,
}

/// 前端可见的回执视图。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptView {
    pub receipt: String,
    pub expires_in_ms: u64,
}

impl Challenge {
    pub fn issue(session_id: &str, release_id: &str, sha256: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            release_id: release_id.to_string(),
            sha256: sha256.to_string(),
            issued_at: Instant::now(),
        }
    }

    pub fn view(&self) -> ChallengeView {
        ChallengeView {
            challenge: self.id.clone(),
            release_id: self.release_id.clone(),
            sha256: self.sha256.clone(),
            expires_in_ms: remaining_ms(self.issued_at, CHALLENGE_TTL),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.checked_duration_since(self.issued_at)
            .is_some_and(|elapsed| elapsed >= CHALLENGE_TTL)
    }

    pub fn matches(&self, session_id: &str, release_id: &str, sha256: &str) -> bool {
        self.session_id == session_id && self.release_id == release_id && self.sha256 == sha256
    }
}

impl Receipt {
    pub fn issue(session_id: &str, release_id: &str, sha256: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            release_id: release_id.to_string(),
            sha256: sha256.to_string(),
            issued_at: Instant::now(),
        }
    }

    pub fn view(&self) -> ReceiptView {
        ReceiptView {
            receipt: self.id.clone(),
            expires_in_ms: remaining_ms(self.issued_at, RECEIPT_TTL),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.checked_duration_since(self.issued_at)
            .is_some_and(|elapsed| elapsed >= RECEIPT_TTL)
    }

    pub fn matches(&self, session_id: &str, release_id: &str, sha256: &str) -> bool {
        self.session_id == session_id && self.release_id == release_id && self.sha256 == sha256
    }
}

fn remaining_ms(issued_at: Instant, ttl: Duration) -> u64 {
    ttl.saturating_sub(issued_at.elapsed()).as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{Challenge, Receipt, CHALLENGE_TTL, RECEIPT_TTL};
    use std::time::{Duration, Instant};

    #[test]
    fn challenge_binds_session_release_and_bytes() {
        let challenge = Challenge::issue("session-1", "release-1", "sha-1");
        assert!(challenge.matches("session-1", "release-1", "sha-1"));
        assert!(!challenge.matches("session-2", "release-1", "sha-1"));
        assert!(!challenge.matches("session-1", "release-2", "sha-1"));
        assert!(!challenge.matches("session-1", "release-1", "sha-2"));
        assert!(!challenge.id().is_empty());
        assert_eq!(challenge.session_id(), "session-1");
    }

    #[test]
    fn challenge_and_receipt_expire_after_ttl() {
        let challenge = Challenge::issue("session-1", "release-1", "sha-1");
        assert!(!challenge.is_expired(Instant::now()));
        assert!(challenge.is_expired(Instant::now() + CHALLENGE_TTL + Duration::from_millis(1)));

        let receipt = Receipt::issue("session-1", "release-1", "sha-1");
        assert!(receipt.matches("session-1", "release-1", "sha-1"));
        assert!(!receipt.is_expired(Instant::now()));
        assert!(receipt.is_expired(Instant::now() + RECEIPT_TTL + Duration::from_millis(1)));
        assert!(!receipt.id().is_empty());
    }
}
