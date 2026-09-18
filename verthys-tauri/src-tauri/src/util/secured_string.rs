/*
 * util/secured_string.rs — 零化擦除的安全字符串包装
 *
 *    "" 第 11.1 项
 *
 * 架构定位：工具层（util）零依赖纯类型模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 仅依赖 zeroize crate 与 serde crate
 *   - 提供 Drop 时自动擦除堆内存的 String 包装类型
 *
 * 第 11.1 项 — 安全擦除：
 *   原 state.rs 中 secure_zero_records 用 ptr::write_bytes 覆写 String 内部缓冲，
 *   属于未定义行为（UB）：String 的堆布局由分配器管理，直接覆写后 Drop 会
 *   向分配器报告错误的布局/长度，可能触发 double-free / heap corruption。
 *
 *   修复：VerthysRecordEntry.name / data 与 VerthysSummaryEntry.name / merkle_leaf
 *   改为 SecuredString（Zeroizing<String>）。Drop 时由 Zeroize trait 通过
 *   String::zeroize() 先以 volatile 写零覆盖堆字节再 clear()，无 UB。
 *   所有显式擦除通过 Zeroize trait 调用，删 ptr::write_bytes。
 *
 * 透明 serde（前端契约无感）：
 *   SecuredString 序列化为普通 JSON 字符串，反序列化从 JSON 字符串构造。
 *   前端 verthys.ts 类型不变（仍是 string），迁移零成本。
 *
 * CI 红线：
 *   - 本文件不输出 log::* 调用（不泄露字符串内容）
 *   - 不实现 Display（避免意外打印明文）
 *   - into_string 消费所有权并放弃自动擦除，仅供必要时使用
 */

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Deref, DerefMut};
use ts_rs::TS;
use zeroize::{Zeroize, Zeroizing};

/// 零化擦除的安全字符串
///
/// 包装 `Zeroizing<String>`：
///   - 序列化/反序列化透明（作为普通 JSON 字符串），前端契约无感
///   - `Deref<Target=str>` 兼容现有 `as_str()` / `len()` / `is_empty()` / `as_bytes()` / `as_ptr()` 调用
///   - Drop 时自动 zeroize 堆内存（String::zeroize 先 volatile 写零再 clear，无 UB）
///   - 实现 `Zeroize` trait 供泛型 `ScanRecord: Zeroize` 约束使用（第 11.3 项）
///
/// 用于 VerthysRecordEntry.name / data 与 VerthysSummaryEntry.name / merkle_leaf 字段，
/// 替代裸 String，消除 secure_zero_records 中 ptr::write_bytes 对 String 的 UB 覆写。
///
/// 注意：不 derive Hash（Zeroizing<String> 未实现 Hash）。
#[derive(Debug, Default, Clone, PartialEq, Eq, TS)]
#[ts(export, export_to = "bindings/", type = "string")]
pub struct SecuredString(Zeroizing<String>);

impl SecuredString {
    /// 从 String 构造（接管所有权，原 String 应由调用方自行 drop）
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// 从 &str 构造（拷贝一份，原引用不变）
    // 说明：保留 from_str 命名——该构造与 From<&str>/From<&String> 实现配套，
    // 全库约 20 处调用点（含安全敏感的记录构造路径），且语义为"安全拷贝构造"
    // 而非 std FromStr 的 fallible 解析，实现该 trait 反而会误导调用方；
    // 重命名将波及大量调用点，得不偿失，故定点豁免。
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self(Zeroizing::new(s.to_string()))
    }

    /// 空字符串
    pub fn empty() -> Self {
        Self::default()
    }

    /// 以 &str 视图访问内容
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 以字节切片访问内容
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// 内容长度（字节数）
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 内容首字节指针（用于 VirtualLock 锁定堆内存区）
    ///
    /// 返回指向 String 堆缓冲首字节的 *const u8。
    /// VirtualLock 据此锁定物理内存页，禁止换出到 pagefile。
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// 可变首字节指针（用于就地擦除写零）
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}

impl Deref for SecuredString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl DerefMut for SecuredString {
    fn deref_mut(&mut self) -> &mut str {
        &mut self.0
    }
}

impl AsRef<str> for SecuredString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for SecuredString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for SecuredString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecuredString {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl From<&String> for SecuredString {
    fn from(s: &String) -> Self {
        Self::from_str(s)
    }
}

impl std::fmt::Write for SecuredString {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.write_str(s)
    }
}

// ===== 透明 serde：序列化为 JSON 字符串，前端契约无感 =====

impl Serialize for SecuredString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecuredString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

// ===== 第 11.3 项：Zeroize trait 实现（供泛型 ScanRecord: Zeroize 约束）=====

impl Zeroize for SecuredString {
    fn zeroize(&mut self) {
        // 委托给内部 Zeroizing<String>::zeroize()
        // String::zeroize() 以 volatile 写零覆盖堆字节后 clear()，无 UB。
        self.0.zeroize();
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_access() {
        let s = SecuredString::from_str("hello");
        assert_eq!(s.as_str(), "hello");
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
        assert_eq!(s.as_bytes(), b"hello");
    }

    #[test]
    fn test_deref() {
        let s = SecuredString::from_str("world");
        // Deref<Target=str> 让 &s 可直接作为 &str
        let r: &str = &s;
        assert_eq!(r, "world");
        assert!(s.starts_with("wor"));
        assert_eq!(s.to_uppercase(), "WORLD");
    }

    #[test]
    fn test_empty() {
        let s = SecuredString::empty();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn test_from_conversions() {
        let s1 = SecuredString::from(String::from("abc"));
        let s2 = SecuredString::from("abc");
        let s3 = SecuredString::from(&String::from("abc"));
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    #[test]
    fn test_serde_transparent() {
        // 序列化应输出普通 JSON 字符串
        let s = SecuredString::from_str("secret_data");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"secret_data\"");

        // 反序列化应从 JSON 字符串构造
        let s2: SecuredString = serde_json::from_str("\"secret_data\"").unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn test_serde_in_struct() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Sample {
            name: SecuredString,
            data: SecuredString,
        }

        let original = Sample {
            name: SecuredString::from_str("记录名"),
            data: SecuredString::from_str("aGVsbG8="),
        };
        let json = serde_json::to_string(&original).unwrap();
        // JSON 应为 {"name":"记录名","data":"aGVsbG8="}
        assert!(json.contains("\"name\":\"记录名\""));
        assert!(json.contains("\"data\":\"aGVsbG8=\""));

        let decoded: Sample = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_zeroize() {
        let mut s = SecuredString::from_str("sensitive_content");
        s.zeroize();
        // zeroize 后内容应被清空
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }
}
