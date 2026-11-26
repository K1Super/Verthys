/*
 * 记录标识 newtype
 *
 * 职责边界：RecordType / RecordId 提供类型安全的记录标识，防止与其它
 * u32/u64 字段混淆。
 */

use serde::{Deserialize, Serialize};
use ts_rs::TS;
// ===== RecordType / RecordId newtype =====
//
// 当前仅定义 newtype，现有结构体继续使用 u32/u64 原始类型。

/// 记录类型 newtype
///
/// 替代裸 u32，提供类型安全防止与其他 u32 字段混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, TS)]
#[repr(transparent)]
#[ts(export, export_to = "bindings/", type = "number")]
pub struct RecordType(pub u32);

impl RecordType {
    pub fn new(t: u32) -> Self {
        RecordType(t)
    }
}

impl From<u32> for RecordType {
    fn from(v: u32) -> Self {
        RecordType(v)
    }
}

impl From<RecordType> for u32 {
    fn from(v: RecordType) -> Self {
        v.0
    }
}

/// 记录 ID newtype
///
/// 替代裸 u64，提供类型安全防止与其他 u64 字段混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, TS)]
#[repr(transparent)]
#[ts(export, export_to = "bindings/", type = "number")]
pub struct RecordId(pub u64);

impl RecordId {
    pub fn new(id: u64) -> Self {
        RecordId(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for RecordId {
    fn from(v: u64) -> Self {
        RecordId(v)
    }
}

impl From<RecordId> for u64 {
    fn from(v: RecordId) -> Self {
        v.0
    }
}
