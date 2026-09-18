/*
 * controller/types.rs — 控制器层共享类型定义
 *
 *
 * 架构定位：控制器层数据契约（与前端 verthys.ts 对齐）
 *   - VerthysRecordEntry: 批量枚举返回的单条记录
 *   - VerthysSummaryEntry: 摘要扫描返回的单条记录
 *   - VerthysResponse: 统一 JSON 响应结构（过渡兼容别名，阶段 8 移除）
 *   - PreflightResult: 路径预检结果（第 8.3 项删除 dir 字段）
 *   - InitStatusResult: 初始化状态查询结果
 *   - DiagInfo: 诊断信息（第 8.3 项删除路径字段，改存在性/哈希标识）
 *   - EnumerateBatch: 流式分页批次（第 8.6 项增加 error 字段）
 *   - InitStatus / DeviceBindingStatus: 枚举（第 8.5 项）
 *   - RecordType / RecordId: newtype（第 8.7 项）
 *
 * 第 8.8 项 — ts-rs 自动生成 TypeScript 绑定：
 *   所有响应类型标注 #[derive(TS)] #[ts(export)]
 *   build.rs 调 ts-rs::export 生成 bindings/ 目录
 *
 *    "分层单向依赖"
 *   类型定义集中在控制器层，供各 controller 子模块共享
 */

use crate::util::secured_string::SecuredString;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use zeroize::Zeroize;

// ===== 第 8.7 项：RecordType / RecordId newtype =====
//
// 阶段 1 仅定义 newtype，现有结构体继续使用 u32/u64 原始类型。
// 阶段 8 统一迁移至 newtype 后启用 ts-rs 生成。

/// 记录类型 newtype（第 8.7 项）
///
/// 替代裸 u32，提供类型安全防止与其他 u32 字段混淆。
/// 阶段 8 统一迁移后，VerthysRecordEntry.rtype 将改为 RecordType。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, TS)]
#[repr(transparent)]
#[ts(export, export_to = "bindings/", type = "number")]
pub struct RecordType(pub u32);

impl RecordType {
    pub fn new(t: u32) -> Self {
        RecordType(t)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
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

/// 记录 ID newtype（第 8.7 项）
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

// ===== 第 8.5 项：InitStatus / DeviceBindingStatus 枚举 =====

/// 加密库初始化状态枚举（第 8.5 项）
///
/// 替代字符串状态（"none"/"ready"/"broken"），提供类型安全。
/// 前端通过枚举变体进行差异化处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "bindings/")]
pub enum InitStatus {
    /// 未初始化（全新用户，无 .verthys 文件）
    None,
    /// 初始化中（worker 正在创建/派生密钥）
    Initializing,
    /// 就绪（.verthys 存在且 magic 合法，可解锁）
    Ready,
    /// 损坏（.verthys magic 不合法 / 状态文件损坏）
    Broken,
    /// 维护中（迁移中 / 修复中 / 恢复模式）
    Maintenance,
}

impl InitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            InitStatus::None => "none",
            InitStatus::Initializing => "initializing",
            InitStatus::Ready => "ready",
            InitStatus::Broken => "broken",
            InitStatus::Maintenance => "maintenance",
        }
    }
}

impl Default for InitStatus {
    fn default() -> Self {
        InitStatus::None
    }
}

/// 设备绑定状态枚举（第 8.5 项）
///
/// 替代字符串状态，提供类型安全的设备绑定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "bindings/")]
pub enum DeviceBindingStatus {
    /// 完全匹配
    Match,
    /// 不匹配（设备指纹变更）
    Mismatch,
    /// 未绑定（首次运行）
    Unbound,
    /// 部分匹配（部分硬件变更，触发有限恢复模式）
    PartialMatch,
    /// 查询错误
    Error,
}

impl DeviceBindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceBindingStatus::Match => "match",
            DeviceBindingStatus::Mismatch => "mismatch",
            DeviceBindingStatus::Unbound => "unbound",
            DeviceBindingStatus::PartialMatch => "partial_match",
            DeviceBindingStatus::Error => "error",
        }
    }
}

/// 第 4.6 项：设备绑定校验结果（结构化返回）
///
/// 替代魔术字符串，提供类型安全的设备绑定结果。
/// status 为状态枚举，detail 为用户可读描述，error_code 供前端差异化处理。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct DeviceBindingResult {
    /// 绑定状态枚举（match/mismatch/unbound/partial_match/error）
    pub status: DeviceBindingStatus,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 错误码（status=error 时有值）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 第 4.5 项：匹配度百分比（0-100，status=match/partial_match 时有值）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_score: Option<u32>,
}

// ===== 第 7.2/7.3/7.5 项：剪贴板结构化响应 =====

/// 第 7.2/7.3/7.5 项：剪贴板清空结果（结构化返回）
///
/// 替代恒成功返回，提供类型安全的剪贴板操作结果。
/// error_code 供前端差异化处理（CLIPBOARD_LOCKED / RATE_LIMITED / CLIPBOARD_MONITOR_FAILED）。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct ClipboardResult {
    /// 操作是否成功（true=剪贴板已安全擦除）
    pub ok: bool,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 第 7.2/7.3/7.5 项：标准化错误码
    ///
    /// 取值：
    ///   - CLIPBOARD_LOCKED：剪贴板被占用，重试后仍失败
    ///   - RATE_LIMITED：频率超限（>10次/分钟）
    ///   - CLIPBOARD_MONITOR_FAILED：监听启动失败
    ///   - TEMPORARY_FAILURE：临时性故障
    ///   - INTERNAL：内部错误
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl ClipboardResult {
    pub fn success() -> Self {
        ClipboardResult {
            ok: true,
            detail: "剪贴板已安全擦除".into(),
            error_code: None,
        }
    }

    pub fn error(code: &str, detail: impl Into<String>) -> Self {
        ClipboardResult {
            ok: false,
            detail: detail.into(),
            error_code: Some(code.into()),
        }
    }
}

/// 第 7.2/7.4/7.5 项：隐私模式设置结果（结构化返回）
///
/// 替代恒成功返回，提供类型安全的隐私模式切换结果。
/// partial_protection=true 表示防截屏已启用但剪贴板监听启动失败（部分保护）。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PrivacyModeResult {
    /// 操作是否成功（true=隐私模式已按预期切换）
    pub ok: bool,
    /// 隐私模式当前状态（true=已启用，false=已关闭）
    pub enabled: bool,
    /// 第 7.2 项：是否处于部分保护状态
    ///
    /// true 表示防截屏已启用但剪贴板监听启动失败，前端应警告用户。
    pub partial_protection: bool,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 第 7.2/7.4/7.5 项：标准化错误码
    ///
    /// 取值：
    ///   - CLIPBOARD_MONITOR_FAILED：剪贴板监听启动失败（partial_protection=true）
    ///   - RATE_LIMITED：频率超限（>10次/分钟）
    ///   - PERMISSION_DENIED：关闭隐私模式缺少授权令牌
    ///   - TEMPORARY_FAILURE：临时性故障
    ///   - INTERNAL：内部错误
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 第 7.4 项：会话令牌（仅 enabled=true 时返回）
    ///
    /// 启用隐私模式时生成的随机令牌，前端需存储并在关闭时作为 auth_token 传入。
    /// 关闭操作要求此令牌匹配，防止恶意脚本无凭据关闭保护。
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl PrivacyModeResult {
    pub fn success(enabled: bool) -> Self {
        let detail = if enabled {
            "隐私模式已启用".into()
        } else {
            "隐私模式已关闭".into()
        };
        PrivacyModeResult {
            ok: true,
            enabled,
            partial_protection: false,
            detail,
            error_code: None,
            session_token: None,
        }
    }

    /// 第 7.4 项：启用成功时附带会话令牌
    pub fn success_with_token(enabled: bool, token: impl Into<String>) -> Self {
        let detail = if enabled {
            "隐私模式已启用".into()
        } else {
            "隐私模式已关闭".into()
        };
        PrivacyModeResult {
            ok: true,
            enabled,
            partial_protection: false,
            detail,
            error_code: None,
            session_token: if enabled { Some(token.into()) } else { None },
        }
    }

    pub fn partial(enabled: bool, code: &str, detail: impl Into<String>) -> Self {
        PrivacyModeResult {
            ok: true, // 部分成功：防截屏已启用
            enabled,
            partial_protection: true,
            detail: detail.into(),
            error_code: Some(code.into()),
            session_token: None,
        }
    }

    /// 第 7.4 项：部分保护时附带会话令牌（仍需前端存储以便关闭）
    pub fn partial_with_token(
        enabled: bool,
        code: &str,
        detail: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        PrivacyModeResult {
            ok: true,
            enabled,
            partial_protection: true,
            detail: detail.into(),
            error_code: Some(code.into()),
            session_token: if enabled { Some(token.into()) } else { None },
        }
    }

    pub fn error(code: &str, detail: impl Into<String>) -> Self {
        PrivacyModeResult {
            ok: false,
            enabled: false,
            partial_protection: false,
            detail: detail.into(),
            error_code: Some(code.into()),
            session_token: None,
        }
    }
}

// ===== 记录条目类型 =====

/// 批量枚举返回的单条记录（与 worker RecordEntry 对齐）
///
/// 第 8.7 项：Base64 字段附 original_size:u64（原始字节数，base64 解码后长度）
///
/// 第 11.1 项：name / data 改为 SecuredString（Zeroizing<String>）：
///   - Drop 时自动 zeroize 堆内存，消除 secure_zero_records 中 ptr::write_bytes
///     对 String 的 UB 覆写
///   - 透明 serde（序列化为普通 JSON 字符串），前端契约无感
///   - Deref<Target=str> 兼容现有 as_str()/len()/is_empty()/as_ptr() 调用
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct VerthysRecordEntry {
    #[ts(type = "number")]
    pub id: u64,
    /// 记录类型（阶段 8 迁移至 RecordType newtype）
    pub rtype: u32,
    /// 第 11.1 项：记录名称（SecuredString，Drop 时零化擦除）
    pub name: SecuredString,
    /// 第 11.1 项：Base64 编码的记录数据（SecuredString，Drop 时零化擦除）
    pub data: SecuredString,
    /// 第 8.7 项：原始数据大小（字节，base64 解码后长度）
    ///
    /// 前端据此预分配解码缓冲区，避免 base64 解码后才知道大小。
    /// 向后兼容：旧响应无此字段时为 None，前端按 data.len() * 3 / 4 估算。
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub original_size: Option<u64>,
}

/// 第 11.1 项：VerthysRecordEntry 的 Zeroize 实现
///
/// 仅擦除敏感字段 name / data（SecuredString::zeroize 以 volatile 写零覆盖堆字节后 clear）。
/// id / rtype / original_size 非敏感，不擦除（保留以便崩溃诊断）。
///
/// 支持第 11.3 项泛型 `ScanRecord: Zeroize` 约束，使 `<[VerthysRecordEntry]>::zeroize()`
/// 可直接对整批记录就地擦除，替代 secure_zero_records 自由函数。
impl Zeroize for VerthysRecordEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.data.zeroize();
    }
}

/// 摘要扫描返回的单条记录（Phase 2C：轻量元数据，不含数据块）
///
/// 与 VerthysRecordEntry 的区别：
///   - 无 data 字段（不解密数据块，解锁后 1-2 秒内完成列表渲染）
///   - 新增 data_size / physical_offset / merkle_leaf（供按需加载定位 + 完整性校验）
///   - ★ Phase 2G：新增 created_time（创建时间戳，解锁后立即展示在列表中）
///
/// merkle_leaf 以 base64 传输（32 字节 → 44 字符），前端用于全盘完整性巡检。
///
/// 第 11.1 项：name / merkle_leaf 改为 SecuredString（Zeroizing<String>）：
///   Drop 时自动零化堆内存，消除 secure_zero_summary_records 中 ptr::write_bytes UB。
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct VerthysSummaryEntry {
    #[ts(type = "number")]
    pub id: u64,
    pub rtype: u32,
    /// 第 11.1 项：记录名称（SecuredString，Drop 时零化擦除）
    pub name: SecuredString,
    /// 原始数据大小（字节，用于显示"大小"列）
    #[ts(type = "number")]
    pub data_size: u64,
    /// 物理槽位偏移（按需加载时直接定位磁盘位置，跳过 B+ 树查找）
    #[ts(type = "number")]
    pub physical_offset: u64,
    /// 第 11.1 项：Merkle 叶子哈希 base64（SecuredString，完整性校验码，Drop 时零化）
    pub merkle_leaf: SecuredString,
    /// ★ Phase 2G：创建时间戳（Unix 秒，列表展示用）
    #[ts(type = "number")]
    pub created_time: u64,
}

/// 第 11.1 项：VerthysSummaryEntry 的 Zeroize 实现
///
/// 仅擦除敏感字段 name / merkle_leaf。其余字段非敏感。
impl Zeroize for VerthysSummaryEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.merkle_leaf.zeroize();
    }
}

// ===== 第 8.1 项：VerthysResponse（阶段 8 标记 deprecated，增量迁移中）=====
//
// 第 8.1 项：ApiResponse<T> 泛型信封 + 操作特化响应类型已定义在 api_error.rs。
// 阶段 5-7 新增的控制器已直接使用结构化响应类型（SecurityResult / ClipboardResult /
// PrivacyModeResult / DeviceBindingResult / PreflightResult 等），不再使用 VerthysResponse。
// 现有遗留控制器（verthys_controller / key_controller / file_controller 等）仍使用
// VerthysResponse，后续增量迁移至 ApiResponse<T>。新代码禁止使用 VerthysResponse。

/* ★ WP-11（P2-3 观测出口）：防御闭环状态报告（主进程侧镜像）
 * 与 worker protocol.rs SecurityStatusReport 字段一一对应（serde 名称对齐）；
 * path_state 下标 = VerthysDefensePath（verthys.h）：
 *   0=挂起绕过 1=内存转储 2=休眠取证 3=IAT/Inline Hook
 *   4=DLL 劫持 5=进程读取 6=跨设备迁移
 * 值域 = VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusReport {
    pub path_state: [u32; 7],
    pub blocked_count: u32,
    pub degraded_count: u32,
    pub failed_count: u32,
    pub all_critical_blocked: bool,
    pub has_degraded: bool,
}

/// 统一 JSON 响应结构（已废弃，新代码使用 ApiResponse<T> 或结构化响应类型）
///
/// 第 8.1 项：新增 ApiResponse<T> 泛型信封替代此结构。
/// 阶段 5-7 新增控制器已使用结构化响应类型。遗留控制器增量迁移中。
#[derive(Serialize, Deserialize)]
pub struct VerthysResponse {
    pub ok: bool,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtype: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 批量枚举记录列表（仅 enumerate_records 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<VerthysRecordEntry>>,
    /// 摘要扫描记录列表（仅 scan_summary_open / scan_summary_next 操作返回）
    /// 轻量元数据，不含数据块（Phase 2C）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_records: Option<Vec<VerthysSummaryEntry>>,
    /// 游标是否已遍历结束（scan_open / scan_fetch 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exhausted: Option<bool>,
    /// 共享内存名称（scan_open 返回，Tauri 主进程据此打开共享内存）
    ///
    /// 第 8.3 项：shm_name 不透传前端，仅主进程内部使用。
    /// 阶段 5 控制器层改造时剥离此字段，改由主进程内部传递。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_name: Option<String>,
    /// 共享内存总大小（字节）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<u64>,
    /// 共享内存中本次返回的记录数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_count: Option<u64>,
    /* ★ 企业级根治方案：解锁响应内联全局主密钥探测结果
     *   worker 解锁成功后进程内一次性完成 has_record + find_lid + get_record，
     *   结果内联到 unlock 响应三字段，彻底消除前端 IPC 链路与 v1 假阴性死锁。
     *   后端仅做透传反序列化 → 前端直接消费。 */
    /// 是否存在全局主密钥记录（仅 unlock 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_global_key: Option<bool>,
    /// 全局主密钥记录的 lid（仅 unlock 操作且 has_global_key=true 时返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_key_id: Option<u64>,
    /// 全局主密钥记录数据 base64（仅 unlock 操作且 has_global_key=true 时返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_key_record: Option<String>,
    /* ★ WP-11（P2-3 观测出口）：防御闭环 7 路径状态
     * 与 worker protocol.rs SecurityStatusReport 字段一一对应；
     * 主进程仅做透传反序列化 → 前端安全中心直接消费。 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_status: Option<SecurityStatusReport>,
    /* ★ Comprehensive_optimization：异步批处理流水线 — 批量导入字段
     *
     * 落实「N 次加密，1 次 IPC 传输」：verthys_add_records_batch 单次 IPC 写入 N 条记录，
     * 返回分配的 verthys ID 列表 + 失败索引 + 检查点信息。WAL 保证断点续传幂等。
     *
     * 字段语义（仅 verthys_add_records_batch / verthys_import_begin / verthys_import_checkpoint 返回）：
     *   - ids：本批次每条记录分配的 verthys ID（0 表示去重跳过或失败）
     *   - batch_id：本批次 ID（从 1 递增，前端据此对齐检查点）
     *   - failed_indices：本批次失败记录的下标列表（加密/入库异常）
     *   - hashes：已 committed 的内容哈希列表（verthys_import_begin / verthys_wal_recover 返回，供生产者去重）
     *   - import_id：导入会话 ID（verthys_import_begin 生成，贯穿整个导入生命周期）
     *   - processed_count：本批次实际处理（含去重跳过）的记录数
     *   - total_count：导入会话累计已 committed 记录数（检查点）
     *   - skipped_count：本批次因哈希去重跳过的记录数 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_indices: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_count: Option<u64>,
}

impl VerthysResponse {
    pub fn ok(op: &str) -> Self {
        VerthysResponse {
            ok: true,
            op: op.into(),
            id: None,
            rtype: None,
            name: None,
            data: None,
            error: None,
            records: None,
            summary_records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
            ids: None,
            batch_id: None,
            failed_indices: None,
            hashes: None,
            import_id: None,
            processed_count: None,
            total_count: None,
            skipped_count: None,
        }
    }
    pub fn err(op: &str, msg: &str) -> Self {
        VerthysResponse {
            ok: false,
            op: op.into(),
            id: None,
            rtype: None,
            name: None,
            data: None,
            error: Some(msg.into()),
            records: None,
            summary_records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
            ids: None,
            batch_id: None,
            failed_indices: None,
            hashes: None,
            import_id: None,
            processed_count: None,
            total_count: None,
            skipped_count: None,
        }
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"ok":false,"op":"error"}"#.into())
    }
}

// ===== 第 8.3 项 / 第 3.4 项：PreflightResult（删除 dir 字段 + 错误码脱敏）=====

/// 路径预检结果（第 8.3 项：删除 dir 字段；第 3.4 项：错误码脱敏）
///
/// 第 8.3 项：删除 dir 字段，前端不再接收路径信息。
/// 第 3.4 项：失败时仅返回标准化错误码 + 无路径提示，不泄露路径。
///   错误码取值：INVALID_PATH / PERMISSION_DENIED / DISK_SPACE_INSUFFICIENT
///   / DISK_SPACE_UNKNOWN / TEMPORARY_FAILURE
/// 详细路径与错误原因仅写入后端日志（经 sanitize_path 脱敏）。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PreflightResult {
    pub ok: bool,
    pub error: Option<String>,
    /// 第 3.4 项：标准化错误码（前端据此差异化处理，不含路径信息）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 第 8.3 项：删除 dir 字段（不透传路径到前端）
    pub is_system_protected: bool,
    pub file_exists: bool,
    /// 磁盘剩余空间（MB）
    #[ts(type = "number")]
    pub disk_space_mb: u64,
    /// 是否自动创建了目录
    pub dir_created: bool,
}

// ===== DiagInfo（第 8.3 项：删除路径字段，改存在性/哈希标识）=====

/// 诊断信息（第 8.3 项：删除 worker_path/dll_path/cwd，改存在性/哈希标识）
///
/// 第 8.3 项变更：
///   - 删除 worker_path: String（不泄露路径）
///   - 删除 dll_path: String（不泄露路径）
///   - 删除 cwd: String（不泄露工作目录）
///   - 新增 worker_exists: bool（保留，原已有）
///   - 新增 dll_hash: String（DLL SHA-256 哈希前 16 字符，用于完整性诊断）
///   - 新增 worker_pid: Option<u32>（worker 进程 PID，运行中时有值）
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct DiagInfo {
    /// worker 可执行文件是否存在
    pub worker_exists: bool,
    /// DLL 文件是否存在
    pub dll_exists: bool,
    /// worker 是否运行中
    pub worker_running: bool,
    /// 第 8.3 项：DLL SHA-256 哈希前 16 字符（完整性诊断用）
    ///
    /// 从 build.rs 生成的 dll_hash.rs 读取，用于诊断 DLL 完整性。
    /// 空字符串表示 DLL 未找到或哈希未生成（开发模式）。
    pub dll_hash: String,
    /// 第 8.3 项：worker 进程 PID（运行中时有值）
    pub worker_pid: Option<u32>,
}

// ===== InitStatusResult（第 8.5 项：使用 InitStatus 枚举）=====

/// 初始化状态查询结果（第 8.5 项：使用 InitStatus 枚举）
///
/// 阶段 1 保留 status: String 字段（向后兼容），
/// 新增 status_enum: Option<InitStatus> 字段供前端渐进迁移。
/// 阶段 8 移除 status 字段，统一使用 status_enum。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct InitStatusResult {
    /// 状态字符串（向后兼容，阶段 8 移除）
    ///
    /// 取值："none" | "ready" | "broken" | "initializing" | "maintenance"
    pub status: String,
    /// 第 8.5 项：状态枚举（类型安全，阶段 8 替代 status 字段）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_enum: Option<InitStatus>,
    /// 加密库路径（ready 时有值，脱敏后返回）
    pub verthys_path: Option<String>,
    /// 状态文件描述
    pub detail: String,
}

// ===== 第 8.6 项：EnumerateBatch（增加 error 字段）=====

/// ★ 项5：枚举记录流式分页批次（Tauri Channel 推送载荷）
///
/// verthys_enumerate_records_stream 命令循环调用 worker enumerate_records，
/// 每批返回通过 on_batch Channel 推送到前端。前端收到一批即渲染一批，
/// 用户感知为渐进式加载而非"瞬间冻结后爆发"，单批处理时间 < 5ms。
///
/// 第 8.6 项：增加 error: Option<ApiError> 字段
/// 批次失败时通过此字段返回错误信息，前端据此决定是否停止循环。
#[derive(serde::Serialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct EnumerateBatch {
    /// 本批记录列表（id/type/name/dataB64）
    pub records: Vec<VerthysRecordEntry>,
    /// 本批最后一条记录的 ID（前端据此发起下一批，0 表示无记录）
    #[ts(type = "number")]
    pub last_id: u64,
    /// 本批记录数
    #[ts(type = "number")]
    pub count: u64,
    /// 是否已遍历完毕（true 时前端停止循环）
    pub exhausted: bool,
    /// 累计已推送记录数（用于前端进度展示）
    #[ts(type = "number")]
    pub total_pushed: u64,
    /// 第 8.6 项：批次错误信息（失败时前端据此停止循环）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::controller::api_error::ApiError>,
}
