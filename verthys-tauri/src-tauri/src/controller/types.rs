/*
 * controller/types.rs — 控制器层共享类型定义
 *
 * 架构定位：控制器层数据契约（与前端 verthys.ts 对齐）
 *   - VerthysRecordEntry: 批量枚举返回的单条记录
 *   - VerthysSummaryEntry: 摘要扫描返回的单条记录
 *   - VerthysResponse: 统一 JSON 响应结构（遗留兼容，新代码不得使用）
 *   - PreflightResult: 路径预检结果（仅错误码，不携带路径）
 *   - InitStatusResult: 初始化状态查询结果
 *   - DiagInfo: 诊断信息（仅存在性/哈希标识，不含路径）
 *   - EnumerateBatch: 流式分页批次（可携带批次错误）
 *   - InitStatus / DeviceBindingStatus: 枚举
 *   - RecordType / RecordId: newtype
 *
 *  ts-rs 自动生成 TypeScript 绑定：
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

// ===== InitStatus / DeviceBindingStatus 枚举 =====

/// 加密库初始化状态枚举
///
/// 替代字符串状态（"none"/"ready"/"broken"），提供类型安全。
/// 前端通过枚举变体进行差异化处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "bindings/")]
pub enum InitStatus {
    /// 未初始化（全新用户，无 .verthys 文件）
    #[default]
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

/// 设备绑定状态枚举
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

/// 设备绑定校验结果（结构化返回）
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
    /// 匹配度百分比（0-100，status=match/partial_match 时有值）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_score: Option<u32>,
}

// ===== 剪贴板结构化响应 =====

/// 剪贴板清空结果（结构化返回）
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
    /// 标准化错误码
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

/// 防截屏保护设置结果（结构化返回）
///
/// 窗口捕获排除为整体成功或整体失败，不存在部分保护：
/// partial_protection 字段保留以维持结构稳定，其值恒为假。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PrivacyModeResult {
    /// 操作是否成功（true=保护已按预期切换）
    pub ok: bool,
    /// 保护当前状态（true=已启用，false=已关闭）
    pub enabled: bool,
    /// 恒为假：保护不存在"部分成功"，保留字段仅为契约稳定
    pub partial_protection: bool,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 标准化错误码
    ///
    /// 取值：
    ///   - PRIVACY_BUSY：已有过渡进行中
    ///   - PRIVACY_QUARANTINED：处于隔离状态，需先对账修复
    ///   - PRIVACY_NO_TARGET_WINDOW：未找到可保护窗口
    ///   - PRIVACY_VERIFY_MISMATCH：设置后回读值不符
    ///   - PRIVACY_ROLLED_BACK：失败并已还原，可重试
    ///   - PRIVACY_TOKEN_MISSING：关闭未提供凭证
    ///   - PRIVACY_TOKEN_INVALID：凭证不匹配
    ///   - PRIVACY_LEASE_HELD：已有未决关闭操作
    ///   - PRIVACY_LEASE_EXPIRED：凭证世代已变更
    ///   - PRIVACY_NOT_RESTORED / PRIVACY_ALREADY_ADOPTED：采纳状态不符
    ///   - PRIVACY_TOKEN_INVARIANT_VIOLATION：槽位不变式被破坏
    ///   - PRIVACY_TRANSITION_SUPERSEDED：过渡被新的状态变更取代
    ///   - RATE_LIMITED：频率超限
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 会话令牌（仅开启成功时返回一次）
    ///
    /// 关闭保护需作为 auth_token 传入；成功后即失效、失败后仍可重试，
    /// 不可重复使用，也不存在无授权的重新签发入口。
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl PrivacyModeResult {
    pub fn success(enabled: bool) -> Self {
        let detail = if enabled {
            "防截屏保护已启用".into()
        } else {
            "防截屏保护已关闭".into()
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

    /// 成功并附带会话令牌
    ///
    /// 空令牌按"无令牌"处理：幂等短路与关闭成功都不返回令牌，
    /// 空串若被当作令牌下发，前端会把无效凭证当成有效凭证保存。
    pub fn success_with_token(enabled: bool, token: impl Into<String>) -> Self {
        let detail = if enabled {
            "防截屏保护已启用".into()
        } else {
            "防截屏保护已关闭".into()
        };
        let token = token.into();
        PrivacyModeResult {
            ok: true,
            enabled,
            partial_protection: false,
            detail,
            error_code: None,
            session_token: if enabled && !token.is_empty() {
                Some(token)
            } else {
                None
            },
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

/// 防截屏保护状态快照
///
/// 前端据此决定按钮状态、是否需要接管会话与是否给出恢复入口；
/// 状态与槽位是两处字段的组合，由后端一次锁内读取给出。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PrivacyStatusResult {
    /// 状态机：disabled / enabled / transitioning / quarantined
    pub state: String,
    /// 凭证槽位：empty / pending_adoption / active
    pub slot: String,
    /// 受保护窗口数量
    #[ts(type = "number")]
    pub protected_count: usize,
    /// 隔离原因（仅 quarantined 时存在）
    ///
    /// 取值：rollback_failed / stuck_in_transition /
    /// token_invariant_violation / reconcile_failed
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_reason: Option<String>,
}

// ===== 记录条目类型 =====

/// 批量枚举返回的单条记录（与 worker RecordEntry 对齐）
///
/// Base64 字段附 original_size:u64（原始字节数，base64 解码后长度）
///
/// name / data 使用 SecuredString（Zeroizing<String>）：
///   - Drop 时自动 zeroize 堆内存
///   - 透明 serde（序列化为普通 JSON 字符串），前端契约无感
///   - Deref<Target=str> 兼容 as_str()/len()/is_empty()/as_ptr() 调用
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct VerthysRecordEntry {
    #[ts(type = "number")]
    pub id: u64,
    /// 记录类型
    pub rtype: u32,
    /// 记录名称（SecuredString，Drop 时零化擦除）
    pub name: SecuredString,
    /// Base64 编码的记录数据（SecuredString，Drop 时零化擦除）
    pub data: SecuredString,
    /// 原始数据大小（字节，base64 解码后长度）
    ///
    /// 前端据此预分配解码缓冲区，避免 base64 解码后才知道大小。
    /// 向后兼容：旧响应无此字段时为 None，前端按 data.len() * 3 / 4 估算。
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub original_size: Option<u64>,
}

/// VerthysRecordEntry 的 Zeroize 实现
///
/// 仅擦除敏感字段 name / data（SecuredString::zeroize 以 volatile 写零覆盖堆字节后 clear）。
/// id / rtype / original_size 非敏感，不擦除（保留以便崩溃诊断）。
///
/// 支持泛型 `ScanRecord: Zeroize` 约束，使 `<[VerthysRecordEntry]>::zeroize()`
/// 可直接对整批记录就地擦除。
impl Zeroize for VerthysRecordEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.data.zeroize();
    }
}

/// 摘要扫描返回的单条记录（轻量元数据，不含数据块）
///
/// 与 VerthysRecordEntry 的区别：
///   - 无 data 字段（不解密数据块，解锁后 1-2 秒内完成列表渲染）
///   - 携带 data_size / physical_offset / merkle_leaf（供按需加载定位 + 完整性校验）
///   - 携带 created_time（创建时间戳，解锁后立即展示在列表中）
///
/// merkle_leaf 以 base64 传输（32 字节 → 44 字符），前端用于全盘完整性巡检。
///
/// name / merkle_leaf 使用 SecuredString（Zeroizing<String>）：Drop 时自动零化堆内存。
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct VerthysSummaryEntry {
    #[ts(type = "number")]
    pub id: u64,
    pub rtype: u32,
    /// 记录名称（SecuredString，Drop 时零化擦除）
    pub name: SecuredString,
    /// 原始数据大小（字节，用于显示"大小"列）
    #[ts(type = "number")]
    pub data_size: u64,
    /// 物理槽位偏移（按需加载时直接定位磁盘位置，跳过 B+ 树查找）
    #[ts(type = "number")]
    pub physical_offset: u64,
    /// Merkle 叶子哈希 base64（SecuredString，完整性校验码，Drop 时零化）
    pub merkle_leaf: SecuredString,
    /// 创建时间戳（Unix 秒，列表展示用）
    #[ts(type = "number")]
    pub created_time: u64,
}

/// VerthysSummaryEntry 的 Zeroize 实现
///
/// 仅擦除敏感字段 name / merkle_leaf。其余字段非敏感。
impl Zeroize for VerthysSummaryEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.merkle_leaf.zeroize();
    }
}

// ===== VerthysResponse（遗留兼容结构）=====
//
// ApiResponse<T> 泛型信封 + 操作特化响应类型已定义在 api_error.rs。
// 新代码禁止使用 VerthysResponse，应使用 ApiResponse<T> 或结构化响应类型；
// 现有控制器仍有使用，迁移完成前保留本结构。

/* 防御闭环状态报告（主进程侧镜像）
 * 与 worker protocol.rs SecurityStatusReport 字段一一对应（serde 名称对齐）；
 * path_state 下标 = VerthysDefensePath（verthys.h）：
 *   0=挂起绕过 1=内存转储 2=休眠取证 3=IAT/Inline Hook
 *   4=DLL 劫持 5=进程读取 6=跨设备迁移
 * 值域 = VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败
 * path_reason 值域 = VerthysDefenseReason（0x0014 追加）。 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusReport {
    pub path_state: [u32; 7],
    pub blocked_count: u32,
    pub degraded_count: u32,
    pub failed_count: u32,
    pub all_critical_blocked: bool,
    pub has_degraded: bool,
    pub path_reason: [u32; 7],
    pub limited_count: u32,
    pub policy_flags: u32,
    pub checked_at_unix_ms: u64,
}

/// 统一 JSON 响应结构（遗留兼容，新代码使用 ApiResponse<T> 或结构化响应类型）
///
/// 新控制器使用结构化响应类型；本结构仅供尚未迁移的控制器使用。
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
    /// 结构化错误码（前端按码分支控制流与引导文案，不做文案判定）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 锁定/限流的建议等待秒数（仅锁定类错误返回，前端展示动态倒计时）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// 批量枚举记录列表（仅 enumerate_records 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<VerthysRecordEntry>>,
    /// 摘要扫描记录列表（仅 scan_summary_open / scan_summary_next 操作返回）
    /// 轻量元数据，不含数据块
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_records: Option<Vec<VerthysSummaryEntry>>,
    /// 游标是否已遍历结束（scan_open / scan_fetch 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exhausted: Option<bool>,
    /// 共享内存名称（scan_open 返回，Tauri 主进程据此打开共享内存）
    ///
    /// shm_name 不透传前端，仅主进程内部使用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_name: Option<String>,
    /// 共享内存总大小（字节）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<u64>,
    /// 共享内存中本次返回的记录数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_count: Option<u64>,
    /// 扫描批内解密失败/索引不一致的记录 ID（仅 verthys_scan_open / verthys_scan_next 返回）
    ///
    /// 上游（C 层）按 lid 记账失败条目而不是静默丢弃，worker 透传本字段；
    /// 前端据此把对应条目标记为损坏（区别于"记录不存在"）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_ids: Option<Vec<u64>>,
    /* 解锁响应内联全局主密钥探测结果
     *   worker 解锁成功后进程内一次性完成 has_record + find_lid + get_record，
     *   结果内联到 unlock 响应三字段，前端无需再发起额外 IPC 查询。
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
    /* 防御闭环 7 路径状态
     * 与 worker protocol.rs SecurityStatusReport 字段一一对应；
     * 主进程仅做透传反序列化 → 前端安全中心直接消费。 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_status: Option<SecurityStatusReport>,
    /* 异步批处理流水线 — 批量导入字段
     *
     * 落实「N 次加密，1 次 IPC 传输」：verthys_add_records_batch 单次 IPC 写入 N 条记录，
     * 返回分配的 verthys ID 列表 + 失败索引 + 检查点信息。WAL 保证断点续传幂等。
     *
     * 字段语义（仅 verthys_add_records_batch / verthys_import_begin / verthys_import_checkpoint 返回）：
     *   - ids：本批次每条记录分配的 verthys ID（0 表示幂等跳过或失败）
     *   - batch_id：本批次 ID（从 1 递增，前端据此对齐检查点）
     *   - failed_indices：本批次失败记录的下标列表（加密/入库异常）
     *   - entry_keys：已 committed 的非内容条目键列表（verthys_import_begin / verthys_wal_recover 返回，供生产者续传幂等）
     *   - import_id：导入会话 ID（verthys_import_begin 生成，贯穿整个导入生命周期）
     *   - processed_count：本批次实际处理（含幂等跳过）的记录数
     *   - total_count：导入会话累计已 committed 记录数（检查点）
     *   - skipped_count：本批次因条目键幂等跳过的记录数 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_indices: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_count: Option<u64>,
    /* 落盘自查结果（仅 verthys_verify_disk_persist 返回）
     *
     * 由 worker 进程内 C 层持锁句柄自查产生（主进程外部读在 Windows
     * 强制字节范围锁下必失败）。字段名与 worker protocol.rs 保持一致，
     * serde 反序列化直接同名透传。均为非敏感结构元数据。 */
    /// C 端 VerPersistStatus 状态码（0=OK / 1=HEADER / 2=SIZE / 3=WAL / 4=IO / 5=INTERNAL）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    /// 容器文件字节大小
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    /// 文件修改时间（Unix 毫秒；不可得为 0）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_ms: Option<u64>,
    /// 磁盘偏移 0 的副本帧头 magic
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_magic: Option<u32>,
    /// 容器格式版本
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_version: Option<u32>,
    /* 内容层加密的公开参数（worker 透传）
     *
     * 这些字段不含原始密钥：salt 与 wrapped_key 是落盘公开参数，
     * 文件密钥在使用点由包裹态密钥一次性解封。 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    /// 记录型块密文内嵌的块序号（仅 module_open 的 chunk 布局返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u32>,
    /// 记录型块密文内嵌的块总数（仅 module_open 的 chunk 布局返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    /// 一次性恢复码（仅 v4_create 返回；展示确认后前端必须清零）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code: Option<String>,
    /// PCR 是否已启用（仅 v4_pcr_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_enabled: Option<bool>,
    /// PCR 位图（PCR0–23，仅 v4_pcr_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_select: Option<u32>,
    /// keyfile 因子是否已启用（仅 v4_keyfile_status / enable / disable 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyfile_enabled: Option<bool>,
    /// 当前会话是否由恢复码打开（仅 v4_keyfile_status 返回）；
    /// 恢复会话可重绑/关闭 keyfile（keyfile 丢失逃生）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_mode: Option<bool>,
    /// 模块加密是否已启用（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// 模块本会话是否已解锁（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocked: Option<bool>,
    /// 模块是否已绑定恢复码槽（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_recovery: Option<bool>,
    /// 模块是否已删除（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /* 全库 DEK 轮换统计（仅 v4_rotate_begin 返回）
     *
     * 与 worker protocol.rs rotate_* 字段一一对应；均为统计计数，
     * 不含记录名、明文或密钥。 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_stage: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_modules_ready: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_records: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_chunks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_bytes: Option<u64>,
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
            error_code: None,
            retry_after_secs: None,
            records: None,
            summary_records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            failed_ids: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
            ids: None,
            batch_id: None,
            failed_indices: None,
            entry_keys: None,
            import_id: None,
            processed_count: None,
            total_count: None,
            skipped_count: None,
            status_code: None,
            file_size: None,
            mtime_ms: None,
            header_magic: None,
            header_version: None,
            salt: None,
            wrapped_key: None,
            iterations: None,
            seq: None,
            total: None,
            recovery_code: None,
            pcr_enabled: None,
            pcr_select: None,
            keyfile_enabled: None,
            recovery_mode: None,
            enabled: None,
            unlocked: None,
            has_recovery: None,
            deleted: None,
            rotate_stage: None,
            rotate_modules_ready: None,
            rotate_records: None,
            rotate_files: None,
            rotate_chunks: None,
            rotate_bytes: None,
        }
    }
    /// 结构化错误响应：携带稳定错误码（前端按码分支），文案仅作展示
    pub fn err_code(op: &str, code: &str, msg: &str) -> Self {
        let mut resp = Self::err(op, msg);
        resp.error_code = Some(code.into());
        resp
    }
    /// 结构化锁定/限流错误响应：附建议等待秒数
    pub fn err_code_retry(op: &str, code: &str, msg: &str, retry_after_secs: u64) -> Self {
        let mut resp = Self::err_code(op, code, msg);
        resp.retry_after_secs = Some(retry_after_secs);
        resp
    }
    /// worker 响应把稳定错误码放在 error 字段（ERR_XXXXXXXX）；解析后补齐
    /// error_code，让前端按码分支而不是匹配文案。
    pub fn adopt_worker_error_code(&mut self) {
        if self.ok || self.error_code.is_some() {
            return;
        }
        if let Some(err) = self.error.as_deref() {
            if let Some(hex) = err.strip_prefix("ERR_") {
                if hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    self.error_code = Some(err.to_string());
                }
            }
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
            error_code: None,
            retry_after_secs: None,
            records: None,
            summary_records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            failed_ids: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
            ids: None,
            batch_id: None,
            failed_indices: None,
            entry_keys: None,
            import_id: None,
            processed_count: None,
            total_count: None,
            skipped_count: None,
            status_code: None,
            file_size: None,
            mtime_ms: None,
            header_magic: None,
            header_version: None,
            salt: None,
            wrapped_key: None,
            iterations: None,
            seq: None,
            total: None,
            recovery_code: None,
            pcr_enabled: None,
            pcr_select: None,
            keyfile_enabled: None,
            recovery_mode: None,
            enabled: None,
            unlocked: None,
            has_recovery: None,
            deleted: None,
            rotate_stage: None,
            rotate_modules_ready: None,
            rotate_records: None,
            rotate_files: None,
            rotate_chunks: None,
            rotate_bytes: None,
        }
    }
}

// ===== PreflightResult（错误码脱敏，不携带路径）=====

/// 路径预检结果（错误码脱敏，不携带路径）
///
/// 失败时仅返回标准化错误码 + 无路径提示，不泄露路径。
///   错误码取值：INVALID_PATH / PERMISSION_DENIED / DISK_SPACE_INSUFFICIENT
///   / DISK_SPACE_UNKNOWN / TEMPORARY_FAILURE
/// 详细路径与错误原因仅写入后端日志（经 sanitize_path 脱敏）。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PreflightResult {
    pub ok: bool,
    pub error: Option<String>,
    /// 标准化错误码（前端据此差异化处理，不含路径信息）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 目标路径是否位于系统保护目录（不透传路径到前端）
    pub is_system_protected: bool,
    pub file_exists: bool,
    /// 磁盘剩余空间（MB）
    #[ts(type = "number")]
    pub disk_space_mb: u64,
    /// 是否自动创建了目录
    pub dir_created: bool,
}

// ===== DiagInfo（仅存在性/哈希标识，不含路径）=====

/// 诊断信息（仅存在性与哈希标识，不含 worker/dll 路径与工作目录）
///
/// 不返回路径字段，避免通过诊断接口泄露本地目录结构。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct DiagInfo {
    /// worker 可执行文件是否存在
    pub worker_exists: bool,
    /// DLL 文件是否存在
    pub dll_exists: bool,
    /// worker 是否运行中
    pub worker_running: bool,
    /// DLL SHA-256 哈希前 16 字符（完整性诊断用）
    ///
    /// 从 build.rs 生成的 dll_hash.rs 读取，用于诊断 DLL 完整性。
    /// 空字符串表示 DLL 未找到或哈希未生成（开发模式）。
    pub dll_hash: String,
    /// worker 进程 PID（运行中时有值）
    pub worker_pid: Option<u32>,
}

// ===== InitStatusResult（使用 InitStatus 枚举）=====

/// 初始化状态查询结果
///
/// status 为字符串形式，status_enum 为类型安全枚举，两者并存以保持兼容。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct InitStatusResult {
    /// 状态字符串（取值见下）
    ///
    /// 取值："none" | "ready" | "broken" | "initializing" | "maintenance"
    pub status: String,
    /// 状态枚举（类型安全形式）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_enum: Option<InitStatus>,
    /// 加密库路径（ready 时有值，脱敏后返回）
    pub verthys_path: Option<String>,
    /// 状态文件描述
    pub detail: String,
}

// ===== EnumerateBatch（流式分页批次）=====

/// 枚举记录流式分页批次（Tauri Channel 推送载荷）
///
/// verthys_enumerate_records_stream 命令循环调用 worker enumerate_records，
/// 每批返回通过 on_batch Channel 推送到前端。前端收到一批即渲染一批，
/// 用户感知为渐进式加载而非"瞬间冻结后爆发"，单批处理时间 < 5ms。
///
/// 批次失败时通过 error 字段返回错误信息，前端据此决定是否停止循环。
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
    /// 批次错误信息（失败时前端据此停止循环）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::controller::api_error::ApiError>,
}

// ===== 照片导入批量协议类型 =====
//
// verthys_add_records_batch 的输入/进度契约，与前端 verthys.ts 对齐。
// 定义于本模块供控制器命令入口与单写者通道（state::import_writer）共享，
// 避免跨分层重复定义同一批处理数据类型。

/// 单条已加密记录输入（前端 Worker 池加密后产出）
///
/// 字段语义：
///   - rtype：记录类型（与 verthys_add_record 一致）
///   - name：记录名称（如 `meta_xxx.jpg`）
///   - entry_key：调用方生成的非内容身份键（用于会话内幂等/WAL 续传）
///   - data_b64：已加密的记录数据 base64（前端 XChaCha20-Poly1305 加密产物）
///   - chunk_ids / chunk_hashes：外置块引用（仅大文件外置模式携带；
///     导入时校验块在本会话已成功上传，防止悬空引用）
#[derive(Debug, Clone, Deserialize)]
pub struct BatchRecordInput {
    pub rtype: u32,
    pub name: String,
    #[serde(default)]
    pub entry_key: String,
    pub data_b64: String,
    #[serde(default)]
    pub chunk_ids: Option<Vec<u64>>,
    #[serde(default)]
    pub chunk_hashes: Option<Vec<String>>,
}

/// 单条外置加密块输入（verthys_add_chunk_batch 载荷元素）
///
/// 字段语义：
///   - chunk_key：调用方生成的非内容块键（记录名与会话内幂等依据；
///     不得由内容哈希派生）
///   - data_b64：块密文 base64（前端 XChaCha20-Poly1305 加密产物）
///   - rtype：记录类型（外置载荷角色）。缺省为照片数据块；索引瘦身布局的
///     缩略图记录显式指定缩略图类型，写者据此分配记录名与类型，二者共用
///     同一上传通道、台账与幂等映射
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkBlob {
    #[serde(default)]
    pub chunk_key: String,
    pub data_b64: String,
    #[serde(default)]
    pub rtype: Option<u32>,
}

/// 批量写入进度（通过 Tauri Channel 流式推送到前端）
///
/// 前端在 requestAnimationFrame 内接收并绘制进度条，保证任何时刻最多一帧间隔更新，
/// 绝不参与数据处理热路径。
#[derive(Debug, Clone, Serialize)]
pub struct ImportBatchProgress {
    /// 本批次 ID（从 1 递增，前端据此对齐检查点）
    pub batch_id: u64,
    /// 本批次已处理记录数（含幂等跳过 + 失败）
    pub processed_in_batch: u64,
    /// 本批次总记录数
    pub total_in_batch: u64,
    /// 导入会话累计已 committed 记录数（检查点）
    pub total_committed: u64,
    /// 导入会话累计因条目键幂等跳过的记录数
    pub total_skipped: u64,
    /// 本批次已耗时（毫秒，自批次开始累计）
    pub elapsed_ms: u64,
}
