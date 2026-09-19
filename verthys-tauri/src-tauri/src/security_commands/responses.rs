/*
 * responses.rs — 安全命令响应类型定义
 *
 *
 *
 * 职责：
 *   集中定义所有安全命令返回给前端的响应类型，保留全部
 *   #[derive(serde::Serialize, TS)] 属性以维持序列化与 TS 绑定生成。
 */

use ts_rs::TS;

/* ====================================================================== *
 *  响应类型                                                               *
 * ====================================================================== */

/// 暴力拦截检查结果（序列化给前端）
#[derive(serde::Serialize, TS)]
#[serde(tag = "kind")]
#[ts(export, export_to = "bindings/")]
pub enum BruteForceCheckResponse {
    /// 允许尝试解锁
    Allow,
    /// 界面锁定中，剩余秒数
    Locked { #[ts(type = "number")] remaining_secs: u64 },
    /// 需要清空索引并触发完整性校验
    PurgeRequired,
}

/// 暴力拦截状态快照
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct BruteForceStatus {
    pub consecutive_failures: u32,
    pub total_failures: u32,
    #[ts(type = "number")]
    pub remaining_lock_secs: u64,
    pub purge_required: bool,
}

/// 模块巡检结果中的未知模块
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct UnknownModuleInfo {
    pub name: String,
    pub path: String,
    pub reason: String,
}

/// 影子休眠状态（返回真实 txid）
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct ShadowSleepStatus {
    pub in_shadow_sleep: bool,
    #[ts(type = "number")]
    pub txid: u64,
}

/// 敏感操作结构化结果
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct SecurityResult {
    /// 操作是否成功
    pub ok: bool,
    /// 用户可读描述
    pub detail: String,
    /// 错误码（PERMISSION_DENIED / INVALID_TOKEN / INVALID_PATH / RATE_LIMITED / INTERNAL）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl SecurityResult {
    pub fn success(detail: impl Into<String>) -> Self {
        SecurityResult {
            ok: true,
            detail: detail.into(),
            error_code: None,
        }
    }

    pub fn error(code: &str, detail: impl Into<String>) -> Self {
        SecurityResult {
            ok: false,
            detail: detail.into(),
            error_code: Some(code.to_string()),
        }
    }
}

/// 权限令牌生成结果
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct AuthTokenResult {
    pub ok: bool,
    pub token: Option<String>,
    pub detail: String,
}

/// 三档安全预设配置（前端展示用）
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PresetConfig {
    /// 预设名称：BALANCED / SECURE / PERFORMANCE
    pub name: &'static str,
    /// 预设代号：0=BALANCED, 1=SECURE, 2=PERFORMANCE
    pub code: u32,
    /// 各安全特性开关
    pub features: PresetFeatures,
}

#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PresetFeatures {
    pub anti_debug: bool,
    pub anti_inject: bool,
    pub integrity_check: bool,
    pub memory_guard: bool,
    pub key_separation: bool,
    pub emergency_response: bool,
    pub session_lock_on_idle: bool,
    pub shadow_sleep: bool,
    pub module_patrol: bool,
    pub clip_clear_on_lock: bool,
    pub usb_clone_detect: bool,
    pub trace_cleanup: bool,
}
