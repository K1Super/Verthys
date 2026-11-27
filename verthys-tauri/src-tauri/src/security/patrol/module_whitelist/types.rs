/* ====================================================================== *
 *  数据结构                                                               *
 * ====================================================================== */

/// 检测到的未知/可疑模块信息（前端弹窗展示用，serde::Serialize 序列化）
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnknownModule {
    /// 模块名（如 xxx.dll）
    pub name: String,
    /// 模块完整路径
    pub path: String,
    /// 威胁原因："未知路径" 或 "未签名"
    pub reason: String,
}

/// 模块 Authenticode 签名核验结论。
///
/// 后台巡检据此区分「第三方软件主动注入（NVIDIA Overlay、Bonjour mDNS
/// 命名空间提供程序等）」与「未签名注入」：前者签名链有效，属合法软件
/// 行为；后者才是真正的注入/劫持信号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// 签名链有效，吊销检查通过
    Valid,
    /// 签名链有效，但吊销状态未知（离线 / CRL/OCSP 不可达）
    ValidRevocationUnknown,
    /// 未签名或签名无效
    Invalid,
}

impl SignatureStatus {
    /// 是否可认定为有效签名（吊销状态未知仍视为已签署）
    pub fn is_signed(self) -> bool {
        !matches!(self, SignatureStatus::Invalid)
    }
}

/// 系统目录模块哈希基线核验结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCheck {
    /// 哈希与基线一致
    Match,
    /// 哈希与基线不一致（可能是替换，也可能是系统更新）
    Mismatch,
    /// 无法读取文件计算哈希（文件已删除 / 权限不足）
    Unreadable,
    /// 模块不在基线中（非系统目录模块）
    NotInBaseline,
}
