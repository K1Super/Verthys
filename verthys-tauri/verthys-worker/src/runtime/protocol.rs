/* protocol.rs — JSON 协议 + base64 编解码
 *
 * 职责：Request / RecordEntry / Response 结构体 + impl Response + base64_encode/decode。
 * 依赖：serde。被引用方：dispatch.rs / gmk.rs / main_loop.rs。
 */

use serde::{Deserialize, Serialize};

/* ------------------------------------------------------------------ *
 * JSON 协议                                                           *
 * ------------------------------------------------------------------ */

#[derive(Deserialize)]
pub(crate) struct Request {
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) id: u64,
    #[serde(default)]
    pub(crate) rtype: u32,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) data: String, // base64
    #[serde(default)]
    pub(crate) old_password: String,
    #[serde(default)]
    pub(crate) new_password: String,
    // GMK 派生相关（#2 敏感操作下沉）
    #[serde(default)]
    pub(crate) bin_data: String, // base64 .bin 文件内容
    #[serde(default)]
    pub(crate) bin_password: String,
    #[serde(default)]
    pub(crate) module_id: String,
    // 安全预设选择（create_with_preset 操作）
    // 0 = BALANCED（日常推荐），1 = SECURE（涉密/合规）
    #[serde(default)]
    pub(crate) preset: u32,
    // 批量删除 ID 列表（delete_records 操作，合并为单次 flush）
    #[serde(default)]
    pub(crate) ids: Vec<u64>,
    // ★ unlock 操作的 flags 位域（预热状态透传）
    // 0x01 = 索引区已预热，0x02 = 允许加载持久化缓存
    #[serde(default)]
    pub(crate) flags: u32,
}

/// 批量枚举返回的单条记录（用于 enumerate_records / scan_fetch 操作）
#[derive(Serialize)]
pub(crate) struct RecordEntry {
    pub(crate) id: u64,
    pub(crate) rtype: u32,
    pub(crate) name: String,
    pub(crate) data: String, // base64
}

/* ★ 防御闭环状态报告（与 verthys.h
 * VerthysSecurityStatus 字段一一对应；path_state 下标 = VerthysDefensePath，
 * 值域 = VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败） */
#[derive(Serialize)]
pub(crate) struct SecurityStatusReport {
    /// 逐路径防御状态（7 项：挂起绕过/内存转储/休眠取证/Hook/DLL劫持/进程读取/跨设备）
    pub(crate) path_state: [u32; 7],
    pub(crate) blocked_count: u32,
    pub(crate) degraded_count: u32,
    pub(crate) failed_count: u32,
    pub(crate) all_critical_blocked: bool,
    pub(crate) has_degraded: bool,
}

#[derive(Serialize)]
pub(crate) struct Response {
    pub(crate) ok: bool,
    pub(crate) op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rtype: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    /// 批量枚举记录列表（仅 enumerate_records / scan_fetch 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) records: Option<Vec<RecordEntry>>,
    /// 游标是否已遍历结束（仅 scan_fetch 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exhausted: Option<bool>,
    /// 共享内存名称（仅 scan_open / scan_fetch 操作返回，Windows 专用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shm_name: Option<String>,
    /// 共享内存总大小（字节）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shm_size: Option<u64>,
    /// 共享内存中本次返回的记录数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) record_count: Option<u64>,
    /* ★ 企业级根治：解锁响应内联全局主密钥探测结果
     *   将原本解锁后 3~4 次 IPC 往返（has_record → find_lid → get_record）
     *   下沉到 worker 解锁成功分支进程内完成，直接内联到 unlock 响应。
     *   消除前端 probe 链路竞态与 v1 容器假阴性导致的 loading 死锁。 */
    /// 是否存在全局主密钥记录（仅 unlock 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) has_global_key: Option<bool>,
    /// 全局主密钥记录的 lid（仅 unlock 操作且 has_global_key=true 时返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_key_id: Option<u64>,
    /// 全局主密钥记录数据 base64（仅 unlock 操作且 has_global_key=true 时返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_key_record: Option<String>,
    /// ★ 防御闭环 7 路径状态（仅 security_status 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) security_status: Option<SecurityStatusReport>,
}

impl Response {
    pub(crate) fn ok(op: &str) -> Self {
        Response {
            ok: true,
            op: op.to_string(),
            id: None,
            rtype: None,
            name: None,
            data: None,
            error: None,
            records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
        }
    }
    pub(crate) fn err(op: &str, code: u32) -> Self {
        // ★ 错误码统一化（反 Oracle 设计，与 verthys.h VerthysResult 契约对齐）：
        //   认证/格式/IO/损坏/内部异常统一映射为 AUTH，防止通过错误码区分
        //   "密码错误"还是"文件篡改"等信息泄露。
        //   功能性状态码按 C 层契约透传，供上层做流程决策（v1 既有 + 扩展）：
        //   - INVALID/NOTFOUND/EXISTS/LOCKED/RATE：v1 既有功能码
        //   - SNAPSHOT(0x0B)：扫描游标快照过期，需重建游标
        //   - PEPPER_SOURCE(0x0C)：OS 托管 pepper 源变更，C 层显式区别于 AUTH，
        //     上层应提示"安全源已变更"而非引导重试密码
        //   - EXPORT_TOO_MANY(0x0D)：导出超 v1 容量上限
        //   - CNG_UNAVAILABLE(0x0E)：CNG 内核态密码服务不可用
        //   - RESOURCE_LIMIT(0x0F)：内存预算耗尽，可回收后重试
        //   - QUORUM_FAILED(0x10)：超级块法定人数不满足，须触发 WAL 恢复
        //   - PARTIAL_UNLOCK(0x11)：渐进式解锁最小可操作状态
        //   - TIMEOUT(0x12)：解锁流水线预算超时，可安全重试
        //   - UNSUPPORTED(0x13)：当前容器格式不支持该操作（退役 op 显式拒绝）
        const VERTHYS_ERR_AUTH: u32 = 0x00000002;
        const VERTHYS_ERR_INVALID: u32 = 0x00000001;
        const VERTHYS_ERR_NOTFOUND: u32 = 0x00000003;
        const VERTHYS_ERR_EXISTS: u32 = 0x00000004;
        const VERTHYS_ERR_LOCKED: u32 = 0x00000007;
        const VERTHYS_ERR_RATE: u32 = 0x0000000A;
        const VERTHYS_ERR_SNAPSHOT: u32 = 0x0000000B;
        const VERTHYS_ERR_PEPPER_SOURCE: u32 = 0x0000000C;
        const VERTHYS_ERR_EXPORT_TOO_MANY: u32 = 0x0000000D;
        const VERTHYS_ERR_CNG_UNAVAILABLE: u32 = 0x0000000E;
        const VERTHYS_ERR_RESOURCE_LIMIT: u32 = 0x0000000F;
        const VERTHYS_ERR_QUORUM_FAILED: u32 = 0x00000010;
        const VERTHYS_ERR_PARTIAL_UNLOCK: u32 = 0x00000011;
        const VERTHYS_ERR_TIMEOUT: u32 = 0x00000012;
        const VERTHYS_ERR_UNSUPPORTED: u32 = 0x00000013;

        let unified_code = match code {
            VERTHYS_ERR_INVALID
            | VERTHYS_ERR_NOTFOUND
            | VERTHYS_ERR_EXISTS
            | VERTHYS_ERR_LOCKED
            | VERTHYS_ERR_RATE
            | VERTHYS_ERR_SNAPSHOT
            | VERTHYS_ERR_PEPPER_SOURCE
            | VERTHYS_ERR_EXPORT_TOO_MANY
            | VERTHYS_ERR_CNG_UNAVAILABLE
            | VERTHYS_ERR_RESOURCE_LIMIT
            | VERTHYS_ERR_QUORUM_FAILED
            | VERTHYS_ERR_PARTIAL_UNLOCK
            | VERTHYS_ERR_TIMEOUT
            | VERTHYS_ERR_UNSUPPORTED => code,
            // AUTH(0x02)/FORMAT(0x05)/IO(0x08)/CORRUPT(0x09)/INTERNAL(0xFFFFFFFF)
            // 及未知码全部统一为 AUTH（反信息泄露）
            _ => VERTHYS_ERR_AUTH,
        };

        Response {
            ok: false,
            op: op.to_string(),
            id: None,
            rtype: None,
            name: None,
            data: None,
            error: Some(format!("ERR_{:08X}", unified_code)),
            records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
        }
    }
}

/* ------------------------------------------------------------------ *
 * base64 编解码                                                       *
 * ------------------------------------------------------------------ */

const B64_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64_TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let cleaned: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    if !cleaned.len().is_multiple_of(4) {
        return Err("invalid base64 length");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let lookup = |c: u8| -> i32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i32,
            b'a'..=b'z' => (c - b'a' + 26) as i32,
            b'0'..=b'9' => (c - b'0' + 52) as i32,
            b'+' => 62,
            b'/' => 63,
            b'=' => -1,
            _ => -2,
        }
    };
    let mut i = 0;
    while i < cleaned.len() {
        let a = lookup(cleaned[i]);
        let b = lookup(cleaned[i + 1]);
        let c = lookup(cleaned[i + 2]);
        let d = lookup(cleaned[i + 3]);
        if a < 0 || b < 0 || c == -2 || d == -2 {
            return Err("invalid base64 char");
        }
        let n = ((a as u32) << 18)
            | ((b as u32) << 12)
            | (if c >= 0 { (c as u32) << 6 } else { 0 })
            | (if d >= 0 { d as u32 } else { 0 });
        out.push((n >> 16) as u8);
        if c >= 0 {
            out.push((n >> 8) as u8);
        }
        if d >= 0 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}
