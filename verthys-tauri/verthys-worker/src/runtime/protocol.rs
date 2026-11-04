/* protocol.rs — JSON 协议 + base64 编解码
 *
 * 职责：Request / RecordEntry / Response 结构体 + impl Response + base64_encode/decode。
 * 依赖：serde。被引用方：dispatch.rs / gmk.rs / main_loop.rs。
 */

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::budget::PB_IPC_MAX_RESPONSE_LINE_BYTES;

/* ------------------------------------------------------------------ *
 * JSON 协议                                                           *
 * ------------------------------------------------------------------ */

/// 批量写入的单条记录（仅 add_records 消费；data 为 base64）
#[derive(Deserialize)]
pub(crate) struct BatchAddRecord {
    pub(crate) rtype: u32,
    pub(crate) name: String,
    /// base64 密文载荷；Zeroizing 保证解码后原始串随请求释放时清零
    pub(crate) data: Zeroizing<String>,
}

/// 口令/记录明文字段统一使用 Zeroizing<String>：
/// Drop 时自动 volatile 清零堆缓冲，主循环 line 缓冲与请求字段
/// 的口令明文在处理完成后不驻留内存。
/// serde 透明：线格式仍为普通 JSON 字符串（zeroize serde feature）。
#[derive(Deserialize)]
pub(crate) struct Request {
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) path: String,
    /// v4 D9 轮换临时新库路径（仅 v4_rotate_begin 消费）。
    /// 必须不存在且与源库同目录；worker 只转发，具体校验由 C 层完成。
    #[serde(default)]
    pub(crate) new_path: String,
    /// v4 D9 轮换提交时是否保留旧库备份（仅 v4_rotate_commit 消费）
    #[serde(default)]
    pub(crate) keep_old: bool,
    /// v4 D9 轮换 Run 的取消事件名（父进程创建的命名事件；仅 v4_rotate_run 消费）
    #[serde(default)]
    pub(crate) cancel_event: String,
    /// 路径授权的模式（read/write；仅 authorize_path 消费）
    #[serde(default)]
    pub(crate) mode: String,
    /// 路径授权绑定的目标操作（仅 authorize_path 消费）
    #[serde(default)]
    pub(crate) target_op: String,
    #[serde(default)]
    pub(crate) password: Zeroizing<String>,
    #[serde(default)]
    pub(crate) id: u64,
    #[serde(default)]
    pub(crate) rtype: u32, // 记录类型（仅 add_record / has_record_by_type 消费）
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) data: Zeroizing<String>, // base64
    /// 批量写入记录列表（仅 add_records 消费；单次上限由 dispatch 校验）
    #[serde(default)]
    pub(crate) records: Vec<BatchAddRecord>,
    // 枚举/扫描批量上限（enumerate_records / scan_open / scan_summary_open）：
    // 0 = 使用各操作缺省值。与 rtype（记录类型）语义分离——曾共用 rtype
    // 字段承载"批量上限"，同名字段双语义导致调用点可读性差，现拆分。
    #[serde(default)]
    pub(crate) max_count: u32,
    #[serde(default)]
    pub(crate) old_password: Zeroizing<String>,
    #[serde(default)]
    pub(crate) new_password: Zeroizing<String>,
    // GMK 派生相关
    #[serde(default)]
    pub(crate) bin_data: Zeroizing<String>, // base64 .bin 文件内容
    #[serde(default)]
    pub(crate) bin_password: Zeroizing<String>,
    // 安全预设选择（create_with_preset 操作）
    // 0 = BALANCED（日常推荐），1 = SECURE（涉密/合规）
    #[serde(default)]
    pub(crate) preset: u32,
    // 批量删除 ID 列表（delete_records 操作，合并为单次 flush）
    #[serde(default)]
    pub(crate) ids: Vec<u64>,
    // unlock 操作的 flags 位域（预热状态透传）
    // 0x01 = 索引区已预热，0x02 = 允许加载持久化缓存
    #[serde(default)]
    pub(crate) flags: u32,
    /// 父进程心跳事件句柄值（仅 arm_heartbeat 消费；该句柄由父进程
    /// DuplicateHandle 注入 worker 进程，worker 只调用 SetEvent）。
    #[serde(default)]
    pub(crate) hb_handle: u64,
    // SHM 载荷认证密钥（base64 编码的一次性 32 字节随机 key；空串=未提供）
    // 仅 scan_fetch / scan_summary_fetch 使用：提供时 worker 写入 SHM 认证块
    #[serde(default)]
    pub(crate) shm_key: String,
    // 扫描投影（仅 scan_open 消费）："" / "full" = 全部记录解密（历史行为），
    // "index" = 仅对不超过 inline_max_bytes 的记录解密取数（列表/索引类调用）
    #[serde(default)]
    pub(crate) project: String,
    // INDEX 投影的内联数据字节阈值（scan_open；0 = 纯索引，任何记录都不取数）
    #[serde(default)]
    pub(crate) inline_max_bytes: u64,
    // v4 模块 M1 的模块索引（0=photo/1=accounts/2=fileverthys；
    // 0xFFFFFFFF 仅 v4_module_lock 表示全部）
    #[serde(default)]
    pub(crate) module_id: u32,
    // v4 PCR 位图（PCR0–23），仅 v4_pcr_enable 消费
    #[serde(default)]
    pub(crate) pcr_select: u32,
    // v4 模块启用/绑定恢复槽时的当前容器恢复码（可空）
    #[serde(default)]
    pub(crate) recovery_code: Zeroizing<String>,
    // v4 keyfile 因子（D3）：VKFL 文件绝对路径（仅 keyfile 系列 op 消费）。
    // 只传路径；文件内容由 C 层在 worker 进程内读取，不进入 IPC 载荷。
    #[serde(default)]
    pub(crate) keyfile_path: String,
    // v4 恢复码轮换时的旧恢复码
    #[serde(default)]
    pub(crate) old_recovery: Zeroizing<String>,
    // v4 模块删除的二次确认字面量（必须为 "DELETE"，非密钥）
    #[serde(default)]
    pub(crate) confirm: String,
    // 内容层加密的模块标识（photo / file）
    #[serde(default)]
    pub(crate) module: String,
    // 内容层加密的具体布局种类（meta / chunk / slim_meta / slim_chunk / thumb / chunkset / v2_chunk / v2_check）
    #[serde(default)]
    pub(crate) kind: String,
    // 文件盐（base64，16 字节）；空串表示由 worker 生成或从密文头部读取
    #[serde(default)]
    pub(crate) salt: String,
    // BLAKE3 文件哈希（64 字符十六进制）
    #[serde(default)]
    pub(crate) file_hash: String,
    // 块序号（0 起）与块总数；seq < total 且 total > 0
    #[serde(default)]
    pub(crate) seq: u32,
    #[serde(default)]
    pub(crate) total: u32,
    // 文件块 v2 的 PBKDF2 迭代次数；0 表示采用缺省值
    #[serde(default)]
    pub(crate) iterations: u32,
    /* 注意：旧版 module_seal/open 的 wrapped_key 参数已随 v3 内容路径退役。
     * 请求里若仍携带该字段，serde 按未知字段忽略——它不是密钥材料，
     * v4 分片的外层密钥由 C 层 MDEK 持有。 */
}

/// 批量枚举返回的单条记录（用于 enumerate_records / scan_fetch 操作）
#[derive(Serialize)]
pub(crate) struct RecordEntry {
    pub(crate) id: u64,
    pub(crate) rtype: u32,
    pub(crate) name: String,
    pub(crate) data: String, // base64
}

impl Drop for RecordEntry {
    /* 记录名与 base64 数据都属于敏感明文派生，Drop 时清零堆缓冲，
     * 避免批量枚举响应在序列化完成后把明文留在分配器中。 */
    fn drop(&mut self) {
        self.name.zeroize();
        self.data.zeroize();
    }
}

/* 防御闭环状态报告（与 verthys.h
 * VerthysSecurityStatus 字段一一对应；path_state 下标 = VerthysDefensePath，
 * 值域 = VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败）。
 * 0x0014 追加 path_reason/limited_count/policy_flags/checked_at_unix_ms。 */
#[derive(Serialize)]
pub(crate) struct SecurityStatusReport {
    /// 逐路径防御状态（7 项：挂起绕过/内存转储/休眠取证/Hook/DLL劫持/进程读取/跨设备）
    pub(crate) path_state: [u32; 7],
    pub(crate) blocked_count: u32,
    pub(crate) degraded_count: u32,
    pub(crate) failed_count: u32,
    pub(crate) all_critical_blocked: bool,
    pub(crate) has_degraded: bool,
    /// 逐路径判定原因码（VerthysDefenseReason）
    pub(crate) path_reason: [u32; 7],
    /// 架构限制导致的降级路径数
    pub(crate) limited_count: u32,
    /// 运行时守卫与策略位（bit0=心跳 bit1=挂起守卫 bit2=防转储巡检）
    pub(crate) policy_flags: u32,
    /// 快照采样时间（Unix 毫秒）
    pub(crate) checked_at_unix_ms: u64,
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
    /* 修复：解锁响应内联全局主密钥探测结果
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
    /// 防御闭环 7 路径状态（仅 security_status 操作返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) security_status: Option<SecurityStatusReport>,
    /// 批内解密失败/索引不一致的记录 ID（仅 scan_open / scan_fetch 返回）
    ///
    /// C 层按 lid 记账失败条目（不静默丢弃），worker 以本字段透传；上游
    /// 据此把对应条目标记为损坏，与"记录不存在"区分开。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failed_ids: Option<Vec<u64>>,
    /// 按类型枚举返回的记录 ID 列表（仅 list_ids_by_type 操作返回）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ids: Vec<u64>,
    /* 落盘自查结果（仅 verify_persist 操作返回）：
     * 主机侧命令消费这些字段做三态判定（OK / 可重试 IO / 结构性失败）。
     * 均为非敏感结构元数据，不含密钥或明文。 */
    /// C 端 VerPersistStatus 状态码（0=OK / 1=HEADER / 2=SIZE / 3=WAL / 4=IO / 5=INTERNAL）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status_code: Option<i32>,
    /// 容器文件字节大小
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_size: Option<u64>,
    /// 文件修改时间（Unix 毫秒；不可得为 0）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mtime_ms: Option<u64>,
    /// 磁盘偏移 0 的副本帧头 magic
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) header_magic: Option<u32>,
    /// 容器格式版本
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) header_version: Option<u32>,
    /// WAL 区起始绝对偏移
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) wal_offset: Option<u64>,
    /// 记录型块密文内嵌的块序号（仅 module_open 的 chunk 布局返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) seq: Option<u32>,
    /// 记录型块密文内嵌的块总数（仅 module_open 的 chunk 布局返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) total: Option<u32>,
    /// v4 模块加密是否已启用（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) enabled: Option<bool>,
    /// v4 模块本会话是否已解锁（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unlocked: Option<bool>,
    /// v4 模块是否已绑定恢复码槽（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) has_recovery: Option<bool>,
    /// v4 模块是否已删除（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) deleted: Option<bool>,
    /// PCR 是否已启用（仅 v4_pcr_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pcr_enabled: Option<bool>,
    /// PCR 位图（PCR0–23，仅 v4_pcr_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pcr_select: Option<u32>,
    /// v4 keyfile 因子是否已启用（仅 v4_keyfile_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) keyfile_enabled: Option<bool>,
    /// 当前会话是否由恢复码打开（仅 v4_keyfile_status 返回）；
    /// 恢复会话允许重绑/关闭 keyfile（丢失逃生）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_mode: Option<bool>,
    /// v4 恢复码轮换成功后的新码（仅本条响应内有效，序列化后立即清零）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_code: Option<String>,
    /* v4 D9 全库 DEK 轮换统计（仅 v4_rotate_begin 返回）。
     * 字段前缀 rotate_ 避免与既有 records（批量记录列表）语义冲突。 */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rotate_stage: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rotate_modules_ready: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rotate_records: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rotate_files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rotate_chunks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rotate_bytes: Option<u64>,
}

impl Response {
    /// 清零响应中的敏感明文。
    ///
    /// 序列化完成后必须调用；批量记录由 `RecordEntry::drop` 负责，
    /// 此处只处理单条记录名、单条数据与全局主密钥数据。
    /// 错误文本不含密钥，保留以便诊断。
    pub(crate) fn scrub(&mut self) {
        if let Some(name) = self.name.as_mut() {
            name.zeroize();
        }
        if let Some(data) = self.data.as_mut() {
            data.zeroize();
        }
        if let Some(record) = self.global_key_record.as_mut() {
            record.zeroize();
        }
        if let Some(code) = self.recovery_code.as_mut() {
            code.zeroize();
        }
    }

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
            failed_ids: None,
            ids: Vec::new(),
            status_code: None,
            file_size: None,
            mtime_ms: None,
            header_magic: None,
            header_version: None,
            wal_offset: None,
            seq: None,
            total: None,
            enabled: None,
            unlocked: None,
            has_recovery: None,
            deleted: None,
            pcr_enabled: None,
            pcr_select: None,
            keyfile_enabled: None,
            recovery_mode: None,
            recovery_code: None,
            rotate_stage: None,
            rotate_modules_ready: None,
            rotate_records: None,
            rotate_files: None,
            rotate_chunks: None,
            rotate_bytes: None,
        }
    }
    pub(crate) fn err(op: &str, code: u32) -> Self {
        // 错误码统一化（反 Oracle 设计，与 verthys.h VerthysResult 契约对齐）：
        //   认证/格式/IO/损坏/内部异常统一映射为 AUTH，防止通过错误码区分
        //   "密码错误"还是"文件篡改"等信息泄露。
        //   功能性状态码按 C 层契约透传，供上层做流程决策（v1 既有 + 扩展）：
        //   - INVALID/NOTFOUND/EXISTS/LOCKED/RATE：v1 既有功能码
        //   - SNAPSHOT(0x0B)：扫描游标快照过期，需重建游标
        //   - PEPPER_SOURCE(0x0C)：OS 托管 pepper 源变更，C 层显式区别于 AUTH，
        //     上层应提示"安全源已变更"而非引导重试密码
        //   - EXPORT_TOO_MANY(0x0D)：导出超 v1 容量上限
        //   - CNG_UNAVAILABLE(0x0E)：CNG 内核态密码服务不可用
        //   - RESOURCE_LIMIT(0x0F)：容量告罄（内存预算耗尽可回收后重试；
        //     容器 extent/audit 容量或磁盘空间耗尽不可自愈，须用户释放空间）
        //   - QUORUM_FAILED(0x10)：超级块法定人数不满足，须触发 WAL 恢复
        //   - PARTIAL_UNLOCK(0x11)：渐进式解锁最小可操作状态
        //   - TIMEOUT(0x12)：解锁流水线预算超时，可安全重试
        //   - UNSUPPORTED(0x13)：当前容器格式不支持该操作（退役 op 显式拒绝）
        //   - NONCE_EXHAUSTED(0x14)：加密层 nonce 计数器耗尽，须密钥轮换
        //   - CONTAINER_BUSY(0x15)：容器被其他进程独占占用
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
        const VERTHYS_ERR_NONCE_EXHAUSTED: u32 = 0x00000014;
        const VERTHYS_ERR_CONTAINER_BUSY: u32 = 0x00000015;
        const VERTHYS_ERR_POLICY: u32 = 0x00000017;
        const VERTHYS_ERR_TPM: u32 = 0x00000018;
        const VERTHYS_ERR_ROLLBACK: u32 = 0x00000019;
        const VERTHYS_ERR_KEYFILE_REQUIRED: u32 = 0x0000001A;
        const VERTHYS_ERR_KEYFILE_INVALID: u32 = 0x0000001B;
        const VERTHYS_ERR_ROTATE_PENDING: u32 = 0x0000001C;
        const VERTHYS_ERR_MODULE_LOCKED: u32 = 0x0000001D;
        const VERTHYS_ERR_NO_SPACE: u32 = 0x0000001E;
        const VERTHYS_ERR_VERIFY: u32 = 0x0000001F;

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
            | VERTHYS_ERR_UNSUPPORTED
            | VERTHYS_ERR_NONCE_EXHAUSTED
            | VERTHYS_ERR_CONTAINER_BUSY
            | VERTHYS_ERR_POLICY
            | VERTHYS_ERR_TPM
            | VERTHYS_ERR_ROLLBACK
            | VERTHYS_ERR_KEYFILE_REQUIRED
            | VERTHYS_ERR_KEYFILE_INVALID
            | VERTHYS_ERR_ROTATE_PENDING
            | VERTHYS_ERR_MODULE_LOCKED
            | VERTHYS_ERR_NO_SPACE
            | VERTHYS_ERR_VERIFY => code,
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
            failed_ids: None,
            ids: Vec::new(),
            status_code: None,
            file_size: None,
            mtime_ms: None,
            header_magic: None,
            header_version: None,
            wal_offset: None,
            seq: None,
            total: None,
            enabled: None,
            unlocked: None,
            has_recovery: None,
            deleted: None,
            pcr_enabled: None,
            pcr_select: None,
            keyfile_enabled: None,
            recovery_mode: None,
            recovery_code: None,
            rotate_stage: None,
            rotate_modules_ready: None,
            rotate_records: None,
            rotate_files: None,
            rotate_chunks: None,
            rotate_bytes: None,
        }
    }
}

/* ------------------------------------------------------------------ *
 * 响应行写侧约束                                                      *
 * ------------------------------------------------------------------ */

/// 单条响应行的字节上限（写侧自我约束）。
///
/// Why：父进程按行读取 worker 输出，并对超过其读取上限的行判定为协议断裂
///   （标记子进程死亡、后续请求全部失败）。合法记录（导入侧允许单条
///   12 MiB 的 base64 载荷）经取回再编码后可达约 16 MiB，若原样写出就会
///   命中该判定。写侧先按本上限收敛：超限响应替换为受控错误行，
///   使失败停在"单条读取失败"而不是"整个会话被打断"。
///
/// 取值约束（由跨层预算常量静态断言）：大于最大合法响应行，
///   且小于父进程读取上限（父进程侧留有更大兜底值以识别真正的协议损坏）。
pub(crate) const MAX_RESPONSE_LINE_BYTES: usize = PB_IPC_MAX_RESPONSE_LINE_BYTES as usize;

/// 约束响应行长度：未超限原样返回；超限返回受控错误响应。
///
/// @param json 已序列化的响应行
/// @param op 请求操作名（保留在错误响应中，便于上层定位失败的操作）
/// @return 可安全写入 stdout 的单行 JSON
pub(crate) fn bound_response_line(mut json: String, op: &str) -> String {
    if json.len() <= MAX_RESPONSE_LINE_BYTES {
        return json;
    }
    /* 超限响应可能包含大段记录明文；替换为受控错误行前先记录长度，
     * 再清零原缓冲。清零会截断字符串，先取长度才能给出准确的诊断值。 */
    let observed = json.len();
    json.zeroize();
    serde_json::json!({
        "ok": false,
        "op": op,
        "error": format!(
            "response payload too large: {} bytes exceeds limit {} bytes",
            observed, MAX_RESPONSE_LINE_BYTES
        ),
    })
    .to_string()
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

#[cfg(test)]
mod tests {
    use super::{
        base64_decode, base64_encode, bound_response_line, Request, Response,
        MAX_RESPONSE_LINE_BYTES,
    };

    // 扫描投影请求字段：缺省（不传该字段的既有调用方）必须等价于
    // FULL 投影 + 无内联阈值，语义与历史行为一致
    #[test]
    fn request_scan_projection_defaults_to_full() {
        let req: Request = serde_json::from_str(r#"{"op":"scan_open"}"#)
            .expect("无投影字段的请求必须可解析");
        assert_eq!(req.project, "");
        assert_eq!(req.inline_max_bytes, 0);

        let req2: Request = serde_json::from_str(
            r#"{"op":"scan_open","project":"index","inline_max_bytes":65536}"#,
        )
        .expect("显式投影字段必须可解析");
        assert_eq!(req2.project, "index");
        assert_eq!(req2.inline_max_bytes, 65536);
    }

    // 全局密钥读回验证依赖的编码契约：decode(encode(x)) == x 且
    // encode 为无换行标准字母表——AddRecord 写入的 record base64 与
    // GetRecord 读回重编码结果必须逐字节相等，否则落盘读回验证恒失败。
    #[test]
    fn base64_roundtrip_idempotent() {
        let samples: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0u8, 1, 2, 3, 4, 5, 6, 7],
            &[0xFFu8; 10],
            &[0u8; 124], // 全局密钥 record 长度
        ];
        for s in samples {
            let enc = base64_encode(s);
            assert!(!enc.contains('\n'), "输出不得含换行");
            let dec = base64_decode(&enc).expect("decode(encode(x)) 必须成功");
            assert_eq!(dec.as_slice(), *s, "roundtrip 字节相等");
            assert_eq!(base64_encode(&dec), enc, "encode 幂等：重编码逐字节相等");
        }
    }

    // 传输层容错：decode 宽容 CR/LF/空格（SHM/管道拼接场景）
    #[test]
    fn base64_decode_tolerates_whitespace() {
        let enc = base64_encode(&[0xABu8; 13]);
        let with_crlf = format!("{}\r\n{}", &enc[..8], &enc[8..]);
        let dec = base64_decode(&with_crlf).expect("CR/LF 容错");
        assert_eq!(dec, vec![0xABu8; 13]);
    }

    // 写侧约束：上限内原样透传
    #[test]
    fn bound_response_line_passes_through_within_limit() {
        let json = r#"{"ok":true,"op":"get_record","data":"AAAA"}"#.to_string();
        assert_eq!(bound_response_line(json.clone(), "get_record"), json);
    }

    // 写侧约束：超限响应被替换为受控错误行（保留 op 便于定位失败操作）
    #[test]
    fn bound_response_line_replaces_oversized_payload() {
        let oversized = format!(
            r#"{{"ok":true,"op":"get_record","data":"{}"}}"#,
            "A".repeat(MAX_RESPONSE_LINE_BYTES),
        );
        assert!(oversized.len() > MAX_RESPONSE_LINE_BYTES);

        let bounded = bound_response_line(oversized, "get_record");
        assert!(bounded.len() < 4096, "受控错误行必须是固定量级的小体积");
        let v: serde_json::Value =
            serde_json::from_str(&bounded).expect("受控错误行必须是合法 JSON");
        assert_eq!(v["ok"], serde_json::Value::Bool(false));
        assert_eq!(v["op"], serde_json::Value::String("get_record".into()));
        assert!(
            v["error"]
                .as_str()
                .unwrap_or_default()
                .contains("too large")
        );
    }

    // 跨层预算：导入侧允许的最大记录取回后仍落在写侧上限内
    #[test]
    fn max_legal_record_response_fits_writer_limit() {
        // 与导入守卫一致：单条记录的 base64 载荷上限取自跨层预算常量
        let payload = crate::runtime::budget::PB_IPC_MAX_PAYLOAD_BYTES as usize;
        let worst_case = payload / 3 * 4 + 64 * 1024;
        assert!(
            worst_case < MAX_RESPONSE_LINE_BYTES,
            "最大合法响应行 {} 字节必须落在写侧上限 {} 字节内",
            worst_case,
            MAX_RESPONSE_LINE_BYTES
        );
    }

    // 模块策略拒绝必须保留 0x17，不得折叠为 AUTH：调用方需要区分
    // “模块未解锁/未绑定恢复码”和“口令错误”。
    #[test]
    fn policy_error_not_collapsed_to_auth() {
        let resp = Response::err("v4_module_unlock", 0x00000017);
        assert_eq!(resp.error.as_deref(), Some("ERR_00000017"));
        let auth = Response::err("v4_module_unlock", 0x00000002);
        assert_eq!(auth.error.as_deref(), Some("ERR_00000002"));
    }

    // 恢复码轮换响应只能存活到序列化完成；scrub 后不得残留。
    #[test]
    fn recovery_code_response_is_scrubbed() {
        let mut resp = Response::ok("v4_recovery_rotate");
        resp.recovery_code = Some("ABCD-EFGH".into());
        resp.scrub();
        let code = resp.recovery_code.as_deref().unwrap_or("");
        assert!(code.chars().all(|c| c == '\0'), "恢复码必须被清零");
    }

    // TPM/回滚错误必须保留 0x18/0x19：UI 需要引导恢复码重密封或提示文件回退，
    // 折叠为 AUTH 会让这两类可行动错误退化成“口令错误”。
    #[test]
    fn tpm_and_rollback_errors_not_collapsed_to_auth() {
        let tpm = Response::err("v4_pcr_enable", 0x00000018);
        assert_eq!(tpm.error.as_deref(), Some("ERR_00000018"));
        let rollback = Response::err("unlock", 0x00000019);
        assert_eq!(rollback.error.as_deref(), Some("ERR_00000019"));
    }

    // 轮换作业错误必须保留原码：调用方需要区分“作业进行中/模块未解锁/
    // 空间不足/完整性复核失败”，折叠为 AUTH 会使这四类可行动错误退化。
    #[test]
    fn rotate_errors_not_collapsed_to_auth() {
        for code in [0x0000001Cu32, 0x0000001D, 0x0000001E, 0x0000001F] {
            let resp = Response::err("v4_rotate_run", code);
            let expected = format!("ERR_{:08X}", code);
            assert_eq!(resp.error.as_deref(), Some(expected.as_str()));
        }
    }

    // v4 模块请求字段：缺省值必须兼容既有调用方，显式字段可解析。
    #[test]
    fn request_v4_module_fields_parse() {
        let req: Request = serde_json::from_str(r#"{"op":"v4_module_unlock"}"#)
            .expect("无模块字段的请求必须可解析");
        assert_eq!(req.module_id, 0);
        assert!(req.recovery_code.is_empty());
        assert!(req.old_recovery.is_empty());

        let req2: Request = serde_json::from_str(
            r#"{"op":"v4_module_enable","module_id":2,"password":"pw","recovery_code":"CODE"}"#,
        )
        .expect("模块请求必须可解析");
        assert_eq!(req2.module_id, 2);
        assert_eq!(req2.recovery_code.as_str(), "CODE");

        let pcr: Request =
            serde_json::from_str(r#"{"op":"v4_pcr_enable","pcr_select":2176}"#)
                .expect("PCR 请求必须可解析");
        assert_eq!(pcr.pcr_select, 2176);
    }
}