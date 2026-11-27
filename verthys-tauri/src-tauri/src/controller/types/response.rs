/*
 * 统一 JSON 响应结构
 *
 * 职责边界：VerthysResponse 遗留兼容响应信封，仅供尚未迁移的控制器使用；
 * 新代码应使用 structured response 或 ApiResponse<T>。
 */

use super::*;
use serde::{Deserialize, Serialize};
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
    /// 回退锚点列表（仅 verthys_rollback_anchor_list 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchors: Option<Vec<AnchorInfo>>,
    /// 状态文件整体状态（0=absent / 1=ok / 2=corrupt）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_state: Option<u32>,
    /// 批量释放逐条结果（仅 verthys_rollback_anchor_release_batch 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_release_results: Option<Vec<AnchorReleaseOutcome>>,
    /// 释放条数汇总（批量释放：released=1 的数量）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_released: Option<u32>,
    /// 见证清理失败条数汇总（批量释放返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_cleanup_failed: Option<u32>,
    /// 容器扫描结果（仅 verthys_rollback_anchor_scan 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_scan: Option<AnchorScanResult>,
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
    /// 改钥清理结果：新记录已落盘但旧记录未删除干净（仅 change_global_key 返回）。
    /// true 表示新钥已是权威（最新记录），旧记录将在下次解锁收敛时清除。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_pending: Option<bool>,
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
    /// 存储统计（仅 verthys_storage_stats 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_stats: Option<StorageStatsDto>,
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
            anchors: None,
            anchor_state: None,
            anchor_release_results: None,
            anchor_released: None,
            anchor_cleanup_failed: None,
            anchor_scan: None,
            ids: None,
            cleanup_pending: None,
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
            storage_stats: None,

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
            anchors: None,
            anchor_state: None,
            anchor_release_results: None,
            anchor_released: None,
            anchor_cleanup_failed: None,
            anchor_scan: None,
            ids: None,
            cleanup_pending: None,
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
            storage_stats: None,

        }
    }
}
