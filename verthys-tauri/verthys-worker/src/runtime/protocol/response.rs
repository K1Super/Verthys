/* response.rs — Response 与响应行长度约束
 *
 * 职责：Response 结构体、impl Response（构造/错误折叠/清零）、
 *       MAX_RESPONSE_LINE_BYTES 与 bound_response_line。
 */

use serde::Serialize;
use zeroize::Zeroize;

use crate::runtime::budget::PB_IPC_MAX_RESPONSE_LINE_BYTES;

use super::payloads::{
    CompactResultEntry, FileFinishPayload, FileNextPayload, MediaDamageScan, MediaExportPayload,
    MediaFinishPayload, MediaMetaItem, MediaNextPayload, MediaPreviewRecord, MediaReadPayload,
    MediaVencPreview, StorageStatsEntry,
};
use super::records::{AnchorEntry, KernelStatusReport, RecordEntry, SecurityStatusReport};

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
    /// 结构化错误码（可选；如照片布局不支持原生读取）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    /// 锁定/限流的建议等待秒数（0x0A RATE / 0x1D MODULE_LOCKED 响应携带）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) retry_after_secs: Option<u64>,
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
    /// 内核加固状态（仅 kernel_status 轻量查询返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kernel_status: Option<KernelStatusReport>,
    /// 回退锚点列表（仅 rollback_anchor_list 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchors: Option<Vec<AnchorEntry>>,
    /// 状态文件整体状态（0=absent/1=ok/2=corrupt，仅 rollback_anchor_list 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchor_state: Option<u32>,
    /// 回收条数（仅 rollback_anchor_reclaim 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchor_removed: Option<u32>,
    /// 释放条数（仅 rollback_anchor_release 返回；1=删除，0=幂等未命中）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchor_released: Option<u32>,
    /// 见证清理失败条数（仅 rollback_anchor_reclaim/release 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchor_cleanup_failed: Option<u32>,
    /// 批内解密失败/索引不一致的记录 ID（仅 scan_open / scan_fetch 返回）
    ///
    /// C 层按 lid 记账失败条目（不静默丢弃），worker 以本字段透传；上游
    /// 据此把对应条目标记为损坏，与"记录不存在"区分开。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failed_ids: Option<Vec<u64>>,
    /// 按类型枚举返回的记录 ID 列表（仅 list_ids_by_type 操作返回）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ids: Vec<u64>,
    /// 改钥清理结果：新记录已落盘但旧记录未删除干净（仅 change_global_key 返回）。
    /// true 表示新钥已是权威（最新记录），旧记录将在下次解锁收敛时清除。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cleanup_pending: Option<bool>,
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
    /// 模块加密是否已启用（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) enabled: Option<bool>,
    /// 模块本会话是否已解锁（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unlocked: Option<bool>,
    /// 模块是否已绑定恢复码槽（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) has_recovery: Option<bool>,
    /// 模块是否已删除（仅 v4_module_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) deleted: Option<bool>,
    /// PCR 是否已启用（仅 v4_pcr_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pcr_enabled: Option<bool>,
    /// PCR 位图（PCR0–23，仅 v4_pcr_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pcr_select: Option<u32>,
    /// keyfile 因子是否已启用（仅 v4_keyfile_status 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) keyfile_enabled: Option<bool>,
    /// 当前会话是否由恢复码打开（仅 v4_keyfile_status 返回）；
    /// 恢复会话允许重绑/关闭 keyfile（丢失逃生）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_mode: Option<bool>,
    /// 恢复码轮换成功后的新码（仅本条响应内有效，序列化后立即清零）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_code: Option<String>,
    /* 全库 DEK 轮换统计（仅 v4_rotate_begin 返回）。
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
    /// 存储统计（仅 storage_stats 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) storage_stats: Option<StorageStatsEntry>,
    /// 压缩结果（仅 storage_compact 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) compact_result: Option<CompactResultEntry>,
    /// 照片导入单步结果（仅 photo_import_job_next 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo: Option<MediaNextPayload>,
    /// 清藏导入单步结果（仅 file_import_job_next 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file: Option<FileNextPayload>,
    /// 清藏导入收尾结果（仅 file_import_job_finish 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_finish: Option<FileFinishPayload>,
    /// 照片导入收尾结果（仅 photo_import_job_finish 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_finish: Option<MediaFinishPayload>,
    /// 照片读取结果（仅 photo_read_job_* 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_read: Option<MediaReadPayload>,
    /// 懒生成预览的待写回记录（仅 photo_read_job_begin 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_record: Option<MediaPreviewRecord>,
    /// 照片导出单事件（仅 photo_export_job_next 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_export: Option<MediaExportPayload>,
    /// 网格展示元数据（仅 photo_meta_get 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_meta: Option<Vec<MediaMetaItem>>,
    /// 元数据损坏扫描结果（仅 photo_meta_probe 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_damage: Option<MediaDamageScan>,
    /// VENC 清单预览（仅 photo_venc_inspect 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_previews: Option<Vec<MediaVencPreview>>,
    /// 名称查找是否命中（仅 find_lid_by_name 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) found: Option<bool>,
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
        if let Some(read) = self.photo_read.as_mut() {
            if let Some(data) = read.data_b64.as_mut() {
                data.zeroize();
            }
        }
        if let Some(record) = self.photo_record.as_mut() {
            record.data_b64.zeroize();
        }
        if let Some(photo) = self.photo.as_mut() {
            if let Some(thumb) = photo.thumb_b64.as_mut() {
                thumb.zeroize();
            }
        }
        if let Some(finish) = self.photo_finish.as_mut() {
            finish.meta_b64.zeroize();
            if let Some(preview) = finish.preview_b64.as_mut() {
                preview.zeroize();
            }
        }
        if let Some(export) = self.photo_export.as_mut() {
            if let Some(data) = export.data_b64.as_mut() {
                data.zeroize();
            }
        }
        if let Some(items) = self.photo_meta.as_mut() {
            for item in items {
                if let Some(thumb) = item.thumb_b64.as_mut() {
                    thumb.zeroize();
                }
            }
        }
        if let Some(previews) = self.photo_previews.as_mut() {
            for preview in previews {
                preview.thumb_b64.zeroize();
            }
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
            error_code: None,
            retry_after_secs: None,
            records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
            kernel_status: None,
            anchors: None,
            anchor_state: None,
            anchor_removed: None,
            anchor_released: None,
            anchor_cleanup_failed: None,
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
            storage_stats: None,
            compact_result: None,
            photo: None,
            file: None,
            file_finish: None,
            photo_finish: None,
            photo_read: None,
            photo_record: None,
            photo_export: None,
            photo_meta: None,
            photo_damage: None,
            photo_previews: None,
            found: None,
            cleanup_pending: None,
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
        const VERTHYS_ERR_SECURITY_STATE: u32 = 0x00000020;
        const VERTHYS_ERR_ANCHOR_FULL: u32 = 0x00000021;

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
            | VERTHYS_ERR_VERIFY
            | VERTHYS_ERR_SECURITY_STATE
            | VERTHYS_ERR_ANCHOR_FULL => code,
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
            error_code: None,
            retry_after_secs: None,
            records: None,
            exhausted: None,
            shm_name: None,
            shm_size: None,
            record_count: None,
            has_global_key: None,
            global_key_id: None,
            global_key_record: None,
            security_status: None,
            kernel_status: None,
            anchors: None,
            anchor_state: None,
            anchor_removed: None,
            anchor_released: None,
            anchor_cleanup_failed: None,
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
            storage_stats: None,
            compact_result: None,
            photo: None,
            file: None,
            file_finish: None,
            photo_finish: None,
            photo_read: None,
            photo_record: None,
            photo_export: None,
            photo_meta: None,
            photo_damage: None,
            photo_previews: None,
            found: None,
            cleanup_pending: None,
        }
    }

    /// 原样保留错误码的响应（仅用于锚点维护接口）。
    ///
    /// 容器解锁路径的反 Oracle 折叠不适用于维护面板：状态文件损坏(0x09)、
    /// IO(0x08)、调用方未授权(0x16) 等都是可行动的维护错误，折叠为 AUTH
    /// 会让 UI 无法区分“状态文件损坏”和“口令错误”。
    pub(crate) fn err_raw(op: &str, code: u32) -> Self {
        let mut resp = Self::err(op, code);
        resp.error = Some(format!("ERR_{:08X}", code));
        resp
    }

    /// 锁定/限流错误响应：附建议等待秒数（仅 0x0A / 0x1D 路径使用）。
    pub(crate) fn err_with_retry(op: &str, code: u32, retry_after_secs: u64) -> Self {
        let mut resp = Self::err(op, code);
        if retry_after_secs > 0 {
            resp.retry_after_secs = Some(retry_after_secs);
        }
        resp
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
