/* request.rs — 请求类
 *
 * 职责：BatchAddRecord / StagedAddRecord / Request / FileImportSource。
 * 被引用方：dispatch.rs / gmk.rs / main_loop.rs。
 */

use serde::Deserialize;
use zeroize::Zeroizing;

/// 批量写入的单条记录（仅 add_records 消费；data 为 base64）
#[derive(Deserialize)]
pub(crate) struct BatchAddRecord {
    pub(crate) rtype: u32,
    pub(crate) name: String,
    /// base64 密文载荷；Zeroizing 保证解码后原始串随请求释放时清零
    pub(crate) data: Zeroizing<String>,
}

/// 暂存块提交的单条引用（仅 add_records_staged 消费）。
///
/// 密文不出 worker：本结构只携带定位信息，worker 用 job_id + chunk_key
/// 从导入 job 的暂存区取出密文，并以 chunk_hash 复核内容。
#[derive(Deserialize)]
pub(crate) struct StagedAddRecord {
    pub(crate) rtype: u32,
    pub(crate) name: String,
    pub(crate) job_id: String,
    pub(crate) chunk_key: String,
    pub(crate) chunk_hash: String,
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
    /// 轮换临时新库路径（仅 v4_rotate_begin 消费）。
    /// 必须不存在且与源库同目录；worker 只转发，具体校验由 C 层完成。
    #[serde(default)]
    pub(crate) new_path: String,
    /// 轮换提交时是否保留旧库备份（仅 v4_rotate_commit 消费）
    #[serde(default)]
    pub(crate) keep_old: bool,
    /// 轮换 Run 的取消事件名（父进程创建的命名事件；仅 v4_rotate_run 消费）
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
    /// 暂存块引用列表（仅 add_records_staged 消费；密文留在 worker 暂存区）
    #[serde(default)]
    pub(crate) staged_records: Vec<StagedAddRecord>,
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
    /// 改钥：继任 .bin 文件内容（base64）与口令（仅 change_global_key 消费）
    #[serde(default)]
    pub(crate) new_bin_data: Zeroizing<String>,
    #[serde(default)]
    pub(crate) new_bin_password: Zeroizing<String>,
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
    /// 回退锚点批量释放目标 UUID 列表（32 位十六进制；仅
    /// rollback_anchor_release_batch 消费）。数量与重复由 dispatch 校验。
    #[serde(default)]
    pub(crate) uuids: Vec<String>,
    /// 回退锚点释放/回收的显式确认（仅 rollback_anchor_* 消费）。
    /// 与模块删除的字符串 confirm 字段分离，避免类型与语义冲突。
    #[serde(default)]
    pub(crate) anchor_confirm: bool,
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
    // 模块 M1 的模块索引（0=photo/1=accounts/2=fileverthys；
    // 0xFFFFFFFF 仅 v4_module_lock 表示全部）
    #[serde(default)]
    pub(crate) module_id: u32,
    // PCR 位图（PCR0–23），仅 v4_pcr_enable 消费
    #[serde(default)]
    pub(crate) pcr_select: u32,
    // 模块启用/绑定恢复槽时的当前容器恢复码（可空）
    #[serde(default)]
    pub(crate) recovery_code: Zeroizing<String>,
    // keyfile 因子：VKFL 文件绝对路径（仅 keyfile 系列 op 消费）。
    // 只传路径；文件内容由 C 层在 worker 进程内读取，不进入 IPC 载荷。
    #[serde(default)]
    pub(crate) keyfile_path: String,
    // 恢复码轮换时的旧恢复码
    #[serde(default)]
    pub(crate) old_recovery: Zeroizing<String>,
    // 模块删除的二次确认字面量（必须为 "DELETE"，非密钥）
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
    /// 照片导入/读取 job 标识（仅 photo_import_job_* / photo_read_job_* 消费）
    #[serde(default)]
    pub(crate) job_id: String,
    /// 照片 meta 记录 ID（仅 photo_read_job_begin 消费）
    #[serde(default)]
    pub(crate) meta_id: u64,
    /// 批量路径授权列表（仅 authorize_path_batch 消费）
    #[serde(default)]
    pub(crate) paths: Vec<String>,
    /// 宿主 WAL 已提交的条目键（仅 photo_import_job_begin 消费）。
    /// 缺省为空集：旧宿主不传时退化为逐文件解码后去重。
    #[serde(default)]
    pub(crate) committed_entry_keys: Vec<String>,
    /// 照片导入完成时回填的块记录 ID（仅 photo_import_job_finish 消费）
    #[serde(default)]
    pub(crate) chunk_ids: Vec<u64>,
    /// 导出格式（original / venc-single / venc-multiple / png）
    #[serde(default)]
    pub(crate) format: String,
    /// 导出/还原令牌（VENC 外层 KDF 凭据；不落日志）
    #[serde(default)]
    pub(crate) token: Zeroizing<String>,
    /// 预览扫描得到的逐张 fileHash（仅 photo_restore_job_begin 消费）
    #[serde(default)]
    pub(crate) expected_hashes: Vec<String>,
    /// 还原时跳过该张落库（仅 photo_restore_photo_finish 消费）
    #[serde(default)]
    pub(crate) skip_photo: bool,
    // 块序号（0 起）与块总数；seq < total 且 total > 0
    #[serde(default)]
    pub(crate) seq: u32,
    #[serde(default)]
    pub(crate) total: u32,
    // 文件块 v2 的 PBKDF2 迭代次数；0 表示采用缺省值
    #[serde(default)]
    pub(crate) iterations: u32,
    /// 清藏原生导入的文件清单（仅 file_import_job_begin 消费）。
    /// 名称与 MIME 由宿主从用户可见信息解析后下发，worker 不重新推断。
    #[serde(default)]
    pub(crate) files: Vec<FileImportSource>,
}

/// 清藏原生导入的单个来源文件。
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FileImportSource {
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) mime: String,
}
