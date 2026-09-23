/*
 * types/verthys.ts — Verthys IPC 层统一类型定义
 *
 * 与后端 Rust 结构体严格对齐，字段名保持 snake_case（Tauri 自动映射）
 */

/** 后端统一响应（脱敏：仅返回操作结果与必要数据，不含密钥/句柄） */
export interface VerthysResponse {
  ok: boolean;
  op: string;
  id?: number;
  rtype?: number;
  name?: string;
  data?: string; // base64 编码的二进制数据
  error?: string;
  /** 批量枚举记录列表（仅 enumerate_records 操作返回） */
  records?: VerthysRecordEntry[];
  /** 摘要扫描记录列表（仅 scan_summary_open / scan_summary_next 操作返回） */
  summary_records?: VerthysSummaryEntry[];
  /** 游标是否已遍历结束（scan_open / scan_next 返回） */
  exhausted?: boolean;
  /** 共享内存名称（scan_open 返回） */
  shm_name?: string;
  /** 共享内存总大小（字节） */
  shm_size?: number;
  /** 共享内存中本次返回的记录数 */
  record_count?: number;
  /* 修复：解锁响应内联全局主密钥探测结果
   *   worker 解锁成功后进程内一次性完成 has_record + find_lid + get_record，
   *   结果内联到 unlock 响应三字段，彻底消除前端 IPC 链路与 v1 假阴性死锁。
   *
   * 健壮性契约（前端据此决策，无需再发 probe）：
   *   - has_global_key=true + global_key_id + global_key_record → 命中且读取成功
   *   - has_global_key=true + global_key_id（无 record）        → 命中 lid 但读取失败
   *   - has_global_key=false                                    → 确认无全局密钥记录
   *   - has_global_key 缺失（undefined）                        → 探测异常，前端回退 probe */
  /** 是否存在全局主密钥记录（仅 unlock 操作返回） */
  has_global_key?: boolean;
  /** 全局主密钥记录的 lid（仅 unlock 操作且 has_global_key=true 时返回） */
  global_key_id?: number;
  /** 全局主密钥记录数据 base64（仅 unlock 操作且 has_global_key=true 时返回） */
  global_key_record?: string;
  /* 防御闭环状态报告（仅 security_status 操作返回）
   *
   * 与后端 Rust controller::types::SecurityStatusReport 严格对齐
   * （字段名保持 snake_case）。防御状态为进程级事实，锁定态亦可查询。 */
  security_status?: SecurityStatusReport;
  /* 异步批处理流水线 — 批量导入字段
   *
   * 「N 次加密，1 次 IPC 传输」：verthys_add_records_batch 单次 IPC 写入 N 条记录，
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
  ids?: number[];
  batch_id?: number;
  failed_indices?: number[];
  hashes?: string[];
  import_id?: string;
  processed_count?: number;
  total_count?: number;
  skipped_count?: number;
}

/**
 * 解锁进度信息
 *
 * 与后端 Rust worker::UnlockProgress 严格对齐（字段名保持 snake_case）。
 * 解锁期间通过 Tauri Channel 流式推送，在解锁各阶段触发：
 *   - stage=1 读超级块（5%）
 *   - stage=2 Argon2id 开始（10%）
 *   - stage=3 Argon2id 完成（50%）
 *   - stage=4 缓存检查（55%）
 *   - stage=5 索引解密（60%）
 *   - stage=6 B+树完成（85%）
 *   - stage=7 摘要完成（95%）
 *   - stage=8 Merkle完成（100%）
 *
 * 字段含义：
 *   - stage：VerthysUnlockStage 枚举值（1~8）
 *   - percent：0~100 累计进度百分比
 *   - elapsed_ms：自解锁开始累计耗时（毫秒）
 *   - message：UTF-8 阶段描述（供前端直接展示）
 */
export interface UnlockProgress {
  stage: number;
  percent: number;
  elapsed_ms: number;
  message: string;
}

/**
 * 防御闭环状态报告
 *
 * 与后端 Rust controller::types::SecurityStatusReport 严格对齐
 * （字段名保持 snake_case）。Verthys_GetSecurityStatus 的结构化输出。
 *
 * 7 条攻击路径（path_state 下标，与 verthys.h VerthysDefensePath 对齐）：
 *   0=挂起绕过 1=内存转储 2=休眠取证 3=IAT Hook
 *   4=DLL 劫持 5=进程读取 6=跨设备
 *
 * 路径状态值（VerthysDefenseState）：
 *   0=未校验 1=已阻断 2=降级 3=校验失败
 */
export interface SecurityStatusReport {
  /** 7 条攻击路径各自的状态（0=未校验 1=已阻断 2=降级 3=失败） */
  path_state: number[];
  /** 处于阻断态的路径数 */
  blocked_count: number;
  /** 处于降级态的路径数 */
  degraded_count: number;
  /** 校验失败的路径数 */
  failed_count: number;
  /** 关键路径是否全部阻断（安全基线达成） */
  all_critical_blocked: boolean;
  /** 是否存在降级路径（环境不支持部分防护时为 true） */
  has_degraded: boolean;
}

/** 批量枚举返回的单条记录（与后端 VerthysRecordEntry 对齐） */
export interface VerthysRecordEntry {
  id: number;
  rtype: number;
  name: string;
  data: string; // base64
}

/**
 * 项5：枚举记录流式分页批次（Tauri Channel 推送载荷）
 *
 * 与后端 Rust controller::types::EnumerateBatch 严格对齐（字段名保持 snake_case）。
 * verthys_enumerate_records_stream 命令循环调用 worker，每批通过 Channel 推送到前端。
 *
 * 字段含义：
 *   - records：本批记录列表（id/type/name/dataB64）
 *   - last_id：本批最后一条记录的 ID（前端据此发起下一批，0 表示无记录）
 *   - count：本批记录数
 *   - exhausted：是否已遍历完毕（true 时前端停止循环）
 *   - total_pushed：累计已推送记录数（用于前端进度展示）
 */
export interface EnumerateBatch {
  records: VerthysRecordEntry[];
  last_id: number;
  count: number;
  exhausted: boolean;
  total_pushed: number;
}

/** 摘要扫描返回的单条记录（轻量元数据，不含数据块）
 *
 * 与 VerthysRecordEntry 的区别：
 *   - 无 data 字段（不解密数据块，解锁后 1-2 秒内完成列表渲染）
 *   - 新增 data_size / physical_offset / merkle_leaf（供按需加载定位 + 完整性校验）
 *   - 新增 created_time（创建时间戳，列表展示用）
 *
 * 与后端 Rust VerthysSummaryEntry 严格对齐（字段名保持 snake_case）
 */
export interface VerthysSummaryEntry {
  id: number;
  rtype: number;
  name: string;
  /** 原始数据大小（字节，用于显示"大小"列） */
  data_size: number;
  /** 物理槽位偏移（按需加载时直接定位磁盘位置，跳过 B+ 树查找） */
  physical_offset: number;
  /** Merkle 叶子哈希 base64（完整性校验码，后台巡检用） */
  merkle_leaf: string;
  /** 创建时间戳（Unix 秒，列表展示用） */
  created_time: number;
}

/** 账号记录字段（前端序列化为 JSON → base64 → 传给 worker → DLL 存储） */
export interface AccountFields {
  platform: string;
  username: string;
  password: string;
  note: string;
  /** 是否对该密码追加独立加密层（需携带 encKey 才能查看） */
  encrypted: boolean;
  /** 独立加密密钥（仅在新增时由用户输入，查看时需重新输入；不随记录序列化存储明文，仅存盐/校验值） */
  encKey?: string;
}

/** 枚举得到的记录条目 */
export interface RecordEntry {
  id: number;
  type: number; // 0x01 照片, 0x02 账号
  name: string;
}

/** 路径预检结果（错误码脱敏，dir 字段已废弃不再透传） */
export interface PreflightResult {
  ok: boolean;
  error: string | null;
  /** 标准化错误码（INVALID_PATH/PERMISSION_DENIED/DISK_SPACE_INSUFFICIENT/DISK_SPACE_UNKNOWN/TEMPORARY_FAILURE） */
  error_code?: string | null;
  /** @deprecated dir 字段已删除，后端不再透传路径，保留仅为类型兼容 */
  dir: string;
  is_system_protected: boolean;
  file_exists: boolean;
  /** 磁盘剩余空间（MB） */
  disk_space_mb: number;
  /** 是否自动创建了目录 */
  dir_created: boolean;
}

/** 初始化状态结果 */
export interface InitStatusResult {
  /** "none" | "ready" | "broken" */
  status: string;
  /** 加密库路径（ready 时有值） */
  verthys_path: string | null;
  /** 状态描述 */
  detail: string;
}

/** 设备绑定校验结果（结构化返回） */
export interface DeviceBindingResult {
  /** 绑定状态（match/mismatch/unbound/partial_match/error） */
  status: "match" | "mismatch" | "unbound" | "partial_match" | "error";
  /** 用户可读描述 */
  detail: string;
  /** 错误码（status=error 时有值） */
  error_code?: string | null;
  /** 匹配度百分比（0-100） */
  match_score?: number | null;
}

/** 剪贴板清空结果（结构化返回） */
export interface ClipboardResult {
  /** 操作是否成功（true=剪贴板已安全擦除） */
  ok: boolean;
  /** 用户可读描述 */
  detail: string;
  /** 错误码（CLIPBOARD_LOCKED/RATE_LIMITED/CLIPBOARD_MONITOR_FAILED/TEMPORARY_FAILURE/INTERNAL） */
  error_code?: string | null;
}

/** 第 7.2/7.4/7.5 项：隐私模式设置结果（结构化返回） */
export interface PrivacyModeResult {
  /** 操作是否成功（true=隐私模式已按预期切换） */
  ok: boolean;
  /** 隐私模式当前状态（true=已启用，false=已关闭） */
  enabled: boolean;
  /** 是否处于部分保护状态（防截屏已启用但剪贴板监听失败） */
  partial_protection: boolean;
  /** 用户可读描述 */
  detail: string;
  /** 错误码（CLIPBOARD_MONITOR_FAILED/RATE_LIMITED/PERMISSION_DENIED/TEMPORARY_FAILURE/INTERNAL） */
  error_code?: string | null;
  /** 会话令牌（仅 enabled=true 时返回，关闭时需作为 authToken 传入） */
  session_token?: string | null;
}

/** v2 安全预设 */
export type VerthysPreset = 0 | 1;

/** 三档预设代号（3 = CUSTOM 自定义模板，仅前端处理） */
export type SecurityPresetCode = 0 | 1 | 2 | 3;

/** 暴力拦截检查结果（与 Rust BruteForceCheckResponse 对齐，tag=kind） */
export type BruteForceCheckResponse =
  | { kind: "Allow" }
  | { kind: "Locked"; remaining_secs: number }
  | { kind: "PurgeRequired" };

/** 暴力拦截状态快照 */
export interface BruteForceStatus {
  consecutive_failures: number;
  total_failures: number;
  remaining_lock_secs: number;
  purge_required: boolean;
}

/** 模块巡检中的未知/可疑模块 */
export interface UnknownModuleInfo {
  name: string;
  path: string;
  reason: string;
}

/** 影子休眠状态 */
export interface ShadowSleepStatus {
  in_shadow_sleep: boolean;
  txid: number;
}

/** 预设下的安全特性开关集合 */
export interface PresetFeatures {
  anti_debug: boolean;
  anti_inject: boolean;
  integrity_check: boolean;
  memory_guard: boolean;
  key_separation: boolean;
  emergency_response: boolean;
  session_lock_on_idle: boolean;
  shadow_sleep: boolean;
  module_patrol: boolean;
  clip_clear_on_lock: boolean;
  usb_clone_detect: boolean;
  trace_cleanup: boolean;
}

/** 三档预设配置详情 */
export interface PresetConfig {
  name: string;
  code: number;
  features: PresetFeatures;
}

/* ================================================================== *
 * Comprehensive_optimization：照片导入异步批处理流水线类型           *
 *                                                                  *
 * 与后端 Rust controller::verthys_batch_controller 严格对齐            *
 * （字段名保持 snake_case，Tauri 自动映射）                          *
 * ================================================================== */

/**
 * 单条已加密记录输入（前端 Worker 池加密后产出）
 *
 * 与后端 BatchRecordInput 对齐。前端传输器阶段并行加密后，
 * 消费者阶段将多条 BatchRecordInput 打包为单次 IPC 调用 verthys_add_records_batch。
 */
export interface BatchRecordInput {
  /** 记录类型（TYPE_PHOTO_META=1 等） */
  rtype: number;
  /** 记录名称（如 `meta_xxx.jpg`） */
  name: string;
  /** 原始文件内容的 BLAKE3 hex（用于去重 + WAL 幂等） */
  hash: string;
  /** 已加密的记录数据 base64（前端 XChaCha20-Poly1305 加密产物） */
  data_b64: string;
}

/**
 * 批量写入进度（通过 Tauri Channel 流式推送到前端）
 *
 * 与后端 ImportBatchProgress 对齐。前端在 requestAnimationFrame 内接收并绘制进度条，
 * 保证任何时刻最多一帧间隔更新，绝不参与数据处理热路径。
 */
export interface ImportBatchProgress {
  /** 本批次 ID（从 1 递增，前端据此对齐检查点） */
  batch_id: number;
  /** 本批次已处理记录数（含去重跳过 + 失败） */
  processed_in_batch: number;
  /** 本批次总记录数 */
  total_in_batch: number;
  /** 导入会话累计已 committed 记录数（检查点） */
  total_committed: number;
  /** 导入会话累计因哈希去重跳过的记录数 */
  total_skipped: number;
  /** 本批次已耗时（毫秒，自批次开始累计） */
  elapsed_ms: number;
}

/**
 * verthys_import_begin 返回结果
 */
export interface ImportBeginResult {
  /** 是否成功 */
  ok: boolean;
  /** 导入会话 ID（贯穿整个导入生命周期） */
  import_id: string;
  /** 已 committed 的内容哈希列表（生产者据此去重，保证幂等） */
  hashes: string[];
  /** 续传起始的累计 committed 计数（检查点） */
  total_count: number;
  /** 错误信息（ok=false 时有值） */
  error?: string;
}

/**
 * verthys_add_records_batch 返回结果
 */
export interface AddRecordsBatchResult {
  /** 是否成功 */
  ok: boolean;
  /** 本批次每条记录分配的 verthys ID（0 表示去重跳过或失败） */
  ids: number[];
  /** 本批次 ID（从 1 递增） */
  batch_id: number;
  /** 本批次失败记录的下标列表 */
  failed_indices: number[];
  /** 本批次实际处理（含去重跳过）的记录数 */
  processed_count: number;
  /** 导入会话累计已 committed 记录数（检查点） */
  total_count: number;
  /** 本批次因哈希去重跳过的记录数 */
  skipped_count: number;
  /** 错误信息（ok=false 时有值） */
  error?: string;
}

/**
 * verthys_wal_recover 返回结果（断点续传去重哈希集）
 */
export interface WalRecoverResult {
  /** 是否成功 */
  ok: boolean;
  /** 已 committed 的内容哈希列表（续传去重依据） */
  hashes: string[];
  /** 累计 committed 计数 */
  total_count: number;
  /** 活跃的 import_id（WAL 未 end 时有值，表示上次崩溃未完成） */
  import_id?: string;
  /** 最后一个检查点的批次 ID */
  batch_id?: number;
  /** 是否有活跃会话未 end（1=有，0=已 end 或无遗留） */
  processed_count?: number;
  /** 错误信息（ok=false 时有值） */
  error?: string;
}
