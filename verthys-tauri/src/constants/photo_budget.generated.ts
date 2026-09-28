/* photo_budget.generated.ts — 跨层预算常量（前端侧）
 *
 * 本文件为生成物：由跨层预算常量生成器按单一权威来源产出，禁止手工编辑。
 * 修改预算请改权威来源并重新生成；门禁会校验生成物与来源一致。
 */

/** 扫描缓存 dataB64 管控阈值（字节）：超过仅缓存索引，数据置空按需 IPC 取回 */
export const DATAB64_CACHE_MAX_BYTES = 65536;

/** 缩略图 base64 字符上限：保证含缩略图的元数据记录可被扫描缓存承载 */
export const PHOTO_THUMB_MAX_CHARS = 45000;

/** 单次 IPC 载荷上限（字节，base64 编码后的字符数口径） */
export const MAX_IPC_PAYLOAD_BYTES = 12582912;

/** 单次块上传的块数上限 */
export const MAX_CHUNKS_PER_IPC = 8;

/** 数据块明文分片大小（字节） */
export const PAYLOAD_CHUNK_SIZE_BYTES = 1048576;

/** 索引瘦身布局的索引明文上界（字节）：展示字段与聚合引用（逐块项已移入块集记录） */
export const PHOTO_INDEX_MAX_BYTES = 2656;

/** 批量枚举单批数据预算（字节，base64 长度合计）：worker 按此截批并以游标续批 */
export const ENUM_RESPONSE_DATA_BUDGET_BYTES = 12582912;

/** 单文件分块大小（字节）：FileVerthys 分块模型的分片口径 */
export const MAX_FILE_CHUNK_SIZE_BYTES = 4194304;

/** 照片单文件上限（字节）：导入闸门按此拒绝超限文件 */
export const PHOTO_MAX_BYTES = 104857600;

/** 单文件体量上限（字节）：用户授权文件读写（含分片）与单文件导出的统一上限 */
export const USER_FILE_SIZE_LIMIT = 2147483648;

/** 单文件导出累计上限（字节）：与 USER_FILE_SIZE_LIMIT 同源（同一上限的两个消费名） */
export const MAX_EXPORT_SINGLE_BYTES = 2147483648;

/** 落盘 flush 链重试次数上限 */
export const FLUSH_MAX_RETRIES = 3;

/** 落盘 flush 链重试退避（毫秒） */
export const FLUSH_RETRY_BACKOFF_MS = 100;

/** 落盘校验（结构自查）超时（毫秒） */
export const FLUSH_VERIFY_TIMEOUT_MS = 5000;

/** 导入会话开始阶段超时（毫秒） */
export const SESSION_BEGIN_TIMEOUT_MS = 3000;

/** 导入会话结束阶段超时（毫秒） */
export const SESSION_END_TIMEOUT_MS = 30000;

/** 导入会话强制清理超时（毫秒） */
export const SESSION_FORCE_CLOSE_TIMEOUT_MS = 5000;
