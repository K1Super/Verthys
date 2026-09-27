/* photo_budget.rs — 跨层预算常量（主进程与 worker 同源）
 *
 * 本文件为生成物：由跨层预算常量生成器按单一权威来源产出，禁止手工编辑。
 * 修改预算请改权威来源并重新生成；门禁会校验生成物与来源一致。
 *
 * 引入方式：与共享内存协议契约同源，主进程与 worker 各自 include! 引入本文件，
 * 使跨进程预算常量为单一定义，改权威来源后两端同步重编译。
 *
 * 命名前缀 PB_：预算常量，避免与协议契约既有常量重名。
 */

/// 共享内存段容量（字节）：扫描通道单批传输窗口
pub const PB_SHM_DEFAULT_SIZE: u64 = 8_388_608;

/// 扫描单批取数预算（字节，名称 + 数据合计）：段容量水位线，越过即收批
pub const PB_SCAN_BATCH_MAX_BYTES: u64 = 5_033_164;

/// 段内固定开销预留（字节）：头部 + 索引条目表 + 载荷认证块
pub const PB_SCAN_SHM_OVERHEAD_BYTES: u64 = 65_536;

/// 索引投影内联阈值上限（字节）：后端接受的单条内联记录上限
pub const PB_SCAN_INDEX_INLINE_MAX_BYTES: u64 = 1_048_576;

/// 扫描缓存数据管控阈值（字节）
pub const PB_DATAB64_CACHE_MAX_BYTES: u64 = 65_536;

/// 缩略图 base64 字符上限
pub const PB_PHOTO_THUMB_MAX_CHARS: u64 = 45_000;

/// 元数据 JSON 非缩略图部分的字符预算（名称与引用等）
pub const PB_META_INDEX_OVERHEAD_CHARS: u64 = 4_096;

/// 元数据记录密文 base64 长度上限：与缓存管控阈值相等（缩略图可被缓存承载）
pub const PB_META_RECORD_B64_MAX: u64 = 65_536;

/// 索引瘦身布局的索引明文上界（字节）
pub const PB_PHOTO_INDEX_PLAIN_MAX: u64 = 2_656;

/// 索引瘦身布局的索引密文 base64 长度上界（须落在缓存管控阈值内）
pub const PB_PHOTO_INDEX_RECORD_B64_MAX: u64 = 3_616;

/// 块集记录明文上界（字节）
pub const PB_CHUNK_SET_PLAIN_MAX: u64 = 7_964;

/// 块集记录密文 base64 长度上界（须落在缓存管控阈值内）
pub const PB_CHUNK_SET_RECORD_B64_MAX: u64 = 10_696;

/// 单次 IPC 载荷上限（字节，base64 编码后的字符数口径）
pub const PB_IPC_MAX_PAYLOAD_BYTES: u64 = 12_582_912;

/// 单次块上传的块数上限
pub const PB_MAX_CHUNKS_PER_IPC: u64 = 8;

/// 数据块明文分片大小（字节）
pub const PB_PAYLOAD_CHUNK_SIZE_BYTES: u64 = 1_048_576;

/// 单批块上传载荷上限（字节，base64 口径）
pub const PB_MAX_CHUNK_BATCH_B64: u64 = 11_185_504;

/// 单条记录 chunk 密文 base64 长度上限
pub const PB_CHUNK_RECORD_B64_MAX: u64 = 1_398_188;

/// 最大合法响应行（字节）：单条载荷上限再编码一次 + JSON 头
pub const PB_MAX_LEGAL_RESPONSE_LINE: u64 = 16_781_312;

/// worker 请求行上限（字节）
pub const PB_IPC_MAX_REQUEST_LINE_BYTES: u64 = 16_777_216;

/// worker 响应行上限（字节，写侧自我约束）
pub const PB_IPC_MAX_RESPONSE_LINE_BYTES: u64 = 25_165_824;

/// 主进程读取行上限（字节，读侧兜底）
pub const PB_IPC_MAX_LINE_BYTES: u64 = 33_554_432;

/// JSON 帧固定开销预留（字节）
pub const PB_JSON_FRAME_OVERHEAD_BYTES: u64 = 4_096;

/// 批量枚举单批数据预算（字节，base64 长度合计）：worker 按此截批并以游标续批
pub const PB_ENUM_RESPONSE_DATA_BUDGET_BYTES: u64 = 12_582_912;

/// 单文件分块大小（字节）
pub const PB_MAX_FILE_CHUNK_SIZE_BYTES: u64 = 4_194_304;

/// 落盘 flush 链重试次数上限
pub const PB_FLUSH_MAX_RETRIES: u64 = 3;

/// 落盘 flush 链重试退避（毫秒）
pub const PB_FLUSH_RETRY_BACKOFF_MS: u64 = 100;

/// 落盘校验（结构自查）超时（毫秒）
pub const PB_FLUSH_VERIFY_TIMEOUT_MS: u64 = 5_000;

/// 导入会话开始阶段超时（毫秒）
pub const PB_SESSION_BEGIN_TIMEOUT_MS: u64 = 3_000;

/// 导入会话结束阶段超时（毫秒）
pub const PB_SESSION_END_TIMEOUT_MS: u64 = 30_000;

/// 导入会话强制清理超时（毫秒）
pub const PB_SESSION_FORCE_CLOSE_TIMEOUT_MS: u64 = 5_000;

/// 编译期不变式断言（const 上下文 panic 即编译错误，锚点行号即失败断言）
const fn pb_assert(cond: bool) {
    if !cond {
        panic!("photo budget invariant violated");
    }
}

const _: () = {
    pb_assert(
        PB_SCAN_BATCH_MAX_BYTES + PB_SCAN_INDEX_INLINE_MAX_BYTES + PB_SCAN_SHM_OVERHEAD_BYTES
            <= PB_SHM_DEFAULT_SIZE,
    );
    pb_assert(PB_META_RECORD_B64_MAX <= PB_DATAB64_CACHE_MAX_BYTES);
    pb_assert(PB_DATAB64_CACHE_MAX_BYTES <= PB_SCAN_INDEX_INLINE_MAX_BYTES);
    pb_assert(PB_MAX_LEGAL_RESPONSE_LINE <= PB_IPC_MAX_RESPONSE_LINE_BYTES);
    pb_assert(PB_MAX_LEGAL_RESPONSE_LINE <= PB_IPC_MAX_LINE_BYTES);
    pb_assert(PB_MAX_CHUNK_BATCH_B64 + PB_JSON_FRAME_OVERHEAD_BYTES <= PB_IPC_MAX_PAYLOAD_BYTES);
    pb_assert(PB_IPC_MAX_PAYLOAD_BYTES + PB_JSON_FRAME_OVERHEAD_BYTES <= PB_IPC_MAX_REQUEST_LINE_BYTES);
    pb_assert(PB_PHOTO_INDEX_RECORD_B64_MAX <= PB_DATAB64_CACHE_MAX_BYTES);
    pb_assert(PB_CHUNK_SET_RECORD_B64_MAX <= PB_DATAB64_CACHE_MAX_BYTES);
    pb_assert(
        PB_ENUM_RESPONSE_DATA_BUDGET_BYTES + PB_JSON_FRAME_OVERHEAD_BYTES
            <= PB_IPC_MAX_RESPONSE_LINE_BYTES,
    );
    pb_assert(PB_MAX_FILE_CHUNK_SIZE_BYTES <= PB_IPC_MAX_PAYLOAD_BYTES / 2);
    pb_assert(PB_SESSION_END_TIMEOUT_MS > PB_SESSION_BEGIN_TIMEOUT_MS);
};
