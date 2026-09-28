#!/usr/bin/env node
/*
 * generate.mjs — 跨层预算常量生成器
 *
 * 职责：读取单一权威来源（同目录的预算 schema），计算派生量，校验跨层
 *   不变式，产出前端 TS 与 Rust 两侧常量文件。
 *
 * 用法：
 *   node constants/generate.mjs          重新生成两侧常量
 *   node constants/generate.mjs --check  只校验生成物与权威来源一致（CI 门禁）
 *
 * 设计约束：
 *   - 零第三方依赖（仅 node 内置模块），本地与 CI 行为一致；
 *   - 生成物禁止手工编辑：漂移由 --check 检出并让门禁变红；
 *   - 不产出 C 头文件：C 层不消费编译期预算（预算经函数参数传入，由调用方
 *     运行时给定），凭空产出无消费者的常量只会制造新的漂移面。
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(here, "..");
const schemaPath = join(here, "photo_budget.schema.json");
const tsOutPath = join(projectRoot, "src", "constants", "photo_budget.generated.ts");
const rsOutPath = join(projectRoot, "photo_budget.rs");

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const C = schema.constants;
const L = schema.layouts;

/** base64 编码长度（无换行，按 4 字节对齐向上取整） */
const b64Len = (raw) => Math.ceil(raw / L.base64_den) * L.base64_num;
/** 单条记录密文 base64 长度：明文 JSON + 盐 + nonce + 认证标签 */
const recordB64 = (plainChars, cryptoOverhead) =>
  b64Len(plainChars + cryptoOverhead);

const derived = {
  scan_batch_max_bytes: Math.floor(
    (C.shm_default_size * C.scan_batch_waterline_num) / C.scan_batch_waterline_den,
  ),
  // 批量枚举单批可承载的数据预算（base64 长度合计）：与单条写入上限同值——
  // 写入侧允许的最大单条记录经取回再编码后必须仍可单独返回；多记录聚合由
  // worker 按本预算截批并以游标续批（详见 worker 侧 build_enum_batch）
  enum_response_data_budget: C.ipc_max_payload,
  meta_record_b64_max: recordB64(
    C.photo_thumb_max_chars + C.meta_index_overhead_chars,
    L.meta_crypto_overhead,
  ),
  chunk_record_b64_max: recordB64(C.payload_chunk_size, L.chunk_crypto_overhead),
  max_legal_response_line: Math.floor((C.ipc_max_payload / L.base64_den) * L.base64_num) + L.json_frame_overhead,
  // 索引瘦身布局的索引明文上界：逐块项已移入块集记录，索引只含展示字段与聚合引用
  // （名称最坏 JSON 转义 + 固定字段 + 缩略图/块集引用与包裹密钥）
  photo_index_plain_max:
    C.max_record_name_bytes * 2 + C.meta_fixed_plain_bytes + C.meta_ref_bytes,
  // 块集记录明文上界：按最大照片的分块数推导（逐块引用 + 逐块哈希）
  chunk_set_plain_max: (() => {
    const chunks = Math.ceil(C.photo_max_bytes / C.payload_chunk_size);
    return chunks * (C.chunk_ref_bytes + C.chunk_hash_bytes) + C.chunk_set_fixed_plain_bytes;
  })(),
};
derived.photo_index_record_b64_max = recordB64(
  derived.photo_index_plain_max,
  L.meta_crypto_overhead,
);
derived.chunk_set_record_b64_max = recordB64(
  derived.chunk_set_plain_max,
  L.meta_crypto_overhead,
);

const checks = [
  {
    name: "扫描取批预算 + 单条最大内联记录 + 段内固定开销 不超过共享内存段容量",
    ok:
      derived.scan_batch_max_bytes + C.scan_index_inline_max + C.scan_shm_overhead_bytes
      <= C.shm_default_size,
  },
  {
    name: "含缩略图的元数据记录密文 可被扫描缓存承载（不超过缓存管控阈值）",
    ok: derived.meta_record_b64_max <= C.datab64_cache_max,
  },
  {
    name: "扫描缓存管控阈值 不超过后端索引投影内联阈值（请求值不被后端夹紧）",
    ok: C.datab64_cache_max <= C.scan_index_inline_max,
  },
  {
    name: "最大合法响应行 落在 worker 写侧行上限内",
    ok: derived.max_legal_response_line <= C.ipc_max_response_line,
  },
  {
    name: "最大合法响应行 落在主进程读取行上限内",
    ok: derived.max_legal_response_line <= C.ipc_max_line,
  },
  {
    name: "单批块上传（base64 口径）+ JSON 头 不超过单次载荷上限",
    ok:
      derived.chunk_record_b64_max * C.max_chunks_per_ipc + L.json_frame_overhead
      <= C.ipc_max_payload,
  },
  {
    name: "单次载荷上限 + JSON 头 落在 worker 请求行上限内",
    ok: C.ipc_max_payload + L.json_frame_overhead <= C.ipc_max_request_line,
  },
  {
    name: "索引瘦身布局的索引密文 可被扫描缓存承载（列表渲染零 IPC 的前提）",
    ok: derived.photo_index_record_b64_max <= C.datab64_cache_max,
  },
  {
    name: "块集记录密文 可被扫描缓存承载（查看原图/导出零 IPC 的前提）",
    ok: derived.chunk_set_record_b64_max <= C.datab64_cache_max,
  },
  {
    name: "缩略图记录密文 可被扫描缓存承载",
    ok:
      recordB64(
        Math.floor((C.photo_thumb_max_chars * 3) / 4),
        L.meta_crypto_overhead,
      ) <= C.datab64_cache_max,
  },
  {
    name: "批量枚举单批数据预算 + JSON 头 落在 worker 响应行上限内",
    ok:
      derived.enum_response_data_budget + L.json_frame_overhead
      <= C.ipc_max_response_line,
  },
  {
    name: "单文件块大小 不超过单条载荷上限一半",
    ok: C.max_file_chunk_size <= Math.floor(C.ipc_max_payload / 2),
  },
  {
    name: "导出分片 不超过单次载荷上限一半",
    ok: C.write_file_chunk_bytes <= Math.floor(C.ipc_max_payload / 2),
  },
  {
    name: "单文件体量上限（统一口径） 不小于 导出分片（否则任何导出都无法开始）",
    ok: C.user_file_size_limit >= C.write_file_chunk_bytes,
  },
  {
    name: "会话结束超时 大于 会话开始超时",
    ok: C.session_end_timeout_ms > C.session_begin_timeout_ms,
  },
];

const failures = checks.filter((c) => !c.ok);
if (failures.length > 0) {
  console.error("[常量生成] 跨层不变式校验失败，拒绝生成：");
  for (const f of failures) console.error(`  - ${f.name}`);
  process.exit(1);
}

/** Rust 整数书写：千位下划线分隔，提升可读性 */
const rs = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, "_");

/** 生成物文件头：单一权威来源提示（注释仅描述本文件的生成属性） */
const header = (title, extraLines = []) =>
  [
    `/* ${title}`,
    " *",
    " * 本文件为生成物：由跨层预算常量生成器按单一权威来源产出，禁止手工编辑。",
    " * 修改预算请改权威来源并重新生成；门禁会校验生成物与来源一致。",
    ...extraLines.map((l) => (l ? ` * ${l}` : " *")),
    " */",
  ].join("\n");

const tsContent = `${header("photo_budget.generated.ts — 跨层预算常量（前端侧）")}

/** 扫描缓存 dataB64 管控阈值（字节）：超过仅缓存索引，数据置空按需 IPC 取回 */
export const DATAB64_CACHE_MAX_BYTES = ${C.datab64_cache_max};

/** 缩略图 base64 字符上限：保证含缩略图的元数据记录可被扫描缓存承载 */
export const PHOTO_THUMB_MAX_CHARS = ${C.photo_thumb_max_chars};

/** 单次 IPC 载荷上限（字节，base64 编码后的字符数口径） */
export const MAX_IPC_PAYLOAD_BYTES = ${C.ipc_max_payload};

/** 单次块上传的块数上限 */
export const MAX_CHUNKS_PER_IPC = ${C.max_chunks_per_ipc};

/** 数据块明文分片大小（字节） */
export const PAYLOAD_CHUNK_SIZE_BYTES = ${C.payload_chunk_size};

/** 索引瘦身布局的索引明文上界（字节）：展示字段与聚合引用（逐块项已移入块集记录） */
export const PHOTO_INDEX_MAX_BYTES = ${derived.photo_index_plain_max};

/** 批量枚举单批数据预算（字节，base64 长度合计）：worker 按此截批并以游标续批 */
export const ENUM_RESPONSE_DATA_BUDGET_BYTES = ${derived.enum_response_data_budget};

/** 单文件分块大小（字节）：FileVerthys 分块模型的分片口径 */
export const MAX_FILE_CHUNK_SIZE_BYTES = ${C.max_file_chunk_size};

/** 照片单文件上限（字节）：导入闸门按此拒绝超限文件 */
export const PHOTO_MAX_BYTES = ${C.photo_max_bytes};

/** 单文件体量上限（字节）：用户授权文件读写（含分片）与单文件导出的统一上限 */
export const USER_FILE_SIZE_LIMIT = ${C.user_file_size_limit};

/** 单文件导出累计上限（字节）：与 USER_FILE_SIZE_LIMIT 同源（同一上限的两个消费名） */
export const MAX_EXPORT_SINGLE_BYTES = ${C.user_file_size_limit};

/** 落盘 flush 链重试次数上限 */
export const FLUSH_MAX_RETRIES = ${C.flush_max_retries};

/** 落盘 flush 链重试退避（毫秒） */
export const FLUSH_RETRY_BACKOFF_MS = ${C.flush_retry_backoff_ms};

/** 落盘校验（结构自查）超时（毫秒） */
export const FLUSH_VERIFY_TIMEOUT_MS = ${C.flush_verify_timeout_ms};

/** 导入会话开始阶段超时（毫秒） */
export const SESSION_BEGIN_TIMEOUT_MS = ${C.session_begin_timeout_ms};

/** 导入会话结束阶段超时（毫秒） */
export const SESSION_END_TIMEOUT_MS = ${C.session_end_timeout_ms};

/** 导入会话强制清理超时（毫秒） */
export const SESSION_FORCE_CLOSE_TIMEOUT_MS = ${C.session_force_close_timeout_ms};
`;

const rsContent = `${header("photo_budget.rs — 跨层预算常量（主进程与 worker 同源）", [
  "",
  "引入方式：与共享内存协议契约同源，主进程与 worker 各自 include! 引入本文件，",
  "使跨进程预算常量为单一定义，改权威来源后两端同步重编译。",
  "",
  "命名前缀 PB_：预算常量，避免与协议契约既有常量重名。",
])}

/// 共享内存段容量（字节）：扫描通道单批传输窗口
pub const PB_SHM_DEFAULT_SIZE: u64 = ${rs(C.shm_default_size)};

/// 扫描单批取数预算（字节，名称 + 数据合计）：段容量水位线，越过即收批
pub const PB_SCAN_BATCH_MAX_BYTES: u64 = ${rs(derived.scan_batch_max_bytes)};

/// 段内固定开销预留（字节）：头部 + 索引条目表 + 载荷认证块
pub const PB_SCAN_SHM_OVERHEAD_BYTES: u64 = ${rs(C.scan_shm_overhead_bytes)};

/// 索引投影内联阈值上限（字节）：后端接受的单条内联记录上限
pub const PB_SCAN_INDEX_INLINE_MAX_BYTES: u64 = ${rs(C.scan_index_inline_max)};

/// 扫描缓存数据管控阈值（字节）
pub const PB_DATAB64_CACHE_MAX_BYTES: u64 = ${rs(C.datab64_cache_max)};

/// 缩略图 base64 字符上限
pub const PB_PHOTO_THUMB_MAX_CHARS: u64 = ${rs(C.photo_thumb_max_chars)};

/// 元数据 JSON 非缩略图部分的字符预算（名称与引用等）
pub const PB_META_INDEX_OVERHEAD_CHARS: u64 = ${rs(C.meta_index_overhead_chars)};

/// 元数据记录密文 base64 长度上限：与缓存管控阈值相等（缩略图可被缓存承载）
pub const PB_META_RECORD_B64_MAX: u64 = ${rs(derived.meta_record_b64_max)};

/// 索引瘦身布局的索引明文上界（字节）
pub const PB_PHOTO_INDEX_PLAIN_MAX: u64 = ${rs(derived.photo_index_plain_max)};

/// 索引瘦身布局的索引密文 base64 长度上界（须落在缓存管控阈值内）
pub const PB_PHOTO_INDEX_RECORD_B64_MAX: u64 = ${rs(derived.photo_index_record_b64_max)};

/// 块集记录明文上界（字节）
pub const PB_CHUNK_SET_PLAIN_MAX: u64 = ${rs(derived.chunk_set_plain_max)};

/// 块集记录密文 base64 长度上界（须落在缓存管控阈值内）
pub const PB_CHUNK_SET_RECORD_B64_MAX: u64 = ${rs(derived.chunk_set_record_b64_max)};

/// 单次 IPC 载荷上限（字节，base64 编码后的字符数口径）
pub const PB_IPC_MAX_PAYLOAD_BYTES: u64 = ${rs(C.ipc_max_payload)};

/// 单次块上传的块数上限
pub const PB_MAX_CHUNKS_PER_IPC: u64 = ${rs(C.max_chunks_per_ipc)};

/// 数据块明文分片大小（字节）
pub const PB_PAYLOAD_CHUNK_SIZE_BYTES: u64 = ${rs(C.payload_chunk_size)};

/// 单批块上传载荷上限（字节，base64 口径）
pub const PB_MAX_CHUNK_BATCH_B64: u64 = ${rs(derived.chunk_record_b64_max * C.max_chunks_per_ipc)};

/// 单条记录 chunk 密文 base64 长度上限
pub const PB_CHUNK_RECORD_B64_MAX: u64 = ${rs(derived.chunk_record_b64_max)};

/// 最大合法响应行（字节）：单条载荷上限再编码一次 + JSON 头
pub const PB_MAX_LEGAL_RESPONSE_LINE: u64 = ${rs(derived.max_legal_response_line)};

/// worker 请求行上限（字节）
pub const PB_IPC_MAX_REQUEST_LINE_BYTES: u64 = ${rs(C.ipc_max_request_line)};

/// worker 响应行上限（字节，写侧自我约束）
pub const PB_IPC_MAX_RESPONSE_LINE_BYTES: u64 = ${rs(C.ipc_max_response_line)};

/// 主进程读取行上限（字节，读侧兜底）
pub const PB_IPC_MAX_LINE_BYTES: u64 = ${rs(C.ipc_max_line)};

/// JSON 帧固定开销预留（字节）
pub const PB_JSON_FRAME_OVERHEAD_BYTES: u64 = ${rs(L.json_frame_overhead)};

/// 批量枚举单批数据预算（字节，base64 长度合计）：worker 按此截批并以游标续批
pub const PB_ENUM_RESPONSE_DATA_BUDGET_BYTES: u64 = ${rs(derived.enum_response_data_budget)};

/// 单文件分块大小（字节）
pub const PB_MAX_FILE_CHUNK_SIZE_BYTES: u64 = ${rs(C.max_file_chunk_size)};

/// 记录名长度上限（字节）
pub const PB_MAX_RECORD_NAME_BYTES: u64 = ${rs(C.max_record_name_bytes)};

/// 流式导出单次追加分片上限（字节）
pub const PB_WRITE_FILE_CHUNK_BYTES: u64 = ${rs(C.write_file_chunk_bytes)};

/// 单文件体量上限（字节）：用户授权文件读写（含分片）与单文件导出的统一上限
pub const PB_USER_FILE_SIZE_LIMIT: u64 = ${rs(C.user_file_size_limit)};

/// 单文件导出累计上限（字节）：与 PB_USER_FILE_SIZE_LIMIT 同源（同一上限的两个消费名）
pub const PB_MAX_EXPORT_SINGLE_BYTES: u64 = ${rs(C.user_file_size_limit)};

/* 落盘与导入会话超时属前端语义，由前端生成物承载并消费，
   不在本文件发射，避免无消费者常量沉淀。 */

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
    pb_assert(PB_WRITE_FILE_CHUNK_BYTES <= PB_IPC_MAX_PAYLOAD_BYTES / 2);
    pb_assert(PB_MAX_EXPORT_SINGLE_BYTES >= PB_WRITE_FILE_CHUNK_BYTES);
    // 统一口径：读写上限与导出上限必须同源（任一漂移即编译失败）
    pb_assert(PB_MAX_EXPORT_SINGLE_BYTES == PB_USER_FILE_SIZE_LIMIT);
};
`;

const outputs = [
  { path: tsOutPath, content: tsContent, label: "前端 TS 常量" },
  { path: rsOutPath, content: rsContent, label: "Rust 同源常量" },
];

if (process.argv.includes("--check")) {
  let drift = false;
  for (const out of outputs) {
    let current = null;
    try {
      current = readFileSync(out.path, "utf8");
    } catch {
      current = null;
    }
    if (current !== out.content) {
      drift = true;
      console.error(
        `[常量生成] 生成物与权威来源不一致：${out.label}（${relative(projectRoot, out.path)}）`,
      );
    }
  }
  if (drift) {
    console.error("[常量生成] 请运行 node constants/generate.mjs 重新生成并提交生成物");
    process.exit(1);
  }
  console.log("[常量生成] 校验通过：生成物与权威来源一致");
  process.exit(0);
}

for (const out of outputs) {
  writeFileSync(out.path, out.content, "utf8");
  console.log(`[常量生成] 已写出${out.label}：${relative(projectRoot, out.path)}`);
}
for (const c of checks) console.log(`[常量生成] 不变式通过：${c.name}`);