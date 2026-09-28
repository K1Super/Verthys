/*
 * constants/crypto_const.ts — 加密层统一常量
 *
 * 设计原则（codebase-design 深模块）：
 *   - 所有长度、迭代次数、AD 文本标识、VENC 魔数/版本集中定义
 *   - 前端加密层（crypto.ts）唯一常量入口，消除散落的魔术数字
 *   - 常量值与后端 C 层协议严格对齐，禁止单独修改
 *   - 跨层共享的载荷/分片预算由预算常量生成物提供（单一定义）
 *
 */
import { PAYLOAD_CHUNK_SIZE_BYTES } from "./photo_budget.generated";

/* 跨层预算再导出：导入链路（批量记录与分块上传）按此约束单次 IPC 载荷 */
export { MAX_IPC_PAYLOAD_BYTES, MAX_CHUNKS_PER_IPC } from "./photo_budget.generated";

/* 照片与导出上限再导出：取值来自跨层预算常量（单一权威来源），
   保持既有导入路径不变；本模块不再保留同义字面量。 */
export {
  PHOTO_MAX_BYTES as MAX_PHOTO_BYTES,
  MAX_EXPORT_SINGLE_BYTES,
} from "./photo_budget.generated";

/* ------------------------------------------------------------------ *
 * 密钥派生参数                                                        *
 * ------------------------------------------------------------------ */

/** PBKDF2-SHA256 迭代次数（与后端 C 层一致） */
export const PBKDF2_ITER = 150000;

/** 主密钥长度（256 位） */
export const KEY_LEN = 32;

/** 盐值长度（128 位） */
export const SALT_LEN = 16;

/** XChaCha20 Nonce 长度（192 位，标准值） */
export const NONCE_LEN = 24;

/** Poly1305 认证标签长度（128 位） */
export const TAG_LEN = 16;

/* ------------------------------------------------------------------ *
 * 数据块结构长度                                                      *
 * ------------------------------------------------------------------ */

/** 块序号长度（4 字节大端） */
export const SEQ_LEN = 4;

/** 总块数长度（4 字节大端） */
export const TOTAL_LEN = 4;

/** 单块大小（1 MiB，取跨层预算常量：写入侧分片口径与解析侧一致） */
export const CHUNK_SIZE = PAYLOAD_CHUNK_SIZE_BYTES;

/** BLAKE3 文件哈希长度（256 位） */
export const FILE_HASH_LEN = 32;

/* ------------------------------------------------------------------ *
 * 照片导入批量处理约束（内存边界与韧性上限）                          *
 *                                                                    *
 * 单文件上限由跨层预算常量再导出；其余约束为导入链路的单一权威来源，  *
 * 任何环节不得使用字面量替代。                                        *
 * ------------------------------------------------------------------ */

/** 内联 meta 阈值（加密 chunk 原始字节）。
 *
 *  恒为 0：照片分块一律落独立记录，meta 只保存引用与缩略图。
 *
 *  Why：meta 记录一旦内联分块，其体积约为照片原始体积的 1.78 倍（分块 base64 →
 *    JSON → 加密 → 再 base64 四层放大），列表渲染与缩略图读取会被迫搬运 MB 级
 *   密文；同时该体积远超扫描缓存的 64 KiB 管控阈值，使缓存形同虚设。
 *    改为恒定外置后，单条 meta 稳定在几十 KB（缩略图 + 引用），
 *    分块只在查看原图/导出/删除级联时按需读取。
 *
 *  读取侧对两种形态都有实现：meta 内联 chunkDataB64 与 meta 引用 chunkIds
 *   并存解析，因此存量内联照片不受影响。 */
export const MAX_INLINE_META_BYTES = 0;

/** 单任务最大投递尝试次数（超过判定毒丸失败） */
export const MAX_TASK_ATTEMPTS = 3;

/** 单槽位连续失败（崩溃/超时）上限（超过槽位永久失效） */
export const MAX_CONSECUTIVE_SLOT_CRASHES = 5;

/* ------------------------------------------------------------------ *
 * AEAD 附加数据（AD）文本标识                                         *
 *                                                                    *
 * AD 用于绑定上下文，防止重放攻击：                                    *
 *   - 元数据 AD：固定文本，标识元数据加密上下文                        *
 *   - 块 AD 前缀：与块序号 + 总块数 + 文件哈希拼接，绑定块顺序        *
 * ------------------------------------------------------------------ */

/** 元数据加密 AD 文本 */
export const META_AD_TEXT = "VERTHYSPHOTO_META_v1";

/** 数据块 AD 前缀文本（后接 seq + total + fileHash） */
export const CHUNK_AD_PREFIX_TEXT = "VERTHYSPHOTO_CHUNK_v1";

/** 文件子密钥 HKDF info 文本 */
export const FILE_KEY_INFO_TEXT = "VERTHYSPHOTO_FILE_KEY_v1";

/** 缩略图记录加密 AD 文本（后接 fileHash，绑定缩略图归属，防跨照片换用） */
export const THUMB_AD_TEXT = "VERTHYSPHOTO_THUMB_v1";

/** 文件密钥包裹 AD 文本（包裹态文件密钥的解封上下文标识） */
export const FILE_KEY_WRAP_AD_TEXT = "VERTHYSPHOTO_FILEKEY_v1";

/** 块集记录加密 AD 文本（后接 fileHash，绑定块集归属，防跨照片换用） */
export const CHUNK_SET_AD_TEXT = "VERTHYSPHOTO_CHUNKSET_v1";

/* ------------------------------------------------------------------ *
 * 照片布局标记与写入开关                                              *
 *                                                                    *
 * 布局一（既有）：每条记录自包含（索引密文携带缩略图；块密文携带       *
 *   salt|seq|total|nonce；逐块按盐派生）。                              *
 * 布局二（索引瘦身）：缩略图独立记录；随机文件密钥由包裹态密钥解封，     *
 *   块密文仅 nonce|密文；索引只保留展示字段与引用。                     *
 *                                                                    *
 * 读取侧对两种布局并存解析（按索引内的 fmt 标记分流）；写入侧由下方      *
 * 开关决定新导入采用哪种布局。容器导入按来源布局保留——块密文无法在     *
 * 缺少来源密钥时重写，保留布局是数据保真的唯一正确做法。                *
 * ------------------------------------------------------------------ */

/** 布局标记：既有布局 */
export const PHOTO_FMT_LEGACY = 1;

/** 布局标记：索引瘦身布局（缩略图独立记录 + 包裹文件密钥 + 块仅 nonce|密文） */
export const PHOTO_FMT_SLIM = 2;

/** 照片写入布局开关（新导入采用；默认既有布局）。
 *
 *  Why 默认关：布局二改变落盘结构，切换前必须完成双布局读写验证；
 *  显式切换是"可回退"的前提（回退开关后新导入回到既有布局，
 *  已写入的布局二数据仍由读取侧分流解析，不产生不可读窗口）。 */
export const PHOTO_WRITE_FMT: number = PHOTO_FMT_LEGACY;

/** 判断索引记录是否采用索引瘦身布局（缩略图独立、块密钥包裹） */
export function isSlimPhotoMeta(meta: { fmt?: number; thumbId?: number }): boolean {
  return meta.fmt === PHOTO_FMT_SLIM && typeof meta.thumbId === "number" && meta.thumbId > 0;
}

/**
 * 判断索引记录是否声明为索引瘦身布局（只看布局标记）。
 *
 * 与 isSlimPhotoMeta 的分工：本函数用于"块引用与文件密钥的承载方式"判定
 * （块集 / 包裹密钥 / 块解密布局），这些与缩略图是否存在无关——源照片没有
 * 缩略图时索引仍为瘦身布局，只是不携带缩略图引用。
 */
export function isSlimLayout(meta: { fmt?: number }): boolean {
  return meta.fmt === PHOTO_FMT_SLIM;
}

/* ------------------------------------------------------------------ *
 * VENC 打包格式常量                                                   *
 *                                                                    *
 * .venc v2 文件结构（自描述信封 + 内容密钥封装 + 逐帧 AEAD）：         *
 *   [Outer Header 明文 42B] [Wrapped Content Key 48B]                 *
 *   [Frame]* [Trailer 帧]                                            *
 *   帧头：[type 1B] [seq 4B 大端] [len 4B 大端]                       *
 *   帧体：[nonce 24B] [ciphertext+tag 变长]                           *
 * ------------------------------------------------------------------ */

/** VENC v2 文件魔数文本（4 字节 ASCII） */
export const VENC_MAGIC_TEXT = "VENC";

/** VENC 当前版本（v2：自描述信封 + 逐帧 AEAD） */
export const VENC_VERSION = 2;

/** 外层头部固定字节数（magic4 + version2 + flags2 + kdfId2 + iterations4 + salt16 + iv12） */
export const VENC_OUTER_HEADER_BYTES = 42;

/** 外层 PBKDF2-SHA256 的 KDF 标识（写入头部自描述，解密端按其选择参数） */
export const VENC_KDF_ID_PBKDF2_SHA256 = 1;

/** 外层内容密钥封装输出固定字节数（ct 32 + tag 16） */
export const VENC_WRAPPED_KEY_BYTES = 48;

/** 帧头固定字节数（type1 + seq4 + len4） */
export const VENC_FRAME_HEADER_BYTES = 9;

/** 帧类型：轻量元数据头帧 */
export const VENC_FRAME_TYPE_LIGHT_META = 1;

/** 帧类型：加密块负载帧 */
export const VENC_FRAME_TYPE_CHUNK = 2;

/** 帧类型：尾部校验帧（frame_count + body_bytes 交叉校验） */
export const VENC_FRAME_TYPE_TRAILER = 3;

/** 解析容器帧数上限（拒绝恶意超大 frame_count 引发的无效分配） */
export const PARSE_MAX_FRAME_COUNT = 100_000;

/** 解析容器单帧负载字节上限 */
export const PARSE_MAX_FRAME_BYTES = 64 * 1024 * 1024;

/** 解析容器总字节上限 */
export const PARSE_MAX_CONTAINER_BYTES = 1 * 1024 * 1024 * 1024;

/** 令牌最小长度（字符数）：自定义令牌与解析导入共用的下限 */
export const MIN_TOKEN_LENGTH = 8;

/** 导出文件名 UTF-8 字节上限（净化与截断基准，防超长名写入失败） */
export const MAX_EXPORT_FILENAME_BYTES = 200;

/* 单文件导出上限与流式分片上限属跨层预算口径：上限由本模块再导出
   （前端在单文件模式前置拦截）；分片上限仅由后端强制，前端不保留副本。 */

/** 尾部校验帧负载固定字节数（frame_count u32 + body_bytes u64） */
export const VENC_TRAILER_PAYLOAD_BYTES = 12;

/* ------------------------------------------------------------------ *
 * Verthys 记录类型常量
 *
 * 修复：TYPE 常量统一到 constants/record_types.ts（单一真相源）
 *
 * 原缺陷：TYPE_PHOTO_CHUNK=0x05 与 FileVerthys.vue 局部定义的 TYPE_META=0x05
 * 值相同，导致照片数据块与文件保险箱元数据互相误识。
 *
 * 修复：全部记录类型常量集中到 record_types.ts 统一分配，确保全局唯一。
 * 此处改为 re-export，保持现有 import 路径向后兼容。
 * ------------------------------------------------------------------ */

export {
  TYPE_PHOTO_META,
  TYPE_PHOTO_CHUNK,
  TYPE_PHOTO_THUMB,
  TYPE_PHOTO_CHUNK_SET,
} from "./record_types";
