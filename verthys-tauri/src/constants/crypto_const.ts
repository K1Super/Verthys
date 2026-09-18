/*
 * constants/crypto_const.ts — 加密层统一常量
 *
 * 设计原则（codebase-design 深模块）：
 *   - 所有长度、迭代次数、AD 文本标识、VENC 魔数/版本集中定义
 *   - 前端加密层（crypto.ts）唯一常量入口，消除散落的魔术数字
 *   - 常量值与后端 C 层协议严格对齐，禁止单独修改
 *
 */

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

/** 单块大小（1 MiB） */
export const CHUNK_SIZE = 1 * 1024 * 1024;

/** BLAKE3 文件哈希长度（256 位） */
export const FILE_HASH_LEN = 32;

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

/* ------------------------------------------------------------------ *
 * VENC 打包格式常量                                                   *
 *                                                                    *
 * .venc 文件结构：                                                    *
 *   [魔数 8B] [版本 4B 大端] [照片数 4B 大端]                         *
 *   for each photo:                                                  *
 *     [元数据长度 4B] [元数据 bytes]                                 *
 *     [块数 4B]                                                      *
 *     for each chunk: [块长度 4B] [块 bytes]                         *
 * ------------------------------------------------------------------ */

/** VENC 文件魔数文本 */
export const VENC_MAGIC_TEXT = "VERTHYSPHOTO";

/** VENC 当前版本 */
export const VENC_VERSION = 1;

/* ------------------------------------------------------------------ *
 * Verthys 记录类型常量
 *
 * ★ 企业级根治：TYPE 常量统一到 constants/record_types.ts（单一真相源）
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
} from "./record_types";
