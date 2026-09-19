/*
 * types/crypto.ts — 加密层类型定义
 *
 * 设计原则：
 *   - 前端加密层所有 TS 接口集中定义，供 crypto.ts 与上层组件共用
 *   - 类型与运行时数据格式严格对齐（类型与 crypto_const.ts 注释对齐）
 *   - 向后兼容字段标注可选，禁止破坏已存储的数据格式
 *
 */

/* ------------------------------------------------------------------ *
 * 照片元数据                                                          *
 *                                                                    *
 * 加密后以 JSON 明文存储，再经 XChaCha20-Poly1305 加密为 base64       *
 * 存储格式：[salt(16)] [nonce(24)] [ciphertext+tag(变长)]             *
 * ------------------------------------------------------------------ */

export interface PhotoMeta {
  /** 原始文件名（加密存储） */
  name: string;
  /** MIME 类型（加密存储） */
  mime: string;
  /** 文件字节数 */
  size: number;
  /** 缩略图 base64（JPEG 0.85 质量） */
  thumbB64: string;
  /** 旧格式：数据块在 verthys 中的记录 ID（向后兼容） */
  chunkIds: number[];
  /** 新格式：内联存储加密 chunk 数据（base64），避免 ID 漂移导致数据丢失 */
  chunkDataB64?: string[];
  /** BLAKE3 文件哈希（hex 编码，32 字节 → 64 字符） */
  fileHash: string;
  /** 创建时间戳（毫秒） */
  createdAt: number;
}

/* ------------------------------------------------------------------ *
 * VENC 打包数据                                                       *
 *                                                                    *
 * 用于 .venc 导出文件的打包/解包：                                    *
 *   - metaB64：加密后的元数据 base64                                  *
 *   - chunkB64List：加密后的数据块 base64 数组                        *
 * ------------------------------------------------------------------ */

export interface VencPhotoData {
  /** 加密后的元数据 base64 */
  metaB64: string;
  /** 加密后的数据块 base64 数组 */
  chunkB64List: string[];
}
