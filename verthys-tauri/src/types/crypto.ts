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
  /** 缩略图 base64（JPEG 0.85 质量）；索引瘦身布局下为空串（缩略图在独立记录） */
  thumbB64: string;
  /** 块引用：数据块在 verthys 中的记录 ID（旧格式密文使用） */
  chunkIds: number[];
  /** 内联存储：加密 chunk 数据（base64），避免 ID 漂移导致数据丢失 */
  chunkDataB64?: string[];
  /**
   * 各加密块密文的 BLAKE3 hex（与 chunkDataB64 顺序一致）。
   * 仅作诊断：模块密钥轮换会换封密文并使其合法失配；内容权威值是 fileHash。
   */
  chunkHashes?: string[];
  /** 非内容续传条目键（可选；不参与内容寻址，仅用于 WAL 幂等） */
  entryKey?: string;
  /** BLAKE3 文件哈希（hex 编码，32 字节 → 64 字符） */
  fileHash: string;
  /** 创建时间戳（毫秒） */
  createdAt: number;
  /**
   * 布局标记（缺省 = 既有布局）：取值见布局常量。
   * 读取侧据此分流：既有布局直读内联缩略图；索引瘦身布局按引用取独立记录。
   */
  fmt?: number;
  /** 索引瘦身布局：缩略图记录 ID（独立记录，载荷为加密缩略图） */
  thumbId?: number;
  /** 索引瘦身布局：包裹态文件密钥（base64，内含文件盐；解封得到块级文件密钥） */
  wrappedFileKey?: string;
  /**
   * 索引瘦身布局：块集记录 ID（独立记录，载荷为逐块引用与逐块哈希）。
   * 索引据此与照片大小解耦；早期布局二未携带本字段时，逐块引用回落到
   * 索引内联的 chunkIds / chunkHashes。
   */
  chunkSetId?: number;
  /** 索引瘦身布局：块总数（与块集内容交叉校验；列表路径不取块集即可展示） */
  chunkCount?: number;
}

/* ------------------------------------------------------------------ *
 * 可移植备份容器类型                                                  *
 *                                                                    *
 * 自描述信封 + 内容密钥封装 + 逐帧 AEAD：                              *
 *   - LightMeta：容器内的清单（明文结构，经内容密钥逐帧加密传输），    *
 *     不携带任何模块密钥或布局信息                                    *
 *   - VencPhotoSpec：单张照片的清单 + 原始明文块字节                   *
 * ------------------------------------------------------------------ */

/** 容器内的清单（明文结构）：与本地存储 PhotoMeta 的分体投影 */
export interface LightMeta {
  /** 原始文件名 */
  name: string;
  /** MIME 类型 */
  mime: string;
  /** 文件字节数 */
  size: number;
  /** 缩略图 base64（JPEG 0.85 质量）；可为空串 */
  thumbB64: string;
  /** BLAKE3 文件哈希（hex 编码，完整明文） */
  fileHash: string;
  /** 创建时间戳（毫秒） */
  createdAt: number;
  /** 数据块总数 */
  chunkCount: number;
}

/** 单张照片的容器数据：清单 + 原始明文块字节 */
export interface VencPhotoSpec {
  /** 容器清单（明文） */
  lightMeta: LightMeta;
  /** 原始明文块（每块对应一个块帧负载） */
  chunkBytes: Uint8Array[];
}

/** 块集记录载荷（解密后）：逐块记录 ID 与逐块密文哈希，按序一一对应 */
export interface SlimChunkSet {
  /** 块记录 ID（数组顺序即块序号，与 AD 绑定的 seq 一致） */
  ids: number[];
  /** 各块密文的 BLAKE3 hex（顺序与 ids 一致） */
  hashes: string[];
}
