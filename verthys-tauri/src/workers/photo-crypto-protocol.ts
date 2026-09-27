/**
 * workers/photo-crypto-protocol.ts — 照片加密 Worker 消息协议与响应装配
 *
 * 职责：集中定义 photo-crypto.worker 与主线程（Worker 池）之间的消息契约，
 * 并提供 Worker 侧的纯装配函数：把加密处理产物逐字段装箱为响应消息。
 *
 * 关键约束：完整加密的成功响应必须原样携带处理产物的全部字段，尤其是
 * 外置块产物（external）。漏传会让主线程把外置路径误判为内联路径，大文件
 * 导入在「加密产物缺少元数据」处必然失败；装配函数把该不变式收敛到唯一
 * 实现点，并由单元测试锁定。
 *
 * 解密操作（decrypt_meta / decrypt_chunks）的同型约束：明文块必须以可转移的
 * ArrayBuffer 原样装箱——装配若做防御性拷贝，Worker 侧零拷贝转移即失效，并让
 * MB 级明文在工作线程多驻留一份。
 *
 * 本模块不依赖 self / DOM / Worker 运行时，可在任意环境（含单测）直接导入。
 */

import type { PhotoMeta, SlimChunkSet } from "../types/crypto";

/* ------------------------------------------------------------------ *
 * 消息类型定义                                                        *
 * ------------------------------------------------------------------ */

/** 主线程 → Worker 请求（完整加密） */
export interface PhotoCryptoRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 文件名（用于 meta.name + 记录名） */
  fileName: string;
  /** MIME 类型 */
  mime: string;
  /** 文件原始字节（通过 transferList 零拷贝转让） */
  fileBytes: ArrayBuffer;
  /** 照片模块独立密钥 */
  photoKey: string;
}

/** 外置块输出（块密文总量超过内联阈值时的成功产物） */
export interface PhotoExternalParts {
  /** 加密块 base64 列表（外置块记录载荷，主线程经块上传命令落库） */
  chunkB64List: string[];
  /** 逐块密文 BLAKE3 hex（块去重与完整性校验权威值） */
  chunkHashes: string[];
  /** 待补 chunkIds 的元数据模板（主线程块上传后回填并重新加密） */
  metaTemplate: PhotoMeta;
}

/** 完整加密处理产物（Worker 内部处理函数的返回值，装配响应前的中间结构） */
export interface PhotoProcessResult {
  /** BLAKE3 文件哈希 hex（去重 + WAL 幂等） */
  hash: string;
  /** 缩略图 base64（JPEG 0.85，最大 400×400） */
  thumbB64: string;
  /** 已加密的元数据 base64（内联路径）；外置路径为空 */
  metaB64?: string;
  /** 外置块输出（块密文总量超过内联阈值时携带） */
  external?: PhotoExternalParts;
  /** 记录名（`meta_${fileName}`） */
  name: string;
  /** MIME 类型 */
  mime: string;
  /** 原始文件大小（字节） */
  size: number;
}

/** Worker → 主线程 响应（完整加密成功） */
export interface PhotoCryptoSuccess {
  id: number;
  ok: true;
  /** BLAKE3 文件哈希 hex（去重 + WAL 幂等） */
  hash: string;
  /** 缩略图 base64（JPEG 0.85，最大 400×400） */
  thumbB64: string;
  /** 已加密的元数据 base64（内联模式）；外置模式下为空 */
  metaB64?: string;
  /** 外置块输出（块密文总量超过内联阈值时携带） */
  external?: PhotoExternalParts;
  /** 记录名（`meta_${fileName}`） */
  name: string;
  /** MIME 类型 */
  mime: string;
  /** 原始文件大小（字节） */
  size: number;
}

/** Worker → 主线程 响应（失败） */
export interface PhotoCryptoFailure {
  id: number;
  ok: false;
  /** 文件名（用于错误提示） */
  name: string;
  /** 错误信息 */
  error: string;
}

/** 索引瘦身布局的加密参数（索引密文盐必须与包裹密钥同盐） */
export interface SlimMetaParams {
  /** 文件盐 base64（由加密任务生成并贯穿到索引加密任务） */
  fileSaltB64: string;
}

/** 主线程 → Worker 请求（meta-only 加密，解析导入路径） */
export interface PhotoMetaCryptoRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 已解密的元数据对象（解析阶段解密，此处重新加密） */
  meta: PhotoMeta;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 记录名（`parsed_${timestamp}_${index}`，由调用方生成保证唯一） */
  recordName: string;
  /** 索引瘦身布局参数（缺省 = 既有布局：按随机盐加密索引） */
  slim?: SlimMetaParams;
}

/** 主线程 → Worker 请求（索引瘦身布局：加密缩略图记录载荷） */
export interface PhotoSlimThumbRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：显式判别字段（与其它请求无歧义） */
  op: "encrypt_slim_thumb";
  /** 缩略图 base64（明文 JPEG，来自完整加密产物） */
  thumbB64: string;
  /** 文件盐 base64（索引加密任务共用同一盐） */
  fileSaltB64: string;
  /** 文件哈希 hex（缩略图 AD 绑定，防跨照片换用） */
  fileHashHex: string;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 定位标识（记录名或照片名，用于日志与错误提示） */
  label: string;
}

/** 索引瘦身布局缩略图加密产物 */
export interface SlimThumbResult {
  /** 缩略图记录载荷 base64（nonce ‖ 密文+tag） */
  thumbCipherB64: string;
  /** 缩略图密文的 BLAKE3 hex（记录去重与完整性校验权威值） */
  thumbHash: string;
}

/** Worker → 主线程 响应（缩略图记录加密成功） */
export interface PhotoSlimThumbSuccess {
  id: number;
  ok: true;
  /** 缩略图记录载荷 base64 */
  thumbCipherB64: string;
  /** 缩略图密文的 BLAKE3 hex */
  thumbHash: string;
}

/** 主线程 → Worker 请求（索引瘦身布局：加密块集记录载荷） */
export interface PhotoSlimSetRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：显式判别字段 */
  op: "encrypt_slim_set";
  /** 块集内容（逐块记录 ID 与逐块密文哈希，按序一一对应） */
  set: SlimChunkSet;
  /** 文件盐 base64（索引加密任务共用同一盐） */
  fileSaltB64: string;
  /** 文件哈希 hex（块集 AD 绑定，防跨照片换用） */
  fileHashHex: string;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 定位标识（记录名或照片名，用于日志与错误提示） */
  label: string;
}

/** 索引瘦身布局块集加密产物 */
export interface SlimSetResult {
  /** 块集记录载荷 base64（nonce ‖ 密文+tag） */
  setCipherB64: string;
  /** 块集密文的 BLAKE3 hex（记录去重与完整性校验权威值） */
  setHash: string;
}

/** Worker → 主线程 响应（块集记录加密成功） */
export interface PhotoSlimSetSuccess {
  id: number;
  ok: true;
  /** 块集记录载荷 base64 */
  setCipherB64: string;
  /** 块集密文的 BLAKE3 hex */
  setHash: string;
}

/** 主线程 → Worker 请求（块集记录解密：查看原图 / 导出 / 删除级联） */
export interface PhotoDecryptSlimSetRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：解密请求的显式判别字段 */
  op: "decrypt_slim_set";
  /** 块集记录载荷 base64 */
  setCipherB64: string;
  /** 包裹态文件密钥（含文件盐，与索引同盐） */
  wrappedFileKey: string;
  /** 文件哈希 hex（块集 AD 绑定） */
  fileHashHex: string;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 定位标识（记录 ID 或照片名，用于日志与错误提示） */
  label: string;
  /** 模块密钥失效后由池标记：本次任务先行清空派生缓存再执行 */
  clearCache?: boolean;
}

/** Worker → 主线程 响应（块集记录解密成功） */
export interface PhotoDecryptSlimSetSuccess {
  id: number;
  ok: true;
  /** 块集内容（逐块记录 ID 与逐块密文哈希） */
  set: SlimChunkSet;
}

/** 主线程 → Worker 请求（重打包：把既有布局照片重加密为索引瘦身布局） */
export interface PhotoSlimRepackRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：显式判别字段 */
  op: "encrypt_slim_photo";
  /** 照片原始明文字节（transferList 零拷贝转让） */
  fileBytes: ArrayBuffer;
  /** 文件哈希 hex（与源索引一致，用于校验与 AD 绑定） */
  fileHashHex: string;
  /** 展示字段（沿用源索引；缩略图不重新生成，避免重编码漂移） */
  name: string;
  /** MIME 类型 */
  mime: string;
  /** 原始文件大小（字节） */
  size: number;
  /** 创建时间戳（毫秒，沿用源索引） */
  createdAt: number;
  /** 明文缩略图 base64（源索引内解出的展示字段） */
  thumbB64: string;
  /** 照片模块独立密钥 */
  photoKey: string;
}

/** meta-only 加密处理产物 */
export interface PhotoMetaProcessResult {
  /** 已加密的元数据 base64（XChaCha20-Poly1305） */
  metaB64: string;
  /** BLAKE3 文件哈希 hex（从 meta.fileHash 提取，去重 + WAL 幂等） */
  hash: string;
  /** 缩略图 base64（从 meta.thumbB64 提取） */
  thumbB64: string;
  /** 记录名（`parsed_${timestamp}_${index}`，用于 verthys 记录名） */
  recordName: string;
}

/** Worker → 主线程 响应（meta-only 加密成功） */
export interface PhotoMetaCryptoSuccess {
  id: number;
  ok: true;
  /** 已加密的元数据 base64（XChaCha20-Poly1305） */
  metaB64: string;
  /** BLAKE3 文件哈希 hex（从 meta.fileHash 提取，去重 + WAL 幂等） */
  hash: string;
  /** 缩略图 base64（从 meta.thumbB64 提取） */
  thumbB64: string;
  /** 记录名 */
  name: string;
  /** MIME 类型（从 meta.mime 提取） */
  mime: string;
  /** 原始文件大小（从 meta.size 提取） */
  size: number;
  /** 记录名（`parsed_${timestamp}_${index}`，用于 verthys 记录名） */
  recordName: string;
}

/** 主线程 → Worker 请求（元数据解密：列表按需解密与查看原图回填） */
export interface PhotoDecryptMetaRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：解密请求的显式判别字段（加密请求无此字段，Worker 据此稳定分发） */
  op: "decrypt_meta";
  /** 加密的元数据 base64（含盐与 nonce） */
  metaB64: string;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 定位标识（记录 ID 或照片名，用于日志与错误提示） */
  label: string;
  /**
   * 索引瘦身布局：缩略图记录载荷 base64。
   * 与元数据同任务解密——索引解密已派生出所需密钥（同盐），省去独立任务的
   * 第二次密钥派生；缺省表示既有布局（缩略图内联于元数据）。
   */
  thumbCipherB64?: string;
  /** 模块密钥失效后由池标记：本次任务先行清空派生缓存再执行 */
  clearCache?: boolean;
}

/** 主线程 → Worker 请求（数据块解密：查看原图） */
export interface PhotoDecryptChunksRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：解密请求的显式判别字段（加密请求无此字段，Worker 据此稳定分发） */
  op: "decrypt_chunks";
  /** 按序排列的块密文 base64 列表（顺序即块序号，用于 AD 校验） */
  chunksB64: string[];
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 文件哈希 hex（块 AD 绑定，校验块归属与顺序） */
  fileHashHex: string;
  /** 定位标识（记录 ID 或照片名，用于日志与错误提示） */
  label: string;
  /** 索引瘦身布局：包裹态文件密钥（提供时块按 nonce|密文 布局解密） */
  wrappedFileKey?: string;
  /** 索引瘦身布局：块总数（密文不携带总数，AD 绑定由调用方给出） */
  chunkTotal?: number;
  /** 模块密钥失效后由池标记：本次任务先行清空派生缓存再执行 */
  clearCache?: boolean;
}

/** 主线程 → Worker 请求（缩略图记录解密：索引瘦身布局的列表路径） */
export interface PhotoDecryptThumbRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 操作标识：解密请求的显式判别字段 */
  op: "decrypt_thumb";
  /** 缩略图记录载荷 base64（nonce ‖ 密文+tag） */
  thumbCipherB64: string;
  /** 包裹态文件密钥（含文件盐，与索引同盐） */
  wrappedFileKey: string;
  /** 文件哈希 hex（缩略图 AD 绑定） */
  fileHashHex: string;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 定位标识（记录 ID 或照片名，用于日志与错误提示） */
  label: string;
  /** 模块密钥失效后由池标记：本次任务先行清空派生缓存再执行 */
  clearCache?: boolean;
}

/** Worker → 主线程 响应（缩略图记录解密成功） */
export interface PhotoDecryptThumbSuccess {
  id: number;
  ok: true;
  /** 缩略图原始字节（经 transferList 零拷贝回传） */
  thumbBytes: ArrayBuffer;
}

/** Worker → 主线程 响应（元数据解密成功） */
export interface PhotoDecryptMetaSuccess {
  id: number;
  ok: true;
  /** 解密后的元数据（展示字段 + 块引用） */
  meta: PhotoMeta;
  /** 索引瘦身布局：解密后的缩略图原始字节（经 transferList 零拷贝回传） */
  thumbBytes?: ArrayBuffer;
}

/** Worker → 主线程 响应（数据块解密成功） */
export interface PhotoDecryptChunksSuccess {
  id: number;
  ok: true;
  /** 按输入顺序的明文块（经 transferList 零拷贝回传，Worker 侧已无访问权） */
  plaintexts: ArrayBuffer[];
}

/** Worker 响应联合类型 */
export type PhotoCryptoResponse =
  | PhotoCryptoSuccess
  | PhotoCryptoFailure
  | PhotoMetaCryptoSuccess
  | PhotoSlimThumbSuccess
  | PhotoSlimSetSuccess
  | PhotoDecryptMetaSuccess
  | PhotoDecryptThumbSuccess
  | PhotoDecryptSlimSetSuccess
  | PhotoDecryptChunksSuccess;

/** 请求联合类型（Worker 消息入口的输入：加密类 + 解密类） */
export type PhotoCryptoRequestEnvelope =
  | PhotoCryptoRequest
  | PhotoSlimRepackRequest
  | PhotoMetaCryptoRequest
  | PhotoSlimThumbRequest
  | PhotoSlimSetRequest
  | PhotoDecryptMetaRequest
  | PhotoDecryptThumbRequest
  | PhotoDecryptSlimSetRequest
  | PhotoDecryptChunksRequest;

/* ------------------------------------------------------------------ *
 * 响应装配（纯函数）                                                  *
 * ------------------------------------------------------------------ */

/**
 * 装配完整加密的成功响应。
 *
 * 不变式：external 与 metaB64 互斥——外置路径的产物无 metaB64（元数据待
 * 主线程回填块引用后重新加密），内联路径的产物无 external。装配逐字段
 * 透传全部产物字段，禁止裁剪：任何字段丢失都会让主线程走错分支（外置
 * 产物丢失时表现为「加密产物缺少元数据」导入失败）。
 *
 * @param id 任务 ID（与请求一一对应，池据此关联在途任务）
 * @param result 加密处理产物
 * @returns 完整加密成功响应（external / metaB64 按产物原样透传）
 */
export function assemblePhotoCryptoSuccess(
  id: number,
  result: PhotoProcessResult,
): PhotoCryptoSuccess {
  return {
    id,
    ok: true,
    hash: result.hash,
    thumbB64: result.thumbB64,
    metaB64: result.metaB64,
    external: result.external,
    name: result.name,
    mime: result.mime,
    size: result.size,
  };
}

/**
 * 装配索引瘦身布局缩略图加密的成功响应。
 *
 * @param id 任务 ID
 * @param result 缩略图加密产物（密文与密文哈希）
 * @returns 缩略图加密成功响应
 */
export function assemblePhotoSlimThumbSuccess(
  id: number,
  result: SlimThumbResult,
): PhotoSlimThumbSuccess {
  return {
    id,
    ok: true,
    thumbCipherB64: result.thumbCipherB64,
    thumbHash: result.thumbHash,
  };
}

/**
 * 装配索引瘦身布局块集加密的成功响应。
 *
 * @param id 任务 ID
 * @param result 块集加密产物（密文与密文哈希）
 * @returns 块集加密成功响应
 */
export function assemblePhotoSlimSetSuccess(
  id: number,
  result: SlimSetResult,
): PhotoSlimSetSuccess {
  return {
    id,
    ok: true,
    setCipherB64: result.setCipherB64,
    setHash: result.setHash,
  };
}

/**
 * 装配块集记录解密成功响应。
 *
 * 不变式：块集内容原样透传（逐块 ID 与哈希一一对应）——读取侧据此按序取块
 * 并逐块比对密文哈希，字段裁剪会让块序号错位或完整性校验失效。
 *
 * @param id 任务 ID
 * @param set 解密后的块集内容
 * @returns 块集解密成功响应
 */
export function assemblePhotoDecryptSlimSetSuccess(
  id: number,
  set: SlimChunkSet,
): PhotoDecryptSlimSetSuccess {
  return { id, ok: true, set };
}

/**
 * 装配元数据解密成功响应。
 *
 * 不变式：meta 原样透传（不重建对象、不裁剪字段）——解密产物是列表渲染
 * 字段与后续块读取（chunkIds / chunkHashes / fileHash / mime）的唯一来源，
 * 字段缺失会让查看原图或导出在后续步骤失败；索引瘦身布局下缩略图明文
 * 以可转移缓冲原样携带（拷贝会让零拷贝转移失效并多驻留一份）。
 *
 * @param id 任务 ID
 * @param meta 解密后的元数据
 * @param thumbBytes 索引瘦身布局的缩略图原始字节（既有布局为 undefined）
 * @returns 元数据解密成功响应
 */
export function assemblePhotoDecryptMetaSuccess(
  id: number,
  meta: PhotoMeta,
  thumbBytes?: ArrayBuffer,
): PhotoDecryptMetaSuccess {
  return { id, ok: true, meta, thumbBytes };
}

/**
 * 装配缩略图记录解密成功响应。
 *
 * 不变式：thumbBytes 以可转移缓冲原样携带——Worker 侧以其作为 transferList
 * 零拷贝转移所有权，任何防御性拷贝都会让转移失效。
 *
 * @param id 任务 ID
 * @param thumbBytes 缩略图原始字节
 * @returns 缩略图解密成功响应
 */
export function assemblePhotoDecryptThumbSuccess(
  id: number,
  thumbBytes: ArrayBuffer,
): PhotoDecryptThumbSuccess {
  return { id, ok: true, thumbBytes };
}

/**
 * 装配 meta-only 加密的成功响应：除密文与哈希外，把元数据中的
 * 展示字段（名称/MIME/大小/缩略图）一并提升为响应顶层字段，
 * 主线程据此构造列表项而无需再次解密。
 *
 * @param id 任务 ID
 * @param result meta-only 加密处理产物
 * @param meta 参与加密的元数据（展示字段来源）
 * @returns meta-only 加密成功响应
 */
export function assemblePhotoMetaCryptoSuccess(
  id: number,
  result: PhotoMetaProcessResult,
  meta: PhotoMeta,
): PhotoMetaCryptoSuccess {
  return {
    id,
    ok: true,
    metaB64: result.metaB64,
    hash: result.hash,
    thumbB64: result.thumbB64,
    name: meta.name,
    mime: meta.mime,
    size: meta.size,
    recordName: result.recordName,
  };
}

/**
 * 装配失败响应。
 *
 * @param id 任务 ID
 * @param name 文件名或记录名（用于错误提示与日志定位）
 * @param error 错误信息（面向用户的简短描述）
 * @returns 失败响应
 */
export function assemblePhotoCryptoFailure(
  id: number,
  name: string,
  error: string,
): PhotoCryptoFailure {
  return { id, ok: false, name, error };
}

/**
 * 装配数据块解密成功响应。
 *
 * 不变式：plaintexts 保持调用方数组与元素引用不变——Worker 侧以该数组作为
 * transferList 零拷贝转移明文所有权；任何防御性拷贝都会让转移失效，并使
 * MB 级明文在工作线程多驻留一份。
 *
 * @param id 任务 ID
 * @param plaintexts 按输入顺序的明文块
 * @returns 数据块解密成功响应
 */
export function assemblePhotoDecryptChunksSuccess(
  id: number,
  plaintexts: ArrayBuffer[],
): PhotoDecryptChunksSuccess {
  return { id, ok: true, plaintexts };
}