/**
 * workers/photo-decrypt-bridge.ts — 读取链路解密桥（Worker 池优先 + 主线程兜底）
 *
 * 职责：把读取链路的解密调用收敛到同一策略——优先在 photo-crypto Worker 池
 * 执行（主线程不做 base64 解码、密钥派生与 AEAD），池不可用时回退主线程实现。
 * 调用方无需自行判定错误类别。
 *
 * 失败分类（决定是否回退）：
 * - Worker 明确拒绝（TaskRejectedError）：确定性失败（标签校验不过、密文损坏），
 *   主线程执行同一套密码学运算必然得到同样结果，回退只会重复付出派生成本，
 *   故直接向上传播。
 * - 池基础设施失败（崩溃、超时、毒丸、已终止、通信失败）：回退主线程，
 *   保证加密 Worker 不可用时读取链路仍可工作（读路径不因写路径故障而中断）。
 *
 * 两条路径复用 lib/crypto 的同一套原语（decryptMeta / decryptChunk），
 * 密文布局与解密结果完全一致，回退不改变任何产物。
 */
import {
  decryptMeta, decryptChunk, decryptSlimThumb, unwrapSlimFileKey, decryptSlimChunk,
  decryptSlimChunkSet, computeChunkHashesForB64, computeFileHash,
  type PhotoMeta, type SlimChunkSet,
} from "../lib/crypto";
import { bytesToHex } from "../utils/binary_codec";
import { createLogger } from "../utils/logger";
import { photoWorkerPool, TaskRejectedError } from "./photoWorkerPool";

const log = createLogger("photo-decrypt-bridge");

/** 元数据解密产物：索引 + （索引瘦身布局的）缩略图原始字节 */
export interface MetaDecryptOutcome {
  meta: PhotoMeta;
  /** 索引瘦身布局的缩略图原始字节（既有布局为 undefined） */
  thumbBytes?: ArrayBuffer;
}

/** 索引瘦身布局的块解密参数 */
export interface SlimChunkParams {
  /** 包裹态文件密钥（解封随机文件密钥后按 nonce|密文 布局逐块解密） */
  wrappedFileKey: string;
  /** 块总数（密文不携带总数，AD 绑定由调用方给出） */
  chunkTotal: number;
}

/**
 * 解密照片元数据：优先 Worker 池，池基础设施失败时回退主线程。
 *
 * @param metaB64 加密的元数据 base64
 * @param photoKey 照片模块独立密钥
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @param thumbCipherB64 索引瘦身布局的缩略图记录密文（可选）：与元数据同任务
 *   解密（索引解密已派生同一把包裹密钥），主线程回退路径同样在本函数内完成
 * @returns 元数据与（瘦身布局的）缩略图原始字节
 * @throws Error 确定性失败（密文损坏/标签校验不过）或回退路径的原始错误
 */
export async function decryptMetaPreferWorker(
  metaB64: string,
  photoKey: string,
  label: string,
  thumbCipherB64?: string,
): Promise<MetaDecryptOutcome> {
  try {
    const { meta, thumbBytes } = await photoWorkerPool.submitDecryptMeta({
      metaB64,
      photoKey,
      label,
      thumbCipherB64,
    });
    return { meta, thumbBytes };
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，回退主线程解密元数据（${label}）:`, e);
    return decryptMetaOnMainThread(metaB64, photoKey, thumbCipherB64);
  }
}

/**
 * 解密索引瘦身布局的缩略图记录：优先 Worker 池，池基础设施失败时回退主线程。
 *
 * 用于列表路径在元数据解密后补取缩略图（元数据任务未携带缩略图密文时）。
 * 与元数据共用同一文件盐，池内派生缓存可命中时不产生额外 PBKDF2。
 *
 * @param thumbCipherB64 缩略图记录载荷 base64（nonce ‖ 密文+tag）
 * @param photoKey 照片模块独立密钥
 * @param wrappedFileKey 包裹态文件密钥（含文件盐）
 * @param fileHashHex 文件哈希 hex（缩略图 AD 绑定）
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @returns 缩略图原始字节
 */
export async function decryptThumbPreferWorker(
  thumbCipherB64: string,
  photoKey: string,
  wrappedFileKey: string,
  fileHashHex: string,
  label: string,
): Promise<Uint8Array> {
  try {
    const { thumbBytes } = await photoWorkerPool.submitDecryptThumb({
      thumbCipherB64,
      photoKey,
      wrappedFileKey,
      fileHashHex,
      label,
    });
    return new Uint8Array(thumbBytes);
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，回退主线程解密缩略图（${label}）:`, e);
    return decryptSlimThumb(thumbCipherB64, photoKey, wrappedFileKey, fileHashHex);
  }
}

/**
 * 解密索引瘦身布局的块集记录：优先 Worker 池，池基础设施失败时回退主线程。
 *
 * 用于查看原图 / 导出 / 删除级联取用逐块引用与逐块哈希；与元数据共用同一
 * 文件盐，池内派生缓存可命中时不产生额外 PBKDF2。
 *
 * @param setCipherB64 块集记录载荷 base64（nonce ‖ 密文+tag）
 * @param photoKey 照片模块独立密钥
 * @param wrappedFileKey 包裹态文件密钥（含文件盐）
 * @param fileHashHex 文件哈希 hex（块集 AD 绑定）
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @returns 块集内容（逐块记录 ID 与逐块密文哈希）
 */
export async function decryptChunkSetPreferWorker(
  setCipherB64: string,
  photoKey: string,
  wrappedFileKey: string,
  fileHashHex: string,
  label: string,
): Promise<SlimChunkSet> {
  try {
    const { set } = await photoWorkerPool.submitDecryptSlimSet({
      setCipherB64,
      photoKey,
      wrappedFileKey,
      fileHashHex,
      label,
    });
    return set;
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，回退主线程解密块集（${label}）:`, e);
    return decryptSlimChunkSet(setCipherB64, photoKey, wrappedFileKey, fileHashHex);
  }
}

/** 主线程解密（池不可用时的兜底实现）：元数据 + 可选缩略图，语义与 Worker 路径一致 */
async function decryptMetaOnMainThread(
  metaB64: string,
  photoKey: string,
  thumbCipherB64?: string,
): Promise<MetaDecryptOutcome> {
  const meta = await decryptMeta(metaB64, photoKey);
  if (!thumbCipherB64) return { meta };
  if (!meta.wrappedFileKey) {
    throw new Error("索引缺少包裹态文件密钥，无法解密缩略图记录");
  }
  const thumb = await decryptSlimThumb(thumbCipherB64, photoKey, meta.wrappedFileKey, meta.fileHash);
  return {
    meta,
    thumbBytes: thumb.buffer.slice(thumb.byteOffset, thumb.byteOffset + thumb.byteLength) as ArrayBuffer,
  };
}

/** 块解密任务的完整性权威值（缺省表示不校验：历史记录无权威值的兼容路径） */
export interface ChunkVerifyOptions {
  /** 逐块密文哈希（非空时在解密前逐块校验） */
  expectedHashes?: string[];
  /** 整图明文哈希（提供时对解密产物按序增量校验） */
  expectedFileHash?: string;
}

/**
 * 解密照片数据块：优先 Worker 池，池基础设施失败时回退主线程。
 *
 * @param chunksB64 按序排列的块密文 base64 列表
 * @param photoKey 照片模块独立密钥
 * @param fileHashHex 文件哈希 hex（块 AD 绑定）
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @param slim 索引瘦身布局参数（提供时按 nonce|密文 布局解密）
 * @param verify 完整性权威值：随任务透传给 Worker 在解密前后比对；
 *   回退主线程时保持同等校验标准（降级不降标准）
 * @returns 按输入顺序的明文块（长度与输入一致）
 * @throws Error 任一块解密失败或校验不符即整体失败（不产出残缺序列）
 */
export async function decryptChunksPreferWorker(
  chunksB64: string[],
  photoKey: string,
  fileHashHex: string,
  label: string,
  slim?: SlimChunkParams,
  verify?: ChunkVerifyOptions,
): Promise<Uint8Array[]> {
  try {
    const { plaintexts } = await photoWorkerPool.submitDecryptChunks({
      chunksB64,
      photoKey,
      fileHashHex,
      label,
      wrappedFileKey: slim?.wrappedFileKey,
      chunkTotal: slim?.chunkTotal,
      expectedHashes: verify?.expectedHashes,
      expectedFileHash: verify?.expectedFileHash,
    });
    // 转移回传的缓冲直接以视图消费：不再拷贝，避免 MB 级明文在主线程翻倍驻留
    return plaintexts.map((buf) => new Uint8Array(buf));
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，回退主线程解密数据块（${label}）:`, e);
    return decryptChunksOnMainThread(chunksB64, photoKey, fileHashHex, slim, verify);
  }
}

/**
 * 主线程逐块解密（池不可用时的兜底实现）。
 *
 * 语义与 Worker 路径一致：任一块失败即整体失败；错误信息携带块序号，
 * 便于定位损坏块。
 */
async function decryptChunksOnMainThread(
  chunksB64: string[],
  photoKey: string,
  fileHashHex: string,
  slim?: SlimChunkParams,
  verify?: ChunkVerifyOptions,
): Promise<Uint8Array[]> {
  if (slim && (!Number.isInteger(slim.chunkTotal) || slim.chunkTotal !== chunksB64.length)) {
    throw new Error(`块总数与密文数量不一致（声明 ${slim.chunkTotal}，实得 ${chunksB64.length}）`);
  }
  const expectedHashes = verify?.expectedHashes;
  if (expectedHashes && expectedHashes.length > 0) {
    if (expectedHashes.length !== chunksB64.length) {
      throw new Error(
        `哈希项数与块数不一致（哈希 ${expectedHashes.length}，块 ${chunksB64.length}）`,
      );
    }
    // 降级路径保持同等校验标准：密文哈希先于解密比对
    const actualHashes = computeChunkHashesForB64(chunksB64);
    for (let i = 0; i < actualHashes.length; i++) {
      if (actualHashes[i].toLowerCase() !== expectedHashes[i].toLowerCase()) {
        throw new Error(`块密文哈希校验失败（第 ${i + 1}/${chunksB64.length} 块）`);
      }
    }
  }
  const plaintexts: Uint8Array[] = [];
  let fileKey: Uint8Array | null = null;
  try {
    if (slim) {
      fileKey = await unwrapSlimFileKey(slim.wrappedFileKey, photoKey);
    }
    for (let c = 0; c < chunksB64.length; c++) {
      try {
        if (fileKey) {
          plaintexts.push(decryptSlimChunk(chunksB64[c], fileKey, fileHashHex, c, chunksB64.length));
        } else {
          const { plaintext, seq, total } = await decryptChunk(chunksB64[c], photoKey, fileHashHex);
          // 自描述位置校验：与 Worker 路径同一判定——块头部声明必须与列表
          // 位置一致，乱序/截断在拼接前拒绝（避免产出错误顺序的整图）
          if (seq !== c || total !== chunksB64.length) {
            throw new Error(
              `数据块顺序校验失败（seq=${seq} total=${total}，期望 ${c}/${chunksB64.length}）`,
            );
          }
          plaintexts.push(plaintext);
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`第 ${c + 1}/${chunksB64.length} 块解密失败: ${msg}`);
      }
    }
    if (verify?.expectedFileHash) {
      // 降级路径保持同等校验标准：整图哈希在此按拼接结果比对
      //（可接受的降级成本：仅在 Worker 池不可用时发生）
      const totalLen = plaintexts.reduce((s, c) => s + c.length, 0);
      const fullBytes = new Uint8Array(totalLen);
      let offset = 0;
      for (const c of plaintexts) { fullBytes.set(c, offset); offset += c.length; }
      const actualFileHash = bytesToHex(computeFileHash(fullBytes));
      if (actualFileHash !== verify.expectedFileHash) {
        throw new Error(
          `整图哈希校验失败（期望 ${verify.expectedFileHash}，实际 ${actualFileHash}）`,
        );
      }
    }
    return plaintexts;
  } finally {
    fileKey?.fill(0);
  }
}