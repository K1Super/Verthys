/**
 * workers/photo-decrypt-bridge.ts — 读取链路解密桥（Worker 池优先 + 主线程直连）
 *
 * 职责：把读取链路的解密调用收敛到同一策略——优先在 photo-crypto Worker 池
 * 执行（主线程不做载荷解码与调度），池不可用时在主线程直接调用同一组
 * Tauri 模块加解密命令。
 *
 * 密钥边界：两条路径都不在 JS 内派生或持有文件密钥；瘦身布局由 worker
 * 每次用包裹态密钥一次性解封文件密钥，解封结果只在该次调用内驻留。
 *
 * 失败分类：池基础设施失败回退直连；Worker 明确拒绝（数据损坏、标签校验
 * 不过）属确定性失败，直接向上传播，不在主线程重复解密。
 */
import type { PhotoMeta, SlimChunkSet } from "../types/crypto";
import { bytesToBase64, base64ToBytes, bytesToHex } from "../utils/binary_codec";
import { blake3 } from "@noble/hashes/blake3";
import { FILE_HASH_LEN } from "../constants/crypto_const";
import { createLogger } from "../utils/logger";
import { photoWorkerPool, TaskRejectedError } from "./photoWorkerPool";
import { openRecord } from "../lib/module_crypto";

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

/** 块解密任务的完整性权威值（缺省表示不校验：历史记录无权威值的兼容路径） */
export interface ChunkVerifyOptions {
  /** 逐块密文哈希（非空时在解密前逐块校验） */
  expectedHashes?: string[];
  /** 整图明文哈希（提供时对解密产物按序增量校验） */
  expectedFileHash?: string;
}

/** 解析元数据明文（JSON），失败按数据损坏处理 */
function parseMeta(plain: Uint8Array): PhotoMeta {
  try {
    return JSON.parse(new TextDecoder().decode(plain)) as PhotoMeta;
  } catch (e) {
    throw new Error(`解密后的元数据 JSON 解析失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** 校验块集结构：项数一致、ID 为正整数 */
function parseChunkSet(plain: Uint8Array): SlimChunkSet {
  let raw: SlimChunkSet;
  try {
    raw = JSON.parse(new TextDecoder().decode(plain)) as SlimChunkSet;
  } catch (e) {
    throw new Error(`块集 JSON 解析失败: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!raw || !Array.isArray(raw.ids) || !Array.isArray(raw.hashes)) {
    throw new Error("块集结构非法");
  }
  if (raw.ids.length === 0 || raw.ids.length !== raw.hashes.length) {
    throw new Error(`块集项数不一致（id=${raw.ids.length}，hash=${raw.hashes.length}）`);
  }
  for (const id of raw.ids) {
    if (!Number.isInteger(id) || id <= 0) {
      throw new Error(`块集包含非法记录 ID: ${id}`);
    }
  }
  return raw;
}

/** 主线程直连解密元数据 */
async function decryptMetaDirect(metaB64: string): Promise<PhotoMeta> {
  const opened = await openRecord("photo", "meta", metaB64);
  const plain = base64ToBytes(opened.dataB64);
  try {
    return parseMeta(plain);
  } finally {
    plain.fill(0);
  }
}

/** 主线程直连解密缩略图记录 */
async function decryptThumbDirect(
  thumbCipherB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
): Promise<Uint8Array> {
  const opened = await openRecord("photo", "thumb", thumbCipherB64, {
    wrappedKey: wrappedFileKey,
    fileHash: fileHashHex,
  });
  return base64ToBytes(opened.dataB64);
}

/** 主线程直连解密块集记录 */
async function decryptChunkSetDirect(
  setCipherB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
): Promise<SlimChunkSet> {
  const opened = await openRecord("photo", "chunkset", setCipherB64, {
    wrappedKey: wrappedFileKey,
    fileHash: fileHashHex,
  });
  const plain = base64ToBytes(opened.dataB64);
  try {
    return parseChunkSet(plain);
  } finally {
    plain.fill(0);
  }
}

/**
 * 解密照片元数据：优先 Worker 池，池基础设施失败时主线程直连同一命令。
 *
 * @param metaB64 加密的元数据 base64
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @param thumbCipherB64 索引瘦身布局的缩略图记录密文（可选）
 * @returns 元数据与（瘦身布局的）缩略图原始字节
 */
export async function decryptMetaPreferWorker(
  metaB64: string,
  label: string,
  thumbCipherB64?: string,
): Promise<MetaDecryptOutcome> {
  let meta: PhotoMeta;
  try {
    ({ meta } = await photoWorkerPool.submitDecryptMeta({ metaB64, label }));
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，主线程直连解密元数据（${label}）:`, e);
    meta = await decryptMetaDirect(metaB64);
  }
  if (!thumbCipherB64) return { meta };
  if (!meta.wrappedFileKey) {
    throw new Error("索引缺少包裹态文件密钥，无法解密缩略图记录");
  }
  const thumb = await decryptThumbPreferWorker(
    thumbCipherB64,
    meta.wrappedFileKey,
    meta.fileHash,
    `${label}:thumb`,
  );
  return { meta, thumbBytes: thumb.buffer.slice(thumb.byteOffset, thumb.byteOffset + thumb.byteLength) as ArrayBuffer };
}

/**
 * 解密索引瘦身布局的缩略图记录：优先 Worker 池，池基础设施失败时主线程直连。
 *
 * @param thumbCipherB64 缩略图记录载荷 base64（nonce ‖ 密文+tag）
 * @param wrappedFileKey 包裹态文件密钥（含文件盐）
 * @param fileHashHex 文件哈希 hex（缩略图 AD 绑定）
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @returns 缩略图原始字节
 */
export async function decryptThumbPreferWorker(
  thumbCipherB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
  label: string,
): Promise<Uint8Array> {
  try {
    const { thumbBytes } = await photoWorkerPool.submitDecryptThumb({
      thumbCipherB64,
      wrappedFileKey,
      fileHashHex,
      label,
    });
    return new Uint8Array(thumbBytes);
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，主线程直连解密缩略图（${label}）:`, e);
    return decryptThumbDirect(thumbCipherB64, wrappedFileKey, fileHashHex);
  }
}

/**
 * 解密索引瘦身布局的块集记录：优先 Worker 池，池基础设施失败时主线程直连。
 *
 * @param setCipherB64 块集记录载荷 base64（nonce ‖ 密文+tag）
 * @param wrappedFileKey 包裹态文件密钥（含文件盐）
 * @param fileHashHex 文件哈希 hex（块集 AD 绑定）
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @returns 块集内容（逐块记录 ID 与逐块密文哈希）
 */
export async function decryptChunkSetPreferWorker(
  setCipherB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
  label: string,
): Promise<SlimChunkSet> {
  try {
    const { set } = await photoWorkerPool.submitDecryptSlimSet({
      setCipherB64,
      wrappedFileKey,
      fileHashHex,
      label,
    });
    return set;
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，主线程直连解密块集（${label}）:`, e);
    return decryptChunkSetDirect(setCipherB64, wrappedFileKey, fileHashHex);
  }
}

/**
 * 解密照片数据块：优先 Worker 池，池基础设施失败时主线程直连。
 *
 * @param chunksB64 按序排列的块密文 base64 列表
 * @param fileHashHex 文件哈希 hex（块 AD 绑定）
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @param slim 索引瘦身布局参数（提供时按 nonce|密文 布局解密）
 * @param verify 完整性权威值：池路径随任务透传；直连路径在本函数内校验
 * @returns 按输入顺序的明文块（长度与输入一致）
 */
export async function decryptChunksPreferWorker(
  chunksB64: string[],
  fileHashHex: string,
  label: string,
  slim?: SlimChunkParams,
  verify?: ChunkVerifyOptions,
): Promise<Uint8Array[]> {
  let wrappedFileKey: string | undefined;
  if (slim) {
    if (!Number.isInteger(slim.chunkTotal) || slim.chunkTotal !== chunksB64.length) {
      throw new Error(`块总数与密文数量不一致（声明 ${slim.chunkTotal}，实得 ${chunksB64.length}）`);
    }
    wrappedFileKey = slim.wrappedFileKey;
  }
  try {
    const { plaintexts } = await photoWorkerPool.submitDecryptChunks({
      chunksB64,
      fileHashHex,
      label,
      wrappedFileKey,
      chunkTotal: slim?.chunkTotal,
      expectedHashes: verify?.expectedHashes,
      expectedFileHash: verify?.expectedFileHash,
    });
    // 转移回传的缓冲直接以视图消费：不再拷贝，避免 MB 级明文在主线程翻倍驻留
    return plaintexts.map((buf) => new Uint8Array(buf));
  } catch (e) {
    if (e instanceof TaskRejectedError) throw e;
    log.warn(`Worker 池不可用，主线程直连解密数据块（${label}）:`, e);
    return decryptChunksDirect(chunksB64, fileHashHex, wrappedFileKey, slim?.chunkTotal, verify);
  }
}

/**
 * 主线程逐块解密（池不可用时的直连实现）。
 *
 * 语义与 Worker 路径一致：任一块失败即整体失败；错误信息携带块序号；
 * 密文哈希在解密前比对，整图明文哈希在拼接前按序增量比对。
 */
async function decryptChunksDirect(
  chunksB64: string[],
  fileHashHex: string,
  wrappedFileKey?: string,
  chunkTotal?: number,
  verify?: ChunkVerifyOptions,
): Promise<Uint8Array[]> {
  if (chunksB64.length === 0) {
    throw new Error("待解密块列表为空");
  }
  if (wrappedFileKey !== undefined
    && (!Number.isInteger(chunkTotal) || chunkTotal !== chunksB64.length)) {
    throw new Error(`块总数与密文数量不一致（声明 ${chunkTotal}，实得 ${chunksB64.length}）`);
  }
  const expectedHashes = verify?.expectedHashes;
  if (expectedHashes && expectedHashes.length > 0 && expectedHashes.length !== chunksB64.length) {
    throw new Error(`哈希项数与块数不一致（哈希 ${expectedHashes.length}，块 ${chunksB64.length}）`);
  }

  const plaintexts: Uint8Array[] = [];
  const fileHasher = verify?.expectedFileHash
    ? blake3.create({ dkLen: FILE_HASH_LEN })
    : null;
  try {
    for (let c = 0; c < chunksB64.length; c++) {
      try {
        if (expectedHashes && expectedHashes.length > 0) {
          const actual = bytesToHex(
            blake3(base64ToBytes(chunksB64[c]), { dkLen: FILE_HASH_LEN }),
          );
          if (actual !== expectedHashes[c]) {
            throw new Error(`块密文哈希校验失败（第 ${c + 1}/${chunksB64.length} 块）`);
          }
        }
        const opened = wrappedFileKey !== undefined
          ? await openRecord("photo", "slim_chunk", chunksB64[c], {
              fileHash: fileHashHex,
              seq: c,
              total: chunksB64.length,
              wrappedKey: wrappedFileKey,
            })
          : await openRecord("photo", "chunk", chunksB64[c], { fileHash: fileHashHex });
        if (wrappedFileKey === undefined
          && (opened.seq !== c || opened.total !== chunksB64.length)) {
          throw new Error(
            `数据块顺序校验失败（seq=${opened.seq} total=${opened.total}，期望 ${c}/${chunksB64.length}）`,
          );
        }
        const plaintext = base64ToBytes(opened.dataB64);
        fileHasher?.update(plaintext);
        plaintexts.push(plaintext);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`第 ${c + 1}/${chunksB64.length} 块解密失败: ${msg}`);
      }
    }
    if (fileHasher && verify?.expectedFileHash) {
      const actualFileHash = bytesToHex(fileHasher.digest());
      if (actualFileHash !== verify.expectedFileHash) {
        throw new Error(
          `整图哈希校验失败（期望 ${verify.expectedFileHash}，实际 ${actualFileHash}）`,
        );
      }
    }
    return plaintexts;
  } catch (e) {
    for (const buf of plaintexts) buf.fill(0);
    throw e;
  }
}
