/**
 * photo-album/chunk-refs.ts — 照片逐块引用的布局分流解析（单一实现点）
 *
 * 职责：把"照片元数据 → 逐块记录 ID 与逐块密文哈希"的三种承载形态收敛到
 * 一处解析——索引瘦身布局的独立块集记录、早期布局二的内联引用、既有布局的
 * 旧格式引用。查看原图、导出、删除级联三条路径共用本模块，避免各自实现
 * 造成分流口径不一致。
 *
 * 依赖方向：本模块只依赖缓存取数、解密桥与加密层常量，不持有状态，可被任意
 * composable 调用；Worker 池不可用时由解密桥自动回退主线程。
 */
import { getRecordsDataB64Batch } from "../../lib/keyManager";
import { isSlimLayout } from "../../constants/crypto_const";
import type { PhotoMeta, SlimChunkSet } from "../../lib/crypto";
import { decryptChunkSetPreferWorker } from "../../workers/photo-decrypt-bridge";

/**
 * 解析照片的块集（索引瘦身布局专用）。
 *
 * @param meta 已解密的照片元数据
 * @param photoKey 照片模块独立密钥
 * @param label 定位标识（记录 ID 或照片名，用于日志与错误提示）
 * @returns 块集内容；非瘦身布局或未携带块集引用时返回 null（调用方回落内联引用）
 * @throws Error 块集记录缺失、解密失败或与索引声明项数不一致
 */
export async function resolveChunkSet(
  meta: PhotoMeta,
  photoKey: string,
  label: string,
): Promise<SlimChunkSet | null> {
  if (!isSlimLayout(meta) || !meta.wrappedFileKey || !meta.chunkSetId) {
    return null;
  }
  // 块集属小记录（≤ 扫描缓存管控阈值）：命中扫描缓存时零 IPC
  const map = await getRecordsDataB64Batch([meta.chunkSetId]);
  const cipherB64 = map.get(meta.chunkSetId) ?? "";
  if (!cipherB64) {
    throw new Error(`块集记录缺失（id=${meta.chunkSetId}）`);
  }
  const set = await decryptChunkSetPreferWorker(
    cipherB64, photoKey, meta.wrappedFileKey, meta.fileHash, label,
  );
  if (typeof meta.chunkCount === "number" && meta.chunkCount !== set.ids.length) {
    throw new Error(
      `块集项数与索引声明不一致（块集 ${set.ids.length} ≠ 索引 ${meta.chunkCount}）`,
    );
  }
  return set;
}

/** 逐块引用的三种承载形态（按优先级解析结果） */
export interface ChunkRefs {
  /** 逐块记录 ID（需按序取记录；内联密文形态为空数组） */
  ids: number[];
  /** 逐块密文哈希（完整性校验权威值；缺失时为空数组，由调用方现场补算） */
  hashes: string[];
  /** 内联逐块密文 base64（非空时无需按 ID 取记录） */
  inlineCipher: string[];
}

/**
 * 解析照片的逐块引用（三条读取路径共用的分流口径）。
 *
 * 优先级：块集记录（瘦身布局）→ 索引内联 chunkIds + chunkHashes（早期布局二 /
 * 既有布局）→ 索引内联 chunkDataB64（更早的内联形态）。
 *
 * @throws Error 块集缺失/解密失败（瘦身布局的数据不完整，调用方按损坏提示）
 */
export async function resolveChunkRefs(
  meta: PhotoMeta,
  photoKey: string,
  label: string,
): Promise<ChunkRefs> {
  const set = await resolveChunkSet(meta, photoKey, label);
  if (set) {
    return { ids: set.ids, hashes: set.hashes, inlineCipher: [] };
  }
  if (meta.chunkDataB64 && meta.chunkDataB64.length > 0) {
    return { ids: [], hashes: meta.chunkHashes ?? [], inlineCipher: [...meta.chunkDataB64] };
  }
  return {
    ids: meta.chunkIds ?? [],
    hashes: meta.chunkHashes ?? [],
    inlineCipher: [],
  };
}

/**
 * 按逐块引用取出密文并按序返回（内联形态直接返回；外置形态经扫描缓存优先取数）。
 *
 * @returns 密文列表与缺失块数（缺失即数据不完整，调用方拒绝渲染）
 */
export async function loadChunkCiphers(
  refs: ChunkRefs,
): Promise<{ ciphers: string[]; missing: number }> {
  if (refs.inlineCipher.length > 0) {
    return { ciphers: [...refs.inlineCipher], missing: 0 };
  }
  if (refs.ids.length === 0) {
    return { ciphers: [], missing: 0 };
  }
  const map = await getRecordsDataB64Batch(refs.ids);
  const ciphers: string[] = [];
  let missing = 0;
  for (const id of refs.ids) {
    const c = map.get(id);
    if (!c) {
      missing++;
      continue;
    }
    ciphers.push(c);
  }
  return { ciphers, missing };
}