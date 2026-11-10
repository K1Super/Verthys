/**
 * file-verthys/damage.ts — 清藏损坏文件扫描（纯逻辑，依赖注入）
 *
 * 判定口径：
 *   - 只有“带独立访问密码”的文件才存在内容层信封（外层 MDEK + 内层文件口令）。
 *     扫描只验证外层：不需要用户提供每文件口令，外层认证失败即确定损坏；
 *   - 未设独立密码的文件不存在内层信封，数据只受记录层 AEAD 保护，
 *     记录可读即完整；扫描跳过并单独计数，绝不当作损坏；
 *   - 元数据损坏（`corrupt`）的条目本身已不可用，直接计入损坏；
 *   - 模块锁定、IPC 超时、载荷暂不可读等一律计入不可判定，绝不删除。
 */

import { base64ToBytes } from "../../utils/binary_codec";

/** 扫描所需的最小条目字段（来自清藏列表条目） */
export interface FileRepairEntry {
  /** 列表条目本地 ID */
  id: number;
  /** 展示名 */
  name: string;
  /** 元数据记录 ID */
  metaId?: number;
  /** 外置块记录 ID 列表（当前写入形态） */
  chunkIds?: number[];
  /** 历史内联块密文（仅元数据中携带；列表不驻留） */
  chunkDataB64?: string[];
  /** 是否设置了独立访问密码（存在内容层信封） */
  encrypted?: boolean;
  /** 文件级 KDF 参数（当前 v2 加密布局；历史布局可能缺失） */
  kdf?: unknown;
  /** 口令校验块（当前 v2 加密布局；历史布局可能缺失） */
  passwordCheck?: string;
  /** 元数据不可读（仅可删除） */
  corrupt?: boolean;
  /** 文件大小（用于限制内联形态的按需读取） */
  size?: number;
  /** 分块数（0 字节文件为 0） */
  totalChunks?: number;
}

/** 扫描依赖 */
export interface FileDamageDeps {
  /** 按记录 ID 读取载荷（base64）；记录不存在/读取失败返回 null */
  fetchRecord: (id: number) => Promise<string | null>;
  /** 只探测外层信封：true=完整，false=确定损坏，异常=不可判定 */
  probeOuter: (payloadB64: string) => Promise<boolean>;
}

export interface FileDamageScanResult {
  /** 参与检查的条目数（含损坏与跳过） */
  checked: number;
  /** 确定损坏（可删除）的条目 */
  damaged: FileRepairEntry[];
  /** 外层完整或无需探测（0 字节）的条目数 */
  healthy: number;
  /** 无内容层信封或历史内联过大而跳过探测的条目数 */
  skipped: number;
  /** 无法判定（读取失败/模块锁定/超时/结构无法解析）的条目数 */
  inconclusive: number;
}

/**
 * 历史内联布局按 meta 懒读取的体积上限。
 *
 * 超过该值不从元数据记录拉取整份块密文（IPC 预算与内存都不可接受），
 * 按“不可判定”跳过；当前写入形态（外置块引用）不受该限制影响。
 */
export const MAX_INLINE_SCAN_BYTES = 6 * 1024 * 1024;

type FirstChunk =
  | { kind: "payload"; b64: string }
  | { kind: "empty" }
  | { kind: "unknown" };

function parseMeta(payloadB64: string): Record<string, unknown> | null {
  try {
    const plain = new TextDecoder().decode(base64ToBytes(payloadB64));
    const parsed: unknown = JSON.parse(plain);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * 取第一条块密文用于外层探测。
 *
 * 优先级：列表内联 → 列表块引用 → 按 metaId 读取元数据（仅中小型内联布局）。
 */
async function firstChunkPayload(
  entry: FileRepairEntry,
  deps: FileDamageDeps,
): Promise<FirstChunk> {
  if (Array.isArray(entry.chunkDataB64) && entry.chunkDataB64.length > 0) {
    return { kind: "payload", b64: entry.chunkDataB64[0] };
  }
  if (Array.isArray(entry.chunkIds) && entry.chunkIds.length > 0) {
    const payload = await deps.fetchRecord(entry.chunkIds[0]);
    return payload ? { kind: "payload", b64: payload } : { kind: "unknown" };
  }
  if (!entry.metaId) return { kind: "unknown" };
  if ((entry.size ?? 0) > MAX_INLINE_SCAN_BYTES) return { kind: "unknown" };

  const metaPayload = await deps.fetchRecord(entry.metaId);
  const meta = metaPayload ? parseMeta(metaPayload) : null;
  if (!meta) return { kind: "unknown" };

  if (Array.isArray(meta.chunkDataB64) && meta.chunkDataB64.length > 0) {
    return { kind: "payload", b64: String(meta.chunkDataB64[0]) };
  }
  if (Array.isArray(meta.chunkIds) && meta.chunkIds.length > 0) {
    const first = meta.chunkIds[0];
    if (typeof first !== "number" || first <= 0) return { kind: "unknown" };
    const payload = await deps.fetchRecord(first);
    return payload ? { kind: "payload", b64: payload } : { kind: "unknown" };
  }
  return { kind: "empty" };
}

/**
 * 扫描清藏文件，返回确定损坏的条目。
 *
 * 串行执行：每个文件最多一次记录读取 + 一次外层探测，不会同时拉起
 * 大量 IPC；条目数量级由用户文件数决定，扫描期间有进度对话框承接。
 */
export async function scanDamagedFiles(
  entries: FileRepairEntry[],
  deps: FileDamageDeps,
): Promise<FileDamageScanResult> {
  const damaged: FileRepairEntry[] = [];
  let healthy = 0;
  let skipped = 0;
  let inconclusive = 0;

  for (const entry of entries) {
    // 元数据损坏：条目本身已不可用，无需再探测内容
    if (entry.corrupt) {
      damaged.push(entry);
      continue;
    }
    /* 只有当前 v2 加密布局（独立密码 + KDF + 口令校验块）才保证分块是
     * 标准内容层信封。无密码文件与历史布局可能是明文/其他封装，探测会把
     * “结构不符”误判为损坏，因此一律跳过。 */
    const hasV2Envelope =
      entry.encrypted === true
      && entry.kdf !== undefined
      && entry.kdf !== null
      && typeof entry.passwordCheck === "string"
      && entry.passwordCheck.length > 0;
    if (!hasV2Envelope) {
      skipped += 1;
      continue;
    }
    // 0 字节文件没有块记录，不存在可损坏的内容
    if (entry.totalChunks === 0) {
      healthy += 1;
      continue;
    }

    let first: FirstChunk;
    try {
      first = await firstChunkPayload(entry, deps);
    } catch {
      inconclusive += 1;
      continue;
    }
    if (first.kind === "empty") {
      healthy += 1;
      continue;
    }
    if (first.kind === "unknown") {
      inconclusive += 1;
      continue;
    }

    try {
      const intact = await deps.probeOuter(first.b64);
      if (intact) healthy += 1;
      else damaged.push(entry);
    } catch {
      // 模块锁定 / 超时 / 策略拒绝：不可判定，不进入删除范围
      inconclusive += 1;
    }
  }

  return {
    checked: entries.length,
    damaged,
    healthy,
    skipped,
    inconclusive,
  };
}
