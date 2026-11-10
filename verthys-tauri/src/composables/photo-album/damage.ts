/**
 * photo-album/damage.ts — 损坏记录判定（纯函数）
 *
 * 损坏清理只允许删除“确定无法解密”的记录：内容层认证失败
 * （ERR_00000002）才算确定损坏。模块锁定、IPC 超时、记录暂不可读等
 * 一律视为不可判定，绝不把暂态故障当成损坏删除。
 *
 * 历史明文布局（记录载荷本身就是 JSON，而非分片信封）在内容层同样会
 * 返回认证失败，但它可能仍被旧版本按明文读取，因此也不计入损坏。
 */
import { base64ToBytes } from "../../utils/binary_codec";
import { MODULE_ERR_AUTH } from "../../lib/module_crypto";

/** 记录载荷是否为历史明文 JSON 布局（首个非空白字节为 '{' 且可解析） */
export function looksLikeLegacyPlainJson(payloadB64: string): boolean {
  try {
    const bytes = base64ToBytes(payloadB64);
    let i = 0;
    while (
      i < bytes.length
      && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d)
    ) {
      i += 1;
    }
    if (i >= bytes.length || bytes[i] !== 0x7b) return false;
    JSON.parse(new TextDecoder().decode(bytes));
    return true;
  } catch {
    return false;
  }
}

/** 是否为内容层认证失败（模块密钥不匹配 / 密文被篡改） */
function isModuleCryptoAuthError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { name?: unknown; code?: unknown };
  return candidate.name === "ModuleCryptoError" && candidate.code === MODULE_ERR_AUTH;
}

/** 错误是否构成“确定损坏”：仅内容层认证失败，且载荷不是历史明文布局 */
export function isDefinitelyDamaged(error: unknown, payloadB64: string): boolean {
  return isModuleCryptoAuthError(error) && !looksLikeLegacyPlainJson(payloadB64);
}

/** 损坏扫描结果 */
export interface DamageScanResult {
  /** 参与检查的记录数 */
  checked: number;
  /** 确定损坏（可删除）的记录 ID */
  damaged: number[];
  /** 无法判定（读取失败/模块锁定/超时/历史明文）的记录数，绝不删除 */
  inconclusive: number;
}

/**
 * 扫描给定 metaId 列表，判定哪些记录确定损坏。
 *
 * 依赖注入（批量取数与单条解封）使该逻辑可脱离 Tauri/Worker 单测；
 * 判定口径与 `isDefinitelyDamaged` 完全一致：只有 AUTH 失败且非历史
 * 明文 JSON 才计入 `damaged`，其余一律计入 `inconclusive`。
 */
export async function scanDamagedMetaIds(
  ids: number[],
  fetchBatch: (ids: number[]) => Promise<Map<number, string>>,
  openMeta: (payloadB64: string) => Promise<unknown>,
  options: { batchSize?: number; concurrency?: number } = {},
): Promise<DamageScanResult> {
  const batchSize = options.batchSize ?? 24;
  const concurrency = options.concurrency ?? 4;
  const damaged: number[] = [];
  let inconclusive = 0;

  for (let offset = 0; offset < ids.length; offset += batchSize) {
    const batch = ids.slice(offset, offset + batchSize);
    let payloads: Map<number, string>;
    try {
      payloads = await fetchBatch(batch);
    } catch {
      // 整批读取失败：无法判定，不得删除
      inconclusive += batch.length;
      continue;
    }

    let cursor = 0;
    const run = async (): Promise<void> => {
      while (cursor < batch.length) {
        const id = batch[cursor++];
        const payload = payloads.get(id);
        if (!payload) {
          inconclusive += 1;
          continue;
        }
        try {
          await openMeta(payload);
        } catch (e) {
          if (isDefinitelyDamaged(e, payload)) damaged.push(id);
          else inconclusive += 1;
        }
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(concurrency, batch.length) }, run),
    );
  }

  return { checked: ids.length, damaged, inconclusive };
}
