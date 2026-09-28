/**
 * file-verthys/useFileExport.ts — 清藏导出管道
 *
 * 职责：把一条文件条目的分块记录还原为本地文件，保证"要么产出完整文件、
 * 要么不产出文件"，且内存占用与文件大小无关。
 *
 * 设计要点：
 * - 单遍流式：逐块取回 → 结构校验 →（可选）解密 → 追加写入 → 累计长度，
 *   全程只驻留单块明文与其 base64 中间量；
 * - 完整性前置：块数、逐块长度、累计长度三项与声明值一致，任一不符即失败；
 * - 失败可收敛：任一步失败即中止流式写入并删除暂存，目标位置不产生文件；
 * - 密码前置：当前加密形态以 passwordCheck 为唯一判定点（选路径之前完成）；
 *   历史逐块盐形态无判定点，改以首个数据块的前置解密暴露口令错误；
 * - 职责唯一：块解密失败一律按数据损坏处理，不再据"全部块失败"推断口令错误；
 * - 依赖注入：取记录、解密、选路径、流式写入均由调用方提供，便于单元测试。
 */
import { MAX_FILE_CHUNK_SIZE_BYTES } from "../../constants/photo_budget.generated";
import { base64ToBytes } from "../../lib/verthys";
import type { FileKdfV2 } from "../../lib/crypto";
import { createBLAKE3 } from "hash-wasm";

/** 导出失败原因分类（调用方据此决定文案与后续动作） */
export type FileExportErrorCode =
  | "E_LAYOUT_INVALID"
  | "E_CHUNK_MISSING"
  | "E_CHUNK_CORRUPTED"
  | "E_PWD_WRONG"
  | "E_PWD_OR_CORRUPT"
  | "E_DISK_FULL"
  | "E_READ_FAILED"
  | "E_STREAM_FAILED"
  | "CANCELLED";

/** v1（无口令判定点）解密失败的合并文案：区分不了口令错误与数据损坏，
    按方案口径给出可执行引导（先核对口令，确认无误则按损坏处置）。 */
const V1_PWD_OR_CORRUPT_MESSAGE =
  "密码错误或数据已损坏：请先核对密码；若密码确认无误，则文件数据可能已损坏，建议从备份恢复或联系支持";

/** 导出输入：从列表条目与 meta 记录收敛出的最小字段集 */
export interface ExportSourceEntry {
  /** 展示名（同时作为保存对话框默认文件名） */
  name: string;
  /** 明文长度（字节），导出结果的长度权威值 */
  size: number;
  /** 分块总数（meta 声明值） */
  totalChunks: number;
  /** 是否设置了独立访问密码 */
  encrypted: boolean;
  /** 外置块记录 ID 列表（当前写入形态） */
  chunkIds?: number[];
  /** 历史内联块密文（旧形态，读取兼容） */
  chunkDataB64?: string[];
  /** 分块口径（meta 声明值；缺省表示历史记录未携带） */
  chunkSize?: number;
  /** 逐块密文哈希（写入侧生成的完整性权威值；历史记录缺省） */
  chunkHashes?: string[];
  /** 文件级密钥派生参数（当前加密形态必携；历史逐块盐形态缺省） */
  kdf?: FileKdfV2;
  /** 密码校验块（口令判定的唯一权威值；历史逐块盐形态缺省） */
  passwordCheck?: string;
}

/** v2 块解密会话（文件级密钥已解锁；口令已在前置阶段判定通过） */
export interface FileDecryptSession {
  /** 解密单块密文（base64 入参，返回原始明文） */
  decryptChunk: (b64: string) => Promise<Uint8Array>;
}

/** 导出依赖集合（生产实现见模块装配处；测试以桩替换） */
export interface FileExportDeps {
  /** 按记录 ID 取回块密文（base64）；记录不存在返回 null */
  getRecord: (id: number) => Promise<{ dataB64: string } | null>;
  /** 解锁 v2 文件密钥并校验口令；口令不匹配返回 null（选路径之前完成） */
  openV2Decryptor?: (
    entry: ExportSourceEntry,
    password: string,
  ) => Promise<FileDecryptSession | null>;
  /** v1 逐块解密（历史逐块盐形态：base64 入参、base64 返回） */
  decryptField: (b64: string, password: string) => Promise<string>;
  /** 选取保存位置；用户取消返回 null */
  pickSavePath: (defaultName: string) => Promise<string | null>;
  /** 查询目标路径所在卷的可用空间（字节；导出前预检用） */
  freeSpaceBytes: (path: string) => Promise<number>;
  /** 打开流式写入会话，返回会话标识 */
  streamOpen: (path: string) => Promise<string>;
  /** 追加一块原始字节 */
  streamAppend: (streamId: string, data: Uint8Array) => Promise<void>;
  /** 终结会话（后端同步落盘并原子替换目标文件） */
  streamFinalize: (streamId: string) => Promise<void>;
  /** 中止会话（删除暂存；幂等） */
  streamAbort: (streamId: string) => Promise<void>;
}

export interface FileExportSuccess {
  ok: true;
  /** 实际写出字节数 */
  bytes: number;
}

export interface FileExportFailure {
  ok: false;
  code: FileExportErrorCode;
  /** 面向用户的说明（已含必要的定位信息，如缺失块序号） */
  message: string;
}

export type FileExportResult = FileExportSuccess | FileExportFailure;

type ChunkLayout =
  | { kind: "inline"; chunks: string[]; count: number }
  | { kind: "external"; ids: number[]; count: number }
  | { kind: "empty"; count: 0 };

/**
 * 解析块布局并完成与声明值的一致性校验。
 *
 * 校验口径（任一不符即拒绝导出，避免产出错位文件）：
 *   - 块数 == 分块总数，且 == 由声明长度推出的应有块数 ceil(size / 分块口径)；
 *   - 空文件与零块严格对应；
 *   - 分块口径被 meta 声明时必须与当前常量一致（历史记录缺省不校验）。
 */
function resolveLayout(
  entry: ExportSourceEntry,
): { ok: true; layout: ChunkLayout } | FileExportFailure {
  const expectedCount = entry.size === 0 ? 0 : Math.ceil(entry.size / MAX_FILE_CHUNK_SIZE_BYTES);

  // 逐块哈希为写入侧权威值：一旦携带，块数必须严格对齐（防错位校验）
  if (entry.chunkHashes && entry.chunkHashes.length !== expectedCount) {
    return {
      ok: false,
      code: "E_LAYOUT_INVALID",
      message: "文件分块校验信息与元数据不一致，无法导出",
    };
  }

  const inline = entry.chunkDataB64;
  if (inline && inline.length > 0) {
    if (inline.length !== expectedCount) {
      return {
        ok: false,
        code: "E_LAYOUT_INVALID",
        message: "文件分块数量与长度不一致，无法导出",
      };
    }
    return { ok: true, layout: { kind: "inline", chunks: inline, count: inline.length } };
  }

  const ids = entry.chunkIds;
  if (!Array.isArray(ids)) {
    return {
      ok: false,
      code: "E_LAYOUT_INVALID",
      message: "文件元数据不完整，无法导出",
    };
  }

  if (entry.chunkSize !== undefined && entry.chunkSize !== MAX_FILE_CHUNK_SIZE_BYTES) {
    return {
      ok: false,
      code: "E_LAYOUT_INVALID",
      message: "文件分块口径与当前版本不一致，无法导出",
    };
  }

  if (ids.length === 0) {
    if (entry.size !== 0) {
      return {
        ok: false,
        code: "E_LAYOUT_INVALID",
        message: "文件元数据不完整，无法导出",
      };
    }
    return { ok: true, layout: { kind: "empty", count: 0 } };
  }

  if (ids.length !== entry.totalChunks || ids.length !== expectedCount) {
    return {
      ok: false,
      code: "E_LAYOUT_INVALID",
      message: "文件分块数量与元数据不一致，无法导出",
    };
  }

  return { ok: true, layout: { kind: "external", ids, count: ids.length } };
}

/** 体量读数（GB 口径，整数省略小数）：空间不足提示与上限展示共用 */
function formatGigabytes(bytes: number): string {
  const gb = bytes / (1024 * 1024 * 1024);
  return Number.isInteger(gb) ? String(gb) : gb.toFixed(1);
}

/** 计算第 i 块的期望明文长度：除尾块外恒为分块口径 */
function expectedChunkLength(entry: ExportSourceEntry, index: number): number {
  const remaining = entry.size - index * MAX_FILE_CHUNK_SIZE_BYTES;
  return Math.min(remaining, MAX_FILE_CHUNK_SIZE_BYTES);
}

/**
 * 执行导出。
 *
 * @param entry 列表条目（含块引用与声明长度）
 * @param password 独立访问密码；未加密条目传 null
 * @param deps 依赖集合
 * @returns 成功（含写出字节数）/ 失败（含分类与文案）/ 用户取消
 */
export async function runFileExport(
  entry: ExportSourceEntry,
  password: string | null,
  deps: FileExportDeps,
): Promise<FileExportResult> {
  const resolved = resolveLayout(entry);
  if (!resolved.ok) return resolved;
  const layout = resolved.layout;

  const fetchChunkB64 = async (index: number): Promise<string | null> => {
    if (layout.kind === "inline") return layout.chunks[index] ?? null;
    if (layout.kind === "external") {
      const record = await deps.getRecord(layout.ids[index]);
      return record ? record.dataB64 : null;
    }
    return null;
  };

  // 逐块密文哈希校验：写入侧生成的完整性权威值，缺失（历史记录）时跳过
  const expectedHashes =
    entry.chunkHashes && entry.chunkHashes.length > 0 ? entry.chunkHashes : null;
  const verifier = expectedHashes ? await createBLAKE3() : null;
  const hashMismatch = (b64: string, index: number): boolean => {
    if (!verifier || !expectedHashes) return false;
    verifier.init();
    verifier.update(base64ToBytes(b64));
    return verifier.digest("hex") !== expectedHashes[index];
  };

  // 口令前置（唯一判定点）：最小 v2 条目（携 kdf + passwordCheck）在选取
  // 保存位置之前完成解锁与校验，错误口令不消耗用户选择路径的操作。
  let session: FileDecryptSession | null = null;
  if (entry.encrypted) {
    if (!password) {
      return { ok: false, code: "E_PWD_OR_CORRUPT", message: "需要文件访问密码" };
    }
    if (entry.passwordCheck && entry.kdf) {
      if (!deps.openV2Decryptor) {
        // 装配缺失属内部错误：不得退化为"密码错误"误导用户
        return { ok: false, code: "E_LAYOUT_INVALID", message: "文件加密形态与当前版本不符，无法导出" };
      }
      try {
        session = await deps.openV2Decryptor(entry, password);
      } catch {
        session = null;
      }
      if (!session) {
        return { ok: false, code: "E_PWD_WRONG", message: "密码错误" };
      }
    }
  }

  // 首个数据块先行取回并解密：历史逐块盐形态（无口令判定点）的口令错误
  // 在选取保存位置之前暴露，该块明文随后直接参与写出，不产生二次读取
  let firstChunkPlain: Uint8Array | null = null;
  if (layout.count > 0 && entry.encrypted && !session) {
    let headB64: string | null;
    try {
      headB64 = await fetchChunkB64(0);
    } catch {
      return { ok: false, code: "E_READ_FAILED", message: "读取文件数据失败，请重试" };
    }
    if (headB64 === null) {
      return { ok: false, code: "E_CHUNK_MISSING", message: "第 1 块数据缺失，文件可能已损坏" };
    }
    if (hashMismatch(headB64, 0)) {
      return { ok: false, code: "E_CHUNK_CORRUPTED", message: "第 1 块数据校验失败，文件可能已损坏" };
    }
    try {
      firstChunkPlain = base64ToBytes(await deps.decryptField(headB64, password!));
    } catch {
      return { ok: false, code: "E_PWD_OR_CORRUPT", message: V1_PWD_OR_CORRUPT_MESSAGE };
    }
    if (firstChunkPlain.length !== expectedChunkLength(entry, 0)) {
      return {
        ok: false,
        code: "E_CHUNK_CORRUPTED",
        message: "第 1 块数据校验失败，文件可能已损坏",
      };
    }
  }

  // 选取保存位置：对话框本身失败按保存流程失败处理，取消则静默返回
  let savePath: string | null;
  try {
    savePath = await deps.pickSavePath(entry.name);
  } catch {
    return { ok: false, code: "E_STREAM_FAILED", message: "保存失败，请重试" };
  }
  if (savePath === null) {
    return { ok: false, code: "CANCELLED", message: "" };
  }

  // 目标卷空间预检：不足即在开流之前拒绝（不产生暂存文件）。
  // 读数不可得时不阻断（写入阶段失败仍会在终结前中止并清理暂存）。
  if (entry.size > 0) {
    let free: number | null = null;
    try {
      free = await deps.freeSpaceBytes(savePath);
    } catch {
      free = null;
    }
    if (free !== null && free < entry.size) {
      return {
        ok: false,
        code: "E_DISK_FULL",
        message: `目标磁盘空间不足：需要约 ${formatGigabytes(entry.size)} GB，可用 ${formatGigabytes(free)} GB`,
      };
    }
  }

  let streamId: string | null = null;
  try {
    streamId = await deps.streamOpen(savePath);

    let offset = 0;
    for (let index = 0; index < layout.count; index++) {
      let plain: Uint8Array;
      if (index === 0 && firstChunkPlain) {
        plain = firstChunkPlain;
        firstChunkPlain = null;
      } else {
        let chunkB64: string | null;
        try {
          chunkB64 = await fetchChunkB64(index);
        } catch {
          await safeAbort(deps, streamId);
          return { ok: false, code: "E_READ_FAILED", message: "读取文件数据失败，请重试" };
        }
        if (chunkB64 === null) {
          await safeAbort(deps, streamId);
          return {
            ok: false,
            code: "E_CHUNK_MISSING",
            message: `第 ${index + 1} 块数据缺失，文件可能已损坏`,
          };
        }
        if (hashMismatch(chunkB64, index)) {
          await safeAbort(deps, streamId);
          return {
            ok: false,
            code: "E_CHUNK_CORRUPTED",
            message: `第 ${index + 1} 块数据校验失败，文件可能已损坏`,
          };
        }
        if (entry.encrypted) {
          if (session) {
            // v2：口令已前置判定通过，此处解密失败一律按数据损坏处理
            try {
              plain = await session.decryptChunk(chunkB64);
            } catch {
              await safeAbort(deps, streamId);
              return {
                ok: false,
                code: "E_CHUNK_CORRUPTED",
                message: `第 ${index + 1} 块数据校验失败，文件可能已损坏`,
              };
            }
          } else {
            // v1（历史逐块盐）：无判定点，解密失败返回合并文案
            try {
              plain = base64ToBytes(await deps.decryptField(chunkB64, password!));
            } catch {
              await safeAbort(deps, streamId);
              return { ok: false, code: "E_PWD_OR_CORRUPT", message: V1_PWD_OR_CORRUPT_MESSAGE };
            }
          }
        } else {
          plain = base64ToBytes(chunkB64);
        }
      }

      const expected = expectedChunkLength(entry, index);
      if (plain.length !== expected) {
        await safeAbort(deps, streamId);
        return {
          ok: false,
          code: "E_CHUNK_CORRUPTED",
          message: `第 ${index + 1} 块数据校验失败，文件可能已损坏`,
        };
      }
      await deps.streamAppend(streamId, plain);
      offset += plain.length;
    }

    // 逐块长度校验已蕴含"累计长度 == 声明长度"（期望长度总和恒等于 size），
    // 这里只累计实际写出字节数用于结果回报
    await deps.streamFinalize(streamId);
    return { ok: true, bytes: offset };
  } catch {
    if (streamId !== null) {
      await safeAbort(deps, streamId);
    }
    return { ok: false, code: "E_STREAM_FAILED", message: "保存失败，请重试" };
  }
}

/** 中止流式会话；中止本身失败不改变主流程结论（暂存由后端按龄清理兜底） */
async function safeAbort(deps: FileExportDeps, streamId: string): Promise<void> {
  try {
    await deps.streamAbort(streamId);
  } catch {
    /* 中止失败不掩盖主流程失败原因 */
  }
}