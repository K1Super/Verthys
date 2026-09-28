/**
 * useFileExport 单测 — 导出管道完整性矩阵
 *
 * 覆盖：正常多块还原、缺块、块长度不符、布局不一致（块数/长度/分块口径）、
 * 加密条目密码错误与正确路径、零字节文件、历史内联形态、用户取消、
 * 流式终结失败。断言口径：成功必 finalize 且无 abort；失败必 abort 且不 finalize；
 * 布局校验失败不得打开流。
 */
import { describe, expect, it } from "vitest";
import { createBLAKE3 } from "hash-wasm";
import { MAX_FILE_CHUNK_SIZE_BYTES } from "../../constants/photo_budget.generated";
import { base64ToBytes, bytesToBase64 } from "../../lib/verthys";
import {
  runFileExport,
  type ExportSourceEntry,
  type FileDecryptSession,
  type FileExportDeps,
} from "./useFileExport";

const CHUNK = MAX_FILE_CHUNK_SIZE_BYTES;

/** v1 合并文案（与实现同源断言的用户可见引导口径） */
const V1_MERGED_MESSAGE =
  "密码错误或数据已损坏：请先核对密码；若密码确认无误，则文件数据可能已损坏，建议从备份恢复或联系支持";

async function blake3Hex(bytes: Uint8Array): Promise<string> {
  const h = await createBLAKE3();
  h.init();
  h.update(bytes);
  return h.digest("hex");
}

interface HarnessOptions {
  records?: Map<number, string>;
  decrypt?: (b64: string, pwd: string) => Promise<string>;
  savePath?: string | null;
  finalizeFails?: boolean;
  /** v2 解密会话（undefined = 未装配该依赖；null = 口令不匹配） */
  v2Session?: FileDecryptSession | null;
  /** v2 装配标志：true 时注入 openV2Decryptor */
  withV2?: boolean;
  /** 会话解密注入失败 */
  v2DecryptThrows?: boolean;
  /** 目标卷可用空间注入（缺省=充裕；null=读数不可得） */
  freeSpace?: number | null;
}

function makeHarness(opts: HarnessOptions = {}) {
  const appended: Uint8Array[] = [];
  const aborted: string[] = [];
  const finalized: string[] = [];
  const opened: string[] = [];
  const picked: string[] = [];
  const stats = { decrypt: 0, v2Open: 0 };

  const deps: FileExportDeps = {
    getRecord: async (id) => {
      const value = opts.records?.get(id);
      return value === undefined ? null : { dataB64: value };
    },
    ...(opts.withV2
      ? {
          openV2Decryptor: async () => {
            stats.v2Open += 1;
            if (opts.v2Session === null) return null;
            const session: FileDecryptSession = {
              decryptChunk: async (b64) => {
                if (opts.v2DecryptThrows) throw new Error("注入的块解密失败");
                return base64ToBytes(b64);
              },
            };
            return opts.v2Session ?? session;
          },
        }
      : {}),
    decryptField: async (b64, pwd) => {
      stats.decrypt += 1;
      if (opts.decrypt) return opts.decrypt(b64, pwd);
      return b64;
    },
    pickSavePath: async (name) => {
      picked.push(name);
      return opts.savePath === undefined ? "C:\\out\\file.bin" : opts.savePath;
    },
    freeSpaceBytes: async () => {
      if (opts.freeSpace === null) throw new Error("空间读数不可得");
      return opts.freeSpace ?? Number.MAX_SAFE_INTEGER;
    },
    streamOpen: async (path) => {
      opened.push(path);
      return "stream-1";
    },
    streamAppend: async (_sid, data) => {
      appended.push(data);
    },
    streamFinalize: async (sid) => {
      if (opts.finalizeFails) throw new Error("finalize 注入失败");
      finalized.push(sid);
    },
    streamAbort: async (sid) => {
      aborted.push(sid);
    },
  };

  return { deps, appended, aborted, finalized, opened, picked, stats };
}

function chunkBuffer(fill: number, len: number): Uint8Array {
  const buf = new Uint8Array(len);
  buf.fill(fill);
  return buf;
}

function entryOf(size: number, ids: number[]): ExportSourceEntry {
  return {
    name: "a.bin",
    size,
    totalChunks: ids.length,
    encrypted: false,
    chunkIds: ids,
    chunkSize: CHUNK,
  };
}

/** 当前加密形态条目（携文件级派生参数与口令校验块） */
function entryV2(size: number, ids: number[]): ExportSourceEntry {
  return {
    ...entryOf(size, ids),
    encrypted: true,
    kdf: { version: 2, saltB64: bytesToBase64(new Uint8Array(16).fill(1)), iterations: 150000 },
    passwordCheck: bytesToBase64(new Uint8Array(44).fill(2)),
  };
}

describe("runFileExport", () => {
  it("外置三块导出：块序与长度完全还原，末尾一次 finalize", async () => {
    const size = CHUNK * 2 + 10;
    const records = new Map<number, string>([
      [10, bytesToBase64(chunkBuffer(1, CHUNK))],
      [11, bytesToBase64(chunkBuffer(2, CHUNK))],
      [12, bytesToBase64(chunkBuffer(9, 10))],
    ]);
    const h = makeHarness({ records });

    const result = await runFileExport(entryOf(size, [10, 11, 12]), null, h.deps);

    expect(result).toEqual({ ok: true, bytes: size });
    expect(h.appended.map((b) => b.length)).toEqual([CHUNK, CHUNK, 10]);
    expect(h.appended[0][0]).toBe(1);
    expect(h.appended[2][0]).toBe(9);
    expect(h.finalized).toEqual(["stream-1"]);
    expect(h.aborted).toEqual([]);
    expect(h.picked).toEqual(["a.bin"]);
  });

  it("缺块：定位到第 N 块并中止流，不 finalize", async () => {
    const size = CHUNK * 2;
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, CHUNK))]]);
    const h = makeHarness({ records });

    const result = await runFileExport(entryOf(size, [10, 11]), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_CHUNK_MISSING");
      expect(result.message).toContain("第 2 块");
    }
    expect(h.aborted).toEqual(["stream-1"]);
    expect(h.finalized).toEqual([]);
  });

  it("块长度与声明不符：按损坏处理并中止流", async () => {
    const size = CHUNK + 10;
    const records = new Map<number, string>([
      [10, bytesToBase64(chunkBuffer(1, CHUNK))],
      [11, bytesToBase64(chunkBuffer(2, 5))],
    ]);
    const h = makeHarness({ records });

    const result = await runFileExport(entryOf(size, [10, 11]), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_CHUNK_CORRUPTED");
      expect(result.message).toContain("第 2 块");
    }
    expect(h.aborted).toEqual(["stream-1"]);
    expect(h.finalized).toEqual([]);
  });

  it("块哈希与元数据不符：按损坏处理并中止流", async () => {
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, CHUNK))]]);
    const h = makeHarness({ records });
    const entry = { ...entryOf(CHUNK, [10]), chunkHashes: ["00".repeat(32)] };

    const result = await runFileExport(entry, null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_CHUNK_CORRUPTED");
      expect(result.message).toContain("第 1 块");
    }
    expect(h.aborted).toEqual(["stream-1"]);
    expect(h.finalized).toEqual([]);
  });

  it("块哈希逐块一致：校验通过并正常导出", async () => {
    const plain = chunkBuffer(1, CHUNK);
    const records = new Map<number, string>([[10, bytesToBase64(plain)]]);
    const h = makeHarness({ records });
    const entry = { ...entryOf(CHUNK, [10]), chunkHashes: [await blake3Hex(plain)] };

    const result = await runFileExport(entry, null, h.deps);

    expect(result).toEqual({ ok: true, bytes: CHUNK });
    expect(h.finalized).toEqual(["stream-1"]);
  });

  it("哈希条数与块数不一致：布局校验失败且不打开流", async () => {
    const h = makeHarness();
    const entry = { ...entryOf(CHUNK, [10]), chunkHashes: [] };

    const result = await runFileExport(entry, null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_LAYOUT_INVALID");
    expect(h.opened).toEqual([]);
    expect(h.picked).toEqual([]);
  });

  it("块数与声明总数不一致：布局校验失败且不打开流", async () => {
    const entry = { ...entryOf(CHUNK * 2, [10, 11]), totalChunks: 3 };
    const h = makeHarness();

    const result = await runFileExport(entry, null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_LAYOUT_INVALID");
    expect(h.opened).toEqual([]);
    expect(h.picked).toEqual([]);
  });

  it("块数与文件长度不一致：布局校验失败", async () => {
    const entry = entryOf(CHUNK + 1, [10, 11, 12]);
    const h = makeHarness();

    const result = await runFileExport(entry, null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_LAYOUT_INVALID");
    expect(h.opened).toEqual([]);
  });

  it("分块口径与当前常量不一致：布局校验失败", async () => {
    const entry = { ...entryOf(8, [10]), chunkSize: 1024 };
    const h = makeHarness();

    const result = await runFileExport(entry, null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_LAYOUT_INVALID");
    expect(h.opened).toEqual([]);
  });

  it("目标磁盘空间不足：开流之前拒绝且不产生暂存", async () => {
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, CHUNK))]]);
    const h = makeHarness({ records, freeSpace: 10 });

    const result = await runFileExport(entryOf(CHUNK, [10]), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_DISK_FULL");
      expect(result.message).toContain("目标磁盘空间不足");
    }
    expect(h.opened).toEqual([]);
    expect(h.finalized).toEqual([]);
    expect(h.aborted).toEqual([]);
  });

  it("目标空间读数不可得：不阻断导出（前置预检为尽力而为）", async () => {
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, 4))]]);
    const h = makeHarness({ records, freeSpace: null });

    const result = await runFileExport(entryOf(4, [10]), null, h.deps);

    expect(result.ok).toBe(true);
    expect(h.finalized).toEqual(["stream-1"]);
  });

  it("加密条目密码错误：在选取保存位置之前失败", async () => {
    const entry = { ...entryOf(8, [10]), encrypted: true };
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, 8))]]);
    const h = makeHarness({
      records,
      decrypt: async () => {
        throw new Error("解密封装失败");
      },
    });

    const result = await runFileExport(entry, "wrong", h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_PWD_OR_CORRUPT");
      expect(result.message).toBe(V1_MERGED_MESSAGE);
    }
    expect(h.picked).toEqual([]);
    expect(h.opened).toEqual([]);
    expect(h.aborted).toEqual([]);
  });

  it("v2 错误口令：passwordCheck 前置失败，不消费保存路径选择、不落 v1 解密", async () => {
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, 8))]]);
    const h = makeHarness({ records, withV2: true, v2Session: null });

    const result = await runFileExport(entryV2(8, [10]), "wrong", h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_PWD_WRONG");
      expect(result.message).toBe("密码错误");
    }
    expect(h.stats.v2Open).toBe(1);
    expect(h.stats.decrypt).toBe(0);
    expect(h.picked).toEqual([]);
    expect(h.opened).toEqual([]);
  });

  it("v2 口令正确但块损坏：报数据损坏（不得报密码错）", async () => {
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, 8))]]);
    const h = makeHarness({ records, withV2: true, v2DecryptThrows: true });

    const result = await runFileExport(entryV2(8, [10]), "right", h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("E_CHUNK_CORRUPTED");
      expect(result.message).toContain("第 1 块");
    }
    expect(h.aborted).toEqual(["stream-1"]);
    expect(h.finalized).toEqual([]);
  });

  it("v2 正常导出：会话逐块解密参与写出，末尾一次 finalize", async () => {
    const cipher = chunkBuffer(1, 8);
    const records = new Map<number, string>([[10, bytesToBase64(cipher)]]);
    const h = makeHarness({ records, withV2: true });

    const result = await runFileExport(entryV2(8, [10]), "right", h.deps);

    expect(result).toEqual({ ok: true, bytes: 8 });
    // 桩会话为恒等解密：写出字节即记录载荷字节
    expect(Array.from(h.appended[0])).toEqual(Array.from(cipher));
    expect(h.finalized).toEqual(["stream-1"]);
    expect(h.picked).toEqual(["a.bin"]);
  });

  it("v2 条目但解密装配缺失：报形态不符（不得退化为密码错误）", async () => {
    const h = makeHarness({ records: new Map([[10, bytesToBase64(chunkBuffer(1, 8))]]) });

    const result = await runFileExport(entryV2(8, [10]), "right", h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_LAYOUT_INVALID");
    expect(h.picked).toEqual([]);
    expect(h.opened).toEqual([]);
  });

  it("加密条目密码正确：解密后字节参与写出", async () => {
    const plain = chunkBuffer(7, 8);
    const entry = { ...entryOf(8, [10]), encrypted: true };
    const records = new Map<number, string>([[10, bytesToBase64(chunkBuffer(1, 8))]]);
    const h = makeHarness({ records, decrypt: async () => bytesToBase64(plain) });

    const result = await runFileExport(entry, "correct", h.deps);

    expect(result).toEqual({ ok: true, bytes: 8 });
    expect(h.stats.decrypt).toBe(1);
    expect(Array.from(h.appended[0])).toEqual(Array.from(plain));
    expect(h.finalized).toEqual(["stream-1"]);
  });

  it("零字节文件：不追加数据块，仍产出空文件", async () => {
    const entry: ExportSourceEntry = {
      name: "empty.bin",
      size: 0,
      totalChunks: 0,
      encrypted: false,
      chunkIds: [],
      chunkSize: CHUNK,
    };
    const h = makeHarness();

    const result = await runFileExport(entry, null, h.deps);

    expect(result).toEqual({ ok: true, bytes: 0 });
    expect(h.appended).toEqual([]);
    expect(h.finalized).toEqual(["stream-1"]);
  });

  it("历史内联形态：按内联块还原且不访问记录", async () => {
    const plain = chunkBuffer(3, 4);
    const entry: ExportSourceEntry = {
      name: "legacy.bin",
      size: 4,
      totalChunks: 1,
      encrypted: false,
      chunkDataB64: [bytesToBase64(plain)],
    };
    const h = makeHarness();

    const result = await runFileExport(entry, null, h.deps);

    expect(result).toEqual({ ok: true, bytes: 4 });
    expect(Array.from(h.appended[0])).toEqual(Array.from(plain));
  });

  it("用户取消保存位置：不打开流且不视为错误", async () => {
    const h = makeHarness({ records: new Map([[10, bytesToBase64(chunkBuffer(1, 4))]]), savePath: null });

    const result = await runFileExport(entryOf(4, [10]), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("CANCELLED");
    expect(h.opened).toEqual([]);
    expect(h.finalized).toEqual([]);
    expect(h.aborted).toEqual([]);
  });

  it("流式终结失败：报保存失败并中止流", async () => {
    const h = makeHarness({
      records: new Map([[10, bytesToBase64(chunkBuffer(1, 4))]]),
      finalizeFails: true,
    });

    const result = await runFileExport(entryOf(4, [10]), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_STREAM_FAILED");
    expect(h.aborted).toEqual(["stream-1"]);
    expect(h.finalized).toEqual([]);
  });

  it("读取记录通道异常：报读取失败并中止流", async () => {
    const h = makeHarness();
    h.deps.getRecord = async (id) => {
      if (id === 11) throw new Error("IPC 通信失败");
      return { dataB64: bytesToBase64(chunkBuffer(1, CHUNK)) };
    };

    const result = await runFileExport(entryOf(CHUNK + 4, [10, 11]), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_READ_FAILED");
    expect(h.aborted).toEqual(["stream-1"]);
    expect(h.finalized).toEqual([]);
  });

  it("保存位置对话框异常：报保存失败且不打开流", async () => {
    const h = makeHarness();
    h.deps.pickSavePath = async () => {
      throw new Error("对话框异常");
    };

    const result = await runFileExport(entryOf(0, []), null, h.deps);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("E_STREAM_FAILED");
    expect(h.opened).toEqual([]);
    expect(h.aborted).toEqual([]);
  });
});