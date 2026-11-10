/**
 * damage.spec.ts — 清藏损坏扫描契约
 *
 * 锁定判定边界：
 *   - 未设独立密码的文件没有内容层信封，不得计入损坏；
 *   - 外层探测失败 = 确定损坏；探测异常 = 不可判定；
 *   - 元数据损坏的条目直接计入损坏（本身已不可用）。
 */
import { describe, expect, it, vi } from "vitest";
import { bytesToBase64 } from "../../utils/binary_codec";
import {
  MAX_INLINE_SCAN_BYTES,
  scanDamagedFiles,
  type FileRepairEntry,
} from "./damage";

function entry(overrides: Partial<FileRepairEntry> = {}): FileRepairEntry {
  return {
    id: 1,
    name: "a.pdf",
    metaId: 101,
    chunkIds: [201, 202],
    encrypted: true,
    kdf: { version: 2, saltB64: "c2FsdA==", iterations: 150000 },
    passwordCheck: "check",
    totalChunks: 2,
    size: 1024,
    ...overrides,
  };
}

function metaWithInline(chunks: string[]): string {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify({ chunkDataB64: chunks })));
}

describe("scanDamagedFiles", () => {
  it("未设独立密码的文件跳过，不判定损坏", async () => {
    const result = await scanDamagedFiles(
      [entry({ encrypted: false })],
      { fetchRecord: vi.fn(), probeOuter: vi.fn() },
    );

    expect(result.damaged).toEqual([]);
    expect(result.skipped).toBe(1);
    expect(result.checked).toBe(1);
  });

  it("历史加密布局（缺 KDF/口令校验块）跳过，避免结构误判", async () => {
    const probeOuter = vi.fn();
    const result = await scanDamagedFiles(
      [entry({ kdf: undefined, passwordCheck: undefined })],
      { fetchRecord: vi.fn(), probeOuter },
    );

    expect(result.damaged).toEqual([]);
    expect(result.skipped).toBe(1);
    expect(probeOuter).not.toHaveBeenCalled();
  });

  it("外层探测失败计入损坏，成功计入完整", async () => {
    const fetchRecord = vi.fn(async (id: number) => `payload-${id}`);
    const probeOuter = vi.fn(async (payload: string) => payload !== "payload-201");

    const result = await scanDamagedFiles(
      [entry(), entry({ id: 2, metaId: 102, chunkIds: [203] })],
      { fetchRecord, probeOuter },
    );

    expect(fetchRecord).toHaveBeenCalledWith(201);
    expect(fetchRecord).toHaveBeenCalledWith(203);
    expect(result.damaged.map((e) => e.id)).toEqual([1]);
    expect(result.healthy).toBe(1);
    expect(result.inconclusive).toBe(0);
  });

  it("探测异常按不可判定处理，绝不删除", async () => {
    const result = await scanDamagedFiles(
      [entry()],
      {
        fetchRecord: async () => "payload",
        probeOuter: async () => { throw new Error("ERR_00000007"); },
      },
    );

    expect(result.damaged).toEqual([]);
    expect(result.inconclusive).toBe(1);
  });

  it("元数据损坏条目直接计入损坏", async () => {
    const probeOuter = vi.fn();
    const result = await scanDamagedFiles(
      [entry({ corrupt: true })],
      { fetchRecord: vi.fn(), probeOuter },
    );

    expect(result.damaged.map((e) => e.id)).toEqual([1]);
    expect(probeOuter).not.toHaveBeenCalled();
  });

  it("历史内联布局按 meta 读取首块并探测", async () => {
    const fetchRecord = vi.fn(async (id: number) =>
      id === 101 ? metaWithInline(["inline-cipher"]) : null,
    );
    const probeOuter = vi.fn(async () => true);

    const result = await scanDamagedFiles(
      [entry({ chunkIds: undefined })],
      { fetchRecord, probeOuter },
    );

    expect(fetchRecord).toHaveBeenCalledWith(101);
    expect(probeOuter).toHaveBeenCalledWith("inline-cipher");
    expect(result.healthy).toBe(1);
  });

  it("内联布局超出上限时跳过探测并计入不可判定", async () => {
    const fetchRecord = vi.fn();
    const result = await scanDamagedFiles(
      [entry({ chunkIds: undefined, size: MAX_INLINE_SCAN_BYTES + 1 })],
      { fetchRecord, probeOuter: vi.fn() },
    );

    expect(fetchRecord).not.toHaveBeenCalled();
    expect(result.inconclusive).toBe(1);
  });

  it("块载荷缺失计入不可判定；0 字节文件视为完整", async () => {
    const missing = await scanDamagedFiles(
      [entry()],
      { fetchRecord: async () => null, probeOuter: vi.fn() },
    );
    expect(missing.inconclusive).toBe(1);

    const empty = await scanDamagedFiles(
      [entry({ totalChunks: 0, chunkIds: [] })],
      { fetchRecord: vi.fn(), probeOuter: vi.fn() },
    );
    expect(empty.healthy).toBe(1);
  });
});
