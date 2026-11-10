/**
 * damage.spec.ts — 损坏判定纯函数契约
 *
 * 锁定核心安全语义：只有“内容层认证失败 + 非历史明文布局”才算确定损坏；
 * 模块锁定、超时等不可判定错误与历史明文 JSON 一律不得计入删除范围。
 */
import { describe, expect, it, vi } from "vitest";
import { bytesToBase64 } from "../../utils/binary_codec";
import {
  isDefinitelyDamaged,
  looksLikeLegacyPlainJson,
  scanDamagedMetaIds,
} from "./damage";

function authError(code = "ERR_00000002"): Error {
  return Object.assign(new Error("解密记录(meta)失败"), {
    name: "ModuleCryptoError",
    code,
  });
}

const JSON_PAYLOAD = bytesToBase64(new TextEncoder().encode('{"name":"photo.jpg"}'));
/* 分片信封形态：uuid(16) + seq/total/pt_len(12) + nonce(24) + tag(16) */
const ENVELOPE_PAYLOAD = bytesToBase64(new Uint8Array(68).fill(0x11));

describe("damage 损坏判定", () => {
  it("历史明文 JSON 布局不计入损坏", () => {
    expect(looksLikeLegacyPlainJson(JSON_PAYLOAD)).toBe(true);
    expect(isDefinitelyDamaged(authError(), JSON_PAYLOAD)).toBe(false);
  });

  it("认证失败 + 分片信封形态 = 确定损坏", () => {
    expect(looksLikeLegacyPlainJson(ENVELOPE_PAYLOAD)).toBe(false);
    expect(isDefinitelyDamaged(authError(), ENVELOPE_PAYLOAD)).toBe(true);
  });

  it("非认证失败错误不得判定为损坏", () => {
    expect(isDefinitelyDamaged(authError("ERR_00000007"), ENVELOPE_PAYLOAD)).toBe(false);
    expect(isDefinitelyDamaged(new Error("timeout"), ENVELOPE_PAYLOAD)).toBe(false);
    expect(isDefinitelyDamaged(null, ENVELOPE_PAYLOAD)).toBe(false);
    expect(isDefinitelyDamaged("AUTH", ENVELOPE_PAYLOAD)).toBe(false);
  });

  it("空载荷与非法 base64 不误判", () => {
    expect(looksLikeLegacyPlainJson("")).toBe(false);
    expect(looksLikeLegacyPlainJson("!!!not-base64!!!")).toBe(false);
  });
});

describe("scanDamagedMetaIds 批量扫描", () => {
  const payloads = new Map<number, string>([
    [1, ENVELOPE_PAYLOAD],
    [2, ENVELOPE_PAYLOAD],
    [3, JSON_PAYLOAD],
  ]);

  it("只把认证失败且非历史明文的记录计入损坏", async () => {
    // 三条记录都在内容层认证失败；记录 3 因历史明文布局不得计入损坏
    const openMetaMixed = vi.fn(async () => {
      throw authError();
    });

    const result = await scanDamagedMetaIds([1, 2, 3], async (ids) => {
      const map = new Map<number, string>();
      for (const id of ids) {
        const value = payloads.get(id);
        if (value) map.set(id, value);
      }
      return map;
    }, openMetaMixed);

    expect(result.checked).toBe(3);
    expect([...result.damaged].sort((a, b) => a - b)).toEqual([1, 2]);
    expect(result.inconclusive).toBe(1);
  });

  it("整批读取失败全部计入不可判定，绝不删除", async () => {
    const openMeta = vi.fn();

    const result = await scanDamagedMetaIds(
      [1, 2],
      async () => { throw new Error("ipc timeout"); },
      openMeta,
    );

    expect(result.damaged).toEqual([]);
    expect(result.inconclusive).toBe(2);
    expect(openMeta).not.toHaveBeenCalled();
  });

  it("缺失载荷与非认证错误计入不可判定", async () => {
    const result = await scanDamagedMetaIds(
      [1, 2],
      async () => new Map<number, string>(),
      vi.fn(),
    );

    expect(result.damaged).toEqual([]);
    expect(result.inconclusive).toBe(2);
  });

  it("分批与并发不改变判定结果", async () => {
    const ids = [1, 2, 3, 4, 5];
    const fetchBatch = vi.fn(async (batch: number[]) => {
      const map = new Map<number, string>();
      for (const id of batch) map.set(id, ENVELOPE_PAYLOAD);
      return map;
    });

    const result = await scanDamagedMetaIds(
      ids,
      fetchBatch,
      async () => { throw authError("ERR_00000007"); },
      { batchSize: 2, concurrency: 2 },
    );

    expect(fetchBatch).toHaveBeenCalledTimes(3);
    expect(fetchBatch.mock.calls.map(([batch]) => batch.length)).toEqual([2, 2, 1]);
    expect(result.damaged).toEqual([]);
    expect(result.inconclusive).toBe(5);
  });
});
