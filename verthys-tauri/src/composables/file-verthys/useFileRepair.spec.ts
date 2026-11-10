/**
 * useFileRepair.spec.ts — 清藏检查结果 Toast 契约
 *
 * 锁定：检查结果只走统一 Toast（有损坏 → 顶部红；通过/不适用 → 底部状态），
 * 损坏列表供模块内常驻告知条使用；清理成功后才清空。
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { shallowRef } from "vue";
import { useFileRepair } from "./useFileRepair";
import type { FileRepairEntry } from "./damage";

function file(id: number): FileRepairEntry {
  return {
    id,
    name: `file-${id}.bin`,
    metaId: 100 + id,
    chunkIds: [200 + id],
    encrypted: true,
    kdf: { version: 2, saltB64: "c2FsdA==", iterations: 150000 },
    passwordCheck: "check",
    totalChunks: 1,
    size: 1024,
  };
}

function setup(overrides: Partial<Parameters<typeof useFileRepair>[0]> = {}) {
  const files = shallowRef<FileRepairEntry[]>([file(1), file(2)]);
  const fetchRecord = vi.fn(async (id: number) => `payload-${id}`);
  const probeOuter = vi.fn(async (payload: string) => payload !== "payload-201");
  const cleanup = vi.fn(async (_entries: FileRepairEntry[]) => true);
  const showError = vi.fn();
  const showStatus = vi.fn();
  const api = useFileRepair({
    files,
    isTauri: true,
    fetchRecord,
    probeOuter,
    cleanup,
    showError,
    showStatus,
    ...overrides,
  });
  return { files, fetchRecord, probeOuter, cleanup, showError, showStatus, ...api };
}

describe("useFileRepair 检查与清理", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("发现损坏时走顶部错误 Toast，并记录损坏列表", async () => {
    const { scan, scanning, damaged, showError, showStatus } = setup();

    await scan();

    expect(scanning.value).toBe(false);
    expect(damaged.value.map((e) => e.id)).toEqual([1]);
    expect(showError).toHaveBeenCalledWith("完整性检查：1 个文件无法解密");
    expect(showStatus).not.toHaveBeenCalled();
  });

  it("全部完整时走底部状态 Toast", async () => {
    const { scan, damaged, showError, showStatus } = setup({
      probeOuter: async () => true,
    });

    await scan();

    expect(damaged.value).toEqual([]);
    expect(showStatus).toHaveBeenCalledWith("完整性检查通过");
    expect(showError).not.toHaveBeenCalled();
  });

  it("不可判定数量并入结果文案，不误报为损坏", async () => {
    const { scan, damaged, showError } = setup({
      fetchRecord: async () => null,
    });

    await scan();

    expect(damaged.value).toEqual([]);
    expect(showError).not.toHaveBeenCalled();
  });

  it("无可校验文件时明确说明原因", async () => {
    const files = shallowRef<FileRepairEntry[]>([
      { ...file(1), kdf: undefined, passwordCheck: undefined },
    ]);
    const { scan, showStatus } = setup({
      files,
      fetchRecord: vi.fn(),
      probeOuter: vi.fn(),
    });

    await scan();

    expect(showStatus).toHaveBeenCalledWith(
      "完整性检查：无独立密码或历史布局，跳过校验",
    );
  });

  it("清理成功后清空损坏列表并给出状态提示", async () => {
    const { scan, damaged, cleanupDamaged, cleanup, showStatus } = setup();
    await scan();
    expect(damaged.value.length).toBe(1);

    const ok = await cleanupDamaged();

    expect(ok).toBe(true);
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(cleanup.mock.calls[0][0].map((e) => e.id)).toEqual([1]);
    expect(damaged.value).toEqual([]);
    expect(showStatus).toHaveBeenCalledWith("已清理 1 个无法打开的文件");
  });

  it("清理失败保留损坏列表，等待重试", async () => {
    const cleanup = vi.fn(async (_entries: FileRepairEntry[]) => false);
    const { scan, damaged, cleanupDamaged } = setup({ cleanup });
    await scan();

    const ok = await cleanupDamaged();

    expect(ok).toBe(false);
    expect(damaged.value.map((e) => e.id)).toEqual([1]);
  });

  it("非桌面端直接提示，不执行扫描", async () => {
    const { scan, showError, fetchRecord } = setup({ isTauri: false });

    await scan();

    expect(showError).toHaveBeenCalledWith("完整性检查仅在桌面端可用");
    expect(fetchRecord).not.toHaveBeenCalled();
  });
});
