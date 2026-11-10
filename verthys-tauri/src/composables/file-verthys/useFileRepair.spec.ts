/**
 * useFileRepair.spec.ts — 清藏损坏清理交互契约
 *
 * 锁定：打开即扫描；删除必须二次确认；失败保持结果页；成功后关闭。
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
  const api = useFileRepair({
    files,
    isTauri: true,
    fetchRecord,
    probeOuter,
    cleanup,
    showError,
    ...overrides,
  });
  return { files, fetchRecord, probeOuter, cleanup, showError, ...api };
}

describe("useFileRepair 损坏清理", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("打开即扫描并呈现完整/损坏/跳过计数", async () => {
    const { open, visible, stage, checked, healthy, damaged, skipped, inconclusive } = setup();

    await open();

    expect(visible.value).toBe(true);
    expect(stage.value).toBe("scanned");
    expect(checked.value).toBe(2);
    expect(damaged.value.map((e) => e.id)).toEqual([1]);
    expect(healthy.value).toBe(1);
    expect(skipped.value).toBe(0);
    expect(inconclusive.value).toBe(0);
  });

  it("第一次点击只进入二次确认，不删除", async () => {
    const { open, requestCleanup, confirming, cleanup } = setup();
    await open();

    requestCleanup();

    expect(confirming.value).toBe(true);
    expect(cleanup).not.toHaveBeenCalled();
  });

  it("二次确认后批量删除并关闭", async () => {
    const { open, requestCleanup, cleanupDamaged, cleanup, visible, stage } = setup();
    await open();
    requestCleanup();

    await cleanupDamaged();

    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(cleanup.mock.calls[0][0].map((e) => e.id)).toEqual([1]);
    expect(visible.value).toBe(false);
    expect(stage.value).toBe("idle");
  });

  it("删除失败保持结果页可重试", async () => {
    const cleanup = vi.fn(async () => false);
    const { open, requestCleanup, cleanupDamaged, visible, stage } = setup({ cleanup });
    await open();
    requestCleanup();

    await cleanupDamaged();

    expect(visible.value).toBe(true);
    expect(stage.value).toBe("scanned");
  });

  it("单条读取异常按不可判定处理，扫描不中断也不误删", async () => {
    const { open, stage, showError, damaged, inconclusive } = setup({
      fetchRecord: async () => { throw new Error("ipc down"); },
    });

    await open();

    expect(stage.value).toBe("scanned");
    expect(damaged.value).toEqual([]);
    expect(inconclusive.value).toBe(2);
    expect(showError).not.toHaveBeenCalled();
  });

  it("扫描中禁止关闭", async () => {
    let resolveProbe!: (v: boolean) => void;
    let probeCalls = 0;
    const probeOuter = vi.fn(() => {
      probeCalls += 1;
      if (probeCalls === 1) {
        return new Promise<boolean>((resolve) => { resolveProbe = resolve; });
      }
      return Promise.resolve(true);
    });
    const { open, close, visible, stage } = setup({ probeOuter });

    const opening = open();
    expect(stage.value).toBe("scanning");
    close();
    expect(visible.value).toBe(true);
    expect(stage.value).toBe("scanning");

    // 等扫描推进到 probeOuter（此前有一次记录读取的微任务）
    for (let i = 0; i < 10 && !resolveProbe; i += 1) {
      await Promise.resolve();
    }
    resolveProbe(true);
    await opening;
    expect(stage.value).toBe("scanned");
  });
});
