/**
 * usePhotoRepair.spec.ts — 损坏清理交互契约
 *
 * 锁定三条语义：
 *   1. 打开即扫描，扫描结果如实呈现（检查数 / 损坏数 / 不可判定数）；
 *   2. 删除必须经过二次确认（第一次点击只进入确认态，不调用删除）；
 *   3. 删除失败保持结果页可重试，成功后关闭对话框。
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { shallowRef } from "vue";
import type { PhotoEntry } from "./types";
import { usePhotoRepair } from "./usePhotoRepair";

function makePhoto(id: number): PhotoEntry {
  return {
    id,
    metaId: id,
    name: `photo-${id}.jpg`,
    thumb: "",
    size: "1 KB",
    height: 180,
  };
}

function setup(overrides: Partial<Parameters<typeof usePhotoRepair>[0]> = {}) {
  const photos = shallowRef<PhotoEntry[]>([makePhoto(11), makePhoto(12)]);
  const scanDamaged = vi.fn(async () => ({
    checked: 2,
    damaged: [11],
    inconclusive: 1,
  }));
  const cleanupDamaged = vi.fn(async () => true);
  const showError = vi.fn();
  const api = usePhotoRepair({
    photos,
    isTauri: true,
    scanDamaged,
    cleanupDamaged,
    showError,
    ...overrides,
  });
  return { photos, scanDamaged, cleanupDamaged, showError, ...api };
}

describe("usePhotoRepair 损坏清理", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("打开即扫描并呈现结果", async () => {
    const { open, visible, stage, checked, damagedIds, inconclusive, scanDamaged } = setup();

    await open();

    expect(scanDamaged).toHaveBeenCalledTimes(1);
    expect(visible.value).toBe(true);
    expect(stage.value).toBe("scanned");
    expect(checked.value).toBe(2);
    expect(damagedIds.value).toEqual([11]);
    expect(inconclusive.value).toBe(1);
  });

  it("第一次点击只进入二次确认，不执行删除", async () => {
    const { open, requestCleanup, confirming, cleanupDamaged } = setup();
    await open();

    requestCleanup();

    expect(confirming.value).toBe(true);
    expect(cleanupDamaged).not.toHaveBeenCalled();
  });

  it("二次确认后删除成功并关闭对话框", async () => {
    const { open, requestCleanup, cleanup, visible, stage, cleanupDamaged } = setup();
    await open();
    requestCleanup();

    await cleanup();

    expect(cleanupDamaged).toHaveBeenCalledWith([11]);
    expect(visible.value).toBe(false);
    expect(stage.value).toBe("idle");
  });

  it("删除失败保持结果页可重试", async () => {
    const cleanupDamaged = vi.fn(async () => false);
    const { open, requestCleanup, cleanup, visible, stage } = setup({ cleanupDamaged });
    await open();
    requestCleanup();

    await cleanup();

    expect(cleanupDamaged).toHaveBeenCalledTimes(1);
    expect(visible.value).toBe(true);
    expect(stage.value).toBe("scanned");
  });

  it("扫描异常回到初始态并提示", async () => {
    const scanDamaged = vi.fn(async () => {
      throw new Error("模块密钥已失效");
    });
    const { open, stage, showError } = setup({ scanDamaged });

    await open();

    expect(stage.value).toBe("idle");
    expect(showError).toHaveBeenCalledWith("模块密钥已失效");
  });

  it("扫描中禁止关闭，避免状态错位", async () => {
    let resolveScan!: (value: { checked: number; damaged: number[]; inconclusive: number }) => void;
    const scanDamaged = vi.fn(
      () => new Promise<{ checked: number; damaged: number[]; inconclusive: number }>((resolve) => {
        resolveScan = resolve;
      }),
    );
    const { open, close, visible, stage } = setup({ scanDamaged });

    const opening = open();
    expect(stage.value).toBe("scanning");
    close();
    expect(visible.value).toBe(true);
    expect(stage.value).toBe("scanning");

    resolveScan({ checked: 2, damaged: [], inconclusive: 0 });
    await opening;
    expect(stage.value).toBe("scanned");
  });
});
