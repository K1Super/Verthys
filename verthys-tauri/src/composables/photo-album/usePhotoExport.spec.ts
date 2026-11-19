/**
 * usePhotoExport.spec.ts — 桌面原生导出回归
 *
 * 覆盖：四种格式映射、错误码文案、取消、浏览器 PNG 下载路径。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, shallowRef, type EffectScope } from "vue";

const { exportStartMock, saveMock, openMock } = vi.hoisted(() => ({
  exportStartMock: vi.fn(),
  saveMock: vi.fn(),
  openMock: vi.fn(),
}));

vi.mock("../../lib/verthys", () => ({
  photoExportStart: exportStartMock,
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: openMock,
  save: saveMock,
}));
vi.mock("./utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./utils")>();
  return {
    ...actual,
    convertToPngBytes: vi.fn(async () => new Uint8Array([0x89, 0x50, 0x4e, 0x47])),
    downloadBlob: vi.fn(),
  };
});

import { usePhotoExport } from "./usePhotoExport";
import { convertToPngBytes, downloadBlob } from "./utils";
import type { PhotoEntry } from "./types";

const photo = (id: number): PhotoEntry => ({
  id,
  metaId: id,
  name: `p${id}.jpg`,
  thumb: "",
  size: "3B",
  height: 180,
  loaded: true,
});

function makeExport(photos: PhotoEntry[], isTauri = true): {
  api: ReturnType<typeof usePhotoExport>;
  scope: EffectScope;
} {
  const scope = effectScope();
  const api = scope.run(() =>
    usePhotoExport({
      photos: shallowRef(photos),
      isTauri,
      ensurePhotoKey: () => true,
      showError: vi.fn(),
      showExportDone: vi.fn(),
      showCopied: vi.fn(),
    }),
  )!;
  api.showExportDialog.value = true;
  api.exportPath.value = isTauri ? "C:/out" : "browser_download";
  api.exportToken.value = "token-12345678";
  return { api, scope };
}

const nativeOk = (exported: number) => ({
  ok: true,
  exported,
  failed: [],
  total: exported,
  elapsedMs: 1,
  cancelled: false,
});

describe("usePhotoExport — 桌面原生链路", () => {
  let scope: EffectScope;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    scope?.stop();
    vi.useRealTimers();
  });

  it.each([
    ["single", "venc-single"],
    ["multiple", "venc-multiple"],
    ["original", "original"],
    ["png", "png"],
  ] as const)("格式 %s 映射到原生 %s", async (uiFormat, nativeFormat) => {
    exportStartMock.mockResolvedValue(nativeOk(1));
    const ctx = makeExport([photo(1)]);
    scope = ctx.scope;
    ctx.api.exportFormat.value = uiFormat;
    ctx.api.exportSelectedIds.value = new Set([1]);

    await ctx.api.doExport();

    expect(exportStartMock).toHaveBeenCalledTimes(1);
    expect(exportStartMock.mock.calls[0][1]).toBe(nativeFormat);
    expect(exportStartMock.mock.calls[0][0]).toEqual([1]);
  });

  it("E_EXPORT_TOO_LARGE 给出多文件模式提示", async () => {
    exportStartMock.mockResolvedValue({
      ok: false, exported: 0, failed: [], total: 1, elapsedMs: 1,
      cancelled: false, errorCode: "E_EXPORT_TOO_LARGE", error: "too large",
    });
    const ctx = makeExport([photo(1)]);
    scope = ctx.scope;
    ctx.api.exportFormat.value = "single";
    ctx.api.exportSelectedIds.value = new Set([1]);

    await ctx.api.doExport();

    expect(ctx.api.exportStatus.value).toContain("请改用多文件模式");
  });

  it("取消时状态如实显示已导出数量", async () => {
    exportStartMock.mockResolvedValue({
      ok: false, exported: 2, failed: [], total: 3, elapsedMs: 1,
      cancelled: true,
    });
    const ctx = makeExport([photo(1), photo(2), photo(3)]);
    scope = ctx.scope;
    ctx.api.exportFormat.value = "multiple";
    ctx.api.exportSelectedIds.value = new Set([1, 2, 3]);

    await ctx.api.doExport();

    expect(ctx.api.exportStatus.value).toContain("已导出 2 张");
  });

  it("原生失败明细按原因分类计入结果", async () => {
    exportStartMock.mockResolvedValue({
      ok: false, exported: 1, total: 2, elapsedMs: 1, cancelled: false,
      failed: [{ index: 1, name: "p2.jpg", reason: "decrypt-failed" }],
    });
    const ctx = makeExport([photo(1), photo(2)]);
    scope = ctx.scope;
    ctx.api.exportFormat.value = "multiple";
    ctx.api.exportSelectedIds.value = new Set([1, 2]);

    await ctx.api.doExport();

    expect(ctx.api.exportStatus.value).toContain("失败 1 张");
  });
});

describe("usePhotoExport — 浏览器 PNG", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("使用内存字节转换并下载", async () => {
    const ph = photo(9);
    ph.rawBytes = new Uint8Array([1, 2, 3]);
    const ctx = makeExport([ph], false);
    try {
      ctx.api.exportFormat.value = "png";
      ctx.api.exportSelectedIds.value = new Set([9]);
      await ctx.api.doExport();
      expect(exportStartMock).not.toHaveBeenCalled();
      expect(convertToPngBytes).toHaveBeenCalledTimes(1);
      expect(downloadBlob).toHaveBeenCalledTimes(1);
    } finally {
      ctx.scope.stop();
    }
  });
});
