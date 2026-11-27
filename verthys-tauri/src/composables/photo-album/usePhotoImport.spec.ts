/**
 * usePhotoImport.spec.ts — 原生导入路径回归
 *
 * 覆盖：桌面只调用 photoImportStart；进度/取消/错误收尾；浏览器内存导入。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, shallowRef } from "vue";

const { importStartMock, importCancelMock } = vi.hoisted(() => ({
  importStartMock: vi.fn(),
  importCancelMock: vi.fn(async () => {}),
}));

vi.mock("../../lib/verthys", () => ({
  userFileStat: vi.fn(async () => ({ size: 3, mtime_ms: 0 })),
  photoImportStart: importStartMock,
  photoImportCancel: importCancelMock,
}));
vi.mock("../../lib/util/keyManager", () => ({
  persistVerthysDetailed: vi.fn(async () => ({ kind: "ok" })),
  setModuleCache: vi.fn(),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("./utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./utils")>();
  let memId = 1000;
  return {
    ...actual,
    generateThumbnail: vi.fn(async () => "thumb-b64"),
    nextMemoryPhotoId: () => ++memId,
    openBrowserFileDialog: vi.fn(),
    importedToPhotoEntries: vi.fn((items: Array<{ metaId: number; displayName: string }>) =>
      items.map((it) => ({
        id: it.metaId,
        metaId: it.metaId,
        name: it.displayName,
        thumb: "",
        size: "0B",
        height: 180,
      })),
    ),
  };
});

import { usePhotoImport } from "./usePhotoImport";
import { open } from "@tauri-apps/plugin-dialog";
import { openBrowserFileDialog } from "./utils";
import { photoImportStart } from "../../lib/verthys";

const okResult = (overrides: Record<string, unknown> = {}) => ({
  ok: true,
  imported: [],
  failedRecords: [],
  skipped: 0,
  total: 1,
  elapsedMs: 1,
  cancelled: false,
  ...overrides,
});

function makeTauri() {
  return usePhotoImport({
    photos: shallowRef([]),
    isTauri: true,
    ensurePhotoKey: () => true,
    showError: vi.fn(),
  });
}

describe("usePhotoImport — 原生导入", () => {
  let scope: ReturnType<typeof effectScope>;

  beforeEach(() => {
    vi.clearAllMocks();
    scope = effectScope();
    importStartMock.mockImplementation(async () => okResult());
  });

  afterEach(() => {
    scope.stop();
    vi.useRealTimers();
  });

  it("桌面端只调用 photoImportStart，并把进度映射到 ref", async () => {
    (open as ReturnType<typeof vi.fn>).mockResolvedValue(["C:/a.jpg"]);
    importStartMock.mockImplementation(async (_paths: string[], onProgress: (p: unknown) => void) => {
      onProgress({
        percent: 42,
        elapsedMs: 10,
        phase: "importing",
        totalChunks: 2,
        currentChunk: 1,
        currentName: "a.jpg",
        doneFiles: 0,
        totalFiles: 1,
      });
      return okResult({
        imported: [{
          metaId: 7, name: "meta_a.jpg", displayName: "a.jpg",
          thumbB64: "", size: 3, mime: "image/jpeg",
        }],
      });
    });

    const api = scope.run(() => makeTauri())!;
    await api.onImport();

    expect(photoImportStart).toHaveBeenCalledTimes(1);
    expect(importStartMock.mock.calls[0][0]).toEqual(["C:/a.jpg"]);
    expect(api.importing.value).toBe(false);
  });

  it("导入阶段提供阶段标签与计数，不显示文件名", async () => {
    (open as ReturnType<typeof vi.fn>).mockResolvedValue(["C:/a.jpg"]);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    importStartMock.mockImplementation(
      async (_paths: string[], onProgress: (p: unknown) => void) => {
        onProgress({
          percent: 42,
          elapsedMs: 10,
          phase: "importing",
          totalChunks: 2,
          currentChunk: 1,
          currentName: "a.jpg",
          doneFiles: 0,
          totalFiles: 100,
        });
        await gate;
        return okResult();
      },
    );

    const api = scope.run(() => makeTauri())!;
    const pending = api.onImport();

    await vi.waitFor(() => expect(api.importStatus.value).toBe("正在导入"));
    expect(api.importCurrent.value).toBe(1);
    expect(api.importTotal.value).toBe(100);
    expect(api.importStatus.value).not.toContain("a.jpg");

    release();
    await pending;
  });

  it("取消结果标记为 ABORTED 并显示已导入数量", async () => {
    (open as ReturnType<typeof vi.fn>).mockResolvedValue(["C:/a.jpg"]);
    importStartMock.mockResolvedValue(okResult({ cancelled: true }));

    const api = scope.run(() => makeTauri())!;
    await api.onImport();

    expect(api.importStatus.value).toContain("导入已取消");
  });

  it("会话级错误透传 showError", async () => {
    (open as ReturnType<typeof vi.fn>).mockResolvedValue(["C:/a.jpg"]);
    importStartMock.mockResolvedValue(okResult({ ok: false, error: "E_BOOM" }));
    const showError = vi.fn();
    const api = scope.run(() =>
      usePhotoImport({
        photos: shallowRef([]), isTauri: true,
        ensurePhotoKey: () => true, showError,
      }),
    )!;
    await api.onImport();
    expect(showError).toHaveBeenCalledWith("导入失败: E_BOOM");
  });

  it("去重跳过显式提示，不静默", async () => {
    (open as ReturnType<typeof vi.fn>).mockResolvedValue(["C:/a.jpg"]);
    importStartMock.mockResolvedValue(okResult({ skipped: 2 }));
    const showToast = vi.fn();
    const api = scope.run(() =>
      usePhotoImport({
        photos: shallowRef([]), isTauri: true,
        ensurePhotoKey: () => true, showError: vi.fn(), showToast,
      }),
    )!;
    await api.onImport();
    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast.mock.calls[0][0]).toContain("重复跳过");
    expect(api.importStatus.value).toContain("重复跳过 2 张");
  });

  it("文件对话框连点只发起一次导入", async () => {
    (open as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise(() => { /* 挂起 */ }),
    );
    const api = scope.run(() => makeTauri())!;
    void api.onImport();
    await api.onImport();
    expect(open).toHaveBeenCalledTimes(1);
  });
});

describe("usePhotoImport — 浏览器内存导入", () => {
  it("不调用 IPC，直接生成内存条目", async () => {
    const file = new File([new Uint8Array([1, 2, 3])], "a.jpg", { type: "image/jpeg" });
    (openBrowserFileDialog as ReturnType<typeof vi.fn>).mockResolvedValue([file]);
    const scope = effectScope();
    const api = scope.run(() =>
      usePhotoImport({
        photos: shallowRef([]), isTauri: false,
        ensurePhotoKey: () => true, showError: vi.fn(),
      }),
    )!;
    await api.onImport();
    expect(photoImportStart).not.toHaveBeenCalled();
    expect(api.importing.value).toBe(false);
    scope.stop();
  });
});
