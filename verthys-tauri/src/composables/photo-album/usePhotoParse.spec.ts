/**
 * usePhotoParse.spec.ts — 备份预览与还原原生链路回归
 *
 * 覆盖：photoParseStart 装载清单；photoRestoreStart 导入结果；浏览器模式不调用 IPC。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, ref, shallowRef } from "vue";

const { parseStartMock, restoreStartMock } = vi.hoisted(() => ({
  parseStartMock: vi.fn(),
  restoreStartMock: vi.fn(),
}));

vi.mock("../../lib/verthys", () => ({
  userFileStat: vi.fn(async () => ({ size: 100, mtime_ms: 0 })),
  photoParseStart: parseStartMock,
  photoRestoreStart: restoreStartMock,
}));
vi.mock("../../lib/keyManager", () => ({
  persistVerthysDetailed: vi.fn(async () => ({ kind: "ok" })),
  setModuleCache: vi.fn(),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("./utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./utils")>();
  return {
    ...actual,
    importedToPhotoEntries: vi.fn((items: Array<{ metaId: number; displayName: string }>) =>
      items.map((it) => ({
        id: it.metaId, metaId: it.metaId, name: it.displayName,
        thumb: "", size: "0B", height: 180,
      })),
    ),
  };
});

import { usePhotoParse } from "./usePhotoParse";

const previews = [{
  name: "a.jpg", mime: "image/jpeg", size: 3,
  fileHash: "a".repeat(64), thumbB64: "dGh1bWI=", chunkCount: 1, createdAt: 1,
}];

const restoreOk = {
  ok: true,
  imported: [{
    metaId: 5, name: "parsed_1_0", displayName: "a.jpg",
    thumbB64: "", size: 3, mime: "image/jpeg",
  }],
  failedRecords: [], skipped: 0, total: 1, elapsedMs: 1, cancelled: false,
};

function makeParse(isTauri = true) {
  const photos = shallowRef([]);
  const scope = effectScope();
  const api = scope.run(() =>
    usePhotoParse({
      photos,
      isTauri,
      ensurePhotoKey: () => true,
      showError: vi.fn(),
      showToast: vi.fn(),
      importProgress: ref(0),
      importStatus: ref(""),
      importElapsed: ref(0),
      importCurrent: ref(0),
      importTotal: ref(0),
    }),
  )!;
  return { api, photos, scope };
}

describe("usePhotoParse — 原生预览与还原", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    parseStartMock.mockResolvedValue(previews);
    restoreStartMock.mockResolvedValue(restoreOk);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("桌面解析调用 photoParseStart 并装载清单", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      return setTimeout(() => cb(performance.now()), 16) as unknown as number;
    });
    vi.stubGlobal("cancelAnimationFrame", (id: number) => clearTimeout(id));

    const { api, scope } = makeParse(true);
    api.openParseDialog();
    api.parseFilePath.value = "C:/b.venc";
    api.parseToken.value = "token-12345678";
    const running = api.doParse();
    await vi.advanceTimersByTimeAsync(2_000);
    await running;

    expect(parseStartMock).toHaveBeenCalledWith("C:/b.venc", "token-12345678");
    expect(api.parsedPhotos.value).toHaveLength(1);
    expect(api.parsedPhotos.value[0].fileHash).toBe(previews[0].fileHash);
    expect(api.parsing.value).toBe(false);
    scope.stop();
    vi.unstubAllGlobals();
  });

  it("桌面导入调用 photoRestoreStart 并提交列表", async () => {
    const { api, photos, scope } = makeParse(true);
    api.openParseDialog();
    api.parseFilePath.value = "C:/b.venc";
    api.parseToken.value = "token-12345678";
    api.parsedPhotos.value = [{
      name: "a.jpg", thumb: "", size: 3, mime: "image/jpeg",
      fileHash: "a".repeat(64), chunkCount: 1, createdAt: 1,
    }];

    await api.importParsedPhotos();

    expect(restoreStartMock).toHaveBeenCalledTimes(1);
    expect(restoreStartMock.mock.calls[0][0]).toBe("C:/b.venc");
    expect(restoreStartMock.mock.calls[0][2]).toEqual(["a".repeat(64)]);
    expect(photos.value).toHaveLength(1);
    scope.stop();
  });

  it("浏览器模式解析不调用 IPC", async () => {
    const { api, scope } = makeParse(false);
    expect(api.parseFileName.value).toBe("");
    expect(parseStartMock).not.toHaveBeenCalled();
    scope.stop();
  });
});
