// @vitest-environment happy-dom
/**
 * usePhotoViewer.spec.ts — 原图直读回归
 *
 * 覆盖：点击后先呈现加载环（不显示缩略图占位）；原图就绪后直接显示原图；
 * 命中原图缓存不发起 IPC；读取失败时报错并关闭查看器。
 */
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from "vitest";
import { effectScope, shallowRef } from "vue";

const { fullBeginMock, fullNextMock, fullCancelMock } = vi.hoisted(() => ({
  fullBeginMock: vi.fn(),
  fullNextMock: vi.fn(),
  fullCancelMock: vi.fn(async () => {}),
}));

vi.mock("../../lib/verthys", () => ({
  photoFullBegin: fullBeginMock,
  photoFullNext: fullNextMock,
  photoFullCancel: fullCancelMock,
}));
vi.mock("../../utils/ui/modal_stack", () => ({
  pushModal: vi.fn(),
  popModal: vi.fn(),
}));

import { usePhotoViewer } from "./usePhotoViewer";
import { photoViewerCache, fullCacheKey } from "./photoBlobCache";
import type { PhotoEntry } from "./types";

const createObjectURL = vi.fn(() => "blob:mock-original");
const revokeObjectURL = vi.fn();

beforeAll(() => {
  Object.assign(URL, { createObjectURL, revokeObjectURL });
});

/** 构造一条带缩略图的照片（缩略图绝不进入查看器） */
function makePhoto(metaId = 7): PhotoEntry {
  return {
    id: metaId,
    metaId,
    name: "a.jpg",
    thumb: "url(data:image/jpeg;base64,AAAA)",
    size: "1.2KB",
    height: 180,
    meta: { name: "a.jpg", size: 1234, mime: "image/jpeg", entryKey: "k" } as PhotoEntry["meta"],
  };
}

function makeViewer(showError = vi.fn()) {
  const scope = effectScope();
  const api = scope.run(() =>
    usePhotoViewer({
      photos: shallowRef([]),
      isTauri: true,
      ensurePhotoKey: () => true,
      showError,
    }),
  )!;
  return { api, scope, showError };
}

describe("usePhotoViewer — 原图直读", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    photoViewerCache.clear();
    createObjectURL.mockReturnValue("blob:mock-original");
    fullNextMock.mockReset();
    fullCancelMock.mockReset().mockResolvedValue(undefined);
    fullBeginMock.mockReset().mockResolvedValue({
      jobId: "job-1",
      name: "a.jpg",
      mime: "image/jpeg",
      size: 1234,
      chunkTotal: 1,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("加载期间只显示加载环，原图就绪后直接显示原图", async () => {
    const payload = new TextEncoder().encode("original-bytes");
    fullBeginMock.mockResolvedValueOnce({
      jobId: "job-1",
      name: "a.jpg",
      mime: "image/jpeg",
      size: payload.length,
      chunkTotal: 1,
    });
    let resolveChunk: (value: unknown) => void = () => {};
    fullNextMock.mockImplementation(
      () => new Promise((resolve) => { resolveChunk = resolve; }),
    );

    const { api, scope } = makeViewer();
    const pending = api.onView(makePhoto());

    await vi.waitFor(() => expect(fullNextMock).toHaveBeenCalledTimes(1));
    // 打开即加载态：不出现缩略图，src 保持为空，UI 呈现加载环
    expect(api.viewer.value).toBe(true);
    expect(api.viewerLoading.value).toBe(true);
    expect(api.viewerSrc.value).toBe("");

    resolveChunk(payload);
    await pending;

    expect(api.viewerLoading.value).toBe(false);
    expect(api.viewerSrc.value).toBe("blob:mock-original");
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    scope.stop();
  });

  it("按 begin.chunkTotal 精确拉取全部块", async () => {
    fullBeginMock.mockResolvedValueOnce({
      jobId: "job-2",
      name: "b.jpg",
      mime: "image/jpeg",
      size: 6,
      chunkTotal: 2,
    });
    fullNextMock
      .mockResolvedValueOnce(new Uint8Array([1, 2, 3]))
      .mockResolvedValueOnce(new Uint8Array([4, 5, 6]));

    const { api, scope } = makeViewer();

    await api.onView(makePhoto());

    expect(fullNextMock).toHaveBeenCalledTimes(2);
    expect(api.viewerLoading.value).toBe(false);
    expect(api.viewerSrc.value).toBe("blob:mock-original");
    scope.stop();
  });

  it("累计字节数与元数据不一致时报错并关闭查看器", async () => {
    fullBeginMock.mockResolvedValueOnce({
      jobId: "job-3",
      name: "c.jpg",
      mime: "image/jpeg",
      size: 999,
      chunkTotal: 1,
    });
    fullNextMock.mockResolvedValueOnce(new Uint8Array([1, 2, 3]));

    const { api, scope, showError } = makeViewer();

    await api.onView(makePhoto());

    expect(showError).toHaveBeenCalledTimes(1);
    expect(api.viewer.value).toBe(false);
    expect(api.viewerSrc.value).toBe("");
    expect(createObjectURL).not.toHaveBeenCalled();
    scope.stop();
  });

  it("命中原图缓存直接显示，不发起读取 IPC", async () => {
    photoViewerCache.put(fullCacheKey(7), "blob:cached-original", 16);
    const { api, scope } = makeViewer();

    await api.onView(makePhoto());

    expect(fullBeginMock).not.toHaveBeenCalled();
    expect(api.viewerSrc.value).toBe("blob:cached-original");
    expect(api.viewerLoading.value).toBe(false);
    scope.stop();
  });

  it("原图读取失败：报错并关闭查看器", async () => {
    fullBeginMock.mockRejectedValueOnce(new Error("E_BOOM"));
    const { api, scope, showError } = makeViewer();

    await api.onView(makePhoto());

    expect(showError).toHaveBeenCalledTimes(1);
    expect(api.viewer.value).toBe(false);
    expect(api.viewerSrc.value).toBe("");
    expect(api.viewerLoading.value).toBe(false);
    scope.stop();
  });
});
