/**
 * usePhotoDelete.spec.ts — 批量删除链路回归
 *
 * 锁定三条核心契约：
 *   1. 确认删除后卡片当帧移除（用户即刻看到响应），不等待后端 IPC；
 *   2. 前端只提交 metaId，外置块由后端台账展开，不再逐条解密 meta；
 *   3. 删除未发生时恢复卡片与缓存，并给出错误提示（不允许界面已删、磁盘仍在）。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { shallowRef } from "vue";
import type { PhotoEntry } from "./types";

vi.mock("../../lib/keyManager", () => ({
  deleteAndPersistBatch: vi.fn(),
  persistVerthysDetailed: vi.fn(),
  setModuleCache: vi.fn(),
  invalidateSummaryRecord: vi.fn(),
  invalidateFullRecord: vi.fn(),
  invalidateScannedRecord: vi.fn(),
}));

vi.mock("../../lib/verthys", () => ({
  verthysForgetImportKeys: vi.fn(),
  verthysGcOrphanChunks: vi.fn(),
}));

import {
  deleteAndPersistBatch,
  persistVerthysDetailed,
  setModuleCache,
} from "../../lib/keyManager";
import { verthysForgetImportKeys, verthysGcOrphanChunks } from "../../lib/verthys";
import { usePhotoDelete } from "./usePhotoDelete";

const deleteMock = vi.mocked(deleteAndPersistBatch);
const persistMock = vi.mocked(persistVerthysDetailed);
const forgetMock = vi.mocked(verthysForgetImportKeys);
const gcMock = vi.mocked(verthysGcOrphanChunks);

function makePhoto(id: number, metaId: number): PhotoEntry {
  return {
    id,
    metaId,
    name: `photo-${id}.jpg`,
    thumb: "",
    size: "1 KB",
    height: 180,
  };
}

function setup() {
  const photos = shallowRef<PhotoEntry[]>([
    makePhoto(101, 11),
    makePhoto(102, 12),
    makePhoto(103, 13),
  ]);
  const showError = vi.fn();
  const showToast = vi.fn();
  const api = usePhotoDelete({
    photos,
    isTauri: true,
    onView: vi.fn(),
    showError,
    showToast,
  });
  return { photos, showError, showToast, ...api };
}

describe("usePhotoDelete 批量删除", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    persistMock.mockResolvedValue({ kind: "ok" });
    forgetMock.mockResolvedValue(undefined);
    gcMock.mockResolvedValue(0);
  });

  it("确认后卡片当帧移除，只提交 metaId，并在成功后释放续传锁", async () => {
    let resolveDelete: (ok: boolean) => void = () => {};
    deleteMock.mockReturnValue(
      new Promise<boolean>((resolve) => {
        resolveDelete = resolve;
      }),
    );

    const { photos, selectedPhotoIds, confirmDelete, deleting, showError, showToast } = setup();
    selectedPhotoIds.value = new Set([101, 102]);

    const running = confirmDelete();

    // 同步断言：后端删除尚未返回，卡片已经消失（即刻响应）
    expect(deleteMock).toHaveBeenCalledTimes(1);
    expect(deleteMock).toHaveBeenCalledWith([11, 12]);
    expect(photos.value.map((p) => p.id)).toEqual([103]);
    expect(deleting.value).toBe(true);
    expect(setModuleCache).toHaveBeenCalled();

    resolveDelete(true);
    await running;

    expect(photos.value.map((p) => p.id)).toEqual([103]);
    expect(forgetMock).toHaveBeenCalledWith([], [11, 12]);
    expect(showError).not.toHaveBeenCalled();
    expect(showToast).toHaveBeenCalledWith("已删除 2 张照片");
    expect(deleting.value).toBe(false);
  });

  it("删除未发生时恢复卡片与缓存，并提示失败", async () => {
    deleteMock.mockResolvedValue(false);

    const { photos, selectedPhotoIds, confirmDelete, deleting, showError } = setup();
    selectedPhotoIds.value = new Set([101, 102]);

    await confirmDelete();

    expect(photos.value.map((p) => p.id)).toEqual([101, 102, 103]);
    expect(setModuleCache).toHaveBeenCalledTimes(2);
    expect(showError).toHaveBeenCalledWith("删除未生效（数据仍保留），请重试");
    expect(forgetMock).not.toHaveBeenCalled();
    expect(deleting.value).toBe(false);
  });
});
