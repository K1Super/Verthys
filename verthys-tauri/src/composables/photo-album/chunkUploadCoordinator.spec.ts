import { describe, it, expect, vi } from "vitest";
import {
  ChunkUploadCoordinator,
  ChunkUploadError,
  type ChunkUploadResponse,
} from "./chunkUploadCoordinator";

function item(key: string, data: string = "x") {
  return { chunk_key: key, data_b64: data };
}

function okResponse(count: number, startId: number = 1): ChunkUploadResponse {
  return {
    ok: true,
    ids: Array.from({ length: count }, (_, i) => startId + i),
    failed_indices: [],
  };
}

describe("ChunkUploadCoordinator", () => {
  it("聚合并发导入项的分块为更少批次，并按输入顺序返回 ID", async () => {
    const batches: Array<Array<{ chunk_key: string }>> = [];
    const coordinator = new ChunkUploadCoordinator(
      async (items) => {
        batches.push(items.map((i) => ({ chunk_key: i.chunk_key })));
        return okResponse(items.length, batches.length * 10);
      },
      { maxChunksPerBatch: 8, maxInflightBatches: 2 },
    );

    const p1 = coordinator.uploadChunks([item("a1"), item("a2")]);
    const p2 = coordinator.uploadChunks([item("b1"), item("b2"), item("b3")]);

    const [ids1, ids2] = await Promise.all([p1, p2]);
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(5);
    expect(ids1).toEqual([10, 11]);
    expect(ids2).toEqual([12, 13, 14]);
    coordinator.close();
  });

  it("按条数上限切批，返回顺序仍与输入一致", async () => {
    const batchSizes: number[] = [];
    const coordinator = new ChunkUploadCoordinator(
      async (items) => {
        batchSizes.push(items.length);
        return okResponse(
          items.length,
          batchSizes.reduce((sum, n) => sum + n, 0) - items.length + 1,
        );
      },
      { maxChunksPerBatch: 3, maxInflightBatches: 1, coalesceWindowMs: 1 },
    );

    const items = Array.from({ length: 7 }, (_, i) => item(`k${i}`));
    const ids = await coordinator.uploadChunks(items);
    expect(batchSizes).toEqual([3, 3, 1]);
    expect(ids).toEqual([1, 2, 3, 4, 5, 6, 7]);
    coordinator.close();
  });

  it("命令级失败按幂等键重试，重试成功后不失败导入项", async () => {
    let attempts = 0;
    const coordinator = new ChunkUploadCoordinator(
      async (items) => {
        attempts++;
        if (attempts === 1) {
          return { ok: false, ids: [], failed_indices: [], error: "写者通道繁忙" };
        }
        return okResponse(items.length);
      },
      { maxRetries: 1, retryDelayMs: 1, maxChunksPerBatch: 8 },
    );

    const ids = await coordinator.uploadChunks([item("a"), item("b")]);
    expect(ids).toEqual([1, 2]);
    expect(attempts).toBe(2);
    coordinator.close();
  });

  it("重试耗尽后整批导入项按 ChunkUploadError 失败", async () => {
    const coordinator = new ChunkUploadCoordinator(
      async () => ({ ok: false, ids: [], failed_indices: [], error: "通道关闭" }),
      { maxRetries: 1, retryDelayMs: 1 },
    );
    await expect(coordinator.uploadChunks([item("a")])).rejects.toBeInstanceOf(
      ChunkUploadError,
    );
    coordinator.close();
  });

  it("项级失败只影响对应导入项，同批其他导入项成功", async () => {
    let calls = 0;
    const coordinator = new ChunkUploadCoordinator(
      async (items) => {
        calls++;
        if (calls === 1) {
          return {
            ok: true,
            ids: items.map((_, i) => i + 1),
            failed_indices: [0],
          };
        }
        return okResponse(items.length);
      },
      { maxRetries: 2, retryDelayMs: 1, maxChunksPerBatch: 8 },
    );

    const p1 = coordinator.uploadChunks([item("bad")]);
    const p2 = coordinator.uploadChunks([item("good")]);
    await expect(p1).rejects.toBeInstanceOf(ChunkUploadError);
    /* 失败的块被后端拒绝后不重试；剩余成功块正常返回 */
    await expect(p2).resolves.toHaveLength(1);
    coordinator.close();
  });

  it("关闭后未决导入项立即失败，生产者不会悬挂", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const coordinator = new ChunkUploadCoordinator(
      async (items) => {
        await gate;
        return okResponse(items.length);
      },
      { maxInflightBatches: 1 },
    );

    const pending = coordinator.uploadChunks([item("a")]);
    coordinator.close("导入已取消");
    await expect(pending).rejects.toBeInstanceOf(ChunkUploadError);

    release();
    coordinator.close();
  });

  it("超过单批上限的大导入项分多批上传且不丢块", async () => {
    const seen: string[] = [];
    const coordinator = new ChunkUploadCoordinator(
      async (items) => {
        seen.push(...items.map((i) => i.chunk_key));
        return okResponse(items.length, seen.length - items.length + 1);
      },
      { maxChunksPerBatch: 4, maxInflightBatches: 2, coalesceWindowMs: 1 },
    );

    const items = Array.from({ length: 9 }, (_, i) => item(`k${i}`));
    const ids = await coordinator.uploadChunks(items);
    expect(seen.sort()).toEqual(items.map((i) => i.chunk_key).sort());
    expect(ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    coordinator.close();
  });

  it("空输入直接返回空数组且不触发上传", async () => {
    const upload = vi.fn(async () => okResponse(0));
    const coordinator = new ChunkUploadCoordinator(upload);
    await expect(coordinator.uploadChunks([])).resolves.toEqual([]);
    expect(upload).not.toHaveBeenCalled();
    coordinator.close();
  });
});
