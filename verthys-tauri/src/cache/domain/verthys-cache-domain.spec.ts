/*
 * verthys-cache-domain.spec.ts — 权威类型 ID 缓存契约
 *
 * 覆盖：分页聚合、同类型单飞、路径切换失效、显式清空失效、
 * 非单调响应拒绝。类型 ID 必须来自后端类型盲索引，不得依赖摘要 type。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ScannedRecord } from "../../types/key_manager";
import type { SummaryRecord } from "../../lib/verthys";
import {
  VerthysCacheDomain,
  type VerthysCacheApi,
} from "./verthys-cache-domain";

function createApi(): VerthysCacheApi {
  return {
    scanOpen: vi.fn(async () => ({
      records: [] as ScannedRecord[],
      exhausted: true,
      failedIds: [],
    })),
    scanNext: vi.fn(async () => ({
      records: [] as ScannedRecord[],
      exhausted: true,
      failedIds: [],
    })),
    scanClose: vi.fn(async () => true),
    enumerateRecords: vi.fn(async () => [] as ScannedRecord[]),
    enumerateRecordsStream: vi.fn(async () => 0),
    scanSummaryOpen: vi.fn(async () => ({
      records: [] as SummaryRecord[],
      exhausted: true,
    })),
    scanSummaryNext: vi.fn(async () => ({
      records: [] as SummaryRecord[],
      exhausted: true,
    })),
    scanSummaryClose: vi.fn(async () => true),
    listIdsByType: vi.fn(async () => ({ ids: [] as number[], exhausted: true })),
    getRecord: vi.fn(async () => null),
  };
}

describe("VerthysCacheDomain 权威类型 ID", () => {
  let api: VerthysCacheApi;
  let path: string;
  let domain: VerthysCacheDomain;

  beforeEach(() => {
    api = createApi();
    path = "C:/vault/alpha.verthys";
    domain = new VerthysCacheDomain(
      api,
      { moduleKeyReady: { value: { photo: false, accounts: false, fileverthys: false } } },
      () => path,
      {
        pendingDeletionIds: new Set<number>(),
        committedDeletionIds: new Set<number>(),
        shouldAbortBackgroundWork: () => false,
        stopBackgroundTasks: async () => {},
      },
    );
  });

  it("分页聚合全部 ID，并按类型缓存避免重复 IPC", async () => {
    const list = vi.mocked(api.listIdsByType);
    list
      .mockResolvedValueOnce({ ids: [1, 2], exhausted: false })
      .mockResolvedValueOnce({ ids: [3], exhausted: true });

    await expect(domain.ensureTypeIds(0x01)).resolves.toEqual([1, 2, 3]);
    expect(list).toHaveBeenCalledTimes(2);
    expect(list).toHaveBeenNthCalledWith(1, 0x01, 0, 1000);
    expect(list).toHaveBeenNthCalledWith(2, 0x01, 2, 1000);

    await expect(domain.ensureTypeIds(0x01)).resolves.toEqual([1, 2, 3]);
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("同类型并发调用复用同一枚举 Promise", async () => {
    let release!: (value: { ids: number[]; exhausted: boolean }) => void;
    const pending = new Promise<{ ids: number[]; exhausted: boolean }>(
      (resolve) => {
        release = resolve;
      },
    );
    vi.mocked(api.listIdsByType).mockReturnValue(pending);

    const p1 = domain.ensureTypeIds(0x01);
    const p2 = domain.ensureTypeIds(0x01);
    expect(vi.mocked(api.listIdsByType)).toHaveBeenCalledTimes(1);
    release({ ids: [7], exhausted: true });
    await expect(p1).resolves.toEqual([7]);
    await expect(p2).resolves.toEqual([7]);
  });

  it("容器路径切换后旧缓存失效并重新枚举", async () => {
    vi.mocked(api.listIdsByType).mockResolvedValue({ ids: [1], exhausted: true });
    await domain.ensureTypeIds(0x01);

    path = "C:/vault/beta.verthys";
    vi.mocked(api.listIdsByType).mockResolvedValue({ ids: [9], exhausted: true });
    await expect(domain.ensureTypeIds(0x01)).resolves.toEqual([9]);
    expect(vi.mocked(api.listIdsByType)).toHaveBeenCalledTimes(2);
  });

  it("显式清空后重新枚举", async () => {
    vi.mocked(api.listIdsByType).mockResolvedValue({ ids: [1], exhausted: true });
    await domain.ensureTypeIds(0x01);
    domain.clearTypeIdCache();
    await expect(domain.ensureTypeIds(0x01)).resolves.toEqual([1]);
    expect(vi.mocked(api.listIdsByType)).toHaveBeenCalledTimes(2);
  });

  it("拒绝非严格升序响应，避免游标死循环", async () => {
    vi.mocked(api.listIdsByType).mockResolvedValue({
      ids: [2, 2],
      exhausted: false,
    });
    await expect(domain.ensureTypeIds(0x01)).rejects.toThrow("非单调");
  });

  it("过滤待删除 ID，防止已删记录从类型索引回填", async () => {
    vi.mocked(api.listIdsByType).mockResolvedValue({
      ids: [1, 2, 3],
      exhausted: true,
    });
    const deps = domain as unknown as {
      pendingDeletionIds: Set<number>;
    };
    deps.pendingDeletionIds.add(2);
    await expect(domain.ensureTypeIds(0x01)).resolves.toEqual([1, 3]);
  });
});
