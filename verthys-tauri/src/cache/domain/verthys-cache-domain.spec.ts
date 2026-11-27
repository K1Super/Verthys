/*
 * verthys-cache-domain.spec.ts — Verthys 缓存领域行为契约
 *
 * 覆盖：
 *   1. 权威类型 ID：分页聚合、同类型单飞、路径切换失效、显式清空失效、
 *      非单调响应拒绝
 *   2. 记录扫描：游标合并、待删过滤、大体积管控、进度计数、取消与清除的
 *      令牌失效、游标扫描失败回退
 *   3. 摘要扫描：游标合并、失败静默、早停命中与缓存优先
 *   4. 全量记录：单飞加载、删除过滤、addFullRecord 的摘要同步与类型失效
 *   5. 清空编排：全量清空、模块登出、事件通知
 */
import { describe, it, expect, vi, beforeEach, type Mock } from "vitest";
import type { ScannedRecord } from "../../types/key_manager";
import type { SummaryRecord } from "../../lib/verthys";
import { MODULE_CACHE_KEY } from "../../constants/key_manager_const";
import { DATAB64_CACHE_MAX_BYTES } from "../../constants/photo_budget.generated";
import {
  VerthysCacheDomain,
  type KeyStateForCache,
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

function rec(id: number, type = 1, dataB64 = "AAAA"): ScannedRecord {
  return { id, type, name: `r${id}`, dataB64 };
}

function summary(id: number, type = 2): SummaryRecord {
  return {
    id,
    type,
    name: `s${id}`,
    dataSize: 4,
    physicalOffset: 0,
    merkleLeaf: "",
    createdTime: 0,
  };
}

describe("VerthysCacheDomain 权威类型 ID", () => {
  let api: VerthysCacheApi;
  let path: string;
  let domain: VerthysCacheDomain;
  let keyState: KeyStateForCache;
  let pendingDeletionIds: Set<number>;
  let committedDeletionIds: Set<number>;
  let stopBackgroundTasks: Mock<() => Promise<void>>;

  beforeEach(() => {
    api = createApi();
    path = "C:/vault/alpha.verthys";
    keyState = {
      moduleKeyReady: { value: { photo: false, accounts: false, fileverthys: false } },
    };
    pendingDeletionIds = new Set<number>();
    committedDeletionIds = new Set<number>();
    stopBackgroundTasks = vi.fn(async () => {});
    domain = new VerthysCacheDomain(
      api,
      keyState,
      () => path,
      {
        pendingDeletionIds,
        committedDeletionIds,
        shouldAbortBackgroundWork: () => false,
        stopBackgroundTasks,
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
    pendingDeletionIds.add(2);
    await expect(domain.ensureTypeIds(0x01)).resolves.toEqual([1, 3]);
  });

  it("模块登录只登记状态，不创建模块级闲置计时器", async () => {
    vi.useFakeTimers();
    try {
      domain.markModuleReady("photo");
      expect(keyState.moduleKeyReady.value.photo).toBe(true);

      // 模块锁定只由全局会话空闲锁定触发；本层不得存在任何独立到期逻辑
      await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
      expect(keyState.moduleKeyReady.value.photo).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("VerthysCacheDomain 记录扫描", () => {
  let api: VerthysCacheApi;
  let domain: VerthysCacheDomain;
  let pendingDeletionIds: Set<number>;

  beforeEach(() => {
    api = createApi();
    pendingDeletionIds = new Set<number>();
    domain = new VerthysCacheDomain(
      api,
      { moduleKeyReady: { value: { photo: false, accounts: false, fileverthys: false } } },
      () => "C:/vault/alpha.verthys",
      {
        pendingDeletionIds,
        committedDeletionIds: new Set<number>(),
        shouldAbortBackgroundWork: () => false,
        stopBackgroundTasks: async () => {},
      },
    );
  });

  it("游标合并记录，并以 maxScannedId+1 增量续扫", async () => {
    vi.mocked(api.scanOpen).mockResolvedValueOnce({
      records: [rec(1), rec(2)],
      exhausted: false,
      failedIds: [],
    });
    vi.mocked(api.scanNext).mockResolvedValueOnce({
      records: [rec(3)],
      exhausted: true,
      failedIds: [],
    });

    await domain.ensureRecordScan();

    expect(domain.getRecordIdsByType(1)).toEqual([1, 2, 3]);
    expect(domain.getRecordFromScan(2)?.name).toBe("r2");
    expect(api.scanClose).toHaveBeenCalledTimes(1);
    expect(vi.mocked(api.scanOpen).mock.calls[0][2]).toEqual({
      project: "index",
      inlineMaxBytes: DATAB64_CACHE_MAX_BYTES,
    });

    vi.mocked(api.scanOpen).mockResolvedValue({
      records: [],
      exhausted: true,
      failedIds: [],
    });
    await domain.ensureRecordScan();
    expect(vi.mocked(api.scanOpen).mock.calls[1][0]).toBe(4);
  });

  it("过滤待删 ID，并按批次上报真实进度与损坏记账", async () => {
    pendingDeletionIds.add(2);
    vi.mocked(api.scanOpen).mockResolvedValueOnce({
      records: [rec(1), rec(2)],
      exhausted: true,
      failedIds: [9],
    });
    const progresses: Array<{ cached: number; scanned: number; failed: number }> = [];

    await domain.ensureRecordScan((p) => progresses.push(p));

    expect(domain.getRecordIdsByType(1)).toEqual([1]);
    expect(domain.getScanFailedIds()).toEqual([9]);
    expect(progresses.at(-1)).toEqual({ cached: 1, scanned: 3, failed: 1 });
  });

  it("超管控阈值的数据不驻留，批量读取回退单条 IPC", async () => {
    const big = "A".repeat(DATAB64_CACHE_MAX_BYTES + 4);
    vi.mocked(api.scanOpen).mockResolvedValueOnce({
      records: [rec(1, 1, big)],
      exhausted: true,
      failedIds: [],
    });
    await domain.ensureRecordScan();
    expect(domain.getRecordFromScan(1)?.dataB64).toBe("");

    vi.mocked(api.getRecord).mockResolvedValue({ type: 1, name: "r1", dataB64: big });
    const map = await domain.getRecordsDataB64Batch([1]);
    expect(map.get(1)).toBe(big);
    expect(api.getRecord).toHaveBeenCalledWith(1);
  });

  it("取消扫描在批次边界生效：已合并保留，后续批次丢弃并关闭游标", async () => {
    vi.mocked(api.scanOpen).mockResolvedValueOnce({
      records: [rec(1)],
      exhausted: false,
      failedIds: [],
    });
    let releaseNext!: (value: {
      records: ScannedRecord[];
      exhausted: boolean;
      failedIds: number[];
    }) => void;
    vi.mocked(api.scanNext).mockReturnValueOnce(
      new Promise((resolve) => {
        releaseNext = resolve;
      }),
    );

    const scan = domain.ensureRecordScan();
    await vi.waitFor(() => expect(api.scanNext).toHaveBeenCalledTimes(1));
    domain.cancelRecordScan();
    releaseNext({ records: [rec(2)], exhausted: true, failedIds: [] });
    await scan;

    expect(domain.getRecordFromScan(1)).not.toBeNull();
    expect(domain.getRecordFromScan(2)).toBeNull();
    expect(api.scanClose).toHaveBeenCalledTimes(1);
  });

  it("清除缓存令在途扫描失效：结果不落缓存，游标移交后继", async () => {
    vi.mocked(api.scanOpen).mockResolvedValueOnce({
      records: [rec(1)],
      exhausted: false,
      failedIds: [],
    });
    let releaseNext!: (value: {
      records: ScannedRecord[];
      exhausted: boolean;
      failedIds: number[];
    }) => void;
    vi.mocked(api.scanNext).mockReturnValueOnce(
      new Promise((resolve) => {
        releaseNext = resolve;
      }),
    );

    const scan = domain.ensureRecordScan();
    await vi.waitFor(() => expect(api.scanNext).toHaveBeenCalledTimes(1));
    domain.clearRecordScanCache();
    releaseNext({ records: [rec(2)], exhausted: true, failedIds: [] });
    await scan;

    expect(domain.getRecordFromScan(1)).toBeNull();
    expect(domain.getRecordFromScan(2)).toBeNull();
    expect(api.scanClose).not.toHaveBeenCalled();
  });

  it("游标扫描失败回退流式枚举，游标仍由属主收尾关闭", async () => {
    vi.mocked(api.scanOpen).mockRejectedValueOnce(new Error("v1 不支持游标"));
    vi.mocked(api.enumerateRecordsStream).mockImplementation(
      async (_startId, _batchSize, onBatch) => {
        onBatch({ records: [rec(5)] });
        return 1;
      },
    );

    await domain.ensureRecordScan();

    expect(domain.getRecordFromScan(5)).not.toBeNull();
    expect(api.scanClose).toHaveBeenCalledTimes(1);
  });

  it("失效单条记录后从更小的起点续扫，避免复用 ID 漏扫", async () => {
    vi.mocked(api.scanOpen).mockResolvedValueOnce({
      records: [rec(1), rec(2), rec(3)],
      exhausted: true,
      failedIds: [],
    });
    await domain.ensureRecordScan();
    domain.invalidateScannedRecord(3);

    vi.mocked(api.scanOpen).mockResolvedValue({
      records: [],
      exhausted: true,
      failedIds: [],
    });
    await domain.ensureRecordScan();
    expect(vi.mocked(api.scanOpen).mock.calls[1][0]).toBe(3);
  });
});

describe("VerthysCacheDomain 摘要扫描", () => {
  let api: VerthysCacheApi;
  let domain: VerthysCacheDomain;

  beforeEach(() => {
    api = createApi();
    domain = new VerthysCacheDomain(
      api,
      { moduleKeyReady: { value: { photo: false, accounts: false, fileverthys: false } } },
      () => "C:/vault/alpha.verthys",
      {
        pendingDeletionIds: new Set<number>(),
        committedDeletionIds: new Set<number>(),
        shouldAbortBackgroundWork: () => false,
        stopBackgroundTasks: async () => {},
      },
    );
  });

  it("摘要游标合并记录并关闭游标", async () => {
    vi.mocked(api.scanSummaryOpen).mockResolvedValueOnce({
      records: [summary(1)],
      exhausted: false,
    });
    vi.mocked(api.scanSummaryNext).mockResolvedValueOnce({
      records: [summary(2)],
      exhausted: true,
    });

    await domain.ensureSummaryScan();

    expect(domain.getSummaryIdsByType(2)).toEqual([1, 2]);
    expect(domain.getSummaryRecord(2)?.name).toBe("s2");
    expect(api.scanSummaryClose).toHaveBeenCalledTimes(1);
  });

  it("摘要扫描失败静默返回，不触发全量解密回退", async () => {
    vi.mocked(api.scanSummaryOpen).mockRejectedValueOnce(new Error("v1"));

    await expect(domain.ensureSummaryScan()).resolves.toBeUndefined();

    expect(domain.getSummaryCacheSize()).toBe(0);
    expect(api.enumerateRecords).not.toHaveBeenCalled();
  });

  it("早停命中首条匹配即返回并关闭游标", async () => {
    vi.mocked(api.scanSummaryOpen).mockResolvedValueOnce({
      records: [summary(1, 5), summary(2, 7)],
      exhausted: false,
    });

    await expect(domain.findLidByTypeEarlyStop(7)).resolves.toBe(2);

    expect(api.scanSummaryClose).toHaveBeenCalledTimes(1);
    expect(api.scanSummaryNext).not.toHaveBeenCalled();
  });

  it("常驻摘要缓存优先，早停不重复打开游标", async () => {
    vi.mocked(api.scanSummaryOpen).mockResolvedValueOnce({
      records: [summary(1, 5)],
      exhausted: true,
    });
    await domain.ensureSummaryScan();

    await expect(domain.findLidByTypeEarlyStop(5)).resolves.toBe(1);

    expect(api.scanSummaryOpen).toHaveBeenCalledTimes(1);
  });
});

describe("VerthysCacheDomain 全量记录与清空编排", () => {
  let api: VerthysCacheApi;
  let domain: VerthysCacheDomain;
  let pendingDeletionIds: Set<number>;
  let stopBackgroundTasks: Mock<() => Promise<void>>;

  beforeEach(() => {
    api = createApi();
    pendingDeletionIds = new Set<number>();
    stopBackgroundTasks = vi.fn(async () => {});
    domain = new VerthysCacheDomain(
      api,
      { moduleKeyReady: { value: { photo: false, accounts: false, fileverthys: false } } },
      () => "C:/vault/alpha.verthys",
      {
        pendingDeletionIds,
        committedDeletionIds: new Set<number>(),
        shouldAbortBackgroundWork: () => false,
        stopBackgroundTasks,
      },
    );
  });

  it("同 ID 并发加载复用同一 IPC，成功结果进入全量缓存", async () => {
    let release!: (value: { type: number; name: string; dataB64: string } | null) => void;
    vi.mocked(api.getRecord).mockReturnValueOnce(
      new Promise((resolve) => {
        release = resolve;
      }),
    );

    const p1 = domain.getFullRecord(10);
    const p2 = domain.getFullRecord(10);
    expect(api.getRecord).toHaveBeenCalledTimes(1);

    release({ type: 1, name: "x", dataB64: "QUJD" });
    await expect(p1).resolves.toEqual({ id: 10, type: 1, name: "x", dataB64: "QUJD" });
    await expect(p2).resolves.toEqual({ id: 10, type: 1, name: "x", dataB64: "QUJD" });
    expect(domain.hasFullRecord(10)).toBe(true);
  });

  it("待删 ID 不发起全量读取", async () => {
    pendingDeletionIds.add(11);
    await expect(domain.getFullRecord(11)).resolves.toBeNull();
    expect(api.getRecord).not.toHaveBeenCalled();
  });

  it("addFullRecord 同步摘要并失效该类型的 ID 枚举", async () => {
    vi.mocked(api.listIdsByType).mockResolvedValue({ ids: [1], exhausted: true });
    await domain.ensureTypeIds(3);

    domain.addFullRecord(9, 3, "n", "AAAA");

    expect(domain.getSummaryRecord(9)?.name).toBe("n");
    expect(domain.getSummaryIdsByType(3)).toEqual([9]);
    await domain.ensureTypeIds(3);
    expect(api.listIdsByType).toHaveBeenCalledTimes(2);
  });

  it("全量清空先停后台任务，再清状态与四类缓存", async () => {
    domain.markModuleReady("photo");
    domain.setModuleCache("k", { a: 1 });
    domain.addRecordToScan(1, 1, "n", "AAAA");
    domain.addSummaryRecord(summary(1, 1));
    domain.addFullRecord(2, 1, "m", "AAAA");

    await domain.clearAllVerthysCaches();

    expect(stopBackgroundTasks).toHaveBeenCalledTimes(1);
    expect(domain.getModuleCache("k").data).toBeNull();
    expect(domain.getRecordIdsByType(1)).toEqual([]);
    expect(domain.getSummaryCacheSize()).toBe(0);
    expect(domain.getFullRecordCacheSize()).toBe(0);
  });

  it("模块登出清除登录状态与该模块全部明文缓存", async () => {
    domain.markModuleReady("photo");
    domain.setModuleCache(MODULE_CACHE_KEY.photo, { a: 1 });
    domain.addRecordToScan(1, 1, "n", "AAAA");
    domain.addSummaryRecord(summary(1, 1));
    domain.addFullRecord(2, 1, "m", "AAAA");

    domain.removeModuleKey("photo");

    expect(domain.getModuleCache(MODULE_CACHE_KEY.photo).data).toBeNull();
    expect(domain.getRecordFromScan(1)).toBeNull();
    expect(domain.getSummaryCacheSize()).toBe(0);
    expect(domain.getFullRecordCacheSize()).toBe(0);
  });

  it("清理记录缓存与摘要缓存时发出对应事件", () => {
    const seen: string[] = [];
    domain.on("scan-cleared", () => seen.push("scan"));
    domain.on("summary-cleared", () => seen.push("summary"));

    domain.clearRecordScanCache();
    domain.clearSummaryCache();

    expect(seen).toEqual(["scan", "summary"]);
  });
});
