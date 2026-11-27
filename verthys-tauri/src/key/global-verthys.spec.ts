/*
 * key/global-verthys.spec.ts — 全局密钥编排回归测试
 *
 * 覆盖全局密钥落地的三条路径与收口项：
 *   1. initGlobalKey：成功推进、AddRecord 失败、读回不一致、
 *      reconcile 失败、补偿动作自身失败（强制复位兜底）、重入互斥锁
 *   2. changeGlobalKey：后端单命令薄封装（成功/cleanup_pending/错误码映射/互斥）
 *   3. verifyGlobalKey：全局密钥记录解析（最新有效记录权威/类型索引回退）
 *
 * 依赖隔离：lib/verthys（IPC 面）、verthys-cache（冲刷队列）、
 * security-session（会话门禁）、background-tasks、module-auth、
 * type-migration、logger 全部 vi.mock；
 * key_state / verthys_error / promise_utils / constants 使用真实实现。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../lib/verthys", () => ({
  ensureWorkerReady: vi.fn(),
  ensureCleanWorkerState: vi.fn(),
  verthysUnlock: vi.fn(),
  verthysCreate: vi.fn(),
  verthysPreflight: vi.fn(),
  verthysAddRecord: vi.fn(),
  verthysDeleteRecord: vi.fn(),
  verthysInitStatus: vi.fn(),
  verthysDeriveAndStoreGlobalKey: vi.fn(),
  verthysVerifyGlobalKey: vi.fn(),
  verthysClearGlobalKey: vi.fn(),
  verthysResetGlobalKeyState: vi.fn(),
  verthysReconcileKeyPresence: vi.fn(),
  verthysGetRecord: vi.fn(),
  verthysEnumerateRecords: vi.fn(),
  verthysListIdsByType: vi.fn(),
  verthysChangeGlobalKey: vi.fn(),
  verthysScanSummaryOpen: vi.fn(),
  verthysScanSummaryNext: vi.fn(),
  verthysScanSummaryClose: vi.fn(),
  bytesToBase64: vi.fn(),
  readUserFile: vi.fn(),
  setDeviceBinding: vi.fn(),
  checkDeviceBinding: vi.fn(),
  getDeviceFingerprint: vi.fn(),
  securityBruteCheck: vi.fn(),
  securitySessionStart: vi.fn(),
  securitySessionStop: vi.fn(),
  preloadWorker: vi.fn(),
  invalidateWorkerPreload: vi.fn(),
}));

vi.mock("../cache/composition/verthys-cache", () => ({
  persistVerthys: vi.fn(),
  clearModuleKeyCache: vi.fn(),
  clearRecordScanCache: vi.fn(),
  resetFlushChain: vi.fn(),
  clearSummaryCache: vi.fn(),
  clearFullRecordCache: vi.fn(),
  invalidateSummaryRecord: vi.fn(),
  invalidateScannedRecord: vi.fn(),
  findLidByTypeEarlyStop: vi.fn(),
  enqueueFlush: vi.fn(),
  flushVerthysNow: vi.fn(),
  ensureSummaryScan: vi.fn(),
  ensureRecordScan: vi.fn(),
}));

vi.mock("../session/security-session", async () => {
  const { ref } = await import("vue");
  return {
    resetSessionTimer: vi.fn(),
    clearSessionTimer: vi.fn(),
    applySecurityPreset: vi.fn(),
    checkBruteForceGate: vi.fn(),
    awaitLockAllIfInProgress: vi.fn(),
    securityHardeningFailedRef: ref(false),
  };
});

vi.mock("../core/background-tasks", () => ({
  startBackgroundTasks: vi.fn(() => Promise.resolve()),
  stopBackgroundTasks: vi.fn(() => Promise.resolve()),
}));

vi.mock("./module-auth", () => ({
  loadModuleKeyStatus: vi.fn(),
}));

vi.mock("./type-migration", () => ({
  migrateRecordTypes: vi.fn(),
  isAccountRecordB64: vi.fn(() => false),
}));

vi.mock("../utils/logging/logger", () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

import * as verthysLib from "../lib/verthys";
import * as cacheLib from "../cache/composition/verthys-cache";
import * as sessionLib from "../session/security-session";
import { initGlobalKey, changeGlobalKey, verifyGlobalKey } from "./global-verthys";
import { keyState, resetAllState } from "../state/key_state";
import { TYPE_GLOBAL_KEY } from "../constants/key_manager_const";
import { VerthysErrorCode } from "../lib/util/verthys_error";

const PWD = "p@ss-verthys-9";
const BIN_PWD = "bin-pass";
const BIN_BYTES = new Uint8Array([0x01, 0x02, 0x03]);
const RECORD_B64 = "RECORD_B64";
const NEW_RECORD_B64 = "NEW_RECORD_B64";
const OLD_RECORD_B64 = "OLD_RECORD_B64";
const OLD_ID = 42;
const NEW_ID = 43;

/** 判定结果为失败且携带指定错误码 */
function expectErr(
  result: { ok: boolean; code?: VerthysErrorCode; message?: string },
  code: VerthysErrorCode,
): void {
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.code).toBe(code);
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  resetAllState();
  keyState.verthysReady.value = true;

  // 默认成功配置（各用例按需覆盖）
  vi.mocked(verthysLib.bytesToBase64).mockReturnValue("BIN_B64");
  vi.mocked(verthysLib.verthysDeriveAndStoreGlobalKey).mockResolvedValue({
    id: NEW_ID,
    recordB64: RECORD_B64,
  });
  vi.mocked(verthysLib.verthysAddRecord).mockResolvedValue(NEW_ID);
  vi.mocked(verthysLib.verthysGetRecord).mockResolvedValue({
    type: TYPE_GLOBAL_KEY,
    name: "global-key",
    dataB64: RECORD_B64,
  });
  vi.mocked(verthysLib.verthysDeleteRecord).mockResolvedValue(true);
  vi.mocked(verthysLib.verthysClearGlobalKey).mockResolvedValue(true);
  vi.mocked(verthysLib.verthysResetGlobalKeyState).mockResolvedValue(true);
  vi.mocked(verthysLib.verthysReconcileKeyPresence).mockResolvedValue(true);
  vi.mocked(verthysLib.verthysVerifyGlobalKey).mockResolvedValue(true);
  vi.mocked(verthysLib.verthysEnumerateRecords).mockResolvedValue([]);
  vi.mocked(verthysLib.verthysListIdsByType).mockResolvedValue({ ids: [], exhausted: true });
  vi.mocked(verthysLib.verthysChangeGlobalKey).mockResolvedValue({
    id: NEW_ID,
    recordB64: NEW_RECORD_B64,
    deletedIds: [OLD_ID],
    cleanupPending: false,
  });
  vi.mocked(verthysLib.verthysScanSummaryOpen).mockResolvedValue({ records: [], exhausted: true });
  vi.mocked(verthysLib.verthysScanSummaryNext).mockResolvedValue({ records: [], exhausted: true });
  vi.mocked(verthysLib.verthysScanSummaryClose).mockResolvedValue(true);
  vi.mocked(verthysLib.securitySessionStart).mockResolvedValue(undefined);
  vi.mocked(verthysLib.securitySessionStop).mockResolvedValue(undefined);
  vi.mocked(cacheLib.persistVerthys).mockResolvedValue(true);
  vi.mocked(cacheLib.flushVerthysNow).mockResolvedValue({ ok: true, value: undefined });
  vi.mocked(cacheLib.findLidByTypeEarlyStop).mockResolvedValue(null);
  // applySecurityPreset 现契约：后端切档成功返回 PresetConfig（失败抛错），不再返回 null
  vi.mocked(sessionLib.applySecurityPreset).mockResolvedValue({
    name: "BALANCED",
    code: 0,
    features: {
      anti_debug: true,
      anti_inject: true,
      integrity_check: true,
      memory_guard: true,
      key_separation: true,
      emergency_response: true,
      session_lock_on_idle: true,
      module_patrol: true,
      clip_clear_on_lock: true,
      usb_clone_detect: true,
      trace_cleanup: true,
    },
  });
  vi.mocked(sessionLib.checkBruteForceGate).mockResolvedValue({ allowed: true });
  vi.mocked(sessionLib.awaitLockAllIfInProgress).mockResolvedValue(undefined);
  vi.mocked(sessionLib.resetSessionTimer).mockReturnValue(undefined);
  vi.mocked(sessionLib.clearSessionTimer).mockReturnValue(undefined);
});

describe("initGlobalKey — 状态推进后置与失败补偿", () => {
  it("成功路径：worker 派生持久化 + reconcile 推进，进度单调递增", async () => {
    const progress: number[] = [];
    const result = await initGlobalKey(PWD, BIN_BYTES, BIN_PWD, (p) => progress.push(p.percent));

    expect(result.ok).toBe(true);
    expect(progress).toEqual([8, 20, 70, 88]);
    // 存储动作下沉 worker 新操作：派生与落盘确认在单次 IPC 内原子完成
    expect(verthysLib.verthysDeriveAndStoreGlobalKey).toHaveBeenCalledWith(
      PWD, "BIN_B64", BIN_PWD,
    );
    expect(verthysLib.verthysAddRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysGetRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysReconcileKeyPresence).toHaveBeenCalledWith(true);
    // 前端状态仅在全部确认后落地
    expect(keyState.globalKeyReady.value).toBe(true);
    expect(keyState.hasGlobalKeyRecord.value).toBe(true);
    expect(keyState.globalKeyRecordB64.value).toBe(RECORD_B64);
    expect(keyState.globalKeyRecordId.value).toBe(NEW_ID);
    expect(sessionLib.resetSessionTimer).toHaveBeenCalled();
    // 成功路径不得触碰强制复位
    expect(verthysLib.verthysResetGlobalKeyState).not.toHaveBeenCalled();
  });

  it("worker 派生持久化失败：清理现场（清 GMK + reconcile(false)），状态不推进", async () => {
    vi.mocked(verthysLib.verthysDeriveAndStoreGlobalKey).mockRejectedValue(
      new Error("存储失败（读回不一致已被 worker 自清）"),
    );

    const result = await initGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
    // worker 已内部自清，前端补偿不依赖删除命令
    expect(verthysLib.verthysDeleteRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysClearGlobalKey).toHaveBeenCalled();
    expect(verthysLib.verthysReconcileKeyPresence).toHaveBeenCalledWith(false);
    expect(keyState.globalKeyReady.value).toBe(false);
    expect(keyState.hasGlobalKeyRecord.value).toBe(false);
    expect(verthysLib.verthysResetGlobalKeyState).not.toHaveBeenCalled();
  });

  it("reconcile(true) 失败：复位后靠重试收敛（不前端删除），状态不推进", async () => {
    // true → 失败（状态机拒绝推进）；false → 成功（补偿复位可达）
    vi.mocked(verthysLib.verthysReconcileKeyPresence).mockImplementation(
      async (has: boolean) => has === false,
    );

    const result = await initGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
    // 记录已在磁盘：不依赖删除命令，
    // 重试时 worker 收敛先清残留再写入，恒收敛单条
    expect(verthysLib.verthysDeleteRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysReconcileKeyPresence).toHaveBeenCalledWith(true);
    expect(verthysLib.verthysReconcileKeyPresence).toHaveBeenCalledWith(false);
    expect(keyState.globalKeyReady.value).toBe(false);
  });

  it("补偿动作自身连续失败：强制复位命令兜底", async () => {
    vi.mocked(verthysLib.verthysDeriveAndStoreGlobalKey).mockRejectedValue(
      new Error("存储失败"),
    );
    vi.mocked(verthysLib.verthysClearGlobalKey).mockRejectedValue(new Error("ipc down"));
    vi.mocked(verthysLib.verthysReconcileKeyPresence).mockResolvedValue(false);

    const result = await initGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
    expect(verthysLib.verthysResetGlobalKeyState).toHaveBeenCalledTimes(1);
  });

  it("派生 in-flight 期间重复调用被互斥锁拒绝（杜绝新死锁形态）", async () => {
    let releaseInner: ((v: { id: number; recordB64: string }) => void) | null = null;
    vi.mocked(verthysLib.verthysDeriveAndStoreGlobalKey).mockImplementation(
      () =>
        new Promise<{ id: number; recordB64: string }>((resolve) => {
          releaseInner = resolve;
        }),
    );

    const first = initGlobalKey(PWD, BIN_BYTES, BIN_PWD);
    const second = await initGlobalKey(PWD, BIN_BYTES, BIN_PWD);
    expectErr(second, VerthysErrorCode.E_VERTHYS_NOT_READY);

    releaseInner!({ id: NEW_ID, recordB64: RECORD_B64 });
    const firstResult = await first;
    expect(firstResult.ok).toBe(true);
  });
});

describe("changeGlobalKey — 后端单命令薄封装", () => {
  function setupOldState(): void {
    keyState.globalKeyRecordB64.value = OLD_RECORD_B64;
    keyState.globalKeyRecordId.value = OLD_ID;
    keyState.hasGlobalKeyRecord.value = true;
    keyState.globalKeyReady.value = true;
  }

  function expectMappedError(errorCode: string, expected: VerthysErrorCode) {
    setupOldState();
    const error = Object.assign(new Error("boom"), { errorCode });
    vi.mocked(verthysLib.verthysChangeGlobalKey).mockRejectedValue(error);
    return changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    ).then((result) => {
      expectErr(result, expected);
      expect(keyState.globalKeyRecordId.value).toBe(OLD_ID);
    });
  }

  it("成功路径：单命令调用、状态同步、旧 id 缓存失效", async () => {
    setupOldState();

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.cleanupPending).toBe(false);
    expect(verthysLib.verthysChangeGlobalKey).toHaveBeenCalledWith(
      PWD, "BIN_B64", BIN_PWD, "new-p@ss-9", "BIN_B64", "new-bin",
    );
    expect(keyState.globalKeyRecordB64.value).toBe(NEW_RECORD_B64);
    expect(keyState.globalKeyRecordId.value).toBe(NEW_ID);
    expect(cacheLib.invalidateSummaryRecord).toHaveBeenCalledWith(OLD_ID);
    expect(cacheLib.invalidateScannedRecord).toHaveBeenCalledWith(OLD_ID);
    expect(sessionLib.resetSessionTimer).toHaveBeenCalled();
    // 前端不再做多步编排
    expect(verthysLib.verthysAddRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysDeleteRecord).not.toHaveBeenCalled();
  });

  it("cleanup_pending=true：成功并携带清理标记", async () => {
    setupOldState();
    vi.mocked(verthysLib.verthysChangeGlobalKey).mockResolvedValue({
      id: NEW_ID,
      recordB64: NEW_RECORD_B64,
      deletedIds: [],
      cleanupPending: true,
    });

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.cleanupPending).toBe(true);
    expect(keyState.globalKeyRecordId.value).toBe(NEW_ID);
  });

  it("旧钥错误 → E_GLOBAL_KEY_VERIFY_FAILED", async () => {
    await expectMappedError("E_GLOBAL_KEY_VERIFY_FAILED", VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED);
  });

  it("记录缺失 → E_GLOBAL_KEY_RECORD_NOT_FOUND", async () => {
    await expectMappedError("E_GLOBAL_KEY_RECORD_NOT_FOUND", VerthysErrorCode.E_GLOBAL_KEY_RECORD_NOT_FOUND);
  });

  it("落盘失败 → E_GLOBAL_KEY_PERSIST_FAILED", async () => {
    await expectMappedError("E_GLOBAL_KEY_PERSIST_FAILED", VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
  });

  it("结果未确认 → E_GLOBAL_KEY_CHANGE_UNCONFIRMED", async () => {
    await expectMappedError(
      "E_GLOBAL_KEY_CHANGE_UNCONFIRMED",
      VerthysErrorCode.E_GLOBAL_KEY_CHANGE_UNCONFIRMED,
    );
  });

  it("限流 → E_RATE_LIMITED 且保留 retryAfterSecs", async () => {
    setupOldState();
    const error = Object.assign(new Error("locked"), {
      errorCode: "E_RATE_LIMITED",
      retryAfterSecs: 7,
    });
    vi.mocked(verthysLib.verthysChangeGlobalKey).mockRejectedValue(error);

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expectErr(result, VerthysErrorCode.E_RATE_LIMITED);
    if (!result.ok) expect(result.retryAfterSecs).toBe(7);
  });

  it("并发调用被互斥锁拒绝", async () => {
    let releaseInner: ((v: {
      id: number;
      recordB64: string;
      deletedIds: number[];
      cleanupPending: boolean;
    }) => void) | null = null;
    vi.mocked(verthysLib.verthysChangeGlobalKey).mockImplementation(
      () => new Promise((resolve) => {
        releaseInner = resolve;
      }),
    );

    const first = changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );
    const second = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );
    expectErr(second, VerthysErrorCode.E_VERTHYS_NOT_READY);

    releaseInner!({
      id: NEW_ID,
      recordB64: NEW_RECORD_B64,
      deletedIds: [],
      cleanupPending: false,
    });
    const firstResult = await first;
    expect(firstResult.ok).toBe(true);
  });
});

describe("全局密钥记录解析 — 最新有效记录权威", () => {
  const VALID_RECORD = btoa("x".repeat(124));

  function setupVerify(): void {
    keyState.verthysReady.value = true;
    keyState.globalKeyRecordB64.value = "";
    keyState.globalKeyRecordId.value = 0;
  }

  it("多记录取最大 id，并缓存最新记录", async () => {
    setupVerify();
    vi.mocked(verthysLib.verthysListIdsByType).mockResolvedValue({ ids: [3, 5], exhausted: true });
    vi.mocked(verthysLib.verthysGetRecord).mockImplementation(async (id: number) => {
      if (id === 3 || id === 5) {
        return { type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: VALID_RECORD };
      }
      return null;
    });

    const result = await verifyGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expect(result.ok).toBe(true);
    expect(verthysLib.verthysVerifyGlobalKey).toHaveBeenCalledWith(
      PWD, "BIN_B64", BIN_PWD, VALID_RECORD,
    );
    expect(keyState.globalKeyRecordId.value).toBe(5);
  });

  it("忽略非全局密钥记录（名称/长度不符）", async () => {
    setupVerify();
    vi.mocked(verthysLib.verthysListIdsByType).mockResolvedValue({ ids: [1, 2, 3], exhausted: true });
    vi.mocked(verthysLib.verthysGetRecord).mockImplementation(async (id: number) => {
      if (id === 1) {
        return { type: TYPE_GLOBAL_KEY, name: "account", dataB64: VALID_RECORD };
      }
      if (id === 2) {
        return { type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: btoa("short") };
      }
      if (id === 3) {
        return { type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: VALID_RECORD };
      }
      return null;
    });

    const result = await verifyGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expect(result.ok).toBe(true);
    expect(keyState.globalKeyRecordId.value).toBe(3);
  });

  it("类型索引不可用 → 回退全量枚举", async () => {
    setupVerify();
    vi.mocked(verthysLib.verthysListIdsByType).mockRejectedValue(new Error("index down"));
    vi.mocked(verthysLib.verthysEnumerateRecords).mockResolvedValue([
      { id: 9, type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: VALID_RECORD },
    ]);
    vi.mocked(verthysLib.verthysGetRecord).mockImplementation(async (id: number) => {
      if (id === 9) {
        return { type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: VALID_RECORD };
      }
      return null;
    });

    const result = await verifyGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expect(result.ok).toBe(true);
    expect(keyState.globalKeyRecordId.value).toBe(9);
  });

  it("无有效记录 → E_GLOBAL_KEY_RECORD_NOT_FOUND", async () => {
    setupVerify();
    vi.mocked(verthysLib.verthysListIdsByType).mockResolvedValue({ ids: [], exhausted: true });

    const result = await verifyGlobalKey(PWD, BIN_BYTES, BIN_PWD);

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_RECORD_NOT_FOUND);
  });
});