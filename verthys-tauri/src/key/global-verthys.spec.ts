/*
 * key/global-verthys.spec.ts — 全局密钥编排回归测试
 *
 * 覆盖全局密钥落地失败根治后的三条路径与收口项：
 *   1. initGlobalKey：成功推进、AddRecord 失败、读回不一致、
 *      reconcile 失败、补偿动作自身失败（强制复位兜底）、重入互斥锁
 *   2. changeGlobalKey：先新后旧成功、删旧失败回滚、derive 失败补偿、
 *      旧密钥验证失败拦截、残留记录收敛、未预期异常兜底补偿
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
  verthysDeriveGlobalKey: vi.fn(),
  verthysDeriveAndStoreGlobalKey: vi.fn(),
  verthysVerifyGlobalKey: vi.fn(),
  verthysClearGlobalKey: vi.fn(),
  verthysResetGlobalKeyState: vi.fn(),
  verthysReconcileKeyPresence: vi.fn(),
  verthysGetRecord: vi.fn(),
  verthysEnumerateRecords: vi.fn(),
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
  findLidByTypeEarlyStop: vi.fn(),
  enqueueFlush: vi.fn(),
  flushVerthysNow: vi.fn(),
  ensureSummaryScan: vi.fn(),
  ensureRecordScan: vi.fn(),
}));

vi.mock("../session/security-session", () => ({
  resetSessionTimer: vi.fn(),
  clearSessionTimer: vi.fn(),
  applySecurityPreset: vi.fn(),
  checkBruteForceGate: vi.fn(),
  awaitLockAllIfInProgress: vi.fn(),
}));

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

vi.mock("../utils/logger", () => ({
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
import { initGlobalKey, changeGlobalKey } from "./global-verthys";
import { keyState, resetAllState } from "../state/key_state";
import { TYPE_GLOBAL_KEY } from "../constants/key_manager_const";
import { VerthysErrorCode } from "../lib/verthys_error";

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
  vi.mocked(verthysLib.verthysDeriveGlobalKey).mockResolvedValue(RECORD_B64);
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
      shadow_sleep: true,
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

describe("changeGlobalKey — 先新后旧与失败回滚", () => {
  /** 布置旧密钥验证与旧记录定位共用的成功前置 */
  function setupOldRecord(): void {
    keyState.globalKeyRecordB64.value = OLD_RECORD_B64;
    keyState.globalKeyRecordId.value = OLD_ID;
    vi.mocked(cacheLib.findLidByTypeEarlyStop).mockResolvedValue(OLD_ID);
    let oldDeleted = false;
    vi.mocked(verthysLib.verthysGetRecord).mockImplementation(async (id: number) => {
      if (id === NEW_ID) {
        return { type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: NEW_RECORD_B64 };
      }
      if (id === OLD_ID) {
        return oldDeleted
          ? null
          : { type: TYPE_GLOBAL_KEY, name: "global-key", dataB64: OLD_RECORD_B64 };
      }
      return null;
    });
    vi.mocked(verthysLib.verthysDeleteRecord).mockImplementation(async (id: number) => {
      if (id === OLD_ID) {
        oldDeleted = true;
      }
      return true;
    });
  }

  it("成功路径：先写新记录读回确认，再删旧记录读回确认删除生效", async () => {
    setupOldRecord();
    vi.mocked(verthysLib.verthysDeriveGlobalKey).mockResolvedValue(NEW_RECORD_B64);

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expect(result.ok).toBe(true);
    // 先新后旧：AddRecord 先于旧记录删除
    expect(verthysLib.verthysAddRecord).toHaveBeenCalledWith(TYPE_GLOBAL_KEY, "global-key", NEW_RECORD_B64);
    expect(verthysLib.verthysDeleteRecord).toHaveBeenCalledWith(OLD_ID);
    expect(verthysLib.verthysClearGlobalKey).not.toHaveBeenCalled();
    expect(keyState.globalKeyRecordB64.value).toBe(NEW_RECORD_B64);
    expect(keyState.globalKeyRecordId.value).toBe(NEW_ID);
  });

  it("旧密钥验证失败：拦截在派生之前，不触碰记录", async () => {
    keyState.globalKeyRecordB64.value = OLD_RECORD_B64;
    vi.mocked(verthysLib.verthysVerifyGlobalKey).mockResolvedValue(false);

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED);
    expect(verthysLib.verthysDeriveGlobalKey).not.toHaveBeenCalled();
    expect(verthysLib.verthysAddRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysDeleteRecord).not.toHaveBeenCalled();
  });

  it("删旧失败：回收新记录 + 清 GMK 回 Locked，磁盘回单条旧记录", async () => {
    setupOldRecord();
    vi.mocked(verthysLib.verthysDeriveGlobalKey).mockResolvedValue(NEW_RECORD_B64);
    vi.mocked(verthysLib.verthysDeleteRecord).mockImplementation(async (id: number) => {
      return id !== OLD_ID; // 新记录回收成功，旧记录删除失败
    });

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
    expect(verthysLib.verthysDeleteRecord).toHaveBeenCalledWith(NEW_ID);
    expect(verthysLib.verthysClearGlobalKey).toHaveBeenCalled();
    // 前端状态不推进
    expect(keyState.globalKeyRecordId.value).toBe(OLD_ID);
  });

  it("derive 新密钥失败：仅清 GMK 补偿，不产生任何记录写入", async () => {
    setupOldRecord();
    // 真实签名返回 Promise<string>；mock 以 null 表达 worker 派生失败
    vi.mocked(verthysLib.verthysDeriveGlobalKey).mockResolvedValue(null as unknown as string);

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED);
    expect(verthysLib.verthysAddRecord).not.toHaveBeenCalled();
    expect(verthysLib.verthysClearGlobalKey).toHaveBeenCalled();
  });

  it("收敛：历史中断残留的 global-key 记录被清除，目标记录保留", async () => {
    setupOldRecord();
    vi.mocked(verthysLib.verthysDeriveGlobalKey).mockResolvedValue(NEW_RECORD_B64);
    vi.mocked(verthysLib.verthysScanSummaryOpen).mockResolvedValue({
      records: [
        {
          id: 7,
          type: TYPE_GLOBAL_KEY,
          name: "global-key",
          dataSize: 124,
          physicalOffset: 65536,
          merkleLeaf: "leaf7",
          createdTime: 1,
        },
        {
          id: OLD_ID,
          type: TYPE_GLOBAL_KEY,
          name: "global-key",
          dataSize: 124,
          physicalOffset: 65660,
          merkleLeaf: "leaf42",
          createdTime: 1,
        },
      ],
      exhausted: true,
    });

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expect(result.ok).toBe(true);
    expect(verthysLib.verthysDeleteRecord).toHaveBeenCalledWith(7);
    expect(verthysLib.verthysDeleteRecord).toHaveBeenCalledWith(OLD_ID);
    expect(verthysLib.verthysScanSummaryClose).toHaveBeenCalled();
  });

  it("未预期异常：外层兜底补偿后按持久化失败上报", async () => {
    setupOldRecord();
    vi.mocked(verthysLib.verthysDeriveGlobalKey).mockResolvedValue(NEW_RECORD_B64);
    vi.mocked(verthysLib.verthysAddRecord).mockRejectedValue(new Error("unexpected ipc"));

    const result = await changeGlobalKey(
      PWD, BIN_BYTES, BIN_PWD,
      "new-p@ss-9", new Uint8Array([9]), "new-bin",
    );

    expectErr(result, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
    expect(verthysLib.verthysClearGlobalKey).toHaveBeenCalled();
  });
});