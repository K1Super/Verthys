// @vitest-environment happy-dom
/*
 * security-session.spec.ts — 会话安全层回归
 *
 * 覆盖：
 *   1. 标准档恢复：受信档位应用后前端状态/会话超时同步
 *   2. 迁移路径：localStorage 迁移后保留为只读缓存（不删键）
 *   3. 竞态仲裁：恢复读取期间与恢复应用入口的 epoch 双重校验
 *   4. 自定义档：超时取档位常量、空闲锁定随特性开关启停
 *   5. 空闲锁定关闭时不武装自动锁定计时器；恢复启用后重新武装
 *   6. 空闲锁定由真实输入活动驱动：活动刷新截止时间，未空闲不得到点锁定
 *
 * 依赖隔离：lib/verthys（IPC 面）、缓存组合层、后台任务全部 mock；
 * key_state（真实 ref）/ 常量 / promise_utils 使用真实实现。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { keyState } from "../state/key_state";
import { SECURITY_PRESET_KEY, CUSTOM_FEATURES_KEY, PRESET_SESSION_TIMEOUT_MS, CUSTOM_SESSION_MINUTES_DEFAULT } from "../constants/key_manager_const";
import {
  applySecurityPreset,
  restoreSecurityPreset,
  bumpPresetEpoch,
  setSessionTimeout,
  getSessionTimeout,
  isSessionLockEnabled,
  clearSessionTimer,
  resetSessionTimer,
  sessionIdleDeadlineRef,
  lockAll,
} from "./security-session";

const mocks = vi.hoisted(() => ({
  securityApplyPreset: vi.fn(),
  securityLoadPresetState: vi.fn(),
  securitySessionSetHardening: vi.fn(),
  securitySessionStart: vi.fn(),
  securitySessionStop: vi.fn(),
  securityBruteCheck: vi.fn(),
  securityBruteClearPurge: vi.fn(),
  securityBruteStatus: vi.fn(),
  verthysClearGlobalKey: vi.fn(),
  verthysLock: vi.fn(),
  verthysLockPersist: vi.fn(),
  workerDestroy: vi.fn(),
  waitForFlush: vi.fn(),
  clearAllCacheTimers: vi.fn(),
  clearModuleKeyCache: vi.fn(),
  clearModuleCache: vi.fn(),
  clearRecordScanCache: vi.fn(),
  clearSummaryCache: vi.fn(),
  clearFullRecordCache: vi.fn(),
  cancelDebouncedFlush: vi.fn(),
  resetFlushChain: vi.fn(),
  setCacheDirty: vi.fn(),
  isCacheDirty: vi.fn(),
  startBackgroundTasks: vi.fn(),
  stopBackgroundTasks: vi.fn(),
}));

vi.mock("../lib/verthys", () => ({
  securityBruteCheck: mocks.securityBruteCheck,
  securityBruteClearPurge: mocks.securityBruteClearPurge,
  securityBruteStatus: mocks.securityBruteStatus,
  securitySessionStart: mocks.securitySessionStart,
  securitySessionStop: mocks.securitySessionStop,
  securitySessionSetHardening: mocks.securitySessionSetHardening,
  securityApplyPreset: mocks.securityApplyPreset,
  securityLoadPresetState: mocks.securityLoadPresetState,
  verthysClearGlobalKey: mocks.verthysClearGlobalKey,
  verthysLock: mocks.verthysLock,
  verthysLockPersist: mocks.verthysLockPersist,
  workerDestroy: mocks.workerDestroy,
}));

vi.mock("../cache/composition/verthys-cache", () => ({
  clearModuleKeyCache: mocks.clearModuleKeyCache,
  clearModuleCache: mocks.clearModuleCache,
  clearRecordScanCache: mocks.clearRecordScanCache,
  cancelDebouncedFlush: mocks.cancelDebouncedFlush,
  resetFlushChain: mocks.resetFlushChain,
  waitForFlush: mocks.waitForFlush,
  clearAllCacheTimers: mocks.clearAllCacheTimers,
  setCacheDirty: mocks.setCacheDirty,
  isCacheDirty: mocks.isCacheDirty,
  clearSummaryCache: mocks.clearSummaryCache,
  clearFullRecordCache: mocks.clearFullRecordCache,
}));

vi.mock("../core/background-tasks", () => ({
  startBackgroundTasks: mocks.startBackgroundTasks,
  stopBackgroundTasks: mocks.stopBackgroundTasks,
}));

/** 全开特性快照（与 PresetFeatures 字段一一对应） */
function allTrue() {
  return {
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
  };
}

/** 标准档后端返回的权威配置 */
function presetConfig(code: number) {
  return { name: ["BALANCED", "SECURE", "PERFORMANCE"][code] ?? "UNKNOWN", code, features: allTrue() };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.isCacheDirty.mockReturnValue(false);
  localStorage.clear();
  keyState.securityPreset.value = 0;
  keyState.globalKeyReady.value = true;
  keyState.customSessionMinutes.value = CUSTOM_SESSION_MINUTES_DEFAULT;
  setSessionTimeout(PRESET_SESSION_TIMEOUT_MS[0]);
  clearSessionTimer();
  mocks.securityApplyPreset.mockImplementation(async (code: number) => presetConfig(code));
  mocks.securitySessionSetHardening.mockResolvedValue(true);
  mocks.securityLoadPresetState.mockResolvedValue({ state: null, persistDirty: false });
  mocks.waitForFlush.mockResolvedValue(undefined);
  mocks.clearRecordScanCache.mockReturnValue(undefined);
});

afterEach(() => {
  clearSessionTimer();
  vi.useRealTimers();
});

describe("标准档应用与恢复", () => {
  it("应用安全档：前端档位/会话超时同步为 10 分钟", async () => {
    await applySecurityPreset(1);
    expect(mocks.securityApplyPreset).toHaveBeenCalledWith(1);
    expect(keyState.securityPreset.value).toBe(1);
    expect(getSessionTimeout()).toBe(PRESET_SESSION_TIMEOUT_MS[1]);
    expect(isSessionLockEnabled()).toBe(true);
  });

  it("恢复链以受信档位为准并应用", async () => {
    mocks.securityLoadPresetState.mockResolvedValue({ state: { code: 1 }, persistDirty: false });
    await restoreSecurityPreset();
    expect(mocks.securityApplyPreset).toHaveBeenCalledWith(1);
    expect(keyState.securityPreset.value).toBe(1);
  });

  it("恢复链：读取期间用户已切换 → 放弃恢复结果", async () => {
    mocks.securityLoadPresetState.mockImplementation(async () => {
      bumpPresetEpoch();
      return { state: { code: 1 }, persistDirty: false };
    });
    await restoreSecurityPreset();
    expect(mocks.securityApplyPreset).not.toHaveBeenCalled();
  });

  it("持久化不一致标记透传到恢复报告（供上层可见提示）", async () => {
    mocks.securityLoadPresetState.mockResolvedValue({ state: null, persistDirty: true });
    const report = await restoreSecurityPreset();
    expect(report.persistDirty).toBe(true);
  });

  it("应用入口仲裁：恢复结果被用户切换超越 → 放弃应用（返回 null）", async () => {
    bumpPresetEpoch();
    const config = await applySecurityPreset(1, 0);
    expect(config).toBeNull();
    expect(mocks.securityApplyPreset).not.toHaveBeenCalled();
  });
});

describe("迁移路径缓存保留", () => {
  it("localStorage 迁移后保留为只读缓存（不删键）", async () => {
    mocks.securityLoadPresetState.mockResolvedValue({ state: null, persistDirty: false });
    localStorage.setItem(SECURITY_PRESET_KEY, "2");
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify(allTrue()));

    await restoreSecurityPreset();

    expect(mocks.securityApplyPreset).toHaveBeenCalledWith(2);
    expect(keyState.securityPreset.value).toBe(2);
    // 缓存保留：清键会造成下次启动前端初值退化，进而存在覆盖受信副本的路径
    expect(localStorage.getItem(SECURITY_PRESET_KEY)).toBe("2");
    expect(localStorage.getItem(CUSTOM_FEATURES_KEY)).not.toBeNull();
  });

  it("两端均无：应用默认平衡档建立权威副本", async () => {
    mocks.securityLoadPresetState.mockResolvedValue({ state: null, persistDirty: false });
    await restoreSecurityPreset();
    expect(mocks.securityApplyPreset).toHaveBeenCalledWith(0);
    expect(keyState.securityPreset.value).toBe(0);
  });
});

describe("自定义档会话语义", () => {
  it("空闲锁定开启：超时取自定义档常量、剪贴板监听随开关启用", async () => {
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify({ ...allTrue(), session_lock_on_idle: true, clip_clear_on_lock: true }));
    await applySecurityPreset(3);
    expect(getSessionTimeout()).toBe(PRESET_SESSION_TIMEOUT_MS[3]);
    expect(isSessionLockEnabled()).toBe(true);
    // 自定义档不暴露挂起锁定；剪贴板监听由专用开关控制
    expect(mocks.securitySessionSetHardening).toHaveBeenCalledWith(false, true);
  });

  it("空闲锁定关闭：开关关闭但剪贴板监听不受牵连（两能力解耦）", async () => {
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify({ ...allTrue(), session_lock_on_idle: false, clip_clear_on_lock: true }));
    await applySecurityPreset(3);
    expect(isSessionLockEnabled()).toBe(false);
    // 关键断言：关闭空闲锁定不得同时关闭剪贴板监听（旧实现为单一布尔合并）
    expect(mocks.securitySessionSetHardening).toHaveBeenCalledWith(false, true);
  });

  it("从自定义关闭状态切回标准档：空闲锁定恢复启用", async () => {
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify({ ...allTrue(), session_lock_on_idle: false }));
    await applySecurityPreset(3);
    expect(isSessionLockEnabled()).toBe(false);

    await applySecurityPreset(0);
    expect(isSessionLockEnabled()).toBe(true);
    expect(getSessionTimeout()).toBe(PRESET_SESSION_TIMEOUT_MS[0]);
  });

  it("自定义档空闲锁定时长按用户设置生效并随应用落盘", async () => {
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify({ ...allTrue(), session_lock_on_idle: true }));
    keyState.customSessionMinutes.value = 45;

    await applySecurityPreset(3);

    expect(getSessionTimeout()).toBe(45 * 60_000);
    expect(mocks.securityApplyPreset).toHaveBeenCalledWith(3, expect.anything(), 45);
  });

  it("恢复链采用后端受信的空闲锁定时长（覆盖本地缓存）", async () => {
    keyState.customSessionMinutes.value = 20;
    mocks.securityLoadPresetState.mockResolvedValue({
      state: { code: 3, customFeatures: allTrue(), customSessionTimeoutMinutes: 50 },
      persistDirty: false,
    });

    await restoreSecurityPreset();

    expect(getSessionTimeout()).toBe(50 * 60_000);
    expect(keyState.customSessionMinutes.value).toBe(50);
  });
});

describe("lockAll 重入与代际闸门", () => {
  it("并发重入：只跑一条真实销毁链，两方均等待其完成", async () => {
    mocks.verthysLockPersist.mockResolvedValue(undefined);
    mocks.verthysLock.mockResolvedValue(undefined);
    mocks.workerDestroy.mockResolvedValue(undefined);

    const first = lockAll();
    const second = lockAll();
    await Promise.all([first, second]);

    // 第二次调用必须等待第一次的真实工作，不得并行启动第二条销毁链
    expect(mocks.verthysLockPersist).toHaveBeenCalledTimes(1);
    expect(mocks.workerDestroy).toHaveBeenCalledTimes(1);
  });

  it("闸门释放：前一序列完成后可再次完整锁定", async () => {
    mocks.verthysLockPersist.mockResolvedValue(undefined);
    mocks.verthysLock.mockResolvedValue(undefined);
    mocks.workerDestroy.mockResolvedValue(undefined);

    await lockAll();
    await lockAll();

    expect(mocks.verthysLockPersist).toHaveBeenCalledTimes(2);
    expect(mocks.workerDestroy).toHaveBeenCalledTimes(2);
  });

  it("干净锁库返回可安装结果", async () => {
    mocks.waitForFlush.mockResolvedValue(undefined);
    mocks.verthysClearGlobalKey.mockResolvedValue(undefined);
    mocks.verthysLockPersist.mockResolvedValue(undefined);
    mocks.securitySessionStop.mockResolvedValue(undefined);
    mocks.verthysLock.mockResolvedValue(undefined);
    mocks.workerDestroy.mockResolvedValue(undefined);

    const outcome = await lockAll();

    expect(outcome).toMatchObject({ clean: true, flushed: true, dirty: false });
    expect(outcome.errors).toEqual([]);
  });

  it("脏缓存返回不可安装结果", async () => {
    mocks.isCacheDirty.mockReturnValue(true);

    const outcome = await lockAll();

    expect(outcome.clean).toBe(false);
    expect(outcome.dirty).toBe(true);
  });
});

describe("空闲锁定计时器武装", () => {
  it("关闭状态下不武装：计时器到点不触发锁定", async () => {
    vi.useFakeTimers();
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify({ ...allTrue(), session_lock_on_idle: false }));
    await applySecurityPreset(3);

    resetSessionTimer();
    await vi.advanceTimersByTimeAsync(PRESET_SESSION_TIMEOUT_MS[3] + 1000);
    // 未武装计时器：锁定链路（落盘等待）不应被触发
    expect(mocks.waitForFlush).not.toHaveBeenCalled();
  });

  it("启用状态下武装：计时器到点触发锁定链路", async () => {
    vi.useFakeTimers();
    await applySecurityPreset(1);

    resetSessionTimer();
    await vi.advanceTimersByTimeAsync(PRESET_SESSION_TIMEOUT_MS[1] + 1000);
    expect(mocks.waitForFlush).toHaveBeenCalled();
  });
});

describe("空闲锁定的活动驱动语义", () => {
  it("真实输入活动刷新截止时间：未空闲时到点不得锁定", async () => {
    vi.useFakeTimers();
    await applySecurityPreset(1);
    const armedDeadline = sessionIdleDeadlineRef.value;
    expect(armedDeadline).toBeGreaterThan(0);

    // 到点前 1 秒产生真实输入（指针活动）
    await vi.advanceTimersByTimeAsync(PRESET_SESSION_TIMEOUT_MS[1] - 1000);
    window.dispatchEvent(new Event("pointerdown"));

    // 活动已把空闲起点前移：截止时间必须同步后移
    expect(sessionIdleDeadlineRef.value).toBeGreaterThan(armedDeadline);

    // 原截止时刻已过：用户未空闲，不得锁定
    await vi.advanceTimersByTimeAsync(1500);
    expect(mocks.waitForFlush).not.toHaveBeenCalled();

    // 新截止时间到点且期间无任何输入 → 才允许锁定
    await vi.advanceTimersByTimeAsync(PRESET_SESSION_TIMEOUT_MS[1]);
    expect(mocks.waitForFlush).toHaveBeenCalled();
  });

  it("锁定/解除武装：截止时间清零（UI 据此复位显示）", async () => {
    vi.useFakeTimers();
    await applySecurityPreset(0);
    expect(sessionIdleDeadlineRef.value).toBeGreaterThan(0);

    clearSessionTimer();
    expect(sessionIdleDeadlineRef.value).toBe(0);
  });
});