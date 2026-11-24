// @vitest-environment happy-dom
/*
 * display-settings.spec.ts — 显示设置域契约回归
 *
 * 覆盖：
 *   1. 默认值 / 局部合并 / 非法枚举回退 / 数值钳制 / 档位递增归一化
 *   2. 损坏 JSON、未知 schema、存储读写异常一律回退默认且不抛错
 *   3. 帧间隔派生（含无限制 = 0）与空闲档位解析边界
 *   4. 更新去重、持久化写入、恢复默认清除存储
 */
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import {
  DISPLAY_SETTINGS_STORAGE_KEY,
  activeFrameIntervalMs,
  clearStoredDisplaySettings,
  createDefaultDisplaySettings,
  displaySettings,
  frameIntervalMsForFps,
  frameIntervalMsForLevel,
  idleThresholdsMs,
  normalizeDisplaySettings,
  parseStoredDisplaySettings,
  readStoredDisplaySettings,
  resetDisplaySettings,
  resolveIdleLevel,
  tierFrameIntervalMs,
  updateDisplaySettings,
  writeStoredDisplaySettings,
  type DisplaySettingsStorage,
} from "./display-settings";

/** 可观测的存储替身：与 localStorage 的最小契约一致 */
function makeStorage(initial?: string): DisplaySettingsStorage & { has: (key: string) => boolean } {
  const map = new Map<string, string>();
  if (initial !== undefined) map.set(DISPLAY_SETTINGS_STORAGE_KEY, initial);
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
    },
    removeItem: (key) => {
      map.delete(key);
    },
    has: (key) => map.has(key),
  };
}

beforeEach(() => {
  window.localStorage.clear();
  resetDisplaySettings();
});

afterEach(() => {
  vi.restoreAllMocks();
  resetDisplaySettings();
  window.localStorage.clear();
});

describe("默认值与归一化", () => {
  it("默认值完整且不可被调用方互相污染", () => {
    const a = createDefaultDisplaySettings();
    const b = createDefaultDisplaySettings();
    expect(a).toEqual({
      schemaVersion: 1,
      activeFps: 120,
      tiers: {
        settling: { afterSec: 3, fps: 30 },
        idle: { afterSec: 10, fps: 5 },
        "deep-idle": { afterSec: 60, fps: 1 },
      },
    });
    a.tiers.settling.afterSec = 99;
    expect(b.tiers.settling.afterSec).toBe(3);
  });

  it("非对象输入回退默认值", () => {
    expect(normalizeDisplaySettings(null)).toEqual(createDefaultDisplaySettings());
    expect(normalizeDisplaySettings("bad")).toEqual(createDefaultDisplaySettings());
    expect(normalizeDisplaySettings([])).toEqual(createDefaultDisplaySettings());
  });

  it("非法交互态上限回退默认；白名单值原样保留", () => {
    expect(normalizeDisplaySettings({ activeFps: 144 }).activeFps).toBe(120);
    expect(normalizeDisplaySettings({ activeFps: "max" }).activeFps).toBe(120);
    expect(normalizeDisplaySettings({ activeFps: "unlimited" }).activeFps).toBe("unlimited");
    expect(normalizeDisplaySettings({ activeFps: 60 }).activeFps).toBe(60);
  });

  it("档位帧率只接受该档白名单，越界组合回退默认", () => {
    expect(normalizeDisplaySettings({ tiers: { "deep-idle": { fps: 60 } } }).tiers["deep-idle"].fps).toBe(1);
    expect(normalizeDisplaySettings({ tiers: { idle: { fps: 10 } } }).tiers.idle.fps).toBe(10);
    expect(normalizeDisplaySettings({ tiers: { settling: { fps: 5 } } }).tiers.settling.fps).toBe(30);
  });

  it("等待秒数取整并钳制到各档范围", () => {
    const normalized = normalizeDisplaySettings({
      tiers: { settling: { afterSec: 0 }, idle: { afterSec: 9999 }, "deep-idle": { afterSec: 2.6 } },
    });
    expect(normalized.tiers.settling.afterSec).toBe(1);
    expect(normalized.tiers.idle.afterSec).toBe(300);
    /* deep-idle 至少比空闲大 1 秒：301 在范围内，取 301 而非 3 */
    expect(normalized.tiers["deep-idle"].afterSec).toBe(301);
  });

  it("档位严格递增：冲突时向上级联", () => {
    const normalized = normalizeDisplaySettings({
      tiers: {
        settling: { afterSec: 20 },
        idle: { afterSec: 5 },
        "deep-idle": { afterSec: 10 },
      },
    });
    expect(normalized.tiers.settling.afterSec).toBe(20);
    expect(normalized.tiers.idle.afterSec).toBe(21);
    expect(normalized.tiers["deep-idle"].afterSec).toBe(22);
  });

  it("未知 schema 不猜测字段语义，整体回退默认", () => {
    expect(
      normalizeDisplaySettings({ schemaVersion: 2, activeFps: 30, tiers: { settling: { afterSec: 9 } } }),
    ).toEqual(createDefaultDisplaySettings());
  });
});

describe("持久化", () => {
  it("损坏 JSON 回退默认", () => {
    expect(parseStoredDisplaySettings("{bad")).toEqual(createDefaultDisplaySettings());
    expect(readStoredDisplaySettings(makeStorage("{bad"))).toEqual(createDefaultDisplaySettings());
  });

  it("写入后可完整读回归一化结果", () => {
    const storage = makeStorage();
    const settings = normalizeDisplaySettings({ activeFps: 60, tiers: { idle: { afterSec: 30 } } });
    writeStoredDisplaySettings(settings, storage);
    expect(storage.has(DISPLAY_SETTINGS_STORAGE_KEY)).toBe(true);
    expect(readStoredDisplaySettings(storage)).toEqual(settings);
  });

  it("存储读取抛错回退默认，写入抛错不向上冒泡", () => {
    const throwingRead: DisplaySettingsStorage = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {},
      removeItem: () => {},
    };
    expect(readStoredDisplaySettings(throwingRead)).toEqual(createDefaultDisplaySettings());

    const throwingWrite: DisplaySettingsStorage = {
      getItem: () => null,
      setItem: () => {
        throw new Error("quota");
      },
      removeItem: () => {},
    };
    expect(() => writeStoredDisplaySettings(createDefaultDisplaySettings(), throwingWrite)).not.toThrow();
  });

  it("恢复默认清除持久化键", () => {
    const storage = makeStorage();
    writeStoredDisplaySettings(normalizeDisplaySettings({ activeFps: 30 }), storage);
    clearStoredDisplaySettings(storage);
    expect(storage.has(DISPLAY_SETTINGS_STORAGE_KEY)).toBe(false);
  });
});

describe("运行时派生", () => {
  it("帧间隔按帧率派生，无限制为 0", () => {
    expect(frameIntervalMsForFps(120)).toBeCloseTo(8.333, 2);
    expect(frameIntervalMsForFps(60)).toBeCloseTo(16.667, 2);
    expect(frameIntervalMsForFps("unlimited")).toBe(0);
    expect(activeFrameIntervalMs()).toBeCloseTo(8.333, 2);
    expect(tierFrameIntervalMs("settling")).toBeCloseTo(33.333, 2);
    expect(frameIntervalMsForLevel("active")).toBeCloseTo(8.333, 2);
    expect(frameIntervalMsForLevel("deep-idle")).toBe(1000);
  });

  it("空闲阈值按设置派生", () => {
    expect(idleThresholdsMs()).toEqual({ settling: 3000, idle: 10000, "deep-idle": 60000 });
    updateDisplaySettings({ tiers: { settling: { afterSec: 5 }, idle: { afterSec: 20 } } });
    expect(idleThresholdsMs()).toEqual({ settling: 5000, idle: 20000, "deep-idle": 60000 });
  });

  it("空闲档位解析在阈值边界上确定性落档", () => {
    const thresholds = { settling: 3000, idle: 10000, "deep-idle": 60000 };
    expect(resolveIdleLevel(0, thresholds)).toBe("active");
    expect(resolveIdleLevel(2999, thresholds)).toBe("active");
    expect(resolveIdleLevel(3000, thresholds)).toBe("settling");
    expect(resolveIdleLevel(9999, thresholds)).toBe("settling");
    expect(resolveIdleLevel(10000, thresholds)).toBe("idle");
    expect(resolveIdleLevel(59999, thresholds)).toBe("idle");
    expect(resolveIdleLevel(60000, thresholds)).toBe("deep-idle");
  });
});

describe("更新与去重", () => {
  it("局部更新只改目标字段，其余保持", () => {
    updateDisplaySettings({ activeFps: 60 });
    expect(displaySettings.value.activeFps).toBe(60);
    expect(displaySettings.value.tiers.settling.afterSec).toBe(3);
  });

  it("同值更新不产生新快照，避免无意义重排与写入", () => {
    const first = updateDisplaySettings({ activeFps: 60 });
    const second = updateDisplaySettings({ activeFps: 60 });
    expect(second).toBe(first);
  });

  it("更新写入持久化，恢复默认回到默认并清除存储", () => {
    updateDisplaySettings({ activeFps: 30, tiers: { idle: { afterSec: 20 } } });
    const stored = window.localStorage.getItem(DISPLAY_SETTINGS_STORAGE_KEY);
    expect(stored).not.toBeNull();
    expect(JSON.parse(stored!)).toMatchObject({ activeFps: 30, tiers: { idle: { afterSec: 20 } } });

    resetDisplaySettings();
    expect(displaySettings.value.activeFps).toBe(120);
    expect(window.localStorage.getItem(DISPLAY_SETTINGS_STORAGE_KEY)).toBeNull();
  });

  it("级联归一化会同步修正后续档位", () => {
    updateDisplaySettings({ tiers: { settling: { afterSec: 25 } } });
    expect(displaySettings.value.tiers.settling.afterSec).toBe(25);
    expect(displaySettings.value.tiers.idle.afterSec).toBe(26);
    expect(displaySettings.value.tiers["deep-idle"].afterSec).toBe(60);
  });
});
