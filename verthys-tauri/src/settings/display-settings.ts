/**
 * display-settings.ts — 显示与性能设置唯一权威源
 *
 * 职责：
 *   - 定义可持久化的交互态帧率上限与空闲三档参数
 *   - 纯函数校验 / 归一化：非法枚举回退默认、越界钳制、档位严格递增
 *   - localStorage 读写与故障回退（隐私模式、容量不足、JSON 损坏均不抛错）
 *   - 向运行时暴露只读快照与帧间隔派生
 *
 * 约束：
 *   - 本模块不得导入业务层或组件层，避免把密钥链路拖入首屏
 *   - 帧间隔只在此处派生；消费方禁止复制常量或自行换算
 *   - 档位等待时间以「距上次交互」为基准，修改后由调度器按基准重算
 */
import { readonly, shallowRef } from "vue";

/** 全局空闲档位（含满帧态） */
export type IdleLevel = "active" | "settling" | "idle" | "deep-idle";

/** 空闲三档（active 由交互态上限单独表达） */
export type IdleTier = Exclude<IdleLevel, "active">;

/** 交互态帧率上限；unlimited = 跟随屏幕刷新率 */
export type ActiveFpsPreset = 30 | 60 | 120 | "unlimited";

/** 单档参数：等待秒数 + 目标帧率 */
export interface IdleTierSettings {
  afterSec: number;
  fps: number;
}

/** 持久化结构（schemaVersion 用于未来迁移，当前只接受 1） */
export interface DisplaySettings {
  schemaVersion: 1;
  activeFps: ActiveFpsPreset;
  tiers: Record<IdleTier, IdleTierSettings>;
}

/** 局部更新载荷：未提供的字段保持当前值 */
export interface DisplaySettingsPatch {
  activeFps?: ActiveFpsPreset;
  tiers?: Partial<Record<IdleTier, Partial<IdleTierSettings>>>;
}

/** 存储键（命名空间前缀防碰撞；版本号随 schema 同步） */
export const DISPLAY_SETTINGS_STORAGE_KEY = "Verthys:display-settings:v1";

/** 交互态默认上限：高刷屏下兼顾顺滑与功耗 */
const DEFAULT_ACTIVE_FPS: ActiveFpsPreset = 120;

/** 三档默认值：3s/30fps → 10s/5fps → 60s/1fps */
const DEFAULT_TIERS: Record<IdleTier, IdleTierSettings> = {
  settling: { afterSec: 3, fps: 30 },
  idle: { afterSec: 10, fps: 5 },
  "deep-idle": { afterSec: 60, fps: 1 },
};

/** 档位枚举顺序（归一化、遍历与设置面板选项的唯一顺序源） */
export const IDLE_TIERS: readonly IdleTier[] = ["settling", "idle", "deep-idle"];

/** 交互态上限白名单 */
export const ACTIVE_FPS_VALUES: readonly ActiveFpsPreset[] = [30, 60, 120, "unlimited"];

/** 各档允许的帧率集合：越界组合（如深度空闲 60fps）没有语义，拒绝暴露 */
export const TIER_FPS_VALUES: Record<IdleTier, readonly number[]> = {
  settling: [30, 60],
  idle: [5, 10, 30],
  "deep-idle": [1, 2, 5],
};

/** 各档等待秒数范围（上限同时承担误输入防护） */
export const TIER_AFTER_RANGE: Record<IdleTier, readonly [number, number]> = {
  settling: [1, 30],
  idle: [2, 300],
  "deep-idle": [5, 3600],
};

/** 档位之间的最小间隔（秒）：保证三档语义严格有序 */
const MIN_TIER_GAP_SEC = 1;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const clamp = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, value));

/** 整数秒：非有限数回退默认值，其余取整后钳制 */
const clampInt = (value: unknown, range: readonly [number, number], fallback: number): number => {
  const numeric = typeof value === "number" && Number.isFinite(value) ? Math.round(value) : fallback;
  return clamp(numeric, range[0], range[1]);
};

const cloneTier = (tier: IdleTier): IdleTierSettings => ({ ...DEFAULT_TIERS[tier] });

/** 默认值的独立副本：调用方共享同一份可变对象会污染默认值 */
export const createDefaultDisplaySettings = (): DisplaySettings => ({
  schemaVersion: 1,
  activeFps: DEFAULT_ACTIVE_FPS,
  tiers: {
    settling: cloneTier("settling"),
    idle: cloneTier("idle"),
    "deep-idle": cloneTier("deep-idle"),
  },
});

/** 只读快照（写入入口只有 updateDisplaySettings / resetDisplaySettings） */
const state = shallowRef<DisplaySettings>(createDefaultDisplaySettings());

/** 对外只读视图：组件按需订阅，运行时选择器直接读取当前快照 */
export const displaySettings = readonly(state);

/** 解析交互态上限：仅接受白名单，其余回退默认 */
function readActiveFps(value: unknown): ActiveFpsPreset {
  return ACTIVE_FPS_VALUES.includes(value as ActiveFpsPreset)
    ? (value as ActiveFpsPreset)
    : DEFAULT_ACTIVE_FPS;
}

/** 解析单档：字段级回退默认，避免一个坏字段拖垮整份设置 */
function readTier(raw: unknown, tier: IdleTier): IdleTierSettings {
  const fallback = DEFAULT_TIERS[tier];
  if (!isRecord(raw)) return cloneTier(tier);
  const allowedFps = TIER_FPS_VALUES[tier];
  const fps =
    typeof raw.fps === "number" && allowedFps.includes(raw.fps) ? raw.fps : fallback.fps;
  return {
    afterSec: clampInt(raw.afterSec, TIER_AFTER_RANGE[tier], fallback.afterSec),
    fps,
  };
}

/**
 * 归一化任意输入为合法设置。
 *
 * 顺序契约：settling < idle < deep-idle，且相邻至少 MIN_TIER_GAP_SEC。
 * 冲突时只向上级联，不试图猜测用户意图 —— 结果确定且可复现。
 */
export function normalizeDisplaySettings(input: unknown): DisplaySettings {
  const source = isRecord(input) ? input : {};
  /* 未知 schema 不猜测字段含义：直接回退默认，避免未来格式被误读 */
  if (source.schemaVersion !== undefined && source.schemaVersion !== 1) {
    return createDefaultDisplaySettings();
  }

  const tiersSource = isRecord(source.tiers) ? source.tiers : {};
  const settling = readTier(tiersSource.settling, "settling");
  const idle = readTier(tiersSource.idle, "idle");
  const deepIdle = readTier(tiersSource["deep-idle"], "deep-idle");

  idle.afterSec = clamp(
    Math.max(idle.afterSec, settling.afterSec + MIN_TIER_GAP_SEC),
    TIER_AFTER_RANGE.idle[0],
    TIER_AFTER_RANGE.idle[1],
  );
  deepIdle.afterSec = clamp(
    Math.max(deepIdle.afterSec, idle.afterSec + MIN_TIER_GAP_SEC),
    TIER_AFTER_RANGE["deep-idle"][0],
    TIER_AFTER_RANGE["deep-idle"][1],
  );

  return {
    schemaVersion: 1,
    activeFps: readActiveFps(source.activeFps),
    tiers: { settling, idle, "deep-idle": deepIdle },
  };
}

/** 解析持久化字符串：空值 / 损坏 / 未知版本均回退默认 */
export function parseStoredDisplaySettings(raw: string | null): DisplaySettings {
  if (!raw) return createDefaultDisplaySettings();
  try {
    return normalizeDisplaySettings(JSON.parse(raw));
  } catch {
    return createDefaultDisplaySettings();
  }
}

/** 可读写存储的最小契约（测试注入与浏览器 localStorage 共用） */
export type DisplaySettingsStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** 浏览器存储探测：隐私模式或禁用时返回 null，调用方保持内存态 */
function resolveStorage(): DisplaySettingsStorage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/** 读取持久化设置（故障时回退默认，绝不阻断启动） */
export function readStoredDisplaySettings(
  storage: DisplaySettingsStorage | null = resolveStorage(),
): DisplaySettings {
  if (!storage) return createDefaultDisplaySettings();
  try {
    return parseStoredDisplaySettings(storage.getItem(DISPLAY_SETTINGS_STORAGE_KEY));
  } catch {
    return createDefaultDisplaySettings();
  }
}

/** 写入持久化设置（失败只影响下次启动回退，不影响当前生效值） */
export function writeStoredDisplaySettings(
  settings: DisplaySettings,
  storage: DisplaySettingsStorage | null = resolveStorage(),
): void {
  if (!storage) return;
  try {
    storage.setItem(DISPLAY_SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch {
    /* 容量不足 / 隐私模式：当前会话继续使用内存态 */
  }
}

/** 清除持久化设置（恢复默认时调用） */
export function clearStoredDisplaySettings(
  storage: DisplaySettingsStorage | null = resolveStorage(),
): void {
  if (!storage) return;
  try {
    storage.removeItem(DISPLAY_SETTINGS_STORAGE_KEY);
  } catch {
    /* 清除失败不影响内存态恢复默认 */
  }
}

const isSameSettings = (a: DisplaySettings, b: DisplaySettings): boolean =>
  a.activeFps === b.activeFps &&
  IDLE_TIERS.every(
    (tier) =>
      a.tiers[tier].afterSec === b.tiers[tier].afterSec &&
      a.tiers[tier].fps === b.tiers[tier].fps,
  );

/**
 * 应用局部设置：归一化 → 去重 → 更新快照 → 同步持久化。
 *
 * 同步写入的理由：对象极小（数百字节），而防抖会在窗口隐藏/退出路径上
 * 丢失最后一次修改；设置属于用户显式操作，落盘即时性优先。
 */
export function updateDisplaySettings(patch: DisplaySettingsPatch): DisplaySettings {
  const current = state.value;
  const candidate = normalizeDisplaySettings({
    schemaVersion: 1,
    activeFps: patch.activeFps ?? current.activeFps,
    tiers: {
      settling: { ...current.tiers.settling, ...patch.tiers?.settling },
      idle: { ...current.tiers.idle, ...patch.tiers?.idle },
      "deep-idle": { ...current.tiers["deep-idle"], ...patch.tiers?.["deep-idle"] },
    },
  });

  if (isSameSettings(current, candidate)) return current;

  state.value = candidate;
  writeStoredDisplaySettings(candidate);
  return candidate;
}

/** 恢复默认：内存态立即生效，并清除持久化键 */
export function resetDisplaySettings(): DisplaySettings {
  const next = createDefaultDisplaySettings();
  state.value = next;
  clearStoredDisplaySettings();
  return next;
}

/** 按会话启动时的持久化值初始化（模块加载即完成，首帧之前） */
state.value = readStoredDisplaySettings();

/** 帧率 → 帧间隔（ms）；unlimited 返回 0 表示每个 rAF 帧都执行 */
export function frameIntervalMsForFps(fps: ActiveFpsPreset | number): number {
  return fps === "unlimited" ? 0 : 1000 / fps;
}

/** 交互态帧间隔（ms） */
export function activeFrameIntervalMs(): number {
  return frameIntervalMsForFps(state.value.activeFps);
}

/** 指定空闲档的帧间隔（ms） */
export function tierFrameIntervalMs(tier: IdleTier): number {
  return 1000 / state.value.tiers[tier].fps;
}

/** 任意空闲档位的帧间隔（ms）；active 走交互态上限 */
export function frameIntervalMsForLevel(level: IdleLevel): number {
  return level === "active" ? activeFrameIntervalMs() : tierFrameIntervalMs(level);
}

/** 三档等待阈值（ms），供空闲调度器按上次交互时刻重排 */
export function idleThresholdsMs(): Record<IdleTier, number> {
  return {
    settling: state.value.tiers.settling.afterSec * 1000,
    idle: state.value.tiers.idle.afterSec * 1000,
    "deep-idle": state.value.tiers["deep-idle"].afterSec * 1000,
  };
}

/**
 * 按「距上次交互的经过时长」解析应处档位。
 *
 * 抽成纯函数：调度器重排与测试共用同一判定，避免边界逻辑出现第二份。
 */
export function resolveIdleLevel(
  elapsedMs: number,
  thresholds: Record<IdleTier, number> = idleThresholdsMs(),
): IdleLevel {
  if (elapsedMs < thresholds.settling) return "active";
  if (elapsedMs < thresholds.idle) return "settling";
  if (elapsedMs < thresholds["deep-idle"]) return "idle";
  return "deep-idle";
}
