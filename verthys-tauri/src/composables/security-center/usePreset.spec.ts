/*
 * usePreset.spec.ts — 安全防护预设状态机回归
 *
 * 覆盖：
 *   1. 锚点播种：初始游标与激活锚点按后端权威档位推导（自定义档无锚点）
 *   2. 氛围迟滞：进入带 25/75、退出带 31/69 的收敛行为
 *   3. 释放守卫：切档进行中的释放请求回撤视觉且不重复切档
 *   4. 吸附路径复位拖拽标志（轨道渐变不冻结）
 *   5. 自定义档应用后的游标停靠与面板展开
 *   6. 特性快照加载：标准档取后端、自定义档取本地
 *
 * 依赖隔离：keyManager 单例 ref 与 lib/verthys 全部 mock；
 * promise_utils / presetMetrics 使用真实实现。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { nextTick, ref } from "vue";
import { securityPresetRef, globalKeyReadyRef } from "../../lib/keyManager";
import { usePreset } from "./usePreset";

const mocks = vi.hoisted(() => ({
  applySecurityPreset: vi.fn(),
  bumpPresetEpoch: vi.fn(),
  loadCustomFeatures: vi.fn(),
  saveCustomFeatures: vi.fn(),
  isLockedFeature: vi.fn(),
  securityGetPresetConfig: vi.fn(),
}));

vi.mock("../../lib/keyManager", async () => {
  const { ref } = await import("vue");
  return {
    securityPresetRef: ref(0),
    globalKeyReadyRef: ref(true),
    applySecurityPreset: mocks.applySecurityPreset,
    bumpPresetEpoch: mocks.bumpPresetEpoch,
    loadCustomFeatures: mocks.loadCustomFeatures,
    saveCustomFeatures: mocks.saveCustomFeatures,
    isLockedFeature: mocks.isLockedFeature,
  };
});

vi.mock("../../lib/verthys", () => ({
  securityGetPresetConfig: mocks.securityGetPresetConfig,
}));

/** 核心防护特性键（不可在自定义模板逐项关闭） */
const LOCKED_KEYS = [
  "anti_debug",
  "anti_inject",
  "integrity_check",
  "memory_guard",
  "key_separation",
  "emergency_response",
];

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

/** usePreset 依赖注入桩 */
function stubOptions() {
  return {
    showError: vi.fn(),
    showToast: vi.fn(),
    resetSession: vi.fn(),
    cpuUsage: ref(-1),
    defenseMeta: ref({
      blocked: 0,
      degraded: 0,
      failed: 0,
      unchecked: 7,
      allCriticalBlocked: false,
      stance: "pending" as const,
      stanceLabel: "待检测",
    }),
  };
}

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  securityPresetRef.value = 0;
  globalKeyReadyRef.value = true;
  mocks.applySecurityPreset.mockResolvedValue({ name: "BALANCED", code: 0, features: allTrue() });
  mocks.loadCustomFeatures.mockReturnValue(allTrue());
  mocks.isLockedFeature.mockImplementation((key: string) => LOCKED_KEYS.includes(key));
  mocks.securityGetPresetConfig.mockResolvedValue({ name: "BALANCED", code: 0, features: allTrue() });
  // 组合式函数在无组件实例环境下调用 onBeforeUnmount 会触发框架告警：此处仅屏蔽输出
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
});

describe("usePreset 锚点播种", () => {
  it("安全档：初始游标 100、激活锚点 2、最近锚点 2", () => {
    securityPresetRef.value = 1;
    const api = usePreset(stubOptions());
    expect(api.orbitSliderPos.value).toBe(100);
    expect(api.activeAnchorIdx.value).toBe(2);
    expect(api.nearestAnchorIdx.value).toBe(2);
  });

  it("性能档：初始游标 0、激活锚点 0", () => {
    securityPresetRef.value = 2;
    const api = usePreset(stubOptions());
    expect(api.orbitSliderPos.value).toBe(0);
    expect(api.activeAnchorIdx.value).toBe(0);
  });

  it("自定义档：停靠中位且无激活锚点", () => {
    securityPresetRef.value = 3;
    const api = usePreset(stubOptions());
    expect(api.orbitSliderPos.value).toBe(50);
    expect(api.activeAnchorIdx.value).toBe(-1);
  });
});

describe("usePreset 氛围迟滞", () => {
  it("进入带 25/75、退出带 31/69 逐步收敛", async () => {
    const api = usePreset(stubOptions());
    expect(api.presetAmbienceMode.value).toBe("balanced");

    api.orbitSliderPos.value = 24;
    await nextTick();
    expect(api.presetAmbienceMode.value).toBe("performance");

    api.orbitSliderPos.value = 26;
    await nextTick();
    // 退出带未达（需 > 31）：保持性能氛围，避免阈值附近切换风暴
    expect(api.presetAmbienceMode.value).toBe("performance");

    api.orbitSliderPos.value = 32;
    await nextTick();
    expect(api.presetAmbienceMode.value).toBe("balanced");

    api.orbitSliderPos.value = 76;
    await nextTick();
    expect(api.presetAmbienceMode.value).toBe("secure");

    api.orbitSliderPos.value = 69;
    await nextTick();
    // 安全氛围退出带为 < 69：69 不退出
    expect(api.presetAmbienceMode.value).toBe("secure");

    api.orbitSliderPos.value = 68;
    await nextTick();
    expect(api.presetAmbienceMode.value).toBe("balanced");
  });
});

describe("usePreset 吸附与守卫", () => {
  it("吸附路径复位拖拽标志并触发切档", async () => {
    const api = usePreset(stubOptions());
    api.onOrbitSliderInput();
    expect(api.orbitDragging.value).toBe(true);

    api.snapToAnchor(0);
    expect(api.orbitDragging.value).toBe(false);
    expect(mocks.applySecurityPreset).toHaveBeenCalledWith(2);
    await nextTick();
  });

  it("释放守卫：切档进行中释放回撤视觉且不重复切档", async () => {
    const api = usePreset(stubOptions());
    expect(api.orbitSliderPos.value).toBe(50);

    let release!: (v: unknown) => void;
    mocks.applySecurityPreset.mockImplementationOnce(
      () => new Promise((resolve) => { release = resolve; }),
    );

    api.snapToAnchor(2);
    expect(api.orbitSliderPos.value).toBe(100);
    expect(mocks.applySecurityPreset).toHaveBeenCalledTimes(1);

    api.onOrbitSliderInput();
    api.onOrbitSliderRelease();
    // 守卫路径：视觉回撤到权威位置（平衡档 50），且不得发起第二次切档
    expect(api.orbitSliderPos.value).toBe(50);
    expect(mocks.applySecurityPreset).toHaveBeenCalledTimes(1);

    release({ name: "SECURE", code: 1, features: allTrue() });
    await nextTick();
  });

  it("切档失败：视觉回撤到权威位置", async () => {
    const api = usePreset(stubOptions());
    mocks.applySecurityPreset.mockRejectedValueOnce(new Error("backend unavailable"));

    const ok = await api.onApplyPreset(1);
    expect(ok).toBe(false);
    expect(api.orbitSliderPos.value).toBe(50);
    expect(api.activeAnchorIdx.value).toBe(1);
  });
});

describe("usePreset 自定义档语义", () => {
  it("应用自定义档：游标停靠中位、清锚点、展开面板", async () => {
    const api = usePreset(stubOptions());
    mocks.applySecurityPreset.mockImplementationOnce(async (code: number) => {
      securityPresetRef.value = code as 0 | 1 | 2 | 3;
      return { name: "CUSTOM", code, features: allTrue() };
    });

    const ok = await api.onApplyPreset(3);
    expect(ok).toBe(true);
    expect(api.orbitSliderPos.value).toBe(50);
    expect(api.activeAnchorIdx.value).toBe(-1);
    expect(api.customPanelOpen.value).toBe(true);
    expect(api.presetAmbienceMode.value).toBe("balanced");
  });
});

describe("usePreset 特性快照加载", () => {
  it("标准档经后端拉取特性快照并与游标同位", async () => {
    securityPresetRef.value = 1;
    const api = usePreset(stubOptions());

    await api.loadPresetConfig();

    expect(mocks.securityGetPresetConfig).toHaveBeenCalledWith(1);
    expect(api.currentPresetFeatures.value.anti_debug).toBe(true);
    expect(api.orbitSliderPos.value).toBe(100);
  });

  it("自定义档取本地配置", async () => {
    securityPresetRef.value = 3;
    const api = usePreset(stubOptions());

    await api.loadPresetConfig();

    expect(mocks.securityGetPresetConfig).not.toHaveBeenCalled();
    expect(api.currentPresetFeatures.value.session_lock_on_idle).toBe(true);
  });
});