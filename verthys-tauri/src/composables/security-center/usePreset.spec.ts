/*
 * usePreset.spec.ts — 安全防护预设状态机回归
 *
 * 覆盖：
 *   1. 锚点播种：初始游标与激活锚点按后端权威档位推导（自定义档无锚点）
 *   2. 氛围迟滞：进入带 25/75、退出带 31/69 的收敛行为
 *   3. 释放守卫：切档进行中的释放请求回撤视觉且不重复切档
 *   4. 吸附路径复位拖拽标志（轨道渐变不冻结）
 *   5. 自定义档应用后的游标停靠与锚点清除
 *   6. 特性快照加载：标准档取后端、自定义档取本地
 *
 * 依赖隔离：keyManager 单例 ref 与 lib/verthys 全部 mock；
 * promise_utils / presetMetrics 使用真实实现。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { nextTick, ref } from "vue";
import { securityPresetRef, globalKeyReadyRef, customSessionMinutesRef } from "../../lib/keyManager";
import { usePreset } from "./usePreset";

const mocks = vi.hoisted(() => ({
  applySecurityPreset: vi.fn(),
  bumpPresetEpoch: vi.fn(),
  loadCustomFeatures: vi.fn(),
  saveCustomFeatures: vi.fn(),
  saveSecurityPreset: vi.fn(),
  isLockedFeature: vi.fn(),
  securityGetPresetConfig: vi.fn(),
  securityLoadPresetState: vi.fn(),
}));

vi.mock("../../lib/keyManager", async () => {
  const { ref } = await import("vue");
  return {
    securityPresetRef: ref(0),
    globalKeyReadyRef: ref(true),
    customSessionMinutesRef: ref(20),
    applySecurityPreset: mocks.applySecurityPreset,
    bumpPresetEpoch: mocks.bumpPresetEpoch,
    loadCustomFeatures: mocks.loadCustomFeatures,
    saveCustomFeatures: mocks.saveCustomFeatures,
    saveSecurityPreset: mocks.saveSecurityPreset,
    isLockedFeature: mocks.isLockedFeature,
  };
});

vi.mock("../../lib/verthys", () => ({
  securityGetPresetConfig: mocks.securityGetPresetConfig,
  securityLoadPresetState: mocks.securityLoadPresetState,
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
      limited: 0,
      failed: 0,
      unchecked: 7,
      allCriticalBlocked: false,
      stance: "pending" as const,
      stanceLabel: "待检测",
      stale: false,
      checkedAtMs: 0,
      checkedAtLabel: "",
    }),
    onSecurePresetApplied: vi.fn(),
  };
}

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  securityPresetRef.value = 0;
  globalKeyReadyRef.value = true;
  customSessionMinutesRef.value = 20;
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

describe("usePreset 高安全 PCR 引导", () => {
  it("安全档应用成功触发 PCR 引导；平衡档不触发", async () => {
    const options = stubOptions();
    const api = usePreset(options);

    mocks.applySecurityPreset.mockResolvedValueOnce({
      name: "SECURE",
      code: 1,
      features: allTrue(),
    });
    await api.onApplyPreset(1);
    expect(options.onSecurePresetApplied).toHaveBeenCalledTimes(1);

    mocks.applySecurityPreset.mockResolvedValueOnce({
      name: "BALANCED",
      code: 0,
      features: allTrue(),
    });
    await api.onApplyPreset(0);
    expect(options.onSecurePresetApplied).toHaveBeenCalledTimes(1);
  });
});

describe("usePreset 自定义档语义", () => {
  it("应用自定义档：游标停靠中位、清锚点", async () => {
    const api = usePreset(stubOptions());
    mocks.applySecurityPreset.mockImplementationOnce(async (code: number) => {
      securityPresetRef.value = code as 0 | 1 | 2 | 3;
      return { name: "CUSTOM", code, features: allTrue() };
    });

    const ok = await api.onApplyPreset(3);
    expect(ok).toBe(true);
    expect(api.orbitSliderPos.value).toBe(50);
    expect(api.activeAnchorIdx.value).toBe(-1);
    expect(api.presetAmbienceMode.value).toBe("balanced");
  });
});

describe("usePreset 自定义防护自动保存", () => {
  it("非自定义档切换开关：快照当前真实特性与真实时长后以自定义档保存", async () => {
    securityPresetRef.value = 1; // 高安全：空闲锁定 10 分钟
    const api = usePreset(stubOptions());
    await api.loadPresetConfig();
    mocks.applySecurityPreset.mockResolvedValueOnce({
      name: "CUSTOM",
      code: 3,
      features: { ...allTrue(), module_patrol: false },
    });

    await api.onToggleCustomFeature("module_patrol");

    expect(mocks.applySecurityPreset).toHaveBeenCalledWith(
      3,
      undefined,
      expect.objectContaining({ module_patrol: false, anti_debug: true }),
      10,
    );
    expect(api.customFeatures.value.module_patrol).toBe(false);
  });

  it("自动保存失败：自定义档回滚到最近一次已落盘配置并可见报错", async () => {
    securityPresetRef.value = 3;
    const options = stubOptions();
    const api = usePreset(options);
    await api.loadPresetConfig();
    mocks.applySecurityPreset.mockRejectedValueOnce(new Error("ipc down"));

    await api.onToggleCustomFeature("module_patrol");

    expect(api.customFeatures.value.module_patrol).toBe(true);
    expect(options.showError).toHaveBeenCalledWith("自定义防护保存失败");
  });

  it("非自定义档自动保存失败：草稿恢复为转换前模板", async () => {
    securityPresetRef.value = 1;
    const options = stubOptions();
    const api = usePreset(options);
    await api.loadPresetConfig();
    const before = { ...api.customFeatures.value };
    mocks.applySecurityPreset.mockRejectedValueOnce(new Error("ipc down"));

    await api.onToggleCustomFeature("module_patrol");

    expect(api.customFeatures.value).toEqual(before);
    expect(options.showError).toHaveBeenCalledWith("自定义防护保存失败");
  });

  it("恢复默认：全开 + 默认时长并自动保存", async () => {
    securityPresetRef.value = 3;
    const options = stubOptions();
    const api = usePreset(options);
    await api.loadPresetConfig();

    await api.onResetCustom();

    expect(mocks.applySecurityPreset).toHaveBeenCalledWith(
      3,
      undefined,
      expect.objectContaining({
        module_patrol: true,
        clip_clear_on_lock: true,
        trace_cleanup: true,
      }),
      60,
    );
    expect(options.showToast).toHaveBeenCalledWith("已恢复默认配置");
  });

  it("空闲锁定时长：越界收敛且停手后仅自动保存一次终值", async () => {
    vi.useFakeTimers();
    try {
      securityPresetRef.value = 3;
      const api = usePreset(stubOptions());
      await api.loadPresetConfig();

      api.onSetCustomSessionMinutes(0);
      expect(api.customSessionMinutes.value).toBe(1);
      api.onSetCustomSessionMinutes(99999);
      expect(api.customSessionMinutes.value).toBe(120);
      api.onSetCustomSessionMinutes(45.6);
      expect(api.customSessionMinutes.value).toBe(46);

      await vi.advanceTimersByTimeAsync(300);

      expect(mocks.applySecurityPreset).toHaveBeenCalledTimes(1);
      expect(mocks.applySecurityPreset).toHaveBeenCalledWith(
        3,
        undefined,
        expect.any(Object),
        46,
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("档位真实空闲时长与自定义档标识", () => {
    const api = usePreset(stubOptions());

    expect(api.isCustomPreset.value).toBe(false);
    expect(api.activeIdleMinutes.value).toBe(30); // 平衡

    securityPresetRef.value = 1;
    expect(api.activeIdleMinutes.value).toBe(10); // 高安全

    securityPresetRef.value = 2;
    expect(api.activeIdleMinutes.value).toBe(60); // 性能

    securityPresetRef.value = 3;
    expect(api.isCustomPreset.value).toBe(true);
    expect(api.activeIdleMinutes.value).toBe(20); // 自定义草稿
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

  it("核心防护文案映射真实能力：key_separation 显示 密钥隔离", () => {
    const api = usePreset(stubOptions());
    const item = api.lockedFeatures.value.find((f) => f.key === "key_separation");
    expect(item).toBeTruthy();
    expect(item?.label).toBe("密钥隔离");
    expect(item?.desc).toContain("密钥隔离堆");
    expect(item?.desc).not.toContain("三权分立");
  });

  it("自定义档取本地配置", async () => {
    securityPresetRef.value = 3;
    const api = usePreset(stubOptions());

    await api.loadPresetConfig();

    expect(mocks.securityGetPresetConfig).not.toHaveBeenCalled();
    expect(api.currentPresetFeatures.value.session_lock_on_idle).toBe(true);
  });

  it("加载失败 → presetSyncFailed 可见 + 错误提示（不得静默保留旧快照）", async () => {
    securityPresetRef.value = 1;
    const options = stubOptions();
    const api = usePreset(options);
    mocks.securityGetPresetConfig.mockRejectedValueOnce(new Error("ipc down"));

    const ok = await api.loadPresetConfig();

    expect(ok).toBe(false);
    expect(api.presetSyncFailed.value).toBe(true);
    expect(options.showError).toHaveBeenCalledWith(
      "安全预设配置加载失败，当前显示可能不准确",
    );
  });
});