// @vitest-environment happy-dom
/*
 * SecurityDashboard.spec.ts — 面板视觉状态契约回归
 *
 * 覆盖：
 *   1. 挂载期播种：--pos/--posw 在挂载后立即等于权威游标位置
 *      （挂载前 immediate watch 无法写入，缺播种会导致重进面板回中位）
 *   2. 重挂载（模拟退出面板再进入）后指示不回落 CSS 默认中位
 *   3. 变更期同步：model 变化驱动 DOM 写入（含亮层 2% 量化口径）
 *
 * 依赖：happy-dom 提供 DOM；v-tip 以空指令注册（仅视觉提示，无行为依赖）
 */
import { describe, it, expect } from "vitest";
import { createApp, defineComponent, h, nextTick, ref, type Ref } from "vue";
import SecurityDashboard from "./SecurityDashboard.vue";

/** 面板 Props 基线（与本组件 defineProps 契约一一对应） */
const baseProps = {
  globalKeyReady: true,
  presetApplying: false,
  presetAmbienceMode: "secure",
  cpuUtilization: 12,
  securityCoverage: 80,
  overallScore: 70,
  ringCircumference: 2 * Math.PI * 50,
  ringDashOffset: (val: number) => val,
  orbitAnchors: [
    { pos: 0, label: "性能", code: 2 },
    { pos: 50, label: "平衡", code: 0 },
    { pos: 100, label: "安全", code: 1 },
  ],
  nearestAnchorIdx: 2,
  activeAnchorIdx: 2,
  orbitTrackGradient: { background: "linear-gradient(90deg, #000, #fff)" },
  toggleableFeatures: [{ key: "session_lock_on_idle", label: "空闲锁定", desc: "会话空闲超时自动锁定" }],
  lockedFeatures: [{ key: "anti_debug", label: "调试检测", desc: "调试器检测与反附加" }],
  presetFeatures: { anti_debug: true },
  customFeatures: { session_lock_on_idle: true },
  customMode: true,
  presetIdleMinutes: 10,
  customSessionMinutes: 10,
  presetSyncFailed: false,
  hardeningFailed: false,
  defensePaths: [
    {
      key: "suspend_bypass",
      label: "挂起绕过",
      desc: "管理员调试挂起绕过防护",
      state: 1,
      stateLabel: "已阻断",
      stateClass: "blocked",
      reason: 1,
      reasonLabel: "当前无驻留密钥",
      limited: false,
    },
  ],
  defenseMeta: {
    blocked: 1,
    degraded: 0,
    limited: 0,
    failed: 0,
    unchecked: 6,
    allCriticalBlocked: true,
    stance: "ok" as const,
    stanceLabel: "关键路径全阻断",
    stale: false,
    checkedAtMs: 1700000000000,
    checkedAtLabel: "12:00:00",
  },
  kernelStatus: null,
  kernelPolicyDegraded: false,
  kernelStatusPending: false,
};

/** 挂载面板：以模型 ref 驱动 orbit-slider-pos 双向绑定 */
function mountDashboard(
  model: Ref<number>,
  overrides: Record<string, unknown> = {},
  handlers: {
    setMinutes?: (minutes: number) => void;
    toggleFeature?: (key: string) => void;
  } = {},
) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const Root = defineComponent({
    setup() {
      return () =>
        h(SecurityDashboard, {
          ...baseProps,
          ...overrides,
          orbitSliderPos: model.value,
          "onUpdate:orbitSliderPos": (v: number) => {
            model.value = v;
          },
          onSetCustomSessionMinutes: handlers.setMinutes ?? (() => {}),
          onToggleCustomFeature: handlers.toggleFeature ?? (() => {}),
        });
    },
  });
  const app = createApp(Root);
  app.directive("tip", {});
  app.mount(container);
  return {
    app,
    container,
    teardown: () => {
      app.unmount();
      container.remove();
    },
  };
}

/** 读取测线元素的 CSS 变量（视觉位置的唯一载体） */
function readVar(container: HTMLElement, name: string): string {
  const track = container.querySelector(".bs-track") as HTMLElement | null;
  expect(track).not.toBeNull();
  return track!.style.getPropertyValue(name);
}

describe("SecurityDashboard 视觉状态契约", () => {
  it("挂载即播种：安全档位游标写入 100，亮层满点亮", () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model);
    try {
      expect(readVar(container, "--pos")).toBe("100.000");
      expect(readVar(container, "--posw")).toBe("100.00%");
    } finally {
      teardown();
    }
  });

  it("挂载即播种：性能档位游标写入 0", () => {
    const model = ref(0);
    const { teardown, container } = mountDashboard(model);
    try {
      expect(readVar(container, "--pos")).toBe("0.000");
      expect(readVar(container, "--posw")).toBe("0.00%");
    } finally {
      teardown();
    }
  });

  it("退出面板再进入（重挂载）不回中位：指示保持权威位置", () => {
    const model = ref(100);
    const first = mountDashboard(model);
    try {
      expect(readVar(first.container, "--pos")).toBe("100.000");
    } finally {
      first.teardown();
    }
    // 重新挂载同一权威位置（不改动模型值）：不得回落 CSS 默认中位
    const second = mountDashboard(model);
    try {
      expect(readVar(second.container, "--pos")).toBe("100.000");
      expect(readVar(second.container, "--posw")).toBe("100.00%");
    } finally {
      second.teardown();
    }
  });

  it("变更期同步：model 变化驱动写入，亮层按 2% 档位量化", async () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model);
    try {
      model.value = 25;
      await nextTick();
      expect(readVar(container, "--pos")).toBe("25.000");
      // 亮层量化口径：Math.round(25 / 2) * 2 = 26
      expect(readVar(container, "--posw")).toBe("26.00%");

      model.value = 0;
      await nextTick();
      expect(readVar(container, "--pos")).toBe("0.000");
      expect(readVar(container, "--posw")).toBe("0.00%");
    } finally {
      teardown();
    }
  });

  it("非自定义档：端子显示当前档位真实状态而非模板草稿", () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model, {
      customMode: false,
      presetIdleMinutes: 10,
      presetFeatures: { session_lock_on_idle: true },
      customFeatures: { session_lock_on_idle: false },
    });
    try {
      expect(container.querySelector(".cus-tag")?.textContent?.trim()).toBe("启用");
      expect(container.querySelector(".cus-count")?.textContent?.trim()).toBe("1/1");
      const toggle = container.querySelector(".cus-toggle") as HTMLButtonElement;
      expect(toggle.disabled).toBe(false);
      expect(toggle.getAttribute("aria-pressed")).toBe("true");
    } finally {
      teardown();
    }
  });

  it("在途应用：计数保持稳定，不切换为同步中", () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model, {
      presetApplying: true,
      customMode: true,
      customFeatures: { session_lock_on_idle: true },
    });
    try {
      expect(container.querySelector(".cus-count")?.textContent?.trim()).toBe("1/1");
    } finally {
      teardown();
    }
  });

  it("档位快照未确认：端子显示未确认且不可操作，不伪装成关闭", () => {
    const model = ref(0);
    const { teardown, container } = mountDashboard(model, {
      customMode: false,
      presetSyncFailed: true,
      presetFeatures: { session_lock_on_idle: false },
    });
    try {
      expect(container.querySelector(".cus-tag")?.textContent?.trim()).toBe("未确认");
      expect(container.querySelector(".cus-count")?.textContent?.trim()).toBe("未确认");
      const toggle = container.querySelector(".cus-toggle") as HTMLButtonElement;
      expect(toggle.disabled).toBe(true);
    } finally {
      teardown();
    }
  });

  it("非自定义档：空闲谱线展示当前档位真实时长而非模板草稿", () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model, {
      customMode: false,
      presetIdleMinutes: 10,
      customSessionMinutes: 45,
    });
    try {
      const track = container.querySelector(".cus-idle-track") as HTMLElement | null;
      expect(track?.getAttribute("aria-valuenow")).toBe("10");
      expect(track?.getAttribute("aria-valuetext")).toBe("10 分钟");
    } finally {
      teardown();
    }
  });

  it("内核加固：已启用状态显示，未安装状态不打扰用户", () => {
    const model = ref(100);
    const active = mountDashboard(model, {
      kernelStatus: {
        state: 3,
        reason: 0,
        capabilities: 3,
        protocol_major: 1,
        protocol_minor: 0,
      },
    });
    try {
      expect(active.container.textContent).toContain("内核加固 已启用");
    } finally {
      active.teardown();
    }

    const missing = mountDashboard(model, {
      kernelStatus: {
        state: 6,
        reason: 1,
        capabilities: 0,
        protocol_major: 0,
        protocol_minor: 0,
      },
    });
    try {
      expect(missing.container.textContent).not.toContain("内核加固");
    } finally {
      missing.teardown();
    }

    const degraded = mountDashboard(model, {
      kernelStatus: {
        state: 6,
        reason: 1,
        capabilities: 0,
        protocol_major: 0,
        protocol_minor: 0,
      },
      kernelPolicyDegraded: true,
    });
    try {
      expect(degraded.container.textContent).toContain("高安全 用户态降级");
      expect(degraded.container.textContent).toContain("驱动未安装");
    } finally {
      degraded.teardown();
    }

    /* 报告尚未到达：显示确认中，不得误报“用户态降级”。 */
    const pending = mountDashboard(model, {
      kernelStatus: null,
      kernelStatusPending: true,
    });
    try {
      expect(pending.container.textContent).toContain("内核加固 确认中");
      expect(pending.container.textContent).not.toContain("用户态降级");
    } finally {
      pending.teardown();
    }

    /* 宿主 REGISTER 失败但 worker 已自登记：驱动 ACTIVE，标签必须一致。 */
    const selfRegistered = mountDashboard(model, {
      kernelStatus: {
        state: 3,
        reason: 5,
        capabilities: 3,
        protocol_major: 1,
        protocol_minor: 0,
      },
      kernelPolicyDegraded: false,
    });
    try {
      expect(selfRegistered.container.textContent).toContain("内核加固 已启用");
      expect(selfRegistered.container.textContent).toContain("登记降级");
      expect(selfRegistered.container.textContent).not.toContain("用户态降级");
    } finally {
      selfRegistered.teardown();
    }
  });

  it("自定义防护：点击端子行切换特性，键盘调节空闲锁定时长", () => {
    const model = ref(100);
    const toggled: string[] = [];
    const minutes: number[] = [];
    const { teardown, container } = mountDashboard(model, {}, {
      toggleFeature: (key) => toggled.push(key),
      setMinutes: (value) => minutes.push(value),
    });
    try {
      const toggle = container.querySelector(".cus-toggle") as HTMLButtonElement | null;
      expect(toggle).not.toBeNull();
      toggle!.click();
      expect(toggled).toEqual(["session_lock_on_idle"]);

      const track = container.querySelector(".cus-idle-track") as HTMLElement | null;
      expect(track).not.toBeNull();
      track!.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
      expect(minutes).toEqual([11]);
      track!.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true }));
      expect(minutes).toEqual([11, 120]);
    } finally {
      teardown();
    }
  });

  it("CPU 占用：无有效样本显示「—」，不以 0 冒充", () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model, { cpuUtilization: null });
    try {
      const value = container.querySelector(".bs-star-value");
      expect(value?.textContent?.trim()).toBe("—");
      expect(value?.textContent).not.toContain("%");
    } finally {
      teardown();
    }
  });

  it("CPU 占用：有样本显示数值与单位", () => {
    const model = ref(100);
    const { teardown, container } = mountDashboard(model, { cpuUtilization: 12 });
    try {
      expect(container.querySelector(".bs-star-value")?.textContent?.trim()).toBe("12%");
    } finally {
      teardown();
    }
  });
});