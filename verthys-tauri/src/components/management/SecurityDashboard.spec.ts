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
  securityPresetCode: 1,
  presetApplying: false,
  presetAmbienceMode: "secure",
  cpuOverhead: 12,
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
  customPanelOpen: false,
  presetSyncFailed: false,
  defensePaths: [
    {
      key: "suspend_bypass",
      label: "挂起绕过",
      desc: "管理员调试挂起绕过防护",
      state: 1,
      stateLabel: "已阻断",
      stateClass: "blocked",
    },
  ],
  defenseMeta: {
    blocked: 1,
    degraded: 0,
    failed: 0,
    unchecked: 6,
    allCriticalBlocked: true,
    stance: "ok" as const,
    stanceLabel: "关键路径全阻断",
  },
};

/** 挂载面板：以模型 ref 驱动 orbit-slider-pos 双向绑定 */
function mountDashboard(model: Ref<number>) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const Root = defineComponent({
    setup() {
      return () =>
        h(SecurityDashboard, {
          ...baseProps,
          orbitSliderPos: model.value,
          "onUpdate:orbitSliderPos": (v: number) => {
            model.value = v;
          },
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
});