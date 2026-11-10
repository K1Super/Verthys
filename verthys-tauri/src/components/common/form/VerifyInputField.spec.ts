// @vitest-environment happy-dom
/*
 * VerifyInputField.spec.ts — 验证类密钥输入场契约
 *
 * 覆盖：
 *   1. 输入回传 v-model，回车提交
 *   2. 显隐端子切换明文；开始验证即收回明文并锁定端子
 *   3. 验证中渲染周缘星轨；失败时星轨停止并改走底缘红线 + 抖动
 *   4. 宿主关闭后收回明文显示
 *   5. 外部禁用与验证中一致锁定输入与显隐端子
 *
 * 星轨的帧门控与空闲治理由真实实现承担，本用例只校验输入场对外的
 * DOM 契约与状态应答，故对该层使用桩替身，避免测试环境无画布尺寸。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, reactive, type App } from "vue";
import VerifyInputField from "./VerifyInputField.vue";

const mocks = vi.hoisted(() => ({
  start: vi.fn(),
  stop: vi.fn(),
  requestExemption: vi.fn(() => ({ status: "granted", token: { id: 1 } })),
  releaseExemption: vi.fn(),
}));

vi.mock("../../../composables/useGlobalIdleScheduler", () => ({
  useGlobalIdleScheduler: () => ({ level: { value: "active" } }),
}));
vi.mock("../../../composables/useFrameGate", () => ({
  useFrameGate: () => ({ start: mocks.start, stop: mocks.stop }),
}));
vi.mock("../../../core/master-frame-loop", () => ({
  masterFrameLoop: {
    requestExemption: mocks.requestExemption,
    releaseExemption: mocks.releaseExemption,
  },
}));

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  vi.clearAllMocks();
});

interface State {
  modelValue: string;
  verifying: boolean;
  error: boolean;
  disabled: boolean;
  active: boolean;
}

function mount(initial: Partial<State> = {}) {
  const state = reactive<State>({
    modelValue: "",
    verifying: false,
    error: false,
    disabled: false,
    active: true,
    ...initial,
  });
  const onUpdate = vi.fn((value: string) => {
    state.modelValue = value;
  });
  const onSubmit = vi.fn();
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(VerifyInputField, {
        modelValue: state.modelValue,
        verifying: state.verifying,
        error: state.error,
        disabled: state.disabled,
        active: state.active,
        label: "恢复码",
        placeholder: "恢复码",
        "onUpdate:modelValue": onUpdate,
        onSubmit,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  return { state, onUpdate, onSubmit, container };
}

const field = (container: HTMLElement) => container.querySelector<HTMLElement>(".vif-field");
const input = (container: HTMLElement) => container.querySelector<HTMLInputElement>(".vif-input");
const eye = (container: HTMLElement) => container.querySelector<HTMLButtonElement>(".vif-eye");

describe("验证类密钥输入场", () => {
  it("输入回传 v-model，回车提交", () => {
    const { onUpdate, onSubmit, container } = mount();
    const el = input(container)!;

    el.value = "AAAA-BBBB-CCCC-DDDD";
    el.dispatchEvent(new Event("input"));
    expect(onUpdate).toHaveBeenCalledWith("AAAA-BBBB-CCCC-DDDD");

    el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(el.getAttribute("aria-label")).toBe("恢复码");
  });

  it("显隐端子切换明文；开始验证即收回明文并锁定端子", async () => {
    const { state, container } = mount();

    expect(input(container)?.type).toBe("password");
    eye(container)?.click();
    await nextTick();

    expect(input(container)?.type).toBe("text");
    expect(eye(container)?.getAttribute("aria-pressed")).toBe("true");

    state.verifying = true;
    await nextTick();

    expect(input(container)?.type).toBe("password");
    expect(eye(container)?.disabled).toBe(true);
  });

  it("验证中渲染周缘星轨；失败时星轨停止并改走底缘红线与抖动", async () => {
    const { state, container } = mount();

    state.verifying = true;
    await nextTick();
    await nextTick();

    expect(input(container)?.disabled).toBe(true);
    expect(container.querySelector(".vif-orbit-canvas")).not.toBeNull();

    state.error = true;
    await nextTick();

    expect(container.querySelector(".vif-orbit-canvas")).toBeNull();
    expect(field(container)?.classList.contains("vif-field--error")).toBe(true);
    expect(input(container)?.classList.contains("vif-input--error")).toBe(true);
  });

  it("宿主关闭后收回明文显示", async () => {
    const { state, container } = mount();

    eye(container)?.click();
    await nextTick();
    expect(input(container)?.type).toBe("text");

    state.active = false;
    await nextTick();

    expect(input(container)?.type).toBe("password");
  });

  it("外部禁用与验证中一致锁定输入与显隐端子", async () => {
    const { state, container } = mount();

    state.disabled = true;
    await nextTick();

    expect(input(container)?.disabled).toBe(true);
    expect(eye(container)?.disabled).toBe(true);
  });
});
