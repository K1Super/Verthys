// @vitest-environment happy-dom
/*
 * UnlockView.spec.ts — 解锁页恢复码入口与标题互斥契约
 *
 * 覆盖：
 *   - 已有容器（canRecover）→ 标题为“解锁安全存储”，存储框内出现恢复码图标入口
 *   - 无容器/新建（canRecover=false）→ 标题为“安全存储初始化”，不显示恢复入口
 *   - 解锁中隐藏存储框（含恢复入口）
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import UnlockView from "./UnlockView.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountView(overrides: Record<string, unknown> = {}) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(UnlockView, {
        verthysPath: "C:\\Vault.verthys",
        unlocking: false,
        unlockProgressMsg: "",
        unlockProgressElapsed: 0,
        initStatusRef: "ready",
        initDetailRef: "",
        isCreate: false,
        canRecover: true,
        ...overrides,
      }),
  });
  app.directive("tip", {});
  app.mount(container);
  mounted.push({ app, container });
  /* UnlockView 的 CosmicBackdrop 会 Teleport 到 body */
  return document.body;
}

function findRecoveryEntry(root: HTMLElement): Element | null {
  return root.querySelector('[aria-label="使用恢复码解锁"]');
}

describe("解锁页恢复码入口", () => {
  it("已有容器时标题切换为解锁并在存储框内显示恢复码图标入口", () => {
    const root = mountView();
    expect(root.textContent).toContain("解锁安全存储");
    expect(root.textContent).not.toContain("安全存储初始化");
    expect(root.textContent).toContain("已选择已有存储文件");
    expect(findRecoveryEntry(root)?.closest(".ps-actions")).not.toBeNull();
  });

  it("无容器或新建模式不显示恢复码入口", () => {
    const root = mountView({ canRecover: false, isCreate: true });
    expect(root.textContent).toContain("安全存储初始化");
    expect(findRecoveryEntry(root)).toBeNull();
  });

  it("解锁中隐藏恢复码入口", () => {
    const root = mountView({ unlocking: true });
    expect(findRecoveryEntry(root)).toBeNull();
  });

  it("恢复码弹窗提交期间抑制底层解锁进度", () => {
    const root = mountView({ unlocking: true, progressSuppressed: true });

    expect(root.querySelector(".qf-slot")).toBeNull();
    expect(root.querySelector(".qf-fill")).toBeNull();
  });

  it("进度来源 ref 更新直接驱动合成器 transform（不触发布局）", async () => {
    const source = ref(0);
    const root = mountView({ unlocking: true, progressSource: source });
    const fill = root.querySelector(".qf-fill") as HTMLElement | null;
    expect(fill).not.toBeNull();
    expect(fill?.style.transform).toBe("scaleX(0)");

    source.value = 42.5;
    await nextTick();
    expect(fill?.style.transform).toBe("scaleX(0.425)");
  });
});
