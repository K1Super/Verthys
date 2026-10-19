// @vitest-environment happy-dom
/*
 * useModuleEntrance.spec.ts — 模块步入窗口与错峰曲线的契约守卫
 *
 * 覆盖两条不可回退的契约：
 *   1. 错峰延迟渐近饱和：序 0 无延迟、序列单调非降、任意序均有界
 *      （长列表/虚拟滚动绝对索引不得出现秒级空白）、步长前大后小；
 *   2. 步入窗口一次性：内容异步就绪时窗口自就绪批开启；窗口耗尽后
 *      动态挂载的条目不再重演入场（虚拟滚动换行不留白、不整屏闪烁）。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createApp, defineComponent, h, nextTick, ref } from "vue";
import { useModuleEntrance, revealDelayOf } from "./useModuleEntrance";
import { MODULE_REVEAL } from "../app/constants";

describe("revealDelayOf 错峰曲线", () => {
  it("序 0 无延迟；序列单调非降；任意序均有界", () => {
    expect(revealDelayOf(0)).toBe(0);
    /* 越界序按 0 处理（防守：调用方索引异常不得产生负延迟） */
    expect(revealDelayOf(-3)).toBe(0);

    let previous = 0;
    for (const order of [1, 2, 3, 5, 8, 13, 40, 400]) {
      const delay = revealDelayOf(order);
      expect(delay).toBeGreaterThanOrEqual(previous);
      expect(delay).toBeLessThan(MODULE_REVEAL.staggerSpanMs);
      previous = delay;
    }
  });

  it("步长前大后小（渐近饱和，非线性截顶）", () => {
    const headStep = revealDelayOf(2) - revealDelayOf(0);
    const tailStep = revealDelayOf(40) - revealDelayOf(30);
    expect(headStep).toBeGreaterThan(tailStep);
    expect(tailStep).toBeGreaterThanOrEqual(0);
  });
});

describe("useModuleEntrance 步入窗口", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  /** 挂载最小探针：暴露窗口标记为根节点类名 */
  const mountProbe = (isReady: () => boolean) => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const app = createApp(defineComponent({
      setup() {
        const { entering } = useModuleEntrance(isReady);
        return () => h("div", { class: entering.value ? "is-entering" : "" });
      },
    }));
    app.mount(host);
    const opened = () => (host.firstElementChild as HTMLElement).classList.contains("is-entering");
    return { app, opened };
  };

  it("内容异步就绪：窗口自就绪批开启，并在窗口时长后关闭", async () => {
    const ready = ref(false);
    const { app, opened } = mountProbe(() => ready.value);

    /* 未就绪：窗口不得开启（否则条目出现前窗口已耗尽，整批直接呈现） */
    expect(opened()).toBe(false);

    ready.value = true;
    await nextTick();
    expect(opened()).toBe(true);

    vi.advanceTimersByTime(MODULE_REVEAL.holdMs - 1);
    await nextTick();
    expect(opened()).toBe(true);

    vi.advanceTimersByTime(1);
    await nextTick();
    expect(opened()).toBe(false);

    app.unmount();
  });

  it("静态内容：窗口随挂载开启", async () => {
    const { app, opened } = mountProbe(() => true);
    expect(opened()).toBe(true);

    vi.advanceTimersByTime(MODULE_REVEAL.holdMs);
    await nextTick();
    expect(opened()).toBe(false);

    app.unmount();
  });

  it("一次性：窗口耗尽后重复就绪不再重开", async () => {
    const ready = ref(true);
    const { app, opened } = mountProbe(() => ready.value);

    vi.advanceTimersByTime(MODULE_REVEAL.holdMs);
    await nextTick();
    expect(opened()).toBe(false);

    ready.value = false;
    await nextTick();
    ready.value = true;
    await nextTick();
    expect(opened()).toBe(false);

    app.unmount();
  });

  it("窗口时长覆盖「最大错峰延迟 + 显影时长」（中途撤标记不得突跳）", () => {
    expect(MODULE_REVEAL.holdMs).toBeGreaterThanOrEqual(
      MODULE_REVEAL.staggerSpanMs + MODULE_REVEAL.durMs,
    );
  });
});
