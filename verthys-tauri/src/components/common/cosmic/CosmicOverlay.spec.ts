// @vitest-environment happy-dom
/*
 * CosmicOverlay.spec.ts — 弹窗背衬折射边界契约
 *
 * 覆盖：幕层与底板同域并列、遮罩根节点不承载透明度、入场/退场透明度只落在幕层与底板自身。
 * 动机：opacity 小于 1 的元素会成为背衬折射的根边界，折射只能采样边界之内的画面。
 *   遮罩根节点一旦参与淡入，底板在整段入场期内拿不到页面衬底、结束帧才一次性
 *   接上 —— 观感即「扫过后突变」。故根节点只登记过渡时长，底色与装饰归幕层。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, type App } from "vue";
import { readFileSync } from "node:fs";
import CosmicOverlay from "./CosmicOverlay.vue";

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), "utf8");

/** 去注释：断言只针对声明本身，注释里的措辞不得被当作声明命中 */
const stripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, " ");

/** 取某选择器的规则体（选择器须独占规则行首；空白按一个及以上空白符匹配） */
function ruleBody(source: string, selector: string): string {
  const pattern = selector
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/ /g, "\\s+");
  return stripComments(
    source.match(new RegExp(`^\\s*${pattern}\\s*\\{([^}]*)\\}`, "m"))?.[1] ?? "",
  );
}

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountOverlay(): HTMLElement {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(
        CosmicOverlay,
        { show: true, teleport: true, ariaLabel: "契约弹窗" },
        { default: () => h("div", { class: "spec-payload" }, "payload") },
      ),
  });
  app.mount(container);
  mounted.push({ app, container });
  return document.body;
}

describe("宇宙弹窗 · 背衬折射边界", () => {
  it("底板与幕层并列：底板不在幕层内，装饰在幕层内", () => {
    const root = mountOverlay();
    const backdrop = root.querySelector<HTMLElement>(".cosmic-backdrop");
    expect(backdrop).toBeTruthy();
    const veil = backdrop?.querySelector<HTMLElement>(".cb-veil");
    expect(veil).toBeTruthy();
    expect(veil?.querySelector(".cosmic-dialog")).toBeNull();
    expect(backdrop?.querySelector(".cosmic-dialog")).toBeTruthy();
    expect(veil?.querySelector(".cosmic-bg .cb-star")).toBeTruthy();
  });

  it("遮罩根节点不承载透明度与底色，底色归幕层且不拦截点击", () => {
    const source = read("./CosmicBackdrop.vue");
    const rootRule = ruleBody(source, ".cosmic-backdrop");
    expect(rootRule, ".cosmic-backdrop 未找到规则").not.toBe("");
    expect(rootRule, "遮罩根节点不得承载 opacity").not.toMatch(/opacity\s*:/);
    expect(rootRule, "遮罩根节点不得承载底色").not.toMatch(/background\s*:/);
    expect(rootRule, "遮罩根节点不得承载一次性动画").not.toMatch(/animation\s*:/);

    const veilRule = ruleBody(source, ".cb-veil");
    expect(veilRule, ".cb-veil 未找到规则").not.toBe("");
    expect(veilRule, "幕层须承载底色").toMatch(/background\s*:/);
    expect(veilRule, "幕层须点击穿透（点击语义归根节点）").toMatch(
      /pointer-events\s*:\s*none/,
    );
  });

  it("入场/退场透明度只落在幕层与底板自身，根节点只登记时长", () => {
    const source = read("./CosmicOverlay.vue");
    expect(ruleBody(source, ".cosmic-enter-from"), "根节点不得参与入场透明").toBe("");
    expect(ruleBody(source, ".cosmic-leave-to"), "根节点不得参与退场透明").toBe("");
    expect(ruleBody(source, ".cosmic-enter-active")).not.toMatch(/opacity\s*:/);
    expect(ruleBody(source, ".cosmic-leave-active")).not.toMatch(/opacity\s*:/);

    expect(
      ruleBody(source, ".cosmic-enter-from :deep(.cb-veil)"),
      "幕层须承担入场淡入",
    ).toMatch(/opacity\s*:\s*0/);
    expect(
      ruleBody(source, ".cosmic-enter-active :deep(.cb-veil)"),
      "幕层须登记入场过渡",
    ).toMatch(/transition[^;]*opacity/);
    expect(
      ruleBody(source, ".cosmic-leave-active :deep(.cb-veil)"),
      "幕层须登记退场过渡",
    ).toMatch(/transition[^;]*opacity/);

    expect(
      ruleBody(source, ".cosmic-enter-active :deep(.cosmic-dialog)"),
      "底板入场只允许不透明度",
    ).not.toMatch(/(?:^|[;\s])transform\s*:/);
  });
});
