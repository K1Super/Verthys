/// <reference types="node" />
/*
 * button_style_single_source.spec.ts — 按钮样式单源守卫
 *
 * 用途：把「图标键的几何与皮肤只能有一处来源」变成可复跑的断言，而不是靠人工目检：
 *   1. 方形图标键的几何（边长 / 内边距 / 图标口径）与主键皮肤只在全局样式层定义；
 *   2. 共享按钮组件以这些全局类成型，自身不重复声明几何；
 *   3. 拾光顶栏的五个图标键必须由共享组件承载，其本地样式块只允许状态与色相规则。
 *
 * 说明：本用例读取源文件文本，属于结构约束测试（不渲染、不依赖 DOM）。
 *   若确需为某个键新增几何声明，必须先在此显式登记并说明理由。
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), "utf8");

/** 拾光顶栏图标键的状态类（这些键必须由共享组件承载） */
const PHOTO_BAR_KEYS = [
  "privacy-btn",
  "export-top-btn",
  "import-top-btn",
  "repack-top-btn",
  "del-top-btn",
];

/** 几何声明：按钮盒模型只允许来自全局单源，不得出现在组件本地样式块 */
const GEOMETRY_DECL = /\b(width|height|padding|border-radius)\s*:/;

/**
 * 已登记豁免：带文案形态的内边距（与方形键几何无关，不属本单源约束范围）与
 * 图标元素自身的尺寸规则（作用于按钮内的 svg 等）。
 */
const EXEMPT_SELECTOR = /\.(action-plus|action-label|action-labeled)|svg/;

/** 从样式块中取出全部规则（选择器 + 声明体） */
const ruleOf = (block: string): string[] => block.match(/[^{}]+\{[^}]*\}/g) ?? [];

const globalSheet = read("../../../styles/components.css");
const actionButton = read("./ActionButton.vue");
const photoAlbum = read("../../modules/PhotoAlbum.vue");
const photoStyleBlock = photoAlbum.split("<style scoped>")[1] ?? "";

describe("方形图标键：全局单源", () => {
  it("全局样式层定义了几何与主键皮肤", () => {
    expect(globalSheet).toMatch(/\.btn-icon\s*\{[^}]*width:\s*32px/);
    expect(globalSheet).toMatch(/\.btn-icon\s*\{[^}]*height:\s*32px/);
    expect(globalSheet).toMatch(/\.btn-icon\s*\{[^}]*padding:\s*0/);
    expect(globalSheet).toMatch(/\.btn-icon\s*>\s*svg\s*\{/);
    expect(globalSheet).toMatch(/\.btn-primary\s*\{/);
  });

  it("共享按钮组件以全局类成型，自身不声明按钮盒模型几何", () => {
    expect(actionButton).toContain("'btn-icon': iconOnly");
    expect(actionButton).toContain("const iconOnly = computed(() => !props.label && !slots.default)");
    const styleBlock = actionButton.split("<style scoped>")[1] ?? "";
    for (const rule of ruleOf(styleBlock)) {
      const selector = rule.split("{")[0];
      if (EXEMPT_SELECTOR.test(selector)) continue;
      expect(rule, selector).not.toMatch(GEOMETRY_DECL);
    }
  });
});

describe("拾光顶栏图标键：只使用共享组件样式", () => {
  it("五键全部由共享组件承载，模板中不再手写按钮元素", () => {
    for (const key of PHOTO_BAR_KEYS) {
      expect(photoAlbum, key).toContain(`class="${key}"`);
      expect(photoAlbum, key).not.toMatch(new RegExp(`<button[^>]*class="[^"]*${key}`));
    }
  });

  it("本地样式块不再声明几何（几何只来自全局 .btn-icon）", () => {
    for (const key of PHOTO_BAR_KEYS) {
      const rules = photoStyleBlock.match(new RegExp(`\\.${key}[^{]*\\{[^}]*\\}`, "g")) ?? [];
      for (const rule of rules) {
        expect(rule, rule).not.toMatch(GEOMETRY_DECL);
      }
    }
  });

  it("本地保留的规则必须都是状态规则（状态限定符），不得新增静态肤色", () => {
    const keyRules = PHOTO_BAR_KEYS.flatMap(
      (key) => photoStyleBlock.match(new RegExp(`\\.${key}[^{]*\\{[^}]*\\}`, "g")) ?? [],
    );
    expect(keyRules.length).toBeGreaterThan(0);
    for (const rule of keyRules) {
      const selector = rule.split("{")[0];
      expect(selector, selector).toMatch(/:hover|:active|:focus|:disabled|\.on\b|\.active\b|::before/);
    }
  });
});
