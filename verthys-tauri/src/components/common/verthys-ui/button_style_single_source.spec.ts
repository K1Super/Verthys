/// <reference types="node" />
/*
 * button_style_single_source.spec.ts — 按钮样式单源守卫
 *
 * 用途：把「图标键的几何与皮肤只能有一处来源」变成可复跑的断言，而不是靠人工目检：
 *   1. 方形图标键的几何（边长 / 内边距 / 图标口径）与主键皮肤只在全局样式层定义；
 *   2. 共享按钮组件以这些全局类成型，自身不重复声明几何；
 *   3. 拾光顶栏的五个图标键必须由共享组件承载，其本地样式块只允许状态与色相规则；
 *   4. 删除 / 取消键的星野键色相（赤势 / 中性）只在全局样式层定义，
 *      拾光本地不得覆盖其键面肤色。
 *
 * 说明：本用例读取源文件文本，属于结构约束测试（不渲染、不依赖 DOM）。
 *   若确需为某个键新增几何声明，必须先在此显式登记并说明理由。
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), "utf8");

/** 拾光顶栏图标键的状态类（这些键必须由共享组件承载） */
const PHOTO_BAR_KEYS = [
  "privacy-btn",
  "export-top-btn",
  "import-top-btn",
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
const tokens = read("../../../styles/tokens.css");
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

describe("星野键族：赤势 / 中性色相单源", () => {
  const SKINS = ["btn-primary", "btn-destructive", "btn-neutral"];

  it("三键共用同一副骨骼，删除与取消只允许声明色相变量", () => {
    const skeleton =
      globalSheet.match(/\.btn-primary,\s*\.btn-destructive,\s*\.btn-neutral\s*\{[^}]*\}/)?.[0] ??
      "";
    expect(skeleton).toContain("var(--key-edge-light), var(--key-surface)");
    expect(skeleton).toContain("var(--key-accent-rgb)");
    const destructive =
      globalSheet.match(/\.btn-destructive\s*\{\s*--key-accent-rgb:[^}]*\}/)?.[0] ?? "";
    expect(destructive).toContain("--key-accent-rgb: var(--accent-red-rgb)");
    expect(destructive).not.toMatch(/clip-path|border-radius|box-shadow|border:\s*0/);
    const neutral = globalSheet.match(/\.btn-neutral\s*\{\s*--key-accent-rgb:[^}]*\}/)?.[0] ?? "";
    expect(neutral).toContain("--key-accent-rgb: var(--neutral-rgb)");
    expect(neutral).not.toMatch(/clip-path|border-radius|box-shadow|border:\s*0/);
  });

  it("半透明键面：三套色相共用同一组底板，不挂背景装饰层", () => {
    expect(globalSheet).toMatch(/\.btn-primary\s*\{[^}]*--key-accent-rgb:\s*var\(--accent-rgb\)/);
    expect(globalSheet).toMatch(
      /\.btn-destructive\s*\{[^}]*--key-accent-rgb:\s*var\(--accent-red-rgb\)/,
    );
    expect(globalSheet).toMatch(
      /\.btn-neutral\s*\{[^}]*--key-accent-rgb:\s*var\(--neutral-rgb\)/,
    );
    expect(tokens).toContain("--key-surface:");
    expect(tokens).toContain("--key-surface-hover:");
    expect(tokens).toContain("--neutral-rgb:");
    expect(tokens).not.toContain("--key-stars");
    expect(globalSheet).not.toMatch(
      /\.btn-primary::after|\.btn-destructive::after|\.btn-neutral::after/,
    );
  });

  it("三键在每条共享状态规则中同组出现，不允许任何一键单独分叉", () => {
    const states = [
      "",
      "::before",
      ":hover:not(:disabled)",
      ":hover:not(:disabled)::before",
      ":focus-visible",
      ":focus-visible::before",
      ":active:not(:disabled)",
      ":active:not(:disabled)::before",
      ":disabled",
      ":disabled::before",
    ];
    for (const state of states) {
      const rule = ruleOf(globalSheet).find(
        (r) =>
          r.includes(`.btn-primary${state}`) &&
          r.includes(`.btn-destructive${state}`) &&
          r.includes(`.btn-neutral${state}`),
      );
      expect(rule, state).toBeTruthy();
    }
  });

  it("势隙线默认隐藏，只在悬浮/键盘焦点显影（三键同一条轨道）", () => {
    const seam =
      globalSheet.match(
        /\.btn-primary::before,\s*\.btn-destructive::before,\s*\.btn-neutral::before\s*\{[^}]*\}/,
      )?.[0] ?? "";
    expect(seam).toContain("opacity: 0");
    expect(seam).not.toContain("animation:");
    expect(seam).toContain("var(--key-seam-core)");
    expect(seam).toContain("var(--key-seam-spark)");
    for (const skin of SKINS) {
      expect(globalSheet, skin).toMatch(
        new RegExp(`\\.${skin}:hover:not\\(:disabled\\)::before[^{]*\\{[^}]*opacity:\\s*1`),
      );
      expect(globalSheet, skin).toMatch(
        new RegExp(`\\.${skin}:focus-visible::before[^{]*\\{[^}]*opacity:\\s*1`),
      );
    }
  });

  it("共享组件默认落到中性皮肤，破坏性变体映射赤势皮肤", () => {
    expect(actionButton).toMatch(/variant === 'destructive'\s*\?\s*'btn-destructive'/);
    expect(actionButton).toContain(": 'btn-neutral'");
    expect(actionButton).toContain('variant: "neutral"');
    const styleBlock = actionButton.split("<style scoped>")[1] ?? "";
    expect(styleBlock).not.toContain("danger");
  });

  it("拾光删除键走 destructive、取消键走 neutral，本地不声明键面肤色", () => {
    const keys: Array<[string, string]> = [
      ["del-top-btn", "destructive"],
      ["select-delete-btn", "destructive"],
      ["select-cancel-btn", "neutral"],
    ];
    for (const [key, variant] of keys) {
      const tags = photoAlbum.match(new RegExp(`<ActionButton[^>]*class="${key}"[^>]*>`, "g")) ?? [];
      expect(tags.length, key).toBe(1);
      expect(tags[0], key).toContain(`variant="${variant}"`);
    }
    expect(photoStyleBlock).not.toContain(".select-delete-btn");
    expect(photoStyleBlock).not.toContain(".select-cancel-btn");
  });
});

describe("旧按钮族：全项目清除", () => {
  const componentsDir = fileURLToPath(new URL("../..", import.meta.url)).replace(/[\\/]+$/, "");

  const vueFiles = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory()
        ? vueFiles(path)
        : path.endsWith(".vue")
          ? [path]
          : [];
    });

  it("任何 .vue 不得再引用 kv-confirm / kv-cancel / kv-danger", () => {
    const offenders = vueFiles(componentsDir)
      .filter((path) => /kv-(confirm|cancel|danger)\b/.test(readFileSync(path, "utf8")))
      .map((path) => path.slice(componentsDir.length + 1));
    expect(offenders).toEqual([]);
  });

  it("不得重新引入 mini-btn / editor-delete 手写键皮肤", () => {
    const offenders: string[] = [];
    for (const path of vueFiles(componentsDir)) {
      const text = readFileSync(path, "utf8");
      for (const match of text.matchAll(/<button[^>]*class="([^"]+)"/g)) {
        const tokens = match[1].split(/\s+/);
        for (const legacy of ["mini-btn", "editor-delete"]) {
          if (tokens.includes(legacy)) {
            offenders.push(`${path.slice(componentsDir.length + 1)} :: ${legacy}`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("卡片动作行统一使用星野键族微缩规格", () => {
    const card = read("../../modules/account/VaultItemCard.vue");
    expect(card).toContain('class="btn btn-neutral btn-mini"');
    expect(card).toContain('class="btn btn-destructive btn-mini"');
    const file = read("../../modules/FileVerthys.vue");
    expect(file).toContain('class="btn btn-neutral btn-mini"');
    expect(file).toContain('class="btn btn-destructive btn-mini"');
  });

  it("所有 .btn 系按钮必须落到星野键族色相", () => {
    const offenders: string[] = [];
    for (const path of vueFiles(componentsDir)) {
      // 皮肤由 :class 动态挂载，字面 class 属基座
      if (path.endsWith("ActionButton.vue")) continue;
      const text = readFileSync(path, "utf8");
      for (const match of text.matchAll(/<button[^>]*class="([^"]*\bbtn\b[^"]*)"/g)) {
        const tokens = match[1].split(/\s+/);
        if (!tokens.includes("btn")) continue;
        if (!tokens.some((token) => ["btn-primary", "btn-destructive", "btn-neutral"].includes(token))) {
          offenders.push(`${path.slice(componentsDir.length + 1)} :: ${tokens.join(" ")}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("回退锚点管理弹窗：按钮族装配", () => {
  const anchorDialog = read("../../management/AnchorManagerDialog.vue");

  it("动作按钮全部使用星野键族色相，并统一紧凑规格", () => {
    const tags = anchorDialog.match(/<button[^>]*>/g) ?? [];
    expect(tags.length).toBeGreaterThan(0);
    for (const tag of tags) {
      expect(tag).toMatch(/class="[^"]*btn-(primary|destructive|neutral)/);
      expect(tag).toContain("btn-compact");
      expect(tag).not.toMatch(/kv-danger|kv-confirm|kv-cancel/);
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
