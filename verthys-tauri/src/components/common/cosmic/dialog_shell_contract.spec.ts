/// <reference types="node" />
/*
 * dialog_shell_contract.spec.ts — 全局弹窗外壳单一性守卫
 *
 * 为什么需要本守卫：弹窗外壳一旦出现第二套实现，焦点陷阱、Esc 栈序、
 * 滚动锁与背景材质就会各自漂移；界面看似只是"风格不同"，实际是模态
 * 行为不再可预测。这里把"全项目只有一套弹窗外壳"变成可复跑的断言。
 *
 * 边界：只扫描模板与样式中的外壳痕迹，不限制业务内容的局部布局类；
 * 注释在匹配前剥离，避免说明文字被误判为实现。
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const SRC_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

const read = (abs: string): string => readFileSync(abs, "utf8");

/** 去注释：只保留声明本身，注释中的历史说明不得被当作实现命中 */
const stripComments = (source: string): string =>
  source
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^\s*\/\/.*$/gm, " ");

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
      continue;
    }
    if (entry.name.endsWith(".vue") || entry.name.endsWith(".css")) out.push(full);
  }
  return out;
}

/** 禁止出现的外壳与皮肤标识：出现即说明又长出了第二套弹窗实现 */
const BANNED_SHELL_TOKENS = [
  "VerthysDialog",
  "dialog-overlay",
  "reg-panel",
  "reg-desk",
  "export-dialog-overlay",
  "cd-overlay",
  "cd-dialog",
] as const;

describe("全局弹窗外壳单一性", () => {
  it("模板与样式中不存在第二套弹窗外壳或皮肤标识", () => {
    const hits: string[] = [];
    for (const file of walk(SRC_ROOT)) {
      const source = stripComments(read(file));
      for (const token of BANNED_SHELL_TOKENS) {
        if (source.includes(token)) hits.push(`${file} → ${token}`);
      }
    }
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("入口只引入全局样式层，不挂载弹窗皮肤文件", () => {
    const main = read(join(SRC_ROOT, "main.ts"));
    expect(main).not.toContain("reg-desk");
  });

  it("外壳承担模态栈、滚动锁与初始焦点策略", () => {
    const overlay = read(join(SRC_ROOT, "components/common/cosmic/CosmicOverlay.vue"));
    expect(overlay).toContain("pushModal(modalId)");
    expect(overlay).toContain("popModal(modalId)");
    expect(overlay).toContain("isTopModal(modalId)");
    expect(overlay).toContain("initialFocus");
  });

  it("底板提供长表单滚动窗口，装饰层不随内容滚走", () => {
    const dialog = read(join(SRC_ROOT, "components/common/cosmic/CosmicDialog.vue"));
    expect(dialog).toMatch(/max-height\s*:\s*86vh/);
    expect(dialog).toMatch(/\.cd-content\s*\{[^}]*overflow-y\s*:\s*auto/);
  });
});
