// @vitest-environment happy-dom
/*
 * registry.spec.ts — 开发工具登记表契约
 *
 * 覆盖：首批工具数量与唯一 id、分组完整性、非法登记项拒绝。
 */
import { describe, expect, it } from "vitest";
import {
  DEV_TOOL_GROUPS,
  createDevTools,
  validateDevTools,
  type DevTool,
} from "./registry";

function actionTool(id: string, overrides: Partial<DevTool> = {}): DevTool {
  return {
    id,
    group: "logs",
    kind: "action",
    label: "标签",
    hint: "说明",
    run: () => {},
    ...overrides,
  } as DevTool;
}

describe("开发工具注册表", () => {
  it("首批七项工具 id 唯一且分组全部存在", () => {
    const tools = createDevTools();
    const groupIds = new Set(DEV_TOOL_GROUPS.map((group) => group.id));

    expect(tools.length).toBe(7);
    expect(new Set(tools.map((tool) => tool.id)).size).toBe(tools.length);
    for (const tool of tools) {
      expect(groupIds.has(tool.group)).toBe(true);
    }
  });

  it("拒绝重复 id", () => {
    expect(() => validateDevTools([actionTool("dup"), actionTool("dup")])).toThrow(
      "开发工具 id 重复",
    );
  });

  it("拒绝空标签与不存在分组", () => {
    expect(() => validateDevTools([actionTool("empty", { label: " " })])).toThrow(
      "开发工具缺少标签",
    );
    expect(() =>
      validateDevTools([actionTool("bad-group", { group: "missing" as DevTool["group"] })]),
    ).toThrow("开发工具分组不存在");
  });

  it("拒绝 kind 契约不完整的登记项", () => {
    const missingRun = {
      id: "no-run",
      group: "logs",
      kind: "action",
      label: "标签",
      hint: "说明",
    } as unknown as DevTool;

    expect(() => validateDevTools([missingRun])).toThrow("动作工具缺少 run");
  });
});
