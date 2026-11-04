/*
 * devtools/registry.ts — 开发工具注册表
 *
 * 扩展方式：新增工具只追加一条登记项，面板按分组统一渲染；不允许在
 * 面板组件里为单个工具写特例，避免开发入口演化成第二套产品界面。
 *
 * 启动期校验放在仅 DEV 加载的模块内：id 重复、分组缺失或 kind 契约
 * 不完整会立即暴露，而不是在点击时静默失败。
 */
import { environmentTools } from "./tools/environment";
import { logTools } from "./tools/logs";
import { runtimeTools } from "./tools/runtime";

export type DevToolGroupId = "logs" | "runtime" | "environment" | "actions";

export interface DevToolGroup {
  id: DevToolGroupId;
  label: string;
}

/** 只读信息面板的键值集合；布尔值用于性能开关快照 */
export type DevToolReadout = Record<string, string | number | boolean>;

/** 工具执行上下文：提示统一走应用 Toast，不自行创建浮层 */
export interface DevToolContext {
  notify: (message: string) => void;
  error: (message: string) => void;
  close: () => void;
}

/** 动作风险语义：danger 表示会丢弃未保存的界面状态，需要显式警示 */
export type DevToolTone = "danger";

export interface DevToolAction {
  label: string;
  run: (ctx: DevToolContext) => Promise<void> | void;
  /** 次级动作同样可声明风险语义，展示层据此直陈危险色 */
  tone?: DevToolTone;
}

interface DevToolBase {
  id: string;
  group: DevToolGroupId;
  label: string;
  hint: string;
  /** 主动作的风险语义；只影响展示，不改变执行路径 */
  tone?: DevToolTone;
  /** 只读工具可携带的次级动作（复制、清除等） */
  actions?: DevToolAction[];
}

export interface DevToolActionItem extends DevToolBase {
  kind: "action";
  run: (ctx: DevToolContext) => Promise<void> | void;
}

export interface DevToolInfoItem extends DevToolBase {
  kind: "info";
  /** 每次面板刷新时读取最新快照，不缓存可变状态 */
  read: () => DevToolReadout;
}

export type DevTool = DevToolActionItem | DevToolInfoItem;

export const DEV_TOOL_GROUPS: readonly DevToolGroup[] = [
  { id: "logs", label: "日志与诊断" },
  { id: "runtime", label: "运行时观测" },
  { id: "environment", label: "环境信息" },
  { id: "actions", label: "界面动作" },
];

/**
 * 校验登记项契约；仅在 DEV 模块加载期调用。
 *
 * 为什么直接抛出：开发工具自身配置错误必须在开发期立刻可见，
 * 静默跳过会让面板出现不可执行或不可解释的条目。
 */
export function validateDevTools(tools: readonly DevTool[]): void {
  const groupIds = new Set<string>(DEV_TOOL_GROUPS.map((group) => group.id));
  const seenIds = new Set<string>();

  for (const tool of tools) {
    if (!tool.id.trim()) throw new Error("开发工具 id 不能为空");
    if (seenIds.has(tool.id)) throw new Error(`开发工具 id 重复: ${tool.id}`);
    seenIds.add(tool.id);

    if (!tool.label.trim()) throw new Error(`开发工具缺少标签: ${tool.id}`);
    if (!tool.hint.trim()) throw new Error(`开发工具缺少说明: ${tool.id}`);
    if (!groupIds.has(tool.group)) throw new Error(`开发工具分组不存在: ${tool.id}`);

    if (tool.kind === "action" && typeof tool.run !== "function") {
      throw new Error(`动作工具缺少 run: ${tool.id}`);
    }
    if (tool.kind === "info" && typeof tool.read !== "function") {
      throw new Error(`只读工具缺少 read: ${tool.id}`);
    }

    for (const action of tool.actions ?? []) {
      if (!action.label.trim()) throw new Error(`开发工具动作缺少标签: ${tool.id}`);
      if (typeof action.run !== "function") throw new Error(`开发工具动作缺少 run: ${tool.id}`);
    }
  }
}

/** 汇总全部登记项并校验；面板与测试共用同一入口 */
export function createDevTools(): DevTool[] {
  const tools: DevTool[] = [...logTools, ...runtimeTools, ...environmentTools];
  validateDevTools(tools);
  return tools;
}
