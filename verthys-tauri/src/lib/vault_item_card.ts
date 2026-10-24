/*
 * lib/vault_item_card.ts — 条目卡片的声明式视图映射
 *
 * 用途：把「条目数据 + 类型定义」映射为可渲染的卡片视图（主标题、次行、
 *   敏感行、类型标识素材、到期读数、搜索文本），供列表卡片与编辑窗口共用。
 *
 * 职责边界：只做数据到视图的纯映射，不触碰 DOM、不发起 IO、不读全局状态。
 *   卡片尺寸、网格参数与动效属于样式层，不在此模块表达。
 *
 * 关键约束：
 *   1. 视图输出与逐项类名无关：类型差异只体现为内容与标识，不产生随数据
 *      变化的元素类名，避免列表重排与样式抖动。
 *   2. 敏感值不进入默认展示：映射只给出敏感行与原始取值，展示态由条目持有，
 *      卡片据此在掩码、已加密与明文之间切换。
 *   3. 到期读数口径与编辑窗口读数同源（同一天数阈值与同一文案模板），
 *      避免同一到期日在两处显示不一致。
 *   4. 类型定义缺失时不回显任何字段名与取值：只给出字段数与重新指派入口。
 *   5. 卡片只呈现有值的内容：空字段不进入次行、空敏感字段不进入敏感行；
 *      卡片固定高度，摘要只取 cardFields；完整字段由详情窗口承担。
 */
import type { VaultTone, VaultTypeDef } from "../constants/vault_item_types";
import {
  DEFAULT_VAULT_ICON_ID,
  VAULT_EXPIRY_FIELD_ID,
  resolveVaultIcon,
} from "../constants/vault_item_types";

/** 敏感值掩码：长度统一，避免同一列表里掩码长短不一 */
export const VAULT_SECRET_MASK = "••••••••••";

/**
 * 敏感字段的展示文本（卡片与详情窗口共用）。
 *
 * 未处于展示态时一律掩码（已加密字段给出「已加密」）；处于展示态时优先
 * 取解出的明文，非加密字段的 raw 本身就是明文。绝不在未展示态回显 raw。
 *
 * @param input 展示态、已解出明文、加密标记与原始取值
 * @returns 可直接渲染的展示文本
 */
export function vaultSecretText(input: {
  visible: boolean;
  plain?: string;
  encrypted: boolean;
  raw: string;
}): string {
  if (!input.visible) return input.encrypted ? "已加密" : VAULT_SECRET_MASK;
  return input.plain ?? (input.encrypted ? "已加密" : input.raw);
}

/** 类型定义缺失时卡片上的类型名 */
export const VAULT_UNKNOWN_TYPE_LABEL = "未知类型";

/** 卡片次行展示项 */
export interface VaultCardLine {
  /** 字段 id（列表渲染的稳定键） */
  fieldId: string;
  /** 字段显示名 */
  label: string;
  /** 字段取值 */
  value: string;
  /** 是否敏感（次行只承载非敏感字段，恒为 false；保留字段以兼容既有视图契约） */
  sensitive: boolean;
}

/** 卡片敏感行：类型声明中的一个敏感字段（secrets 列表按字段顺序排列） */
export interface VaultCardSecret {
  /** 字段 id */
  fieldId: string;
  /** 字段显示名 */
  label: string;
  /** 该字段在记录中已被独立加密（查看需独立密钥） */
  encrypted: boolean;
  /** 记录中的原始取值（已独立加密时是密文） */
  raw: string;
}

/** 卡片视图 */
export interface VaultCardView {
  /** 类型 id */
  kind: string;
  /** 类型名（类型标识文案） */
  typeLabel: string;
  /** 类型图标标记文本 */
  icon: string;
  /** 类型色调 */
  tone: VaultTone;
  /** 类型定义是否缺失 */
  unknown: boolean;
  /** 主标题取值 */
  title: string;
  /** 次行展示项（仅非敏感、有值、非到期字段） */
  lines: VaultCardLine[];
  /** 敏感行（全部有值的敏感字段；该类型无敏感字段时为空数组） */
  secrets: VaultCardSecret[];
  /** 首个敏感行（查看密钥与复制入口的兼容取值；无敏感字段时为 null） */
  secret: VaultCardSecret | null;
  /** 到期读数；该类型未声明到期字段时为 null */
  expiry: VaultCardExpiry | null;
  /**
   * 类型定义缺失时的已存字段数（仅供卡片说明「有 N 项数据待重新指派」）。
   * 字段值与字段名一概不外泄 —— 类型未知即无法判断哪些字段敏感。
   */
  fieldCount: number;
}

/** 到期读数：tone 决定色调语义，text 为展示文案 */
export interface VaultExpiryReadout {
  tone: "none" | "valid" | "expiring" | "expired";
  text: string;
}

/** 卡片到期读数：读数口径 + 到期字段的显示名 */
export interface VaultCardExpiry extends VaultExpiryReadout {
  label: string;
}

/** 类型色调 → 设计令牌中的 RGB 三元组变量名（供类型标识着色） */
export const VAULT_TONE_RGB_VARS: Record<VaultTone, string> = {
  accent: "--accent-rgb",
  purple: "--accent-purple-rgb",
  success: "--success-rgb",
  warning: "--warning-rgb",
  danger: "--danger-rgb",
};

/**
 * 到期读数的着色变量名。
 *
 * @param readout 到期读数
 * @returns 有效 / 临期 / 过期分别对应成功 / 警告 / 危险色；未设置到期日返回 null
 *          （调用方据此沿用次要文字色）
 */
export function vaultReadoutColorVar(readout: VaultExpiryReadout): string | null {
  if (readout.tone === "valid") return "--success-rgb";
  if (readout.tone === "expiring") return "--warning-rgb";
  if (readout.tone === "expired") return "--danger-rgb";
  return null;
}

/** 临期阈值（天）：剩余天数小于该值按临期呈现 */
export const VAULT_EXPIRY_WARN_DAYS = 30;

/** 一天的毫秒数（本地日历日换算用） */
const DAY_MS = 86_400_000;

/** 纯日期字符串（`YYYY-MM-DD`，日期控件唯一产出形态） */
const DATE_ONLY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * 把到期取值解析为「本地日历日」起点时间戳。
 *
 * `new Date("YYYY-MM-DD")` 按 **UTC** 解析，而日期控件与用户心智都是本地日期：
 * 东八区当天 08:00 之后，UTC 零点已过 → 同一张「今日到期」的卡片会被读成
 * 「已过期 1 天」。故纯日期一律按本地年月日构造；
 * 带时刻的取值（历史数据）退回原生解析，语义保持「到那一刻为止」。
 *
 * @param expiry 到期取值
 * @returns 毫秒时间戳；空值或不可解析返回 null
 */
export function vaultExpiryTimestamp(expiry: string): number | null {
  if (!expiry) return null;
  const dateOnly = DATE_ONLY_RE.exec(expiry);
  if (dateOnly) {
    return new Date(Number(dateOnly[1]), Number(dateOnly[2]) - 1, Number(dateOnly[3])).getTime();
  }
  const time = new Date(expiry).getTime();
  return Number.isNaN(time) ? null : time;
}

/** 取时间戳所属的本地日历日起点（跨夏令时仍以日历日为准） */
function startOfLocalDay(time: number): number {
  const d = new Date(time);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/**
 * 计算到期读数。
 *
 * @param expiry 到期日（日期字符串；空值表示未设置）
 * @param now 参照时刻（毫秒时间戳，默认当前时刻；便于固定断言）
 * @returns 读数语调与文案；未设置到期日按永久有效呈现
 *
 * 天数一律按**本地日历日差**计算：到期日当天整天都算「今日内到期」，
 * 不因当前钟点（或时区）提前判定过期。
 */
export function vaultExpiryReadout(expiry: string, now: number = Date.now()): VaultExpiryReadout {
  if (!expiry) return { tone: "none", text: "永久有效" };

  const target = vaultExpiryTimestamp(expiry);
  if (target === null) return { tone: "none", text: "永久有效" };

  const diffDays = Math.round(
    (startOfLocalDay(target) - startOfLocalDay(now)) / DAY_MS,
  );

  if (diffDays < 0) return { tone: "expired", text: `已过期 ${-diffDays} 天` };
  if (diffDays === 0) return { tone: "expiring", text: "今日内到期" };
  if (diffDays < VAULT_EXPIRY_WARN_DAYS) return { tone: "expiring", text: `${diffDays} 天后到期` };
  return { tone: "valid", text: `${diffDays} 天后到期` };
}

/**
 * 取条目的主标题取值。
 *
 * @param data 条目数据字典
 * @param def 类型定义；缺失时返回空串
 * @returns 主标题文本
 *
 * 类型缺失时不回落到「首个取值」：类型未知即无法判断该值是否敏感，
 * 以原始数据充当标题等于在卡面上泄露一条未受保护的信息。
 * 卡片改以类型标识承担主信息（见 buildVaultCardView 的 unknown 分支）。
 */
export function vaultItemTitle(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): string {
  if (!def) return "";
  return data[def.titleField] ?? "";
}

/**
 * 取条目的类型显示名。
 *
 * @param def 类型定义；缺失时返回未知类型名
 * @returns 类型名（类型标识与筛选摘要共用）
 */
export function vaultItemTypeLabel(def: VaultTypeDef | undefined): string {
  return def ? def.label : VAULT_UNKNOWN_TYPE_LABEL;
}

/**
 * 构建卡片视图。
 *
 * @param data 条目数据字典
 * @param def 类型定义；缺失时按未知类型兜底展示（不展示任何字段值）
 * @returns 卡片视图
 *
 * 类型缺失的安全裁定：字段名与字段值**一律不出卡面**。类型声明是「哪些字段
 * 敏感」的唯一依据，声明缺失时无法判断任意取值的敏感属性 —— 此时展示原文
 * 等于把密码/证件号平铺在卡片上。故只给出字段数，取值由「重新指派类型」
 * 或显式查看入口承担。
 */
export function buildVaultCardView(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): VaultCardView {
  if (!def) {
    return {
      kind: "",
      typeLabel: VAULT_UNKNOWN_TYPE_LABEL,
      icon: resolveVaultIcon(DEFAULT_VAULT_ICON_ID),
      tone: "accent",
      unknown: true,
      title: "",
      lines: [],
      secrets: [],
      secret: null,
      expiry: null,
      fieldCount: Object.keys(data).length,
    };
  }

  const expiryField = def.fields.find((f) => f.id === VAULT_EXPIRY_FIELD_ID);

  /* 敏感字段全部进入敏感行：空值不入卡（空字段没有可展示的内容，掩码反而
     会让人误以为已填写）。独立加密标记由载荷的 encrypted 字段承载（账号
     类型声明该字段），其余类型恒为明文。 */
  const secrets: VaultCardSecret[] = def.fields
    .filter((field) => field.sensitive === true && !field.transient)
    .map((field) => ({
      fieldId: field.id,
      label: field.label,
      encrypted: data.encrypted === "1",
      raw: data[field.id] ?? "",
    }))
    .filter((secret) => secret.raw.length > 0);

  const expiry: VaultCardExpiry | null = expiryField
    ? { label: expiryField.label, ...vaultExpiryReadout(data[VAULT_EXPIRY_FIELD_ID] ?? "") }
    : null;

  const lines: VaultCardLine[] = [];
  for (const fieldId of def.cardFields) {
    // 主标题已由卡头承载，不重复进入次行
    if (fieldId === def.titleField) continue;
    const field = def.fields.find((f) => f.id === fieldId);
    if (!field) continue;
    // 敏感字段与到期字段分别由敏感行、到期读数承载，次行不重复呈现同一取值
    if (field.sensitive === true && !field.transient) continue;
    if (expiryField && expiryField.id === fieldId) continue;
    const value = data[fieldId] ?? "";
    // 空值不占版面：卡片只呈现真实填写过的内容
    if (value.trim().length === 0) continue;
    lines.push({
      fieldId,
      label: field.label,
      value,
      sensitive: false,
    });
  }

  return {
    kind: def.id,
    typeLabel: vaultItemTypeLabel(def),
    icon: resolveVaultIcon(def.icon),
    tone: def.tone,
    unknown: false,
    title: vaultItemTitle(data, def),
    lines,
    secrets,
    secret: secrets[0] ?? null,
    expiry,
    fieldCount: Object.keys(data).length,
  };
}

/**
 * 生成条目的搜索文本（小写）。
 *
 * @param data 条目数据字典
 * @param def 类型定义；缺失时返回空串
 * @returns 参与搜索的字段值拼接文本
 *
 * 类型缺失时不参与检索：类型声明同时决定「哪些字段可搜」，声明缺失即无法
 * 判断某个取值是否敏感 —— 若把它纳入检索，用户可用关键字试探出未展示的
 * 密码/证件号（卡面已掩码，检索却成了旁路）。故宁可搜不到，不可泄值。
 */
export function vaultSearchText(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): string {
  if (!def) return "";
  const parts: string[] = [];
  for (const fieldId of def.searchFields) {
    const value = data[fieldId];
    if (value) parts.push(value);
  }
  return parts.join("\u0000").toLowerCase();
}
