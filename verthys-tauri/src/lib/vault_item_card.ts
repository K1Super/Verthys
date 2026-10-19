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
 *   2. 敏感值不进入默认展示：敏感字段在卡片上以掩码呈现，是否展开由条目的
 *      展示态决定，映射本身只给出掩码文本。
 *   3. 到期读数口径与编辑窗口读数同源（同一天数阈值与同一文案模板），
 *      避免同一到期日在两处显示不一致。
 *   4. 类型定义缺失时不得留白：主标题回落到数据中的首个取值，次行取其后两项。
 */
import type { VaultFieldDef, VaultTone, VaultTypeDef } from "../constants/vault_item_types";
import {
  DEFAULT_VAULT_ICON_ID,
  VAULT_EXPIRY_FIELD_ID,
  resolveVaultIcon,
} from "../constants/vault_item_types";

/** 敏感值掩码：长度统一，避免同一列表里掩码长短不一 */
export const VAULT_SECRET_MASK = "••••••••••";

/** 类型定义缺失时卡片上的类型名 */
export const VAULT_UNKNOWN_TYPE_LABEL = "未知类型";

/** 类型定义缺失时卡片的次行取值上限 */
const UNKNOWN_TYPE_LINE_LIMIT = 2;

/** 卡片次行展示项 */
export interface VaultCardLine {
  /** 字段 id（列表渲染的稳定键） */
  fieldId: string;
  /** 字段显示名 */
  label: string;
  /** 字段取值 */
  value: string;
  /** 是否敏感（卡片上以掩码呈现，不直接展示取值） */
  sensitive: boolean;
}

/** 卡片敏感行：类型中首个未进入次行的敏感字段 */
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
  /** 次行展示项 */
  lines: VaultCardLine[];
  /** 敏感行；该类型无敏感字段时为 null */
  secret: VaultCardSecret | null;
  /** 到期读数；该类型未声明到期字段时为 null */
  expiry: VaultCardExpiry | null;
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

/** 一天的毫秒数（天数换算用） */
const DAY_MS = 86_400_000;

/**
 * 计算到期读数。
 *
 * @param expiry 到期日（日期字符串；空值表示未设置）
 * @param now 参照时刻（毫秒时间戳，默认当前时刻；便于固定断言）
 * @returns 读数语调与文案；未设置到期日按永久有效呈现
 *
 * 阈值语义：已过期按超出天数告警、剩余不足一天按今日内到期、剩余不足
 * 临期阈值按临期、其余按有效。
 */
export function vaultExpiryReadout(expiry: string, now: number = Date.now()): VaultExpiryReadout {
  if (!expiry) return { tone: "none", text: "永久有效" };

  const diffDays = (new Date(expiry).getTime() - now) / DAY_MS;
  if (Number.isNaN(diffDays)) return { tone: "none", text: "永久有效" };
  if (diffDays < 0) return { tone: "expired", text: `已过期 ${Math.ceil(-diffDays)} 天` };
  if (diffDays < 1) return { tone: "expiring", text: "今日内到期" };
  if (diffDays < VAULT_EXPIRY_WARN_DAYS) return { tone: "expiring", text: `${Math.floor(diffDays)} 天后到期` };
  return { tone: "valid", text: `${Math.floor(diffDays)} 天后到期` };
}

/**
 * 取卡片敏感行对应的字段：类型中首个敏感字段。
 *
 * 选首个而非"首个未进入次行"的字段，是为了让每个掩码取值都有唯一的查看入口：
 * 敏感字段一旦同时在次行与敏感行呈现，同一取值会出现两处展示，且其中一处
 * 没有查看控件。因此敏感字段统一由敏感行承载，次行只保留可直读的字段。
 *
 * @param def 类型定义
 * @returns 字段定义；该类型无敏感字段时返回 undefined
 */
export function findCardSecretField(def: VaultTypeDef): VaultFieldDef | undefined {
  return def.fields.find((field) => field.sensitive === true && !field.transient);
}

/**
 * 取条目的主标题取值。
 *
 * @param data 条目数据字典
 * @param def 类型定义；缺失时取数据中的首个取值
 * @returns 主标题文本
 */
export function vaultItemTitle(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): string {
  if (def) return data[def.titleField] ?? "";
  const first = Object.values(data)[0];
  return first ?? "";
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
 * @param def 类型定义；缺失时按未知类型兜底展示
 * @returns 卡片视图
 */
export function buildVaultCardView(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): VaultCardView {
  if (!def) {
    const entries = Object.entries(data);
    return {
      kind: "",
      typeLabel: VAULT_UNKNOWN_TYPE_LABEL,
      icon: resolveVaultIcon(DEFAULT_VAULT_ICON_ID),
      tone: "accent",
      unknown: true,
      title: vaultItemTitle(data, undefined),
      lines: entries.slice(1, 1 + UNKNOWN_TYPE_LINE_LIMIT).map(([fieldId, value]) => ({
        fieldId,
        label: fieldId,
        value,
        sensitive: false,
      })),
      secret: null,
      expiry: null,
    };
  }

  const secretField = findCardSecretField(def);
  const expiryField = def.fields.find((f) => f.id === VAULT_EXPIRY_FIELD_ID);

  const secret: VaultCardSecret | null = secretField
    ? {
        fieldId: secretField.id,
        label: secretField.label,
        // 独立加密标记由载荷的 encrypted 字段承载（账号类型声明该字段）
        encrypted: data.encrypted === "1",
        raw: data[secretField.id] ?? "",
      }
    : null;

  const expiry: VaultCardExpiry | null = expiryField
    ? { label: expiryField.label, ...vaultExpiryReadout(data[VAULT_EXPIRY_FIELD_ID] ?? "") }
    : null;

  const lines: VaultCardLine[] = [];
  for (const fieldId of def.cardFields) {
    const field = def.fields.find((f) => f.id === fieldId);
    if (!field) continue;
    // 敏感字段与到期字段分别由敏感行、到期读数承载，次行不重复呈现同一取值
    if (secretField && secretField.id === fieldId) continue;
    if (expiryField && expiryField.id === fieldId) continue;
    const sensitive = field.sensitive === true;
    lines.push({
      fieldId,
      label: field.label,
      // 敏感字段只输出掩码：明文不进入视图，查看由敏感行统一承担
      value: sensitive ? VAULT_SECRET_MASK : (data[fieldId] ?? ""),
      sensitive,
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
    secret,
    expiry,
  };
}

/**
 * 生成条目的搜索文本（小写）。
 *
 * @param data 条目数据字典
 * @param def 类型定义；缺失时以全部字段值参与搜索
 * @returns 参与搜索的字段值拼接文本
 */
export function vaultSearchText(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): string {
  const fields = def ? def.searchFields : Object.keys(data);
  const parts: string[] = [];
  for (const fieldId of fields) {
    const value = data[fieldId];
    if (value) parts.push(value);
  }
  return parts.join("\u0000").toLowerCase();
}
