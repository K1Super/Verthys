/*
 * lib/vault_item_filter.ts — 条目高级筛选与排序（纯函数）
 *
 * 用途：把「已加载的条目集合 + 筛选条件」映射为筛选并排序后的集合，
 *   同时给出条件摘要与生效维度计数，供筛选面板与列表共用。
 *
 * 职责边界：只处理内存中的条目数据，不发起 IPC、不读写缓存、不触碰 DOM。
 *   类型定义的查询由调用方以取值函数注入（类型索引的持有者是列表模块）。
 *
 * 关键约束：
 *   1. 筛选与搜索是叠加关系：本模块只做筛选维度，关键字匹配由调用方先行完成；
 *   2. 维度内部为「或」关系（多选任一项命中即保留），维度之间为「与」关系；
 *   3. 条件为空时保持输入顺序不变，避免无筛选状态下出现隐式排序；
 *   4. 排序稳定：同键值的条目保持输入相对顺序（按主标题二次比较以保证确定性）。
 */
import type { VaultTypeDef } from "../constants/vault_item_types";
import { VAULT_EXPIRY_FIELD_ID } from "../constants/vault_item_types";
import {
  vaultExpiryReadout,
  vaultExpiryTimestamp,
  vaultItemTitle,
  vaultItemTypeLabel,
} from "./vault_item_card";

/** 到期状态筛选取值 */
export type VaultExpiryFilter = "expired" | "expiring" | "hasExpiry" | "noExpiry";

/** 保护状态筛选取值 */
export type VaultProtectionFilter = "encrypted" | "sensitive" | "none";

/** 排序键（default = 保持加载顺序，即记录写入顺序） */
export type VaultSortKey = "default" | "recent" | "name" | "kind" | "expiry";

/** 筛选条件 */
export interface VaultFilterCriteria {
  /** 类型 id 多选；空数组表示不限类型 */
  kinds: string[];
  /** 到期状态多选；空数组表示不限 */
  expiry: VaultExpiryFilter[];
  /** 保护状态多选；空数组表示不限 */
  protection: VaultProtectionFilter[];
  /** 排序键 */
  sort: VaultSortKey;
}

/** 筛选与排序所需的条目最小形态（与列表条目的数据字段一致） */
export interface VaultFilterEntry {
  kind: string;
  data: Record<string, string>;
  recordId?: number;
}

/** 到期状态筛选项的展示定义（面板渲染顺序即此顺序） */
export const VAULT_EXPIRY_FILTER_OPTIONS: readonly { id: VaultExpiryFilter; label: string }[] = [
  { id: "expired", label: "已过期" },
  { id: "expiring", label: "即将到期" },
  { id: "hasExpiry", label: "已设到期" },
  { id: "noExpiry", label: "未设到期" },
];

/** 保护状态筛选项的展示定义 */
export const VAULT_PROTECTION_FILTER_OPTIONS: readonly { id: VaultProtectionFilter; label: string }[] = [
  { id: "encrypted", label: "含独立加密" },
  { id: "sensitive", label: "含敏感字段" },
  { id: "none", label: "均无" },
];

/** 排序项展示定义（默认顺序在首位，保证未指定排序时与既有列表顺序一致） */
export const VAULT_SORT_OPTIONS: readonly { id: VaultSortKey; label: string }[] = [
  { id: "default", label: "默认顺序" },
  { id: "recent", label: "最近更新" },
  { id: "name", label: "名称" },
  { id: "kind", label: "类型" },
  { id: "expiry", label: "到期先后" },
];

/** 默认筛选条件（无筛选，按加载顺序展示） */
export function createEmptyVaultFilter(): VaultFilterCriteria {
  return { kinds: [], expiry: [], protection: [], sort: "default" };
}

/** 判断条件是否处于默认态（类型 / 到期 / 保护三个维度均不限） */
export function isEmptyVaultFilter(criteria: VaultFilterCriteria): boolean {
  return criteria.kinds.length === 0 && criteria.expiry.length === 0 && criteria.protection.length === 0;
}

/** 生效的筛选条件数（类型按选中个数计，其余维度各计一项，不含排序） */
export function countActiveVaultFilters(criteria: VaultFilterCriteria): number {
  const expiryWeight = criteria.expiry.length > 0 ? 1 : 0;
  const protectionWeight = criteria.protection.length > 0 ? 1 : 0;
  return criteria.kinds.length + expiryWeight + protectionWeight;
}

/**
 * 生成筛选条件摘要。
 *
 * @param criteria 筛选条件
 * @param labelOf 类型 id → 类型显示名
 * @returns 摘要文本（如「账号 · 银行卡 +1」）；无筛选时返回空串
 */
export function describeVaultFilter(
  criteria: VaultFilterCriteria,
  labelOf: (kind: string) => string,
): string {
  const parts: string[] = criteria.kinds.map((kind) => labelOf(kind));
  const text = parts.join(" · ");
  const extra = countActiveVaultFilters(criteria) - criteria.kinds.length;
  if (extra <= 0) return text;
  return text ? `${text} +${extra}` : `+${extra}`;
}

/** 类型是否声明了到期字段（到期维度与到期排序的唯一准入判据） */
function declaresExpiry(def: VaultTypeDef | undefined): boolean {
  return def?.fields.some((field) => field.id === VAULT_EXPIRY_FIELD_ID) === true;
}

/** 条目是否命中到期状态维度（维度内为或关系） */
function matchExpiry(
  entry: VaultFilterEntry,
  def: VaultTypeDef | undefined,
  wanted: VaultExpiryFilter[],
): boolean {
  // 未声明到期字段的类型不参与到期维度：历史载荷可能残留 expiry 键
  // （如已移除日期字段的银行卡模板），按类型声明判定才不会把无日期条目
  // 归入「已设到期」。
  const value = declaresExpiry(def) ? (entry.data[VAULT_EXPIRY_FIELD_ID] ?? "") : "";
  const hasValue = value.length > 0;
  return wanted.some((flag) => {
    if (flag === "hasExpiry") return hasValue;
    if (flag === "noExpiry") return !hasValue;
    if (!hasValue) return false;
    const tone = vaultExpiryReadout(value).tone;
    return flag === "expired" ? tone === "expired" : tone === "expiring";
  });
}

/** 条目是否命中保护状态维度（维度内为或关系） */
function matchProtection(entry: VaultFilterEntry, def: VaultTypeDef | undefined, wanted: VaultProtectionFilter[]): boolean {
  const encrypted = entry.data.encrypted === "1";
  // 敏感字段的存在性来自类型声明：声明了敏感字段即视为该类型承载敏感数据
  const sensitive = def ? def.fields.some((field) => field.sensitive === true && !field.transient) : false;
  return wanted.some((flag) => {
    if (flag === "encrypted") return encrypted;
    if (flag === "sensitive") return sensitive;
    return !encrypted && !sensitive;
  });
}

/** 取条目排序用的到期时间（毫秒；未声明到期字段、无到期或日期非法返回 null）。
 *  与到期读数共用同一解析（纯日期按本地日历日）—— 排序与读数不出现时区分歧 */
function expiryTimeOf(entry: VaultFilterEntry, def: VaultTypeDef | undefined): number | null {
  if (!declaresExpiry(def)) return null;
  return vaultExpiryTimestamp(entry.data[VAULT_EXPIRY_FIELD_ID] ?? "");
}

/**
 * 应用筛选与排序。
 *
 * @param entries 待处理条目（顺序为调用方给定顺序）
 * @param criteria 筛选条件
 * @param defOf 类型 id → 类型定义
 * @returns 新数组（不改动入参数组）；无筛选时按排序键排序，排序键为默认且无条件时保持原顺序
 *
 * 排序语义：「最近更新」按记录 id 降序（编辑会重建记录，id 更大即更近更新）；
 * 「到期先后」按到期时间升序，未设到期的条目置于末尾（避免无到期条目挤占顶部）。
 */
export function applyVaultFilter<T extends VaultFilterEntry>(
  entries: readonly T[],
  criteria: VaultFilterCriteria,
  defOf: (kind: string) => VaultTypeDef | undefined,
): T[] {
  const defs = new Map<string, VaultTypeDef | undefined>();
  const getDef = (kind: string): VaultTypeDef | undefined => {
    if (!defs.has(kind)) defs.set(kind, defOf(kind));
    return defs.get(kind);
  };

  const filtered = entries.filter((entry) => {
    if (criteria.kinds.length > 0 && !criteria.kinds.includes(entry.kind)) return false;
    const def = getDef(entry.kind);
    if (criteria.expiry.length > 0 && !matchExpiry(entry, def, criteria.expiry)) return false;
    if (criteria.protection.length > 0 && !matchProtection(entry, def, criteria.protection)) return false;
    return true;
  });

  // 默认顺序：保持调用方给定顺序（即记录写入顺序），不引入隐式重排
  if (criteria.sort === "default" || filtered.length === 0) return filtered;

  const titleOf = (entry: T): string => vaultItemTitle(entry.data, getDef(entry.kind));
  const labelOf = (entry: T): string => vaultItemTypeLabel(getDef(entry.kind));

  const sorted = [...filtered];
  switch (criteria.sort) {
    case "name":
      sorted.sort((a, b) => titleOf(a).localeCompare(titleOf(b), "zh-Hans-CN"));
      break;
    case "kind":
      sorted.sort(
        (a, b) =>
          labelOf(a).localeCompare(labelOf(b), "zh-Hans-CN") ||
          titleOf(a).localeCompare(titleOf(b), "zh-Hans-CN"),
      );
      break;
    case "expiry":
      sorted.sort((a, b) => {
        const at = expiryTimeOf(a, getDef(a.kind));
        const bt = expiryTimeOf(b, getDef(b.kind));
        if (at === null && bt === null) return titleOf(a).localeCompare(titleOf(b), "zh-Hans-CN");
        if (at === null) return 1;
        if (bt === null) return -1;
        return at - bt;
      });
      break;
    case "recent":
      // 最近更新：记录 id 降序；缺失记录 id 的条目（写入失败）排在末尾
      sorted.sort((a, b) => (b.recordId ?? Number.NEGATIVE_INFINITY) - (a.recordId ?? Number.NEGATIVE_INFINITY));
      break;
    default:
      break;
  }
  return sorted;
}
