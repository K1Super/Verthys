/*
 * lib/vault_item_detail.ts — 条目详情视图的全字段投影（纯函数）
 *
 * 用途：把「条目数据 + 类型定义」投影为只读详情窗口可直接渲染的分区与字段，
 *   承载卡片摘要之外的完整信息。
 *
 * 职责边界：只做数据到只读视图的纯映射，不触碰 DOM、不发起 IO、不持有展示态。
 *   敏感字段的掩码/明文切换由条目展示态在渲染层完成，投影只提供原始取值。
 *
 * 与卡片视图的分工：
 *   - 卡片（lib/vault_item_card）只取 cardFields 的少量摘要，固定高度；
 *   - 详情（本模块）遍历类型声明的全部字段，空值不占行，完整文本不截断。
 *   因此「卡片看不到的字段」在详情里一定可见，两者不共用任何截断规则。
 */
import type {
  VaultFieldDef,
  VaultTypeDef,
} from "../constants/vault_item_types";
import {
  VAULT_EXPIRY_FIELD_ID,
  groupVaultFieldSections,
  vaultRangeStartFieldId,
} from "../constants/vault_item_types";
import { vaultExpiryReadout, type VaultExpiryReadout } from "./vault_item_card";

/** 详情窗口中的一行 */
export interface VaultDetailField {
  /** 字段 id（渲染稳定键与复制入口） */
  fieldId: string;
  /** 字段显示名 */
  label: string;
  /** 展示取值（敏感字段为原始取值，由渲染层按展示态掩码） */
  value: string;
  /** 是否敏感（渲染层提供显隐/复制） */
  sensitive: boolean;
  /** 是否为多行文本（渲染层保留换行） */
  multiline: boolean;
  /** 是否已独立加密（仅账号密码可能为真） */
  encrypted: boolean;
  /** 到期读数（仅到期字段；无到期日按永久有效口径） */
  readout: VaultExpiryReadout | null;
}

/** 详情窗口中的一个分区 */
export interface VaultDetailSection {
  name: string;
  fields: VaultDetailField[];
}

/**
 * 投影单个字段。
 *
 * @param field 字段定义
 * @param data 条目数据
 * @param def 类型定义（取主标题与独立加密标记）
 * @returns 详情行；该字段不应出现在详情中（transient / 主标题 / 空值）时返回 null
 *
 * 主标题由详情窗口头部承担，不在字段列表重复；transient 字段（独立密钥）
 * 只在编辑窗口采集，详情窗口不得回显。空值字段不占行 —— 详情展示的是
 * 已填写的信息，而不是一张空白表单。
 */
function buildDetailField(
  field: VaultFieldDef,
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef,
): VaultDetailField | null {
  if (field.transient) return null;
  if (field.id === def.titleField) return null;

  const raw = data[field.id] ?? "";
  const encrypted = data.encrypted === "1";
  const isExpiry = field.id === VAULT_EXPIRY_FIELD_ID;

  // 选项开关是状态而非文本：始终展示「已开启 / 未开启」
  if (field.kind === "switch") {
    return {
      fieldId: field.id,
      label: field.label,
      value: raw === "1" ? "已开启" : "未开启",
      sensitive: false,
      multiline: false,
      encrypted: false,
      readout: null,
    };
  }

  // 敏感字段：空值不展示；展示态由渲染层处理
  if (field.sensitive === true) {
    if (raw.length === 0) return null;
    return {
      fieldId: field.id,
      label: field.label,
      value: raw,
      sensitive: true,
      multiline: false,
      encrypted,
      readout: null,
    };
  }

  /* 日期区间：起点与终点分别按声明键读取，展示时保留端点语义标签。
     到期字段即使两端为空也要出现（未设置 + 永久有效是有效信息）；
     普通区间两端为空则不占行。 */
  if (field.kind === "dateRange") {
    const startId = vaultRangeStartFieldId(field);
    const start = data[startId] ?? "";
    const end = raw;
    if (!start && !end && !isExpiry) return null;

    const startLabel = field.rangeStartLabel ?? "自";
    const endLabel = field.rangeEndLabel ?? "至";
    let value: string;
    if (start && end) value = `${startLabel} ${start} · ${endLabel} ${end}`;
    else if (end) value = `${endLabel} ${end}`;
    else if (start) value = `${startLabel} ${start} · ${endLabel} 长期`;
    else value = "未设置";

    return {
      fieldId: field.id,
      label: field.label,
      value,
      sensitive: false,
      multiline: false,
      encrypted: false,
      readout: isExpiry ? vaultExpiryReadout(end) : null,
    };
  }

  // 单日期：到期字段即使未设置也展示，普通日期空值不占行
  if (field.kind === "date") {
    if (!raw && !isExpiry) return null;
    return {
      fieldId: field.id,
      label: field.label,
      value: raw || "未设置",
      sensitive: false,
      multiline: false,
      encrypted: false,
      readout: isExpiry ? vaultExpiryReadout(raw) : null,
    };
  }

  // 其余控件：空值不占行
  if (raw.trim().length === 0) return null;
  return {
    fieldId: field.id,
    label: field.label,
    value: raw,
    sensitive: false,
    multiline: field.kind === "multiline",
    encrypted: false,
    readout: null,
  };
}

/**
 * 构建详情窗口的分区与字段。
 *
 * @param data 条目数据字典
 * @param def 类型定义；缺失时返回空数组（调用方不打开详情窗口）
 * @returns 分区清单；不可展示字段与空分区均被剔除
 */
export function buildVaultDetailSections(
  data: Readonly<Record<string, string>>,
  def: VaultTypeDef | undefined,
): VaultDetailSection[] {
  if (!def) return [];

  const sections: VaultDetailSection[] = [];
  for (const section of groupVaultFieldSections(def)) {
    const fields: VaultDetailField[] = [];
    for (const field of section.fields) {
      const detail = buildDetailField(field, data, def);
      if (detail) fields.push(detail);
    }
    if (fields.length > 0) sections.push({ name: section.name, fields });
  }
  return sections;
}
