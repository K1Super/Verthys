/*
 * lib/vault_item_type_store.ts — 自定义条目类型的容器读写
 *
 * 用途：把全部自定义类型定义作为**单条设置记录**持久化（记录 type 为
 *   TYPE_VAULT_TYPES），并对外提供校验、读取与写入三件事。
 *
 * 关键约束（缓存一致性，必须严格遵守）：
 *   1. 写入新记录后立即回填全量记录缓存与模块缓存，保证同一会话内读到的
 *      类型定义与落盘内容一致；
 *   2. 删除被替换的旧记录后立即失效三层缓存（摘要索引 / 全量记录 / 扫描），
 *      否则缓存索引仍指向已删除记录，重载后自定义类型会整体消失；
 *   3. 不引入落盘旁路：一律走既有记录读写与串行落盘队列，与既有模块同模式。
 *
 * 设计取舍：
 *   - 单条记录承载全部定义，读写各一次 IPC，无逐条记录碎片；
 *   - 读取侧对损坏内容逐条降级而不是整体判废：一条定义异常不影响其余定义；
 *   - 写入侧先落新记录再删旧记录，避免删除后新建时记录 id 复用导致内容错位。
 *
 * 线程与副作用：读写涉及 IPC 与全局缓存写入，非纯函数；同一会话内多次
 *   写入由调用方串行化（类型管理界面为单入口），不做额外并发控制。
 */
import type { VaultTypeDef, VaultFieldDef, VaultFieldKind, VaultTone } from "../constants/vault_item_types";
import {
  BUILTIN_VAULT_TYPE_IDS,
  CUSTOM_VAULT_TYPE_PREFIX,
  DEFAULT_VAULT_ICON_ID,
  MAX_VAULT_CARD_FIELDS,
  VAULT_FIELD_KINDS,
  VAULT_TONES,
  isVaultIconId,
} from "../constants/vault_item_types";
import { TYPE_VAULT_TYPES } from "../constants/record_types";
import {
  addFullRecord,
  getModuleCache,
  getRecordIdsByType,
  getRecordsDataB64Batch,
  getSummaryIdsByType,
  invalidateFullRecord,
  invalidateScannedRecord,
  invalidateSummaryRecord,
  persistVerthys,
  setModuleCache,
} from "../cache/composition/verthys-cache";
import { ensureIndexSourceSafe } from "../utils/verthys_scan_safe";
import { verthysAddRecord, verthysDeleteRecord } from "./verthys";
import { deserializeFromJsonB64, serializeToJsonB64 } from "../utils/json_codec";
import { createLogger } from "../utils/logger";

const log = createLogger("vault-item-type-store");

/** 自定义类型定义在模块缓存中的键（与记录同为单一来源，读写两侧共用） */
export const VAULT_TYPES_CACHE_KEY = "vault_types";

/** 自定义类型定义记录的显示名（记录列表中的可读标识） */
export const VAULT_TYPES_RECORD_NAME = "vault-types";

/** 合法字段控件种类（单一权威源派生 — 校验集合与类型声明同源） */
const VALID_FIELD_KINDS: readonly VaultFieldKind[] = VAULT_FIELD_KINDS;

/** 合法色调（单一权威源派生） */
const VALID_TONES: readonly VaultTone[] = VAULT_TONES;

/** 卡片次行字段上限（单一权威源：与编辑侧校验同取 vault_item_types） */
const MAX_CARD_FIELDS = MAX_VAULT_CARD_FIELDS;

/** 写入结果：ok 表示记录已写入并同步缓存；persisted 表示已落盘 */
export interface SaveCustomVaultTypesResult {
  ok: boolean;
  persisted: boolean;
}

/** 判断是否为普通对象（排除 null、数组与函数） */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** 把未知值收敛为字符串数组（非数组输入返回空数组） */
function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

/**
 * 从字段名列表里取出真实存在的字段 id，并保持首次出现的顺序去重。
 *
 * 展示与搜索字段一旦重复，卡片会把同一个值渲染两次，故在入口收敛。
 */
function pickExistingFieldIds(value: unknown, existing: ReadonlySet<string>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const fieldId of toStringArray(value)) {
    if (!existing.has(fieldId) || seen.has(fieldId)) continue;
    seen.add(fieldId);
    out.push(fieldId);
  }
  return out;
}

/**
 * 归一化单个字段定义。
 *
 * @param raw 未知来源的字段定义
 * @returns 合法字段定义；结构不可用返回 null
 *
 * 选项缺失的 select 字段回退为文本控件：让界面仍能录入，而不是渲染出
 * 无法选择的空下拉。
 */
function sanitizeVaultField(raw: unknown): VaultFieldDef | null {
  if (!isPlainObject(raw)) return null;

  const id = typeof raw.id === "string" ? raw.id.trim() : "";
  const label = typeof raw.label === "string" ? raw.label.trim() : "";
  if (!id || !label) return null;

  let kind = raw.kind as VaultFieldKind;
  if (!VALID_FIELD_KINDS.includes(kind)) kind = "text";

  const options = toStringArray(raw.options).filter((opt) => opt.length > 0);
  if (kind === "select" && options.length === 0) kind = "text";

  const field: VaultFieldDef = { id, label, kind };
  if (raw.transient === true) field.transient = true;
  if (raw.carrier === true) field.carrier = true;
  if (raw.required === true) field.required = true;
  if (raw.sensitive === true) field.sensitive = true;
  if (kind === "select" && options.length > 0) field.options = options;
  if (kind === "multiline") {
    const rows = typeof raw.multilineRows === "number" ? raw.multilineRows : 0;
    field.multilineRows = Number.isInteger(rows) && rows >= 1 && rows <= 12 ? rows : 2;
  }
  if (typeof raw.hint === "string" && raw.hint.length > 0) field.hint = raw.hint;
  return field;
}

/**
 * 归一化单个类型定义（读取与写入两侧共用）。
 *
 * @param raw 未知来源的类型定义
 * @returns 合法类型定义；结构不可用返回 null
 *
 * 校验后仍可能缺失主标题或展示字段（存储内容被改写、字段被删）：
 * 主标题回落到首个字段，展示字段与搜索字段收敛到实际存在的字段，
 * 保证卡片渲染取得到主标题、查得到字段。
 */
export function sanitizeVaultTypeDef(raw: unknown): VaultTypeDef | null {
  if (!isPlainObject(raw)) return null;

  const id = typeof raw.id === "string" ? raw.id.trim() : "";
  const label = typeof raw.label === "string" ? raw.label.trim() : "";
  if (!id || !label) return null;

  const rawFields = Array.isArray(raw.fields) ? raw.fields : [];
  const fields: VaultFieldDef[] = [];
  const seenFieldIds = new Set<string>();
  for (const item of rawFields) {
    const field = sanitizeVaultField(item);
    if (!field || seenFieldIds.has(field.id)) continue;
    seenFieldIds.add(field.id);
    fields.push(field);
  }
  if (fields.length === 0) return null;

  const icon = typeof raw.icon === "string" && isVaultIconId(raw.icon) ? raw.icon : DEFAULT_VAULT_ICON_ID;
  const tone = VALID_TONES.includes(raw.tone as VaultTone) ? (raw.tone as VaultTone) : "accent";

  const rawTitle = typeof raw.titleField === "string" ? raw.titleField : "";
  const titleField = seenFieldIds.has(rawTitle) ? rawTitle : fields[0].id;

  const cardFields = pickExistingFieldIds(raw.cardFields, seenFieldIds).slice(0, MAX_CARD_FIELDS);
  const searchFields = pickExistingFieldIds(raw.searchFields, seenFieldIds);

  return {
    id,
    label,
    icon,
    tone,
    titleField,
    cardFields,
    searchFields: searchFields.length > 0 ? searchFields : [titleField],
    fields,
    builtin: false,
  };
}

/**
 * 归一化类型定义数组：逐条降级 + 按 id 去重。
 *
 * @param raw 未知来源的类型定义集合
 * @returns 合法定义数组；非数组输入返回空数组
 */
export function sanitizeVaultTypeDefs(raw: unknown): VaultTypeDef[] {
  if (!Array.isArray(raw)) return [];
  const out: VaultTypeDef[] = [];
  const seenIds = new Set<string>();
  for (const item of raw) {
    const def = sanitizeVaultTypeDef(item);
    if (!def || seenIds.has(def.id)) continue;
    seenIds.add(def.id);
    out.push(def);
  }
  return out;
}

/**
 * 校验自定义类型定义集合（写入前调用，返回问题清单）。
 *
 * @param types 待校验的类型定义
 * @param reservedIds 保留 id（内置类型），自定义类型不得与之冲突
 * @returns 问题描述列表；空数组表示全部合法
 */
export function validateVaultTypeDefs(
  types: readonly VaultTypeDef[],
  reservedIds: readonly string[] = BUILTIN_VAULT_TYPE_IDS,
): string[] {
  const errors: string[] = [];
  const seenIds = new Set<string>();
  const seenLabels = new Set<string>();

  for (const def of types) {
    const who = def.label || def.id || "未命名类型";
    const id = typeof def.id === "string" ? def.id.trim() : "";
    const label = typeof def.label === "string" ? def.label.trim() : "";

    if (!id) {
      errors.push(`${who}：类型 id 不能为空`);
    } else {
      if (reservedIds.includes(id)) errors.push(`${who}：类型 id 已被内置类型占用`);
      if (!id.startsWith(CUSTOM_VAULT_TYPE_PREFIX)) {
        errors.push(`${who}：类型 id 必须以 ${CUSTOM_VAULT_TYPE_PREFIX} 开头`);
      }
      if (seenIds.has(id)) errors.push(`${who}：类型 id 重复`);
      seenIds.add(id);
    }

    if (!label) {
      errors.push(`${who}：类型名不能为空`);
    } else {
      if (seenLabels.has(label)) errors.push(`${who}：类型名重复`);
      seenLabels.add(label);
    }

    if (!isVaultIconId(def.icon)) errors.push(`${who}：图标不在图标库内`);
    if (!VALID_TONES.includes(def.tone)) errors.push(`${who}：色调不合法`);

    const fields = Array.isArray(def.fields) ? def.fields : [];
    if (fields.length === 0) {
      errors.push(`${who}：字段清单不能为空`);
      continue;
    }

    const fieldIds = new Set<string>();
    const fieldLabels = new Set<string>();
    for (const field of fields) {
      const fieldId = typeof field.id === "string" ? field.id.trim() : "";
      const fieldLabel = typeof field.label === "string" ? field.label.trim() : "";
      if (!fieldId) errors.push(`${who}：字段 id 不能为空`);
      else {
        if (fieldIds.has(fieldId)) errors.push(`${who}：字段 id 重复（${fieldId}）`);
        fieldIds.add(fieldId);
      }
      if (!fieldLabel) errors.push(`${who}：字段名不能为空`);
      else {
        if (fieldLabels.has(fieldLabel)) errors.push(`${who}：字段名重复（${fieldLabel}）`);
        fieldLabels.add(fieldLabel);
      }
      if (!VALID_FIELD_KINDS.includes(field.kind)) {
        errors.push(`${who}：字段控件种类不合法（${field.label || field.id}）`);
      }
      if (field.kind === "select" && (field.options ?? []).length === 0) {
        errors.push(`${who}：选项字段必须提供候选项（${field.label || field.id}）`);
      }
    }

    if (!fieldIds.has(def.titleField)) errors.push(`${who}：主标题字段必须属于字段清单`);
    for (const fieldId of def.cardFields ?? []) {
      if (!fieldIds.has(fieldId)) errors.push(`${who}：卡片展示字段必须属于字段清单（${fieldId}）`);
    }
    if ((def.cardFields ?? []).length > MAX_CARD_FIELDS) {
      errors.push(`${who}：卡片展示字段最多 ${MAX_CARD_FIELDS} 项`);
    }
    for (const fieldId of def.searchFields ?? []) {
      if (!fieldIds.has(fieldId)) errors.push(`${who}：搜索字段必须属于字段清单（${fieldId}）`);
    }
  }

  return errors;
}

/**
 * 解析类型定义记录的 base64 内容。
 *
 * @param b64 记录载荷
 * @returns 类型定义数组；载荷不是数组（结构不符）时返回 null ——
 *   调用方据此继续回退更早的记录。不得把「形状不符」当成「空类型集」：
 *   那会让一条损坏的新记录遮蔽掉仍然可用的旧记录，用户观感为类型全部丢失。
 */
function parseVaultTypesRecord(b64: string): VaultTypeDef[] | null {
  try {
    const raw = deserializeFromJsonB64<unknown>(b64);
    if (!Array.isArray(raw)) {
      log.warn("类型定义记录不是数组，按结构不符跳过并继续回退");
      return null;
    }
    return sanitizeVaultTypeDefs(raw);
  } catch (e) {
    log.warn("类型定义记录解析失败", e);
    return null;
  }
}

/**
 * 收集当前容器内全部类型定义记录 id（升序）。
 *
 * 三个来源互补：模块缓存记录 id（最近一次写入）、扫描缓存、摘要索引。
 * 扫描失败时保留已收集到的 id，不因一次扫描异常丢失删除依据。
 */
async function collectVaultTypeRecordIds(): Promise<number[]> {
  const ids = new Set<number>();

  const cached = getModuleCache<VaultTypeDef[]>(VAULT_TYPES_CACHE_KEY);
  if (cached.recordId !== null) ids.add(cached.recordId);

  let useSummary = false;
  try {
    useSummary = await ensureIndexSourceSafe();
  } catch (e) {
    log.warn("索引源准备失败，改用已收集的记录 id", e);
  }

  if (useSummary) {
    for (const id of getSummaryIdsByType(TYPE_VAULT_TYPES)) ids.add(id);
  }
  for (const id of getRecordIdsByType(TYPE_VAULT_TYPES)) ids.add(id);

  return [...ids].sort((a, b) => a - b);
}

/** 自定义类型读取结果（判别式：读取失败不得伪装成「没有类型」） */
export interface VaultTypesLoadResult {
  /** 可用的类型定义 */
  types: VaultTypeDef[];
  /**
   * 读取失败（区别于「容器内确实没有类型」）。
   * 失败时调用方应保留上次已知类型并提示，而不是把界面呈现为「零自定义类型」。
   */
  failed: boolean;
}

/**
 * 读取自定义类型定义。
 *
 * @returns 类型定义 + 读取状态；容器内无该记录或内容不可用时类型为空数组
 *
 * 顺序：模块缓存命中即返回；否则按记录 id 从大到小尝试解析（最新写入的
 * 记录 id 最大），首个可解析的记录即为结果。
 */
export async function loadCustomVaultTypes(): Promise<VaultTypesLoadResult> {
  const cached = getModuleCache<VaultTypeDef[]>(VAULT_TYPES_CACHE_KEY);
  if (cached.data !== null) return { types: cached.data, failed: false };

  let ids: number[];
  try {
    ids = await collectVaultTypeRecordIds();
  } catch (e) {
    // 索引源不可用不代表「没有类型」—— 不得写空缓存（否则本会话永久为空）
    log.warn("类型定义记录 id 收集失败，按读取失败返回且不写缓存", e);
    return { types: [], failed: true };
  }
  if (ids.length === 0) {
    setModuleCache(VAULT_TYPES_CACHE_KEY, []);
    return { types: [], failed: false };
  }

  let dataB64Map: Map<number, string>;
  try {
    dataB64Map = await getRecordsDataB64Batch(ids);
  } catch (e) {
    // 取数异常时不写缓存：空结果一旦入缓存，本会话后续读取会一直为空
    log.warn("类型定义记录批量取数失败，按读取失败返回且不写缓存", e);
    return { types: [], failed: true };
  }

  for (const id of [...ids].reverse()) {
    const b64 = dataB64Map.get(id);
    if (!b64) continue;
    const defs = parseVaultTypesRecord(b64);
    if (defs === null) continue;
    setModuleCache(VAULT_TYPES_CACHE_KEY, defs, id);
    return { types: defs, failed: false };
  }

  setModuleCache(VAULT_TYPES_CACHE_KEY, []);
  return { types: [], failed: false };
}

/**
 * 保存自定义类型定义（先写新记录，再删除被替换的旧记录）。
 *
 * @param types 类型定义集合（调用方需先经 {@link validateVaultTypeDefs} 校验）
 * @returns ok 表示新记录已写入并同步缓存；persisted 表示已落盘
 *
 * 写入后依次：回填全量缓存 → 删除旧记录并失效其三层缓存 → 回填模块缓存
 * → 触发落盘。旧记录删除失败不阻断新定义生效，但会记录告警。
 */
export async function saveCustomVaultTypes(
  types: readonly VaultTypeDef[],
): Promise<SaveCustomVaultTypesResult> {
  const normalized = sanitizeVaultTypeDefs(types);
  const dataB64 = serializeToJsonB64(normalized);

  const newId = await verthysAddRecord(TYPE_VAULT_TYPES, VAULT_TYPES_RECORD_NAME, dataB64);
  if (newId === null) {
    log.error("类型定义记录写入失败：新增记录未返回 id");
    return { ok: false, persisted: false };
  }

  addFullRecord(newId, TYPE_VAULT_TYPES, VAULT_TYPES_RECORD_NAME, dataB64, dataB64.length);

  const staleIds = await collectVaultTypeRecordIds();
  for (const staleId of staleIds) {
    if (staleId === newId) continue;
    try {
      await verthysDeleteRecord(staleId);
    } catch (e) {
      log.warn(`被替换的类型定义记录删除失败（id=${staleId}）`, e);
    }
    invalidateSummaryRecord(staleId);
    invalidateFullRecord(staleId);
    invalidateScannedRecord(staleId);
  }

  setModuleCache(VAULT_TYPES_CACHE_KEY, normalized, newId);

  let persisted = false;
  try {
    persisted = await persistVerthys();
  } catch (e) {
    log.error("类型定义落盘异常", e);
  }
  return { ok: true, persisted };
}
