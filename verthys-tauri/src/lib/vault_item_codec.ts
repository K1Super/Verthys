/*
 * lib/vault_item_codec.ts — 统一条目载荷编解码与敏感字段保存决策
 *
 * 用途：
 *   1. 条目信封 {kind, data} 与 base64 文本之间的往返编解码；
 *   2. 由字段清单与表单取值投影出落盘数据字典；
 *   3. 由落盘数据字典还原账号字段（账号条目的内存形态）；
 *   4. 独立加密字段在保存时该写入哪种取值与加密标记的纯决策。
 *
 * 关键约束：
 *   - 字段值一律为字符串：布尔用 "1"/"0"，数值转十进制字符串；编码侧
 *     统一归一化，保证落盘形态只有一种（避免同一字段出现两种类型）。
 *   - 读取侧对损坏输入兜底而不抛错：单条损坏记录不得让整个列表加载失败。
 *   - 账号字段映射的键名与既有账户载荷逐字一致，账号条目保持既有形态。
 *   - 保存决策只做判定，不触碰密钥材料；真正的加密动作由调用方执行，
 *     因此本模块无副作用、可并发调用、可单测。
 *   - 独立加密的取值判定依据「既有取值本身是否已是密文」，不以"取值是否
 *     变化"为唯一依据，避免把明文以已加密名义落盘造成不可查看。
 *
 * 线程与副作用：纯函数模块，无 IO、无全局状态。
 */
import type { AccountFields } from "../types/verthys";
import type { VaultItemPayload, VaultTypeDef } from "../constants/vault_item_types";
import { ACCOUNT_VAULT_TYPE_ID } from "../constants/vault_item_types";
import { deserializeFromJsonB64, serializeToJsonB64 } from "../utils/json_codec";
import { createLogger } from "../utils/logger";

const log = createLogger("vault-item-codec");

/** 判断是否为普通对象（排除 null、数组与函数） */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 归一化字段值字典：只保留可安全承载的值，其余丢弃。
 *
 * @param raw 未知来源的取值集合（可能来自存储）
 * @returns 仅含字符串值的字典；非对象输入返回空字典
 *
 * 布尔转 "1"/"0"、有限数值转十进制字符串，是为让落盘形态单一；
 * null、未定义、数组与对象一律丢弃，避免把不可表达的值写入记录。
 */
export function normalizeVaultData(raw: unknown): Record<string, string> {
  const data: Record<string, string> = {};
  if (!isPlainObject(raw)) return data;

  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "string") {
      data[key] = value;
    } else if (typeof value === "number" && Number.isFinite(value)) {
      data[key] = String(value);
    } else if (typeof value === "boolean") {
      data[key] = value ? "1" : "0";
    }
  }
  return data;
}

/**
 * 归一化条目信封：补齐缺失类型、清洗字段值。
 *
 * 兼容三种合法落盘形态（按优先级嗅探，识别成功一律产出信封）：
 *   1. 信封形态 `{ kind, data }` —— 当前写入形态；
 *   2. 旧版账号形态（扁平 AccountFields：`platform` / `username` 同现）——
 *      v0x10 账户记录迁入 0x02 时载荷原样搬运，未改写结构；
 *   3. 旧版账号形态的布尔标记：`encrypted: true/false` 经归一化转 "1"/"0"。
 *
 * 判据为「结构形状」而非记录类型：同一记录类型下历史载荷共存，
 * 若只认信封形态，旧记录会被读成空载荷并在列表侧被当作损坏丢弃 ——
 * 用户观感即「升级后账号全部消失」。
 *
 * @param raw 未知来源的信封对象
 * @returns 合法信封；结构无法识别时返回 null（由调用方判为不可读，
 *          不得降级为空信封 —— 那会把「损坏」伪装成「空条目」）
 */
function normalizeVaultItemPayload(raw: unknown): VaultItemPayload | null {
  if (!isPlainObject(raw)) return null;

  /* 形态 1：信封 —— data 必须是对象（空对象合法，代表「无字段」） */
  if (isPlainObject(raw.data)) {
    const rawKind = raw.kind;
    const kind =
      typeof rawKind === "string" && rawKind.length > 0 ? rawKind : ACCOUNT_VAULT_TYPE_ID;
    if (kind !== rawKind) {
      log.warn("条目信封缺少合法类型 id，按账号类型兜底");
    }
    return { kind, data: normalizeVaultData(raw.data) };
  }

  /* 形态 2：旧版扁平账号载荷 —— 以平台/账户双键同现为识别依据
     （这两个键是账号类型的必填字段，命中即几乎不可能是其它结构） */
  if (typeof raw.platform === "string" && typeof raw.username === "string") {
    return { kind: ACCOUNT_VAULT_TYPE_ID, data: normalizeVaultData(raw) };
  }

  return null;
}

/**
 * 获取条目载荷的 base64 文本（写入侧唯一出口）。
 *
 * @param payload 条目信封
 * @returns base64 文本
 */
export function serializeVaultItem(payload: VaultItemPayload): string {
  return serializeToJsonB64({
    kind: payload.kind,
    data: normalizeVaultData(payload.data),
  });
}

/** 条目载荷解码失败的原因（供界面区分「空记录」与「损坏记录」） */
export type VaultDecodeFailure =
  /** 载荷为空 */
  | "empty"
  /** base64 / JSON 解码失败 */
  | "undecodable"
  /** 结构可解析但不属于任何已知载荷形态 */
  | "unrecognized";

/** 条目载荷解码结果（判别式：失败不得伪装成空信封） */
export type VaultDecodeResult =
  | {
      ok: true;
      payload: VaultItemPayload;
      /** 是否为旧版扁平账号载荷（调用方可据此在首次编辑时按新形态重写） */
      legacy: boolean;
    }
  | { ok: false; reason: VaultDecodeFailure };

/**
 * 解码条目载荷（唯一读取入口）。
 *
 * @param b64 base64 文本（可能来自存储，按未知输入处理）
 * @returns 判别式结果；不抛错，失败原因交调用方呈现
 *
 * 失败与「空条目」必须可区分：前者是数据不可读（用户仍需看见该记录存在），
 * 后者是合法但无字段值的信封。混为一谈会把损坏记录从界面上抹掉。
 */
export function decodeVaultItem(b64: string): VaultDecodeResult {
  if (!b64) return { ok: false, reason: "empty" };

  let raw: unknown;
  try {
    raw = deserializeFromJsonB64<unknown>(b64);
  } catch (e) {
    log.warn("条目载荷反序列化失败", e);
    return { ok: false, reason: "undecodable" };
  }

  const payload = normalizeVaultItemPayload(raw);
  if (!payload) {
    log.warn("条目载荷结构无法识别（既非信封亦非旧版账号形态）");
    return { ok: false, reason: "unrecognized" };
  }

  const legacy = !(isPlainObject(raw) && isPlainObject(raw.data));
  return { ok: true, payload, legacy };
}

/**
 * 由字段清单与表单取值投影出落盘数据字典。
 *
 * @param def 类型定义（提供字段顺序与落盘键名）
 * @param values 表单取值（键为字段 id）
 * @returns 数据字典：仅含非 transient 字段，缺失取值落为空串
 *
 * transient 字段（如独立密钥）只参与当次窗口交互，不进入数据字典，
 * 以避免密钥材料随记录落盘。
 */
export function buildVaultItemData(
  def: VaultTypeDef,
  values: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const data: Record<string, string> = {};
  for (const field of def.fields) {
    if (field.transient) continue;
    data[field.id] = values[field.id] ?? "";
  }
  return data;
}

/**
 * 由数据字典还原账号字段。
 *
 * @param data 数据字典（键为账号类型的字段 id）
 * @returns 账号字段；缺失键回落为空串，"1" 视为已独立加密
 */
export function vaultDataToAccountFields(data: Readonly<Record<string, string>>): AccountFields {
  return {
    platform: data.platform ?? "",
    username: data.username ?? "",
    password: data.password ?? "",
    note: data.note ?? "",
    encrypted: data.encrypted === "1",
  };
}

/** 独立加密字段的保存动作 */
export type SecretSaveAction =
  /** 明文落盘（未启用独立加密） */
  | "plain"
  /** 沿用既有密文（既有已加密且取值未改动） */
  | "reuse"
  /** 按当前取值加密后再落盘 */
  | "encrypt"
  /** 已启用独立加密但缺少密钥，需在窗口内联提示并中止保存 */
  | "needs-key";

/** 独立加密字段的保存决策结果 */
export interface SecretSavePlan {
  /** 保存动作 */
  action: SecretSaveAction;
  /**
   * 该字段应写入记录的取值：
   * reuse 为既有密文；plain 与 encrypt 为窗口当前取值；needs-key 为空串。
   */
  value: string;
  /** 该字段应写入记录的独立加密标记 */
  encrypted: boolean;
}

/** 独立加密字段的保存决策入参 */
export interface SecretSaveInput {
  /** 既有条目该字段是否已独立加密（新增条目为 false） */
  previousEncrypted: boolean;
  /**
   * 既有条目该字段在记录中的原始取值。
   * 既有已加密时为密文，编辑窗口回填的即此值。
   */
  previousValue: string;
  /** 编辑窗口当前取值 */
  currentValue: string;
  /** 本次保存是否启用独立加密 */
  enableEncryption: boolean;
  /** 本次是否已提供独立密钥 */
  hasKey: boolean;
}

/**
 * 判定独立加密字段的保存方式。
 *
 * 判定依据是「既有取值本身是否已是密文」，而不是"取值是否变化"：
 *   - 既有已加密且取值未改动 → 沿用原密文，不二次加密（二次加密会使密文
 *     套密文，任何密钥都无法解出原文）；
 *   - 既有为明文而本次新开启加密 → 无论取值是否与原文相同都必须加密；
 *   - 取值已改动 → 必须按新值加密；
 *   - 需要加密却未提供密钥 → 返回 needs-key，由窗口内联提示而非静默放弃。
 *
 * 前置条件：既有取值已是密文时，调用方不得关闭独立加密（该分支不在判定
 * 覆盖范围内，账号编辑窗口在既有加密时禁用开关以保证此前提）。
 *
 * @param input 保存决策入参
 * @returns 保存决策：动作、应写入的取值与加密标记
 */
export function resolveSecretSaveAction(input: SecretSaveInput): SecretSavePlan {
  if (!input.enableEncryption) {
    return { action: "plain", value: input.currentValue, encrypted: false };
  }

  const unchanged = input.currentValue === input.previousValue;
  if (input.previousEncrypted && unchanged) {
    return { action: "reuse", value: input.previousValue, encrypted: true };
  }
  if (!input.hasKey) {
    return { action: "needs-key", value: "", encrypted: true };
  }
  return { action: "encrypt", value: input.currentValue, encrypted: true };
}
