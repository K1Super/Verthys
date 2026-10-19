/*
 * constants/vault_item_types.ts — 统一条目类型注册表（单一真相源）
 *
 * 用途：声明「一种条目类型长什么样」——字段清单、表单控件种类、主标题字段、
 *   卡片次行字段、参与搜索的字段，以及类型标识所用的图标与色调。
 *
 * 职责边界：本模块只做声明，不含序列化、读写、缓存、校验与渲染逻辑。
 *   条目数据落盘形态由 lib/vault_item_codec 决定；自定义类型的容器读写
 *   由 lib/vault_item_type_store 承担；卡片视图映射由 lib/vault_item_card 承担。
 *
 * 关键约束：
 *   1. 字段 id 是落盘的键名，一旦有数据写入即不可更改（改 id 等同改数据结构）。
 *   2. 账号类型（id 为 "account"）的字段 id 必须与既有账户记录载荷的键名
 *      逐字一致，且必填项只含平台与账户，以保证账号条目与既有实现的行为一致。
 *   3. 自定义类型与内置类型同构：界面完全由本模块的声明驱动；新增一种类型
 *      只是新增一条声明数据，不新增代码分支。
 *   4. icon 取 VAULT_ICON_LIBRARY 的键名而非内联标记：图标集合封闭，
 *      渲染入口只接受库内键名，从根上杜绝标记注入。
 *   5. tone 只取既有设计令牌中的点缀色名，不引入未定义的颜色变量。
 *   6. 到期语义固定使用字段 id "expiry"（VAULT_EXPIRY_FIELD_ID）：
 *      卡片到期读数与到期筛选按该 id 取值，类型声明不再重复标注。
 *   7. transient 字段只在编辑窗口采集、不写入条目数据，用于"独立密钥"这类
 *      仅供当次加密使用的输入，避免密钥材料随记录落盘。
 *
 * 兼容与副作用：纯常量与纯类型声明，无副作用、无 IO，可安全并发读取。
 *   内置类型不可被用户删除或改写字段语义；自定义类型元数据的持久化由
 *   lib/vault_item_type_store 负责。
 */

/** 字段控件种类：决定编辑窗口渲染何种输入控件 */
export type VaultFieldKind = "text" | "password" | "date" | "multiline" | "select" | "switch";

/**
 * 色调标识：取值对应既有设计令牌中的点缀色名。
 * 渲染侧据此外取实际颜色变量，未定义的色名一律落到 accent，不产生无效样式。
 */
export type VaultTone = "accent" | "purple" | "success" | "warning" | "danger";

/**
 * 图标库：键名为图标 id，值为 24×24 描边标记。
 * 集合封闭——类型声明与自定义类型只引用键名，渲染入口按键名取标记，
 * 因此不存在把外部标记注入界面的路径。
 */
export const VAULT_ICON_LIBRARY = {
  account:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/></svg>',
  idcard:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2.5" y="5" width="19" height="14" rx="2"/><circle cx="8.5" cy="11" r="2"/><path d="M5 16.5c.8-1.6 2-2.4 3.5-2.4s2.7.8 3.5 2.4"/><path d="M14 9.5h5"/><path d="M14 12.5h5"/><path d="M14 15.5h3"/></svg>',
  passport:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="3" width="14" height="18" rx="2"/><circle cx="12" cy="10" r="3"/><path d="M9 16.5h6"/></svg>',
  bankcard:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2.5" y="5.5" width="19" height="13" rx="2"/><path d="M2.5 10h19"/><path d="M6 14.5h4"/></svg>',
  certificate:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="9" r="5"/><path d="M9 13.5 8 21l4-2.2 4 2.2-1-7.5"/></svg>',
  secretkey:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="12" r="4"/><path d="M12 12h9"/><path d="M17.5 12v3"/><path d="M20.5 12v2"/></svg>',
  address:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 21s7-5.6 7-11a7 7 0 0 0-14 0c0 5.4 7 11 7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>',
  email:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2.5" y="5" width="19" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/></svg>',
  social:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.3 10.8 15.7 7.2"/><path d="M8.3 13.2l7.4 3.6"/></svg>',
  wifi:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2.5 9.5a15 15 0 0 1 19 0"/><path d="M6 13a10 10 0 0 1 12 0"/><path d="M9.5 16.5a5 5 0 0 1 5 0"/><circle cx="12" cy="19.4" r="0.8" fill="currentColor"/></svg>',
  server:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="6.5" rx="1.5"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.5"/><path d="M7 7.2h.01"/><path d="M7 16.7h.01"/></svg>',
  note:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5 4.5h11l3 3v12H5z"/><path d="M8.5 9.5h7"/><path d="M8.5 13h7"/><path d="M8.5 16.5h4"/></svg>',
  lock:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/></svg>',
  generic:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.6" fill="currentColor"/></svg>',
} as const;

/** 图标库键名（类型声明只允许引用此集合内的键） */
export type VaultIconId = keyof typeof VAULT_ICON_LIBRARY;

/** 图标缺省值：图标键名非法时一律回落到此图标，界面不出现空图标 */
export const DEFAULT_VAULT_ICON_ID: VaultIconId = "generic";

/** 判断字符串是否为库内合法图标 id（供存储读取侧校验） */
export function isVaultIconId(id: string): id is VaultIconId {
  return Object.prototype.hasOwnProperty.call(VAULT_ICON_LIBRARY, id);
}

/**
 * 按图标 id 取标记文本。
 *
 * @param id 图标键名（可能来自存储，故按未知值处理）
 * @returns 库内标记；键名非法时返回缺省图标标记
 */
export function resolveVaultIcon(id: string): string {
  const library = VAULT_ICON_LIBRARY as Record<string, string>;
  return library[id] ?? VAULT_ICON_LIBRARY[DEFAULT_VAULT_ICON_ID];
}

/** 条目字段定义：编辑窗口按 fields 顺序渲染，落盘按 id 写入数据字典 */
export interface VaultFieldDef {
  /** 字段 id：落盘键名，稳定且不可更改 */
  id: string;
  /** 字段显示名（编辑窗口标签） */
  label: string;
  /** 控件种类 */
  kind: VaultFieldKind;
  /** 是否必填：决定保存按钮禁用条件与保存前校验 */
  required?: boolean;
  /** 是否敏感：卡片默认掩码，查看需解密；账号密码另走独立密钥 */
  sensitive?: boolean;
  /** 是否仅采集不落盘（如独立密钥），默认 false */
  transient?: boolean;
  /** 是否以内容舱承载（长文本凭据：支持拖拽与导入文件），默认 false */
  carrier?: boolean;
  /** 候选项（kind 为 select 时生效） */
  options?: string[];
  /** 文本行数（kind 为 multiline 时生效） */
  multilineRows?: number;
  /** 字段说明（可选，编辑窗口提示语） */
  hint?: string;
}

/** 条目类型定义：界面、卡片与搜索的单一驱动来源 */
export interface VaultTypeDef {
  /** 类型 id：内置为短标识，自定义以 CUSTOM_VAULT_TYPE_PREFIX 开头 */
  id: string;
  /** 类型名（类型标识、筛选、编辑窗口标题共用） */
  label: string;
  /** 图标库键名 */
  icon: VaultIconId;
  /** 色调标识 */
  tone: VaultTone;
  /** 卡片主标题取哪个字段的值 */
  titleField: string;
  /** 卡片次行展示字段（顺序即展示顺序，最多 3 项） */
  cardFields: string[];
  /** 参与搜索的字段 */
  searchFields: string[];
  /** 字段清单（顺序即表单顺序） */
  fields: VaultFieldDef[];
  /** 是否内置：内置类型不可被用户删除或改写 */
  builtin: boolean;
}

/**
 * 条目载荷信封：类型 id + 字段值字典。
 * 字段值一律为字符串：掩码、截断与序列化都不依赖具体类型，
 * 布尔与数值在写入前由调用方转为字符串（布尔用 "1"/"0"）。
 */
export interface VaultItemPayload {
  /** 类型 id（内置 id 或自定义 id） */
  kind: string;
  /** 字段值字典（键为 VaultFieldDef.id） */
  data: Record<string, string>;
}

/** 账号类型 id：与既有账户记录共用同一类型，保证账号条目形态不变 */
export const ACCOUNT_VAULT_TYPE_ID = "account";

/** 到期字段 id：卡片到期读数与到期筛选固定按此 id 取值 */
export const VAULT_EXPIRY_FIELD_ID = "expiry";

/** 自定义类型 id 前缀：区分内置与自定义，便于按前缀路由与校验 */
export const CUSTOM_VAULT_TYPE_PREFIX = "custom:";

/** 判断类型 id 是否为自定义类型 */
export function isCustomVaultTypeId(id: string): boolean {
  return id.startsWith(CUSTOM_VAULT_TYPE_PREFIX);
}

/**
 * 生成自定义类型 id。
 *
 * 用随机标识而非递增序号：类型被删除后其 id 不得被复用——复用会让仍在容器内的
 * 历史条目被误解释为另一种类型。随机标识在空间上排除了这种碰撞。
 *
 * @returns 以自定义前缀开头的类型 id
 */
export function createCustomVaultTypeId(): string {
  const uuid = globalThis.crypto?.randomUUID?.();
  if (uuid) return `${CUSTOM_VAULT_TYPE_PREFIX}${uuid}`;
  return `${CUSTOM_VAULT_TYPE_PREFIX}${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * 由字段显示名生成字段 id。
 *
 * @param label 字段显示名
 * @param existing 已占用的字段 id（同类型内）
 * @returns 未被占用的字段 id
 *
 * 字段 id 是落盘键名：只在字段创建时生成一次，之后改名不改 id——改 id 会让
 * 既有条目读不到该字段。中文等非 ASCII 名称无法构成可读 slug 时退回序号形式。
 */
export function createCustomFieldId(label: string, existing: readonly string[] = []): string {
  const slug = label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");

  const base = slug ? `f_${slug}` : "f_field";
  if (!existing.includes(base)) return base;

  let index = 2;
  while (existing.includes(`${base}_${index}`)) index += 1;
  return `${base}_${index}`;
}

/**
 * 内置类型表（编译期常量，顺序即类型选择台的展示顺序）。
 *
 * 每条类型的字段 id 均为语义化短标识；账号类型的 id 与既有账户载荷键名
 * 逐字一致（platform/username/password/note/encrypted），并额外声明
 * transient 的 encKey 供编辑窗口采集独立密钥。
 */
export const BUILTIN_VAULT_TYPES: readonly VaultTypeDef[] = [
  {
    id: ACCOUNT_VAULT_TYPE_ID,
    label: "账号",
    icon: "account",
    tone: "accent",
    titleField: "platform",
    cardFields: ["username"],
    searchFields: ["platform", "username"],
    fields: [
      { id: "platform", label: "平台", kind: "text", required: true },
      { id: "username", label: "账户", kind: "text", required: true },
      { id: "password", label: "密码", kind: "password", sensitive: true },
      { id: "encrypted", label: "独立加密", kind: "switch", hint: "查看时需二次输入独立密钥" },
      { id: "encKey", label: "密钥", kind: "password", sensitive: true, transient: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "idcard",
    label: "身份证",
    icon: "idcard",
    tone: "purple",
    titleField: "name",
    cardFields: ["number", VAULT_EXPIRY_FIELD_ID],
    searchFields: ["name", "number"],
    fields: [
      { id: "name", label: "姓名", kind: "text", required: true },
      { id: "number", label: "号码", kind: "text", sensitive: true },
      { id: VAULT_EXPIRY_FIELD_ID, label: "有效期", kind: "date" },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "passport",
    label: "护照",
    icon: "passport",
    tone: "purple",
    titleField: "name",
    cardFields: ["number", VAULT_EXPIRY_FIELD_ID],
    searchFields: ["name", "number"],
    fields: [
      { id: "name", label: "姓名", kind: "text", required: true },
      { id: "number", label: "号码", kind: "text", sensitive: true },
      { id: VAULT_EXPIRY_FIELD_ID, label: "有效期", kind: "date" },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "bankcard",
    label: "银行卡",
    icon: "bankcard",
    tone: "warning",
    titleField: "bank",
    cardFields: ["number", VAULT_EXPIRY_FIELD_ID],
    searchFields: ["bank", "number"],
    fields: [
      { id: "bank", label: "银行", kind: "text", required: true },
      { id: "number", label: "卡号", kind: "text", sensitive: true },
      { id: VAULT_EXPIRY_FIELD_ID, label: "有效期", kind: "date" },
      { id: "cvv", label: "安全码", kind: "password", sensitive: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "certificate",
    label: "证书",
    icon: "certificate",
    tone: "success",
    titleField: "name",
    cardFields: ["certType", VAULT_EXPIRY_FIELD_ID],
    searchFields: ["name", "certType"],
    fields: [
      { id: "name", label: "名称", kind: "text", required: true },
      {
        id: "certType",
        label: "类型",
        kind: "select",
        options: ["SSL/TLS", "CA", "代码签名", "客户端", "其他"],
      },
      { id: VAULT_EXPIRY_FIELD_ID, label: "到期", kind: "date" },
      { id: "content", label: "内容", kind: "multiline", sensitive: true, carrier: true, multilineRows: 5 },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "secretkey",
    label: "密钥",
    icon: "secretkey",
    tone: "danger",
    titleField: "name",
    cardFields: ["alg", "fingerprint"],
    searchFields: ["name", "alg", "fingerprint"],
    fields: [
      { id: "name", label: "名称", kind: "text", required: true },
      { id: "alg", label: "算法", kind: "text" },
      { id: "fingerprint", label: "指纹", kind: "text" },
      { id: "key", label: "密钥内容", kind: "multiline", sensitive: true, carrier: true, multilineRows: 5 },
      { id: "passphrase", label: "口令", kind: "password", sensitive: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "address",
    label: "地址",
    icon: "address",
    tone: "accent",
    titleField: "name",
    cardFields: ["region"],
    searchFields: ["name", "region", "detail"],
    fields: [
      { id: "name", label: "名称", kind: "text", required: true },
      { id: "region", label: "省市区", kind: "text" },
      { id: "detail", label: "详细地址", kind: "multiline", multilineRows: 2 },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "email",
    label: "邮箱",
    icon: "email",
    tone: "accent",
    titleField: "address",
    cardFields: ["note"],
    searchFields: ["address", "note"],
    fields: [
      { id: "address", label: "地址", kind: "text", required: true },
      { id: "password", label: "密码", kind: "password", sensitive: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "social",
    label: "社交",
    icon: "social",
    tone: "purple",
    titleField: "platform",
    cardFields: ["username"],
    searchFields: ["platform", "username", "note"],
    fields: [
      { id: "platform", label: "平台", kind: "text", required: true },
      { id: "username", label: "账号", kind: "text", required: true },
      { id: "password", label: "密码", kind: "password", sensitive: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "wifi",
    label: "Wi-Fi",
    icon: "wifi",
    tone: "success",
    titleField: "ssid",
    cardFields: ["security"],
    searchFields: ["ssid", "security"],
    fields: [
      { id: "ssid", label: "SSID", kind: "text", required: true },
      { id: "security", label: "加密方式", kind: "select", options: ["WPA3", "WPA2", "WEP", "开放"] },
      { id: "password", label: "密码", kind: "password", sensitive: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "server",
    label: "服务器",
    icon: "server",
    tone: "accent",
    titleField: "host",
    cardFields: ["username", "port"],
    searchFields: ["host", "username", "port"],
    fields: [
      { id: "host", label: "主机", kind: "text", required: true },
      { id: "port", label: "端口", kind: "text" },
      { id: "username", label: "用户名", kind: "text" },
      { id: "key", label: "密钥", kind: "password", sensitive: true },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2 },
    ],
    builtin: true,
  },
  {
    id: "note",
    label: "便签",
    icon: "note",
    tone: "warning",
    titleField: "title",
    cardFields: ["body"],
    searchFields: ["title", "body"],
    fields: [
      { id: "title", label: "标题", kind: "text", required: true },
      { id: "body", label: "内容", kind: "multiline", multilineRows: 4 },
    ],
    builtin: true,
  },
];

/** 内置类型 id 集合（自定义类型校验时作为保留 id，避免覆盖内置类型） */
export const BUILTIN_VAULT_TYPE_IDS: readonly string[] = BUILTIN_VAULT_TYPES.map((t) => t.id);

/** 内置类型索引（按 id 查询为 O(1)，供渲染与搜索路径反复查表） */
const BUILTIN_VAULT_TYPE_INDEX: ReadonlyMap<string, VaultTypeDef> = new Map(
  BUILTIN_VAULT_TYPES.map((t) => [t.id, t]),
);

/**
 * 按 id 取内置类型定义。
 *
 * @param id 类型 id
 * @returns 内置类型定义；未命中返回 undefined（调用方可继续查自定义类型索引）
 */
export function getBuiltinVaultType(id: string): VaultTypeDef | undefined {
  return BUILTIN_VAULT_TYPE_INDEX.get(id);
}

/** 类型 id 是否为内置类型 */
export function isBuiltinVaultTypeId(id: string): boolean {
  return BUILTIN_VAULT_TYPE_INDEX.has(id);
}

/**
 * 由内置类型与自定义类型合并出查询索引。
 *
 * @param customDefs 自定义类型定义（可为空）
 * @returns 类型 id → 定义 的只读索引；自定义类型 id 与内置重复时以内置为准
 */
export function buildVaultTypeIndex(
  customDefs: readonly VaultTypeDef[] = [],
): ReadonlyMap<string, VaultTypeDef> {
  const index = new Map<string, VaultTypeDef>(BUILTIN_VAULT_TYPE_INDEX);
  for (const def of customDefs) {
    if (!index.has(def.id)) index.set(def.id, def);
  }
  return index;
}
