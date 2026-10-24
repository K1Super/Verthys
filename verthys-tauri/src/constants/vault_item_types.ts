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
 *   8. 日期区间以「结束键 + 起始键」成对落盘：结束键恒为字段 id（到期语义
 *      固定取 "expiry"，卡片读数与筛选据此取值），起始键由 rangeStartId
 *      声明。区间只是一个控件形态，落盘仍是扁平键值，不引入嵌套结构。
 *   9. 地区字段只存「省/市/区」名称路径，不存行政区划代码：名称路径可直接
 *      展示与检索，且区划代码随时间调整时不会让既有记录失去可读性。
 *
 * 兼容与副作用：纯常量与纯类型声明，无副作用、无 IO，可安全并发读取。
 *   内置类型不可被用户删除或改写字段语义；自定义类型元数据的持久化由
 *   lib/vault_item_type_store 负责。
 */

/**
 * 字段控件种类（单一权威源）：决定编辑窗口渲染何种输入控件。
 * 由常量数组派生联合类型 —— 校验集合与类型声明不可能漂移。
 */
export const VAULT_FIELD_KINDS = [
  "text",
  "password",
  "date",
  "dateRange",
  "multiline",
  "select",
  "region",
  "switch",
] as const;

export type VaultFieldKind = (typeof VAULT_FIELD_KINDS)[number];

/**
 * 色调标识：取值对应既有设计令牌中的点缀色名。
 * 渲染侧据此外取实际颜色变量，未定义的色名一律落到 accent，不产生无效样式。
 * 同为常量数组派生：校验集合与类型声明单一来源。
 */
export const VAULT_TONES = ["accent", "purple", "success", "warning", "danger"] as const;

export type VaultTone = (typeof VAULT_TONES)[number];

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
  /**
   * 新增条目时的默认取值（编辑既有条目时不覆盖）。
   * 仅内置标准模板使用：让「护照类型 / 签发国家」这类常选项从可用状态开始，
   * 同时避免把默认值当作校验兜底（用户仍可清空）。
   */
  default?: string;
  /**
   * 区间起始字段 id（kind 为 dateRange 时必填）：与 id 成对落盘。
   * id 承载结束日期，因此到期读数与筛选无需感知区间形态。
   */
  rangeStartId?: string;
  /** 区间起始端标签（缺省「自」） */
  rangeStartLabel?: string;
  /** 区间结束端标签（缺省「至」） */
  rangeEndLabel?: string;
  /**
   * 展示分组名：相邻同名字段合为一个分区，缺省归入以类型名命名的单区。
   * 只影响排版，不参与落盘与校验。
   */
  group?: string;
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

/**
 * 卡片摘要字段上限（单一权威源）。
 *
 * 卡片固定为原始高度，只承载最能识别条目的少数摘要字段；完整字段由详情
 * 窗口（lib/vault_item_detail）展示。本上限约束卡片排版与类型编辑器的可选
 * 数量，写入侧截断与编辑侧校验同取本常量 —— 两处不得各存一份。
 */
export const MAX_VAULT_CARD_FIELDS = 3;

/** 表单/详情共用的展示分区 */
export interface VaultFieldSection {
  /** 分区名（相邻同名 group 合并；无 group 时取类型名） */
  name: string;
  /** 分区内字段（保持声明顺序） */
  fields: VaultFieldDef[];
}

/**
 * 按字段 group 把声明聚成相邻分区。
 *
 * 编辑窗口与详情窗口共用同一份分区规则：两处各写一套分组逻辑，必然会在
 * 新增字段组时漂移，出现「编辑分三节、详情分两节」的观感断裂。
 *
 * @param def 类型定义
 * @returns 分区清单（相邻同名合并；空类型返回空数组）
 */
export function groupVaultFieldSections(def: VaultTypeDef): VaultFieldSection[] {
  const sections: VaultFieldSection[] = [];
  let last: VaultFieldSection | null = null;
  for (const field of def.fields) {
    const name = field.group ?? def.label;
    if (!last || last.name !== name) {
      last = { name, fields: [] };
      sections.push(last);
    }
    last.fields.push(field);
  }
  return sections;
}

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
 * 取日期区间的起始字段 id。
 *
 * 声明完整时即为 rangeStartId；声明缺失时退回 `${id}Start`，让控件与落盘
 * 投影（lib/vault_item_codec）使用同一个键 —— 两处各写一套回退规则会让
 * 界面采集到的起始日写不进记录。
 *
 * @param field 日期区间字段
 * @returns 起始字段 id（恒非空）
 */
export function vaultRangeStartFieldId(field: VaultFieldDef): string {
  return field.rangeStartId ?? `${field.id}Start`;
}

/**
 * 生成日期区间的起始字段 id。
 *
 * 起始键与字段 id 共用同一张落盘表：以 `${fieldId}_start` 为基名并避开
 * 已占用键。只在字段首次切换为日期区间时生成一次，之后不随字段改名。
 *
 * @param fieldId 区间结束字段 id
 * @param existing 已占用的落盘键（字段 id 与其它区间起始键）
 * @returns 未占用的起始字段 id
 */
export function createCustomRangeStartId(
  fieldId: string,
  existing: readonly string[] = [],
): string {
  const base = `${fieldId}_start`;
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
    cardFields: ["username", "note"],
    searchFields: ["platform", "username"],
    fields: [
      { id: "platform", label: "平台", kind: "text", required: true },
      { id: "username", label: "账户", kind: "text", required: true },
      { id: "password", label: "密码", kind: "password", sensitive: true },
      { id: "encrypted", label: "独立加密", kind: "switch", hint: "查看时需二次输入独立密钥" },
      { id: "encKey", label: "密钥", kind: "password", sensitive: true, transient: true },
      /* 备注与账户半宽同排：两项刚好占满一行，避免卡片栅格出现空列 */
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
    cardFields: ["note"],
    searchFields: ["name", "number"],
    fields: [
      { id: "name", label: "姓名", kind: "text", required: true, group: "证件" },
      /* 身份号码是身份证的唯一定位依据：缺失即无法证明持证身份，故列为必填。
         字段 id 保持 "number"（落盘键名不可改），只收敛显示名与校验。 */
      { id: "number", label: "身份号码", kind: "text", required: true, sensitive: true, group: "证件" },
      /* 法定证件有效期为「签发日 → 到期日」区间：id 仍为 expiry（到期读数
         与筛选的固定取值键），rangeStartId 承载起始日。 */
      {
        id: VAULT_EXPIRY_FIELD_ID,
        label: "有效期",
        kind: "dateRange",
        rangeStartId: "validFrom",
        rangeStartLabel: "自",
        rangeEndLabel: "至",
        group: "证件",
      },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2, group: "附注" },
    ],
    builtin: true,
  },
  {
    id: "passport",
    label: "护照",
    icon: "passport",
    tone: "purple",
    titleField: "name",
    cardFields: ["type"],
    searchFields: ["name", "number", "type", "country", "authority"],
    fields: [
      { id: "name", label: "姓名", kind: "text", required: true, group: "证件" },
      { id: "number", label: "护照号码", kind: "text", sensitive: true, group: "证件" },
      {
        id: "type",
        label: "护照类型",
        kind: "select",
        options: ["普通护照", "公务护照", "公务普通护照", "外交护照", "其他"],
        default: "普通护照",
        group: "证件",
      },
      { id: "country", label: "签发国家", kind: "text", default: "中国", group: "证件" },
      { id: "nationality", label: "国籍", kind: "text", default: "中国", group: "证件" },
      { id: "birthDate", label: "出生日期", kind: "date", group: "个人信息" },
      { id: "birthPlace", label: "出生地点", kind: "text", group: "个人信息" },
      {
        id: "gender",
        label: "性别",
        kind: "select",
        options: ["男", "女", "未注明"],
        group: "个人信息",
      },
      { id: "issuePlace", label: "签发地点", kind: "text", group: "签发" },
      { id: "authority", label: "签发机关", kind: "text", group: "签发" },
      /* 标准护照的「有效期」即签发日到到期日；起始端沿用签发日的语义标签。 */
      {
        id: VAULT_EXPIRY_FIELD_ID,
        label: "有效期",
        kind: "dateRange",
        rangeStartId: "issueDate",
        rangeStartLabel: "签发",
        rangeEndLabel: "到期",
        group: "签发",
      },
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2, group: "附注" },
    ],
    builtin: true,
  },
  {
    id: "bankcard",
    label: "银行卡",
    icon: "bankcard",
    tone: "warning",
    titleField: "bank",
    cardFields: ["type", "holder"],
    searchFields: ["bank", "type", "holder"],
    fields: [
      { id: "bank", label: "银行", kind: "text", required: true, group: "账户" },
      { id: "number", label: "卡号", kind: "text", sensitive: true, group: "账户" },
      {
        id: "type",
        label: "卡类型",
        kind: "select",
        options: ["储蓄卡", "信用卡", "预付卡", "其他"],
        group: "账户",
      },
      { id: "holder", label: "持卡人", kind: "text", group: "账户" },
      { id: "cvv", label: "安全码", kind: "password", sensitive: true, group: "凭据" },
      /* 银行卡不设日期字段：卡片有效期以卡面印字为准，且 MM/YY 形态无法由
         日期控件无损承载；收藏卡号与安全码本身不依赖到期读数。 */
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2, group: "附注" },
    ],
    builtin: true,
  },
  {
    id: "certificate",
    label: "证书",
    icon: "certificate",
    tone: "success",
    titleField: "name",
    cardFields: ["certType"],
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
    cardFields: ["region", "recipient", "phone"],
    searchFields: ["name", "region", "detail", "recipient"],
    fields: [
      { id: "name", label: "名称", kind: "text", required: true, group: "地址" },
      { id: "recipient", label: "姓名", kind: "text", group: "地址" },
      { id: "phone", label: "电话", kind: "text", group: "地址" },
      /* 省市区取全国行政区划三级联动；落盘为「省/市/区」名称路径，
         历史自由文本原样保留，直到用户在联动框中显式重选。 */
      { id: "region", label: "省市区", kind: "region", group: "地址" },
      { id: "detail", label: "详细地址", kind: "multiline", multilineRows: 2, group: "地址" },
      { id: "postalCode", label: "邮政编码", kind: "text", group: "地址" },
      /* 备注与邮编同排半宽：地址卡要在有限高度内同时呈现邮编与备注，
         备注只作两行摘要，完整内容在悬浮提示与编辑窗口中查看。 */
      { id: "note", label: "备注", kind: "multiline", multilineRows: 2, group: "附注" },
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
    cardFields: ["username", "note"],
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
    cardFields: ["security", "note"],
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
