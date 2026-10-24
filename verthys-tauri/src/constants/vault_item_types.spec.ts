/*
 * vault_item_types.spec.ts — 内置类型注册表的自洽性校验
 *
 * 覆盖：类型 id 与字段 id 唯一、主标题与展示字段落在字段清单内、
 * 图标与色调取值合法，以及账号类型的字段形态与既有账户载荷一致。
 */
import { describe, it, expect } from "vitest";
import {
  BUILTIN_VAULT_TYPES,
  BUILTIN_VAULT_TYPE_IDS,
  ACCOUNT_VAULT_TYPE_ID,
  CUSTOM_VAULT_TYPE_PREFIX,
  MAX_VAULT_CARD_FIELDS,
  VAULT_EXPIRY_FIELD_ID,
  DEFAULT_VAULT_ICON_ID,
  buildVaultTypeIndex,
  createCustomFieldId,
  createCustomRangeStartId,
  createCustomVaultTypeId,
  getBuiltinVaultType,
  isBuiltinVaultTypeId,
  isCustomVaultTypeId,
  isVaultIconId,
  resolveVaultIcon,
  type VaultTypeDef,
} from "./vault_item_types";

const VALID_TONES = ["accent", "purple", "success", "warning", "danger"];

describe("内置类型注册表自洽性", () => {
  it("类型 id 与类型名均唯一", () => {
    const ids = BUILTIN_VAULT_TYPES.map((t) => t.id);
    const labels = BUILTIN_VAULT_TYPES.map((t) => t.label);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(labels).size).toBe(labels.length);
    expect(BUILTIN_VAULT_TYPE_IDS).toEqual(ids);
  });

  it("每种内置类型的字段结构自洽", () => {
    for (const def of BUILTIN_VAULT_TYPES) {
      const fieldIds = def.fields.map((f) => f.id);
      expect(def.fields.length, def.id).toBeGreaterThan(0);
      expect(new Set(fieldIds).size, def.id).toBe(fieldIds.length);
      expect(fieldIds, def.id).toContain(def.titleField);
      expect(def.cardFields.length, def.id).toBeLessThanOrEqual(MAX_VAULT_CARD_FIELDS);
      for (const fieldId of def.cardFields) expect(fieldIds, def.id).toContain(fieldId);
      expect(def.searchFields.length, def.id).toBeGreaterThan(0);
      for (const fieldId of def.searchFields) expect(fieldIds, def.id).toContain(fieldId);
      for (const field of def.fields) {
        expect(field.label.trim().length, `${def.id}.${field.id}`).toBeGreaterThan(0);
        if (field.kind === "select") {
          expect((field.options ?? []).length, `${def.id}.${field.id}`).toBeGreaterThan(0);
        }
      }
      expect(isVaultIconId(def.icon), def.id).toBe(true);
      expect(VALID_TONES, def.id).toContain(def.tone);
      expect(def.builtin, def.id).toBe(true);
    }
  });

  it("账号类型的字段形态与既有账户载荷一致", () => {
    const account = getBuiltinVaultType(ACCOUNT_VAULT_TYPE_ID);
    expect(account).toBeDefined();
    expect(account!.fields.map((f) => f.id)).toEqual([
      "platform",
      "username",
      "password",
      "encrypted",
      "encKey",
      "note",
    ]);
    expect(account!.fields.filter((f) => f.required).map((f) => f.id)).toEqual([
      "platform",
      "username",
    ]);
    // 密码在既有实现中不是必填项，声明为必填会让保存按钮提前禁用
    expect(account!.fields.find((f) => f.id === "password")?.required).toBeUndefined();
    // 独立密钥只参与窗口交互，不得写入条目数据
    expect(account!.fields.find((f) => f.id === "encKey")?.transient).toBe(true);
    expect(account!.fields.find((f) => f.id === "encrypted")?.transient).toBeUndefined();
  });

  it("到期字段 id 被需要到期语义的类型声明", () => {
    for (const typeId of ["idcard", "passport", "certificate"]) {
      const def = getBuiltinVaultType(typeId);
      expect(def!.fields.map((f) => f.id)).toContain(VAULT_EXPIRY_FIELD_ID);
    }
  });

  it("身份证：身份号码必填，有效期为「自 → 至」区间", () => {
    const def = getBuiltinVaultType("idcard")!;
    const number = def.fields.find((field) => field.id === "number")!;
    expect(number.label).toBe("身份号码");
    expect(number.required).toBe(true);
    expect(number.sensitive).toBe(true);

    const expiry = def.fields.find((field) => field.id === VAULT_EXPIRY_FIELD_ID)!;
    expect(expiry.kind).toBe("dateRange");
    expect(expiry.rangeStartId).toBe("validFrom");
    expect(expiry.rangeStartLabel).toBe("自");
    expect(expiry.rangeEndLabel).toBe("至");
  });

  it("护照：标准证件字段齐备，有效期为「签发 → 到期」区间", () => {
    const def = getBuiltinVaultType("passport")!;
    const ids = def.fields.map((field) => field.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        "name",
        "number",
        "type",
        "country",
        "nationality",
        "birthDate",
        "birthPlace",
        "gender",
        "issuePlace",
        "authority",
        VAULT_EXPIRY_FIELD_ID,
        "note",
      ]),
    );
    expect(def.fields.find((field) => field.id === "type")!.options).toContain("普通护照");
    expect(def.fields.find((field) => field.id === "country")!.default).toBe("中国");

    const expiry = def.fields.find((field) => field.id === VAULT_EXPIRY_FIELD_ID)!;
    expect(expiry.kind).toBe("dateRange");
    expect(expiry.rangeStartId).toBe("issueDate");
    expect(expiry.rangeStartLabel).toBe("签发");
    expect(expiry.rangeEndLabel).toBe("到期");
  });

  it("银行卡：标准字段齐备且不含任何日期字段", () => {
    const def = getBuiltinVaultType("bankcard")!;
    const ids = def.fields.map((field) => field.id);
    expect(ids).toEqual(
      expect.arrayContaining(["bank", "number", "type", "holder", "cvv", "note"]),
    );
    expect(ids).not.toContain(VAULT_EXPIRY_FIELD_ID);
    // 日期控件与日期区间都不得出现（银行卡模板按需求完全移除日期）
    expect(def.fields.some((field) => field.kind === "date" || field.kind === "dateRange")).toBe(false);
    expect(def.cardFields).not.toContain(VAULT_EXPIRY_FIELD_ID);
  });

  it("地址：省市区使用全国三级联动的地区控件，姓名/电话为卡片摘要", () => {
    const def = getBuiltinVaultType("address")!;
    const region = def.fields.find((field) => field.id === "region")!;
    expect(region.kind).toBe("region");

    expect(def.fields.find((field) => field.id === "recipient")!.label).toBe("姓名");
    expect(def.fields.find((field) => field.id === "phone")!.label).toBe("电话");
    expect(def.cardFields).toEqual(["region", "recipient", "phone"]);
  });

  it("卡片摘要字段保持精简：完整字段由详情窗口承载", () => {
    const passport = getBuiltinVaultType("passport")!;
    expect(passport.cardFields).toEqual(["type"]);
    const address = getBuiltinVaultType("address")!;
    expect(address.cardFields.length).toBe(3);
  });
});

describe("类型查询与索引", () => {
  it("内置类型判定与查询", () => {
    expect(isBuiltinVaultTypeId("account")).toBe(true);
    expect(isBuiltinVaultTypeId("custom:abc")).toBe(false);
    expect(getBuiltinVaultType("not-exists")).toBeUndefined();
  });

  it("自定义类型 id 前缀判定", () => {
    expect(isCustomVaultTypeId(`${CUSTOM_VAULT_TYPE_PREFIX}1`)).toBe(true);
    expect(isCustomVaultTypeId("account")).toBe(false);
  });

  it("合并索引以内置类型为准，自定义类型按 id 补入", () => {
    const custom: VaultTypeDef = {
      id: `${CUSTOM_VAULT_TYPE_PREFIX}abc`,
      label: "自定义",
      icon: "generic",
      tone: "accent",
      titleField: "f_a",
      cardFields: ["f_a"],
      searchFields: ["f_a"],
      fields: [{ id: "f_a", label: "甲", kind: "text" }],
      builtin: false,
    };
    const hijack: VaultTypeDef = { ...custom, id: ACCOUNT_VAULT_TYPE_ID, label: "伪装账号" };
    const index = buildVaultTypeIndex([custom, hijack]);
    expect(index.get(ACCOUNT_VAULT_TYPE_ID)!.label).toBe("账号");
    expect(index.get(custom.id)!.label).toBe("自定义");
    expect(index.size).toBe(BUILTIN_VAULT_TYPES.length + 1);
  });

  it("图标键名非法时回落到缺省图标", () => {
    expect(resolveVaultIcon("account")).toContain("<svg");
    expect(resolveVaultIcon("not-in-library")).toBe(resolveVaultIcon(DEFAULT_VAULT_ICON_ID));
    expect(resolveVaultIcon("not-in-library").length).toBeGreaterThan(0);
    expect(isVaultIconId("not-in-library")).toBe(false);
  });
});

describe("自定义标识生成", () => {
  it("类型 id 带自定义前缀且每次不同（不复用旧 id）", () => {
    const first = createCustomVaultTypeId();
    const second = createCustomVaultTypeId();
    expect(isCustomVaultTypeId(first)).toBe(true);
    expect(isCustomVaultTypeId(second)).toBe(true);
    expect(first).not.toBe(second);
  });

  it("字段 id 由显示名生成 slug，非 ASCII 名退回序号形式", () => {
    expect(createCustomFieldId("Card Number")).toBe("f_card_number");
    expect(createCustomFieldId("  邮箱  ")).toBe("f_field");
  });

  it("字段 id 冲突时追加序号，且避开已占用的序号", () => {
    expect(createCustomFieldId("Mail", ["f_mail"])).toBe("f_mail_2");
    expect(createCustomFieldId("Mail", ["f_mail", "f_mail_2"])).toBe("f_mail_3");
  });

  it("区间起始键由字段 id 派生，并避开已占用的落盘键", () => {
    expect(createCustomRangeStartId("f_range")).toBe("f_range_start");
    expect(createCustomRangeStartId("f_range", ["f_range_start"])).toBe("f_range_start_2");
    expect(createCustomRangeStartId("f_range", ["f_range_start", "f_range_start_2"])).toBe(
      "f_range_start_3",
    );
  });
});
