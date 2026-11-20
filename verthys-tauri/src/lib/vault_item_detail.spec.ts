/*
 * vault_item_detail.spec.ts — 详情视图全字段投影
 *
 * 覆盖：主标题不在字段列表重复、全部已填写字段按声明顺序进入分区、空值不占行、
 * transient 字段不回显、敏感字段保留原始取值与加密标记、日期区间端点语义、
 * 到期读数与开关开启态。
 */
import { describe, it, expect } from "vitest";
import { buildVaultDetailSections } from "./vault_item_detail";
import { getBuiltinVaultType } from "../constants/vault_item_types";

const account = getBuiltinVaultType("account")!;
const idcard = getBuiltinVaultType("idcard")!;
const passport = getBuiltinVaultType("passport")!;
const bankcard = getBuiltinVaultType("bankcard")!;
const address = getBuiltinVaultType("address")!;

const flatten = (sections: ReturnType<typeof buildVaultDetailSections>) =>
  sections.flatMap((section) => section.fields);

describe("详情字段投影", () => {
  it("地址：全部已填写字段按分区完整出现，主标题不重复", () => {
    const sections = buildVaultDetailSections(
      {
        name: "家",
        region: "广东省/深圳市/南山区",
        detail: "科技园南区\n8 栋 801",
        note: "工作日送达",
      },
      address,
    );
    expect(sections.map((section) => section.name)).toEqual(["地址", "附注"]);
    const fields = flatten(sections);
    expect(fields.map((field) => field.fieldId)).toEqual([
      "region",
      "detail",
      "note",
    ]);
    expect(fields.find((field) => field.fieldId === "detail")).toMatchObject({
      multiline: true,
      value: "科技园南区\n8 栋 801",
    });
    expect(fields.some((field) => field.fieldId === "name")).toBe(false);
  });

  it("护照：号码敏感行、全部个人信息与签发字段、有效期读数均进入详情", () => {
    const sections = buildVaultDetailSections(
      {
        name: "张三",
        number: "E12345678",
        type: "普通护照",
        country: "中国",
        nationality: "中国",
        birthDate: "1990-01-01",
        birthPlace: "北京市",
        gender: "男",
        issuePlace: "北京市",
        authority: "中华人民共和国公安部出入境管理局",
        issueDate: "2020-03-01",
        expiry: "2050-03-01",
        note: "备用证件",
      },
      passport,
    );
    expect(sections.map((section) => section.name)).toEqual([
      "证件",
      "个人信息",
      "签发",
      "附注",
    ]);
    const fields = flatten(sections);
    expect(fields.map((field) => field.fieldId)).toEqual([
      "number",
      "type",
      "country",
      "nationality",
      "birthDate",
      "birthPlace",
      "gender",
      "issuePlace",
      "authority",
      "expiry",
      "note",
    ]);
    expect(fields.find((field) => field.fieldId === "number")).toMatchObject({
      sensitive: true,
      encrypted: false,
      value: "E12345678",
    });
    expect(fields.find((field) => field.fieldId === "expiry")).toMatchObject({
      value: "签发 2020-03-01 · 到期 2050-03-01",
    });
    expect(fields.find((field) => field.fieldId === "expiry")!.readout?.tone).toBe("valid");
    expect(fields.find((field) => field.fieldId === "note")!.multiline).toBe(true);
  });

  it("银行卡：卡号是唯一敏感行，主标题银行不重复", () => {
    const sections = buildVaultDetailSections(
      { bank: "示例银行", number: "6222", type: "储蓄卡", note: "备注" },
      bankcard,
    );
    const fields = flatten(sections);
    expect(fields.map((field) => field.fieldId)).toEqual(["number", "type", "note"]);
    expect(fields.filter((field) => field.sensitive).map((field) => field.fieldId)).toEqual([
      "number",
    ]);
    expect(fields.some((field) => field.fieldId === "bank")).toBe(false);
  });

  it("账号：独立加密开关以状态文案展示，transient 密钥不回显", () => {
    const sections = buildVaultDetailSections(
      {
        platform: "示例平台",
        username: "user",
        password: "secret",
        encrypted: "1",
        encKey: "不应出现",
        note: "备注",
      },
      account,
    );
    const fields = flatten(sections);
    expect(fields.map((field) => field.fieldId)).toEqual([
      "username",
      "password",
      "encrypted",
      "note",
    ]);
    expect(fields.find((field) => field.fieldId === "password")).toMatchObject({
      sensitive: true,
      encrypted: true,
    });
    expect(fields.find((field) => field.fieldId === "encrypted")!.value).toBe("已开启");
    expect(fields.some((field) => field.fieldId === "encKey")).toBe(false);
  });

  it("开关关闭不占行：未启用独立加密时详情不出现该行", () => {
    const fields = flatten(
      buildVaultDetailSections(
        {
          platform: "示例平台",
          username: "user",
          password: "secret",
          encrypted: "0",
          note: "备注",
        },
        account,
      ),
    );
    expect(fields.map((field) => field.fieldId)).toEqual(["username", "password", "note"]);
  });

  it("空值不占行：只填主标题的地址没有任何详情分区", () => {
    expect(buildVaultDetailSections({ name: "家" }, address)).toEqual([]);
    expect(buildVaultDetailSections({ a: "1" }, undefined)).toEqual([]);
  });

  it("日期区间保留端点标签，到期留空按长期有效", () => {
    const sections = buildVaultDetailSections(
      { name: "张三", number: "110101", validFrom: "2015-01-01" },
      idcard,
    );
    const expiry = flatten(sections).find((field) => field.fieldId === "expiry")!;
    expect(expiry.value).toBe("自 2015-01-01 · 至 长期");
    expect(expiry.readout).toEqual({ tone: "none", text: "永久有效" });
  });
});
