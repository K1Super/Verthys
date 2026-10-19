/*
 * vault_item_card.spec.ts — 卡片视图映射、到期读数与色调变量
 *
 * 覆盖：各类型的主标题 / 次行 / 敏感行 / 到期读数选取规则、敏感值与到期字段
 * 不重复呈现、未知类型兜底展示，以及到期读数的阈值边界与色调变量映射。
 */
import { describe, it, expect } from "vitest";
import {
  VAULT_SECRET_MASK,
  VAULT_TONE_RGB_VARS,
  VAULT_UNKNOWN_TYPE_LABEL,
  buildVaultCardView,
  findCardSecretField,
  vaultExpiryReadout,
  vaultReadoutColorVar,
  vaultSearchText,
} from "./vault_item_card";
import { getBuiltinVaultType, type VaultTypeDef, type VaultTone } from "../constants/vault_item_types";

const account = getBuiltinVaultType("account")!;
const idcard = getBuiltinVaultType("idcard")!;
const bankcard = getBuiltinVaultType("bankcard")!;
const certificate = getBuiltinVaultType("certificate")!;
const address = getBuiltinVaultType("address")!;

describe("卡片视图映射", () => {
  it("账号条目：主标题取平台、次行取账户、敏感行为密码", () => {
    const view = buildVaultCardView(
      { platform: "示例平台", username: "user", password: "明文密码", note: "", encrypted: "0" },
      account,
    );
    expect(view.title).toBe("示例平台");
    expect(view.lines).toEqual([
      { fieldId: "username", label: "账户", value: "user", sensitive: false },
    ]);
    expect(view.secret).toEqual({
      fieldId: "password",
      label: "密码",
      encrypted: false,
      raw: "明文密码",
    });
    expect(view.expiry).toBeNull();
    expect(view.typeLabel).toBe("账号");
    expect(view.unknown).toBe(false);
  });

  it("账号条目已独立加密时敏感行标记密文态", () => {
    const view = buildVaultCardView({ platform: "p", encrypted: "1", password: "密文" }, account);
    expect(view.secret!.encrypted).toBe(true);
    expect(view.secret!.raw).toBe("密文");
  });

  it("敏感字段由敏感行承载，次行不重复呈现同一取值", () => {
    const view = buildVaultCardView({ name: "张三", number: "110101199001010011" }, idcard);
    expect(view.secret).toEqual({
      fieldId: "number",
      label: "号码",
      encrypted: false,
      raw: "110101199001010011",
    });
    // 号码与有效期分别由敏感行、到期读数承载，次行不再重复
    expect(view.lines).toEqual([]);
    expect(view.expiry).toMatchObject({ label: "有效期", tone: "none" });
  });

  it("敏感行的原始取值可解，且次行不含任何明文敏感值", () => {
    const view = buildVaultCardView({ name: "张三", number: "110101" }, idcard);
    expect(view.secret!.raw).toBe("110101");
    expect(view.lines.every((line) => line.value !== "110101")).toBe(true);
    expect(JSON.stringify(view.lines)).not.toContain("110101");
  });

  it("银行卡的敏感行为卡号，安全码不进入卡片视图", () => {
    expect(findCardSecretField(bankcard)!.id).toBe("number");
    const view = buildVaultCardView(
      { bank: "示例银行", number: "6222", expiry: "", cvv: "123" },
      bankcard,
    );
    expect(view.secret!.fieldId).toBe("number");
    expect(view.lines).toEqual([]);
    expect(JSON.stringify(view)).not.toContain("123");
  });

  it("承载长文本凭据的类型以该字段作为敏感行，次行保留其余可直读字段", () => {
    expect(findCardSecretField(certificate)!.id).toBe("content");
    const view = buildVaultCardView(
      { name: "站点证书", certType: "SSL/TLS", expiry: "", content: "-----BEGIN" },
      certificate,
    );
    expect(view.lines).toEqual([
      { fieldId: "certType", label: "类型", value: "SSL/TLS", sensitive: false },
    ]);
    expect(view.expiry).toMatchObject({ label: "到期" });
  });

  it("未声明到期字段的类型不产生到期读数", () => {
    expect(buildVaultCardView({ name: "公司", region: "北京市" }, address).expiry).toBeNull();
  });

  it("类型定义缺失：主标题取首个取值、次行取其后的两项，标识为未知类型", () => {
    const view = buildVaultCardView({ b: "乙", c: "丙", d: "丁" }, undefined);
    expect(view.unknown).toBe(true);
    expect(view.typeLabel).toBe(VAULT_UNKNOWN_TYPE_LABEL);
    expect(view.title).toBe("乙");
    expect(view.lines.map((l) => l.value)).toEqual(["丙", "丁"]);
    expect(view.secret).toBeNull();
    expect(view.expiry).toBeNull();
    expect(view.tone).toBe("accent");
    expect(view.icon.length).toBeGreaterThan(0);
  });

  it("类型定义缺失且数据为空：主标题与次行均为空而非留白异常", () => {
    const view = buildVaultCardView({}, undefined);
    expect(view.title).toBe("");
    expect(view.lines).toEqual([]);
  });

  it("敏感行仅取首个敏感字段，且不取仅用于窗口交互的字段", () => {
    // 账号的独立密钥字段声明为 transient，不得成为卡片敏感行
    const view = buildVaultCardView({ platform: "p", encKey: "不应出现" }, account);
    expect(view.secret!.fieldId).toBe("password");
  });
});

describe("搜索文本", () => {
  it("按类型声明的搜索字段拼接并小写化", () => {
    const text = vaultSearchText({ platform: "Example", username: "User", note: "忽略" }, account);
    expect(text).toBe("example\u0000user");
  });

  it("类型定义缺失时以全部取值参与搜索", () => {
    const text = vaultSearchText({ a: "Alpha", b: "Beta" }, undefined);
    expect(text).toBe("alpha\u0000beta");
  });
});

describe("到期读数", () => {
  const now = Date.parse("2030-01-01T00:00:00Z");

  it("未设置到期日按永久有效", () => {
    expect(vaultExpiryReadout("")).toEqual({ tone: "none", text: "永久有效" });
  });

  it("已过期按超出天数告警", () => {
    const readout = vaultExpiryReadout("2029-12-30", now);
    expect(readout.tone).toBe("expired");
    expect(readout.text).toBe("已过期 2 天");
  });

  it("当日到期按今日内到期", () => {
    expect(vaultExpiryReadout("2030-01-01T12:00:00Z", now)).toEqual({
      tone: "expiring",
      text: "今日内到期",
    });
  });

  it("临期阈值内按临期天数回显", () => {
    expect(vaultExpiryReadout("2030-01-11", now)).toEqual({ tone: "expiring", text: "10 天后到期" });
  });

  it("超出临期阈值按有效回显", () => {
    expect(vaultExpiryReadout("2030-03-01", now)).toEqual({ tone: "valid", text: "59 天后到期" });
  });

  it("无法解析的到期日按未设置处理，不产生异常读数", () => {
    expect(vaultExpiryReadout("非日期", now).tone).toBe("none");
  });

  it("读数色调对应设计令牌：有效 / 临期 / 过期各取一色，未设置不着色", () => {
    expect(vaultReadoutColorVar({ tone: "valid", text: "" })).toBe("--success-rgb");
    expect(vaultReadoutColorVar({ tone: "expiring", text: "" })).toBe("--warning-rgb");
    expect(vaultReadoutColorVar({ tone: "expired", text: "" })).toBe("--danger-rgb");
    expect(vaultReadoutColorVar({ tone: "none", text: "" })).toBeNull();
  });
});

describe("类型标识色调", () => {
  it("每种色调都映射到已定义的设计令牌变量", () => {
    const tones: VaultTone[] = ["accent", "purple", "success", "warning", "danger"];
    for (const tone of tones) {
      expect(VAULT_TONE_RGB_VARS[tone]).toMatch(/^--[a-z-]+-rgb$/);
    }
    expect(new Set(Object.values(VAULT_TONE_RGB_VARS)).size).toBe(tones.length);
  });

  it("卡片视图的色调取自类型声明", () => {
    expect(buildVaultCardView({}, certificate).tone).toBe("success");
    expect(buildVaultCardView({}, bankcard).tone).toBe("warning");
  });
});

describe("自定义类型与内置类型同构", () => {
  it("自定义类型同样按声明取主标题、次行与敏感行", () => {
    const custom: VaultTypeDef = {
      id: "custom:demo",
      label: "演示",
      icon: "note",
      tone: "purple",
      titleField: "title",
      cardFields: ["sub"],
      searchFields: ["title"],
      fields: [
        { id: "title", label: "标题", kind: "text", required: true },
        { id: "sub", label: "副标题", kind: "text" },
        { id: "secret", label: "机密", kind: "password", sensitive: true },
      ],
      builtin: false,
    };
    const view = buildVaultCardView({ title: "甲", sub: "乙", secret: "丙" }, custom);
    expect(view.title).toBe("甲");
    expect(view.lines[0]).toEqual({ fieldId: "sub", label: "副标题", value: "乙", sensitive: false });
    expect(view.secret!.raw).toBe("丙");
    expect(view.expiry).toBeNull();
  });
});

describe("掩码常量", () => {
  it("掩码为固定长度的占位字符，不含任何取值信息", () => {
    expect(VAULT_SECRET_MASK).toHaveLength(10);
    expect(VAULT_SECRET_MASK).not.toMatch(/[0-9a-zA-Z]/);
  });
});
