/*
 * vault_item_card.spec.ts — 卡片视图映射、到期读数与色调变量
 *
 * 覆盖：各类型的主标题 / 次行 / 敏感行 / 到期读数选取规则、敏感值与到期字段
 * 不重复呈现、未知类型只披露数据量而不回显取值与检索、到期读数的阈值边界
 * 与本地日历日口径、色调变量映射。
 */
import { describe, it, expect } from "vitest";
import {
  VAULT_SECRET_MASK,
  VAULT_TONE_RGB_VARS,
  VAULT_UNKNOWN_TYPE_LABEL,
  buildVaultCardView,
  vaultExpiryReadout,
  vaultReadoutColorVar,
  vaultSearchText,
} from "./vault_item_card";
import { getBuiltinVaultType, type VaultTypeDef, type VaultTone } from "../constants/vault_item_types";

const account = getBuiltinVaultType("account")!;
const idcard = getBuiltinVaultType("idcard")!;
const passport = getBuiltinVaultType("passport")!;
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
      label: "身份号码",
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

  it("银行卡的敏感行包含卡号与安全码，且安全码不进入明文次行", () => {
    const view = buildVaultCardView(
      { bank: "示例银行", number: "6222", type: "储蓄卡", holder: "张三", cvv: "123", expiry: "2030-01-01" },
      bankcard,
    );
    expect(view.secret!.fieldId).toBe("number");
    expect(view.secrets.map((secret) => secret.fieldId)).toEqual(["number", "cvv"]);
    expect(view.secrets.map((secret) => secret.label)).toEqual(["卡号", "安全码"]);
    expect(view.lines).toEqual([
      { fieldId: "type", label: "卡类型", value: "储蓄卡", sensitive: false },
      { fieldId: "holder", label: "持卡人", value: "张三", sensitive: false },
    ]);
    // 安全码只作为敏感行存在（默认掩码），绝不进入明文次行
    expect(JSON.stringify(view.lines)).not.toContain("123");
    // 银行卡模板不声明日期字段：历史载荷即便带有 expiry，也不产生到期读数
    expect(view.expiry).toBeNull();
  });

  it("护照标准模板：护照号码为敏感行，类型与国家为次行，有效期取区间结束日", () => {
    const view = buildVaultCardView(
      {
        name: "张三",
        number: "E12345678",
        type: "普通护照",
        country: "中国",
        issueDate: "2020-03-01",
        expiry: "2050-03-01",
      },
      passport,
    );
    expect(view.secret).toMatchObject({ fieldId: "number", label: "护照号码" });
    expect(view.lines).toEqual([
      { fieldId: "type", label: "护照类型", value: "普通护照", sensitive: false },
    ]);
    // 有效期为「签发 → 到期」区间，卡片读数只看结束日（与筛选、排序同源）
    expect(view.expiry).toMatchObject({ label: "有效期", tone: "valid" });
  });

  it("护照卡片只保留摘要字段，完整字段由详情窗口承载", () => {
    const view = buildVaultCardView(
      {
        name: "张三",
        number: "E12345678",
        type: "普通护照",
        country: "中国",
        nationality: "中国",
        birthDate: "1990-01-01",
        gender: "男",
        birthPlace: "北京市",
        issuePlace: "北京市",
        authority: "中华人民共和国公安部出入境管理局",
        note: "备用证件",
        expiry: "2050-03-01",
      },
      passport,
    );
    expect(view.lines.map((line) => line.fieldId)).toEqual(["type"]);
    expect(view.secrets.map((secret) => secret.fieldId)).toEqual(["number"]);
  });

  it("地址卡片只保留省市区/姓名/电话摘要，其余字段由详情窗口承载", () => {
    const view = buildVaultCardView(
      {
        name: "家",
        region: "广东省/深圳市/南山区",
        recipient: "张三",
        phone: "13800138000",
        detail: "科技园南区 8 栋 801",
        postalCode: "518000",
        note: "工作日送达",
      },
      address,
    );
    expect(view.lines.map((line) => line.fieldId)).toEqual([
      "region",
      "recipient",
      "phone",
    ]);
    expect(view.lines.find((line) => line.fieldId === "region")).toMatchObject({
      label: "省市区",
    });
    expect(view.lines.find((line) => line.fieldId === "recipient")).toMatchObject({
      label: "姓名",
    });
    expect(view.lines.find((line) => line.fieldId === "phone")).toMatchObject({
      label: "电话",
    });
    expect(view.secrets).toEqual([]);
  });

  it("承载长文本凭据的类型以该字段作为敏感行，次行保留其余可直读字段", () => {
    const view = buildVaultCardView(
      { name: "站点证书", certType: "SSL/TLS", expiry: "", content: "-----BEGIN" },
      certificate,
    );
    expect(view.secret).toMatchObject({ fieldId: "content", label: "内容" });
    expect(view.lines).toEqual([
      { fieldId: "certType", label: "类型", value: "SSL/TLS", sensitive: false },
    ]);
    expect(view.expiry).toMatchObject({ label: "到期" });
  });

  it("未声明到期字段的类型不产生到期读数", () => {
    expect(buildVaultCardView({ name: "公司", region: "北京市" }, address).expiry).toBeNull();
  });

  it("类型定义缺失：不回显任何字段名与取值，只给出待重新指派的数据量", () => {
    const view = buildVaultCardView({ b: "乙", c: "丙", d: "丁" }, undefined);
    expect(view.unknown).toBe(true);
    expect(view.typeLabel).toBe(VAULT_UNKNOWN_TYPE_LABEL);
    // 类型缺失即无法判断哪些字段敏感：取一个值当标题等于在卡面泄露未保护信息
    expect(view.title).toBe("");
    expect(view.lines).toEqual([]);
    expect(view.fieldCount).toBe(3);
    expect(JSON.stringify(view)).not.toContain("乙");
    expect(JSON.stringify(view)).not.toContain("丙");
    expect(view.secret).toBeNull();
    expect(view.expiry).toBeNull();
    expect(view.tone).toBe("accent");
    expect(view.icon.length).toBeGreaterThan(0);
  });

  it("类型定义缺失且数据为空：视图为空且数据量为 0", () => {
    const view = buildVaultCardView({}, undefined);
    expect(view.title).toBe("");
    expect(view.lines).toEqual([]);
    expect(view.fieldCount).toBe(0);
  });

  it("敏感行排除仅用于窗口交互的 transient 字段，全部敏感字段进入 secrets", () => {
    // 账号的独立密钥字段声明为 transient，不得成为卡片敏感行
    const view = buildVaultCardView(
      { platform: "p", password: "明文密码", encKey: "不应出现" },
      account,
    );
    expect(view.secret).toMatchObject({ fieldId: "password" });
    expect(view.secrets.map((secret) => secret.fieldId)).toEqual(["password"]);
  });
});

describe("搜索文本", () => {
  it("按类型声明的搜索字段拼接并小写化", () => {
    const text = vaultSearchText({ platform: "Example", username: "User", note: "忽略" }, account);
    expect(text).toBe("example\u0000user");
  });

  it("类型定义缺失时不参与检索：关键字不得试探出未展示的取值", () => {
    expect(vaultSearchText({ a: "Alpha", b: "Beta" }, undefined)).toBe("");
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

  it("纯日期按本地日历日计算：当天深夜仍算今日内到期", () => {
    // 本地时间 2030-01-01 23:30 —— UTC 已跨到 01-02，若按 UTC 解析会误报已过期
    const lateNight = new Date(2030, 0, 1, 23, 30).getTime();
    expect(vaultExpiryReadout("2030-01-01", lateNight)).toEqual({
      tone: "expiring",
      text: "今日内到期",
    });
    expect(vaultExpiryReadout("2030-01-02", lateNight)).toEqual({
      tone: "expiring",
      text: "1 天后到期",
    });
    expect(vaultExpiryReadout("2029-12-31", new Date(2030, 0, 1, 0, 5).getTime())).toEqual({
      tone: "expired",
      text: "已过期 1 天",
    });
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
    expect(view.lines[0]).toEqual({
      fieldId: "sub",
      label: "副标题",
      value: "乙",
      sensitive: false,
    });
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
