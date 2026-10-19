/*
 * vault_item_codec.spec.ts — 条目信封编解码与独立加密保存决策
 *
 * 覆盖：信封往返一致、脏取值归一化、损坏输入兜底；账号字段双向映射；
 * 独立加密保存决策的全部正反例（尤其是"既有取值已是密文"这一判据）。
 */
import { describe, it, expect } from "vitest";
import {
  buildVaultItemData,
  deserializeVaultItem,
  normalizeVaultData,
  resolveSecretSaveAction,
  serializeVaultItem,
  vaultDataToAccountFields,
} from "./vault_item_codec";
import { serializeToJsonB64 } from "../utils/json_codec";
import { ACCOUNT_VAULT_TYPE_ID, getBuiltinVaultType } from "../constants/vault_item_types";

describe("条目信封编解码", () => {
  it("合法信封往返一致", () => {
    const payload = { kind: "idcard", data: { name: "张三", number: "110101199001010011" } };
    expect(deserializeVaultItem(serializeVaultItem(payload))).toEqual(payload);
  });

  it("编码侧归一化脏取值：布尔与有限数值转字符串，其余丢弃", () => {
    const dirty = {
      a: "文本",
      b: 12,
      c: true,
      d: false,
      e: null,
      f: undefined,
      g: { nested: 1 },
      h: [1, 2],
      i: Number.NaN,
      j: Number.POSITIVE_INFINITY,
    };
    const b64 = serializeVaultItem({
      kind: "custom:demo",
      data: dirty as unknown as Record<string, string>,
    });
    expect(deserializeVaultItem(b64)).toEqual({
      kind: "custom:demo",
      data: { a: "文本", b: "12", c: "1", d: "0" },
    });
  });

  it("字段值归一化只保留可承载的取值", () => {
    expect(normalizeVaultData({ s: "x", n: 3, b: true })).toEqual({ s: "x", n: "3", b: "1" });
    expect(normalizeVaultData(null)).toEqual({});
    expect(normalizeVaultData([1, 2])).toEqual({});
    expect(normalizeVaultData("字符串")).toEqual({});
  });

  it("损坏输入一律兜底为账号信封，不抛错", () => {
    const fallback = { kind: ACCOUNT_VAULT_TYPE_ID, data: {} };
    expect(deserializeVaultItem("")).toEqual(fallback);
    expect(deserializeVaultItem("%%%非base64%%%")).toEqual(fallback);
    expect(deserializeVaultItem(serializeToJsonB64([1, 2]))).toEqual(fallback);
    expect(deserializeVaultItem(serializeToJsonB64("纯字符串"))).toEqual(fallback);
  });

  it("类型 id 缺失或非字符串时兜底为账号类型，字段值仍被保留", () => {
    expect(deserializeVaultItem(serializeToJsonB64({ data: { a: "1" } }))).toEqual({
      kind: ACCOUNT_VAULT_TYPE_ID,
      data: { a: "1" },
    });
    expect(deserializeVaultItem(serializeToJsonB64({ kind: 7, data: { a: "1" } }))).toEqual({
      kind: ACCOUNT_VAULT_TYPE_ID,
      data: { a: "1" },
    });
  });
});

describe("条目数据投影与账号字段映射", () => {
  const account = getBuiltinVaultType(ACCOUNT_VAULT_TYPE_ID)!;

  it("账号数据字典恰含落盘字段，独立密钥被排除", () => {
    const data = buildVaultItemData(account, {
      platform: "示例平台",
      username: "user",
      password: "secret",
      encrypted: "1",
      encKey: "独立密钥",
      note: "备注",
    });
    expect(data).toEqual({
      platform: "示例平台",
      username: "user",
      password: "secret",
      encrypted: "1",
      note: "备注",
    });
    expect(Object.keys(data)).not.toContain("encKey");
  });

  it("缺失取值落为空串，保证落盘形态固定", () => {
    const data = buildVaultItemData(account, { platform: "示例平台" });
    expect(data).toEqual({ platform: "示例平台", username: "", password: "", encrypted: "", note: "" });
  });

  it("账号字段还原：仅「1」视为已独立加密，缺失键回落空串", () => {
    expect(vaultDataToAccountFields({ platform: "p", username: "u", password: "c", encrypted: "1" })).toEqual({
      platform: "p",
      username: "u",
      password: "c",
      note: "",
      encrypted: true,
    });
    expect(vaultDataToAccountFields({ encrypted: "0" }).encrypted).toBe(false);
    expect(vaultDataToAccountFields({}).encrypted).toBe(false);
  });
});

describe("独立加密保存决策", () => {
  it("未启用独立加密：明文落盘", () => {
    expect(
      resolveSecretSaveAction({
        previousEncrypted: false,
        previousValue: "",
        currentValue: "明文",
        enableEncryption: false,
        hasKey: false,
      }),
    ).toEqual({ action: "plain", value: "明文", encrypted: false });
  });

  it("新增条目启用加密：有密钥则加密，无密钥给出待补密钥动作", () => {
    const base = {
      previousEncrypted: false,
      previousValue: "",
      currentValue: "明文",
      enableEncryption: true,
    };
    expect(resolveSecretSaveAction({ ...base, hasKey: true })).toEqual({
      action: "encrypt",
      value: "明文",
      encrypted: true,
    });
    expect(resolveSecretSaveAction({ ...base, hasKey: false })).toEqual({
      action: "needs-key",
      value: "",
      encrypted: true,
    });
  });

  it("既有已加密且取值未改动：沿用原密文，不二次加密", () => {
    expect(
      resolveSecretSaveAction({
        previousEncrypted: true,
        previousValue: "既有密文",
        currentValue: "既有密文",
        enableEncryption: true,
        hasKey: false,
      }),
    ).toEqual({ action: "reuse", value: "既有密文", encrypted: true });
  });

  it("既有已加密但取值已改动：按新值加密，缺密钥则待补密钥", () => {
    const base = {
      previousEncrypted: true,
      previousValue: "既有密文",
      currentValue: "新的明文",
      enableEncryption: true,
    };
    expect(resolveSecretSaveAction({ ...base, hasKey: true })).toEqual({
      action: "encrypt",
      value: "新的明文",
      encrypted: true,
    });
    expect(resolveSecretSaveAction({ ...base, hasKey: false })).toEqual({
      action: "needs-key",
      value: "",
      encrypted: true,
    });
  });

  it("既有为明文而新开启加密：取值与原文相同也必须加密", () => {
    expect(
      resolveSecretSaveAction({
        previousEncrypted: false,
        previousValue: "原文",
        currentValue: "原文",
        enableEncryption: true,
        hasKey: true,
      }),
    ).toEqual({ action: "encrypt", value: "原文", encrypted: true });
  });
});
