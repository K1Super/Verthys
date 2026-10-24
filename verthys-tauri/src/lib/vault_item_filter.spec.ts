/*
 * vault_item_filter.spec.ts — 条目筛选与排序（纯逻辑）
 *
 * 覆盖：各筛选维度的取中与不取中、维度间与关系、维度内或关系、
 * 排序键语义、条件摘要与生效条件计数，以及与关键字叠加的情形（调用方先行过滤）。
 */
import { describe, it, expect } from "vitest";
import {
  applyVaultFilter,
  countActiveVaultFilters,
  createEmptyVaultFilter,
  describeVaultFilter,
  isEmptyVaultFilter,
  type VaultFilterCriteria,
  type VaultFilterEntry,
} from "./vault_item_filter";
import { getBuiltinVaultType, type VaultTypeDef } from "../constants/vault_item_types";

const account = getBuiltinVaultType("account")!;
const idcard = getBuiltinVaultType("idcard")!;
const bankcard = getBuiltinVaultType("bankcard")!;
const address = getBuiltinVaultType("address")!;

const DEFS: Record<string, VaultTypeDef> = {
  account,
  idcard,
  bankcard,
  address,
};
const defOf = (kind: string): VaultTypeDef | undefined => DEFS[kind];

/** 到期日相对当天的天数（构造过期/临期样本用） */
const dayOffset = (days: number): string =>
  new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);

const ENTRIES: VaultFilterEntry[] = [
  { kind: "account", data: { platform: "平台甲", username: "u1", password: "p", encrypted: "0" }, recordId: 1 },
  { kind: "account", data: { platform: "平台乙", username: "u2", password: "p", encrypted: "1" }, recordId: 3 },
  { kind: "idcard", data: { name: "甲", number: "1", expiry: dayOffset(-5) }, recordId: 2 },
  { kind: "idcard", data: { name: "乙", number: "2", expiry: dayOffset(10) }, recordId: 4 },
  { kind: "address", data: { name: "丙", region: "北京市" }, recordId: 5 },
  { kind: "custom:gone", data: { a: "未知类型条目" }, recordId: 6 },
];

const withCriteria = (part: Partial<VaultFilterCriteria>): VaultFilterCriteria => ({
  ...createEmptyVaultFilter(),
  ...part,
});

describe("默认条件", () => {
  it("空条件保持输入顺序且不重排", () => {
    const result = applyVaultFilter(ENTRIES, createEmptyVaultFilter(), defOf);
    expect(result.map((e) => e.recordId)).toEqual([1, 3, 2, 4, 5, 6]);
  });

  it("空条件的判定与计数", () => {
    const empty = createEmptyVaultFilter();
    expect(isEmptyVaultFilter(empty)).toBe(true);
    expect(countActiveVaultFilters(empty)).toBe(0);
    expect(describeVaultFilter(empty, () => "类型")).toBe("");
  });
});

describe("类型维度", () => {
  it("单选类型只保留该类型条目", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ kinds: ["account"] }), defOf);
    expect(result.map((e) => e.kind)).toEqual(["account", "account"]);
  });

  it("多选类型为并集", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ kinds: ["account", "address"] }), defOf);
    expect(result.map((e) => e.kind)).toEqual(["account", "account", "address"]);
  });
});

describe("到期维度", () => {
  it("已过期只命中到期日已过的条目", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ expiry: ["expired"] }), defOf);
    expect(result.map((e) => e.data.name)).toEqual(["甲"]);
  });

  it("即将到期只命中临期阈值内的条目", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ expiry: ["expiring"] }), defOf);
    expect(result.map((e) => e.data.name)).toEqual(["乙"]);
  });

  it("到期日为今日的条目归入即将到期（按本地日历日，不因钟点提前过期）", () => {
    const today = new Date();
    const stamp = [
      today.getFullYear(),
      String(today.getMonth() + 1).padStart(2, "0"),
      String(today.getDate()).padStart(2, "0"),
    ].join("-");
    const entries: VaultFilterEntry[] = [
      { kind: "idcard", data: { name: "今日", number: "9", expiry: stamp }, recordId: 7 },
    ];
    expect(applyVaultFilter(entries, withCriteria({ expiry: ["expiring"] }), defOf)).toHaveLength(1);
    expect(applyVaultFilter(entries, withCriteria({ expiry: ["expired"] }), defOf)).toHaveLength(0);
  });

  it("已设到期与未设到期覆盖全部条目且互斥", () => {
    const has = applyVaultFilter(ENTRIES, withCriteria({ expiry: ["hasExpiry"] }), defOf);
    const none = applyVaultFilter(ENTRIES, withCriteria({ expiry: ["noExpiry"] }), defOf);
    expect(has.length + none.length).toBe(ENTRIES.length);
  });

  it("维度内多选为或关系", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ expiry: ["expired", "expiring"] }), defOf);
    expect(result.map((e) => e.data.name)).toEqual(["甲", "乙"]);
  });

  it("类型未声明到期字段时，历史 expiry 残值不参与到期维度", () => {
    const entries: VaultFilterEntry[] = [
      // 银行卡模板已移除日期字段：历史载荷即便残留 expiry，也不得算作已设到期
      { kind: "bankcard", data: { bank: "示例银行", number: "6222", expiry: dayOffset(-5) }, recordId: 8 },
      { kind: "idcard", data: { name: "甲", number: "1", expiry: dayOffset(-5) }, recordId: 9 },
    ];
    expect(applyVaultFilter(entries, withCriteria({ expiry: ["expired"] }), defOf).map((e) => e.recordId)).toEqual([9]);
    expect(applyVaultFilter(entries, withCriteria({ expiry: ["hasExpiry"] }), defOf).map((e) => e.recordId)).toEqual([9]);
    expect(applyVaultFilter(entries, withCriteria({ expiry: ["noExpiry"] }), defOf).map((e) => e.recordId)).toEqual([8]);
  });
});

describe("保护状态维度", () => {
  it("含独立加密只命中带加密标记的条目", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ protection: ["encrypted"] }), defOf);
    expect(result.map((e) => e.data.platform)).toEqual(["平台乙"]);
  });

  it("含敏感字段按类型声明判定", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ protection: ["sensitive"] }), defOf);
    // 账号（密码）与身份证（身份号码）声明了敏感字段；地址类型没有
    expect(result.map((e) => e.kind)).toEqual(["account", "account", "idcard", "idcard"]);
  });

  it("均无命中既无独立加密也无敏感字段声明的条目", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ protection: ["none"] }), defOf);
    expect(result.map((e) => e.kind)).toEqual(["address", "custom:gone"]);
  });
});

describe("维度叠加与排序", () => {
  it("多个维度之间为与关系", () => {
    const result = applyVaultFilter(
      ENTRIES,
      withCriteria({ kinds: ["idcard"], expiry: ["expired"] }),
      defOf,
    );
    expect(result.map((e) => e.data.name)).toEqual(["甲"]);
  });

  it("无命中时返回空集合", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ kinds: ["address"], expiry: ["expired"] }), defOf);
    expect(result).toEqual([]);
  });

  it("按名称排序（同类型内以名称升序）", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ kinds: ["idcard"], sort: "name" }), defOf);
    // 「甲」的拼音序在「乙」之前
    expect(result.map((e) => e.data.name)).toEqual(["甲", "乙"]);
  });

  it("按类型排序把同类型条目聚拢", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ sort: "kind" }), defOf);
    const kinds = result.map((e) => e.kind);
    const firstSeen: string[] = [];
    for (const kind of kinds) {
      if (!firstSeen.includes(kind)) firstSeen.push(kind);
    }
    expect(firstSeen.length).toBe(new Set(kinds).size);
  });

  it("按到期先后排序：升序且未设到期置于末尾", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ sort: "expiry" }), defOf);
    expect(result[0].data.name).toBe("甲");
    expect(result[1].data.name).toBe("乙");
    expect(result.slice(2).every((e) => !e.data.expiry)).toBe(true);
  });

  it("到期排序把未声明到期字段的类型置于末尾（历史 expiry 残值不参与排序）", () => {
    const entries: VaultFilterEntry[] = [
      { kind: "bankcard", data: { bank: "乙", expiry: dayOffset(-10) }, recordId: 1 },
      { kind: "idcard", data: { name: "甲", expiry: dayOffset(10) }, recordId: 2 },
    ];
    const sorted = applyVaultFilter(entries, withCriteria({ sort: "expiry" }), defOf);
    expect(sorted.map((e) => e.recordId)).toEqual([2, 1]);
  });

  it("按最近更新排序：记录 id 降序", () => {
    const result = applyVaultFilter(ENTRIES, withCriteria({ sort: "recent" }), defOf);
    expect(result.map((e) => e.recordId)).toEqual([6, 5, 4, 3, 2, 1]);
  });

  it("排序不改变筛选集合，仅改变顺序", () => {
    const filtered = applyVaultFilter(ENTRIES, withCriteria({ kinds: ["account"] }), defOf);
    const sorted = applyVaultFilter(ENTRIES, withCriteria({ kinds: ["account"], sort: "recent" }), defOf);
    expect(new Set(sorted.map((e) => e.recordId))).toEqual(new Set(filtered.map((e) => e.recordId)));
    expect(sorted.map((e) => e.recordId)).toEqual([3, 1]);
  });

  it("不改动入参数组（返回新数组）", () => {
    const input = [...ENTRIES];
    const snapshot = input.map((e) => e.recordId);
    applyVaultFilter(input, withCriteria({ sort: "recent" }), defOf);
    expect(input.map((e) => e.recordId)).toEqual(snapshot);
  });
});

describe("条件摘要与计数", () => {
  const labelOf = (kind: string): string => DEFS[kind]?.label ?? kind;

  it("类型名以分隔符连接，其余维度压缩为增量计数", () => {
    const criteria = withCriteria({ kinds: ["account", "idcard"], expiry: ["expired"] });
    expect(describeVaultFilter(criteria, labelOf)).toBe("账号 · 身份证 +1");
    expect(countActiveVaultFilters(criteria)).toBe(3);
  });

  it("仅其他维度生效时只给出增量计数", () => {
    const criteria = withCriteria({ protection: ["encrypted"] });
    expect(describeVaultFilter(criteria, labelOf)).toBe("+1");
  });

  it("非默认条件被判定为已启用", () => {
    expect(isEmptyVaultFilter(withCriteria({ kinds: ["account"] }))).toBe(false);
    expect(isEmptyVaultFilter(withCriteria({ sort: "name" }))).toBe(true);
  });
});
