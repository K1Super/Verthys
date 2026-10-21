/*
 * vault_item_type_store.spec.ts — 自定义类型定义读写与校验
 *
 * 覆盖：校验规则正反例、存储内容逐条降级、读取缓存与回填、
 * 以及"写入回填全量缓存 + 删除失效三层缓存"这一必须成立的缓存一致性契约。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
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
import { serializeToJsonB64 } from "../utils/json_codec";
import { TYPE_VAULT_TYPES } from "../constants/record_types";
import type { VaultTypeDef } from "../constants/vault_item_types";
import {
  VAULT_TYPES_CACHE_KEY,
  loadCustomVaultTypes,
  sanitizeVaultTypeDef,
  sanitizeVaultTypeDefs,
  saveCustomVaultTypes,
  validateVaultTypeDefs,
} from "./vault_item_type_store";

vi.mock("../cache/composition/verthys-cache", () => ({
  addFullRecord: vi.fn(),
  getModuleCache: vi.fn(() => ({ data: null, recordId: null })),
  getRecordIdsByType: vi.fn(() => []),
  getRecordsDataB64Batch: vi.fn(async () => new Map<number, string>()),
  getSummaryIdsByType: vi.fn(() => []),
  invalidateFullRecord: vi.fn(),
  invalidateScannedRecord: vi.fn(),
  invalidateSummaryRecord: vi.fn(),
  persistVerthys: vi.fn(async () => true),
  setModuleCache: vi.fn(),
}));

vi.mock("../utils/verthys_scan_safe", () => ({
  ensureIndexSourceSafe: vi.fn(async () => true),
}));

vi.mock("./verthys", () => ({
  verthysAddRecord: vi.fn(async () => 1),
  verthysDeleteRecord: vi.fn(async () => true),
}));

const addRecordMock = vi.mocked(verthysAddRecord);
const deleteRecordMock = vi.mocked(verthysDeleteRecord);
const persistMock = vi.mocked(persistVerthys);
const cacheMock = vi.mocked(getModuleCache);
const setCacheMock = vi.mocked(setModuleCache);
const addFullRecordMock = vi.mocked(addFullRecord);
const summaryIdsMock = vi.mocked(getSummaryIdsByType);
const scanIdsMock = vi.mocked(getRecordIdsByType);
const batchMock = vi.mocked(getRecordsDataB64Batch);
const indexSourceMock = vi.mocked(ensureIndexSourceSafe);

function makeDef(over: Partial<VaultTypeDef> = {}): VaultTypeDef {
  return {
    id: "custom:demo",
    label: "演示",
    icon: "generic",
    tone: "accent",
    titleField: "f_a",
    cardFields: ["f_a"],
    searchFields: ["f_a"],
    fields: [{ id: "f_a", label: "甲", kind: "text", required: true }],
    builtin: false,
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  cacheMock.mockReturnValue({ data: null, recordId: null });
  indexSourceMock.mockResolvedValue(true);
  summaryIdsMock.mockReturnValue([]);
  scanIdsMock.mockReturnValue([]);
  batchMock.mockResolvedValue(new Map<number, string>());
  addRecordMock.mockResolvedValue(1);
  deleteRecordMock.mockResolvedValue(true);
  persistMock.mockResolvedValue(true);
});

describe("自定义类型校验", () => {
  it("合法定义无问题项", () => {
    expect(validateVaultTypeDefs([makeDef()])).toEqual([]);
  });

  it("拒绝空类型名、重名与重 id", () => {
    expect(validateVaultTypeDefs([makeDef({ label: "  " })]).length).toBeGreaterThan(0);
    expect(validateVaultTypeDefs([makeDef(), makeDef({ id: "custom:other" })])).toContain(
      "演示：类型名重复",
    );
    expect(validateVaultTypeDefs([makeDef(), makeDef({ label: "另一个" })])).toContain(
      "另一个：类型 id 重复",
    );
  });

  it("拒绝占用内置 id 与非自定义前缀的 id", () => {
    const errors = validateVaultTypeDefs([
      makeDef({ id: "account", label: "甲型" }),
      makeDef({ id: "plain-id", label: "乙型" }),
    ]);
    expect(errors).toContain("甲型：类型 id 已被内置类型占用");
    expect(errors).toContain("乙型：类型 id 必须以 custom: 开头");
  });

  it("拒绝空字段清单与重复字段", () => {
    expect(validateVaultTypeDefs([makeDef({ fields: [] })])).toContain("演示：字段清单不能为空");
    const dupFields = makeDef({
      fields: [
        { id: "f_a", label: "甲", kind: "text" },
        { id: "f_a", label: "甲", kind: "text" },
      ],
    });
    expect(validateVaultTypeDefs([dupFields]).length).toBeGreaterThan(0);
  });

  it("拒绝主标题、卡片字段与搜索字段越界", () => {
    expect(validateVaultTypeDefs([makeDef({ titleField: "f_x" })])).toContain(
      "演示：主标题字段必须属于字段清单",
    );
    expect(validateVaultTypeDefs([makeDef({ cardFields: ["f_x"] })])).toContain(
      "演示：卡片展示字段必须属于字段清单（f_x）",
    );
    expect(validateVaultTypeDefs([makeDef({ searchFields: ["f_x"] })])).toContain(
      "演示：搜索字段必须属于字段清单（f_x）",
    );
  });

  it("拒绝超过三项的卡片展示字段与无候选项的选项字段", () => {
    const wide = makeDef({
      fields: [
        { id: "a", label: "甲", kind: "text" },
        { id: "b", label: "乙", kind: "text" },
        { id: "c", label: "丙", kind: "text" },
        { id: "d", label: "丁", kind: "text" },
      ],
      titleField: "a",
      cardFields: ["a", "b", "c", "d"],
      searchFields: ["a"],
    });
    expect(validateVaultTypeDefs([wide])).toContain("演示：卡片展示字段最多 3 项");

    const selectNoOptions = makeDef({
      fields: [{ id: "f_a", label: "甲", kind: "select" }],
    });
    expect(validateVaultTypeDefs([selectNoOptions])).toContain("演示：选项字段必须提供候选项（甲）");
  });

  it("拒绝库外图标与非法色调", () => {
    expect(validateVaultTypeDefs([makeDef({ icon: "nope" as VaultTypeDef["icon"] })])).toContain(
      "演示：图标不在图标库内",
    );
    expect(validateVaultTypeDefs([makeDef({ tone: "navy" as VaultTypeDef["tone"] })])).toContain(
      "演示：色调不合法",
    );
  });
});

describe("存储内容降级", () => {
  it("结构不可用返回空值", () => {
    expect(sanitizeVaultTypeDef(null)).toBeNull();
    expect(sanitizeVaultTypeDef("文本")).toBeNull();
    expect(sanitizeVaultTypeDef({ id: "custom:x", label: "甲", fields: [] })).toBeNull();
    expect(sanitizeVaultTypeDefs({})).toEqual([]);
  });

  it("库外图标回落缺省图标，非法色调回落 accent", () => {
    const def = sanitizeVaultTypeDef({
      id: "custom:x",
      label: "甲",
      icon: "nope",
      tone: "navy",
      titleField: "f_a",
      cardFields: ["f_a"],
      searchFields: ["f_a"],
      fields: [{ id: "f_a", label: "甲", kind: "text" }],
    })!;
    expect(def.icon).toBe("generic");
    expect(def.tone).toBe("accent");
    expect(def.builtin).toBe(false);
  });

  it("字段去重、主标题回落首个字段、展示字段收敛到存在的字段", () => {
    const def = sanitizeVaultTypeDef({
      id: "custom:x",
      label: "甲",
      icon: "note",
      tone: "warning",
      titleField: "missing",
      cardFields: ["f_a", "f_a", "missing", "f_b", "f_c"],
      searchFields: ["f_b"],
      fields: [
        { id: "f_a", label: "甲", kind: "text" },
        { id: "f_a", label: "甲重复", kind: "text" },
        { id: "f_b", label: "乙", kind: "text" },
      ],
    })!;
    expect(def.fields.map((f) => f.id)).toEqual(["f_a", "f_b"]);
    expect(def.titleField).toBe("f_a");
    expect(def.cardFields).toEqual(["f_a", "f_b"]);
    expect(def.searchFields).toEqual(["f_b"]);
  });

  it("无候选项的选项字段回退为文本控件，未知控件种类回退为文本", () => {
    const def = sanitizeVaultTypeDef({
      id: "custom:x",
      label: "甲",
      icon: "note",
      tone: "warning",
      titleField: "f_a",
      cardFields: ["f_a"],
      searchFields: ["f_a"],
      fields: [
        { id: "f_a", label: "甲", kind: "select" },
        { id: "f_b", label: "乙", kind: "unknown" },
        { id: "f_c", label: "丙", kind: "select", options: ["甲", "乙"] },
      ],
    })!;
    expect(def.fields.map((f) => f.kind)).toEqual(["text", "text", "select"]);
    expect(def.fields[2].options).toEqual(["甲", "乙"]);
  });

  it("数组级降级：逐条丢弃非法项并按 id 去重", () => {
    const defs = sanitizeVaultTypeDefs([
      makeDef(),
      null,
      makeDef({ label: "重复 id" }),
      { id: "custom:ok", label: "合法", fields: [{ id: "f_a", label: "甲", kind: "text" }] },
    ]);
    expect(defs.map((d) => d.id)).toEqual(["custom:demo", "custom:ok"]);
  });
});

describe("读取自定义类型", () => {
  it("模块缓存命中时直接返回，不触发任何扫描", async () => {
    const cached = [makeDef()];
    cacheMock.mockReturnValue({ data: cached, recordId: 3 });
    expect(await loadCustomVaultTypes()).toEqual({ types: cached, failed: false });
    expect(indexSourceMock).not.toHaveBeenCalled();
    expect(batchMock).not.toHaveBeenCalled();
  });

  it("容器内无记录时返回空数组并写入空缓存", async () => {
    expect(await loadCustomVaultTypes()).toEqual({ types: [], failed: false });
    expect(setCacheMock).toHaveBeenCalledWith(VAULT_TYPES_CACHE_KEY, []);
  });

  it("有记录时解析并回填模块缓存（含记录 id）", async () => {
    const defs = [makeDef()];
    summaryIdsMock.mockReturnValue([7]);
    batchMock.mockResolvedValue(new Map([[7, serializeToJsonB64(defs)]]));
    expect(await loadCustomVaultTypes()).toEqual({ types: defs, failed: false });
    expect(setCacheMock).toHaveBeenCalledWith(VAULT_TYPES_CACHE_KEY, defs, 7);
  });

  it("摘要为空时改用扫描缓存取数", async () => {
    const defs = [makeDef()];
    indexSourceMock.mockResolvedValue(false);
    scanIdsMock.mockReturnValue([5]);
    batchMock.mockResolvedValue(new Map([[5, serializeToJsonB64(defs)]]));
    expect(await loadCustomVaultTypes()).toEqual({ types: defs, failed: false });
    expect(setCacheMock).toHaveBeenCalledWith(VAULT_TYPES_CACHE_KEY, defs, 5);
  });

  it("损坏记录被跳过，改用较大 id 之外的可解析记录", async () => {
    const defs = [makeDef()];
    summaryIdsMock.mockReturnValue([7, 9]);
    batchMock.mockResolvedValue(
      new Map([
        [9, "%%%损坏%%%"],
        [7, serializeToJsonB64(defs)],
      ]),
    );
    expect(await loadCustomVaultTypes()).toEqual({ types: defs, failed: false });
    expect(setCacheMock).toHaveBeenCalledWith(VAULT_TYPES_CACHE_KEY, defs, 7);
  });

  it("结构不是数组的记录被跳过并继续回退更早的记录", async () => {
    const defs = [makeDef()];
    summaryIdsMock.mockReturnValue([7, 9]);
    batchMock.mockResolvedValue(
      new Map([
        [9, serializeToJsonB64({ kind: "not-an-array" })],
        [7, serializeToJsonB64(defs)],
      ]),
    );
    expect(await loadCustomVaultTypes()).toEqual({ types: defs, failed: false });
    expect(setCacheMock).toHaveBeenCalledWith(VAULT_TYPES_CACHE_KEY, defs, 7);
  });

  it("取数异常时按读取失败返回，不清空已缓存的可用类型", async () => {
    summaryIdsMock.mockReturnValue([7]);
    batchMock.mockRejectedValue(new Error("ipc failed"));
    expect(await loadCustomVaultTypes()).toEqual({ types: [], failed: true });
    expect(setCacheMock).not.toHaveBeenCalled();
  });

  it("记录 id 收集失败时同样按读取失败返回且不写缓存", async () => {
    indexSourceMock.mockRejectedValue(new Error("index unavailable"));
    vi.mocked(getRecordIdsByType).mockImplementation(() => {
      throw new Error("scan unavailable");
    });
    expect(await loadCustomVaultTypes()).toEqual({ types: [], failed: true });
    expect(setCacheMock).not.toHaveBeenCalled();
  });
});

describe("写入自定义类型（缓存一致性契约）", () => {
  it("写入后回填全量缓存与模块缓存，并删除被替换的旧记录且失效其三层缓存", async () => {
    addRecordMock.mockResolvedValue(42);
    summaryIdsMock.mockReturnValue([7, 42]);
    const result = await saveCustomVaultTypes([makeDef()]);

    expect(result).toEqual({ ok: true, persisted: true });
    expect(addRecordMock).toHaveBeenCalledWith(TYPE_VAULT_TYPES, "vault-types", expect.any(String));
    expect(addFullRecordMock).toHaveBeenCalledWith(
      42,
      TYPE_VAULT_TYPES,
      "vault-types",
      expect.any(String),
      expect.any(Number),
    );
    expect(deleteRecordMock).toHaveBeenCalledTimes(1);
    expect(deleteRecordMock).toHaveBeenCalledWith(7);
    expect(vi.mocked(invalidateSummaryRecord)).toHaveBeenCalledWith(7);
    expect(vi.mocked(invalidateFullRecord)).toHaveBeenCalledWith(7);
    expect(vi.mocked(invalidateScannedRecord)).toHaveBeenCalledWith(7);
    expect(setCacheMock).toHaveBeenCalledWith(VAULT_TYPES_CACHE_KEY, [makeDef()], 42);
    expect(persistMock).toHaveBeenCalledTimes(1);
  });

  it("新记录写入失败时中止，不写缓存也不落盘", async () => {
    addRecordMock.mockResolvedValue(null);
    const result = await saveCustomVaultTypes([makeDef()]);
    expect(result).toEqual({ ok: false, persisted: false });
    expect(addFullRecordMock).not.toHaveBeenCalled();
    expect(setCacheMock).not.toHaveBeenCalled();
    expect(persistMock).not.toHaveBeenCalled();
  });

  it("旧记录删除失败不阻断新定义生效，仍失效其缓存", async () => {
    addRecordMock.mockResolvedValue(42);
    summaryIdsMock.mockReturnValue([7, 42]);
    deleteRecordMock.mockRejectedValue(new Error("delete failed"));
    const result = await saveCustomVaultTypes([makeDef()]);
    expect(result.ok).toBe(true);
    expect(vi.mocked(invalidateSummaryRecord)).toHaveBeenCalledWith(7);
    expect(setCacheMock).toHaveBeenCalled();
  });

  it("落盘失败时如实报告 persisted=false", async () => {
    persistMock.mockResolvedValue(false);
    const result = await saveCustomVaultTypes([makeDef()]);
    expect(result).toEqual({ ok: true, persisted: false });
  });

  it("写入内容经过归一化，落盘形态与模块缓存一致", async () => {
    addRecordMock.mockResolvedValue(42);
    indexSourceMock.mockResolvedValue(false);
    scanIdsMock.mockReturnValue([3]);
    await saveCustomVaultTypes([makeDef({ icon: "nope" as VaultTypeDef["icon"] })]);

    const cachedDefs = setCacheMock.mock.calls[0][1] as VaultTypeDef[];
    expect(cachedDefs[0].icon).toBe("generic");
    expect(deleteRecordMock).toHaveBeenCalledWith(3);
  });
});
