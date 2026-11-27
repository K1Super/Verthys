/*
 * calendar.spec.ts — 日历面板日期计算契约
 *
 * 覆盖：ISO 日期解析与非法日期拒绝、整周网格的首尾补齐与周一起始、
 * 闰年天数、月位移跨年、按天位移跨月跨年。
 */
import { describe, it, expect } from "vitest";
import {
  buildMonthGrid,
  daysInMonth,
  parseIsoDate,
  shiftDay,
  shiftMonth,
  todayIso,
  toIsoDate,
} from "./calendar";

describe("日期解析与生成", () => {
  it("合法纯日期解析为年月日", () => {
    expect(parseIsoDate("2026-11-26")).toEqual({ year: 2026, month: 11, day: 26 });
    expect(parseIsoDate("2024-02-29")).toEqual({ year: 2024, month: 2, day: 29 });
  });

  it("形态不符或不存在的日期一律返回 null", () => {
    expect(parseIsoDate("2026-1-01")).toBeNull();
    expect(parseIsoDate("2026/11/26")).toBeNull();
    expect(parseIsoDate("2026-13-01")).toBeNull();
    expect(parseIsoDate("2026-00-10")).toBeNull();
    expect(parseIsoDate("2023-02-29")).toBeNull();
    expect(parseIsoDate("2026-04-31")).toBeNull();
    expect(parseIsoDate("")).toBeNull();
  });

  it("年月日按两位补零生成，今日取本地日历日", () => {
    expect(toIsoDate(2026, 1, 5)).toBe("2026-01-05");
    expect(todayIso(new Date(2026, 10, 26, 23, 59))).toBe("2026-11-26");
  });

  it("闰年二月天数正确", () => {
    expect(daysInMonth(2024, 2)).toBe(29);
    expect(daysInMonth(2025, 2)).toBe(28);
    expect(daysInMonth(2026, 11)).toBe(30);
  });
});

describe("月份网格", () => {
  it("周一起始并向首尾补齐整周", () => {
    // 2026-11-01 是周日：首行前面补 10-26 ~ 10-31 六格，共 6 行 42 格
    const cells = buildMonthGrid(2026, 11);
    expect(cells).toHaveLength(42);
    expect(cells[0]).toEqual({ date: "2026-10-26", day: 26, inMonth: false });
    expect(cells[6]).toEqual({ date: "2026-11-01", day: 1, inMonth: true });
    expect(cells[35]).toEqual({ date: "2026-11-30", day: 30, inMonth: true });
    expect(cells[41]).toEqual({ date: "2026-12-06", day: 6, inMonth: false });
  });

  it("行数随月份伸缩：整周恰好收尾时不多补一行", () => {
    // 2026-02-01 是周日，28 天 → 首行补 6 格 + 28 天 = 34 格，收成 5 行
    const cells = buildMonthGrid(2026, 2);
    expect(cells).toHaveLength(35);
    expect(cells[0].date).toBe("2026-01-26");
    expect(cells[34].date).toBe("2026-03-01");
  });

  it("闰年二月包含 29 日", () => {
    const cells = buildMonthGrid(2024, 2);
    expect(cells.some((cell) => cell.date === "2024-02-29" && cell.inMonth)).toBe(true);
  });
});

describe("日期位移", () => {
  it("月位移跨年进位与借位", () => {
    expect(shiftMonth(2026, 1, -1)).toEqual({ year: 2025, month: 12 });
    expect(shiftMonth(2026, 12, 1)).toEqual({ year: 2027, month: 1 });
    expect(shiftMonth(2026, 6, -18)).toEqual({ year: 2024, month: 12 });
  });

  it("按天位移跨月跨年由本地日期自然进位", () => {
    expect(shiftDay("2026-12-31", 1)).toBe("2027-01-01");
    expect(shiftDay("2026-01-01", -1)).toBe("2025-12-31");
    expect(shiftDay("2026-03-01", -1)).toBe("2026-02-28");
    expect(shiftDay("2024-02-28", 1)).toBe("2024-02-29");
    expect(shiftDay("not-a-date", 1)).toBe("");
  });
});
