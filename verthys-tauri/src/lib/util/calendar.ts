/*
 * lib/calendar.ts — 日历面板的纯日期计算
 *
 * 用途：为日期选择控件提供日期解析、月份网格与日期位移。
 *
 * 职责边界：纯函数，不触碰 DOM、不读外部状态。纯日期字符串一律按本地
 *   年月日构造，不经过 UTC 解析，避免时区把「当天」读成前一天。
 *
 * 关键约束：
 *   1. 对外 month 一律 1 起算，与 ISO 字符串的读数一致；JS Date 的
 *      0 起算只在本模块内部转换。
 *   2. 非法日期（如 2026-02-30）解析为 null，不静默改写为其它日期。
 *   3. 周视图按周一起始，周末聚合在行尾。
 *   4. 网格始终输出整周：首行补齐上月尾日、末行补齐下月首日，
 *      行数随月份自然伸缩（4~6 行），调用方不写死行高或行数。
 */

/** 解析后的日历日期（month 为 1~12） */
export interface CalendarDate {
  year: number;
  month: number;
  day: number;
}

/** 月份网格中的一格 */
export interface CalendarCell {
  /** 该格对应的日期（`YYYY-MM-DD`） */
  date: string;
  /** 日号（1~31） */
  day: number;
  /** 是否属于当前展示月（补齐格为 false） */
  inMonth: boolean;
}

/** 纯日期字符串的唯一形态 */
const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * 取某年某月的天数。
 *
 * @param year 年
 * @param month 月（1~12）
 * @returns 天数
 */
export function daysInMonth(year: number, month: number): number {
  return new Date(year, month, 0).getDate();
}

/**
 * 解析纯日期字符串。
 *
 * @param value 待解析取值
 * @returns 日历日期；形态不符或日期不存在（如 2 月 30 日）返回 null
 */
export function parseIsoDate(value: string): CalendarDate | null {
  const matched = ISO_DATE_RE.exec(value);
  if (!matched) return null;
  const year = Number(matched[1]);
  const month = Number(matched[2]);
  const day = Number(matched[3]);
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  return { year, month, day };
}

/**
 * 由年月日生成纯日期字符串。
 *
 * @param year 年
 * @param month 月（1~12）
 * @param day 日
 * @returns `YYYY-MM-DD`
 */
export function toIsoDate(year: number, month: number, day: number): string {
  return `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

/**
 * 按本地日历日生成今日的纯日期字符串。
 *
 * @param now 参照时刻（便于固定断言）
 * @returns `YYYY-MM-DD`
 */
export function todayIso(now: Date = new Date()): string {
  return toIsoDate(now.getFullYear(), now.getMonth() + 1, now.getDate());
}

/**
 * 生成某年某月的整周网格（周一起始）。
 *
 * @param year 年
 * @param month 月（1~12）
 * @returns 首尾都补齐到整周日的格子清单
 */
export function buildMonthGrid(year: number, month: number): CalendarCell[] {
  const firstWeekday = (new Date(year, month - 1, 1).getDay() + 6) % 7;
  const total = daysInMonth(year, month);
  const rowCount = Math.ceil((firstWeekday + total) / 7);
  const cells: CalendarCell[] = [];
  for (let index = 0; index < rowCount * 7; index += 1) {
    const offset = index - firstWeekday;
    const date = new Date(year, month - 1, offset + 1);
    cells.push({
      date: toIsoDate(date.getFullYear(), date.getMonth() + 1, date.getDate()),
      day: date.getDate(),
      inMonth: offset >= 0 && offset < total,
    });
  }
  return cells;
}

/**
 * 按月位移，跨年自动进位或借位。
 *
 * @param year 起始年
 * @param month 起始月（1~12）
 * @param delta 位移月数（可为负）
 * @returns 位移后的年月
 */
export function shiftMonth(
  year: number,
  month: number,
  delta: number,
): { year: number; month: number } {
  const total = year * 12 + (month - 1) + delta;
  return {
    year: Math.floor(total / 12),
    month: ((total % 12) + 12) % 12 + 1,
  };
}

/**
 * 按天位移，跨月跨年由本地日期自然进位。
 *
 * @param value 起始日期（`YYYY-MM-DD`）
 * @param delta 位移天数（可为负）
 * @returns 位移后的日期；起始值非法返回空串
 */
export function shiftDay(value: string, delta: number): string {
  const parsed = parseIsoDate(value);
  if (!parsed) return "";
  const date = new Date(parsed.year, parsed.month - 1, parsed.day + delta);
  return toIsoDate(date.getFullYear(), date.getMonth() + 1, date.getDate());
}
