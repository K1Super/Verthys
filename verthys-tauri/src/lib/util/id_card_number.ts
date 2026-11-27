/*
 * lib/id_card_number.ts — 居民身份证号码校验（纯函数）
 *
 * 用途：校验 18 位公民身份号码的形态与末位校验码。
 *
 * 职责边界：只做字符串校验，不解析行政区划、不推导出生日期与性别、
 *   不触碰存储与界面。校验不改变号码本身，调用方按需决定是否拦下保存。
 *
 * 关键约束：
 *   1. 校验码按 GB 11643 的「前 17 位加权求和模 11」口径计算，
 *      权重与校验码表的顺序不可调整，改动会让合法号码被误判。
 *   2. 末位小写 x 与 X 等价；首尾空白先行去除，号码内部的空白不合法。
 *   3. 只接受 18 位：15 位旧号码没有校验位，不在本校验的覆盖范围内。
 */

/** 前 17 位的加权因子（GB 11643，位置固定） */
const WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2] as const;

/** 模 11 余数 → 校验码（下标即余数，顺序固定） */
const CHECK_CODES = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"] as const;

/** 18 位形态：前 17 位数字，末位数字或 X */
const ID_NUMBER_RE = /^\d{17}[\dXx]$/;

/** 校验不通过的原因 */
export type IdCardNumberFailure =
  /** 长度或字符形态不符（非 18 位，或末位之外的字符不是数字） */
  | "format"
  /** 形态合法但末位校验码与计算结果不一致 */
  | "checksum";

/** 校验结果（判别式：通过时不携带任何附加信息） */
export type IdCardNumberCheck =
  | { ok: true }
  | { ok: false; reason: IdCardNumberFailure };

/**
 * 校验 18 位公民身份号码。
 *
 * @param raw 用户输入的号码（按未知输入处理）
 * @returns 校验结果；不抛错
 */
export function validateIdCardNumber(raw: string): IdCardNumberCheck {
  const value = raw.trim();
  if (!ID_NUMBER_RE.test(value)) return { ok: false, reason: "format" };

  let sum = 0;
  for (let index = 0; index < 17; index += 1) {
    sum += Number(value[index]) * WEIGHTS[index];
  }
  const expected = CHECK_CODES[sum % 11];
  if (value[17].toUpperCase() !== expected) return { ok: false, reason: "checksum" };
  return { ok: true };
}
