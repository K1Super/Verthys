/*
 * id_card_number.spec.ts — 18 位公民身份号码校验契约
 *
 * 覆盖：合法号码（末位数字 / X / 小写 x）、长度与字符形态、校验位不符、
 * 首尾空白归一，以及内部空白不被接受。
 */
import { describe, it, expect } from "vitest";
import { validateIdCardNumber } from "./id_card_number";

describe("公民身份号码校验", () => {
  it("合法号码通过：末位数字、X 与小写 x 等价", () => {
    expect(validateIdCardNumber("440524188001010014")).toEqual({ ok: true });
    expect(validateIdCardNumber("11010519491231002X")).toEqual({ ok: true });
    expect(validateIdCardNumber("11010519491231002x")).toEqual({ ok: true });
    expect(validateIdCardNumber("110101199001010015")).toEqual({ ok: true });
  });

  it("首尾空白不影响判定，内部空白按非法形态处理", () => {
    expect(validateIdCardNumber("  11010519491231002X  ")).toEqual({ ok: true });
    expect(validateIdCardNumber("1101051949123100 2X")).toEqual({
      ok: false,
      reason: "format",
    });
  });

  it("长度或字符形态不符判为 format", () => {
    expect(validateIdCardNumber("")).toEqual({ ok: false, reason: "format" });
    expect(validateIdCardNumber("11010519491231002")).toEqual({
      ok: false,
      reason: "format",
    });
    expect(validateIdCardNumber("1101051949123100211")).toEqual({
      ok: false,
      reason: "format",
    });
    expect(validateIdCardNumber("1101051949123100AX")).toEqual({
      ok: false,
      reason: "format",
    });
    // 只有末位允许出现 X
    expect(validateIdCardNumber("X1010519491231002X")).toEqual({
      ok: false,
      reason: "format",
    });
  });

  it("形态合法但校验位不符判为 checksum", () => {
    expect(validateIdCardNumber("110105194912310021")).toEqual({
      ok: false,
      reason: "checksum",
    });
    expect(validateIdCardNumber("440524188001010015")).toEqual({
      ok: false,
      reason: "checksum",
    });
  });
});
