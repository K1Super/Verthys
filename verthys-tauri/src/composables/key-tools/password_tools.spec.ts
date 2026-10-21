/**
 * password_tools.spec.ts — 钥域纯逻辑契约测试
 *
 * 锁定四类此前会误导用户的口径：
 *   1. 字符池构造与「排除相似字符」；
 *   2. 生成取样：长度精确、每类覆盖、拒绝采样不越界；
 *   3. 强度估算：周期重复 / 等差顺子不得被评为强（`aaaaaaaaaaaaaaaa`
 *      曾被评为「强 · 75 bits」）；
 *   4. 破解时间分档与真实量级一致（不得在百万年就报「宇宙年龄」）。
 */
import { describe, it, expect } from "vitest";
import {
  ARGON2_PARAMS,
  argonParamsLabel,
  buildCharset,
  calcCrackTime,
  calcStrength,
  charsetSizeOf,
  composePassword,
  enabledCharsets,
  formatBase64,
  formatHex,
  formatToken,
  minimalPeriod,
  PASSWORD_CHARSETS,
  pickCharset,
  randomKeyFileName,
  sequentialChars,
  type RandomSource,
} from "./password_tools";

/** 确定性 LCG 随机源（跨用例互不干扰，每个用例各自新建） */
function lcgSource(seed = 1): RandomSource {
  let state = seed >>> 0;
  return (out) => {
    for (let i = 0; i < out.length; i++) {
      state = (state * 1664525 + 1013904223) >>> 0;
      out[i] = state;
    }
  };
}

const ALL_ON = { upper: true, lower: true, digits: true, symbols: true, exclude: false };
const ALL_OFF = { upper: false, lower: false, digits: false, symbols: false, exclude: false };

describe("字符池构造", () => {
  it("全选时并集为四类之和", () => {
    expect(buildCharset(ALL_ON).length).toBe(26 + 26 + 10 + 26);
    expect(charsetSizeOf("aA1!")).toBe(94);
  });

  it("只选数字时池内不含字母与符号", () => {
    const pool = buildCharset({ ...ALL_OFF, digits: true });
    expect(pool).toBe(PASSWORD_CHARSETS.digits);
  });

  it("全关时字符池为空（生成器必须显式拒绝而不是产出空密码）", () => {
    expect(buildCharset(ALL_OFF)).toBe("");
    expect(enabledCharsets(ALL_OFF)).toEqual([]);
  });

  it("排除相似字符：三类中的 I l 1 O 0 o 全部移除", () => {
    const groups = enabledCharsets({ ...ALL_ON, exclude: true });
    const pool = groups.join("");
    for (const ch of PASSWORD_CHARSETS.similar) {
      expect(pool.includes(ch)).toBe(false);
    }
    expect(pool.length).toBe(88 - 6);
  });
});

describe("随机取样与密码合成", () => {
  it("长度精确且只取池内字符", () => {
    const out = pickCharset("abc", 6, lcgSource(7));
    expect(out).toHaveLength(6);
    expect([...out].every((ch) => "abc".includes(ch))).toBe(true);
  });

  it("空池或零长度返回空串", () => {
    expect(pickCharset("", 5, lcgSource())).toBe("");
    expect(pickCharset("abc", 0, lcgSource())).toBe("");
  });

  it("全选四类时每类至少出现一次（长度足够）", () => {
    const pwd = composePassword(ALL_ON, 12, lcgSource(11));
    expect(pwd).toHaveLength(12);
    expect(/[A-Z]/.test(pwd)).toBe(true);
    expect(/[a-z]/.test(pwd)).toBe(true);
    expect(/[0-9]/.test(pwd)).toBe(true);
    expect(/[^a-zA-Z0-9]/.test(pwd)).toBe(true);
  });

  it("排除相似字符后生成结果不含易混淆字符", () => {
    const pwd = composePassword({ ...ALL_ON, exclude: true }, 24, lcgSource(23));
    for (const ch of PASSWORD_CHARSETS.similar) {
      expect(pwd.includes(ch)).toBe(false);
    }
  });

  it("长度短于字符类数量时按长度截断（不越界补齐）", () => {
    expect(composePassword(ALL_ON, 2, lcgSource(5))).toHaveLength(2);
    expect(composePassword(ALL_ON, 0, lcgSource(5))).toBe("");
    expect(composePassword(ALL_OFF, 8, lcgSource(5))).toBe("");
  });
});

describe("强度估算", () => {
  it("空输入为零级", () => {
    expect(calcStrength("")).toEqual({ level: 0, percent: 0, entropy: 0, label: "" });
  });

  it("同字符重复不得评为强（aaaaaaaaaaaaaaaa）", () => {
    const r = calcStrength("aaaaaaaaaaaaaaaa");
    expect(r.level).toBe(1);
    expect(r.entropy).toBeLessThan(10);
    expect(r.label).toBe("极弱");
  });

  it("周期重复不得因长度增加而提升（abcabcabcabc）", () => {
    expect(minimalPeriod([...'abcabcabcabc'])).toBe(3);
    expect(calcStrength("abcabcabcabc").level).toBe(1);
  });

  it("等差顺子被扣减（abcdefghijklmnop / 0123456789abcdef）", () => {
    expect(sequentialChars([..."abcd"])).toBe(4);
    expect(calcStrength("abcdefghijklmnop").level).toBeLessThanOrEqual(2);
    expect(calcStrength("0123456789abcdef").level).toBeLessThanOrEqual(2);
  });

  it("普通高熵口令落在中等及以上", () => {
    expect(calcStrength("Tr0ub4dor&3").level).toBeGreaterThanOrEqual(3);
    // 32 位随机串：字符集熵约 200 bits → 极强
    expect(calcStrength("Q7$vL2!nR9@xP4#kM8&wT1%zB6^cJ3*d").level).toBe(5);
  });

  it("非 ASCII 口令按保守 6 bit/字符计，不按码位空间高估", () => {
    const r = calcStrength("中文密码");
    expect(r.entropy).toBe(24);
    expect(r.level).toBe(1);
  });
});

describe("破解时间分档", () => {
  it("零熵为即时", () => {
    expect(calcCrackTime(0)).toBe("即时");
  });

  it("分钟 / 天 / 年 档位与量级一致", () => {
    expect(calcCrackTime(40)).toBe("2 分钟");
    expect(calcCrackTime(52)).toBe("5 天");
    expect(calcCrackTime(60)).toBe("4 年");
  });

  it("百万年不得谎报宇宙年龄", () => {
    // 2^80 / 1e10 ≈ 3.83e6 年 → 万年档
    expect(calcCrackTime(80)).toBe("383 万年");
    // 2^90 ≈ 3.9e9 年 → 亿年档（仍小于 138 亿年）
    expect(calcCrackTime(90)).toBe("39 亿年");
    // 2^120 远超宇宙年龄
    expect(calcCrackTime(120)).toBe("超过宇宙年龄");
  });
});

describe("格式化与密钥文件名", () => {
  it("十六进制小写定长", () => {
    expect(formatHex(new Uint8Array([0, 1, 15, 16, 255]))).toBe("00010f10ff");
  });

  it("Base64 与标准编码一致", () => {
    expect(formatBase64(new Uint8Array([1, 2, 3]))).toBe("AQID");
    expect(formatToken(new Uint8Array([1, 2, 3]), "hex")).toBe("010203");
  });

  it("密钥文件名：固定前缀/长度/字母表，且随机源可注入", () => {
    const name = randomKeyFileName(lcgSource(3));
    expect(name).toMatch(/^verthys_[a-z0-9]{12}\.bin$/);
    // 同一种子可复现，不同种子应不同
    expect(randomKeyFileName(lcgSource(3))).toBe(name);
    expect(randomKeyFileName(lcgSource(4))).not.toBe(name);
  });
});

describe("Argon2id 参数单一来源", () => {
  it("标签与参数对象同源", () => {
    expect(argonParamsLabel()).toBe(
      `t=${ARGON2_PARAMS.iterations} m=${ARGON2_PARAMS.memorySize} p=${ARGON2_PARAMS.parallelism} len=${ARGON2_PARAMS.hashLength}`,
    );
  });
});
