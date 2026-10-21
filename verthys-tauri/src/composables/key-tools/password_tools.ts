/**
 * key-tools/password_tools.ts — 钥域纯逻辑层
 *
 * 职责：把密码生成、强度估算、令牌/密钥格式化等**无副作用**逻辑从组件中
 * 抽出，作为单元测试可直接锁定的单一实现。组件只保留状态编排与 DOM 交互。
 *
 * 口径说明（强度估算）：
 *   - 基础熵 = 字符类并集大小 × 字符数（ASCII）；非 ASCII 字符按 6 bit/字符
 *     保守计入（CJK 码位空间远大于此，但口令多为词/短语，按码位空间会高估）。
 *   - 周期重复不新增熵：`aaaaaaaa` / `abcabcabc` 只按最小周期的种子计。
 *   - 等差顺子（`abcd` / `1234` / `9876`）逐字符扣减，避免把可预测序列评为强。
 *   - 本模型不含字典/键盘布局检测，界面须以「字符集熵估算」如实标注。
 */

/**
 * Argon2id 参数（界面标签与计算调用共用此单一来源）。
 *
 * 参数取当前桌面端常用档位（64 MiB / t=3），非安全核心常量：
 * 安全核心的 KDF 参数由 Rust/C 层权威定义，此处仅服务于工具页的单向哈希演示。
 */
export const ARGON2_PARAMS = {
  parallelism: 1,
  memorySize: 65536,
  iterations: 3,
  hashLength: 32,
} as const;

/* ===== 字符集 ===== */

/** 可选字符集（与界面上的五个开关一一对应） */
export const PASSWORD_CHARSETS = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
  /** 易混淆字符：I l 1 O 0 o */
  similar: "Il1O0o",
} as const;

export interface CharsetOptions {
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  /** 排除易混淆字符 */
  exclude: boolean;
}

/** 去掉易混淆字符 */
export function excludeSimilar(charset: string): string {
  return charset.split("").filter((c) => !PASSWORD_CHARSETS.similar.includes(c)).join("");
}

/** 按选项得到每个启用字符类的字符池（已应用排除规则） */
export function enabledCharsets(opts: CharsetOptions): string[] {
  const groups: string[] = [];
  if (opts.upper) groups.push(PASSWORD_CHARSETS.upper);
  if (opts.lower) groups.push(PASSWORD_CHARSETS.lower);
  if (opts.digits) groups.push(PASSWORD_CHARSETS.digits);
  if (opts.symbols) groups.push(PASSWORD_CHARSETS.symbols);
  return opts.exclude ? groups.map(excludeSimilar) : groups;
}

/** 按选项构造合并字符池（全部关闭时为空串） */
export function buildCharset(opts: CharsetOptions): string {
  return enabledCharsets(opts).join("");
}

/* ===== 随机取样 ===== */

/** 随机源：把随机字节写入给定数组（生产实现为 crypto.getRandomValues） */
export type RandomSource = (out: Uint32Array | Uint8Array) => void;

/**
 * 无模偏差取样：从字符池中取 length 个字符。
 *
 * 直接 `随机数 % pool.length` 会让靠前的字符出现概率偏高（2^32 不能被池长
 * 整除）；此处先算出可整除上界，落在偏斜区间的随机数直接丢弃重取。
 */
export function pickCharset(pool: string, length: number, random: RandomSource): string {
  if (!pool || length <= 0) return "";
  const size = pool.length;
  // 上界 = 小于 2^32 且能被池长整除的最大倍数
  const limit = Math.floor(0x100000000 / size) * size;
  let out = "";
  while (out.length < length) {
    const need = length - out.length;
    const buf = new Uint32Array(Math.max(8, need * 2));
    random(buf);
    for (let i = 0; i < buf.length && out.length < length; i++) {
      if (buf[i] >= limit) continue;
      out += pool[buf[i] % size];
    }
  }
  return out;
}

/** 用同一随机源做 Fisher-Yates 洗牌（只影响顺序，不影响字符分布） */
function shuffleInPlace(items: string[], random: RandomSource): string[] {
  if (items.length <= 1) return items;
  const draw = new Uint32Array(items.length);
  random(draw);
  for (let i = items.length - 1; i > 0; i--) {
    const j = draw[i] % (i + 1);
    const tmp = items[i];
    items[i] = items[j];
    items[j] = tmp;
  }
  return items;
}

/**
 * 生成密码：先为每个启用字符类各取至少一个字符（长度允许时），
 * 余量从合并池补齐，最后整体洗牌 —— 保证「全选 A-Z/a-z/0-9/!@#」时
 * 不会恰好一个数字或符号都没有。
 */
export function composePassword(opts: CharsetOptions, length: number, random: RandomSource): string {
  if (length <= 0) return "";
  const groups = enabledCharsets(opts);
  const pool = groups.join("");
  if (!pool) return "";

  const chars: string[] = [];
  for (const group of groups) {
    if (chars.length >= length) break;
    chars.push(pickCharset(group, 1, random));
  }
  const rest = pickCharset(pool, Math.max(0, length - chars.length), random);
  for (const ch of rest) chars.push(ch);
  return shuffleInPlace(chars, random).join("");
}

/* ===== 强度估算 ===== */

export interface Strength {
  /** 0 = 空；1 极弱 … 5 极强 */
  level: number;
  percent: number;
  entropy: number;
  label: string;
}

/** 非 ASCII 字符的保守熵（bit/字符） */
const NON_ASCII_BITS = 6;
/** 顺子中每个字符的熵扣减（bit） */
const SEQUENTIAL_PENALTY_BITS = 2;

/** 最小重复周期：`abcabc` → 3；无周期 → 长度本身 */
export function minimalPeriod(chars: readonly string[]): number {
  const n = chars.length;
  for (let p = 1; p < n; p++) {
    if (n % p !== 0) continue;
    let same = true;
    for (let i = p; i < n; i++) {
      if (chars[i] !== chars[i % p]) {
        same = false;
        break;
      }
    }
    if (same) return p;
  }
  return n;
}

/** 等差顺子覆盖的字符数（差值恒为 ±1 的连续段） */
export function sequentialChars(chars: readonly string[]): number {
  let count = 0;
  let i = 0;
  while (i < chars.length - 1) {
    const step = chars[i + 1].charCodeAt(0) - chars[i].charCodeAt(0);
    if (step === 1 || step === -1) {
      let j = i + 1;
      while (
        j < chars.length - 1
        && chars[j + 1].charCodeAt(0) - chars[j].charCodeAt(0) === step
      ) {
        j++;
      }
      count += j - i + 1;
      i = j;
    } else {
      i++;
    }
  }
  return count;
}

/** 字符类并集大小（ASCII 口径） */
export function charsetSizeOf(pwd: string): number {
  let size = 0;
  if (/[a-z]/.test(pwd)) size += 26;
  if (/[A-Z]/.test(pwd)) size += 26;
  if (/[0-9]/.test(pwd)) size += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) size += 32;
  return size;
}

/**
 * 估算密码强度。
 *
 * @returns level 0 表示空输入；entropy 为估算位数（≥1，除空输入外）
 */
export function calcStrength(pwd: string): Strength {
  if (!pwd) return { level: 0, percent: 0, entropy: 0, label: "" };
  const chars = Array.from(pwd);

  // 周期重复：只按种子计熵，重复部分不新增熵
  const period = minimalPeriod(chars);
  const seed = period < chars.length ? chars.slice(0, period) : chars;

  let asciiCount = 0;
  let nonAsciiCount = 0;
  for (const ch of seed) {
    if ((ch.codePointAt(0) ?? 0) > 0x7f) nonAsciiCount += 1;
    else asciiCount += 1;
  }

  const poolSize = Math.max(charsetSizeOf(pwd), 1);
  const base = asciiCount * Math.log2(poolSize) + nonAsciiCount * NON_ASCII_BITS;
  // 顺子按全串计（即使周期种子内也属可预测序列）
  const entropy = Math.max(1, Math.round(base - sequentialChars(chars) * SEQUENTIAL_PENALTY_BITS));

  let level = 1;
  let label = "极弱";
  let percent = 20;
  if (entropy >= 40) { level = 2; label = "弱"; percent = 40; }
  if (entropy >= 60) { level = 3; label = "中等"; percent = 60; }
  if (entropy >= 80) { level = 4; label = "强"; percent = 80; }
  if (entropy >= 100) { level = 5; label = "极强"; percent = 100; }
  return { level, percent, entropy, label };
}

/** 离线爆破速度假设（10^10 次/秒） */
const GUESSES_PER_SECOND = 1e10;
const SECONDS_PER_YEAR = 31536000;
/** 宇宙年龄（年） */
const UNIVERSE_AGE_YEARS = 1.38e10;

/**
 * 熵 → 可读破解时间。
 *
 * 分档必须与真实量级一致：早期实现在约 100 万年就输出「宇宙年龄+」，
 * 而宇宙年龄约 138 亿年，属夸大安全感的错误文案。
 */
export function calcCrackTime(entropy: number): string {
  if (entropy <= 0) return "即时";
  const seconds = Math.pow(2, entropy) / GUESSES_PER_SECOND;
  if (!Number.isFinite(seconds)) return "超过宇宙年龄";
  if (seconds < 1) return "即时";
  if (seconds < 60) return `${Math.round(seconds)} 秒`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} 小时`;
  if (seconds < SECONDS_PER_YEAR) return `${Math.round(seconds / 86400)} 天`;
  const years = seconds / SECONDS_PER_YEAR;
  if (years < 1e4) return `${Math.round(years)} 年`;
  if (years < 1e8) return `${Math.round(years / 1e4)} 万年`;
  if (years < UNIVERSE_AGE_YEARS) return `${Math.round(years / 1e8)} 亿年`;
  return "超过宇宙年龄";
}

/* ===== 令牌 / 密钥格式化 ===== */

/** 字节 → 小写十六进制 */
export function formatHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** 字节 → 标准 Base64（分块转换，避免大数组展开撑爆参数栈） */
export function formatBase64(bytes: Uint8Array): string {
  let binary = "";
  const STEP = 0x8000;
  for (let i = 0; i < bytes.length; i += STEP) {
    binary += String.fromCharCode(...bytes.subarray(i, i + STEP));
  }
  return btoa(binary);
}

/** 令牌/密钥显示格式化（uuid 由调用方直接用 crypto.randomUUID） */
export function formatToken(bytes: Uint8Array, format: "hex" | "base64"): string {
  return format === "hex" ? formatHex(bytes) : formatBase64(bytes);
}

/** 密钥文件名使用的字母表（小写字母 + 数字，无大写，不暴露任何信息） */
const KEY_FILENAME_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

/**
 * 生成 `verthys_<12 位小写字母数字>.bin` 的文件名。
 *
 * 取样采用拒绝采样：256 不能被 36 整除，直接取模会让前 4 个字符偏多。
 */
export function randomKeyFileName(random: RandomSource): string {
  const size = KEY_FILENAME_ALPHABET.length;
  const limit = Math.floor(256 / size) * size; // 252
  let suffix = "";
  while (suffix.length < 12) {
    const buf = new Uint8Array(24);
    random(buf);
    for (const b of buf) {
      if (b >= limit) continue;
      suffix += KEY_FILENAME_ALPHABET[b % size];
      if (suffix.length === 12) break;
    }
  }
  return `verthys_${suffix}.bin`;
}

/* ===== Argon2id 参数（单一来源） ===== */

/** Argon2id 参数标签（界面展示与调用参数同源，杜绝两处字面量漂移） */
export function argonParamsLabel(): string {
  return `t=${ARGON2_PARAMS.iterations} m=${ARGON2_PARAMS.memorySize} p=${ARGON2_PARAMS.parallelism} len=${ARGON2_PARAMS.hashLength}`;
}
