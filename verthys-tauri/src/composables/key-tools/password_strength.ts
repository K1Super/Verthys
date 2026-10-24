/**
 * key-tools/password_strength.ts — 口令强度评估的映射层与 Worker 桥接层
 *
 * 职责分两段，边界清晰：
 *   1. 纯映射：把 Worker 回传的猜测数与模式摘要翻译成界面可直接渲染的评估
 *      结果（等级、位数、破解时间、中文弱点提示）。无副作用、可单测。
 *   2. 桥接：管理分析 Worker 的生命周期、请求代际、超时与降级，对外只暴露
 *      assess / preload / dispose。
 *
 * 口径（为什么两种来源并存）：
 *   - 引擎命中模式时，以引擎猜测数为准：词典、键盘布局、重复、日期这类
 *     可预测结构是字符集模型完全看不见的，`Password123!` 在字符集模型下
 *     有约 72 位，实际猜测量只有 3.6 万次。
 *   - 引擎的暴力分支按每字符 10 次猜测计（产物内固定基数），对真正随机的
 *     口令会系统性低估。因此映射层把「未被模式覆盖的字符」按实际字符集
 *     空间重算：引擎猜测数 × (字符集/10)^未覆盖字符数。该换算是同一乘积
 *     结构下的等价替换（引擎总猜测数 = 段猜测数之积 × 段数的排列数），
 *     在无模式命中时结果恰好等于字符集空间，与生成器口径一致。实测 16 位
 *     随机口令中约一成会偶然命中短词典词，若不换算会从约 104 位骤降到
 *     约 49 位。
 *   - 引擎完全未命中模式时直接走字符集模型，保持生成器与评估面板同一实现。
 *   - 已知边界：换算假定未覆盖字符取自完整字符集。人工自造词或拼音等未被
 *     词典识别的片段会因此偏乐观；不换算则相反——16 位随机口令会被压到约
 *     53 位，与生成器给出的约 104 位自相矛盾。两害相权取前者，并用弱点
 *     提示把用户引向生成器产出的随机口令。
 *
 * 性能约束（实测数据，决定必须走 Worker）：单次分析约 8 字符 0.3ms、
 * 32 字符 4.5ms、64 字符 32ms、128 字符 740ms。主线程单帧预算 16ms，
 * 因此分析一律在 Worker 中执行，且主线程先截取分析前缀再下发。
 *
 * 降级：Worker 不可用、引擎异常或超时，一律退回字符集估算，并在 source
 * 字段上标注，由界面如实呈现，不得把降级结果冒充模式分析结果。
 */

import {
  calcCrackTime,
  calcStrength,
  charsetSizeOf,
  levelFromEntropy,
  type Strength,
} from "./password_tools";
import type {
  StrengthPatternHit,
  StrengthPatternKind,
  StrengthRequest,
  StrengthResponse,
} from "../../workers/password-strength-protocol";

/**
 * 参与模式分析的最大字符数。
 *
 * 上限由实测耗时决定：64 字符约 32ms（Worker 内可接受），128 字符约 740ms
 * （已接近超时阈值）。超出部分不参与分析，结果偏保守（可能低估强度），
 * 由界面标注截断事实。
 */
export const PASSWORD_ANALYSIS_MAX_CHARS = 64;

/** 单次分析的时间上限（毫秒）：超时即终止 Worker 并降级，防止卡死的任务堆积 */
const ANALYSIS_TIMEOUT_MS = 1500;

/** 评估来源：决定界面文案，禁止把降级结果伪装成模式分析 */
export type AssessmentSource = "pattern" | "charset" | "charset-fallback";

/** 口令评估结果（在 Strength 之上补充来源、弱点提示与截断标记） */
export interface PasswordAssessment extends Strength {
  /** 可读破解时间（沿用生成器同一爆破速度假设） */
  crackTime: string;
  /** 评估来源 */
  source: AssessmentSource;
  /** 最显著弱点提示；无模式命中或降级时为空串 */
  warning: string;
  /** 实际参与分析的字符数 */
  analyzedChars: number;
  /** 输入是否被截断（analyzedChars < 输入长度） */
  truncated: boolean;
}

/** 空输入的评估结果（等级 0，界面不显示等级文案） */
export const EMPTY_ASSESSMENT: Readonly<PasswordAssessment> = Object.freeze({
  level: 0,
  percent: 0,
  entropy: 0,
  label: "",
  crackTime: "即时",
  source: "charset" as AssessmentSource,
  warning: "",
  analyzedChars: 0,
  truncated: false,
});

/** 词典名 → 中文弱点标签（未列出的词典归入「常见词」） */
const DICTIONARY_LABELS: Record<string, string> = {
  passwords: "常见弱口令",
  english_wikipedia: "常用英文单词",
  us_tv_and_film: "影视常见词",
  surnames: "常见姓氏",
  male_names: "常见人名",
  female_names: "常见人名",
  user_inputs: "个人信息",
};

/** 模式类别 → 中文弱点标签 */
const PATTERN_LABELS: Record<Exclude<StrengthPatternKind, "dictionary" | "bruteforce">, string> = {
  spatial: "键盘相邻键位",
  repeat: "重复片段",
  sequence: "连续字符",
  date: "日期",
  regex: "年份数字",
};

/** 模式类别 → 改进建议（与标签成对维护） */
const PATTERN_ADVICE: Record<Exclude<StrengthPatternKind, "dictionary" | "bruteforce">, string> = {
  spatial: "避免沿键盘相邻键位输入",
  repeat: "避免重复字符或重复片段",
  sequence: "避免连续字母或数字",
  date: "避免生日、纪念日与年份",
  regex: "避免只由年份数字构成",
};

/** 截取参与分析的前缀（按码位切分，避免截断代理对） */
function analyzePrefix(password: string): { text: string; truncated: boolean } {
  const chars = Array.from(password);
  if (chars.length <= PASSWORD_ANALYSIS_MAX_CHARS) {
    return { text: password, truncated: false };
  }
  return {
    text: chars.slice(0, PASSWORD_ANALYSIS_MAX_CHARS).join(""),
    truncated: true,
  };
}

/** 字符集模型评估（用于纯随机串与降级路径） */
export function charsetAssessment(
  text: string,
  source: Exclude<AssessmentSource, "pattern">,
  truncated = false,
): PasswordAssessment {
  const base = calcStrength(text);
  return {
    ...base,
    crackTime: calcCrackTime(base.entropy),
    source,
    warning: "",
    analyzedChars: Array.from(text).length,
    truncated,
  };
}

/**
 * 生成中文弱点提示。
 *
 * 只取覆盖最长的一类模式（协议层已按片段长度降序并去重）：多条并列提示
 * 会让评估面板失焦，且对用户可执行的改进没有增量。
 *
 * @param patterns 模式摘要（已按片段长度降序）
 * @returns 一句提示；无可用模式时为空串
 */
export function describeWeakness(patterns: readonly StrengthPatternHit[]): string {
  const top = patterns[0];
  if (!top) return "";
  if (top.pattern === "dictionary") {
    const label = DICTIONARY_LABELS[top.dictionaryName ?? ""] ?? "常见词";
    return `检测到${label}，建议改用随机生成器产出的口令`;
  }
  if (top.pattern === "bruteforce") return "";
  const label = PATTERN_LABELS[top.pattern];
  const advice = PATTERN_ADVICE[top.pattern];
  // 运行时兜底：摘要来自 Worker 消息，类别超出预期时宁可不提示也不渲染 undefined
  if (!label || !advice) return "";
  return `检测到${label}，${advice}`;
}

/** 引擎暴力分支的字符基数（其猜测数为 10^长度，产物内为固定常量） */
const ENGINE_BRUTEFORCE_CARDINALITY = 10;

/**
 * 弱点提示的展示门槛。
 *
 * 提示的价值在于指出「为什么弱、怎么改」，只对极弱与弱有意义：中等及以上
 * 再提示只是把长度偶然带来的巧合片段（十六进制串里的 4 位日期、3 位连续
 * 字符）当成缺陷，属于噪音。同时要求命中的片段本身具备分量，避免 64 位
 * 随机串因 6 位偶然日期就被告知「存在日期模式」。
 */
const WARNING_MAX_LEVEL = 2;
/** 最显著片段的最小字符数 */
const WARNING_MIN_TOKEN_LENGTH = 4;
/** 模式覆盖占分析长度的最低比例 */
const WARNING_MIN_COVERAGE = 0.25;

/** 把上报的覆盖字符数收敛到合法区间（传输边界校验） */
function clampCoveredChars(coveredChars: number | undefined, length: number): number {
  const reported = typeof coveredChars === "number" && Number.isFinite(coveredChars)
    ? coveredChars
    : 0;
  return Math.min(Math.max(reported, 0), length);
}

/**
 * 把未被模式覆盖的字符从引擎的暴力基数改按实际字符集空间计。
 *
 * 引擎总猜测数 = 各段猜测数之积 × 段数排列数，因此只替换暴力段的基数等价于
 * 整体乘以 (字符集/10)^未覆盖字符数。未覆盖为 0 时原样返回。
 *
 * @param guesses 引擎猜测数（> 0 且有限）
 * @param analyzed 参与分析的文本
 * @param coveredChars 非暴力模式覆盖的字符数（可缺失，缺失按 0 处理）
 * @returns 换算后的猜测数；溢出时收敛到 Number.MAX_VALUE
 */
export function correctGuessesForUncovered(
  guesses: number,
  analyzed: string,
  coveredChars: number | undefined,
): number {
  const length = Array.from(analyzed).length;
  const uncovered = length - clampCoveredChars(coveredChars, length);
  if (uncovered === 0) return guesses;
  const pool = Math.max(charsetSizeOf(analyzed), ENGINE_BRUTEFORCE_CARDINALITY);
  const corrected = guesses * Math.pow(pool / ENGINE_BRUTEFORCE_CARDINALITY, uncovered);
  return Number.isFinite(corrected) ? corrected : Number.MAX_VALUE;
}

/**
 * 判断最显著的模式是否具备提示价值。
 *
 * @param patterns 模式摘要（已按片段长度降序）
 * @param coveredChars 非暴力模式覆盖的字符数
 * @param length 参与分析的字符数
 * @returns 片段够长且覆盖占比达标时为真
 */
function isMaterialWeakness(
  patterns: readonly StrengthPatternHit[],
  coveredChars: number,
  length: number,
): boolean {
  const top = patterns[0];
  if (!top || top.tokenLength < WARNING_MIN_TOKEN_LENGTH) return false;
  return coveredChars >= length * WARNING_MIN_COVERAGE;
}

/**
 * 引擎响应 → 评估结果。
 *
 * @param response Worker 回传的成功响应
 * @param analyzed 参与分析的文本（已截取）
 * @param truncated 输入是否被截断
 * @returns 评估结果；猜测数非法时降级为字符集估算
 */
export function mapEngineResult(
  response: StrengthResponse,
  analyzed: string,
  truncated: boolean,
): PasswordAssessment {
  const guesses = response.guesses;
  if (typeof guesses !== "number" || !Number.isFinite(guesses) || guesses <= 0) {
    return charsetAssessment(analyzed, "charset-fallback", truncated);
  }

  const patterns = Array.isArray(response.patterns) ? response.patterns : [];
  if (patterns.length === 0) {
    // 无模式命中：引擎只剩暴力分支，此时字符集空间才是准确口径
    return charsetAssessment(analyzed, "charset", truncated);
  }

  const length = Array.from(analyzed).length;
  const coveredChars = clampCoveredChars(response.coveredChars, length);
  const corrected = correctGuessesForUncovered(guesses, analyzed, response.coveredChars);
  const entropy = Math.max(0, Math.round(Math.log2(corrected)));
  const grade = levelFromEntropy(entropy);
  // 中等及以上不提示：长随机串里的偶然片段不是用户可执行的改进项
  const warning = grade.level <= WARNING_MAX_LEVEL && isMaterialWeakness(patterns, coveredChars, length)
    ? describeWeakness(patterns)
    : "";
  return {
    ...grade,
    entropy,
    crackTime: calcCrackTime(entropy),
    source: "pattern",
    warning,
    analyzedChars: length,
    truncated,
  };
}

/* ===== Worker 桥接 ===== */

/** 分析 Worker 最小接口（依赖注入：测试以伪实现替代真实 Worker） */
export interface StrengthWorkerLike {
  postMessage(message: StrengthRequest): void;
  onmessage: ((event: MessageEvent<StrengthResponse>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  terminate(): void;
}

/** 桥接配置 */
export interface PasswordStrengthBridgeOptions {
  /** Worker 工厂（测试注入点；默认创建真实 Worker） */
  workerFactory?: () => StrengthWorkerLike;
  /** 单次分析超时（毫秒） */
  timeoutMs?: number;
}

/** 默认 Worker 工厂：按需冷启动，实例随桥接生命周期复用 */
function defaultWorkerFactory(): StrengthWorkerLike {
  return new Worker(
    new URL("../../workers/password-strength.worker.ts", import.meta.url),
    { type: "module" },
  );
}

/** 在途请求（同一时刻最多一个：新请求会取代旧请求） */
interface InFlightRequest {
  id: number;
  analyzed: string;
  truncated: boolean;
  resolve: (value: PasswordAssessment | null) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * 强度分析桥接。
 *
 * 并发语义：assess 可被高频调用（输入框每敲一个字符），桥接只保留最新请求，
 * 被取代的请求以 null 结算，调用方据此丢弃结果；任何时刻最多一个在途请求。
 */
export class PasswordStrengthBridge {
  private readonly workerFactory: () => StrengthWorkerLike;
  private readonly timeoutMs: number;
  private worker: StrengthWorkerLike | null = null;
  private pending: InFlightRequest | null = null;
  private seq = 0;
  private disposed = false;
  /** Worker 脚本级失败（加载失败/崩溃）后不再反复重建，直接降级 */
  private engineBroken = false;

  constructor(options: PasswordStrengthBridgeOptions = {}) {
    this.workerFactory = options.workerFactory ?? defaultWorkerFactory;
    this.timeoutMs = options.timeoutMs ?? ANALYSIS_TIMEOUT_MS;
  }

  /** 预热引擎：输入框聚焦时提前创建 Worker，首次键入无需等待脚本加载与编译 */
  preload(): void {
    if (this.disposed || this.engineBroken) return;
    this.ensureWorker();
  }

  /**
   * 评估口令。
   *
   * @param password 原始口令
   * @returns 评估结果；空输入返回等级 0；请求被更新输入取代或桥接已销毁时
   *          返回 null（调用方必须丢弃）
   */
  assess(password: string): Promise<PasswordAssessment | null> {
    if (!password) return Promise.resolve({ ...EMPTY_ASSESSMENT });
    if (this.disposed) return Promise.resolve(null);

    this.supersedePending();
    const prefix = analyzePrefix(password);
    const worker = this.ensureWorker();
    if (!worker) {
      return Promise.resolve(charsetAssessment(prefix.text, "charset-fallback", prefix.truncated));
    }

    const id = ++this.seq;
    return new Promise<PasswordAssessment | null>((resolve) => {
      const timer = setTimeout(() => {
        // 超时视为 Worker 卡死：终止后重建，避免下一次请求排在死任务之后
        this.pending = null;
        this.abandonWorker();
        resolve(charsetAssessment(prefix.text, "charset-fallback", prefix.truncated));
      }, this.timeoutMs);

      this.pending = { id, analyzed: prefix.text, truncated: prefix.truncated, resolve, timer };
      try {
        worker.postMessage({ id, password: prefix.text });
      } catch {
        clearTimeout(timer);
        this.pending = null;
        this.abandonWorker();
        resolve(charsetAssessment(prefix.text, "charset-fallback", prefix.truncated));
      }
    });
  }

  /** 销毁桥接：终止 Worker，在途请求以 null 结算 */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    const pending = this.pending;
    this.pending = null;
    if (pending) {
      clearTimeout(pending.timer);
      pending.resolve(null);
    }
    this.abandonWorker();
  }

  /** 取用或创建 Worker；创建失败时返回 null 由调用方降级 */
  private ensureWorker(): StrengthWorkerLike | null {
    if (this.worker) return this.worker;
    if (this.engineBroken || this.disposed) return null;
    try {
      const worker = this.workerFactory();
      worker.onmessage = (event) => this.handleMessage(event);
      worker.onerror = () => {
        // 脚本加载失败或未捕获异常：本次及后续请求直接降级，不反复重建
        this.engineBroken = true;
        this.failPendingAsFallback();
        this.abandonWorker();
      };
      this.worker = worker;
      return worker;
    } catch {
      this.engineBroken = true;
      return null;
    }
  }

  /** 响应处理：只接受当前在途请求，过期响应直接丢弃 */
  private handleMessage(event: MessageEvent<StrengthResponse>): void {
    const data = event.data;
    const pending = this.pending;
    if (!pending || !data || data.id !== pending.id) return;

    this.pending = null;
    clearTimeout(pending.timer);

    if (!data.ok) {
      pending.resolve(charsetAssessment(pending.analyzed, "charset-fallback", pending.truncated));
      return;
    }
    try {
      pending.resolve(mapEngineResult(data, pending.analyzed, pending.truncated));
    } catch {
      pending.resolve(charsetAssessment(pending.analyzed, "charset-fallback", pending.truncated));
    }
  }

  /** 以旧请求的字符集估算结算在途请求（不得让调用方永远等不到结果） */
  private failPendingAsFallback(): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    clearTimeout(pending.timer);
    pending.resolve(charsetAssessment(pending.analyzed, "charset-fallback", pending.truncated));
  }

  /** 取代在途请求：旧请求以 null 结算，调用方丢弃 */
  private supersedePending(): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    clearTimeout(pending.timer);
    pending.resolve(null);
  }

  /** 终止并清空 Worker 引用 */
  private abandonWorker(): void {
    const worker = this.worker;
    this.worker = null;
    if (!worker) return;
    try {
      worker.terminate();
    } catch {
      // 已销毁的 Worker 再次 terminate 属于无操作，忽略
    }
  }
}

/** 创建桥接实例（组件每次挂载一个实例，随卸载销毁） */
export function createPasswordStrengthBridge(
  options: PasswordStrengthBridgeOptions = {},
): PasswordStrengthBridge {
  return new PasswordStrengthBridge(options);
}
