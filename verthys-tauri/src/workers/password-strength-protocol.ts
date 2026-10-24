/**
 * workers/password-strength-protocol.ts — 密码强度分析 Worker 消息协议
 *
 * 职责：集中定义主线程与 password-strength.worker 的消息契约，以及响应装箱
 * 的唯一实现点。
 *
 * 关键约束：口令明文只允许出现在请求方向；响应只允许回传猜测数与模式摘要
 * （类别、词典名、片段长度），禁止回传口令或模式命中的原始片段——响应会进入
 * 主线程响应式状态并可能被渲染，回传片段等于把口令明文搬到界面层。
 *
 * 本模块不依赖 self / DOM / Worker 运行时，可在任意环境（含单测）直接导入。
 */

/** 模式类别（与引擎输出的 pattern 字段一致） */
export type StrengthPatternKind =
  | "dictionary"
  | "spatial"
  | "repeat"
  | "sequence"
  | "date"
  | "regex"
  | "bruteforce";

/** 引擎输出的单个模式片段（字段名与产物一致；本模块只读取类别与长度） */
export interface StrengthEngineMatch {
  /** 模式类别（引擎侧为字符串，落库前经白名单校验） */
  pattern: string;
  /** 词典名（仅 dictionary 模式提供） */
  dictionary_name?: string;
  /** 命中的原始片段（不得进入响应） */
  token: string;
}

/** 引擎输出的评估结果 */
export interface StrengthEngineResult {
  /** 整串猜测数估计（≥1） */
  guesses: number;
  /** 按覆盖顺序排列的模式片段 */
  sequence: readonly StrengthEngineMatch[];
}

/** 已确认类别的模式片段（白名单之外的类别不参与统计与提示） */
function isKnownPattern(pattern: string): pattern is StrengthPatternKind {
  return (
    pattern === "dictionary"
    || pattern === "spatial"
    || pattern === "repeat"
    || pattern === "sequence"
    || pattern === "date"
    || pattern === "regex"
    || pattern === "bruteforce"
  );
}

/** 模式命中摘要（不含原始片段） */
export interface StrengthPatternHit {
  /** 模式类别 */
  pattern: StrengthPatternKind;
  /** 词典名（仅 dictionary 模式携带；用于区分弱口令词典与普通词表） */
  dictionaryName?: string;
  /** 命中片段的字符数（用于挑选最显著弱点） */
  tokenLength: number;
}

/** 主线程 → Worker 请求 */
export interface StrengthRequest {
  /** 任务 ID（响应关联 + 过期结果丢弃） */
  id: number;
  /** 待评估口令（已按分析上限截取） */
  password: string;
}

/** Worker 失败原因（固定枚举，禁止携带口令相关内容） */
export type StrengthFailureCode = "engine" | "protocol";

/** Worker → 主线程响应 */
export interface StrengthResponse {
  /** 与请求一致的 ID */
  id: number;
  /** 是否成功 */
  ok: boolean;
  /** 整串猜测数估计（成功时必带，≥1） */
  guesses?: number;
  /**
   * 非暴力模式覆盖的字符总数（成功时必带）。
   * 主线程据此把未被模式覆盖的字符从引擎的暴力基数改按字符集空间计；
   * 缺失该字段会让随机口令被系统性低估。
   */
  coveredChars?: number;
  /** 模式命中摘要（已剔除 bruteforce，按片段长度降序） */
  patterns?: StrengthPatternHit[];
  /** 失败原因（失败时必带） */
  error?: StrengthFailureCode;
}

/** 单次回传的模式摘要条数上限（口令再长也不让响应无界膨胀） */
export const MAX_PATTERN_HITS = 8;

/**
 * 统计非暴力模式覆盖的字符总数。
 *
 * 统计口径为原始片段之和（不做去重）：同一类别出现多次时覆盖范围会累加，
 * 去重只影响提示文案，不影响「有多少字符可被模式解释」这一事实。
 *
 * @param sequence 引擎输出的模式片段序列
 * @returns 覆盖字符数（未知类别与暴力分支不计）
 */
export function countCoveredChars(sequence: readonly StrengthEngineMatch[]): number {
  let covered = 0;
  for (const match of sequence) {
    if (!isKnownPattern(match.pattern) || match.pattern === "bruteforce") continue;
    covered += Array.from(match.token).length;
  }
  return covered;
}

/**
 * 把引擎输出的模式序列压缩为回传摘要。
 *
 * 处理规则：剔除白名单之外的类别与 bruteforce（无信息量）、按类别与词典名
 * 去重（保留同类别里覆盖最长的片段）、按片段长度降序、截断到上限。
 *
 * @param sequence 引擎输出的模式片段序列（可含口令明文，本函数只读取类别字段）
 * @returns 不含口令片段内容的摘要列表
 */
export function collectPatternHits(
  sequence: readonly StrengthEngineMatch[],
): StrengthPatternHit[] {
  const byKey = new Map<string, StrengthPatternHit>();
  for (const match of sequence) {
    if (!isKnownPattern(match.pattern) || match.pattern === "bruteforce") continue;
    const pattern = match.pattern;
    const key = `${pattern}:${match.dictionary_name ?? ""}`;
    const tokenLength = Array.from(match.token).length;
    const existing = byKey.get(key);
    if (!existing || tokenLength > existing.tokenLength) {
      byKey.set(key, {
        pattern,
        tokenLength,
        ...(match.dictionary_name ? { dictionaryName: match.dictionary_name } : {}),
      });
    }
  }
  return [...byKey.values()]
    .sort((a, b) => b.tokenLength - a.tokenLength)
    .slice(0, MAX_PATTERN_HITS);
}

/**
 * 装配成功响应（Worker 侧唯一装箱点）。
 *
 * @param id 请求 ID
 * @param result 引擎评估结果
 * @returns 只含猜测数、覆盖字符数与模式摘要的响应
 */
export function buildStrengthSuccess(id: number, result: StrengthEngineResult): StrengthResponse {
  return {
    id,
    ok: true,
    guesses: result.guesses,
    coveredChars: countCoveredChars(result.sequence),
    patterns: collectPatternHits(result.sequence),
  };
}

/**
 * 装配失败响应（固定失败码，不得携带口令或异常文本）。
 *
 * @param id 请求 ID
 * @param error 失败原因
 */
export function buildStrengthFailure(id: number, error: StrengthFailureCode): StrengthResponse {
  return { id, ok: false, error };
}

