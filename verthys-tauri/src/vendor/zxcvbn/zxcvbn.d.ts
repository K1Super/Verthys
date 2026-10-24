/**
 * vendor/zxcvbn/zxcvbn.d.ts — 内置 zxcvbn 构建产物的模块声明
 *
 * 构建产物本体没有类型：本文件声明它的默认导出（引擎函数）与最小结果结构。
 * 运行时不会加载本文件，类型由 index.ts 对外转出。
 */

/** 引擎识别出的单个模式片段（字段名与产物输出一致） */
export interface ZxcvbnMatch {
  /** 模式类别：dictionary / spatial / repeat / sequence / date / regex / bruteforce */
  pattern: string;
  /** 词典名（仅 dictionary 模式提供） */
  dictionary_name?: string;
  /** 命中的原始片段 */
  token: string;
  /** 该片段的猜测数估计 */
  guesses?: number;
}

/** 引擎评估结果（仅保留本项目消费的字段） */
export interface ZxcvbnResult {
  /** 整串口令的猜测数估计（≥1） */
  guesses: number;
  /** 按覆盖顺序排列的模式片段 */
  sequence: ZxcvbnMatch[];
}

/** 引擎签名（同步计算，CPU 密集，必须只在 Worker 中调用） */
export type ZxcvbnFn = (password: string) => ZxcvbnResult;

declare const engine: ZxcvbnFn;
export default engine;
