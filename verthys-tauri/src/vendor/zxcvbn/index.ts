/**
 * vendor/zxcvbn/index.ts — 内置 zxcvbn 引擎的 ESM 门面
 *
 * 职责：内置产物唯一的对外入口。产物本体是 browserify 的 UMD 构建，已在
 * 内置时追加两行 ESM 包装（局部 module/exports 绑定 + 默认导出），因此
 * 主线程、Worker、单测环境都按同一条路径加载，不依赖任何全局挂载。
 *
 * 关键约束：调用方只允许通过本门面导入引擎，禁止直接引用 zxcvbn.js，
 * 以便产物替换或包装方式调整时只改一处。
 */
import engine from "./zxcvbn.js";

export type { ZxcvbnFn, ZxcvbnMatch, ZxcvbnResult } from "./zxcvbn.js";

/** 引擎入口（同步 CPU 密集计算） */
export const zxcvbn = engine;
