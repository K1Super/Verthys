/**
 * workers/password-strength.worker.ts — 密码强度模式分析 Worker
 *
 * 职责：在独立线程中执行 zxcvbn 的模式分析（词典、键盘布局、重复、序列、
 * 日期），把结果压缩为猜测数 + 模式摘要后回传主线程。
 *
 * 关键约束：
 * - 主线程只在请求方向写入口令明文，本文件不在响应中回传任何口令内容；
 *   异常信息可能夹带片段，因此 catch 分支只回传固定失败码。
 * - 分析前缀已在主线程截取（超长口令的模式分析代价随长度急剧上升），
 *   本层不再二次截断，避免两处上限口径漂移。
 * - 引擎为同步 CPU 密集计算，禁止在主线程直接调用；本文件是唯一调用点。
 *
 * 安全边界：口令串在 Worker 内存中以不可变字符串形式存在，无法原地清零，
 * 约束为「任务内使用、不跨任务持有引用」；请求处理结束后不保留任何副本。
 */
/// <reference lib="webworker" />

import { zxcvbn } from "../vendor/zxcvbn";
import {
  buildStrengthFailure,
  buildStrengthSuccess,
  type StrengthRequest,
  type StrengthResponse,
} from "./password-strength-protocol";

const workerScope = self as unknown as DedicatedWorkerGlobalScope;

workerScope.onmessage = (event: MessageEvent<StrengthRequest>) => {
  const request = event.data;
  if (!request || typeof request.id !== "number" || typeof request.password !== "string") {
    // 协议异常：能关联到任务 ID 时回传失败码，否则丢弃（向未知 ID 回包会让
    // 主线程把错误挂到别的任务上）
    if (request && typeof request.id === "number") {
      workerScope.postMessage(buildStrengthFailure(request.id, "protocol"));
    }
    return;
  }

  let response: StrengthResponse;
  try {
    response = buildStrengthSuccess(request.id, zxcvbn(request.password));
  } catch {
    response = buildStrengthFailure(request.id, "engine");
  }
  workerScope.postMessage(response);
};
