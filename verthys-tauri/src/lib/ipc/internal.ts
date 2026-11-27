/*
 * ipc/internal.ts — 私有 invoke 包装
 *
 * 所有域模块的 Tauri invoke 统一经由 ipc()：原生错误包装为 VerthysError。
 * 本模块不被 lib/verthys.ts barrel 重导出，避免暴露可自定义命令的通用入口。
 */

import { invokeWithTimeout } from "../../utils/ipc/invoke_wrapper";
import { wrapAsVerthysError } from "../util/verthys_error";

export async function ipc<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invokeWithTimeout<T>(cmd, args);
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}
