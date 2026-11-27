/*
 * key/global/status.ts — 加密库初始化状态查询
 */
import { verthysInitStatus, type InitStatusResult } from "../../lib/verthys";
import { keyState } from "../../state/key_state";
import { withTimeout } from "../../utils/ipc/promise_utils";
import { isTauriEnvironment } from "../../utils/ipc/tauri_env";
import { log } from "./shared";

/**
 * 查询初始化状态（读取 .verthys_state 文件）
 * 供 SecurityCenter 在 onMounted 时调用，确定走哪个分支：
 *   none   → 全新用户，显示路径选择
 *   ready  → 老用户，自动填充路径并解锁
 *   broken → 损坏残留，已自动清理，按全新用户处理
 *
 * @returns 状态结果，Tauri 不可用时返回 "none"
 */
export async function checkInitStatus(): Promise<InitStatusResult> {
  if (!isTauriEnvironment()) {
    keyState.initStatus.value = "none";
    keyState.storedVerthysPath.value = "";
    keyState.initDetail.value = "浏览器模式";
    return { status: "none", verthys_path: null, detail: "浏览器模式" };
  }
  try {
    const result = await withTimeout(verthysInitStatus(), 5000, "状态查询");
    keyState.initStatus.value = result.status;
    keyState.storedVerthysPath.value = result.verthys_path ?? "";
    keyState.initDetail.value = result.detail;
    log.info("status:", result.status, "path:", result.verthys_path, "detail:", result.detail);
    return result;
  } catch (e) {
    log.error("查询失败", e);
    keyState.initStatus.value = "none";
    keyState.storedVerthysPath.value = "";
    keyState.initDetail.value = `查询失败: ${e}`;
    return { status: "none", verthys_path: null, detail: `查询失败: ${e}` };
  }
}
