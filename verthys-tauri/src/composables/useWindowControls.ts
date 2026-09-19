/**
 * useWindowControls — 窗口控制逻辑（最小化/最大化/关闭/拖动）
 *
 * 职责：
 *   1. 窗口最小化、最大化/还原、关闭按钮逻辑
 *   2. 关闭流程：后端隐藏窗口 + 前端异步清理 + exit(0)
 *   3. 窗口拖动：data-tauri-drag-region 的增强备用路径
 *
 * ★ 企业级关闭响应优化（根治"关闭按钮延迟数秒"）：
 *
 *   旧实现根因：
 *     前端 `await getCurrentWindow().hide()` 为 IPC 往返调用。
 *     后端事件循环繁忙（verthys 操作 / background_patrol / lock_monitor）时，
 *     hide() 的 IPC 消息被排队，窗口实际隐藏延迟数秒。
 *     用户点击关闭按钮后看到窗口迟迟不消失，体验极差。
 *
 *   新实现架构（窗口隐藏下沉至 Rust 后端，零 IPC 延迟）：
 *     1. 用户点击关闭按钮 / Alt+F4 → window.close() → 触发后端 CloseRequested
 *     2. 后端 on_window_event 直接调用 window.hide()（Rust 原生 Win32 调用，微秒级）
 *        + api.prevent_close()（阻止 WebView 销毁，保留 JS 引擎供 lockAll 执行）
 *        + emit("verthys://cleanup-and-exit") 通知前端
 *     3. 前端 listen("verthys://cleanup-and-exit") 接收事件 → 执行 lockAll 异步清理
 *     4. lockAll 完成（数据落盘）后前端调用 exit(0) 退出进程
 *     5. 后端 45s 超时兜底：前端卡死时强制 app_handle.exit(0)
 *
 *   效果：
 *     - 窗口在用户点击的瞬间消失（微秒级，Rust 直接调用 Win32 API）
 *     - lockAll 在后台异步执行（数据落盘），用户无感知
 *     - 进程在 lockAll 完成后退出，或 45s 超时后强制退出
 *     - 数据安全铁律：45s 覆盖 lockAll 40s 安全网 + 5s 余量
 */

import { getCurrentWindow } from "@tauri-apps/api/window";
import { exit } from "@tauri-apps/plugin-process";
import { isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { onMounted, onUnmounted } from "vue";
import {
  lockAll,
  verthysReadyRef,
} from "../lib/keyManager";

/* 环境检测：使用公开 API isTauri() 替代内部实现细节 __TAURI_INTERNALS__
 * isTauri() 检查 window.isTauri 标志，由 Tauri 运行时注入，跨版本稳定 */
const isTauriEnv = typeof window !== "undefined" && isTauri();

/* 关闭互斥标志：防止按钮点击与系统关闭事件（Alt+F4）并发执行清理
 * 模块级单例，整个应用生命周期内共享 */
let isClosing = false;

/**
 * 统一退出策略：exit(0) 优先，3 秒超时或失败后降级 destroy。
 * 无论来源（按钮点击 / 系统事件），退出方式保持一致，确保进程彻底清理。
 */
async function exitWithFallback(): Promise<void> {
  try {
    await Promise.race([
      exit(0),
      new Promise<void>((_, reject) =>
        setTimeout(() => reject(new Error("exit 超时")), 3000),
      ),
    ]);
  } catch {
    // exit 超时或失败 → destroy 强制关闭窗口兜底
    try {
      await getCurrentWindow().destroy();
    } catch { /* */ }
  }
}

/**
 * 前端异步清理执行器：接收到后端 "verthys://cleanup-and-exit" 事件后调用。
 *
 * 流程：
 *   1. verthys 未初始化 → 无需清理，直接 exit(0)
 *   2. verthys 已初始化 → lockAll 异步清理（waitForFlush 落盘 → 清空缓存 →
 *      verthysLockPersist 原子落盘 → securitySessionStop → verthysLock 销毁 worker）
 *   3. lockAll 完成（或异常）后 exit(0)
 *
 * ★ 后端 45s 超时兜底确保进程必然退出（防 worker 卡死导致僵尸进程）。
 *   窗口已由后端在 CloseRequested 时隐藏（Rust 原生调用，微秒级），用户无感知。
 *
 * ★ 数据安全铁律：lockAll 内部 40s 安全网确保 v1 容器 waitForFlush（22s）
 *   + verthysLockPersist（12s）完整执行后再销毁 worker，防止数据丢失。
 */
async function performCleanupAndExit(): Promise<void> {
  // 1. 互斥检查：防止并发关闭（按钮点击 + Alt+F4 同时触发）
  if (isClosing) return;
  isClosing = true;

  // 2. verthys 未初始化 → 无需清理，直接退出
  if (!verthysReadyRef.value) {
    await exitWithFallback();
    return;
  }

  // 3. verthys 已初始化 → lockAll 异步清理（数据落盘 + 销毁 worker）
  //    ★ 窗口已由后端在 CloseRequested 时隐藏（零 IPC 延迟），此处无需再隐藏
  //    ★ lockAll 内部 40s 安全网 + 后端 45s 超时兜底，双保险确保进程退出
  try {
    await lockAll();
  } catch { /* lockAll 内部已吞错，此处兜底 */ }

  // 4. 统一退出：exit(0) 优先，3 秒超时后 destroy 兜底
  await exitWithFallback();
}

export function useWindowControls() {
  /* ===== 窗口控制（浏览器模式做空操作） ===== */
  const onMinimize = async () => {
    if (!isTauriEnv) return;
    try {
      await getCurrentWindow().minimize();
    } catch { /* */ }
  };

  const onToggleMax = async () => {
    if (!isTauriEnv) return;
    try {
      await getCurrentWindow().toggleMaximize();
    } catch { /* */ }
  };

  /**
   * 关闭按钮点击：调用 window.close() 触发后端 CloseRequested 事件。
   *
   * ★ 后端 on_window_event 处理器在 CloseRequested 时：
   *   1. api.prevent_close() — 阻止默认关闭
   *   2. window.hide() — Rust 原生调用，微秒级隐藏窗口（零 IPC 延迟）
   *   3. emit("verthys://cleanup-and-exit") — 通知前端执行 lockAll
   *
   * 前端无需在此处执行任何清理逻辑，全部由 listen 回调处理。
   */
  const onClose = async () => {
    if (!isTauriEnv) return;
    try {
      await getCurrentWindow().close();
    } catch { /* */ }
  };

  /* ===== 窗口拖动：data-tauri-drag-region 的增强备用路径 =====
   * 预加载窗口模块，避免 mousedown 事件中异步导入导致错过拖动时机
   */
  let startDraggingFn: (() => Promise<void>) | null = null;

  const onDragRegionMouseDown = (e: MouseEvent) => {
    if (!startDraggingFn) return;
    if (e.button !== 0) return;
    const target = e.target as HTMLElement;
    if (target.closest("button")) return;
    startDraggingFn();
  };

  /* ===== 后端清理事件监听器（onMounted 注册，onUnmounted 注销） ===== */
  let unlistenCleanup: UnlistenFn | null = null;

  onMounted(() => {
    if (!isTauriEnv) return;
    try {
      const win = getCurrentWindow();
      startDraggingFn = () => win.startDragging();

      // ★ 监听后端 emit 的 "verthys://cleanup-and-exit" 事件
      //   后端在 CloseRequested 时已隐藏窗口（Rust 原生调用，微秒级），
      //   前端收到此事件后执行 lockAll 异步清理 + exit(0)
      listen("verthys://cleanup-and-exit", () => {
        performCleanupAndExit();
      }).then((unlisten) => {
        unlistenCleanup = unlisten;
      }).catch(() => { /* 注册失败时忽略，后端 45s 超时兜底 */ });
    } catch { /* */ }
  });

  onUnmounted(() => {
    if (unlistenCleanup) {
      unlistenCleanup();
      unlistenCleanup = null;
    }
  });

  return {
    onMinimize,
    onToggleMax,
    onClose,
    onDragRegionMouseDown,
  };
}
