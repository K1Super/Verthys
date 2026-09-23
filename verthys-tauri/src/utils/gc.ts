/**
 * gc.ts — V8 垃圾回收辅助工具
 *
 * 本工具的职责：
 *   - 在 main.ts 启动时调用 installGcHelper()，将原生 gc() 桥接为 window.gc()
 *   - 提供 tryGc() 安全调用入口（dev 环境跳过，避免影响调试）
 *   - 提供 scheduleGc() 延迟调度入口（避免在用户交互的关键路径触发 GC）
 *
 * 依赖前提：原生 gc() 仅在 V8 以 --expose-gc 启动时存在。窗口未启用
 * 该选项时 installGcHelper 不做任何注册，tryGc/scheduleGc 均为安全
 * no-op；各函数保留完整类型守卫，环境显式启用 gc 时桥接自动生效。
 */

/** V8 原生 gc 函数类型（由 --expose-gc 暴露） */
type NativeGc = () => void;

/** V8 原生 gc 函数的全局对象形状 */
interface GlobalWithGc {
  gc?: NativeGc;
}

/**
 * 安装 GC 辅助工具：将 V8 原生 gc() 桥接为 window.gc()
 *
 * 调用时机：main.ts 启动入口（在 Vue 应用创建之前）
 *
 * 注意：仅在 --expose-gc 启用时原生 gc() 才存在。若未启用则 window.gc
 * 不会被注册，tryGc() 调用将安全跳过（避免运行时错误）。
 */
export function installGcHelper(): void {
  const globalObj = globalThis as unknown as GlobalWithGc;

  // 仅当原生 gc 存在且 window.gc 未被覆盖时注册
  if (typeof globalObj.gc === "function" && typeof window !== "undefined") {
    const win = window as unknown as GlobalWithGc;
    if (typeof win.gc !== "function") {
      win.gc = globalObj.gc;
    }
  }
}

/**
 * 安全触发一次 Major GC
 *
 * 使用场景：
 *   - 模块卸载后释放大对象（PhotoAlbum onUnmounted）
 *   - 模块切换延迟 500ms 后触发（useModuleNavigation watch）
 *   - 大批量数据替换后（verthysEnumerateRecords 流式加载完成后）
 *
 * @returns true 表示 GC 已触发，false 表示跳过（dev 环境 / 原生 gc 未暴露）
 */
export function tryGc(): boolean {
  // dev 环境跳过：GC 会干扰性能分析与热更新
  if (import.meta.env.DEV) return false;

  const win = window as unknown as GlobalWithGc;
  if (typeof win.gc !== "function") return false;

  try {
    win.gc();
    return true;
  } catch {
    // GC 调用失败（极少见，可能因 OOM）：静默失败，避免影响业务流程
    return false;
  }
}

/**
 * 延迟调度 GC（避免在用户交互的关键路径触发）
 *
 * @param delay 延迟毫秒数（默认 500ms，足够让 UI 完成渲染）
 * @returns timer id（可用于取消调度）
 */
export function scheduleGc(delay: number = 500): number {
  if (import.meta.env.DEV) return -1;
  return window.setTimeout(() => {
    tryGc();
  }, delay);
}
