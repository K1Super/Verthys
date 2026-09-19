/*
 * cache/concurrency/typed-event-emitter.ts — 零依赖类型化事件发射器
 *
 * ★ 构建约束说明（重要）：
 *   原设计中 VerthysCacheDomain 继承 Node 的 EventEmitter（import { EventEmitter } from 'events'）。
 *   本项目为 Vite 浏览器构建（verthys-tauri），依赖中无 `events` 包亦无 Node
 *   polyfill（vite.config.ts 无 alias/polyfill 配置），Node 内置模块在
 *   浏览器 bundle 中无法解析。故提供本零依赖等价实现：
 *     - on / once / off / emit / removeAllListeners API 与 EventEmitter 对齐
 *     - 事件名与监听器参数由泛型事件表静态约束（比 Node 版更类型安全）
 *
 * 使用示例：
 *   type Events = { "scan-cleared": []; "error": [Error] };
 *   class Domain extends TypedEventEmitter<Events> {}
 *   domain.on("scan-cleared", () => { ... });
 *   domain.emit("scan-cleared");
 */
/** 事件表：事件名 → 监听器参数元组 */
export type EventMap = Record<string, unknown[]>;

type AnyListener = (...args: never[]) => void;

export class TypedEventEmitter<E extends EventMap> {
  private listeners = new Map<keyof E, Set<AnyListener>>();

  /** 注册持久监听器，返回 this 支持链式调用 */
  on<K extends keyof E>(event: K, listener: (...args: E[K]) => void): this {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener as unknown as AnyListener);
    return this;
  }

  /** 注册一次性监听器：首次触发后自动移除 */
  once<K extends keyof E>(event: K, listener: (...args: E[K]) => void): this {
    const wrapper: (...args: E[K]) => void = (...args) => {
      this.off(event, wrapper);
      listener(...args);
    };
    return this.on(event, wrapper);
  }

  /** 移除指定监听器（未注册时静默） */
  off<K extends keyof E>(event: K, listener: (...args: E[K]) => void): this {
    this.listeners.get(event)?.delete(listener as unknown as AnyListener);
    return this;
  }

  /**
   * 触发事件，同步依次调用全部监听器。
   * 单个监听器抛异常不中断其余监听器（异常经 console.error 上报）。
   * @returns 是否存在监听器（与 EventEmitter.emit 语义一致）
   */
  emit<K extends keyof E>(event: K, ...args: E[K]): boolean {
    const set = this.listeners.get(event);
    if (!set || set.size === 0) return false;
    for (const listener of [...set]) {
      try {
        (listener as unknown as (...args: E[K]) => void)(...args);
      } catch (e) {
        console.error(`[TypedEventEmitter] 事件 ${String(event)} 监听器异常`, e);
      }
    }
    return true;
  }

  /** 清空全部监听器（实例销毁 / 会话重置时调用） */
  removeAllListeners(): void {
    this.listeners.clear();
  }
}
