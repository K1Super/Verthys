// @vitest-environment happy-dom
/*
 * useSystemMetrics.spec.ts — 系统指标轮询契约回归
 *
 * 覆盖：
 *   1. 无有效样本保持 null（不以 0 占位）
 *   2. 有效快照钳制取整后写入
 *   3. 后端返回 null 立即清为 null
 *   4. IPC 失败保留上次值，超过陈旧上限清为 null
 *   5. 禁用不轮询，启用后立即首采
 *   6. 在途请求期间不重复发起
 *   7. 卸载停止轮询并丢弃在途结果
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createApp, defineComponent, nextTick, ref, type Ref } from "vue";
import { useSystemMetrics } from "./useSystemMetrics";

const mocks = vi.hoisted(() => ({
  getSnapshot: vi.fn(),
}));

vi.mock("../../lib/verthys", () => ({
  verthysGetSystemSnapshot: mocks.getSnapshot,
}));

/** 挂载消费者组件：生命周期钩子需要组件实例 */
function mountMetrics(enabled: Ref<boolean>) {
  let api: ReturnType<typeof useSystemMetrics> | null = null;
  const Root = defineComponent({
    setup() {
      api = useSystemMetrics(enabled);
      return () => null;
    },
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp(Root);
  app.mount(container);
  return {
    api: api as unknown as ReturnType<typeof useSystemMetrics>,
    teardown: () => {
      app.unmount();
      container.remove();
    },
  };
}

/** 等待轮询的微任务链落定 */
async function flush() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
}

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  mocks.getSnapshot.mockReset();
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
  vi.useRealTimers();
});

describe("useSystemMetrics", () => {
  it("无有效样本保持 null，不以 0 占位", async () => {
    mocks.getSnapshot.mockResolvedValue({ cpu_usage: null });
    const { api, teardown } = mountMetrics(ref(true));
    try {
      await flush();
      expect(api.cpuUsage.value).toBeNull();
    } finally {
      teardown();
    }
  });

  it("有效快照钳制取整后写入", async () => {
    mocks.getSnapshot.mockResolvedValue({ cpu_usage: 42.6 });
    const { api, teardown } = mountMetrics(ref(true));
    try {
      await flush();
      expect(api.cpuUsage.value).toBe(43);
    } finally {
      teardown();
    }
  });

  it("越界值钳制到上限，非法值清为 null", async () => {
    mocks.getSnapshot.mockResolvedValue({ cpu_usage: 173.2 });
    const { api, teardown } = mountMetrics(ref(true));
    try {
      await flush();
      expect(api.cpuUsage.value).toBe(100);

      mocks.getSnapshot.mockResolvedValue({ cpu_usage: Number.NaN });
      vi.advanceTimersByTime(1000);
      await flush();
      expect(api.cpuUsage.value).toBeNull();
    } finally {
      teardown();
    }
  });

  it("后端返回 null 立即清为 null", async () => {
    mocks.getSnapshot.mockResolvedValue({ cpu_usage: 55 });
    const { api, teardown } = mountMetrics(ref(true));
    try {
      await flush();
      expect(api.cpuUsage.value).toBe(55);

      mocks.getSnapshot.mockResolvedValue({ cpu_usage: null });
      vi.advanceTimersByTime(1000);
      await flush();
      expect(api.cpuUsage.value).toBeNull();
    } finally {
      teardown();
    }
  });

  it("IPC 失败保留上次值，超过陈旧上限清为 null", async () => {
    mocks.getSnapshot.mockResolvedValue({ cpu_usage: 55 });
    const { api, teardown } = mountMetrics(ref(true));
    try {
      await flush();
      expect(api.cpuUsage.value).toBe(55);

      mocks.getSnapshot.mockRejectedValue(new Error("ipc down"));
      vi.advanceTimersByTime(1000);
      await flush();
      expect(api.cpuUsage.value).toBe(55);

      vi.advanceTimersByTime(6000);
      await flush();
      expect(api.cpuUsage.value).toBeNull();
    } finally {
      teardown();
    }
  });

  it("禁用不轮询，启用后立即首采", async () => {
    const enabled = ref(false);
    mocks.getSnapshot.mockResolvedValue({ cpu_usage: 10 });
    const { api, teardown } = mountMetrics(enabled);
    try {
      await flush();
      expect(mocks.getSnapshot).not.toHaveBeenCalled();

      enabled.value = true;
      await nextTick();
      await flush();
      expect(mocks.getSnapshot).toHaveBeenCalledTimes(1);
      expect(api.cpuUsage.value).toBe(10);
    } finally {
      teardown();
    }
  });

  it("在途请求期间不重复发起", async () => {
    let resolveSnapshot: (value: { cpu_usage: number | null }) => void = () => {};
    mocks.getSnapshot.mockImplementation(
      () =>
        new Promise<{ cpu_usage: number | null }>((resolve) => {
          resolveSnapshot = resolve;
        }),
    );
    const { api, teardown } = mountMetrics(ref(true));
    try {
      await flush();
      vi.advanceTimersByTime(3000);
      await flush();
      expect(mocks.getSnapshot).toHaveBeenCalledTimes(1);

      resolveSnapshot({ cpu_usage: 20 });
      await flush();
      expect(api.cpuUsage.value).toBe(20);
    } finally {
      teardown();
    }
  });

  it("卸载停止轮询并丢弃在途结果", async () => {
    let resolveSnapshot: (value: { cpu_usage: number | null }) => void = () => {};
    mocks.getSnapshot.mockImplementation(
      () =>
        new Promise<{ cpu_usage: number | null }>((resolve) => {
          resolveSnapshot = resolve;
        }),
    );
    const { api, teardown } = mountMetrics(ref(true));
    await flush();
    teardown();

    resolveSnapshot({ cpu_usage: 99 });
    await flush();
    expect(api.cpuUsage.value).toBeNull();

    vi.advanceTimersByTime(2000);
    await flush();
    expect(mocks.getSnapshot).toHaveBeenCalledTimes(1);
  });
});
