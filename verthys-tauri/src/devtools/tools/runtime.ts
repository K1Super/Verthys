/*
 * devtools/tools/runtime.ts — 运行时观测工具
 *
 * 只读快照在面板展开时按秒刷新；所有读取入口都返回新对象，不暴露
 * 监控器或 flags 的内部可变引用。
 */
import { isTauri } from "@tauri-apps/api/core";
import { PERF_FLAGS_STORAGE_KEY, perfFlags } from "../../app/feature-flags";
import { useGlobalIdleScheduler } from "../../composables/useGlobalIdleScheduler";
import { frameBudgetMonitor } from "../../core/frame-budget";
import type { DevTool } from "../registry";

const round = (value: number): number => Math.round(value * 100) / 100;

function readMetrics(): Record<string, string | number> {
  const metrics = frameBudgetMonitor.getMetrics();
  return {
    空闲档位: useGlobalIdleScheduler().level.value,
    采样帧: metrics.samples,
    "P50(ms)": round(metrics.p50Ms),
    "P95(ms)": round(metrics.p95Ms),
    "P99(ms)": round(metrics.p99Ms),
    降档级别: metrics.level,
    绘制调用: metrics.drawCalls,
  };
}

function buildSnapshot(): string {
  const metrics = frameBudgetMonitor.getMetrics();
  return [
    "Verthys dev snapshot",
    `version: ${import.meta.env.VITE_APP_VERSION ?? "unknown"}`,
    `mode: ${import.meta.env.MODE}`,
    `tauri: ${isTauri()}`,
    `viewport: ${window.innerWidth}x${window.innerHeight} @ ${window.devicePixelRatio}x`,
    `idle: ${useGlobalIdleScheduler().level.value}`,
    `metrics: ${JSON.stringify(metrics)}`,
    `perfFlags: ${JSON.stringify(perfFlags)}`,
  ].join("\n");
}

export const runtimeTools: DevTool[] = [
  {
    id: "runtime.metrics",
    group: "runtime",
    kind: "info",
    label: "帧预算指标",
    hint: "任务耗时分位、降档级别与绘制调用；仅面板展开时刷新",
    read: readMetrics,
  },
  {
    id: "runtime.flags",
    group: "runtime",
    kind: "info",
    label: "性能开关快照",
    hint: "启动时解析的 perfFlags；清除 localStorage 覆盖后需重载",
    read: () => ({ ...perfFlags }),
    actions: [
      {
        label: "复制 JSON",
        run: async (ctx) => {
          await navigator.clipboard.writeText(JSON.stringify(perfFlags, null, 2));
          ctx.notify("性能开关 JSON 已复制");
        },
      },
      {
        label: "清除覆盖并重载",
        tone: "danger",
        run: () => {
          if (!window.confirm("清除性能开关覆盖并重载？未保存的界面状态会丢失")) return;
          window.localStorage.removeItem(PERF_FLAGS_STORAGE_KEY);
          window.location.reload();
        },
      },
    ],
  },
  {
    id: "runtime.snapshot",
    group: "runtime",
    kind: "action",
    label: "复制开发快照",
    hint: "环境、帧指标与性能开关合并为文本写入剪贴板",
    run: async (ctx) => {
      await navigator.clipboard.writeText(buildSnapshot());
      ctx.notify("开发快照已复制");
    },
  },
];
