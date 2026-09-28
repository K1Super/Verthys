/**
 * useToastCenter.spec.ts — 全局 Toast 中心单例语义与通道行为回归
 *
 * 覆盖（Wave 56 收口约束的防回退门）：
 * - 单例语义：任意调用方写入收敛到同一份状态（跨 composable 共享不丢失 —
 *   旧 useErrorToast 非单例导致提示丢失的问题不得复活）
 * - 各通道自动消失时长：error 2.5s / status 2.5s（可显式覆写）/
 *   copied 1.5s / exportDone 2.6s；重复触发重置计时
 * - clip 通道为长驻状态：无自动消失计时，仅显式收起（由 useClipToast 驱动）
 * - 通道互不干扰：同屏并存时各通道独立计时与覆盖
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { toastState, useToastCenter } from "./useToastCenter";

/** 时长口径（与实现常量对齐；改动实现须同步本文件） */
const ERROR_MS = 2500;
const STATUS_MS = 2500;
const COPIED_MS = 1500;
const EXPORT_MS = 2600;

describe("useToastCenter", () => {
  const center = useToastCenter();

  beforeEach(() => {
    vi.useFakeTimers();
    /* 单例状态跨用例复位（模块级共享，防止用例间串扰） */
    toastState.error.value = "";
    toastState.status.value = "";
    toastState.copied.value = false;
    toastState.exportDone.value = null;
    toastState.clip.value = null;
    vi.clearAllTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("单例语义：跨调用方的写入收敛到同一份状态", () => {
    const a = useToastCenter();
    const b = useToastCenter();
    // 方法同一引用 + 状态同一来源（不存在第二份副本）
    expect(a.showError).toBe(b.showError);
    expect(a.showError).toBe(center.showError);

    a.showError("错误A");
    expect(toastState.error.value).toBe("错误A");
    b.showError("错误B");
    expect(toastState.error.value).toBe("错误B");
  });

  it("error 通道：2.5s 自动消失，重复触发重置计时", () => {
    center.showError("失败");
    vi.advanceTimersByTime(ERROR_MS - 1);
    expect(toastState.error.value).toBe("失败");
    vi.advanceTimersByTime(1);
    expect(toastState.error.value).toBe("");

    center.showError("第一次");
    vi.advanceTimersByTime(2000);
    center.showError("第二次");
    vi.advanceTimersByTime(2000); // 距第二次仅 2s < 2.5s：不得提前消失
    expect(toastState.error.value).toBe("第二次");
    vi.advanceTimersByTime(500);
    expect(toastState.error.value).toBe("");
  });

  it("status 通道：默认 2.5s；显式时长覆写生效（拾光 2s 口径）", () => {
    center.showStatus("已保存");
    vi.advanceTimersByTime(STATUS_MS);
    expect(toastState.status.value).toBe("");

    center.showStatus("已删除", 2000);
    vi.advanceTimersByTime(1999);
    expect(toastState.status.value).toBe("已删除");
    vi.advanceTimersByTime(1);
    expect(toastState.status.value).toBe("");
  });

  it("copied 通道：1.5s 自动消失", () => {
    center.showCopied();
    expect(toastState.copied.value).toBe(true);
    vi.advanceTimersByTime(COPIED_MS - 1);
    expect(toastState.copied.value).toBe(true);
    vi.advanceTimersByTime(1);
    expect(toastState.copied.value).toBe(false);
  });

  it("exportDone 通道：2.6s 自动消失且载荷保真", () => {
    center.showExportDone("导出完成", "success");
    expect(toastState.exportDone.value).toEqual({ msg: "导出完成", type: "success" });

    center.showExportDone("导出失败，请重试", "error"); // 同通道覆盖并重置计时
    expect(toastState.exportDone.value).toEqual({ msg: "导出失败，请重试", type: "error" });
    vi.advanceTimersByTime(EXPORT_MS);
    expect(toastState.exportDone.value).toBeNull();
  });

  it("clip 通道：长驻状态（无自动消失计时，仅显式收起）", () => {
    center.setClip({ text: "密码已复制", seconds: 15 });
    expect(toastState.clip.value).toEqual({ text: "密码已复制", seconds: 15 });

    // 秒级刷新由 useClipToast 推入；中心不做任何计时
    vi.advanceTimersByTime(60_000);
    expect(toastState.clip.value).not.toBeNull();

    center.setClip({ text: "密码已复制", seconds: 14 });
    expect(toastState.clip.value?.seconds).toBe(14);
    center.setClip(null);
    expect(toastState.clip.value).toBeNull();
  });

  it("通道互不干扰：同屏并存各自独立计时", () => {
    center.showError("错误");
    vi.advanceTimersByTime(1000);
    center.showStatus("状态"); // 不影响 error 已消耗的计时
    vi.advanceTimersByTime(1500); // error 到期（自触发起满 2.5s）
    expect(toastState.error.value).toBe("");
    expect(toastState.status.value).toBe("状态");

    vi.advanceTimersByTime(1000); // status 到期（自触发起满 2.5s）
    expect(toastState.status.value).toBe("");

    // 反向验证：仅触发 status 时 error 通道保持空
    center.showStatus("仅状态");
    vi.advanceTimersByTime(1000);
    expect(toastState.error.value).toBe("");
    expect(toastState.status.value).toBe("仅状态");
  });
});