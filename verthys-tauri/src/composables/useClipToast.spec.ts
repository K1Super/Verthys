/**
 * useClipToast.spec.ts — 剪贴板安全清空链路回归
 *
 * 覆盖（用户裁定的轮番提示契约）：
 *   1. 复制成功先提示结果；成功提示收起后再单独提示清空时间（不叠加、不常驻）
 *   2. 默认 1 分钟静默清空：到期覆写剪贴板 + 调用 Tauri 清空，全程无逐秒倒计时
 *   3. 新复制取消上一笔清空计时（最后复制的内容才拥有清空权）
 *   4. 组件卸载只取消接力提示，清空计时继续（跨模块切换仍按时清空）
 *   5. 写入被拒（无权限 / 被占用）：如实返回 false，不提示成功
 *   6. 降级写入器成功 / 失败 / 抛错三种收口
 *   7. 无 clipboard API / 到期时 API 消失：不得抛未捕获异常
 *
 * 说明：onBeforeUnmount 需组件实例，node 测试环境以 vi.mock 捕获注册回调、
 * 手动触达卸载路径（仓库既有口径：无 SFC 组件测试基建）。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { toastState } from "./useToastCenter";

/* ===== 捕获 onBeforeUnmount 注册（按调用顺序）===== */
const { unmountCbs } = vi.hoisted(() => ({ unmountCbs: [] as Array<() => void> }));
vi.mock("vue", async (importOriginal) => {
  const actual = await importOriginal<typeof import("vue")>();
  return {
    ...actual,
    onBeforeUnmount: (cb: () => void) => { unmountCbs.push(cb); },
  };
});

/* ===== 剪贴板与 Tauri 清空打桩 ===== */
const { clearClipboardMock } = vi.hoisted(() => ({ clearClipboardMock: vi.fn() }));
vi.mock("../lib/verthys", () => ({ clearClipboard: clearClipboardMock }));

import { useClipToast } from "./useClipToast";

/** 清空时长口径（默认 1 分钟） */
const CLEAR_MS = 60_000;
/** 成功提示展示时长（与实现常量对齐） */
const STATUS_MS = 2500;
/** 接力提示间隔（与实现常量对齐） */
const RELAY_GAP_MS = 200;

describe("useClipToast", () => {
  const writeTextMock = vi.fn(() => Promise.resolve());

  beforeEach(() => {
    vi.useFakeTimers();
    unmountCbs.length = 0;
    clearClipboardMock.mockClear();
    writeTextMock.mockClear();
    vi.stubGlobal("navigator", { clipboard: { writeText: writeTextMock } });
    /* 单例状态复位（与 useToastCenter.spec 同口径） */
    toastState.status.value = "";
    vi.clearAllTimers();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("成功：先提示复制结果，不显示倒计时也不常驻", async () => {
    const { copyWithTimeout } = useClipToast("模块密钥已复制");
    await expect(copyWithTimeout("secret")).resolves.toBe(true);

    expect(writeTextMock).toHaveBeenCalledWith("secret");
    expect(toastState.status.value).toBe("模块密钥已复制");
    // 无秒级倒计时文案
    expect(toastState.status.value).not.toContain("s 后自动清空");
  });

  it("轮番提示：成功提示收起后，再单独提示清空时间（不同屏叠加）", async () => {
    const { copyWithTimeout } = useClipToast("模块密钥已复制");
    await copyWithTimeout("secret");

    // 成功提示到期收起
    await vi.advanceTimersByTimeAsync(STATUS_MS);
    expect(toastState.status.value).toBe("");

    // 间隔后接力给出设定时长（60 秒 — 不折算已消耗的提示时间）
    await vi.advanceTimersByTimeAsync(RELAY_GAP_MS);
    expect(toastState.status.value).toBe("剪贴板将在 60 秒后自动清空");
  });

  it("到期：静默覆写剪贴板 + 调用 Tauri 清空", async () => {
    const { copyWithTimeout } = useClipToast("模块密钥已复制");
    await copyWithTimeout("secret");
    writeTextMock.mockClear();

    await vi.advanceTimersByTimeAsync(CLEAR_MS - 1);
    expect(clearClipboardMock).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(writeTextMock).toHaveBeenCalledWith("\u0000".repeat(32)); // 覆写
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);            // Tauri 清空
  });

  it("新复制重置清空计时：仅最后复制的内容拥有清空权", async () => {
    const { copyWithTimeout } = useClipToast("密码已复制");
    await copyWithTimeout("first");
    await vi.advanceTimersByTimeAsync(30_000);
    expect(clearClipboardMock).not.toHaveBeenCalled();

    await copyWithTimeout("second");
    writeTextMock.mockClear();
    // 首笔原定 60s 到点不得清空（已被第二笔接管）
    await vi.advanceTimersByTimeAsync(30_000);
    expect(clearClipboardMock).not.toHaveBeenCalled();

    // 第二笔满 60s 才清空
    await vi.advanceTimersByTimeAsync(30_000);
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);
  });

  it("卸载：只取消接力提示，清空计时继续（跨模块切换仍按时清空）", async () => {
    const { copyWithTimeout } = useClipToast("模块密钥已复制");
    await copyWithTimeout("secret");

    unmountCbs[0](); // 组件卸载
    // 接力提示不再弹出
    await vi.advanceTimersByTimeAsync(STATUS_MS + RELAY_GAP_MS);
    expect(toastState.status.value).toBe("");

    // 清空仍按时执行
    await vi.advanceTimersByTimeAsync(CLEAR_MS);
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);
  });

  it("写入被拒：如实返回失败，不提示成功", async () => {
    writeTextMock.mockRejectedValueOnce(new Error("clipboard denied"));
    const { copyWithTimeout } = useClipToast("密码已复制");

    await expect(copyWithTimeout("secret")).resolves.toBe(false);
    expect(toastState.status.value).toBe("");
    await vi.advanceTimersByTimeAsync(CLEAR_MS * 2);
    expect(clearClipboardMock).not.toHaveBeenCalled();
  });

  it("Clipboard API 不可用但注入降级写入器成功：按成功处理", async () => {
    writeTextMock.mockRejectedValueOnce(new Error("clipboard denied"));
    const fallback = vi.fn(async () => true);
    const { copyWithTimeout } = useClipToast("已复制", { write: fallback });

    await expect(copyWithTimeout("secret")).resolves.toBe(true);
    expect(fallback).toHaveBeenCalledWith("secret");
    expect(toastState.status.value).toBe("已复制");
  });

  it("降级写入器同样失败：返回失败且不提示成功", async () => {
    writeTextMock.mockRejectedValueOnce(new Error("clipboard denied"));
    const fallback = vi.fn(async () => false);
    const { copyWithTimeout } = useClipToast("已复制", { write: fallback });

    await expect(copyWithTimeout("secret")).resolves.toBe(false);
    expect(toastState.status.value).toBe("");
  });

  it("降级写入器抛出：按失败收口，异常不逃逸", async () => {
    writeTextMock.mockRejectedValueOnce(new Error("clipboard denied"));
    const fallback = vi.fn(async () => {
      throw new Error("execCommand failed");
    });
    const { copyWithTimeout } = useClipToast("已复制", { write: fallback });

    await expect(copyWithTimeout("secret")).resolves.toBe(false);
    expect(toastState.status.value).toBe("");
  });

  it("无 clipboard API：如实返回失败，不抛未捕获异常", async () => {
    vi.stubGlobal("navigator", {});
    const { copyWithTimeout } = useClipToast("已复制");

    await expect(copyWithTimeout("secret")).resolves.toBe(false);
    expect(toastState.status.value).toBe("");
  });

  it("到期清理路径：计时中途 clipboard 不可用仍安全走完", async () => {
    const { copyWithTimeout } = useClipToast("已复制");
    await copyWithTimeout("secret");
    writeTextMock.mockClear();

    vi.stubGlobal("navigator", {});
    await vi.advanceTimersByTimeAsync(CLEAR_MS);
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);
  });

  it("自定义清空时长：提示与清空均按该时长收敛", async () => {
    const { copyWithTimeout } = useClipToast("已复制", { seconds: 10 });
    await copyWithTimeout("secret");

    await vi.advanceTimersByTimeAsync(STATUS_MS + RELAY_GAP_MS);
    expect(toastState.status.value).toBe("剪贴板将在 10 秒后自动清空");

    await vi.advanceTimersByTimeAsync(10_000 - STATUS_MS - RELAY_GAP_MS);
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);
  });
});
