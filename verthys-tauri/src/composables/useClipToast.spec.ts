/**
 * useClipToast.spec.ts — 剪贴板安全倒计时链路回归
 *
 * 覆盖（Wave 56 收口 + 复审缺陷 2 的防回退门）：
 * - 复制后倒计时提示经全局 Toast 中心渲染：起步秒数入通道、逐秒递减、
 *   到期收起并覆写剪贴板 + 调用 Tauri 清空
 * - 通道单写者自守：被新实例接管后，旧实例计时器自行让出（不交错回写）
 * - 卸载归属判定：仅收回本实例写入的提示 —— 模块交叉淡出（新旧并存）时，
 *   旧实例卸载不得误清新实例已接管的倒计时通道
 * - 清理路径健壮性：无 clipboard API 时不得以未捕获异常逃逸出计时回调
 *
 * 断言口径说明：起步秒数由实现常量（COUNTDOWN_SECONDS）决定，属可调产品
 * 口径 —— 本测试不钉值，动态读取起步值后验证「逐秒递减 + 到期收束」。
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

describe("useClipToast", () => {
  const writeTextMock = vi.fn(() => Promise.resolve());

  /** 读取当前提示秒数（起步值由实现常量决定） */
  const clipSeconds = () => toastState.clip.value?.seconds;

  beforeEach(() => {
    vi.useFakeTimers();
    unmountCbs.length = 0;
    clearClipboardMock.mockClear();
    writeTextMock.mockClear();
    vi.stubGlobal("navigator", { clipboard: { writeText: writeTextMock } });
    /* 单例状态复位（与 useToastCenter.spec 同口径） */
    toastState.clip.value = null;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("复制即入倒计时通道：起步秒数入通道并逐秒递减", async () => {
    const { copyWithTimeout } = useClipToast("密码已复制");
    await copyWithTimeout("secret");

    expect(writeTextMock).toHaveBeenCalledWith("secret");
    const start = clipSeconds();
    expect(start).toBeGreaterThan(0);
    expect(toastState.clip.value?.text).toBe("密码已复制");

    await vi.advanceTimersByTimeAsync(1000);
    expect(clipSeconds()).toBe(start! - 1);

    await vi.advanceTimersByTimeAsync(1000);
    expect(clipSeconds()).toBe(start! - 2);
  });

  it("到期：收起提示 + 覆写剪贴板 + 调用 Tauri 清空", async () => {
    const { copyWithTimeout } = useClipToast("已复制");
    await copyWithTimeout("secret");
    const start = clipSeconds()!;
    writeTextMock.mockClear();

    await vi.advanceTimersByTimeAsync(start * 1000 - 1000);
    expect(clipSeconds()).toBe(1); // 到期前一秒仍在
    await vi.advanceTimersByTimeAsync(1000);

    expect(toastState.clip.value).toBeNull();
    expect(writeTextMock).toHaveBeenCalledWith("\u0000".repeat(32)); // 覆写
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);            // Tauri 清空
  });

  it("清理路径健壮性：无 clipboard API 时不抛未捕获异常", async () => {
    vi.stubGlobal("navigator", {}); // 无 clipboard
    const { copyWithTimeout } = useClipToast("已复制");
    await copyWithTimeout("secret");
    const start = clipSeconds()!;

    // 到期清理路径含 clipboard 覆写：无 API 时也必须安全走完（异常将在此 await 抛出）
    await vi.advanceTimersByTimeAsync(start * 1000);
    expect(toastState.clip.value).toBeNull();
    expect(clearClipboardMock).toHaveBeenCalledTimes(1);
  });

  it("卸载归属判定：被新实例接管后旧实例让出，卸载不得误清他人状态", async () => {
    const a = useClipToast("A");
    await a.copyWithTimeout("a-secret");

    const b = useClipToast("B");
    await b.copyWithTimeout("b-secret");
    const bStart = clipSeconds()!;

    // 双计时器并存一个节拍：B（后写）保持通道，A 自守让出
    await vi.advanceTimersByTimeAsync(1000);
    expect(toastState.clip.value).toEqual({ text: "B", seconds: bStart - 1 });

    // 交叉淡出：旧实例 A 先卸载 —— 归属非 A，不得清除
    unmountCbs[0]();
    expect(toastState.clip.value).toEqual({ text: "B", seconds: bStart - 1 });

    // 再推进：状态仅由 B 驱动（若 A 未让出将出现秒数抽动）
    await vi.advanceTimersByTimeAsync(1000);
    expect(toastState.clip.value).toEqual({ text: "B", seconds: bStart - 2 });

    // 新实例 B 卸载 —— 归属为 B，精确收回
    unmountCbs[1]();
    expect(toastState.clip.value).toBeNull();
  });

  it("卸载即收回：单实例未到期卸载时提示不残留且计时停止", async () => {
    const a = useClipToast("密码已复制");
    await a.copyWithTimeout("secret");
    await vi.advanceTimersByTimeAsync(2000);
    expect(toastState.clip.value).not.toBeNull();

    unmountCbs[0]();
    expect(toastState.clip.value).toBeNull();

    // 卸载后定时器已停止：继续推进时间不得回写状态
    await vi.advanceTimersByTimeAsync(120_000);
    expect(toastState.clip.value).toBeNull();
  });

  it("重复复制：重置倒计时（旧计时器被替换）", async () => {
    const { copyWithTimeout } = useClipToast("密码已复制");
    await copyWithTimeout("first");
    const start = clipSeconds()!;
    await vi.advanceTimersByTimeAsync(1000);
    expect(clipSeconds()).toBe(start - 1);

    await copyWithTimeout("second"); // 重新起步
    expect(clipSeconds()).toBe(start);
    await vi.advanceTimersByTimeAsync(1000);
    expect(clipSeconds()).toBe(start - 1); // 仅一次递减：旧计时器已替换
  });
});