/*
 * useUnlockFlow.spec.ts — 解锁流程的介质绑定确认回归
 *
 * 覆盖：
 *   1. 克隆嫌疑错误码不直接报错，而是升起"介质标识变化"确认态
 *   2. 用户确认后带确认参数重试解锁（重绑定以凭据验证通过为前提）
 *   3. 用户取消后关闭确认态并给出可见提示（不静默）
 *   4. 其他错误码维持既有报错路径（无回归）
 *
 * 依赖隔离：keyManager（initUnlock/initCreate/hasGlobalKeyRecordRef）与
 * lib/verthys（预热/预检/预启动）、对话框插件全部 mock；
 * verthys_error 的实际错误码枚举与文案翻译使用真实实现。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ref } from "vue";
import { VerthysErrorCode } from "../../lib/verthys_error";

const mocks = vi.hoisted(() => ({
  initUnlock: vi.fn(),
  initCreate: vi.fn(),
  verthysPreheat: vi.fn(),
  verthysPreflight: vi.fn(),
  preloadWorker: vi.fn(),
}));

vi.mock("../../lib/keyManager", async () => {
  const { ref } = await import("vue");
  const actual = await vi.importActual<typeof import("../../lib/verthys_error")>(
    "../../lib/verthys_error",
  );
  return {
    // 真实错误码与文案翻译：确认流程依赖错误码判别
    VerthysErrorCode: actual.VerthysErrorCode,
    translateVerthysError: actual.translateVerthysError,
    hasGlobalKeyRecordRef: ref(false),
    initUnlock: mocks.initUnlock,
    initCreate: mocks.initCreate,
  };
});

vi.mock("../../lib/verthys", () => ({
  verthysPreheat: mocks.verthysPreheat,
  verthysPreflight: mocks.verthysPreflight,
  preloadWorker: mocks.preloadWorker,
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
  save: vi.fn(),
}));

import { useUnlockFlow } from "./useUnlockFlow";

/** 依赖注入桩 */
function stubOptions() {
  return {
    isTauri: true,
    showError: vi.fn(),
    showToast: vi.fn(),
    checkDevice: vi.fn(async () => {}),
  };
}

/** 成功结果（与 VerthysResult<void> 契约一致） */
function okResult() {
  return { ok: true as const, value: undefined };
}

/** 克隆嫌疑失败结果 */
function cloneResult() {
  return {
    ok: false as const,
    code: VerthysErrorCode.E_USB_CLONE_SUSPECTED,
    message: "介质标识与登记记录不一致，已阻止解锁",
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("useUnlockFlow 介质绑定确认", () => {
  it("克隆嫌疑：升起确认态且不直接弹错误", async () => {
    mocks.initUnlock.mockResolvedValueOnce(cloneResult());
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/vault.verthys", false);

    expect(api.usbRebindPrompt.value).toEqual({
      path: "/tmp/vault.verthys",
      isCreate: false,
    });
    expect(options.showError).not.toHaveBeenCalled();
    // 首次调用未携带确认参数
    expect(mocks.initUnlock.mock.calls[0][3]).toBe(false);
  });

  it("用户确认：带确认参数重试并在成功后清除确认态", async () => {
    mocks.initUnlock
      .mockResolvedValueOnce(cloneResult())
      .mockResolvedValueOnce(okResult());
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/vault.verthys", false);
    expect(api.usbRebindPrompt.value).not.toBeNull();

    await api.confirmUsbRebind();

    expect(mocks.initUnlock).toHaveBeenCalledTimes(2);
    // 第二次调用必须携带确认参数（后端据此放行阻断并在验证通过后重绑定）
    expect(mocks.initUnlock.mock.calls[1][3]).toBe(true);
    expect(api.usbRebindPrompt.value).toBeNull();
    expect(options.showToast).toHaveBeenCalled();
    expect(options.showError).not.toHaveBeenCalled();
  });

  it("用户取消：关闭确认态并给出可见提示", async () => {
    mocks.initUnlock.mockResolvedValueOnce(cloneResult());
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/vault.verthys", false);
    api.cancelUsbRebind();

    expect(api.usbRebindPrompt.value).toBeNull();
    expect(options.showError).toHaveBeenCalledWith(
      "已取消介质更换确认，解锁保持阻止状态",
    );
  });

  it("其他错误码：维持既有报错路径（不升起确认态）", async () => {
    mocks.initUnlock.mockResolvedValueOnce({
      ok: false as const,
      code: VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED,
      message: "打开加密库失败",
    });
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/vault.verthys", false);

    expect(api.usbRebindPrompt.value).toBeNull();
    expect(options.showError).toHaveBeenCalled();
  });
});