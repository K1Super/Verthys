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
import type { VerifyRhythm } from "./useVerifyRhythm";

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

/** 进度感知层桩：记录业务层推送与收束/冻结指令 */
function stubRhythm() {
  return {
    visualValue: ref(0),
    visualPercent: ref(0),
    dimmed: ref(false),
    phase: ref<'IDLE'>('IDLE'),
    start: vi.fn(),
    pushRealProgress: vi.fn(),
    seal: vi.fn(),
    halt: vi.fn(),
    waitForComplete: vi.fn(async () => {}),
    waitForHaltMin: vi.fn(async () => {}),
    dispose: vi.fn(),
  } as unknown as VerifyRhythm & {
    start: ReturnType<typeof vi.fn>;
    pushRealProgress: ReturnType<typeof vi.fn>;
    seal: ReturnType<typeof vi.fn>;
    halt: ReturnType<typeof vi.fn>;
    waitForComplete: ReturnType<typeof vi.fn>;
  };
}

/** 依赖注入桩 */
function stubOptions() {
  return {
    isTauri: true,
    showError: vi.fn(),
    showToast: vi.fn(),
    checkDevice: vi.fn(async () => {}),
    rhythm: stubRhythm(),
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

describe("useUnlockFlow keyfile 因子（D3）", () => {
  /** 动态取到被 mock 的 open，避免顶部静态 import 与 hoist 冲突 */
  async function openMock() {
    const mod = await import("@tauri-apps/plugin-dialog");
    return mod.open as unknown as ReturnType<typeof vi.fn>;
  }

  it("缺 keyfile：弹出选择并把路径作为第六参数重试一次", async () => {
    mocks.initUnlock
      .mockResolvedValueOnce({
        ok: false as const,
        code: VerthysErrorCode.E_KEYFILE_REQUIRED,
        message: "该加密库已启用 keyfile",
      })
      .mockResolvedValueOnce(okResult());
    const open = await openMock();
    open.mockResolvedValueOnce("C:\\keys\\vault.vkf");
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/kf.verthys", false);

    expect(mocks.initUnlock).toHaveBeenCalledTimes(2);
    expect(mocks.initUnlock.mock.calls[1][5]).toBe("C:\\keys\\vault.vkf");
    expect(api.keyfilePath.value).toBe("C:\\keys\\vault.vkf");
    expect(options.showError).not.toHaveBeenCalled();
  });

  it("缺 keyfile 但用户取消选择：只调用一次并明确报错", async () => {
    mocks.initUnlock.mockResolvedValueOnce({
      ok: false as const,
      code: VerthysErrorCode.E_KEYFILE_REQUIRED,
      message: "该加密库已启用 keyfile",
    });
    const open = await openMock();
    open.mockResolvedValueOnce(null);
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/kf.verthys", false);

    expect(mocks.initUnlock).toHaveBeenCalledTimes(1);
    expect(options.showError).toHaveBeenCalled();
  });

});

describe("useUnlockFlow 进度感知层集成", () => {
  it("阶段进度推送感知层，100 仅作完成提示，成功后收束补满", async () => {
    type Progress = {
      stage: number;
      percent: number;
      elapsed_ms: number;
      message: string;
    };
    mocks.initUnlock.mockImplementationOnce(
      async (
        _path: string,
        _pre: unknown,
        onProgress?: (p: Progress) => void,
      ) => {
        onProgress?.({ stage: 1, percent: 8, elapsed_ms: 5, message: "解锁加密库" });
        onProgress?.({ stage: 2, percent: 88, elapsed_ms: 20, message: "建立索引与同步状态" });
        onProgress?.({ stage: 4, percent: 100, elapsed_ms: 30, message: "解锁完成" });
        return okResult();
      },
    );
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/v.verthys", false);

    expect(options.rhythm.start).toHaveBeenCalledTimes(1);
    // 终值 100 不推送：进度补满由收束事件负责
    expect(options.rhythm.pushRealProgress.mock.calls.map(([v]) => v)).toEqual([
      0.08,
      0.88,
    ]);
    expect(options.rhythm.seal).toHaveBeenCalledTimes(1);
    expect(options.rhythm.waitForComplete).toHaveBeenCalledTimes(1);
    expect(api.unlockProgressMsg.value).toBe("解锁完成");
  });

  it("失败路径冻结感知层，不伪装完成", async () => {
    mocks.initUnlock.mockResolvedValueOnce({
      ok: false as const,
      code: VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED,
      message: "打开加密库失败",
    });
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/v.verthys", false);

    expect(options.rhythm.halt).toHaveBeenCalled();
    expect(options.rhythm.seal).not.toHaveBeenCalled();
  });
});

describe("useUnlockFlow 恢复码链路", () => {
  it("新建成功：一次性恢复码进入待确认状态，清零后消失", async () => {
    mocks.initCreate.mockResolvedValueOnce({ ok: true, value: "AAAA-BBBB" });
    const options = stubOptions();
    const api = useUnlockFlow(options);

    await api.doUnlock("/tmp/new.verthys", true);
    expect(api.pendingRecoveryCode.value).toBe("AAAA-BBBB");
    expect(api.unlocking.value).toBe(false);

    api.clearRecoveryCode();
    expect(api.pendingRecoveryCode.value).toBeNull();
  });

  it("恢复解锁：恢复码作为第五参数传递且成功返回 true", async () => {
    mocks.initUnlock.mockResolvedValueOnce(okResult());
    const options = stubOptions();
    const api = useUnlockFlow(options);

    const ok = await api.doRecoveryUnlock("/tmp/v.verthys", "CODE-1234");
    expect(ok).toBe(true);
    expect(mocks.initUnlock.mock.calls[0][4]).toBe("CODE-1234");
  });

  it("恢复解锁失败：返回 false 且不显示成功提示", async () => {
    mocks.initUnlock.mockResolvedValueOnce({
      ok: false,
      code: VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED,
      message: "失败",
    });
    const options = stubOptions();
    const api = useUnlockFlow(options);

    const ok = await api.doRecoveryUnlock("/tmp/v.verthys", "CODE-1234");
    expect(ok).toBe(false);
    expect(options.showToast).not.toHaveBeenCalled();
    expect(api.unlocking.value).toBe(false);
  });
});