/*
 * useGlobalKey.spec.ts — 改钥交互的前置校验与错误映射
 *
 * 覆盖：
 *   - 新钥 < 8 字节：前端拦截，不调用后端
 *   - 密钥文件未加载：显式提示，不静默返回
 *   - 成功 / cleanup_pending 两种成功提示
 *   - 旧钥错误 / 落盘失败 / 结果未确认 / 限流（含秒数）的提示映射
 *
 * 依赖隔离：keyManager（GMK 命令面）、lib/verthys（文件读取）、
 * useUnlockFlow（超时包裹）、plugin-dialog 全部 vi.mock。
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ref } from "vue";

vi.mock("../../lib/keyManager", async () => {
  const { ref: vueRef } = await import("vue");
  const actual = await vi.importActual<typeof import("../../lib/verthys_error")>(
    "../../lib/verthys_error",
  );
  return {
    initGlobalKey: vi.fn(),
    verifyGlobalKey: vi.fn(),
    changeGlobalKey: vi.fn(),
    bindDevice: vi.fn(),
    translateVerthysError: vi.fn((r: { message?: string }) => r.message ?? "翻译错误"),
    globalKeyReadyRef: vueRef(false),
    hasGlobalKeyRecordRef: vueRef(false),
    globalKeyRecordIdRef: vueRef(0),
    VerthysErrorCode: actual.VerthysErrorCode,
  };
});

vi.mock("../../lib/verthys", () => ({
  readUserFile: vi.fn(),
  writeUserFile: vi.fn(),
}));

vi.mock("./useUnlockFlow", () => ({
  withFrontendTimeout: <T>(promise: Promise<T>) => promise,
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
  save: vi.fn(),
}));

import { open } from "@tauri-apps/plugin-dialog";
import * as keyManager from "../../lib/keyManager";
import * as verthysLib from "../../lib/verthys";
import { VerthysErrorCode, ok, err } from "../../lib/verthys_error";
import { useGlobalKey } from "./useGlobalKey";
import type { VerifyRhythm } from "./useVerifyRhythm";

function makeRhythm(): VerifyRhythm {
  return {
    start: vi.fn(),
    seal: vi.fn(),
    halt: vi.fn(),
    reset: vi.fn(),
    waitForComplete: vi.fn().mockResolvedValue(undefined),
    waitForHaltMin: vi.fn().mockResolvedValue(undefined),
    pushRealProgress: vi.fn(),
    visualPercent: ref(0),
    dimmed: ref(false),
  } as unknown as VerifyRhythm;
}

function setup() {
  const showError = vi.fn();
  const showToast = vi.fn();
  const api = useGlobalKey({
    isTauri: true,
    showError,
    showToast,
    postVerifyAnim: ref(false),
    postInitAnim: ref(false),
    verifyRhythm: makeRhythm(),
    unlockProgressMsg: ref(""),
    unlockProgressPercent: ref(0),
    unlockProgressElapsed: ref(0),
  });
  return { ...api, showError, showToast };
}

async function chooseBins(api: ReturnType<typeof setup>): Promise<void> {
  vi.mocked(open).mockResolvedValueOnce("C:\\keys\\old.bin");
  vi.mocked(open).mockResolvedValueOnce("C:\\keys\\new.bin");
  vi.mocked(verthysLib.readUserFile).mockResolvedValue(new Uint8Array([1, 2, 3]));
  await api.browseOldBin();
  await api.browseNewBin();
  api.oldPassword.value = "old-p@ss-9";
  api.oldBinPassword.value = "old-bin-pass";
  api.newPassword.value = "new-p@ss-9";
  api.newBinPassword.value = "new-bin-pass";
  api.showChangeKeyDialog.value = true;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(verthysLib.readUserFile).mockResolvedValue(new Uint8Array([1, 2, 3]));
});

describe("useGlobalKey.onConfirmChangeKey — 前置校验", () => {
  it("新钥不足 8 字节：前端拦截，不调用后端", async () => {
    const api = setup();
    await chooseBins(api);
    api.newPassword.value = "short";

    await api.onConfirmChangeKey();

    expect(api.showError).toHaveBeenCalledWith("访问密钥至少 8 位");
    expect(keyManager.changeGlobalKey).not.toHaveBeenCalled();
    expect(api.changeKeyProcessing.value).toBe(false);
  });

  it("密钥文件未加载：显式提示，不静默返回", async () => {
    const api = setup();
    api.oldPassword.value = "old-p@ss-9";
    api.oldBinPassword.value = "old-bin-pass";
    api.newPassword.value = "new-p@ss-9";
    api.newBinPassword.value = "new-bin-pass";
    api.showChangeKeyDialog.value = true;

    await api.onConfirmChangeKey();

    expect(api.showError).toHaveBeenCalledWith("密钥文件未加载，请重新选择");
    expect(keyManager.changeGlobalKey).not.toHaveBeenCalled();
  });
});

describe("useGlobalKey.onConfirmChangeKey — 结果映射", () => {
  it("成功：提示成功、关闭弹窗并清空字段", async () => {
    const api = setup();
    await chooseBins(api);
    vi.mocked(keyManager.changeGlobalKey).mockResolvedValue(
      ok({ cleanupPending: false }),
    );

    await api.onConfirmChangeKey();

    expect(keyManager.changeGlobalKey).toHaveBeenCalledWith(
      "old-p@ss-9", expect.any(Uint8Array), "old-bin-pass",
      "new-p@ss-9", expect.any(Uint8Array), "new-bin-pass",
    );
    // 成功后敏感字节被 zeroBytes 清零：只断言长度，不断言内容
    const call = vi.mocked(keyManager.changeGlobalKey).mock.calls[0];
    expect((call[1] as Uint8Array).byteLength).toBe(3);
    expect((call[4] as Uint8Array).byteLength).toBe(3);
    expect(api.showToast).toHaveBeenCalledWith("全局密钥修改成功");
    expect(api.showChangeKeyDialog.value).toBe(false);
    expect(api.oldPassword.value).toBe("");
    expect(api.newPassword.value).toBe("");
  });

  it("cleanup_pending：成功提示携带清理说明", async () => {
    const api = setup();
    await chooseBins(api);
    vi.mocked(keyManager.changeGlobalKey).mockResolvedValue(
      ok({ cleanupPending: true }),
    );

    await api.onConfirmChangeKey();

    expect(api.showToast).toHaveBeenCalledWith(
      "全局密钥已修改；旧记录将在下次解锁自动清理",
    );
    expect(api.showChangeKeyDialog.value).toBe(false);
  });

  it("旧钥错误 → 提示旧密钥验证失败", async () => {
    const api = setup();
    await chooseBins(api);
    vi.mocked(keyManager.changeGlobalKey).mockResolvedValue(
      err(VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED, "旧密钥验证失败"),
    );

    await api.onConfirmChangeKey();

    expect(api.showError).toHaveBeenCalledWith("旧密钥验证失败，请检查");
    expect(api.showChangeKeyDialog.value).toBe(true);
  });

  it("落盘失败 → 明确旧钥仍有效", async () => {
    const api = setup();
    await chooseBins(api);
    vi.mocked(keyManager.changeGlobalKey).mockResolvedValue(
      err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "落盘失败"),
    );

    await api.onConfirmChangeKey();

    expect(api.showError).toHaveBeenCalledWith("新密钥写入失败，旧密钥仍有效");
  });

  it("结果未确认 → 引导重启后以新密钥验证", async () => {
    const api = setup();
    await chooseBins(api);
    vi.mocked(keyManager.changeGlobalKey).mockResolvedValue(
      err(VerthysErrorCode.E_GLOBAL_KEY_CHANGE_UNCONFIRMED, "超时"),
    );

    await api.onConfirmChangeKey();

    expect(api.showError).toHaveBeenCalledWith(
      "修改结果未确认：请重启应用后以新密钥验证",
    );
  });

  it("限流 → 携带建议等待秒数", async () => {
    const api = setup();
    await chooseBins(api);
    vi.mocked(keyManager.changeGlobalKey).mockResolvedValue(
      err(VerthysErrorCode.E_RATE_LIMITED, "锁定", undefined, 7),
    );

    await api.onConfirmChangeKey();

    expect(api.showError).toHaveBeenCalledWith("尝试次数过多，请 7 秒后再试");
  });
});
