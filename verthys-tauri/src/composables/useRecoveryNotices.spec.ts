// @vitest-environment happy-dom
/*
 * useRecoveryNotices.spec.ts — 恢复会话常驻入口契约
 *
 * 覆盖：
 *   1. 非恢复会话 / 未就绪会话不产生告知
 *   2. 重绑前后告知条目收敛（重绑完成只保留轮换入口）
 *   3. 重绑动作：keyfile 关闭直接提交、启用时选择文件、取消不提交
 *   4. 重绑失败保持未完成并报错
 *   5. 轮换入口开合、提交收敛与模块状态刷新
 *   6. 恢复标记清零时自动收起轮换弹窗
 *   7. 锁库重置恢复会话状态（入口随会话销毁消失）
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { effectScope, nextTick, type EffectScope } from "vue";
import { keyState, resetAllState } from "../state/key_state";

const mocks = vi.hoisted(() => ({
  open: vi.fn(),
  verthysKeyfileStatus: vi.fn(),
  verthysResealDevice: vi.fn(),
  loadModuleKeyStatus: vi.fn(),
  showStatus: vi.fn(),
  showError: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: mocks.open }));
vi.mock("../lib/verthys", () => ({
  verthysKeyfileStatus: mocks.verthysKeyfileStatus,
  verthysResealDevice: mocks.verthysResealDevice,
}));
vi.mock("../key/module-auth", () => ({
  loadModuleKeyStatus: mocks.loadModuleKeyStatus,
}));
vi.mock("./useToastCenter", () => ({
  useToastCenter: () => ({
    showStatus: mocks.showStatus,
    showError: mocks.showError,
  }),
}));

import { useRecoveryNotices } from "./useRecoveryNotices";

let scope: EffectScope;

beforeEach(() => {
  vi.clearAllMocks();
  resetAllState();
  keyState.verthysReady.value = true;
  keyState.globalKeyReady.value = true;
  keyState.recoveryMode.value = true;
  keyState.recoveryResealDone.value = false;
  mocks.verthysKeyfileStatus.mockResolvedValue({ ok: true, keyfile_enabled: false });
  mocks.verthysResealDevice.mockResolvedValue({ ok: true });
  mocks.loadModuleKeyStatus.mockResolvedValue(undefined);
  scope = effectScope();
});

afterEach(() => {
  scope.stop();
});

function setup() {
  return scope.run(() => useRecoveryNotices())!;
}

describe("恢复会话常驻入口", () => {
  it("非恢复会话或会话未就绪时不产生告知", () => {
    const api = setup();

    keyState.recoveryMode.value = false;
    expect(api.notices.value).toEqual([]);

    keyState.recoveryMode.value = true;
    keyState.globalKeyReady.value = false;
    expect(api.notices.value).toEqual([]);
  });

  it("重绑前给出两条告知，重绑完成后只保留轮换入口", () => {
    const api = setup();

    expect(api.notices.value.map((notice) => notice.key)).toEqual(["reseal", "rotate"]);
    expect(api.notices.value[0]?.tone).toBe("warning");
    expect(api.notices.value[0]?.actionLabel).toBe("重绑本机设备");

    keyState.recoveryResealDone.value = true;
    expect(api.notices.value.map((notice) => notice.key)).toEqual(["rotate"]);
  });

  it("keyfile 未启用时直接提交重绑并标记完成", async () => {
    const api = setup();

    api.onNoticeAction("reseal");

    await vi.waitFor(() => {
      expect(mocks.verthysResealDevice).toHaveBeenCalledTimes(1);
    });
    expect(mocks.verthysResealDevice).toHaveBeenCalledWith(undefined);
    expect(keyState.recoveryResealDone.value).toBe(true);
    expect(mocks.showStatus).toHaveBeenCalledWith("本机普通解锁已恢复");
    expect(mocks.open).not.toHaveBeenCalled();
  });

  it("keyfile 启用时提交所选路径", async () => {
    const api = setup();
    mocks.verthysKeyfileStatus.mockResolvedValueOnce({ ok: true, keyfile_enabled: true });
    mocks.open.mockResolvedValueOnce("C:\\keys\\current.vkf");

    api.onNoticeAction("reseal");

    await vi.waitFor(() => {
      expect(mocks.verthysResealDevice).toHaveBeenCalledWith("C:\\keys\\current.vkf");
    });
    expect(keyState.recoveryResealDone.value).toBe(true);
  });

  it("keyfile 选择被取消时不提交重绑", async () => {
    const api = setup();
    mocks.verthysKeyfileStatus.mockResolvedValueOnce({ ok: true, keyfile_enabled: true });
    mocks.open.mockResolvedValueOnce(null);

    api.onNoticeAction("reseal");
    await Promise.resolve();
    await Promise.resolve();

    expect(mocks.verthysResealDevice).not.toHaveBeenCalled();
    expect(keyState.recoveryResealDone.value).toBe(false);
  });

  it("重绑失败保持未完成并报错", async () => {
    const api = setup();
    mocks.verthysResealDevice.mockResolvedValueOnce({ ok: false });

    api.onNoticeAction("reseal");

    await vi.waitFor(() => {
      expect(mocks.showError).toHaveBeenCalledTimes(1);
    });
    expect(keyState.recoveryResealDone.value).toBe(false);
    expect(mocks.showStatus).not.toHaveBeenCalled();
  });

  it("重绑 IPC 异常按失败提示且不标记完成", async () => {
    const api = setup();
    mocks.verthysResealDevice.mockRejectedValueOnce(new Error("ipc failed"));

    api.onNoticeAction("reseal");

    await vi.waitFor(() => {
      expect(mocks.showError).toHaveBeenCalledTimes(1);
    });
    expect(keyState.recoveryResealDone.value).toBe(false);
  });

  it("轮换入口打开弹窗，提交后收敛恢复态并刷新模块状态", async () => {
    const api = setup();
    const versionBefore = keyState.verthysStateVersion.value;
    keyState.recoveryResealDone.value = true;

    expect(api.rotateDialogMounted.value).toBe(false);
    api.onNoticeAction("rotate");
    await nextTick();
    expect(api.rotateDialogOpen.value).toBe(true);
    expect(api.rotateDialogMounted.value).toBe(true);

    api.onRotateCommitted();
    await nextTick();

    expect(api.rotateDialogOpen.value).toBe(false);
    expect(keyState.recoveryMode.value).toBe(false);
    expect(keyState.recoveryResealDone.value).toBe(false);
    expect(keyState.verthysStateVersion.value).toBe(versionBefore + 1);
    expect(mocks.loadModuleKeyStatus).toHaveBeenCalledTimes(1);
  });

  it("恢复标记清零时自动收起轮换弹窗", async () => {
    const api = setup();
    api.onNoticeAction("rotate");
    expect(api.rotateDialogOpen.value).toBe(true);

    keyState.recoveryMode.value = false;
    await nextTick();

    expect(api.rotateDialogOpen.value).toBe(false);
  });

  it("锁库重置恢复会话状态", () => {
    keyState.recoveryMode.value = true;
    keyState.recoveryResealDone.value = true;

    resetAllState();

    expect(keyState.recoveryMode.value).toBe(false);
    expect(keyState.recoveryResealDone.value).toBe(false);
  });
});
