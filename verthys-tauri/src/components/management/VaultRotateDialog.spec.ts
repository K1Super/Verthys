// @vitest-environment happy-dom
/*
 * VaultRotateDialog.spec.ts — 全库 DEK 轮换向导契约
 *
 * 覆盖：恢复会话门禁、已启用模块口令门禁、Begin→UnlockModule→Run→Commit
 * 顺序、提交成功通知、Run 后中止路径。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";

const mocks = vi.hoisted(() => ({
  keyfileStatus: vi.fn(),
  pcrStatus: vi.fn(),
  moduleStatus: vi.fn(),
  begin: vi.fn(),
  attachKeyfile: vi.fn(),
  unlockModule: vi.fn(),
  run: vi.fn(),
  cancel: vi.fn(),
  commit: vi.fn(),
  abort: vi.fn(),
  save: vi.fn(),
  open: vi.fn(),
}));

vi.mock("../../lib/verthys", () => ({
  verthysKeyfileStatus: mocks.keyfileStatus,
  verthysPcrStatus: mocks.pcrStatus,
  verthysV4ModuleStatus: mocks.moduleStatus,
  verthysV4RotateBegin: mocks.begin,
  verthysV4RotateAttachKeyfile: mocks.attachKeyfile,
  verthysV4RotateUnlockModule: mocks.unlockModule,
  verthysV4RotateRun: mocks.run,
  verthysV4RotateCancel: mocks.cancel,
  verthysV4RotateCommit: mocks.commit,
  verthysV4RotateAbort: mocks.abort,
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({ save: mocks.save, open: mocks.open }));

const suppression = vi.hoisted(() => ({ setSessionLockSuppressed: vi.fn() }));
vi.mock("../../session/security-session", () => ({
  setSessionLockSuppressed: suppression.setSessionLockSuppressed,
}));

import VaultRotateDialog from "./VaultRotateDialog.vue";
import { setCurrentVerthysPath } from "../../state/key_state";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  vi.clearAllMocks();
});

beforeEach(() => {
  setCurrentVerthysPath("C:/tmp/verthys.vty");
});

function mountDialog(onClose = vi.fn(), onCommitted = vi.fn()) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(VaultRotateDialog, {
        show: true,
        onClose,
        onCommitted,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  /* VerthysDialog 默认 teleport 到 body */
  return document.body;
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (b) => b.textContent?.trim() === text,
  );
}

async function settle() {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function setupRecoverySession(moduleEnabled: boolean, keyfileEnabled = false) {
  mocks.keyfileStatus.mockResolvedValue({
    ok: true,
    recovery_mode: true,
    keyfile_enabled: keyfileEnabled,
  });
  mocks.pcrStatus.mockResolvedValue({ ok: true, pcr_enabled: false });
  mocks.moduleStatus.mockImplementation(async (moduleId: number) => ({
    ok: true,
    enabled: moduleEnabled && moduleId === 0,
    deleted: false,
    has_recovery: true,
    unlocked: false,
  }));
  mocks.begin.mockResolvedValue({
    ok: true,
    rotate_stage: 1,
    rotate_modules_ready: 0,
    rotate_records: 0,
    rotate_files: 0,
    rotate_chunks: 0,
    rotate_bytes: 0,
  });
  mocks.attachKeyfile.mockResolvedValue({ ok: true });
  mocks.cancel.mockResolvedValue({ ok: true });
  mocks.unlockModule.mockResolvedValue({ ok: true });
  mocks.run.mockImplementation(async (onProgress?: (p: unknown) => void) => {
    onProgress?.({
      stage: 2,
      modules_ready: moduleEnabled ? 1 : 0,
      records: 2,
      files: 1,
      chunks: 3,
      bytes: 4096,
    });
    return { ok: true };
  });
  mocks.commit.mockResolvedValue({ ok: true });
  mocks.abort.mockResolvedValue({ ok: true });
}

describe("全库 DEK 轮换向导", () => {
  it("keepOld + PCR：提示旧备份只能用恢复码打开", async () => {
    setupRecoverySession(false);
    mocks.pcrStatus.mockResolvedValue({ ok: true, pcr_enabled: true });
    const body = mountDialog();
    await settle();

    const keepOldCheckbox = Array.from(
      body.querySelectorAll<HTMLInputElement>("input[type=checkbox]"),
    ).find((box) => box.parentElement?.textContent?.includes("保留旧库备份"))!;
    expect(body.textContent).not.toContain("旧备份只能用恢复码打开");

    keepOldCheckbox.checked = true;
    keepOldCheckbox.dispatchEvent(new Event("change"));
    await settle();
    expect(body.textContent).toContain("旧备份只能用恢复码打开");
  });

  it("非恢复会话直接阻断，开始按钮不可用", async () => {
    mocks.keyfileStatus.mockResolvedValue({
      ok: true,
      recovery_mode: false,
      keyfile_enabled: false,
    });
    const body = mountDialog();
    await settle();
    expect(body.textContent).toContain("仅恢复码会话可执行全库密钥轮换");
    expect(buttonByText(body, "开始轮换")?.disabled).toBe(true);
    expect(mocks.begin).not.toHaveBeenCalled();
  });

  it("已启用模块必须填写口令后才允许开始", async () => {
    setupRecoverySession(true);
    const body = mountDialog();
    await settle();
    expect(body.textContent).toContain("已启用模块需要提供模块口令");
    const start = buttonByText(body, "开始轮换")!;
    expect(start.disabled).toBe(true);

    const passwordInput = Array.from(
      body.querySelectorAll<HTMLInputElement>("input[type=password]"),
    )[0]!;
    passwordInput.value = "module-pw";
    passwordInput.dispatchEvent(new Event("input"));
    await settle();
    expect(buttonByText(body, "开始轮换")?.disabled).toBe(false);
  });

  it("按 Begin → UnlockModule → Run → Commit 顺序执行并通知提交成功", async () => {
    setupRecoverySession(true);
    const onCommitted = vi.fn();
    const body = mountDialog(vi.fn(), onCommitted);
    await settle();

    const passwordInput = Array.from(
      body.querySelectorAll<HTMLInputElement>("input[type=password]"),
    )[0]!;
    passwordInput.value = "module-pw";
    passwordInput.dispatchEvent(new Event("input"));
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();

    expect(mocks.begin).toHaveBeenCalledWith("C:/tmp/verthys.vty.rot.vty", 0);
    expect(mocks.unlockModule).toHaveBeenCalledWith(0, "module-pw");
    expect(mocks.run).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("复制与完整性复核已完成");
    expect(body.textContent).toContain("4.0 KiB");

    buttonByText(body, "提交并替换源库")!.click();
    await settle();
    expect(mocks.commit).toHaveBeenCalledWith(false);
    expect(onCommitted).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("轮换已提交");
  });

  it("Run 完成后可中止并丢弃临时库", async () => {
    setupRecoverySession(false);
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(mocks.begin).toHaveBeenCalledTimes(1);
    expect(mocks.unlockModule).not.toHaveBeenCalled();

    buttonByText(body, "中止并丢弃新库")!.click();
    await settle();
    expect(mocks.abort).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("轮换已中止");
  });

  it("启用 keyfile 时必须选择文件并先补录再 Begin", async () => {
    setupRecoverySession(false, true);
    mocks.open.mockResolvedValue("C:/tmp/current.vkf");
    const body = mountDialog();
    await settle();

    expect(body.textContent).toContain("轮换需要当前 keyfile");
    expect(buttonByText(body, "开始轮换")?.disabled).toBe(true);

    buttonByText(body, "选择 keyfile…")!.click();
    await settle();
    expect(buttonByText(body, "开始轮换")?.disabled).toBe(false);

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(mocks.attachKeyfile).toHaveBeenCalledWith("C:/tmp/current.vkf");
    expect(mocks.begin).toHaveBeenCalledTimes(1);
  });

  it("复制阶段可取消，Run 收敛后自动中止", async () => {
    setupRecoverySession(false);
    let resolveRun!: (value: unknown) => void;
    mocks.run.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRun = resolve;
        }),
    );
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(body.textContent).toContain("正在全量复制记录与文件…");

    buttonByText(body, "取消轮换")!.click();
    await settle();
    expect(mocks.cancel).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("正在取消…");

    resolveRun({ ok: false, error: "ERR_00000017" });
    await settle();
    expect(mocks.abort).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("轮换已中止");
  });

  it("空闲锁定抑制仅在命令在途：Run 完成进入 ready 后解除", async () => {
    setupRecoverySession(false);
    let resolveRun!: (value: unknown) => void;
    mocks.run.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRun = resolve;
        }),
    );
    const body = mountDialog();
    await settle();

    // 对话框挂载（命令未在途）不得抑制空闲锁定
    expect(suppression.setSessionLockSuppressed).toHaveBeenLastCalledWith(false);

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(suppression.setSessionLockSuppressed).toHaveBeenLastCalledWith(true);

    resolveRun({ ok: true });
    await settle();
    expect(body.textContent).toContain("复制与完整性复核已完成");
    // 作业处于 ready、worker 空闲：抑制必须解除，空闲锁定照常生效
    expect(suppression.setSessionLockSuppressed).toHaveBeenLastCalledWith(false);
  });

  it("解锁阶段取消：Run 收敛后仍按取消中止", async () => {
    setupRecoverySession(true);
    let resolveUnlock!: (value: unknown) => void;
    let resolveRun!: (value: unknown) => void;
    mocks.unlockModule.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveUnlock = resolve;
        }),
    );
    mocks.run.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRun = resolve;
        }),
    );
    const body = mountDialog();
    await settle();

    const passwordInput = Array.from(
      body.querySelectorAll<HTMLInputElement>("input[type=password]"),
    )[0]!;
    passwordInput.value = "module-pw";
    passwordInput.dispatchEvent(new Event("input"));
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(body.textContent).toContain("正在登记模块口令");

    buttonByText(body, "取消轮换")!.click();
    await settle();
    expect(mocks.cancel).toHaveBeenCalledTimes(1);

    resolveUnlock({ ok: true });
    await settle();
    expect(mocks.run).toHaveBeenCalledTimes(1);

    resolveRun({ ok: false, error: "ERR_00000017" });
    await settle();
    expect(mocks.abort).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("轮换已中止");
  });

  it("Run 成功但已取消：强制中止，不进入提交态", async () => {
    setupRecoverySession(false);
    let resolveRun!: (value: unknown) => void;
    mocks.run.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRun = resolve;
        }),
    );
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    buttonByText(body, "取消轮换")!.click();
    await settle();
    expect(mocks.cancel).toHaveBeenCalledTimes(1);

    resolveRun({ ok: true });
    await settle();
    expect(mocks.abort).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("轮换已中止");
    expect(body.textContent).not.toContain("提交并替换源库");
  });

  it("Run 真实失败且中止删除失败：作业释放并保留失败与残留提示", async () => {
    setupRecoverySession(false);
    mocks.run.mockResolvedValue({ ok: false, error: "ERR_00000008" });
    mocks.abort.mockResolvedValue({ ok: false, error: "ERR_00000008" });
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(mocks.abort).toHaveBeenCalledTimes(1);
    expect(body.textContent).toContain("复制阶段失败");
    expect(body.textContent).toContain("临时库删除失败");
    expect(buttonByText(body, "中止作业")).toBeUndefined();
  });

  it("keyfile 补录失败：阻断 Begin 并给出原因", async () => {
    setupRecoverySession(false, true);
    mocks.open.mockResolvedValue("C:/tmp/current.vkf");
    mocks.attachKeyfile.mockResolvedValue({ ok: false, error: "ERR_0000001B" });
    const body = mountDialog();
    await settle();

    buttonByText(body, "选择 keyfile…")!.click();
    await settle();
    buttonByText(body, "开始轮换")!.click();
    await settle();

    expect(mocks.attachKeyfile).toHaveBeenCalledTimes(1);
    expect(mocks.begin).not.toHaveBeenCalled();
    expect(body.textContent).toContain("keyfile 补录失败");
  });

  it("Begin 失败：不产生作业，也不调用 Abort", async () => {
    setupRecoverySession(false);
    mocks.begin.mockResolvedValue({ ok: false, error: "ERR_00000004" });
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(mocks.abort).not.toHaveBeenCalled();
    expect(body.textContent).toContain("新库位置已存在");
  });

  it("口令失败退避期间 Begin 返回 RATE 时给出可读提示", async () => {
    setupRecoverySession(false);
    mocks.begin.mockResolvedValue({ ok: false, error: "ERR_0000000A" });
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(mocks.abort).not.toHaveBeenCalled();
    expect(body.textContent).toContain("尝试过于频繁");
  });

  it("提交失败：保留活动作业并提示，不自动中止", async () => {
    setupRecoverySession(false);
    mocks.commit.mockResolvedValue({ ok: false, error: "ERR_00000008" });
    const body = mountDialog();
    await settle();

    buttonByText(body, "开始轮换")!.click();
    await settle();
    expect(body.textContent).toContain("复制与完整性复核已完成");
    buttonByText(body, "提交并替换源库")!.click();
    await settle();

    expect(mocks.commit).toHaveBeenCalledTimes(1);
    expect(mocks.abort).not.toHaveBeenCalled();
    expect(body.textContent).toContain("提交失败");
    expect(buttonByText(body, "中止作业")).toBeDefined();
  });
});
