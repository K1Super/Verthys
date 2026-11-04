/*
 * key/module-auth.spec.ts — v4 模块 M1 前端投影契约
 *
 * 覆盖：
 *   1. loadModuleKeyStatus 以 C 层状态为权威（enabled/unlocked/deleted）
 *   2. 查询失败 fail-closed（不降级为"保护关闭"）
 *   3. setModuleKey：未启用 → enable；已启用 → 必须带原口令 rotate
 *   4. verifyModuleKey：口令认证失败不登记 ready
 *   5. disableModuleProtection：成功后清除 enabled/ready
 *   6. logoutModule：锁定 C 层模块会话
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const v4Status = vi.fn();
const v4Enable = vi.fn();
const v4Rotate = vi.fn();
const v4Disable = vi.fn();
const v4Bind = vi.fn();
const v4Reseal = vi.fn();
const keyUnlock = vi.fn();
const keyLock = vi.fn();

/* 部分 mock：保留 lib/verthys 的其余导出（缓存域初始化会引用扫描 API），
 * 只替换模块 M1 相关命令。 */
vi.mock("../lib/verthys", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/verthys")>();
  return {
    ...actual,
    verthysV4ModuleStatus: (...args: unknown[]) => v4Status(...args),
    verthysV4ModuleEnable: (...args: unknown[]) => v4Enable(...args),
    verthysV4ModuleRotatePassword: (...args: unknown[]) => v4Rotate(...args),
    verthysV4ModuleDisable: (...args: unknown[]) => v4Disable(...args),
    verthysV4ModuleBindRecovery: (...args: unknown[]) => v4Bind(...args),
    verthysV4ModuleResealDevice: (...args: unknown[]) => v4Reseal(...args),
    verthysModuleKeyUnlock: (...args: unknown[]) => keyUnlock(...args),
    verthysModuleKeyLock: (...args: unknown[]) => keyLock(...args),
  };
});

import {
  addFullRecord,
  getModuleCache,
  hasFullRecord,
  initVerthysCache,
  setModuleCache,
} from "../cache/composition/verthys-cache";
import { keyState } from "../state/key_state";
import {
  bindModuleRecovery,
  disableModuleProtection,
  hasModuleKey,
  isModuleReady,
  loadModuleKeyStatus,
  logoutModule,
  resealModuleDevice,
  setModuleKey,
  verifyModuleKey,
} from "./module-auth";

const okResp = (fields: Record<string, unknown>) => ({ ok: true, op: "test", ...fields });
const errResp = (code: string) => ({ ok: false, op: "test", error: code });

function resetModuleState(): void {
  keyState.verthysReady.value = true;
  keyState.hasModuleKeyRecord.value = { photo: false, accounts: false, fileverthys: false };
  keyState.moduleKeyEnabled.value = { photo: false, accounts: false, fileverthys: false };
  keyState.moduleKeyReady.value = { photo: false, accounts: false, fileverthys: false };
  keyState.moduleHasRecovery.value = { photo: false, accounts: false, fileverthys: false };
  keyState.moduleKeyStatusLoaded.value = false;
  keyState.moduleKeyStatusLoading.value = false;
  keyState.moduleKeyStatusFailed.value = false;
}

describe("module-auth（v4 模块 M1）", () => {
  beforeAll(() => {
    // markModuleReady / removeModuleKey 依赖缓存域单例；测试只验证状态投影
    initVerthysCache();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    keyLock.mockResolvedValue(okResp({}));
    resetModuleState();
  });

  it("loadModuleKeyStatus 以 C 层状态为权威并忽略已删除模块", async () => {
    v4Status.mockImplementation(async (index: number) => {
      if (index === 0) {
        return okResp({ enabled: true, unlocked: true, deleted: false, has_recovery: true });
      }
      if (index === 1) {
        return okResp({ enabled: true, unlocked: false, deleted: false, has_recovery: false });
      }
      return okResp({ enabled: false, unlocked: false, deleted: true, has_recovery: false });
    });

    const result = await loadModuleKeyStatus();

    expect(result.ok).toBe(true);
    expect(keyState.moduleKeyEnabled.value).toEqual({ photo: true, accounts: true, fileverthys: false });
    expect(keyState.moduleKeyReady.value).toEqual({ photo: true, accounts: false, fileverthys: false });
    expect(keyState.hasModuleKeyRecord.value).toEqual({ photo: true, accounts: true, fileverthys: false });
    expect(keyState.moduleHasRecovery.value).toEqual({ photo: true, accounts: false, fileverthys: false });
    expect(keyState.moduleKeyStatusLoaded.value).toBe(true);
    expect(keyState.moduleKeyStatusFailed.value).toBe(false);
  });

  it("loadModuleKeyStatus 任一模块查询失败即 fail-closed", async () => {
    v4Status.mockResolvedValue(errResp("ERR_00000007"));

    const result = await loadModuleKeyStatus();

    expect(result.ok).toBe(false);
    expect(keyState.moduleKeyStatusLoaded.value).toBe(false);
    expect(keyState.moduleKeyStatusFailed.value).toBe(true);
    // 失败不得把任何模块降级为"保护关闭"的已加载状态
    expect(keyState.moduleKeyEnabled.value).toEqual({ photo: false, accounts: false, fileverthys: false });
  });

  it("setModuleKey：未启用调用 enable；已启用必须带原口令调用 rotate", async () => {
    v4Enable.mockResolvedValue(okResp({ enabled: true, unlocked: true }));
    const first = await setModuleKey("photo", "first-pass");
    expect(first.ok).toBe(true);
    expect(v4Enable).toHaveBeenCalledWith(0, "first-pass");
    expect(hasModuleKey("photo")).toBe(true);
    expect(isModuleReady("photo")).toBe(true);

    // 已启用：缺少原口令 → 直接拒绝，不触达后端
    const missingOld = await setModuleKey("photo", "next-pass");
    expect(missingOld.ok).toBe(false);
    expect(v4Rotate).not.toHaveBeenCalled();

    v4Rotate.mockResolvedValue(okResp({ enabled: true, unlocked: true }));
    const rotated = await setModuleKey("photo", "next-pass", "first-pass");
    expect(rotated.ok).toBe(true);
    expect(v4Rotate).toHaveBeenCalledWith(0, "first-pass", "next-pass");
  });

  it("setModuleKey 首次启用可携带恢复码绑定模块恢复槽", async () => {
    v4Enable.mockResolvedValue(okResp({ enabled: true, unlocked: true, has_recovery: true }));
    const bound = await setModuleKey("accounts", "module-pass", undefined, "RECOVERY-CODE");
    expect(bound.ok).toBe(true);
    expect(v4Enable).toHaveBeenCalledWith(1, "module-pass", "RECOVERY-CODE");
    expect(keyState.moduleHasRecovery.value.accounts).toBe(true);
  });

  it("verifyModuleKey 认证失败不登记 ready；成功才登记", async () => {
    keyState.moduleKeyEnabled.value = { photo: true, accounts: false, fileverthys: false };

    keyUnlock.mockResolvedValueOnce(errResp("ERR_00000002"));
    const denied = await verifyModuleKey("photo", "wrong-pass");
    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.code).toBe("E_MODULE_VERIFY_FAILED");
    expect(isModuleReady("photo")).toBe(false);

    keyUnlock.mockResolvedValueOnce(okResp({ enabled: true, unlocked: true }));
    const granted = await verifyModuleKey("photo", "right-pass");
    expect(granted.ok).toBe(true);
    expect(isModuleReady("photo")).toBe(true);
  });

  it("disableModuleProtection 成功后才清除保护状态与登录状态", async () => {
    keyState.moduleKeyEnabled.value = { photo: true, accounts: false, fileverthys: false };
    keyState.hasModuleKeyRecord.value = { photo: true, accounts: false, fileverthys: false };
    keyState.moduleKeyReady.value = { photo: true, accounts: false, fileverthys: false };

    v4Disable.mockResolvedValueOnce(errResp("ERR_00000002"));
    const denied = await disableModuleProtection("photo", "wrong-pass");
    expect(denied.ok).toBe(false);
    expect(keyState.moduleKeyEnabled.value.photo).toBe(true);
    expect(isModuleReady("photo")).toBe(true);

    v4Disable.mockResolvedValueOnce(okResp({ enabled: false }));
    const done = await disableModuleProtection("photo", "right-pass");
    expect(done.ok).toBe(true);
    expect(keyState.moduleKeyEnabled.value.photo).toBe(false);
    expect(hasModuleKey("photo")).toBe(false);
    /* 关闭保护后 MDEK 回 Keyring：内容路径无需口令，ready 立即恢复可用 */
    expect(isModuleReady("photo")).toBe(true);
    expect(v4Disable).toHaveBeenLastCalledWith(0, "right-pass");
  });

  it("logoutModule 清除登录状态并锁定对应 C 层模块", () => {
    keyState.moduleKeyReady.value = { photo: true, accounts: true, fileverthys: false };

    logoutModule("accounts");

    expect(isModuleReady("accounts")).toBe(false);
    expect(keyLock).toHaveBeenCalledWith("accounts");
  });

  it("logoutModule 同时清空该模块列表缓存与明文记录缓存", () => {
    setModuleCache("accounts", { secret: "plaintext" }, 7);
    addFullRecord(4242, 0x02, "acct", "ZGF0YQ==");
    expect(getModuleCache("accounts").data).toEqual({ secret: "plaintext" });
    expect(hasFullRecord(4242)).toBe(true);

    logoutModule("accounts");

    expect(getModuleCache("accounts").data).toBeNull();
    expect(hasFullRecord(4242)).toBe(false);
  });

  it("bindModuleRecovery 成功后登记恢复槽并保持模块可用", async () => {
    keyState.moduleKeyEnabled.value = { photo: true, accounts: false, fileverthys: false };
    v4Bind.mockResolvedValueOnce(okResp({ enabled: true, unlocked: true, has_recovery: true }));

    const result = await bindModuleRecovery("photo", "module-pass", "RECOVERY-CODE");

    expect(result.ok).toBe(true);
    expect(v4Bind).toHaveBeenCalledWith(0, "module-pass", "RECOVERY-CODE");
    expect(keyState.moduleHasRecovery.value.photo).toBe(true);
    expect(isModuleReady("photo")).toBe(true);
  });

  it("bindModuleRecovery 未启用保护时拒绝且不触达后端", async () => {
    const result = await bindModuleRecovery("photo", "module-pass", "RECOVERY-CODE");

    expect(result.ok).toBe(false);
    expect(v4Bind).not.toHaveBeenCalled();
  });

  it("resealModuleDevice 策略拒绝映射为当前会话不允许", async () => {
    keyState.moduleKeyEnabled.value = { photo: true, accounts: false, fileverthys: false };
    v4Reseal.mockResolvedValueOnce(errResp("ERR_00000017"));

    const denied = await resealModuleDevice("photo", "module-pass");

    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.code).toBe("E_MODULE_POLICY");
      expect(denied.message).toContain("当前会话或模块状态不允许");
    }

    v4Reseal.mockResolvedValueOnce(okResp({ enabled: true, unlocked: true, has_recovery: true }));
    const done = await resealModuleDevice("photo", "module-pass");
    expect(done.ok).toBe(true);
    expect(isModuleReady("photo")).toBe(true);
  });
});
