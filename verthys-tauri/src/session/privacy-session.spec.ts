/**
 * privacy-session.spec.ts — 防截屏保护应用级会话单例测试
 *
 * 覆盖点：切换单飞（连击只发一次 IPC）、采纳单飞（并发入口只采纳一次）、
 * 已接管不重复签发、凭证丢失诊断（不发必然被拒的关闭请求）、
 * 关闭路径回传凭证、对账收敛到启用后的再采纳。
 *
 * 模块级单例状态在用例间必须隔离：每个用例重新载入模块（连同被 mock 的
 * IPC 包装一起取回新实例），后端用带状态的假实现建模，避免"静态桩掩盖
 * 先采纳后生效"的状态迁移。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../utils/invoke_wrapper", () => ({ invokeWithTimeout: vi.fn() }));
vi.mock("../core/frontend-ipc-priority", () => ({ markFrontendIpcActive: vi.fn() }));

const ISSUED_TOKEN = "issued-token-1";

/** 后端状态模型（槽位迁移与真实状态机一致） */
interface BackendState {
  enabled: boolean;
  slot: "empty" | "pending_adoption" | "active";
  state: "disabled" | "enabled" | "quarantined";
  adoptCalls: number;
  reconcileCalls: number;
  setCalls: Array<{ enabled: boolean; authToken: string | null }>;
  /** 让指定命令抛异常（模拟 IPC 层失败：命令内部错误 / 通道断开） */
  failCommands?: Set<string>;
}

interface Harness {
  session: typeof import("./privacy-session");
  invoke: ReturnType<typeof vi.mocked<(typeof import("../utils/invoke_wrapper"))["invokeWithTimeout"]>>;
  backend: BackendState;
}

function newBackend(overrides: Partial<BackendState>): BackendState {
  return {
    enabled: false,
    slot: "empty",
    state: "disabled",
    adoptCalls: 0,
    reconcileCalls: 0,
    setCalls: [],
    ...overrides,
  };
}

/** 重新载入模块（隔离单例状态）并接上带状态的假后端 */
async function loadSession(backend: BackendState): Promise<Harness> {
  vi.resetModules();
  const wrapper = await import("../utils/invoke_wrapper");
  const invoke = vi.mocked(wrapper.invokeWithTimeout);
  invoke.mockImplementation(
    async (
      cmd: string,
      args?: Record<string, unknown> | ArrayBuffer | Uint8Array,
    ): Promise<unknown> => {
      const jsonArgs =
        args instanceof ArrayBuffer || args instanceof Uint8Array
          ? undefined
          : (args as Record<string, unknown> | undefined);
      if (backend.failCommands?.has(cmd)) {
        throw new Error(`IPC 失败: ${cmd}`);
      }
      switch (cmd) {
        case "get_privacy_status":
          return {
            state: backend.state,
            slot: backend.slot,
            protected_count: backend.enabled ? 1 : 0,
          };
        case "adopt_privacy_session":
          backend.adoptCalls += 1;
          backend.slot = "active";
          return { ok: true, enabled: true, partial_protection: false, detail: "", session_token: ISSUED_TOKEN };
        case "set_privacy_mode": {
          const enabled = Boolean(jsonArgs?.enabled);
          const authToken = (jsonArgs?.authToken as string | null) ?? null;
          backend.setCalls.push({ enabled, authToken });
          backend.enabled = enabled;
          backend.slot = enabled ? "active" : "empty";
          backend.state = enabled ? "enabled" : "disabled";
          return {
            ok: true,
            enabled,
            partial_protection: false,
            detail: "",
            session_token: enabled ? ISSUED_TOKEN : null,
          };
        }
        case "reconcile_privacy":
          backend.reconcileCalls += 1;
          backend.state = "enabled";
          backend.slot = "pending_adoption";
          backend.enabled = true;
          return { ok: true, enabled: true, partial_protection: false, detail: "" };
        default:
          throw new Error(`未预期的命令: ${cmd}`);
      }
    },
  );
  const session = await import("./privacy-session");
  return { session, invoke, backend };
}

describe("privacy-session 单例", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("连击十次只发一次 set_privacy_mode IPC", async () => {
    const h = await loadSession(newBackend({}));
    const results = await Promise.all(
      Array.from({ length: 10 }, () => h.session.togglePrivacy()),
    );

    expect(results.every((outcome) => outcome.ok)).toBe(true);
    expect(h.backend.setCalls).toHaveLength(1);
    expect(h.backend.setCalls[0].enabled).toBe(true);
    expect(h.session.privacyEnabled.value).toBe(true);
  });

  it("采纳单飞：并发入口只采纳一次", async () => {
    const h = await loadSession(
      newBackend({ enabled: true, state: "enabled", slot: "pending_adoption" }),
    );
    const [first, second] = await Promise.all([
      h.session.ensureAdopted(),
      h.session.ensureAdopted(),
    ]);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(h.backend.adoptCalls).toBe(1);
    expect(h.session.privacyTokenLost.value).toBe(false);
  });

  it("已接管后再次调用不重复签发", async () => {
    const h = await loadSession(
      newBackend({ enabled: true, state: "enabled", slot: "pending_adoption" }),
    );
    await h.session.ensureAdopted();
    await h.session.ensureAdopted();

    expect(h.backend.adoptCalls).toBe(1);
  });

  it("凭证丢失：后端生效而本会话无凭证时置为真", async () => {
    const h = await loadSession(
      newBackend({ enabled: true, state: "enabled", slot: "active" }),
    );
    await h.session.refreshPrivacyStatus();

    expect(h.session.privacyTokenLost.value).toBe(true);
  });

  it("凭证丢失时关闭不发必然被拒的 IPC", async () => {
    const h = await loadSession(
      newBackend({ enabled: true, state: "enabled", slot: "active" }),
    );
    const outcome = await h.session.togglePrivacy();

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe("PRIVACY_TOKEN_MISSING");
    expect(h.backend.setCalls).toHaveLength(0);
  });

  it("关闭路径回传采纳所得凭证", async () => {
    const h = await loadSession(
      newBackend({ enabled: true, state: "enabled", slot: "pending_adoption" }),
    );
    await h.session.ensureAdopted();

    const outcome = await h.session.togglePrivacy();
    expect(outcome.ok).toBe(true);
    expect(h.backend.setCalls).toHaveLength(1);
    expect(h.backend.setCalls[0]).toEqual({ enabled: false, authToken: ISSUED_TOKEN });
    expect(h.session.privacyEnabled.value).toBe(false);
  });

  it("对账收敛到启用后自动再采纳取得新凭证", async () => {
    const h = await loadSession(
      newBackend({ enabled: true, state: "quarantined", slot: "active" }),
    );
    const outcome = await h.session.reconcilePrivacySession();

    expect(outcome.ok).toBe(true);
    expect(h.backend.reconcileCalls).toBe(1);
    expect(h.backend.adoptCalls).toBe(1);
    expect(h.session.privacyQuarantined.value).toBe(false);
    expect(h.session.privacyTokenLost.value).toBe(false);
  });

  it("切换 IPC 异常不外泄：转为失败结果且单飞可重试", async () => {
    const backend = newBackend({});
    const h = await loadSession(backend);
    backend.failCommands = new Set(["set_privacy_mode"]);

    const first = await h.session.togglePrivacy();
    expect(first.ok).toBe(false);
    expect(first.code).toBe("PRIVACY_IPC_FAILED");

    // 单飞状态已释放：故障恢复后可直接重试成功
    backend.failCommands.clear();
    const second = await h.session.togglePrivacy();
    expect(second.ok).toBe(true);
    expect(backend.setCalls).toHaveLength(1);
    expect(h.session.privacyEnabled.value).toBe(true);
  });

  it("对账 IPC 异常不外泄：转为失败结果", async () => {
    const backend = newBackend({ enabled: true, state: "quarantined", slot: "active" });
    const h = await loadSession(backend);
    backend.failCommands = new Set(["reconcile_privacy"]);

    const outcome = await h.session.reconcilePrivacySession();
    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe("PRIVACY_IPC_FAILED");
  });

  it("点击即刻反馈：未等 IPC 返回即切换显示态，完成后在途标志清除", async () => {
    const h = await loadSession(newBackend({}));
    await h.session.refreshPrivacyStatus();

    const pending = h.session.togglePrivacy();
    // 同帧断言：乐观态已切换（图标即时响应，不等后端往返）
    expect(h.session.privacyEnabled.value).toBe(true);
    expect(h.session.privacyBusy.value).toBe(true);

    const outcome = await pending;
    expect(outcome.ok).toBe(true);
    expect(h.session.privacyBusy.value).toBe(false);
    expect(h.session.privacyEnabled.value).toBe(true);
    expect(h.backend.setCalls).toHaveLength(1);
  });

  it("失败回退：命令被拒后显示态回到真实值", async () => {
    const backend = newBackend({});
    const h = await loadSession(backend);
    await h.session.refreshPrivacyStatus();
    // 后端拒绝开启（模拟系统调用失败被还原）
    h.invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "set_privacy_mode") {
        return {
          ok: false,
          enabled: false,
          partial_protection: false,
          detail: "保护失败，已还原到变更前状态",
          error_code: "PRIVACY_ROLLED_BACK",
        };
      }
      return { state: backend.state, slot: backend.slot, protected_count: 0 };
    });

    const outcome = await h.session.togglePrivacy();
    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe("PRIVACY_ROLLED_BACK");
    // 乐观态已清空：界面回到后端真实状态（未保护）
    expect(h.session.privacyEnabled.value).toBe(false);
  });
});