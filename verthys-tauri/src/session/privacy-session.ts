/*
 * session/privacy-session.ts — 防截屏保护应用级会话层
 *
 * 职责：
 *   - 状态与凭证存放于模块级单例（应用生命周期内唯一实例），组件的挂载与卸载
 *     不影响保护能力，卸载也不发任何隐私命令
 *   - 采纳单飞：启动对账读状态，需要时采纳保护会话取得凭证；重挂载、热更新、
 *     多入口调用只会触发一次 IPC
 *   - 切换单飞：连击复用同一个 Promise，不重复发 IPC
 *   - 凭证丢失诊断：后端已启用且槽位为生效态而本会话不持有凭证时置为真，
 *     界面据此置灰按钮并提示重启接管
 *
 * 为什么不提供"重新签发凭证"入口：
 *   签发是无中生有的凭证生成操作，一旦暴露为无授权接口，凭证体系即刻瓦解。
 *   唯一恢复路径是重启应用——重启后启动序列把槽位置为待采纳，前端重新采纳。
 *
 * 本模块不依赖组件与提示设施：错误码交由界面层映射为提示文案。
 */

import { computed, ref } from "vue";
import {
  adoptPrivacySession,
  getPrivacyStatus,
  reconcilePrivacy,
  setPrivacyMode,
  type PrivacyStatusResult,
} from "../lib/verthys";

/** 保护状态快照（null = 尚未查询） */
const status = ref<PrivacyStatusResult | null>(null);
/** 会话凭证：仅存于前端内存，随进程结束消失 */
let token: string | null = null;
/** 乐观显示状态：点击后先把图标切到目标态，后端确认或失败后收敛 */
const optimisticEnabled = ref<boolean | null>(null);
/** 本会话在途标志：覆盖单飞窗口期，按钮即时置忙（不重复受单飞吞并） */
const inFlight = ref(false);
/**
 * 状态写序号：本地权威收敛（切换成功/采纳成功）递增；
 * 在途的旧状态查询结果按序号丢弃，防止"旧查询晚到覆盖新状态"。
 */
let statusEpoch = 0;
/** 切换单飞（对账复用同一把单飞锁：两者都是状态变更，不得并发） */
let toggleInFlight: Promise<PrivacyOutcome> | null = null;
/** 采纳单飞 */
let adoptInFlight: Promise<PrivacyOutcome> | null = null;

/** 操作结果：失败时携带错误码（界面据此分支提示） */
export interface PrivacyOutcome {
  ok: boolean;
  code?: string;
}

/**
 * 会话层操作契约：对调用方不抛异常
 *
 * IPC 层异常（命令内部错误、通道断开等）统一转为失败结果，
 * 界面层只按 outcome 分支提示；异常若外泄会成为无提示的
 * unhandled rejection（按钮无反馈、状态不同步）。
 */
async function runGuarded(
  operation: () => Promise<PrivacyOutcome>,
): Promise<PrivacyOutcome> {
  try {
    return await operation();
  } catch (e) {
    console.warn("[privacy] 会话操作失败", e);
    // 异常意味着结果不可知（可能已生效也可能未生效）：后台校准状态快照
    void refreshPrivacyStatus();
    return { ok: false, code: "PRIVACY_IPC_FAILED" };
  }
}

export const privacyStatus = computed(() => status.value);
/** 保护是否启用（乐观态优先：点击后立即反映目标值，避免按钮迟滞感） */
export const privacyEnabled = computed(
  () => optimisticEnabled.value ?? status.value?.state === "enabled",
);
/** 处理中：本会话在途或后端过渡态（按钮据此置忙并给出悬浮提示） */
export const privacyBusy = computed(
  () => inFlight.value || status.value?.state === "transitioning",
);
export const privacyQuarantined = computed(() => status.value?.state === "quarantined");
export const privacyProtectedCount = computed(() => status.value?.protected_count ?? 0);
/** 凭证丢失：后端已启用且槽位生效，而本会话不持有凭证（签发响应丢失或热更新） */
export const privacyTokenLost = computed(
  () =>
    status.value?.state === "enabled" &&
    status.value?.slot === "active" &&
    token === null,
);

/**
 * 刷新状态快照
 *
 * 查询失败不抛出：状态不可知时界面按不可用处理（按钮禁用），
 * 不把失败伪造成"已关闭"（那是"看起来未保护"的另一种撒谎方式）。
 */
export async function refreshPrivacyStatus(): Promise<void> {
  const epoch = statusEpoch;
  try {
    const snapshot = await getPrivacyStatus();
    // 查询期间发生本地权威收敛：丢弃本次旧结果，不覆盖新状态
    if (epoch === statusEpoch) {
      status.value = snapshot;
    }
  } catch (e) {
    console.warn("[privacy] 状态查询失败", e);
  }
}

/**
 * 采纳单飞：读取后端状态，待采纳时采纳保护会话取得凭证
 *
 * 调用时机：主界面挂载与拾光挂载（单飞保证只触发一次 IPC）。
 */
export function ensureAdopted(): Promise<PrivacyOutcome> {
  if (!adoptInFlight) {
    adoptInFlight = runGuarded(async (): Promise<PrivacyOutcome> => {
      await refreshPrivacyStatus();
      const snapshot = status.value;
      if (snapshot?.state === "enabled" && snapshot.slot === "pending_adoption") {
        const result = await adoptPrivacySession();
        if (result.ok) {
          token = result.session_token ?? null;
          // 采纳成功即槽位语义已定：旧的在途查询结果不得再覆盖
          statusEpoch += 1;
        }
        await refreshPrivacyStatus();
        return result.ok ? { ok: true } : { ok: false, code: result.error_code ?? undefined };
      }
      return { ok: true };
    }).finally(() => {
      adoptInFlight = null;
    });
  }
  return adoptInFlight;
}

/**
 * 切换保护（连击复用同一 Promise）
 *
 * 即时响应：点击后先乐观切换显示态（图标同帧变化），命令返回后按后端
 * 契约本地收敛——成功后启用=槽位生效 / 关闭=槽位清空，免去串行的状态
 * 查询 IPC；失败或异常时由状态收敛与提示兜底（界面回到真实态）。
 * 关闭路径需要本会话持有的凭证：状态未知时先接管；凭证丢失时如实返回
 * PRIVACY_TOKEN_MISSING 而不是发起一次必然被拒的 IPC。
 */
export function togglePrivacy(): Promise<PrivacyOutcome> {
  if (toggleInFlight) {
    return toggleInFlight;
  }
  inFlight.value = true;
  toggleInFlight = runGuarded(async (): Promise<PrivacyOutcome> => {
    // 状态未知才需要接管流程（最早挂载点已调用，正常命中缓存）
    if (status.value === null) {
      const adopted = await ensureAdopted();
      if (!adopted.ok) {
        return adopted;
      }
    }
    const target = !privacyEnabled.value;
    if (!target && token === null) {
      return { ok: false, code: "PRIVACY_TOKEN_MISSING" };
    }
    optimisticEnabled.value = target;

    const result = await setPrivacyMode(target, target ? undefined : token ?? undefined);
    if (result.ok) {
      token = target ? (result.session_token ?? null) : null;
      // 后端契约：成功后完成态确定（启用=待命/生效槽位，关闭=清空槽位），
      // 本地直接收敛，无需再等一次状态查询；旧的在途查询结果按序号丢弃
      statusEpoch += 1;
      status.value = {
        state: target ? "enabled" : "disabled",
        slot: target ? "active" : "empty",
        protected_count: status.value?.protected_count ?? 0,
      };
      // 幂等开（已启用且无令牌）等边界：后台校准，不阻塞按钮反馈
      if (target && token === null) {
        void refreshPrivacyStatus();
      }
      return { ok: true };
    }
    void refreshPrivacyStatus();
    return { ok: false, code: result.error_code ?? undefined };
  }).finally(() => {
    optimisticEnabled.value = null;
    toggleInFlight = null;
    inFlight.value = false;
  });
  return toggleInFlight;
}

/**
 * 隔离对账（用户从恢复对话框触发）
 *
 * 与切换共用单飞；对账收敛到启用时槽位回待采纳，需要再次采纳取得新凭证。
 */
export function reconcilePrivacySession(): Promise<PrivacyOutcome> {
  if (toggleInFlight) {
    return toggleInFlight;
  }
  inFlight.value = true;
  toggleInFlight = runGuarded(async (): Promise<PrivacyOutcome> => {
    const result = await reconcilePrivacy();
    if (!result.ok) {
      await refreshPrivacyStatus();
      return { ok: false, code: result.error_code ?? undefined };
    }
    if (result.enabled) {
      const adopted = await ensureAdopted();
      if (!adopted.ok) {
        return adopted;
      }
    } else {
      token = null;
      await refreshPrivacyStatus();
    }
    return { ok: true };
  }).finally(() => {
    toggleInFlight = null;
    inFlight.value = false;
  });
  return toggleInFlight;
}