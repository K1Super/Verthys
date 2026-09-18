/**
 * useModuleNavigation — 模块导航与密钥守卫逻辑
 *
 * 职责：
 *   1. 当前模块状态与 Dock 自动隐藏/展开
 *   2. 模块切换守卫：密码工具/安全管理直接进入，业务模块检查密钥状态
 *   3. 模块密钥登录对话框：确认/取消
 *   4. Verthys 未就绪提示：跳转安全管理
 *
 * 从 MainView.vue 抽离，功能 100% 保留。
 */

import { ref, computed, watch, type Ref } from "vue";
import {
  touchSession,
  hasModuleKeyRecordRef,
  verifyModuleKey, isModuleReady, isModuleKeyEnabled,
  verthysReadyRef,
  moduleKeyStatusLoadingRef,
  moduleKeyStatusLoadedRef,
  moduleKeyEnabledRef,
  MODULE_LABELS,
  type ModuleId,
} from "../lib/keyManager";
import { useErrorToast } from "./useErrorToast";
import {
  scheduleBackgroundFlush,
  ensureRecordScan,
} from "../cache/composition/verthys-cache";
import { scheduleGc } from "../utils/gc";
import { withTimeout } from "../utils/promise_utils";

/* ------------------------------------------------------------------ *
 * ★ 安全守卫修复：等待布尔 Ref 变为 false（带超时兜底）
 *
 * 用于 switchModule 防御性守卫——解锁关键路径若仍在加载模块密钥状态
 * （moduleKeyStatusLoading=true），切换业务模块前必须等待其完成，
 * 否则 isModuleKeyEnabled 读到默认 false 会误判「保护已关闭」直接放行。
 *
 * 实现：watch 监听 flag，已 false 立即 resolve；变 false 时 resolve；
 *       withTimeout 兜底防止永久等待（lockAll 等异常场景）。
 * ------------------------------------------------------------------ */
function waitForFlagFalse(flag: Ref<boolean>, timeoutMs: number): Promise<void> {
  if (!flag.value) return Promise.resolve();
  return new Promise<void>((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      unwatch();
      resolve();
    };
    const unwatch = watch(flag, (v) => {
      if (!v) finish();
    });
    // 超时兜底：无论 flag 是否变 false 都 resolve（调用方事后重检 verthysReady）
    setTimeout(finish, timeoutMs);
  });
}

/* ★ 安全守卫根治：等待布尔 Ref 变为 true（带超时兜底）
 *
 * 用于 switchModule 防御性守卫——模块密钥状态未加载完（moduleKeyStatusLoaded=false）
 * 时，切换业务模块前必须等待 loadModuleKeyStatus 完成（loaded=true），
 * 否则 isModuleKeyEnabled 读到默认 false 会误判「保护已关闭」直接放行。
 *
 * 与 waitForFlagFalse 的区别：等待 true（加载完成），超时后由调用方安全兜底（弹密钥框）。 */
function waitForFlagTrue(flag: Ref<boolean>, timeoutMs: number): Promise<void> {
  if (flag.value) return Promise.resolve();
  return new Promise<void>((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      unwatch();
      resolve();
    };
    const unwatch = watch(flag, (v) => {
      if (v) finish();
    });
    // 超时兜底：无论 flag 是否变 true 都 resolve（调用方事后重检 + 安全兜底弹密钥框）
    setTimeout(finish, timeoutMs);
  });
}

/* ===== 模块定义（安全管理放在最后） ===== */
export const modules = [
  {
    id: "accounts",
    label: "存签",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  },
  {
    id: "certs",
    label: "枢钥",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
  },
  {
    id: "tools",
    label: "钥域",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  },
  {
    id: "photos",
    label: "拾光",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
  },
  {
    id: "verthys",
    label: "清藏",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/><line x1="12" y1="17" x2="12" y2="19"/></svg>`,
  },
  {
    id: "security",
    label: "中枢",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>`,
  },
];

/** 需要独立密钥的业务模块（密码工具和安全管理不需要） */
const KEY_REQUIRED_MODULES = ["accounts", "certs", "photos", "verthys"];

/* 模块 ID 到 ModuleId 的映射（用于模块密钥查询） */
const MODULE_ID_MAP: Record<string, ModuleId> = {
  accounts: "accounts",
  certs: "certs",
  photos: "photo",
  verthys: "fileverthys",
};

export function useModuleNavigation() {
  const { errorMsg, showError } = useErrorToast();

  /* ===== 当前模块状态 ===== */
  const currentModule = ref<string>("");

  /* ===== 导航栏自动隐藏（面板全屏时收起，悬浮左侧触发区展开） ===== */
  const dockCollapsed = ref(false);
  const dockHovered = ref(false);
  const onPanelActive = (val: boolean) => { dockCollapsed.value = val; };
  watch(currentModule, (m) => {
    if (m !== "security") { dockCollapsed.value = false; dockHovered.value = false; }
    // ★ 项12：模块切换后延迟 500ms 触发 V8 Major GC
    // 旧模块组件已通过 onUnmounted 释放 blobUrl/大对象引用，
    // 延迟 500ms 确保新模块首屏渲染完成后再触发 GC，
    // 避免在切换动画的关键帧中产生 Stop-The-World 暂停造成卡顿。
    scheduleGc(500);
  });

  /* 鼠标在导航栏区域时展开 Dock，离开区域时收缩（统一控制，避免 mouseleave 冲突）
   * ★ 性能根治：workspace 铺满视口 → 直接用视口坐标判定（去 getBoundingClientRect
   * 强制布局读取）；值未变化不写响应式 ref（省一次 Vue patch 调度） */
  const onDockEdgeHover = (e: MouseEvent) => {
    if (!dockCollapsed.value) return;
    const hovered = e.clientX < 80;
    if (hovered !== dockHovered.value) dockHovered.value = hovered;
  };

  /* ===== 模块密钥登录守卫状态 ===== */
  const showModuleKeyVerify = ref(false);
  const showVerthysNotReadyHint = ref(false);
  const pendingModule = ref("");
  const moduleKeyInput = ref("");
  const moduleKeyVerifying = ref(false);
  /* ★ 验证进度条（1.5s 感知时长，复用 QuantumProgressFlow 通道样式，非量子动画） */
  const moduleKeyVerifyPercent = ref(0);
  const moduleKeyVerifyMsg = ref("");
  /* ★ 企业级感知：验证错误状态标记（触发密码框抖动 + 红色边框，错误密码绝不放行） */
  const moduleKeyVerifyError = ref(false);
  /* 用户重新输入时清除错误状态（红色边框 + 抖动复位） */
  watch(moduleKeyInput, (v) => {
    if (v && moduleKeyVerifyError.value) moduleKeyVerifyError.value = false;
  });
  let verifyRafId: number | null = null;

  /* 待登录模块的 ModuleId（用于查询 hasModuleKeyRecordRef） */
  const pendingModuleId = computed<ModuleId>(() => MODULE_ID_MAP[pendingModule.value] || "accounts");
  const pendingModuleLabel = computed(() => {
    const mid = MODULE_ID_MAP[pendingModule.value];
    return mid ? MODULE_LABELS[mid] : pendingModule.value;
  });

  /**
   * ★ 路由前置守卫（完全非阻塞）
   *
   * 导航切换零等待：scheduleBackgroundFlush + ensureRecordScan 全部后台执行，
   * currentModule.value 立即写入，模块从内存缓存即时渲染。
   *
   * 数据正确性保证：
   *   - 内存缓存是权威数据源，已包含最新增删改数据
   *   - ensureRecordScan 后台合并磁盘记录（仅补充缺失项，不覆盖内存缓存）
   *   - pendingDeletionIds 过滤已删除 ID，磁盘旧数据无法回填
   */
  function preSwitchFlush(): void {
    // 后台冲刷：取消防抖 + 立即入队 flush（非阻塞）
    scheduleBackgroundFlush();
    // 后台扫描：补充缺失记录（非阻塞，模块从现有缓存即时渲染）
    ensureRecordScan().catch(e => {
      console.warn("[preSwitchFlush] ensureRecordScan 后台异常", e);
    });
  }

  /** 统一应用模块切换：前置守卫 → touchSession → 写 currentModule */
  function applySwitch(id: string): void {
    preSwitchFlush();
    touchSession();
    currentModule.value = id;
  }

  const switchModule = async (id: string): Promise<void> => {
    // 密码工具、安全管理：直接进入，无需任何密钥
    if (id === "tools" || id === "security") {
      applySwitch(id);
      return;
    }
    // 业务模块：检查是否属于需要独立密钥的模块
    if (!KEY_REQUIRED_MODULES.includes(id)) {
      applySwitch(id);
      return;
    }
    const moduleId = MODULE_ID_MAP[id];
    if (!moduleId) {
      applySwitch(id);
      return;
    }
    // 0b. verthys 未解锁（自动解锁失败或全新用户）→ 提示前往安全管理初始化
    //     此处不切换模块，无需冲刷
    if (!verthysReadyRef.value) {
      pendingModule.value = id;
      moduleKeyInput.value = "";
      showVerthysNotReadyHint.value = true;
      return;
    }
    // ★ 安全守卫根治：模块密钥状态未加载完前，不允许进入业务模块
    //
    // 原缺陷：用 moduleKeyStatusLoading 等待，但 global-verthys 超时后重置 loading=false，
    // 守卫误判"加载完成"→ 读 isModuleKeyEnabled=false → 放行，绕过密钥验证。
    //
    // 根治：改用 moduleKeyStatusLoaded 判断。
    //   - loaded=false（未加载完）→ 等待 loadModuleKeyStatus 完成（最多 10s）
    //   - 等待期间 verthys 被锁定 → 提示前往安全管理
    //   - 超时仍未加载完 → 安全兜底弹密钥框（绝不放行）
    //   - loaded=true → 正常判断 isModuleKeyEnabled
    if (!moduleKeyStatusLoadedRef.value) {
      await waitForFlagTrue(moduleKeyStatusLoadedRef, 10000);
      // lockAll 竞态防护：await 期间 verthys 可能已被锁定
      if (!verthysReadyRef.value) {
        pendingModule.value = id;
        moduleKeyInput.value = "";
        showVerthysNotReadyHint.value = true;
        return;
      }
      // ★ 安全兜底：超时仍未加载完 → 绝不放行，弹密钥验证框
      if (!moduleKeyStatusLoadedRef.value) {
        pendingModule.value = id;
        moduleKeyInput.value = "";
        showModuleKeyVerify.value = true;
        return;
      }
    }
    const keyEnabled = isModuleKeyEnabled(moduleId);
    // 1. 密钥保护已关闭 → 直接进入，无需任何密钥
    if (!keyEnabled) {
      applySwitch(id);
      return;
    }
    // 2. 模块已设置密钥且本会话已登录 → 直接进入
    if (isModuleReady(moduleId)) {
      applySwitch(id);
      return;
    }
    // 3. 未设置密钥或未登录 → 弹出密钥对话框（内部根据状态显示不同提示）
    //    此处不切换模块，无需冲刷
    pendingModule.value = id;
    moduleKeyInput.value = "";
    showModuleKeyVerify.value = true;
  };

  /* ===== 模块密钥登录对话框确认/取消 ===== */
  /* ★ 1.5s 感知时长：rAF 推进进度条至 90%，实际验证完成后跳 100%，保证用户感知
   * ★ 企业级安全修复（刚性约束）：
   *   - verifyModuleKey 返回 VerthysResult<void> 判别联合对象，必须用 result.ok 判断
   *     旧代码 `const ok = await ...; if (!ok)` 判断对象引用（永远 truthy），
   *     导致错误密码永远放行 —— 已彻底修复
   *   - 错误密码绝不放行：弹窗保持开启 + 密码框抖动 + 红色边框 + 清空密码 + 顶部红条
   *   - 无论成功/失败都保证 1.5s 最小感知时长，杜绝"无感知直接放行"
   */
  const VERIFY_DURATION = 1500;
  const confirmModuleKeyVerify = async () => {
    if (!pendingModule.value || !moduleKeyInput.value) return;
    moduleKeyVerifying.value = true;
    moduleKeyVerifyError.value = false;
    moduleKeyVerifyPercent.value = 0;
    moduleKeyVerifyMsg.value = "正在验证密钥";
    const t0 = performance.now();
    const tick = () => {
      const elapsed = performance.now() - t0;
      const ratio = Math.min(elapsed / VERIFY_DURATION, 1);
      moduleKeyVerifyPercent.value = Math.round(ratio * 90);
      if (ratio < 1) verifyRafId = requestAnimationFrame(tick);
    };
    verifyRafId = requestAnimationFrame(tick);

    /* ★ 企业级感知：无论成功/失败，都保证 1.5s 最小感知时长
     * 错误密码也不能立即返回，必须让用户感知到完整验证过程 */
    const ensureMinDuration = async () => {
      const remaining = VERIFY_DURATION - (performance.now() - t0);
      if (remaining > 0) await new Promise((r) => setTimeout(r, remaining));
      if (verifyRafId !== null) { cancelAnimationFrame(verifyRafId); verifyRafId = null; }
    };

    /* ★ 企业级感知：验证失败统一处理
     * 跑完感知动画 → 标记错误状态 → 顶部红条 → 清空密码 → 保持弹窗开启
     * 绝不消失弹窗，让用户重试 */
    const handleVerifyError = async (msg: string) => {
      await ensureMinDuration();
      moduleKeyVerifyMsg.value = "验证失败";
      moduleKeyVerifyError.value = true;
      showError(msg);
      moduleKeyInput.value = "";
      /* 抖动动画 0.4s + 失败状态停留，让用户清晰感知 */
      await new Promise((r) => setTimeout(r, 400));
    };

    try {
      const moduleId = MODULE_ID_MAP[pendingModule.value];
      if (!moduleId) {
        await handleVerifyError("密钥错误，请重试");
        return;
      }
      /* ★ 核心安全修复：verifyModuleKey 返回 VerthysResult<void>
       * 必须用 result.ok 判断成功/失败，旧代码 `if (!ok)` 判断对象引用永远为 false */
      const result = await verifyModuleKey(moduleId, moduleKeyInput.value);
      if (!result.ok) {
        await handleVerifyError("密钥错误，请重试");
        return;
      }
      // 验证成功 → 跳 100% + 进入目标模块
      await ensureMinDuration();
      moduleKeyVerifyPercent.value = 100;
      moduleKeyVerifyMsg.value = "验证完成";
      await new Promise((r) => setTimeout(r, 200));
      const target = pendingModule.value;
      showModuleKeyVerify.value = false;
      pendingModule.value = "";
      moduleKeyInput.value = "";
      applySwitch(target);
    } catch {
      await handleVerifyError("密钥错误，请重试");
    } finally {
      if (verifyRafId !== null) { cancelAnimationFrame(verifyRafId); verifyRafId = null; }
      moduleKeyVerifying.value = false;
    }
  };

  const cancelModuleKeyVerify = () => {
    if (verifyRafId !== null) { cancelAnimationFrame(verifyRafId); verifyRafId = null; }
    moduleKeyVerifyError.value = false;
    showModuleKeyVerify.value = false;
    pendingModule.value = "";
    moduleKeyInput.value = "";
  };

  /* Verthys 未就绪提示：跳转安全管理 */
  const goToSecurityFromHint = () => {
    showVerthysNotReadyHint.value = false;
    pendingModule.value = "";
    applySwitch("security");
  };

  return {
    /* 错误提示 */
    errorMsg,
    showError,
    /* 模块状态 */
    currentModule,
    /* Dock 状态 */
    dockCollapsed,
    dockHovered,
    onPanelActive,
    onDockEdgeHover,
    /* 模块密钥登录守卫 */
    showModuleKeyVerify,
    showVerthysNotReadyHint,
    pendingModule,
    moduleKeyInput,
    moduleKeyVerifying,
    moduleKeyVerifyPercent,
    moduleKeyVerifyMsg,
    moduleKeyVerifyError,
    pendingModuleId,
    pendingModuleLabel,
    hasModuleKeyRecordRef,
    /* 方法 */
    switchModule,
    confirmModuleKeyVerify,
    cancelModuleKeyVerify,
    goToSecurityFromHint,
  };
}
