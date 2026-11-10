/*
 * state/key_state.ts — 密钥管理统一状态对象
 *
 * 所有响应式状态集中在此文件，子业务域通过 import 使用
 * keyManager.ts 再导出个别 ref 保持对外 API 不变
 */
import { ref, type Ref } from "vue";
import type { SecurityPresetCode, PresetFeatures } from "../types/verthys";
import type { ModuleId } from "../types/key_manager";
import {
  DEFAULT_CUSTOM_FEATURES,
  CUSTOM_FEATURES_KEY,
  CUSTOM_SESSION_MINUTES_KEY,
  CUSTOM_SESSION_MINUTES_DEFAULT,
  CUSTOM_SESSION_MINUTES_MIN,
  CUSTOM_SESSION_MINUTES_MAX,
  SECURITY_PRESET_KEY,
  LOCKED_FEATURES,
} from "../constants/key_manager_const";

/* ------------------------------------------------------------------ *
 * 统一 KeyState 对象                                                  *
 *                                                                    *
 * 所有分散的 ref 聚合到此对象，子业务域通过 keyState.xxx 引用         *
 * 对外仍通过 keyManager.ts 再导出独立 ref 保持 API 兼容              *
 * ------------------------------------------------------------------ */

export interface KeyState {
  /** verthys 已解锁 */
  verthysReady: Ref<boolean>;
  /** 全局根密钥已就绪 */
  globalKeyReady: Ref<boolean>;
  /** verthys 中存在全局密钥记录 */
  hasGlobalKeyRecord: Ref<boolean>;
  /** 全局密钥记录加载标志（恒 false，保留供防御性检查）
   *
   * worker 解锁成功后进程内即时完成全局密钥记录探测，结果内联到
   * unlock 响应，前端无异步扫描阶段，故该标志恒为 false；
   * 保留定义供 resetAllState 防御性重置与未来扩展使用。 */
  globalKeyRecordLoading: Ref<boolean>;
  /** 全局密钥记录缓存（避免 verifyGlobalKey 重复扫描 40s）
   *
   * initUnlock 找到全局密钥记录后，将 recordB64 和 id 缓存到此。
   * verifyGlobalKey 优先读取缓存，跳过重复的 findGlobalKeyRecord 扫描。
   * verthysReady=false 或 lockAll 时清空。 */
  globalKeyRecordB64: Ref<string>;
  globalKeyRecordId: Ref<number>;
  /** 各模块密钥已验证（会话中可用） */
  moduleKeyReady: Ref<Record<ModuleId, boolean>>;
  /** 各模块已设置独立密钥（持久化在 verthys 中） */
  hasModuleKeyRecord: Ref<Record<ModuleId, boolean>>;
  /** 各模块密钥保护开关 */
  moduleKeyEnabled: Ref<Record<ModuleId, boolean>>;
  /** 各模块是否已绑定恢复槽（换机恢复该模块的前提） */
  moduleHasRecovery: Ref<Record<ModuleId, boolean>>;
  /** 模块密钥状态后台加载标志
   *
   * initUnlock 将 loadModuleKeyStatus 置于后台非阻塞执行，
   * 避免"正在加载密钥配置…"阻塞主流程。
   * 此标志在解锁后置 true，后台加载完成/被并发修改丢弃后置 false。
   *
   * 用途：
   *   1. 模块组件据此判断 moduleKeyEnabled 是否为"已确认的真实状态"还是"安全默认值"
   *   2. SecurityCenter 开关操作据此与后台加载做乐观并发控制
   *      —— 后台加载期间若用户切换开关，版本号变化导致后台加载丢弃结果，
   *         杜绝"后台加载用旧 verthys 状态覆盖用户刚切换的开关"全局回滚缺陷 */
  moduleKeyStatusLoading: Ref<boolean>;
  /** 模块密钥状态已加载完成标志
   *
   * 区分"未加载"（loaded=false，状态不确定，守卫必须等待/拦截）与
   * "已加载但无配置"（loaded=true + enabled=false，确实不需要验证，放行）。
   *
   * 约束：不可仅用 moduleKeyStatusLoading 判断——其超时后被重置为 false，
   * 守卫会误判"加载完成"→ 读取默认 moduleKeyEnabled=false → 直接放行，
   * 绕过密钥验证。故 loaded 初始 false，仅 loadModuleKeyStatus 真正完成
   * （含乐观并发丢弃）时设 true：switchModule 守卫据此判断，
   * 未加载完不允许进入业务模块。 */
  moduleKeyStatusLoaded: Ref<boolean>;
  /** 模块密钥状态加载失败标志（加载异常；守卫据此立即 fail-closed，
   *  避免每次切换模块空等超时窗口） */
  moduleKeyStatusFailed: Ref<boolean>;
  /** 当前安全预设 */
  securityPreset: Ref<SecurityPresetCode>;
  /** 会话空闲锁定开关（false = 不自动锁定；自定义档可关闭此项） */
  sessionLockEnabled: Ref<boolean>;
  /** 自定义档空闲锁定时长（分钟，仅自定义档生效；后端受信预设文件为权威） */
  customSessionMinutes: Ref<number>;
  /** 初始化状态 */
  initStatus: Ref<string>;
  /** 状态文件中记录的加密库路径 */
  storedVerthysPath: Ref<string>;
  /** 最近一次初始化失败的错误信息 */
  lastInitError: Ref<string>;
  /** 初始化状态详情（含修复失败告警等可观测信息）
   *
   * verthys_init_status 返回的 detail 字段，由 SecurityCenter 显示给用户。
   * 当 repair_fail_count >= 3 时携带"状态文件写入异常"告警，
   * 引导用户检查磁盘空间与权限。 */
  initDetail: Ref<string>;
  /** 会话级状态版本：轮换提交等全局状态变化后自增，面板据此重查权威状态 */
  verthysStateVersion: Ref<number>;
  /** 当前会话是否由恢复码打开
   *
   * 权威来源 = C 层会话状态（恢复解锁成功后写入）；普通解锁、轮换提交与
   * 锁库一律清零。必须跨模块存续：恢复会话存续期间，重绑设备槽与全库
   * 轮换入口在中枢管理界面必须始终可恢复，不得随中枢组件卸载而丢失。 */
  recoveryMode: Ref<boolean>;
  /** 当前恢复会话是否已完成本机设备槽重绑
   *
   * 进程内会话状态：C 层不提供“重绑是否已完成”的读数，故由前端在重绑
   * 成功后置位；锁库、新恢复会话与轮换提交一律清零。与 recoveryMode
   * 分离：重绑成功只是消除设备槽风险，会话本身仍是恢复会话。 */
  recoveryResealDone: Ref<boolean>;
}

export const keyState: KeyState = {
  verthysReady: ref(false),
  globalKeyReady: ref(false),
  hasGlobalKeyRecord: ref(false),
  globalKeyRecordLoading: ref(false),
  globalKeyRecordB64: ref(""),
  globalKeyRecordId: ref(0),
  moduleKeyReady: ref({ photo: false, accounts: false, fileverthys: false }),
  hasModuleKeyRecord: ref({ photo: false, accounts: false, fileverthys: false }),
  /* moduleKeyEnabled 默认 false（安全默认）。
   * 权威来源是 C 层 模块状态（`v4_module_status`）：只有 M1 保护真正
   * 启用（MDEK 已移出 Keyring）的模块才置 true。查询失败时守卫按
   * moduleKeyStatusFailed fail-closed，不把"未知"当成"保护关闭"。 */
  moduleKeyEnabled: ref({ photo: false, accounts: false, fileverthys: false }),
  moduleHasRecovery: ref({ photo: false, accounts: false, fileverthys: false }),
  // 模块密钥状态后台加载标志（初始 false，解锁后置 true）
  moduleKeyStatusLoading: ref(false),
  // 模块密钥状态已加载完成标志（初始 false，loadModuleKeyStatus 完成时置 true）
  moduleKeyStatusLoaded: ref(false),
  // 模块密钥状态加载失败标志（初始 false；加载异常时置 true，守卫据此立即 fail-closed）
  moduleKeyStatusFailed: ref(false),
  securityPreset: ref<SecurityPresetCode>(loadSecurityPreset()),
  sessionLockEnabled: ref(true),
  customSessionMinutes: ref(loadCustomSessionMinutes()),
  initStatus: ref("none"),
  storedVerthysPath: ref(""),
  lastInitError: ref(""),
  initDetail: ref(""),
  verthysStateVersion: ref(0),
  recoveryMode: ref(false),
  recoveryResealDone: ref(false),
};

/* ------------------------------------------------------------------ *
 * 非响应式状态                                                        *
 * ------------------------------------------------------------------ */

/** 当前 verthys 路径（模块级缓存，供 verthysFlush 使用） */
let _currentVerthysPath = "";

export function getCurrentVerthysPath(): string {
  return _currentVerthysPath;
}

export function setCurrentVerthysPath(path: string): void {
  _currentVerthysPath = path;
}

/** 通知自包含面板重查权威状态（轮换提交后恢复态/模块态可能变化）。 */
export function bumpVerthysState(): void {
  keyState.verthysStateVersion.value += 1;
}

/* ------------------------------------------------------------------ *
 * 状态重置                                                            *
 * ------------------------------------------------------------------ */

/**
 * 重置所有全局状态为初始值（回滚专用）
 *
 * 在任意初始化步骤失败时调用，确保状态一致性
 * 注意：worker 内存中的 GMK 由 verthysClearGlobalKey 清零，此处仅重置前端状态
 */
export function resetAllState(): void {
  keyState.verthysReady.value = false;
  keyState.globalKeyReady.value = false;
  keyState.hasGlobalKeyRecord.value = false;
  keyState.globalKeyRecordLoading.value = false;
  keyState.globalKeyRecordB64.value = "";
  keyState.globalKeyRecordId.value = 0;
  _currentVerthysPath = "";
  keyState.moduleKeyReady.value = { photo: false, accounts: false, fileverthys: false };
  // 重置为安全默认 false（与初始化默认一致）
  keyState.moduleKeyEnabled.value = { photo: false, accounts: false, fileverthys: false };
  keyState.moduleHasRecovery.value = { photo: false, accounts: false, fileverthys: false };
  keyState.hasModuleKeyRecord.value = { photo: false, accounts: false, fileverthys: false };
  // 重置后台加载标志
  keyState.moduleKeyStatusLoading.value = false;
  // 重置已加载标志
  keyState.moduleKeyStatusLoaded.value = false;
  keyState.moduleKeyStatusFailed.value = false;
  // 恢复会话状态随会话销毁清零：锁库、外部锁定与初始化回滚后不得残留入口
  keyState.recoveryMode.value = false;
  keyState.recoveryResealDone.value = false;
}

/* ------------------------------------------------------------------ *
 * 当前安全预设持久化（localStorage）                                  *
 *                                                                    *
 * 持久化用户选择的安全模式代号（0=BALANCED, 1=SECURE,                  *
 * 2=PERFORMANCE, 3=CUSTOM），使应用重启后保持上次选择而非回退默认。    *
 * ------------------------------------------------------------------ */

/** 读取 localStorage 中持久化的当前安全预设代号（非法值回退为 BALANCED=0） */
export function loadSecurityPreset(): SecurityPresetCode {
  try {
    const raw = localStorage.getItem(SECURITY_PRESET_KEY);
    if (raw == null) return 0;
    const v = Number(raw);
    // 严格校验：仅接受 0~3 的整数，防止篡改导致越界
    if (!Number.isInteger(v) || v < 0 || v > 3) return 0;
    return v as SecurityPresetCode;
  } catch {
    return 0;
  }
}

/** 保存当前安全预设代号到 localStorage */
export function saveSecurityPreset(preset: SecurityPresetCode): void {
  try {
    localStorage.setItem(SECURITY_PRESET_KEY, String(preset));
  } catch (e) {
    console.warn("[saveSecurityPreset] 保存失败", e);
  }
}

/* ------------------------------------------------------------------ *
 * 自定义特性持久化（localStorage）                                    *
 * ------------------------------------------------------------------ */

/** 读取 localStorage 中的自定义特性配置 */
export function loadCustomFeatures(): PresetFeatures {
  try {
    const raw = localStorage.getItem(CUSTOM_FEATURES_KEY);
    if (!raw) return { ...DEFAULT_CUSTOM_FEATURES };
    const parsed = JSON.parse(raw) as Partial<PresetFeatures>;
    const merged: PresetFeatures = { ...DEFAULT_CUSTOM_FEATURES, ...parsed };
    LOCKED_FEATURES.forEach((k) => { (merged as any)[k] = true; });
    return merged;
  } catch {
    return { ...DEFAULT_CUSTOM_FEATURES };
  }
}

/** 保存自定义特性配置到 localStorage */
export function saveCustomFeatures(features: PresetFeatures): void {
  try {
    const safe: PresetFeatures = { ...features };
    LOCKED_FEATURES.forEach((k) => { (safe as any)[k] = true; });
    localStorage.setItem(CUSTOM_FEATURES_KEY, JSON.stringify(safe));
  } catch (e) {
    console.warn("[saveCustomFeatures] 保存失败", e);
  }
}

/** 判断某项特性是否为 C 层锁定项（不可关闭） */
export function isLockedFeature(key: string): boolean {
  return LOCKED_FEATURES.has(key);
}

/* ------------------------------------------------------------------ *
 * 自定义档空闲锁定时长（分钟）                                        *
 * ------------------------------------------------------------------ */

/** 归一化自定义空闲锁定时长：非有限数取默认值，超界收敛到边界整数 */
export function normalizeCustomSessionMinutes(minutes: number): number {
  if (!Number.isFinite(minutes)) return CUSTOM_SESSION_MINUTES_DEFAULT;
  return Math.max(
    CUSTOM_SESSION_MINUTES_MIN,
    Math.min(CUSTOM_SESSION_MINUTES_MAX, Math.round(minutes)),
  );
}

/** 读取本地缓存的自定义空闲锁定时长（非法值回退默认值） */
function loadCustomSessionMinutes(): number {
  try {
    const raw = localStorage.getItem(CUSTOM_SESSION_MINUTES_KEY);
    if (raw == null) return CUSTOM_SESSION_MINUTES_DEFAULT;
    return normalizeCustomSessionMinutes(Number(raw));
  } catch {
    return CUSTOM_SESSION_MINUTES_DEFAULT;
  }
}

/** 保存自定义空闲锁定时长到本地缓存（仅在应用成功后调用） */
export function saveCustomSessionMinutes(minutes: number): void {
  try {
    localStorage.setItem(
      CUSTOM_SESSION_MINUTES_KEY,
      String(normalizeCustomSessionMinutes(minutes)),
    );
  } catch (e) {
    console.warn("[saveCustomSessionMinutes] 保存失败", e);
  }
}
