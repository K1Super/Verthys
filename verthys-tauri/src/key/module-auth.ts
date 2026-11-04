/*
 * key/module-auth.ts — 模块 M1 保护层（C 层 v4 模块状态机的前端投影）
 *
 * 职责：
 *   1. 模块保护生命周期（setModuleKey / disableModuleProtection）
 *      —— 启用/轮换/关闭全部由 C 层事务完成，前端不保存任何密钥材料。
 *   2. 模块登录（verifyModuleKey / logoutModule）
 *      —— 口令一次性交给 C 层解封 MDEK user 槽，本层只登记会话就绪标志。
 *   3. 模块状态查询（hasModuleKey / isModuleReady / isModuleKeyEnabled /
 *      loadModuleKeyStatus）——权威来源是 C 层 `v4_module_status`，
 *      不再读写 verthys 内的 v3 校验器/开关记录。
 *
 * 语义：
 *   - 启用保护 = `v4_module_enable`：MDEK 从 Keyring 移入 user/device 槽，
 *     并单事务重写该模块的全部记录/分片；不是"写一条校验记录"。
 *   - 关闭保护 = `v4_module_disable`：保留 MDEK 与数据，MDEK 回到 Keyring；
 *     必须提供模块口令，口令正确性由 C 层判定。
 *   - 修改口令 = `v4_module_rotate_password`：只重封 user 槽，不重写数据。
 *   - 模块未启用时内容路径不需要口令（MDEK 在 Keyring），解锁为幂等空操作。
 *
 * 并发：模块状态加载与用户开关存在竞态，loadModuleKeyStatus 以版本号
 * 提交（乐观并发）：加载期间发生任何保护变更，本次加载结果整体丢弃，
 * 绝不用旧状态覆盖用户刚完成的操作。
 */
import { keyState } from "../state/key_state";
import { MODULE_CACHE_KEY, MODULE_IDS } from "../constants/key_manager_const";
import {
  clearModuleCache,
  clearRecordScanCache,
  markModuleReady,
  removeModuleKey,
} from "../cache/composition/verthys-cache";
import { touchSession } from "../session/security-session";
import {
  verthysModuleKeyUnlock,
  verthysV4ModuleBindRecovery,
  verthysV4ModuleDisable,
  verthysV4ModuleEnable,
  verthysV4ModuleResealDevice,
  verthysV4ModuleRotatePassword,
  verthysV4ModuleStatus,
  type VerthysResponse,
} from "../lib/verthys";
import type { ModuleId } from "../types/key_manager";
import {
  ok,
  err,
  errFromUnknown,
  VerthysErrorCode,
  type VerthysResult,
} from "../lib/verthys_error";
import { createLogger } from "../utils/logger";
import { bytesToBase64 } from "../utils/binary_codec";

const log = createLogger("module-auth");

/* ------------------------------------------------------------------ *
 * 模块索引与状态                                                      *
 * ------------------------------------------------------------------ */

/** 前端模块 ID → C 层模块索引（0=photo，1=accounts，2=fileverthys） */
const MODULE_INDEX: Record<ModuleId, number> = {
  photo: 0,
  accounts: 1,
  fileverthys: 2,
};

/** worker 错误码：认证失败（口令错误或数据校验未通过） */
const WORKER_ERR_AUTH = "ERR_00000002";
/** worker 错误码：加密库锁定或模块未解锁 */
const WORKER_ERR_LOCKED = "ERR_00000007";
/** worker 错误码：策略拒绝（如非恢复会话重密封设备槽） */
const WORKER_ERR_POLICY = "ERR_00000017";

/**
 * 模块密文状态变化后的缓存失效。
 *
 * M1 保护的记录在模块锁定期间不可读：扫描若在锁定窗口内执行会部分失败并
 * 记住已扫到的最大 ID；解锁/重写/关闭后必须从零重扫，否则失败区段之后的
 * 记录会被增量游标永久跳过。模块列表缓存里的密文也会随重写/清除失效。
 */
function invalidateModuleCaches(moduleId: ModuleId, dropModuleList: boolean): void {
  clearRecordScanCache();
  if (dropModuleList) {
    clearModuleCache(MODULE_CACHE_KEY[moduleId]);
  }
}

/** 模块状态快照（C 层权威值） */
interface ModuleStatus {
  /** M1 保护是否启用（已删除模块恒为 false） */
  enabled: boolean;
  /** 本会话 MDEK 是否已解锁 */
  unlocked: boolean;
  /** 模块是否已被删除（数据叶已清除） */
  deleted: boolean;
  /** 是否已绑定恢复槽 */
  hasRecovery: boolean;
}

/**
 * 模块状态加载版本号（乐观并发控制）
 *
 * 加载开始时捕获 startVersion，完成后校验：期间发生 setModuleKey /
 * disableModuleProtection / verifyModuleKey → 版本递增 → 丢弃本次结果。
 */
let moduleKeyStatusVersion = 0;

/* ------------------------------------------------------------------ *
 * 状态加载                                                            *
 * ------------------------------------------------------------------ */

/** 解析单模块状态响应；失败返回 null（调用方按 fail-closed 处理） */
function parseStatus(resp: VerthysResponse): ModuleStatus | null {
  if (!resp.ok) return null;
  const deleted = resp.deleted === true;
  const enabled = resp.enabled === true && !deleted;
  return {
    enabled,
    unlocked: enabled && resp.unlocked === true,
    deleted,
    hasRecovery: enabled && resp.has_recovery === true,
  };
}

/**
 * 从 C 层加载全部模块的 M1 状态，更新 hasModuleKeyRecord / moduleKeyEnabled /
 * moduleKeyReady。
 *
 * 任一模块查询失败即整体失败（fail-closed）：不把"查询失败"降级为
 * "保护关闭"，否则守卫会直接放行未验证的模块入口。
 */
export async function loadModuleKeyStatus(): Promise<VerthysResult<void>> {
  const startVersion = moduleKeyStatusVersion;
  keyState.moduleKeyStatusLoading.value = true;
  keyState.moduleKeyStatusFailed.value = false;
  try {
    const hasRecord: Record<ModuleId, boolean> = { photo: false, accounts: false, fileverthys: false };
    const enabled: Record<ModuleId, boolean> = { photo: false, accounts: false, fileverthys: false };
    const ready: Record<ModuleId, boolean> = { photo: false, accounts: false, fileverthys: false };
    const hasRecovery: Record<ModuleId, boolean> = { photo: false, accounts: false, fileverthys: false };

    for (const moduleId of MODULE_IDS) {
      const resp = await verthysV4ModuleStatus(MODULE_INDEX[moduleId]);
      const status = parseStatus(resp);
      if (!status) {
        throw new Error(resp.error ?? "模块状态查询失败");
      }
      hasRecord[moduleId] = status.enabled;
      enabled[moduleId] = status.enabled;
      hasRecovery[moduleId] = status.hasRecovery;
      /* ready 的语义是“内容路径可用”：未启用模块的 MDEK 在 Keyring，
       * 不需要口令即可加解密；启用模块必须已解锁 user 槽；已删除模块
       * 数据叶已清除，任何情况下都不标记可用。 */
      ready[moduleId] = status.deleted
        ? false
        : status.enabled
          ? status.unlocked
          : true;
    }

    if (startVersion !== moduleKeyStatusVersion) {
      log.info(
        `loadModuleKeyStatus: 检测到并发保护变更（start=${startVersion}, current=${moduleKeyStatusVersion}），丢弃本次加载结果`,
      );
      keyState.moduleKeyStatusLoading.value = false;
      keyState.moduleKeyStatusLoaded.value = true;
      keyState.moduleKeyStatusFailed.value = false;
      return ok(undefined);
    }

    keyState.hasModuleKeyRecord.value = hasRecord;
    keyState.moduleKeyEnabled.value = enabled;
    keyState.moduleHasRecovery.value = hasRecovery;
    keyState.moduleKeyReady.value = ready;
    keyState.moduleKeyStatusLoading.value = false;
    keyState.moduleKeyStatusLoaded.value = true;
    keyState.moduleKeyStatusFailed.value = false;
    return ok(undefined);
  } catch (e) {
    log.error("loadModuleKeyStatus 失败", e);
    keyState.moduleKeyStatusLoading.value = false;
    /* 失败不等于"无保护"：loaded 保持 false（fail-closed），并置 failed
     * 供守卫跳过超时等待、直接要求口令验证。 */
    keyState.moduleKeyStatusLoaded.value = false;
    keyState.moduleKeyStatusFailed.value = true;
    return errFromUnknown(e, VerthysErrorCode.E_INIT_FAILED);
  }
}

/* ------------------------------------------------------------------ *
 * 错误映射                                                            *
 * ------------------------------------------------------------------ */

/** 把 worker/C 层失败响应映射为结构化错误；错误码不做文案匹配 */
function moduleFailure(
  resp: VerthysResponse,
  action: string,
  fallback: VerthysErrorCode,
): VerthysResult<never> {
  const code = resp.error_code ?? resp.error ?? "";
  if (code === WORKER_ERR_LOCKED) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, `${action}失败：加密库或模块已锁定`);
  }
  if (code === WORKER_ERR_AUTH) {
    return err(VerthysErrorCode.E_MODULE_VERIFY_FAILED, `${action}失败：口令不正确或数据校验未通过`);
  }
  if (code === WORKER_ERR_POLICY) {
    return err(VerthysErrorCode.E_MODULE_POLICY, `${action}失败：当前会话或模块状态不允许该操作`);
  }
  return err(fallback, `${action}失败（${code || "未知错误"}）`);
}

/* ------------------------------------------------------------------ *
 * 模块口令与保护开关                                                  *
 * ------------------------------------------------------------------ */

/** 生成随机模块口令（32 字节 base64；与用户自设口令等价，仅含可见 ASCII） */
export function generateModuleKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64(bytes);
}

/** 查询模块保护是否开启（C 层状态缓存） */
export function isModuleKeyEnabled(moduleId: ModuleId): boolean {
  return keyState.moduleKeyEnabled.value[moduleId] ?? false;
}

/** 检查模块是否已启用保护（等价于 v4 enabled） */
export function hasModuleKey(moduleId: ModuleId): boolean {
  return keyState.hasModuleKeyRecord.value[moduleId] ?? false;
}

/** 检查模块是否已登录（本会话 MDEK 已解锁） */
export function isModuleReady(moduleId: ModuleId): boolean {
  return keyState.moduleKeyReady.value[moduleId] ?? false;
}

/**
 * 设置/修改模块口令，并启用模块保护。
 *
 * - 未启用：`v4_module_enable`（MDEK 移出 Keyring + 单事务重写模块数据）
 * - 已启用：`v4_module_rotate_password`（必须提供 oldKey，只重封 user 槽）
 *
 * 成功后 C 层保持该模块解锁（MDEK 已在会话内），因此同步登记 ready。
 */
export async function setModuleKey(
  moduleId: ModuleId,
  key: string,
  oldKey?: string,
  recoveryCode?: string,
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  if (!key) {
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "模块口令不能为空");
  }
  const index = MODULE_INDEX[moduleId];
  const rotating = isModuleKeyEnabled(moduleId);
  if (rotating && !oldKey) {
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "修改模块口令必须提供原口令");
  }

  try {
    const resp = rotating
      ? await verthysV4ModuleRotatePassword(index, oldKey as string, key)
      : recoveryCode
        ? await verthysV4ModuleEnable(index, key, recoveryCode)
        : await verthysV4ModuleEnable(index, key);
    if (!resp.ok) {
      return moduleFailure(
        resp,
        rotating ? "轮换模块口令" : "启用模块保护",
        VerthysErrorCode.E_MODULE_KEY_SET_FAILED,
      );
    }

    moduleKeyStatusVersion++;
    keyState.hasModuleKeyRecord.value = { ...keyState.hasModuleKeyRecord.value, [moduleId]: true };
    keyState.moduleKeyEnabled.value = { ...keyState.moduleKeyEnabled.value, [moduleId]: true };
    keyState.moduleHasRecovery.value = {
      ...keyState.moduleHasRecovery.value,
      [moduleId]: resp.has_recovery === true,
    };
    keyState.moduleKeyReady.value = { ...keyState.moduleKeyReady.value, [moduleId]: true };
    /* 启用会在 C 层重写该模块全部记录（密文与 ID 可能变化）：列表缓存与
     * 增量扫描游标都必须从零重建；轮换口令不改写数据，只需保留列表缓存。 */
    invalidateModuleCaches(moduleId, !rotating);
    touchSession();
    log.info(`模块 ${moduleId} 保护已${rotating ? "轮换口令" : "启用"}`);
    return ok(undefined);
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_KEY_SET_FAILED);
  }
}

/**
 * 验证模块口令（模块登录入口）。
 *
 * 保护未启用时无口令可验：返回成功但不登记 ready（内容路径不依赖口令）。
 * 已启用时由 C 层解封 user 槽；认证失败统一映射为 E_MODULE_VERIFY_FAILED。
 */
export async function verifyModuleKey(
  moduleId: ModuleId,
  key: string,
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  if (!isModuleKeyEnabled(moduleId)) {
    return ok(undefined);
  }
  if (!key) {
    return err(VerthysErrorCode.E_MODULE_VERIFY_FAILED, "请输入模块口令");
  }

  try {
    const resp = await verthysModuleKeyUnlock(moduleId, key);
    if (!resp.ok) {
      return moduleFailure(resp, "验证模块口令", VerthysErrorCode.E_MODULE_VERIFY_FAILED);
    }
    markModuleReady(moduleId);
    /* 解锁前扫描可能因模块锁定只完成了一部分；清缓存让下一次扫描从零覆盖。 */
    invalidateModuleCaches(moduleId, false);
    touchSession();
    log.info(`模块 ${moduleId} 口令验证成功`);
    return ok(undefined);
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_VERIFY_FAILED);
  }
}

/**
 * 关闭模块保护：必须提供当前模块口令，口令正确性由 C 层判定。
 *
 * 关闭保留 MDEK 与全部数据（MDEK 回到 Keyring），不会删除内容；
 * 需要删除数据请使用模块删除（不可逆）。
 */
export async function disableModuleProtection(
  moduleId: ModuleId,
  password: string,
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  if (!password) {
    return err(VerthysErrorCode.E_MODULE_VERIFY_FAILED, "请输入模块口令");
  }

  try {
    const resp = await verthysV4ModuleDisable(MODULE_INDEX[moduleId], password);
    if (!resp.ok) {
      return moduleFailure(resp, "关闭模块保护", VerthysErrorCode.E_MODULE_VERIFY_FAILED);
    }
    moduleKeyStatusVersion++;
    keyState.hasModuleKeyRecord.value = { ...keyState.hasModuleKeyRecord.value, [moduleId]: false };
    keyState.moduleKeyEnabled.value = { ...keyState.moduleKeyEnabled.value, [moduleId]: false };
    keyState.moduleHasRecovery.value = { ...keyState.moduleHasRecovery.value, [moduleId]: false };
    /* removeModuleKey 原子清空会话就绪标志并联动 C 层锁定该模块缓存；
     * 关闭保护后 MDEK 已回 Keyring，内容路径无需口令，ready 立即恢复为可用。 */
    removeModuleKey(moduleId);
    keyState.moduleKeyReady.value = { ...keyState.moduleKeyReady.value, [moduleId]: true };
    invalidateModuleCaches(moduleId, false);
    touchSession();
    log.info(`模块 ${moduleId} 保护已关闭（数据保留）`);
    return ok(undefined);
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_VERIFY_FAILED);
  }
}

/**
 * 绑定模块恢复槽：模块口令解封 share，容器恢复码包裹 device share。
 *
 * 绑定后该模块可在换机时用同一恢复码替代设备因子（仍需模块口令）。
 * 绑定不重写记录/分片，但会解锁该模块，故仍需清一次扫描缓存。
 */
export async function bindModuleRecovery(
  moduleId: ModuleId,
  password: string,
  recoveryCode: string,
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  if (!isModuleKeyEnabled(moduleId)) {
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "模块保护未启用，无法绑定恢复槽");
  }
  if (!password) {
    return err(VerthysErrorCode.E_MODULE_VERIFY_FAILED, "请输入模块口令");
  }
  const code = recoveryCode.trim();
  if (!code) {
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "请输入容器恢复码");
  }

  try {
    const resp = await verthysV4ModuleBindRecovery(MODULE_INDEX[moduleId], password, code);
    if (!resp.ok) {
      return moduleFailure(resp, "绑定模块恢复槽", VerthysErrorCode.E_MODULE_KEY_SET_FAILED);
    }
    moduleKeyStatusVersion++;
    keyState.moduleHasRecovery.value = {
      ...keyState.moduleHasRecovery.value,
      [moduleId]: true,
    };
    keyState.moduleKeyReady.value = { ...keyState.moduleKeyReady.value, [moduleId]: true };
    invalidateModuleCaches(moduleId, false);
    touchSession();
    log.info(`模块 ${moduleId} 恢复槽已绑定`);
    return ok(undefined);
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_KEY_SET_FAILED);
  }
}

/**
 * 换机后重密封模块设备槽。
 *
 * 只有恢复码解锁的会话能通过 C 层策略；普通会话调用返回策略拒绝，
 * 由 UI 明确提示"请先用恢复码解锁"。
 */
export async function resealModuleDevice(
  moduleId: ModuleId,
  password: string,
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  if (!isModuleKeyEnabled(moduleId)) {
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "模块保护未启用，无法重密封设备槽");
  }
  if (!password) {
    return err(VerthysErrorCode.E_MODULE_VERIFY_FAILED, "请输入模块口令");
  }

  try {
    const resp = await verthysV4ModuleResealDevice(MODULE_INDEX[moduleId], password);
    if (!resp.ok) {
      return moduleFailure(resp, "重密封模块设备槽", VerthysErrorCode.E_MODULE_KEY_SET_FAILED);
    }
    moduleKeyStatusVersion++;
    keyState.moduleKeyReady.value = { ...keyState.moduleKeyReady.value, [moduleId]: true };
    invalidateModuleCaches(moduleId, false);
    touchSession();
    log.info(`模块 ${moduleId} 设备槽已重密封`);
    return ok(undefined);
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_KEY_SET_FAILED);
  }
}

/**
 * 登出模块：清除会话就绪状态并锁定 C 层模块缓存。
 *
 * 不影响持久化的模块口令与数据；再次进入时需重新验证口令。
 */
export function logoutModule(moduleId: ModuleId): void {
  /* removeModuleKey 原子清空会话就绪标志并联动 C 层锁定该模块。 */
  removeModuleKey(moduleId);
  log.info(`模块 ${moduleId} 已登出`);
}
