/*
 * key/module-auth.ts — 模块独立密钥认证层
 *
 * 职责：
 *   1. 模块密钥 CRUD（generateModuleKey / setModuleKey / verifyModuleKey / getModuleKey）
 *   2. 模块状态查询（hasModuleKey / isModuleReady / isModuleKeyEnabled / loadModuleKeyStatus）
 *   3. 模块登出（logoutModule）
 *   4. 模块密钥保护开关（setModuleKeyEnabled）
 *
 * ★ 架构优化目标：
 *   - 统一错误契约 — 所有公共函数返回 Promise<VerthysResult<T>>
 *   - CacheCoordinator — 缓存操作由单一协调器管理，消除遗漏风险
 *   - 版本化 + 自愈 — findModuleKeyRecord 返回 version 最大者，发现多条记录触发后台清理
 *   - 增量状态加载 — loadModuleKeyStatus 使用摘要缓存，O(N) → O(1)
 *   - 会话状态原子化 — cacheModuleKey/removeModuleKey 内部原子更新 moduleKeyReady
 *   - 延迟冲刷 — setModuleKey/setModuleKeyEnabled 使用 flushVerthysAsync(false)
 */
import {
  verthysAddRecord, verthysDeleteRecord,
  bytesToBase64,
  encryptPasswordField, decryptPasswordField,
  verthysGetRecord,
} from "../lib/verthys";
import { keyState } from "../state/key_state";
import {
  TYPE_MODULE_KEY, TYPE_MODULE_KEY_CONFIG,
  MODULE_KEY_RECORD_VERSION,
  MODULE_KEY_SELF_HEAL_BATCH,
} from "../constants/key_manager_const";
import {
  serializeModuleKeyRecord, deserializeModuleKeyRecord,
  serializeModuleKeyConfigRecord, deserializeModuleKeyConfigRecord,
  moduleVerifierPlain,
} from "../utils/serialization";
import { scanVerthysRecords } from "../utils/verthys_traversal";
import {
  cacheModuleKey, fetchModuleKey, removeModuleKey,
  ensureRecordScan,
  getSummaryIdsByType,
  getRecordIdsByType,
  getRecordFromScan,
  deleteAndPersist,
  persistVerthys,
} from "../cache/composition/verthys-cache";
import { cacheCoordinator } from "../cache/coordination/cache-coordinator";
import { touchSession } from "../session/security-session";
import type { ModuleId, ModuleKeyRecord, ModuleKeyConfigRecord } from "../types/key_manager";
import { ok, err, errFromUnknown, VerthysErrorCode, type VerthysResult } from "../lib/verthys_error";
import { createLogger } from "../utils/logger";

const log = createLogger("module-auth");

/* ------------------------------------------------------------------ *
 * ★ 企业级根治修复6：模块密钥状态乐观并发控制                          *
 *                                                                    *
 * 原缺陷（"开关直接影响全局"根因）：                                   *
 *   loadModuleKeyStatus 会整体覆盖 keyState.moduleKeyEnabled 全部模块  *
 *   状态。若后台加载（修复4将 loadModuleKeyStatus 移至后台）与用户开关  *
 *   操作并发，时序如下：                                               *
 *     1. initUnlock 后台启动 loadModuleKeyStatus（读取 verthys 旧状态）  *
 *     2. 用户切换某模块开关 → setModuleKeyEnabled 持久化 + 更新状态    *
 *     3. 后台 loadModuleKeyStatus 完成 → 用步骤1读取的旧状态整体覆盖   *
 *        → 用户刚切换的开关被回滚，全部模块状态被还原为旧值            *
 *   此即用户反馈的"开启或关闭密钥存在严重缺陷，直接影响全局"。         *
 *                                                                    *
 * 修复：乐观并发版本号（Optimistic Concurrency Control）              *
 *   - moduleKeyStatusVersion：全局单调递增版本号                       *
 *   - loadModuleKeyStatus 启动时捕获 startVersion，完成后校验：        *
 *       startVersion === moduleKeyStatusVersion → 无并发修改，提交     *
 *       startVersion !== moduleKeyStatusVersion → 有并发修改，丢弃     *
 *   - setModuleKeyEnabled / setModuleKey 在更新状态前递增版本号        *
 *   - 确保后台加载永远不会覆盖用户主动操作的最新状态                   *
 * ------------------------------------------------------------------ */
let moduleKeyStatusVersion = 0;

/* ------------------------------------------------------------------ *
 * verthys 记录查找（版本化 + 自愈清理）                                  *
 *                                                                    *
 * ★ 版本化 + 自愈清理：
 *   findModuleKeyRecord 收集全部同 moduleId 的记录，                 *
 *   返回 version 最大者（即使删除失败导致新旧记录共存，也能正确返回   *
 *   最新记录）。发现多条记录时触发后台自愈清理。                      *
 * ------------------------------------------------------------------ */

/**
 * 通用模块记录查找（用于 config 记录，无版本化需求）。
 */
async function findModuleRecord<T>(
  type: number,
  moduleId: ModuleId,
  deserialize: (b64: string) => T | null,
  matchModule: (rec: T) => boolean,
): Promise<{ id: number; rec: T } | null> {
  try { await ensureRecordScan(); } catch { /* scanVerthysRecords 内部会回退到逐条 IPC */ }
  let result: { id: number; rec: T } | null = null;
  await scanVerthysRecords((entry) => {
    if (entry.type === type) {
      const rec = deserialize(entry.dataB64);
      if (rec && matchModule(rec)) {
        result = { id: entry.id, rec };
        return true; // 找到第一条即停止（config 记录无需版本化）
      }
    }
    return false;
  });
  return result;
}

/**
 * 在 verthys 中查找指定模块的密钥验证器记录
 *
 * ★ 版本化 + 自愈清理
 *
 * 行为：
 *   1. 查找全部同 moduleId 的记录
 *   2. 返回 version 最大者（即使删除失败导致新旧记录共存，也能正确返回最新记录）
 *   3. 若发现多条记录 → 触发后台自愈清理（删除旧版本记录）
 *
 * @param moduleId 模块 ID
 * @returns { id, rec } 或 null
 */
async function findModuleKeyRecord(
  moduleId: ModuleId,
): Promise<{ id: number; rec: ModuleKeyRecord } | null> {
  // 收集全部同 moduleId 的记录（不提前终止）
  const candidates: Array<{ id: number; rec: ModuleKeyRecord }> = [];

  // ★ 优先使用摘要缓存增量加载（O(1) IPC，模块记录极少）
  const keyIds = getSummaryIdsByType(TYPE_MODULE_KEY);
  if (keyIds.length > 0) {
    // 摘要缓存已就绪 → 逐条 verthysGetRecord（常数次 IPC）
    for (const id of keyIds) {
      try {
        const r = await verthysGetRecord(id);
        if (r) {
          const rec = deserializeModuleKeyRecord(r.dataB64);
          if (rec && rec.moduleId === moduleId) {
            candidates.push({ id, rec });
          }
        }
      } catch (e) {
        log.warn(`findModuleKeyRecord: verthysGetRecord(${id}) 失败`, e);
      }
    }
  } else {
    // 摘要缓存未就绪 → 回退到全量扫描
    try { await ensureRecordScan(); } catch { /* */ }
    await scanVerthysRecords((entry) => {
      if (entry.type === TYPE_MODULE_KEY) {
        const rec = deserializeModuleKeyRecord(entry.dataB64);
        if (rec && rec.moduleId === moduleId) {
          candidates.push({ id: entry.id, rec });
        }
      }
      return false; // 不提前终止，收集全部候选
    });
  }

  if (candidates.length === 0) return null;

  // 按 version 降序排序，取最大者
  candidates.sort((a, b) => (b.rec.version ?? 0) - (a.rec.version ?? 0));
  const latest = candidates[0];

  // ★ 自愈：发现多条记录 → 后台清理旧版本
  if (candidates.length > 1) {
    const staleIds = candidates.slice(1).map((c) => c.id);
    log.info(`模块 ${moduleId} 发现 ${candidates.length} 条记录，触发自愈清理: ${staleIds.join(",")}`);
    // 异步清理（不阻塞当前查询）
    selfHealCleanupStaleRecords(staleIds).catch((e) => {
      log.warn(`模块 ${moduleId} 自愈清理失败`, e);
    });
  }

  return latest;
}

/**
 * ★ 自愈清理：删除指定 ID 的旧版本记录
 *
 * 使用 deleteAndPersist 入队（防抖合并 flush），失败不阻塞主流程。
 * 单次最多清理 MODULE_KEY_SELF_HEAL_BATCH 条，防止极端情况阻塞。
 */
async function selfHealCleanupStaleRecords(ids: number[]): Promise<void> {
  const batch = ids.slice(0, MODULE_KEY_SELF_HEAL_BATCH);
  for (const id of batch) {
    try {
      await deleteAndPersist(async () => {
        await verthysDeleteRecord(id);
        return true;
      }, id);
      log.info(`自愈清理：已删除旧记录 ID=${id}`);
    } catch (e) {
      log.warn(`自愈清理：删除记录 ${id} 失败`, e);
    }
  }
}

/**
 * 在 verthys 中查找指定模块的密钥保护开关记录
 *
 * ★ 企业级根治：改用摘要缓存 O(1) 查询替代全量扫描（根治开关操作卡慢）
 *
 * 原缺陷：findModuleKeyConfigRecord 调用 findModuleRecord → ensureRecordScan +
 *   scanVerthysRecords 全量扫描所有记录（含照片块），verthys 有 N 条记录时
 *   耗时 5-20s。用户每次切换模块密钥开关都触发全量扫描 → UI 卡死。
 *
 * 修复：与 findModuleKeyRecord 一致，优先使用 getSummaryIdsByType 摘要缓存
 *   获取 TYPE_MODULE_KEY_CONFIG 记录 ID 列表（常数条，通常 ≤4），逐条
 *   verthysGetRecord 反序列化匹配 moduleId。仅常数次 IPC，<100ms。
 */
async function findModuleKeyConfigRecord(
  moduleId: ModuleId,
): Promise<{ id: number; rec: ModuleKeyConfigRecord } | null> {
  // ★ 优先使用摘要缓存（O(1) IPC，模块配置记录极少）
  const configIds = getSummaryIdsByType(TYPE_MODULE_KEY_CONFIG);
  if (configIds.length > 0) {
    for (const id of configIds) {
      try {
        const r = await verthysGetRecord(id);
        if (r) {
          const rec = deserializeModuleKeyConfigRecord(r.dataB64);
          if (rec && rec.moduleId === moduleId) {
            return { id, rec };
          }
        }
      } catch (e) {
        log.warn(`findModuleKeyConfigRecord: verthysGetRecord(${id}) 失败`, e);
      }
    }
    return null;
  }

  // ★ 回退：摘要缓存未就绪 → 全量扫描（仅极端情况触发）
  try { await ensureRecordScan(); } catch { /* */ }
  let result: { id: number; rec: ModuleKeyConfigRecord } | null = null;
  await scanVerthysRecords((entry) => {
    if (entry.type === TYPE_MODULE_KEY_CONFIG) {
      const rec = deserializeModuleKeyConfigRecord(entry.dataB64);
      if (rec && rec.moduleId === moduleId) {
        result = { id: entry.id, rec };
        return true;
      }
    }
    return false;
  });
  return result;
}

/* ------------------------------------------------------------------ *
 * 模块状态加载（增量加载，O(N) → O(1)）                               *
 * ------------------------------------------------------------------ */

/**
 * 扫描 verthys 中所有模块密钥记录与开关配置，更新 hasModuleKeyRecord 和 moduleKeyEnabled
 *
 * ★ 增量状态加载
 *   不再全量扫描，而是利用摘要缓存 getSummaryIdsByType 快速获取 ID 列表，
 *   然后逐个 verthysGetRecord 获取数据（模块记录极少，仅常数次 IPC）。
 *   若摘要未就绪，回退到原有扫描。将 O(N) 降为 O(1)。
 *
 * @returns VerthysResult<void>
 */
export async function loadModuleKeyStatus(): Promise<VerthysResult<void>> {
  // ★ 捕获启动版本号，用于完成后并发校验
  const startVersion = moduleKeyStatusVersion;
  // ★ 标记后台加载进行中（供模块组件/SecurityCenter 守卫）
  keyState.moduleKeyStatusLoading.value = true;
  try {
    const status: Record<ModuleId, boolean> = { photo: false, accounts: false, certs: false, fileverthys: false };
    // ★ 企业级根治修复：enabled 默认 false（安全默认）
    //
    // 原缺陷：默认 true 意味着"保护开关开启"=所有模块需密钥验证。
    // 当 verthys 中无 TYPE_MODULE_KEY_CONFIG 记录时（用户从未配置过保护开关），
    // enabled 保持 true → 全部模块显示为已开启保护，与用户实际设置不符。
    // 用户反馈"本来我设置两个模块需要密钥验证但是现在全部模块被自动开启了"。
    //
    // 修复：默认 false（无配置记录=不开启保护）。
    // 仅当 verthys 中存在 TYPE_MODULE_KEY_CONFIG 记录且 cfg.enabled=true 时才开启。
    const enabled: Record<ModuleId, boolean> = { photo: false, accounts: false, certs: false, fileverthys: false };

    // ★ 企业级根治修复：主动触发摘要扫描确保缓存就绪
    //
    // 原缺陷：直接调用 getSummaryIdsByType 读取摘要缓存，若摘要扫描未完成
    // （startBackgroundTasks 有 2.5s 延迟），返回空数组 → 回退到全量解密扫描。
    // 模块密钥记录极少（最多 4 条），但回退路径会全量解密所有记录（含照片），
    // 造成 20-30s 延迟。
    //
    // ★ 性能根治：移除冗余 ensureSummaryScan 调用
    //
    // initUnlock/initCreate 在调用 loadModuleKeyStatus 之前已调用 ensureSummaryScan（行 560/353），
    // 此处重复调用浪费 IPC（v1 格式下还会静默失败）。
    // 直接读取 getSummaryIdsByType，若为空则进入 fallback（已由 ensureRecordScan 兜底）。

    // ★ 增量加载：优先使用摘要缓存（O(1) IPC）
    const keyIds = getSummaryIdsByType(TYPE_MODULE_KEY);
    const configIds = getSummaryIdsByType(TYPE_MODULE_KEY_CONFIG);

    if (keyIds.length === 0 && configIds.length === 0) {
      // 摘要缓存未就绪或为空（v1 格式 / 无模块密钥记录）→ 回退到全量扫描
      await loadModuleKeyStatusFallback(status, enabled);
    } else {
      // 摘要缓存已就绪 → 逐条 verthysGetRecord（模块记录极少，常数次 IPC）
      for (const id of keyIds) {
        try {
          const r = await verthysGetRecord(id);
          if (r) {
            const rec = deserializeModuleKeyRecord(r.dataB64);
            if (rec) {
              const mid = rec.moduleId as ModuleId;
              if (mid in status) status[mid] = true;
            }
          }
        } catch (e) {
          log.warn(`loadModuleKeyStatus: verthysGetRecord(${id}) 失败`, e);
        }
      }
      for (const id of configIds) {
        try {
          const r = await verthysGetRecord(id);
          if (r) {
            const cfg = deserializeModuleKeyConfigRecord(r.dataB64);
            if (cfg) {
              const mid = cfg.moduleId as ModuleId;
              if (mid in enabled) enabled[mid] = cfg.enabled;
            }
          }
        } catch (e) {
          log.warn(`loadModuleKeyStatus: verthysGetRecord(${id}) 失败 (config)`, e);
        }
      }
    }

    // ★ 企业级根治修复6：乐观并发提交校验
    //
    // 加载期间若用户切换了任一模块的密钥开关（setModuleKeyEnabled/setModuleKey），
    // moduleKeyStatusVersion 会递增 → startVersion !== moduleKeyStatusVersion。
    // 此时丢弃本次加载结果，避免用旧 verthys 状态覆盖用户最新操作。
    //
    // 典型时序（修复前缺陷）：
    //   T0: 后台 loadModuleKeyStatus 启动（startVersion=0），开始读取 verthys
    //   T1: 用户切换 photo 开关 → setModuleKeyEnabled 递增 version=1 + 更新状态
    //   T2: 后台 loadModuleKeyStatus 完成读取（旧状态 photo=false）
    //   T3: 校验 0 !== 1 → 丢弃，不覆盖 → 用户 photo=true 保留
    if (startVersion !== moduleKeyStatusVersion) {
      log.info(
        `loadModuleKeyStatus: 检测到并发修改（startVersion=${startVersion}, current=${moduleKeyStatusVersion}），丢弃本次加载结果，保留用户最新操作`,
      );
      keyState.moduleKeyStatusLoading.value = false;
      // ★ 安全守卫根治：标记已加载完成（虽丢弃结果，但 setModuleKeyEnabled 已更新状态，状态已知）
      keyState.moduleKeyStatusLoaded.value = true;
      return ok(undefined);
    }

    keyState.hasModuleKeyRecord.value = status;
    keyState.moduleKeyEnabled.value = enabled;
    keyState.moduleKeyStatusLoading.value = false;
    // ★ 安全守卫根治：标记已加载完成（switchModule 守卫据此放行/拦截）
    keyState.moduleKeyStatusLoaded.value = true;
    return ok(undefined);
  } catch (e) {
    log.error("loadModuleKeyStatus 失败", e);
    keyState.moduleKeyStatusLoading.value = false;
    return errFromUnknown(e, VerthysErrorCode.E_INIT_FAILED);
  }
}

/** 回退路径：摘要缓存未就绪时复用 ensureRecordScan 缓存（消除重复全量枚举）
 *
 * ★ 性能根治：复用 ensureRecordScan 缓存，替代直接 verthysEnumerateRecords
 *
 * 原缺陷：
 *   loadModuleKeyStatusFallback 直接调用 verthysEnumerateRecords(1) 全量枚举，
 *   结果不缓存。模块组件挂载时又调用 ensureRecordScanSafe() → ensureRecordScan()
 *   → v1 fallback → verthysEnumerateRecords(1)，重复全量枚举，加剧 worker 争抢。
 *
 * 修复：
 *   1. 调用 ensureRecordScan()（v1 fallback 到 verthysEnumerateRecords，结果缓存到 recordScanCache）
 *   2. 用 getRecordIdsByType(TYPE_MODULE_KEY/TYPE_MODULE_KEY_CONFIG) 查询 ID（零 IPC，O(1) 索引）
 *   3. 用 getRecordFromScan(id) 读取数据（零 IPC，从缓存读取）
 *   4. 全量枚举只执行一次，结果被模块组件的 ensureRecordScanSafe() 复用（scanInProgress 去重）
 *
 * 收益：消除 loadModuleKeyStatus 与模块组件的重复全量枚举，worker 通道争抢减半。 */
async function loadModuleKeyStatusFallback(
  status: Record<ModuleId, boolean>,
  enabled: Record<ModuleId, boolean>,
): Promise<void> {
  // ★ 复用 ensureRecordScan 缓存：全量枚举只执行一次，结果供模块组件复用
  try { await ensureRecordScan(); } catch { /* ensureRecordScan 内部已回退兜底 */ }

  // 从扫描缓存按类型查询 ID（零 IPC，O(1) 索引查询）
  const keyIds = getRecordIdsByType(TYPE_MODULE_KEY);
  for (const id of keyIds) {
    const entry = getRecordFromScan(id);
    if (entry?.dataB64) {
      const rec = deserializeModuleKeyRecord(entry.dataB64);
      if (rec) {
        const mid = rec.moduleId as ModuleId;
        if (mid in status) status[mid] = true;
      }
    }
  }

  const configIds = getRecordIdsByType(TYPE_MODULE_KEY_CONFIG);
  for (const id of configIds) {
    const entry = getRecordFromScan(id);
    if (entry?.dataB64) {
      const cfg = deserializeModuleKeyConfigRecord(entry.dataB64);
      if (cfg) {
        const mid = cfg.moduleId as ModuleId;
        if (mid in enabled) enabled[mid] = cfg.enabled;
      }
    }
  }
}

/* ------------------------------------------------------------------ *
 * 模块密钥保护开关                                                    *
 * ------------------------------------------------------------------ */

/**
 * 设置模块密钥保护开关（持久化到 verthys）。
 *
 * ★ 返回 VerthysResult<void>
 * ★ 通过 CacheCoordinator 统一同步缓存
 * ★ 使用 flushVerthysAsync(false) 延迟冲刷
 *
 * 写入顺序：先添加新记录，成功后再删除旧记录（先添后删）。
 *
 * @returns VerthysResult<void>
 */
export async function setModuleKeyEnabled(moduleId: ModuleId, enabled: boolean): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  const rec: ModuleKeyConfigRecord = { moduleId, enabled };
  const dataB64 = serializeModuleKeyConfigRecord(rec);

  // 1. 先查找旧记录
  const existing = await findModuleKeyConfigRecord(moduleId);

  // 2. 先添加新记录
  const name = `module-key-config-${moduleId}`;
  const id = await verthysAddRecord(TYPE_MODULE_KEY_CONFIG, name, dataB64);
  if (id === null) {
    return err(VerthysErrorCode.E_MODULE_CONFIG_SAVE_FAILED, "写入 verthys 失败");
  }

  // ★ 通过 CacheCoordinator 统一同步缓存（消除手动调用遗漏风险）
  cacheCoordinator.addRecord({
    id, type: TYPE_MODULE_KEY_CONFIG, name, dataB64, dataSize: dataB64.length,
  });

  // 3. 添加成功后再删除旧记录
  if (existing) {
    await verthysDeleteRecord(existing.id);
    cacheCoordinator.removeRecord(existing.id);
  }

  // ★ 企业级根治修复：await persistVerthys 替代 void persistVerthys（根治持久化丢失）
  //
  // 原缺陷：void persistVerthys() 火并忘，写入 worker 内存后不等待落盘。
  // 若用户快速操作或应用退出，flush 未完成 → 磁盘无新配置 → 下次解锁"设置被遗忘"。
  // 用户反馈"原先verthys文件的设置和内容被直接忘记了"。
  //
  // 修复：await persistVerthys() 确保落盘完成后再返回成功。
  // 模块密钥配置是低频操作（用户手动切换开关），await 的延迟可接受。
  // persistVerthys 内部通过 flushChain 串行执行，不会并发竞态。
  const flushOk = await persistVerthys();
  if (!flushOk) {
    log.error(`setModuleKeyEnabled: 模块 ${moduleId} 配置落盘失败`);
    return err(VerthysErrorCode.E_MODULE_CONFIG_SAVE_FAILED, "配置落盘失败，请重试");
  }

  // 更新状态（数据已确认落盘）
  // ★ 递增版本号，使进行中的 loadModuleKeyStatus 丢弃其旧结果
  //   杜绝后台加载用旧 verthys 状态覆盖用户刚切换的开关（"开关直接影响全局"根因）
  moduleKeyStatusVersion++;
  keyState.moduleKeyEnabled.value = { ...keyState.moduleKeyEnabled.value, [moduleId]: enabled };
  log.info(`模块 ${moduleId} 保护开关已${enabled ? "开启" : "关闭"}`);
  return ok(undefined);
}

/** 查询模块密钥保护是否开启
 *
 * ★ 企业级根治修复：兜底默认 false（与 key_state 初始化默认一致）
 *
 * 原缺陷：兜底 true，当 moduleKeyEnabled 未被 loadModuleKeyStatus 正确填充时，
 * 任何模块查询都返回 true（保护开启），导致"全部模块被自动开启密钥"。
 */
export function isModuleKeyEnabled(moduleId: ModuleId): boolean {
  return keyState.moduleKeyEnabled.value[moduleId] ?? false;
}

/* ------------------------------------------------------------------ *
 * 模块密钥 CRUD                                                       *
 * ------------------------------------------------------------------ */

/** 生成随机模块密钥（32 字节 base64） */
export function generateModuleKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64(bytes);
}

/**
 * 设置模块独立密钥（首次设置或修改）
 *
 * ★ 返回 VerthysResult<void>
 * ★ 通过 CacheCoordinator 统一同步缓存
 * ★ 版本递增（每次 setModuleKey 递增 version）
 * ★ 使用 flushVerthysAsync(false) 延迟冲刷
 *
 * 写入顺序：先添加新记录（带递增 version），成功后再删除旧记录。
 *
 * @returns VerthysResult<void>
 */
export async function setModuleKey(moduleId: ModuleId, key: string): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  // 1. 用模块密钥加密验证器明文
  const plain = moduleVerifierPlain(moduleId);
  let verifierB64: string;
  try {
    verifierB64 = await encryptPasswordField(plain, key);
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_KEY_SET_FAILED);
  }

  // 2. 查找旧记录（用于版本号递增 + 后续删除）
  const existing = await findModuleKeyRecord(moduleId);
  // ★ 版本递增
  const newVersion = (existing?.rec.version ?? 0) + 1;

  // 3. 构造记录（带 version）
  const rec: ModuleKeyRecord = {
    moduleId,
    verifierB64,
    version: newVersion,
  };
  const dataB64 = serializeModuleKeyRecord(rec);

  // 4. 先添加新记录
  const name = `module-key-${moduleId}`;
  const id = await verthysAddRecord(TYPE_MODULE_KEY, name, dataB64);
  if (id === null) {
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "写入 verthys 失败");
  }

  // ★ 通过 CacheCoordinator 统一同步缓存
  cacheCoordinator.addRecord({
    id, type: TYPE_MODULE_KEY, name, dataB64, dataSize: dataB64.length,
  });

  // 5. 删除旧记录（先添后删）
  if (existing) {
    await verthysDeleteRecord(existing.id);
    cacheCoordinator.removeRecord(existing.id);
  }

  // ★ 企业级根治修复：await persistVerthys 替代 void persistVerthys（根治持久化丢失）
  //
  // 原缺陷：void persistVerthys() 火并忘，写入 worker 内存后不等待落盘。
  // 若用户快速操作或应用退出，flush 未完成 → 磁盘无新密钥记录 → 下次解锁"密钥验证完全无效"。
  // 用户反馈"原先的密钥验证完全无效"。
  //
  // 修复：await persistVerthys() 确保落盘完成后再返回成功。
  // 模块密钥设置是低频关键操作，await 的延迟可接受且必须保证持久化。
  const flushOk = await persistVerthys();
  if (!flushOk) {
    log.error(`setModuleKey: 模块 ${moduleId} 密钥记录落盘失败`);
    return err(VerthysErrorCode.E_MODULE_KEY_SET_FAILED, "密钥落盘失败，请重试");
  }

  // 6. 更新状态（数据已确认落盘）
  // ★ 递增版本号，使进行中的 loadModuleKeyStatus 丢弃其旧结果
  //   杜绝后台加载用旧 verthys 状态覆盖用户刚设置的模块密钥记录状态
  moduleKeyStatusVersion++;
  keyState.hasModuleKeyRecord.value = { ...keyState.hasModuleKeyRecord.value, [moduleId]: true };
  log.info(`模块 ${moduleId} 密钥已设置 (version=${newVersion})`);
  return ok(undefined);
}

/**
 * 验证模块独立密钥（模块登录时调用）
 *
 * ★ 返回 VerthysResult<void>
 * ★ cacheModuleKey 内部原子地设置 moduleKeyReady=true
 *
 * @returns VerthysResult<void>
 */
export async function verifyModuleKey(moduleId: ModuleId, key: string): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  const found = await findModuleKeyRecord(moduleId);
  if (!found) {
    return err(VerthysErrorCode.E_MODULE_KEY_NOT_FOUND, "模块密钥未设置");
  }

  try {
    const plain = await decryptPasswordField(found.rec.verifierB64, key);
    if (plain !== moduleVerifierPlain(moduleId)) {
      return err(VerthysErrorCode.E_MODULE_VERIFY_FAILED, "原独立密钥验证失败");
    }
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_MODULE_VERIFY_FAILED);
  }

  // ★ cacheModuleKey 内部原子地设置 moduleKeyReady=true
  //   消除「先缓存密钥后置状态」的不一致窗口
  cacheModuleKey(moduleId, key);
  touchSession();
  log.info(`模块 ${moduleId} 验证成功`);
  return ok(undefined);
}

/**
 * 获取会话中缓存的模块密钥（模块内加密/解密数据时调用）
 * @returns 模块密钥字符串，若未登录返回 null
 */
export function getModuleKey(moduleId: ModuleId): string | null {
  if (!keyState.moduleKeyReady.value[moduleId]) return null;
  return fetchModuleKey(moduleId);
}

/** 检查模块是否已设置独立密钥（持久化在 verthys 中） */
export function hasModuleKey(moduleId: ModuleId): boolean {
  return keyState.hasModuleKeyRecord.value[moduleId] ?? false;
}

/** 检查模块是否已登录（会话中密钥已验证） */
export function isModuleReady(moduleId: ModuleId): boolean {
  return keyState.moduleKeyReady.value[moduleId] ?? false;
}

/**
 * 登出模块（清除会话密钥缓存，不影响持久化记录）
 *
 * ★ 会话状态原子化
 *   removeModuleKey 内部原子地同时清空密钥字节 + 置 moduleKeyReady=false，
 *   消除「先清缓存再置状态」的不一致窗口。
 */
export function logoutModule(moduleId: ModuleId): void {
  removeModuleKey(moduleId); // 内部原子地清空 key + 置 ready=false
  log.info(`模块 ${moduleId} 已登出`);
}
