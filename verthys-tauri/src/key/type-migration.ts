/*
 * key/type-migration.ts — Verthys 记录类型冲突迁移引擎
 *
 * ★★★ 企业级根治：TYPE 常量冲突数据迁移 ★★★
 *
 * 背景：
 *   原 TYPE_GLOBAL_KEY (0x10) 与 TYPE_ACCOUNT (0x10) 值相同，导致已存储的
 *   verthys 文件中全局密钥记录与账户记录共享同一类型值，无法区分。
 *   同理 TYPE_PHOTO_CHUNK (0x05) 与旧 TYPE_META (FileVerthys 0x05) 冲突。
 *
 * 迁移策略（内容嗅探 + 先添后删）：
 *   1. 扫描所有 type=0x10 的记录：
 *      - 尝试 JSON 反序列化为 AccountFields（含 platform/username 字段）
 *      - 成功 → 识别为账户记录 → 重写为 TYPE_ACCOUNT (0x02)
 *      - 失败 → 识别为全局密钥记录（二进制格式）→ 保持 0x10 不变
 *   2. 扫描所有 type=0x05 的记录：
 *      - 尝试 JSON 反序列化为 FileVerthys 元数据（含 name/mime/chunkDataB64 字段）
 *      - 成功 → 识别为文件元数据 → 重写为 TYPE_FILEVERTHYS_META (0x08)
 *      - 失败 → 识别为照片数据块（二进制密文）→ 保持 0x05 不变
 *
 * 安全保证：
 *   - 先添后删：先 verthysAddRecord 新记录，成功后再 verthysDeleteRecord 旧记录
 *   - 幂等性：已迁移记录的新类型（0x02/0x08）不会被 getSummaryIdsByType(0x10/0x05) 查到
 *   - 落盘保证：迁移完成后 await persistVerthys() 确保数据写入磁盘
 *   - 缓存一致：通过 cacheCoordinator 原子更新三层缓存（摘要/扫描/全量）
 *   - LID 引用安全：FileVerthys 元数据的 chunkIds 引用数据块 LID，数据块类型值
 *     (0x04) 不变，迁移元数据不影响 chunkIds 引用有效性
 *   - 错误隔离：单条迁移失败不阻断其他记录，记录错误日志后继续
 *
 * 调用时机：
 *   initUnlock 中 ensureSummaryScan 之后、loadModuleKeyStatus 之前执行。
 *   确保模块加载前所有记录类型已正确，避免误拾/漏拾。
 */
import {
  verthysAddRecord,
  verthysDeleteRecord,
  base64ToBytes,
} from "../lib/verthys";
import {
  getSummaryIdsByType,
  getSummaryRecord,
  getFullRecord,
  persistVerthys,
} from "../cache/composition/verthys-cache";
import { cacheCoordinator } from "../cache/coordination/cache-coordinator";
import {
  TYPE_ACCOUNT,
  TYPE_FILEVERTHYS_META,
  TYPE_ACCOUNT_OLD,
  TYPE_FILEVERTHYS_META_OLD,
} from "../constants/record_types";
import { withTimeout } from "../utils/promise_utils";
import { createLogger } from "../utils/logger";

const log = createLogger("type-migration");

/** 迁移结果统计 */
export interface MigrationResult {
  /** 成功迁移的记录数 */
  migrated: number;
  /** 识别为无需迁移（保持原类型）的记录数 */
  skipped: number;
  /** 迁移失败的记录数 */
  errors: number;
}

/* ------------------------------------------------------------------ *
 * 内容嗅探：区分冲突类型的记录                                       *
 *                                                                    *
 * 原理：JSON 记录可通过 base64→UTF-8→JSON.parse 成功解析并包含特定   *
 *       结构字段；二进制记录（全局密钥/照片密文）JSON.parse 必失败。  *
 * ------------------------------------------------------------------ */

/**
 * 判断 dataB64 是否为账户记录（AccountFields JSON）
 *
 * AccountFields 结构：{ platform, username, password, note, ... }
 * 全局密钥记录为二进制格式，JSON.parse 必然失败。
 *
 * ★ 企业级根治：导出供 initUnlock 校验缓存的全局密钥记录
 *
 * 用途：worker 内联 probe 在迁移前搜 0x10 记录，可能误拾旧账户记录（同为 0x10）
 * 并将其作为 global_key_record 缓存。迁移后需用本函数嗅探缓存值——若为账户记录
 * 说明 probe 命中了错误记录，必须重新 findGlobalKeyRecord 获取真正的全局密钥。
 */
export function isAccountRecordB64(dataB64: string): boolean {
  try {
    const json = new TextDecoder().decode(base64ToBytes(dataB64));
    const obj = JSON.parse(json);
    return (
      typeof obj === "object" && obj !== null &&
      typeof obj.platform === "string" &&
      typeof obj.username === "string"
    );
  } catch {
    return false;
  }
}

/**
 * 判断 dataB64 是否为 FileVerthys 元数据记录（JSON）
 *
 * FileVerthys meta 结构：{ name, size, mime, chunkDataB64/chunkIds, ... }
 * 照片数据块为 XChaCha20-Poly1305 密文，JSON.parse 必然失败。
 */
function isFileVerthysMetaRecord(dataB64: string): boolean {
  try {
    const json = new TextDecoder().decode(base64ToBytes(dataB64));
    const obj = JSON.parse(json);
    return (
      typeof obj === "object" && obj !== null &&
      typeof obj.name === "string" &&
      typeof obj.mime === "string" &&
      (Array.isArray(obj.chunkDataB64) || Array.isArray(obj.chunkIds))
    );
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ *
 * 单条记录迁移（先添后删 + 缓存同步）                                *
 * ------------------------------------------------------------------ */

/**
 * 将单条记录从旧类型迁移到新类型
 *
 * 流程：
 *   1. verthysAddRecord(newType, name, dataB64) — 写入新记录
 *   2. verthysDeleteRecord(oldId) — 删除旧记录
 *   3. cacheCoordinator.removeRecord(oldId) — 失效旧缓存
 *   4. cacheCoordinator.addRecord(newId, newType, ...) — 写入新缓存
 *
 * 先添后删保证数据安全：若 add 失败，旧记录仍在；若 delete 失败，
 * 产生重复记录（下次迁移时旧记录仍会被识别并重写，可手动清理）。
 *
 * @param oldId 旧记录 ID
 * @param newType 新记录类型
 * @param name 记录名称
 * @param dataB64 记录数据（原样保留，不重新序列化）
 * @returns 新记录 ID，失败返回 null
 */
async function migrateSingleRecord(
  oldId: number,
  newType: number,
  name: string,
  dataB64: string,
): Promise<number | null> {
  // 1. 先添：写入新类型记录
  const newId = await verthysAddRecord(newType, name, dataB64);
  if (newId === null) {
    log.error(`迁移失败：verthysAddRecord 返回 null（旧 ID=${oldId}, 新类型=0x${newType.toString(16)}）`);
    return null;
  }

  // 2. 后删：删除旧类型记录
  try {
    await verthysDeleteRecord(oldId);
  } catch (e) {
    // 删除失败不回滚（新记录已写入），记录警告
    // 旧记录残留会在下次迁移时被再次识别，产生重复——可接受的安全 tradeoff
    log.warn(`迁移警告：删除旧记录 ID=${oldId} 失败（新记录 ID=${newId} 已写入）`, e);
  }

  // 3. 缓存同步：先失效旧记录，再写入新记录
  cacheCoordinator.removeRecord(oldId);
  cacheCoordinator.addRecord({
    id: newId,
    type: newType,
    name,
    dataB64,
    dataSize: dataB64.length,
  });

  return newId;
}

/* ------------------------------------------------------------------ *
 * 主迁移入口                                                         *
 * ------------------------------------------------------------------ */

/** 单条记录迁移的超时时间（ms）——防止损坏记录阻塞整个迁移 */
const MIGRATE_RECORD_TIMEOUT_MS = 5000;

/** FileVerthys 元数据的体积上限（JSON，通常 < 64KB；超过则判定为非元数据） */
const FILEVERTHYS_META_MAX_SIZE = 65536;

/**
 * 执行记录类型冲突迁移（幂等，安全重复调用）
 *
 * 在 initUnlock 中 ensureSummaryScan 之后调用。
 * 扫描所有 type=0x10 和 type=0x05 的记录，通过内容嗅探确定正确类型，
 * 需要迁移的记录以"先添后删"方式重写为新类型。
 *
 * ★ 企业级根治：摘要预过滤 + 单条超时（根治"正在加载密钥配置"卡死）
 *
 * 原缺陷：
 *   迁移对每条 0x10/0x05 记录调用 getFullRecord（完整解密数据块）。
 *   若 verthys 有大量记录或某条记录损坏导致 IPC 挂起，迁移总耗时可达数分钟
 *   → initUnlock 永远停在"正在加载密钥配置…"阶段。
 *
 * 修复：
 *   1. 摘要预过滤：用 getSummaryRecord(id) 获取 name/dataSize（纯索引查询，
 *      不解密数据块），跳过明确无需迁移的记录（全局密钥 name="global-key"，
 *      照片块 dataSize > 64KB），仅对候选记录调用 getFullRecord + 内容嗅探。
 *   2. 单条超时：每条 getFullRecord + 迁移操作包裹 withTimeout(5s)，
 *      单条超时不阻断后续记录，计入 errors 继续。
 *   3. 去冗余：不再内部调用 ensureSummaryScan（调用方 initUnlock 已调用）。
 *
 * 性能：
 *   - 首次迁移（有冲突数据）：仅候选记录 × 3 IPC（通常 <3s）
 *   - 后续调用（无冲突数据）：2 次 getSummaryIdsByType 查询（O(1) 索引），<1ms
 *   - 全局密钥记录（0x10）：摘要预过滤跳过，0 次 IPC
 *
 * @returns 迁移结果统计
 */
export async function migrateRecordTypes(): Promise<MigrationResult> {
  const result: MigrationResult = { migrated: 0, skipped: 0, errors: 0 };

  // 1. 收集需要检查的记录 ID（type=0x10 和 type=0x05）
  //    ★ 不再内部调用 ensureSummaryScan——调用方 initUnlock 已在迁移前调用
  let type10Ids: number[] = [];
  let type05Ids: number[] = [];
  try {
    type10Ids = getSummaryIdsByType(TYPE_ACCOUNT_OLD);       // 0x10
    type05Ids = getSummaryIdsByType(TYPE_FILEVERTHYS_META_OLD); // 0x05
  } catch (e) {
    log.warn("摘要索引查询失败，跳过类型迁移", e);
    return result;
  }

  if (type10Ids.length === 0 && type05Ids.length === 0) {
    // 无冲突类型记录，无需迁移
    return result;
  }

  log.info(`类型迁移开始：0x10 记录 ${type10Ids.length} 条，0x05 记录 ${type05Ids.length} 条`);

  // 2. 迁移 0x10 记录（区分全局密钥 vs 旧账户）
  //    ★ 摘要预过滤：name="global-key" 的记录是全局密钥，无需迁移，跳过 getFullRecord
  for (const id of type10Ids) {
    try {
      // 预过滤：从摘要缓存读取 name（纯索引，不解密数据块）
      const summary = getSummaryRecord(id);
      if (summary && summary.name === "global-key") {
        // 全局密钥记录 → 保持 0x10 不变，无需 getFullRecord
        result.skipped++;
        continue;
      }

      // 候选记录：可能是旧账户记录 → getFullRecord + 内容嗅探（带超时防挂起）
      const record = await withTimeout(
        getFullRecord(id),
        MIGRATE_RECORD_TIMEOUT_MS,
        `getFullRecord(0x10, id=${id})`,
      );
      if (!record || !record.dataB64) {
        log.warn(`迁移跳过：记录 ID=${id} 数据为空`);
        result.errors++;
        continue;
      }

      // 防御性校验：确认记录实际类型仍为 0x10（避免缓存过期误操作）
      if (record.type !== TYPE_ACCOUNT_OLD) {
        log.debug(`迁移跳过：记录 ID=${id} 类型已变更（0x${record.type.toString(16)}），可能已被迁移`);
        result.skipped++;
        continue;
      }

      // 内容嗅探：尝试识别为账户记录
      if (isAccountRecordB64(record.dataB64)) {
        // 识别为账户记录 → 迁移到 TYPE_ACCOUNT (0x02)
        const newId = await migrateSingleRecord(
          id,
          TYPE_ACCOUNT,
          record.name,
          record.dataB64,
        );
        if (newId !== null) {
          result.migrated++;
          log.info(`账户记录迁移成功：ID=${id} → ID=${newId}（0x10 → 0x02）`);
        } else {
          result.errors++;
        }
      } else {
        // 识别为全局密钥记录（二进制格式）→ 保持 0x10 不变
        result.skipped++;
      }
    } catch (e) {
      log.error(`迁移异常：记录 ID=${id}`, e);
      result.errors++;
    }
  }

  // 3. 迁移 0x05 记录（区分照片块 vs 旧 FileVerthys 元数据）
  //    ★ 摘要预过滤：dataSize > 64KB 的记录不可能是 FileVerthys 元数据（JSON），
  //      跳过 getFullRecord 避免解密大体积照片密文
  for (const id of type05Ids) {
    try {
      // 预过滤：从摘要缓存读取 dataSize（纯索引，不解密数据块）
      const summary = getSummaryRecord(id);
      if (summary && summary.dataSize > FILEVERTHYS_META_MAX_SIZE) {
        // 大体积记录 → 照片数据块（二进制密文），无需迁移
        result.skipped++;
        continue;
      }

      // 候选记录：可能是 FileVerthys 元数据 → getFullRecord + 内容嗅探（带超时防挂起）
      const record = await withTimeout(
        getFullRecord(id),
        MIGRATE_RECORD_TIMEOUT_MS,
        `getFullRecord(0x05, id=${id})`,
      );
      if (!record || !record.dataB64) {
        log.warn(`迁移跳过：记录 ID=${id} 数据为空`);
        result.errors++;
        continue;
      }

      // 防御性校验：确认记录实际类型仍为 0x05
      if (record.type !== TYPE_FILEVERTHYS_META_OLD) {
        log.debug(`迁移跳过：记录 ID=${id} 类型已变更（0x${record.type.toString(16)}），可能已被迁移`);
        result.skipped++;
        continue;
      }

      // 内容嗅探：尝试识别为 FileVerthys 元数据
      if (isFileVerthysMetaRecord(record.dataB64)) {
        // 识别为 FileVerthys 元数据 → 迁移到 TYPE_FILEVERTHYS_META (0x08)
        const newId = await migrateSingleRecord(
          id,
          TYPE_FILEVERTHYS_META,
          record.name,
          record.dataB64,
        );
        if (newId !== null) {
          result.migrated++;
          log.info(`FileVerthys 元数据迁移成功：ID=${id} → ID=${newId}（0x05 → 0x08）`);
        } else {
          result.errors++;
        }
      } else {
        // 识别为照片数据块（二进制密文）→ 保持 0x05 不变
        result.skipped++;
      }
    } catch (e) {
      log.error(`迁移异常：记录 ID=${id}`, e);
      result.errors++;
    }
  }

  // 4. 落盘：如果有记录被迁移，await persistVerthys 确保写入磁盘
  if (result.migrated > 0) {
    const flushOk = await persistVerthys();
    if (!flushOk) {
      log.error("类型迁移落盘失败！迁移已写入 worker 内存但未落盘，下次解锁可能需要重新迁移");
      // 不改变 result.migrated 计数——数据已在 worker 内存中，
      // 应用退出时 waitForFlush 兜底，或下次解锁重新迁移（幂等）
    } else {
      log.info(`类型迁移完成并已落盘：迁移 ${result.migrated} 条，跳过 ${result.skipped} 条，错误 ${result.errors} 条`);
    }
  } else {
    log.info(`类型迁移完成：无需迁移（跳过 ${result.skipped} 条，错误 ${result.errors} 条）`);
  }

  return result;
}
