/*
 * ipc/records.ts — 导入收尾/WAL/记录读取/扫描/删除/导出导入
 */

import { Channel } from "@tauri-apps/api/core";
import { invokeWithTimeout } from "../../utils/ipc/invoke_wrapper";
import { SESSION_END_TIMEOUT_MS } from "../../constants/photo_budget.generated";
import { markFrontendIpcActive } from "../../core/frontend-ipc-priority";
import { ipcFailed } from "../util/verthys_error";
import { ipc } from "./internal";
import type {
  VerthysResponse,
  EnumerateBatch,
  WalRecoverResult,
} from "../../types/verthys";

/**
 * 关闭导入会话：success=true 触发 WAL 压缩，failure 保留 WAL 供续传。
 *
 * @param success 是否成功完成（true 压缩 WAL，false 保留供续传）
 * @returns { ok, total_count, import_id }
 */
export async function verthysImportEnd(
  success: boolean,
): Promise<{ ok: boolean; total_count: number; import_id: string; error?: string }> {
  // 会话结束超时（跨层预算常量）：WAL 压缩可能较慢，超时给足 30s；
  // 超时按失败返回（非抛出），由管线的 endSessionSafely 重试并自愈清理
  try {
    const r = await invokeWithTimeout<VerthysResponse>(
      "verthys_import_end",
      { success },
      SESSION_END_TIMEOUT_MS,
    );
    return {
      ok: r.ok,
      total_count: r.total_count ?? 0,
      import_id: r.import_id ?? "",
      error: r.error,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn("[verthysImportEnd] 调用失败/超时:", msg);
    return { ok: false, total_count: 0, import_id: "", error: `会话结束超时或失败: ${msg}` };
  }
}

/**
 * 查询当前导入会话的检查点状态（累计 committed 计数 + 条目键集）。
 *
 * 用于前端在导入过程中查询实时进度，或断点续传前确认当前状态。纯只读。
 *
 * @returns { ok, import_id, entry_keys, total_count, batch_id }
 */
export async function verthysImportCheckpoint(): Promise<{
  ok: boolean;
  import_id: string;
  entry_keys: string[];
  total_count: number;
  batch_id: number;
  error?: string;
}> {
  const r = await ipc<VerthysResponse>("verthys_import_checkpoint");
  return {
    ok: r.ok,
    import_id: r.import_id ?? "",
    entry_keys: r.entry_keys ?? [],
    total_count: r.total_count ?? 0,
    batch_id: r.batch_id ?? 0,
    error: r.error,
  };
}

/**
 * 扫描遗留 WAL，返回 committed 条目键集（续传幂等，不创建新会话）。
 *
 * 应用启动时或导入前调用，检查是否存在遗留 WAL（上次崩溃/关闭未完成）：
 *   - WAL 不存在 → 返回空键集（无需续传）
 *   - WAL 存在且未 end → 返回 committed 条目键集（续传依据）
 *
 * @param verthysPath 可选 verthys 路径（不传则从当前会话守卫读取）
 * @returns { ok, entry_keys, total_count, import_id?, batch_id?, processed_count? }
 */
export async function verthysWalRecover(
  verthysPath?: string,
): Promise<WalRecoverResult> {
  const r = await ipc<VerthysResponse>("verthys_wal_recover", {
    verthysPath: verthysPath ?? null,
  });
  return {
    ok: r.ok,
    entry_keys: r.entry_keys ?? [],
    total_count: r.total_count ?? 0,
    import_id: r.import_id,
    batch_id: r.batch_id,
    processed_count: r.processed_count,
    error: r.error,
  };
}

/** 读取失败的归因分类：供调用方分流提示与告警 */
export type GetRecordErrorCode = "not_found" | "record_too_large" | "channel_error";

/** 单条记录读取结果（判别式）：成功携带记录；失败携带原始错误与可归类语义 */
export type GetRecordOutcome =
  | { ok: true; record: { type: number; name: string; dataB64: string } }
  | { ok: false; error: string; code: GetRecordErrorCode };

/** 把后端错误文案归类为可判别的语义（后端未定义结构化错误码，按文案前缀匹配） */
function classifyGetRecordError(error: string): GetRecordErrorCode {
  if (error.includes("record_too_large") || error.includes("超过单条")) {
    return "record_too_large";
  }
  if (error.includes("not found") || error.includes("不存在") || error.includes("no such")) {
    return "not_found";
  }
  return "channel_error";
}

/**
 * 读取单条记录的判别式版本：失败原因原样透出并可归类，
 * 供需要区分「记录不存在 / 超出单条上限 / 通道异常」的调用方使用。
 */
export async function verthysGetRecordDetailed(id: number): Promise<GetRecordOutcome> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_get_record", { id });
  if (!r.ok) {
    const error = r.error ?? "unknown error";
    // 失败必须留痕：记录过大（record_too_large）、通道异常与"记录不存在"若
    // 静默返回 null，会使结构性问题退化为"记录缺失"而无法定位（调用方只看到空数据）。
    console.warn(`[verthysGetRecord] 读取记录 ${id} 失败: ${error}`);
    return { ok: false, error, code: classifyGetRecordError(error) };
  }
  return {
    ok: true,
    record: {
      type: r.rtype ?? 0,
      name: r.name ?? "",
      dataB64: r.data ?? "",
    },
  };
}

/** 读取记录（返回 base64 数据；失败返回 null，兼容既有调用方） */
export async function verthysGetRecord(
  id: number
): Promise<{ type: number; name: string; dataB64: string } | null> {
  const outcome = await verthysGetRecordDetailed(id);
  return outcome.ok ? outcome.record : null;
}

/**
 * 批量枚举记录（一次 IPC 调用获取所有记录）
 * 替代前端逐条探测的 enumerateRecords，消除 N 次 IPC 往返开销
 * @param startId 增量扫描起始 ID（从该 ID 开始顺序读取）
 * @returns 记录数组（id/type/name/dataB64）
 */
export async function verthysEnumerateRecords(
  startId: number = 1
): Promise<{ id: number; type: number; name: string; dataB64: string }[]> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_enumerate_records", { startId });
  if (!r.ok || !r.records) return [];
  return r.records.map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataB64: e.data,
  }));
}

/**
 * 流式枚举记录（Tauri Channel 分页推送）
 *
 * 替代一次性 verthysEnumerateRecords（数千条记录 JSON.parse 阻塞主线程 100ms+）。
 * 后端循环调用 worker enumerate_records（每批 batchSize 条），
 * 每批通过 onBatch Channel 推送到前端，前端收到一批即渲染一批。
 *
 * 用户感知：渐进式加载（首批 200 条 100ms 内到达），而非"瞬间冻结后爆发"。
 * 单批 JSON 体积小，JSON.parse 耗时 < 5ms，主线程不阻塞。
 *
 * @param startId 起始记录 ID（首屏传 1，后续批 = 上一批 last_id + 1）
 * @param batchSize 每批最多返回条数（默认 200，上限 500）
 * @param onBatch 每批到达回调（参数含 records/last_id/count/exhausted/total_pushed）
 * @returns 累计推送总数（exhausted=true 时表示已遍历完毕）
 */
export async function verthysEnumerateRecordsStream(
  startId: number,
  batchSize: number,
  onBatch: (batch: EnumerateBatch) => void,
): Promise<number> {
  // 创建 Tauri Channel 用于流式接收批次（与 verthysUnlock 模式一致）
  const channel = new Channel<EnumerateBatch>();
  channel.onmessage = onBatch;

  const r = await ipc<VerthysResponse>("verthys_enumerate_records_stream", {
    startId,
    batchSize,
    onBatch: channel,
  });
  // 返回累计推送总数（后端 record_count 字段）
  return r.record_count ?? 0;
}

/* ------------------------------------------------------------------ *
 * 游标批量扫描（双缓冲流水线预取，替代逐条 enumerate_records）        *
 *                                                                    *
 * 架构：                                                             *
 *   - verthysScanOpen  → 打开游标，返回首批记录 + exhausted 标记       *
 *   - verthysScanNext  → 返回下一批记录（后台预取已就绪）+ exhausted    *
 *   - verthysScanClose → 关闭游标，释放所有资源                        *
 *                                                                    *
 * 前端用法：                                                         *
 *   const first = await verthysScanOpen(0, 1000);                      *
 *   process(first.records);                                          *
 *   while (!first.exhausted) {                                       *
 *     const next = await verthysScanNext(1000);                        *
 *     process(next.records);                                         *
 *     if (next.exhausted) break;                                     *
 *   }                                                                *
 *   await verthysScanClose();                                          *
 * ------------------------------------------------------------------ */

/** 记录扫描投影选项（缺省 = 全量解密） */
export interface ScanProjectOptions {
  /**
   * 投影选择：
   *   - "full"（缺省）：全部记录完整解密并返回数据；
   *   - "index"：仅对不超过 inlineMaxBytes 的记录解密并返回数据，超出阈值的
   *     记录仍返回索引条目但 dataB64 为空（后端不解密、不搬运数据）。
   */
  project?: "full" | "index";
  /** INDEX 投影的内联数据字节阈值（0 = 纯索引，任何记录都不附带数据） */
  inlineMaxBytes?: number;
}

/** 打开扫描游标，返回首批记录
 * @param startId 起始记录 ID（0 表示从头扫描）
 * @param batchSize 单批拉取条数（<1KB 记录建议 1000~2000，>1KB 建议 200~500）
 * @param options 投影选项（索引/列表类调用传 { project: "index", inlineMaxBytes }）
 * @returns 首批记录列表 + 是否遍历结束 + 本批损坏记录 ID
 * @throws 当后端 scan_open 失败时抛异常（v1 格式不支持游标扫描等）
 *
 * 失败时不静默返回空记录，而是抛异常让调用方决定回退策略。
 * 原因：scan_open 返回 ok=false 可能是"v1 格式不支持"或"熔断"等错误，
 * 静默返回空会导致 ensureRecordScan 误认为"verthys 为空"，模块内容不显示。
 */
export async function verthysScanOpen(
  startId: number = 0,
  batchSize: number = 1000,
  options: ScanProjectOptions = {}
): Promise<{ records: { id: number; type: number; name: string; dataB64: string }[]; exhausted: boolean; failedIds: number[] }> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_scan_open", {
    startId,
    batchSize,
    project: options.project,
    inlineMaxBytes: options.inlineMaxBytes,
  });
  if (!r.ok) {
    throw ipcFailed(`scan_open failed: ${r.error ?? "unknown error"}`);
  }
  const records = (r.records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataB64: e.data,
  }));
  return { records, exhausted: r.exhausted ?? false, failedIds: r.failed_ids ?? [] };
}

/** 拉取下一批记录（双缓冲流水线切换）
 *
 * 失败必须上抛（与 scanOpen 同一契约）：静默返回空批会让调用方误判「已遍历
 * 完毕」，扫描缓存被无声截断——表现为相册/文件库缺失记录且无任何错误提示。
 * 上抛后由调用方（记录扫描）进入回退链路（enumerate 全量 + 流式枚举）。
 *
 * @param batchSize 单批拉取条数（与 open 时一致）
 * @returns 下一批记录列表 + 是否遍历结束 + 本批损坏记录 ID
 */
export async function verthysScanNext(
  batchSize: number = 1000
): Promise<{ records: { id: number; type: number; name: string; dataB64: string }[]; exhausted: boolean; failedIds: number[] }> {
  const r = await ipc<VerthysResponse>("verthys_scan_next", { batchSize });
  if (!r.ok) {
    throw new Error(`scan_next failed: ${r.error ?? "unknown error"}`);
  }
  const records = (r.records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataB64: e.data,
  }));
  return { records, exhausted: r.exhausted ?? false, failedIds: r.failed_ids ?? [] };
}

/** 关闭扫描游标，释放所有资源（共享内存、C 游标、预取任务） */
export async function verthysScanClose(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_scan_close", {});
  return r.ok;
}

/* ------------------------------------------------------------------ *
 * 摘要扫描（轻量元数据，不读数据块）                        *
 *                                                                    *
 * 与全量扫描的区别：                                                  *
 *   - 仅返回 lid/type/name/data_size/physical_offset/merkle_leaf     *
 *   - 不解密数据块，解锁后 1-2 秒内加载全部摘要索引                   *
 *   - 用于列表渲染 + 搜索 + 删除（用户体感零延迟）                    *
 *   - 完整数据按需加载（verthysGetRecord / 全量扫描）                   *
 *                                                                    *
 * 前端用法：                                                          *
 *   const first = await verthysScanSummaryOpen(0, 1000);               *
 *   summaryCache.populate(first.records);                            *
 *   while (!first.exhausted) {                                       *
 *     const next = await verthysScanSummaryNext(1000);                 *
 *     summaryCache.populate(next.records);                           *
 *     if (next.exhausted) break;                                     *
 *   }                                                                *
 *   await verthysScanSummaryClose();                                   *
 * ------------------------------------------------------------------ */

/** 摘要记录（前端简化类型，供 verthys-cache.ts 两层缓存使用）
 *  createdTime 为创建时间戳，列表展示用
 */
export interface SummaryRecord {
  id: number;
  type: number;
  name: string;
  dataSize: number;
  physicalOffset: number;
  merkleLeaf: string;
  createdTime: number;
}

/** 打开摘要扫描游标，返回首批摘要记录
 * @param startId 起始记录 ID（0 表示从头扫描）
 * @param batchSize 单批拉取条数（元数据极小，建议 1000~2000）
 * @returns 首批摘要记录列表 + 是否遍历结束
 * @throws 当后端 scan_summary_open 失败时抛异常（v1 格式不支持 / 熔断等）
 */
export async function verthysScanSummaryOpen(
  startId: number = 0,
  batchSize: number = 1000
): Promise<{ records: SummaryRecord[]; exhausted: boolean }> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_scan_summary_open", { startId, batchSize });
  if (!r.ok) {
    throw ipcFailed(`scan_summary_open failed: ${r.error ?? "unknown error"}`);
  }
  const records = (r.summary_records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataSize: e.data_size,
    physicalOffset: e.physical_offset,
    merkleLeaf: e.merkle_leaf,
    createdTime: e.created_time ?? 0,
  }));
  return { records, exhausted: r.exhausted ?? false };
}

/** 拉取下一批摘要记录（双缓冲流水线切换）
 * @param batchSize 单批拉取条数（与 open 时一致）
 * @returns 下一批摘要记录列表 + 是否遍历结束
 */
export async function verthysScanSummaryNext(
  batchSize: number = 1000
): Promise<{ records: SummaryRecord[]; exhausted: boolean }> {
  const r = await ipc<VerthysResponse>("verthys_scan_summary_next", { batchSize });
  if (!r.ok) return { records: [], exhausted: true };
  const records = (r.summary_records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataSize: e.data_size,
    physicalOffset: e.physical_offset,
    merkleLeaf: e.merkle_leaf,
    createdTime: e.created_time ?? 0,
  }));
  return { records, exhausted: r.exhausted ?? false };
}

/** 关闭摘要扫描游标，释放所有资源（摘要共享内存、C 游标、预取任务） */
export async function verthysScanSummaryClose(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_scan_summary_close", {});
  return r.ok;
}

/** 删除记录 */
export async function verthysDeleteRecord(id: number): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_delete_record", { id });
  return r.ok;
}

/** 批量删除记录（单次事务，合并为单次 flush）
 *  将整个 ID 列表传给 Rust 层，单次 verthys_flush 一次性移除所有条目，
 *  只做一次重加密和一次全局 HMAC 更新 */
export async function verthysDeleteRecords(ids: number[]): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_delete_records", { ids });
  return r.ok;
}

/** 获取已加载的轻量摘要记录数
 *  返回解锁时从 summary_index_off 加载的摘要记录数。
 *  >0 表示摘要索引可用，前端可直接渲染列表无需 B+ 树扫描。
 *
 *  worker 返回 ok=false 时抛出异常而非返回 0：
 *    返回 0 会被调用方误判"verthys 为空"→ UI 显示"初始化密钥"；
 *    抛异常后调用方 catch 走"计数未知"路径，继续第一批扫描
 */
export async function verthysGetSummaryCount(): Promise<number> {
  const r = await ipc<VerthysResponse & { record_count?: number }>(
    "verthys_get_summary_count",
    {}
  );
  if (!r.ok) {
    throw new Error(`verthysGetSummaryCount worker 失败: ${r.error ?? "未知错误"}`);
  }
  return r.record_count ?? 0;
}

/** 轻量级记录类型存在性检查（只扫摘要索引，不读数据块）
 *
 *  C 层 Verthys_HasRecordByType 直接遍历 B+ 树叶子节点检查 type 字段，
 *  不分配 name 堆内存，不访问数据区块，典型耗时 < 100ms。
 *
 *  用于启动阶段快速判断是否有全局密钥记录。
 *
 *  @param rtype 目标记录类型（如 TYPE_GLOBAL_KEY = 0x10）
 *  @returns true=存在匹配类型的记录，false=不存在
 *  @throws worker 失败时抛异常（v1 容器不支持、worker 未初始化等）
 */
export async function verthysHasRecordByType(rtype: number): Promise<boolean> {
  const r = await ipc<VerthysResponse & { record_count?: number }>(
    "verthys_has_record_by_type",
    { rtype }
  );
  if (!r.ok) {
    throw new Error(`verthysHasRecordByType worker 失败: ${r.error ?? "未知错误"}`);
  }
  return (r.record_count ?? 0) > 0;
}

/** 按类型分页枚举记录 ID
 *
 *  权威来源：类型盲索引（VTY_KS_TYPE），不读取记录密文，跨重启稳定。
 *  摘要扫描的 type 恒为未知 0，禁止用它过滤业务类型。
 *
 *  @param rtype 记录业务类型
 *  @param afterId 上一页最后一个 ID；首页传 0
 *  @param maxCount 本页上限（1..4096）
 *  @returns { ids, exhausted }：ids 严格升序；exhausted=true 表示末页
 *  @throws worker 失败 / 参数非法 / 非容器格式时抛异常
 */
export async function verthysListIdsByType(
  rtype: number,
  afterId: number = 0,
  maxCount: number = 1000,
): Promise<{ ids: number[]; exhausted: boolean }> {
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_list_ids_by_type", {
    rtype,
    afterId,
    maxCount,
  });
  if (!r.ok) {
    throw new Error(`verthysListIdsByType worker 失败: ${r.error ?? "未知错误"}`);
  }
  return { ids: r.ids ?? [], exhausted: r.exhausted ?? true };
}

/** 导出为独立 .verthys 文件 */
export async function verthysExport(
  exportPath: string,
  password: string
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_export", { exportPath, password });
  return r.ok;
}

/** 导入 .verthys 文件 */
export async function verthysImport(
  importPath: string,
  password: string
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_import", { importPath, password });
  return r.ok;
}
