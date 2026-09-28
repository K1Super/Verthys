/**
 * file-verthys/useFileImport.ts — 清藏导入管道
 *
 * 职责：把用户选择的本地文件经导入会话（单写者通道）落成「外置块 + 元数据」，
 * 保证「要么完整成功、要么可续传重试」，且内存占用与文件大小无关。
 *
 * 设计要点：
 * - 单遍优先：会话无遗留去重集合时单遍处理（读分片 → 可选文件级加密 → 上传块 →
 *   汇算文件哈希 → 写元数据）；有遗留集合时先做整轮只读哈希（只读轮）判定
 *   是否重复，未重复再走上传轮——中断续传的重试因此只有只读开销；
 * - 来源身份稳定：文件开始、每个块批边界、文件结束三处复查（长度与修改时间），
 *   收尾断言已读总字节等于初始长度，任一不符即中止该文件；
 * - 两轮一致：续传形态的上传轮重算文件哈希并与只读轮比对，两轮读到不同
 *   内容即中止（长度与时间戳被还原的隐性改写因此仍可暴露）；
 * - 完整性前置：块引用全部确认后才写元数据；元数据写入失败即失败，
 *   不计成功、不进列表，已上传块留台账由孤儿回收处理；
 * - 去重语义：文件级——同内容且同加密形态的文件命中即跳过并显式报告；
 *   块级重传不保证幂等（加密形态每块随机盐使密文互异），重复导入的载荷
 *   增长由文件级跳过阻断；
 * - 批预算：单批块数由跨层预算常量推导（载荷上限与块数上限双约束）；
 * - 明文缓冲用后清零；依赖注入，便于单测。
 */
import { createBLAKE3 } from "hash-wasm";
import {
  MAX_CHUNKS_PER_IPC,
  MAX_FILE_CHUNK_SIZE_BYTES,
  MAX_IPC_PAYLOAD_BYTES,
  USER_FILE_SIZE_LIMIT,
} from "../../constants/photo_budget.generated";
import { FILE_HASH_LEN } from "../../constants/crypto_const";
import { TYPE_FILEVERTHYS_CHUNK, TYPE_FILEVERTHYS_META } from "../../constants/record_types";
import { bytesToBase64, IMPORT_SESSION_BUSY_CODE } from "../../lib/verthys";
import type { FileKeyV2, FileKdfV2 } from "../../lib/crypto";
import type {
  AddChunkBatchResult,
  AddRecordsBatchResult,
  BatchRecordInput,
  ChunkBlobInput,
  ImportBeginResult,
} from "../../types/verthys";

/** 分块口径（跨层预算常量单一权威来源） */
const CHUNK_SIZE = MAX_FILE_CHUNK_SIZE_BYTES;

/** 元数据载荷的当前写入形态标记（读取侧按字段存在性分流，不依赖该值） */
const FILE_META_SCHEMA = 2;

/** 导入前的容器卷空间余量系数：容器内除块数据外还有索引与日志开销 */
const FILE_IMPORT_DISK_HEADROOM = 1.05;

/** 去重键的域分隔标识：写入形态变更时递增，避免跨形态把不同语义误判为重复 */
const FILE_HASH_FORMAT_VER = 1;

/** 无密码文件的指纹域字节（固定值，不随内容变化） */
export const FILE_FINGERPRINT_PLAIN = 0x00;

/**
 * 有密码文件的指纹域字节（固定值）。
 *
 * 去重键不引入任何密钥/口令材料：会话日志为明文落盘，任何口令派生量入键
 * 即构成可离线爆破的验证器；且文件盐逐次随机，密钥摘要无法作为稳定键
 * （会让续传重试重复导入已提交文件）。同内容不同口令因此共用一键，
 * 换口令导入须先删除原条目（删除会释放去重键）。
 */
export const FILE_FINGERPRINT_ENCRYPTED = 0x01;

/**
 * 文件去重键的尾缀（域标识 + 指纹域）。
 *
 * 去重键 = BLAKE3(明文 ‖ 本尾缀)；导出供测试复算同一口径。
 */
export function fileHashSuffix(encrypted: boolean): Uint8Array {
  return new Uint8Array([
    FILE_HASH_FORMAT_VER,
    encrypted ? FILE_FINGERPRINT_ENCRYPTED : FILE_FINGERPRINT_PLAIN,
  ]);
}

/**
 * 单批块数：由载荷预算与块数上限共同推导（禁止字面量）。
 *
 * 后端按「块哈希长度 + 载荷 base64 长度」之和校验单批载荷；
 * 单块按最大分片评估，取两个上限的较小值并保证至少一块。
 */
export function blocksPerBatchBudget(): number {
  const perChunkBytes = Math.ceil((CHUNK_SIZE * 4) / 3) + FILE_HASH_LEN * 2;
  const byPayload = Math.floor(MAX_IPC_PAYLOAD_BYTES / perChunkBytes);
  return Math.max(1, Math.min(MAX_CHUNKS_PER_IPC, byPayload));
}

/** 导入失败原因分类（调用方据此决定文案与后续动作） */
export type FileImportErrorCode =
  | "E_STAT_FAILED"
  | "E_READ_FAILED"
  | "E_ENCRYPT_FAILED"
  | "E_CHUNK_FAILED"
  | "E_META_FAILED"
  | "E_FILE_CHANGED"
  | "E_FILE_TOO_LARGE"
  | "E_DISK_FULL";

/** 待导入文件（来自文件对话框的路径与展示名） */
export interface ImportSourceFile {
  /** 绝对路径（来自用户显式选择） */
  path: string;
  /** 展示名与元数据名称 */
  name: string;
  /** MIME 类型（展示用；由调用方按扩展名解析） */
  mime: string;
}

/** 单文件导入成功产物（列表条目与缓存同步所需的全部字段） */
export interface ImportedFileEntry {
  name: string;
  mime: string;
  size: number;
  totalChunks: number;
  encrypted: boolean;
  metaId: number;
  metaName: string;
  /** 元数据记录的 base64 载荷（列表缓存同步用） */
  metaB64: string;
  chunkIds: number[];
  chunkHashes: string[];
  chunkSize: number;
  fileHash: string;
  /** 文件级密钥派生参数（加密条目必携；明文条目缺省） */
  kdf?: FileKdfV2;
  /** 密码校验块（加密条目必携；口令判定的唯一权威值） */
  passwordCheck?: string;
}

/** 单文件导入失败明细 */
export interface ImportFailure {
  name: string;
  code: FileImportErrorCode;
  message: string;
}

/** 导入进度（按块推进；调用方按 fileFraction 映射百分比） */
export interface ImportProgress {
  fileIndex: number;
  fileCount: number;
  fileName: string;
  /** 当前文件已处理块数 */
  doneInFile: number;
  /** 当前文件块总数（0 字节文件为 0） */
  totalInFile: number;
  /** "scan" = 续传形态的只读校验轮；"upload" = 上传轮 */
  phase: "scan" | "upload";
  /** 当前文件的整体完成比例（0~1；续传形态下只读轮占前一半权重） */
  fileFraction: number;
}

/** 导入总结果（文件级结果与会话级结果分离，互不掩盖） */
export interface FileImportResult {
  /** 文件级是否全部成功（去重跳过不计失败） */
  ok: boolean;
  /** 是否由用户取消（取消保留断点状态，不计失败） */
  cancelled: boolean;
  successCount: number;
  skippedCount: number;
  failCount: number;
  entries: ImportedFileEntry[];
  /** 因文件级去重命中而跳过的文件名 */
  skipped: string[];
  failures: ImportFailure[];
  /** 会话级失败（初始化未建立，所有文件都未处理） */
  error?: string;
  /** 会话结束未收敛（断点状态保留，可重试收敛） */
  sessionWarning?: string;
}

/** 文件级密钥套件（加密导入的唯一加密路径：每文件一次派生 + 逐块 AES-GCM） */
export interface FileKeySuite {
  /** 新建文件密钥（随机盐一次派生；每文件调用一次） */
  createFileKey: (password: string) => Promise<FileKeyV2>;
  /** 加密单块（返回密文原始字节 `iv‖ct+tag`） */
  encryptChunk: (plain: Uint8Array, key: FileKeyV2) => Promise<Uint8Array>;
  /** 生成密码校验块（固定明文 AEAD，口令判定的唯一权威值） */
  buildPasswordCheck: (key: FileKeyV2) => Promise<string>;
}

/** 导入依赖集合（生产实现见模块装配处；测试以桩替换） */
export interface FileImportDeps {
  /** 读取文件元数据（长度 + 修改时间），用于分块规划与身份基线 */
  statFile: (path: string) => Promise<{ size: number; mtime_ms: number }>;
  /** 分片读取（越界由后端拒绝，返回长度恒等于请求长度） */
  readChunk: (path: string, offset: number, length: number) => Promise<Uint8Array>;
  /** 文件级密钥套件（有密码导入必用） */
  v2: FileKeySuite;
  /** 查询可用空间（字节）：path 为空表示容器卷（导入前预检用） */
  freeSpaceBytes: (path: string | null) => Promise<number>;
  /** 扫描遗留会话日志（断点去重集合；失败不阻断） */
  walRecover: () => Promise<{ ok: boolean; hashes: string[] }>;
  /** 创建导入会话 */
  importBegin: () => Promise<ImportBeginResult>;
  /** 结束导入会话（成功语义触发日志压缩） */
  importEnd: (success: boolean) => Promise<{ ok: boolean; error?: string }>;
  /** 强制清理残留会话（结束连续失败后的兜底） */
  forceCloseSession: () => Promise<boolean>;
  /** 上传外置块（单批块数受预算约束） */
  chunkBatch: (chunks: ChunkBlobInput[]) => Promise<AddChunkBatchResult>;
  /** 批量写入元数据记录 */
  recordsBatch: (records: BatchRecordInput[]) => Promise<AddRecordsBatchResult>;
  /** 回收孤儿块（会话成功结束后 best-effort） */
  gcOrphanChunks: () => Promise<number>;
  /** 会话冲突确认：返回 true 表示允许结束上一会话后继续 */
  onSessionBusy: () => Promise<boolean>;
  /** 取消信号：用户请求取消后返回 true（在每个文件与每个块批边界检查） */
  isCancelled: () => boolean;
  /** 进度回调（可选） */
  onProgress?: (progress: ImportProgress) => void;
}

/** 管道内部中止信号（携带分类，避免逐层转换错误类型） */
class ImportAbort extends Error {
  readonly code: FileImportErrorCode;

  constructor(code: FileImportErrorCode, message: string) {
    super(message);
    this.name = "ImportAbort";
    this.code = code;
  }
}

/** 取消信号（与失败分离：取消不计失败，保留断点状态） */
class ImportCancelled extends Error {
  constructor() {
    super("导入已取消");
    this.name = "ImportCancelled";
  }
}

/** 文件身份快照 */
interface FileSnapshot {
  size: number;
  mtime_ms: number;
}

/** 单文件读取并上传阶段的产物 */
interface UploadPassResult {
  chunkIds: number[];
  chunkHashes: string[];
  fileHash: string;
}

/** 会话建立结果（成功携带去重集合，失败携带原因） */
type SessionStart =
  | { ok: true; hashes: string[] }
  | { ok: false; error: string };

/**
 * 执行导入。
 *
 * @param files 待导入文件（顺序处理，单文件失败不中断后续文件）
 * @param password 独立访问密码；不加密传 null
 * @param deps 依赖集合
 * @returns 文件级与会话级结果
 */
export async function runFileImport(
  files: ImportSourceFile[],
  password: string | null,
  deps: FileImportDeps,
): Promise<FileImportResult> {
  const result: FileImportResult = {
    ok: false,
    cancelled: false,
    successCount: 0,
    skippedCount: 0,
    failCount: 0,
    entries: [],
    skipped: [],
    failures: [],
  };
  if (files.length === 0) {
    result.ok = true;
    return result;
  }

  const encrypted = !!password;
  const perBatch = blocksPerBatchBudget();
  const session = await beginSession(deps);
  if (!session.ok) {
    result.error = session.error;
    return result;
  }

  /** 会话级去重集合（遗留集合 + 本轮已提交文件；文件级跳过判定依据） */
  const committed = new Set<string>(session.hashes);
  // 去重集合为容器级共享：只要容器内发生过任何批量导入（含照片链路），
  // 集合即非空，本轮按"只读轮 + 上传轮"两遍形态执行——续传场景的跳过
  // 正确性优先于一轮额外读取的开销；两侧去重键的构造域不同，不会互相误跳过。
  const twoPass = session.hashes.length > 0;

  for (let i = 0; i < files.length; i++) {
    if (deps.isCancelled()) {
      result.cancelled = true;
      break;
    }
    const file = files[i];
    const report = makeProgressReporter(deps, {
      fileIndex: i,
      fileCount: files.length,
      fileName: file.name,
      scanShare: twoPass ? 0.5 : 0,
    });
    try {
      const outcome = await importOneFile(
        file,
        password,
        encrypted,
        twoPass,
        perBatch,
        committed,
        report,
        deps,
      );
      if (outcome.kind === "skipped") {
        result.skippedCount += 1;
        result.skipped.push(file.name);
      } else {
        result.successCount += 1;
        result.entries.push(outcome.entry);
      }
    } catch (e) {
      if (e instanceof ImportCancelled || deps.isCancelled()) {
        result.cancelled = true;
        break;
      }
      result.failCount += 1;
      result.failures.push({
        name: file.name,
        code: e instanceof ImportAbort ? e.code : "E_READ_FAILED",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  const allSucceeded = result.failCount === 0 && !result.cancelled;
  const closed = await endSessionSafely(deps, allSucceeded);
  if (!closed) {
    result.sessionWarning =
      "导入已完成，但会话未能正常结束（断点状态已保留）；可重新导入以收敛断点";
  }
  if (allSucceeded) {
    void deps.gcOrphanChunks().catch(() => 0);
  }

  result.ok = allSucceeded;
  return result;
}

/** 建立导入会话（含并发互斥的确认与恢复） */
async function beginSession(deps: FileImportDeps): Promise<SessionStart> {
  try {
    await deps.walRecover();
  } catch {
    /* 扫描失败不阻断：会话创建会自行载入日志快照并恢复去重集合 */
  }

  let begin = await deps.importBegin();
  if (!begin.ok && begin.error_code === IMPORT_SESSION_BUSY_CODE) {
    // 并发互斥：存在活跃会话（上次中断未结束，或另一模块导入进行中）。
    // 按后端结构化错误码判定（不做文案判定）；结束上一会话保留其断点
    // 状态，不丢数据。
    const allowed = await deps.onSessionBusy().catch(() => false);
    if (allowed) {
      await deps.importEnd(false).catch(() => undefined);
      begin = await deps.importBegin();
      if (!begin.ok) {
        await deps.forceCloseSession().catch(() => false);
        begin = await deps.importBegin();
      }
    }
  }

  if (!begin.ok) {
    return { ok: false, error: begin.error ?? "导入初始化失败" };
  }
  return { ok: true, hashes: begin.hashes };
}

/** 结束导入会话：失败重试一次，仍失败则强制清理残留（断点状态保留） */
async function endSessionSafely(deps: FileImportDeps, success: boolean): Promise<boolean> {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const r = await deps.importEnd(success);
      if (r.ok) return true;
    } catch {
      /* 超时/异常按失败处理，进入重试 */
    }
    if (attempt < 2) {
      await new Promise<void>((resolve) => setTimeout(resolve, 500));
    }
  }
  await deps.forceCloseSession().catch(() => false);
  return false;
}

/** 构造进度上报函数（把两轮形态的完成度折算为单一文件比例） */
function makeProgressReporter(
  deps: FileImportDeps,
  meta: { fileIndex: number; fileCount: number; fileName: string; scanShare: number },
): (done: number, total: number, phase: "scan" | "upload") => void {
  return (done, total, phase) => {
    if (!deps.onProgress) return;
    const inner = total === 0 ? 1 : done / total;
    const base = phase === "scan" ? 0 : meta.scanShare;
    const share = phase === "scan" ? meta.scanShare : 1 - meta.scanShare;
    deps.onProgress({
      fileIndex: meta.fileIndex,
      fileCount: meta.fileCount,
      fileName: meta.fileName,
      doneInFile: done,
      totalInFile: total,
      phase,
      fileFraction: Math.max(0, Math.min(1, base + inner * share)),
    });
  };
}

/**
 * 处理单个文件：快照 →（重复判定）→ 读取上传 → 元数据。
 *
 * 上传前/后任一校验失败均抛 {@link ImportAbort}；已上传块留在台账中，
 * 由会话结束后的孤儿回收处理（不在前端做补偿删除，避免与回收竞态）。
 */
async function importOneFile(
  file: ImportSourceFile,
  password: string | null,
  encrypted: boolean,
  twoPass: boolean,
  perBatch: number,
  committed: Set<string>,
  report: (done: number, total: number, phase: "scan" | "upload") => void,
  deps: FileImportDeps,
): Promise<{ kind: "imported"; entry: ImportedFileEntry } | { kind: "skipped" }> {
  const snapshot = await takeSnapshot(file, deps);
  // 体量预检：超限文件在读取任何分片之前拒绝（上限为跨层预算常量单一权威来源）
  if (snapshot.size > USER_FILE_SIZE_LIMIT) {
    throw new ImportAbort(
      "E_FILE_TOO_LARGE",
      `文件大小 ${formatGigabytes(snapshot.size)} GB 超过单文件上限 ${formatGigabytes(USER_FILE_SIZE_LIMIT)} GB，无法导入`,
    );
  }
  const totalChunks = snapshot.size === 0 ? 0 : Math.ceil(snapshot.size / CHUNK_SIZE);
  report(0, totalChunks, twoPass ? "scan" : "upload");

  // 容器卷空间预检：不足即前置拒绝（不读块、不建块记录）。
  // 读数不可得时不阻断（前置预检为尽力而为；真实写入失败仍会在写者处以
  // 明确错误暴露并保留断点），仅空间确定不足时拒绝。
  if (snapshot.size > 0) {
    const required = Math.ceil(snapshot.size * FILE_IMPORT_DISK_HEADROOM);
    let free: number | null = null;
    try {
      free = await deps.freeSpaceBytes(null);
    } catch (e) {
      console.warn("[useFileImport] 容器卷空间读数不可得，跳过前置预检", e);
      free = null;
    }
    if (free !== null && free < required) {
      throw new ImportAbort(
        "E_DISK_FULL",
        `容器磁盘空间不足：需要约 ${formatGigabytes(required)} GB，可用 ${formatGigabytes(free)} GB`,
      );
    }
  }

  // 文件级密钥：加密条目在只读轮之前派生一次，两轮共用同一句柄
  let fileKey: FileKeyV2 | null = null;
  if (encrypted && password) {
    try {
      fileKey = await deps.v2.createFileKey(password);
    } catch (e) {
      throw new ImportAbort("E_ENCRYPT_FAILED", `文件密钥派生失败：${errorText(e)}`);
    }
  }

  // 重复判定：仅当会话存在遗留去重集合时才值得先做整轮只读哈希
  let knownHash: string | null = null;
  if (twoPass) {
    knownHash = await scanFileHash(file, snapshot, encrypted, perBatch, report, deps);
    if (committed.has(knownHash)) {
      return { kind: "skipped" };
    }
  }

  const uploaded = await readAndUpload(
    file,
    snapshot,
    fileKey,
    encrypted,
    perBatch,
    knownHash,
    report,
    deps,
  );
  report(totalChunks, totalChunks, "upload");

  // 单遍形态下上传完成才知文件哈希：同轮重复内容显式跳过（块已上传，
  // 无口令时同哈希复用既有块记录，有口令时的多余块由孤儿回收处理）
  if (committed.has(uploaded.fileHash)) {
    return { kind: "skipped" };
  }

  const entry = await writeMeta(file, snapshot, totalChunks, encrypted, fileKey, uploaded, deps);
  committed.add(uploaded.fileHash);
  if (entry === null) {
    // 后端按会话日志跳过：键已提交，按跳过入账（不计成功、不产生条目）
    return { kind: "skipped" };
  }
  return { kind: "imported", entry };
}

/** 采集初始快照（失败即中止该文件：没有基线就无法做身份复查） */
async function takeSnapshot(
  file: ImportSourceFile,
  deps: FileImportDeps,
): Promise<FileSnapshot> {
  try {
    const stat = await deps.statFile(file.path);
    return { size: stat.size, mtime_ms: stat.mtime_ms };
  } catch (e) {
    throw new ImportAbort("E_STAT_FAILED", `无法读取文件信息：${errorText(e)}`);
  }
}

/** 复查来源身份：长度或修改时间任一变化即中止该文件 */
async function checkIdentity(
  file: ImportSourceFile,
  snapshot: FileSnapshot,
  deps: FileImportDeps,
): Promise<void> {
  let now: FileSnapshot;
  try {
    now = await deps.statFile(file.path);
  } catch (e) {
    throw new ImportAbort("E_FILE_CHANGED", `源文件状态无法复查：${errorText(e)}`);
  }
  if (now.size !== snapshot.size || now.mtime_ms !== snapshot.mtime_ms) {
    throw new ImportAbort("E_FILE_CHANGED", "源文件在导入过程中被修改，本次导入已中止");
  }
}

/** 读取单块（长度必须与请求一致，读少即报错） */
async function readChunkExact(
  file: ImportSourceFile,
  offset: number,
  length: number,
  index: number,
  deps: FileImportDeps,
): Promise<Uint8Array> {
  let bytes: Uint8Array;
  try {
    bytes = await deps.readChunk(file.path, offset, length);
  } catch (e) {
    throw new ImportAbort("E_READ_FAILED", `第 ${index + 1} 块读取失败：${errorText(e)}`);
  }
  if (bytes.length !== length) {
    throw new ImportAbort(
      "E_READ_FAILED",
      `第 ${index + 1} 块读取长度不符（期望 ${length} 字节，实际 ${bytes.length} 字节）`,
    );
  }
  return bytes;
}

/**
 * 整轮只读哈希：逐块读取并汇算去重键，不做加密与上传。
 *
 * 用于续传场景的重复判定；结束前做总字节断言与身份复查。
 */
async function scanFileHash(
  file: ImportSourceFile,
  snapshot: FileSnapshot,
  encrypted: boolean,
  perBatch: number,
  report: (done: number, total: number, phase: "scan" | "upload") => void,
  deps: FileImportDeps,
): Promise<string> {
  const totalChunks = snapshot.size === 0 ? 0 : Math.ceil(snapshot.size / CHUNK_SIZE);
  const hasher = await createBLAKE3();
  hasher.init();

  let bytesRead = 0;
  for (let i = 0; i < totalChunks; i++) {
    if (deps.isCancelled()) throw new ImportCancelled();
    const offset = i * CHUNK_SIZE;
    const length = Math.min(CHUNK_SIZE, snapshot.size - offset);
    const plain = await readChunkExact(file, offset, length, i, deps);
    hasher.update(plain);
    plain.fill(0);
    bytesRead += length;
    report(i + 1, totalChunks, "scan");
    if ((i + 1) % perBatch === 0) {
      await checkIdentity(file, snapshot, deps);
    }
  }

  await checkIdentity(file, snapshot, deps);
  if (bytesRead !== snapshot.size) {
    throw new ImportAbort("E_FILE_CHANGED", "已读字节数与文件长度不符，本次导入已中止");
  }
  hasher.update(fileHashSuffix(encrypted));
  return hasher.digest("hex");
}

/**
 * 读取并上传整轮：逐块读取 → 可选文件级加密 → 上传块批 → 汇算文件哈希。
 *
 * @param knownHash 只读轮已算出的去重键；为空表示单遍形态（本轮汇算）。
 *                  非空时本轮重算并与该值比对，两轮内容不一致即中止。
 */
async function readAndUpload(
  file: ImportSourceFile,
  snapshot: FileSnapshot,
  fileKey: FileKeyV2 | null,
  encrypted: boolean,
  perBatch: number,
  knownHash: string | null,
  report: (done: number, total: number, phase: "scan" | "upload") => void,
  deps: FileImportDeps,
): Promise<UploadPassResult> {
  const totalChunks = snapshot.size === 0 ? 0 : Math.ceil(snapshot.size / CHUNK_SIZE);
  const fileHasher = await createBLAKE3();
  fileHasher.init();
  const chunkHasher = await createBLAKE3();

  const chunkIds: number[] = [];
  const chunkHashes: string[] = [];
  let bytesRead = 0;

  for (let i = 0; i < totalChunks; i += perBatch) {
    if (deps.isCancelled()) throw new ImportCancelled();
    const upper = Math.min(i + perBatch, totalChunks);
    const blobs: ChunkBlobInput[] = [];
    const batchHashes: string[] = [];

    for (let index = i; index < upper; index++) {
      const offset = index * CHUNK_SIZE;
      const length = Math.min(CHUNK_SIZE, snapshot.size - offset);
      const plain = await readChunkExact(file, offset, length, index, deps);
      bytesRead += length;

      let cipherB64: string;
      let cipherBytes: Uint8Array;
      if (encrypted) {
        if (!fileKey) {
          // 加密条目的密钥在文件开始处一次性派生，缺失即编程错误
          throw new ImportAbort("E_ENCRYPT_FAILED", "文件密钥缺失，导入已中止");
        }
        try {
          cipherBytes = await deps.v2.encryptChunk(plain, fileKey);
        } catch (e) {
          plain.fill(0);
          throw new ImportAbort("E_ENCRYPT_FAILED", `第 ${index + 1} 块加密失败：${errorText(e)}`);
        }
        cipherB64 = bytesToBase64(cipherBytes);
      } else {
        cipherB64 = bytesToBase64(plain);
        cipherBytes = plain;
      }

      // 文件哈希按明文汇算：与加密形态解耦，同内容同形态命中去重键
      fileHasher.update(plain);
      chunkHasher.init();
      chunkHasher.update(cipherBytes);
      const chunkHash = chunkHasher.digest("hex");
      batchHashes.push(chunkHash);
      blobs.push({ hash: chunkHash, data_b64: cipherB64, rtype: TYPE_FILEVERTHYS_CHUNK });

      // 明文与密文缓冲用后清零（无口令时两者为同一缓冲，单次清零即可）
      plain.fill(0);
      if (cipherBytes !== plain) cipherBytes.fill(0);
      report(index + 1, totalChunks, "upload");
    }

    let resp: AddChunkBatchResult;
    try {
      resp = await deps.chunkBatch(blobs);
    } catch (e) {
      // 传输层异常（超时/通道断开）必须按块写入失败分类，不得退化为未分类的读取失败
      throw new ImportAbort(
        "E_CHUNK_FAILED",
        `第 ${i + 1} 块批次写入失败：${errorText(e)}`,
      );
    }
    const firstBad = firstBadChunkIndex(resp, blobs.length);
    if (firstBad >= 0) {
      throw new ImportAbort(
        "E_CHUNK_FAILED",
        `第 ${i + firstBad + 1} 块写入失败${resp.error ? `：${resp.error}` : ""}`,
      );
    }
    chunkIds.push(...resp.ids);
    chunkHashes.push(...batchHashes);

    await checkIdentity(file, snapshot, deps);
  }

  await checkIdentity(file, snapshot, deps);
  if (bytesRead !== snapshot.size) {
    throw new ImportAbort("E_FILE_CHANGED", "已读字节数与文件长度不符，本次导入已中止");
  }

  fileHasher.update(fileHashSuffix(encrypted));
  const fileHash = fileHasher.digest("hex");
  if (knownHash !== null && fileHash !== knownHash) {
    // 两轮读到不同内容：长度与时间戳被还原的隐性改写在此暴露
    throw new ImportAbort("E_FILE_CHANGED", "源文件在导入过程中被修改，本次导入已中止");
  }

  return { chunkIds, chunkHashes, fileHash };
}

/** 返回首个失败块下标（全部成功返回 -1）：ok=false / 失败集 / 非法 ID 均判失败 */
function firstBadChunkIndex(resp: AddChunkBatchResult, expectedCount: number): number {
  if (!resp.ok) return 0;
  if (resp.failed_indices.length > 0) return resp.failed_indices[0];
  if (resp.ids.length !== expectedCount) return 0;
  return resp.ids.findIndex((id) => id <= 0);
}

/**
 * 写入元数据记录（块引用全部确认后执行；失败即失败，不产生条目）。
 *
 * @returns 成功返回列表条目；返回 null 表示后端按会话日志去重跳过
 *          （该键已在会话已提交集合中，调用方按跳过入账而非失败）
 */
async function writeMeta(
  file: ImportSourceFile,
  snapshot: FileSnapshot,
  totalChunks: number,
  encrypted: boolean,
  fileKey: FileKeyV2 | null,
  uploaded: UploadPassResult,
  deps: FileImportDeps,
): Promise<ImportedFileEntry | null> {
  // 口令判定块的唯一权威值：加密条目必携；生成失败即整文件失败
  let passwordCheck: string | undefined;
  if (encrypted) {
    if (!fileKey) {
      throw new ImportAbort("E_ENCRYPT_FAILED", "文件密钥缺失，导入已中止");
    }
    try {
      passwordCheck = await deps.v2.buildPasswordCheck(fileKey);
    } catch (e) {
      throw new ImportAbort("E_ENCRYPT_FAILED", `密码校验块生成失败：${errorText(e)}`);
    }
  }

  const meta = {
    schema: FILE_META_SCHEMA,
    name: file.name,
    size: snapshot.size,
    mime: file.mime,
    chunkIds: uploaded.chunkIds,
    chunkHashes: uploaded.chunkHashes,
    chunkSize: CHUNK_SIZE,
    totalChunks,
    encrypted,
    fileHash: uploaded.fileHash,
    // 明文条目无口令校验面：两个字段均不写
    ...(passwordCheck && fileKey ? { kdf: fileKey.kdf, passwordCheck } : {}),
  };
  const metaB64 = bytesToBase64(new TextEncoder().encode(JSON.stringify(meta)));
  const metaName = `meta_${file.name}`;
  const record: BatchRecordInput = {
    rtype: TYPE_FILEVERTHYS_META,
    name: metaName,
    hash: uploaded.fileHash,
    data_b64: metaB64,
    chunk_ids: uploaded.chunkIds,
    chunk_hashes: uploaded.chunkHashes,
  };

  let resp: AddRecordsBatchResult;
  try {
    resp = await deps.recordsBatch([record]);
  } catch (e) {
    // 传输层异常必须按元数据失败分类，避免"块已落库却报告读取失败"的误导归因
    throw new ImportAbort("E_META_FAILED", `元数据写入失败，本次导入未生效：${errorText(e)}`);
  }
  if (
    resp.ok &&
    resp.failed_indices.length === 0 &&
    (resp.ids[0] ?? 0) <= 0 &&
    resp.skipped_count > 0
  ) {
    // 会话日志已持有该去重键 → 后端幂等跳过（结构化字段判定）
    return null;
  }
  const metaId = resp.ok && resp.failed_indices.length === 0 ? (resp.ids[0] ?? 0) : 0;
  if (metaId <= 0) {
    throw new ImportAbort(
      "E_META_FAILED",
      `元数据写入失败，本次导入未生效${resp.error ? `：${resp.error}` : ""}`,
    );
  }

  return {
    name: file.name,
    mime: file.mime,
    size: snapshot.size,
    totalChunks,
    encrypted,
    metaId,
    metaName,
    metaB64,
    chunkIds: uploaded.chunkIds,
    chunkHashes: uploaded.chunkHashes,
    chunkSize: CHUNK_SIZE,
    fileHash: uploaded.fileHash,
    ...(passwordCheck && fileKey ? { kdf: fileKey.kdf, passwordCheck } : {}),
  };
}

/** 体量读数（GB 口径，整数省略小数）：超限提示与上限展示共用 */
function formatGigabytes(bytes: number): string {
  const gb = bytes / (1024 * 1024 * 1024);
  return Number.isInteger(gb) ? String(gb) : gb.toFixed(1);
}

/** 错误对象转可读文案（保持原始原因，便于调用方定位） */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}