/**
 * photo-album/repack.ts — 存量照片后台重打包引擎（既有布局 → 索引瘦身布局）
 *
 * 职责：以单张照片为幂等单元，把既有布局（每块自包含、缩略图内联于索引）
 * 就地改写为索引瘦身布局（缩略图 / 块集独立记录 + 包裹文件密钥）。
 *
 * 设计约束：
 * - 依赖注入：本引擎不直接触碰 IPC / Worker 池 / 缓存，读取与写入全部经注入
 *   回调完成，故可在单测中完整覆盖成功 / 跳过 / 失败 / 取消 / 校验不通过分支；
 * - 低优先级与不阻塞：调用方负责调度时让位（每张之间让出主线程）；
 * - 可取消：每张开始前检查取消标志，取消后不再处理新照片（在途一张正常收尾）；
 * - 可续跑：进度由"仍为既有布局的照片"驱动，已迁移项自动跳过，重启后自然续跑；
 * - 安全前置：源数据必须完整解密且整图哈希与索引声明一致才允许改写，
 *   任一校验不通过即按失败记账并保留源记录（绝不产出"改写后不可读"的数据）。
 */
import { PHOTO_FMT_SLIM } from "../../constants/crypto_const";

/** 单张迁移结果分类 */
export type RepackItemOutcome = "migrated" | "skipped" | "failed";

/** 重打包进度快照（逐张上报） */
export interface RepackProgress {
  /** 待迁移总数（开始时快照） */
  total: number;
  /** 已处理数（含跳过与失败） */
  processed: number;
  /** 成功迁移数 */
  migrated: number;
  /** 跳过数（已是布局二 / 后端去重跳过） */
  skipped: number;
  /** 失败数 */
  failed: number;
  /** 当前处理项标签（文件名或记录 ID） */
  currentLabel: string;
}

/** 重打包最终结果 */
export interface RepackResult {
  total: number;
  migrated: number;
  skipped: number;
  failed: number;
  /** 是否因取消而提前结束 */
  aborted: boolean;
}

/** 重打包依赖（由调用方装配；全部为异步或纯读取，引擎不持有状态） */
export interface RepackDeps {
  /** 待迁移候选：当前索引中的全部照片索引记录 ID */
  listMetaIds: () => number[];
  /** 读取记录 dataB64（扫描缓存优先；缺失的记录不在返回的 Map 中） */
  readRecords: (ids: number[]) => Promise<Map<number, string>>;
  /** 解密索引（Worker 优先 + 主线程兜底） */
  decryptMeta: (metaB64: string, label: string) => Promise<PhotoMetaLike>;
  /** 读取并解密既有布局的块密文，按序返回明文块 */
  decryptChunks: (meta: PhotoMetaLike, label: string) => Promise<Uint8Array[]>;
  /** 写入索引瘦身布局（重新加密并落库），返回新索引记录 ID；
   *  入参为已拼接的整图明文字节（校验通过后才会调用） */
  writeSlimPhoto: (meta: PhotoMetaLike, plainBytes: Uint8Array) => Promise<number>;
  /** 删除旧记录集（旧索引 + 旧块记录） */
  deleteLegacyRecords: (metaId: number, chunkIds: number[]) => Promise<void>;
  /** 单张迁移完成回调（调用方据此更新列表项与缓存） */
  onMigrated?: (oldMetaId: number, newMetaId: number) => void;
  /** 逐张进度回调 */
  onProgress?: (progress: RepackProgress) => void;
  /** 计算明文整图哈希 hex（与写入侧同源，校验源数据完整性） */
  hashPlaintext: (bytes: Uint8Array) => string;
}

/** 引擎所需的元数据最小视图（避免耦合完整类型定义） */
export interface PhotoMetaLike {
  name?: string;
  mime?: string;
  size?: number;
  createdAt?: number;
  fmt?: number;
  thumbId?: number;
  thumbB64?: string;
  chunkIds?: number[];
  chunkDataB64?: string[];
  chunkHashes?: string[];
  fileHash: string;
  wrappedFileKey?: string;
  chunkSetId?: number;
}

/** 判断是否已是索引瘦身布局（含缩略图引用的完整形态） */
function alreadySlim(meta: PhotoMetaLike): boolean {
  return meta.fmt === PHOTO_FMT_SLIM && typeof meta.thumbId === "number" && meta.thumbId > 0;
}

/** 拼接明文块 */
function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/** 取消标志（由调用方持有，置 true 即请求取消） */
export interface RepackSignal {
  aborted: boolean;
}

/**
 * 执行一轮重打包。
 *
 * 单张流程：读索引 → 解密（已是布局二则跳过）→ 取块密文并解密 →
 * 整图哈希校验 → 重加密为布局二并落库 → 删除旧记录集 → 通知调用方。
 * 任一步失败按张记账并保留源记录；取消在张边界生效。
 */
export async function runPhotoRepack(
  deps: RepackDeps,
  signal: RepackSignal,
): Promise<RepackResult> {
  const metaIds = deps.listMetaIds();
  const progress: RepackProgress = {
    total: metaIds.length,
    processed: 0,
    migrated: 0,
    skipped: 0,
    failed: 0,
    currentLabel: "",
  };
  const report = () => deps.onProgress?.({ ...progress });
  report();

  for (const metaId of metaIds) {
    if (signal.aborted) {
      return { ...toResult(progress), total: progress.total, aborted: true };
    }

    progress.currentLabel = `#${metaId}`;
    report();

    let meta: PhotoMetaLike;
    try {
      const records = await deps.readRecords([metaId]);
      const metaB64 = records.get(metaId) ?? "";
      if (!metaB64) {
        progress.failed++;
        progress.processed++;
        report();
        continue;
      }
      meta = await deps.decryptMeta(metaB64, `重打包 #${metaId}`);
    } catch {
      // 索引不可读（密钥不匹配 / 密文损坏）：保留源记录，按失败记账
      progress.failed++;
      progress.processed++;
      report();
      continue;
    }

    if (meta.name) progress.currentLabel = meta.name;

    if (alreadySlim(meta)) {
      progress.skipped++;
      progress.processed++;
      report();
      continue;
    }

    try {
      // 源数据取用与校验：不完整或哈希不符一律不迁移（源记录保持不变）
      const chunks = await deps.decryptChunks(meta, meta.name || `#${metaId}`);
      const plain = concatChunks(chunks);
      const actualHash = deps.hashPlaintext(plain);
      if (actualHash !== meta.fileHash) {
        plain.fill(0);
        progress.failed++;
        progress.processed++;
        report();
        continue;
      }

      const newMetaId = await deps.writeSlimPhoto(meta, plain);
      plain.fill(0);
      if (!(newMetaId > 0)) {
        progress.failed++;
        progress.processed++;
        report();
        continue;
      }

      // 新索引落库确认后才删除旧记录集：任何时刻都有可读索引
      await deps.deleteLegacyRecords(metaId, meta.chunkIds ?? []);
      deps.onMigrated?.(metaId, newMetaId);
      progress.migrated++;
      progress.processed++;
      report();
    } catch (e) {
      // 后端按内容哈希去重跳过：非失败语义（源记录保留，下一轮再试）
      if (e instanceof Error && e.message === "DUPLICATE_SKIPPED") {
        progress.skipped++;
      } else {
        progress.failed++;
      }
      progress.processed++;
      report();
    }
  }

  return { ...toResult(progress), total: progress.total, aborted: signal.aborted };
}

function toResult(progress: RepackProgress): Omit<RepackResult, "total" | "aborted"> {
  return {
    migrated: progress.migrated,
    skipped: progress.skipped,
    failed: progress.failed,
  };
}