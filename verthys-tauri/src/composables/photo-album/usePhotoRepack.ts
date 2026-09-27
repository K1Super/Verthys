/**
 * photo-album/usePhotoRepack.ts — 后台重打包编排层（存量布局 → 索引瘦身布局）
 *
 * 职责：为 repack 引擎装配真实依赖（摘要索引、扫描缓存取数、解密桥、Worker 池、
 * 导入流水线的写入会话），维护运行态与进度，处理列表项引用切换与取消。
 *
 * 门禁：仅在写入布局开关为索引瘦身布局时可用（默认关 → 入口不出现）；
 * 运行期为后台任务：逐张处理、可取消、可续跑（已迁移项自动跳过），
 * 不阻塞前台交互（解密与加密均在 Worker 池执行，逐张之间让出主线程）。
 */
import { ref, type Ref, type ShallowRef } from "vue";
import {
  deleteAndPersistBatch, invalidateSummaryRecord, invalidateFullRecord, invalidateScannedRecord,
  getSummaryIdsByType, getRecordsDataB64Batch,
} from "../../lib/keyManager";
import {
  computeFileHash, bytesToHex, type PhotoMeta,
} from "../../lib/crypto";
import {
  PHOTO_FMT_SLIM, PHOTO_WRITE_FMT, TYPE_PHOTO_META,
} from "../../constants/crypto_const";
import { decryptMetaPreferWorker } from "../../workers/photo-decrypt-bridge";
import { photoWorkerPool } from "../../workers/photoWorkerPool";
import { updateShallowItem } from "../../utils/shallow-array";
import { yieldToMain } from "../../utils/promise_utils";
import type { ImportPipeline } from "./importPipeline";
import type { PhotoEntry } from "./types";
import { revokeThumbUrl } from "./utils";
import { resolveChunkRefs, loadChunkCiphers } from "./chunk-refs";
import {
  runPhotoRepack, type PhotoMetaLike, type RepackProgress, type RepackSignal,
} from "./repack";
import { decryptChunksPreferWorker } from "../../workers/photo-decrypt-bridge";
import { createLogger } from "../../utils/logger";

const log = createLogger("photo-repack");

/** 重打包依赖注入 */
export interface UsePhotoRepackParams {
  /** 照片列表（迁移完成后原位替换记录引用） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 照片模块独立密钥 */
  photoKey: Ref<string>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 导入流水线（重打包复用其外置写入链路与会话） */
  getPipeline: () => ImportPipeline;
  showToast: (msg: string) => void;
  showError: (msg: string) => void;
}

/** 重打包对外状态 */
export interface RepackState {
  running: boolean;
  /** 已处理 / 总数（真实计数） */
  processed: number;
  total: number;
  /** 进度百分比（processed/total，无待迁移项时为 0） */
  percent: number;
  message: string;
}

export function usePhotoRepack(params: UsePhotoRepackParams) {
  const { photos, photoKey, isTauri, getPipeline, showToast, showError } = params;

  /** 写入布局开关是否允许重打包（默认关：既有布局下不提供迁移入口） */
  const repackAvailable = ref(PHOTO_WRITE_FMT === PHOTO_FMT_SLIM);
  /** 是否正在重打包 */
  const repackRunning = ref(false);
  /** 进度快照（运行中与刚结束时可见，结束后由 UI 自行收起） */
  const repackState = ref<RepackState | null>(null);

  /** 取消标志（引擎在张边界读取） */
  let signal: RepackSignal = { aborted: false };

  const toState = (p: RepackProgress): RepackState => ({
    running: true,
    processed: p.processed,
    total: p.total,
    percent: p.total > 0 ? Math.floor((p.processed / p.total) * 100) : 0,
    message: `迁移旧布局照片 ${p.processed}/${p.total}（成功 ${p.migrated}，跳过 ${p.skipped}，失败 ${p.failed}）`,
  });

  /** 迁移完成回调：列表项引用切换到新记录，并复位其解密状态等待按需重解密 */
  const onMigrated = (oldMetaId: number, newMetaId: number) => {
    const arr = photos.value;
    for (let i = 0; i < arr.length; i++) {
      if (arr[i].metaId === oldMetaId) {
        if (arr[i].thumb) revokeThumbUrl(arr[i].thumb);
        updateShallowItem(photos, i, {
          id: newMetaId,
          metaId: newMetaId,
          thumb: "",
          size: "",
          loaded: false,
          failed: false,
          meta: undefined,
        });
        return;
      }
    }
  };

  /** 删除旧记录集（索引 + 旧块）并失效三层缓存 */
  const deleteLegacyRecords = async (metaId: number, chunkIds: number[]): Promise<void> => {
    const ids = [metaId, ...chunkIds];
    await deleteAndPersistBatch(ids);
    for (const id of ids) {
      invalidateSummaryRecord(id);
      invalidateFullRecord(id);
      invalidateScannedRecord(id);
    }
  };

  /** 启动重打包（幂等：运行中重复调用直接返回） */
  const startRepack = async (): Promise<void> => {
    if (repackRunning.value) return;
    if (!isTauri) return;
    if (!repackAvailable.value) {
      showError("写入布局开关未开启（默认既有布局），重打包不可用");
      return;
    }
    if (!photoKey.value) {
      showError("模块密钥不可用，请重新验证后重试");
      return;
    }
    const metaIds = getSummaryIdsByType(TYPE_PHOTO_META);
    if (metaIds.length === 0) {
      showToast("没有可迁移的照片");
      return;
    }

    signal = { aborted: false };
    repackRunning.value = true;
    repackState.value = {
      running: true, processed: 0, total: metaIds.length, percent: 0,
      message: `迁移旧布局照片 0/${metaIds.length}`,
    };

    const pipeline = getPipeline();
    let sessionOpen = false;
    try {
      await pipeline.beginRepackSession();
      sessionOpen = true;

      const result = await runPhotoRepack(
        {
          listMetaIds: () => getSummaryIdsByType(TYPE_PHOTO_META),
          readRecords: (ids) => getRecordsDataB64Batch(ids),
          decryptMeta: async (metaB64, label) => {
            const { meta } = await decryptMetaPreferWorker(metaB64, photoKey.value, label);
            return meta;
          },
          decryptChunks: async (metaLike, label) => {
            const meta = metaLike as PhotoMeta;
            const refs = await resolveChunkRefs(meta, photoKey.value, label);
            const { ciphers, missing } = await loadChunkCiphers(refs);
            if (missing > 0 || ciphers.length === 0) {
              throw new Error(`源数据块不完整（缺失 ${missing} 块）`);
            }
            return decryptChunksPreferWorker(ciphers, photoKey.value, meta.fileHash, label);
          },
          writeSlimPhoto: async (metaLike, plainBytes) => {
            const meta = metaLike as PhotoMeta;
            const success = await photoWorkerPool.submitSlimRepack({
              fileBytes: plainBytes,
              request: {
                fileHashHex: meta.fileHash,
                name: meta.name ?? "photo",
                mime: meta.mime ?? "application/octet-stream",
                size: meta.size ?? plainBytes.length,
                createdAt: meta.createdAt ?? Date.now(),
                thumbB64: meta.thumbB64 ?? "",
                photoKey: photoKey.value,
              },
            });
            return pipeline.writeRepackedPhoto(
              success, photoKey.value, `meta_${meta.name ?? "photo"}`,
            );
          },
          deleteLegacyRecords,
          onMigrated,
          onProgress: (p) => {
            repackState.value = toState(p);
          },
          hashPlaintext: (bytes) => bytesToHex(computeFileHash(bytes)),
        },
        signal,
      );

      await pipeline.endRepackSession(result.failed === 0);
      sessionOpen = false;
      const tail = result.aborted ? "（已取消，可再次点击继续）" : "";
      showToast(
        `迁移完成：成功 ${result.migrated}，跳过 ${result.skipped}，失败 ${result.failed}${tail}`,
      );
      if (result.failed > 0) {
        log.warn(`重打包存在失败项: ${result.failed}（源记录保持不变）`);
      }
      repackState.value = null;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log.error("重打包异常:", e);
      if (sessionOpen) {
        try { await pipeline.endRepackSession(false); } catch { /* 会话收尾失败忽略 */ }
      }
      showError(`迁移失败：${msg}`);
      repackState.value = null;
    } finally {
      // 逐张之间让出主线程：会话收尾后刷新一次待迁移集合，为下一轮续跑留出视图
      await yieldToMain();
      repackRunning.value = false;
    }
  };

  /** 请求取消（在张边界生效；在途一张正常收尾，源记录不会被半途删除） */
  const cancelRepack = (): void => {
    if (!repackRunning.value) return;
    signal.aborted = true;
    showToast("已请求取消迁移，当前照片收尾后停止");
  };

  return {
    repackAvailable,
    repackRunning,
    repackState,
    startRepack,
    cancelRepack,
  };
}