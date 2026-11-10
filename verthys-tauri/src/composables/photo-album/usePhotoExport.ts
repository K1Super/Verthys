/**
 * photo-album/usePhotoExport.ts — 拾光模块导出层 composable
 *
 * 职责：管理照片导出对话框和三种导出格式（single/multiple/png）。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + 全局 Toast 中心的 showError/showExportDone/showCopied（依赖注入）
 * - 三种导出格式：单个打包文件 / 多个独立文件 / PNG 明文图片
 * - Tauri 模式写入磁盘，浏览器模式触发下载
 * - 兼容两种容器格式（内联 chunkDataB64 / 外置 chunkIds）
 * - meta 缺失时按需解密回退（重启后占位项导出场景）
 * - copyExportToken 三级降级：Tauri clipboard → navigator.clipboard → textarea execCommand
 * - tokenCopied 为按钮 UI 状态（图标切换），独立于 copiedToast 提示
 * - 结果契约：成功计数 / 失败明细，完成文案仅由成功计数派生
 * - 导出文件名经 sanitizeFileName 净化 + uniqueFileName 批次内唯一化
 */
import { ref, computed, watch, onScopeDispose, type ShallowRef } from "vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import { verthysGetRecord, verthysGetRecordDetailed, bytesToBase64, writeUserFile, writeUserFileStream, appendUserFileChunk, finalizeUserFileStream, abortUserFileStream } from "../../lib/verthys";
import {
  packVenc, packVencStreamedLazy,
  estimateVencTotalBytes, toLightMeta,
  generateRandomToken, VENC_CONTAINER_FIXED_BYTES, vencPhotoFramesBytes,
  type PhotoMeta, type VencPhotoSpec,
} from "../../lib/crypto";
import {
  decryptMetaPreferWorker, decryptThumbPreferWorker, decryptChunksPreferWorker,
} from "../../workers/photo-decrypt-bridge";
import { MAX_EXPORT_FILENAME_BYTES, MAX_EXPORT_SINGLE_BYTES, MIN_TOKEN_LENGTH, isSlimPhotoMeta, isSlimLayout } from "../../constants/crypto_const";
import type { PhotoEntry, ExportFormat } from "./types";
import {
  guessMime, downloadBlob, convertToPngBytes,
  sanitizeFileName, uniqueFileName,
} from "./utils";
import { resolveChunkRefs, loadChunkCiphers } from "./chunk-refs";
import { createLogger } from "../../utils/logger";
import { pushModal, popModal } from "../../utils/modal_stack";

const log = createLogger("photo-export");

/** 导出失败原因分类（跨格式统一，供 UI 汇总） */
type ExportFailureReason =
  | "data-missing"    // 记录/元数据/块数据缺失（含占位项无法解密）
  | "pack-failed"     // 容器打包失败（清单越界/令牌加密失败）
  | "decrypt-failed"  // 明文导出解密失败
  | "convert-failed"  // 图片格式转换失败
  | "write-failed";   // 落盘/下载失败

/** 单条失败明细（按张定位，供结果摘要展示） */
interface ExportFailure {
  /** 照片显示名（缺失时回退记录 ID 描述） */
  name: string;
  /** 失败原因分类 */
  reason: ExportFailureReason;
}

/** 照片解密/完整性校验失败（与格式转换失败区分，保证失败归因准确） */
class PhotoDecryptError extends Error {}

/**
 * 单文件容器体积超出上限。
 *
 * 惰性写出路径在「写出该张之前」累计真实帧字节，超限即抛本错误；
 * 调用方据此给出「请改用多文件模式」的专用提示，而不是通用导出失败。
 */
class ExportTooLargeError extends Error {
  constructor() {
    super("容器体积超过单文件上限");
    this.name = "ExportTooLargeError";
  }
}

/** 导出结果三态契约：完成文案与 Toast 的唯一派生来源 */
export interface ExportOutcome {
  /** 成功导出的照片数 */
  successCount: number;
  /** 失败的照片数（含失败明细） */
  failCount: number;
  /** 失败明细（按照片） */
  failures: ExportFailure[];
}

/** usePhotoExport 依赖注入接口 */
export interface UsePhotoExportParams {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 恢复模块密钥（从 keyManager 会话缓存） */
  ensurePhotoKey: () => boolean;
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示导出完成提示（来自全局 Toast 中心） */
  showExportDone: (msg: string, type: "success" | "error") => void;
  /** 显示复制成功提示（来自全局 Toast 中心） */
  showCopied: () => void;
}

export function usePhotoExport(params: UsePhotoExportParams) {
  const { photos, isTauri, ensurePhotoKey, showError, showExportDone, showCopied } = params;

  /* ===== 导出对话框状态 ===== */
  const showExportDialog = ref(false);
  const exportSelectedIds = ref<Set<number>>(new Set());
  const exportToken = ref("");
  const exportFormat = ref<ExportFormat>("single");
  const exportPath = ref("");
  const exporting = ref(false);
  const exportProgress = ref(0);
  const exportStatus = ref("");
  /** 复制按钮 UI 状态：true 时显示对勾图标（1.4s 后复位），独立于 copiedToast 提示 */
  const tokenCopied = ref(false);
  let tokenCopiedTimer: ReturnType<typeof setTimeout> | undefined;

  /* ===== 模态层身份（滚动锁与 Esc 栈序由共享模态栈统一管理） =====
   * 导出面板与查看器、确认窗可以叠层：入栈/出栈必须严格成对，
   * 否则一次 Esc 会连内层一并关掉，或滚动锁提前解除。 */
  const exportModalId = Symbol("photo-export");
  let exportModalEngaged = false;
  const engageExportModal = () => {
    if (exportModalEngaged) return;
    exportModalEngaged = true;
    pushModal(exportModalId);
  };
  const releaseExportModal = () => {
    if (!exportModalEngaged) return;
    exportModalEngaged = false;
    popModal(exportModalId);
  };

  /* ===== 写入 .venc 文件到磁盘（Tauri 模式） ===== */
  /** 走 writeUserFile（Raw body + x-path 头），与 write_user_file 命令协议一致；
   *   导出路径由用户通过 save() 对话框显式选择，不应受沙箱白名单限制 */
  const writeVencFile = async (path: string, bytes: Uint8Array): Promise<void> => {
    await writeUserFile(path, bytes);
  };

  /**
   * 读取单张照片的容器数据（惰性路径的唯一驻留单位）。
   *
   * 只有当前这一张的明文块被解码为字节，帧写出后引用即失效 —— 这是单文件
   * 导出内存峰值与容器总字节解耦的关键。
   */
  const loadPhotoSpec = async (
    ph: PhotoEntry,
  ): Promise<
    | { ok: true; spec: VencPhotoSpec }
    | { ok: false; name: string; reason: ExportFailureReason }
  > => {
    const outcome = await loadPortableSpec(ph);
    if (outcome.ok) return { ok: true, spec: outcome.spec };
    return { ok: false, name: outcome.name, reason: outcome.reason };
  };

  /**
   * 单文件惰性流式写出：建会话 → 逐张加载 → 逐帧追加 → finalize 原子替换。
   *
   * 峰值内存 = 一张照片的块字节 + 一个输出段（与容器总字节无关）。
   * 体积预算在写出该张之前累计（`VENC_CONTAINER_FIXED_BYTES` + 逐张帧字节），
   * 超限即抛 ExportTooLargeError，暂存文件随会话中止清理 —— 不会留下
   * 超限或半截产物。
   *
   * @returns packed 实际打包张数；skippedEmpty 表示全部照片都不可导出（未 finalize）
   */
  const writeVencFileStreamedLazy = async (
    path: string,
    selected: readonly PhotoEntry[],
    failures: ExportFailure[],
    onPhoto: (index: number, total: number) => void,
  ): Promise<{ packed: number; skippedEmpty: boolean }> => {
    const streamId = await writeUserFileStream(path);
    let produced = VENC_CONTAINER_FIXED_BYTES;
    let packed = 0;
    try {
      await packVencStreamedLazy(
        selected.length,
        exportToken.value,
        async (index) => {
          const ph = selected[index];
          const outcome = await loadPhotoSpec(ph);
          onPhoto(index, selected.length);
          if (!outcome.ok) {
            failures.push({ name: outcome.name, reason: outcome.reason });
            return null;
          }
          const spec = outcome.spec;
          produced += vencPhotoFramesBytes(spec.lightMeta, spec.chunkBytes.map((c) => c.length));
          if (produced > MAX_EXPORT_SINGLE_BYTES) throw new ExportTooLargeError();
          packed += 1;
          return spec;
        },
        async (part) => {
          await appendUserFileChunk(streamId, part);
        },
      );
      if (packed === 0) {
        // 一张都没能打包：容器不允许零照片，直接中止暂存会话（不 finalize）
        try { await abortUserFileStream(streamId); } catch { /* 清理失败仅记录在调用方 */ }
        return { packed: 0, skippedEmpty: true };
      }
      await finalizeUserFileStream(streamId);
      return { packed, skippedEmpty: false };
    } catch (e) {
      try {
        await abortUserFileStream(streamId);
      } catch (abortErr) {
        console.error("[导出] 流式会话中止清理失败", abortErr);
      }
      throw e;
    }
  };

  const openExportDialog = () => {
    if (photos.value.length === 0) return;
    // 模块密钥超时锁定后提示用户返回重新解锁
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }
    // 默认全选
    exportSelectedIds.value = new Set(photos.value.map(p => p.id));
    // 自动生成随机令牌
    exportToken.value = generateRandomToken(32);
    exportFormat.value = "single";
    exportPath.value = isTauri ? "" : "browser_download";
    exportProgress.value = 0;
    exportStatus.value = "";
    showExportDialog.value = true;
    engageExportModal();
  };

  const closeExportDialog = () => {
    if (exporting.value) return;
    showExportDialog.value = false;
    releaseExportModal();
  };

  /* 格式切换时重置路径（single 选文件 vs multiple/png 选目录，路径类型不同） */
  watch(exportFormat, () => {
    exportPath.value = isTauri ? "" : "browser_download";
  });

  const togglePhotoSelect = (id: number) => {
    const s = new Set(exportSelectedIds.value);
    if (s.has(id)) s.delete(id);
    else s.add(id);
    exportSelectedIds.value = s;
  };

  const selectAllPhotos = () => {
    exportSelectedIds.value = new Set(photos.value.map(p => p.id));
  };

  const deselectAllPhotos = () => {
    exportSelectedIds.value = new Set();
  };

  /** 是否已全选：全选/取消全选单键的派生状态（相册为空时不成立） */
  const allPhotosSelected = computed(
    () => photos.value.length > 0 && exportSelectedIds.value.size === photos.value.length,
  );

  /** 单键全选切换：已全选则清空，否则全选 */
  const toggleSelectAllPhotos = () => {
    if (allPhotosSelected.value) deselectAllPhotos();
    else selectAllPhotos();
  };

  const regenerateExportToken = () => {
    // 直接重新生成（不弹确认窗口）——令牌仅在本次导出窗口内
    // 有效，尚未导出时不存在既有凭据失效风险
    exportToken.value = generateRandomToken(32);
    // 新旧令牌已不同：复制成功态必须复位，不能继续显示上一枚令牌的对勾
    tokenCopied.value = false;
    if (tokenCopiedTimer) {
      clearTimeout(tokenCopiedTimer);
      tokenCopiedTimer = undefined;
    }
  };

  const copyExportToken = async () => {
    if (!exportToken.value) return;
    let success = false;
    // 优先尝试 Tauri clipboard 插件（若已安装）
    if (isTauri) {
      try {
        const moduleName = "@tauri-apps/plugin-clipboard-manager";
        const mod: any = await import(/* @vite-ignore */ moduleName);
        if (mod?.writeText) { await mod.writeText(exportToken.value); success = true; }
      } catch { /* 插件未安装，降级 */ }
    }
    // 降级到 navigator.clipboard
    if (!success) {
      try { await navigator.clipboard.writeText(exportToken.value); success = true; } catch { /* */ }
    }
    // 最终降级：textarea + execCommand（兼容旧版 WebView）
    if (!success) {
      const ta = document.createElement("textarea");
      try {
        ta.value = exportToken.value;
        ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        // execCommand 返回布尔：false 表示复制未发生，不能当作成功
        success = document.execCommand("copy");
      } catch {
        success = false;
      } finally {
        ta.remove();
      }
    }
    // 三级通道全部失败：如实提示，不置对勾、不启动复位计时
    if (!success) {
      showError("复制失败：剪贴板不可用或权限被拒绝");
      return;
    }
    // 通过全局 Toast 中心统一显示复制成功提示
    showCopied();
    // tokenCopied 为按钮 UI 状态（图标切换为对勾），独立于提示
    tokenCopied.value = true;
    if (tokenCopiedTimer) clearTimeout(tokenCopiedTimer);
    tokenCopiedTimer = setTimeout(() => { tokenCopied.value = false; }, 1400);
  };

  // 组件卸载时清理复制按钮复位定时器（与导入/解析层的定时器纳管规范一致）
  onScopeDispose(() => {
    if (tokenCopiedTimer) clearTimeout(tokenCopiedTimer);
    // 面板未关闭即卸载：必须归还滚动锁，否则整页永久不可滚动
    releaseExportModal();
  });

  const chooseExportPath = async () => {
    if (isTauri) {
      if (exportFormat.value === "single") {
        const path = await save({
          defaultPath: `verthys_${Date.now()}.venc`,
          filters: [{ name: "Verthys 加密照片", extensions: ["venc"] }],
        });
        if (path) exportPath.value = path;
      } else {
        const dir = await open({ directory: true });
        if (dir) exportPath.value = typeof dir === "string" ? dir : "";
      }
    } else {
      // 浏览器模式：标记为下载
      exportPath.value = "browser_download";
    }
  };

  /**
   * 读取单张照片并产出可移植容器输入：本地解密为原始明文块。
   *
   * 容器不再携带模块密钥加密态；导出必须先在当前模块密钥下完成解密与
   * 完整性校验，再由容器令牌密钥重新加密。失败按可归因分类返回，
   * 不把「解密失败」误报为「数据缺失」。
   */
  const loadPortableSpec = async (
    ph: PhotoEntry,
  ): Promise<
    | { ok: true; spec: VencPhotoSpec }
    | { ok: false; name: string; reason: ExportFailureReason }
  > => {
    const displayName = ph.meta?.name || ph.name || `记录 #${ph.metaId ?? ph.id}`;
    let metaB64 = "";
    if (ph.metaId) {
      try {
        const readOutcome = await verthysGetRecordDetailed(ph.metaId);
        if (readOutcome.ok) {
          metaB64 = readOutcome.record.dataB64;
        } else {
          log.warn(`[导出] 读取照片元数据失败（${readOutcome.code}）: ${readOutcome.error}`);
        }
      } catch (e) {
        // 单条读取异常不得中断整批导出：按该张数据缺失记账，其余照常
        log.warn(`[导出] 读取照片元数据异常（${displayName}）:`, e);
      }
    }
    if (!ph.metaId || !metaB64) {
      return { ok: false, name: displayName, reason: "data-missing" };
    }

    let meta: PhotoMeta | null = ph.meta ?? null;
    if (!meta) {
      try {
        const outcome = await decryptMetaPreferWorker(metaB64, displayName);
        meta = outcome.meta;
      } catch (e) {
        log.warn(`[导出] 元数据解密失败（${displayName}）:`, e);
        return { ok: false, name: displayName, reason: "decrypt-failed" };
      }
    }
    if (!meta) {
      return { ok: false, name: displayName, reason: "data-missing" };
    }

    // 索引瘦身布局：缩略图在独立记录中，容器清单需要明文缩略图
    if (isSlimPhotoMeta(meta) && meta.thumbId && meta.wrappedFileKey && !meta.thumbB64) {
      let thumbRecord: { dataB64?: string } | null = null;
      try {
        thumbRecord = await verthysGetRecord(meta.thumbId);
      } catch (e) {
        log.warn(`[导出] 读取缩略图记录异常（${displayName}）:`, e);
      }
      if (!thumbRecord?.dataB64) {
        return { ok: false, name: displayName, reason: "data-missing" };
      }
      try {
        const thumbBytes = await decryptThumbPreferWorker(
          thumbRecord.dataB64, meta.wrappedFileKey, meta.fileHash, displayName,
        );
        meta = { ...meta, thumbB64: bytesToBase64(thumbBytes) };
      } catch (e) {
        log.warn(`[导出] 缩略图解密失败（${displayName}）:`, e);
        return { ok: false, name: displayName, reason: "decrypt-failed" };
      }
    }

    let ciphers: string[];
    let hashes: string[];
    try {
      const refs = await resolveChunkRefs(meta, displayName);
      const loaded = await loadChunkCiphers(refs);
      if (loaded.missing > 0) {
        return { ok: false, name: displayName, reason: "data-missing" };
      }
      ciphers = loaded.ciphers;
      hashes = refs.hashes;
    } catch (e) {
      log.warn(`[导出] 读取块引用失败（${displayName}）:`, e);
      return { ok: false, name: displayName, reason: "data-missing" };
    }
    if (ciphers.length === 0) {
      return { ok: false, name: displayName, reason: "data-missing" };
    }

    const slim = isSlimLayout(meta) && meta.wrappedFileKey
      ? { wrappedFileKey: meta.wrappedFileKey, chunkTotal: ciphers.length }
      : undefined;
    let chunkBytes: Uint8Array[];
    try {
      chunkBytes = await decryptChunksPreferWorker(
        ciphers, meta.fileHash, displayName, slim,
        {
          expectedHashes: hashes.length > 0 ? hashes : undefined,
          // 整图明文哈希是轮换后仍成立的权威值；逐块密文哈希仅作诊断
          expectedFileHash: meta.fileHash,
        },
      );
    } catch (e) {
      log.warn(`[导出] 数据块解密失败（${displayName}）:`, e);
      return { ok: false, name: displayName, reason: "decrypt-failed" };
    }
    const total = chunkBytes.reduce((sum, chunk) => sum + chunk.length, 0);
    if (total !== meta.size) {
      log.warn(`[导出] 明文块字节数与元数据不符（${displayName}）: ${total} ≠ ${meta.size}`);
      return { ok: false, name: displayName, reason: "decrypt-failed" };
    }
    try {
      return { ok: true, spec: { lightMeta: toLightMeta(meta, chunkBytes.length), chunkBytes } };
    } catch (e) {
      // 清单字段超出容器契约（历史数据可能携带超限缩略图/名称）：按该张失败记账，
      // 不得让一条坏记录拖垮整批导出。
      log.warn(`[导出] 照片清单字段非法（${displayName}）:`, e);
      return { ok: false, name: displayName, reason: "pack-failed" };
    }
  };

  /**
   * 解密并合并照片完整原始字节，执行三重完整性校验：
   *   1. 块数校验：取出的块密文数量必须与引用声明一致（缺失即抛错）
   *   2. 顺序校验：既有布局的块自描述位置（seq/total）必须与列表位置一致
   *      （在共享解密路径内判定，与查看器/重打包口径统一）
   *   3. 内容校验：合并字节的 BLAKE3 与 meta.fileHash 比对（截断/替换即抛错）
   * 解密经 Worker 池（主线程不做派生与 AEAD），池不可用时由桥回退主线程；
   * 校验失败统一抛 Error，由调用方按 decrypt-failed 记账并指名照片，
   * 杜绝「截断/乱序产物被当作成功导出」的静默路径。
   */
  const decryptPhotoBytesWithVerify = async (meta: PhotoMeta): Promise<Uint8Array> => {
    const label = meta.name || "导出";
    // 逐块引用布局分流（瘦身布局取块集记录；既有布局取索引内联引用）
    const refs = await resolveChunkRefs(meta, label);
    const { ciphers: chunkB64List, missing } = await loadChunkCiphers(refs);
    if (missing > 0) throw new Error(`数据块记录缺失 ${missing} 条`);
    if (chunkB64List.length === 0) throw new Error("照片无数据块");

    const expectedTotal = chunkB64List.length;
    // 逐块哈希权威值非空即必须与块数一致；残缺或不符在解密任务内拒绝
    //   （空哈希数组属历史记录，保持兼容不比对）。
    if (refs.hashes.length > 0 && refs.hashes.length !== expectedTotal) {
      throw new Error(`哈希项数与块数不一致（哈希 ${refs.hashes.length} ≠ 块 ${expectedTotal}）`);
    }
    // 索引瘦身布局：块密文不携带序号与总数，位置由列表给出并绑定进 AD
    const slim = isSlimLayout(meta) && meta.wrappedFileKey
      ? { wrappedFileKey: meta.wrappedFileKey, chunkTotal: expectedTotal }
      : undefined;
    // 完整性校验随解密任务下沉：整图明文哈希为唯一权威值，逐块密文哈希仅作
    //   诊断（密钥轮换会合法改变密文）；主线程不做兆字节级同步哈希。
    const chunks = await decryptChunksPreferWorker(
      chunkB64List, meta.fileHash, label, slim,
      {
        expectedHashes: refs.hashes.length > 0 ? refs.hashes : undefined,
        expectedFileHash: meta.fileHash,
      },
    );
    if (chunks.length !== expectedTotal) {
      throw new Error(`解密块数不一致: 期望 ${expectedTotal}，实得 ${chunks.length}`);
    }

    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const fullBytes = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) { fullBytes.set(c, offset); offset += c.length; }
    return fullBytes;
  };

  /**
   * 获取照片完整明文字节与元数据（用于 PNG 明文导出、文件名与 MIME 推导）。
   * Tauri 模式：解密（经 Worker 池）+ 三重完整性校验；浏览器模式：直接使用内存 rawBytes。
   *
   * @returns 明文字节与元数据；元数据不可得时返回 null（调用方按 decrypt-failed 记账）
   * @throws PhotoDecryptError 解密或完整性校验失败（调用方据此与格式转换失败区分）
   */
  const getDecryptedPhotoBytes = async (
    ph: PhotoEntry,
  ): Promise<{ bytes: Uint8Array; meta: PhotoMeta | null } | null> => {
    // 浏览器模式：直接用缓存的原始字节（未加密存储，无哈希元数据可校验）
    if (!isTauri && ph.rawBytes) {
      return { bytes: ph.rawBytes, meta: ph.meta ?? null };
    }

    // meta 缺失时按需解密（重启后 watch 解密未完成即导出的场景）
    let meta = ph.meta;
    if (!meta) {
      if (!ph.metaId) return null;
      // 判别式读取：归因保留（超限/通道异常不再与"记录不存在"混同）
      let readOutcome: Awaited<ReturnType<typeof verthysGetRecordDetailed>>;
      try {
        readOutcome = await verthysGetRecordDetailed(ph.metaId);
      } catch (e) {
        console.warn(`[导出] 读取照片元数据异常（${ph.name || ph.metaId}）:`, e);
        return null;
      }
      if (!readOutcome.ok) {
        console.warn(`[导出] 读取照片元数据失败（${readOutcome.code}）: ${readOutcome.error}`);
        return null;
      }
      const metaB64 = readOutcome.record.dataB64;
      if (!metaB64) return null;
      try {
        const outcome = await decryptMetaPreferWorker(
          metaB64, ph.name || `导出 #${ph.metaId}`,
        );
        meta = outcome.meta;
      } catch {
        return null;
      }
    }

    try {
      const bytes = await decryptPhotoBytesWithVerify(meta);
      return { bytes, meta };
    } catch (e) {
      // 统一抛给调用方记账：完整性校验失败的照片不得静默产出截断文件；
      // 专用错误类型让调用方把「解密失败」与「格式转换失败」区分开
      throw new PhotoDecryptError(
        `照片 "${meta.name}" 完整性校验失败: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  };

  /**
   * 收集选中照片的容器数据（浏览器/多文件共用入口）。
   * 逐张失败显式计入 failures，并保留可归因原因。
   */
  const collectPhotoSpecs = async (
    selected: PhotoEntry[],
    failures: ExportFailure[],
  ): Promise<VencPhotoSpec[]> => {
    const specs: VencPhotoSpec[] = [];
    for (const ph of selected) {
      if (isTauri && ph.metaId) {
        const outcome = await loadPortableSpec(ph);
        if (!outcome.ok) {
          failures.push({ name: outcome.name, reason: outcome.reason });
          continue;
        }
        specs.push(outcome.spec);
      } else {
        if (!isTauri && ph.rawBytes) {
          /* 浏览器模式没有 Tauri worker，无法在密钥不出渲染进程的前提下产出
           * 明文块；导出功能只在桌面运行时提供，不回退到在 JS 内派生模块密钥。 */
          log.warn(`浏览器模式不支持加密容器导出: ${ph.name}`);
        }
        failures.push({ name: ph.name || `照片 #${ph.id}`, reason: "data-missing" });
      }
    }
    return specs;
  };

  /** 文件名净化：字节预算必须含扩展名，否则超长名称拼上后缀后仍会越界 */
  const sanitizeWithExtension = (name: string, ext: string): string => {
    const extBytes = new TextEncoder().encode(ext).length;
    return `${sanitizeFileName(name, Math.max(1, MAX_EXPORT_FILENAME_BYTES - extBytes))}${ext}`;
  };

  /** 派生导出目标文件名（净化 + 批次内唯一化），basename 缺失时回退占位 */
  const makeExportFileName = (
    baseName: string,
    ext: string,
    fallbackId: number,
    used: Set<string>,
  ): string => {
    const cleaned = sanitizeWithExtension(baseName, ext);
    const stem = cleaned === `photo${ext}` ? `photo_${fallbackId}${ext}` : cleaned;
    return uniqueFileName(stem, used);
  };

  const doExport = async () => {
    if (exportSelectedIds.value.size === 0) return;
    // 浏览器模式自动满足路径条件
    if (isTauri && !exportPath.value) return;
    // 对话框可能在模块密钥超时锁定后仍停留：执行前必须重新确认会话密钥可用，
    // 否则会把「模块已锁定」误报为逐张解密/完整性失败。
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }
    // 加密导出的令牌为必填且不低于最小长度（支持自定义编辑，可能被清空或
    // 过短）：前置拦截，避免读完照片数据才在打包层失败；PNG 为明文导出，
    // 不需要令牌
    if (exportFormat.value !== "png" && exportToken.value.trim().length < MIN_TOKEN_LENGTH) {
      showError(`加密令牌至少 ${MIN_TOKEN_LENGTH} 位字符，请填写或重新生成`);
      return;
    }
    if (exportFormat.value !== "png") {
      // 与还原端归一化口径一致：令牌首尾空白不参与派生，否则导出可成功但
      // 还原端按 trim 后的令牌派生会解封失败（备份不可恢复）
      exportToken.value = exportToken.value.trim();
    }
    exporting.value = true;
    exportProgress.value = 0;

    const selected = photos.value.filter(p => exportSelectedIds.value.has(p.id));
    if (selected.length === 0) {
      // 选片集合与当前列表脱节（列表被刷新/清空）：不得以「已导出 0 张」假成功收尾
      exporting.value = false;
      return;
    }
    // 批次内输出名唯一化上下文：任何格式下同一名称不互相覆盖
    const usedNames = new Set<string>();

    try {
      let outcome: ExportOutcome;

      if (exportFormat.value === "single") {
        // === 单文件模式：全部选中照片打包为单个 .venc 备份容器 ===
        const failures: ExportFailure[] = [];
        exportStatus.value = "读取照片数据…";
        exportProgress.value = 10;

        if (isTauri) {
          // 惰性流式写出：一次只驻留一张照片的块字节，体积预算在写出该张
          // 之前累计；超限即中止暂存会话（不留超限产物），并以专用文案引导
          // 改用多文件模式。
          exportStatus.value = "逐帧加密打包…";
          exportProgress.value = 50;
          let writtenResult: { packed: number; skippedEmpty: boolean };
          try {
            writtenResult = await writeVencFileStreamedLazy(
              exportPath.value,
              selected,
              failures,
              (index, total) => {
                exportStatus.value = `逐帧加密打包 ${index + 1}/${total}…`;
                exportProgress.value = Math.min(96, 50 + Math.round(((index + 1) / total) * 46));
              },
            );
          } catch (e) {
            if (e instanceof ExportTooLargeError) {
              // 上限读数按 GB 展示（跨层常量为 GB 级时，MB 读数不易比较）
              const limitGb = MAX_EXPORT_SINGLE_BYTES / (1024 * 1024 * 1024);
              const limitText = `${Number.isInteger(limitGb) ? limitGb : limitGb.toFixed(1)} GB`;
              exportStatus.value = `容器体积超过单文件上限 ${limitText}，请改用多文件模式`;
              showExportDone(`容器体积超过单文件上限（${limitText}），请改用多文件模式`, "error");
              exporting.value = false;
              return;
            }
            throw e;
          }
          exportProgress.value = 100;
          outcome = {
            successCount: writtenResult.packed,
            failCount: failures.length,
            failures,
          };
        } else {
          // 浏览器模式：无流式落盘通道，保持「装配后一次性下载」
          const specs = await collectPhotoSpecs(selected, failures);
          if (specs.length > 0) {
            const estimatedBytes = estimateVencTotalBytes(specs);
            if (estimatedBytes > MAX_EXPORT_SINGLE_BYTES) {
              const limitGb = MAX_EXPORT_SINGLE_BYTES / (1024 * 1024 * 1024);
              const limitText = `${Number.isInteger(limitGb) ? limitGb : limitGb.toFixed(1)} GB`;
              exportStatus.value = `预计容器体积超过单文件上限 ${limitText}，请改用多文件模式`;
              showExportDone(`容器体积超过单文件上限（${limitText}），请改用多文件模式`, "error");
              exporting.value = false;
              return;
            }
            exportStatus.value = "逐帧加密打包…";
            exportProgress.value = 50;
            const vencBytes = await packVenc(specs, exportToken.value);
            downloadBlob(vencBytes, `verthys_${Date.now()}.venc`);
          }
          exportProgress.value = 100;
          outcome = {
            successCount: specs.length,
            failCount: failures.length,
            failures,
          };
        }
      } else if (exportFormat.value === "png") {
        // === PNG 明文导出模式：逐张解密（三重完整性校验）→ 转换 → 写出 ===
        outcome = await (async (): Promise<ExportOutcome> => {
          let successCount = 0;
          const failures: ExportFailure[] = [];

          if (isTauri) {
            const dir = exportPath.value.replace(/[\\/]+$/, "");
            for (let i = 0; i < selected.length; i++) {
              const ph = selected[i];
              exportStatus.value = `转换 ${ph.name || `#${ph.metaId ?? ph.id}`}（${i + 1}/${selected.length}）…`;
              exportProgress.value = Math.round((i / selected.length) * 100);

              try {
                const decoded = await getDecryptedPhotoBytes(ph);
                if (!decoded) {
                  failures.push({ name: ph.name || `#${ph.metaId ?? ph.id}`, reason: "decrypt-failed" });
                  continue;
                }
                // 名称与 MIME 一律以解密出的元数据为准：占位项 ph.name 为空串，
                //   若以其命名将产出 ".png" 并互相覆盖
                const displayName = decoded.meta?.name || ph.name || `照片${ph.metaId ?? ph.id}`;
                const mime = decoded.meta?.mime || guessMime(displayName);
                const pngBytes = await convertToPngBytes(decoded.bytes, mime);
                const fileName = makeExportFileName(
                  displayName.replace(/\.(png|jpe?g|webp|gif|bmp)$/i, ""),
                  ".png",
                  ph.metaId ?? ph.id,
                  usedNames,
                );
                await writeVencFile(`${dir}/${fileName}`, pngBytes);
                successCount++;
              } catch (e) {
                console.error(`[PNG 导出] ${ph.name} 转换失败:`, e);
                failures.push({
                  name: ph.name || `#${ph.metaId ?? ph.id}`,
                  reason: e instanceof PhotoDecryptError ? "decrypt-failed" : "convert-failed",
                });
              }
            }
          } else {
            // 浏览器模式：逐个转换并下载
            for (let i = 0; i < selected.length; i++) {
              const ph = selected[i];
              exportStatus.value = `转换 ${ph.name}（${i + 1}/${selected.length}）…`;
              exportProgress.value = Math.round((i / selected.length) * 100);

              try {
                const decoded = await getDecryptedPhotoBytes(ph);
                if (!decoded) {
                  failures.push({ name: ph.name, reason: "decrypt-failed" });
                  continue;
                }
                const displayName = decoded.meta?.name || ph.name;
                const mime = decoded.meta?.mime || guessMime(displayName);
                const pngBytes = await convertToPngBytes(decoded.bytes, mime);
                downloadBlob(pngBytes, sanitizeWithExtension(displayName, ".png"));
                successCount++;
                // 防止浏览器拦截多下载
                await new Promise(r => setTimeout(r, 500));
              } catch (e) {
                console.error(`[PNG 导出] ${ph.name} 转换失败:`, e);
                failures.push({
                  name: ph.name,
                  reason: e instanceof PhotoDecryptError ? "decrypt-failed" : "convert-failed",
                });
              }
            }
          }

          return { successCount, failCount: failures.length, failures };
        })();
      } else {
        // === 多文件模式：逐张打包为独立 .venc，占位项按需解密后计入结果 ===
        outcome = await (async (): Promise<ExportOutcome> => {
          let successCount = 0;
          const failures: ExportFailure[] = [];

          if (isTauri) {
            const dir = exportPath.value.replace(/[\\/]+$/, "");
            for (let i = 0; i < selected.length; i++) {
              const ph = selected[i];
              exportStatus.value = `导出 ${ph.name || `#${ph.metaId ?? ph.id}`}（${i + 1}/${selected.length}）…`;
              exportProgress.value = Math.round((i / selected.length) * 100);

              let outcome: Awaited<ReturnType<typeof loadPortableSpec>>;
              try {
                outcome = await loadPortableSpec(ph);
              } catch (e) {
                console.error(`[多文件导出] ${ph.name} 读取失败:`, e);
                failures.push({ name: ph.name || `#${ph.metaId ?? ph.id}`, reason: "data-missing" });
                continue;
              }
              if (!outcome.ok) {
                failures.push({ name: outcome.name, reason: outcome.reason });
                continue;
              }
              let vencBytes: Uint8Array;
              try {
                vencBytes = await packVenc([outcome.spec], exportToken.value);
              } catch (e) {
                console.error(`[多文件导出] ${ph.name} 打包失败:`, e);
                failures.push({ name: outcome.spec.lightMeta.name || ph.name, reason: "pack-failed" });
                continue;
              }
              const displayName = outcome.spec.lightMeta.name || ph.name;
              const fileName = sanitizeWithExtension(displayName, ".venc");
              try {
                await writeVencFile(`${dir}/${uniqueFileName(fileName, usedNames)}`, vencBytes);
                successCount++;
              } catch (e) {
                console.error(`[多文件导出] ${ph.name} 写入失败:`, e);
                failures.push({ name: displayName, reason: "write-failed" });
              }
            }
          } else {
            // 浏览器模式：逐个下载
            for (let i = 0; i < selected.length; i++) {
              const ph = selected[i];
              exportStatus.value = `导出 ${ph.name}（${i + 1}/${selected.length}）…`;
              exportProgress.value = Math.round((i / selected.length) * 100);

              const specs = await collectPhotoSpecs([ph], failures);
              if (specs.length > 0) {
                try {
                  const vencBytes = await packVenc(specs, exportToken.value);
                  downloadBlob(vencBytes, sanitizeWithExtension(ph.name, ".venc"));
                  successCount++;
                  // 防止浏览器拦截多下载
                  await new Promise(r => setTimeout(r, 500));
                } catch (e) {
                  console.error(`[多文件导出] ${ph.name} 浏览器打包失败:`, e);
                  failures.push({ name: ph.name, reason: "pack-failed" });
                }
              }
            }
          }

          return { successCount, failCount: failures.length, failures };
        })();
      }

      // ===== 结果文案仅由 ExportOutcome 派生（不得使用选中数/总数） =====
      exportProgress.value = 100;
      const { successCount, failCount, failures } = outcome;
      if (failCount === 0) {
        exportStatus.value = `已导出 ${successCount} 张照片`;
        showExportDone("导出完成", "success");
      } else if (successCount === 0) {
        const reasonText = failures[0]
          ? {
              "data-missing": "照片数据缺失",
              "pack-failed": "容器打包失败",
              "decrypt-failed": "照片解密或完整性校验失败",
              "convert-failed": "图片转换失败",
              "write-failed": "写入失败",
            }[failures[0].reason]
          : "未知错误";
        exportStatus.value = `导出失败：${failCount} 张（${reasonText}）`;
        showExportDone(`导出失败（${failCount} 张）`, "error");
      } else {
        exportStatus.value = `已导出 ${successCount} 张，失败 ${failCount} 张`;
        showExportDone(`部分导出成功（失败 ${failCount} 张）`, "error");
      }
      setTimeout(() => {
        exporting.value = false;
        showExportDialog.value = false;
        releaseExportModal();
      }, 2000);
    } catch (e) {
      console.error("[onExportBatch] 导出失败", e);
      exportStatus.value = "导出失败，请重试";
      showExportDone("导出失败，请重试", "error");
      exporting.value = false;
    }
  };

  return {
    // ===== 导出对话框状态 =====
    showExportDialog,
    exportSelectedIds,
    exportToken,
    exportFormat,
    exportPath,
    exporting,
    exportProgress,
    exportStatus,
    tokenCopied,
    // ===== 导出对话框方法 =====
    openExportDialog,
    closeExportDialog,
    togglePhotoSelect,
    allPhotosSelected,
    toggleSelectAllPhotos,
    regenerateExportToken,
    copyExportToken,
    chooseExportPath,
    // ===== 导出执行 =====
    doExport,
    // ===== 写出通道（保留导出以支持协议级测试断言） =====
    writeVencFile,
  };
}
