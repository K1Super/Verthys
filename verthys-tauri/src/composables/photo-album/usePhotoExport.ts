/**
 * photo-album/usePhotoExport.ts — 拾光模块导出层 composable
 *
 * 职责：管理照片导出对话框和三种导出格式（single/multiple/png）。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + 全局 Toast 中心的 showError/showExportDone/showCopied（依赖注入）
 * - 三种导出格式：单个打包文件 / 多个独立文件 / PNG 明文图片
 * - Tauri 模式写入磁盘，浏览器模式触发下载
 * - 兼容新旧 verthys 格式（内联 chunkDataB64 / 旧 chunkIds）
 * - meta 缺失时按需解密回退（重启后占位项导出场景）
 * - copyExportToken 三级降级：Tauri clipboard → navigator.clipboard → textarea execCommand
 * - tokenCopied 为按钮 UI 状态（图标切换），独立于 copiedToast 提示
 * - 结果三态契约：成功计数 / 失败明细 / 跳过明细，完成文案仅由成功计数派生
 * - 导出文件名经 sanitizeFileName 净化 + uniqueFileName 批次内唯一化
 */
import { ref, watch, onScopeDispose, type Ref, type ShallowRef } from "vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import { verthysGetRecord, verthysGetRecordDetailed, bytesToBase64, writeUserFile, writeUserFileStream, appendUserFileChunk, finalizeUserFileStream, abortUserFileStream } from "../../lib/verthys";
import { base64ToBytes } from "../../utils/binary_codec";
import {
  encryptChunk,
  computeFileHash, bytesToHex, packVencV2, packVencV2Streamed,
  estimateVencTotalBytes, toLightMeta, computeChunkHashesForB64,
  generateRandomToken, CHUNK_SIZE,
  type PhotoMeta, type VencPhotoSpecV2,
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

const log = createLogger("photo-export");

/** 导出失败原因分类（跨格式统一，供 UI 汇总） */
type ExportFailureReason =
  | "data-missing"    // 记录/元数据/块数据缺失（含占位项无法解密）
  | "pack-failed"     // 容器打包失败
  | "encrypt-failed"  // 外层令牌加密失败
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

/** 导出结果三态契约：完成文案与 Toast 的唯一派生来源 */
export interface ExportOutcome {
  /** 成功导出的照片数 */
  successCount: number;
  /** 失败的照片数（含失败明细） */
  failCount: number;
  /** 被跳过的照片数（如单文件模式因个别照片缺数据被剔除） */
  skippedCount: number;
  /** 失败明细（按照片） */
  failures: ExportFailure[];
}

/** usePhotoExport 依赖注入接口 */
export interface UsePhotoExportParams {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 模块独立密钥 */
  photoKey: Ref<string>;
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
  const { photos, photoKey, isTauri, ensurePhotoKey, showError, showExportDone, showCopied } = params;

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

  /* ===== 写入 .venc 文件到磁盘（Tauri 模式） ===== */
  /** 修复：走 writeUserFile（Raw body + x-path 头），
   *   与 write_user_file 命令的真实协议一致；JSON+dataB64 旧写法与命令签名不符必失败。
   *   导出路径由用户通过 save() 对话框显式选择，不应受沙箱白名单限制 */
  const writeVencFile = async (path: string, bytes: Uint8Array): Promise<void> => {
    await writeUserFile(path, bytes);
  };

  /** 单文件流式写出：建会话 → 逐帧追加 → finalize 原子替换。
   *
   *  容器按帧流式产出即写盘：前端峰值内存与容器总字节解耦（单张照片
   *  上限 100MB，容器可达数百 MB）。失败路径中止会话清理暂存，abort
   *  幂等（会话不存在视为成功）；清理失败仅记录，原始错误原样上抛，
   *  成功/失败判定不依赖清理结果。
   *
   * @param onBytes 每段落盘后的进度回调（累计已写字节 / 预估总字节） */
  const writeVencFileStreamed = async (
    path: string,
    specs: VencPhotoSpecV2[],
    onBytes: (written: number, total: number) => void,
  ): Promise<void> => {
    const streamId = await writeUserFileStream(path);
    const totalBytes = estimateVencTotalBytes(specs);
    let written = 0;
    try {
      await packVencV2Streamed(specs, exportToken.value, async (part) => {
        await appendUserFileChunk(streamId, part);
        written += part.length;
        onBytes(written, totalBytes);
      });
      await finalizeUserFileStream(streamId);
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
  };

  const closeExportDialog = () => {
    if (exporting.value) return;
    showExportDialog.value = false;
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

  const regenerateExportToken = () => {
    // 直接重新生成（用户决策：不再弹确认窗口）——令牌仅在本次导出窗口内
    // 有效，尚未导出时不存在旧凭据失效风险
    exportToken.value = generateRandomToken(32);
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
      try {
        const ta = document.createElement("textarea");
        ta.value = exportToken.value;
        ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        success = true;
      } catch { /* */ }
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
   * 从 verthys 读取单张照片的加密数据（兼容新旧两种格式）
   * - 新格式：chunk 数据内联在 meta 记录的 chunkDataB64 字段中（推荐，避免 ID 漂移）
   * - 旧格式：通过 chunkIds 单独查找 chunk 记录（向后兼容）
   * 修复：meta 缺失时按需解密回填（重启后占位项 meta=undefined 的场景）
   */
  const getPhotoVerthysData = async (
    ph: PhotoEntry,
  ): Promise<{
    metaB64: string;
    chunkB64List: string[];
    meta: PhotoMeta | null;
    /** 逐块密文哈希（块集/索引给出的权威值；缺失时调用方现场补算） */
    chunkHashesForExport: string[];
  }> => {
    let metaB64 = "";
    if (ph.metaId) {
      // 判别式读取：超出单条上限 / 通道异常与"记录不存在"分流留痕，
      //   不再统一退化为"记录缺失"（旧返回值无法定位归因）。
      const readOutcome = await verthysGetRecordDetailed(ph.metaId);
      if (readOutcome.ok) {
        metaB64 = readOutcome.record.dataB64;
      } else {
        console.warn(`[导出] 读取照片元数据失败（${readOutcome.code}）: ${readOutcome.error}`);
      }
    }
    const chunkB64List: string[] = [];
    let chunkHashesForExport: string[] = [];
    // 修复：meta 缺失时按需解密（重启后 watch 解密未完成即导出的场景）
    let meta: PhotoMeta | null = ph.meta ?? null;
    if (!meta && ph.metaId && metaB64) {
      try {
        const outcome = await decryptMetaPreferWorker(
          metaB64, photoKey.value, ph.name || `导出 #${ph.metaId}`,
        );
        meta = outcome.meta;
      } catch {
        // 解密失败：meta 置空，由调用方按 data-missing 记账并展示
        meta = null;
      }
    }
    if (meta) {
      // 索引瘦身布局：缩略图在独立记录中，导出容器需要明文缩略图
      //   （容器轻量头带缩略图，由容器密钥保护）；解密经 Worker 池（与索引
      //   同盐时命中池内派生缓存，不额外产生 PBKDF2），池不可用时由桥回退。
      if (isSlimPhotoMeta(meta) && meta.thumbId && meta.wrappedFileKey && !meta.thumbB64) {
        const thumbRecord = await verthysGetRecord(meta.thumbId);
        if (!thumbRecord?.dataB64) {
          // 缩略图记录缺失：按数据缺失记账（不产出无缩略图的容器）
          return { metaB64, chunkB64List: [], meta: null, chunkHashesForExport: [] };
        }
        const thumbBytes = await decryptThumbPreferWorker(
          thumbRecord.dataB64, photoKey.value, meta.wrappedFileKey, meta.fileHash,
          meta.name || `导出 #${ph.metaId}`,
        );
        meta = { ...meta, thumbB64: bytesToBase64(thumbBytes) };
      }
      // 逐块引用布局分流（瘦身布局取块集记录；既有布局取索引内联引用）
      try {
        const refs = await resolveChunkRefs(meta, photoKey.value, meta.name || `记录 #${ph.metaId}`);
        const { ciphers, missing } = await loadChunkCiphers(refs);
        if (missing > 0) {
          // 任一记录缺失即整体不可靠（块数将少于声明值），清空后由调用方记失败
          return { metaB64, chunkB64List: [], meta: null, chunkHashesForExport: [] };
        }
        for (const cb of ciphers) chunkB64List.push(cb);
        // 逐块权威哈希随引用一并带回（容器逐块校验与导出结果使用）
        chunkHashesForExport = refs.hashes;
      } catch (e) {
        log.warn(`导出读取块引用失败: ${e instanceof Error ? e.message : String(e)}`);
        return { metaB64, chunkB64List: [], meta: null, chunkHashesForExport: [] };
      }
    }
    return { metaB64, chunkB64List, meta, chunkHashesForExport };
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
    const refs = await resolveChunkRefs(meta, photoKey.value, label);
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
    // 完整性校验随解密任务下沉：逐块密文哈希与整图明文哈希在 Worker 内比对，
    //   主线程不再对兆字节级数据做同步哈希（回退路径保持同等校验标准）。
    const chunks = await decryptChunksPreferWorker(
      chunkB64List, photoKey.value, meta.fileHash, label, slim,
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

    // 修复：meta 缺失时按需解密（重启后 watch 解密未完成即导出的场景）
    let meta = ph.meta;
    if (!meta) {
      if (!ph.metaId) return null;
      // 判别式读取：归因保留（超限/通道异常不再与"记录不存在"混同）
      const readOutcome = await verthysGetRecordDetailed(ph.metaId);
      if (!readOutcome.ok) {
        console.warn(`[导出] 读取照片元数据失败（${readOutcome.code}）: ${readOutcome.error}`);
        return null;
      }
      const metaB64 = readOutcome.record.dataB64;
      if (!metaB64) return null;
      try {
        const outcome = await decryptMetaPreferWorker(
          metaB64, photoKey.value, ph.name || `导出 #${ph.metaId}`,
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
   * 收集选中照片的容器数据（单文件/多文件模式共用入口，v2 逐帧容器）。
   * 逐张失败显式计入 failures；历史记录缺 chunkHashes 时现场补算（与块密文同源）。
   */
  const collectPhotoSpecs = async (
    selected: PhotoEntry[],
    failures: ExportFailure[],
  ): Promise<VencPhotoSpecV2[]> => {
    const specs: VencPhotoSpecV2[] = [];
    for (const ph of selected) {
      if (isTauri && ph.metaId) {
        // 修复：基于 metaId 判断（非 meta），重启后占位项也能导出
        // Tauri 模式：从 verthys 读取（兼容新旧格式 + 按需解密回退）
        const { metaB64, chunkB64List, meta, chunkHashesForExport } = await getPhotoVerthysData(ph);
        if (!metaB64 || chunkB64List.length === 0 || !meta) {
          failures.push({ name: meta?.name || ph.name || `记录 #${ph.metaId}`, reason: "data-missing" });
          continue;
        }
        const chunkBytes = chunkB64List.map((cb) => base64ToBytes(cb));
        // 块哈希优先取权威值（块集 / 索引给出；缺失时现场补算），保证容器逐块校验可用
        const chunkHashes =
          chunkHashesForExport.length === chunkBytes.length
            ? chunkHashesForExport
            : computeChunkHashesForB64(chunkB64List);
        const lightMeta = toLightMeta({ ...meta, chunkDataB64: chunkB64List, chunkHashes });
        specs.push({ lightMeta, chunkBytes });
      } else if (!isTauri && ph.rawBytes) {
        // 浏览器模式：从内存中的原始字节加密（每块密文即帧负载）
        const fileHashBytes = computeFileHash(ph.rawBytes);
        const fileHashHex = bytesToHex(fileHashBytes);
        const mime = guessMime(ph.name);
        const totalChunks = Math.ceil(ph.rawBytes.length / CHUNK_SIZE);
        const b64List: string[] = [];
        const chunkBytes: Uint8Array[] = [];

        for (let c = 0; c < totalChunks; c++) {
          const start = c * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, ph.rawBytes.length);
          const chunkPlain = ph.rawBytes.slice(start, end);
          const encryptedChunk = await encryptChunk(chunkPlain, photoKey.value, c, totalChunks, fileHashHex);
          b64List.push(bytesToBase64(encryptedChunk));
          chunkBytes.push(encryptedChunk);
        }

        const thumbB64 = ph.thumb.includes("base64,") ? ph.thumb.split("base64,")[1].replace(")", "") : "";
        const meta: PhotoMeta = {
          name: ph.name, mime, size: ph.rawBytes.length, thumbB64,
          chunkIds: [], chunkDataB64: b64List,
          chunkHashes: computeChunkHashesForB64(b64List),
          fileHash: fileHashHex, createdAt: Date.now(),
        };
        specs.push({ lightMeta: toLightMeta(meta), chunkBytes });
      } else {
        failures.push({ name: ph.name || `照片 #${ph.id}`, reason: "data-missing" });
      }
    }
    return specs;
  };

  /** 派生导出目标文件名（净化 + 批次内唯一化），basename 缺失时回退占位 */
  const makeExportFileName = (
    baseName: string,
    ext: string,
    fallbackId: number,
    used: Set<string>,
  ): string => {
    const cleaned = sanitizeFileName(baseName, MAX_EXPORT_FILENAME_BYTES);
    const stem = cleaned === "photo" ? `photo_${fallbackId}` : cleaned;
    return uniqueFileName(`${stem}${ext}`, used);
  };

  const doExport = async () => {
    if (exportSelectedIds.value.size === 0) return;
    // 浏览器模式自动满足路径条件
    if (isTauri && !exportPath.value) return;
    // 加密导出的令牌为必填且不低于最小长度（支持自定义编辑，可能被清空或
    // 过短）：前置拦截，避免读完照片数据才在打包层失败；PNG 为明文导出，
    // 不需要令牌
    if (exportFormat.value !== "png" && exportToken.value.trim().length < MIN_TOKEN_LENGTH) {
      showError(`加密令牌至少 ${MIN_TOKEN_LENGTH} 位字符，请填写或重新生成`);
      return;
    }
    exporting.value = true;
    exportProgress.value = 0;

    const selected = photos.value.filter(p => exportSelectedIds.value.has(p.id));
    // 批次内输出名唯一化上下文：任何格式下同一名称不互相覆盖
    const usedNames = new Set<string>();

    try {
      let outcome: ExportOutcome;

      if (exportFormat.value === "single") {
        // === 单文件模式：全部选中照片打包为单个 .venc v2 容器 ===
        const failures: ExportFailure[] = [];
        exportStatus.value = "读取照片数据…";
        exportProgress.value = 10;
        const specs = await collectPhotoSpecs(selected, failures);

        if (specs.length > 0) {
          // 单文件模式的累计上限前置拦截：先按产出估算拦截，避免读完照片
          //   数据、写出部分帧后才在追加阶段失败（浪费解密与 IO 成本）。
          const estimatedBytes = estimateVencTotalBytes(specs);
          if (estimatedBytes > MAX_EXPORT_SINGLE_BYTES) {
            // 上限读数按 GB 展示（跨层常量为 GB 级时，MB 读数不易比较）
            const limitGb = MAX_EXPORT_SINGLE_BYTES / (1024 * 1024 * 1024);
            const limitText = `${Number.isInteger(limitGb) ? limitGb : limitGb.toFixed(1)} GB`;
            exportStatus.value = `预计容器体积超过单文件上限 ${limitText}，请改用多文件模式`;
            showExportDone(`容器体积超过单文件上限（${limitText}），请改用多文件模式`, "error");
            exporting.value = false;
            return;
          }
          exportStatus.value = "逐帧加密打包…";
          exportProgress.value = 50;

          if (isTauri) {
            // 单文件模式流式写出：容器逐帧产出即落盘，峰值内存与容器
            // 总字节解耦；进度按「累计已写 / 预估总量」换算，单调爬升。
            await writeVencFileStreamed(exportPath.value, specs, (written, total) => {
              const ratio = total > 0 ? written / total : 0;
              exportProgress.value = Math.min(95, 50 + Math.round(ratio * 45));
            });
          } else {
            const vencBytes = await packVencV2(specs, exportToken.value);
            downloadBlob(vencBytes, `verthys_${Date.now()}.venc`);
          }
        }

        exportProgress.value = 100;
        outcome = {
          successCount: specs.length,
          failCount: failures.length,
          skippedCount: 0,
          failures,
        };
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
                downloadBlob(pngBytes, `${sanitizeFileName(displayName, MAX_EXPORT_FILENAME_BYTES)}.png`);
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

          return { successCount, failCount: failures.length, skippedCount: 0, failures };
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

              try {
                const { metaB64, chunkB64List, meta, chunkHashesForExport } = await getPhotoVerthysData(ph);
                if (!metaB64 || chunkB64List.length === 0 || !meta) {
                  failures.push({
                    name: meta?.name || ph.name || `记录 #${ph.metaId ?? ph.id}`,
                    reason: "data-missing",
                  });
                  continue;
                }
                const chunkBytes = chunkB64List.map((cb) => base64ToBytes(cb));
                const chunkHashes =
                  chunkHashesForExport.length === chunkBytes.length
                    ? chunkHashesForExport
                    : computeChunkHashesForB64(chunkB64List);
                const lightMeta = toLightMeta({ ...meta, chunkDataB64: chunkB64List, chunkHashes });
                const vencBytes = await packVencV2([{ lightMeta, chunkBytes }], exportToken.value);
                const displayName = meta.name || ph.name;
                const fileName = `${sanitizeFileName(displayName, MAX_EXPORT_FILENAME_BYTES)}.venc`;
                await writeVencFile(`${dir}/${uniqueFileName(fileName, usedNames)}`, vencBytes);
                successCount++;
              } catch (e) {
                console.error(`[多文件导出] ${ph.name} 失败:`, e);
                failures.push({ name: ph.name || `#${ph.metaId ?? ph.id}`, reason: "write-failed" });
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
                const vencBytes = await packVencV2(specs, exportToken.value);
                downloadBlob(vencBytes, `${sanitizeFileName(ph.name, MAX_EXPORT_FILENAME_BYTES)}.venc`);
                successCount++;
                // 防止浏览器拦截多下载
                await new Promise(r => setTimeout(r, 500));
              }
            }
          }

          return { successCount, failCount: failures.length, skippedCount: 0, failures };
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
              "encrypt-failed": "加密失败",
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
    selectAllPhotos,
    deselectAllPhotos,
    regenerateExportToken,
    copyExportToken,
    chooseExportPath,
    // ===== 导出执行 =====
    doExport,
    // ===== 写出通道（保留导出以支持协议级测试断言） =====
    writeVencFile,
  };
}
