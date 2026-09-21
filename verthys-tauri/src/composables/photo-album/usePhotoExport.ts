/**
 * photo-album/usePhotoExport.ts — 拾光模块导出层 composable
 *
 * 职责：管理照片导出对话框和三种导出格式（single/multiple/png）。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + usePhotoToast 的 showError/showToast/showExportDone/showCopied（依赖注入）
 * - 三种导出格式：单个打包文件 / 多个独立文件 / PNG 明文图片
 * - Tauri 模式写入磁盘，浏览器模式触发下载
 * - 兼容新旧 verthys 格式（内联 chunkDataB64 / 旧 chunkIds）
 * - meta 缺失时按需解密回退（重启后占位项导出场景）
 * - copyExportToken 三级降级：Tauri clipboard → navigator.clipboard → textarea execCommand
 * - tokenCopied 为按钮 UI 状态（图标切换），独立于 copiedToast 提示
 */
import { ref, watch, type Ref, type ShallowRef } from "vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import { verthysGetRecord, bytesToBase64, writeUserFile } from "../../lib/verthys";
import {
  encryptMeta, encryptChunk, decryptMeta, decryptChunk,
  computeFileHash, bytesToHex, packVencFile, packVencMultiFile,
  encryptExportFile, generateRandomToken, CHUNK_SIZE,
  type PhotoMeta, type VencPhotoData,
} from "../../lib/crypto";
import type { PhotoEntry, ExportFormat } from "./types";
import {
  guessMime, getBaseName, downloadBlob,
  convertToPngBytes, toArrayBuffer,
} from "./utils";

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
  /** 显示错误提示（来自 usePhotoToast，统一 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示导出完成提示（来自 usePhotoToast，统一 Toast 中心） */
  showExportDone: (msg: string, type: "success" | "error") => void;
  /** 显示复制成功提示（来自 usePhotoToast，统一 Toast 中心） */
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
  /** ★ 企业级根治：走 writeUserFile（Raw body + x-path 头），
   *   与 write_user_file 命令的真实协议一致；JSON+dataB64 旧写法与命令签名不符必失败。
   *   导出路径由用户通过 save() 对话框显式选择，不应受沙箱白名单限制 */
  const writeVencFile = async (path: string, bytes: Uint8Array): Promise<void> => {
    await writeUserFile(path, bytes);
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
    // ★ 通过 usePhotoToast 统一显示复制成功提示（替代原 copiedToast.value = true）
    showCopied();
    // tokenCopied 为按钮 UI 状态（图标切换为对勾），独立于提示
    tokenCopied.value = true;
    if (tokenCopiedTimer) clearTimeout(tokenCopiedTimer);
    tokenCopiedTimer = setTimeout(() => { tokenCopied.value = false; }, 1400);
  };

  const chooseExportPath = async () => {
    if (isTauri) {
      if (exportFormat.value === "single") {
        const path = await save({
          defaultPath: `photos_${Date.now()}.venc`,
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
   * ★ 企业级根治：meta 缺失时按需解密回填（重启后占位项 meta=undefined 的场景）
   */
  const getPhotoVerthysData = async (ph: PhotoEntry): Promise<{ metaB64: string; chunkB64List: string[] }> => {
    const metaB64 = ph.metaId ? (await verthysGetRecord(ph.metaId))?.dataB64 || "" : "";
    const chunkB64List: string[] = [];
    // ★ 企业级根治：meta 缺失时按需解密（重启后 watch 解密未完成即导出的场景）
    let meta = ph.meta;
    if (!meta && ph.metaId && metaB64) {
      try { meta = await decryptMeta(metaB64, photoKey.value); } catch { /* 解密失败 */ }
    }
    if (meta) {
      // 优先使用内联 chunkDataB64（新格式）
      if (meta.chunkDataB64 && meta.chunkDataB64.length > 0) {
        for (const cb of meta.chunkDataB64) chunkB64List.push(cb);
      } else if (meta.chunkIds && meta.chunkIds.length > 0) {
        // 旧格式：通过 verthys 记录 ID 查找 chunk
        for (const cid of meta.chunkIds) {
          const r = await verthysGetRecord(cid);
          if (r) chunkB64List.push(r.dataB64);
        }
      }
    }
    return { metaB64, chunkB64List };
  };

  /** 收集选中照片的加密数据 */
  const collectPhotoData = async (selected: PhotoEntry[]): Promise<VencPhotoData[]> => {
    const photoData: VencPhotoData[] = [];
    for (const ph of selected) {
      if (isTauri && ph.metaId) {
        // ★ 企业级根治：基于 metaId 判断（非 meta），重启后占位项也能导出
        // Tauri 模式：从 verthys 读取（兼容新旧格式 + 按需解密回退）
        const { metaB64, chunkB64List } = await getPhotoVerthysData(ph);
        if (metaB64) photoData.push({ metaB64, chunkB64List });
      } else if (!isTauri && ph.rawBytes) {
        // 浏览器模式：从内存中的原始字节加密
        const fileHashBytes = computeFileHash(ph.rawBytes);
        const fileHashHex = bytesToHex(fileHashBytes);
        const mime = guessMime(ph.name);
        const totalChunks = Math.ceil(ph.rawBytes.length / CHUNK_SIZE);
        const chunkB64List: string[] = [];

        for (let c = 0; c < totalChunks; c++) {
          const start = c * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, ph.rawBytes.length);
          const chunkPlain = ph.rawBytes.slice(start, end);
          const encryptedChunk = await encryptChunk(chunkPlain, photoKey.value, c, totalChunks, fileHashHex);
          chunkB64List.push(bytesToBase64(encryptedChunk));
        }

        const thumbB64 = ph.thumb.includes("base64,") ? ph.thumb.split("base64,")[1].replace(")", "") : "";
        const meta: PhotoMeta = {
          name: ph.name, mime, size: ph.rawBytes.length, thumbB64,
          chunkIds: [], fileHash: fileHashHex, createdAt: Date.now(),
        };
        const metaB64 = await encryptMeta(meta, photoKey.value);
        photoData.push({ metaB64, chunkB64List });
      }
    }
    return photoData;
  };

  /**
   * 从 verthys 解密照片的完整原始字节（用于 PNG 明文导出）
   * Tauri 模式：从 verthys 读取加密 chunk → 解密 → 合并
   * 浏览器模式：直接使用内存中的 rawBytes
   */
  const getDecryptedPhotoBytes = async (ph: PhotoEntry): Promise<Uint8Array | null> => {
    // 浏览器模式：直接用缓存的原始字节
    if (!isTauri && ph.rawBytes) {
      return ph.rawBytes;
    }

    // ★ 企业级根治：meta 缺失时按需解密（重启后 watch 解密未完成即导出的场景）
    let meta = ph.meta;
    if (!meta) {
      if (!ph.metaId) return null;
      const metaB64 = (await verthysGetRecord(ph.metaId))?.dataB64 || "";
      if (!metaB64) return null;
      try { meta = await decryptMeta(metaB64, photoKey.value); } catch { return null; }
    }

    const chunks: Uint8Array[] = [];

    // 优先使用内联 chunkDataB64（新格式，避免 ID 漂移）
    if (meta.chunkDataB64 && meta.chunkDataB64.length > 0) {
      for (let c = 0; c < meta.chunkDataB64.length; c++) {
        try {
          const { plaintext } = await decryptChunk(
            meta.chunkDataB64[c], photoKey.value, meta.fileHash
          );
          chunks.push(plaintext);
        } catch { /* skip corrupt chunk */ }
      }
    } else if (meta.chunkIds && meta.chunkIds.length > 0) {
      // 旧格式：通过 verthys 记录 ID 查找 chunk
      for (const chunkId of meta.chunkIds) {
        const r = await verthysGetRecord(chunkId);
        if (!r) continue;
        try {
          const { plaintext } = await decryptChunk(r.dataB64, photoKey.value, meta.fileHash);
          chunks.push(plaintext);
        } catch { /* skip corrupt chunk */ }
      }
    }

    if (chunks.length === 0) return null;

    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const fullBytes = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) { fullBytes.set(c, offset); offset += c.length; }
    return fullBytes;
  };

  const doExport = async () => {
    if (exportSelectedIds.value.size === 0) return;
    // 浏览器模式自动满足路径条件
    if (isTauri && !exportPath.value) return;
    exporting.value = true;
    exportProgress.value = 0;

    const selected = photos.value.filter(p => exportSelectedIds.value.has(p.id));

    try {
      if (exportFormat.value === "single") {
        // === 单文件模式 ===
        exportStatus.value = "读取照片数据…";
        exportProgress.value = 10;
        const photoData = await collectPhotoData(selected);

        exportStatus.value = "打包加密数据…";
        exportProgress.value = 50;
        const vencBytes = packVencMultiFile(photoData);

        exportStatus.value = "AES-256-GCM 加密…";
        exportProgress.value = 70;
        const encrypted = await encryptExportFile(vencBytes, exportToken.value);

        exportStatus.value = "写入…";
        exportProgress.value = 90;

        if (isTauri) {
          await writeVencFile(exportPath.value, encrypted);
        } else {
          downloadBlob(encrypted, `photos_${Date.now()}.venc`);
        }

        exportProgress.value = 100;
        exportStatus.value = `导出完成（${selected.length} 张照片）`;
      } else if (exportFormat.value === "png") {
        // === PNG 明文导出模式 ===
        let successCount = 0;
        let failCount = 0;

        if (isTauri) {
          const dir = exportPath.value.replace(/[\\/]+$/, "");
          for (let i = 0; i < selected.length; i++) {
            const ph = selected[i];
            exportStatus.value = `转换 ${ph.name}（${i + 1}/${selected.length}）…`;
            exportProgress.value = Math.round((i / selected.length) * 100);

            try {
              const rawBytes = await getDecryptedPhotoBytes(ph);
              if (!rawBytes) {
                console.error(`[PNG 导出] ${ph.name} 解密失败，跳过`);
                failCount++;
                continue;
              }
              const mime = ph.meta?.mime || guessMime(ph.name);
              const pngBytes = await convertToPngBytes(rawBytes, mime);
              await writeVencFile(`${dir}/${getBaseName(ph.name)}.png`, pngBytes);
              successCount++;
            } catch (e) {
              console.error(`[PNG 导出] ${ph.name} 转换失败:`, e);
              failCount++;
            }
          }
        } else {
          // 浏览器模式：逐个转换并下载
          for (let i = 0; i < selected.length; i++) {
            const ph = selected[i];
            exportStatus.value = `转换 ${ph.name}（${i + 1}/${selected.length}）…`;
            exportProgress.value = Math.round((i / selected.length) * 100);

            try {
              const rawBytes = await getDecryptedPhotoBytes(ph);
              if (!rawBytes) {
                failCount++;
                continue;
              }
              const mime = ph.meta?.mime || guessMime(ph.name);
              const pngBytes = await convertToPngBytes(rawBytes, mime);
              downloadBlob(pngBytes, `${getBaseName(ph.name)}.png`);
              successCount++;
              // 防止浏览器拦截多下载
              await new Promise(r => setTimeout(r, 500));
            } catch (e) {
              console.error(`[PNG 导出] ${ph.name} 转换失败:`, e);
              failCount++;
            }
          }
        }

        exportProgress.value = 100;
        exportStatus.value = failCount > 0
          ? `已导出 ${successCount} 张 PNG（${failCount} 张失败）`
          : `已导出 ${successCount} 张 PNG`;
      } else {
        // === 多文件模式 ===
        if (isTauri) {
          const dir = exportPath.value.replace(/[\\/]+$/, "");
          for (let i = 0; i < selected.length; i++) {
            const ph = selected[i];
            exportStatus.value = `导出 ${ph.name}（${i + 1}/${selected.length}）…`;
            exportProgress.value = Math.round((i / selected.length) * 100);

            if (ph.meta) {
              const { metaB64, chunkB64List } = await getPhotoVerthysData(ph);
              const vencBytes = await packVencFile(metaB64, chunkB64List);
              const encrypted = await encryptExportFile(vencBytes, exportToken.value);
              await writeVencFile(`${dir}/${ph.name}.venc`, encrypted);
            }
          }
        } else {
          // 浏览器模式：逐个下载
          for (let i = 0; i < selected.length; i++) {
            const ph = selected[i];
            exportStatus.value = `导出 ${ph.name}（${i + 1}/${selected.length}）…`;
            exportProgress.value = Math.round((i / selected.length) * 100);

            const photoData = await collectPhotoData([ph]);
            if (photoData.length > 0) {
              const vencBytes = await packVencFile(photoData[0].metaB64, photoData[0].chunkB64List);
              const encrypted = await encryptExportFile(vencBytes, exportToken.value);
              downloadBlob(encrypted, `${ph.name}.venc`);
              // 防止浏览器拦截多下载
              await new Promise(r => setTimeout(r, 500));
            }
          }
        }

        exportProgress.value = 100;
        exportStatus.value = `已导出 ${selected.length} 张照片`;
      }

      // ★ 通过 usePhotoToast 统一显示导出完成提示
      showExportDone("导出完成", "success");
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

  /** 单张照片导出（从照片卡片上的导出按钮触发） */
  const onExportSingle = async (ph: PhotoEntry) => {
    // 模块密钥超时锁定后提示用户返回重新解锁
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }

    const token = generateRandomToken(32);

    if (isTauri) {
      const savePath = await save({
        defaultPath: `${ph.name}.venc`,
        filters: [{ name: "Verthys 加密照片", extensions: ["venc"] }],
      });
      if (!savePath) return;

      try {
        if (ph.meta) {
          const { metaB64, chunkB64List } = await getPhotoVerthysData(ph);
          const vencBytes = await packVencFile(metaB64, chunkB64List);
          const encrypted = await encryptExportFile(vencBytes, token);
          await writeVencFile(savePath, encrypted);
        }
      } catch (e) {
        console.error("导出失败:", e);
      }
    } else {
      // 浏览器模式：直接下载
      try {
        const photoData = await collectPhotoData([ph]);
        if (photoData.length > 0) {
          const vencBytes = await packVencFile(photoData[0].metaB64, photoData[0].chunkB64List);
          const encrypted = await encryptExportFile(vencBytes, token);
          downloadBlob(encrypted, `${ph.name}.venc`);
        }
      } catch (e) {
        console.error("导出失败:", e);
      }
    }

    exportToken.value = token;
    // ★ 通过 usePhotoToast 统一显示复制成功提示
    showCopied();
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
    // ===== 导出数据处理 =====
    getPhotoVerthysData,
    collectPhotoData,
    getDecryptedPhotoBytes,
    // ===== 导出执行 =====
    doExport,
    onExportSingle,
    // ===== 工具函数 =====
    writeVencFile,
  };
}
