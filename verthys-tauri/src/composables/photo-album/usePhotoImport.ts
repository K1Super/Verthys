/**
 * photo-album/usePhotoImport.ts — 拾光模块导入层 composable
 *
 * Comprehensive_optimization：异步批处理流水线重构
 *
 * 职责：管理照片导入（加密入库）逻辑。
 * - Tauri 模式：使用三阶段异步流水线（生产者 → 传输器 → 消费者）
 *   - 生产者：流式读取文件 → transferList 零拷贝到 Worker
 *   - 传输器：Worker 池并行加密（hardwareConcurrency-1）
 *   - 消费者：批量 IPC 写入（N 次加密 1 次 IPC）+ 批量三层缓存同步 + WAL
 * - 浏览器模式：保留原始字节到内存（用于后续导出），不使用流水线
 *
 * 保持 ref 兼容：importing / importProgress / importStatus
 * 新增 ref：importElapsed / importEta（供 QuantumProgressFlow 使用）
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + usePhotoToast 的 showError（依赖注入）
 * - 批量构建 importedItems 后一次性 pushShallowItems，避免循环内多次触发响应式
 * - persistVerthys + 返回值检查 + setModuleCache 更新缓存
 */
import { ref, watch, type ShallowRef, type Ref } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { readUserFile } from "../../lib/verthys";
import { persistVerthys, setModuleCache } from "../../lib/keyManager";
import { pushShallowItems } from "../../utils/shallow-array";
import { yieldToMain } from "../../utils/promise_utils";
import type { PhotoEntry } from "./types";
import { formatSize, generateThumbnail, guessMime, openBrowserFileDialog, toArrayBuffer } from "./utils";
import { ImportPipeline, importedToPhotoEntries, type ImportFileInput } from "./importPipeline";

/** usePhotoImport 依赖注入接口 */
export interface UsePhotoImportDeps {
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
}

export function usePhotoImport(deps: UsePhotoImportDeps) {
  const { photos, photoKey, isTauri, ensurePhotoKey, showError } = deps;

  /* ===== 导入状态（保持 ref 兼容） ===== */
  const importing = ref(false);
  const importProgress = ref(0);
  const importStatus = ref("");
  /* ===== 新增：耗时与 ETA（供 QuantumProgressFlow 使用） ===== */
  const importElapsed = ref(0);
  const importEta = ref(0);

  /* ===== 流水线实例（惰性创建，复用） ===== */
  let pipeline: ImportPipeline | null = null;

  /** 获取或创建流水线实例 */
  const getPipeline = (): ImportPipeline => {
    if (!pipeline) {
      pipeline = new ImportPipeline();
      // 将流水线进度状态机的响应式 ref 同步到本 composable 的 ref
      // 通过 watch 实现帧对齐刷新到组件层
      watch(pipeline.progress.percent, (v) => { importProgress.value = v; });
      watch(pipeline.progress.text, (v) => { importStatus.value = v; });
      watch(pipeline.progress.elapsedMs, (v) => { importElapsed.value = v; });
      watch(pipeline.progress.etaMs, (v) => { importEta.value = v; });
    }
    return pipeline;
  };

  /* ===== 导入照片（异步批处理流水线） ===== */
  const onImport = async () => {
    // 模块密钥超时锁定后提示用户返回重新解锁（15min 内 ensurePhotoKey 从缓存恢复，不触发）
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }

    // 获取文件列表（Tauri 或浏览器）
    let filesToProcess: ImportFileInput[] = [];
    let browserFiles: File[] = []; // 浏览器模式保留 File 引用（用于 blobUrl）

    if (isTauri) {
      const selected = await open({
        multiple: true,
        filters: [{ name: "图片", extensions: ["png", "jpg", "jpeg", "webp", "gif", "bmp"] }],
      });
      if (!selected || (Array.isArray(selected) && selected.length === 0)) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      filesToProcess = paths.map((p) => ({
        name: p.split(/[\\/]/).pop() || "photo",
        mime: guessMime(p.split(/[\\/]/).pop() || "photo"),
        readBytes: () => readUserFile(p),
      }));
    } else {
      // 浏览器模式：使用 File API
      browserFiles = await openBrowserFileDialog();
      if (browserFiles.length === 0) return;
      filesToProcess = browserFiles.map((f) => ({
        name: f.name,
        mime: guessMime(f.name),
        readBytes: () => f.arrayBuffer().then((buf) => new Uint8Array(buf)),
      }));
    }

    importing.value = true;

    if (isTauri) {
      // ===== Tauri 模式：使用三阶段异步流水线 =====
      try {
        const pipe = getPipeline();
        const result = await pipe.run(filesToProcess, photoKey.value);

        if (!result.ok && result.error) {
          if (result.error.includes("VERTHYS_WRITE_BLOCKED")) {
            showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
          } else {
            showError(`导入失败: ${result.error}`);
          }
        }

        // 将导入结果转换为 PhotoEntry 并追加到照片列表
        if (result.imported.length > 0) {
          const newEntries = importedToPhotoEntries(result.imported, photos.value.length);
          pushShallowItems(photos, newEntries);
        }

        if (result.skipped > 0) {
          importStatus.value = `完成：导入 ${result.imported.length} 张，去重跳过 ${result.skipped} 张`;
        }

        // 修复：持久化到磁盘 + 返回值检查
        let persistOk = false;
        try {
          persistOk = await persistVerthys();
        } catch (e) {
          console.error("[onImport] persistVerthys 异常", e);
        }
        if (!persistOk && result.imported.length > 0) {
          showError(`${result.imported.length} 张照片已导入内存但持久化失败，重启后可能丢失。请勿关闭应用，尝试重新导入或联系支持。`);
        }

        // 同步模块缓存：导入后立即更新缓存，防止切走再切回时 loadPhotos 用旧缓存覆盖
        setModuleCache("photos", photos.value);
      } catch (e) {
        if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
          showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        } else {
          console.error("[onImport] 流水线异常", e);
          showError("导入失败，请重试");
        }
      } finally {
        importing.value = false;
        importProgress.value = 100;
        setTimeout(() => {
          importStatus.value = "";
          importProgress.value = 0;
          importElapsed.value = 0;
          importEta.value = 0;
        }, 1500);
      }
    } else {
      // ===== 浏览器模式：保留原始字节到内存（用于后续导出） =====
      // 浏览器模式不使用流水线（无 IPC），保持原有简单逻辑
      const importedItems: PhotoEntry[] = [];

      for (let i = 0; i < filesToProcess.length; i++) {
        const { name: fileName, readBytes } = filesToProcess[i];
        const file = browserFiles[i];
        importProgress.value = Math.round((i / filesToProcess.length) * 100);
        importStatus.value = `读取 ${fileName}…`;

        try {
          const origBytes = await readBytes();
          const mime = guessMime(fileName);

          // 生成缩略图
          const dataB64 = arrayBufferToBase64(origBytes.buffer.slice(
            origBytes.byteOffset,
            origBytes.byteOffset + origBytes.byteLength,
          ) as ArrayBuffer);
          const thumbB64 = await generateThumbnail(dataB64, mime);

          // 浏览器模式：保留原始字节到内存（用于后续导出）
          const blob = new Blob([toArrayBuffer(origBytes)], { type: mime });
          const blobUrl = URL.createObjectURL(blob);
          importedItems.push({
            id: Date.now() + i,
            name: fileName,
            thumb: `url(data:image/jpeg;base64,${thumbB64})`,
            size: formatSize(origBytes.length),
            height: 180 + ((i * 23) % 100),
            blobUrl,
            rawBytes: origBytes,
          });
        } catch (e) {
          console.error("[importPhotos] 导入失败", e);
          showError("导入失败，请重试");
        }
        // P0：每处理完一张后 yieldToMain，避免串行 await 阻塞主线程
        await yieldToMain();
      }

      if (importedItems.length > 0) {
        pushShallowItems(photos, importedItems);
      }

      importing.value = false;
      importProgress.value = 100;
      setTimeout(() => { importStatus.value = ""; importProgress.value = 0; }, 1500);
    }
  };

  return {
    importing,
    importProgress,
    importStatus,
    /* 新增：耗时与 ETA（供 QuantumProgressFlow 使用） */
    importElapsed,
    importEta,
    onImport,
    /* Parsed Import：导出流水线获取函数，供 usePhotoParse 复用同一实例
       （共享进度状态机，已通过 watch 绑定到 importing/importProgress/importStatus refs） */
    getPipeline,
  };
}

/** ArrayBuffer → base64（浏览器模式辅助函数，避免引入 bytesToBase64 的循环依赖） */
function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunkSize = 0x8000; // 32KB 分块，避免 call stack overflow
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return btoa(binary);
}
