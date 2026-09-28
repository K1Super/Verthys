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
 * - 接收 usePhotoData 返回值 + 全局 Toast 中心的 showError（依赖注入）
 * - 批量构建 importedItems 后一次性 pushShallowItems，避免循环内多次触发响应式
 * - persistVerthys + 返回值检查 + setModuleCache 更新缓存
 */
import { ref, watch, onScopeDispose, type ShallowRef, type Ref } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { readUserFile } from "../../lib/verthys";
import { persistVerthysDetailed, setModuleCache } from "../../lib/keyManager";
import { pushShallowItems } from "../../utils/shallow-array";
import { yieldToMain } from "../../utils/promise_utils";
import type { PhotoEntry } from "./types";
import { formatSize, generateThumbnail, guessMime, nextMemoryPhotoId, openBrowserFileDialog, toArrayBuffer } from "./utils";
import { useSingleTimer } from "./utils/timer";
import { ImportPipeline, importedToPhotoEntries, type ImportFileInput } from "./importPipeline";
import { MAX_PHOTO_BYTES } from "../../constants/crypto_const";

/**
 * 导入流程阶段状态机：
 *   - idle：空闲，可发起新导入或收尾倒计时中接管
 *   - acquiring：已取到发起权，正在做密钥校验与文件选择（跨越 await 边界仍有效）
 *   - running：流水线执行中（epoch 区分代次）
 *   - finishing：主体已结束、视觉清理倒计时中
 */
type ImportPhase =
  | { kind: "idle" }
  | { kind: "acquiring" }
  | { kind: "running"; epoch: number }
  | { kind: "finishing"; epoch: number };

/** acquiring 阶段看门狗阈值：防止文件对话框异常挂起导致状态机永久停留在该阶段 */
const ACQUIRE_TIMEOUT_MS = 30_000;

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
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示非错误警告提示（可选；缺省回退 showError）。用于落盘结构自查告警 */
  showToast?: (msg: string) => void;
}

export function usePhotoImport(deps: UsePhotoImportDeps) {
  const { photos, photoKey, isTauri, ensurePhotoKey, showError, showToast } = deps;

  /* ===== 导入状态（保持 ref 兼容） ===== */
  const importing = ref(false);
  const importProgress = ref(0);
  const importStatus = ref("");
  /* ===== 新增：耗时与 ETA（供 QuantumProgressFlow 使用） ===== */
  const importElapsed = ref(0);
  const importEta = ref(0);

  /* ===== 导入流程阶段状态机（跨 await 边界的重入守卫权威） ===== */
  const phase = ref<ImportPhase>({ kind: "idle" });
  let epochCounter = 0;
  /** 完成清理定时器（句柄纳管：旧回调不允许污染新导入的视觉状态） */
  const importDoneTimer = useSingleTimer("photo-import-done");
  /** 文件选择阶段看门狗：对话框异常挂起时兜底回空闲态 */
  const acquireWatchdog = useSingleTimer("photo-import-acquire");

  /** 尝试取得导入发起权：仅空闲或收尾倒计时中可进入，进行中一律拒绝 */
  const tryEnterAcquiring = (): boolean => {
    const cur = phase.value;
    if (cur.kind === "acquiring" || cur.kind === "running") return false;
    // idle / finishing：作废旧收尾定时器（视觉状态由新流程接管），进入发起态
    importDoneTimer.cancel();
    phase.value = { kind: "acquiring" };
    return true;
  };

  /**
   * 统一收尾：主体结束后转入 finishing 并启动视觉清理倒计时。
   * 仅当 phase 仍归属本代次时生效（防御旧代次延迟收尾覆盖新代次）。
   */
  const finishImport = (epoch: number) => {
    if (phase.value.kind !== "running" || phase.value.epoch !== epoch) return;
    phase.value = { kind: "finishing", epoch };
    importing.value = false;
    importProgress.value = 100;
    importDoneTimer.schedule(() => {
      // finishing 期间若被新导入接管（tryEnterAcquiring 已清掉本定时器，
      // 但保持双重校验防竞态），则不得清理新导入的视觉状态
      if (phase.value.kind === "finishing") {
        phase.value = { kind: "idle" };
        importStatus.value = "";
        importProgress.value = 0;
        importElapsed.value = 0;
        importEta.value = 0;
      }
    }, 1500);
  };

  onScopeDispose(() => {
    importDoneTimer.dispose();
    acquireWatchdog.dispose();
  });

  /* ===== 流水线实例（惰性创建，复用） ===== */
  let pipeline: ImportPipeline | null = null;
  /* ===== 进行中导入的取消控制器（组件卸载时中止，收尾保留 WAL） ===== */
  let activeAbort: AbortController | null = null;

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
    // 重入守卫：入口同步取到发起权（finishing 倒计时中允许接管），
    // 跨越后续 await 边界依然有效，杜绝对话框期间连点造成并发导入
    if (!tryEnterAcquiring()) return;
    // 文件选择阶段看门狗：对话框异常挂起（永不 resolve）时兜底回空闲态
    acquireWatchdog.schedule(() => {
      if (phase.value.kind === "acquiring") {
        console.warn("[onImport] 文件选择阶段超时，回退空闲态");
        phase.value = { kind: "idle" };
      }
    }, ACQUIRE_TIMEOUT_MS);

    try {
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

      // 文件确认后正式进入运行态（代次递增供收尾归属校验）
      const epoch = ++epochCounter;
      phase.value = { kind: "running", epoch };
      importing.value = true;

      if (isTauri) {
        activeAbort = new AbortController();
        // ===== Tauri 模式：使用三阶段异步流水线 =====
        try {
          const pipe = getPipeline();
          const result = await pipe.run(filesToProcess, photoKey.value, activeAbort.signal);

          if (result.error === "ABORTED") {
            // 取消路径：静默收尾，不弹错误（组件卸载场景无 UI）；
            // 状态文案如实补记已导入数量（已提交批次已落库）
            importStatus.value = `导入已取消（已导入 ${result.imported.length} 张）`;
          } else if (!result.ok) {
            if (result.error) {
              showError(`导入失败: ${result.error}`);
            } else {
              // 部分失败且无会话级错误：按失败计数提示（成功项已入账，可重试失败部分）
              showError(`导入 ${result.imported.length} 张，失败 ${result.failedRecords.length} 张，请重试`);
            }
          }

          // 落盘（判别式）：partial_persisted 表示 flush 已成功（数据已 fsync），
          // 仅结构自查未过——不得再报"重启后可能丢失"，改为非错误警告文案；
          // 只有 not_persisted（flush 本身失败）才提示应保留应用。
          let persistOutcome: Awaited<ReturnType<typeof persistVerthysDetailed>> = {
            kind: "ok",
          };
          if (result.imported.length > 0) {
            try {
              persistOutcome = await persistVerthysDetailed();
            } catch (e) {
              console.error("[onImport] persistVerthysDetailed 异常", e);
              persistOutcome = { kind: "not_persisted", reason: String(e) };
            }
            if (persistOutcome.kind === "not_persisted") {
              showError(`${result.imported.length} 张照片已导入内存但持久化失败，请勿关闭应用，尝试重新导入或联系支持。`);
            } else if (persistOutcome.kind === "partial_persisted") {
              const warnMsg = `照片已导入（校验警告）：${persistOutcome.reason}；如重启后异常请重新导入`;
              (showToast ?? showError)(warnMsg);
            }
          }

          // 将导入结果转换为 PhotoEntry 并追加到照片列表
          // （取消时返回的已提交批次照常入列：记录已落库，UI 与后端保持一致）
          if (result.imported.length > 0) {
            const newEntries = importedToPhotoEntries(result.imported);
            pushShallowItems(photos, newEntries);
          }

          if (result.skipped > 0) {
            importStatus.value = `完成：导入 ${result.imported.length} 张，去重跳过 ${result.skipped} 张`;
          }

          // 同步模块缓存：导入后立即更新缓存，防止切走再切回时 loadPhotos 用旧缓存覆盖
          setModuleCache("photos", photos.value);
        } catch (e) {
          console.error("[onImport] 流水线异常", e);
          showError("导入失败，请重试");
        } finally {
          activeAbort = null;
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

          // 单文件硬上限：与 Tauri 流水线同源常量，读前按 File.size 拒绝，
          // 越限文件不进入内存读取（输入全校验，Tauri/浏览器两路径口径一致）
          if (file.size > MAX_PHOTO_BYTES) {
            showError(`「${fileName}」超过单文件大小上限，已跳过`);
            continue;
          }

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
              id: nextMemoryPhotoId(),
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
          // 每处理完一张后让出主线程，避免串行 await 阻塞渲染
          await yieldToMain();
        }

        if (importedItems.length > 0) {
          pushShallowItems(photos, importedItems);
        }
      }

      // 所有路径统一收尾（含进度 100% + 1.5s 后视觉清理）
      finishImport(epoch);
    } finally {
      acquireWatchdog.cancel();
      if (phase.value.kind === "acquiring") {
        phase.value = { kind: "idle" };
      }
    }
  };

  /** 取消进行中的导入（组件卸载时调用）：中止投喂新文件，已提交批次收尾并保留 WAL 续传 */
  const abortImport = () => {
    activeAbort?.abort();
  };

  return {
    importing,
    importProgress,
    importStatus,
    /* 新增：耗时与 ETA（供 QuantumProgressFlow 使用） */
    importElapsed,
    importEta,
    onImport,
    abortImport,
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
