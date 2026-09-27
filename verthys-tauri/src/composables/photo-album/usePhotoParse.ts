/**
 * photo-album/usePhotoParse.ts — 拾光模块解析层 composable
 *
 * 职责：管理 .venc 文件反向解密和导入。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + usePhotoToast 的 showError/showToast（依赖注入）
 * - chooseParseFile：Tauri 用 open() + readUserFile；浏览器用 input[type=file]
 *   感知：文件读取过程复用进度条样式
 *     rAF 推进至 90% → 实际完成跳 100%，1.5s 最小感知时长，进度单调递增
 * - doParse：decryptExportFile → unpackVencMultiFile → 遍历用当前密钥 decryptMeta 预览
 *   感知：解析过程复用中枢初始化窗口进度条样式（非量子动画）
 *     rAF 推进至 90% → 实际完成跳 100%，1.5s 最小感知时长，进度单调递增
 * - importParsedPhotos（重构）：使用 ImportPipeline.runParsed() 三阶段流水线
 *   - 生产者：构造新 meta（内联已加密 chunks）→ submitMetaOnly() 到 Worker 池并行加密
 *   - 传输器：Worker 池并行 encryptMeta（CPU 密集型任务移出主线程，UI 不卡死）
 *   - 消费者：verthysAddRecordsBatch 批量 IPC + WAL 断点续传 + 三层缓存同步
 *   - 进度：ImportProgressState 逐文件更新 + rAF 帧对齐 → QuantumProgressFlow 实时显示
 *   - 持久化：pipeline 完成后 persistVerthys + 返回值检查
 *   - 复用 usePhotoImport 的 pipeline 实例 + importing refs（共享 QuantumProgressFlow）
 */
import { ref, onScopeDispose, type Ref, type ShallowRef } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { readUserFile } from "../../lib/verthys";
import { persistVerthysDetailed, setModuleCache } from "../../lib/keyManager";
import { MIN_TOKEN_LENGTH } from "../../constants/crypto_const";
import { pushShallowItems } from "../../utils/shallow-array";
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import { formatSize, nextMemoryPhotoId } from "./utils";
import { useSingleTimer } from "./utils/timer";
import type { ImportPipeline } from "./importPipeline";
import { importedToPhotoEntries } from "./importPipeline";
import type {
  ParseCryptoRequest,
  ParseCryptoResponse,
  ParseCryptoCompletion,
  ParseCryptoPreview,
} from "../../workers/parse-crypto.worker";

/** 解析 Worker 最小接口（依赖注入：测试以伪实现替代真实 Worker） */
export interface ParseWorkerLike {
  postMessage(message: ParseCryptoRequest, transfer?: Transferable[]): void;
  onmessage: ((e: MessageEvent<ParseCryptoResponse>) => void) | null;
  onerror: ((e: ErrorEvent) => void) | null;
  terminate(): void;
}

/** 默认解析 Worker 工厂：按需冷启动（一次解析一个实例，完成即终止） */
function defaultParseWorkerFactory(): ParseWorkerLike {
  return new Worker(
    new URL("../../workers/parse-crypto.worker.ts", import.meta.url),
    { type: "module" },
  );
}

/* ===== 进度条感知参数（复用 useModuleNavigation 的 1.5s 感知模式） ===== */
/** 最小感知时长（毫秒）—— 保证用户清晰感知加载过程 */
const MIN_PERCEIVE_MS = 1500;
/** rAF 推进的目标百分比（预留 100% 给实际完成） */
const PROGRESS_RAF_TARGET = 90;

/** usePhotoParse 依赖注入接口 */
export interface UsePhotoParseDeps {
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
  /** 显示成功提示（来自 usePhotoToast，统一 Toast 中心） */
  showToast: (msg: string) => void;
  /* Parsed Import：复用 usePhotoImport 的流水线实例 + 导入状态 refs */
  /** 获取流水线实例（复用 usePhotoImport 的 pipeline，共享进度状态机） */
  getPipeline: () => ImportPipeline;
  /** 导入中标志（控制 QuantumProgressFlow 显示，复用 usePhotoImport 的 ref） */
  importing: Ref<boolean>;
  /** 导入进度百分比（0-100，复用 usePhotoImport 的 ref） */
  importProgress: Ref<number>;
  /** 导入状态文本（复用 usePhotoImport 的 ref） */
  importStatus: Ref<string>;
  /** 导入已耗时（毫秒，复用 usePhotoImport 的 ref） */
  importElapsed: Ref<number>;
  /** 导入预计剩余时间（毫秒，复用 usePhotoImport 的 ref） */
  importEta: Ref<number>;
  /** 解析 Worker 工厂（测试注入点；默认真实 Worker） */
  parseWorkerFactory?: () => ParseWorkerLike;
}

export function usePhotoParse(deps: UsePhotoParseDeps) {
  const {
    photos, photoKey, isTauri, ensurePhotoKey, showError, showToast,
    /* Parsed Import：复用 usePhotoImport 的流水线 + 导入状态 refs */
    getPipeline, importing, importProgress, importStatus, importElapsed, importEta,
    parseWorkerFactory = defaultParseWorkerFactory,
  } = deps;

  /* ===== 解析对话框（反向解密 .venc 文件） ===== */
  const showParseDialog = ref(false);
  const parseFileName = ref("");
  const parseFileData = ref<Uint8Array | null>(null);
  /** 已选文件的完整路径（Tauri 模式）：解析会把字节所有权转移给 Worker，
   *  失败后重试必须能按原路径重读，避免复用已转移（detached）缓冲区 */
  const parseFilePath = ref<string | null>(null);
  const parseToken = ref("");
  const parsing = ref(false);
  const parsedPhotos = ref<ParsedPhotoPreview[]>([]);
  /** 无法用当前模块密钥解密的照片数（doParse 预检结果，导入前展示原因） */
  const parsedUndecryptable = ref(0);
  /** 空数据记录数（容器内无内容块）：与"密钥不匹配"分列，避免向用户报错原因 */
  const parsedEmpty = ref(0);
  /* Parsed Import：对话框内导入进度条状态（复用 QuantumProgressFlow 组件）
     importingParsed 控制对话框内 QuantumProgressFlow 显示，与顶部的 importing ref 解耦，
     避免关闭对话框造成的视觉割裂（用户在对话框内实时看到导入进度） */
  const importingParsed = ref(false);

  /* ===== 感知：进度条状态（复用中枢初始化窗口进度条样式，非量子动画） ===== */
  /** 文件读取中（chooseParseFile 阶段） */
  const fileLoading = ref(false);
  const fileLoadingPercent = ref(0);
  const fileLoadingMsg = ref("");
  /** 解析中（doParse 阶段）进度 —— parsing 控制开关，parsingPercent/parsingMsg 控制展示 */
  const parsingPercent = ref(0);
  const parsingMsg = ref("");

  /* ===== rAF 句柄（组件级闭包，chooseParseFile/doParse 各自独立） ===== */
  let fileLoadRafId: number | null = null;
  let parseRafId: number | null = null;

  /* Parsed Import：导入完成后的清理定时器（句柄纳管统一工具）
     用于在 openParseDialog 时清除残留定时器，防止旧回调污染新状态 */
  const importDoneTimer = useSingleTimer("photo-parse-done");

  onScopeDispose(() => {
    importDoneTimer.dispose();
  });

  /**
   * 创建单调递增进度发射器（复用 global-verthys.ts 的 lastEmittedPercent 闸门模式）
   *
   * 铁律：进度条单调递增，严禁回退（Math.max 钳制）
   *   - rAF 按耗时比例推进至 PROGRESS_RAF_TARGET（90%）
   *   - 实际操作完成后跳 100%
   *   - 1.5s 最小感知时长（无论操作多快，进度条至少跑满 1.5s）
   *
   * @param percentRef 进度百分比响应式引用（caller 传入，emitter 写入）
   */
  const createProgressEmitter = (
    percentRef: Ref<number>,
  ) => {
    let lastEmitted = 0;
    const t0 = performance.now();

    /** rAF tick：按耗时比例推进至 PROGRESS_RAF_TARGET（90%） */
    const tick = () => {
      const elapsed = performance.now() - t0;
      const ratio = Math.min(elapsed / MIN_PERCEIVE_MS, 1);
      const target = Math.round(ratio * PROGRESS_RAF_TARGET);
      // 单调递增闸门：Math.max 钳制，防止回退
      const clamped = Math.max(target, lastEmitted);
      lastEmitted = clamped;
      percentRef.value = clamped;
      if (ratio < 1) {
        return requestAnimationFrame(tick);
      }
      return null;
    };

    /** 发射任意百分比（单调递增钳制） */
    const emit = (percent: number) => {
      const clamped = Math.max(percent, lastEmitted);
      lastEmitted = clamped;
      percentRef.value = clamped;
    };

    /** 等待最小感知时长（操作完成后调用，保证 1.5s 完整感知） */
    const ensureMinDuration = async () => {
      const remaining = MIN_PERCEIVE_MS - (performance.now() - t0);
      if (remaining > 0) await new Promise((r) => setTimeout(r, remaining));
    };

    return { tick, emit, ensureMinDuration, t0 };
  };

  const openParseDialog = () => {
    // 清除上一次可能残留的导入完成定时器（防止状态错乱）
    importDoneTimer.cancel();
    showParseDialog.value = true;
    parseFileName.value = "";
    parseFileData.value = null;
    parseFilePath.value = null;
    parseToken.value = "";
    parsedPhotos.value = [];
    parsedUndecryptable.value = 0;
    parsedEmpty.value = 0;
    // 重置进度状态（防止上次残留）
    fileLoading.value = false;
    fileLoadingPercent.value = 0;
    fileLoadingMsg.value = "";
    parsingPercent.value = 0;
    parsingMsg.value = "";
    // 重置导入状态（防止上次残留导致对话框显示错误状态）
    importingParsed.value = false;
    importProgress.value = 0;
    importStatus.value = "";
    importElapsed.value = 0;
    importEta.value = 0;
  };

  const closeParseDialog = () => {
    // 解析中禁止关闭（保护数据完整性）
    if (parsing.value) return;
    // 文件读取中也禁止关闭（保护读取流程）
    if (fileLoading.value) return;
    // 导入中禁止关闭（保护流水线数据完整性）
    if (importingParsed.value) return;
    showParseDialog.value = false;
  };

  const chooseParseFile = async () => {
    /* 感知修正：进度条仅在用户真正选择文件后启动
     *   旧实现：函数入口即启动 rAF → 用户未选文件就显示进度条（虚假进度）
     *   正确：先打开文件选择对话框，用户确认选择后再启动 rAF 推进真实读取进度
     *   用户取消选择 → 不显示任何进度，静默返回
     */

    /** 启动进度条（仅在用户确认选择文件后调用） */
    const startLoading = () => {
      fileLoading.value = true;
      fileLoadingPercent.value = 0;
      fileLoadingMsg.value = "正在读取加密文件";
    };

    /** 统一收尾：取消 rAF + 等待最小感知时长 + 跳 100% + 关闭 loading */
    const finishLoading = async (
      emitter: ReturnType<typeof createProgressEmitter>,
    ) => {
      await emitter.ensureMinDuration();
      if (fileLoadRafId !== null) { cancelAnimationFrame(fileLoadRafId); fileLoadRafId = null; }
      emitter.emit(100);
      fileLoadingMsg.value = "读取完成";
      await new Promise((r) => setTimeout(r, 200));
      fileLoading.value = false;
    };

    /** 统一错误处理：跑满感知时长 → 显示错误 → 关闭 loading */
    const handleFileError = async (
      emitter: ReturnType<typeof createProgressEmitter>,
      msg: string,
    ) => {
      await emitter.ensureMinDuration();
      if (fileLoadRafId !== null) { cancelAnimationFrame(fileLoadRafId); fileLoadRafId = null; }
      showError(msg);
      fileLoading.value = false;
    };

    if (isTauri) {
      // 先打开文件选择对话框，不启动进度条
      const path = await open({ filters: [{ name: "VENC Files", extensions: ["venc"] }] });
      if (!path || typeof path !== "string") {
        // 用户取消选择 → 静默返回，不显示任何进度
        return;
      }
      // 用户已确认选择文件 → 启动真实读取进度
      startLoading();
      const emitter = createProgressEmitter(fileLoadingPercent);
      fileLoadRafId = requestAnimationFrame(emitter.tick);
      try {
        // 修复：使用 readUserFile 而非 readFileBytes
        //   用户通过对话框显式选择的文件已获授权，不应受沙箱白名单限制
        //   原缺陷：readFileBytes 白名单仅含 home_dir，D:\ 等路径被拒
        //   二进制 IPC 直传 Uint8Array（去 base64 化）
        parseFileData.value = await readUserFile(path);
        parseFilePath.value = path;
        parseFileName.value = path.split(/[\\/]/).pop() || "unknown.venc";
        await finishLoading(emitter);
      } catch (e) {
        // 修复：打印详细错误，便于定位（原 catch 吞掉错误详情）
        console.error("[chooseParseFile] 读取文件失败:", e);
        const msg = e instanceof Error ? e.message : String(e);
        await handleFileError(emitter, "读取文件失败：" + msg);
      }
    } else {
      // 浏览器模式：使用 File API（先弹选择框，用户选择后启动进度条）
      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".venc";
      input.onchange = async () => {
        if (!(input.files && input.files[0])) {
          // 用户取消选择 → 静默返回，不显示任何进度
          return;
        }
        // 用户已确认选择文件 → 启动真实读取进度
        startLoading();
        const emitter = createProgressEmitter(fileLoadingPercent);
        fileLoadRafId = requestAnimationFrame(emitter.tick);
        try {
          const file = input.files[0];
          parseFileName.value = file.name;
          parseFileData.value = new Uint8Array(await file.arrayBuffer());
          // 浏览器模式无路径可重读：置空以触发"请重新选择文件"的保护分支
          parseFilePath.value = null;
          await finishLoading(emitter);
        } catch (e) {
          console.error("[chooseParseFile] 浏览器读取失败:", e);
          await handleFileError(emitter, "读取文件失败");
        }
      };
      input.click();
    }
  };

  const doParse = async () => {
    if (!parseFileData.value || !parseToken.value.trim()) return;

    // 令牌归一化：从剪贴板/聊天工具粘贴常带首尾空白或换行，须先剔除再参与密钥派生
    const token = parseToken.value.trim();
    parseToken.value = token;
    // 格式预检：令牌仅约束最小长度——支持任意自定义令牌（字符集不限，
    //   与导出侧的可编辑令牌口径一致）；过短令牌给出专用提示，避免走
    //   PBKDF2 后撞击 TAG 校验失败并把内部错误文案暴露给用户
    if (token.length < MIN_TOKEN_LENGTH) {
      showError(`令牌格式不正确（至少 ${MIN_TOKEN_LENGTH} 位字符）`);
      return;
    }
    // 感知：启动 rAF 进度推进（复用中枢初始化窗口进度条样式）
    parsing.value = true;
    parsingPercent.value = 0;
    parsingMsg.value = "正在解密加密文件";
    parsedPhotos.value = [];
    const emitter = createProgressEmitter(parsingPercent);
    parseRafId = requestAnimationFrame(emitter.tick);

    /** 统一收尾：取消 rAF + 等待最小感知时长 + 跳 100% + 关闭 loading */
    const finishParsing = async () => {
      await emitter.ensureMinDuration();
      if (parseRafId !== null) { cancelAnimationFrame(parseRafId); parseRafId = null; }
      emitter.emit(100);
      parsingMsg.value = "解析完成";
      await new Promise((r) => setTimeout(r, 200));
      parsing.value = false;
    };

    /** 统一错误处理：跑满感知时长 → 显示错误 → 关闭 loading */
    const handleParseError = async (msg: string) => {
      await emitter.ensureMinDuration();
      if (parseRafId !== null) { cancelAnimationFrame(parseRafId); parseRafId = null; }
      showError(msg);
      parsing.value = false;
    };

    /** rAF 去重标志（防止高频进度更新导致过度渲染） */
    let parseRafPending = false;

    /**
     * P0 修复：发射真实进度（rAF 去重）
     *
     * 旧实现：rAF 按系统时间自嗨式推进（假进度），主线程被 await 阻塞时 rAF 无法执行
     * 新实现：每解密完一张照片发射真实进度，rAF 仅负责将真实数字渲染到 DOM
     *         rAF 去重：同一帧内多次发射仅渲染最后一次
     */
    const emitRealProgress = (current: number, total: number) => {
      const percent = Math.round((current / total) * 100);
      if (!parseRafPending) {
        parseRafPending = true;
        requestAnimationFrame(() => {
          // 真实进度映射，留 1% 给完成动画
          emitter.emit(Math.min(percent, 99));
          parsingMsg.value = `正在还原照片预览 ${current}/${total}`;
          parseRafPending = false;
        });
      }
    };

    try {
      // 1. 容器解包 + 逐张预览还原全部在解析 Worker 内完成：
      //    令牌派生、逐帧 AEAD、首块密钥预检与块 base64 转换均不占主线程；
      //    主线程仅等待完成、按 worker 进度消息渲染、装载预览结果
      parsingMsg.value = "正在解密加密文件";

      // 缓冲区所有权契约：上一次解析已把字节所有权转移给 Worker（原引用变为
      // detached，byteLength 归零）。失败后未重选文件直接重试时，必须重新获取
      // 缓冲区——优先按原路径重读（不增加常驻内存），浏览器模式无路径可用时
      // 明确要求重新选择；绝不把 0 字节缓冲投递给 Worker 导致"文件已损坏"的
      // 误导性失败。
      let data = parseFileData.value;
      if (!data || data.buffer.byteLength === 0) {
        if (parseFilePath.value) {
          try {
            data = await readUserFile(parseFilePath.value);
            parseFileData.value = data;
          } catch (e) {
            console.error("[doParse] 重新读取文件失败:", e);
            await handleParseError("无法重新读取文件，请重新选择");
            return;
          }
        } else {
          await handleParseError("文件数据已释放，请重新选择文件");
          return;
        }
      }
      // 转移容器字节所有权（零拷贝）；视图与底层缓冲不重合时先复制精确片段
      const ownsBuffer =
        data.byteOffset === 0 && data.byteLength === data.buffer.byteLength;
      const transferBuffer: ArrayBuffer = ownsBuffer
        ? data.buffer
        : data.slice().buffer;

      const worker = parseWorkerFactory();
      const finalResponse = new Promise<ParseCryptoCompletion>((resolve) => {
        worker.onmessage = (e) => {
          const msg: ParseCryptoResponse = e.data;
          if (msg.type === "progress") {
            // 真实进度映射（rAF 去重），留 1% 给完成动画
            emitRealProgress(msg.current, msg.total);
            return;
          }
          resolve(msg);
        };
        worker.onerror = (err) => {
          resolve({
            id: 0,
            type: "failure",
            ok: false,
            error: err.message ?? "解析 Worker 异常退出",
          });
        };
      });

      worker.postMessage(
        {
          id: 1,
          fileBytes: transferBuffer,
          token,
          photoKey: photoKey.value,
        } satisfies ParseCryptoRequest,
        [transferBuffer],
      );

      const res = await finalResponse;
      try {
        worker.terminate();
      } catch {
        // 终止失败忽略：实例随引用释放被回收
      }

      if (!res.ok) {
        // 面向用户文案：区分密钥错误与文件损坏，不暴露内部错误码与实现细节
        const msg = res.error.includes("TAG_VERIFICATION_FAILED")
          ? "密钥不正确，或文件已损坏/被篡改"
          : "文件格式无法识别或已损坏";
        await handleParseError(`解析失败：${msg}`);
        return;
      }

      const previews: ParsedPhotoPreview[] = res.previews.map(
        (p: ParseCryptoPreview): ParsedPhotoPreview => ({
          name: p.name,
          thumb: p.thumb,
          size: p.size,
          metaB64: p.metaB64,
          chunkB64List: p.chunkB64List,
          meta: p.meta,
        }),
      );
      parsedPhotos.value = previews;
      // 预检结果：不可解密数量供结果区与导入提示使用（与流水线分类口径一致）
      parsedUndecryptable.value = res.undecryptable;
      parsedEmpty.value = res.emptyCount;
      await finishParsing();
    } catch (e) {
      console.error("[doParse] 解析失败:", e);
      // 面向用户文案：区分密钥错误与文件损坏，不暴露内部错误码与实现细节
      const msg = e instanceof Error && e.message.includes("TAG_VERIFICATION_FAILED")
        ? "密钥不正确，或文件已损坏/被篡改"
        : "文件格式无法识别或已损坏";
      await handleParseError(`解析失败：${msg}`);
    }
  };

  const importParsedPhotos = async () => {
    // 重入守卫：解析导入进行中禁止再次触发（连点/双击防护）
    if (importingParsed.value) return;

    // 模块密钥超时锁定后提示用户返回重新解锁
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }

    // 清除上一次可能残留的导入完成定时器
    importDoneTimer.cancel();

    // 保持解析对话框开启，在对话框内复用 QuantumProgressFlow 显示导入进度
    importingParsed.value = true;

    if (isTauri) {
      // ===== Tauri 模式：使用三阶段异步流水线 =====

      // ----- 阶段 1：执行流水线（异常分离） -----
      let result;
      try {
        const pipe = getPipeline();
        result = await pipe.runParsed(parsedPhotos.value, photoKey.value);
      } catch (e) {
        // 异常路径：重置导入状态，保留 parsedPhotos 供重试，不关闭对话框
        importingParsed.value = false;
        importProgress.value = 0;
        importStatus.value = "";
        importElapsed.value = 0;
        importEta.value = 0;

        if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
          showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        } else {
          console.error("[importParsedPhotos] 流水线异常", e);
          showError("导入失败，请重试");
        }
        return;
      }

      // ----- 阶段 2：处理 pipeline 返回的错误（非异常） -----
      if (!result.ok) {
        // 失败路径：重置导入状态，保留 parsedPhotos 供重试，不关闭对话框
        importingParsed.value = false;
        importProgress.value = 0;
        importStatus.value = "";
        importElapsed.value = 0;
        importEta.value = 0;

        if (result.error?.includes("VERTHYS_WRITE_BLOCKED")) {
          showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        } else if (result.error) {
          showError(`导入失败: ${result.error}`);
        } else {
          // 部分失败且无会话级错误：按失败计数提示（成功项已入账，可重试失败部分）
          showError(`导入 ${result.imported.length} 张，失败 ${result.failedRecords.length} 张，请重试`);
        }
        return;
      }

      // ----- 阶段 3：成功路径 — 先落盘，后按三态提交 -----
      try {
        // 1. 落盘（判别式）：
        //    ok                → 落盘且结构自查通过；
        //    partial_persisted → flush 成功（数据已 fsync）但结构自查未过，仍提交列表；
        //    not_persisted     → flush 本身失败，不提交、保留 parsedPhotos 供重试。
        let persistOutcome: Awaited<ReturnType<typeof persistVerthysDetailed>>;
        try {
          persistOutcome = await persistVerthysDetailed();
        } catch (e) {
          console.error("[importParsedPhotos] persistVerthysDetailed 异常", e);
          persistOutcome = { kind: "not_persisted", reason: String(e) };
        }
        if (persistOutcome.kind === "not_persisted") {
          importingParsed.value = false;
          importProgress.value = 0;
          importStatus.value = "";
          importElapsed.value = 0;
          importEta.value = 0;
          showError("持久化失败，本次导入未生效，请重试");
          return;
        }
        // 结构性自查告警（partial_persisted）：数据已落盘，仅提示，不阻断提交
        const persistWarning =
          persistOutcome.kind === "partial_persisted" ? persistOutcome.reason : null;

        // 2. 提交列表：仅成功导入项（不可解密项已由流水线剔除，不写入列表）
        if (result.imported.length > 0) {
          const newEntries = importedToPhotoEntries(result.imported);
          pushShallowItems(photos, newEntries);
        }

        // 3. 同步模块缓存（落盘成功之后，避免缓存与磁盘状态脱节）
        setModuleCache("photos", photos.value);

        const totalImported = result.imported.length;

        // 关键：进度条显示 100% 完成状态，保持 importingParsed=true 1.5s
        //   让用户看到完成反馈，然后一次性清理状态并关闭对话框
        //   （避免 importingParsed=false 后 parsedPhotos 未清空导致结果复现）
        importProgress.value = 100;
        // 文案仅由成功计数派生；不可解密项单列并说明原因，不混入成功计数
        const undecryptableNote = result.undecryptable > 0
          ? `（${result.undecryptable} 张无法用当前密钥解密，未导入）`
          : "";
        if (result.skipped > 0) {
          importStatus.value = `完成：导入 ${totalImported} 张，去重跳过 ${result.skipped} 张${undecryptableNote}`;
        } else {
          importStatus.value = `完成：导入 ${totalImported} 张照片${undecryptableNote}`;
        }

        // Toast 提示（toast 层级高于对话框，立即显示）
        if (result.skipped > 0) {
          showToast(`已导入 ${totalImported} 张照片，去重跳过 ${result.skipped} 张${undecryptableNote}`);
        } else {
          showToast(`已导入 ${totalImported} 张照片${undecryptableNote}`);
        }
        // 落盘结构性告警（partial_persisted）：数据已落盘，用非 error 的
        // 警告 toast 提示；不阻断提交，也不使用红色 error 条。
        if (persistWarning) {
          showToast(`照片已导入（校验警告）：${persistWarning}；如重启后异常请重新导入`);
        }

        // 1.5s 后一次性清理所有状态 + 关闭对话框（无缝衔接）
        //   顺序：清空 parsedPhotos → 重置 importingParsed → 重置进度 → 关闭对话框
        //   必须同时执行，避免中间状态导致模板回退到结果显示
        importDoneTimer.schedule(() => {
          parsedPhotos.value = [];           // 清理解析结果（根治"关闭后又复现"）
          importingParsed.value = false;      // 隐藏进度条
          importProgress.value = 0;
          importStatus.value = "";
          importElapsed.value = 0;
          importEta.value = 0;
          showParseDialog.value = false;      // 关闭对话框
        }, 1500);
      } catch (e) {
        // 持久化或缓存同步异常：重置导入状态，保留 parsedPhotos 供重试
        importingParsed.value = false;
        importProgress.value = 0;
        importStatus.value = "";
        importElapsed.value = 0;
        importEta.value = 0;
        console.error("[importParsedPhotos] 持久化/缓存异常", e);
        showError("导入后处理失败，请重试");
      }
    } else {
      // ===== 浏览器模式：仅添加到内存列表（无加密、无 IPC），ID 统一走单调计数器 =====
      const importable = parsedPhotos.value.filter(ph => ph.meta);
      const skipCount = parsedPhotos.value.length - importable.length;
      const newPhotos: PhotoEntry[] = importable.map((ph, i) => ({
        id: nextMemoryPhotoId(),
        name: ph.name,
        thumb: ph.thumb,
        size: formatSize(ph.size),
        height: 180 + ((i * 23) % 100),
        meta: ph.meta || undefined,
      }));
      pushShallowItems(photos, newPhotos);
      setModuleCache("photos", photos.value);
      // 文案仅由成功计数派生；浏览器模式不持久化，需向用户明示会话级生命周期
      const skipNote = skipCount > 0 ? `（${skipCount} 张无法用当前密钥解密，未导入）` : "";
      showToast(`已导入 ${newPhotos.length} 张照片${skipNote}（浏览器模式不持久化，仅本次会话可见）`);
      // 浏览器模式：立即清理并关闭
      parsedPhotos.value = [];
      importingParsed.value = false;
      showParseDialog.value = false;
    }
  };

  return {
    // ===== 状态 =====
    showParseDialog,
    parseFileName,
    parseFileData,
    parseToken,
    parsing,
    parsedPhotos,
    /** 无法用当前模块密钥解密的照片数（结果区预检展示用） */
    parsedUndecryptable,
    parsedEmpty,
    // 感知：进度条状态（复用中枢初始化窗口进度条样式，非量子动画）
    fileLoading,
    fileLoadingPercent,
    fileLoadingMsg,
    parsingPercent,
    parsingMsg,
    /* Parsed Import：对话框内导入进度条状态（复用 QuantumProgressFlow 组件）
       importingParsed=true 时对话框内显示 QuantumProgressFlow，替换"导入到拾光"按钮区 */
    importingParsed,
    // ===== 方法 =====
    openParseDialog,
    closeParseDialog,
    chooseParseFile,
    doParse,
    importParsedPhotos,
  };
}
