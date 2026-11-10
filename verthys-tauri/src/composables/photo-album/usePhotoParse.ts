/**
 * photo-album/usePhotoParse.ts — 拾光模块解析层 composable
 *
 * 职责：管理 .venc 文件反向解密和导入。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + 全局 Toast 中心的 showError/showToast（依赖注入）
 * - chooseParseFile：Tauri 用 open() + readUserFile；浏览器用 input[type=file]
 *   感知：文件读取过程复用进度条样式
 *     rAF 推进至 90% → 实际完成跳 100%，1.5s 最小感知时长，进度单调递增
 * - doParse：容器结构扫描在预览 Worker 内完成（令牌派生、清单解密、帧序与
 *   尾部计数校验），主线程只渲染进度并装载预览；预览不保留任何块载荷
 *   感知：解析过程复用中枢初始化窗口进度条样式（非量子动画）
 *     rAF 推进至 90% → 实际完成跳 100%，1.5s 最小感知时长，进度单调递增
 * - importParsedPhotos：Tauri 模式按原路径重读容器，交给
 *   ImportPipeline.runContainer() 三阶段流水线
 *   - 解密：导入 Worker 逐帧认证、整图哈希校验，并用当前模块 MDEK 逐块重封装
 *   - 传输器：外置块上传（跨照片聚合提交）
 *   - 消费者：verthysAddRecordsBatch 批量 IPC + WAL 断点续传 + 三层缓存同步
 *   - 去重：内容身份键（清单内 BLAKE3 文件哈希），跨备份文件/设备一致
 *   - 进度：ImportProgressState 逐文件更新 + rAF 帧对齐 → QuantumProgressFlow 实时显示
 *   - 持久化：pipeline 完成后 persistVerthys + 返回值检查
 *   - 复用 usePhotoImport 的 pipeline 实例 + 导入状态 refs（共享 QuantumProgressFlow）
 */
import { ref, shallowRef, onScopeDispose, type Ref, type ShallowRef } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { readUserFile, userFileStat } from "../../lib/verthys";
import { unpackVenc } from "../../lib/crypto";
import { persistVerthysDetailed, setModuleCache } from "../../lib/keyManager";
import { MAX_EXPORT_SINGLE_BYTES, MIN_TOKEN_LENGTH } from "../../constants/crypto_const";
import { pushShallowItems, replaceShallowArray } from "../../utils/shallow-array";
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import { formatSize, nextMemoryPhotoId, sortByMetaId, toPhotoCacheEntries } from "./utils";
import { useSingleTimer } from "./utils/timer";
import type { ImportPipeline } from "./importPipeline";
import { importedToPhotoEntries } from "./importPipeline";
import type {
  ParseCryptoRequest,
  ParseCryptoResponse,
  ParseCryptoCompletion,
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

/** 解析容器体积上限：与单文件导出口径一致，读盘前预检 */
const MAX_PARSE_CONTAINER_BYTES = MAX_EXPORT_SINGLE_BYTES;

/** 上限读数（GB 级常量按 GB 展示，便于与文件大小比较） */
const containerLimitText = (): string => {
  const gb = MAX_PARSE_CONTAINER_BYTES / (1024 * 1024 * 1024);
  return `${Number.isInteger(gb) ? gb : gb.toFixed(1)} GB`;
};

/**
 * 解析失败的用户文案。
 *
 * Why 分类：密钥错误、旧版本容器与结构损坏对应完全不同的用户动作——
 *   密钥错误需要重新输入令牌，旧版本需要换用对应版本的备份，结构损坏
 *   只能重新导出；统一报「格式无法识别」会让用户无从判断。
 */
function describeParseFailure(error: string): string {
  if (error.includes("TAG_VERIFICATION_FAILED")) {
    return "密钥不正确，或文件已损坏/被篡改";
  }
  if (error.includes("UNSUPPORTED_VERSION")) {
    return error.includes("备份格式版本")
      ? "该备份文件为旧版本格式，当前版本不再支持"
      : "备份文件使用了不支持的加密参数";
  }
  return "文件格式无法识别或已损坏";
}

/** usePhotoParse 依赖注入接口 */
export interface UsePhotoParseDeps {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 恢复模块密钥（从 keyManager 会话缓存） */
  ensurePhotoKey: () => boolean;
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示成功提示（来自全局 Toast 中心） */
  showToast: (msg: string) => void;
  /* Parsed Import：复用 usePhotoImport 的流水线实例 + 导入状态 refs */
  /** 获取流水线实例（复用 usePhotoImport 的 pipeline，共享进度状态机） */
  getPipeline: () => ImportPipeline;
  /** 导入进度百分比（0-100，复用 usePhotoImport 的 ref） */
  importProgress: Ref<number>;
  /** 导入状态文本（复用 usePhotoImport 的 ref） */
  importStatus: Ref<string>;
  /** 导入已耗时（毫秒，复用 usePhotoImport 的 ref） */
  importElapsed: Ref<number>;
  /** 解析 Worker 工厂（测试注入点；默认真实 Worker） */
  parseWorkerFactory?: () => ParseWorkerLike;
}

export function usePhotoParse(deps: UsePhotoParseDeps) {
  const {
    photos, isTauri, ensurePhotoKey, showError, showToast,
    /* Parsed Import：复用 usePhotoImport 的流水线 + 导入状态 refs */
    getPipeline, importProgress, importStatus, importElapsed,
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
  /**
   * 解析结果（shallowRef）：只含清单字段的预览项，不携带任何块载荷。
   * 本层只整体替换数组（预览列表不可变），shallowRef 语义完全够用。
   */
  const parsedPhotos = shallowRef<ParsedPhotoPreview[]>([]);
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

  /** 作用域已销毁：异步任务返回后不得再写界面状态或弹提示 */
  let disposed = false;
  /** 当前解析 Worker（组件卸载时必须终止，避免后台继续读取用户备份） */
  let activeParseWorker: ParseWorkerLike | null = null;
  /** 在途解析 Promise 的终结函数（终止 Worker 时同步收敛等待者） */
  let activeParseSettle: ((result: ParseCryptoCompletion) => void) | null = null;

  const terminateActiveParseWorker = (): void => {
    const worker = activeParseWorker;
    activeParseWorker = null;
    if (worker) {
      try {
        worker.terminate();
      } catch {
        // 终止失败仅表示实例将随引用释放回收
      }
    }
    // Worker 被终止时不会自发回消息：显式收敛等待者，避免解析 Promise 永久悬挂
    const settle = activeParseSettle;
    activeParseSettle = null;
    settle?.({
      id: 0,
      type: "failure",
      ok: false,
      error: "解析已取消",
    });
  };

  onScopeDispose(() => {
    disposed = true;
    importDoneTimer.dispose();
    if (fileLoadRafId !== null) {
      cancelAnimationFrame(fileLoadRafId);
      fileLoadRafId = null;
    }
    if (parseRafId !== null) {
      cancelAnimationFrame(parseRafId);
      parseRafId = null;
    }
    terminateActiveParseWorker();
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
  };

  const closeParseDialog = () => {
    // 解析中禁止关闭（保护数据完整性）
    if (parsing.value) return;
    // 文件读取中也禁止关闭（保护读取流程）
    if (fileLoading.value) return;
    // 导入中禁止关闭（保护流水线数据完整性）
    if (importingParsed.value) return;
    showParseDialog.value = false;
    // 关闭即释放解析产物：容器可达 GB 级，不依赖下次打开时才重置
    importDoneTimer.cancel();
    parsedPhotos.value = [];
    parseFileData.value = null;
    parseFilePath.value = null;
    parseFileName.value = "";
    parseToken.value = "";
  };

  const chooseParseFile = async () => {
    // 重入守卫：读取/解析/导入任一在途时不得再弹文件选择框
    if (disposed || fileLoading.value || parsing.value || importingParsed.value) return;
    /* 进度条仅在用户真正选择文件后启动
     *   先打开文件选择对话框，用户确认选择后再启动 rAF 推进真实读取进度
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
      if (disposed) return;
      if (fileLoadRafId !== null) { cancelAnimationFrame(fileLoadRafId); fileLoadRafId = null; }
      emitter.emit(100);
      fileLoadingMsg.value = "读取完成";
      await new Promise((r) => setTimeout(r, 200));
      if (disposed) return;
      fileLoading.value = false;
    };

    /** 统一错误处理：跑满感知时长 → 显示错误 → 关闭 loading */
    const handleFileError = async (
      emitter: ReturnType<typeof createProgressEmitter>,
      msg: string,
    ) => {
      await emitter.ensureMinDuration();
      if (disposed) return;
      if (fileLoadRafId !== null) { cancelAnimationFrame(fileLoadRafId); fileLoadRafId = null; }
      showError(msg);
      fileLoading.value = false;
    };

    if (isTauri) {
      // 先打开文件选择对话框，不启动进度条
      const path = await open({ filters: [{ name: "VENC Files", extensions: ["venc"] }] });
      if (disposed) return;
      if (!path || typeof path !== "string") {
        // 用户取消选择 → 静默返回，不显示任何进度
        return;
      }
      // 体积预检：容器整包进入内存前先按文件长度拒绝超限项。
      //   统计失败不阻断（读取/解包层仍会拒绝超长数据），但成功时绝不把
      //   超限文件读进内存。
      try {
        const stat = await userFileStat(path);
        if (stat.size > MAX_PARSE_CONTAINER_BYTES) {
          showError(`容器超过解析上限（${containerLimitText()}），无法解析`);
          return;
        }
      } catch (e) {
        console.warn("[chooseParseFile] 文件长度预检失败，按读取/解包层兜底", e);
      }
      if (disposed) return;
      // 用户已确认选择文件 → 启动真实读取进度
      startLoading();
      const emitter = createProgressEmitter(fileLoadingPercent);
      fileLoadRafId = requestAnimationFrame(emitter.tick);
      try {
        // 使用 readUserFile：用户通过对话框显式选择的文件已获授权，
        //   不受沙箱白名单限制；二进制 IPC 直传 Uint8Array
        const bytes = await readUserFile(path);
        if (disposed) return;
        parseFileData.value = bytes;
        parseFilePath.value = path;
        parseFileName.value = path.split(/[\\/]/).pop() || "unknown.venc";
        await finishLoading(emitter);
      } catch (e) {
        // 打印详细错误，便于定位
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
        if (disposed) return;
        if (!(input.files && input.files[0])) {
          // 用户取消选择 → 静默返回，不显示任何进度
          return;
        }
        const file = input.files[0];
        // 体积预检：浏览器无流式落盘，整包进内存前先拒绝超限项
        if (file.size > MAX_PARSE_CONTAINER_BYTES) {
          showError(`容器超过解析上限（${containerLimitText()}），无法解析`);
          return;
        }
        // 用户已确认选择文件 → 启动真实读取进度
        startLoading();
        const emitter = createProgressEmitter(fileLoadingPercent);
        fileLoadRafId = requestAnimationFrame(emitter.tick);
        try {
          const bytes = new Uint8Array(await file.arrayBuffer());
          if (disposed) return;
          parseFileName.value = file.name;
          parseFileData.value = bytes;
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
    // 重入守卫：同一解析任务只能有一个在途（连点/回车重复触发）
    if (disposed || parsing.value || fileLoading.value || importingParsed.value) return;
    if (!parseFileData.value || !parseToken.value.trim()) return;

    // 模块密钥超时锁定后提示用户返回重新解锁（正式导入必须用当前 MDEK 重封装）
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }

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
      if (disposed) return;
      if (parseRafId !== null) { cancelAnimationFrame(parseRafId); parseRafId = null; }
      emitter.emit(100);
      parsingMsg.value = "解析完成";
      await new Promise((r) => setTimeout(r, 200));
      if (disposed) return;
      parsing.value = false;
    };

    /** 统一错误处理：跑满感知时长 → 显示错误 → 关闭 loading */
    const handleParseError = async (msg: string) => {
      await emitter.ensureMinDuration();
      if (disposed) return;
      if (parseRafId !== null) { cancelAnimationFrame(parseRafId); parseRafId = null; }
      showError(msg);
      parsing.value = false;
    };

    /** rAF 去重标志（防止高频进度更新导致过度渲染） */
    let parseRafPending = false;

    /**
     * 发射真实扫描进度
     *
     * 容器不提供照片总数，进度只展示已扫描张数；百分比由 rAF 时间轴推进，
     * 不按未知总数换算（避免分母缺失导致的假百分比）。
     */
    const emitRealProgress = (current: number) => {
      if (disposed) return;
      if (!parseRafPending) {
        parseRafPending = true;
        requestAnimationFrame(() => {
          if (disposed) return;
          parsingMsg.value = `正在还原照片预览 ${current} 张`;
          parseRafPending = false;
        });
      }
    };

    try {
      // 1. 容器结构扫描全部在预览 Worker 内完成：
      //    令牌派生、清单解密、帧序与尾部计数校验均不占主线程；
      //    主线程仅等待完成、按 worker 进度消息渲染、装载预览结果
      parsingMsg.value = "正在解密加密文件";

      // 缓冲区所有权契约：
      //   Tauri 模式把字节所有权转移给 Worker，正式导入时按原路径重读；
      //   浏览器模式没有导入流水线，保留原缓冲供内存导入，只转让副本。
      //   失败后未重选文件直接重试时，Tauri 模式按原路径重读。
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
      // 转让缓冲：视图与底层缓冲不重合时先复制精确片段
      const ownsBuffer =
        data.byteOffset === 0 && data.byteLength === data.buffer.byteLength;
      const transferBuffer: ArrayBuffer = isTauri
        ? (ownsBuffer ? (data.buffer as ArrayBuffer) : (data.slice().buffer as ArrayBuffer))
        : (data.slice().buffer as ArrayBuffer);

      const worker = parseWorkerFactory();
      activeParseWorker = worker;
      if (disposed) {
        terminateActiveParseWorker();
        return;
      }
      const finalResponse = new Promise<ParseCryptoCompletion>((resolve) => {
        activeParseSettle = resolve;
        worker.onmessage = (e) => {
          const msg = e.data as ParseCryptoResponse;
          if (msg.type === "progress") {
            emitRealProgress(msg.current);
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
        } satisfies ParseCryptoRequest,
        [transferBuffer],
      );

      const res = await finalResponse;
      terminateActiveParseWorker();
      // 作用域已销毁：结果不再写回界面（备份内容已无展示载体）
      if (disposed) return;

      if (!res.ok) {
        // 面向用户文案：区分密钥错误、旧版本与文件损坏，不暴露内部错误码与实现细节
        await handleParseError(`解析失败：${describeParseFailure(res.error)}`);
        return;
      }

      // 预览项与 Worker 协议结构同构（只含清单字段），直接装载
      parsedPhotos.value = res.previews;
      await finishParsing();
    } catch (e) {
      console.error("[doParse] 解析失败:", e);
      terminateActiveParseWorker();
      if (disposed) return;
      const msg = describeParseFailure(e instanceof Error ? e.message : String(e));
      await handleParseError(`解析失败：${msg}`);
    }
  };

  const importParsedPhotos = async () => {
    // 重入守卫：作用域已销毁或解析导入进行中时禁止再次触发（连点/双击防护）
    if (disposed || importingParsed.value) return;

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
      // ===== Tauri 模式：按原路径重读容器，交给导入 Worker + 三阶段流水线 =====

      const path = parseFilePath.value;
      if (!path) {
        importingParsed.value = false;
        showError("请重新选择备份文件");
        return;
      }

      // 重读前体积预检：预览后文件可能被替换，超限文件不得整包读入内存
      try {
        const stat = await userFileStat(path);
        if (stat.size > MAX_PARSE_CONTAINER_BYTES) {
          importingParsed.value = false;
          importProgress.value = 0;
          importStatus.value = "";
          importElapsed.value = 0;
          showError(`容器超过解析上限（${containerLimitText()}），无法导入`);
          return;
        }
      } catch (e) {
        console.warn("[importParsedPhotos] 文件长度预检失败，按读取/解包层兜底", e);
      }
      if (disposed) return;

      // ----- 阶段 1：重读容器并执行流水线（异常分离） -----
      let result;
      try {
        const bytes = await readUserFile(path);
        if (disposed) return;
        const pipe = getPipeline();
        result = await pipe.runContainer(parsedPhotos.value, {
          bytes,
          token: parseToken.value.trim(),
        });
      } catch (e) {
        // 异常路径：重置导入状态，保留 parsedPhotos 供重试，不关闭对话框
        importingParsed.value = false;
        importProgress.value = 0;
        importStatus.value = "";
        importElapsed.value = 0;

        console.error("[importParsedPhotos] 流水线异常", e);
        if (!disposed) showError("导入失败，请重试");
        return;
      }

      // ----- 阶段 2：先落盘（部分成功同样必须持久化） -----
      //    ok                → 落盘且结构自查通过；
      //    partial_persisted → flush 成功（数据已 fsync）但结构自查未过，仍提交列表；
      //    not_persisted     → flush 本身失败，不提交、保留 parsedPhotos 供重试。
      let persistWarning: string | null = null;
      if (result.imported.length > 0) {
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
          if (!disposed) showError("持久化失败，本次导入未生效，请重试");
          return;
        }
        persistWarning =
          persistOutcome.kind === "partial_persisted" ? persistOutcome.reason : null;
      }

      // ----- 阶段 3：提交列表与缓存（成功项已落盘，失败项保留供重试） -----
      try {
        // 作用域已销毁：数据已落盘，界面不再回写（列表已被卸载清理）
        if (disposed) return;

        if (result.imported.length > 0) {
          const newEntries = importedToPhotoEntries(result.imported);
          pushShallowItems(photos, newEntries);
          // 列表约定按记录 ID 升序：ID 复用场景下增量项需重新归位
          replaceShallowArray(photos, sortByMetaId(photos.value));
          // 同步模块缓存（落盘成功之后，避免缓存与磁盘状态脱节）
          setModuleCache("photos", toPhotoCacheEntries(photos.value));
        }

        // 落盘结构性告警（partial_persisted）：数据已落盘，用非 error 的
        // 警告 toast 提示；不阻断提交，也不使用红色 error 条。
        if (persistWarning) {
          showToast(`照片已导入（校验警告）：${persistWarning}；如重启后异常请重新导入`);
        }

        // ----- 阶段 4：失败/部分失败：成功项已入列，失败项保留供重试 -----
        if (!result.ok) {
          importingParsed.value = false;
          importProgress.value = 0;
          importStatus.value = "";
          importElapsed.value = 0;
          if (result.error) {
            showError(`导入失败: ${result.error}`);
          } else {
            // 部分失败且无会话级错误：按失败计数提示（成功项已入账，可重试失败部分）
            showError(
              `导入 ${result.imported.length} 张，失败 ${result.failedRecords.length} 张，请重试`,
            );
          }
          return;
        }

        // ----- 阶段 5：成功路径 — 进度收口与对话框关闭 -----
        const totalImported = result.imported.length;

        // 关键：进度条显示 100% 完成状态，保持 importingParsed=true 1.5s
        //   让用户看到完成反馈，然后一次性清理状态并关闭对话框
        //   （避免 importingParsed=false 后 parsedPhotos 未清空导致结果复现）
        importProgress.value = 100;
        // 文案仅由成功/跳过计数派生
        if (result.skipped > 0) {
          importStatus.value = `完成：导入 ${totalImported} 张，去重跳过 ${result.skipped} 张`;
        } else {
          importStatus.value = `完成：导入 ${totalImported} 张照片`;
        }

        // Toast 提示（toast 层级高于对话框，立即显示）
        if (result.skipped > 0) {
          showToast(`已导入 ${totalImported} 张照片，去重跳过 ${result.skipped} 张`);
        } else {
          showToast(`已导入 ${totalImported} 张照片`);
        }

        // 1.5s 后一次性清理所有状态 + 关闭对话框（无缝衔接）
        //   顺序：清空 parsedPhotos → 重置 importingParsed → 重置进度 → 关闭对话框
        //   必须同时执行，避免中间状态导致模板回退到结果显示
        importDoneTimer.schedule(() => {
          parsedPhotos.value = [];           // 清理解析结果（避免关闭后又复现）
          // 容器字节可能达 GB 级：成功后立即释放，不依赖下次打开对话框时重置
          parseFileData.value = null;
          parseFilePath.value = null;
          parseFileName.value = "";
          parseToken.value = "";
          importingParsed.value = false;      // 隐藏进度条
          importProgress.value = 0;
          importStatus.value = "";
          importElapsed.value = 0;
          showParseDialog.value = false;      // 关闭对话框
        }, 1500);
      } catch (e) {
        // 缓存同步异常：重置导入状态，保留 parsedPhotos 供重试
        importingParsed.value = false;
        importProgress.value = 0;
        importStatus.value = "";
        importElapsed.value = 0;
        console.error("[importParsedPhotos] 缓存同步异常", e);
        if (!disposed) showError("导入后处理失败，请重试");
      }
    } else {
      // ===== 浏览器模式：内存列表（无模块密钥、无 IPC） =====
      // 浏览器模式没有导入流水线，也没有当前模块 MDEK 可重封装；直接在本线程
      // 完整解包容器，把原始明文块拼回单张照片字节，仅本次会话可见。
      const source = parseFileData.value;
      if (!source || source.buffer.byteLength === 0) {
        importingParsed.value = false;
        showError("文件数据已释放，请重新选择文件");
        return;
      }
      let specs;
      try {
        specs = await unpackVenc(source, parseToken.value.trim());
      } catch (e) {
        importingParsed.value = false;
        console.error("[importParsedPhotos] 浏览器解包失败", e);
        if (!disposed) showError("导入失败：文件已损坏或密钥不正确");
        return;
      }
      if (disposed) return;
      const newPhotos: PhotoEntry[] = specs.map((spec, i) => {
        const rawBytes = new Uint8Array(spec.lightMeta.size);
        let offset = 0;
        for (const chunk of spec.chunkBytes) {
          rawBytes.set(chunk, offset);
          offset += chunk.length;
        }
        return {
          id: nextMemoryPhotoId(),
          name: spec.lightMeta.name,
          thumb: spec.lightMeta.thumbB64
            ? `url(data:image/jpeg;base64,${spec.lightMeta.thumbB64})`
            : "",
          size: formatSize(spec.lightMeta.size),
          height: 180 + ((i * 23) % 100),
          rawBytes,
        };
      });
      pushShallowItems(photos, newPhotos);
      setModuleCache("photos", toPhotoCacheEntries(photos.value));
      // 浏览器模式不持久化，需向用户明示会话级生命周期
      showToast(`已导入 ${newPhotos.length} 张照片（浏览器模式不持久化，仅本次会话可见）`);
      // 浏览器模式：立即释放容器字节并关闭
      parsedPhotos.value = [];
      parseFileData.value = null;
      parseFilePath.value = null;
      parseFileName.value = "";
      parseToken.value = "";
      importingParsed.value = false;
      showParseDialog.value = false;
    }
  };

  return {
    // ===== 状态 =====
    showParseDialog,
    parseFileName,
    parseFileData,
    parseFilePath,
    parseToken,
    parsing,
    parsedPhotos,
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
