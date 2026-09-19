/**
 * photo-album/usePhotoParse.ts — 拾光模块解析层 composable
 *
 * 职责：管理 .venc 文件反向解密和导入。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + usePhotoToast 的 showError/showToast（依赖注入）
 * - chooseParseFile：Tauri 用 open() + readUserFile；浏览器用 input[type=file]
 *   ★ 企业级感知：文件读取过程复用中枢初始化窗口进度条样式（非量子动画）
 *     rAF 推进至 90% → 实际完成跳 100%，1.5s 最小感知时长，进度单调递增
 * - doParse：decryptExportFile → unpackVencMultiFile → 遍历用当前密钥 decryptMeta 预览
 *   ★ 企业级感知：解析过程复用中枢初始化窗口进度条样式（非量子动画）
 *     rAF 推进至 90% → 实际完成跳 100%，1.5s 最小感知时长，进度单调递增
 * - importParsedPhotos（★ 企业级重构）：使用 ImportPipeline.runParsed() 三阶段流水线
 *   - 生产者：构造新 meta（内联已加密 chunks）→ submitMetaOnly() 到 Worker 池并行加密
 *   - 传输器：Worker 池并行 encryptMeta（CPU 密集型任务移出主线程，UI 不卡死）
 *   - 消费者：verthysAddRecordsBatch 批量 IPC + WAL 断点续传 + 三层缓存同步
 *   - 进度：ImportProgressState 逐文件更新 + rAF 帧对齐 → QuantumProgressFlow 实时显示
 *   - 持久化：pipeline 完成后 persistVerthys + 返回值检查
 *   - 复用 usePhotoImport 的 pipeline 实例 + importing refs（共享 QuantumProgressFlow）
 */
import { ref, type Ref, type ShallowRef } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { readUserFile } from "../../lib/verthys";
import { persistVerthys, setModuleCache } from "../../lib/keyManager";
import {
  decryptMeta, decryptExportFile, unpackVencMultiFile,
  type PhotoMeta,
} from "../../lib/crypto";
import { pushShallowItems } from "../../utils/shallow-array";
import { yieldToMain } from "../../utils/promise_utils";
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import { formatSize } from "./utils";
import type { ImportPipeline } from "./importPipeline";
import { importedToPhotoEntries } from "./importPipeline";

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
  /* ★ Parsed Import：复用 usePhotoImport 的流水线实例 + 导入状态 refs */
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
}

export function usePhotoParse(deps: UsePhotoParseDeps) {
  const {
    photos, photoKey, isTauri, ensurePhotoKey, showError, showToast,
    /* ★ Parsed Import：复用 usePhotoImport 的流水线 + 导入状态 refs */
    getPipeline, importing, importProgress, importStatus, importElapsed, importEta,
  } = deps;

  /* ===== 解析对话框（反向解密 .venc 文件） ===== */
  const showParseDialog = ref(false);
  const parseFileName = ref("");
  const parseFileData = ref<Uint8Array | null>(null);
  const parseToken = ref("");
  const parsing = ref(false);
  const parsedPhotos = ref<ParsedPhotoPreview[]>([]);
  /* ★ Parsed Import：对话框内导入进度条状态（复用 QuantumProgressFlow 组件）
     importingParsed 控制对话框内 QuantumProgressFlow 显示，与顶部的 importing ref 解耦，
     避免关闭对话框造成的视觉割裂（用户在对话框内实时看到导入进度） */
  const importingParsed = ref(false);

  /* ===== 企业级感知：进度条状态（复用中枢初始化窗口进度条样式，非量子动画） ===== */
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

  /* ★ Parsed Import：导入完成后的清理定时器
     用于追踪 setTimeout 句柄，在 openParseDialog 时清除残留定时器，防止内存泄漏 */
  let importDoneTimer: ReturnType<typeof setTimeout> | null = null;

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
      // ★ 单调递增闸门：Math.max 钳制，防止回退
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
    // ★ 清除上一次可能残留的导入完成定时器（防止内存泄漏 + 状态错乱）
    if (importDoneTimer) {
      clearTimeout(importDoneTimer);
      importDoneTimer = null;
    }
    showParseDialog.value = true;
    parseFileName.value = "";
    parseFileData.value = null;
    parseToken.value = "";
    parsedPhotos.value = [];
    // 重置进度状态（防止上次残留）
    fileLoading.value = false;
    fileLoadingPercent.value = 0;
    fileLoadingMsg.value = "";
    parsingPercent.value = 0;
    parsingMsg.value = "";
    // ★ 重置导入状态（防止上次残留导致对话框显示错误状态）
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
    // ★ 导入中禁止关闭（保护流水线数据完整性）
    if (importingParsed.value) return;
    showParseDialog.value = false;
  };

  const chooseParseFile = async () => {
    /* ★ 企业级感知修正：进度条仅在用户真正选择文件后启动
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
      // ★ 先打开文件选择对话框，不启动进度条
      const path = await open({ filters: [{ name: "VENC Files", extensions: ["venc"] }] });
      if (!path || typeof path !== "string") {
        // 用户取消选择 → 静默返回，不显示任何进度
        return;
      }
      // ★ 用户已确认选择文件 → 启动真实读取进度
      startLoading();
      const emitter = createProgressEmitter(fileLoadingPercent);
      fileLoadRafId = requestAnimationFrame(emitter.tick);
      try {
        // ★ 企业级根治：使用 readUserFile 而非 readFileBytes
        //   用户通过对话框显式选择的文件已获授权，不应受沙箱白名单限制
        //   原缺陷：readFileBytes 白名单仅含 home_dir，D:\ 等路径被拒
        //   二进制 IPC 直传 Uint8Array（去 base64 化）
        parseFileData.value = await readUserFile(path);
        parseFileName.value = path.split(/[\\/]/).pop() || "unknown.venc";
        await finishLoading(emitter);
      } catch (e) {
        // ★ 企业级根治：打印详细错误，便于定位（原 catch 吞掉错误详情）
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
        // ★ 用户已确认选择文件 → 启动真实读取进度
        startLoading();
        const emitter = createProgressEmitter(fileLoadingPercent);
        fileLoadRafId = requestAnimationFrame(emitter.tick);
        try {
          const file = input.files[0];
          parseFileName.value = file.name;
          parseFileData.value = new Uint8Array(await file.arrayBuffer());
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
    if (!parseFileData.value || !parseToken.value) return;
    // ★ 企业级感知：启动 rAF 进度推进（复用中枢初始化窗口进度条样式）
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
     * ★ P0 修复：发射真实进度（rAF 去重）
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
      // 1. 解密外层 AES-256-GCM
      parsingMsg.value = "正在解密加密文件";
      const vencBytes = await decryptExportFile(parseFileData.value, parseToken.value);

      // 2. 解包（unpackVencMultiFile 内部校验 magic 头 "VERTHYSPHOTO"(9字节) + 版本号）
      parsingMsg.value = "正在解包照片数据";
      const photoList = unpackVencMultiFile(vencBytes);

      // 3. 尝试用当前密钥解密元数据以预览（不同设备密钥不同时显示占位）
      // ★ P0 修复：逐张解密 + 真实进度 + yieldToMain 让出主线程
      //   旧实现：for 循环内 await decryptMeta 串行阻塞，rAF 无法执行 → 进度条冻结
      //   新实现：每解密完一张 → emitRealProgress 真实进度 → yieldToMain 让出 → rAF 得以执行
      parsingMsg.value = "正在还原照片预览";
      const preview: ParsedPhotoPreview[] = [];
      const total = photoList.length;
      for (let i = 0; i < photoList.length; i++) {
        const p = photoList[i];
        let name = "加密照片";
        let thumb = "";
        let size = 0;
        let meta: PhotoMeta | null = null;
        if (photoKey.value) {
          try {
            meta = await decryptMeta(p.metaB64, photoKey.value);
            name = meta.name;
            size = meta.size;
            if (meta.thumbB64) thumb = `url(data:image/jpeg;base64,${meta.thumbB64})`;
          } catch { /* 当前密钥无法解密，显示占位 */ }
        }
        preview.push({ name, thumb, size, metaB64: p.metaB64, chunkB64List: p.chunkB64List, meta });

        // ★ 发射真实进度（rAF 去重）
        emitRealProgress(i + 1, total);

        // ★ P0 核心：每解密完一张照片后 yieldToMain，强制让出主线程
        //   保证 requestAnimationFrame 回调（进度条渲染）得到执行机会
        //   这是让进度条「真正动起来」的唯一解
        await yieldToMain();
      }
      parsedPhotos.value = preview;
      await finishParsing();
    } catch (e) {
      console.error("[doParse] 解析失败:", e);
      const msg = e instanceof Error ? e.message : "未知错误";
      await handleParseError("解析失败：" + msg);
    }
  };

  const importParsedPhotos = async () => {
    // 模块密钥超时锁定后提示用户返回重新解锁
    if (!ensurePhotoKey()) {
      showError("拾光模块已锁定，请返回重新解锁");
      return;
    }

    // ★ 清除上一次可能残留的导入完成定时器
    if (importDoneTimer) {
      clearTimeout(importDoneTimer);
      importDoneTimer = null;
    }

    // ★ 保持解析对话框开启，在对话框内复用 QuantumProgressFlow 显示导入进度
    importingParsed.value = true;

    if (isTauri) {
      // ===== Tauri 模式：使用三阶段异步流水线 =====

      // ----- 阶段 1：执行流水线（异常分离） -----
      let result;
      try {
        const pipe = getPipeline();
        result = await pipe.runParsed(parsedPhotos.value, photoKey.value);
      } catch (e) {
        // ★ 异常路径：重置导入状态，保留 parsedPhotos 供重试，不关闭对话框
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
      if (!result.ok && result.error) {
        // ★ 失败路径：重置导入状态，保留 parsedPhotos 供重试，不关闭对话框
        importingParsed.value = false;
        importProgress.value = 0;
        importStatus.value = "";
        importElapsed.value = 0;
        importEta.value = 0;

        if (result.error.includes("VERTHYS_WRITE_BLOCKED")) {
          showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        } else {
          showError(`导入失败: ${result.error}`);
        }
        return;
      }

      // ----- 阶段 3：成功路径 — 处理导入结果 -----
      try {
        // 将导入结果转换为 PhotoEntry 并追加到照片列表
        if (result.imported.length > 0) {
          const newEntries = importedToPhotoEntries(result.imported, photos.value.length);
          pushShallowItems(photos, newEntries);
        }

        // ★ 无法解密的照片（meta 为 null，不同设备导入）：仅添加到内存列表
        const inMemoryOnly = parsedPhotos.value.filter(ph => !ph.meta);
        if (inMemoryOnly.length > 0) {
          const memoryEntries: PhotoEntry[] = inMemoryOnly.map((ph, i) => ({
            id: Date.now() + result.imported.length + i,
            name: ph.name,
            thumb: ph.thumb,
            size: formatSize(ph.size),
            height: 180 + (((result.imported.length + i) * 23) % 100),
            meta: ph.meta || undefined,
          }));
          pushShallowItems(photos, memoryEntries);
        }

        // ★ 企业级根治：持久化到磁盘 + 返回值检查
        let persistOk = false;
        try {
          persistOk = await persistVerthys();
        } catch (e) {
          console.error("[importParsedPhotos] persistVerthys 异常", e);
        }
        if (!persistOk && result.imported.length > 0) {
          showError(`${result.imported.length} 张照片已导入内存但持久化失败，重启后可能丢失。请勿关闭应用，尝试重新导入或联系支持。`);
        }

        // 同步模块缓存
        setModuleCache("photos", photos.value);

        const totalImported = result.imported.length + inMemoryOnly.length;

        // ★ 关键：进度条显示 100% 完成状态，保持 importingParsed=true 1.5s
        //   让用户看到完成反馈，然后一次性清理状态并关闭对话框
        //   （避免 importingParsed=false 后 parsedPhotos 未清空导致结果复现）
        importProgress.value = 100;
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

        // ★ 1.5s 后一次性清理所有状态 + 关闭对话框（无缝衔接）
        //   顺序：清空 parsedPhotos → 重置 importingParsed → 重置进度 → 关闭对话框
        //   必须同时执行，避免中间状态导致模板回退到结果显示
        importDoneTimer = setTimeout(() => {
          importDoneTimer = null;
          parsedPhotos.value = [];           // ★ 清理解析结果（根治"关闭后又复现"）
          importingParsed.value = false;      // ★ 隐藏进度条
          importProgress.value = 0;
          importStatus.value = "";
          importElapsed.value = 0;
          importEta.value = 0;
          showParseDialog.value = false;      // ★ 关闭对话框
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
      // ===== 浏览器模式：仅添加到内存列表（无加密、无 IPC） =====
      const newPhotos: PhotoEntry[] = parsedPhotos.value.map((ph, i) => ({
        id: Date.now() + i,
        name: ph.name,
        thumb: ph.thumb,
        size: formatSize(ph.size),
        height: 180 + ((i * 23) % 100),
        meta: ph.meta || undefined,
      }));
      pushShallowItems(photos, newPhotos);
      setModuleCache("photos", photos.value);
      showToast(`已导入 ${newPhotos.length} 张照片`);
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
    // ★ 企业级感知：进度条状态（复用中枢初始化窗口进度条样式，非量子动画）
    fileLoading,
    fileLoadingPercent,
    fileLoadingMsg,
    parsingPercent,
    parsingMsg,
    /* ★ Parsed Import：对话框内导入进度条状态（复用 QuantumProgressFlow 组件）
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
