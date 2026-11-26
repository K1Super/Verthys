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
import { photoExportStart } from "../../lib/verthys";
import {
  packVenc, estimateVencTotalBytes, toLightMeta,
  generateRandomToken,
  type PhotoMeta, type VencPhotoSpec,
} from "../../lib/crypto";
import { MAX_EXPORT_FILENAME_BYTES, MAX_EXPORT_SINGLE_BYTES, MIN_TOKEN_LENGTH, FILE_HASH_LEN } from "../../constants/crypto_const";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "../../utils/binary_codec";
import type { PhotoEntry, ExportFormat } from "./types";
import {
  guessMime, downloadBlob, convertToPngBytes,
  sanitizeFileName,
} from "./utils";
import { detectAnimatedImage } from "../../utils/animated-image";
import { createLogger } from "../../utils/logger";
import { pushModal, popModal } from "../../utils/modal_stack";

const log = createLogger("photo-export");

/** 导出失败原因分类（跨格式统一，供 UI 汇总） */
type ExportFailureReason =
  | "data-missing"    // 记录/元数据/块数据缺失（含占位项无法解密）
  | "pack-failed"     // 容器打包失败（清单越界/令牌加密失败）
  | "decrypt-failed"  // 明文导出解密失败
  | "convert-failed"  // 图片格式转换失败
  | "write-failed"    // 落盘/下载失败
  | "animated-unsupported" // 动图无法用 PNG 单帧格式承载
  | "unknown";        // 未分类失败

/** 单条失败明细（按张定位，供结果摘要展示） */
interface ExportFailure {
  /** 照片显示名（缺失时回退记录 ID 描述） */
  name: string;
  /** 失败原因分类 */
  reason: ExportFailureReason;
}

/**
 * PNG 明文导出是否会丢失动画。
 *
 * 已确认动图（新导入/备份还原）直接判定；历史记录没有标记，只能对解密
 * 后的原始字节补判。PNG 只能承载单帧，命中即跳过并显式记账，不得静默
 * 导出首帧冒充成功。
 */
function isAnimatedForPng(ph: PhotoEntry, mime: string, bytes: Uint8Array): boolean {
  if (ph.animated !== undefined) return ph.animated;
  return detectAnimatedImage(mime, bytes);
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
  /** 当前导出序号/总数：原生按文件、浏览器按选中照片；total=0 时只显示阶段标签 */
  const exportCurrent = ref(0);
  const exportTotal = ref(0);
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

  /** 原生导出是否可用（桌面端恒可用；浏览器走下载降级） */
  const nativeExportAvailable = computed(() => isTauri);

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
    exportCurrent.value = 0;
    exportTotal.value = 0;
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
   * 获取浏览器模式照片明文字节。
   *
   * 桌面端不经过本函数：导出由 worker 解密/打包/编码，前端只接收结果。
   */
  const getBrowserPhotoBytes = (
    ph: PhotoEntry,
  ): { bytes: Uint8Array; meta: PhotoMeta | null } | null => {
    if (!ph.rawBytes) return null;
    return { bytes: ph.rawBytes, meta: ph.meta ?? null };
  };

  /** 收集浏览器模式照片的容器数据；逐张失败显式计入 failures。 */
  const collectPhotoSpecs = (
    selected: PhotoEntry[],
    failures: ExportFailure[],
  ): VencPhotoSpec[] => {
    const specs: VencPhotoSpec[] = [];
    for (const ph of selected) {
      const decoded = getBrowserPhotoBytes(ph);
      if (!decoded) {
        failures.push({ name: ph.name || `照片 #${ph.id}`, reason: "data-missing" });
        continue;
      }
      try {
        specs.push({
          lightMeta: toLightMeta(
            {
              name: ph.name,
              mime: decoded.meta?.mime || guessMime(ph.name),
              size: decoded.bytes.length,
              thumbB64: "",
              chunkIds: [],
              fileHash: decoded.meta?.fileHash
                || bytesToHex(blake3(decoded.bytes, { dkLen: FILE_HASH_LEN })),
              createdAt: decoded.meta?.createdAt || Date.now(),
            },
            1,
          ),
          chunkBytes: [decoded.bytes],
        });
      } catch (e) {
        log.warn(`浏览器模式照片清单非法: ${ph.name}`, e);
        failures.push({ name: ph.name || `照片 #${ph.id}`, reason: "pack-failed" });
      }
    }
    return specs;
  };

  /** 文件名净化：字节预算必须含扩展名，否则超长名称拼上后缀后仍会越界 */
  const sanitizeWithExtension = (name: string, ext: string): string => {
    const extBytes = new TextEncoder().encode(ext).length;
    return `${sanitizeFileName(name, Math.max(1, MAX_EXPORT_FILENAME_BYTES - extBytes))}${ext}`;
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
    // 过短）：前置拦截，避免读完照片数据才在打包层失败；PNG 与原始文件为
    // 明文导出，不需要令牌
    const plaintextFormat = exportFormat.value === "png" || exportFormat.value === "original";
    if (!plaintextFormat && exportToken.value.trim().length < MIN_TOKEN_LENGTH) {
      showError(`加密令牌至少 ${MIN_TOKEN_LENGTH} 位字符，请填写或重新生成`);
      return;
    }
    if (!plaintextFormat) {
      // 与还原端归一化口径一致：令牌首尾空白不参与派生，否则导出可成功但
      // 还原端按 trim 后的令牌派生会解封失败（备份不可恢复）
      exportToken.value = exportToken.value.trim();
    }
    // 原始文件导出只有桌面原生链路
    if (exportFormat.value === "original" && !isTauri) {
      showError("原文件导出仅在桌面端可用");
      return;
    }
    exporting.value = true;
    exportProgress.value = 0;
    exportCurrent.value = 0;
    exportTotal.value = 0;

    const selected = photos.value.filter(p => exportSelectedIds.value.has(p.id));
    if (selected.length === 0) {
      // 选片集合与当前列表脱节（列表被刷新/清空）：不得以「已导出 0 张」假成功收尾
      exporting.value = false;
      return;
    }
    // 原始文件导出必须拿到记录 ID；任一选中项缺失即拒绝，避免误入旧 .venc 分支
    if (exportFormat.value === "original" && !selected.every((p) => p.metaId)) {
      exporting.value = false;
      showError("存在未加载的照片，请刷新后重试");
      return;
    }
    try {
      let outcome: ExportOutcome | null = null;

      /* ===== 桌面原生导出：worker 解密/打包/编码，宿主暂存写盘 ===== */
      if (isTauri) {
        if (!selected.every((p) => p.metaId)) {
          exportStatus.value = "存在未加载的照片，请刷新后重试";
          showExportDone("存在未加载的照片，请刷新后重试", "error");
          exporting.value = false;
          return;
        }
        const nativeFormat: "original" | "venc-single" | "venc-multiple" | "png" =
          exportFormat.value === "single" ? "venc-single"
            : exportFormat.value === "multiple" ? "venc-multiple"
              : exportFormat.value === "original" ? "original" : "png";
        const needsToken = nativeFormat === "venc-single" || nativeFormat === "venc-multiple";
        exportStatus.value = "正在读取照片数据";
        const native = await photoExportStart(
          selected.map((p) => p.metaId as number),
          nativeFormat,
          exportPath.value,
          needsToken ? exportToken.value : undefined,
          (p) => {
            exportProgress.value = p.percent;
            if (p.phase === "scanning") {
              exportCurrent.value = 0;
              exportTotal.value = 0;
              exportStatus.value = "正在读取照片数据";
            } else if (p.phase === "exporting") {
              exportTotal.value = p.totalFiles;
              exportCurrent.value =
                p.totalFiles > 0 ? Math.min(p.doneFiles + 1, p.totalFiles) : 0;
              exportStatus.value = "正在导出";
            } else if (p.phase === "finishing") {
              exportCurrent.value = exportTotal.value;
              exportStatus.value = "正在收尾";
            }
          },
        );
        if (native.errorCode === "E_EXPORT_TOO_LARGE") {
          const limitGb = MAX_EXPORT_SINGLE_BYTES / (1024 * 1024 * 1024);
          const limitText = `${Number.isInteger(limitGb) ? limitGb : limitGb.toFixed(1)} GB`;
          exportStatus.value = `容器体积超过单文件上限 ${limitText}，请改用多文件模式`;
          showExportDone(`容器体积超过单文件上限（${limitText}），请改用多文件模式`, "error");
          exporting.value = false;
          return;
        } else if (native.cancelled) {
          exportStatus.value = `导出已取消（已导出 ${native.exported} 张）`;
          showExportDone("导出已取消", "error");
          exporting.value = false;
          return;
        } else if (!native.ok && native.error && native.exported === 0 && native.failed.length === 0) {
          exportStatus.value = "导出失败，请重试";
          showExportDone(`导出失败：${native.error}`, "error");
          exporting.value = false;
          return;
        } else {
          const reasonOf = (reason: string): ExportFailureReason => {
            const known: ExportFailureReason[] = [
              "data-missing", "pack-failed", "decrypt-failed",
              "convert-failed", "write-failed", "animated-unsupported",
            ];
            return known.includes(reason as ExportFailureReason)
              ? (reason as ExportFailureReason)
              : "unknown";
          };
          const failures: ExportFailure[] = native.failed.map((f) => ({
            name: f.name || `照片 #${f.index}`,
            reason: reasonOf(f.reason),
          }));
          if (!native.ok && native.error && failures.length === 0) {
            failures.push({ name: "导出任务", reason: "unknown" });
          }
          outcome = {
            successCount: native.exported,
            failCount: failures.length,
            failures,
          };
        }
      }

      if (!outcome) {
        // ===== 浏览器模式：内存字节打包 / Canvas PNG / 直接下载 =====
        if (exportFormat.value === "single") {
          const failures: ExportFailure[] = [];
          exportStatus.value = "正在读取照片数据";
          exportProgress.value = 10;
          const specs = collectPhotoSpecs(selected, failures);
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
            exportStatus.value = "正在打包";
            exportProgress.value = 50;
            const vencBytes = await packVenc(specs, exportToken.value);
            downloadBlob(vencBytes, `verthys_${Date.now()}.venc`);
          }
          exportProgress.value = 100;
          outcome = { successCount: specs.length, failCount: failures.length, failures };
        } else if (exportFormat.value === "png") {
          outcome = await (async (): Promise<ExportOutcome> => {
            let successCount = 0;
            const failures: ExportFailure[] = [];
            for (let i = 0; i < selected.length; i++) {
              const ph = selected[i];
              exportStatus.value = "正在转换";
              exportCurrent.value = i + 1;
              exportTotal.value = selected.length;
              exportProgress.value = Math.round((i / selected.length) * 100);

              if (ph.animated === true) {
                failures.push({ name: ph.name, reason: "animated-unsupported" });
                continue;
              }

              try {
                const decoded = getBrowserPhotoBytes(ph);
                if (!decoded) {
                  failures.push({ name: ph.name, reason: "decrypt-failed" });
                  continue;
                }
                const displayName = decoded.meta?.name || ph.name;
                const mime = decoded.meta?.mime || guessMime(displayName);
                if (isAnimatedForPng(ph, mime, decoded.bytes)) {
                  failures.push({ name: displayName, reason: "animated-unsupported" });
                  continue;
                }
                const pngBytes = await convertToPngBytes(decoded.bytes, mime);
                downloadBlob(pngBytes, sanitizeWithExtension(displayName, ".png"));
                successCount++;
                // 防止浏览器拦截多下载
                await new Promise(r => setTimeout(r, 500));
              } catch (e) {
                console.error(`[PNG 导出] ${ph.name} 转换失败:`, e);
                failures.push({ name: ph.name, reason: "convert-failed" });
              }
            }
            return { successCount, failCount: failures.length, failures };
          })();
        } else {
          outcome = await (async (): Promise<ExportOutcome> => {
            let successCount = 0;
            const failures: ExportFailure[] = [];
            for (let i = 0; i < selected.length; i++) {
              const ph = selected[i];
              exportStatus.value = "正在导出";
              exportCurrent.value = i + 1;
              exportTotal.value = selected.length;
              exportProgress.value = Math.round((i / selected.length) * 100);

              const specs = collectPhotoSpecs([ph], failures);
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
            return { successCount, failCount: failures.length, failures };
          })();
        }
      }

      // ===== 结果文案仅由 ExportOutcome 派生（不得使用选中数/总数） =====
      if (!outcome) {
        exporting.value = false;
        return;
      }
      exportProgress.value = 100;
      const { successCount, failCount, failures } = outcome;
      const animatedSkipped = failures.filter(f => f.reason === "animated-unsupported").length;
      const otherFailCount = failCount - animatedSkipped;
      if (failCount === 0) {
        exportStatus.value = `已导出 ${successCount} 张照片`;
        showExportDone("导出完成", "success");
      } else if (successCount === 0 && otherFailCount === 0) {
        exportStatus.value = "动图不支持 PNG 导出，请改用单文件或多文件导出保留动画";
        showExportDone("动图未导出（PNG 不支持动画）", "error");
      } else if (successCount === 0) {
        const reasonText = failures[0]
          ? {
              "data-missing": "照片数据缺失",
              "pack-failed": "容器打包失败",
              "decrypt-failed": "照片解密或完整性校验失败",
              "convert-failed": "图片转换失败",
              "write-failed": "写入失败",
              "animated-unsupported": "动图不支持 PNG 导出",
              "unknown": "未知错误",
            }[failures[0].reason]
          : "未知错误";
        exportStatus.value = `导出失败：${failCount} 张（${reasonText}）`;
        showExportDone(`导出失败（${failCount} 张）`, "error");
      } else if (otherFailCount === 0) {
        exportStatus.value = `已导出 ${successCount} 张，${animatedSkipped} 张动图已跳过`;
        showExportDone(`已导出 ${successCount} 张，${animatedSkipped} 张动图未导出`, "error");
      } else {
        const animatedNote = animatedSkipped > 0 ? `，含 ${animatedSkipped} 张动图跳过` : "";
        exportStatus.value = `已导出 ${successCount} 张，失败 ${failCount} 张${animatedNote}`;
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
    exportCurrent,
    exportTotal,
    tokenCopied,
    nativeExportAvailable,
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
  };
}
