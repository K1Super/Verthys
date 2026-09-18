/**
 * photo-album/usePhotoToast.ts — 拾光模块 Toast 反馈中心
 *
 * 职责：统一管理模块内所有用户可见的瞬时提示（错误/成功/导出完成）。
 *
 * 设计动机（企业级根治 Toast 分裂问题）：
 *   旧实现中 usePhotoImport / usePhotoExport / usePhotoViewer / usePhotoParse / usePhotoDelete
 *   各自独立调用 useErrorToast()，由于 useErrorToast 非单例，每次调用创建独立的 errorMsg ref。
 *   结果：composable A 调用 showError 仅更新 A 的 errorMsg，但模板渲染的是 PhotoAlbum.vue
 *   自己 useErrorToast() 创建的另一份 errorMsg → 错误提示丢失，用户无感知。
 *
 *   修复：本 composable 作为模块级 Toast 反馈中心，创建唯一的 errorMsg / toastMsg / exportDoneToast
 *   实例，由 PhotoAlbum.vue 装配后通过依赖注入分发给各业务 composable。
 *   所有 showError / showToast / showExportDone 调用都更新同一份 ref，模板渲染一致。
 *
 * 提示层级（与项目硬约束对齐）：
 *   - errorMsg：顶部红色 .error-toast，2.5s 自动消失（错误类提示）
 *   - toastMsg：底部 .clip-toast，2s 自动消失（成功类提示）
 *   - exportDoneToast：顶部 .clip-toast--top，2.6s 自动消失（导出完成专用）
 *   - copiedToast：底部 .clip-toast，1.5s 自动消失（复制成功专用）
 */
import { ref, onBeforeUnmount } from "vue";
import type { ExportDoneToast } from "./types";

/** 错误提示显示时长（毫秒）— 与全局 useErrorToast 保持一致 */
const ERROR_DURATION = 2500;
/** 成功提示显示时长（毫秒） */
const TOAST_DURATION = 2000;
/** 导出完成提示显示时长（毫秒） */
const EXPORT_DONE_DURATION = 2600;
/** 复制成功提示显示时长（毫秒） */
const COPIED_DURATION = 1500;

export function usePhotoToast() {
  /* ===== 顶部错误提示（.error-toast，红色主题） ===== */
  const errorMsg = ref("");
  let errorTimer: ReturnType<typeof setTimeout> | null = null;

  const showError = (msg: string) => {
    errorMsg.value = msg;
    if (errorTimer) clearTimeout(errorTimer);
    errorTimer = setTimeout(() => { errorMsg.value = ""; }, ERROR_DURATION);
  };

  /* ===== 底部成功提示（.clip-toast） ===== */
  const toastMsg = ref("");
  let toastTimer: ReturnType<typeof setTimeout> | null = null;

  const showToast = (msg: string) => {
    toastMsg.value = msg;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toastMsg.value = ""; }, TOAST_DURATION);
  };

  /* ===== 导出完成状态提示（顶部 .clip-toast--top） ===== */
  const exportDoneToast = ref<ExportDoneToast | null>(null);
  let exportDoneTimer: ReturnType<typeof setTimeout> | null = null;

  const showExportDone = (msg: string, type: "success" | "error") => {
    exportDoneToast.value = { msg, type };
    if (exportDoneTimer) clearTimeout(exportDoneTimer);
    exportDoneTimer = setTimeout(() => { exportDoneToast.value = null; }, EXPORT_DONE_DURATION);
  };

  /* ===== 复制成功提示（.clip-toast，短暂） ===== */
  const copiedToast = ref(false);
  let copiedTimer: ReturnType<typeof setTimeout> | null = null;

  const showCopied = () => {
    copiedToast.value = true;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => { copiedToast.value = false; }, COPIED_DURATION);
  };

  /* ===== 组件卸载时清理所有定时器，防止内存泄漏 ===== */
  onBeforeUnmount(() => {
    if (errorTimer) { clearTimeout(errorTimer); errorTimer = null; }
    if (toastTimer) { clearTimeout(toastTimer); toastTimer = null; }
    if (exportDoneTimer) { clearTimeout(exportDoneTimer); exportDoneTimer = null; }
    if (copiedTimer) { clearTimeout(copiedTimer); copiedTimer = null; }
  });

  return {
    // ===== 状态 =====
    errorMsg,
    toastMsg,
    exportDoneToast,
    copiedToast,
    // ===== 方法 =====
    showError,
    showToast,
    showExportDone,
    showCopied,
  };
}

/** usePhotoToast 返回值类型（供其他 composable 依赖注入类型推断使用） */
export type UsePhotoToastReturn = ReturnType<typeof usePhotoToast>;
