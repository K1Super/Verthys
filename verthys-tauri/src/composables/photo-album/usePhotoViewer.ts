/**
 * photo-album/usePhotoViewer.ts — 拾光模块查看器层 composable
 *
 * 职责：管理内存预览（解密后 Blob URL，不落地）。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + 全局 Toast 中心的 showError（依赖注入）
 * - viewerBlobUrl 为非响应式 let，避免 Blob URL 字符串被 Vue 深度代理
 * - 浏览器模式直接复用 ph.blobUrl，无需解密
 * - Tauri 模式：meta 缺失时按需解密回填 photos（decryptPhotoMeta）
 * - 解密 chunks 优先内联 chunkDataB64（新格式），回退 chunkIds（旧格式）
 * - 逐块解密优先在 photo-crypto Worker 池执行（主线程不做派生与 AEAD），
 *   池基础设施不可用时回退主线程实现
 * - 原图直读：加载期间只呈现统一加载环，字节齐备后一次性显示原图；
 *   不使用缩略图或预览占位，失败时报错并关闭查看器
 * - 滚轮缩放范围 0.2x ~ 5x，以鼠标位置为中心
 * - 鼠标拖拽平移（mousedown/mousemove/mouseup），边界约束防止拖出视口
 * - 双击重置缩放和位置
 * - 拖拽时光标变化反馈（grab / grabbing）
 * - 窗口失焦/聚焦时 viewer 模糊控制（隐私保护）
 */
import { ref, type ShallowRef } from "vue";
import type { PhotoEntry } from "./types";
import { pushModal, popModal } from "../../utils/modal_stack";
import {
  photoFullBegin,
  photoFullNext,
  photoFullCancel,
} from "../../lib/verthys";
import { photoViewerCache, fullCacheKey } from "./photoBlobCache";

/**
 * usePhotoViewer 依赖注入接口。
 *
 * 接收 usePhotoData 的返回值对象 + 全局 Toast 中心的 showError，保持 Composable 单向数据流。
 */
export interface UsePhotoViewerOptions {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 恢复模块密钥（从 keyManager 会话缓存） */
  ensurePhotoKey: () => boolean;
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
}

export function usePhotoViewer(options: UsePhotoViewerOptions) {
  const { isTauri, ensurePhotoKey, showError } = options;

  /* ===== 内存预览（解密后 Blob URL，不落地） ===== */
  const viewer = ref<boolean>(false);
  const viewerSrc = ref<string>("");
  const viewerName = ref("");
  const viewerBlurred = ref(false);
  const viewerScale = ref(1);
  const viewerOffsetX = ref(0);
  const viewerOffsetY = ref(0);
  const viewerDragging = ref(false);
  /** 原图准备阶段反馈：读取密文块 / 解密中（UI 只呈现加载环，不配文字） */
  const viewerLoading = ref(false);
  let viewerBlobUrl: string | null = null;

  /* ===== 原生查看状态（原图直读） =====
   * viewerBlobUrl 仅跟踪旧 JS 链路自建的 URL；原生路径的 URL 归
   * photoViewerCache 所有，关闭查看器不得 revoke。 */
  let viewerFullJobId: string | null = null;
  /** 原图请求代际：取消/切换后递增，丢弃过期分块结果 */
  let viewerFullSeq = 0;

  /** 取消在途原图读取（关闭查看器/切换照片） */
  const cancelFullLoad = () => {
    viewerFullSeq++;
    if (viewerFullJobId) {
      const jobId = viewerFullJobId;
      viewerFullJobId = null;
      void photoFullCancel(jobId);
    }
  };

  /* ===== 模态层身份（与导出面板/确认窗共用栈：滚动锁计数 + Esc 栈序） ===== */
  const viewerModalId = Symbol("photo-viewer");
  let viewerModalEngaged = false;
  const engageViewerModal = () => {
    if (viewerModalEngaged) return;
    viewerModalEngaged = true;
    pushModal(viewerModalId);
  };
  const releaseViewerModal = () => {
    if (!viewerModalEngaged) return;
    viewerModalEngaged = false;
    popModal(viewerModalId);
  };

  /* 查看请求序号：解密期间网格仍可点击，快速连点会并发进入此流程；
   * 只有最新一次请求允许落地结果，避免"A 的图片 + B 的名称"错位与 Blob 泄漏。 */
  let viewRequestSeq = 0;

  /** 释放当前查看器 Blob URL（覆盖前与关闭时调用） */
  const disposeViewerBlob = () => {
    if (viewerBlobUrl) {
      URL.revokeObjectURL(viewerBlobUrl);
      viewerBlobUrl = null;
    }
  };

  /** 提交查看器内容：仅当请求序号仍为最新时生效 */
  const commitViewer = (seq: number, src: string): boolean => {
    if (seq !== viewRequestSeq) return false;
    viewerSrc.value = src;
    viewer.value = true;
    engageViewerModal();
    return true;
  };

  /** 提交缓存所有的 URL：关闭时不由查看器 revoke */
  const commitCachedViewer = (seq: number, url: string): boolean => {
    if (seq !== viewRequestSeq) return false;
    disposeViewerBlob();
    viewerBlobUrl = null;
    viewerLoading.value = false;
    viewerSrc.value = url;
    viewer.value = true;
    engageViewerModal();
    return true;
  };

  /**
   * 读取原图并直接呈现：分块拉取 → Blob → LRU 缓存。
   *
   * 查看器不再用缩略图/预览占位：加载期间 UI 只呈现统一加载环，原图字节
   * 齐备后一次性显示，避免“先放大缩略图再换图”的跳变。
   *
   * @returns true=原图已提交显示；false=失败/被新请求取代（调用方按序判断）
   */
  const loadFullNative = async (ph: PhotoEntry, seq: number): Promise<boolean> => {
    if (!ph.metaId) return false;
    const key = fullCacheKey(ph.metaId);
    const cached = photoViewerCache.get(key);
    if (cached) {
      return commitCachedViewer(seq, cached);
    }

    const loadSeq = ++viewerFullSeq;
    viewerLoading.value = true;
    /* jobId 必须是本次调用的局部值：共享变量会被后发请求覆盖，
     * 旧请求的 catch/finally 误取消新任务并清掉新任务的加载态。 */
    let jobId: string | null = null;
    try {
      const begin = await photoFullBegin(ph.metaId);
      if (!begin.jobId) throw new Error("原图读取任务创建失败");
      jobId = begin.jobId;
      viewerFullJobId = jobId;

      const chunkTotal = begin.chunkTotal;
      if (!Number.isSafeInteger(chunkTotal) || chunkTotal <= 0) {
        throw new Error("原图分块数量非法");
      }
      const parts: Uint8Array[] = [];
      let total = 0;
      for (let i = 0; i < chunkTotal; i++) {
        const data = await photoFullNext(jobId);
        if (loadSeq !== viewerFullSeq || seq !== viewRequestSeq) return false;
        /* 二进制 IPC 直接给到原始字节：零 base64、零解码、零重编码 */
        parts.push(data);
        total += data.length;
      }
      if (viewerFullJobId === jobId) viewerFullJobId = null;
      if (loadSeq !== viewerFullSeq || seq !== viewRequestSeq) return false;
      if (total !== begin.size) throw new Error("原图字节数与元数据不一致");

      const url = URL.createObjectURL(
        new Blob(parts as BlobPart[], {
          type: begin.mime || "application/octet-stream",
        }),
      );
      photoViewerCache.put(key, url, total);
      if (loadSeq !== viewerFullSeq || seq !== viewRequestSeq) {
        photoViewerCache.delete(key);
        return false;
      }
      viewerBlobUrl = null;
      viewerSrc.value = url;
      return true;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (!msg.includes("E_PHOTO_READ_CANCELLED")) {
        console.warn(`[onView] 原图读取失败: ${msg}`);
      }
      if (jobId && viewerFullJobId === jobId) {
        viewerFullJobId = null;
        void photoFullCancel(jobId);
      }
      return false;
    } finally {
      // 只有当前代次的请求才能清加载态；旧请求不得覆盖新请求
      if (loadSeq === viewerFullSeq) viewerLoading.value = false;
    }
  };

  /* ===== 拖拽平移状态（非响应式闭包变量） ===== */
  let dragStartX = 0;
  let dragStartY = 0;
  let dragStartOffsetX = 0;
  let dragStartOffsetY = 0;
  let dragImgEl: HTMLImageElement | null = null;

  const onView = async (ph: PhotoEntry) => {
    const seq = ++viewRequestSeq;
    viewerName.value = ph.name;
    viewerBlurred.value = false;
    viewerScale.value = 1;
    viewerOffsetX.value = 0;
    viewerOffsetY.value = 0;
    viewerDragging.value = false;

    // 浏览器模式：直接用缓存的 Blob URL（无解密链路，点击即出图）
    if (!isTauri && ph.blobUrl) {
      viewerSrc.value = "";
      viewerLoading.value = false;
      commitViewer(seq, ph.blobUrl);
      return;
    }

    // 无模块密钥 → 同步可判定，直接报错、不打开查看器（避免「开图再关闭」闪动）
    if (!ensurePhotoKey()) {
      showError("模块密钥不可用，请重新登录拾光模块");
      return;
    }

    /* 原生查看：原图直读。桌面端不再保留 JS 解密回退：瘦身布局与既有
     * 布局都由 worker 原生读取；原图未就绪时查看器只呈现统一加载环。 */
    if (!isTauri) {
      showError("照片数据不可用，请重新导入");
      return;
    }
    if (!ph.metaId) {
      showError("照片元数据缺失，无法预览原图");
      return;
    }

    cancelFullLoad();
    viewerSrc.value = "";
    viewerLoading.value = true;
    viewer.value = true;
    engageViewerModal();

    const ok = await loadFullNative(ph, seq);
    if (seq !== viewRequestSeq) return;   // 用户已关闭或切换，不覆盖新状态
    if (!ok) {
      showError("照片数据无法读取，可能密钥已变更或记录损坏");
      closeViewer();
    }
  };

  const closeViewer = () => {
    viewRequestSeq++;   // 作废在途请求，防止关闭后又被旧结果重新打开
    cancelFullLoad();
    disposeViewerBlob();
    viewerLoading.value = false;
    viewer.value = false;
    viewerSrc.value = "";
    viewerScale.value = 1;
    viewerOffsetX.value = 0;
    viewerOffsetY.value = 0;
    viewerDragging.value = false;
    window.removeEventListener("mousemove", onWindowMouseMove);
    window.removeEventListener("mouseup", onWindowMouseUp);
    releaseViewerModal();
    // 关闭 viewer 不触碰防截屏保护：保护是应用级能力，
    // 由应用级会话单例与拾光按钮显式控制，不随查看器开闭变化
  };

  /* ===== 边界约束：防止图片拖出视口 =====
   * 布局中心（transform-origin: center 时的元素中心）不随 transform 变化，
   * 由当前图像中心减去当前偏移求得。约束逻辑：
   * - 图像缩放后大于视口：限制偏移使图像边缘对齐视口边缘（可平移浏览）
   * - 图像缩放后小于视口：偏移归零（居中显示，无平移空间） */
  const clampOffset = (img: HTMLImageElement, ox: number, oy: number, scale: number) => {
    const imgRect = img.getBoundingClientRect();
    if (imgRect.width === 0 || imgRect.height === 0) return { x: 0, y: 0 };

    const layoutCenterX = imgRect.left + imgRect.width / 2 - viewerOffsetX.value;
    const layoutCenterY = imgRect.top + imgRect.height / 2 - viewerOffsetY.value;

    const baseW = imgRect.width / viewerScale.value;
    const baseH = imgRect.height / viewerScale.value;
    const scaledW = baseW * scale;
    const scaledH = baseH * scale;

    const viewportW = window.innerWidth;
    const viewportH = window.innerHeight;

    let clampedX: number, clampedY: number;
    if (scaledW > viewportW) {
      const maxX = scaledW / 2 - layoutCenterX;
      const minX = viewportW - layoutCenterX - scaledW / 2;
      clampedX = Math.min(maxX, Math.max(minX, ox));
    } else {
      clampedX = 0;
    }
    if (scaledH > viewportH) {
      const maxY = scaledH / 2 - layoutCenterY;
      const minY = viewportH - layoutCenterY - scaledH / 2;
      clampedY = Math.min(maxY, Math.max(minY, oy));
    } else {
      clampedY = 0;
    }
    return { x: clampedX, y: clampedY };
  };

  /* ===== 滚轮缩放：以鼠标位置为中心，范围 0.2x ~ 5x，带边界约束 =====
   * 数学推导（transform: translate(offset) scale(s)，origin: center）：
   *   图像上某点 p 的屏幕位置 = layoutCenter + offset + s * p_local
   *   缩放前鼠标下方的图像点：p_local = (mouse - layoutCenter - offset_old) / s_old
   *   缩放后保持该点在鼠标下方：offset_new = (mouse - layoutCenter) - ratio * (mouse - layoutCenter - offset_old)
   *   其中 ratio = s_new / s_old */
  const onViewerWheel = (e: WheelEvent) => {
    const content = e.currentTarget as HTMLElement;
    const img = content.querySelector(".viewer-image") as HTMLImageElement | null;

    const oldScale = viewerScale.value;
    const delta = e.deltaY < 0 ? 0.15 : -0.15;
    const newScale = Math.min(5, Math.max(0.2, +(oldScale + delta).toFixed(2)));
    if (newScale === oldScale) return;

    if (img) {
      const imgRect = img.getBoundingClientRect();
      const layoutCenterX = imgRect.left + imgRect.width / 2 - viewerOffsetX.value;
      const layoutCenterY = imgRect.top + imgRect.height / 2 - viewerOffsetY.value;
      const mRelX = e.clientX - layoutCenterX;
      const mRelY = e.clientY - layoutCenterY;
      const ratio = newScale / oldScale;
      const newOffsetX = mRelX - ratio * (mRelX - viewerOffsetX.value);
      const newOffsetY = mRelY - ratio * (mRelY - viewerOffsetY.value);

      const clamped = clampOffset(img, newOffsetX, newOffsetY, newScale);
      viewerOffsetX.value = clamped.x;
      viewerOffsetY.value = clamped.y;
    } else {
      viewerOffsetX.value = 0;
      viewerOffsetY.value = 0;
    }

    viewerScale.value = newScale;
  };

  /* ===== 鼠标拖拽平移（mousedown 在图像上，mousemove/mouseup 委托 window） ===== */
  const onWindowMouseMove = (e: MouseEvent) => {
    if (!viewerDragging.value || !dragImgEl) return;
    const dx = e.clientX - dragStartX;
    const dy = e.clientY - dragStartY;
    const newOffsetX = dragStartOffsetX + dx;
    const newOffsetY = dragStartOffsetY + dy;
    const clamped = clampOffset(dragImgEl, newOffsetX, newOffsetY, viewerScale.value);
    viewerOffsetX.value = clamped.x;
    viewerOffsetY.value = clamped.y;
  };

  const onWindowMouseUp = () => {
    if (!viewerDragging.value) return;
    viewerDragging.value = false;
    window.removeEventListener("mousemove", onWindowMouseMove);
    window.removeEventListener("mouseup", onWindowMouseUp);
  };

  const onViewerMouseDown = (e: MouseEvent) => {
    if (e.button !== 0) return;
    dragStartX = e.clientX;
    dragStartY = e.clientY;
    dragStartOffsetX = viewerOffsetX.value;
    dragStartOffsetY = viewerOffsetY.value;
    dragImgEl = e.currentTarget as HTMLImageElement;
    viewerDragging.value = true;
    e.preventDefault();
    window.addEventListener("mousemove", onWindowMouseMove);
    window.addEventListener("mouseup", onWindowMouseUp);
  };

  /* ===== 双击重置缩放和位置 ===== */
  const onViewerDoubleClick = () => {
    viewerScale.value = 1;
    viewerOffsetX.value = 0;
    viewerOffsetY.value = 0;
  };

  /* ===== 窗口失焦/聚焦时 viewer 模糊控制（隐私保护） ===== */
  const onBlur = () => { if (viewer.value) viewerBlurred.value = true; };
  const onFocus = () => { if (viewer.value) viewerBlurred.value = false; };

  /**
   * 组件卸载时清理：释放查看器 Blob URL（防止内存泄漏）
   *
   * 入口文件 onUnmounted 调用，将资源清理收敛至查看器层（单一职责）。
   *   viewerBlobUrl 为非响应式 let（闭包变量），通过 cleanup 方法访问最新值。
   */
  const cleanup = () => {
    viewRequestSeq++;   // 作废在途请求，防止卸载后旧结果落地
    cancelFullLoad();
    disposeViewerBlob();
    viewerLoading.value = false;
    releaseViewerModal();
    window.removeEventListener("mousemove", onWindowMouseMove);
    window.removeEventListener("mouseup", onWindowMouseUp);
  };

  return {
    // ===== 查看器状态 =====
    viewer,
    viewerSrc,
    viewerName,
    viewerBlurred,
    viewerScale,
    viewerOffsetX,
    viewerOffsetY,
    viewerDragging,
    /** 原图准备阶段反馈（true 时 UI 只展示统一加载环） */
    viewerLoading,
    // ===== 查看器方法 =====
    onView,
    closeViewer,
    onViewerWheel,
    onViewerMouseDown,
    onViewerDoubleClick,
    onBlur,
    onFocus,
    // ===== 生命周期清理 =====
    cleanup,
  };
}
