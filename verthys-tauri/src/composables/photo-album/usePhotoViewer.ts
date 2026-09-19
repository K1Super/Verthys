/**
 * photo-album/usePhotoViewer.ts — 拾光模块查看器层 composable
 *
 * 职责：管理内存预览（解密后 Blob URL，不落地）。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值 + usePhotoToast 的 showError（依赖注入）
 * - viewerBlobUrl 为非响应式 let，避免 Blob URL 字符串被 Vue 深度代理
 * - 浏览器模式直接复用 ph.blobUrl，无需解密
 * - Tauri 模式：meta 缺失时按需解密回填 photos（decryptPhotoMeta）
 * - 解密 chunks 优先内联 chunkDataB64（新格式），回退 chunkIds（旧格式）
 * - 合并字节 → Blob → viewerBlobUrl，失败时显示缩略图 + 错误提示
 * - 滚轮缩放范围 0.2x ~ 5x，以鼠标位置为中心
 * - 鼠标拖拽平移（mousedown/mousemove/mouseup），边界约束防止拖出视口
 * - 双击重置缩放和位置
 * - 拖拽时光标变化反馈（grab / grabbing）
 * - 窗口失焦/聚焦时 viewer 模糊控制（隐私保护）
 */
import { ref, type Ref, type ShallowRef } from "vue";
import { verthysGetRecord } from "../../lib/verthys";
import { decryptMeta, decryptChunk } from "../../lib/crypto";
import { updateShallowItem } from "../../utils/shallow-array";
import type { PhotoEntry, DecryptedPhotoMeta } from "./types";
import { toArrayBuffer } from "./utils";

/**
 * usePhotoViewer 依赖注入接口。
 *
 * 接收 usePhotoData 的返回值对象 + usePhotoToast 的 showError，保持 Composable 单向数据流。
 */
export interface UsePhotoViewerOptions {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 模块独立密钥（按需解密使用） */
  photoKey: Ref<string>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 恢复模块密钥（从 keyManager 会话缓存） */
  ensurePhotoKey: () => boolean;
  /** 解密单张照片完整元数据（来自 usePhotoData） */
  decryptPhotoMeta: (vid: number, prefetchedMetaB64?: string) => Promise<DecryptedPhotoMeta | null>;
  /** 显示错误提示（来自 usePhotoToast，统一 Toast 中心） */
  showError: (msg: string) => void;
}

export function usePhotoViewer(options: UsePhotoViewerOptions) {
  const { photos, photoKey, isTauri, ensurePhotoKey, decryptPhotoMeta, showError } = options;

  /* ===== 内存预览（解密后 Blob URL，不落地） ===== */
  const viewer = ref<boolean>(false);
  const viewerSrc = ref<string>("");
  const viewerName = ref("");
  const viewerBlurred = ref(false);
  const viewerScale = ref(1);
  const viewerOffsetX = ref(0);
  const viewerOffsetY = ref(0);
  const viewerDragging = ref(false);
  let viewerBlobUrl: string | null = null;

  /* ===== 拖拽平移状态（非响应式闭包变量） ===== */
  let dragStartX = 0;
  let dragStartY = 0;
  let dragStartOffsetX = 0;
  let dragStartOffsetY = 0;
  let dragImgEl: HTMLImageElement | null = null;

  const onView = async (ph: PhotoEntry) => {
    viewerName.value = ph.name;
    viewerBlurred.value = false;
    viewerSrc.value = "";
    viewerScale.value = 1;
    viewerOffsetX.value = 0;
    viewerOffsetY.value = 0;
    viewerDragging.value = false;

    // 浏览器模式：直接用缓存的 Blob URL
    if (!isTauri && ph.blobUrl) {
      viewerSrc.value = ph.blobUrl;
      viewer.value = true;
      return;
    }

    // 无模块密钥 → 显示错误（在 meta 检查之前，因为按需解密需要密钥）
    if (!ensurePhotoKey()) {
      showError("模块密钥不可用，请重新登录拾光模块");
      viewer.value = true;
      return;
    }

    // ★ 企业级根治：meta 缺失时按需解密回退
    //    场景：重启后 loadPhotos 创建占位项（loaded=false, meta=undefined），
    //    若用户在 watch(visiblePhotos)→ensureVisiblePhotosDecrypted 完成前点击照片，
    //    ph.meta 为 undefined。此处直接调用 decryptPhotoMeta 按需解密，
    //    解密成功后回填到 photos 数组（后续点击直接命中），解密失败才报错。
    let meta = ph.meta;
    if (!meta) {
      if (!ph.metaId) {
        // 无 metaId（演示数据等）→ 显示缩略图 + 警告
        showError("照片元数据缺失，无法预览原图");
        viewerSrc.value = ph.thumb.replace(/^url\((.*)\)$/, "$1").replace(/^['"]|['"]$/g, "");
        viewer.value = true;
        return;
      }
      // 按需解密：直接调用 decryptPhotoMeta 获取完整元数据
      const data = await decryptPhotoMeta(ph.metaId);
      if (!data) {
        showError("照片元数据解密失败，可能密钥已变更或数据损坏");
        viewerSrc.value = ph.thumb.replace(/^url\((.*)\)$/, "$1").replace(/^['"]|['"]$/g, "");
        viewer.value = true;
        return;
      }
      // 回填到 photos 数组（后续点击直接命中，无需重复解密）
      const pidx = photos.value.findIndex(p => p.metaId === ph.metaId);
      if (pidx >= 0) {
        updateShallowItem(photos, pidx, { ...data, loaded: true });
      }
      meta = data.meta;
    }

    try {
      const chunks: Uint8Array[] = [];
      let missingChunks = 0;
      let notFoundChunks = 0;  // verthys 记录丢失（旧格式 ID 漂移）
      let formatType: "new" | "old" | "none" = "none";

      // 优先使用内联 chunkDataB64（新格式，避免 ID 漂移）
      if (meta.chunkDataB64 && meta.chunkDataB64.length > 0) {
        formatType = "new";
        console.log(`[onView] 使用新格式（内联 chunkDataB64），共 ${meta.chunkDataB64.length} 块`);
        for (let c = 0; c < meta.chunkDataB64.length; c++) {
          try {
            const { plaintext } = await decryptChunk(
              meta.chunkDataB64[c], photoKey.value, meta.fileHash
            );
            chunks.push(plaintext);
          } catch (e) {
            console.error(`[onView] 内联 chunk ${c} 解密失败:`, e);
            missingChunks++;
          }
        }
      } else if (meta.chunkIds && meta.chunkIds.length > 0) {
        formatType = "old";
        console.log(`[onView] 使用旧格式（chunkIds），共 ${meta.chunkIds.length} 块, IDs:`, meta.chunkIds);
        // 旧格式：通过 verthys 记录 ID 查找 chunk
        for (const chunkId of meta.chunkIds) {
          const r = await verthysGetRecord(chunkId);
          if (!r) {
            console.warn(`[onView] chunk 记录 ID=${chunkId} 不存在（ID 漂移）`);
            notFoundChunks++;
            missingChunks++;
            continue;
          }
          try {
            const { plaintext } = await decryptChunk(r.dataB64, photoKey.value, meta.fileHash);
            chunks.push(plaintext);
          } catch (e) {
            console.error(`[onView] chunk ${chunkId} 解密失败:`, e);
            missingChunks++;
          }
        }
      }

      if (chunks.length === 0) {
        if (formatType === "old" && notFoundChunks > 0) {
          console.error(`[onView] 旧格式数据块丢失: notFoundChunks=${notFoundChunks}`);
          showError("此照片数据已损坏，请删除后重新导入");
        } else if (missingChunks > 0) {
          console.error(`[onView] 解密失败: missingChunks=${missingChunks}`);
          showError("照片数据无法读取，可能密钥已变更");
        } else {
          showError("未找到照片数据");
        }
        viewer.value = true;
        return;
      }

      const totalLen = chunks.reduce((s, c) => s + c.length, 0);
      const fullBytes = new Uint8Array(totalLen);
      let offset = 0;
      for (const c of chunks) { fullBytes.set(c, offset); offset += c.length; }

      const blob = new Blob([toArrayBuffer(fullBytes)], { type: meta.mime });
      viewerBlobUrl = URL.createObjectURL(blob);
      viewerSrc.value = viewerBlobUrl;
      viewer.value = true;

      fullBytes.fill(0);

      // 隐私模式已启用时无需重复调用（避免生成新令牌覆盖旧令牌）
      // 防截屏保护在隐私模式启用时已覆盖所有窗口，viewer 覆盖层不影响其生效
    } catch (e) {
      console.error("预览失败:", e);
      showError("预览失败，请重试");
      viewer.value = true;
    }
  };

  const closeViewer = () => {
    if (viewerBlobUrl) {
      URL.revokeObjectURL(viewerBlobUrl);
      viewerBlobUrl = null;
    }
    viewer.value = false;
    viewerSrc.value = "";
    viewerScale.value = 1;
    viewerOffsetX.value = 0;
    viewerOffsetY.value = 0;
    viewerDragging.value = false;
    window.removeEventListener("mousemove", onWindowMouseMove);
    window.removeEventListener("mouseup", onWindowMouseUp);
    // 关闭 viewer 时不再自动关闭隐私模式
    // 隐私模式由用户通过 togglePrivacy 按钮显式控制，viewer 关闭不应影响其状态
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
   * ★ 入口文件 onUnmounted 调用，将资源清理收敛至查看器层（单一职责）。
   *   viewerBlobUrl 为非响应式 let（闭包变量），通过 cleanup 方法访问最新值。
   */
  const cleanup = () => {
    if (viewerBlobUrl) {
      URL.revokeObjectURL(viewerBlobUrl);
      viewerBlobUrl = null;
    }
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
