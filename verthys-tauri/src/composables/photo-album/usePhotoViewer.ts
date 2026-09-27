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
 * - 逐块解密优先在 photo-crypto Worker 池执行（主线程不做派生与 AEAD），
 *   池基础设施不可用时回退主线程实现
 * - 合并字节 → Blob → viewerBlobUrl，失败时显示缩略图 + 错误提示
 * - 滚轮缩放范围 0.2x ~ 5x，以鼠标位置为中心
 * - 鼠标拖拽平移（mousedown/mousemove/mouseup），边界约束防止拖出视口
 * - 双击重置缩放和位置
 * - 拖拽时光标变化反馈（grab / grabbing）
 * - 窗口失焦/聚焦时 viewer 模糊控制（隐私保护）
 */
import { ref, type Ref, type ShallowRef } from "vue";
import { computeChunkHashesForB64 } from "../../lib/crypto";
import { decryptChunksPreferWorker } from "../../workers/photo-decrypt-bridge";
import { isSlimLayout } from "../../constants/crypto_const";
import { updateShallowItem } from "../../utils/shallow-array";
import type { PhotoEntry, DecryptedPhotoMeta } from "./types";
import { toArrayBuffer, thumbUrlOf } from "./utils";
import { resolveChunkRefs, loadChunkCiphers, type ChunkRefs } from "./chunk-refs";

/** 逐块密文哈希比对（hex 串，大小写不敏感） */
function hashesEqual(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].toLowerCase() !== b[i].toLowerCase()) return false;
  }
  return true;
}

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
  /** 原图准备阶段反馈：读取密文块 / 解密中（真实阶段，非动画占位） */
  const viewerLoading = ref(false);
  const viewerProgressMsg = ref("");
  let viewerBlobUrl: string | null = null;

  /** 更新原图准备阶段反馈（文案为空即视为阶段结束） */
  const setViewerProgress = (message: string) => {
    viewerProgressMsg.value = message;
    viewerLoading.value = message !== "";
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
    return true;
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
    viewerSrc.value = "";
    viewerScale.value = 1;
    viewerOffsetX.value = 0;
    viewerOffsetY.value = 0;
    viewerDragging.value = false;
    setViewerProgress("");

    // 浏览器模式：直接用缓存的 Blob URL
    if (!isTauri && ph.blobUrl) {
      commitViewer(seq, ph.blobUrl);
      return;
    }

    // 无模块密钥 → 显示错误（在 meta 检查之前，因为按需解密需要密钥）
    if (!ensurePhotoKey()) {
      showError("模块密钥不可用，请重新登录拾光模块");
      commitViewer(seq, "");
      return;
    }

    // meta 缺失时按需解密回退
    //    场景：摘要首屏与重启后的占位项（loaded=false、meta 未解密），
    //    若用户在可视区按需解密完成前点击照片，ph.meta 为 undefined。
    //    此处直接调用 decryptPhotoMeta 按需解密，成功后回填列表（后续点击直接命中）。
    let meta = ph.meta;
    if (!meta) {
      if (!ph.metaId) {
        // 无 metaId（演示数据等）→ 显示缩略图 + 警告
        showError("照片元数据缺失，无法预览原图");
        commitViewer(seq, thumbUrlOf(ph.thumb));
        return;
      }
      setViewerProgress("读取照片元数据…");
      const data = await decryptPhotoMeta(ph.metaId);
      if (seq !== viewRequestSeq) return;   // 已被更新的点击取代，丢弃过期结果
      setViewerProgress("");
      if (!data) {
        showError("照片元数据解密失败，可能密钥已变更或数据损坏");
        commitViewer(seq, thumbUrlOf(ph.thumb));
        return;
      }
      // 回填到 photos 数组（后续点击直接命中，无需重复解密）
      const pidx = photos.value.findIndex(p => p.metaId === ph.metaId);
      if (pidx >= 0) {
        updateShallowItem(photos, pidx, { ...data, loaded: true, failed: false });
      }
      meta = data.meta;
    }

    try {
      // 逐块引用布局分流：瘦身布局取块集记录，既有布局取索引内联引用
      //   （口径统一收敛在 chunk-refs，查看器/导出/删除共用）
      let refs: ChunkRefs;
      try {
        refs = await resolveChunkRefs(meta, photoKey.value, ph.name);
      } catch (e) {
        console.error(`[onView] 块集解析失败: ${e instanceof Error ? e.message : String(e)}`);
        showError("照片索引数据不完整，无法读取原图");
        commitViewer(seq, thumbUrlOf(ph.thumb));
        return;
      }
      if (seq !== viewRequestSeq) return;

      const { ciphers: cipherB64, missing: notFound } = await loadChunkCiphers(refs);
      const expected = refs.inlineCipher.length > 0 ? refs.inlineCipher.length : refs.ids.length;
      if (seq !== viewRequestSeq) return;

      if (expected === 0) {
        showError("未找到照片数据");
        commitViewer(seq, thumbUrlOf(ph.thumb));
        return;
      }

      // 渲染前完整性校验：块数必须等于元数据声明，逐块密文哈希必须与权威值一致。
      //   残缺数据直接拼接会渲染出半张图/花屏，用户会误判为照片本身损坏；
      //   校验用的是密文哈希，无需先解密即可发现缺失与篡改。
      const hashMismatch = refs.hashes.length === cipherB64.length
        && !hashesEqual(computeChunkHashesForB64(cipherB64), refs.hashes);
      if (cipherB64.length !== expected || hashMismatch) {
        const detail = notFound > 0
          ? `缺失 ${notFound} 块`
          : hashMismatch ? "逐块哈希校验未通过" : "块数不一致";
        console.error(`[onView] 照片数据不完整：${detail}`);
        showError("此照片数据已损坏，请删除后重新导入");
        commitViewer(seq, thumbUrlOf(ph.thumb));
        return;
      }

      // 逐块解密：优先在 photo-crypto Worker 池执行（主线程不做派生与 AEAD），
      //   池基础设施不可用时由桥回退主线程实现；任一块失败即整体失败，
      //   与旧实现"逐块尝试后统计失败"的可见行为一致（都拒绝渲染残缺图）。
      //   解密在 Worker 内一次任务完成（同文件复用同一子密钥），
      //   阶段反馈按"整批解密"如实呈现，不做无法对应的逐块假进度。
      //   索引瘦身布局：先解封包裹态文件密钥，再按 nonce|密文 布局逐块解密。
      let plaintexts: Uint8Array[];
      try {
        setViewerProgress(`解密中（${cipherB64.length} 块）`);
        const slim = isSlimLayout(meta) && meta.wrappedFileKey
          ? { wrappedFileKey: meta.wrappedFileKey, chunkTotal: cipherB64.length }
          : undefined;
        plaintexts = await decryptChunksPreferWorker(
          cipherB64, photoKey.value, meta.fileHash, ph.name, slim,
        );
        setViewerProgress("");
      } catch (e) {
        console.error(`[onView] 照片数据解密失败: ${e instanceof Error ? e.message : String(e)}`);
        if (seq !== viewRequestSeq) return;
        setViewerProgress("");
        showError("照片数据无法读取，可能密钥已变更");
        commitViewer(seq, thumbUrlOf(ph.thumb));
        return;
      }
      if (seq !== viewRequestSeq) return;

      const totalLen = plaintexts.reduce((s, c) => s + c.length, 0);
      const fullBytes = new Uint8Array(totalLen);
      let offset = 0;
      for (const c of plaintexts) { fullBytes.set(c, offset); offset += c.length; }

      const blob = new Blob([toArrayBuffer(fullBytes)], { type: meta.mime });
      const url = URL.createObjectURL(blob);
      fullBytes.fill(0);
      if (seq !== viewRequestSeq) {
        URL.revokeObjectURL(url);   // 过期请求：本次产出的 Blob 立即释放
        return;
      }
      disposeViewerBlob();          // 覆盖前释放上一次的 Blob URL
      viewerBlobUrl = url;
      commitViewer(seq, url);

      // 隐私模式已启用时无需重复调用（避免生成新令牌覆盖旧令牌）
      // 防截屏保护在隐私模式启用时已覆盖所有窗口，viewer 覆盖层不影响其生效
    } catch (e) {
      console.error("预览失败:", e);
      setViewerProgress("");
      showError("预览失败，请重试");
      commitViewer(seq, thumbUrlOf(ph.thumb));
    }
  };

  const closeViewer = () => {
    viewRequestSeq++;   // 作废在途请求，防止关闭后又被旧结果重新打开
    disposeViewerBlob();
    setViewerProgress("");
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
   * 入口文件 onUnmounted 调用，将资源清理收敛至查看器层（单一职责）。
   *   viewerBlobUrl 为非响应式 let（闭包变量），通过 cleanup 方法访问最新值。
   */
  const cleanup = () => {
    viewRequestSeq++;   // 作废在途请求，防止卸载后旧结果落地
    disposeViewerBlob();
    setViewerProgress("");
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
    /** 原图准备阶段反馈（true 时 UI 展示 viewerProgressMsg） */
    viewerLoading,
    viewerProgressMsg,
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
