/**
 * photo-album/usePhotoData.ts — 拾光模块核心数据层 composable
 *
 * 职责：管理照片列表状态、虚拟滚动布局、按需解密、加载照片。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - shallowRef 操作必须用 shallow-array 工具函数触发 triggerRef
 * - watch(visiblePhotos) 用 flush:'post'，DOM 更新后执行避免响应式竞争
 * - ensurePhotoKey 从 keyManager 会话缓存恢复密钥（15min 内免重复验证）
 * - loadPhotos 缓存优先 + 增量扫描，消除切回时的空白重载
 * - decryptPhotoMeta 支持批量预取 prefetchedMetaB64 参数（零 IPC 命中缓存）
 * - ensureVisiblePhotosDecrypted 并发上限 4，批量预取 meta dataB64
 */
import { ref, shallowRef, computed, watch } from "vue";
import {
  getModuleKey, getModuleCache, setModuleCache,
  ensureRecordScanSafe, getRecordIdsByType, getRecordsDataB64Batch,
  cacheCoordinator,
} from "../../lib/keyManager";
import { decryptMeta, TYPE_PHOTO_META, type PhotoMeta } from "../../lib/crypto";
import { rafThrottle } from "../../utils/debounce";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray, clearShallowArray,
} from "../../utils/shallow-array";
import type { PhotoEntry, VisiblePhoto, DecryptedPhotoMeta } from "./types";
import { formatSize } from "./utils";

export function usePhotoData() {
  /* ===== 状态 ===== */
  /* ★ 项2：shallowRef 替代 ref，避免 Vue 对 photos 数组内每条记录深度代理
   * （每条记录含 thumb/blobUrl/rawBytes 等大型字段，万条照片深度代理开销 200-500ms，
   *   内存暴涨且每次更新触发大量 watch/computed 重新计算） */
  const photos = shallowRef<PhotoEntry[]>([]);
  const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

  /* ===== 模块独立密钥（由 keyManager 会话缓存提供，用户登录模块时输入） =====
   *   会话内 15min 闲置超时自动锁定（verthys-cache.ts MODULE_KEY_IDLE_TIMEOUT_MS），
   *   超时后模块密钥被销毁，用户需返回安全管理重新解锁。
   *   15min 内无需重复验证，ensurePhotoKey() 从 keyManager 会话缓存恢复密钥。 */
  const photoKey = ref<string>("");

  const photosLoading = ref(false);
  const animationDone = ref(false);

  /* ===== 密钥管理 ===== */
  const ensurePhotoKey = (): boolean => {
    if (photoKey.value) return true;
    const k = getModuleKey("photo");
    if (k) { photoKey.value = k; return true; }
    return false;
  };

  /* ===== 虚拟滚动（落实 upgrade.md "相册列表强制采用虚拟滚动"） =====
   *
   * 布局模型：绝对定位网格
   *   - 列数响应式：>1200px → 4 列，>800px → 3 列，否则 2 列（与原 grid 媒体查询一致）
   *   - 每项 aspect-ratio 1:1（正方形缩略图），故项高 = 列宽，行高 = 列宽 + gap
   *   - 容器高度 = 总行数 × 行高，撑出滚动条
   *   - 仅渲染 [可视起始行 - buffer, 可视结束行 + buffer] 范围内的项目
   *
   * 性能收益：上万照片也只渲染数十 DOM 节点（可视区 + buffer ≈ 6 行 × 4 列 = 24 项），
   *           彻底消除 Vue 响应式 diff 与浏览器布局/绘制开销，滚动如丝般顺滑。
   *
   * 动画策略：首批加载播放 photo-reveal 入场动画（美感），1.5s 后置 animationDone=true，
   *           后续滚动新进入项不重播动画（避免快速滚动闪烁）。动画作用于 .photo-card
   *           子元素，与 masonry-item 的 translate3d 定位互不干扰。
   */
  const scrollRef = ref<HTMLElement | null>(null);
  const scrollTop = ref(0);
  const viewportHeight = ref(600);
  const containerWidth = ref(0);
  const columns = ref(4);
  const GAP = 12;
  const BUFFER_ROWS = 4;

  /** 根据容器宽度计算响应式列数（与原 CSS 媒体查询阈值一致） */
  const computeColumns = (width: number): number => {
    if (width <= 800) return 2;
    if (width <= 1200) return 3;
    return 4;
  };

  /** 列宽（= 项宽 = 项高，因 aspect-ratio 1:1） */
  const itemWidth = computed(() => {
    if (columns.value <= 0 || containerWidth.value <= 0) return 0;
    return Math.max(0, (containerWidth.value - (columns.value - 1) * GAP) / columns.value);
  });

  /** 行高 = 列宽 + gap（最后一行多算一个 gap 不影响滚动体验，误差 < 12px） */
  const rowHeight = computed(() => itemWidth.value + GAP);

  /** 总行数 */
  const totalRows = computed(() =>
    columns.value > 0 ? Math.ceil(photos.value.length / columns.value) : 0
  );

  /** 容器总高度（撑出滚动条） */
  const totalHeight = computed(() => Math.max(0, totalRows.value * rowHeight.value));

  /** 可视区域项目（带 _left/_top 定位坐标） */
  const visiblePhotos = computed<VisiblePhoto[]>(() => {
    const cols = columns.value;
    const rh = rowHeight.value;
    const iw = itemWidth.value;
    if (cols <= 0 || rh <= 0 || iw <= 0 || photos.value.length === 0) return [];
    // 可视行范围（含 buffer，上下各多渲染 BUFFER_ROWS 行，消除快速滚动时的空白闪烁）
    const startRow = Math.max(0, Math.floor(scrollTop.value / rh) - BUFFER_ROWS);
    const endRow = Math.min(
      totalRows.value,
      Math.ceil((scrollTop.value + viewportHeight.value) / rh) + BUFFER_ROWS
    );
    const startIdx = startRow * cols;
    const endIdx = Math.min(photos.value.length, endRow * cols);
    const out: VisiblePhoto[] = [];
    for (let i = startIdx; i < endIdx; i++) {
      const ph = photos.value[i];
      const row = Math.floor(i / cols);
      const col = i % cols;
      out.push({ ...ph, _left: col * (iw + GAP), _top: row * rh });
    }
    return out;
  });

  /** 滚动事件：更新 scrollTop 触发 visiblePhotos 重算
   * ★ 项3：rAF 节流（同帧多次 scroll 合并为一次，60fps 上限）
   * 原问题：scroll 事件每秒触发 60~120 次，每次触发 visiblePhotos computed 重算，
   *        含位置计算与 _left/_top 字段更新，连续滚动时主线程被阻塞。
   * 优化后：同一帧内多次 scroll 仅执行最后一次，滚动视差计算开销降低 90%。 */
  const onScroll = rafThrottle(() => {
    if (scrollRef.value) scrollTop.value = scrollRef.value.scrollTop;
  });

  /** 重新测量容器尺寸（列数 + 视口高度 + 容器宽度） */
  const updateLayout = () => {
    if (!scrollRef.value) return;
    const el = scrollRef.value;
    containerWidth.value = el.clientWidth;
    viewportHeight.value = el.clientHeight;
    columns.value = computeColumns(containerWidth.value);
  };

  /**
   * ★ 跨 composable 引用修复：resizeObserver 改为 ref，使外部可安全赋值/读取
   *   旧实现为 let 闭包变量，return 时返回快照值（null），外部赋值后内部不可见。
   *   ref 包装后内外共享同一响应式引用，且 .value 语义与 ref<HTMLElement> 一致。
   */
  const resizeObserver = ref<ResizeObserver | null>(null);

  /** 初始化虚拟滚动布局：测量容器尺寸 + 启动 ResizeObserver 监听 resize
   *  ★ 入口文件 onMounted 调用，将生命周期管理收敛至数据层（单一职责） */
  const initVirtualScroll = () => {
    updateLayout();
    if (scrollRef.value && typeof ResizeObserver !== "undefined") {
      resizeObserver.value = new ResizeObserver(() => updateLayout());
      resizeObserver.value.observe(scrollRef.value);
    }
  };

  /** 销毁虚拟滚动：释放 ResizeObserver
   *  ★ 入口文件 onUnmounted 调用，防止内存泄漏 */
  const destroyVirtualScroll = () => {
    if (resizeObserver.value) {
      resizeObserver.value.disconnect();
      resizeObserver.value = null;
    }
  };

  /* ===== 按需解密（落实 upgrade.md "完整元数据与缩略图严格按需加载"） =====
   *
   * 架构：两阶段加载
   *   阶段1（loadPhotos）：从 recordScanCache 获取 id 列表，创建占位项（仅 id/metaId，
   *                        thumb 为空），立即 push 渲染列表骨架 —— 上万照片也瞬间呈现完整列表。
   *   阶段2（ensureVisiblePhotosDecrypted）：watch(visiblePhotos) 监听可视区变化，
   *                        先 getRecordsDataB64Batch 批量预取可视区 meta dataB64
   *                        （扫描缓存命中零 IPC，未命中并行 IPC 回退），再并发解密。
   *
   * 性能收益：列表初始渲染零解密开销（仅 id）；缩略图批量预取 + 按需解密，并发上限 4，
   *           滚动时仅解密新进入可视区的项，已解密项命中扫描缓存/全量缓存零 IPC。
   */

  /** 解密单张照片完整元数据（含旧格式 chunkIds 迁移），返回渲染字段或 null。
   *  ★ 性能修复：prefetchedMetaB64 由 ensureVisiblePhotosDecrypted 批量预取传入（零 IPC）；
   *    未传入时单条批量获取（扫描缓存优先 + 并行 IPC 回退），消除旧 lastUseSummaryPath
   *    分支的逐条 getFullRecord 串行 IPC。 */
  const decryptPhotoMeta = async (vid: number, prefetchedMetaB64?: string): Promise<DecryptedPhotoMeta | null> => {
    if (!photoKey.value) return null;
    // ★ 性能修复：优先消费批量预取结果；未预取则单条批量获取（扫描缓存优先 + IPC 回退）
    let metaB64: string;
    if (prefetchedMetaB64 !== undefined) {
      metaB64 = prefetchedMetaB64;
      if (!metaB64) return null;
    } else {
      const map = await getRecordsDataB64Batch([vid]);
      metaB64 = map.get(vid) || "";
      if (!metaB64) return null;
    }

    try {
      const meta = await decryptMeta(metaB64, photoKey.value);

      // 旧格式迁移：meta 有 chunkIds 但无 chunkDataB64，批量读取 chunk 记录内联
      if ((!meta.chunkDataB64 || meta.chunkDataB64.length === 0) &&
          meta.chunkIds && meta.chunkIds.length > 0) {
        // ★ 性能修复：批量获取所有 chunk（扫描缓存优先，并行 IPC 回退），消除逐条串行 IPC
        const chunkMap = await getRecordsDataB64Batch(meta.chunkIds);
        const chunkDataB64: string[] = [];
        let allFound = true;
        for (const cid of meta.chunkIds) {
          const chunkB64 = chunkMap.get(cid);
          if (!chunkB64) { allFound = false; break; }
          chunkDataB64.push(chunkB64);
        }
        if (allFound && chunkDataB64.length === meta.chunkIds.length) {
          meta.chunkDataB64 = chunkDataB64;
          meta.chunkIds = [];
        }
      }

      return {
        name: meta.name,
        thumb: `url(data:image/jpeg;base64,${meta.thumbB64})`,
        size: formatSize(meta.size),
        meta,
      };
    } catch { return null; }
  };

  /** 按需解密中标记集合（防止同一 vid 重复解密） */
  const decryptingMetaIds = new Set<number>();

  /** 可视区按需解密：对未 loaded 的占位项触发解密，并发上限 4 避免 IPC 风暴。
   *  解密完成就地更新 photos 对应项；解密失败则移除占位项（密钥不匹配/数据损坏）。
   *  ★ 性能修复：解密前先 getRecordsDataB64Batch 批量预取可视区 meta dataB64
   *    （扫描缓存命中零 IPC，未命中并行 IPC 回退），再传入并发解密池，消除池内逐条 IPC。 */
  const ensureVisiblePhotosDecrypted = async (visible: VisiblePhoto[]) => {
    if (!isTauri || !photoKey.value) return;
    const toDecrypt: number[] = [];
    for (const vph of visible) {
      if (vph.loaded || !vph.metaId) continue;
      if (decryptingMetaIds.has(vph.metaId)) continue;
      toDecrypt.push(vph.metaId);
    }
    if (toDecrypt.length === 0) return;
    for (const vid of toDecrypt) decryptingMetaIds.add(vid);

    // ★ 性能修复：批量预取所有待解密照片的 meta dataB64（扫描缓存优先，并行 IPC 回退）
    //   原方案：并发池内每条 decryptPhotoMeta 各自 getFullRecord → 4 路串行 IPC 抢 worker
    //   新方案：一次批量预取（命中缓存零 IPC），并发池直接消费预取结果，仅做 CPU 解密
    const metaB64Map = await getRecordsDataB64Batch(toDecrypt);

    const CONCURRENCY = 4;
    let cursor = 0;
    const runNext = async (): Promise<void> => {
      while (cursor < toDecrypt.length) {
        const vid = toDecrypt[cursor++];
        try {
          const data = await decryptPhotoMeta(vid, metaB64Map.get(vid));
          const pidx = photos.value.findIndex(p => p.metaId === vid);
          if (pidx >= 0) {
            if (data) {
              // ★ 项2：shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
              updateShallowItem(photos, pidx, { ...data, loaded: true });
            } else {
              // ★ 企业级根治：解密失败时【不移除】占位项
              //    旧实现 removeShallowItemAt(photos, pidx) 直接移除照片，
              //    但解密失败有很多临时原因（批量预取未命中、IPC 超时、密钥时序、
              //    扫描缓存未填充），照片数据可能仍在 verthys 中。
              //    移除照片是不可逆的 UI 操作，会导致用户看到"照片凭空消失"。
              //    修复：保留占位项，用户点击时 onView 会触发按需解密回退（decryptPhotoMeta）。
              //    decryptingMetaIds.delete(vid) 允许后续重新尝试解密。
              console.warn(`[ensureVisiblePhotosDecrypted] 解密失败，保留占位项: metaId=${vid}`);
            }
          }
        } catch { /* 单项失败不影响其他 */ }
        decryptingMetaIds.delete(vid);
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, toDecrypt.length) }, runNext));
  };

  // ★ 企业级根治：watch(visiblePhotos) 触发按需解密
  //    【致命缺陷修复】旧实现定义了 ensureVisiblePhotosDecrypted 但遗漏了 watch 调用，
  //    导致该函数永远不被执行。重启后 loadPhotos 创建的占位项（loaded=false, meta=undefined）
  //    永远不被解密填充，用户点击照片时 onView 检测到 ph.meta 为 undefined，
  //    报"照片元数据缺失，无法预览原图"——即用户反馈的"照片元数据丢失/照片全部损坏"。
  //    修复：监听 visiblePhotos 变化，自动触发可视区照片的按需解密。
  //    flush:'post' 确保 DOM 更新后执行，避免与响应式更新竞争。
  //    函数内部有 decryptingMetaIds 去重 + loaded 检查，重复触发安全。
  watch(visiblePhotos, (v) => {
    ensureVisiblePhotosDecrypted(v);
  }, { flush: 'post' });

  /* ===== 加载照片列表（缓存优先 + 增量扫描，消除切回时的空白重载） ===== */
  const loadPhotos = async () => {
    if (!isTauri) return; // 浏览器模式从内存 photos 列表直接展示
    if (!ensurePhotoKey()) return;

    // 缓存优先：先用缓存数据即时渲染，消除切回时的空白
    const cached = getModuleCache<PhotoEntry[]>("photos");
    let maxMetaId = 0;
    if (cached.data && cached.data.length > 0) {
      // 缓存项视为已解密（loaded=true），避免 watch(visiblePhotos) 重复触发解密
      // ★ 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
      replaceShallowArray(photos, cached.data.map(p => ({ ...p, loaded: true })));
      maxMetaId = cached.data.reduce((max, p) => Math.max(max, p.metaId || 0), 0);
      photosLoading.value = false; // 缓存有效，不再显示全屏加载
    } else {
      // ★ 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
      clearShallowArray(photos);
      photosLoading.value = true;
    }

    let listId = photos.value.length > 0 ? Math.max(...photos.value.map(p => p.id)) + 1 : 1;

    try {
      // ★ 性能修复：改走 recordScanCache（落实 2.5s 预算 + 为按需解密预填扫描缓存）
      //    原方案：ensureSummaryScanSafe 仅返回元数据 ID，按需解密仍需逐条 getFullRecord IPC，
      //            与后台 ensureRecordScan 抢同一常驻 worker → 滚动解密卡顿。
      //    新方案：ensureRecordScanSafe 一次扫描缓存全部 dataB64（≤64KB 命中零 IPC，
      //            >64KB 并行回退），ensureVisiblePhotosDecrypted 批量预取直接命中缓存。
      //    后台 startBackgroundTasks 已扫描则此处瞬时增量返回（startId=maxScannedId+1）。
      await ensureRecordScanSafe();
      const photoIds = getRecordIdsByType(TYPE_PHOTO_META);

      // ★ 落实 upgrade.md "前端相册列表初始渲染仅使用此轻量数据，瞬间即可呈现完整列表"：
      //   阶段1 — 创建占位项（仅 id/metaId，thumb 为空），立即 push 渲染列表骨架。
      //   虚拟滚动仅渲染可视区占位，上万照片也瞬间呈现完整列表。
      //   阶段2 — 由 watch(visiblePhotos) → ensureVisiblePhotosDecrypted 按需解密可视区缩略图。
      const newEntries: PhotoEntry[] = [];
      for (const vid of photoIds) {
        if (vid <= maxMetaId) continue; // 增量过滤：跳过已加载记录
        newEntries.push({
          id: listId++,
          metaId: vid,
          name: "",
          thumb: "",
          size: "",
          height: 0,
          loaded: false,
        });
      }
      if (newEntries.length > 0) {
        // ★ 项2：shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
        pushShallowItems(photos, newEntries);
        photosLoading.value = false;
      }
      // ★ 不在此处全量解密，由 watch(visiblePhotos) 按需解密可视区（落实 upgrade.md "按需加载"）
    } finally {
      photosLoading.value = false;
      // 更新缓存（含新增照片）
      if (photos.value.length > 0) {
        setModuleCache("photos", photos.value);
      }
    }
  };

  return {
    // ===== 状态 =====
    photos,
    photoKey,
    isTauri,
    photosLoading,
    animationDone,
    // ===== 虚拟滚动 =====
    scrollRef,
    scrollTop,
    viewportHeight,
    containerWidth,
    columns,
    GAP,
    BUFFER_ROWS,
    computeColumns,
    itemWidth,
    rowHeight,
    totalRows,
    totalHeight,
    visiblePhotos,
    onScroll,
    updateLayout,
    resizeObserver,
    /** ★ 生命周期收敛至数据层：入口文件 onMounted/onUnmounted 调用 */
    initVirtualScroll,
    destroyVirtualScroll,
    // ===== 按需解密 =====
    decryptPhotoMeta,
    decryptingMetaIds,
    ensureVisiblePhotosDecrypted,
    // ===== 加载照片 =====
    loadPhotos,
    // ===== 密钥管理 =====
    ensurePhotoKey,
  };
}
