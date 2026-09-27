/**
 * photo-album/usePhotoData.ts — 拾光模块核心数据层 composable
 *
 * 职责：管理照片列表状态、虚拟滚动布局、按需解密、加载照片。
 *
 * 设计要点：
 * - shallowRef 操作必须用 shallow-array 工具函数触发 triggerRef
 * - 列表装载走"摘要优先"：摘要缓存仅含索引（不解密数据），可毫秒级渲染带名称的列表；
 *   缩略图与真实尺寸由可视区按需解密回填，避免进入模块即触发全量数据扫描
 * - 扫描失败必须可见：加载错误经 loadError 上报，禁止把失败折叠成"暂无照片"
 * - 模块密钥失效（闲置销毁/登出）必须联动：清除已解密内容并提示重新验证
 * - ensureVisiblePhotosDecrypted 并发上限 4，批量预取 meta dataB64
 */
import { ref, shallowRef, computed, watch } from "vue";
import {
  getModuleKey, getModuleCache, setModuleCache,
  ensureSummaryScan, ensureRecordScan, cancelRecordScan, cancelSummaryScan,
  getSummaryIdsByType, getSummaryRecord, getSummaryCacheSize, getRecordIdsByType,
  getRecordsDataB64Batch,
  moduleKeyReadyRef,
} from "../../lib/keyManager";
import { verthysGetSummaryCount } from "../../lib/verthys";
import { clearFileKeyCache, TYPE_PHOTO_META, type PhotoMeta } from "../../lib/crypto";
import { decryptMetaPreferWorker, decryptThumbPreferWorker } from "../../workers/photo-decrypt-bridge";
import { photoWorkerPool } from "../../workers/photoWorkerPool";
import { isSlimPhotoMeta } from "../../constants/crypto_const";
import { rafThrottle } from "../../utils/debounce";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray, clearShallowArray,
} from "../../utils/shallow-array";
import type { PhotoEntry, VisiblePhoto, DecryptedPhotoMeta } from "./types";
import {
  formatSize, rehydrateEntries, diffNewIds, sortByMetaId,
  stripMetaRecordPrefix, prefetchRowIndices,
  makeThumbCssValue, makeThumbCssValueFromBytes, revokeThumbUrl,
} from "./utils";
import {
  stageStartPercent, stagePercent, monotonicPercent,
  type PhotoLoadStage,
} from "./load-progress";

/** 可视区解密并发上限（限制同时进行的 IPC/解密数量，避免通道与主线程拥塞） */
const DECRYPT_CONCURRENCY = 4;

/** 滚动解密批次去抖窗口：合并连续滚动产生的重复批次收集 */
const SCROLL_DECRYPT_DEBOUNCE_MS = 80;

/** 运动方向预取行数与反方向兜底行数（方向感知预取，前多后少） */
const PREFETCH_AHEAD_ROWS = 2;
const PREFETCH_TRAIL_ROWS = 1;

export function usePhotoData() {
  /* ===== 状态 ===== */
  /* 项2：shallowRef 替代 ref，避免 Vue 对 photos 数组内每条记录深度代理
   * （每条记录含 thumb/blobUrl/rawBytes 等大型字段，万条照片深度代理开销 200-500ms，
   *   内存暴涨且每次更新触发大量 watch/computed 重新计算） */
  const photos = shallowRef<PhotoEntry[]>([]);
  const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

  /* ===== 模块独立密钥（由 keyManager 会话缓存提供，用户登录模块时输入） =====
   *   会话内 15min 闲置超时自动锁定（verthys-cache.ts MODULE_KEY_IDLE_TIMEOUT_MS），
   *   超时后模块密钥被销毁。photoKey 是会话密钥在本模块内的短时副本，
   *   由 moduleKeyReady 联动：会话密钥一旦失效必须立即清空副本与已解密内容。 */
  const photoKey = ref<string>("");

  const photosLoading = ref(false);
  const animationDone = ref(false);

  /** 列表装载错误（扫描失败/降级/密钥失效），供模块顶部提示与重试入口消费 */
  const loadError = ref<string>("");

  /** 按需解密失败条目数（保留占位并提示，不静默丢弃） */
  const failedCount = ref(0);

  /* ===== 加载进度（信号层 → 表现层透传，数值只来自真实计数） =====
   *
   * 阶段：index（摘要索引）→ records（回退的记录扫描，可取消，批次粒度上报）
   *       → decrypt（可视区首批解密，可暂停）→ done。
   * 百分比经纯函数映射 + 单调闸门，分母不可得的阶段停在区间起点，
   * 由文案承担"仍在推进"的反馈（见 load-progress.ts 的不变式）。
   */
  const loadStage = ref<PhotoLoadStage>("idle");
  const loadPercent = ref(0);
  const loadMessage = ref("");
  const loadElapsedMs = ref(0);
  /** 首批可视区解密是否在进行（表现层据此显示进度卡） */
  const firstFillInFlight = ref(false);
  /** 解密暂停标志（用户取消首批解密后置位；恢复入口会清位） */
  const decryptPaused = ref(false);

  /** 加载起点时间戳（用于耗时展示；0 表示未在加载） */
  let loadStartedAt = 0;
  /** 用户已请求取消本轮装载：阻止其后继阶段（更重的回退扫描等）继续启动 */
  let loadAbortRequested = false;

  /** 推进进度：阶段 + 真实计数 → 百分比（单调不减，异常输入被收束） */
  const pushProgress = (stage: PhotoLoadStage, message: string, done = 0, total = 0) => {
    loadStage.value = stage;
    loadMessage.value = message;
    const next = total > 0 ? stagePercent(stage, done, total) : stageStartPercent(stage);
    loadPercent.value = monotonicPercent(loadPercent.value, next);
    loadElapsedMs.value = loadStartedAt > 0 ? Date.now() - loadStartedAt : 0;
  };

  /* ===== 密钥管理 ===== */
  const ensurePhotoKey = (): boolean => {
    if (photoKey.value) return true;
    const k = getModuleKey("photo");
    if (k) { photoKey.value = k; return true; }
    return false;
  };

  /* ===== 虚拟滚动（相册列表强制采用虚拟滚动） =====
   *
   * 布局模型：绝对定位网格
   *   - 列数响应式：常规窗口 4 列，极窄窗口（≤640px）2 列
   *   - 每项 aspect-ratio 1:1（正方形缩略图），故项高 = 列宽，行高 = 列宽 + gap
   *   - 容器高度 = 总行数 × 行高，撑出滚动条
   *   - 仅渲染 [可视起始行 - buffer, 可视结束行 + buffer] 范围内的项目
   *
   * 性能收益：上万照片也只渲染数十 DOM 节点（可视区 + buffer），
   *           彻底消除 Vue 响应式 diff 与浏览器布局/绘制开销。
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

  /** 滚动方向（供方向感知预取使用；由滚动位移变化更新） */
  const scrollDir = ref<"down" | "up">("down");

  /** 根据容器宽度计算响应式列数。
   * 默认 4 列（一行四张、常规窗口一屏约两行，照片缩略尺寸随宽度自适应）；
   * 极窄窗口（≤640px）退化为 2 列，防止缩略图过小不可辨认。 */
  const computeColumns = (width: number): number => {
    if (width <= 640) return 2;
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

  /** 含 buffer 的行窗口（可视区上下各多渲染 BUFFER_ROWS 行，消除快速滚动空白闪烁） */
  const bufferedRowWindow = computed(() => {
    const rh = rowHeight.value;
    if (rh <= 0) return { startRow: 0, endRow: 0 };
    const startRow = Math.max(0, Math.floor(scrollTop.value / rh) - BUFFER_ROWS);
    const endRow = Math.min(
      totalRows.value,
      Math.ceil((scrollTop.value + viewportHeight.value) / rh) + BUFFER_ROWS
    );
    return { startRow, endRow };
  });

  /** 可视区域项目（带 _left/_top 定位坐标） */
  const visiblePhotos = computed<VisiblePhoto[]>(() => {
    const cols = columns.value;
    const rh = rowHeight.value;
    const iw = itemWidth.value;
    if (cols <= 0 || rh <= 0 || iw <= 0 || photos.value.length === 0) return [];
    const { startRow, endRow } = bufferedRowWindow.value;
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
   * 项3：rAF 节流（同帧多次 scroll 合并为一次，60fps 上限）
   * 同时在位移变化时更新滚动方向，供方向感知预取使用。 */
  const onScroll = rafThrottle(() => {
    if (!scrollRef.value) return;
    const cur = scrollRef.value.scrollTop;
    if (cur !== scrollTop.value) {
      scrollDir.value = cur > scrollTop.value ? "down" : "up";
    }
    scrollTop.value = cur;
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
   * 跨 composable 引用修复：resizeObserver 改为 ref，使外部可安全赋值/读取
   *   旧实现为 let 闭包变量，return 时返回快照值（null），外部赋值后内部不可见。
   *   ref 包装后内外共享同一响应式引用，且 .value 语义与 ref<HTMLElement> 一致。
   */
  const resizeObserver = ref<ResizeObserver | null>(null);

  /** 初始化虚拟滚动布局：测量容器尺寸 + 启动 ResizeObserver 监听 resize
   *  入口文件 onMounted 调用，将生命周期管理收敛至数据层（单一职责） */
  const initVirtualScroll = () => {
    updateLayout();
    if (scrollRef.value && typeof ResizeObserver !== "undefined") {
      resizeObserver.value = new ResizeObserver(() => updateLayout());
      resizeObserver.value.observe(scrollRef.value);
    }
  };

  /** 销毁虚拟滚动：释放 ResizeObserver
   *  入口文件 onUnmounted 调用，防止内存泄漏 */
  const destroyVirtualScroll = () => {
    if (resizeObserver.value) {
      resizeObserver.value.disconnect();
      resizeObserver.value = null;
    }
  };

  /* ===== 列表项定位索引（metaId → 数组下标） =====
   * 按需解密逐批更新条目，旧实现每条都做 findIndex（O(n)），
   * 万张相册下大批量解密退化为 O(n²)。此处以数组引用为失效键惰性重建。 */
  let indexSource: PhotoEntry[] | null = null;
  let indexByMetaId = new Map<number, number>();

  const entryIndexOf = (metaId: number): number => {
    if (indexSource !== photos.value) {
      const map = new Map<number, number>();
      const arr = photos.value;
      for (let i = 0; i < arr.length; i++) {
        const mid = arr[i].metaId;
        if (mid) map.set(mid, i);
      }
      indexByMetaId = map;
      indexSource = arr;
    }
    return indexByMetaId.get(metaId) ?? -1;
  };

  /* ===== 按需解密（完整元数据与缩略图严格按需加载） =====
   *
   * 架构：三阶段加载
   *   阶段1（loadPhotos）：列表 ID 来自摘要缓存（仅索引，不解密数据），创建占位项
   *                        （id/metaId/名称），立即渲染列表骨架 —— 上万照片瞬间呈现。
   *   阶段2（ensureVisiblePhotosDecrypted）：watch(visiblePhotos) 监听可视区变化，
   *                        先 getRecordsDataB64Batch 批量预取可视区 meta dataB64
   *                        （扫描缓存命中零 IPC，未命中并行 IPC 回退），再并发解密。
   *   阶段3（方向感知预取）：可视区批次完成后，按滚动方向提前解密即将进入的行。
   *
   * 性能收益：进入模块不再触发全量数据扫描（避免 8 MiB 扫描窗口承载 MB 级记录时整批失败），
   *           首屏仅需索引；缩略图并发上限 4，滚动时仅解密新进入可视区的项。
   */

  /** 按需解密中标记集合（防止同一 vid 重复解密） */
  const decryptingMetaIds = new Set<number>();

  /* 会话密钥失效联动：闲置销毁/登出后立即清空密钥副本与已解密内容。
   * 旧实现只在组件卸载时清零；密钥销毁后本模块仍持有副本并继续解密照片，
   * 使"闲置自动锁定"形同虚设。 */
  watch(() => moduleKeyReadyRef.value.photo, (ready) => {
    if (ready) return;
    photoKey.value = "";
    decryptingMetaIds.clear();
    // 会话密钥失效：连同按盐缓存的文件子密钥一并销毁，避免派生结果跨会话驻留；
    //   Worker 侧派生缓存由池下发清理标记，于各 Worker 下一任务入口清空
    clearFileKeyCache();
    photoWorkerPool.invalidateDerivedKeys();
    releaseThumbUrls();
    replaceShallowArray(photos, photos.value.map(p => ({
      id: p.id, metaId: p.metaId, name: p.name, thumb: "", size: "", height: 0,
      loaded: false, failed: false,
    })));
    setModuleCache("photos", photos.value);
    failedCount.value = 0;
    firstFillInFlight.value = false;
    decryptPaused.value = false;
    loadStage.value = "idle";
    loadError.value = "模块密钥已失效，请返回安全管理重新验证后进入拾光";
  });

  /** 释放全部条目的缩略图 Blob URL（密钥失效/卸载/整体替换前调用） */
  const releaseThumbUrls = () => {
    for (const p of photos.value) {
      if (p.thumb) revokeThumbUrl(p.thumb);
    }
  };

  /** 解密单张照片完整元数据（含旧格式 chunkIds 迁移），返回渲染字段或 null。
   *  性能修复：prefetchedMetaB64 由 ensureVisiblePhotosDecrypted 批量预取传入（零 IPC）；
   *    未传入时单条批量获取（扫描缓存优先 + 并行 IPC 回退），消除旧 lastUseSummaryPath
   *    分支的逐条 getFullRecord 串行 IPC。
   *  性能修复：解密下沉 photo-crypto Worker 池（主线程不做密钥派生与 AEAD），
   *    池基础设施不可用时由桥自动回退主线程实现，两条路径结果一致。 */
  const decryptPhotoMeta = async (vid: number, prefetchedMetaB64?: string): Promise<DecryptedPhotoMeta | null> => {
    if (!photoKey.value) return null;
    // 性能修复：优先消费批量预取结果；未预取则单条批量获取（扫描缓存优先 + IPC 回退）
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
      const { meta, thumbBytes } = await decryptMetaPreferWorker(metaB64, photoKey.value, String(vid));

      // 缩略图归一：索引瘦身布局的缩略图在独立记录中，需按其记录 ID 取密文
      // 再解密（扫描缓存命中则零 IPC）；既有布局仍取索引内联的缩略图数据。
      let thumbCss = "";
      if (thumbBytes) {
        thumbCss = makeThumbCssValueFromBytes(new Uint8Array(thumbBytes));
      } else if (isSlimPhotoMeta(meta) && meta.thumbId && meta.wrappedFileKey) {
        const thumbMap = await getRecordsDataB64Batch([meta.thumbId]);
        const thumbCipher = thumbMap.get(meta.thumbId) ?? "";
        if (thumbCipher) {
          const bytes = await decryptThumbPreferWorker(
            thumbCipher, photoKey.value, meta.wrappedFileKey, meta.fileHash, `${vid}:thumb`,
          );
          thumbCss = makeThumbCssValueFromBytes(bytes);
        }
      } else {
        thumbCss = makeThumbCssValue(meta.thumbB64);
      }

      // 不再把 chunkIds 预取内联：列表渲染只需要缩略图/名称/尺寸，而分块密文是
      //   MB 级载荷（单张照片可达数十条记录），内联会把"渲染一张缩略图"退化成
      //   "搬运整张照片"。查看原图、导出、删除级联三条路径都已各自按 chunkIds
      //   按需读取，无需在此处预取。

      return {
        name: meta.name,
        // 缩略图以 Blob URL 呈现：数据不进 JS 字符串，释放点见 releaseThumbUrls
        thumb: thumbCss,
        size: formatSize(meta.size),
        meta,
      };
    } catch (e) {
      console.warn("[decryptPhotoMeta] 元数据解密失败", { metaId: vid, reason: e instanceof Error ? e.message : "unknown" });
      return null;
    }
  };

  /** 批量解密给定 metaId 列表（并发上限 4），就地更新列表项。
   *  解密失败保留占位并标记 failed，由上层聚合提示与重试入口处理。
   *
   * @param onItemDone 单项处理完成后回调（真实计数：含失败项），供进度信号层使用。
   *   逐项回调而非批次回调：并发池中先完成的项先计入，进度不随最慢项停滞。 */
  const decryptBatch = async (
    metaIds: number[],
    onItemDone?: () => void,
  ): Promise<void> => {
    if (metaIds.length === 0) return;
    for (const vid of metaIds) decryptingMetaIds.add(vid);
    try {
      // 性能修复：批量预取所有待解密照片的 meta dataB64（扫描缓存优先，并行 IPC 回退）
      //   原实现：并发池内每条 decryptPhotoMeta 各自 getFullRecord → 4 路串行 IPC 抢 worker
      //   新实现：一次批量预取（命中缓存零 IPC），并发池直接消费预取结果，仅做 CPU 解密
      const metaB64Map = await getRecordsDataB64Batch(metaIds);

      let cursor = 0;
      const runNext = async (): Promise<void> => {
        while (cursor < metaIds.length) {
          // 暂停（用户取消首批解密）：在项边界停止取新项，已解密结果保留。
          //   去重标记由 finally 统一释放，恢复时这些项可重新参与解密。
          if (decryptPaused.value) return;
          const vid = metaIds[cursor++];
          try {
            const data = await decryptPhotoMeta(vid, metaB64Map.get(vid));
            const pidx = entryIndexOf(vid);
            if (pidx >= 0) {
              if (data) {
                // 覆盖前释放旧缩略图 Blob URL（重试/重进模块都会走到这里）
                const old = photos.value[pidx];
                if (old?.thumb) revokeThumbUrl(old.thumb);
                // 项2：shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
                updateShallowItem(photos, pidx, { ...data, loaded: true, failed: false });
              } else {
                // 解密失败保留占位（临时原因可能是预取未命中、IPC 超时、密钥时序），
                // 标记 failed 供聚合提示与重试；绝不删除照片（删除是不可逆的 UI 操作）。
                updateShallowItem(photos, pidx, { failed: true });
              }
            }
          } catch { /* 单项失败不影响其他 */ }
          finally { if (onItemDone) onItemDone(); }
        }
      };
      await Promise.all(
        Array.from({ length: Math.min(DECRYPT_CONCURRENCY, metaIds.length) }, runNext),
      );
    } finally {
      // 任何异常路径都必须释放去重标记：残留会使这些照片永不参与后续自动解密
      for (const vid of metaIds) decryptingMetaIds.delete(vid);
      recountFailures();
    }
  };

  /** 重新统计解密失败条目数（保留占位且未成功解密的项） */
  const recountFailures = () => {
    let n = 0;
    for (const p of photos.value) {
      if (p.failed && !p.loaded) n++;
    }
    failedCount.value = n;
  };

  /** 收集方向感知预取目标：含 buffer 窗口之外、运动方向优先的行内待解密项 */
  const collectPrefetchMetaIds = (): number[] => {
    const cols = columns.value;
    if (cols <= 0) return [];
    const rows = prefetchRowIndices(
      bufferedRowWindow.value, totalRows.value, scrollDir.value,
      PREFETCH_AHEAD_ROWS, PREFETCH_TRAIL_ROWS,
    );
    const ids: number[] = [];
    const total = photos.value.length;
    for (const r of rows) {
      for (let c = 0; c < cols; c++) {
        const idx = r * cols + c;
        if (idx >= total) break;
        const ph = photos.value[idx];
        if (ph?.metaId && !ph.loaded && !decryptingMetaIds.has(ph.metaId)) ids.push(ph.metaId);
      }
    }
    return ids;
  };

  /** 可视区按需解密：对未 loaded 的占位项触发解密，并发上限 4 避免 IPC 风暴。
   *
   * 首批（进入模块后的第一次可视区解密）接入进度信号：done/total 均为真实
   * 计数，完成后阶段置 done（进度达 100）。用户取消后 decryptPaused 置位，
   * 本函数与滚动触发的批次一并停摆，由恢复入口重新驱动。 */
  const ensureVisiblePhotosDecrypted = async (visible: VisiblePhoto[]) => {
    if (!isTauri || !photoKey.value || decryptPaused.value) return;
    const toDecrypt: number[] = [];
    for (const vph of visible) {
      if (vph.loaded || !vph.metaId) continue;
      if (decryptingMetaIds.has(vph.metaId)) continue;
      toDecrypt.push(vph.metaId);
    }
    if (toDecrypt.length > 0) {
      const isFirstFill = !firstFillDone;
      if (isFirstFill) firstFillInFlight.value = true;
      let done = 0;
      const total = toDecrypt.length;
      if (isFirstFill) pushProgress("decrypt", `解密缩略图 0/${total}`, 0, total);
      await decryptBatch(toDecrypt, () => {
        done += 1;
        if (isFirstFill) {
          pushProgress("decrypt", `解密缩略图 ${done}/${total}`, done, total);
        }
      });
      if (isFirstFill) {
        firstFillDone = true;
        firstFillInFlight.value = false;
        // 用户中途取消：进度停在真实位置并转为暂停提示（不宣告完成）
        if (decryptPaused.value) {
          pushProgress("cancelled", `已暂停解密（本次 ${done}/${total} 张已完成）`);
        } else {
          pushProgress("done", "加载完成", total, total);
        }
      }
    } else if (!firstFillDone) {
      // 可视区无可解密项（缓存回灌已齐）：首批填充视为已完成，进度不驻留
      firstFillDone = true;
    }
    if (decryptPaused.value) return;
    // 可视区完成后按滚动方向补齐即将进入的行（额度复用同一并发池）
    if (!photoKey.value) return;
    const ahead = collectPrefetchMetaIds();
    if (ahead.length > 0) await decryptBatch(ahead);
  };

  /** 首批可视区解密是否已跑完（进度只覆盖首批，滚动批次不再弹进度） */
  let firstFillDone = false;

  /** 滚动触发的解密去抖：连续滚动期间合并批次收集，避免逐帧重复建批 */
  let decryptDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  const scheduleVisibleDecrypt = (v: VisiblePhoto[]) => {
    if (decryptDebounceTimer !== null) clearTimeout(decryptDebounceTimer);
    decryptDebounceTimer = setTimeout(() => {
      decryptDebounceTimer = null;
      void ensureVisiblePhotosDecrypted(v);
    }, SCROLL_DECRYPT_DEBOUNCE_MS);
  };

  /** 卸载时取消未触发的解密批次（防止卸载后写状态） */
  const cancelPendingDecrypt = () => {
    if (decryptDebounceTimer !== null) {
      clearTimeout(decryptDebounceTimer);
      decryptDebounceTimer = null;
    }
  };

  // 可视区变化 → 去抖后触发按需解密
  //    flush:'post' 确保 DOM 更新后执行，避免与响应式更新竞争。
  //    函数内部有 decryptingMetaIds 去重 + loaded 检查，重复触发安全。
  watch(visiblePhotos, (v) => {
    scheduleVisibleDecrypt(v);
  }, { flush: 'post' });

  /* ===== 加载照片列表（摘要优先：索引渲染列表，数据按需解密） ===== */

  /** 列表 ID 来源：摘要缓存（仅索引）优先，失败回退增量记录扫描 */
  type IdListSource = "summary" | "record";
  interface IdListResult {
    ok: boolean;
    ids: number[];
    source: IdListSource;
    /** true 表示走了回退路径（摘要不可用），列表可能不含全部元数据 */
    degraded: boolean;
    error?: string;
  }

  /** 获取照片 meta 记录 ID 列表。
   *  摘要扫描只读索引、不解密数据，是列表装载的最轻路径；
   *  摘要不可用（旧格式容器等）时回退增量记录扫描并标记降级。
   *
   *  回退路径为大库上可感知的耗时阶段，故接入真实进度：分母取后端统计的
   *  全库条数（估算失败则不推进百分比，由文案报告已装载条数），分子取扫描
   *  缓存当前条数（含历史增量装载，单调增）。 */
  const loadIdList = async (): Promise<IdListResult> => {
    try {
      pushProgress("index", "读取加密索引");
      await ensureSummaryScan();
      const ids = getSummaryIdsByType(TYPE_PHOTO_META);
      // 摘要扫描在旧格式容器/熔断场景下会"静默返回空"，此时缓存整体为空；
      // 需要与"确实没有照片"区分：只有缓存有内容才认定摘要结果可信。
      if (ids.length > 0 || getSummaryCacheSize() > 0) {
        pushProgress("index", "索引就绪", 1, 1);
        return { ok: true, ids, source: "summary", degraded: false };
      }
      console.warn("[loadPhotos] 摘要缓存为空，回退记录索引扫描");
    } catch (e) {
      console.warn("[loadPhotos] 摘要扫描不可用，回退记录索引扫描", e);
    }
    // 用户已请求取消：摘要阶段之后的回退扫描（更重）不得再启动，
    //   以当前缓存内容呈现列表（可能为空），由重试入口继续。
    if (loadAbortRequested) {
      return { ok: true, ids: getRecordIdsByType(TYPE_PHOTO_META), source: "record", degraded: false };
    }
    try {
      // 全库条数（后端一次性统计，不随批次变化）：作为进度分母
      const total = await verthysGetSummaryCount().catch(() => 0);
      await ensureRecordScan((p) => {
        const message = total > 0
          ? `扫描记录 ${p.cached}/${total}`
          : `扫描记录（已读 ${p.scanned} 条）`;
        pushProgress("records", message, p.cached, total);
      });
      if (loadAbortRequested) {
        // 取消发生在记录扫描期间：已装载批次保留，不宣告"就绪"
        return { ok: true, ids: getRecordIdsByType(TYPE_PHOTO_META), source: "record", degraded: false };
      }
      pushProgress("records", "记录索引就绪", 1, 1);
      return { ok: true, ids: getRecordIdsByType(TYPE_PHOTO_META), source: "record", degraded: true };
    } catch (e) {
      console.error("[loadPhotos] 记录索引扫描失败", e);
      return {
        ok: false,
        ids: [],
        source: "record",
        degraded: false,
        error: "照片列表加载失败：索引扫描未能完成，请重试",
      };
    }
  };

  /** 占位项构造：摘要来源可带名称（记录名前缀剥离），解密后由真实名称覆盖 */
  const buildPlaceholder = (metaId: number, source: IdListSource): PhotoEntry => {
    const recordName = source === "summary" ? getSummaryRecord(metaId)?.name ?? "" : "";
    return {
      id: metaId,
      metaId,
      name: recordName ? stripMetaRecordPrefix(recordName) : "",
      thumb: "",
      size: "",
      height: 0,
      loaded: false,
      failed: false,
    };
  };

  /** 把最新 ID 列表合并进当前列表（集合差集，不依赖 ID 单调分配） */
  const mergeIds = (ids: number[], source: IdListSource): void => {
    const known = new Set<number>();
    for (const p of photos.value) {
      if (p.metaId) known.add(p.metaId);
    }
    const newIds = diffNewIds(ids, known);
    if (newIds.length > 0) {
      pushShallowItems(photos, newIds.map(id => buildPlaceholder(id, source)));
      // 保持按记录 ID 升序（增量项可能插入到中间：ID 复用场景）
      replaceShallowArray(photos, sortByMetaId(photos.value));
    }
  };

  const loadPhotos = async () => {
    if (!isTauri) return; // 浏览器模式从内存 photos 列表直接展示
    if (!ensurePhotoKey()) {
      photosLoading.value = false;
      loadError.value = "模块密钥不可用，请返回安全管理验证后进入拾光";
      return;
    }
    loadError.value = "";
    // 进度起点：单调闸门在新一轮装载前归零（阶段节点本身仍是真实节点）
    loadStartedAt = Date.now();
    loadPercent.value = 0;
    loadElapsedMs.value = 0;
    decryptPaused.value = false;
    loadAbortRequested = false;

    // 缓存优先：先用已解密缓存即时渲染，消除切回时的空白
    const cached = getModuleCache<PhotoEntry[]>("photos");
    if (cached.data && cached.data.length > 0) {
      // 回灌只认"已解密"：未解密占位项保持待解密态，由可视区自动补齐；
      // 缩略图按 meta 内的数据重建（上一会话的 Blob URL 已在卸载时释放）。
      releaseThumbUrls();
      replaceShallowArray(photos, rehydrateEntries(cached.data, makeThumbCssValue));
      photosLoading.value = false;
    } else {
      clearShallowArray(photos);
      photosLoading.value = true;
    }

    try {
      const list = await loadIdList();
      if (!list.ok) {
        loadStage.value = "cancelled";
        loadError.value = list.error ?? "照片列表加载失败，请重试";
        return;
      }
      mergeIds(list.ids, list.source);
      if (list.degraded && !loadAbortRequested) {
        // 取消场景保留取消提示（不得被降级提示覆盖）
        loadError.value = "索引摘要不可用，已降级加载：列表可能不含完整信息";
      }
      recountFailures();
    } finally {
      photosLoading.value = false;
      // 阶段收口：扫描阶段结束即转为"待解密"阶段；进度卡只在实际在途时显示，
      //   此处的阶段迁移仅用于让取消入口的语义与当前动作保持一致。
      if (loadStage.value === "index" || loadStage.value === "records") {
        loadStage.value = "decrypt";
        loadMessage.value = "解密可视区缩略图";
      }
      // 不在此处全量解密，由 watch(visiblePhotos) 按需解密可视区
      if (photos.value.length > 0) {
        setModuleCache("photos", photos.value);
      }
    }
  };

  /**
   * 取消加载（用户入口）。
   *
   * 分两种在途状态分别处理：
   * - 索引/记录扫描：请求协作式取消（批次边界生效，已装载批次保留可续扫），
   *   列表以当前缓存内容呈现并标记降级，重试入口可继续；
   * - 首批解密：置暂停标志，已解密结果保留，自动解密停摆（含滚动触发），
   *   由 resumeLoad 重新驱动。
   *
   * 取消不删除任何已装载内容，也不宣告完成。
   */
  const cancelLoad = (): void => {
    loadAbortRequested = true;
    if (loadStage.value === "index") {
      cancelSummaryScan();
    }
    if (loadStage.value === "index" || loadStage.value === "records") {
      cancelRecordScan();
      loadStage.value = "cancelled";
      loadMessage.value = "已取消扫描（已装载的条目保留）";
      loadError.value = "加载已取消：列表可能不完整，可点击重试继续";
      return;
    }
    if (loadStage.value === "decrypt") {
      loadAbortRequested = false;   // 解密暂停不属于"取消装载"，重试入口无需复位
      decryptPaused.value = true;
      loadStage.value = "cancelled";
      loadMessage.value = "已暂停解密（已完成的缩略图保留）";
    }
  };

  /** 恢复加载（取消后的继续入口）：清暂停标志并重新驱动可视区解密 */
  const resumeLoad = (): void => {
    if (!decryptPaused.value) return;
    decryptPaused.value = false;
    loadStage.value = "idle";
    loadMessage.value = "";
    loadError.value = "";
    void ensureVisiblePhotosDecrypted(visiblePhotos.value);
  };

  /** 重试：清空失败标记与在途去重，重新装载列表并触发可视区解密 */
  const retryLoad = (): void => {
    loadError.value = "";
    failedCount.value = 0;
    decryptingMetaIds.clear();
    decryptPaused.value = false;
    firstFillDone = false;
    removeFailedFlags();
    void loadPhotos();
  };

  /** 清除失败标记（保留占位项，等待下一轮解密尝试） */
  const removeFailedFlags = () => {
    let changed = false;
    for (let i = 0; i < photos.value.length; i++) {
      if (photos.value[i].failed) {
        updateShallowItem(photos, i, { failed: false });
        changed = true;
      }
    }
    if (changed) setModuleCache("photos", photos.value);
  };

  return {
    // ===== 状态 =====
    photos,
    photoKey,
    isTauri,
    photosLoading,
    animationDone,
    loadError,
    failedCount,
    scrollDir,
    // ===== 加载进度（信号层） =====
    loadStage,
    loadPercent,
    loadMessage,
    loadElapsedMs,
    firstFillInFlight,
    decryptPaused,
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
    /** 生命周期收敛至数据层：入口文件 onMounted/onUnmounted 调用 */
    initVirtualScroll,
    destroyVirtualScroll,
    // ===== 按需解密 =====
    decryptPhotoMeta,
    decryptingMetaIds,
    ensureVisiblePhotosDecrypted,
    cancelPendingDecrypt,
    // ===== 加载照片 =====
    loadPhotos,
    retryLoad,
    cancelLoad,
    resumeLoad,
    /** 释放全部缩略图 Blob URL（模块卸载时由入口调用，防对象 URL 泄漏） */
    releaseThumbUrls,
    // ===== 密钥管理 =====
    ensurePhotoKey,
  };
}