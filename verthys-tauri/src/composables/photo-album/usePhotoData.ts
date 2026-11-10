/**
 * photo-album/usePhotoData.ts — 拾光模块核心数据层 composable
 *
 * 职责：管理照片列表状态、虚拟滚动布局、按需解密、加载照片。
 *
 * 设计要点：
 * - shallowRef 操作必须用 shallow-array 工具函数触发 triggerRef
 * - 列表装载走"类型盲索引优先"：按 TYPE_PHOTO_META 枚举记录 ID，不解密数据；
 *   摘要缓存仅补名称，缩略图与真实尺寸由可视区按需解密回填，避免进入模块即触发全量数据扫描
 * - 扫描失败必须可见：加载错误经 loadError 上报，禁止把失败折叠成"暂无照片"
 * - 模块密钥失效（闲置销毁/登出）必须联动：清除已解密内容并提示重新验证
 * - ensureVisiblePhotosDecrypted 并发上限 4，批量预取 meta dataB64
 *
 * 滚动性能：
 * 1. 滚动期间主线程不做 O(可见项) 的工作——行窗口状态模型把滚动事件降为
 *    O(行窗口变化)：像素级移动不产生任何重建，跨行时窗口交集内对象整体复用
 *    （由独立行窗口模块统一计算）；
 * 2. hover 与滚动路径禁止重绘型属性参与过渡——卡片视觉全部由层 + opacity /
 *    transform 承担；
 * 3. 滚动期间冻结非必要动画与解码——滚动静默态（scrollQuiet）暂停解密取项、
 *    暂停背景氛围动画并暴露 data-scrolling 供样式层冻结，滚动停止后
 *    统一追帧（解密补齐 + 下一行图片预热）。
 */
import { ref, shallowRef, computed, watch } from "vue";
import {
  getModuleCache, setModuleCache,
  ensureRecordScan, cancelRecordScan,
  getSummaryRecord, getRecordIdsByType,
  getRecordsDataB64Batch, ensureTypeIds, clearTypeIdCache,
  moduleKeyReadyRef,
} from "../../lib/keyManager";
import { lockModuleKey, openRecord } from "../../lib/module_crypto";
import { TYPE_PHOTO_META } from "../../lib/crypto";
import { scanDamagedMetaIds } from "./damage";
import { decryptMetaPreferWorker, decryptThumbPreferWorker } from "../../workers/photo-decrypt-bridge";
import { isSlimPhotoMeta } from "../../constants/crypto_const";
import { scrollPerf } from "../../config/scroll-perf";
import { rafThrottle } from "../../utils/debounce";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray, clearShallowArray,
} from "../../utils/shallow-array";
import type { PhotoEntry, VisiblePhoto, DecryptedPhotoMeta } from "./types";
import {
  formatSize, rehydrateEntries, diffNewIds, sortByMetaId,
  stripMetaRecordPrefix, prefetchRowIndices, thumbUrlOf,
  makeThumbCssValue, makeThumbCssValueFromBytes, revokeThumbUrl,
  toPhotoCacheEntries,
} from "./utils";
import {
  computeRowWindow, buildVisibleWindow,
  type VisibleCacheEntry,
} from "./visible-window";

/** 可视区解密并发上限（限制同时进行的 IPC/解密数量，避免通道与主线程拥塞） */
const DECRYPT_CONCURRENCY = 4;

/** 滚动解密批次去抖窗口：合并连续滚动产生的重复批次收集 */
const SCROLL_DECRYPT_DEBOUNCE_MS = 80;

/** 运动方向预取行数与反方向兜底行数（方向感知预取，前多后少） */
const PREFETCH_AHEAD_ROWS = 2;
const PREFETCH_TRAIL_ROWS = 1;

export function usePhotoData() {
  /* ===== 状态 ===== */
  /* shallowRef 替代 ref，避免 Vue 对 photos 数组内每条记录深度代理
   * （每条记录含 thumb/blobUrl/rawBytes 等大型字段，万条照片深度代理开销 200-500ms，
   *   内存暴涨且每次更新触发大量 watch/computed 重新计算） */
  const photos = shallowRef<PhotoEntry[]>([]);
  const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

  /* ===== 模块独立密钥（由 keyManager 会话状态提供，用户登录模块时输入） =====
   *   会话内 15min 闲置超时自动锁定（verthys-cache.ts MODULE_KEY_IDLE_TIMEOUT_MS），
   *   超时后模块密钥被销毁。模块密钥只交付 worker 托管，本组合式不保留副本；
   *   moduleKeyReady 一旦失效必须立即释放已解密内容。 */

  const photosLoading = ref(false);

  /** 列表装载错误（扫描失败/降级/密钥失效），供模块顶部提示与重试入口消费 */
  const loadError = ref<string>("");

  /** 按需解密失败条目数（保留占位并提示，不静默丢弃） */
  const failedCount = ref(0);

  /* ===== 装载阶段（取消/恢复语义的唯一依据） =====
   *
   * stage：index（摘要索引）→ records（回退记录扫描，可取消）
   *       → decrypt（可视区首批解密，可暂停）。
   * 进度百分比/耗时信号已随进度卡一并移除（模块改为骨架直出 + 常驻恢复条），
   * 此处只保留区分「此刻取消会命中哪一段」的阶段标识。
   */
  type LoadStage = "idle" | "index" | "records" | "decrypt" | "done" | "cancelled";
  const loadStage = ref<LoadStage>("idle");
  /** 解密暂停标志（用户取消首批解密后置位；恢复入口会清位） */
  const decryptPaused = ref(false);

  /** 用户已请求取消本轮装载：阻止其后继阶段（更重的回退扫描等）继续启动 */
  let loadAbortRequested = false;

  /* ===== 密钥管理 ===== */
  const ensurePhotoKey = (): boolean => moduleKeyReadyRef.value.photo === true;

  /* ===== 虚拟滚动（相册列表强制采用虚拟滚动） =====
   *
   * 布局模型：绝对定位网格
   *   - 列数响应式：常规窗口 4 列，极窄窗口（≤640px）2 列
   *   - 每项 aspect-ratio 1:1（正方形缩略图），故项高 = 列宽，行高 = 列宽 + gap
   *   - 容器高度 = 总行数 × 行高，撑出滚动条
   *
   * 行窗口状态模型（滚动性能第 1 铁律）：滚动位置的唯一量化状态是行窗口
   * [winStart, winEnd)；同窗口内的像素级移动不产生任何状态写入，跨行时窗口
   * 交集内的渲染对象整体复用，渲染数组引用保持稳定，
   * 下游 watch/patch 在绝大多数滚动帧零空转。
   */
  const scrollRef = ref<HTMLElement | null>(null);
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

  /* ===== 行窗口状态与渲染数组（滚动性能第 1 铁律） ===== */

  /** 行窗口边界（唯一滚动量化状态；-1 表示未完成首次布局测量） */
  const winStart = ref(-1);
  const winEnd = ref(-1);
  /** 上次滚动的像素位置（非响应式：只服务方向判定，不参与渲染） */
  let lastScrollPos = 0;
  /** 渲染项缓存：下标 → {源引用, 渲染对象, 布局键}（内容不变时对象持续复用） */
  let visibleCacheMap = new Map<number, VisibleCacheEntry>();
  /** 上次返回的渲染数组（内容逐项相同则保持引用，杜绝下游 watch/patch 空转） */
  let lastVisible: VisiblePhoto[] = [];
  /** 稳定空数组（空列表/无效窗口共用同一引用，避免新引用触发空跑） */
  const EMPTY_VISIBLE: VisiblePhoto[] = [];

  /**
   * 可视区域项目（渲染数组）。
   *
   * 缓存复用策略（滚动性能核心）：computed 只在"窗口跨行 / 列表内容变化 /
   * 布局参数变化"三种情况失效重算；重算时按数组下标查缓存，源条目引用与
   * 布局键均未变的项直接复用旧对象，只有新进入窗口或内容更新的项才新建；
   * 若逐项引用与上次一致，则连同数组本身一并复用（下游零感知）。
   */
  const visiblePhotos = computed<VisiblePhoto[]>(() => {
    const list = photos.value;
    const cols = columns.value;
    const iw = itemWidth.value;
    const rh = rowHeight.value;
    if (list.length === 0 || winStart.value < 0 || winEnd.value <= winStart.value
      || cols <= 0 || iw <= 0 || rh <= 0) {
      visibleCacheMap = new Map();
      return EMPTY_VISIBLE;
    }
    const { items, cache } = buildVisibleWindow(
      visibleCacheMap, list,
      { startRow: winStart.value, endRow: winEnd.value },
      cols, iw, rh, GAP,
    );
    visibleCacheMap = cache;
    if (items.length === lastVisible.length && items.every((it, k) => it === lastVisible[k])) {
      return lastVisible;
    }
    lastVisible = items;
    return items;
  });

  /* ===== 滚动静默态（滚动性能第 3 铁律） =====
   *
   * 滚动是瞬时高负载窗口：滚动开始即冻结非必要工作，停止 scrollPerf.scrollSettleMs
   * 后解冻并统一追帧。
   *   - DOM：容器 data-scrolling（样式层冻结 hover 过渡与动画）；
   *     根节点 app-scrolling（idle-governance.css 暂停主界面氛围动画）；
   *   - 数据：scrollQuiet 门控解密取项与图片预热（见 decryptBatch / ensureVisible）；
   *   - 追帧：解冻时立即补齐可视区解密，并对运动方向下一行做图片预热解码。 */
  const scrollQuiet = ref(false);
  let quietSettleTimer: ReturnType<typeof setTimeout> | null = null;

  /** 同步静默态的 DOM 表现（容器 dataset + 根节点治理类） */
  const applyQuietDom = (on: boolean) => {
    const el = scrollRef.value;
    if (el) {
      if (on) el.dataset.scrolling = "";
      else delete el.dataset.scrolling;
    }
    document.documentElement.classList.toggle("app-scrolling", on);
  };

  const enterScrollQuiet = () => {
    if (!scrollQuiet.value) {
      scrollQuiet.value = true;
      applyQuietDom(true);
    }
    if (quietSettleTimer !== null) clearTimeout(quietSettleTimer);
    quietSettleTimer = setTimeout(() => {
      quietSettleTimer = null;
      exitScrollQuiet();
    }, scrollPerf.scrollSettleMs);
  };

  const exitScrollQuiet = () => {
    if (!scrollQuiet.value) return;
    scrollQuiet.value = false;
    applyQuietDom(false);
    // 追帧：停稳后立即补齐可视区解密（不等去抖窗口），并预热运动方向下一行
    void ensureVisiblePhotosDecrypted(visiblePhotos.value).catch((e) => {
      console.warn("[photo] 追帧解密批次异常", e);
    });
    warmNextRow();
  };

  /** 滚动事件：rAF 节流（同帧多次 scroll 合并为一次）。
   * 处理序：方向判定（供方向感知预取）→ 进入/续期静默态 → 行窗口量化更新
   * （只有跨行才写状态；同窗口内的像素级移动不产生任何重建）。 */
  const onScroll = rafThrottle(() => {
    const el = scrollRef.value;
    if (!el) return;
    const cur = el.scrollTop;
    if (cur > lastScrollPos) scrollDir.value = "down";
    else if (cur < lastScrollPos) scrollDir.value = "up";
    lastScrollPos = cur;
    enterScrollQuiet();
    const rh = rowHeight.value;
    if (rh > 0) {
      const next = computeRowWindow(cur, rh, viewportHeight.value, totalRows.value, BUFFER_ROWS);
      if (next.startRow !== winStart.value || next.endRow !== winEnd.value) {
        winStart.value = next.startRow;
        winEnd.value = next.endRow;
      }
    }
  });

  /** 同步行窗口（尺寸变化 / 总行数变化 / 布局变化后调用；像素滚动路径由 onScroll 驱动） */
  const syncWindow = () => {
    const el = scrollRef.value;
    if (!el) return;
    const rh = rowHeight.value;
    if (rh <= 0) return;
    const next = computeRowWindow(el.scrollTop, rh, viewportHeight.value, totalRows.value, BUFFER_ROWS);
    if (next.startRow !== winStart.value || next.endRow !== winEnd.value) {
      winStart.value = next.startRow;
      winEnd.value = next.endRow;
    }
  };

  /** 重新测量容器尺寸（列数 + 视口高度 + 容器宽度），随后同步行窗口
   *  （尺寸变化会改变行高与视口行数：滚动位置未变也可能跨窗口） */
  const updateLayout = () => {
    const el = scrollRef.value;
    if (!el) return;
    containerWidth.value = el.clientWidth;
    viewportHeight.value = el.clientHeight;
    columns.value = computeColumns(containerWidth.value);
    syncWindow();
  };

  /* 列表/布局变化 → 行窗口跟新（初次加载 totalRows 0→N 由此得到首个有效窗口；
     项宽变化会改变行高，同步后行窗口按新行高重算） */
  watch([() => totalRows.value, () => rowHeight.value], syncWindow);

  /** ResizeObserver 句柄（ref 包装便于 init/destroy 成对管理） */
  const resizeObserver = ref<ResizeObserver | null>(null);

  /** 初始化虚拟滚动布局：测量容器尺寸 + 启动 ResizeObserver
   *  入口文件 onMounted 调用，将生命周期管理收敛至数据层（单一职责）。
   *  滚动本身不做任何 JS 接管：滚轮走浏览器原生合成器路径（红线级结论：
   *  主线程插值 / scrollBy smooth 两代平滑实现均在快速滚轮下劣化滚动，
   *  已整体移除）。 */
  const initVirtualScroll = () => {
    updateLayout();
    if (scrollRef.value && typeof ResizeObserver !== "undefined") {
      resizeObserver.value = new ResizeObserver(() => updateLayout());
      resizeObserver.value.observe(scrollRef.value);
    }
  };

  /** 销毁虚拟滚动：释放 ResizeObserver / 静默态定时器与 DOM 标记
   *  入口文件 onUnmounted 调用，防止内存泄漏与遗留全局类 */
  const destroyVirtualScroll = () => {
    if (resizeObserver.value) {
      resizeObserver.value.disconnect();
      resizeObserver.value = null;
    }
    if (quietSettleTimer !== null) {
      clearTimeout(quietSettleTimer);
      quietSettleTimer = null;
    }
    if (scrollQuiet.value) {
      scrollQuiet.value = false;
      applyQuietDom(false);
    }
  };

  /* ===== 列表项定位索引（metaId → 数组下标） =====
   * 按需解密逐批更新条目，若每条都做 findIndex（O(n)），
   * 万张相册下大批量解密会退化为 O(n²)。此处以数组引用为失效键惰性重建。 */
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
   *   阶段1（loadPhotos）：列表 ID 来自类型盲索引（不解密记录），创建占位项
   *                        （id/metaId，名称由摘要缓存可选补齐），立即渲染列表骨架。
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

  /* 会话密钥失效联动：闲置销毁/登出后立即清空已解密内容并清除 worker 托管密钥，
   * 否则密钥销毁后本模块仍会继续解密照片，"闲置自动锁定"形同虚设。 */
  watch(() => moduleKeyReadyRef.value.photo, (ready) => {
    if (ready) return;
    decryptingMetaIds.clear();
    // 会话密钥失效：清除 worker 内模块密钥与派生缓存；已解密内容同步释放
    void lockModuleKey("photo").catch(() => { /* 锁定失败不阻断界面释放 */ });
    releaseThumbUrls();
    replaceShallowArray(photos, photos.value.map(p => ({
      id: p.id, metaId: p.metaId, name: p.name, thumb: "", size: "", height: 0,
      loaded: false, failed: false,
    })));
    setModuleCache("photos", toPhotoCacheEntries(photos.value));
    failedCount.value = 0;
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

  /** 解密单张照片完整元数据（含 chunkIds 回退），返回渲染字段或 null。
   *  prefetchedMetaB64 由 ensureVisiblePhotosDecrypted 批量预取传入（零 IPC）；
   *    未传入时单条批量获取（扫描缓存优先 + 并行 IPC 回退）。
   *  解密调度下沉 photo-crypto Worker 池，AEAD 与密钥派生再由
   *    RPC 转交 Tauri worker；渲染主线程不做载荷解码与哈希。
   *    池基础设施不可用时由桥自动回退主线程直连，两条路径结果一致。 */
  const decryptPhotoMeta = async (vid: number, prefetchedMetaB64?: string): Promise<DecryptedPhotoMeta | null> => {
    if (!moduleKeyReadyRef.value.photo) return null;
    // 优先消费批量预取结果；未预取则单条批量获取（扫描缓存优先 + IPC 回退）
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
      const { meta, thumbBytes } = await decryptMetaPreferWorker(metaB64, String(vid));

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
            thumbCipher, meta.wrappedFileKey, meta.fileHash, `${vid}:thumb`,
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
   *  解密失败保留占位并标记 failed，由上层聚合提示与重试入口处理。 */
  const decryptBatch = async (metaIds: number[]): Promise<void> => {
    if (metaIds.length === 0) return;
    for (const vid of metaIds) decryptingMetaIds.add(vid);
    try {
      // 批量预取所有待解密照片的 meta dataB64（扫描缓存优先，并行 IPC 回退）：
      //   一次批量预取（命中缓存零 IPC），并发池直接消费预取结果，仅做 CPU 解密
      // 异常收敛：批量预取失败不得中断整批（否则全部项停在未加载态且无失败标记），
      //   留空映射让 decryptPhotoMeta 逐条按需取数；单条仍失败则由占位项标 failed 并计数。
      let metaB64Map = new Map<number, string>();
      try {
        metaB64Map = await getRecordsDataB64Batch(metaIds);
      } catch (e) {
        console.warn("[decryptBatch] 批量预取失败，降级逐条取数", e);
      }

      let cursor = 0;
      const runNext = async (): Promise<void> => {
        while (cursor < metaIds.length) {
          // 暂停（用户取消首批解密）或滚动静默态：在项边界停止取新项，已解密结果保留。
          //   去重标记由 finally 统一释放，恢复时这些项可重新参与解密。
          //   静默态冻结的是"滚动期间新启动的解密片"，满足滚动性能第 3 铁律；
          //   滚动停止后由 exitScrollQuiet 的追帧脉冲重新驱动。
          if (decryptPaused.value || scrollQuiet.value) return;
          const vid = metaIds[cursor++];
          try {
            const data = await decryptPhotoMeta(vid, metaB64Map.get(vid));
            const pidx = entryIndexOf(vid);
            if (pidx >= 0) {
              if (data) {
                // 覆盖前释放旧缩略图 Blob URL（重试/重进模块都会走到这里）
                const old = photos.value[pidx];
                if (old?.thumb) revokeThumbUrl(old.thumb);
                // shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
                updateShallowItem(photos, pidx, { ...data, loaded: true, failed: false });
              } else {
                // 解密失败保留占位（临时原因可能是预取未命中、IPC 超时、密钥时序），
                // 标记 failed 供聚合提示与重试；绝不删除照片（删除是不可逆的 UI 操作）。
                updateShallowItem(photos, pidx, { failed: true });
              }
            }
          } catch (e) {
            // 单项异常不中断整批，但同样落失败占位（不静默）：由 recountFailures 聚合提示
            const pidx = entryIndexOf(vid);
            if (pidx >= 0 && !photos.value[pidx].loaded) {
              updateShallowItem(photos, pidx, { failed: true });
            }
            console.warn("[decryptBatch] 单项解密异常", { metaId: vid, reason: e instanceof Error ? e.message : "unknown" });
          }
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
    if (cols <= 0 || winStart.value < 0) return [];
    const rows = prefetchRowIndices(
      { startRow: winStart.value, endRow: winEnd.value },
      totalRows.value, scrollDir.value,
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
   * 用户取消后 decryptPaused 置位，本函数与滚动触发的批次一并停摆，
   * 由恢复入口重新驱动。
   * 滚动静默态（scrollQuiet）期间入口直接拒绝：滚动期不改动解密并发面，
   * 滚动停止后由 exitScrollQuiet 追帧脉冲补齐。 */
  const ensureVisiblePhotosDecrypted = async (visible: VisiblePhoto[]) => {
    if (!isTauri || !moduleKeyReadyRef.value.photo || decryptPaused.value || scrollQuiet.value) return;
    const toDecrypt: number[] = [];
    for (const vph of visible) {
      if (vph.loaded || !vph.metaId) continue;
      if (decryptingMetaIds.has(vph.metaId)) continue;
      toDecrypt.push(vph.metaId);
    }
    if (toDecrypt.length > 0) {
      loadStage.value = "decrypt";
      await decryptBatch(toDecrypt);
    }
    if (decryptPaused.value) return;
    // 可视区完成后按滚动方向补齐即将进入的行（额度复用同一并发池）
    if (!moduleKeyReadyRef.value.photo) return;
    const ahead = collectPrefetchMetaIds();
    if (ahead.length > 0) await decryptBatch(ahead);
  };

  /* ===== 图片预热解码（滚动性能第 3 铁律的"追帧补齐"） =====
   *
   * 缩略图是背景图（Blob URL），若进入视口才首次解码会出现"先空白后弹出"
   * 的一帧等待；本模块在滚动停止后的追帧脉冲里，对运动方向下一行的已加载项
   * 提前解码（Image.decode 只走解码不进 DOM，命中浏览器图片解码缓存），
   * 进入视口即就绪。滚动期间绝不预热（冻结非必要解码）；去重集合有界
   * （先进先出淘汰），防止万张相册长期驻留。 */
  const WARM_DECODE_MAX = 512;
  const warmedThumbs = new Set<string>();

  const warmThumbDecode = (thumb: string) => {
    const url = thumbUrlOf(thumb);
    if (!url || !url.startsWith("blob:")) return;
    if (warmedThumbs.has(url)) return;
    if (warmedThumbs.size >= WARM_DECODE_MAX) {
      // 先进先出淘汰（Set 迭代序即插入序），保持集合有界
      const first = warmedThumbs.values().next().value;
      if (first !== undefined) warmedThumbs.delete(first);
    }
    warmedThumbs.add(url);
    const img = new Image();
    img.decoding = "async";
    img.src = url;
    // 预热失败无害（进入视口时浏览器会正常解码），静默忽略
    void img.decode().catch(() => { /* 仅损失预热收益，无功能影响 */ });
  };

  /** 预热运动方向下一行的已加载缩略图（追帧脉冲调用；至多一行的量） */
  const warmNextRow = () => {
    if (scrollQuiet.value) return;
    const cols = columns.value;
    if (cols <= 0 || winStart.value < 0) return;
    const row = scrollDir.value === "down" ? winEnd.value : winStart.value - 1;
    if (row < 0 || row >= totalRows.value) return;
    for (let c = 0; c < cols; c++) {
      const ph = photos.value[row * cols + c];
      if (ph?.loaded && ph.thumb) warmThumbDecode(ph.thumb);
    }
  };

  /** 滚动触发的解密去抖：连续滚动期间合并批次收集，避免逐帧重复建批 */
  let decryptDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  const scheduleVisibleDecrypt = (v: VisiblePhoto[]) => {
    if (decryptDebounceTimer !== null) clearTimeout(decryptDebounceTimer);
    decryptDebounceTimer = setTimeout(() => {
      decryptDebounceTimer = null;
      void ensureVisiblePhotosDecrypted(v).catch((e) => {
        console.warn("[photo] 滚动解密批次异常", e);
      });
    }, SCROLL_DECRYPT_DEBOUNCE_MS);
  };

  /** 卸载时取消未触发的解密批次（防止卸载后写状态） */
  const cancelPendingDecrypt = () => {
    if (decryptDebounceTimer !== null) {
      clearTimeout(decryptDebounceTimer);
      decryptDebounceTimer = null;
    }
  };

  // 可视区渲染数组变化 → 去抖后触发按需解密。
  //    行窗口模型下数组引用保持稳定：只在"跨行 / 内容变化 / 布局变化"时触发，
  //    滚动帧绝大多数不再空跑本 watch（滚动性能第 1 铁律）。
  //    flush:'post' 确保 DOM 更新后执行，避免与响应式更新竞争。
  //    函数内部有 decryptingMetaIds 去重 + loaded 检查，重复触发安全。
  watch(visiblePhotos, (v) => {
    scheduleVisibleDecrypt(v);
  }, { flush: 'post' });

  /* ===== 加载照片列表（类型索引渲染列表，数据按需解密） ===== */

  /** 列表 ID 来源：权威类型盲索引优先，失败回退增量记录扫描 */
  type IdListSource = "typed" | "record";
  interface IdListResult {
    ok: boolean;
    ids: number[];
    source: IdListSource;
    /** true 表示走了回退路径，列表可能不含全部元数据 */
    degraded: boolean;
    error?: string;
  }

  /** 获取照片 meta 记录 ID 列表。
   *  权威路径：类型盲索引（ensureTypeIds），不读记录密文、跨重启稳定；
   *  不可用时回退增量记录扫描并标记降级。摘要缓存不参与 ID 过滤。
   *
   *  回退扫描的增量回调仅作为协作式取消的批次检查点
   *  （取消入口据此停止更重的后续阶段）。 */
  const loadIdList = async (): Promise<IdListResult> => {
    loadStage.value = "index";
    try {
      const ids = await ensureTypeIds(TYPE_PHOTO_META);
      return { ok: true, ids, source: "typed", degraded: false };
    } catch (e) {
      // 用户取消会令类型枚举代际失效：这是主动取消，不是索引故障，
      // 不得再启动更重的全量扫描。
      if (loadAbortRequested) {
        return {
          ok: true,
          ids: getRecordIdsByType(TYPE_PHOTO_META),
          source: "record",
          degraded: true,
        };
      }
      console.warn("[loadPhotos] 类型盲索引枚举失败，回退记录索引扫描", e);
    }
    // 用户已请求取消：回退扫描（更重）不得再启动，
    //   以当前缓存内容呈现列表（可能为空），由重试入口继续。
    if (loadAbortRequested) {
      return { ok: true, ids: getRecordIdsByType(TYPE_PHOTO_META), source: "record", degraded: false };
    }
    try {
      loadStage.value = "records";
      await ensureRecordScan(() => { /* 扫描批次仅作为协作式取消的检查点 */ });
      if (loadAbortRequested) {
        // 取消发生在记录扫描期间：已装载批次保留，不宣告"就绪"
        return { ok: true, ids: getRecordIdsByType(TYPE_PHOTO_META), source: "record", degraded: false };
      }
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

  /** 占位项构造：摘要缓存有名称则优先展示，解密后由真实名称覆盖 */
  const buildPlaceholder = (metaId: number): PhotoEntry => {
    const recordName = getSummaryRecord(metaId)?.name ?? "";
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
  const mergeIds = (ids: number[]): void => {
    const known = new Set<number>();
    for (const p of photos.value) {
      if (p.metaId) known.add(p.metaId);
    }
    const newIds = diffNewIds(ids, known);
    if (newIds.length > 0) {
      pushShallowItems(photos, newIds.map(id => buildPlaceholder(id)));
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
      mergeIds(list.ids);
      if (list.degraded && !loadAbortRequested) {
        // 取消场景保留取消提示（不得被降级提示覆盖）
        loadError.value = "类型索引不可用，已降级加载：列表可能不含完整信息";
      }
      recountFailures();
    } finally {
      photosLoading.value = false;
      // 阶段收口：扫描阶段结束即转为"待解密"阶段（取消入口据此区分语义）
      if (loadStage.value === "index" || loadStage.value === "records") {
        loadStage.value = "decrypt";
      }
      // 不在此处全量解密，由 watch(visiblePhotos) 按需解密可视区
      if (photos.value.length > 0) {
        setModuleCache("photos", toPhotoCacheEntries(photos.value));
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
      // 类型盲索引枚举的分页循环由代际令牌中止；缓存下次进入时重建。
      clearTypeIdCache(TYPE_PHOTO_META);
    }
    if (loadStage.value === "index" || loadStage.value === "records") {
      cancelRecordScan();
      loadStage.value = "cancelled";
      loadError.value = "加载已取消：列表可能不完整，可点击重试继续";
      return;
    }
    if (loadStage.value === "decrypt") {
      loadAbortRequested = false;   // 解密暂停不属于"取消装载"，重试入口无需复位
      decryptPaused.value = true;
      loadStage.value = "cancelled";
    }
  };

  /** 恢复加载（取消后的继续入口）：清暂停标志并重新驱动可视区解密 */
  const resumeLoad = (): void => {
    if (!decryptPaused.value) return;
    decryptPaused.value = false;
    loadStage.value = "idle";
    loadError.value = "";
    void ensureVisiblePhotosDecrypted(visiblePhotos.value).catch((e) => {
      console.warn("[photo] 恢复解密批次异常", e);
    });
  };

  /** 重试：清空失败标记与在途去重，重新装载列表并触发可视区解密 */
  const retryLoad = (): void => {
    loadError.value = "";
    failedCount.value = 0;
    decryptingMetaIds.clear();
    decryptPaused.value = false;
    removeFailedFlags();
    void loadPhotos().catch((e) => {
      console.warn("[photo] 重试装载异常", e);
      loadError.value = "照片列表加载失败，请重试";
    });
  };

  /** 清除失败标记（保留占位项，等待下一轮解密尝试）
   *  整体替换一次数组（单次 triggerRef），避免逐项 updateShallowItem 触发 N 次重渲染。 */
  const removeFailedFlags = () => {
    let changed = false;
    const next = photos.value.map((p) => {
      if (!p.failed) return p;
      changed = true;
      return { ...p, failed: false };
    });
    if (!changed) return;
    replaceShallowArray(photos, next);
    setModuleCache("photos", toPhotoCacheEntries(photos.value));
  };

  /**
   * 扫描全部照片元数据，返回内容层认证失败（确定损坏）的 metaId 列表。
   *
   * 判定口径：只把 `openRecord("photo","meta",…)` 的 AUTH 失败计为损坏；
   * 模块锁定 / IPC 超时 / 记录暂不可读等不可判定结果一律跳过，绝不误删。
   * 历史明文 JSON 布局由 damage.ts 统一豁免。
   */
  const scanDamagedPhotoMetaIds = async (): Promise<{
    checked: number;
    damaged: number[];
    inconclusive: number;
  }> => {
    if (!isTauri) return { checked: 0, damaged: [], inconclusive: 0 };
    if (!moduleKeyReadyRef.value.photo) {
      throw new Error("模块密钥已失效，请重新验证后重试");
    }

    const ids = photos.value
      .map((p) => p.metaId)
      .filter((id): id is number => typeof id === "number" && id > 0);

    /* 批次预取 + 有限并发解密：元数据记录较小，批量取数避免逐条 IPC；
     * 并发上限复用读取链路的 4，避免与可视区解密抢占通道。
     * 判定与删除口径集中在 damage.ts（纯函数，可单测）。 */
    return scanDamagedMetaIds(
      ids,
      (batch) => getRecordsDataB64Batch(batch),
      (payload) => openRecord("photo", "meta", payload),
    );
  };

  return {
    // ===== 状态 =====
    photos,
    isTauri,
    photosLoading,
    loadError,
    failedCount,
    // ===== 虚拟滚动（行窗口模型：对外只暴露渲染数组与滚动入口） =====
    scrollRef,
    totalHeight,
    visiblePhotos,
    onScroll,
    /** 生命周期收敛至数据层：入口文件 onMounted/onUnmounted 调用 */
    initVirtualScroll,
    destroyVirtualScroll,
    // ===== 按需解密 =====
    decryptPhotoMeta,
    cancelPendingDecrypt,
    // ===== 加载照片 =====
    loadPhotos,
    /** 损坏清理：扫描全部照片元数据，返回确定损坏的 metaId 列表 */
    scanDamagedPhotoMetaIds,
    /* 取消 / 重试 / 恢复：入口文件据此提供常驻恢复条（失败与暂停均可操作）。
       取消为协作式：已装载批次保留，重试入口可继续。 */
    retryLoad,
    cancelLoad,
    resumeLoad,
    /** 首批解密是否被用户暂停（表现层据此显示「继续解密」入口） */
    decryptPaused,
    /** 释放全部缩略图 Blob URL（模块卸载时由入口调用，防对象 URL 泄漏） */
    releaseThumbUrls,
    // ===== 密钥管理 =====
    ensurePhotoKey,
  };
}