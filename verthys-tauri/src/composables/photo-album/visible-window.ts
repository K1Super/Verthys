/**
 * photo-album/visible-window.ts — 虚拟滚动行窗口模型（纯函数）
 *
 * 职责：把"滚动位置的像素级变化"折算为"行窗口变化"，并把窗口内容构建为
 * 引用稳定的渲染数组。行窗口模型是滚动性能的第一铁律落点——
 * 滚动期间主线程只允许做 O(行窗口变化) 的工作，不做 O(可见项) 的重建。
 *
 * 两个函数：
 *   - computeRowWindow：像素滚动量 → 含缓冲区的行窗口（纯计算，无副作用）。
 *     同窗口内的像素级移动不再产生任何新状态，杜绝"每帧全量重建"。
 *   - buildVisibleWindow：给定窗口与列表数据，按"源条目引用 + 布局参数"
 *     复用未变化的渲染对象。背景：条目在文档坐标系中的位置由数组下标唯一
 *     决定（_top = 行号 × 行高），滚动不改变任何项的坐标——真正变化的只有
 *     窗口边界。因此跨行时窗口交集内的对象可以整体复用，只有新进入的行
 *     才新建对象；配合模板 :key，Vue 的 diff 在绝大多数帧直接短路。
 *
 * Why 独立成模块：usePhotoData 承担状态与副作用（解密/静默态/平滑器），
 * 本模块只做纯数据变换，可在 node 环境直接单测边界与引用稳定性。
 */
import type { PhotoEntry, VisiblePhoto } from "./types";

/** 行窗口（含缓冲区的渲染边界，行号区间为 [startRow, endRow)） */
export interface RowWindow {
  startRow: number;
  endRow: number;
}

/** 渲染项缓存条目：按数组下标索引，携带源条目引用与布局键用于失效判定 */
export interface VisibleCacheEntry {
  /** 生成该渲染对象时的源条目引用（解密更新会替换引用 → 该判定自动失效） */
  source: PhotoEntry;
  /** 渲染对象（_left/_top/_style 已按生成时布局参数固化） */
  item: VisiblePhoto;
  /** 布局键（列数 + 项宽）：布局参数变化时全部重建 */
  layoutKey: string;
}

/**
 * 由像素滚动量计算含缓冲区的行窗口。
 *
 * 行号为 [startRow, endRow)，endRow 不含；两端做边界钳制
 * （startRow ≥ 0，endRow ≤ totalRows）。rowHeight 或 totalRows 无效时
 * 返回空窗口（防御未完成布局测量的初始化窗口期）。
 */
export function computeRowWindow(
  scrollTop: number,
  rowHeight: number,
  viewportHeight: number,
  totalRows: number,
  bufferRows: number,
): RowWindow {
  if (rowHeight <= 0 || totalRows <= 0) return { startRow: 0, endRow: 0 };
  const st = Math.max(0, scrollTop);
  const first = Math.floor(st / rowHeight);
  const last = Math.ceil((st + viewportHeight) / rowHeight);
  return {
    startRow: Math.max(0, first - bufferRows),
    endRow: Math.min(totalRows, last + bufferRows),
  };
}

/** 构建布局键（列数 + 项宽共同决定项的坐标与尺寸） */
function layoutKeyOf(columns: number, itemWidth: number): string {
  return `${columns}:${itemWidth}`;
}

/**
 * 构建窗口渲染数组：未变化的项复用旧对象，仅新进入/内容变化的项新建。
 *
 * 复用判定按数组下标查缓存：命中且"源条目引用相同 + 布局键相同"才复用
 * （解密就地更新会替换源引用，从而触发该项重建，其余项不受影响）。
 *
 * 位置坐标取整（translate3d 的 _left/_top 为整数像素）：合成器对整数像素
 * 做吸附，杜绝分数像素偏移导致位图/文字走重采样路径；宽度保留原值，
 * 避免累计舍入改变卡片尺寸。
 *
 * @param prev 上一轮缓存（下标 → 缓存条目）
 * @param photos 当前列表（不可变数组，元素替换即视为该条内容变化）
 * @param win 行窗口
 * @param columns 列数
 * @param itemWidth 项宽（= 项高，1:1 缩略图）
 * @param rowHeight 行高（项宽 + gap）
 * @param gap 列间距
 */
export function buildVisibleWindow(
  prev: ReadonlyMap<number, VisibleCacheEntry>,
  photos: readonly PhotoEntry[],
  win: RowWindow,
  columns: number,
  itemWidth: number,
  rowHeight: number,
  gap: number,
): { items: VisiblePhoto[]; cache: Map<number, VisibleCacheEntry> } {
  const items: VisiblePhoto[] = [];
  const cache = new Map<number, VisibleCacheEntry>();
  if (columns <= 0 || itemWidth <= 0 || rowHeight <= 0) return { items, cache };

  const layoutKey = layoutKeyOf(columns, itemWidth);
  const start = win.startRow * columns;
  const end = Math.min(photos.length, win.endRow * columns);

  for (let i = start; i < end; i++) {
    const src = photos[i];
    const hit = prev.get(i);
    if (hit && hit.source === src && hit.layoutKey === layoutKey) {
      items.push(hit.item);
      cache.set(i, hit);
      continue;
    }
    const row = Math.floor(i / columns);
    const col = i % columns;
    const left = Math.round(col * (itemWidth + gap));
    const top = Math.round(row * rowHeight);
    const item: VisiblePhoto = {
      ...src,
      _left: left,
      _top: top,
      _style: `transform: translate3d(${left}px, ${top}px, 0); width: ${itemWidth}px; height: ${itemWidth}px`,
    };
    cache.set(i, { source: src, item, layoutKey });
    items.push(item);
  }
  return { items, cache };
}