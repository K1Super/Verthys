/**
 * visible-window.spec.ts — 行窗口模型纯函数单元测试
 *
 * 覆盖滚动性能第 1 铁律的两个核心保证：
 *   - computeRowWindow：像素滚动量 → 行窗口的量化与边界钳制
 *     （同窗口内的像素级移动不得产生任何新窗口）；
 *   - buildVisibleWindow：渲染对象复用（源引用 + 布局键失效判定），
 *     跨行时窗口交集项必须原样复用（否则滚动帧退化为 O(可见项) 重建），
 *     内容更新只重建受影响项；位置坐标整数量化（合成器整数吸附）。
 */
import { describe, it, expect } from "vitest";
import {
  computeRowWindow,
  buildVisibleWindow,
  type VisibleCacheEntry,
  type RowWindow,
} from "./visible-window";
import type { PhotoEntry } from "./types";

/** 构造一条占位条目（引用身份即全部语义，字段值仅供构造） */
function makeEntry(i: number): PhotoEntry {
  return {
    id: i,
    metaId: i,
    name: `photo-${i}`,
    thumb: "",
    size: "",
    height: 0,
    loaded: false,
    failed: false,
  };
}

function makeList(n: number): PhotoEntry[] {
  return Array.from({ length: n }, (_, i) => makeEntry(i));
}

const EMPTY_CACHE: ReadonlyMap<number, VisibleCacheEntry> = new Map();

describe("computeRowWindow", () => {
  it("常规位置：可视行上下各扩 buffer 行，且不越过边界", () => {
    // rowH=100, vh=800, scrollTop=1000 → first=10, last=18；buffer 4 → [6, 22)
    expect(computeRowWindow(1000, 100, 800, 100, 4)).toEqual({ startRow: 6, endRow: 22 });
  });

  it("顶部：startRow 钳制为 0（上半 buffer 不越界到负行）", () => {
    expect(computeRowWindow(0, 100, 800, 100, 4)).toEqual({ startRow: 0, endRow: 12 });
  });

  it("底部：endRow 钳制为总行数", () => {
    // first=98, last=106, +4 → 110 → 钳制 100
    expect(computeRowWindow(9800, 100, 800, 100, 4)).toEqual({ startRow: 94, endRow: 100 });
  });

  it("同一行内的像素移动产生完全相同的窗口（滚动路径零状态变化的前提）", () => {
    // 视口顶 1010→1030 都在行 10 内；视口底 1810→1830 都在行 18 内
    const a = computeRowWindow(1010, 100, 800, 100, 4);
    const b = computeRowWindow(1030, 100, 800, 100, 4);
    expect(a).toEqual(b);
  });

  it("防御：行高或总行数无效时返回空窗口", () => {
    expect(computeRowWindow(500, 0, 800, 100, 4)).toEqual({ startRow: 0, endRow: 0 });
    expect(computeRowWindow(500, 100, 800, 0, 4)).toEqual({ startRow: 0, endRow: 0 });
  });

  it("负 scrollTop 视为 0（越界弹性滚动等异常输入不产生负行）", () => {
    expect(computeRowWindow(-50, 100, 800, 100, 4)).toEqual({ startRow: 0, endRow: 12 });
  });
});

describe("buildVisibleWindow", () => {
  const WIN: RowWindow = { startRow: 0, endRow: 2 };

  it("首建：按行优先序生成全部项，坐标整数量化，_style 与坐标一致", () => {
    const { items, cache } = buildVisibleWindow(EMPTY_CACHE, makeList(10), WIN, 3, 150.5, 162.5, 12);
    expect(items).toHaveLength(6);
    expect(cache.size).toBe(6);
    // 列坐标：col × (itemWidth + gap)，取整（150.5+12=162.5 → 0 / 162.5→163 / 325→325）
    expect(items[1]._left).toBe(163);
    expect(items[1]._top).toBe(0);
    // 行坐标：row × rowHeight（162.5 → 0 / 163）
    expect(items[3]._top).toBe(163);
    expect(items[0]._style).toBe("transform: translate3d(0px, 0px, 0); width: 150.5px; height: 150.5px");
    // 源字段透传
    expect(items[2].name).toBe("photo-2");
  });

  it("引用稳定：窗口与数据均未变时，全部项原样复用（===）", () => {
    const list = makeList(10);
    const first = buildVisibleWindow(EMPTY_CACHE, list, WIN, 3, 150, 162, 12);
    const second = buildVisibleWindow(first.cache, list, WIN, 3, 150, 162, 12);
    expect(second.items).toHaveLength(first.items.length);
    second.items.forEach((it, k) => expect(it).toBe(first.items[k]));
  });

  it("内容更新只重建受影响项：其余项保持复用", () => {
    const list = makeList(10);
    const first = buildVisibleWindow(EMPTY_CACHE, list, WIN, 3, 150, 162, 12);
    const next = [...list];
    next[1] = { ...list[1], loaded: true, thumb: "url(\"blob:thumb-1\")" };
    const second = buildVisibleWindow(first.cache, next, WIN, 3, 150, 162, 12);
    expect(second.items[1]).not.toBe(first.items[1]);
    expect(second.items[1].thumb).toBe("url(\"blob:thumb-1\")");
    expect(second.items[0]).toBe(first.items[0]);
    expect(second.items[2]).toBe(first.items[2]);
  });

  it("跨行：窗口交集内的项整体复用，仅新进入行新建（滚动主路径的核心保证）", () => {
    const list = makeList(30);
    const first = buildVisibleWindow(EMPTY_CACHE, list, { startRow: 0, endRow: 2 }, 3, 150, 162, 12);
    const second = buildVisibleWindow(first.cache, list, { startRow: 1, endRow: 3 }, 3, 150, 162, 12);
    // [0,2) → [1,3)：下标 3..5 是交集，必须复用；下标 6..8 是新进入
    expect(second.items).toHaveLength(6);
    expect(second.items[0]).toBe(first.items[3]);
    expect(second.items[1]).toBe(first.items[4]);
    expect(second.items[2]).toBe(first.items[5]);
    expect(second.items[3]).not.toBe(first.items[3]);
    // 复用项坐标不变（文档坐标静态——滚动不改变任何项的 _left/_top）
    expect(second.items[0]._top).toBe(first.items[3]._top);
  });

  it("布局参数变化：项宽变化 → 布局键失效，全部重建", () => {
    const list = makeList(10);
    const first = buildVisibleWindow(EMPTY_CACHE, list, WIN, 3, 150, 162, 12);
    const second = buildVisibleWindow(first.cache, list, WIN, 3, 160, 172, 12);
    second.items.forEach((it, k) => expect(it).not.toBe(first.items[k]));
  });

  it("尾窗钳制：endRow 超过总项数时按列表长度截断", () => {
    const { items } = buildVisibleWindow(EMPTY_CACHE, makeList(4), { startRow: 1, endRow: 3 }, 3, 150, 162, 12);
    expect(items).toHaveLength(1);
    expect(items[0].id).toBe(3);
  });

  it("防御：列数或项宽无效时返回空", () => {
    expect(buildVisibleWindow(EMPTY_CACHE, makeList(10), WIN, 0, 150, 162, 12).items).toHaveLength(0);
    expect(buildVisibleWindow(EMPTY_CACHE, makeList(10), WIN, 3, 0, 162, 12).items).toHaveLength(0);
  });
});