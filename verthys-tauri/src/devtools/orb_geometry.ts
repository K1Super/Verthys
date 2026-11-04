/*
 * devtools/orb_geometry.ts — 悬浮球几何与位置持久化纯函数
 *
 * 不访问 DOM、不持有状态：边界钳制、边缘吸附目标与持久化解析可独立单测，
 * 避免把布局判断混进指针事件处理。
 */
export interface OrbPosition {
  x: number;
  y: number;
}

export interface OrbViewport {
  width: number;
  height: number;
}

/** 球体边长（px） */
export const ORB_SIZE = 56;
/** 距离视口边缘的最小留白（px） */
export const ORB_MARGIN = 16;
/** 顶部留白：避开 40px 窗控拖拽条（px） */
export const ORB_TOP_INSET = 48;
/** 位置持久化键 */
export const ORB_STORAGE_KEY = "Verthys:devtools:orb";

const clampValue = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, value));

/** 默认停靠右下角；窗口尺寸变化后仍会被钳制回安全区 */
export function defaultOrbPosition(viewport: OrbViewport): OrbPosition {
  return clampOrbPosition(
    {
      x: viewport.width - ORB_SIZE - 20,
      y: viewport.height - ORB_SIZE - 20,
    },
    viewport,
  );
}

/** 将球体左上角坐标钳制在视口安全区内，避免拖出窗口或压住窗控条 */
export function clampOrbPosition(
  position: OrbPosition,
  viewport: OrbViewport,
): OrbPosition {
  const maxX = Math.max(ORB_MARGIN, viewport.width - ORB_SIZE - ORB_MARGIN);
  const maxY = Math.max(ORB_TOP_INSET, viewport.height - ORB_SIZE - ORB_MARGIN);
  return {
    x: clampValue(position.x, ORB_MARGIN, maxX),
    y: clampValue(position.y, ORB_TOP_INSET, maxY),
  };
}

/** 松手后吸附到最近的水平边缘，返回目标 x 坐标 */
export function nearestEdgeX(position: OrbPosition, viewport: OrbViewport): number {
  const center = position.x + ORB_SIZE / 2;
  return center < viewport.width / 2
    ? ORB_MARGIN
    : Math.max(ORB_MARGIN, viewport.width - ORB_SIZE - ORB_MARGIN);
}

/** 解析持久化位置；损坏、缺字段或非有限数值一律回落默认位置 */
export function parseStoredOrbPosition(
  raw: string | null,
  viewport: OrbViewport,
): OrbPosition {
  if (!raw) return defaultOrbPosition(viewport);
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) {
      return defaultOrbPosition(viewport);
    }
    const record = parsed as Record<string, unknown>;
    if (
      typeof record.x !== "number" ||
      typeof record.y !== "number" ||
      !Number.isFinite(record.x) ||
      !Number.isFinite(record.y)
    ) {
      return defaultOrbPosition(viewport);
    }
    return clampOrbPosition({ x: record.x, y: record.y }, viewport);
  } catch {
    return defaultOrbPosition(viewport);
  }
}

/** 序列化位置；取整避免亚像素坐标在多次拖拽后累积漂移 */
export function serializeOrbPosition(position: OrbPosition): string {
  return JSON.stringify({
    x: Math.round(position.x),
    y: Math.round(position.y),
  });
}
