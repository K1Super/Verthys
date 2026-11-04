/*
 * orb_geometry.spec.ts — 悬浮球几何与持久化解析契约
 *
 * 覆盖：默认停靠、越界钳制、边缘吸附目标、损坏持久化输入回落。
 */
import { describe, expect, it } from "vitest";
import {
  ORB_MARGIN,
  ORB_SIZE,
  ORB_TOP_INSET,
  clampOrbPosition,
  defaultOrbPosition,
  nearestEdgeX,
  parseStoredOrbPosition,
  serializeOrbPosition,
} from "./orb_geometry";

const viewport = { width: 1280, height: 800 };

describe("悬浮球几何", () => {
  it("默认停靠右下角并留出边距", () => {
    const position = defaultOrbPosition(viewport);

    expect(position.x).toBe(viewport.width - ORB_SIZE - 20);
    expect(position.y).toBe(viewport.height - ORB_SIZE - 20);
  });

  it("越界坐标钳制在安全区内", () => {
    const position = clampOrbPosition({ x: 2000, y: 1000 }, viewport);

    expect(position.x).toBe(viewport.width - ORB_SIZE - ORB_MARGIN);
    expect(position.y).toBe(viewport.height - ORB_SIZE - ORB_MARGIN);
  });

  it("负坐标钳制到最小安全边距与顶部留白", () => {
    const position = clampOrbPosition({ x: -40, y: -20 }, viewport);

    expect(position.x).toBe(ORB_MARGIN);
    expect(position.y).toBe(ORB_TOP_INSET);
  });

  it("按球体中心吸附到最近的水平边缘", () => {
    expect(nearestEdgeX({ x: 20, y: 100 }, viewport)).toBe(ORB_MARGIN);
    expect(nearestEdgeX({ x: 1000, y: 100 }, viewport)).toBe(
      viewport.width - ORB_SIZE - ORB_MARGIN,
    );
  });
});

describe("位置持久化解析", () => {
  it("空值与损坏 JSON 回落默认位置", () => {
    expect(parseStoredOrbPosition(null, viewport)).toEqual(defaultOrbPosition(viewport));
    expect(parseStoredOrbPosition("{", viewport)).toEqual(defaultOrbPosition(viewport));
  });

  it("缺字段或非有限数值回落默认位置", () => {
    expect(parseStoredOrbPosition('{"x":10}', viewport)).toEqual(
      defaultOrbPosition(viewport),
    );
    expect(parseStoredOrbPosition('{"x":null,"y":null}', viewport)).toEqual(
      defaultOrbPosition(viewport),
    );
  });

  it("合法坐标读取后仍按当前视口钳制", () => {
    const position = parseStoredOrbPosition('{"x":5000,"y":9000}', viewport);

    expect(position.x).toBe(viewport.width - ORB_SIZE - ORB_MARGIN);
    expect(position.y).toBe(viewport.height - ORB_SIZE - ORB_MARGIN);
  });

  it("序列化取整，避免亚像素累积", () => {
    expect(serializeOrbPosition({ x: 12.4, y: 30.6 })).toBe('{"x":12,"y":31}');
  });
});
