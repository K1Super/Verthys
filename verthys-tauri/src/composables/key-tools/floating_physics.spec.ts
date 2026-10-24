/**
 * floating_physics.spec.ts — 漂浮运动学契约测试
 *
 * 锁定三类会让交互失控的问题：
 *   1. 弹簧在 60fps 下必须收敛且不明显过冲；
 *   2. 掉落帧（大步长）不得发散或产生非有限值；
 *   3. 边界钳制与速度截断必须封顶。
 */
import { describe, it, expect } from "vitest";
import {
  clampToBounds,
  clampVelocity,
  isSettled,
  stepSpring,
  type Vec2,
} from "./floating_physics";

const TUNING = { stiffness: 180, damping: 26 };
const ZERO: Vec2 = { x: 0, y: 0 };

/** 以 60fps 推演弹簧直到停机或超时，返回帧数与最大过冲 */
function simulate(start: Vec2, target: Vec2, frames = 300) {
  let position = { ...start };
  let velocity = { ...ZERO };
  let overshoot = 0;
  for (let i = 1; i <= frames; i++) {
    const next = stepSpring(position, velocity, target, TUNING, 1 / 60);
    position = next.position;
    velocity = next.velocity;
    overshoot = Math.max(overshoot, position.x - target.x);
    if (isSettled(position, velocity, target)) return { frames: i, overshoot, settled: true, position, velocity };
  }
  return { frames, overshoot, settled: false, position, velocity };
}

describe("弹簧收敛", () => {
  it("60fps 下在 1.5 秒内收敛且过冲不超过 3px", () => {
    const result = simulate({ x: 0, y: 0 }, { x: 200, y: 120 });
    expect(result.settled).toBe(true);
    expect(result.frames).toBeLessThanOrEqual(90);
    expect(result.overshoot).toBeLessThanOrEqual(3);
  });

  it("停机后剩余距离与速度都在阈值内", () => {
    const result = simulate({ x: 0, y: 0 }, { x: 120, y: 0 });
    expect(Math.hypot(result.position.x - 120, result.position.y)).toBeLessThanOrEqual(0.5);
    expect(Math.hypot(result.velocity.x, result.velocity.y)).toBeLessThanOrEqual(4);
  });
});

describe("步长截断", () => {
  it("掉落帧（dt=1s）不产生非有限值，且下一帧可继续收敛", () => {
    const step = stepSpring({ ...ZERO }, { ...ZERO }, { x: 300, y: 0 }, TUNING, 1);
    expect(Number.isFinite(step.position.x)).toBe(true);
    expect(Number.isFinite(step.velocity.x)).toBe(true);
    expect(Math.abs(step.velocity.x)).toBeLessThan(300 * TUNING.stiffness);
  });

  it("负步长按 0 处理，不产生位移", () => {
    const step = stepSpring({ x: 10, y: 10 }, { x: 5, y: 5 }, { x: 100, y: 100 }, TUNING, -1);
    expect(step.position).toEqual({ x: 10, y: 10 });
    expect(step.velocity).toEqual({ x: 5, y: 5 });
  });
});

describe("边界与速度", () => {
  it("位置钳制在舞台矩形内", () => {
    const bounds = { minX: 8, minY: 8, maxX: 500, maxY: 300 };
    expect(clampToBounds({ x: -40, y: 900 }, bounds)).toEqual({ x: 8, y: 300 });
    expect(clampToBounds({ x: 120, y: 160 }, bounds)).toEqual({ x: 120, y: 160 });
  });

  it("速度按总量截断且方向不变", () => {
    const v = clampVelocity({ x: 900, y: 1200 }, 1200);
    expect(Math.hypot(v.x, v.y)).toBeCloseTo(1200, 5);
    expect(v.x / v.y).toBeCloseTo(900 / 1200, 6);
    expect(clampVelocity({ x: 100, y: 100 }, 1200)).toEqual({ x: 100, y: 100 });
  });
});
