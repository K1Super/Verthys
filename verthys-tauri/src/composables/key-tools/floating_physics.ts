/**
 * key-tools/floating_physics.ts — 漂浮卡片运动学纯函数
 *
 * 职责：弹簧积分、边界钳制与静止判定。
 * 不访问 DOM、不持有状态，便于用确定性输入直接单测。
 *
 * 关键约束：
 * - 单帧步长钳制在 1/30s 内：掉帧时半隐式欧拉会放大速度，必须截断。
 * - 所有量均为视觉量，不参与任何安全语义。
 */

/** 二维向量（舞台坐标，单位为像素或像素每秒） */
export interface Vec2 {
  x: number;
  y: number;
}

/** 弹簧参数：刚度与阻尼（阻尼比应接近临界，避免持续振荡） */
export interface SpringTuning {
  stiffness: number;
  damping: number;
}

/** 卡片允许占据的舞台矩形（左上空缺由卡片尺寸与内边距决定） */
export interface Bounds {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

const clamp = (value: number, low: number, high: number): number => Math.min(high, Math.max(low, value));

/** 单帧最大步长（秒）：60fps 一帧的 0.5 倍，掉帧时截断以保持数值稳定 */
const MAX_STEP_SECONDS = 1 / 30;

/**
 * 把位置收敛到舞台允许范围内。
 *
 * @param position 待收敛位置
 * @param bounds 允许矩形（已含卡片尺寸扣除）
 * @returns 新位置对象，不修改入参
 */
export function clampToBounds(position: Vec2, bounds: Bounds): Vec2 {
  return {
    x: clamp(position.x, bounds.minX, bounds.maxX),
    y: clamp(position.y, bounds.minY, bounds.maxY),
  };
}

/**
 * 把速度收敛到给定上限，用于释放瞬间的惯性截断。
 *
 * @param velocity 速度向量（px/s）
 * @param maxSpeed 允许的最大速度（px/s）
 * @returns 新速度对象；未超限时返回拷贝
 */
export function clampVelocity(velocity: Vec2, maxSpeed: number): Vec2 {
  const speed = Math.hypot(velocity.x, velocity.y);
  if (speed <= maxSpeed || speed === 0) return { x: velocity.x, y: velocity.y };
  const ratio = maxSpeed / speed;
  return { x: velocity.x * ratio, y: velocity.y * ratio };
}

/**
 * 半隐式欧拉积分一帧弹簧。
 *
 * 采用速度先更新的半隐式形式：比显式欧拉稳定，配合步长截断即可在 60fps
 * 与掉帧场景下都不发散。弹簧只服务视觉跟随，不做精确物理模拟。
 *
 * @param position 当前位移
 * @param velocity 当前速度（px/s）
 * @param target 目标位移
 * @param tuning 刚度与阻尼
 * @param dt 帧间隔（秒），内部钳制到 1/30
 * @returns 下一帧的位置与速度
 */
export function stepSpring(
  position: Vec2,
  velocity: Vec2,
  target: Vec2,
  tuning: SpringTuning,
  dt: number,
): { position: Vec2; velocity: Vec2 } {
  const step = clamp(dt, 0, MAX_STEP_SECONDS);
  const ax = (target.x - position.x) * tuning.stiffness - velocity.x * tuning.damping;
  const ay = (target.y - position.y) * tuning.stiffness - velocity.y * tuning.damping;
  const vx = velocity.x + ax * step;
  const vy = velocity.y + ay * step;
  return {
    position: { x: position.x + vx * step, y: position.y + vy * step },
    velocity: { x: vx, y: vy },
  };
}

/**
 * 判定弹簧是否已进入停机阈值。
 *
 * @param position 当前位移
 * @param velocity 当前速度
 * @param target 目标位移
 * @param distanceEps 允许的剩余距离（像素）
 * @param speedEps 允许的剩余速度（px/s）
 * @returns 两项同时达标时为真
 */
export function isSettled(
  position: Vec2,
  velocity: Vec2,
  target: Vec2,
  distanceEps = 0.5,
  speedEps = 4,
): boolean {
  return Math.hypot(target.x - position.x, target.y - position.y) <= distanceEps
    && Math.hypot(velocity.x, velocity.y) <= speedEps;
}

