/**
 * useVerifyRhythm.spec.ts — 验证进度感知层单元测试
 *
 * 通过注入假时钟与假帧调度器实现确定性测试：
 * 不依赖真实 rAF / performance.now，动画推进由 frame() 显式驱动。
 *
 * 覆盖：状态机全路径、平滑与软上限、单调不变量、失败冻结与降级、
 * 收束中断、失败重试复位、并发启动单例锁、极快成功策略、
 * 直通降级（reduced-motion）、真实进度回退、输入越界钳制。
 */
import { describe, it, expect, vi } from 'vitest';
import {
  useVerifyRhythm,
  DEFAULT_VERIFY_RHYTHM_CONFIG,
  type VerifyRhythmEnv,
} from './useVerifyRhythm';

/** 单帧推进时长（ms），与常见 60Hz 帧间隔一致 */
const FRAME_MS = 16;

interface FakeEnv {
  env: VerifyRhythmEnv;
  report: ReturnType<typeof vi.fn>;
  /** 推进 n 帧（每帧 frameMs），依次执行已排队的动画回调 */
  frame: (count?: number, frameMs?: number) => void;
  /** 只拨动时钟不推帧（模拟后台标签页挂起后切回） */
  pass: (ms: number) => void;
}

function createFakeEnv(opts: { reducedMotion?: boolean } = {}): FakeEnv {
  let nowMs = 0;
  const frames = new Map<number, () => void>();
  let nextId = 1;
  const report = vi.fn<(event: unknown) => void>();
  const env: VerifyRhythmEnv = {
    now: () => nowMs,
    scheduleFrame: (cb) => {
      const id = nextId++;
      frames.set(id, cb);
      return id;
    },
    cancelFrame: (id) => {
      frames.delete(id);
    },
    prefersReducedMotion: () => opts.reducedMotion ?? false,
    report: (event) => report(event),
  };
  const frame = (count = 1, frameMs = FRAME_MS): void => {
    for (let i = 0; i < count; i++) {
      nowMs += frameMs;
      const pending = [...frames.values()];
      frames.clear();
      for (const cb of pending) cb();
    }
  };
  return { env, report, frame, pass: (ms: number) => (nowMs += ms) };
}

/** 查找某类遥测事件的最近一次记录 */
function findEvent(report: ReturnType<typeof vi.fn>, kind: string): unknown {
  for (const call of report.mock.calls) {
    const event = call[0] as { kind: string };
    if (event.kind === kind) return event;
  }
  return undefined;
}

const softCeiling = DEFAULT_VERIFY_RHYTHM_CONFIG.softCeiling;

describe('useVerifyRhythm — 状态机与成功收束', () => {
  it('启动进入 ACTIVE，seal 经 SEALING 收束补满 100% 后转 DONE，waitForComplete 由完成事件驱动', async () => {
    const { env, report, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    expect(rhythm.phase.value).toBe('IDLE');
    rhythm.start();
    expect(rhythm.phase.value).toBe('ACTIVE');
    expect(rhythm.visualValue.value).toBe(0);

    rhythm.pushRealProgress(0.4);
    frame(20); // 320ms：超过极快成功阈值，走完整收束路径
    const sealStartValue = rhythm.visualValue.value;
    expect(sealStartValue).toBeGreaterThan(0);

    let resolved = false;
    const complete = rhythm.waitForComplete().then(() => {
      resolved = true;
    });
    rhythm.seal();
    rhythm.seal(); // 幂等：SEALING 中重复 seal 忽略
    expect(rhythm.phase.value).toBe('SEALING');

    // 收束前半程（240ms < 520ms）尚未完成，视觉值单调不减且未到 1
    frame(15);
    expect(resolved).toBe(false);
    expect(rhythm.visualValue.value).toBeGreaterThanOrEqual(sealStartValue);
    expect(rhythm.visualValue.value).toBeLessThan(1);

    // 继续推进越过 sealDuration（520ms）
    frame(60);
    await complete;
    expect(resolved).toBe(true);
    expect(rhythm.phase.value).toBe('DONE');
    expect(rhythm.visualValue.value).toBe(1);
    expect(rhythm.visualPercent.value).toBe(100);

    const done = findEvent(report, 'done') as { fastSuccess: boolean; sealMs: number };
    expect(done).toBeDefined();
    expect(done.fastSuccess).toBe(false);
    expect(done.sealMs).toBeGreaterThanOrEqual(DEFAULT_VERIFY_RHYTHM_CONFIG.sealDuration);
  });

  it('极快成功（skipAnimation）：跳过收束动画，立即补满并触发完成事件', async () => {
    const { env, report, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    const complete = rhythm.waitForComplete();
    rhythm.seal(); // totalMs = 0 < fastSuccessThreshold

    expect(rhythm.phase.value).toBe('DONE');
    expect(rhythm.visualValue.value).toBe(1);
    await expect(complete).resolves.toBeUndefined();

    const done = findEvent(report, 'done') as { fastSuccess: boolean };
    expect(done.fastSuccess).toBe(true);

    // DONE 后无动画帧在跑：推帧不产生任何变化
    const before = rhythm.visualValue.value;
    frame(5);
    expect(rhythm.visualValue.value).toBe(before);
  });

  it('极快成功（minStartPoint）：收束起点上抬至 minSealStart 再执行完整收束', async () => {
    const { env, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({
      env,
      config: { fastSuccessStrategy: 'minStartPoint', minSealStart: 0.35, fastSuccessThreshold: 50 },
    });

    rhythm.start();
    frame(10); // 160ms > 50ms 阈值，走 minStartPoint 收束
    rhythm.seal();
    expect(rhythm.phase.value).toBe('SEALING');
    frame(1);
    expect(rhythm.visualValue.value).toBeGreaterThanOrEqual(0.35);
    frame(60);
    expect(rhythm.phase.value).toBe('DONE');
    expect(rhythm.visualValue.value).toBe(1);
  });
});

describe('useVerifyRhythm — 活跃期平滑与不变量', () => {
  it('真实进度离散跳变被吸收为连续变化：单调不减、单帧增量有界、ACTIVE 期严格小于软上限', () => {
    const { env, report, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    rhythm.pushRealProgress(1); // 模拟后端直达 100%，但成功事件未到

    expect(findEvent(report, 'protocol-anomaly')).toBeDefined();

    let prev = 0;
    let maxDelta = 0;
    for (let i = 0; i < 30; i++) {
      frame(1);
      const v = rhythm.visualValue.value;
      expect(v).toBeGreaterThanOrEqual(prev); // 单调不减
      maxDelta = Math.max(maxDelta, v - prev);
      prev = v;
    }
    // 指数趋近平滑：单帧增量有界，无可见瞬跳
    expect(maxDelta).toBeLessThan(0.1);

    // 持续推进趋近软上限，但 ACTIVE 阶段视觉值严格小于 softCeiling（更严格于 <1）
    frame(30);
    expect(rhythm.visualValue.value).toBeGreaterThan(0.9);
    expect(rhythm.visualValue.value).toBeLessThan(softCeiling);
  });

  it('真实进度回退被忽略：视觉值保持单调不减并记录回归遥测', () => {
    const { env, report, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    rhythm.pushRealProgress(0.9);
    frame(30);
    const before = rhythm.visualValue.value;

    rhythm.pushRealProgress(0.2); // 协议异常回退
    expect(findEvent(report, 'real-progress-regression')).toBeDefined();
    frame(10);
    expect(rhythm.visualValue.value).toBeGreaterThanOrEqual(before);
  });

  it('后台挂起切回（dt 钳制）：视觉值不会瞬间跳满', () => {
    const { env, frame, pass } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    rhythm.pushRealProgress(1);
    frame(1);
    const before = rhythm.visualValue.value;

    pass(5000); // 模拟后台标签页挂起 5s 后切回
    frame(1); // 该帧 dt 被钳制到 50ms
    const delta = rhythm.visualValue.value - before;
    expect(delta).toBeLessThan(0.3);
    expect(rhythm.visualValue.value).toBeLessThanOrEqual(softCeiling);
  });

  it('帧率无关：60Hz 与 120Hz 推进同一时刻视觉值偏差 < 1%', () => {
    // 单例锁约束下两个实例不能同时处于活跃期，故以相同输入序列
    // 分别在 16ms（60Hz）与 8ms（120Hz）帧长下顺序运行，逐里程碑对比
    const runAt = (frameMs: number): number[] => {
      const { env, frame } = createFakeEnv();
      const rhythm = useVerifyRhythm({ env });
      rhythm.start();
      rhythm.pushRealProgress(0.85);
      const milestones = [160, 480, 800, 1120, 1600];
      const samples: number[] = [];
      let t = 0;
      for (const m of milestones) {
        while (t < m) {
          frame(1, frameMs);
          t += frameMs;
        }
        samples.push(rhythm.visualValue.value);
      }
      rhythm.dispose();
      return samples;
    };

    const at60Hz = runAt(16);
    const at120Hz = runAt(8);
    expect(at60Hz.length).toBe(at120Hz.length);
    at60Hz.forEach((v, i) => {
      expect(Math.abs(v - at120Hz[i])).toBeLessThan(0.01);
    });
  });

  it('输入越界钳制：超范围数值被钳制处理并记录遥测，NaN 被忽略', () => {
    const { env, report, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    rhythm.pushRealProgress(1.5);
    expect(findEvent(report, 'input-out-of-range')).toBeDefined();
    rhythm.pushRealProgress(Number.NaN); // 忽略，不崩溃
    frame(10);
    expect(rhythm.visualValue.value).toBeLessThanOrEqual(softCeiling);
  });
});

describe('useVerifyRhythm — 失败冻结与中断', () => {
  it('halt：视觉值冻结不回弹、进入降级标识、错误最小展示时长可等待、seal/halt 幂等', async () => {
    const { env, report, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env, config: { errorMinDuration: 30 } });

    rhythm.start();
    rhythm.pushRealProgress(0.5);
    frame(10);
    rhythm.halt();

    expect(rhythm.phase.value).toBe('HALTED');
    expect(rhythm.dimmed.value).toBe(true);
    const frozen = rhythm.visualValue.value;

    const t0 = Date.now();
    await rhythm.waitForHaltMin();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(20); // 30ms 计时器容差

    frame(10);
    expect(rhythm.visualValue.value).toBe(frozen); // 冻结：推帧不改变视觉值

    rhythm.seal(); // HALTED 下 seal 忽略
    rhythm.halt(); // 重复 halt 忽略
    expect(rhythm.phase.value).toBe('HALTED');
    expect(report.mock.calls.filter((c) => (c[0] as { kind: string }).kind === 'halted').length).toBe(1);
  });

  it('收束期收到失败事件：SEALING 转 HALTED，waitForComplete 以 reject 交付', async () => {
    const { env, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    const complete = rhythm.waitForComplete();
    frame(10); // 越过极快成功阈值
    rhythm.seal();
    expect(rhythm.phase.value).toBe('SEALING');

    rhythm.halt();
    await expect(complete).rejects.toThrow();
    expect(rhythm.phase.value).toBe('HALTED');
    expect(rhythm.dimmed.value).toBe(true);
  });

  it('失败重试（reset）：HALTED → ACTIVE，视觉值归零、降级标识清除、假进度时间基准重置', () => {
    const { env, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    rhythm.pushRealProgress(0.6);
    frame(8);
    rhythm.halt();
    expect(rhythm.dimmed.value).toBe(true);

    rhythm.start();
    expect(rhythm.phase.value).toBe('ACTIVE');
    expect(rhythm.visualValue.value).toBe(0);
    expect(rhythm.dimmed.value).toBe(false);

    frame(5);
    expect(rhythm.visualValue.value).toBeGreaterThan(0);
  });

  it('dispose：中断清理动画帧，状态冻结，未决 waitForComplete 被拒绝', async () => {
    const { env, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    const complete = rhythm.waitForComplete();
    frame(2);
    rhythm.dispose();

    expect(rhythm.phase.value).toBe('HALTED');
    await expect(complete).rejects.toThrow();

    const frozen = rhythm.visualValue.value;
    frame(5);
    expect(rhythm.visualValue.value).toBe(frozen); // 帧调度已取消
  });
});

describe('useVerifyRhythm — 单活跃实例约束', () => {
  it('并发启动：新实例接管时旧实例被 halt，同一时刻仅新实例处于活跃期', () => {
    const a = createFakeEnv();
    const b = createFakeEnv();
    const ra = useVerifyRhythm({ env: a.env });
    const rb = useVerifyRhythm({ env: b.env });

    ra.start();
    a.frame(5);
    const frozenA = ra.visualValue.value;
    expect(frozenA).toBeGreaterThan(0);

    rb.start(); // 单例锁接管
    expect(ra.phase.value).toBe('HALTED');
    expect(ra.dimmed.value).toBe(true);
    expect(rb.phase.value).toBe('ACTIVE');

    a.frame(5);
    b.frame(5);
    expect(ra.visualValue.value).toBe(frozenA); // 旧实例视觉值永久冻结
    expect(rb.visualValue.value).toBeGreaterThan(0); // 新实例正常推进
  });

  it('ACTIVE 期间重复 start 被忽略（幂等），不重置进度', () => {
    const { env, frame } = createFakeEnv();
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    frame(5);
    const before = rhythm.visualValue.value;
    expect(before).toBeGreaterThan(0);

    rhythm.start(); // 已在 ACTIVE，忽略
    expect(rhythm.phase.value).toBe('ACTIVE');
    expect(rhythm.visualValue.value).toBe(before);

    frame(1);
    expect(rhythm.visualValue.value).toBeGreaterThanOrEqual(before);
  });
});

describe('useVerifyRhythm — 无障碍直通降级', () => {
  it('prefers-reduced-motion：视觉值直通显示真实进度（软上限仍生效），收束瞬时完成', async () => {
    const { env, frame } = createFakeEnv({ reducedMotion: true });
    const rhythm = useVerifyRhythm({ env });

    rhythm.start();
    rhythm.pushRealProgress(0.4);
    expect(rhythm.visualValue.value).toBe(0.4); // 无平滑、无假进度

    rhythm.pushRealProgress(1);
    expect(rhythm.visualValue.value).toBe(softCeiling); // 软上限仍生效

    const complete = rhythm.waitForComplete();
    rhythm.seal();
    expect(rhythm.phase.value).toBe('DONE'); // 收束瞬时完成
    expect(rhythm.visualValue.value).toBe(1);
    await expect(complete).resolves.toBeUndefined();

    const before = rhythm.visualValue.value;
    frame(5); // 直通模式无动画帧
    expect(rhythm.visualValue.value).toBe(before);
  });
});