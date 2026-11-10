/**
 * useVerifyRhythm.ts — 安全中心进度感知层
 *
 * 使用范围：解锁、创建、全局密钥初始化、验证、会话清理共用同一实例。
 * 业务层只推送后端真实阶段进度，本层负责把离散跳变吸收为连续视觉进度。
 *
 * 职责边界：
 *   - 订阅信号层：真实进度与终结事件由业务层通过
 *     pushRealProgress / seal / halt 注入，本层不反向驱动业务
 *   - 维护验证进度状态机：IDLE / ACTIVE / SEALING / DONE / HALTED
 *   - 维护导引前沿：假进度速度与保底速度取较大者后积分，真实进度作为硬下限；
 *     前沿单调不减且持续前进，吸收离散阶段信号之间的空窗
 *   - 以临界阻尼二阶跟随把前沿输出为视觉值：位置与速度均连续，
 *     阶段密集到达时不会逐段减速归零再重新起步（帧率无关、无过冲）
 *   - 成功收束（SEALING）：速度连续的三次 Hermite 补满 100% 后转 DONE，
 *     完成事件由 waitForComplete 以 Promise 形式交付业务层
 *   - 失败冻结（HALTED）：视觉值冻结不回弹、输出降级标识 dimmed，
 *     并保证错误最小展示时长 —— 保留给中断/降级用途；生产验证与初始化
 *     流程统一采用「收束完成后呈现结果」，不以冻结打断进度与加载编排
 *   - 尊重 prefers-reduced-motion：整体切换为直通策略
 *     （无假进度、无平滑、收束瞬时完成），不留散落分支
 *
 * 关键约束：
 *   - ACTIVE 阶段视觉值严格小于 1（即使真实进度推送 100%）
 *   - 视觉值单调不减（失败重试复位除外）
 *   - 视觉速度连续：阶段跳变只改变加速度，不产生速度跃变
 *   - 时间基准为单调时钟，dt 钳制 50ms，严禁按帧推进
 *   - 模块级单例锁：同一时刻仅一个实例处于 ACTIVE / SEALING，
 *     新实例启动时对旧活跃实例 halt 后接管
 *   - seal / halt 幂等；作用域销毁必须 cancel 动画帧
 *   - 所有节奏参数集中于本文件的单一配置源，业务层不得散落动画时长
 *
 * 术语：信号层（业务产生真实进度与终结事件）、感知层（本模块）、
 *       呈现层（仅渲染视觉值，不做判断）；"视觉值"指呈现层实际渲染
 *       的进度（0-1）；"显示真实进度"指经软上限钳制后的真实进度。
 */

import { computed, ref, type Ref } from 'vue';
import { createLogger } from '../../utils/logger';

const log = createLogger('verify-rhythm');

/* ================================================================== *
 * 单一配置源                                                            *
 * ================================================================== */

/**
 * 验证进度节奏配置。
 * 全部节奏参数集中于此，字段注释给出语义、单位与取值域；
 * 调整节奏只应修改本表，禁止在业务代码中散落动画时长常量。
 */
export interface VerifyRhythmConfig {
  /** 假进度曲线的绝对软上限，严格小于 1，取值域 (0.9, 1) */
  softCeiling: number;
  /** 假进度速度曲线的初始衰减时间常数（s），取值域 (3, 15)。
   *  前沿速度按 softCeiling/tau * exp(-t/tau) 平滑衰减；降到保底速度后
   *  由 floorRate 以同等速度接续，全段速度连续、无急停 */
  fakeRiseTau: number;
  /** 视觉跟随的临界阻尼固有角频率（rad/s），取值域 (5, 16)。
   *  决定阶段跳变后视觉速度的建立与收敛快慢；越大越跟手，速度仍连续 */
  followFrequency: number;
  /** 阶段间保底推进速度（1/s），取值域 (0.01, 0.08)。
   *  距软上限较远时保持该速度，保证 180px 通道上始终有可感知的连续位移 */
  floorRate: number;
  /** 保底推进在接近软上限时的指数衰减尺度（占进度比例），取值域 (0.005, 0.08)。
   *  速度随剩余空间指数收敛，使前沿渐近逼近软上限而永不硬停 */
  floorGapScale: number;
  /** 成功收束动画时长（ms），取值域 (300, 800) */
  sealDuration: number;
  /** 错误最小展示时长（ms），取值域 (200, 800) */
  errorMinDuration: number;
  /** 极快成功判定阈值（ms），取值域 (50, 300) — 仅 skipAnimation 策略消费 */
  fastSuccessThreshold: number;
  /**
   * 极快成功处理策略（默认 fullSeal）：
   *   - fullSeal：无论多快都执行完整收束动画；收束从当前视觉值连续起步，
   *     不以任何预设起点抬升制造瞬跳
   *   - skipAnimation：跳过收束动画，立即补满并触发完成事件（会令进度与
   *     加载编排在极快成功时整体消失，结果抢先落地）
   */
  fastSuccessStrategy: 'skipAnimation' | 'fullSeal';
}

/** 默认节奏配置（生产环境参数） */
export const DEFAULT_VERIFY_RHYTHM_CONFIG: Readonly<VerifyRhythmConfig> = {
  softCeiling: 0.985,
  fakeRiseTau: 7.5,
  followFrequency: 9.5,
  floorRate: 0.05,
  floorGapScale: 0.02,
  sealDuration: 520,
  errorMinDuration: 400,
  fastSuccessThreshold: 150,
  fastSuccessStrategy: 'fullSeal',
};

/* ================================================================== *
 * 状态机与对外契约                                                      *
 * ================================================================== */

/** 感知层状态机阶段 */
export type VerifyRhythmPhase = 'IDLE' | 'ACTIVE' | 'SEALING' | 'DONE' | 'HALTED';

/** 可观测性遥测事件（结构化，供监控与协议异常排查） */
export type VerifyRhythmTelemetry =
  | { kind: 'input-out-of-range'; input: number }
  | { kind: 'real-progress-regression'; from: number; to: number }
  | { kind: 'protocol-anomaly'; detail: 'real-progress-full-while-active' }
  | { kind: 'done'; totalMs: number; sealMs: number; fastSuccess: boolean; ceilingTouched: boolean }
  | { kind: 'halted'; frozenVisual: number }
  | { kind: 'interrupted'; phase: VerifyRhythmPhase };

/** 环境钩子（生产环境使用默认实现；测试可注入假时钟与帧调度器） */
export interface VerifyRhythmEnv {
  /** 单调时钟（ms） */
  now: () => number;
  /** 动画帧调度，返回句柄 */
  scheduleFrame: (cb: () => void) => number;
  /** 动画帧取消 */
  cancelFrame: (handle: number) => void;
  /** prefers-reduced-motion 判定 */
  prefersReducedMotion: () => boolean;
  /** 遥测事件报告 */
  report: (event: VerifyRhythmTelemetry) => void;
}

/** 感知层对外接口（业务层与呈现层通过本接口交互） */
export interface VerifyRhythm {
  /** 视觉值（0-1），呈现层绑定数据源 */
  readonly visualValue: Readonly<Ref<number>>;
  /** 视觉进度（0-100），直接绑定进度条 percent 输入 */
  readonly visualPercent: Readonly<Ref<number>>;
  /** 失败降级标识（冻结 + 视觉降级） */
  readonly dimmed: Readonly<Ref<boolean>>;
  /** 当前状态机阶段 */
  readonly phase: Readonly<Ref<VerifyRhythmPhase>>;
  /** 启动一轮验证（IDLE / HALTED / DONE → ACTIVE；ACTIVE / SEALING 期间忽略） */
  start(): void;
  /** 推送真实进度（0-1；越界钳制；回退忽略但记录遥测） */
  pushRealProgress(progress01: number): void;
  /** 成功收束指令（幂等）：ACTIVE → SEALING，收束完成转 DONE */
  seal(): void;
  /** 失败冻结指令（幂等）：ACTIVE / SEALING → HALTED */
  halt(): void;
  /** 等待收束完成：进入 DONE 时 resolve；被 halt / 销毁中断时 reject */
  waitForComplete(): Promise<void>;
  /** 等待错误最小展示时长经过（HALTED 后调用，到点 resolve） */
  waitForHaltMin(): Promise<void>;
  /** 销毁：取消动画帧调度并释放模块级单例锁 */
  dispose(): void;
}

/** useVerifyRhythm 参数 */
export interface UseVerifyRhythmOptions {
  /** 覆盖默认节奏参数（测试或特殊场景使用） */
  config?: Partial<VerifyRhythmConfig>;
  /** 环境钩子覆盖（测试注入假时钟/帧调度） */
  env?: Partial<VerifyRhythmEnv>;
}

/* ================================================================== *
 * 数学与工具                                                            *
 * ================================================================== */

/** 单帧 dt 钳制上限（ms）。后台标签页切回时 dt 可能为秒级，
 *  钳制后不会因一次大步长导致视觉值瞬间跳满。 */
const DT_CLAMP_MS = 50;

/** 假进度视为触顶的容差（封顶期渐进逼近软上限，按 0.1% 容差判定） */
const CEILING_TOUCH_EPSILON = 0.001;

const clamp01 = (v: number): number => Math.min(Math.max(v, 0), 1);

const clampMs = (v: number): number => Math.min(Math.max(v, 0), DT_CLAMP_MS);

/**
 * 假进度速度曲线（时间基准为 ACTIVE 起点，单位 s）。
 *
 * Why 以速度而非位置建模：前沿需要在任意时刻都有非零推进速度；
 * 位置曲线一旦进入平台期速度会衰减到 0，正是阶段空窗视觉停顿的根源。
 * 这里输出指数衰减的速度，与保底速度取较大者后积分，交接点两者速度
 * 相等，全段速度连续、无急停。
 */
function createFakeVelocity(config: VerifyRhythmConfig): (tSec: number) => number {
  const tau = Math.max(0.001, config.fakeRiseTau);
  const initial = config.softCeiling / tau;
  return (tSec: number): number => initial * Math.exp(-Math.max(0, tSec) / tau);
}

/** 纯假进度位置（仅用于遥测/诊断，不参与前沿推进） */
function fakeProgressAt(config: VerifyRhythmConfig, tSec: number): number {
  const tau = Math.max(0.001, config.fakeRiseTau);
  return config.softCeiling * (1 - Math.exp(-Math.max(0, tSec) / tau));
}

/** 生产环境默认钩子 */
function resolveEnv(overrides: Partial<VerifyRhythmEnv> | undefined): VerifyRhythmEnv {
  return {
    now:
      typeof performance !== 'undefined'
        ? () => performance.now()
        : () => Date.now(),
    scheduleFrame: (cb) => {
      if (typeof requestAnimationFrame === 'function') {
        return requestAnimationFrame(cb);
      }
      // 无 rAF 环境回退 16ms 定时器，保持帧率无关语义
      return setTimeout(cb, 16) as unknown as number;
    },
    cancelFrame: (handle) => {
      if (typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(handle);
      } else {
        clearTimeout(handle);
      }
    },
    prefersReducedMotion: () =>
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    report: (event) => {
      log.debug('telemetry', event);
    },
    ...overrides,
  };
}

/* ================================================================== *
 * 感知层核心实现                                                        *
 * ================================================================== */

interface PendingComplete {
  promise: Promise<void>;
  resolve: () => void;
  reject: (reason: Error) => void;
}

function createVerifyRhythm(env: VerifyRhythmEnv, config: VerifyRhythmConfig): VerifyRhythm {
  /* ---- 响应式输出（呈现层只读绑定） ---- */
  const visualValue = ref(0);
  const visualPercent = computed(() => visualValue.value * 100);
  const dimmed = ref(false);
  const phaseRef = ref<VerifyRhythmPhase>('IDLE');

  /* ---- 非响应式内部状态（动画帧热路径，避免响应式开销） ---- */
  let visual = 0;
  /** 视觉速度（1/s）：与 visual 一起构成二阶状态，保证速度连续 */
  let velocity = 0;
  /** 导引前沿（0-1）：真实进度 / 假进度曲线 / 保底推进的上界，单调不减 */
  let frontier = 0;
  let realDisplay = 0; // 显示真实进度（软上限钳制 + 回退忽略后的单调值）
  let lastReal = 0; // 最近一次真实进度（回退检测）
  let t0 = 0; // ACTIVE 起点（时钟 ms）
  let sealStart = 0; // 收束起点视觉值
  let sealV0 = 0; // 收束起点视觉速度（1/s，已按单调约束钳制）
  let sealT0 = 0; // 收束起始时刻（时钟 ms）
  let haltT0 = 0; // HALTED 时刻（时钟 ms）
  let frameHandle: number | null = null;
  let lastTick = 0;
  let pendingComplete: PendingComplete | null = null;
  let disposed = false;

  // 直通策略：prefers-reduced-motion 时整体替换动画策略（无假进度/无平滑/瞬发收束）
  const reduced = env.prefersReducedMotion();
  const fakeVelocityAt = createFakeVelocity(config);

  const setPhase = (p: VerifyRhythmPhase): void => {
    phaseRef.value = p;
  };

  const flushVisual = (): void => {
    visualValue.value = visual;
  };

  const stopLoop = (): void => {
    if (frameHandle !== null) {
      env.cancelFrame(frameHandle);
      frameHandle = null;
    }
  };

  /** ACTIVE / SEALING 且非直通策略时确保 rAF 循环在跑 */
  const maybeStartLoop = (): void => {
    if (reduced || disposed || frameHandle !== null) return;
    if (phaseRef.value !== 'ACTIVE' && phaseRef.value !== 'SEALING') return;
    lastTick = env.now();
    frameHandle = env.scheduleFrame(tick);
  };

  /**
   * 推进导引前沿。
   *
   * 前沿速度取「假进度速度 / 保底速度」的较大者，再按帧积分；
   * 真实进度作为硬下限（阶段信号到达时直接抬高前沿）。
   *
   * Why：假进度以速度而非位置建模，速度衰减到保底速度后由保底速度
   * 等速接续；若沿用位置曲线，进入平台期后速度会衰减到接近 0，
   * 视觉随之停顿，正是阶段空窗顿挫的根源。
   */
  const advanceFrontier = (now: number, dtSec: number): number => {
    const tSec = (now - t0) / 1000;
    const gap = Math.max(0, config.softCeiling - frontier);
    /* 距软上限越近推进越克制：常见进度区间保持满速，末段指数收敛。
     * 指数场使前沿渐近逼近软上限而永不硬停，避免长时间贴住满格。 */
    const floorRate = config.floorRate * (1 - Math.exp(-gap / config.floorGapScale));
    /* 速度域取上界后积分：假进度速度与保底速度在交接点相等，
     * 前沿速度连续变化，不存在「先冲后停」的拐点。 */
    const speed = Math.max(fakeVelocityAt(tSec), floorRate);
    frontier = Math.min(
      config.softCeiling,
      Math.max(realDisplay, frontier + speed * dtSec),
    );
    return speed;
  };

  /**
   * ACTIVE 期推进：先推进前沿，再以临界阻尼二阶跟随输出视觉值。
   *
   * 帧内把前沿视为常量，对 e'' + 2ωe' + ω²e = 0（e = visual - frontier）
   * 解析求解：位置与速度都连续，阶段进度集中到达时速度不会逐段归零再
   * 重建，而是一次连续滑行；同时临界阻尼无过冲，视觉始终不超越前沿。
   */
  const stepActive = (now: number, dtMs: number): void => {
    const dtSec = dtMs / 1000;
    const frontierSpeed = advanceFrontier(now, dtSec);
    if (dtSec <= 0) return;

    const w = config.followFrequency;
    const e = visual - frontier; // 恒 ≤ 0
    const decay = Math.exp(-w * dtSec);
    const eNext = (e + (velocity + w * e) * dtSec) * decay;
    const vNext = (velocity - w * (velocity + w * e) * dtSec) * decay;

    visual = frontier + eNext;
    velocity = vNext;

    /* 落位保护：视觉抵达前沿后不得归零，跟上前沿速度继续前进
     * （归零会形成一次可见停顿，正是阶段边界顿挫的来源）。 */
    if (visual >= frontier) {
      visual = frontier;
      velocity = Math.min(velocity, frontierSpeed);
    }
    if (visual < 0) {
      visual = 0;
      velocity = 0;
    }
    flushVisual();
  };

  const finishSeal = (now: number): void => {
    visual = 1;
    velocity = 0;
    flushVisual();
    stopLoop();
    setPhase('DONE');
    const totalMs = now - t0;
    const sealMs = now - sealT0;
    const ceilingTouched = fakeProgressAt(config, (sealT0 - t0) / 1000) >= config.softCeiling - CEILING_TOUCH_EPSILON;
    env.report({ kind: 'done', totalMs, sealMs, fastSuccess: false, ceilingTouched });
    resolveComplete();
  };

  /**
   * 收束期推进：三次 Hermite 曲线。
   *
   * 约束：P(0)=sealStart、P'(0)=sealV0、P(1)=1、P'(1)=0。
   * Why：普通缓出曲线在起点速度突变（视觉先顿一下再冲），而保留起点
   * 速度的 Hermite 让收束与 ACTIVE 期速度衔接；斜率参数钳制在 [0,3]
   * 内保证位移单调、不冲过 100%。
   */
  const stepSealing = (now: number): void => {
    const durationSec = config.sealDuration / 1000;
    const p = clamp01((now - sealT0) / config.sealDuration);
    const delta = Math.max(0, 1 - sealStart);
    if (delta <= 0 || durationSec <= 0) {
      finishSeal(now);
      return;
    }
    const alpha = Math.min(3, Math.max(0, (sealV0 * durationSec) / delta));
    const u2 = p * p;
    const u3 = u2 * p;
    visual = sealStart + delta * (3 * u2 - 2 * u3 + alpha * (u3 - 2 * u2 + p));
    flushVisual();
    if (p >= 1) {
      finishSeal(now);
    }
  };

  const tick = (): void => {
    frameHandle = null;
    const state = phaseRef.value;
    if (state !== 'ACTIVE' && state !== 'SEALING') return;
    const now = env.now();
    const dtMs = clampMs(now - lastTick);
    lastTick = now;
    if (state === 'ACTIVE') {
      stepActive(now, dtMs);
    } else {
      stepSealing(now);
    }
    if (phaseRef.value === 'ACTIVE' || phaseRef.value === 'SEALING') {
      frameHandle = env.scheduleFrame(tick);
    }
  };

  /* ---- 收束完成事件（Promise 化） ---- */

  const resolveComplete = (): void => {
    if (pendingComplete) {
      const { resolve } = pendingComplete;
      pendingComplete = null;
      resolve();
    }
  };

  const rejectComplete = (reason: string): void => {
    if (pendingComplete) {
      const { reject } = pendingComplete;
      pendingComplete = null;
      reject(new Error(reason));
    }
  };

  /* ---- 对外指令 ---- */

  const start = (): void => {
    if (disposed) return;
    const state = phaseRef.value;
    if (state === 'ACTIVE' || state === 'SEALING') return; // 已在跑，幂等忽略

    // 模块级单例锁：接管前对旧活跃实例 halt，保证全局唯一活跃实例
    if (activeInstance !== null && activeInstance !== core) {
      activeInstance.halt();
    }
    activeInstance = core;

    stopLoop();
    visual = 0;
    velocity = 0;
    frontier = 0;
    flushVisual();
    realDisplay = 0;
    lastReal = 0;
    dimmed.value = false;
    t0 = env.now();
    setPhase('ACTIVE');
    maybeStartLoop();
  };

  const pushRealProgress = (progress01: number): void => {
    if (phaseRef.value !== 'ACTIVE') return;
    const num = typeof progress01 === 'number' && Number.isFinite(progress01) ? progress01 : Number.NaN;
    if (Number.isNaN(num)) return;
    if (num < 0 || num > 1) {
      env.report({ kind: 'input-out-of-range', input: num });
    }
    const clamped = clamp01(num);
    if (clamped < lastReal) {
      // 协议异常回退：忽略降值（视觉单调不减由 realDisplay 单调钳制保证）
      env.report({ kind: 'real-progress-regression', from: lastReal, to: clamped });
    }
    lastReal = clamped;
    realDisplay = Math.max(realDisplay, Math.min(clamped, config.softCeiling));

    if (clamped >= 1) {
      // 真实进度已到 100% 但成功事件未到：视觉值仍被软上限钳制，不到 1
      env.report({ kind: 'protocol-anomaly', detail: 'real-progress-full-while-active' });
    }

    if (reduced) {
      // 直通策略：视觉值直接等于显示真实进度，无平滑无假进度
      visual = realDisplay;
      velocity = 0;
      flushVisual();
      return;
    }
    maybeStartLoop();
  };

  const seal = (): void => {
    if (phaseRef.value !== 'ACTIVE') return; // 幂等：仅 ACTIVE 可收束
    const now = env.now();
    const totalMs = now - t0;
    const fast = config.fastSuccessStrategy === 'skipAnimation' && totalMs < config.fastSuccessThreshold;

    if (reduced || fast) {
      // 直通策略 / 极快成功 skipAnimation：跳过收束动画，瞬时补满并完成
      stopLoop();
      visual = 1;
      velocity = 0;
      flushVisual();
      setPhase('DONE');
      env.report({
        kind: 'done',
        totalMs,
        sealMs: 0,
        fastSuccess: fast,
        ceilingTouched: fakeProgressAt(config, totalMs / 1000) >= config.softCeiling - CEILING_TOUCH_EPSILON,
      });
      resolveComplete();
      return;
    }

    /* 收束从当前视觉值连续起步，不做任何瞬跳抬升：
     * 快流程也由完整收束动画承担可见编排。 */
    sealStart = visual;
    /* 保留 ACTIVE 期末速度，让收束与前方滑行衔接；斜率按单调约束钳制，
     * 避免过冲 100% 或收束反向。 */
    const durationSec = config.sealDuration / 1000;
    const delta = Math.max(0, 1 - sealStart);
    sealV0 =
      delta > 0 && durationSec > 0
        ? Math.min(Math.max(0, velocity), (3 * delta) / durationSec)
        : 0;
    sealT0 = now;
    setPhase('SEALING');
    maybeStartLoop();
  };

  const halt = (): void => {
    const state = phaseRef.value;
    if (state === 'IDLE' || state === 'DONE' || state === 'HALTED' || disposed) return; // 幂等
    stopLoop();
    haltT0 = env.now();
    setPhase('HALTED');
    dimmed.value = true; // 呈现层据此视觉降级，错误提示取得视觉重心
    env.report({ kind: 'halted', frozenVisual: visual });
    rejectComplete('verify rhythm halted before completion');
  };

  const waitForComplete = (): Promise<void> => {
    if (phaseRef.value === 'DONE') return Promise.resolve();
    if (phaseRef.value !== 'ACTIVE' && phaseRef.value !== 'SEALING') {
      return Promise.reject(new Error('verify rhythm not in an active cycle'));
    }
    if (pendingComplete) return pendingComplete.promise;
    let resolve!: () => void;
    let reject!: (reason: Error) => void;
    const promise = new Promise<void>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    pendingComplete = { promise, resolve, reject };
    return promise;
  };

  const waitForHaltMin = (): Promise<void> => {
    if (phaseRef.value !== 'HALTED') return Promise.resolve();
    const remaining = Math.max(0, config.errorMinDuration - (env.now() - haltT0));
    if (remaining <= 0) return Promise.resolve();
    return new Promise<void>((resolve) => {
      setTimeout(resolve, remaining);
    });
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    stopLoop();
    if (phaseRef.value === 'ACTIVE' || phaseRef.value === 'SEALING') {
      env.report({ kind: 'interrupted', phase: phaseRef.value });
      setPhase('HALTED'); // 中断策略：取消调度，状态冻结
    }
    rejectComplete('verify rhythm disposed');
    if (activeInstance === core) {
      activeInstance = null;
    }
  };

  const core: VerifyRhythm = {
    visualValue,
    visualPercent,
    dimmed,
    phase: phaseRef,
    start,
    pushRealProgress,
    seal,
    halt,
    waitForComplete,
    waitForHaltMin,
    dispose,
  };

  return core;
}

/** 模块级单例锁：任一时刻至多一个实例处于 ACTIVE / SEALING */
let activeInstance: VerifyRhythm | null = null;

/** 创建验证进度感知层实例 */
export function useVerifyRhythm(options: UseVerifyRhythmOptions = {}): VerifyRhythm {
  const config: VerifyRhythmConfig = { ...DEFAULT_VERIFY_RHYTHM_CONFIG, ...options.config };
  const env = resolveEnv(options.env);
  return createVerifyRhythm(env, config);
}