/**
 * packetRitual.ts — 光包传播仪式节奏（纯时间逻辑，无渲染）
 *
 * 职责边界：
 *   - 维护传播仪式状态机：idle → propagating → landing → pending → done
 *   - 传播与落定进度仅由调用方传入的累积墙钟（秒）计算，
 *     与帧步进钳制、帧率档位完全无关
 *   - 完成事件语义：落定逻辑完成帧返回 complete 标志，调用方渲染该帧后，
 *     在下一帧调用 consumeComplete 领取一次性完成事件（双帧约定，
 *     保证落定视觉至少呈现过一帧）
 *   - 幂等：传播/落定期间重复 begin 被拒绝并记录告警
 *   - 后台语义：调用方停帧期间不调用 advance，时钟不推进，
 *     恢复后从暂停处继续（本模块不自持墙钟，天然满足）
 *   - 无障碍降级：reducedMotion=true 时跳过传播与落定，直接进入待完成
 *
 * 关键约束：
 *   - 完成事件只发放一次，且不得早于落定逻辑完成帧的下一帧
 *   - 传播到达终点与进入落定发生在同一帧（到达帧即落定首帧）
 */

import { createLogger } from '../../utils/logger';

const log = createLogger('packet-ritual');

/** 仪式状态机阶段 */
export type RitualPhase = 'idle' | 'propagating' | 'landing' | 'pending' | 'done';

/** 节奏参数（调用方从单一配置源传入） */
export interface PacketRitualConfig {
  /** 传播时长（秒） */
  propagationDuration: number;
  /** 落定时长（秒） */
  landingDuration: number;
  /** 无障碍降级：跳过传播与落定，下一帧即可完成 */
  reducedMotion: boolean;
}

/** 每帧推进结果 */
export interface RitualFrame {
  /** 传播进度 0..1（到达终点后夹紧为 1） */
  propagation: number;
  /** 落定进度 0..1（仅落定期与待完成期 > 0） */
  landing: number;
  /** 落定逻辑完成帧：本帧渲染后，下一帧应领取完成事件 */
  complete: boolean;
}

/** 传播仪式句柄 */
export interface PacketRitual {
  /** 当前阶段（非响应式，供引擎帧循环读取） */
  readonly phase: RitualPhase;
  /** 启动仪式（幂等：仅在 idle 阶段接受） */
  begin(): void;
  /** 按累积墙钟（秒）推进，返回本帧进度 */
  advance(clockSec: number): RitualFrame;
  /** 领取一次性完成事件（仅 pending 阶段可领取一次） */
  consumeComplete(): boolean;
  /** 中断复位（卸载 / 用户返回），回到 idle */
  reset(): void;
}

/** 创建光包传播仪式（一次一实例；预分配帧对象，零 GC） */
export function createPacketRitual(config: PacketRitualConfig): PacketRitual {
  /** 边界判定容差：浮点累加下进度可能偏离 1.0 极小量，按容差视为到达 */
  const EPS = 1e-9;
  let state: RitualPhase = 'idle';
  let startClock = 0;
  let landClock = 0;
  let clockSeeded = false;
  /** 待完成期的完成标志是否已随帧发出（无障碍直通路径需补发一次） */
  let pendingCompleteEmitted = false;

  const frame: RitualFrame = { propagation: 0, landing: 0, complete: false };

  const begin = (): void => {
    if (state !== 'idle') {
      log.warn('begin rejected: ritual already in phase', state);
      return;
    }
    state = config.reducedMotion ? 'pending' : 'propagating';
    clockSeeded = false;
    pendingCompleteEmitted = false;
  };

  const advance = (clockSec: number): RitualFrame => {
    frame.propagation = 0;
    frame.landing = 0;
    frame.complete = false;

    switch (state) {
      case 'idle':
      case 'done':
        return frame;

      case 'propagating': {
        if (!clockSeeded) {
          // 首帧播种时间基准：传播从首帧时刻起算（begin 帧即本帧）
          startClock = clockSec;
          clockSeeded = true;
        }
        const p = (clockSec - startClock) / config.propagationDuration;
        if (p < 1 - EPS) {
          frame.propagation = p;
          return frame;
        }
        // 到达终点：同帧转入落定（到达帧 = 落定首帧）
        state = 'landing';
        landClock = clockSec;
        frame.propagation = 1;
        frame.landing = 0;
        return frame;
      }

      case 'landing': {
        const l = (clockSec - landClock) / config.landingDuration;
        if (l < 1 - EPS) {
          frame.propagation = 1;
          frame.landing = Math.max(0, l);
          return frame;
        }
        // 落定逻辑完成帧：本帧渲染完整落定，下一帧领取完成事件
        state = 'pending';
        pendingCompleteEmitted = true;
        frame.propagation = 1;
        frame.landing = 1;
        frame.complete = true;
        return frame;
      }

      case 'pending': {
        frame.propagation = 1;
        frame.landing = 1;
        if (!pendingCompleteEmitted) {
          // 无障碍直通路径：落定在 begin 帧即时完成，首个推进帧补发完成标志
          pendingCompleteEmitted = true;
          frame.complete = true;
        }
        return frame;
      }
    }
    return frame;
  };

  const consumeComplete = (): boolean => {
    if (state !== 'pending') return false;
    state = 'done';
    return true;
  };

  const reset = (): void => {
    state = 'idle';
    clockSeeded = false;
    frame.propagation = 0;
    frame.landing = 0;
    frame.complete = false;
  };

  return {
    get phase(): RitualPhase {
      return state;
    },
    begin,
    advance,
    consumeComplete,
    reset,
  };
}