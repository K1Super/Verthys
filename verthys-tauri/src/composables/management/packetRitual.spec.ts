/**
 * packetRitual.spec.ts — 光包传播仪式（纯时间逻辑）单元测试
 *
 * 覆盖：墙钟进度与帧率/钳制无关、完成事件时机（双帧约定）、
 * 幂等拒绝、无障碍直通降级、后台暂停续播（不跳终点）、复位重入。
 *
 * 时间基准约定：begin 后首帧 advance 为播种帧（引擎点击帧与渲染帧
 * 的自然顺序），测试统一先播种再推进。
 */
import { describe, it, expect } from 'vitest';
import { createPacketRitual, type PacketRitual, type PacketRitualConfig } from './packetRitual';

const BASE: PacketRitualConfig = {
  propagationDuration: 0.62,
  landingDuration: 0.1,
  reducedMotion: false,
};

function make(config: Partial<PacketRitualConfig> = {}): PacketRitual {
  return createPacketRitual({ ...BASE, ...config });
}

/** 启动仪式并播种时间基准（首帧） */
function beginSeeded(ritual: PacketRitual): void {
  ritual.begin();
  ritual.advance(0);
}

describe('packetRitual — 传播与落定进度', () => {
  it('进度由传入墙钟唯一决定：细步进与粗步进同一时刻进度一致（帧率无关，钳制不参与）', () => {
    // 实例 a：60Hz 细步进（16.7ms 一帧）
    const a = make();
    beginSeeded(a);
    // 实例 b：idle 档粗步进（仅 200ms 采样一次，类比门控跳帧）
    const b = make();
    beginSeeded(b);

    for (let t = 0.0167; t <= 0.61; t += 0.0167) {
      a.advance(t);
    }
    b.advance(0.31);

    const fa = a.advance(0.62); // 恰到达终点
    const fb = b.advance(0.62);
    expect(fa.propagation).toBe(1);
    expect(fa.landing).toBe(0);
    expect(fb.propagation).toBe(1);
    expect(fb.landing).toBe(0);

    // 620ms 前任意时刻：进度 = clock / duration，与采样序列无关
    const pa = a.advance(0.63); // 已进入落定 10%
    const pb = b.advance(0.63);
    expect(pa.landing).toBeCloseTo(0.1, 5);
    expect(pb.landing).toBeCloseTo(0.1, 5);

    const la = a.advance(0.67);
    const lb = b.advance(0.67);
    expect(la.landing).toBeCloseTo(0.5, 5);
    expect(lb.landing).toBeCloseTo(0.5, 5);
  });

  it('到达终点帧 = 落定首帧：传播夹紧为 1，落定从 0 起播（不跳终点）', () => {
    const r = make();
    beginSeeded(r);
    const f = r.advance(0.619); // 差 1ms 未到
    expect(f.propagation).toBeLessThan(1);
    expect(r.phase).toBe('propagating');

    const arrive = r.advance(0.62);
    expect(r.phase).toBe('landing');
    expect(arrive.propagation).toBe(1);
    expect(arrive.landing).toBe(0);
  });

  it('后台暂停语义：停帧期间不推进，恢复后从暂停处继续至终点，落定完整起播', () => {
    const r = make();
    beginSeeded(r);
    expect(r.advance(0.3).propagation).toBeCloseTo(0.3 / 0.62, 5);

    // 停帧 60s（模拟后台 / 深空闲：调用方不给时钟，进度不推进）；
    // 恢复后直接喂当前时刻 0.62s —— 恰好到终点，落定从 0 起始而非跨越
    const resume = r.advance(0.62);
    expect(resume.propagation).toBe(1);
    expect(resume.landing).toBe(0);
    expect(r.phase).toBe('landing');

    const complete = r.advance(0.73);
    expect(complete.complete).toBe(true);
  });
});

describe('packetRitual — 完成事件时机（双帧约定）', () => {
  it('落定逻辑完成帧返回 complete；下一帧 consume 恰好领取一次', () => {
    const r = make();
    beginSeeded(r);

    r.advance(0.62); // 到达终点帧 = 落定首帧
    expect(r.phase).toBe('landing');
    expect(r.consumeComplete()).toBe(false);

    r.advance(0.71); // 落定 90%，未完成
    expect(r.phase).toBe('landing');
    expect(r.consumeComplete()).toBe(false);

    const done = r.advance(0.73);
    expect(done.complete).toBe(true); // 落定逻辑完成帧
    expect(done.landing).toBe(1);
    expect(r.phase).toBe('pending');

    expect(r.consumeComplete()).toBe(true); // 下一帧领取：一次性
    expect(r.phase).toBe('done');
    expect(r.consumeComplete()).toBe(false); // 二次领取拒绝
  });

  it('完成事件不提前：落定未完成时 consume 恒为 false', () => {
    const r = make();
    beginSeeded(r);
    r.advance(0.63); // 落定 10%
    expect(r.consumeComplete()).toBe(false);
    expect(r.phase).toBe('landing');
  });
});

describe('packetRitual — 幂等与非法转移', () => {
  it('传播/落定/待完成期重复 begin 被拒绝，阶段不变', () => {
    // 拒绝语义由阶段不变式验证（告警输出仅开发环境可见，不在此断言）
    const r = make();
    beginSeeded(r);

    r.advance(0.31);
    expect(r.phase).toBe('propagating');
    r.begin(); // 传播期重复点击
    expect(r.phase).toBe('propagating');

    r.advance(0.65);
    expect(r.phase).toBe('landing');
    r.begin(); // 落定期重复点击
    expect(r.phase).toBe('landing');

    r.advance(0.76);
    expect(r.phase).toBe('pending');
    r.begin(); // 待完成期重复点击
    expect(r.phase).toBe('pending');
  });

  it('reset 复位后可重新启动仪式（done → idle → 新一轮）', () => {
    const r = make();
    beginSeeded(r);
    r.advance(0.62);
    r.advance(0.73);
    r.consumeComplete();
    expect(r.phase).toBe('done');

    r.reset();
    expect(r.phase).toBe('idle');
    beginSeeded(r);
    expect(r.advance(0.31).propagation).toBeCloseTo(0.5, 5);
  });
});

describe('packetRitual — 无障碍直通降级', () => {
  it('reducedMotion：跳过传播与落定，首帧即 complete，下一帧可领取', () => {
    const r = make({ reducedMotion: true });
    r.begin();
    expect(r.phase).toBe('pending');

    const f = r.advance(0.001);
    expect(f.complete).toBe(true);
    expect(f.propagation).toBe(1);
    expect(f.landing).toBe(1);
    expect(r.consumeComplete()).toBe(true);
  });
});