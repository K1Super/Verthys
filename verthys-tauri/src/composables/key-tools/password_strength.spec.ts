/**
 * password_strength.spec.ts — 口令强度评估映射层与桥接层契约测试
 *
 * 锁定四类此前会误导用户或卡死界面的口径：
 *   1. 来源如实：模式分析、无模式命中、降级三条路径的 source 不得混用；
 *   2. 降级兜底：Worker 异常、超时、销毁都必须给出结果，不得让调用方悬挂；
 *   3. 代际丢弃：被新输入取代的旧结果不得覆盖当前结果；
 *   4. 明文边界：回传摘要不得携带口令片段，分析前缀不得超过上限。
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { effectScope } from "vue";
import {
  buildStrengthFailure,
  buildStrengthSuccess,
  collectPatternHits,
  countCoveredChars,
  MAX_PATTERN_HITS,
  type StrengthPatternHit,
  type StrengthResponse,
} from "../../workers/password-strength-protocol";
import {
  PasswordStrengthBridge,
  PASSWORD_ANALYSIS_MAX_CHARS,
  charsetAssessment,
  correctGuessesForUncovered,
  describeWeakness,
  mapEngineResult,
  type StrengthWorkerLike,
} from "./password_strength";
import { usePasswordStrength } from "./usePasswordStrength";
import { calcStrength, levelFromEntropy } from "./password_tools";
import { zxcvbn } from "../../vendor/zxcvbn";

/** 可手动驱动的假 Worker（不依赖真实线程） */
class FakeWorker implements StrengthWorkerLike {
  onmessage: ((event: MessageEvent<StrengthResponse>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  readonly sent: { id: number; password: string }[] = [];
  terminated = false;

  postMessage(message: { id: number; password: string }): void {
    this.sent.push(message);
  }

  terminate(): void {
    this.terminated = true;
  }

  /** 模拟 Worker 回包 */
  emit(response: StrengthResponse): void {
    this.onmessage?.({ data: response } as MessageEvent<StrengthResponse>);
  }

  /** 模拟 Worker 脚本级崩溃 */
  crash(): void {
    this.onerror?.({} as ErrorEvent);
  }
}

/** 构造一条词典命中摘要 */
const dictHit = (dictionaryName: string, tokenLength: number): StrengthPatternHit => ({
  pattern: "dictionary",
  dictionaryName,
  tokenLength,
});

afterEach(() => {
  vi.useRealTimers();
});

describe("强度分档单一来源", () => {
  it("字符集模型与分档函数逐位一致", () => {
    const base = calcStrength("aB3!xY7@");
    expect(levelFromEntropy(base.entropy)).toEqual({
      level: base.level,
      label: base.label,
      percent: base.percent,
    });
  });

  it("阈值边界不得漂移", () => {
    expect(levelFromEntropy(39).level).toBe(1);
    expect(levelFromEntropy(40).level).toBe(2);
    expect(levelFromEntropy(60).level).toBe(3);
    expect(levelFromEntropy(80).level).toBe(4);
    expect(levelFromEntropy(100).level).toBe(5);
  });
});

describe("弱点提示", () => {
  it("词典命中文案区分弱口令与人名", () => {
    expect(describeWeakness([dictHit("passwords", 8)])).toContain("常见弱口令");
    expect(describeWeakness([dictHit("surnames", 5)])).toContain("常见姓氏");
    expect(describeWeakness([dictHit("unknown_dict", 5)])).toContain("常见词");
  });

  it("键盘/重复/序列/日期/年份各自成句", () => {
    expect(describeWeakness([{ pattern: "spatial", tokenLength: 6 }])).toContain("键盘相邻键位");
    expect(describeWeakness([{ pattern: "repeat", tokenLength: 16 }])).toContain("重复片段");
    expect(describeWeakness([{ pattern: "sequence", tokenLength: 6 }])).toContain("连续字符");
    expect(describeWeakness([{ pattern: "date", tokenLength: 8 }])).toContain("日期");
    expect(describeWeakness([{ pattern: "regex", tokenLength: 4 }])).toContain("年份数字");
  });

  it("无模式命中时不产出提示", () => {
    expect(describeWeakness([])).toBe("");
    expect(describeWeakness([{ pattern: "bruteforce", tokenLength: 12 }])).toBe("");
  });
});

describe("模式摘要压缩（明文边界）", () => {
  it("剔除暴力分支、按类别去重并保留覆盖最长的片段", () => {
    const hits = collectPatternHits([
      { pattern: "dictionary", dictionary_name: "passwords", token: "abc" },
      { pattern: "dictionary", dictionary_name: "passwords", token: "abcdefgh" },
      { pattern: "bruteforce", token: "zzzz" },
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toEqual({ pattern: "dictionary", dictionaryName: "passwords", tokenLength: 8 });
  });

  it("摘要不含口令片段字段", () => {
    const [hit] = collectPatternHits([
      { pattern: "dictionary", dictionary_name: "passwords", token: "secret" },
    ]);
    expect(Object.keys(hit)).not.toContain("token");
  });

  it("条数收敛到上限", () => {
    const sequence = Array.from({ length: MAX_PATTERN_HITS + 6 }, (_, i) => ({
      pattern: "dictionary",
      dictionary_name: `dict_${i}`,
      token: "x",
    }));
    expect(collectPatternHits(sequence)).toHaveLength(MAX_PATTERN_HITS);
  });

  it("白名单之外的类别不进入摘要与覆盖统计", () => {
    const sequence = [
      { pattern: "future_pattern", token: "abcd" },
      { pattern: "bruteforce", token: "xy" },
    ];
    expect(collectPatternHits(sequence)).toHaveLength(0);
    expect(countCoveredChars(sequence)).toBe(0);
  });

  it("覆盖字符数按原始片段累加（不做去重）", () => {
    expect(countCoveredChars([
      { pattern: "dictionary", dictionary_name: "passwords", token: "abc" },
      { pattern: "dictionary", dictionary_name: "passwords", token: "defgh" },
      { pattern: "bruteforce", token: "zzzzzz" },
    ])).toBe(8);
  });
});

describe("Worker 响应装配（唯一装箱点）", () => {
  it("成功响应携带猜测数、覆盖字符数与摘要", () => {
    const response = buildStrengthSuccess(7, {
      guesses: 36180,
      sequence: [
        { pattern: "dictionary", dictionary_name: "passwords", token: "password" },
        { pattern: "bruteforce", token: "123!" },
      ],
    });
    expect(response).toEqual({
      id: 7,
      ok: true,
      guesses: 36180,
      coveredChars: 8,
      patterns: [{ pattern: "dictionary", dictionaryName: "passwords", tokenLength: 8 }],
    });
  });

  it("失败响应只带固定失败码", () => {
    expect(buildStrengthFailure(3, "engine")).toEqual({ id: 3, ok: false, error: "engine" });
    expect(buildStrengthFailure(4, "protocol")).toEqual({ id: 4, ok: false, error: "protocol" });
  });
});

describe("引擎响应映射", () => {
  it("命中模式时以引擎猜测数为准：Password123! 仍属极弱", () => {
    const assessment = mapEngineResult(
      buildStrengthSuccess(1, {
        guesses: 36180,
        sequence: [
          { pattern: "dictionary", dictionary_name: "passwords", token: "password" },
          { pattern: "bruteforce", token: "123!" },
        ],
      }),
      "Password123!",
      false,
    );
    expect(assessment.source).toBe("pattern");
    // 36180 × (94/10)^4 ≈ 2.8e8 次猜测，约 28 位，等级仍为极弱
    expect(assessment.entropy).toBe(28);
    expect(assessment.level).toBe(1);
    expect(assessment.warning).toContain("常见弱口令");
  });

  it("未覆盖字符按字符集空间换算，随机口令不再被引擎暴力基数低估", () => {
    const text = "Xk9#mQ2$vL4@nR7";
    const length = Array.from(text).length;
    // 引擎对纯暴力串给出 10^长度；模拟偶然命中 6 字符词典片段
    const response: StrengthResponse = {
      id: 1,
      ok: true,
      guesses: Math.pow(10, length),
      coveredChars: 6,
      patterns: [dictHit("passwords", 6)],
    };
    const assessment = mapEngineResult(response, text, false);
    const expected = Math.pow(10, length) * Math.pow(94 / 10, length - 6);
    expect(assessment.entropy).toBe(Math.round(Math.log2(expected)));
    // 未换算时引擎口径约 50 位；换算后应回到 70 位以上（等级不低于中等）
    expect(assessment.entropy).toBeGreaterThan(70);
    expect(assessment.level).toBeGreaterThanOrEqual(3);
  });

  it("换算在无覆盖时等于字符集空间（与生成器同口径）", () => {
    const text = "Xk9#mQ2$vL4@nR7";
    const length = Array.from(text).length;
    const corrected = correctGuessesForUncovered(Math.pow(10, length), text, 0);
    expect(corrected / Math.pow(94, length)).toBeCloseTo(1, 6);
  });

  it("覆盖数被钳制在文本长度内，溢出收敛到有限值", () => {
    expect(correctGuessesForUncovered(1e16, "abcdefgh", 999)).toBe(1e16);
    expect(correctGuessesForUncovered(1e16, "abcdefgh", -5)).toBeGreaterThan(1e16);
    expect(Number.isFinite(correctGuessesForUncovered(Number.MAX_VALUE, "abcdefgh", 0))).toBe(true);
  });

  it("未命中模式时改按字符集空间估算，且不产出弱点提示", () => {
    const text = "3rT!9vLx#qZ7";
    const assessment = mapEngineResult(
      { id: 1, ok: true, guesses: 1e12, coveredChars: 0, patterns: [] },
      text,
      false,
    );
    expect(assessment.source).toBe("charset");
    expect(assessment).toEqual(charsetAssessment(text, "charset"));
    expect(assessment.warning).toBe("");
  });

  it("猜测数非法时降级为字符集估算", () => {
    for (const guesses of [0, Number.NaN, Number.POSITIVE_INFINITY]) {
      const assessment = mapEngineResult({ id: 1, ok: true, guesses }, "abc", false);
      expect(assessment.source).toBe("charset-fallback");
    }
  });

  it("截断标记透传到评估结果", () => {
    const text = "a".repeat(PASSWORD_ANALYSIS_MAX_CHARS);
    const assessment = mapEngineResult(
      { id: 1, ok: true, guesses: 1e30, coveredChars: 3, patterns: [dictHit("passwords", 3)] },
      text,
      true,
    );
    expect(assessment.truncated).toBe(true);
    expect(assessment.analyzedChars).toBe(PASSWORD_ANALYSIS_MAX_CHARS);
  });
});

describe("弱点提示门槛", () => {
  it("弱口令且模式有分量时给出提示", () => {
    const assessment = mapEngineResult(
      { id: 1, ok: true, guesses: 1e9, coveredChars: 6, patterns: [dictHit("passwords", 6)] },
      "dragonXk9#mQ2",
      false,
    );
    expect(assessment.level).toBe(2);
    expect(assessment.warning).toContain("常见弱口令");
  });

  it("中等及以上不提示：巧合片段不算缺陷", () => {
    const assessment = mapEngineResult(
      {
        id: 1,
        ok: true,
        guesses: 1.99e15,
        coveredChars: 5,
        patterns: [{ pattern: "dictionary", dictionaryName: "english_wikipedia", tokenLength: 5 }],
      },
      "MyDogIsNamedRex99",
      false,
    );
    expect(assessment.level).toBeGreaterThanOrEqual(3);
    expect(assessment.warning).toBe("");
  });

  it("片段过短时不提示（即使等级很低）", () => {
    const assessment = mapEngineResult(
      { id: 1, ok: true, guesses: 1e8, coveredChars: 3, patterns: [{ pattern: "sequence", tokenLength: 3 }] },
      "abc12345",
      false,
    );
    expect(assessment.level).toBeLessThanOrEqual(2);
    expect(assessment.warning).toBe("");
  });

  it("覆盖占比过低时不提示", () => {
    // 64 位十六进制串里出现 6 位日期：等级极高，且覆盖仅 9%
    const assessment = mapEngineResult(
      {
        id: 1,
        ok: true,
        guesses: 1e64,
        coveredChars: 6,
        patterns: [{ pattern: "date", tokenLength: 6 }],
      },
      "0523072b628717f6535a8bc3ef834fa2b44a03dfb11f48b2388b9ca21c013970",
      false,
    );
    expect(assessment.level).toBe(5);
    expect(assessment.warning).toBe("");
  });
});

describe("Worker 桥接", () => {
  it("空输入不创建 Worker", async () => {
    const factory = vi.fn(() => new FakeWorker());
    const bridge = new PasswordStrengthBridge({ workerFactory: factory });
    await expect(bridge.assess("")).resolves.toMatchObject({ level: 0 });
    expect(factory).not.toHaveBeenCalled();
  });

  it("超长输入只下发分析前缀", async () => {
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const input = "a".repeat(PASSWORD_ANALYSIS_MAX_CHARS + 40);
    const pending = bridge.assess(input);
    expect(worker.sent[0].password).toHaveLength(PASSWORD_ANALYSIS_MAX_CHARS);
    worker.emit({ id: worker.sent[0].id, ok: true, guesses: 1e20, patterns: [dictHit("passwords", 4)] });
    const assessment = await pending;
    expect(assessment?.truncated).toBe(true);
    expect(assessment?.analyzedChars).toBe(PASSWORD_ANALYSIS_MAX_CHARS);
  });

  it("连续评估只保留最新请求，旧请求以 null 结算", async () => {
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const first = bridge.assess("first-password");
    const second = bridge.assess("second-password");
    expect(worker.sent).toHaveLength(2);
    await expect(first).resolves.toBeNull();
    expect(worker.terminated).toBe(false);
    worker.emit({ id: worker.sent[1].id, ok: true, guesses: 3, patterns: [dictHit("passwords", 6)] });
    await expect(second).resolves.toMatchObject({ source: "pattern" });
  });

  it("过期响应不得冒领当前结果", async () => {
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const pending = bridge.assess("current-password");
    worker.emit({ id: worker.sent[0].id + 99, ok: true, guesses: 1e20, patterns: [] });
    // 非当前 ID 被丢弃后请求仍在途，超时后降级结算
    worker.emit({ id: worker.sent[0].id, ok: true, guesses: 1e20, patterns: [] });
    await expect(pending).resolves.toMatchObject({ source: "charset" });
  });

  it("超时降级并终止 Worker", async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker, timeoutMs: 500 });
    const pending = bridge.assess("timeout-password");
    await vi.advanceTimersByTimeAsync(500);
    const assessment = await pending;
    expect(assessment?.source).toBe("charset-fallback");
    expect(worker.terminated).toBe(true);
  });

  it("Worker 崩溃后降级且不再反复重建", async () => {
    let created = 0;
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({
      workerFactory: () => {
        created += 1;
        return worker;
      },
    });
    const pending = bridge.assess("crash-password");
    worker.crash();
    await expect(pending).resolves.toMatchObject({ source: "charset-fallback" });
    const second = await bridge.assess("another-password");
    expect(second?.source).toBe("charset-fallback");
    expect(created).toBe(1);
  });

  it("响应失败码降级但保留 Worker（不影响后续请求）", async () => {
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const failed = bridge.assess("engine-error");
    worker.emit({ id: worker.sent[0].id, ok: false, error: "engine" });
    await expect(failed).resolves.toMatchObject({ source: "charset-fallback" });
    expect(worker.terminated).toBe(false);

    const retried = bridge.assess("retry-password");
    worker.emit({ id: worker.sent[1].id, ok: true, guesses: 1e12, patterns: [] });
    await expect(retried).resolves.toMatchObject({ source: "charset" });
  });

  it("销毁时终止 Worker 并以 null 结算在途请求", async () => {
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const pending = bridge.assess("dispose-password");
    bridge.dispose();
    await expect(pending).resolves.toBeNull();
    expect(worker.terminated).toBe(true);
    await expect(bridge.assess("after-dispose")).resolves.toBeNull();
  });

  it("预热只创建一次 Worker，且不发起分析", () => {
    const factory = vi.fn(() => new FakeWorker());
    const bridge = new PasswordStrengthBridge({ workerFactory: factory });
    bridge.preload();
    bridge.preload();
    expect(factory).toHaveBeenCalledTimes(1);
    expect(factory.mock.results[0].value.sent).toHaveLength(0);
  });
});

describe("评估面板状态绑定", () => {
  it("防抖窗口内连续输入只触发最后一次，落状态为最新结果", async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const scope = effectScope();
    const state = scope.run(() => usePasswordStrength({ bridge, debounceMs: 100 }));
    if (!state) throw new Error("组合式未建立");

    state.assess("first");
    state.assess("second");
    expect(worker.sent).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(100);
    expect(worker.sent).toHaveLength(1);
    expect(worker.sent[0].password).toBe("second");

    worker.emit({ id: worker.sent[0].id, ok: true, guesses: 1e12, patterns: [] });
    await vi.advanceTimersByTimeAsync(0);
    expect(state.result.value.source).toBe("charset");
    expect(state.pending.value).toBe(false);
    scope.stop();
  });

  it("清空输入立即回到等级 0 并丢弃在途结果", async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const scope = effectScope();
    const state = scope.run(() => usePasswordStrength({ bridge, debounceMs: 10 }));
    if (!state) throw new Error("组合式未建立");

    state.assess("working");
    await vi.advanceTimersByTimeAsync(10);
    state.assess("");
    worker.emit({ id: worker.sent[0].id, ok: true, guesses: 1e12, patterns: [] });
    await vi.advanceTimersByTimeAsync(0);
    expect(state.result.value.level).toBe(0);
    expect(state.pending.value).toBe(false);
    scope.stop();
  });

  it("在途请求期间 pending 为真，落地后复位", async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker();
    const bridge = new PasswordStrengthBridge({ workerFactory: () => worker });
    const scope = effectScope();
    const state = scope.run(() => usePasswordStrength({ bridge, debounceMs: 10 }));
    if (!state) throw new Error("组合式未建立");

    state.assess("in-flight");
    await vi.advanceTimersByTimeAsync(10);
    expect(state.pending.value).toBe(true);

    worker.emit({ id: worker.sent[0].id, ok: true, guesses: 1e12, patterns: [] });
    await vi.advanceTimersByTimeAsync(0);
    expect(state.pending.value).toBe(false);
    expect(state.result.value.source).toBe("charset");
    scope.stop();
  });
});

describe("内置引擎（真实产物）", () => {
  it("引擎已挂载并识别常见弱口令词典", () => {
    const raw = zxcvbn("Password123!");
    const hits = collectPatternHits(raw.sequence);
    expect(hits.some((hit) => hit.dictionaryName === "passwords")).toBe(true);
  });

  it("同一口令在生成器与评估面板得到同一等级口径", () => {
    // Password123! 字符集模型约 72 位，引擎模式口径只有约 28 位：评估必须采信模式
    const raw = zxcvbn("Password123!");
    const assessed = mapEngineResult(buildStrengthSuccess(1, raw), "Password123!", false);
    expect(assessed.entropy).toBeLessThan(40);
    expect(assessed.level).toBeLessThan(3);
  });

  it("无明显模式的长随机串按字符集空间评级", () => {
    const text = "x7Kq!2Lm#9Rt";
    const raw = zxcvbn(text);
    const assessed = mapEngineResult(buildStrengthSuccess(1, raw), text, false);
    expect(assessed.source).toBe("charset");
    expect(assessed.entropy).toBe(calcStrength(text).entropy);
  });

  it("偶然命中短词典词的随机串仍按字符集空间量级评级", () => {
    // 构造引擎只命中 3 字符片段、其余 13 字符为暴力的响应
    const text = "Xk9#mQ2$vL4@nR7";
    const entry = zxcvbn(text);
    const response = buildStrengthSuccess(1, {
      guesses: entry.guesses,
      sequence: [
        { pattern: "dictionary", dictionary_name: "english_wikipedia", token: text.slice(0, 3) },
        { pattern: "bruteforce", token: text.slice(3) },
      ],
    });
    const assessed = mapEngineResult(response, text, false);
    expect(assessed.source).toBe("pattern");
    // 换算后应达到「强」及以上，而不是被引擎 10 次/字符的暴力基数压到「极弱」
    expect(assessed.entropy).toBeGreaterThanOrEqual(80);
  });

  it("十六进制串不再因巧合片段给出日期或连续字符提示", () => {
    for (const text of [
      "0523072b628717f6535a8bc3ef834fa2b44a03dfb11f48b2388b9ca21c013970",
      "75d54d3eb763685f2caf531b3761bf49",
    ]) {
      const assessed = mapEngineResult(buildStrengthSuccess(1, zxcvbn(text)), text, false);
      expect(assessed.level).toBe(5);
      expect(assessed.warning).toBe("");
    }
  });
});
