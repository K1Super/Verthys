/**
 * photoWorkerPool.spec.ts — Worker 池韧性测试（崩溃注入 / 超时 / 池自愈）
 *
 * 覆盖：
 * - 崩溃重投可重放：源字节副本在每次投递生成全新转移副本，两次投递内容一致
 * - 毒丸隔离：达到最大尝试次数后任务被拒绝，池仍可服务后续任务
 * - 超时看门狗：挂起 Worker 被终止、任务重投并成功；用尽尝试后以明确错误拒绝
 * - 连续崩溃超限：槽位永久失效后池自愈重建，在队任务由新 Worker 继续服务
 * - 成功清零：连续失败计数在任务成功后重置，槽位不被误终止
 * - 池终止：在途/在队任务以明确错误 settle，后续提交被拒绝
 * - postMessage 同步异常：任务以明确错误 reject，不悬挂
 * - 背压：pending 达上限时新提交等待 drain
 * - 解密任务：结构化克隆提交、密文载荷可重放、队首优先、Worker 明确拒绝
 *   以 TaskRejectedError 区分于池故障（加密任务保持既有错误语义）
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  PhotoWorkerPool,
  PoolTerminatedError,
  PoisonPillError,
  TaskRejectedError,
  TaskTimeoutError,
  type SubmitInput,
} from "./photoWorkerPool";
import {
  MAX_TASK_ATTEMPTS,
  MAX_CONSECUTIVE_SLOT_CRASHES,
} from "../constants/crypto_const";

/* ------------------------------------------------------------------ *
 * Fake Worker                                                          *
 * ------------------------------------------------------------------ */

interface FakePosted {
  data: {
    id: number;
    fileBytes?: ArrayBuffer;
    /** 解密请求的操作标识（加密请求无该字段） */
    op?: string;
    /** 解密请求的块密文列表（重放一致性断言用） */
    chunksB64?: string[];
  };
  transfer: Transferable[];
}

/** 测试用 Worker 桩：记录投递、可注入崩溃/挂起/postMessage 异常 */
class FakeWorker {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  onmessageerror: (() => void) | null = null;

  posted: FakePosted[] = [];
  terminated = false;
  /** 下一次 postMessage 抛异常（模拟已终止 Worker 的投递竞态） */
  failNextPost = false;
  /** 严格克隆模式：投递前执行真实结构化克隆（与浏览器 postMessage 同语义，
   *  含 Proxy 等不可克隆值的载荷会抛 DataCloneError） */
  cloneStrict = false;

  postMessage(data: any, transfer?: Transferable[]): void {
    if (this.failNextPost) {
      this.failNextPost = false;
      throw new Error("postMessage failed");
    }
    if (this.cloneStrict) {
      structuredClone(data);
    }
    this.posted.push({ data, transfer: transfer ?? [] });
  }

  terminate(): void {
    this.terminated = true;
  }

  /** 对最近一次投递响应成功并消耗该投递 */
  answerLast(extra: Partial<Record<string, unknown>> = {}): void {
    const last = this.posted.pop();
    if (!last) throw new Error("no posted message to answer");
    this.emitSuccess(last, extra);
  }

  /** 对最近一次投递响应失败（Worker 已执行但明确拒绝） */
  emitFailureLast(error: string): void {
    const last = this.posted.pop();
    if (!last) throw new Error("no posted message to answer");
    this.onmessage?.({
      data: { id: last.data.id, ok: false, name: "a.jpg", error },
    } as unknown as MessageEvent);
  }

  /** 对指定投递条目响应成功（不依赖 posted 数组状态） */
  answer(post: FakePosted, extra: Partial<Record<string, unknown>> = {}): void {
    this.emitSuccess(post, extra);
  }

  private emitSuccess(post: FakePosted, extra: Partial<Record<string, unknown>>): void {
    this.onmessage?.({
      data: {
        id: post.data.id,
        ok: true,
        hash: "hash-1",
        thumbB64: "thumb",
        metaB64: "meta-b64",
        name: "meta_a.jpg",
        mime: "image/jpeg",
        size: 3,
        ...extra,
      },
    } as unknown as MessageEvent);
  }

  /** 模拟崩溃 */
  crash(reason = "injected-crash"): void {
    this.onerror?.({ message: reason } as unknown as ErrorEvent);
  }
}

/* ------------------------------------------------------------------ *
 * 夹具                                                                *
 * ------------------------------------------------------------------ */

function makeFileBytes(size = 4): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = i + 1;
  return bytes;
}

function makeInput(fileBytes: Uint8Array = makeFileBytes()): SubmitInput {
  return {
    fileBytes,
    request: { fileName: "a.jpg", mime: "image/jpeg", photoKey: "k" },
  };
}

interface Harness {
  pool: PhotoWorkerPool;
  workers: FakeWorker[];
}

function makePool(poolSize = 1, configure?: (w: FakeWorker) => void): Harness {
  const workers: FakeWorker[] = [];
  const pool = PhotoWorkerPool.create({
    poolSize,
    idleRecycleMs: 999_999_999,
    workerFactory: () => {
      const w = new FakeWorker();
      if (configure) configure(w);
      workers.push(w);
      return w as unknown as Worker;
    },
  });
  return { pool, workers };
}

/** submit 含多级 await 边界：排空微任务队列后 Worker 才被冷启动创建并收到投递。
 *  提交前置流程（终止检查 → 自愈 → 背压等待）为多级 await 链，单次 Promise.resolve
 *  不足以排空，故按固定轮数排空（与实现无关的稳健等待）。 */
const flush = async (): Promise<void> => {
  for (let i = 0; i < 8; i++) await Promise.resolve();
};

/** 最新 Worker */
const lastWorker = (h: Harness) => h.workers[h.workers.length - 1];

describe("photoWorkerPool — 韧性", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("正常任务：完成后返回加密结果，投递使用转移副本", async () => {
    const h = makePool();
    const p = h.pool.submit(makeInput());
    await flush();
    const w = h.workers[0];
    expect(w.posted.length).toBe(1);
    expect(w.posted[0].transfer).toHaveLength(1);
    w.answerLast();
    const result = await p;
    expect(result.hash).toBe("hash-1");
    expect(w.posted).toHaveLength(0);
  });

  it("崩溃重投可重放：两次投递字节一致且任务成功", async () => {
    const h = makePool();
    const original = makeFileBytes(8);
    const p = h.pool.submit(makeInput(original));
    await flush();

    const first = h.workers[0].posted[0];
    expect(first.transfer.length).toBe(1);
    const firstBytes = new Uint8Array(first.data.fileBytes as ArrayBuffer);

    // 调用方修改原引用：不影响池内权威副本
    original[0] = 0xff;

    // 崩溃 → 任务回队 → 重建槽位 → 重新投递
    h.workers[0].crash();
    await flush();
    expect(h.workers.length).toBe(2);
    // 旧 Worker 必须被显式回收（否则槽位替换后线程泄漏）
    expect(h.workers[0].terminated).toBe(true);
    const second = h.workers[1].posted[0];
    const secondBytes = new Uint8Array(second.data.fileBytes as ArrayBuffer);

    // 两次投递的转移副本字节一致（重放无损）
    expect(secondBytes).toEqual(firstBytes);

    h.workers[1].answer(second);
    const result = await p;
    expect(result.ok).toBe(true);
    // 两次投递都产生了有效转移副本（无 detached 重投异常）
    expect((first.transfer[0] as ArrayBuffer).byteLength).toBe(8);
    expect((second.transfer[0] as ArrayBuffer).byteLength).toBe(8);
  });

  it("毒丸隔离：达到最大尝试次数后拒绝，池仍服务后续任务", async () => {
    const h = makePool();
    const p = h.pool.submit(makeInput());
    await flush();

    // 每次崩溃任务回队并重投：attempts 达上限后判毒丸
    for (let i = 0; i < MAX_TASK_ATTEMPTS; i++) {
      lastWorker(h).crash();
      await flush();
    }
    await expect(p).rejects.toBeInstanceOf(PoisonPillError);
    expect(h.pool.getStats().poisonPills).toBe(1);

    // 池仍可用：新任务正常完成
    const p2 = h.pool.submit(makeInput());
    await flush();
    lastWorker(h).answerLast();
    await expect(p2).resolves.toMatchObject({ ok: true });
  });

  it("超时看门狗：挂起 Worker 被终止，任务重投后成功", async () => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date", "performance"],
    });
    const h = makePool();
    const p = h.pool.submit(makeInput());
    await vi.advanceTimersByTimeAsync(0);
    h.workers[0].posted.pop(); // Worker 收到任务但不响应（挂起）

    // 预算窗口（初始 60s）内无响应 → 看门狗终止 Worker 并重投
    await vi.advanceTimersByTimeAsync(120_000);
    expect(h.workers[0].terminated).toBe(true);

    // 重投到新槽位：等待投递完成（advance 期间同步发生）
    const retried = lastWorker(h);
    await vi.waitFor(() => expect(retried.posted.length).toBeGreaterThan(0));
    retried.answerLast();
    await expect(p).resolves.toMatchObject({ ok: true });
    expect(h.pool.getStats().timeouts).toBeGreaterThanOrEqual(1);
  });

  it("超时用尽尝试次数：以 TaskTimeoutError 拒绝，不悬挂", async () => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date", "performance"],
    });
    const h = makePool();
    // 提交即挂 catch 包装：吸收中途 rejection，避免 unhandled
    const p = h.pool.submit(makeInput()).then(
      (v) => ({ ok: true as const, v }),
      (e: Error) => ({ ok: false as const, e }),
    );
    await vi.advanceTimersByTimeAsync(0);
    // 每轮超时触发重投；总尝试次数用尽后拒绝
    for (let i = 0; i < MAX_TASK_ATTEMPTS; i++) {
      lastWorker(h).posted.pop();
      await vi.advanceTimersByTimeAsync(360_000);
    }
    const settled = await p;
    expect(settled.ok).toBe(false);
    expect((settled as { e: Error }).e).toBeInstanceOf(TaskTimeoutError);
  });

  it("连续崩溃超限后槽位永久失效：池自愈重建，新提交由全新 Worker 完成", async () => {
    const h = makePool();
    // 首个任务触发 Worker 冷启动（惰性创建），其后崩溃事件推进连续失败计数
    const seed = h.pool.submit(makeInput());
    await flush();
    seed.catch(() => { /* 种子任务由崩溃路径 settle */ });

    // 无在途任务也推进连续失败计数（崩溃事件即计数）
    for (let i = 0; i <= MAX_CONSECUTIVE_SLOT_CRASHES; i++) {
      lastWorker(h).crash();
      await flush();
    }
    expect(lastWorker(h).terminated).toBe(true);
    expect(h.pool.getStats().slotExhausted).toBe(1);

    // 池自愈：新提交不因历史失效而被拒绝——废弃失效槽位并冷启动新 Worker
    const revived = h.pool.submit(makeInput());
    await flush();
    expect(h.pool.getStats().poolRevivals).toBe(1);
    const fresh = lastWorker(h);
    expect(fresh.terminated).toBe(false);
    await vi.waitFor(() => expect(fresh.posted.length).toBeGreaterThan(0));
    fresh.answerLast();
    await expect(revived).resolves.toMatchObject({ hash: "hash-1" });
  });

  it("池自愈兜底：全部槽位失效时在队任务由重建后的新 Worker 继续服务", async () => {
    const h = makePool(1);
    // 4 个任务：1 个在途 + 3 个在队（池大小 1）
    const settled: Array<Promise<{ ok: boolean; e?: Error }>> = [];
    for (let i = 0; i < 4; i++) {
      settled.push(h.pool.submit(makeInput()).then(
        () => ({ ok: true as const }),
        (e: Error) => ({ ok: false as const, e }),
      ));
    }
    await flush();

    // 连续崩溃直至触发池自愈（全部槽位永久失效 → 重建）
    for (let i = 0; i < MAX_TASK_ATTEMPTS + MAX_CONSECUTIVE_SLOT_CRASHES + 2; i++) {
      lastWorker(h).crash();
      await flush();
      if (h.pool.getStats().poolRevivals >= 1) break;
    }
    expect(h.pool.getStats().poolRevivals).toBeGreaterThanOrEqual(1);

    // 自愈后：存活任务不被拒绝，由新 Worker 串行服务（逐条应答直至排空）
    const fresh = lastWorker(h);
    expect(fresh.terminated).toBe(false);
    for (let i = 0; i < 4 && h.pool.getStats().pendingTasks > 0; i++) {
      await vi.waitFor(() => expect(fresh.posted.length).toBeGreaterThan(0));
      fresh.answerLast();
      await flush();
    }

    const results = await Promise.all(settled);
    // 关键不变量：没有任何任务因「槽位全部失效」被池级拒绝——失败的只能是
    // 尝试次数耗尽的毒丸任务；槽位失效时仍在队的任务由自愈后的新 Worker 完成
    const okCount = results.filter((r) => r.ok).length;
    const failedCount = results.filter((r) => !r.ok).length;
    expect(okCount + failedCount).toBe(4);
    expect(okCount).toBeGreaterThanOrEqual(2);
    for (const r of results) {
      if (!r.ok) expect(r.e).toBeInstanceOf(PoisonPillError);
    }
    expect(h.pool.getStats().pendingTasks).toBe(0);
  });

  it("成功清零：连续崩溃计数在任务成功后重置", async () => {
    const h = makePool();

    /** 驱动一个任务经崩溃重投直至毒丸 settle（每轮消费其在投消息） */
    const driveToPoison = async () => {
      const p = h.pool.submit(makeInput());
      await flush();
      for (let i = 0; i < MAX_TASK_ATTEMPTS; i++) {
        const w = lastWorker(h);
        if (w.posted.length === 0) break;
        w.posted.pop();
        w.crash();
        await flush();
      }
      await expect(p).rejects.toBeInstanceOf(PoisonPillError);
    };

    // 第一段：3 次崩溃（毒丸路径），连续失败计数推至 3
    await driveToPoison();

    // 成功一个任务：连续失败计数清零
    const okTask = h.pool.submit(makeInput());
    await flush();
    lastWorker(h).answerLast();
    await expect(okTask).resolves.toMatchObject({ ok: true });

    // 第二段：再经历毒丸路径（若未清零则会累计超限导致槽位失效）
    await driveToPoison();

    // 槽位未失效：任务仍可正常完成
    expect(h.pool.getStats().slotExhausted).toBe(0);
    const finalTask = h.pool.submit(makeInput());
    await flush();
    await vi.waitFor(() => expect(lastWorker(h).posted.length).toBeGreaterThan(0));
    lastWorker(h).answerLast();
    await expect(finalTask).resolves.toMatchObject({ ok: true });
  });

  it("池终止：在途与在队任务以 PoolTerminatedError settle，后续提交被拒绝", async () => {
    const h = makePool(1);
    const inflight = h.pool.submit(makeInput());
    await flush();
    h.workers[0].posted.pop();
    const queued: Promise<unknown>[] = [];
    for (let i = 0; i < 3; i++) queued.push(h.pool.submit(makeInput()));

    h.pool.terminate();
    await expect(inflight).rejects.toBeInstanceOf(PoolTerminatedError);
    await Promise.all(queued.map((q) => expect(q).rejects.toBeInstanceOf(PoolTerminatedError)));
    await expect(h.pool.submit(makeInput())).rejects.toBeInstanceOf(PoolTerminatedError);
    expect(h.workers[0].terminated).toBe(true);
    expect(h.pool.getStats().pendingTasks).toBe(0);
  });

  it("postMessage 同步异常：任务以明确错误 reject，不悬挂", async () => {
    // 首个 Worker 的首次 postMessage 抛异常（configure 在工厂创建时注入）
    const h = makePool(1, (w) => { w.failNextPost = true; });
    const p = h.pool.submit(makeInput()).then(
      (v) => ({ ok: true as const, v }),
      (e: Error) => ({ ok: false as const, e }),
    );
    await flush();
    const settled = await p;
    expect(settled.ok).toBe(false);
    expect((settled as { e: Error }).e.message).toContain("Worker 通信失败");
    expect(h.pool.getStats().pendingTasks).toBe(0);
  });

  it("meta-only 任务走结构化克隆：无转移副本、可重放", async () => {
    const h = makePool();
    const p = h.pool.submitMetaOnly({
      meta: {
        name: "x.jpg", mime: "image/jpeg", size: 1, thumbB64: "t",
        chunkIds: [], fileHash: "fh", createdAt: 1,
      },
      photoKey: "k",
      recordName: "parsed_1",
    });
    await flush();
    const w = h.workers[0];
    expect(w.posted.length).toBe(1);
    expect(w.posted[0].transfer).toHaveLength(0);
    w.answerLast({ recordName: "parsed_1" });
    await expect(p).resolves.toMatchObject({ ok: true });
  });

  it("载荷含响应式代理（DataCloneError）：池自动脱代理净化并重投成功", async () => {
    // 严格克隆模式：投递前执行真实结构化克隆，代理载荷抛 DataCloneError
    const h = makePool(1, (w) => { w.cloneStrict = true; });

    // 模拟 Vue 响应式污染：meta 的嵌套数组字段为 Proxy（浅层展开不消除——
    // 与解析产物经 parsedPhotos(ref) 存储后的真实形态一致）
    const pollutedMeta = {
      name: "x.jpg", mime: "image/jpeg", size: 1, thumbB64: "t",
      chunkIds: [] as number[],
      chunkHashes: new Proxy(["h1"], {}),
      fileHash: "fh", createdAt: 1,
    };
    const p = h.pool.submitMetaOnly({
      meta: pollutedMeta,
      photoKey: "k",
      recordName: "parsed_1",
    });
    await flush();

    // 自愈重投：投递载荷已净化为可克隆纯数据（再次真实克隆不抛），任务正常完成
    const w = h.workers[0];
    expect(w.posted).toHaveLength(1);
    expect(() => structuredClone(w.posted[0].data)).not.toThrow();
    w.answerLast({ recordName: "parsed_1" });
    await expect(p).resolves.toMatchObject({ ok: true });
    // 任务级载荷缺陷不计入槽位崩溃/毒丸指标（槽位健康无涉）
    expect(h.pool.getStats().totalCrashes).toBe(0);
    expect(h.pool.getStats().poisonPills).toBe(0);
  });

  it("背压：pending 达上限时，新提交等待既有任务 drain 后执行", async () => {
    const h = makePool(1);
    // maxPendingTasks = poolSize * 4 = 4
    const tasks: Promise<unknown>[] = [];
    for (let i = 0; i < 4; i++) tasks.push(h.pool.submit(makeInput(makeFileBytes(2))));
    await flush();
    // 在途 1 + 队列 3 = 4 达到上限；第 5 个提交应等待 drain
    let settled = false;
    const fifth = h.pool.submit(makeInput(makeFileBytes(2))).then(() => { settled = true; });
    await flush();
    expect(settled).toBe(false);

    // 依次完成全部任务释放配额
    for (let i = 0; i < 5; i++) {
      await vi.waitFor(() => {
        expect(lastWorker(h).posted.length).toBeGreaterThan(0);
      });
      lastWorker(h).answerLast();
    }
    await fifth;
    await Promise.all(tasks);
    expect(settled).toBe(true);
  });

  it("waitForCapacity 读取闸门：配额可用时立即放行，达上限时挂起至任务 settle", async () => {
    const h = makePool(1);
    // maxPendingTasks = poolSize * 4 = 4：配额可用 → 立即放行
    await expect(h.pool.waitForCapacity()).resolves.toBeUndefined();

    // 填满配额后闸门挂起
    const tasks: Promise<unknown>[] = [];
    for (let i = 0; i < 4; i++) tasks.push(h.pool.submit(makeInput(makeFileBytes(2))));
    await flush();
    let released = false;
    const gate = h.pool.waitForCapacity().then(() => { released = true; });
    await flush();
    expect(released).toBe(false);

    // 完成全部任务释放配额 → 闸门放行
    for (let i = 0; i < 4; i++) {
      await vi.waitFor(() => {
        expect(lastWorker(h).posted.length).toBeGreaterThan(0);
      });
      lastWorker(h).answerLast();
    }
    await gate;
    await Promise.all(tasks);
    expect(released).toBe(true);
  });

  it("响应 ID 不匹配：按崩溃路径收敛（终止重建 + 重投），任务不悬挂", async () => {
    const h = makePool();
    const p = h.pool.submit(makeInput());
    await flush();

    // Worker 回显错配 ID（协议级异常）：旧槽位响应流不可信
    const stray = h.workers[0].posted[0];
    h.workers[0].onmessage?.({
      data: {
        id: stray.data.id + 999,
        ok: true,
        hash: "stray",
        thumbB64: "",
        metaB64: "",
        name: "stray.jpg",
        mime: "image/jpeg",
        size: 1,
      },
    } as unknown as MessageEvent);
    await flush();

    // 旧 Worker 被终止、槽位重建、在途任务重投到新 Worker
    expect(h.workers[0].terminated).toBe(true);
    expect(h.workers.length).toBe(2);
    const retried = h.workers[1];
    await vi.waitFor(() => expect(retried.posted.length).toBe(1));
    retried.answerLast();
    await expect(p).resolves.toMatchObject({ ok: true });
    expect(h.pool.getStats().pendingTasks).toBe(0);
  });

  it("解密 meta 任务：结构化克隆提交（无转移副本）、op 装配、结果透传", async () => {
    const h = makePool();
    const p = h.pool.submitDecryptMeta({ metaB64: "meta-cipher", photoKey: "k", label: "42" });
    await flush();
    const w = h.workers[0];
    expect(w.posted.length).toBe(1);
    expect(w.posted[0].transfer).toHaveLength(0);
    expect(w.posted[0].data.op).toBe("decrypt_meta");
    // id 由池分配（调用方不传），保证响应可关联
    expect(typeof w.posted[0].data.id).toBe("number");

    const meta = { name: "a.jpg", mime: "image/jpeg", size: 3, thumbB64: "t", chunkIds: [], fileHash: "f", createdAt: 1 };
    w.answerLast({ meta });
    await expect(p).resolves.toMatchObject({ ok: true, meta });
  });

  it("解密 chunks 任务：明文缓冲随响应回传，op 装配为 decrypt_chunks", async () => {
    const h = makePool();
    const p = h.pool.submitDecryptChunks({
      chunksB64: ["c1", "c2"],
      photoKey: "k",
      fileHashHex: "a".repeat(64),
      label: "a.jpg",
    });
    await flush();
    const w = h.workers[0];
    expect(w.posted[0].transfer).toHaveLength(0);
    expect(w.posted[0].data.op).toBe("decrypt_chunks");
    expect(w.posted[0].data.chunksB64).toEqual(["c1", "c2"]);

    const plaintexts = [new ArrayBuffer(2), new ArrayBuffer(3)];
    w.answerLast({ plaintexts });
    const result = await p;
    expect(result.plaintexts).toHaveLength(2);
    expect(result.plaintexts[1].byteLength).toBe(3);
  });

  it("解密任务崩溃重投：密文载荷两次投递一致（任务可重放）", async () => {
    const h = makePool();
    const p = h.pool.submitDecryptChunks({
      chunksB64: ["c1", "c2"],
      photoKey: "k",
      fileHashHex: "b".repeat(64),
      label: "a.jpg",
    });
    await flush();

    const first = h.workers[0].posted[0];
    h.workers[0].crash();
    await flush();
    expect(h.workers.length).toBe(2);
    const retried = h.workers[1];
    await vi.waitFor(() => expect(retried.posted.length).toBe(1));
    // 两次投递载荷一致：崩溃后重投不改变解密输入
    expect(retried.posted[0].data).toEqual(first.data);

    retried.answerLast({ plaintexts: [new ArrayBuffer(1)] });
    await expect(p).resolves.toMatchObject({ ok: true });
    expect(h.pool.getStats().pendingTasks).toBe(0);
  });

  it("解密任务队首优先：先于已排队的加密任务被投递", async () => {
    const h = makePool(1);
    const queued: Promise<unknown>[] = [];
    // 1 个在途 + 2 个在队的加密任务（池大小 1）
    for (let i = 0; i < 3; i++) {
      queued.push(h.pool.submit(makeInput()).catch(() => { /* 由用例自行收敛 */ }));
    }
    await flush();
    const decrypt = h.pool.submitDecryptMeta({ metaB64: "m", photoKey: "k", label: "1" });
    await flush();

    // 在途加密任务完成 → 下一个投递应为解密任务（插队到两条加密任务之前）
    const w = h.workers[0];
    w.answerLast();
    await flush();
    expect(w.posted).toHaveLength(1);
    expect(w.posted[0].data.op).toBe("decrypt_meta");

    w.answerLast({ meta: { name: "x" } });
    await expect(decrypt).resolves.toMatchObject({ ok: true });

    // 剩余加密任务照常完成（插队不改变其在队任务的服务保证）
    for (let i = 0; i < 2; i++) {
      await vi.waitFor(() => expect(w.posted.length).toBeGreaterThan(0));
      w.answerLast();
      await flush();
    }
    await Promise.all(queued);
  });

  it("解密任务被 Worker 明确拒绝：以 TaskRejectedError 拒绝（确定性失败）", async () => {
    const h = makePool();
    const p = h.pool.submitDecryptMeta({ metaB64: "bad", photoKey: "k", label: "7" });
    await flush();
    h.workers[0].emitFailureLast("元数据标签校验失败（密码错误或数据被篡改）");

    const settled = await p.then(() => null, (e: Error) => e);
    expect(settled).toBeInstanceOf(TaskRejectedError);
    expect((settled as TaskRejectedError).reason).toContain("标签校验失败");
    // 池状态收敛：拒绝后配额释放，后续任务不受影响
    expect(h.pool.getStats().pendingTasks).toBe(0);
  });

  it("加密任务被 Worker 拒绝：保持既有错误语义（普通 Error，非 TaskRejectedError）", async () => {
    const h = makePool();
    const p = h.pool.submit(makeInput());
    await flush();
    h.workers[0].emitFailureLast("加密阶段失败原因");

    const settled = await p.then(() => null, (e: Error) => e);
    expect(settled).toBeInstanceOf(Error);
    expect(settled).not.toBeInstanceOf(TaskRejectedError);
    expect((settled as Error).message).toBe("加密阶段失败原因");
  });

  it("解密任务超时用尽：以 TaskTimeoutError 拒绝（池故障类别，可回退）", async () => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date", "performance"],
    });
    const h = makePool();
    const p = h.pool.submitDecryptChunks({
      chunksB64: ["c1"],
      photoKey: "k",
      fileHashHex: "c".repeat(64),
      label: "a.jpg",
    }).then(
      (v) => ({ ok: true as const, v }),
      (e: Error) => ({ ok: false as const, e }),
    );
    await vi.advanceTimersByTimeAsync(0);
    // 每轮超时触发重投；总尝试次数用尽后拒绝
    for (let i = 0; i < MAX_TASK_ATTEMPTS; i++) {
      lastWorker(h).posted.pop();
      await vi.advanceTimersByTimeAsync(360_000);
    }
    const settled = await p;
    expect(settled.ok).toBe(false);
    expect((settled as { e: Error }).e).toBeInstanceOf(TaskTimeoutError);
  });
});