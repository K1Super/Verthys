/**
 * usePhotoParse.spec.ts — 解析链路一致性回归测试
 *
 * 覆盖：
 * - 令牌归一化 + 格式预检：带空白令牌被 trim 后解析；过短令牌（低于最小长度）
 *   给出格式提示且不解密
 * - 不可解密分类：meta 解密失败的预览项计入 undecryptable，导入时不影响列表且文案说明原因
 * - 先落盘后入列：persistVerthys 失败时列表与模块缓存均不写入
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, ref, shallowRef, type EffectScope } from "vue";
import { installBase64Polyfill } from "../../test-utils/base64-polyfill";

// node 环境无 atob/btoa：预览块 base64 转换依赖，测试时补齐
installBase64Polyfill();

// node 环境无 rAF：感知进度状态机依赖帧对齐，测试中以宏任务近似单帧
if (typeof globalThis.requestAnimationFrame !== "function") {
  globalThis.requestAnimationFrame = (cb: FrameRequestCallback) =>
    setTimeout(() => cb(performance.now()), 0) as unknown as number;
}
if (typeof globalThis.cancelAnimationFrame !== "function") {
  globalThis.cancelAnimationFrame = ((id: ReturnType<typeof setTimeout>) =>
    clearTimeout(id)) as unknown as typeof cancelAnimationFrame;
}

const { runParsedMock, persistMock } =
  vi.hoisted(() => ({
    runParsedMock: vi.fn(),
    persistMock: vi.fn(),
  }));

vi.mock("../../lib/verthys", () => ({
  readUserFile: vi.fn(async () => new Uint8Array([1, 2, 3])),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../../lib/keyManager", () => ({
  persistVerthysDetailed: persistMock,
  setModuleCache: vi.fn(),
}));
vi.mock("./utils/timer", () => ({
  useSingleTimer: () => ({ cancel: vi.fn(), schedule: vi.fn(), dispose: vi.fn() }),
}));
vi.mock("./importPipeline", () => {
  class ImportPipeline {
    runParsed = runParsedMock;
  }
  return {
    ImportPipeline,
    importedToPhotoEntries: vi.fn((items: Array<{ metaId: number; name: string }>) =>
      items.map((it, i) => ({
        id: it.metaId,
        metaId: it.metaId,
        name: it.name,
        thumb: "",
        size: "0B",
        height: 180 + i,
      })),
    ),
  };
});

import { usePhotoParse, type ParseWorkerLike } from "./usePhotoParse";
import { setModuleCache } from "../../lib/keyManager";
import type { PhotoEntry } from "./types";
import type { ParseCryptoRequest, ParseCryptoResponse } from "../../workers/parse-crypto.worker";

const VALID_TOKEN = "a".repeat(64);

/** 伪解析 Worker：捕获请求并允许测试驱动响应（替代真实 Worker 构造） */
interface FakeParseWorker {
  requests: ParseCryptoRequest[];
  onmessage: ParseWorkerLike["onmessage"];
  onerror: ParseWorkerLike["onerror"];
  terminate: ReturnType<typeof vi.fn>;
  postMessage(msg: ParseCryptoRequest): void;
}

function makeFakeParseWorker(): FakeParseWorker {
  const worker: FakeParseWorker = {
    requests: [],
    onmessage: null,
    onerror: null,
    terminate: vi.fn(),
    postMessage(msg: ParseCryptoRequest) {
      worker.requests.push(msg);
    },
  };
  return worker;
}

/** 驱动伪 Worker 返回一条消息（模拟真实反序列化回调） */
function respond(worker: FakeParseWorker, data: ParseCryptoResponse) {
  worker.onmessage?.({ data } as MessageEvent<ParseCryptoResponse>);
}

type ParseDepsOverrides = {
  showError?: (msg: string) => void;
  showToast?: (msg: string) => void;
  photoKey?: string;
};

/** 构造预览响应单元（worker 完成消息中的照片项） */
function makePreview(name: string, hash: string) {
  return {
    name,
    thumb: "",
    size: 10,
    metaB64: "",
    chunkB64List: ["chunk-b64"],
    meta: {
      name,
      mime: "image/jpeg",
      size: 10,
      thumbB64: "",
      chunkIds: [],
      chunkDataB64: ["chunk-b64"],
      chunkHashes: [hash],
      fileHash: hash,
      createdAt: 1,
    },
  };
}

function makeParse(overrides: ParseDepsOverrides = {}) {
  const scope = effectScope();
  const photos = shallowRef<PhotoEntry[]>([]);
  const errorCalls: string[] = [];
  const toastCalls: string[] = [];
  const workers: FakeParseWorker[] = [];
  const api = scope.run(() =>
    usePhotoParse({
      photos,
      photoKey: ref(overrides.photoKey ?? "module-key"),
      isTauri: true,
      ensurePhotoKey: () => true,
      showError: (msg) => {
        errorCalls.push(msg);
        overrides.showError?.(msg);
      },
      showToast: (msg) => {
        toastCalls.push(msg);
        overrides.showToast?.(msg);
      },
      getPipeline: () => ({ runParsed: runParsedMock }) as never,
      importing: ref(false),
      importProgress: ref(0),
      importStatus: ref(""),
      importElapsed: ref(0),
      importEta: ref(0),
      parseWorkerFactory: () => {
        const worker = makeFakeParseWorker();
        workers.push(worker);
        return worker as unknown as ParseWorkerLike;
      },
    }),
  )!;
  return { api, photos, errorCalls, toastCalls, scope, workers };
}

describe("usePhotoParse — 令牌校验与归一化", () => {
  let made: ReturnType<typeof makeParse>;
  beforeEach(() => {
    vi.clearAllMocks();
    made = makeParse();
    made.api.parseFileData.value = new Uint8Array([1, 2, 3]);
  });
  afterEach(() => {
    made.scope.stop();
    vi.useRealTimers();
  });

  it("非法令牌（长度不符）被前置拦截：给出格式提示且不启动解析", async () => {
    made.api.parseToken.value = "abc123";
    await made.api.doParse();

    expect(made.workers).toHaveLength(0);
    expect(made.errorCalls.some((m) => m.includes("令牌格式不正确"))).toBe(true);
  });

  it("带首尾空白的合法令牌被归一化：trim 后以 64 位 hex 移交解析 Worker", async () => {
    vi.useFakeTimers();
    made.api.parseToken.value = `  ${VALID_TOKEN}\n`;
    const p = made.api.doParse();
    await vi.advanceTimersByTimeAsync(0);

    // doParse 启动解析 Worker 并移交归一化后的令牌
    expect(made.workers).toHaveLength(1);
    const req = made.workers[0].requests[0];
    expect(req.token).toBe(VALID_TOKEN);
    expect(req.photoKey).toBe("module-key");

    // 驱动 Worker 完成响应
    respond(made.workers[0], {
      id: 1,
      type: "success",
      ok: true,
      previews: [makePreview("归一化.jpg", "f".repeat(64))],
      undecryptable: 0,
      emptyCount: 0,
    });
    await vi.advanceTimersByTimeAsync(3000);
    await p;

    expect(made.api.parsedPhotos.value).toHaveLength(1);
    expect(made.api.parsedPhotos.value[0].name).toBe("归一化.jpg");
    expect(made.api.parseToken.value).toBe(VALID_TOKEN);
    expect(made.workers[0].terminate).toHaveBeenCalled();
  });

  it("可解密性预检：worker 报告不可解密数量计入 parsedUndecryptable", async () => {
    vi.useFakeTimers();
    made.api.parseToken.value = VALID_TOKEN;
    const p = made.api.doParse();
    await vi.advanceTimersByTimeAsync(0);

    respond(made.workers[0], {
      id: 1,
      type: "success",
      ok: true,
      previews: [
        makePreview("可解密.jpg", "e".repeat(64)),
        makePreview("不可解密.jpg", "d".repeat(64)),
      ],
      undecryptable: 1,
      // 空数据记录与"密钥不匹配"分列：预检结果必须分别计数供 UI 准确归因
      emptyCount: 2,
    });
    await vi.advanceTimersByTimeAsync(3000);
    await p;

    expect(made.api.parsedPhotos.value).toHaveLength(2);
    expect(made.api.parsedUndecryptable.value).toBe(1);
    expect(made.api.parsedEmpty.value).toBe(2);
  });

  it("worker 失败（密钥错误）：分类文案提示且不装载预览", async () => {
    vi.useFakeTimers();
    made.api.parseToken.value = VALID_TOKEN;
    const p = made.api.doParse();
    await vi.advanceTimersByTimeAsync(0);

    respond(made.workers[0], {
      id: 1,
      type: "failure",
      ok: false,
      error: "TAG_VERIFICATION_FAILED",
    });
    await vi.advanceTimersByTimeAsync(3000);
    await p;

    expect(made.api.parsedPhotos.value).toHaveLength(0);
    expect(made.errorCalls.some((m) => m.includes("密钥不正确"))).toBe(true);
  });
});

describe("usePhotoParse — 成功语义（先落盘后入列 / 不可解密不入列）", () => {
  let made: ReturnType<typeof makeParse>;
  beforeEach(() => {
    vi.clearAllMocks();
    made = makeParse();
    persistMock.mockResolvedValue({ kind: "ok" });
    runParsedMock.mockResolvedValue({
      ok: true,
      imported: [],
      failedRecords: [],
      skipped: 0,
      undecryptable: 0,
      total: 0,
      elapsedMs: 1,
    });
  });
  afterEach(() => made.scope.stop());

  it("持久化失败（not_persisted）：列表与模块缓存均不写入，保留提示供重试", async () => {
    runParsedMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 100, name: "a.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 0,
      undecryptable: 0,
      total: 1,
      elapsedMs: 1,
    });
    persistMock.mockResolvedValue({ kind: "not_persisted", reason: "flush failed" });
    made.api.parsedPhotos.value = [{
      name: "a.jpg",
      thumb: "",
      size: 10,
      metaB64: "m",
      chunkB64List: ["c"],
      meta: {
        name: "a.jpg",
        mime: "image/jpeg",
        size: 10,
        thumbB64: "",
        chunkIds: [],
        chunkDataB64: ["c"],
        fileHash: "d".repeat(64),
        createdAt: 1,
      },
    }];

    await made.api.importParsedPhotos();

    expect(made.photos.value).toHaveLength(0);
    expect(setModuleCache).not.toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("持久化失败"))).toBe(true);
  });

  it("部分落盘（partial_persisted）：列表仍提交 + 非 error 警告 toast", async () => {
    runParsedMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 150, name: "p.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 0,
      undecryptable: 0,
      total: 1,
      elapsedMs: 1,
    });
    persistMock.mockResolvedValue({
      kind: "partial_persisted",
      reason: "verify failed (status 1)",
      statusCode: 1,
      detail: "frame magic mismatch",
    });
    made.api.parsedPhotos.value = [{
      name: "p.jpg",
      thumb: "",
      size: 10,
      metaB64: "m",
      chunkB64List: ["c"],
      meta: {
        name: "p.jpg",
        mime: "image/jpeg",
        size: 10,
        thumbB64: "",
        chunkIds: [],
        chunkDataB64: ["c"],
        fileHash: "e".repeat(64),
        createdAt: 1,
      },
    }];

    await made.api.importParsedPhotos();

    // 数据已落盘：列表必须提交，缓存同步；不得报 error 红条
    expect(made.photos.value).toHaveLength(1);
    expect(setModuleCache).toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("持久化失败"))).toBe(false);
    expect(made.toastCalls.some((m) => m.includes("校验警告"))).toBe(true);
  });

  it("含不可解密项：成功导入可导入部分，文案说明不可解密原因", async () => {
    runParsedMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 200, name: "b.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 0,
      undecryptable: 1,
      total: 2,
      elapsedMs: 1,
    });
    made.api.parsedPhotos.value = [{
      name: "b.jpg",
      thumb: "",
      size: 10,
      metaB64: "m",
      chunkB64List: ["c"],
      meta: {
        name: "b.jpg",
        mime: "image/jpeg",
        size: 10,
        thumbB64: "",
        chunkIds: [],
        chunkDataB64: ["c"],
        fileHash: "c".repeat(64),
        createdAt: 1,
      },
    }];

    await made.api.importParsedPhotos();

    expect(made.toastCalls.some((m) => m.includes("无法用当前密钥解密"))).toBe(true);
  });

  it("流水线报告 ok=false 且含失败明细：按失败计数提示，不谎报成功", async () => {
    runParsedMock.mockResolvedValue({
      ok: false,
      imported: [],
      failedRecords: [{ index: 0, name: "x.jpg", reason: "server-rejected", retryable: true }],
      skipped: 0,
      undecryptable: 0,
      total: 1,
      elapsedMs: 1,
    });
    made.api.parsedPhotos.value = [];

    await made.api.importParsedPhotos();

    expect(made.errorCalls.some((m) => m.includes("失败 1 张"))).toBe(true);
  });
});