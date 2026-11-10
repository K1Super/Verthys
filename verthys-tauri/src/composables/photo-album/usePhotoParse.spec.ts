/**
 * usePhotoParse.spec.ts — 备份还原链路回归测试
 *
 * 覆盖：
 * - 模块密钥闸门：锁定后 doParse 直接中止并提示，不启动 Worker
 * - 令牌归一化 + 格式预检：带空白令牌被 trim 后解析；过短令牌给出格式提示
 * - 预览装载：Worker 只回清单字段，主线程直接装载，不保留块载荷
 * - Tauri 导入：按原路径重读容器，交给 runContainer（字节与令牌）
 * - 先落盘后入列：persistVerthys 失败时列表与模块缓存均不写入
 * - 部分落盘：列表提交 + 校验警告提示，不报 error
 * - 去重跳过与失败计数：文案仅由真实结果派生
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, ref, shallowRef } from "vue";
import { installBase64Polyfill } from "../../test-utils/base64-polyfill";

// node 环境无 atob/btoa：预览/导入链路依赖
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

const { runContainerMock, readUserFileMock, persistMock } =
  vi.hoisted(() => ({
    runContainerMock: vi.fn(),
    readUserFileMock: vi.fn(async () => new Uint8Array([1, 2, 3])),
    persistMock: vi.fn(),
  }));

vi.mock("../../lib/verthys", () => ({
  readUserFile: readUserFileMock,
  userFileStat: vi.fn(async () => ({ size: 3 })),
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
    runContainer = runContainerMock;
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
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import type { ParseCryptoRequest, ParseCryptoResponse } from "../../workers/parse-crypto.worker";

const VALID_TOKEN = "a".repeat(64);

/** 伪解析 Worker：捕获请求并允许测试驱动响应（替代真实 Worker 构造） */
interface FakeParseWorker {
  requests: ParseCryptoRequest[];
  transfers: Transferable[][];
  onmessage: ParseWorkerLike["onmessage"];
  onerror: ParseWorkerLike["onerror"];
  terminate: ReturnType<typeof vi.fn>;
  postMessage(msg: ParseCryptoRequest, transfer?: Transferable[]): void;
}

function makeFakeParseWorker(): FakeParseWorker {
  const worker: FakeParseWorker = {
    requests: [],
    transfers: [],
    onmessage: null,
    onerror: null,
    terminate: vi.fn(),
    postMessage(msg: ParseCryptoRequest, transfer?: Transferable[]) {
      worker.requests.push(msg);
      worker.transfers.push(transfer ?? []);
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
  ensurePhotoKey?: () => boolean;
};

/** 构造预览项（新契约：只含清单字段） */
function makePreview(name: string, hash: string): ParsedPhotoPreview {
  return {
    name,
    thumb: "",
    size: 10,
    mime: "image/jpeg",
    fileHash: hash,
    chunkCount: 1,
    createdAt: 1,
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
      isTauri: true,
      ensurePhotoKey: overrides.ensurePhotoKey ?? (() => true),
      showError: (msg) => {
        errorCalls.push(msg);
        overrides.showError?.(msg);
      },
      showToast: (msg) => {
        toastCalls.push(msg);
        overrides.showToast?.(msg);
      },
      getPipeline: () => ({ runContainer: runContainerMock }) as never,
      importProgress: ref(0),
      importStatus: ref(""),
      importElapsed: ref(0),
      parseWorkerFactory: () => {
        const worker = makeFakeParseWorker();
        workers.push(worker);
        return worker as unknown as ParseWorkerLike;
      },
    }),
  )!;
  return { api, photos, errorCalls, toastCalls, scope, workers };
}

describe("usePhotoParse — 令牌校验、密钥闸门与预览装载", () => {
  let made: ReturnType<typeof makeParse>;
  beforeEach(() => {
    vi.clearAllMocks();
    made = makeParse();
    made.api.parseFileData.value = new Uint8Array([1, 2, 3]);
    made.api.parseFilePath.value = "C:/backup.venc";
  });
  afterEach(() => {
    made.scope.stop();
    vi.useRealTimers();
  });

  it("模块密钥锁定：doParse 直接中止并提示，不启动解析 Worker", async () => {
    made.scope.stop();
    vi.clearAllMocks();
    made = makeParse({ ensurePhotoKey: () => false });
    made.api.parseFileData.value = new Uint8Array([1, 2, 3]);
    made.api.parseToken.value = VALID_TOKEN;

    await made.api.doParse();

    expect(made.workers).toHaveLength(0);
    expect(made.errorCalls.some((m) => m.includes("已锁定"))).toBe(true);
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

    expect(made.workers).toHaveLength(1);
    const req = made.workers[0].requests[0];
    expect(req.token).toBe(VALID_TOKEN);
    expect(made.workers[0].transfers[0]).toHaveLength(1);

    respond(made.workers[0], {
      id: 1,
      type: "success",
      ok: true,
      previews: [makePreview("归一化.jpg", "f".repeat(64))],
    });
    await vi.advanceTimersByTimeAsync(3000);
    await p;

    expect(made.api.parsedPhotos.value).toHaveLength(1);
    expect(made.api.parsedPhotos.value[0]).toEqual(makePreview("归一化.jpg", "f".repeat(64)));
    expect(made.api.parseToken.value).toBe(VALID_TOKEN);
    expect(made.workers[0].terminate).toHaveBeenCalled();
  });

  it("旧版本容器：明确提示不再支持，不与文件损坏混同", async () => {
    vi.useFakeTimers();
    made.api.parseToken.value = VALID_TOKEN;
    const p = made.api.doParse();
    await vi.advanceTimersByTimeAsync(0);

    respond(made.workers[0], {
      id: 1,
      type: "failure",
      ok: false,
      error: "[UNSUPPORTED_VERSION] 不支持的备份格式版本: 2（当前支持 3）",
    });
    await vi.advanceTimersByTimeAsync(3000);
    await p;

    expect(made.errorCalls.some((m) => m.includes("旧版本格式"))).toBe(true);
    expect(made.errorCalls.some((m) => m.includes("格式无法识别"))).toBe(false);
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

describe("usePhotoParse — 成功语义（先落盘后入列 / 内容去重）", () => {
  let made: ReturnType<typeof makeParse>;
  beforeEach(() => {
    vi.clearAllMocks();
    made = makeParse();
    made.api.parseFilePath.value = "C:/backup.venc";
    made.api.parseToken.value = VALID_TOKEN;
    persistMock.mockResolvedValue({ kind: "ok" });
    readUserFileMock.mockResolvedValue(new Uint8Array([9, 9, 9]));
    runContainerMock.mockResolvedValue({
      ok: true,
      imported: [],
      failedRecords: [],
      skipped: 0,
      total: 0,
      elapsedMs: 1,
    });
  });
  afterEach(() => made.scope.stop());

  it("缺少文件路径：提示重新选择，不调用流水线", async () => {
    made.api.parseFilePath.value = null;
    made.api.parsedPhotos.value = [makePreview("无路径.jpg", "a".repeat(64))];

    await made.api.importParsedPhotos();

    expect(runContainerMock).not.toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("重新选择备份文件"))).toBe(true);
  });

  it("Tauri 导入：按路径重读容器，字节与令牌一并交给 runContainer", async () => {
    const previews = [makePreview("a.jpg", "a".repeat(64))];
    made.api.parsedPhotos.value = previews;
    runContainerMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 100, name: "a.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 0,
      total: 1,
      elapsedMs: 1,
    });

    await made.api.importParsedPhotos();

    expect(readUserFileMock).toHaveBeenCalledWith("C:/backup.venc");
    expect(runContainerMock).toHaveBeenCalledTimes(1);
    const [passedPreviews, source] = runContainerMock.mock.calls[0];
    expect(passedPreviews).toBe(previews);
    expect(source).toEqual({ bytes: new Uint8Array([9, 9, 9]), token: VALID_TOKEN });
    expect(made.photos.value).toHaveLength(1);
  });

  it("持久化失败（not_persisted）：列表与模块缓存均不写入，保留提示供重试", async () => {
    made.api.parsedPhotos.value = [makePreview("a.jpg", "d".repeat(64))];
    runContainerMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 100, name: "a.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 0,
      total: 1,
      elapsedMs: 1,
    });
    persistMock.mockResolvedValue({ kind: "not_persisted", reason: "flush failed" });

    await made.api.importParsedPhotos();

    expect(made.photos.value).toHaveLength(0);
    expect(setModuleCache).not.toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("持久化失败"))).toBe(true);
  });

  it("部分落盘（partial_persisted）：列表仍提交 + 非 error 警告 toast", async () => {
    made.api.parsedPhotos.value = [makePreview("p.jpg", "e".repeat(64))];
    runContainerMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 150, name: "p.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 0,
      total: 1,
      elapsedMs: 1,
    });
    persistMock.mockResolvedValue({
      kind: "partial_persisted",
      reason: "verify failed (status 1)",
      statusCode: 1,
      detail: "frame magic mismatch",
    });

    await made.api.importParsedPhotos();

    // 数据已落盘：列表必须提交，缓存同步；不得报 error 红条
    expect(made.photos.value).toHaveLength(1);
    expect(setModuleCache).toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("持久化失败"))).toBe(false);
    expect(made.toastCalls.some((m) => m.includes("校验警告"))).toBe(true);
  });

  it("去重跳过：文案与 toast 均反映跳过张数", async () => {
    made.api.parsedPhotos.value = [makePreview("b.jpg", "b".repeat(64))];
    runContainerMock.mockResolvedValue({
      ok: true,
      imported: [{ metaId: 200, name: "b.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [],
      skipped: 1,
      total: 2,
      elapsedMs: 1,
    });

    await made.api.importParsedPhotos();

    expect(made.toastCalls.some((m) => m.includes("去重跳过 1 张"))).toBe(true);
  });

  it("部分失败：成功项先落盘并提交列表/缓存，失败项提示重试", async () => {
    made.api.parsedPhotos.value = [
      makePreview("ok.jpg", "a".repeat(64)),
      makePreview("bad.jpg", "b".repeat(64)),
    ];
    runContainerMock.mockResolvedValue({
      ok: false,
      imported: [{ metaId: 300, name: "ok.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [{ index: 1, name: "bad.jpg", reason: "chunk-upload-failed", retryable: true }],
      skipped: 0,
      total: 2,
      elapsedMs: 1,
      error: undefined,
    });

    await made.api.importParsedPhotos();

    // 已提交批次的成功项必须落盘并进入列表，不能因整体 ok=false 而丢失
    expect(persistMock).toHaveBeenCalledTimes(1);
    expect(made.photos.value).toHaveLength(1);
    expect(setModuleCache).toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("失败 1 张"))).toBe(true);
  });

  it("部分失败但落盘失败：不提交列表，明确提示未生效", async () => {
    made.api.parsedPhotos.value = [makePreview("p.jpg", "c".repeat(64))];
    runContainerMock.mockResolvedValue({
      ok: false,
      imported: [{ metaId: 301, name: "p.jpg", thumbB64: "", size: 10, mime: "image/jpeg" }],
      failedRecords: [{ index: 1, name: "x.jpg", reason: "unknown", retryable: true }],
      skipped: 0,
      total: 2,
      elapsedMs: 1,
      error: undefined,
    });
    persistMock.mockResolvedValue({ kind: "not_persisted", reason: "flush failed" });

    await made.api.importParsedPhotos();

    expect(made.photos.value).toHaveLength(0);
    expect(setModuleCache).not.toHaveBeenCalled();
    expect(made.errorCalls.some((m) => m.includes("持久化失败"))).toBe(true);
  });

  it("流水线报告 ok=false 且含失败明细：按失败计数提示，不谎报成功", async () => {
    made.api.parsedPhotos.value = [];
    runContainerMock.mockResolvedValue({
      ok: false,
      imported: [],
      failedRecords: [{ index: 0, name: "x.jpg", reason: "server-rejected", retryable: true }],
      skipped: 0,
      total: 1,
      elapsedMs: 1,
    });

    await made.api.importParsedPhotos();

    expect(made.errorCalls.some((m) => m.includes("失败 1 张"))).toBe(true);
  });
});
