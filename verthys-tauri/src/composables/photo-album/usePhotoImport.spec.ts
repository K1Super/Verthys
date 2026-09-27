/**
 * usePhotoImport.spec.ts — 导入发起权状态机回归测试
 *
 * 覆盖：
 * - 文件对话框挂起期间连点导入：第二次调用立即返回（发起权互斥）
 * - 取消选择/看门狗超时后状态机回空闲态，可再次发起
 * - 流水线运行中重入被拒（importing 为 true 时入口不可达）
 * - 完成清理定时器纳管：旧代次回调不污染新一轮导入；正常倒计时清理
 * - 浏览器模式连点：只产生一个导入批次
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, ref, shallowRef } from "vue";

// vi.mock 工厂在模块顶部执行，实例方法 mock 需经 vi.hoisted 提升
const { runMock, runParsedMock } = vi.hoisted(() => ({
  runMock: vi.fn(),
  runParsedMock: vi.fn(),
}));

vi.mock("../../lib/verthys", () => ({
  readUserFile: vi.fn(async (_p: string) => new Uint8Array([1, 2, 3])),
}));
vi.mock("../../lib/keyManager", () => ({
  persistVerthysDetailed: vi.fn(async () => ({ kind: "ok" })),
  setModuleCache: vi.fn(),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
}));
vi.mock("./utils", () => {
  let memId = 1000;
  return {
    formatSize: vi.fn((n: number) => `${n}B`),
    generateThumbnail: vi.fn(async () => "thumb-b64"),
    guessMime: vi.fn(() => "image/jpeg"),
    nextMemoryPhotoId: () => ++memId,
    openBrowserFileDialog: vi.fn(),
    toArrayBuffer: vi.fn((bytes: Uint8Array) => bytes.buffer),
  };
});
vi.mock("./importPipeline", () => {
  class ImportPipeline {
    progress = {
      percent: ref(0),
      text: ref(""),
      elapsedMs: ref(0),
      etaMs: ref(0),
    };
    run = runMock;
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
      }))),
  };
});

import { usePhotoImport } from "./usePhotoImport";
import type { PhotoEntry } from "./types";
import { open } from "@tauri-apps/plugin-dialog";
import { openBrowserFileDialog, generateThumbnail } from "./utils";
import { importedToPhotoEntries } from "./importPipeline";
import { MAX_PHOTO_BYTES } from "../../constants/crypto_const";

type RunResult = {
  ok: boolean;
  imported: Array<{ metaId: number; name: string; thumbB64: string; size: number; mime: string }>;
  skipped: number;
  failed: number;
  elapsedMs: number;
  error?: string;
};

const okResult = (): RunResult => ({
  ok: true, imported: [], skipped: 0, failed: 0, elapsedMs: 1,
});

function makeTauri() {
  return usePhotoImport({
    photos: shallowRef([]),
    photoKey: ref("test-key"),
    isTauri: true,
    ensurePhotoKey: () => true,
    showError: vi.fn(),
  });
}

function makeBrowser() {
  return usePhotoImport({
    photos: shallowRef([]),
    photoKey: ref("test-key"),
    isTauri: false,
    ensurePhotoKey: () => true,
    showError: vi.fn(),
  });
}

// node 环境可能缺 URL.createObjectURL（浏览器分支依赖）：存在则保留原生实现，缺失则打桩
try {
  if (typeof URL.createObjectURL !== "function") {
    URL.createObjectURL = vi.fn(() => "blob:fake") as unknown as typeof URL.createObjectURL;
  }
} catch {
  /* 属性只读时保留现状，后续用例若触发会显式失败而非静默通过 */
}

describe("usePhotoImport — 导入发起权状态机", () => {
  let scope: ReturnType<typeof effectScope>;

  beforeEach(() => {
    vi.clearAllMocks();
    scope = effectScope();
    // pipeline 默认成功返回，避免各用例重复设置
    runMock.mockImplementation(async () => okResult());
  });

  afterEach(() => {
    scope.stop();
    vi.useRealTimers();
  });

  it("文件对话框挂起期间连点导入：第二次调用立即返回，对话框只打开一次", async () => {
    const api = scope.run(() => makeTauri())!;
    (open as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise(() => { /* 挂起：模拟用户停留在系统文件对话框中 */ }),
    );

    const p1 = api.onImport();
    const p2 = api.onImport();
    // 第二次入口同步返回（无任何 await 前即被发起权互斥拒绝）
    expect(open).toHaveBeenCalledTimes(1);
    // acquiring 期间不置 importing：进度条不出现假启动
    expect(api.importing.value).toBe(false);
    p1.catch(() => { /* 挂起 promise 永远不会 settle，测试不等待它 */ });
    p2.catch(() => { /* 同上 */ });
  });

  it("用户取消文件选择：状态机回空闲态，可再次发起", async () => {
    const api = scope.run(() => makeTauri())!;
    (open as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null).mockResolvedValueOnce(null);

    await api.onImport(); // 第一次：取消
    await api.onImport(); // 第二次：状态机若未复位则此处会被静默拒绝

    expect(open).toHaveBeenCalledTimes(2);
    expect(api.importing.value).toBe(false);
  });

  it("文件选择阶段看门狗超时后回空闲态，可再次发起", async () => {
    vi.useFakeTimers();
    const api = scope.run(() => makeTauri())!;
    (open as ReturnType<typeof vi.fn>).mockImplementationOnce(
      () => new Promise(() => { /* 永久挂起 */ }),
    );

    const p1 = api.onImport();
    // 30s 看门狗推进：acquiring 回 idle
    await vi.advanceTimersByTimeAsync(30_100);
    // 状态机已复位：新导入可以进入（open 第二次调用）
    (open as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
    await api.onImport();
    expect(open).toHaveBeenCalledTimes(2);
    p1.catch(() => { /* 挂起 promise 不等待 */ });
  });

  it("流水线运行中连点：导入入口被拒，run 仅调用一次", async () => {
    const api = scope.run(() => makeTauri())!;
    (open as ReturnType<typeof vi.fn>).mockResolvedValueOnce(["C:\\p\\a.jpg"]);
    let settleRun!: (v: RunResult) => void;
    runMock.mockImplementationOnce(
      () => new Promise<RunResult>((res) => { settleRun = res; }),
    );

    const p1 = api.onImport();
    await vi.waitFor(() => expect(api.importing.value).toBe(true));
    const p2 = api.onImport(); // running 中：立即返回
    expect(runMock).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledTimes(1);

    settleRun(okResult());
    await p1;
    await p2;
    expect(api.importing.value).toBe(false);
  });

  it("完成倒计时期间旧回调被接管：新一轮导入的视觉状态不被旧回调清空", async () => {
    vi.useFakeTimers();
    const api = scope.run(() => makeTauri())!;
    (open as ReturnType<typeof vi.fn>).mockResolvedValue(["C:\\p\\a.jpg"]);

    // 第一轮完成：进度 100，1.5s 清理回调进入挂起
    await api.onImport();
    expect(api.importProgress.value).toBe(100);

    // 600ms 后第二轮开始（收尾倒计时中接管：旧回调被 cancel）
    await vi.advanceTimersByTimeAsync(600);
    await api.onImport();
    expect(api.importProgress.value).toBe(100);
    api.importStatus.value = "完成：导入 0 张，去重跳过 0 张";
    await vi.advanceTimersByTimeAsync(400); // 累计 1000ms：超过旧回调原触发点
    // 旧回调已被取消：第二轮的视觉状态保持
    expect(api.importStatus.value).toBe("完成：导入 0 张，去重跳过 0 张");

    // 第二轮自己的回调在完成 1.5s 后正常清理
    await vi.advanceTimersByTimeAsync(1100);
    expect(api.importStatus.value).toBe("");
    expect(api.importProgress.value).toBe(0);
  });

  it("浏览器模式连点：只产生一个导入批次", async () => {
    const api = scope.run(() => makeBrowser())!;
    let settleRead!: (v: ArrayBuffer) => void;
    const fakeFile = {
      name: "a.jpg",
      arrayBuffer: () => new Promise<ArrayBuffer>((res) => { settleRead = res; }),
    };
    (openBrowserFileDialog as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce([fakeFile as unknown as File]);

    const p1 = api.onImport();
    await vi.waitFor(() => expect(api.importing.value).toBe(true));
    const p2 = api.onImport(); // 运行中：立即返回
    expect(openBrowserFileDialog).toHaveBeenCalledTimes(1);

    settleRead(new Uint8Array([1, 2, 3]).buffer);
    await p1;
    await p2;
    expect(importedToPhotoEntries).toHaveBeenCalledTimes(0);
    expect(api.importing.value).toBe(false);
  });

  it("浏览器模式完整导入：缩略图生成被调用且列表被填充", async () => {
    const photos = shallowRef<PhotoEntry[]>([]);
    const make = () => usePhotoImport({
      photos,
      photoKey: ref("test-key"),
      isTauri: false,
      ensurePhotoKey: () => true,
      showError: vi.fn(),
    });
    const api = scope.run(make)!;
    const fakeFile = {
      name: "b.jpg",
      arrayBuffer: async () => new Uint8Array([4, 5, 6]).buffer,
    };
    (openBrowserFileDialog as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce([fakeFile as unknown as File]);

    await api.onImport();
    expect(generateThumbnail).toHaveBeenCalledTimes(1);
    expect(photos.value.length).toBe(1);
  });

  it("浏览器模式超限文件：读前按 size 拒绝，字节不进入内存读取", async () => {
    const showError = vi.fn();
    const photos = shallowRef<PhotoEntry[]>([]);
    const api = scope.run(() => usePhotoImport({
      photos,
      photoKey: ref("test-key"),
      isTauri: false,
      ensurePhotoKey: () => true,
      showError,
    }))!;
    const arrayBuffer = vi.fn();
    const fakeFile = {
      name: "huge.jpg",
      size: MAX_PHOTO_BYTES + 1,
      arrayBuffer,
    } as unknown as File;
    (openBrowserFileDialog as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce([fakeFile]);

    await api.onImport();

    expect(arrayBuffer).not.toHaveBeenCalled();
    expect(generateThumbnail).not.toHaveBeenCalled();
    expect(photos.value.length).toBe(0);
    expect(showError).toHaveBeenCalled();
  });
});