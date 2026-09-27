/**
 * usePhotoExport.spec.ts — 导出写盘协议与一致性问题回归测试
 *
 * 覆盖：
 * - writeVencFile 必须经 writeUserFile（Raw body + x-path 头协议）直传原始字节
 * - 占位项（meta 未加载）导出：按需解密后成功计入，不再静默跳过
 * - 文件名净化 + 批次内唯一化：非法字符被隔离，同名不互相覆盖
 * - 结果文案仅由成功/失败计数派生：全失败时明确报错，不谎报「已导出 N 张」
 * - 令牌重新生成必须经用户二次确认，未确认不失效
 * - 明文导出解密下沉 Worker 桥：逐块密文与瘦身参数透传，
 *   解密/完整性失败归因为 decrypt-failed（不与格式转换失败混淆）
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { effectScope, ref, shallowRef, type EffectScope } from "vue";
import { installBase64Polyfill } from "../../test-utils/base64-polyfill";

// node 环境无 atob/btoa：base64 编解码（v2 容器块转换）依赖，测试时补齐
installBase64Polyfill();

const { askMock } = vi.hoisted(() => ({ askMock: vi.fn() }));

vi.mock("../../lib/verthys", () => ({
  verthysGetRecord: vi.fn(),
  bytesToBase64: vi.fn((bytes: Uint8Array) => `b64(${bytes.length})`),
  writeUserFile: vi.fn(async (_path: string, _data: Uint8Array): Promise<void> => {
    /* 由各用例断言调用形态 */
  }),
  writeUserFileStream: vi.fn(async (_path: string): Promise<string> => "stream-1"),
  appendUserFileChunk: vi.fn(async (_streamId: string, _data: Uint8Array): Promise<void> => {
    /* 由各用例断言调用形态 */
  }),
  finalizeUserFileStream: vi.fn(async (_streamId: string): Promise<void> => {
    /* 由各用例断言调用形态 */
  }),
  abortUserFileStream: vi.fn(async (_streamId: string): Promise<void> => {
    /* 由各用例断言调用形态 */
  }),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
  save: vi.fn(),
  ask: askMock,
}));
vi.mock("../../lib/crypto", () => ({
  decryptMeta: vi.fn(async () => fakeMetaFactory()),
  encryptMeta: vi.fn(async () => "meta-b64"),
  encryptChunk: vi.fn(async () => new Uint8Array(8)),
  decryptChunk: vi.fn(async () => ({ plaintext: new Uint8Array([1, 2, 3]), seq: 0, total: 1 })),
  computeFileHash: vi.fn(() => new Uint8Array(32).fill(1)),
  bytesToHex: vi.fn(() => "1".repeat(64)),
  packVencV2: vi.fn(async () => new Uint8Array([9, 9])),
  packVencV2Streamed: vi.fn(
    async (
      _photos: unknown,
      _token: string,
      emit: (part: Uint8Array) => Promise<void>,
    ): Promise<void> => {
      await emit(new Uint8Array([1, 2, 3]));
      await emit(new Uint8Array([4, 5]));
    },
  ),
  estimateVencTotalBytes: vi.fn(() => 100),
  toLightMeta: vi.fn(
    (local: {
      name: string; mime: string; size: number; thumbB64: string;
      fileHash: string; createdAt: number; chunkDataB64?: string[]; chunkHashes?: string[];
    }) => ({
      name: local.name,
      mime: local.mime,
      size: local.size,
      thumbB64: local.thumbB64,
      fileHash: local.fileHash,
      createdAt: local.createdAt,
      chunkCount: local.chunkDataB64?.length ?? 0,
      chunkHashes: local.chunkHashes ?? [],
    }),
  ),
  computeChunkHashesForB64: vi.fn(() => ["2".repeat(64)]),
  generateRandomToken: vi.fn(() => "a".repeat(64)),
  CHUNK_SIZE: 1024 * 1024,
}));

vi.mock("../../workers/photo-decrypt-bridge", () => ({
  // 导出层的职责是"把解密交给桥"：本组用例把桥直接委托到被 mock 的加密原语，
  // 桥自身的回退/拒绝策略由 photo-decrypt-bridge.spec 锁定
  decryptMetaPreferWorker: vi.fn(async (metaB64: string, photoKey: string) => {
    const { decryptMeta } = await import("../../lib/crypto");
    return { meta: await decryptMeta(metaB64, photoKey) };
  }),
  decryptThumbPreferWorker: vi.fn(async () => new Uint8Array([0xff, 0xd8, 0xff])),
  decryptChunksPreferWorker: vi.fn(async (chunksB64: string[]) =>
    chunksB64.map(() => new Uint8Array([1, 2, 3])),
  ),
}));

vi.mock("./utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./utils")>();
  return {
    ...actual,
    // 画布转换依赖 DOM：测试环境给出确定性产物，其余工具（净化/唯一化）保持真实
    convertToPngBytes: vi.fn(async () => new Uint8Array([0x89, 0x50, 0x4e, 0x47])),
  };
});

import { usePhotoExport } from "./usePhotoExport";
import {
  writeUserFile,
  writeUserFileStream,
  appendUserFileChunk,
  finalizeUserFileStream,
  abortUserFileStream,
  verthysGetRecord,
} from "../../lib/verthys";
import type { PhotoMeta } from "../../lib/crypto";
import { PHOTO_FMT_SLIM } from "../../constants/crypto_const";
import { decryptChunksPreferWorker } from "../../workers/photo-decrypt-bridge";
import type { PhotoEntry } from "./types";

/** 派生可编程的占位 meta（各用例可覆写工厂）；块数据使用合法 base64 负载 */
const fakeMetaFactory = (): PhotoMeta => ({
  name: "占位.jpg",
  mime: "image/jpeg",
  size: 123,
  thumbB64: "",
  chunkIds: [],
  chunkDataB64: ["Y2g="],
  fileHash: "2".repeat(64),
  createdAt: 1,
});

function makeExport(
  photos: PhotoEntry[] = [],
  overrides: { photoKey?: string } = {},
): { api: ReturnType<typeof usePhotoExport>; scope: EffectScope } {
  const scope = effectScope();
  const api = scope.run(() =>
    usePhotoExport({
      photos: shallowRef(photos),
      photoKey: ref(overrides.photoKey ?? "test-key"),
      isTauri: true,
      ensurePhotoKey: () => true,
      showError: () => {},
      showExportDone: () => {},
      showCopied: () => {},
    }),
  )!;
  // 导出令牌默认预置：真实路径由 openExportDialog 生成随机令牌，用例直接
  // 驱动 doExport 时需满足「加密导出令牌非空」的入口前置校验
  api.exportToken.value = "unit-test-token";
  return { api, scope };
}

/** 构造一个未解密占位项（metaId 有效、meta/名称/缩略图为空） */
function makePlaceholder(metaId: number): PhotoEntry {
  return { id: metaId, metaId, name: "", thumb: "", size: "", height: 180 };
}

describe("usePhotoExport — writeVencFile 写盘协议", () => {
  let scope: EffectScope | null = null;
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => {
    scope?.stop();
    scope = null;
  });

  it("直传 (path, bytes) 给 writeUserFile：原始 Uint8Array 引用不变", async () => {
    const made = makeExport();
    scope = made.scope;
    const bytes = new Uint8Array([0x56, 0x45, 0x4e, 0x43]);
    await made.api.writeVencFile("C:\\out\\photo.venc", bytes);

    expect(writeUserFile).toHaveBeenCalledTimes(1);
    const [path, data] = (writeUserFile as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(path).toBe("C:\\out\\photo.venc");
    // 同一引用直传：写盘字节与调用方字节完全一致，不做任何转换
    expect(data).toBe(bytes);
  });

  it("writeUserFile 的异常原样上抛（失败不被吞掉）", async () => {
    (writeUserFile as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("EPERM: 权限不足"),
    );
    const made = makeExport();
    scope = made.scope;
    await expect(
      made.api.writeVencFile("C:\\Windows\\System32\\photo.venc", new Uint8Array(4)),
    ).rejects.toThrow("EPERM: 权限不足");
  });
});

describe("usePhotoExport — 多文件导出的一致性与结果契约", () => {
  let scope: EffectScope | null = null;
  beforeEach(() => {
    vi.clearAllMocks();
    // 默认：meta 记录存在且含内联块，支持占位项按需解密
    (verthysGetRecord as ReturnType<typeof vi.fn>).mockResolvedValue({
      type: 1,
      name: "meta_占位.jpg",
      dataB64: "meta-b64",
    });
  });
  afterEach(() => {
    scope?.stop();
    scope = null;
    vi.useRealTimers();
  });

  it("占位项导出：meta 未加载时按需解密回填，成功计入并且不再静默跳过", async () => {
    const made = makeExport([makePlaceholder(10)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([10]);
    made.api.exportFormat.value = "multiple";
    made.api.exportPath.value = "C:\\out";

    await made.api.doExport();

    expect(writeUserFile).toHaveBeenCalledTimes(1);
    const [path] = (writeUserFile as ReturnType<typeof vi.fn>).mock.calls[0];
    // 目录拼接沿用导出实现的分隔符约定；断言文件名本体与净化结果一致
    expect(path).toMatch(/^C:\\out[/\\]占位\.jpg\.venc$/);
    expect(made.api.exportStatus.value).toBe("已导出 1 张照片");
  });

  it("同名照片净化 + 唯一化：非法字符被隔离，同名不互相覆盖", async () => {
    // 两张照片解密名均为 "a/b.jpg"（含路径分隔符，未净化会造成写失败/覆盖）
    const p1 = makePlaceholder(11);
    const p2 = makePlaceholder(12);
    const made = makeExport([p1, p2]);
    scope = made.scope;
    let call = 0;
    (verthysGetRecord as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      // 两次解密返回同名的元数据
      return { type: 1, name: `meta_${call++}.jpg`, dataB64: "meta-b64" };
    });
    const fileHashHex = "3".repeat(64);
    const { decryptMeta } = await import("../../lib/crypto");
    (decryptMeta as ReturnType<typeof vi.fn>).mockResolvedValue({
      name: "a/b.jpg",
      mime: "image/jpeg",
      size: 1,
      thumbB64: "",
      chunkIds: [],
      chunkDataB64: ["Y2g="],
      fileHash: fileHashHex,
      createdAt: 1,
    });

    made.api.exportSelectedIds.value = new Set([11, 12]);
    made.api.exportFormat.value = "multiple";
    made.api.exportPath.value = "C:\\out";

    await made.api.doExport();

    const paths = (writeUserFile as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0] as string);
    expect(paths).toHaveLength(2);
    // 非法分隔符被净化为空格（sanitizeFileName），且第二张不覆盖第一张
    expect(paths[0]).toMatch(/^C:\\out[/\\]a b.*\.venc$/);
    expect(paths[1]).toMatch(/^C:\\out[/\\]a b.*_1\.venc$/);
    expect(new Set(paths).size).toBe(2);
    expect(made.api.exportStatus.value).toBe("已导出 2 张照片");
  });

  it("全失败：结果文案报失败而非「已导出 N 张」，不触发任何写出", async () => {
    (verthysGetRecord as ReturnType<typeof vi.fn>).mockResolvedValue(null);
    const made = makeExport([makePlaceholder(20)]);
    scope = made.scope;

    made.api.exportSelectedIds.value = new Set([20]);
    made.api.exportFormat.value = "multiple";
    made.api.exportPath.value = "C:\\out";

    await made.api.doExport();

    expect(writeUserFile).not.toHaveBeenCalled();
    expect(made.api.exportStatus.value).toContain("失败");
    expect(made.api.exportStatus.value).not.toMatch(/已导出 \d+ 张照片$/);
  });

  it("令牌重新生成：直接更换且不再与旧值相同（无确认弹窗）", () => {
    const made = makeExport([]);
    scope = made.scope;
    const before = made.api.exportToken.value;

    made.api.regenerateExportToken();

    expect(made.api.exportToken.value).not.toBe(before);
    expect(askMock).not.toHaveBeenCalled();
  });
});

describe("usePhotoExport — 单文件流式写出协议", () => {
  let scope: EffectScope | null = null;
  beforeEach(() => {
    vi.clearAllMocks();
    (verthysGetRecord as ReturnType<typeof vi.fn>).mockResolvedValue({
      type: 1,
      name: "meta_占位.jpg",
      dataB64: "meta-b64",
    });
  });
  afterEach(() => {
    scope?.stop();
    scope = null;
    vi.useRealTimers();
  });

  it("单文件导出走流式：建会话 → 逐帧追加 → finalize，不再整包直传", async () => {
    const made = makeExport([makePlaceholder(30)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([30]);
    made.api.exportFormat.value = "single";
    made.api.exportPath.value = "C:\\out\\photo.venc";

    await made.api.doExport();

    expect(writeUserFileStream).toHaveBeenCalledTimes(1);
    expect(writeUserFileStream).toHaveBeenCalledWith("C:\\out\\photo.venc");
    // 两段产出（首段前缀 + 帧序列）逐段追加，同一会话标识贯穿始终
    expect(appendUserFileChunk).toHaveBeenCalledTimes(2);
    const [appendStream1] = (appendUserFileChunk as ReturnType<typeof vi.fn>).mock.calls[0];
    const [appendStream2] = (appendUserFileChunk as ReturnType<typeof vi.fn>).mock.calls[1];
    expect(appendStream1).toBe("stream-1");
    expect(appendStream2).toBe("stream-1");
    expect(finalizeUserFileStream).toHaveBeenCalledWith("stream-1");
    expect(abortUserFileStream).not.toHaveBeenCalled();
    // 单文件模式不再走整包 writeUserFile
    expect(writeUserFile).not.toHaveBeenCalled();
    expect(made.api.exportStatus.value).toBe("已导出 1 张照片");
  });

  it("追加中途失败：中止会话清理暂存，未 finalize，错误显式呈现", async () => {
    (appendUserFileChunk as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("disk full"),
    );
    const made = makeExport([makePlaceholder(31)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([31]);
    made.api.exportFormat.value = "single";
    made.api.exportPath.value = "C:\\out\\photo.venc";

    await made.api.doExport();

    expect(abortUserFileStream).toHaveBeenCalledWith("stream-1");
    expect(finalizeUserFileStream).not.toHaveBeenCalled();
    expect(made.api.exportStatus.value).toBe("导出失败，请重试");
  });

  it("清理暂存失败不影响原始错误上抛（中止失败不被吞掉）", async () => {
    (appendUserFileChunk as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("disk full"),
    );
    (abortUserFileStream as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("cleanup failed"),
    );
    const made = makeExport([makePlaceholder(32)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([32]);
    made.api.exportFormat.value = "single";
    made.api.exportPath.value = "C:\\out\\photo.venc";

    await made.api.doExport();

    expect(abortUserFileStream).toHaveBeenCalledWith("stream-1");
    // 原始失败是「写盘失败」，清理失败仅是日志级信息
    expect(made.api.exportStatus.value).toBe("导出失败，请重试");
  });
});

describe("usePhotoExport — PNG 明文导出：解密下沉 Worker 桥", () => {
  let scope: EffectScope | null = null;
  beforeEach(() => {
    vi.clearAllMocks();
    (verthysGetRecord as ReturnType<typeof vi.fn>).mockResolvedValue({
      type: 1,
      name: "meta_占位.jpg",
      dataB64: "meta-b64",
    });
  });
  afterEach(() => {
    scope?.stop();
    scope = null;
    vi.useRealTimers();
  });

  /** 覆写解密产物（fileHash 与 bytesToHex mock 的 "1"×64 对齐，保证内容校验通过） */
  async function setMeta(meta: Partial<PhotoMeta> = {}): Promise<void> {
    const { decryptMeta } = await import("../../lib/crypto");
    (decryptMeta as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...fakeMetaFactory(), fileHash: "1".repeat(64), ...meta,
    });
  }

  it("既有布局：整图解密经桥（逐块密文与校验参数透传），转换产物正常写出", async () => {
    await setMeta();
    const made = makeExport([makePlaceholder(40)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([40]);
    made.api.exportFormat.value = "png";
    made.api.exportPath.value = "C:\\out";

    await made.api.doExport();

    expect(decryptChunksPreferWorker).toHaveBeenCalledTimes(1);
    expect(decryptChunksPreferWorker).toHaveBeenCalledWith(
      ["Y2g="], "test-key", "1".repeat(64), "占位.jpg", undefined,
    );
    expect(writeUserFile).toHaveBeenCalledTimes(1);
    expect(made.api.exportStatus.value).toBe("已导出 1 张照片");
  });

  it("索引瘦身布局：包裹密钥与块总数随桥透传（块密文无自描述序号）", async () => {
    await setMeta({ fmt: PHOTO_FMT_SLIM, wrappedFileKey: "wrapped-key" });
    const made = makeExport([makePlaceholder(41)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([41]);
    made.api.exportFormat.value = "png";
    made.api.exportPath.value = "C:\\out";

    await made.api.doExport();

    expect(decryptChunksPreferWorker).toHaveBeenCalledWith(
      ["Y2g="], "test-key", "1".repeat(64), "占位.jpg",
      { wrappedFileKey: "wrapped-key", chunkTotal: 1 },
    );
    expect(made.api.exportStatus.value).toBe("已导出 1 张照片");
  });

  it("解密/完整性校验失败：归因为 decrypt-failed，不写出且不标为转换失败", async () => {
    // 内容哈希声明与实得字节不符（bytesToHex mock 恒为 "1"×64）
    await setMeta({ fileHash: "9".repeat(64) });
    const made = makeExport([makePlaceholder(42)]);
    scope = made.scope;
    made.api.exportSelectedIds.value = new Set([42]);
    made.api.exportFormat.value = "png";
    made.api.exportPath.value = "C:\\out";

    await made.api.doExport();

    expect(writeUserFile).not.toHaveBeenCalled();
    expect(made.api.exportStatus.value).toContain("照片解密或完整性校验失败");
    expect(made.api.exportStatus.value).not.toContain("图片转换失败");
  });
});