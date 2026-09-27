/**
 * photo-album/repack.spec.ts — 后台重打包引擎契约测试
 *
 * 锁定四条不变式：
 *   1. 幂等单元为单张：已是布局二的照片直接跳过（可续跑），不重复改写；
 *   2. 安全前置：源数据不完整或整图哈希与索引声明不符即失败且零改动；
 *   3. 落库先行：新索引写入成功后才删除旧记录集；写入失败保留源记录；
 *   4. 记账完整：成功/跳过/失败/取消互斥且计数闭合，取消在张边界生效。
 */
import { describe, it, expect, vi } from "vitest";
import { runPhotoRepack, type PhotoMetaLike, type RepackDeps, type RepackSignal } from "./repack";
import { PHOTO_FMT_SLIM } from "../../constants/crypto_const";
import { computeFileHash, bytesToHex } from "../../lib/crypto";
import { bytesToBase64, base64ToBytes } from "../../utils/binary_codec";

/** 源明文与其哈希（写入侧与校验侧同源） */
const PLAIN = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const FILE_HASH = bytesToHex(computeFileHash(PLAIN));

/** 既有布局索引（每块自包含、缩略图内联） */
function legacyMeta(overrides: Partial<PhotoMetaLike> = {}): PhotoMetaLike {
  return {
    name: "a.jpg",
    mime: "image/jpeg",
    size: PLAIN.length,
    createdAt: 1,
    thumbB64: "legacy-thumb",
    chunkIds: [11, 12],
    chunkDataB64: [bytesToBase64(PLAIN.slice(0, 4)), bytesToBase64(PLAIN.slice(4))],
    chunkHashes: ["h1", "h2"],
    fileHash: FILE_HASH,
    ...overrides,
  };
}

/** 已迁移索引（布局二完整形态） */
function slimMeta(): PhotoMetaLike {
  return {
    fmt: PHOTO_FMT_SLIM,
    name: "a.jpg",
    thumbId: 42,
    chunkIds: [],
    wrappedFileKey: "wrapped",
    chunkSetId: 43,
    fileHash: FILE_HASH,
  };
}

/** 默认依赖：单张既有布局照片，全链路成功 */
function makeDeps(
  metaById: Map<number, PhotoMetaLike>,
  overrides: Partial<RepackDeps> = {},
): RepackDeps {
  const deps: RepackDeps = {
    listMetaIds: () => [...metaById.keys()],
    readRecords: async (ids) => {
      const out = new Map<number, string>();
      for (const id of ids) {
        if (metaById.has(id)) out.set(id, `b64:${id}`);
      }
      return out;
    },
    decryptMeta: async (metaB64) => {
      const id = Number(metaB64.slice(4));
      const meta = metaById.get(id);
      if (!meta) throw new Error("索引解密失败");
      return meta;
    },
    decryptChunks: async (meta) => {
      const inline = meta.chunkDataB64 ?? [];
      if (inline.length === 0) throw new Error("源数据块不完整");
      return inline.map((b) => base64ToBytes(b));
    },
    writeSlimPhoto: vi.fn(async () => 900),
    deleteLegacyRecords: vi.fn(async () => { /* 默认成功 */ }),
    onMigrated: vi.fn(),
    hashPlaintext: (bytes) => bytesToHex(computeFileHash(bytes)),
    ...overrides,
  };
  return deps;
}

/** 空取消信号 */
const freshSignal = (): RepackSignal => ({ aborted: false });

describe("单张迁移成功路径", () => {
  it("既有布局照片被改写：先落库新索引，后删除旧记录集，逐张上报进度", async () => {
    const metaById = new Map<number, PhotoMetaLike>([[7, legacyMeta()]]);
    const events: string[] = [];
    let receivedPlain: Uint8Array | null = null;
    let receivedMeta: PhotoMetaLike | null = null;
    let deletedArgs: [number, number[]] | null = null;
    const deps = makeDeps(metaById, {
      writeSlimPhoto: async (meta, plain) => {
        events.push("write");
        receivedMeta = meta;
        // 引擎在写入返回后立即清零明文缓冲（密钥材料不驻留），此处留副本断言
        receivedPlain = plain.slice();
        return 900;
      },
      deleteLegacyRecords: async (id, chunkIds) => {
        events.push("delete");
        deletedArgs = [id, chunkIds];
      },
    });
    const progress: Array<{ processed: number; migrated: number }> = [];
    deps.onProgress = (p) => progress.push({ processed: p.processed, migrated: p.migrated });

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 1, migrated: 1, skipped: 0, failed: 0, aborted: false });
    // 落库先于删除：新索引落库确认后才允许删除旧记录集
    expect(events).toEqual(["write", "delete"]);
    expect(receivedMeta!.fileHash).toBe(FILE_HASH);
    expect(receivedPlain).toEqual(PLAIN);
    expect(deletedArgs).toEqual([7, [11, 12]]);
    expect(deps.onMigrated).toHaveBeenCalledWith(7, 900);
    // 进度单调：processed 从 0 递增到 1，且成功计数同步到位
    expect(progress[0]).toEqual({ processed: 0, migrated: 0 });
    expect(progress[progress.length - 1]).toEqual({ processed: 1, migrated: 1 });
    for (let i = 1; i < progress.length; i++) {
      expect(progress[i].processed).toBeGreaterThanOrEqual(progress[i - 1].processed);
    }
  });

  it("已是布局二的照片直接跳过（幂等：重复运行不重复改写）", async () => {
    const metaById = new Map<number, PhotoMetaLike>([[8, slimMeta()]]);
    const deps = makeDeps(metaById);

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 1, migrated: 0, skipped: 1, failed: 0, aborted: false });
    expect(deps.writeSlimPhoto).not.toHaveBeenCalled();
    expect(deps.deleteLegacyRecords).not.toHaveBeenCalled();
  });
});

describe("安全前置与失败记账", () => {
  it("整图哈希与索引声明不符：按失败记账且零改动（不删源记录、不写新索引）", async () => {
    const metaById = new Map<number, PhotoMetaLike>([
      [9, legacyMeta({ fileHash: "f".repeat(64) })],
    ]);
    const deps = makeDeps(metaById);

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 1, migrated: 0, skipped: 0, failed: 1, aborted: false });
    expect(deps.writeSlimPhoto).not.toHaveBeenCalled();
    expect(deps.deleteLegacyRecords).not.toHaveBeenCalled();
    expect(deps.onMigrated).not.toHaveBeenCalled();
  });

  it("源数据不完整（取块失败）：保留源记录并按失败记账", async () => {
    const metaById = new Map<number, PhotoMetaLike>([[10, legacyMeta()]]);
    const deps = makeDeps(metaById, {
      decryptChunks: async () => { throw new Error("源数据块不完整（缺失 1 块）"); },
    });

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result.failed).toBe(1);
    expect(deps.deleteLegacyRecords).not.toHaveBeenCalled();
  });

  it("索引不可读（记录缺失 / 解密失败）：按失败记账并继续处理后续照片", async () => {
    const metaById = new Map<number, PhotoMetaLike>([
      [13, legacyMeta()],
      [14, legacyMeta()],
    ]);
    const deps = makeDeps(metaById, {
      decryptMeta: async (metaB64) => {
        if (metaB64 === "b64:14") throw new Error("索引解密失败");
        return legacyMeta();
      },
    });

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 2, migrated: 1, skipped: 0, failed: 1, aborted: false });
  });

  it("写入被拒绝（新索引未落库）：保留源记录，不删除旧记录集", async () => {
    const metaById = new Map<number, PhotoMetaLike>([[15, legacyMeta()]]);
    const deps = makeDeps(metaById, {
      writeSlimPhoto: async () => { throw new Error("重打包写入被拒绝"); },
    });

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result.failed).toBe(1);
    expect(deps.deleteLegacyRecords).not.toHaveBeenCalled();
    expect(deps.onMigrated).not.toHaveBeenCalled();
  });

  it("后端按内容哈希去重跳过：计跳过而非失败（源记录保留，下一轮再试）", async () => {
    const metaById = new Map<number, PhotoMetaLike>([[16, legacyMeta()]]);
    const deps = makeDeps(metaById, {
      writeSlimPhoto: async () => { throw new Error("DUPLICATE_SKIPPED"); },
    });

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 1, migrated: 0, skipped: 1, failed: 0, aborted: false });
  });

  it("删除旧记录集失败：新索引已落库，按失败记账（旧记录残留由后续轮次收敛）", async () => {
    const metaById = new Map<number, PhotoMetaLike>([[17, legacyMeta()]]);
    const deps = makeDeps(metaById, {
      deleteLegacyRecords: async () => { throw new Error("删除失败"); },
    });

    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 1, migrated: 0, skipped: 0, failed: 1, aborted: false });
    expect(deps.writeSlimPhoto).toHaveBeenCalledTimes(1);
    expect(deps.onMigrated).not.toHaveBeenCalled();
  });
});

describe("取消与续跑", () => {
  it("取消在张边界生效：在途一张正常收尾，未开始的不再处理", async () => {
    const metaById = new Map<number, PhotoMetaLike>([
      [21, legacyMeta()],
      [22, legacyMeta()],
      [23, legacyMeta()],
    ]);
    const signal = freshSignal();
    let started = 0;
    const deps = makeDeps(metaById, {
      writeSlimPhoto: async () => {
        started++;
        signal.aborted = true; // 首张写入完成后请求取消
        return 900 + started;
      },
    });

    const result = await runPhotoRepack(deps, signal);

    expect(result.aborted).toBe(true);
    expect(result.migrated).toBe(1);
    expect(result.total).toBe(3);
    expect(started).toBe(1);
    // 首张已完整收尾：旧记录集已删除、迁移回调已触发
    expect(deps.deleteLegacyRecords).toHaveBeenCalledTimes(1);
    expect(deps.onMigrated).toHaveBeenCalledTimes(1);
  });

  it("空候选集：立即返回零计数，不触碰任何依赖", async () => {
    const deps = makeDeps(new Map());
    const result = await runPhotoRepack(deps, freshSignal());

    expect(result).toEqual({ total: 0, migrated: 0, skipped: 0, failed: 0, aborted: false });
    expect(deps.writeSlimPhoto).not.toHaveBeenCalled();
  });
});