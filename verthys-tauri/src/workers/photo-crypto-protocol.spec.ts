/**
 * photo-crypto-protocol.spec.ts — 消息装配不变式回归测试
 *
 * 覆盖：
 * - 完整加密成功响应必须原样透传 external（外置块产物）——漏传会让主线程
 *   把外置路径误判为内联路径，大文件导入必然以「加密产物缺少元数据」失败
 * - 内联产物：metaB64 透传且 external 保持缺省
 * - meta-only 成功响应：展示字段（名称/MIME/大小/缩略图）从元数据提升
 * - 解密成功响应：元数据逐字段透传、明文缓冲保持原引用（零拷贝转移前提）
 * - 失败响应：字段逐项透传
 */
import { describe, it, expect } from "vitest";
import {
  assemblePhotoCryptoSuccess,
  assemblePhotoMetaCryptoSuccess,
  assemblePhotoCryptoFailure,
  assemblePhotoDecryptMetaSuccess,
  assemblePhotoDecryptChunksSuccess,
  type PhotoProcessResult,
} from "./photo-crypto-protocol";
import type { PhotoMeta } from "../types/crypto";

/** 构造元数据模板（外置路径下块引用待主线程回填） */
function makeMetaTemplate(): PhotoMeta {
  return {
    name: "大图.jpg",
    mime: "image/jpeg",
    size: 9_000_000,
    thumbB64: "thumb-b64",
    chunkIds: [],
    chunkDataB64: [],
    chunkHashes: ["a".repeat(64), "b".repeat(64)],
    fileHash: "f".repeat(64),
    createdAt: 1_700_000_000_000,
  };
}

describe("assemblePhotoCryptoSuccess — 完整加密响应装配", () => {
  it("外置产物：external 逐字段原样透传（P0 回归：漏传即大文件导入失败）", () => {
    const external = {
      chunkB64List: ["chunk-1", "chunk-2"],
      chunkHashes: ["h1", "h2"],
      metaTemplate: makeMetaTemplate(),
    };
    const result: PhotoProcessResult = {
      hash: "f".repeat(64),
      thumbB64: "thumb-b64",
      external,
      name: "meta_大图.jpg",
      mime: "image/jpeg",
      size: 9_000_000,
    };

    const response = assemblePhotoCryptoSuccess(7, result);

    expect(response.id).toBe(7);
    expect(response.ok).toBe(true);
    expect(response.external).toBeDefined();
    expect(response.external?.chunkB64List).toEqual(["chunk-1", "chunk-2"]);
    expect(response.external?.chunkHashes).toEqual(["h1", "h2"]);
    expect(response.external?.metaTemplate).toEqual(external.metaTemplate);
    // 外置路径无内联元数据密文（主线程回填块引用后重新加密）
    expect(response.metaB64).toBeUndefined();
  });

  it("内联产物：metaB64 透传且 external 保持缺省", () => {
    const result: PhotoProcessResult = {
      hash: "a".repeat(64),
      thumbB64: "t",
      metaB64: "meta-b64",
      name: "meta_小图.jpg",
      mime: "image/png",
      size: 1024,
    };

    const response = assemblePhotoCryptoSuccess(3, result);

    expect(response.metaB64).toBe("meta-b64");
    expect(response.external).toBeUndefined();
    expect(response.name).toBe("meta_小图.jpg");
    expect(response.mime).toBe("image/png");
    expect(response.size).toBe(1024);
  });
});

describe("assemblePhotoMetaCryptoSuccess — meta-only 响应装配", () => {
  it("展示字段从元数据提升，密文与哈希透传", () => {
    const meta = makeMetaTemplate();
    const response = assemblePhotoMetaCryptoSuccess(
      11,
      { metaB64: "re-encrypted", hash: meta.fileHash, thumbB64: meta.thumbB64, recordName: "parsed_1_0" },
      meta,
    );

    expect(response.ok).toBe(true);
    expect(response.metaB64).toBe("re-encrypted");
    expect(response.hash).toBe(meta.fileHash);
    expect(response.name).toBe("大图.jpg");
    expect(response.mime).toBe("image/jpeg");
    expect(response.size).toBe(9_000_000);
    expect(response.recordName).toBe("parsed_1_0");
  });
});

describe("assemblePhotoCryptoFailure — 失败响应装配", () => {
  it("字段逐项透传", () => {
    const response = assemblePhotoCryptoFailure(5, "a.jpg", "加密失败原因");
    expect(response).toEqual({ id: 5, ok: false, name: "a.jpg", error: "加密失败原因" });
  });
});

describe("assemblePhotoDecryptMetaSuccess — 元数据解密响应装配", () => {
  it("元数据原样透传（块引用与哈希不得裁剪）", () => {
    const meta = makeMetaTemplate();
    const response = assemblePhotoDecryptMetaSuccess(9, meta);

    expect(response.ok).toBe(true);
    expect(response.id).toBe(9);
    // 同一引用：装配不做拷贝与裁剪，后续块读取依赖这些字段
    expect(response.meta).toBe(meta);
    expect(response.meta.chunkHashes).toBe(meta.chunkHashes);
    expect(response.meta.fileHash).toBe(meta.fileHash);
  });
});

describe("assemblePhotoDecryptChunksSuccess — 数据块解密响应装配", () => {
  it("明文缓冲保持原引用（零拷贝转移的前提）", () => {
    const bufs = [new ArrayBuffer(4), new ArrayBuffer(8)];
    const response = assemblePhotoDecryptChunksSuccess(12, bufs);

    expect(response.ok).toBe(true);
    expect(response.id).toBe(12);
    // 数组与元素均为原引用：装配若拷贝，Worker 的 transferList 将转移错对象
    expect(response.plaintexts).toBe(bufs);
    expect(response.plaintexts[0]).toBe(bufs[0]);
    expect(response.plaintexts[1].byteLength).toBe(8);
  });
});