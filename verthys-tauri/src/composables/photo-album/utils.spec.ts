/**
 * utils.spec.ts — 拾光模块列表装载纯函数单元测试
 *
 * 覆盖三类此前导致用户可见缺陷的纯逻辑：
 *   - 缓存回灌必须保留"未解密 = 待解密"语义（否则缩略图永久空白）
 *   - 增量过滤必须与 ID 分配策略解耦（否则复用 ID 的新照片不出现）
 *   - 方向感知预取行窗口的边界与去重
 */
import { describe, it, expect } from "vitest";
import {
  rehydrateEntries, diffNewIds, stripMetaRecordPrefix, sortByMetaId, prefetchRowIndices,
  makeThumbBlobUrl, makeThumbCssValue, thumbUrlOf, revokeThumbUrl,
} from "./utils";
import type { PhotoEntry } from "./types";

/** 构造一条已解密条目（具备 meta 即视为已解密） */
function decrypted(metaId: number): PhotoEntry {
  return {
    id: metaId,
    metaId,
    name: `photo-${metaId}.jpg`,
    thumb: `url(data:image/jpeg;base64,AAAA)`,
    size: "1.00 MB",
    height: 0,
    loaded: true,
    meta: {
      name: `photo-${metaId}.jpg`,
      mime: "image/jpeg",
      size: 1048576,
      thumbB64: "AAAA",
      chunkIds: [],
      chunkDataB64: ["BBBB"],
      chunkHashes: ["cccc"],
      fileHash: "d".repeat(64),
      createdAt: 0,
    },
  };
}

/** 构造一条未解密占位项（无 meta） */
function placeholder(metaId: number, name = ""): PhotoEntry {
  return { id: metaId, metaId, name, thumb: "", size: "", height: 0, loaded: false };
}

describe("rehydrateEntries", () => {
  it("已解密项保留缩略图与尺寸，并标记为已加载", () => {
    const [restored] = rehydrateEntries([decrypted(7)]);
    expect(restored.loaded).toBe(true);
    expect(restored.thumb).toContain("data:image/jpeg");
    expect(restored.size).toBe("1.00 MB");
  });

  it("未解密占位项回灌后仍为待解密态（不得被强制标记 loaded）", () => {
    const [restored] = rehydrateEntries([placeholder(8, "a.jpg")]);
    expect(restored.loaded).toBe(false);
    expect(restored.failed).toBe(false);
    expect(restored.name).toBe("a.jpg");
  });

  it("清除上次残留的失败标记与陈旧渲染字段", () => {
    const stale: PhotoEntry = { ...placeholder(9, "b.jpg"), thumb: "url(data:image/jpeg;base64,ZZZZ)", size: "9 MB", failed: true };
    const [restored] = rehydrateEntries([stale]);
    expect(restored.failed).toBe(false);
    expect(restored.thumb).toBe("");
    expect(restored.size).toBe("");
  });

  it("传入重建器时按 meta 内数据重建缩略图（上一会话的 Blob URL 已释放）", () => {
    const stale: PhotoEntry = { ...decrypted(11), thumb: 'url("blob:nodedata:stale")' };
    const [restored] = rehydrateEntries([stale], (b64) => `url("rebuilt:${b64}")`);
    expect(restored.thumb).toBe('url("rebuilt:AAAA")');
    expect(restored.loaded).toBe(true);
  });

  it("重建器存在但 meta 无缩略图数据时置空（不保留陈旧 URL）", () => {
    const noThumb: PhotoEntry = { ...decrypted(12), thumb: 'url("blob:nodedata:stale")' };
    noThumb.meta = { ...noThumb.meta!, thumbB64: "" };
    const [restored] = rehydrateEntries([noThumb], () => 'url("rebuilt")');
    expect(restored.thumb).toBe("");
  });
});

describe("缩略图 URL 助手", () => {
  it("base64 → Blob URL（node 环境无对象存储时返回空串而非抛错）", () => {
    const url = makeThumbBlobUrl("AAAA");
    // Node 18+ 提供 URL.createObjectURL；环境不提供时函数必须安全返回空串
    if (typeof URL.createObjectURL === "function") {
      expect(url.startsWith("blob:")).toBe(true);
      revokeThumbUrl(`url("${url}")`);
    } else {
      expect(url).toBe("");
    }
  });

  it("空输入与非法 base64 返回空串", () => {
    expect(makeThumbBlobUrl("")).toBe("");
    expect(makeThumbBlobUrl("!!!not-base64!!!")).toBe("");
  });

  it("CSS 值与 img 地址互转（兼容 data: 与 blob: 两种形态）", () => {
    expect(thumbUrlOf('url("blob:nodedata:x")')).toBe("blob:nodedata:x");
    expect(thumbUrlOf("url(data:image/jpeg;base64,AAAA)")).toBe("data:image/jpeg;base64,AAAA");
    expect(thumbUrlOf("")).toBe("");
  });

  it("revokeThumbUrl 只处理 blob: 形态（data: 形态无害跳过）", () => {
    expect(() => revokeThumbUrl("url(data:image/jpeg;base64,AAAA)")).not.toThrow();
    expect(() => revokeThumbUrl("")).not.toThrow();
  });

  it("makeThumbCssValue 统一拼接成 background-image 值", () => {
    const css = makeThumbCssValue("AAAA");
    if (css) expect(css).toMatch(/^url\("blob:/);
    else expect(css).toBe("");
    expect(makeThumbCssValue("")).toBe("");
  });
});

describe("diffNewIds", () => {
  it("返回尚未装载的 ID，且保持原顺序", () => {
    expect(diffNewIds([1, 2, 3, 4], new Set([1, 3]))).toEqual([2, 4]);
  });

  it("全部已装载时返回空（重复装载为零）", () => {
    expect(diffNewIds([1, 2, 3], new Set([3, 2, 1]))).toEqual([]);
  });

  it("复用中间 ID 的新记录必须能被识别（不依赖 ID 单调分配）", () => {
    // 已装载 {1,5}，磁盘新增了复用 ID=2 的记录
    expect(diffNewIds([1, 2, 5], new Set([1, 5]))).toEqual([2]);
  });
});

describe("stripMetaRecordPrefix", () => {
  it("剥离导入侧附加的记录名前缀", () => {
    expect(stripMetaRecordPrefix("meta_a.jpg")).toBe("a.jpg");
  });

  it("其它命名原样返回", () => {
    expect(stripMetaRecordPrefix("parsed_1699999999_3")).toBe("parsed_1699999999_3");
    expect(stripMetaRecordPrefix("")).toBe("");
  });
});

describe("sortByMetaId", () => {
  it("按 metaId 升序排列，且不修改入参数组", () => {
    const input = [placeholder(3), placeholder(1), placeholder(2)];
    const sorted = sortByMetaId(input);
    expect(sorted.map(e => e.metaId)).toEqual([1, 2, 3]);
    expect(input.map(e => e.metaId)).toEqual([3, 1, 2]);
  });

  it("无 metaId 的项排在末尾", () => {
    const sorted = sortByMetaId([{ id: 99, name: "demo", thumb: "", size: "", height: 0 }, placeholder(2)]);
    expect(sorted.map(e => e.metaId)).toEqual([2, undefined]);
  });
});

describe("prefetchRowIndices", () => {
  it("向下滚动：运动方向多取，反方向少量兜底", () => {
    expect(prefetchRowIndices({ startRow: 2, endRow: 6 }, 20, "down", 2, 1)).toEqual([6, 7, 1]);
  });

  it("向上滚动：行窗口方向反转", () => {
    expect(prefetchRowIndices({ startRow: 2, endRow: 6 }, 20, "up", 2, 1)).toEqual([0, 1, 6]);
  });

  it("抵达边界时截断且不产生重复行", () => {
    expect(prefetchRowIndices({ startRow: 0, endRow: 0 }, 5, "down", 2, 1)).toEqual([0, 1]);
  });

  it("总行数为 0 时返回空", () => {
    expect(prefetchRowIndices({ startRow: 0, endRow: 0 }, 0, "down", 2, 1)).toEqual([]);
  });
});