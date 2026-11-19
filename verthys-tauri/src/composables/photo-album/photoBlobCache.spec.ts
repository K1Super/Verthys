import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  PhotoBlobCache,
  previewCacheKey,
  fullCacheKey,
} from "./photoBlobCache";

describe("PhotoBlobCache", () => {
  let revoke: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  });

  afterEach(() => {
    revoke.mockRestore();
  });

  it("按字节上限淘汰最久未使用项并释放 URL", () => {
    const cache = new PhotoBlobCache(100, 10);
    cache.put("a", "blob:a", 60);
    cache.put("b", "blob:b", 60);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBe("blob:b");
    expect(revoke).toHaveBeenCalledWith("blob:a");
  });

  it("命中刷新最近使用顺序", () => {
    const cache = new PhotoBlobCache(100, 10);
    cache.put("a", "blob:a", 40);
    cache.put("b", "blob:b", 40);
    expect(cache.get("a")).toBe("blob:a");
    cache.put("c", "blob:c", 40);
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("a")).toBe("blob:a");
    expect(cache.get("c")).toBe("blob:c");
  });

  it("按条目数上限淘汰", () => {
    const cache = new PhotoBlobCache(1024, 2);
    cache.put("a", "blob:a", 1);
    cache.put("b", "blob:b", 1);
    cache.put("c", "blob:c", 1);
    expect(cache.size).toBe(2);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("c")).toBe("blob:c");
  });

  it("同键覆盖释放旧 URL，delete/clear 释放全部", () => {
    const cache = new PhotoBlobCache();
    cache.put("a", "blob:old", 1);
    cache.put("a", "blob:new", 1);
    expect(revoke).toHaveBeenCalledWith("blob:old");
    expect(cache.get("a")).toBe("blob:new");

    cache.put("b", "blob:b", 1);
    cache.delete("a");
    expect(revoke).toHaveBeenCalledWith("blob:new");

    cache.clear();
    expect(revoke).toHaveBeenCalledWith("blob:b");
    expect(cache.size).toBe(0);
    expect(cache.bytes).toBe(0);
  });

  it("单条超过字节上限时保护自身，下一次写入再淘汰", () => {
    const cache = new PhotoBlobCache(100, 10);
    cache.put("huge", "blob:huge", 200);
    expect(cache.get("huge")).toBe("blob:huge");
    expect(revoke).not.toHaveBeenCalledWith("blob:huge");

    cache.put("small", "blob:small", 1);
    expect(cache.get("small")).toBe("blob:small");
    expect(cache.get("huge")).toBeUndefined();
    expect(revoke).toHaveBeenCalledWith("blob:huge");
  });

  it("预览与原图键空间互不串扰", () => {
    expect(previewCacheKey(7)).not.toBe(fullCacheKey(7));
  });
});
