/**
 * usePhotoExport.spec.ts — 导出写盘路径协议回归测试
 *
 * 覆盖：writeVencFile 必须经 writeUserFile（Raw body + x-path 头协议）
 * 直传原始字节，不经过 base64 编码的 JSON 载荷——后者与 write_user_file
 * 命令的 Request<'_> 签名不符，曾导致 Tauri 模式导出全部失败。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ref, shallowRef } from "vue";

vi.mock("../../lib/verthys", () => ({
  verthysGetRecord: vi.fn(),
  bytesToBase64: vi.fn((bytes: Uint8Array) => `b64(${bytes.length})`),
  writeUserFile: vi.fn(async (_path: string, _data: Uint8Array): Promise<void> => {
    /* 由各用例断言调用形态 */
  }),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
  save: vi.fn(),
}));

import { usePhotoExport } from "./usePhotoExport";
import { writeUserFile, bytesToBase64 } from "../../lib/verthys";

function makeExport() {
  return usePhotoExport({
    photos: shallowRef([]),
    photoKey: ref("test-key"),
    isTauri: true,
    ensurePhotoKey: () => true,
    showError: () => {},
    showExportDone: () => {},
    showCopied: () => {},
  });
}

describe("usePhotoExport — writeVencFile 写盘协议", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("直传 (path, bytes) 给 writeUserFile：原始 Uint8Array 引用不变", async () => {
    const api = makeExport();
    const bytes = new Uint8Array([0x56, 0x45, 0x4e, 0x43]);
    await api.writeVencFile("C:\\out\\photo.venc", bytes);

    expect(writeUserFile).toHaveBeenCalledTimes(1);
    const [path, data] = (writeUserFile as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(path).toBe("C:\\out\\photo.venc");
    // 同一引用直传：写盘字节与调用方字节完全一致，不做任何转换
    expect(data).toBe(bytes);
    expect(data).toEqual(new Uint8Array([0x56, 0x45, 0x4e, 0x43]));
  });

  it("写盘路径不经过 base64 编码（bytesToBase64 零调用）", async () => {
    const api = makeExport();
    await api.writeVencFile("C:\\out\\photo.venc", new Uint8Array(32));
    expect(bytesToBase64).not.toHaveBeenCalled();
  });

  it("writeUserFile 的异常原样上抛（失败不被吞掉）", async () => {
    (writeUserFile as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("EPERM: 权限不足"),
    );
    const api = makeExport();
    await expect(
      api.writeVencFile("C:\\Windows\\System32\\photo.venc", new Uint8Array(4)),
    ).rejects.toThrow("EPERM: 权限不足");
  });
});
