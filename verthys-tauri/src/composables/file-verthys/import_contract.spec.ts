/**
 * import_contract 单测 — 清藏导入错误文案映射
 *
 * 数据面行为（分块、去重、KDF、崩溃续传）由 worker/宿主 Rust 单测覆盖；
 * 本文件只锁定前端展示契约：已知码不得退化为通用文案，未知码必须回退。
 */
import { describe, expect, it } from "vitest";
import {
  fileImportErrorMessage,
  type FileImportErrorCode,
} from "./import_contract";

const CASES: Array<[FileImportErrorCode, string]> = [
  ["E_STAT_FAILED", "无法读取文件信息"],
  ["E_READ_FAILED", "读取文件失败"],
  ["E_ENCRYPT_FAILED", "文件加密失败"],
  ["E_CHUNK_FAILED", "数据块写入失败"],
  ["E_META_FAILED", "文件元数据写入失败"],
  ["E_FILE_CHANGED", "文件在导入过程中被改动"],
  ["E_FILE_TOO_LARGE", "文件超过大小上限"],
  ["E_DISK_FULL", "磁盘空间不足"],
  ["E_UNKNOWN", "导入失败，请重试"],
];

describe("fileImportErrorMessage", () => {
  it("每个已知原因码都有专属文案", () => {
    for (const [code, text] of CASES) {
      expect(fileImportErrorMessage(code)).toBe(text);
      if (code !== "E_UNKNOWN") {
        expect(fileImportErrorMessage(code)).not.toBe(fileImportErrorMessage("E_UNKNOWN"));
      }
    }
  });

  it("未知原因码回退为通用文案", () => {
    expect(fileImportErrorMessage("E_NOT_A_REAL_CODE")).toBe("导入失败，请重试");
    expect(fileImportErrorMessage("")).toBe("导入失败，请重试");
  });
});
