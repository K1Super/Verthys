import { describe, expect, it } from "vitest";
import {
  UPDATER_ERROR_CODES,
  UPDATER_ERROR_COPY,
  updaterErrorCopy,
  updaterErrorMessage,
} from "./updater_error";

describe("updater error copy", () => {
  it("每个错误码都有完整用户文案", () => {
    for (const code of UPDATER_ERROR_CODES) {
      const copy = UPDATER_ERROR_COPY[code];
      expect(copy.title.length).toBeGreaterThan(0);
      expect(copy.guidance.length).toBeGreaterThan(0);
    }
  });

  it("未知错误码使用统一兜底，不泄露后端诊断", () => {
    const copy = updaterErrorCopy("E_UPDATER_UNKNOWN");
    expect(copy.title).toBe("更新出现异常");
    expect(updaterErrorMessage(null)).toContain("更新出现异常");
  });
});
