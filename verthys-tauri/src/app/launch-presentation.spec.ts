/*
 * launch-presentation.spec.ts — 启动展示判定纯函数
 *
 * 覆盖：同一次开机直接进入、重启后首映、标记缺失/损坏回退首映、
 * 容差边界、时钟异常回退首映。
 */
import { describe, expect, it } from "vitest";
import {
  BOOT_EPOCH_TOLERANCE_MS,
  decideLaunchPresentation,
  parseStoredBootEpoch,
} from "./launch-presentation";

const EPOCH = 1_700_000_000_000;

describe("parseStoredBootEpoch", () => {
  it("解析合法正整数", () => {
    expect(parseStoredBootEpoch(String(EPOCH))).toBe(EPOCH);
  });

  it("空值与损坏值返回 null", () => {
    for (const raw of [null, "", "abc", "1.5", "0", "-1", "1e309", "NaN"]) {
      expect(parseStoredBootEpoch(raw), String(raw)).toBeNull();
    }
  });
});

describe("decideLaunchPresentation", () => {
  it("同一次开机 → 直接进入", () => {
    expect(decideLaunchPresentation(EPOCH, EPOCH)).toBe("direct");
    expect(
      decideLaunchPresentation(EPOCH, EPOCH - BOOT_EPOCH_TOLERANCE_MS),
    ).toBe("direct");
  });

  it("超出容差（重启）→ 首映", () => {
    expect(
      decideLaunchPresentation(EPOCH, EPOCH - BOOT_EPOCH_TOLERANCE_MS - 1),
    ).toBe("ceremony");
  });

  it("标记缺失 → 首映", () => {
    expect(decideLaunchPresentation(EPOCH, null)).toBe("ceremony");
  });

  it("当前启动时刻不可用 → 首映", () => {
    for (const current of [null, 0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(decideLaunchPresentation(current, EPOCH), String(current)).toBe(
        "ceremony",
      );
    }
  });

  it("时钟回拨超出容差 → 首映（宁可多播不可漏播）", () => {
    expect(
      decideLaunchPresentation(EPOCH, EPOCH + BOOT_EPOCH_TOLERANCE_MS + 1),
    ).toBe("ceremony");
  });
});
