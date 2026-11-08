/**
 * useViewMode.spec.ts — 视图模式裁决回归
 *
 * 覆盖：
 *   1. 基础优先级（未解锁 → 无密钥 → 设备不匹配 → 未验证 → 管理）
 *   2. unlockInProgress 保持位：解锁收束期间即使底层状态已翻转，
 *      视图仍停留在 unlock，确保进度补满后再切换
 */
import { describe, it, expect } from "vitest";
import { ref } from "vue";
import { useViewMode, type UseViewModeOptions, type DeviceCheckResult } from "./useViewMode";

function createOptions(overrides: Partial<UseViewModeOptions> = {}) {
  return {
    verthysReady: ref(true),
    hasGlobalKeyRecord: ref(true),
    globalKeyReady: ref(true),
    deviceCheckResult: ref<DeviceCheckResult>("match"),
    postVerifyAnim: ref(false),
    postInitAnim: ref(false),
    ...overrides,
  };
}

describe("useViewMode", () => {
  it("按固定优先级裁决五态", () => {
    const options = createOptions();
    const { viewMode } = useViewMode(options);

    expect(viewMode.value).toBe("management");

    options.verthysReady.value = false;
    expect(viewMode.value).toBe("unlock");

    options.verthysReady.value = true;
    options.hasGlobalKeyRecord.value = false;
    expect(viewMode.value).toBe("init");

    options.hasGlobalKeyRecord.value = true;
    options.postInitAnim.value = true;
    expect(viewMode.value).toBe("init");
    options.postInitAnim.value = false;

    options.deviceCheckResult.value = "mismatch";
    expect(viewMode.value).toBe("device_mismatch");
    options.deviceCheckResult.value = "match";

    options.globalKeyReady.value = false;
    expect(viewMode.value).toBe("verify");
    options.globalKeyReady.value = true;
    options.postVerifyAnim.value = true;
    expect(viewMode.value).toBe("verify");
    options.postVerifyAnim.value = false;
    expect(viewMode.value).toBe("management");
  });

  it("unlockInProgress 保持解锁视图，释放后才按底层状态切换", () => {
    const unlockInProgress = ref(true);
    const options = createOptions({ unlockInProgress });
    const { viewMode } = useViewMode(options);

    // 收束期间底层状态已翻转（verthysReady=true 且已有全局密钥记录）
    expect(viewMode.value).toBe("unlock");

    unlockInProgress.value = false;
    expect(viewMode.value).toBe("management");
  });
});
