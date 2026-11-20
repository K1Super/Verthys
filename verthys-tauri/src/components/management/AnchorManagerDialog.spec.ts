// @vitest-environment happy-dom
/**
 * AnchorManagerDialog.spec.ts — 回退锚点管理弹窗交互契约
 *
 * 覆盖：
 *   1. 四种见证状态渲染
 *   2. 释放必须“勾选 → 二次确认”，确认后才 emit release
 *   3. 无 DEAD 时回收按钮禁用；有 DEAD 时可用
 *   4. 扫描证据与“未在扫描范围内找到”措辞
 *
 * 依赖：happy-dom + createApp（项目未引入 @vue/test-utils）；
 *       弹窗经 CosmicOverlay teleport 到 body，查询根同步为 body。
 */
import { describe, it, expect, vi } from "vitest";
import { createApp, h, nextTick } from "vue";
import AnchorManagerDialog from "./AnchorManagerDialog.vue";
import type { AnchorInfo, AnchorScanResult } from "../../types/verthys";

const ACTIVE_UUID = "11111111111111111111111111111111";
const DEAD_UUID = "22222222222222222222222222222222";
const TAMPERED_UUID = "33333333333333333333333333333333";
const UNKNOWN_UUID = "44444444444444444444444444444444";

const ANCHORS: AnchorInfo[] = [
  { uuid: ACTIVE_UUID, generation: 7, witness: "active" },
  { uuid: DEAD_UUID, generation: 3, witness: "dead" },
  { uuid: TAMPERED_UUID, generation: 2, witness: "tampered" },
  { uuid: UNKNOWN_UUID, generation: 1, witness: "unknown" },
];

function mountDialog(
  overrides: Partial<{
    anchors: AnchorInfo[];
    scan: AnchorScanResult | null;
    state: number;
    busy: boolean;
    error: string;
    notice: string;
  }> = {},
) {
  const released: string[][] = [];
  let reclaimCount = 0;
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(AnchorManagerDialog, {
        show: true,
        anchors: ANCHORS,
        state: 1,
        scan: null,
        busy: false,
        error: "",
        notice: "",
        ...overrides,
        onRelease: (uuids: string[]) => released.push(uuids),
        onReclaim: () => {
          reclaimCount += 1;
        },
      }),
  });
  app.directive("tip", {});
  app.mount(container);
  return {
    released,
    reclaimCount: () => reclaimCount,
    teardown: () => {
      app.unmount();
      container.remove();
      document.body.innerHTML = "";
    },
  };
}

function buttonByText(text: string): HTMLButtonElement | undefined {
  return Array.from(document.querySelectorAll("button")).find((button) =>
    button.textContent?.includes(text),
  ) as HTMLButtonElement | undefined;
}

describe("AnchorManagerDialog", () => {
  it("renders all four witness states", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const text = document.body.textContent ?? "";
      expect(text).toContain("使用中");
      expect(text).toContain("已失效");
      expect(text).toContain("见证异常");
      expect(text).toContain("未知");
    } finally {
      mounted.teardown();
    }
  });

  it("管理表展示完整 UUID，短码只留在概览摘要", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const text = document.body.textContent ?? "";
      expect(text).toContain(ACTIVE_UUID);
      expect(text).not.toContain("11111111…1111");
    } finally {
      mounted.teardown();
    }
  });

  it("点击 UUID 复制完整值", async () => {
    const writeText = vi.fn(async () => undefined);
    const original = Object.getOwnPropertyDescriptor(navigator, "clipboard");
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    const mounted = mountDialog();
    await nextTick();
    vi.useFakeTimers();
    try {
      const uuid = document.querySelector<HTMLElement>(".anchor-uuid");
      expect(uuid).toBeTruthy();
      uuid!.click();
      await nextTick();
      expect(writeText).toHaveBeenCalledWith(ACTIVE_UUID);
    } finally {
      vi.useRealTimers();
      mounted.teardown();
      if (original) {
        Object.defineProperty(navigator, "clipboard", original);
      } else {
        Reflect.deleteProperty(navigator, "clipboard");
      }
    }
  });

  it("requires explicit selection and a second confirmation before release", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const releaseButton = buttonByText("释放选中");
      expect(releaseButton).toBeTruthy();
      expect(releaseButton!.disabled).toBe(true);

      const checkbox = document.querySelector(
        'input[type="checkbox"]',
      ) as HTMLInputElement | null;
      expect(checkbox).not.toBeNull();
      checkbox!.checked = true;
      checkbox!.dispatchEvent(new Event("change"));
      await nextTick();
      expect(releaseButton!.disabled).toBe(false);

      releaseButton!.click();
      await nextTick();
      expect(document.body.textContent).toContain("若对应容器仍存在");

      const confirmButton = buttonByText("确认");
      expect(confirmButton).toBeTruthy();
      confirmButton!.click();
      await nextTick();
      expect(mounted.released[0]).toEqual([ACTIVE_UUID]);
    } finally {
      mounted.teardown();
    }
  });

  it("disables reclaim when there is no dead anchor and enables it otherwise", async () => {
    const noDead = mountDialog({
      anchors: ANCHORS.filter((anchor) => anchor.witness !== "dead"),
    });
    await nextTick();
    try {
      const disabledReclaim = buttonByText("回收失效");
      expect(disabledReclaim).toBeTruthy();
      expect(disabledReclaim!.disabled).toBe(true);
    } finally {
      noDead.teardown();
    }

    const withDead = mountDialog();
    await nextTick();
    try {
      const reclaim = buttonByText("回收失效");
      expect(reclaim).toBeTruthy();
      expect(reclaim!.disabled).toBe(false);
      reclaim!.click();
      await nextTick();
      const confirm = buttonByText("确认");
      expect(confirm).toBeTruthy();
      confirm!.click();
      await nextTick();
      expect(withDead.reclaimCount()).toBe(1);
    } finally {
      withDead.teardown();
    }
  });

  it("shows scan evidence and the not-found wording", async () => {
    const scan: AnchorScanResult = {
      entries: [
        { uuid: ACTIVE_UUID, paths: ["C:\\Vaults\\daily.verthys"] },
        {
          uuid: "55555555555555555555555555555555",
          paths: ["C:\\Vaults\\orphan.verthys"],
        },
      ],
      files_seen: 12,
      matched_count: 2,
      truncated: false,
      permission_errors: 1,
    };
    const mounted = mountDialog({ scan });
    await nextTick();
    try {
      const text = document.body.textContent ?? "";
      expect(text).toContain("daily.verthys");
      expect(text).toContain("未在扫描范围内找到");
      expect(text).toContain("未登记 UUID");
      expect(text).toContain("权限错误 1");
    } finally {
      mounted.teardown();
    }
  });

  it("selects only anchors not present in scan evidence", async () => {
    const scan: AnchorScanResult = {
      entries: [
        { uuid: ACTIVE_UUID, paths: ["C:\\Vaults\\daily.verthys"] },
      ],
      files_seen: 1,
      matched_count: 1,
      truncated: false,
      permission_errors: 0,
    };
    const mounted = mountDialog({ scan });
    await nextTick();
    try {
      const select = buttonByText("勾选缺失");
      expect(select).toBeTruthy();
      expect(select!.disabled).toBe(false);
      select!.click();
      await nextTick();

      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      expect(release!.disabled).toBe(false);
      release!.click();
      await nextTick();
      const confirm = buttonByText("确认");
      expect(confirm).toBeTruthy();
      confirm!.click();
      await nextTick();
      expect(mounted.released[0].sort()).toEqual(
        [DEAD_UUID, TAMPERED_UUID, UNKNOWN_UUID].sort(),
      );
    } finally {
      mounted.teardown();
    }
  });
});
