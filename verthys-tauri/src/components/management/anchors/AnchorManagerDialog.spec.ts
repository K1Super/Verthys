// @vitest-environment happy-dom
/**
 * AnchorManagerDialog.spec.ts — 回退锚点管理弹窗交互契约
 *
 * 覆盖：
 *   1. 四种见证状态渲染与完整 UUID 复制
 *   2. 释放必须“勾选 → 二次确认”，确认后才 emit release
 *   3. 无 DEAD 时回收按钮禁用；有 DEAD 时可用
 *   4. 扫描覆盖范围、部分扫描门槛与“未在扫描范围内找到”措辞
 *   5. 扫描完整时自动勾选见证有效且未找到的锚点；TAMPERED/UNKNOWN 不选中
 *   6. 单一扫描入口、添加位置与移除自定义位置的事件契约
 *   7. 未登记 UUID 不再进入界面
 */
import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createApp, h, nextTick } from "vue";
import AnchorManagerDialog from "./AnchorManagerDialog.vue";
import type {
  AnchorInfo,
  AnchorScanProgress,
  AnchorScanResult,
  AnchorScanRootReport,
} from "../../../types/verthys";

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(async () => ["D:\\Vaults"]),
}));

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

function root(
  overrides: Partial<AnchorScanRootReport> = {},
): AnchorScanRootReport {
  return {
    path: "C:\\",
    kind: "dir",
    source: "volume",
    available: true,
    last_success_at: 1_700_000_000,
    last_attempt_at: 1_700_000_000,
    files_seen: 12,
    matched_count: 2,
    permission_errors: 0,
    other_errors: 0,
    truncated: false,
    deferred: false,
    entry_count: 2,
    ...overrides,
  };
}

function scanResult(
  overrides: Partial<AnchorScanResult> = {},
): AnchorScanResult {
  return {
    entries: [
      {
        uuid: ACTIVE_UUID,
        paths: ["C:\\Vaults\\daily.verthys"],
        capped: false,
      },
      {
        uuid: "55555555555555555555555555555555",
        paths: ["C:\\Vaults\\orphan.verthys"],
        capped: false,
      },
    ],
    roots: [root()],
    files_seen: 12,
    matched_count: 2,
    truncated: false,
    partial: false,
    permission_errors: 0,
    other_errors: 0,
    scanned_at: 1_700_000_000,
    depth: 8,
    cached: false,
    ...overrides,
  };
}

function mountDialog(
  overrides: Partial<{
    anchors: AnchorInfo[];
    scan: AnchorScanResult | null;
    state: number;
    busy: boolean;
    scanning: boolean;
    scanProgress: AnchorScanProgress | null;
    error: string;
    notice: string;
  }> = {},
) {
  const released: string[][] = [];
  const scans: Array<{ roots?: string[]; force?: boolean }> = [];
  const forgotten: string[] = [];
  let cancelCount = 0;
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
        scanning: false,
        scanProgress: null,
        error: "",
        notice: "",
        ...overrides,
        onRelease: (uuids: string[]) => released.push(uuids),
        onScan: (options: { roots?: string[]; force?: boolean }) =>
          scans.push(options),
        onForgetRoot: (path: string) => forgotten.push(path),
        onCancelScan: () => {
          cancelCount += 1;
        },
        onReclaim: () => {
          reclaimCount += 1;
        },
      }),
  });
  app.directive("tip", {});
  app.mount(container);
  return {
    released,
    scans,
    forgotten,
    cancelCount: () => cancelCount,
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
  it("hides all scrollbars in the anchor manager shell and table", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const content = document.querySelector(".cd-content");
      expect(
        content?.classList.contains("cd-content--no-scrollbar"),
      ).toBe(true);

      const dialogSource = readFileSync(
        resolve(
          process.cwd(),
          "src/components/management/anchors/AnchorManagerDialog.vue",
        ),
        "utf8",
      );
      expect(dialogSource).toContain(".anchor-table-wrap::-webkit-scrollbar");
      expect(dialogSource).toContain("scrollbar-width: none");
      expect(dialogSource).toContain("overscroll-behavior: contain");

      const cosmicSource = readFileSync(
        resolve(
          process.cwd(),
          "src/components/common/cosmic/CosmicDialog.vue",
        ),
        "utf8",
      );
      expect(cosmicSource).toContain(
        ".cd-content--no-scrollbar::-webkit-scrollbar",
      );
    } finally {
      mounted.teardown();
    }
  });

  it("renders all four witness states", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const text = document.body.textContent ?? "";
      expect(text).toContain("见证有效");
      expect(text).toContain("见证缺失");
      expect(text).toContain("见证异常");
      expect(text).toContain("见证未知");
      expect(text).not.toContain("使用中");
      expect(text).not.toContain("已失效");
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
      const disabledReclaim = buttonByText("回收见证缺失");
      expect(disabledReclaim).toBeTruthy();
      expect(disabledReclaim!.disabled).toBe(true);
    } finally {
      noDead.teardown();
    }

    const withDead = mountDialog();
    await nextTick();
    try {
      const reclaim = buttonByText("回收见证缺失");
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

  it("shows scan coverage and the not-found wording without unregistered UUIDs", async () => {
    const mounted = mountDialog({ scan: scanResult() });
    await nextTick();
    try {
      const text = document.body.textContent ?? "";
      expect(text).toContain("扫描位置");
      expect(text).toContain("深度 8");
      expect(text).toContain("本地磁盘");
      expect(text).toContain("C:\\");
      expect(text).toContain("daily.verthys");
      expect(text).toContain("未在扫描范围内找到");
      expect(text).not.toContain("未登记 UUID");
      expect(text).toContain("文件 12");
      expect(text).toContain("命中 2");
      expect(text).toContain("见证状态只反映 TPM 见证");
      expect(text).toContain("不代表容器仍然存在");
    } finally {
      mounted.teardown();
    }
  });

  it("emits cancel-scan while scanning and keeps the dialog closable", async () => {
    const mounted = mountDialog({
      scanning: true,
      scanProgress: {
        phase: "scanning",
        roots_total: 3,
        roots_done: 1,
        current_path: "C:\\",
        files_seen: 10,
        matched_count: 1,
        partial: false,
      },
    });
    await nextTick();
    try {
      const stop = buttonByText("停止扫描");
      expect(stop).toBeTruthy();
      stop!.click();
      await nextTick();
      expect(mounted.cancelCount()).toBe(1);

      const close = buttonByText("关闭");
      expect(close).toBeTruthy();
      expect(close!.disabled).toBe(false);
    } finally {
      mounted.teardown();
    }
  });

  it("does not auto-select when the scan is incomplete", async () => {
    const mounted = mountDialog({
      scan: scanResult({
        partial: true,
        truncated: true,
        permission_errors: 1,
        roots: [root({ truncated: true, permission_errors: 1 })],
      }),
    });
    await nextTick();
    try {
      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      expect(release!.disabled).toBe(true);
      const text = document.body.textContent ?? "";
      expect(text).toContain("未自动勾选缺失锚点");
      expect(text).toContain("权限受限 1");
      expect(text).not.toContain("批量勾选");
    } finally {
      mounted.teardown();
    }
  });

  it("does not auto-select from a cached scan", async () => {
    const mounted = mountDialog({
      scan: scanResult({
        cached: true,
        entries: [],
      }),
    });
    await nextTick();
    try {
      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      expect(release!.disabled).toBe(true);
    } finally {
      mounted.teardown();
    }
  });

  it("auto-selects only active anchors missing from a complete scan", async () => {
    const scan = scanResult({
      entries: [
        {
          uuid: DEAD_UUID,
          paths: ["C:\\Vaults\\stale.verthys"],
          capped: false,
        },
      ],
    });
    const mounted = mountDialog({ scan });
    await nextTick();
    try {
      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      expect(release!.disabled).toBe(false);
      release!.click();
      await nextTick();
      const confirm = buttonByText("确认");
      expect(confirm).toBeTruthy();
      confirm!.click();
      await nextTick();
      expect(mounted.released[0]).toEqual([ACTIVE_UUID]);
      expect(mounted.released[0]).not.toContain(TAMPERED_UUID);
      expect(mounted.released[0]).not.toContain(UNKNOWN_UUID);
      expect(mounted.released[0]).not.toContain(DEAD_UUID);
    } finally {
      mounted.teardown();
    }
  });

  it("keeps capped evidence from blocking auto-selection", async () => {
    const scan = scanResult({
      entries: [
        {
          uuid: DEAD_UUID,
          paths: Array.from(
            { length: 32 },
            (_, index) => `C:\\Vaults\\copy-${index}.verthys`,
          ),
          capped: true,
        },
      ],
    });
    const mounted = mountDialog({ scan });
    await nextTick();
    try {
      const text = document.body.textContent ?? "";
      expect(text).toContain("另有副本未展示");
      expect(text).not.toContain("未自动勾选缺失锚点");

      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      expect(release!.disabled).toBe(false);
      release!.click();
      await nextTick();
      buttonByText("确认")!.click();
      await nextTick();
      expect(mounted.released[0]).toEqual([ACTIVE_UUID]);
    } finally {
      mounted.teardown();
    }
  });

  it("exposes a single scan action and keeps add-location", async () => {
    const mounted = mountDialog({ scan: scanResult() });
    await nextTick();
    try {
      expect(buttonByText("重新扫描")).toBeUndefined();
      expect(buttonByText("深度扫描")).toBeUndefined();
      expect(buttonByText("勾选缺失")).toBeUndefined();

      buttonByText("扫描")!.click();
      await nextTick();
      expect(mounted.scans[0]).toEqual({ force: true });

      buttonByText("添加位置")!.click();
      await nextTick();
      await Promise.resolve();
      expect(mounted.scans[1]).toEqual({ roots: ["D:\\Vaults"] });
    } finally {
      mounted.teardown();
    }
  });

  it("emits forget-root for a custom location", async () => {
    const mounted = mountDialog({
      scan: scanResult({
        roots: [
          root({
            path: "D:\\Custom",
            source: "custom",
          }),
        ],
      }),
    });
    await nextTick();
    try {
      const remove = buttonByText("移除");
      expect(remove).toBeTruthy();
      remove!.click();
      await nextTick();
      expect(mounted.forgotten).toEqual(["D:\\Custom"]);
    } finally {
      mounted.teardown();
    }
  });
});
