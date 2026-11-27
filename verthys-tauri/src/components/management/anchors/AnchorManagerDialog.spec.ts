// @vitest-environment happy-dom
/**
 * AnchorManagerDialog.spec.ts — 回退锚点管理弹窗交互契约
 *
 * 覆盖：
 *   1. 四种见证状态渲染与完整 UUID 复制
 *   2. 单一入口：全 DEAD 为「清理选中」，含其它状态为「释放选中」
 *   3. 打开时自动勾选全部 DEAD，扫描证据不改变该勾选
 *   4. 扫描覆盖范围、部分扫描提示与“未在扫描范围内找到”措辞
 *   5. 单一扫描入口、添加位置与移除自定义位置的事件契约
 *   6. 未登记 UUID 不再进入界面
 */
import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createApp, h, nextTick, reactive } from "vue";
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
  }> = {},
) {
  const released: string[][] = [];
  const scans: Array<{ roots?: string[]; force?: boolean }> = [];
  const forgotten: string[] = [];
  let cancelCount = 0;
  const props = reactive({
    show: true,
    anchors: ANCHORS,
    state: 1,
    scan: null as AnchorScanResult | null,
    busy: false,
    scanning: false,
    scanProgress: null as AnchorScanProgress | null,
    error: "",
    ...overrides,
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(AnchorManagerDialog, {
        ...props,
        onRelease: (uuids: string[]) => released.push(uuids),
        onScan: (options: { roots?: string[]; force?: boolean }) =>
          scans.push(options),
        onForgetRoot: (path: string) => forgotten.push(path),
        onCancelScan: () => {
          cancelCount += 1;
        },
      }),
  });
  app.directive("tip", {});
  app.mount(container);
  return {
    props,
    released,
    scans,
    forgotten,
    cancelCount: () => cancelCount,
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

  it("requires explicit selection before release when no dead anchor is selected", async () => {
    const mounted = mountDialog({
      anchors: ANCHORS.filter((anchor) => anchor.witness !== "dead"),
    });
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

      const confirmButton = buttonByText("确认释放");
      expect(confirmButton).toBeTruthy();
      confirmButton!.click();
      await nextTick();
      expect(mounted.released).toEqual([[ACTIVE_UUID]]);
    } finally {
      mounted.teardown();
    }
  });

  it("auto-selects all dead anchors and shows a calm cleanup confirmation", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const cleanup = buttonByText("清理选中");
      expect(cleanup).toBeTruthy();
      expect(cleanup!.disabled).toBe(false);

      cleanup!.click();
      await nextTick();
      const text = document.body.textContent ?? "";
      expect(text).toContain("确认清理");
      expect(text).toContain("将清理 1 个见证缺失");
      const preview = document.querySelector(".anchor-dead-ids");
      expect(preview?.textContent ?? "").toContain(DEAD_UUID);

      const confirm = buttonByText("确认清理");
      expect(confirm).toBeTruthy();
      confirm!.click();
      await nextTick();
      expect(mounted.released).toEqual([[DEAD_UUID]]);
    } finally {
      mounted.teardown();
    }
  });

  it("opens the confirmation in a separate high-priority dialog and cancels without release", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      expect(document.querySelectorAll(".cosmic-overlay-host").length).toBe(1);
      expect(buttonByText("确认清理")).toBeUndefined();

      buttonByText("清理选中")!.click();
      await nextTick();
      expect(document.querySelectorAll(".cosmic-overlay-host").length).toBe(2);
      expect(
        document.querySelector("#anchor-pending-title")?.textContent ?? "",
      ).toContain("确认清理");

      buttonByText("取消")!.click();
      await nextTick();
      /* 确认窗离场动画 0.22s：等待卸载后再断言只剩管理弹窗 */
      await new Promise((resolve) => setTimeout(resolve, 300));
      await nextTick();
      expect(document.querySelectorAll(".cosmic-overlay-host").length).toBe(1);
      expect(document.querySelector("#anchor-manager-title")).toBeTruthy();
      expect(mounted.released).toEqual([]);
    } finally {
      mounted.teardown();
    }
  });

  it("re-selects all dead anchors when a scan finishes", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const boxes = Array.from(
        document.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
      );
      /* 手动并入 ACTIVE，使当前选中集合包含非 DEAD */
      boxes[0].checked = true;
      boxes[0].dispatchEvent(new Event("change"));
      await nextTick();
      expect(buttonByText("释放选中")).toBeTruthy();

      mounted.props.scanning = true;
      await nextTick();
      mounted.props.scanning = false;
      await nextTick();

      expect(buttonByText("清理选中")).toBeTruthy();
      expect(buttonByText("释放选中")).toBeUndefined();
    } finally {
      mounted.teardown();
    }
  });

  it("adds active anchors missing from a complete scan after scanning", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      /* 默认只勾 DEAD */
      expect(buttonByText("清理选中")).toBeTruthy();
      expect(buttonByText("释放选中")).toBeUndefined();

      mounted.props.scan = scanResult({ entries: [] });
      mounted.props.scanning = true;
      await nextTick();
      mounted.props.scanning = false;
      await nextTick();

      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      release!.click();
      await nextTick();
      const text = document.body.textContent ?? "";
      expect(text).toContain("确认释放");
      expect(text).toContain("并非见证缺失");

      buttonByText("确认释放")!.click();
      await nextTick();
      expect(mounted.released[0]).toEqual([DEAD_UUID, ACTIVE_UUID]);
      expect(mounted.released[0]).not.toContain(TAMPERED_UUID);
      expect(mounted.released[0]).not.toContain(UNKNOWN_UUID);
    } finally {
      mounted.teardown();
    }
  });

  it("keeps only dead selected when the scan is incomplete", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      mounted.props.scan = scanResult({ entries: [], partial: true });
      mounted.props.scanning = true;
      await nextTick();
      mounted.props.scanning = false;
      await nextTick();

      expect(buttonByText("清理选中")).toBeTruthy();
      expect(buttonByText("释放选中")).toBeUndefined();
    } finally {
      mounted.teardown();
    }
  });

  it("switches to release wording when a non-dead anchor is selected", async () => {
    const mounted = mountDialog();
    await nextTick();
    try {
      const checkboxes = Array.from(
        document.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
      );
      checkboxes[0].checked = true;
      checkboxes[0].dispatchEvent(new Event("change"));
      await nextTick();

      const release = buttonByText("释放选中");
      expect(release).toBeTruthy();
      release!.click();
      await nextTick();
      const text = document.body.textContent ?? "";
      expect(text).toContain("确认释放");
      expect(text).toContain("并非见证缺失");

      buttonByText("确认释放")!.click();
      await nextTick();
      expect(mounted.released).toEqual([[DEAD_UUID, ACTIVE_UUID]]);
    } finally {
      mounted.teardown();
    }
  });

  it("shows scan coverage with inline source labels and no unregistered UUIDs", async () => {
    const mounted = mountDialog({ scan: scanResult() });
    await nextTick();
    try {
      const metrics = document.querySelector(".anchor-scan-metrics")?.textContent ?? "";
      expect(metrics).toContain("位置");
      expect(metrics).toContain("深度");
      expect(metrics).toContain("8");
      expect(metrics).toContain("文件");
      expect(metrics).toContain("12");
      expect(metrics).toContain("命中");
      expect(metrics).toContain("2");

      const coverage = document.querySelector(".anchor-coverage")?.textContent ?? "";
      expect(coverage).toContain("磁盘");
      expect(coverage).toContain("C:\\");
      expect(coverage).toContain("正常");

      const text = document.body.textContent ?? "";
      expect(text).toContain("daily.verthys");
      expect(text).toContain("未在扫描范围内找到");
      expect(text).not.toContain("未登记 UUID");
      expect(text).toContain("见证状态只反映 TPM 见证");
      expect(text).toContain("不代表容器仍然存在");
    } finally {
      mounted.teardown();
    }
  });

  it("lists every scanned location inline without ambiguous truncation", async () => {
    const roots = Array.from({ length: 5 }, (_, index) =>
      root({ path: `D:\\Vaults\\copy-${index}`, source: "custom" }),
    );
    const mounted = mountDialog({ scan: scanResult({ roots }) });
    await nextTick();
    try {
      const rows = Array.from(
        document.querySelectorAll<HTMLElement>(".anchor-coverage-row"),
      );
      expect(rows.length).toBe(5);
      for (const row of rows) {
        expect(row.textContent).toContain("自定义");
        expect(row.textContent).toContain("正常");
      }
      expect(document.body.textContent).not.toContain("另有");
    } finally {
      mounted.teardown();
    }

    const scanning = mountDialog({ scan: scanResult({ roots }), scanning: true });
    await nextTick();
    try {
      expect(document.querySelector(".anchor-coverage")).toBeNull();
      expect(document.body.textContent).toContain("扫描中");
      expect(document.body.textContent).toContain("停止扫描");
    } finally {
      scanning.teardown();
    }
  });

  it("emits cancel-scan while scanning and relies on backdrop close", async () => {
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

      expect(buttonByText("关闭")).toBeUndefined();
      expect(buttonByText("清理选中")).toBeTruthy();
      expect(buttonByText("释放选中")).toBeUndefined();
    } finally {
      mounted.teardown();
    }
  });

  it("keeps dead anchors selected even when the scan is incomplete", async () => {
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
      const cleanup = buttonByText("清理选中");
      expect(cleanup).toBeTruthy();
      expect(cleanup!.disabled).toBe(false);
      const text = document.body.textContent ?? "";
      expect(text).toContain("未自动勾选缺失锚点");
      expect(text).toContain("权限受限 1");
      expect(text).not.toContain("批量勾选");
    } finally {
      mounted.teardown();
    }
  });

  it("keeps dead anchors selected from a cached scan", async () => {
    const mounted = mountDialog({
      scan: scanResult({
        cached: true,
        entries: [],
      }),
    });
    await nextTick();
    try {
      const cleanup = buttonByText("清理选中");
      expect(cleanup).toBeTruthy();
      expect(cleanup!.disabled).toBe(false);
    } finally {
      mounted.teardown();
    }
  });

  it("auto-selects every dead anchor regardless of scan evidence", async () => {
    const secondDead = "66666666666666666666666666666666";
    const mounted = mountDialog({
      anchors: [
        ...ANCHORS,
        { uuid: secondDead, generation: 1, witness: "dead" },
      ],
      scan: scanResult(),
    });
    await nextTick();
    try {
      const cleanup = buttonByText("清理选中");
      expect(cleanup).toBeTruthy();
      expect(cleanup!.disabled).toBe(false);
      cleanup!.click();
      await nextTick();
      const preview = document.querySelector(".anchor-dead-ids");
      expect(preview?.textContent ?? "").toContain(DEAD_UUID);
      expect(preview?.textContent ?? "").toContain(secondDead);
      buttonByText("确认清理")!.click();
      await nextTick();
      expect(mounted.released).toEqual([[DEAD_UUID, secondDead]]);
      expect(mounted.released[0]).not.toContain(ACTIVE_UUID);
      expect(mounted.released[0]).not.toContain(TAMPERED_UUID);
      expect(mounted.released[0]).not.toContain(UNKNOWN_UUID);
    } finally {
      mounted.teardown();
    }
  });

  it("keeps capped evidence from affecting dead auto-selection", async () => {
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

      const cleanup = buttonByText("清理选中");
      expect(cleanup).toBeTruthy();
      expect(cleanup!.disabled).toBe(false);
      cleanup!.click();
      await nextTick();
      buttonByText("确认清理")!.click();
      await nextTick();
      expect(mounted.released).toEqual([[DEAD_UUID]]);
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
