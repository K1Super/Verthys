<!--
  DevDock.vue — DEV-only 开发工具悬浮球

  视觉结构：事件视界悬浮球 + 透镜化吸积盘 + 四枚轨道卫星 + 分区式观测台。
  交互结构：
    1. 主球悬浮时沿“朝向视口中心”的扇区展开四枚卫星，并显影轨道系绳
    2. 前三枚卫星对应日志、观测、环境分组，第四枚固定为填充动作
    3. 点击主球展开观测台：左侧扇区导轨切换分区，右侧舞台只渲染当前分区，
       不再把所有分组堆进同一条长列表
    4. 拖拽、边缘吸附与位置持久化沿用几何与指针模块

  隔离约束：组件只由 App.vue 的 import.meta.env.DEV 分支动态加载，
  生产构建不包含本文件、样式与工具依赖；根节点携带构建标记供门禁扫描。
-->
<template>
  <Teleport to="body">
    <div ref="rootEl" class="devdock-root" :data-verthys-devtools="DEVDOCK_MARKER">
      <div
        ref="clusterEl"
        class="devdock-cluster"
        :style="orbStyle"
        @focusin="onClusterFocusIn"
        @focusout="onClusterFocusOut"
      >
        <div
          v-for="(group, index) in SATELLITE_GROUPS"
          :key="group.id"
          class="devdock-sat"
          :class="{ 'is-visible': satellitesVisible }"
          :style="satelliteStyle(index, GROUP_META[group.id].accent, GROUP_META[group.id].accentRgb)"
          :inert="!satellitesVisible"
          :aria-hidden="!satellitesVisible"
          @pointerenter="onSatellitePointerEnter"
          @pointerleave="onSatellitePointerLeave"
        >
          <button
            type="button"
            class="sat-node"
            :tabindex="satellitesVisible ? 0 : -1"
            :aria-label="`${group.label}快捷入口`"
            @click="openGroup(group.id)"
          >
            <svg class="sat-glyph" viewBox="0 0 24 24" aria-hidden="true">
              <path :d="GROUP_META[group.id].glyph" />
            </svg>
            <span class="sat-short">{{ GROUP_META[group.id].short }}</span>
          </button>
        </div>

        <div
          class="devdock-sat devdock-sat--fill"
          :class="{ 'is-visible': satellitesVisible }"
          :style="satelliteStyle(3, FIXTURE_META.accent, FIXTURE_META.accentRgb)"
          :inert="!satellitesVisible"
          :aria-hidden="!satellitesVisible"
          @pointerenter="onSatellitePointerEnter"
          @pointerleave="onSatellitePointerLeave"
        >
          <button
            type="button"
            class="sat-node"
            :tabindex="satellitesVisible ? 0 : -1"
            aria-label="填充当前表单"
            @click="runFixtureFillAction"
          >
            <svg class="sat-glyph" viewBox="0 0 24 24" aria-hidden="true">
              <path :d="FIXTURE_META.glyph" />
            </svg>
            <span class="sat-short">填充</span>
          </button>
        </div>

        <button
          ref="orbEl"
          type="button"
          class="devdock-orb"
          :class="{ 'is-dragging': dragging, 'is-on': satellitesVisible }"
          :aria-expanded="open"
          aria-controls="devdock-panel"
          aria-label="开发工具"
          @pointerdown="onOrbPointerDown"
          @pointermove="onPointerMove"
          @pointerup="onPointerUp"
          @pointercancel="onPointerCancel"
          @click="onClick"
          @pointerenter="onOrbPointerEnter"
          @pointerleave="onOrbPointerLeave"
        >
          <span class="orb-shell">
            <svg class="orb-field" viewBox="0 0 56 56" aria-hidden="true">
              <ellipse
                class="orb-disk"
                cx="28"
                cy="28"
                rx="22.5"
                ry="7.4"
                transform="rotate(-18 28 28)"
              />
              <circle class="orb-photon" cx="28" cy="28" r="12.4" />
              <circle class="orb-horizon" cx="28" cy="28" r="10.4" />
            </svg>
          </span>
        </button>
      </div>

      <section
        v-if="open"
        id="devdock-panel"
        ref="panelEl"
        class="devdock-console"
        :class="{ 'is-open-left': panelOpensLeft }"
        :style="panelStyle"
        role="dialog"
        aria-modal="false"
        aria-label="开发控制台"
        @pointerdown.stop
      >
        <header class="console-head">
          <span class="console-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32">
              <ellipse class="mark-disk" cx="16" cy="16" rx="13" ry="4.4" transform="rotate(-18 16 16)" />
              <circle class="mark-photon" cx="16" cy="16" r="7.4" />
              <circle class="mark-horizon" cx="16" cy="16" r="6.2" />
              <g class="mark-ticks">
                <line x1="16" y1="1" x2="16" y2="3.2" />
                <line x1="16" y1="28.8" x2="16" y2="31" />
                <line x1="1" y1="16" x2="3.2" y2="16" />
                <line x1="28.8" y1="16" x2="31" y2="16" />
              </g>
            </svg>
          </span>
          <div class="console-id">
            <span class="console-kicker">SINGULARITY // DEV</span>
            <span class="console-title">开发控制台</span>
          </div>
          <div class="console-live" aria-hidden="true">
            <span class="console-signal"></span>
            <span>LIVE</span>
          </div>
          <button
            type="button"
            class="console-close"
            aria-label="关闭开发控制台"
            @click="closePanel()"
          >
            <span aria-hidden="true">×</span>
          </button>
        </header>

        <div class="console-frame">
          <nav
            class="console-rail"
            role="tablist"
            aria-orientation="vertical"
            aria-label="工具分区"
          >
            <button
              v-for="(item, index) in RAIL_ITEMS"
              :key="item.id"
              type="button"
              role="tab"
              class="console-tab"
              :id="`devdock-tab-${item.id}`"
              :class="{ 'is-active': activePanel === item.id }"
              :style="{ '--tab-accent': item.accent, '--tab-accent-rgb': item.accentRgb }"
              :data-tab-group="item.id"
              :aria-label="item.label"
              :aria-selected="activePanel === item.id"
              aria-controls="devdock-stage"
              :tabindex="activePanel === item.id ? 0 : -1"
              @click="selectPanel(item.id)"
              @keydown="onRailKeydown($event, index)"
            >
              <span class="tab-glyph" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path :d="item.glyph" /></svg>
              </span>
              <span class="tab-label">{{ item.short }}</span>
            </button>
          </nav>

          <div
            id="devdock-stage"
            ref="panelBodyEl"
            class="console-stage"
            role="tabpanel"
            tabindex="0"
            :aria-labelledby="`devdock-tab-${activePanel}`"
          >
            <section
              v-if="activePanel === 'fixture'"
              :key="'fixture'"
              class="stage-section"
              :style="{
                '--group-accent': FIXTURE_META.accent,
                '--group-accent-rgb': FIXTURE_META.accentRgb,
              }"
            >
              <header class="stage-head">
                <span class="stage-ordinal">{{ activeOrdinal }}</span>
                <div class="stage-id">
                  <span class="stage-kicker">SECTOR {{ activeOrdinal }} / {{ totalOrdinal }}</span>
                  <h2 class="stage-title">{{ FIXTURE_META.label }}</h2>
                </div>
                <span class="stage-count">PROFILE</span>
                <svg class="stage-watermark" viewBox="0 0 24 24" aria-hidden="true">
                  <path :d="FIXTURE_META.glyph" />
                </svg>
              </header>
              <div class="stage-body is-fixture">
                <FixturePanel />
              </div>
            </section>

            <section
              v-else
              :key="activeGroup.id"
              class="stage-section"
              :data-devtool-group="activeGroup.id"
              :style="{
                '--group-accent': activeGroupMeta.accent,
                '--group-accent-rgb': activeGroupMeta.accentRgb,
              }"
            >
              <header class="stage-head">
                <span class="stage-ordinal">{{ activeOrdinal }}</span>
                <div class="stage-id">
                  <span class="stage-kicker">SECTOR {{ activeOrdinal }} / {{ totalOrdinal }}</span>
                  <h2 class="stage-title">{{ activeGroup.label }}</h2>
                </div>
                <span class="stage-count">
                  {{ String(activeGroup.tools.length).padStart(2, "0") }} UNITS
                </span>
                <svg class="stage-watermark" viewBox="0 0 24 24" aria-hidden="true">
                  <path :d="activeGroupMeta.glyph" />
                </svg>
              </header>

              <div class="stage-body">
                <article
                  v-for="(tool, toolIndex) in activeGroup.tools"
                  :key="tool.id"
                  class="devdock-tool-row"
                  :class="{ 'is-info': tool.kind === 'info', 'is-danger': tool.tone === 'danger' }"
                  :style="{ '--row-index': `${toolIndex}` }"
                >
                  <div class="tool-rail" aria-hidden="true">
                    <span class="tool-ordinal">{{ padOrdinal(toolIndex) }}</span>
                    <span class="tool-tick"></span>
                  </div>

                  <div class="tool-main">
                    <div class="tool-headline">
                      <span class="tool-label" :class="{ 'is-danger': tool.tone === 'danger' }">
                        {{ tool.label }}
                      </span>
                      <span class="tool-tag" :class="{ 'is-danger': tool.tone === 'danger' }">
                        {{ toolTag(tool) }}
                      </span>
                    </div>
                    <span class="tool-hint">{{ tool.hint }}</span>

                    <div v-if="tool.kind === 'info'" class="readout">
                      <span
                        v-for="(value, key) in infoValues(tool)"
                        :key="key"
                        class="readout-cell"
                        :class="{ 'is-wide': isWideReadout(value) }"
                      >
                        <span class="readout-key">{{ key }}</span>
                        <span class="readout-value">{{ value }}</span>
                      </span>
                    </div>

                    <div v-if="(tool.actions?.length ?? 0) > 0" class="tool-subkeys">
                      <button
                        v-for="action in tool.actions ?? []"
                        :key="action.label"
                        type="button"
                        class="console-key console-key--sub"
                        :class="{ 'console-key--danger': action.tone === 'danger' }"
                        :disabled="busyId === tool.id"
                        @click="runAction(tool, action)"
                      >
                        {{ busyId === tool.id ? "执行中…" : action.label }}
                      </button>
                    </div>
                  </div>

                  <div v-if="tool.kind === 'action'" class="tool-keys">
                    <button
                      type="button"
                      class="console-key"
                      :class="{ 'console-key--danger': tool.tone === 'danger' }"
                      :disabled="busyId === tool.id"
                      @click="runTool(tool)"
                    >
                      {{ busyId === tool.id ? "执行中…" : tool.label }}
                    </button>
                  </div>
                </article>
              </div>
            </section>
          </div>
        </div>

        <footer class="console-foot">
          <span>BUILD {{ consoleVersion }}</span>
          <span class="foot-rule" aria-hidden="true"></span>
          <span>{{ String(devTools.length).padStart(2, "0") }} UNITS</span>
        </footer>
      </section>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useToastCenter } from "../composables/useToastCenter";
import FixturePanel from "./fixture/FixturePanel.vue";
import "./devdock.css";
import { DEVDOCK_MARKER } from "./marker";
import {
  ORB_MARGIN,
  ORB_SIZE,
  ORB_STORAGE_KEY,
  ORB_TOP_INSET,
  clampOrbPosition,
  defaultOrbPosition,
  parseStoredOrbPosition,
  serializeOrbPosition,
  type OrbPosition,
  type OrbViewport,
} from "./orb_geometry";
import {
  DEV_TOOL_GROUPS,
  createDevTools,
  type DevTool,
  type DevToolAction,
  type DevToolContext,
  type DevToolGroupId,
  type DevToolReadout,
} from "./registry";
import { useOrbDrag } from "./useOrbDrag";
import { dispatchFill } from "./fixture/fill_action";
import { getFixtureProfile } from "./fixture/profile_client";

interface GroupMeta {
  short: string;
  glyph: string;
  accent: string;
  accentRgb: string;
}

type PanelSectionId = DevToolGroupId | "fixture";

interface RailItem {
  id: PanelSectionId;
  label: string;
  short: string;
  glyph: string;
  accent: string;
  accentRgb: string;
}

const GROUP_META: Record<DevToolGroupId, GroupMeta> = {
  logs: {
    short: "日志",
    glyph: "M4 5h12M4 9h12M4 13h8M16 13h.01",
    accent: "rgba(112, 205, 255, 0.9)",
    accentRgb: "112, 205, 255",
  },
  runtime: {
    short: "观测",
    glyph: "M3 12h3l2-7 4 14 3-7h3",
    accent: "rgba(170, 156, 255, 0.9)",
    accentRgb: "170, 156, 255",
  },
  environment: {
    short: "环境",
    glyph: "M12 5a7 7 0 1 0 0 14a7 7 0 0 0 0-14M12 2v3M12 19v3M2 12h3M19 12h3",
    accent: "rgba(156, 174, 194, 0.88)",
    accentRgb: "156, 174, 194",
  },
  actions: {
    short: "动作",
    glyph: "M20 12a8 8 0 1 1-2.34-5.66M20 4v4h-4",
    accent: "rgba(255, 176, 112, 0.9)",
    accentRgb: "255, 176, 112",
  },
};

const FIXTURE_META: GroupMeta & { label: string } = {
  label: "填充配置",
  short: "填充",
  glyph: "M12 3v9M8.5 8.5 12 12l3.5-3.5M5 18h14",
  accent: "rgba(255, 126, 146, 0.88)",
  accentRgb: "255, 126, 146",
};

const { showError, showStatus } = useToastCenter();

/** 前三枚卫星保留分组入口，第四枚固定为填充动作。 */
const SATELLITE_GROUPS = DEV_TOOL_GROUPS.slice(0, 3);

const rootEl = ref<HTMLDivElement | null>(null);
const clusterEl = ref<HTMLDivElement | null>(null);
const orbEl = ref<HTMLButtonElement | null>(null);
const panelEl = ref<HTMLElement | null>(null);
const panelBodyEl = ref<HTMLElement | null>(null);

const viewport = ref<OrbViewport>({
  width: window.innerWidth,
  height: window.innerHeight,
});

function readStoredPosition(): string | null {
  try {
    return window.localStorage.getItem(ORB_STORAGE_KEY);
  } catch {
    return null;
  }
}

/* 记录首次读取时是否存在持久化位置：无持久化记录时，挂载后再按真实视口
   重新落位 — 页面在后台以零尺寸初始化时，setup 期算出的默认位置会贴左上角 */
const storedOrbPosition = readStoredPosition();
const position = ref<OrbPosition>(
  parseStoredOrbPosition(storedOrbPosition, viewport.value),
);

const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
const reducedMotion = ref(motionQuery.matches);

const devTools = createDevTools();
const groups = computed(() =>
  DEV_TOOL_GROUPS.map((group) => ({
    id: group.id,
    label: group.label,
    tools: devTools.filter((tool) => tool.group === group.id),
  })),
);

const activeGroupId = ref<DevToolGroupId>(DEV_TOOL_GROUPS[0].id);
const activePanel = ref<PanelSectionId>(DEV_TOOL_GROUPS[0].id);
const open = ref(false);
const busyId = ref("");
const refreshTick = ref(0);
const satellitesVisible = ref(false);
const clusterHovered = ref(false);
const clusterFocused = ref(false);
const fixtureFillBusy = ref(false);

let refreshTimer: number | null = null;
let hoverTimer: number | null = null;
/* 关闭面板后归还焦点会触发 focusin；该事件不代表展开意图，需跳过卫星展开 */
let suppressNextFocusIn = false;

const consoleVersion = import.meta.env.VITE_APP_VERSION ?? "unknown";

const RAIL_ITEMS = computed<RailItem[]>(() => [
  ...groups.value.map((group) => ({
    id: group.id,
    label: group.label,
    short: GROUP_META[group.id].short,
    glyph: GROUP_META[group.id].glyph,
    accent: GROUP_META[group.id].accent,
    accentRgb: GROUP_META[group.id].accentRgb,
  })),
  {
    id: "fixture",
    label: FIXTURE_META.label,
    short: FIXTURE_META.short,
    glyph: FIXTURE_META.glyph,
    accent: FIXTURE_META.accent,
    accentRgb: FIXTURE_META.accentRgb,
  },
]);

const activeGroup = computed(() => {
  const found = groups.value.find((group) => group.id === activeGroupId.value);
  return found ?? groups.value[0];
});
const activeGroupMeta = computed(() => GROUP_META[activeGroup.value.id]);

const activeRailIndex = computed(() => {
  const index = RAIL_ITEMS.value.findIndex((item) => item.id === activePanel.value);
  return index < 0 ? 0 : index;
});
const activeOrdinal = computed(() => String(activeRailIndex.value + 1).padStart(2, "0"));
const totalOrdinal = computed(() => String(RAIL_ITEMS.value.length).padStart(2, "0"));

/* 卫星沿“朝向视口中心”的扇区展开：球在右下时向左上，球在左上时向右下，
   避免固定方向在边缘处越界。扇区半角 60°，四枚卫星均匀分布。 */
const fanLayout = computed(() => {
  const centerX = position.value.x + ORB_SIZE / 2;
  const centerY = position.value.y + ORB_SIZE / 2;
  let dx = viewport.value.width / 2 - centerX;
  let dy = viewport.value.height / 2 - centerY;
  if (Math.hypot(dx, dy) < 1) {
    dx = -0.707;
    dy = -0.707;
  }
  const baseAngle = Math.atan2(dy, dx);
  const radius = Math.min(
    92,
    Math.max(70, Math.min(viewport.value.width, viewport.value.height) * 0.14),
  );
  const positions = [-60, -20, 20, 60].map((offset) => {
    const angle = baseAngle + (offset * Math.PI) / 180;
    return {
      x: Math.cos(angle) * radius,
      y: Math.sin(angle) * radius,
    };
  });
  return { positions };
});

const orbStyle = computed<Record<string, string>>(() => ({
  transform: `translate3d(${position.value.x}px, ${position.value.y}px, 0)`,
}));

const panelOpensLeft = computed(
  () => position.value.x + ORB_SIZE / 2 > viewport.value.width / 2,
);

function satelliteStyle(
  index: number,
  accent: string,
  accentRgb: string,
): Record<string, string> {
  const fan = fanLayout.value.positions[index] ?? { x: 0, y: 0 };
  const distance = Math.hypot(fan.x, fan.y);
  /* 系绳从卫星边缘起、止于球体边缘，长度按扇区半径裁切，避免压进球体 */
  const tether = Math.max(8, Math.round(distance - ORB_SIZE / 2 - 22));
  const angle = Math.atan2(-fan.y, -fan.x);
  return {
    "--fan-x": `${Math.round(fan.x)}px`,
    "--fan-y": `${Math.round(fan.y)}px`,
    "--fan-delay": `${index * 28}ms`,
    "--sat-accent": accent,
    "--sat-accent-rgb": accentRgb,
    "--sat-angle": `${angle}rad`,
    "--tether-len": `${tether}px`,
  };
}

const panelStyle = computed<Record<string, string>>(() => {
  const gap = 12;
  const width = Math.min(480, Math.max(300, viewport.value.width - ORB_MARGIN * 2));
  const openLeft = panelOpensLeft.value;
  const preferredLeft = openLeft
    ? position.value.x - width - gap
    : position.value.x + ORB_SIZE + gap;
  const left = Math.max(
    ORB_MARGIN,
    Math.min(preferredLeft, viewport.value.width - width - ORB_MARGIN),
  );

  const style: Record<string, string> = {
    left: `${left}px`,
    width: `${width}px`,
  };

  if (position.value.y + ORB_SIZE / 2 > viewport.value.height / 2) {
    style.bottom = `${Math.max(ORB_MARGIN, viewport.value.height - position.value.y + gap)}px`;
    /* 向上展开时同样让出窗控条：顶部安全边距高于普通视口留白 */
    const availableAbove = position.value.y - gap - ORB_TOP_INSET;
    style.maxHeight = `${Math.min(680, Math.max(240, availableAbove))}px`;
  } else {
    style.top = `${Math.max(ORB_TOP_INSET, position.value.y + ORB_SIZE + gap)}px`;
    const availableBelow =
      viewport.value.height - (position.value.y + ORB_SIZE + gap) - ORB_MARGIN;
    style.maxHeight = `${Math.min(680, Math.max(240, availableBelow))}px`;
  }
  return style;
});

function persistPosition(value: OrbPosition): void {
  try {
    window.localStorage.setItem(ORB_STORAGE_KEY, serializeOrbPosition(value));
  } catch {
    /* 隐私模式或存储配额异常不阻断拖拽 */
  }
}

function stopRefresh(): void {
  if (refreshTimer !== null) {
    window.clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

function startRefresh(): void {
  stopRefresh();
  refreshTimer = window.setInterval(() => {
    refreshTick.value += 1;
  }, 1000);
}

function cancelHoverTimer(): void {
  if (hoverTimer !== null) {
    window.clearTimeout(hoverTimer);
    hoverTimer = null;
  }
}

function scheduleSatelliteHide(delay = 140): void {
  cancelHoverTimer();
  if (open.value || dragging.value) {
    satellitesVisible.value = false;
    return;
  }
  hoverTimer = window.setTimeout(() => {
    hoverTimer = null;
    if (!open.value && !dragging.value && !clusterHovered.value && !clusterFocused.value) {
      satellitesVisible.value = false;
    }
  }, delay);
}

function syncSatellites(): void {
  cancelHoverTimer();
  if (open.value || dragging.value) {
    satellitesVisible.value = false;
    return;
  }
  if (clusterHovered.value || clusterFocused.value) {
    satellitesVisible.value = true;
    return;
  }
  scheduleSatelliteHide();
}

function onClusterFocusIn(): void {
  if (suppressNextFocusIn) return;
  clusterFocused.value = true;
  syncSatellites();
}

function onClusterFocusOut(event: FocusEvent): void {
  const next = event.relatedTarget;
  if (next instanceof Node && clusterEl.value?.contains(next)) return;
  clusterFocused.value = false;
  syncSatellites();
}

function onOrbPointerEnter(): void {
  clusterHovered.value = true;
  syncSatellites();
}

function onOrbPointerLeave(): void {
  clusterHovered.value = false;
  syncSatellites();
}

function onSatellitePointerEnter(): void {
  clusterHovered.value = true;
  syncSatellites();
}

function onSatellitePointerLeave(): void {
  clusterHovered.value = false;
  syncSatellites();
}

function onOutsidePointerDown(event: PointerEvent): void {
  const target = event.target;
  if (!(target instanceof Node)) return;
  if (rootEl.value?.contains(target)) return;
  /* 点外关闭不把焦点抢回球体，避免关闭后卫星扇区意外弹出 */
  closePanel(false);
}

function onEscKeydown(event: KeyboardEvent): void {
  if (event.key !== "Escape") return;
  event.preventDefault();
  event.stopPropagation();
  closePanel();
}

function armPanelListeners(): void {
  document.addEventListener("pointerdown", onOutsidePointerDown, true);
  document.addEventListener("keydown", onEscKeydown, true);
}

function disarmPanelListeners(): void {
  document.removeEventListener("pointerdown", onOutsidePointerDown, true);
  document.removeEventListener("keydown", onEscKeydown, true);
}

function padOrdinal(index: number): string {
  return String(index + 1).padStart(2, "0");
}

function selectPanel(target: PanelSectionId): void {
  activePanel.value = target;
  if (target !== "fixture") activeGroupId.value = target;
  if (panelBodyEl.value) panelBodyEl.value.scrollTop = 0;
}

function onRailKeydown(event: KeyboardEvent, index: number): void {
  const total = RAIL_ITEMS.value.length;
  let nextIndex = index;
  if (event.key === "ArrowUp") {
    nextIndex = (index - 1 + total) % total;
  } else if (event.key === "ArrowDown") {
    nextIndex = (index + 1) % total;
  } else if (event.key === "Home") {
    nextIndex = 0;
  } else if (event.key === "End") {
    nextIndex = total - 1;
  } else {
    return;
  }
  event.preventDefault();
  const item = RAIL_ITEMS.value[nextIndex];
  if (!item) return;
  selectPanel(item.id);
  nextTick(() => {
    document.getElementById(`devdock-tab-${item.id}`)?.focus({ preventScroll: true });
  });
}

function openPanel(target?: PanelSectionId): void {
  if (open.value) {
    if (target) selectPanel(target);
    return;
  }
  if (target) {
    activePanel.value = target;
    if (target !== "fixture") activeGroupId.value = target;
  }
  open.value = true;
  satellitesVisible.value = false;
  cancelHoverTimer();
  startRefresh();
  nextTick(() => {
    if (!open.value || !rootEl.value) return;
    armPanelListeners();
    document.getElementById(`devdock-tab-${activePanel.value}`)?.focus({
      preventScroll: true,
    });
  });
}

function closePanel(returnFocus = true): void {
  if (!open.value) return;
  open.value = false;
  disarmPanelListeners();
  stopRefresh();
  /* 关闭动作已消费当前的悬浮与焦点意图：卫星扇区须等待下一次指针进入或焦点进入 */
  clusterHovered.value = false;
  clusterFocused.value = false;
  if (!returnFocus) return;
  nextTick(() => {
    suppressNextFocusIn = true;
    orbEl.value?.focus({ preventScroll: true });
    suppressNextFocusIn = false;
  });
}

function togglePanel(): void {
  if (open.value) {
    closePanel();
  } else {
    openPanel();
  }
}

function openGroup(groupId: DevToolGroupId): void {
  activeGroupId.value = groupId;
  activePanel.value = groupId;
  satellitesVisible.value = false;
  openPanel(groupId);
}

/** 卫星直接执行填充：读取已保存配置并派发事件，不打开面板、不提交。 */
async function runFixtureFillAction(): Promise<void> {
  if (fixtureFillBusy.value) return;
  fixtureFillBusy.value = true;
  satellitesVisible.value = false;
  cancelHoverTimer();
  try {
    const view = await getFixtureProfile();
    const profile = view.profile;
    if (!profile) {
      showError("尚未保存填充配置，请先在填充页签保存");
      return;
    }
    dispatchFill(profile);
    showStatus("已填充表单");
  } catch (error) {
    showError(error instanceof Error ? error.message : "填充失败");
  } finally {
    fixtureFillBusy.value = false;
  }
}

function infoValues(tool: DevTool): DevToolReadout {
  if (tool.kind !== "info") return {};
  void refreshTick.value;
  return tool.read();
}

function isWideReadout(value: string | number | boolean): boolean {
  return String(value).length > 26;
}

function toolTag(tool: DevTool): string {
  if (tool.tone === "danger") return "DANGER";
  return tool.kind === "action" ? "ACTION" : "INFO";
}

const ctx: DevToolContext = {
  notify: (message) => showStatus(message),
  error: (message) => showError(message),
  close: () => closePanel(),
};

async function execute(toolId: string, run: () => Promise<void> | void): Promise<void> {
  if (busyId.value) return;
  busyId.value = toolId;
  try {
    await run();
  } catch (error) {
    showError(error instanceof Error ? error.message : "开发工具执行失败");
  } finally {
    busyId.value = "";
  }
}

function runTool(tool: DevTool): void {
  if (tool.kind !== "action") return;
  void execute(tool.id, () => tool.run(ctx));
}

function runAction(tool: DevTool, action: DevToolAction): void {
  void execute(tool.id, () => action.run(ctx));
}

const {
  dragging,
  onPointerDown,
  onPointerMove,
  onPointerUp,
  onPointerCancel,
  onClick,
  stopSpring,
} = useOrbDrag({
  position,
  viewport,
  reducedMotion,
  onTap: togglePanel,
  onSettled: persistPosition,
});

function onOrbPointerDown(event: PointerEvent): void {
  cancelHoverTimer();
  satellitesVisible.value = false;
  onPointerDown(event);
}

watch([open, dragging], syncSatellites, { flush: "post" });

function syncViewport(): void {
  stopSpring();
  viewport.value = { width: window.innerWidth, height: window.innerHeight };
  const clamped = clampOrbPosition(position.value, viewport.value);
  if (clamped.x !== position.value.x || clamped.y !== position.value.y) {
    position.value = clamped;
    persistPosition(clamped);
  }
}

function onMotionChange(event: MediaQueryListEvent): void {
  reducedMotion.value = event.matches;
}

onMounted(() => {
  position.value =
    storedOrbPosition === null
      ? defaultOrbPosition(viewport.value)
      : clampOrbPosition(position.value, viewport.value);
  window.addEventListener("resize", syncViewport);
  motionQuery.addEventListener("change", onMotionChange);
});

onBeforeUnmount(() => {
  disarmPanelListeners();
  stopRefresh();
  cancelHoverTimer();
  window.removeEventListener("resize", syncViewport);
  motionQuery.removeEventListener("change", onMotionChange);
  stopSpring();
});
</script>
