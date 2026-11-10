<!--
  StatusRail.vue — 常驻状态轨（右侧收敛入口 + 告知面板）

  职责边界（与 ToastLayer 严格分工）：
    - ToastLayer 承载瞬时事件结果：自动消失、不可交互；
    - 本组件承载存续到状态消除的常驻告知：轨内只留一枚语义图标，
      点击后在轨左侧展开告知面板与处置动作。
    常驻告知留在文档流内会挤压视图，浮在内容上又会随滚动容器漂移；
    收敛到视口右缘的独立轨后，两种问题同时消失。

  布局（硬约束）：
    轨道固定于视口右缘（top 40px 对齐工作区上缘，bottom 16px），
    不参与任何滚动容器布局；面板向左展开，避开视口右缘的滚动条通道。
    中枢容器在轨存在时预留右侧内距（.security-center.has-notice-rail），
    分区内容不会滑入轨道覆盖范围。
    轨道挂载于中枢管理视图：恢复会话状态在全局存续，进入中枢即恢复
    处置入口；离开中枢不保留跨模块浮层。

  视觉：
    轨内图标沿用中枢机械刻度键（sf-act）的皮肤；恢复会话必经中枢解锁，
    该样式表在轨出现前已加载。胶囊底板只保留 hairline 边框与上下刻度端线，
    无投影、无发光。
    告知面板直接复用 Toast 的玻璃基面（.notice-card 与 .clip-toast /
    .error-toast 共用同一材质单源），但不含极光立标 ——
    常驻告知靠文字承载语义，不需要装饰标记。

  交互：
    同一时刻只展开一个面板；再次点击关闭，点击轨外或 Escape 关闭。
    面板揭示只走不透明度：文字承载层不做位移入场。

  Props:
    - notices   常驻告知列表（key 稳定标识 / tone 语义色 / icon 图标语义 /
                tip 悬浮提示 / text 正文 / actionLabel 动作文案）
    - label     轨的无障碍分组名称
  Emits:
    - action    面板动作被点击，回传对应告知 key
-->
<template>
  <Transition name="sr-rail">
    <div
      v-if="notices.length > 0"
      class="status-rail"
      role="group"
      :aria-label="label"
    >
      <div class="sr-stack">
        <div v-for="notice in notices" :key="notice.key" class="sr-item">
          <button
            :id="triggerId(notice.key)"
            type="button"
            class="sf-act is-latched sr-trigger"
            :class="[actionToneClass(notice.tone), { 'is-open': openKey === notice.key }]"
            :aria-label="notice.text"
            :aria-expanded="openKey === notice.key"
            :aria-controls="panelId(notice.key)"
            v-tip="openKey === notice.key ? '' : (notice.tip ?? notice.text)"
            @click="toggle(notice.key)"
          >
            <svg
              v-if="notice.icon === 'device'"
              aria-hidden="true"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
            >
              <rect x="3.5" y="4.5" width="17" height="12" rx="2" />
              <path d="M8 20h8M12 16.5V20" />
              <circle cx="12" cy="10.5" r="1.8" />
            </svg>
            <svg
              v-else-if="notice.icon === 'rotate'"
              aria-hidden="true"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
            >
              <path d="M20 12a8 8 0 1 1-2.34-5.66" />
              <path d="M20 4v4h-4" />
              <circle cx="12" cy="12" r="2.2" />
            </svg>
            <svg
              v-else
              aria-hidden="true"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
            >
              <circle cx="12" cy="12" r="8.5" />
              <path d="M12 11v5.5" />
              <circle cx="12" cy="7.6" r="0.9" fill="currentColor" stroke="none" />
            </svg>
          </button>

          <Transition name="sr-panel">
            <div
              v-if="openKey === notice.key"
              :id="panelId(notice.key)"
              class="sr-panel notice-card"
              :class="panelToneClass(notice.tone)"
              role="region"
              :aria-labelledby="triggerId(notice.key)"
            >
              <p class="sr-text">{{ notice.text }}</p>
              <button
                type="button"
                class="sr-action"
                @click="triggerAction(notice.key)"
              >{{ notice.actionLabel }}</button>
            </div>
          </Transition>
        </div>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

export type StatusRailTone = "info" | "warning" | "danger" | "success";
export type StatusRailIcon = "device" | "rotate" | "info";

/** 常驻告知条目：一条状态对应一个稳定 key、一个动作入口 */
export interface StatusRailNotice {
  /** 稳定标识：面板开合与动作回传以此定位，跨渲染保持不变 */
  key: string;
  /** 语义色；只作用于图标、面板光晕与动作键，不铺底 */
  tone?: StatusRailTone;
  /** 图标语义；缺省为通用信息环 */
  icon?: StatusRailIcon;
  /** 悬浮提示；缺省复用正文（面板展开时不再弹提示，避免遮挡面板） */
  tip?: string;
  /** 告知正文 */
  text: string;
  /** 面板内唯一处置动作的文案 */
  actionLabel: string;
}

const props = withDefaults(
  defineProps<{
    /** 常驻告知列表（渲染顺序即轨内顺序） */
    notices: StatusRailNotice[];
    /** 轨的无障碍分组名称 */
    label?: string;
  }>(),
  { label: "常驻状态提醒" },
);

const emit = defineEmits<{
  (e: "action", key: string): void;
}>();

/** 当前展开的告知 key：同一时刻只保留一个面板，避免多条告知叠层 */
const openKey = ref<string | null>(null);

/** 触发器与面板 id：aria-controls / aria-labelledby 的稳定关联 */
const triggerId = (key: string) => `sr-trigger-${key}`;
const panelId = (key: string) => `sr-panel-${key}`;

/** 轨内图标色调复用机械刻度键的语义色（info 取青色档） */
const actionToneClass = (tone: StatusRailTone = "info"): string => {
  if (tone === "warning") return "sf-act--warn";
  if (tone === "danger") return "sf-act--danger";
  if (tone === "success") return "sf-act--success";
  return "sf-act--update";
};

/** 面板语义色只注入 --mark-c：玻璃基面的光晕与文字同源 */
const panelToneClass = (tone: StatusRailTone = "info"): string => `is-${tone}`;

const toggle = (key: string): void => {
  openKey.value = openKey.value === key ? null : key;
};

const close = (): void => {
  openKey.value = null;
};

const triggerAction = (key: string): void => {
  close();
  emit("action", key);
};

/* 告知集合变化时收敛失效面板：状态消除后不得残留上一轮的展开态 */
watch(
  () => props.notices.map((notice) => notice.key).join("\u0000"),
  () => {
    if (openKey.value && !props.notices.some((notice) => notice.key === openKey.value)) {
      openKey.value = null;
    }
  },
);

/* 轨外面板关闭：pointerdown 捕获阶段先于业务点击，
   面板收起不会吞掉用户本次真实点击 */
const onDocumentPointerDown = (event: Event): void => {
  if (!openKey.value) return;
  const target = event.target;
  if (target instanceof Element && target.closest(".status-rail")) return;
  close();
};

const onDocumentKeydown = (event: KeyboardEvent): void => {
  if (event.key === "Escape") close();
};

onMounted(() => {
  document.addEventListener("pointerdown", onDocumentPointerDown, true);
  document.addEventListener("keydown", onDocumentKeydown);
});
onBeforeUnmount(() => {
  document.removeEventListener("pointerdown", onDocumentPointerDown, true);
  document.removeEventListener("keydown", onDocumentKeydown);
});
</script>

<style scoped>
/* ===== 轨宿主：视口右缘固定，纵向与左侧 Dock 共用同一中轴 =====
   top / bottom 均取 40px：两端等距时宿主中轴恒为视口 H/2，
   与左侧 Dock（top: 50%）同高，不随工作区上下留白差异偏移。
   宿主不拦截指针，只有胶囊实体内可交互。 */
.status-rail {
  position: fixed;
  top: 40px;
  right: 22px;
  bottom: 40px;
  z-index: 50;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  pointer-events: none;
}

/* 胶囊底板：hairline 边框 + 上下刻度端线，无投影、无发光 */
.sr-stack {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 10px 6px;
  pointer-events: auto;
  border-radius: var(--radius);
  border: 1px solid rgba(var(--white-rgb), 0.07);
  background:
    linear-gradient(180deg, rgba(var(--accent-rgb), 0.05), transparent 24%),
    linear-gradient(180deg, rgba(16, 19, 30, 0.78), rgba(8, 10, 17, 0.86));
}
/* 刻度端线：加工件量规的起止刻线（纯装饰层，不承载文字） */
.sr-stack::before,
.sr-stack::after {
  content: "";
  position: absolute;
  left: 50%;
  width: 10px;
  height: 1px;
  margin-left: -5px;
  background: rgba(var(--white-rgb), 0.14);
  pointer-events: none;
}
.sr-stack::before { top: 3px; }
.sr-stack::after { bottom: 3px; }

/* 条目：面板相对条目定位，保证面板与触发图标垂直对齐 */
.sr-item {
  position: relative;
  display: flex;
}

/* 展开态：圆形键内极低填充表达「当前面板对应此项」，不引入投影 */
.sr-trigger.is-open {
  background: color-mix(in srgb, currentColor 9%, transparent);
}

/* ===== 告知面板：材质由 components.css 的 .notice-card 单源提供 =====
   本处只负责定位、排印与动作键；面板向左展开，避开右侧滚动条通道。
   纵向居中用静态 translate：面板不做位移动画，文字层不进入逐帧合成。 */
.sr-panel {
  --mark-c: var(--accent);
  position: absolute;
  top: 50%;
  /* 100% = 触发器宽度；额外 18px 中扣除胶囊 6px 内距后，
     面板与胶囊外缘保持 12px 呼吸间隙 */
  right: calc(100% + 18px);
  transform: translateY(-50%);
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
  width: 344px;
  max-width: calc(100vw - 150px);
  padding: 12px 14px 13px;
  color: color-mix(in srgb, var(--mark-c) 40%, #e6eef8);
  font-size: 13px;
  line-height: 1.7;
  letter-spacing: 0.2px;
  text-shadow: 0 1px 1px rgba(var(--black-rgb), 0.34);
}
.sr-panel.is-warning { --mark-c: rgb(var(--warning-rgb)); }
.sr-panel.is-danger { --mark-c: var(--danger); }
.sr-panel.is-success { --mark-c: rgb(var(--success-rgb)); }

.sr-text {
  margin: 0;
  overflow-wrap: anywhere;
}

/* 动作键：透明玻璃键 —— 细描边 + 极低填充，悬浮只提亮边界与填充 */
.sr-action {
  align-self: flex-end;
  flex: none;
  padding: 3px 11px;
  border: 1px solid color-mix(in srgb, var(--mark-c) 22%, transparent);
  border-radius: var(--radius-sm);
  background-color: color-mix(in srgb, var(--mark-c) 4%, transparent);
  color: color-mix(in srgb, var(--mark-c) 58%, #e9f3fb);
  font-family: var(--font);
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.4px;
  line-height: 1.4;
  cursor: pointer;
  transition:
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}
.sr-action:hover {
  border-color: color-mix(in srgb, var(--mark-c) 46%, transparent);
  background-color: color-mix(in srgb, var(--mark-c) 9%, transparent);
  color: color-mix(in srgb, var(--mark-c) 76%, #ffffff);
}
.sr-action:active {
  background-color: color-mix(in srgb, var(--mark-c) 13%, transparent);
}
.sr-action:focus-visible {
  outline: 1px solid color-mix(in srgb, var(--mark-c) 58%, transparent);
  outline-offset: 2px;
}

/* 揭示只走不透明度：面板承载告知文字，位移入场会让字形改用灰度抗锯齿。
   逐条声明而非合并选择器：文字清晰度守卫按单条规则登记与校验。 */
.sr-panel-enter-active {
  transition: opacity 0.26s var(--ease);
}
.sr-panel-leave-active {
  transition: opacity 0.26s var(--ease);
  pointer-events: none;
}
.sr-panel-enter-from {
  opacity: 0;
}
.sr-panel-leave-to {
  opacity: 0;
}
.sr-rail-enter-active {
  transition: opacity 0.3s var(--ease);
}
.sr-rail-leave-active {
  transition: opacity 0.3s var(--ease);
  pointer-events: none;
}
/* 胶囊自体声明了 pointer-events: auto，离场期必须显式收回 ——
   否则轨道正在淡出仍可被点击并触发已消解状态的动作 */
.sr-rail-leave-active .sr-stack {
  pointer-events: none;
}
.sr-rail-enter-from {
  opacity: 0;
}
.sr-rail-leave-to {
  opacity: 0;
}

@media (prefers-reduced-motion: reduce) {
  .sr-panel-enter-active,
  .sr-panel-leave-active,
  .sr-rail-enter-active,
  .sr-rail-leave-active {
    transition: none;
  }
}
</style>
