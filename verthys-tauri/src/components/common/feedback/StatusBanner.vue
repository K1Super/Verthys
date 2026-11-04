<!--
  StatusBanner.vue — 全局常驻状态横幅（唯一实现）

  职责边界（与 Toast 严格分工，两者不得互相替代）：
    - Toast  = 事件结果反馈：瞬时、自动消失、不可交互；
    - 横幅   = 状态告知：存续到状态消除、允许挂载处理动作。
  常驻状态若交给 Toast，会随计时消失而丢失关键告知；事件结果若做成横幅，
  会永久占据版面。两类信息由载体区分，用户无需再判断哪种提示会留下。

  布局（硬约束）：
    组件不自带定位，宽度随内容收敛（fit-content）。常驻使用必须由调用方
    挂进浮层（position: absolute）—— 横幅只覆盖自身所占区域，出现与消失
    都不得改变视图布局；任何把横幅放进文档流、挤压视图内容的用法都不属于
    本组件的支持范围。

  视觉（通透玻璃带）：
    基面取 tokens.css --banner-surface —— 填充压到近无色，通透感由更强的
    背衬折射（blur 26px + 高饱和）承担。瞬时 Toast 的 --toast-surface 更浓，
    用于只存续一两秒的小面积提示合适；同样的浓度放大到常驻横幅会退化为
    一块实心色板，因此两者共用材质语言但不共用浓度。
    无描边：轮廓仅由上下两道随圆角淡出的光缝与内缘顶光界定，不落外投影。
    语义色只落在文字与动作键上，整面保持中性玻璃；不设左缘图标、不设竖向
    隔线 —— 文字与动作由留白分区，任何装饰线都会把通透面重新切回「框」。
    动作是透明玻璃键：细描边 + 极低填充，悬浮只提亮边界与填充，
    无阴影、无渐变、无发光。

  入场：
    只走不透明度 —— 文字承载元素不做位移，位移会把文字层提升为合成层
    并改用灰度抗锯齿，收束时再切回子像素，淡入期间文字会发虚。
    用 transition 而非 animation —— 全局空闲治理以 animation-play-state
    暂停动画，animation 入场在深空闲态下会冻结在首帧（横幅直接不可见）。

  Props:
    - tone           语义色：info（默认）/ warning / danger / success
    - actionLabel    单动作文案；actions 非空时不生效
    - actionDisabled 单动作禁用（处理中）
    - actions        多动作入口（[{ key, label, disabled? }]，渲染顺序即数组顺序）
    - dismissible    关闭入口（仅用于用户可主动收敛的状态）
  Emits:
    - action         动作被点击，回传动作 key（单动作为 "primary"；禁用态不触发）
    - dismiss        关闭入口被点击
  Slots:
    - default        告知文案
    - actions        自定义动作区（优先于 actionLabel/actions；仅需自定义控件时使用）
-->
<template>
  <Transition name="sb-reveal" appear>
    <div
      class="status-banner"
      :class="`is-${tone}`"
      role="status"
    >
      <span class="sb-text"><slot /></span>

      <span v-if="hasActions" class="sb-tail">
        <span v-if="$slots.actions" class="sb-actions"><slot name="actions" /></span>
        <template v-else>
          <button
            v-for="item in actions"
            :key="item.key"
            type="button"
            class="sb-action"
            :disabled="item.disabled"
            @click="$emit('action', item.key)"
          >{{ item.label }}</button>
          <button
            v-if="actions.length === 0 && actionLabel"
            type="button"
            class="sb-action"
            :disabled="actionDisabled"
            @click="$emit('action', PRIMARY_ACTION_KEY)"
          >{{ actionLabel }}</button>
        </template>
        <button
          v-if="dismissible"
          type="button"
          class="sb-dismiss"
          aria-label="关闭提示"
          @click="$emit('dismiss')"
        >×</button>
      </span>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { computed, useSlots } from "vue";

export type BannerTone = "info" | "warning" | "danger" | "success";

/** 多动作条目：key 随 action 事件回传，调用方据此分派 */
export interface BannerAction {
  key: string;
  label: string;
  disabled?: boolean;
}

const props = withDefaults(
  defineProps<{
    /** 语义色（默认中性信息色） */
    tone?: BannerTone;
    /** 单动作文案；actions 非空时不生效 */
    actionLabel?: string;
    /** 单动作禁用（处理中或当前不可用） */
    actionDisabled?: boolean;
    /** 多动作入口（状态存在多个并行处置路径时使用，渲染顺序即数组顺序） */
    actions?: BannerAction[];
    /** 是否提供关闭入口（仅当状态可被用户主动收敛时开启） */
    dismissible?: boolean;
  }>(),
  {
    tone: "info",
    actionLabel: "",
    actionDisabled: false,
    actions: () => [],
    dismissible: false,
  },
);

defineEmits<{
  (e: "action", key: string): void;
  (e: "dismiss"): void;
}>();

/** 单动作入口的固定 key：调用方无需再区分单/多动作事件形态 */
const PRIMARY_ACTION_KEY = "primary";

/** 动作端是否渲染：任一动作来源存在即渲染（空动作区不占位） */
const slots = useSlots();
const hasActions = computed(
  () =>
    Boolean(slots.actions) ||
    Boolean(props.actionLabel) ||
    props.actions.length > 0 ||
    Boolean(props.dismissible),
);
</script>

<style scoped>
/* ===== 胎体：中性玻璃带（无描边）===== */
.status-banner {
  --sb-tone: var(--accent);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 16px;
  /* 内容自适应宽度：常驻告知只占文案与动作所需的篇幅，不铺满整行 */
  width: fit-content;
  max-width: 100%;
  /* 纵向留白压到 6px：高度由动作键（约 25px）与自身内距决定，约 37px */
  padding: 6px 13px 6px 15px;
  /* 浮层宿主可整体设为 pointer-events: none 让空白穿透，
     横幅实体在此重新获得指针事件，动作始终可点 */
  pointer-events: auto;
  border-radius: var(--radius);
  /* 文字取语义色与冷白的混合：保留语义辨识，又不让大面积常驻文字持续刺眼 */
  color: color-mix(in srgb, var(--sb-tone) 44%, #e6eef8);
  font-size: 13px;
  line-height: 1.5;
  letter-spacing: 0.2px;
  text-shadow: 0 1px 1px rgba(var(--black-rgb), 0.34);
  /* 通透度由背衬折射承担：模糊提到 26px、饱和度与亮度微提 ——
     填充近乎无色的玻璃仍能折射出衬底的结构与色温 */
  -webkit-backdrop-filter: blur(26px) saturate(185%) brightness(1.12);
  backdrop-filter: blur(26px) saturate(185%) brightness(1.12);
  background:
    /* 上缘主光缝 / 下缘副光缝：两端随圆角淡出，读作玻璃棱线而非画线成框 */
    linear-gradient(90deg, transparent, rgba(var(--white-rgb), 0.22) 10%, rgba(var(--white-rgb), 0.22) 90%, transparent) top / 100% 1px no-repeat,
    linear-gradient(90deg, transparent, rgba(var(--white-rgb), 0.07) 16%, rgba(var(--white-rgb), 0.07) 84%, transparent) bottom / 100% 1px no-repeat,
    /* 镜面转折反光：光源偏左上的斜掠高光，只在玻璃表面掠过，不参与底色 */
    linear-gradient(108deg, rgba(var(--white-rgb), 0.09), rgba(var(--white-rgb), 0.02) 34%, transparent 62%),
    /* 语义微晕：极低强度，仅让语义色在左端有一层空气感，不构成铺底 */
    radial-gradient(
      ellipse 120% 220% at 0% 50%,
      color-mix(in srgb, var(--sb-tone) 5%, transparent),
      transparent 62%
    ),
    /* 玻璃基面（单源 tokens.css --banner-surface，填充近无） */
    var(--banner-surface);
  /* 通透体只保留内缘顶光；不落外投影，避免被读成一块悬浮的实心板 */
  box-shadow: inset 0 1px 0 rgba(var(--white-rgb), 0.07);
}

/* 语义变体：只改 --sb-tone 单源，文字与动作键随之同色 */
.status-banner.is-warning { --sb-tone: rgb(var(--warning-rgb)); }
.status-banner.is-danger { --sb-tone: var(--danger); }
.status-banner.is-success { --sb-tone: rgb(var(--success-rgb)); }

/* ===== 文案 ===== */
/* flex-basis 取 auto：短文案不被固定基准撑长，横幅宽度严格随内容收敛 */
.sb-text {
  flex: 1 1 auto;
  min-width: 0;
}

/* ===== 动作端 ===== */
.sb-tail {
  flex: none;
  display: flex;
  align-items: center;
  gap: 8px;
  margin-left: auto;
}
.sb-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

/* 动作本体：透明玻璃键 —— 细描边 + 极低填充，悬浮只提亮边界与填充，
   无阴影、无渐变、无发光；按钮靠「边界与填充的透光差」表达可点性 */
.sb-action {
  flex: none;
  /* 纵向内距 3px：动作键总高约 25px，是横幅高度的上限来源 */
  padding: 3px 11px 3px;
  border: 1px solid color-mix(in srgb, var(--sb-tone) 20%, transparent);
  border-radius: var(--radius-sm);
  background-color: color-mix(in srgb, var(--sb-tone) 4%, transparent);
  color: color-mix(in srgb, var(--sb-tone) 58%, #e9f3fb);
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
.sb-action:hover:not(:disabled) {
  border-color: color-mix(in srgb, var(--sb-tone) 46%, transparent);
  background-color: color-mix(in srgb, var(--sb-tone) 9%, transparent);
  color: color-mix(in srgb, var(--sb-tone) 76%, #ffffff);
}
.sb-action:active:not(:disabled) {
  background-color: color-mix(in srgb, var(--sb-tone) 13%, transparent);
}
.sb-action:focus-visible {
  outline: 1px solid color-mix(in srgb, var(--sb-tone) 58%, transparent);
  outline-offset: 2px;
}
/* 禁用：边界退回极淡、填充清空，光标与配色同时收束 */
.sb-action:disabled {
  border-color: color-mix(in srgb, var(--sb-tone) 10%, transparent);
  background-color: transparent;
  color: color-mix(in srgb, var(--sb-tone) 26%, #808a9c);
  cursor: not-allowed;
}

/* 关闭入口：裸字形，不占动作键的视觉权重（关闭不是主处置路径） */
.sb-dismiss {
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  padding: 0;
  border: 0;
  background: none;
  color: var(--text-muted);
  font-family: var(--font);
  font-size: 14px;
  line-height: 1;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.sb-dismiss:hover {
  color: var(--text-primary);
}
.sb-dismiss:focus-visible {
  outline: 1px solid color-mix(in srgb, var(--sb-tone) 55%, transparent);
  outline-offset: 2px;
  border-radius: 2px;
}

/* ===== 入场：只走不透明度 =====
   文字承载元素不做位移入场：位移会把文字层提升为合成层并改用灰度抗锯齿，
   收束时再切回子像素 —— 肉眼读作「淡入期间文字发虚」。
   用 transition 而非 animation：全局空闲治理以 animation-play-state
   暂停动画，animation 入场在深空闲态下会冻结在首帧（横幅直接不可见）。 */
.sb-reveal-enter-active {
  transition: opacity 0.36s var(--ease);
}
.sb-reveal-enter-from {
  opacity: 0;
}

@media (prefers-reduced-motion: reduce) {
  .sb-reveal-enter-active {
    transition: none;
  }
}
</style>
