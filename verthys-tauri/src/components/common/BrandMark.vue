<!--
  BrandMark.vue — VERTHYS 品牌字标总成（星轨刻线体 — 三级唯一样式载体）
  职责：以 SVG 矢量直出定制字标（字形/刻槽/雕刻数据全部来自
    composables/useBrandTitle.ts 唯一权威源），承载三级排印：
      level="intro"   引导页主标（cap 84 — 全量身份：刻槽 + 光门镂空）
      level="compact" 主界面左区（cap 40 — 同源形态，幅度收敛）
      level="mini"    安全弹窗顶部标识（cap 24 — 静默简化锁版：
                      刻槽/镂空收敛为实色，仅保留雕刻与强调锚点）
    默认 mini — 弹窗（安全存储初始化 / 身份验证 / 初始化安全密钥）零改调用。
  结构（每字三层）：
    .wm-glyph   逐字运动层（CSS 变量驱动组装/弹射 — 形态层无随机）
      └ 布局层  translate(x) — 字距为设计定值
        ├ .wm-recess 暗色克隆（双层雕刻 — 物理凹刻深度）
        └ .wm-face   面层（可被刻槽遮罩裁切 — 半深切痕）
  遮罩 id 经 useId 唯一化：引导页与主界面在渡越期同驻挂载树，
    同页多实例不得撞 id。
  纯展示组件：props.level 之外无状态、无监听、零运行时开销。
-->
<template>
  <svg
    class="brand-wordmark"
    :class="`brand-wordmark--${level}`"
    :viewBox="model.viewBox"
    role="img"
    aria-label="VERTHYS"
  >
    <defs>
      <mask
        v-for="g in maskedGlyphs"
        :key="g.key"
        :id="cutId(g.key)"
        maskUnits="userSpaceOnUse"
      >
        <!-- 全幅白底（含笔画与雕刻偏移余量）+ 黑刃口 = 刻槽 -->
        <rect x="-40" y="-40" width="180" height="220" fill="#fff" />
        <rect
          :x="g.notch.cx - model.notch.w / 2"
          :y="g.notch.cy - model.notch.h / 2"
          :width="model.notch.w"
          :height="model.notch.h"
          :transform="`rotate(${model.notch.angle} ${g.notch.cx} ${g.notch.cy})`"
          fill="#000"
        />
      </mask>
    </defs>

    <g
      v-for="g in model.glyphs"
      :key="g.key"
      class="wm-glyph"
      :class="`wm-glyph--${g.tone}`"
      :style="g.style"
    >
      <g :transform="`translate(${g.x} 0)`">
        <g class="wm-recess" aria-hidden="true">
          <path :d="g.d" />
        </g>
        <g class="wm-face" :mask="g.notch ? `url(#${cutId(g.key)})` : undefined">
          <path :d="g.d" />
        </g>
      </g>
    </g>
  </svg>
</template>

<script setup lang="ts">
import { computed, useId } from "vue";
import {
  useBrandTitle,
  type BrandGlyph,
  type BrandLevel,
  type BrandNotch,
} from "../../composables/useBrandTitle";

const props = withDefaults(defineProps<{ level?: BrandLevel }>(), { level: "mini" });

/* level 为挂载期定级（三级由调用点静态实例化 — 运行期不切换，模型零响应式开销） */
const model = useBrandTitle(props.level);

/* 遮罩 id 唯一化（useId 应用级递增 — 同页多实例/多挂载点互不撞 id） */
const uid = useId();
const cutId = (key: string) => `${uid}-cut-${key}`;

/* 仅携刻槽之字需要遮罩（其余字面层零遮罩 — 少一层合成开销） */
type NotchedGlyph = BrandGlyph & { notch: BrandNotch };
const maskedGlyphs = computed(() =>
  model.glyphs.filter((g): g is NotchedGlyph => g.notch !== null),
);
</script>