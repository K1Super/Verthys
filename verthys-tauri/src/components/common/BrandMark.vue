<!--
  BrandMark.vue — VERTHYS 品牌字标总成（星弦衡列体 — 三级唯一样式载体）
  职责：以 SVG 矢量直出定制字标（字形/运动数据全部来自
    composables/useBrandTitle.ts 唯一权威源），承载三级排印：
      level="intro"   引导页主标（全量身份：光门发丝 V + 悬锤垂针 Y）
      level="compact" 主界面左区（同源形态，幅度收敛）
      level="mini"    安全弹窗顶部标识（静默简化版：光门收敛为实弦，
                      仅保留雕刻与强调锚点）
    默认 mini — 弹窗（安全存储初始化 / 身份验证 / 初始化安全密钥）零改调用。
  结构（每字双层，零遮罩零滤镜 — 最少合成开销）：
    .wm-glyph   逐字运动层（CSS 变量驱动升轨入列/离轨升离）
      └ 布局层  translate(x) — 字距为设计定值
        ├ .wm-recess 暗色克隆（双层雕刻 — 物理凹刻深度）
        └ .wm-face   面层（实弦/发丝按三态着色）
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
        <g class="wm-face">
          <path :d="g.d" />
        </g>
      </g>
    </g>
  </svg>
</template>

<script setup lang="ts">
import { useBrandTitle, type BrandLevel } from "../../composables/useBrandTitle";

const props = withDefaults(defineProps<{ level?: BrandLevel }>(), { level: "mini" });

/* level 为挂载期定级（三级由调用点静态实例化 — 运行期不切换，模型零响应式开销） */
const model = useBrandTitle(props.level);
</script>
