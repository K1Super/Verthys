<!--
  BrandMark.vue — VERTHYS 品牌字标总成（星晶棱镜体 — 三级唯一样式载体）
  职责：以 SVG 矢量直出定制字标（字形/材质/运动数据全部来自
    composables/useBrandTitle.ts 唯一权威源），承载三级排印：
      level="intro"   引导页主标（全量身份：棱镜口 V + 悬锤垂针 Y +
                      能量芯 H）
      level="compact" 主界面左区（同源形态，材质与幅度收敛）
      level="mini"    安全弹窗顶部标识（棱镜口收敛为玻璃体 — 极淡轮廓
                      在 30px 高度下低于可辨阈值）
    默认 mini — 弹窗（安全存储初始化 / 身份验证 / 初始化安全密钥）零改调用。

  材质装配（每字四层，全部静态 —— 无遮罩、无滤镜、无运行时渐变计算）：
    布局层 translate(x)
      ├ .wm-refract   折射影：右下方位移的暗像（光穿过晶体后的落点，
      │               以偏移替代表模糊，规避实时滤镜的逐帧重算）
      ├ .wm-glass     玻璃体：半透明光楔描边（深空背景透过笔画可见）
      ├ .wm-edge-far  远侧棱光：右下侧较弱的反光（透过晶体的光打亮远壁）
      └ .wm-edge      近侧棱光：左上侧最强的镜面反光（受光面）
    近/远双侧棱光 + 中间半透明体 + 体后暗像 = 玻璃棒截面，
    而非单侧高光的塑料浮雕。

  光楔（三支 linearGradient）逐实例内联注入并配唯一 id：玻璃体与棱边光
  共用同一斜向光楔（全域 userSpaceOnUse）—— 全字受同一束光，各字因
  相位不同而自然异相。id 经 useId 唯一化：引导页与主界面在渡越期同驻
  挂载树，同页多实例不得撞 id。

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
      <!-- 玻璃体光楔：左上受光（亮）→ 中段透深（让背景穿透）→ 右端回亮 -->
      <linearGradient
        :id="gradId('glass')"
        gradientUnits="userSpaceOnUse"
        x1="-14"
        y1="-4"
        x2="604"
        y2="121"
      >
        <stop offset="0" stop-color="#e9f6ff" stop-opacity="0.9" />
        <stop offset="0.3" stop-color="#b2d2ec" stop-opacity="0.68" />
        <stop offset="0.58" stop-color="#7eaace" stop-opacity="0.46" />
        <stop offset="0.82" stop-color="#a0c8e8" stop-opacity="0.58" />
        <stop offset="1" stop-color="#e2f2ff" stop-opacity="0.86" />
      </linearGradient>

      <!-- 棱边光楔：多段明暗交替 = 序列棱面各自受光（同一束光的不同入射角）。
           峰值高于玻璃体，使近侧棱光在暗背景上明确亮于体 -->
      <linearGradient
        :id="gradId('edge')"
        gradientUnits="userSpaceOnUse"
        x1="-14"
        y1="-4"
        x2="604"
        y2="121"
      >
        <stop offset="0" stop-color="#ffffff" stop-opacity="0.78" />
        <stop offset="0.22" stop-color="#ffffff" stop-opacity="0.2" />
        <stop offset="0.46" stop-color="#ffffff" stop-opacity="0.66" />
        <stop offset="0.7" stop-color="#ffffff" stop-opacity="0.16" />
        <stop offset="1" stop-color="#ffffff" stop-opacity="0.58" />
      </linearGradient>

      <!-- 能量芯光楔（仅 H）：竖向渐变，中段最亮 = 晶体内部能量芯 -->
      <linearGradient
        :id="gradId('core')"
        gradientUnits="userSpaceOnUse"
        x1="346"
        y1="0"
        x2="346"
        y2="100"
      >
        <stop offset="0" stop-color="#16c8ea" stop-opacity="0.12" />
        <stop offset="0.45" stop-color="#2ad8f8" stop-opacity="0.85" />
        <stop offset="1" stop-color="#16c8ea" stop-opacity="0.12" />
      </linearGradient>
    </defs>

    <g
      v-for="g in model.glyphs"
      :key="g.key"
      class="wm-glyph"
      :class="`wm-glyph--${g.tone}`"
      :style="g.style"
    >
      <g :transform="`translate(${g.x} 0)`">
        <g v-if="g.refract" class="wm-refract" aria-hidden="true">
          <path :d="g.d" />
        </g>
        <path class="wm-glass" :d="g.d" :stroke="gradUrl(g.grad)" />
        <path class="wm-edge-far" :d="g.d" :stroke="gradUrl('edge')" />
        <path class="wm-edge" :d="g.d" :stroke="gradUrl('edge')" />
      </g>
    </g>
  </svg>
</template>

<script setup lang="ts">
import { useId } from "vue";
import { useBrandTitle, type BrandLevel } from "../../composables/useBrandTitle";

const props = withDefaults(defineProps<{ level?: BrandLevel }>(), { level: "mini" });

/* level 为挂载期定级（三级由调用点静态实例化 — 运行期不切换，模型零响应式开销） */
const model = useBrandTitle(props.level);

/* 光楔 id 唯一化（useId 应用级递增 — 同页多实例/多挂载点互不撞 id） */
const uid = useId();
const gradId = (key: string) => `${uid}-${key}`;
const gradUrl = (key: string) => `url(#${uid}-${key})`;
</script>
