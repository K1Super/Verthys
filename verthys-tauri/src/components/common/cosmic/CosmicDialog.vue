<!--
  CosmicDialog.vue — 通用宇宙主题弹窗底板（光学切片 · 半透明体系）
  设计取向：以「折射体」定义弹窗，而非卡片；轮廓不靠描边，而靠光与折射自行收束。
    - 无框：不保留可见描边；上缘只留一段偏左的过光缝，下缘以内部压深
      收住体积，左右边缘由背衬折射与极弱内缘光定义 —— 线是「光渐隐」，
      不是「框」；
    - 非对称收角：左上 / 右下为近直角基准角，右上 / 左下为大弧过光角，
      拒绝四角等半径的卡片模板；
    - 半透明材质：薄雾基面 + 单实例小面积背衬折射 + 左上冷光 / 右下紫光 /
      斜掠镜面 / 底缘厚度四层叠加；无彩虹描边、无发光堆积、无内部星点；
    - 刻度：左缘离散刻度承载加工件语义，其中一根暖色基准刻度与深空
      背景的暖金同源；刻度只占上缘局部，不参与围框；
    - 入场：承载文字的底板只走不透明度，光的写入交给 1px 装饰层 ——
      避免文字层被合成器按非 1 比例重栅格化造成字形跳变。
  用法：<CosmicDialog width="420px">…</CosmicDialog>
-->
<template>
  <div class="cosmic-dialog" :style="{ width }">
    <!-- 上缘过光缝：偏左起笔、向右衰减，仅承担光的转折，不做整宽描边 -->
    <div class="cd-aperture" aria-hidden="true"></div>

    <!-- 左缘离散刻度：基准角一侧的机加工读数，缺席即失去仪器语义 -->
    <div class="cd-scale" aria-hidden="true">
      <span
        v-for="(w, i) in scaleTicks"
        :key="i"
        class="cd-scale-tick"
        :class="{ 'cd-scale-tick--datum': i === 2 }"
        :style="{ width: `${w}px`, '--tick-i': i }"
      ></span>
    </div>

    <div class="cd-content">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  width?: string;
}

withDefaults(defineProps<Props>(), {
  width: "400px",
});

/* 刻度长度序列：长短错落（非等距模板），第三根为暖色基准刻度 */
const scaleTicks = [8, 4, 11, 5, 9, 4, 7];
</script>

<style scoped>
/* ===== 折射体 =====
 * 以半透明薄雾承载内容：基面不压满，衬底结构透过折射仍可辨 ——
 * 通透是「看得见轮廓」，不是「糊成一片」。
 * 单实例弹窗的小面积背衬折射与常驻卡片矩阵不同量级；空闲治理的
 * minimal-motion 档位会统一移除折射，届时由基面与内缘光独立成立。 */
.cosmic-dialog {
  position: relative;
  z-index: 1;
  isolation: isolate;
  display: flex;
  flex-direction: column;
  max-width: 90vw;
  max-height: 86vh;
  overflow: hidden;
  padding: 26px 28px 24px;
  border: 0;
  /* 排印契约：弹窗内文字统一项目主字体，不依赖调用方祖先的字体继承 */
  font-family: var(--font);
  /* 对角收角：基准角近直角（刻度与过光缝自此处起笔），过光角大弧 */
  border-radius: 3px 20px 3px 20px;
  color: var(--text-primary);
  color-scheme: dark;
  accent-color: var(--accent);
  background:
    /* 斜掠镜面：光源偏左上的既定约定，只有玻璃体内的一次转折 */
    linear-gradient(
      118deg,
      rgba(205, 224, 244, 0.070),
      rgba(205, 224, 244, 0.016) 24%,
      transparent 42%
    ),
    /* 左上冷光沉积 */
    radial-gradient(
      120% 78% at 8% -6%,
      rgba(var(--accent-rgb), 0.075),
      transparent 56%
    ),
    /* 右下紫光反照（与冷光对位，撑开体积） */
    radial-gradient(
      100% 90% at 102% 108%,
      rgba(var(--accent-purple-rgb), 0.060),
      transparent 60%
    ),
    /* 底缘压深：玻璃厚度在下方聚拢，替代底部描边 */
    linear-gradient(to top, rgba(2, 4, 9, 0.26), transparent 22%),
    /* 薄雾基面 */
    linear-gradient(162deg, rgba(11, 15, 25, 0.52), rgba(5, 8, 14, 0.62));
  -webkit-backdrop-filter: blur(24px) saturate(160%) brightness(1.06);
  backdrop-filter: blur(24px) saturate(160%) brightness(1.06);
  box-shadow:
    /* 近影承担落地感；负扩散避免大范围压暗 */
    0 26px 64px -28px rgba(var(--black-rgb), 0.78),
    0 6px 20px -10px rgba(var(--black-rgb), 0.50),
    /* 内缘光：只写顶缘与两侧的一线反光，不围框 */
    inset 0 1px 0 rgba(236, 246, 255, 0.055),
    inset 1px 0 0 rgba(236, 246, 255, 0.018),
    inset -1px 0 0 rgba(var(--black-rgb), 0.14),
    inset 0 -1px 0 rgba(var(--black-rgb), 0.32);
}
/* 无背衬折射能力时加深基面补偿，保证文字可读 */
@supports not ((-webkit-backdrop-filter: blur(2px)) or (backdrop-filter: blur(2px))) {
  .cosmic-dialog {
    background:
      linear-gradient(118deg, rgba(205, 224, 244, 0.045), transparent 42%),
      linear-gradient(162deg, rgba(11, 15, 25, 0.94), rgba(5, 8, 14, 0.96));
  }
}

/* ===== 下缘反光缝 =====
 * 顶缘进光、底缘反光：两段光各守一侧且都不贯穿全宽，
 * 体积由此闭合，任何一边都不构成可读的「框」。 */
.cosmic-dialog::after {
  content: "";
  position: absolute;
  left: 26%;
  right: 12%;
  bottom: 0;
  height: 1px;
  background: linear-gradient(
    90deg,
    transparent,
    rgba(205, 224, 244, 0.10),
    transparent
  );
  pointer-events: none;
  z-index: 0;
}

/* ===== 上缘过光缝 =====
 * 一段光在顶缘的写入：起笔即亮、向右衰减，长度不足半宽 ——
 * 读作光学切面的进光口，而非整条顶边线。 */
.cd-aperture {
  position: absolute;
  top: 0;
  left: 32px;
  width: 52%;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(236, 246, 255, 0.46),
    rgba(var(--accent-rgb), 0.22) 48%,
    transparent
  );
  transform-origin: 0 50%;
  animation: cd-aperture-write 0.62s cubic-bezier(0.22, 1, 0.36, 1) 80ms both;
  pointer-events: none;
  z-index: 0;
}
@keyframes cd-aperture-write {
  from { opacity: 0; transform: scaleX(0.08); }
  to { opacity: 1; transform: scaleX(1); }
}

/* ===== 左缘刻度 =====
 * 长短错落、透明度递增衰减；暖色刻度是唯一基准读数。
 * 只占上缘局部，不延伸为分隔线，避免重新落回「画框」语法。 */
.cd-scale {
  position: absolute;
  top: 34px;
  left: 12px;
  display: flex;
  flex-direction: column;
  gap: 7px;
  width: 12px;
  pointer-events: none;
  z-index: 0;
}
.cd-scale-tick {
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(205, 224, 244, 0.44),
    rgba(205, 224, 244, 0.02)
  );
  transform-origin: 0 50%;
  animation: cd-tick-write 0.5s cubic-bezier(0.22, 1, 0.36, 1)
    calc(120ms + var(--tick-i, 0) * 55ms) both;
}
.cd-scale-tick--datum {
  background: linear-gradient(
    90deg,
    rgba(255, 217, 160, 0.58),
    rgba(255, 217, 160, 0.02)
  );
}
@keyframes cd-tick-write {
  from { opacity: 0; transform: scaleX(0.2); }
  to { opacity: 1; transform: scaleX(1); }
}

/* 内容层：文字与控件恒在装饰层之上，装饰永不覆盖可读信息。
 * 独立滚动：长表单不撑破视口；滚动只发生在内容区，上缘过光缝与
 * 左缘刻度保持在底板原位，不随内容滚走 */
.cd-content {
  position: relative;
  z-index: 1;
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-gutter: stable;
}

/* 内容词汇（kv-*）由全局 styles/components.css 单源定义：
 * 标题、字段、控件、选项与动作区不得在外壳内二次声明，
 * 否则同一视觉会出现两套规则来源 */

@media (prefers-reduced-motion: reduce) {
  .cd-aperture,
  .cd-scale-tick {
    animation: none;
  }
}
</style>
