<!--
  StarlitSky.vue — 星野装饰层（无框半透明导航带专用）
  职责：为承载方（.starlit-bar）铺一层「三缘溶解」的星野底板 ——
    - 底板：冷调半透明纵向渐变，下缘自然消失（不设边框 / 圆角 / 投影；
      值单源 tokens.css --bar-surface，与模块卡片背景同源）
    - 星云：两块极淡径向（青 / 紫），非对称多相位漂移
    - 星点：确定性散布 + 复合谐波闪烁（去网格感、无辉光）
    - 遮罩：左右渐隐 —— 边界消隐于渐变即「无框」的关键
  用法：置于导航带内首位；纯装饰，aria-hidden，不接收指针事件。
  性能：动效仅走 opacity/transform（合成器属性）；遮罩与渐变静态一次
        栅格化；氛围动画由空闲治理统一暂停，无需登记豁免。
-->
<template>
  <div class="starlit-sky" aria-hidden="true">
    <div class="sky-nebula sky-nebula-a"></div>
    <div class="sky-nebula sky-nebula-b"></div>
    <span v-for="s in stars" :key="s.id" class="sky-star" :style="s.style"></span>
  </div>
</template>

<script setup lang="ts">
interface Props {
  /** 星点数量 */
  count?: number;
  /** 星座相位种子：同一公式按模块错开分布，各处导航带的星空互不相同 */
  seed?: number;
}

const props = withDefaults(defineProps<Props>(), { count: 14, seed: 0 });

/* 色板与项目深空冷调同源（白 / 银青 / 淡紫） */
const starColors = ["#ffffff", "#c8e6f5", "#c9bdf2"];

/* 构建期一次求值：模混合确定性散布（避免网格感与聚集），
 * 周期 2.4-5.1s、相位错开 —— 多带同屏不会整齐划一地闪 */
const stars = Array.from({ length: props.count }, (_, i) => {
  const j = i + 1;
  const size = 0.8 + ((j * 13 + props.seed) % 7) / 8;
  return {
    id: i,
    style: {
      left: `${(j * 41.3 + props.seed * 17.9 + ((j * j * 13) % 71)) % 100}%`,
      top: `${14 + ((j * 29.7 + props.seed * 11.3 + ((j * j * 7) % 61)) % 72)}%`,
      width: `${size.toFixed(2)}px`,
      height: `${size.toFixed(2)}px`,
      background: starColors[(i + props.seed) % starColors.length],
      animationDelay: `${((j * 0.97 + props.seed * 0.43) % 4).toFixed(2)}s`,
      animationDuration: `${(2.4 + ((j * 19 + props.seed * 3) % 30) / 11).toFixed(2)}s`,
    } as Record<string, string>,
  };
});
</script>

<style scoped>
/* 星野底板：冷调半透明纵向渐变 —— 越往下越淡，与内容区自然接续 */
.starlit-sky {
  position: absolute; inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 0;
  /* 底板值单源：tokens.css --bar-surface（模块卡片背景同源复用） */
  background: var(--bar-surface);
  /* 左右渐隐：能感知到的边界是渐变而非线条 —— 无框的关键；
     遮罩静态定值，单次栅格化，不随内容变化重绘 */
  -webkit-mask-image: linear-gradient(90deg, transparent, #000 7%, #000 93%, transparent);
  mask-image: linear-gradient(90deg, transparent, #000 7%, #000 93%, transparent);
}

/* 星云：径向渐变自身柔化（无实时滤镜），非对称多相位漂移 */
.sky-nebula {
  position: absolute;
  border-radius: 50%;
  mix-blend-mode: screen;
  pointer-events: none;
  will-change: transform, opacity;
}
.sky-nebula-a {
  width: 320px; height: 150px;
  left: 4%; top: -46%;
  background: radial-gradient(closest-side, rgba(var(--accent-purple-rgb), 0.13), transparent 100%);
  animation: sky-drift-a 23s ease-in-out infinite;
}
.sky-nebula-b {
  width: 260px; height: 130px;
  right: 5%; bottom: -52%;
  background: radial-gradient(closest-side, rgba(var(--accent-rgb), 0.11), transparent 100%);
  animation: sky-drift-b 31s ease-in-out infinite;
}
@keyframes sky-drift-a {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.5; }
  36% { transform: translate(14px, 4px) scale(1.1); opacity: 0.78; }
  67% { transform: translate(20px, 6px) scale(1.14); opacity: 0.62; }
}
@keyframes sky-drift-b {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.44; }
  41% { transform: translate(-12px, -3px) scale(1.12); opacity: 0.7; }
  73% { transform: translate(-16px, -5px) scale(1.16); opacity: 0.55; }
}

/* 星点：复合谐波闪烁（多相位非等距），纯暗点无辉光 shadow */
.sky-star {
  position: absolute;
  border-radius: 50%;
  animation: sky-twinkle 3.6s ease-in-out infinite;
}
@keyframes sky-twinkle {
  0%, 100% { opacity: 0.08; transform: scale(0.7); }
  22% { opacity: 0.42; }
  47% { opacity: 0.78; transform: scale(1.25); }
  66% { opacity: 0.3; transform: scale(0.92); }
  84% { opacity: 0.55; transform: scale(1.12); }
}

/* 无障碍：偏好减少动态 → 星野静态呈现（星点落在自身基础态，不消失） */
@media (prefers-reduced-motion: reduce) {
  .sky-nebula,
  .sky-star { animation: none; }
}
</style>