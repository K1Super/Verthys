<!--
  CosmicDialog.vue — 通用宇宙主题弹窗底板（深空静场 v2）
  ★ 反大众化重构（根除廉价网感特效，回归安静的顶级质感）：
    - 根除：四色彩虹渐变描边流动（全息棱镜=廉价网感）、conic 旋转极光、
      顶部扫描线（AI/赛博模板重灾区）、box-shadow 呼吸脉动（repaint +
      辉光泛滥）
    - 底板：深空冷调三阶渐变（青/紫角隅微光 — 色板与品牌谱线同源），
      静态阴影一次定值（零重绘）
    - 描边：静态发丝线（1px 银灰低透）+ 顶缘静态微亮收边 — 精密仪器级
      收笔，无流动动画
    - 星云：2 块极淡径向（去 filter:blur 实时滤镜 — 渐变自身已柔化），
      非对称多相位漂移
    - 星点：10 颗确定性散布 + 复合谐波闪烁（去辉光 shadow）
    - 入场：一次性升起（opacity + translateY + scale 复合，自定义缓动）—
      与 CosmicBackdrop fade 编排衔接
  用法：<CosmicDialog width="420px">...</CosmicDialog>
-->
<template>
  <div class="cosmic-dialog" :style="{ width }">
    <!-- 极淡星云（径向渐变自柔化 — 零实时滤镜） -->
    <div class="cd-nebula cd-nebula-a"></div>
    <div class="cd-nebula cd-nebula-b"></div>
    <!-- 微缩星点 -->
    <div class="cd-ministars">
      <span v-for="s in dialogStars" :key="s.id" class="cd-ministar" :style="s.style"></span>
    </div>
    <!-- 顶缘静态收边（发丝亮线 — 精密收笔，无扫描动画） -->
    <div class="cd-top-edge"></div>
    <slot />
  </div>
</template>

<script setup lang="ts">
interface Props {
  width?: string;
}

withDefaults(defineProps<Props>(), {
  width: "400px",
});

/* ============================================================================
 * 弹窗内微缩星点 — 构建期一次求值（确定性散布去网格感）。
 * 色板：白/银青/淡紫（深空冷调）；谐波闪烁周期 2.4-5.4s 差化散相。
 */
const dialogStarColors = ["#ffffff", "#c8e6f5", "#c9bdf2"];
const dialogStars = Array.from({ length: 10 }, (_, i) => ({
  id: i,
  style: {
    left: `${(i * 41.3 + (i * i * 17.9) % 79) % 100}%`,
    top: `${(i * 29.7 + (i * i * 37.1) % 71) % 100}%`,
    width: `${(0.8 + ((i * 13) % 7) / 6).toFixed(2)}px`,
    height: `${(0.8 + ((i * 13) % 7) / 6).toFixed(2)}px`,
    background: dialogStarColors[i % dialogStarColors.length],
    animationDelay: `${((i * 0.97) % 4).toFixed(2)}s`,
    animationDuration: `${(2.4 + ((i * 19) % 30) / 11).toFixed(2)}s`,
  } as Record<string, string>,
}));
</script>

<style scoped>
/* ===== 深空静场弹窗容器 =====
 * 静态阴影一次定值（无 box-shadow 动画 → 零逐帧重绘）；
 * 入场一次性升起（自定义复合缓动 cubic-bezier(0.22, 1, 0.36, 1)） */
.cosmic-dialog {
  position: relative;
  z-index: 1;
  max-width: 90vw;
  overflow: hidden;
  padding: 18px 20px;
  border-radius: var(--radius);
  /* 深空冷调底板：主渐变 + 青/紫角隅微光（色板与品牌谱线同源 —
   * 去粉/薄荷偏离色） */
  background:
    linear-gradient(168deg, rgba(16, 19, 30, 0.97), rgba(9, 11, 18, 0.98)),
    radial-gradient(ellipse at 18% 8%, rgba(0, 212, 255, 0.05), transparent 42%),
    radial-gradient(ellipse at 86% 92%, rgba(139, 92, 246, 0.05), transparent 42%);
  /* 静态发丝描边（替代彩虹渐变流动描边） */
  border: 1px solid rgba(205, 224, 244, 0.12);
  box-shadow:
    0 32px 80px rgba(0, 0, 0, 0.7),
    inset 0 1px 0 rgba(255, 255, 255, 0.07);
  animation: cd-rise 0.6s cubic-bezier(0.22, 1, 0.36, 1) backwards;
  will-change: transform, opacity;
}
@keyframes cd-rise {
  from {
    opacity: 0;
    transform: translateY(14px) scale(0.965);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

/* 顶缘静态收边：1px 发丝亮线（中段亮两端隐 — 精密收笔，
 * 无任何流动/扫描动画） */
.cd-top-edge {
  position: absolute;
  top: 0;
  left: 12%;
  right: 12%;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(205, 224, 244, 0.22), transparent);
  pointer-events: none;
  z-index: 0;
}

/* 极淡星云 — 径向渐变自柔化（去 filter:blur — 渐变 to transparent 已软，
 * 且消除大模糊半径的运行时光栅化成本）；非对称多相位漂移 */
.cd-nebula {
  position: absolute;
  border-radius: 50%;
  mix-blend-mode: screen;
  pointer-events: none;
  will-change: transform, opacity;
  z-index: 0;
}
.cd-nebula-a {
  width: 210px; height: 210px;
  top: 4%; left: 6%;
  background: radial-gradient(circle, rgba(139, 92, 246, 0.10) 0%, transparent 62%);
  animation: cd-neb-drift-a 23s ease-in-out infinite;
}
.cd-nebula-b {
  width: 180px; height: 180px;
  bottom: 6%; right: 5%;
  background: radial-gradient(circle, rgba(0, 212, 255, 0.08) 0%, transparent 62%);
  animation: cd-neb-drift-b 31s ease-in-out infinite;
}
@keyframes cd-neb-drift-a {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.5; }
  36% { transform: translate(11px, 7px) scale(1.1); opacity: 0.78; }
  67% { transform: translate(15px, 9px) scale(1.12); opacity: 0.62; }
}
@keyframes cd-neb-drift-b {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.44; }
  41% { transform: translate(-9px, -7px) scale(1.12); opacity: 0.7; }
  73% { transform: translate(-12px, -9px) scale(1.14); opacity: 0.56; }
}

/* 微缩星点 — 复合谐波闪烁（多相位非等距），纯暗点无辉光 shadow */
.cd-ministars {
  position: absolute; inset: 0;
  pointer-events: none; z-index: 0;
  overflow: hidden;
}
.cd-ministar {
  position: absolute;
  border-radius: 50%;
  animation: cd-star-twinkle 3.6s ease-in-out infinite;
}
@keyframes cd-star-twinkle {
  0%, 100% { opacity: 0.1; transform: scale(0.7); }
  22% { opacity: 0.45; }
  47% { opacity: 0.8; transform: scale(1.25); }
  66% { opacity: 0.35; transform: scale(0.95); }
  84% { opacity: 0.6; transform: scale(1.15); }
}
</style>
