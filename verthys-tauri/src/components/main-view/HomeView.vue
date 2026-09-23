<!--
  HomeView.vue — 主界面默认视图（深空巡天 · 引力星图）
  非对称构图（拒绝居中对称模板）：
    左 8%  — 品牌雕刻排印（useBrandTitle compact 级 — 与引导页同源
              hash 参数场，跨场景品牌形态一致）+ 谱线回声 + 静默引导
    右侧   — 引力星图 HomeAtlas（非同心轨道 + 奇点 + 差速航点）
    对角视觉张力：Dock → 品牌 → 星图 → 深空（阅读动线成势）
  视差策略：本层内容（品牌/星图）不参与指针视差 — 深度感全部
    由 CosmicBackground 三层星场视差承担；内容层恒定静止保证
    品牌文字始终物理像素对齐（零亚像素栅格化 → 恒定锐利）。
  入场编排：逐字轨道落位（错峰复合曲线）→ 谱线生长 → 副标淡升
    → 星图同步揭示（HomeAtlas 内部编排）— 一次性 backwards 零跳变。
-->
<template>
  <div class="home-view">
    <!-- 引力星图（右侧 — 静态锚定） -->
    <div class="atlas-pos">
      <HomeAtlas />
    </div>

    <!-- 品牌区（左侧 — 静态锚定） -->
    <div class="brand-pos">
      <h1 class="brand-title brand-title--compact">
        <span
          v-for="(cv, i) in chars"
          :key="i"
          class="brand-char"
          :class="cv.mode"
          :data-char="cv.ch"
          :style="{
            '--fs': cv.fs + 'px',
            '--dx': cv.dx + 'px',
            '--dy': cv.dy + 'px',
            '--by': cv.by + 'px',
            '--tr': cv.tr + 'deg',
            '--rot': cv.rot + 'deg',
            '--delay': cv.delay + 'ms',
            '--dur': cv.dur + 's',
          }"
        >{{ cv.ch }}</span>
      </h1>

      <!-- 谱线回声（引导页谱线组的静默变体 — 呼吸 + 微跳，相对品牌文字居中） -->
      <div class="hub-ticks">
        <i
          v-for="(tk, i) in ticks"
          :key="i"
          class="spectra-tick"
          :style="{
            '--th': tk.h + 'px',
            '--gap': tk.gap + 'px',
            '--tc': tk.tc,
            '--op': tk.op,
            '--td': tk.td + 'ms',
            '--sd': tk.sd + 's',
            '--sp': tk.sm + 'ms',
            '--jd': tk.jd + 's',
            '--jp': tk.jp + 'ms',
          }"
        ></i>
      </div>

      <p class="hub-sub">选择模块</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import HomeAtlas from "./HomeAtlas.vue";
import { useBrandTitle } from "../../composables/useBrandTitle";
import { useSpectraTicks } from "../../composables/useSpectraTicks";

/* 品牌排印 — compact 级（与引导页同源确定性 hash 场，幅度收敛） */
const chars = useBrandTitle({ compact: true });

/* 谱线回声参数 — echo 变体（与引导页充能组共享唯一权威源
 * useSpectraTicks：光谱色/时序/呼吸/微跳逐线差化） */
const ticks = useSpectraTicks("echo");

/* 视差策略：品牌区/星图静态锚定（无指针视差）— 深度感由
 * CosmicBackground 三层星场视差承担；内容层零位移 = 品牌文字
 * 恒定物理像素对齐 + 零 mousemove 监听（主界面满帧预算全让给背景） */
</script>

<style scoped>
.home-view {
  position: absolute;
  inset: 0;
  overflow: hidden;
}

/* ===== 引力星图位（右侧 — 静态锚定，flex 垂直居中） ===== */
.atlas-pos {
  position: absolute;
  top: 0;
  bottom: 0;
  right: 2%;
  width: min(60%, 780px);
  display: flex;
  align-items: center;
}

/* ===== 品牌区位（左侧 — 静态锚定） =====
 * align-items: center — 谱线组与引导文字相对品牌标题（最宽子项）居中 */
.brand-pos {
  position: absolute;
  top: 0;
  bottom: 0;
  left: 8%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  z-index: 2;
}

/* ============================================================================
 * 品牌雕刻排印：全部复用全局共享体系（animations.css
 * .brand-title + .brand-char + brand-assemble — compact 级幅度经
 * .brand-title--compact 变量覆写：描边/克隆偏移/入射强度收敛，
 * 与引导页引导级同源同轨）
 * ========================================================================== */

/* ===== 谱线回声（基础形态与驻留动效见全局 animations.css 共享体系；
 * 此处仅声明入场编排 + 驻留接入时序 — 呼吸/微跳延迟均精确对齐自身
 * 入场结束时刻，起始帧 = 当前帧零跳变） ===== */
.hub-ticks {
  display: flex;
  align-items: flex-end;
  height: 14px;
  margin-top: 22px;
}
.hub-ticks .spectra-tick {
  animation:
    tick-in 0.7s var(--ease) var(--td, 0ms) backwards,
    spectra-breathe var(--sd, 5s) ease-in-out var(--sp, 700ms) infinite,
    spectra-jitter var(--jd, 6s) linear var(--jp, 800ms) infinite;
}
@keyframes tick-in {
  0% {
    transform: scaleY(0);
    opacity: 0;
  }
  100% {
    transform: scaleY(1);
    opacity: var(--op, 0.5);
  }
}

/* ===== 静默引导（无循环动画 — 安静驻留；相对品牌文字居中，
 * 负右距收缩 letter-spacing 尾距 → 精确视觉居中） ===== */
.hub-sub {
  margin-top: 20px;
  margin-right: -0.58em;
  font-size: 11px;
  color: var(--text-secondary);
  letter-spacing: 0.58em;
  font-family: var(--font);
  opacity: 0;
  animation: sub-in 0.9s var(--ease) 1.35s forwards;
}
@keyframes sub-in {
  from {
    opacity: 0;
    transform: translateY(6px);
  }
  to {
    opacity: 0.9;
    transform: translateY(0);
  }
}

/* ===== 窄窗口适配：星图降透明度让位品牌（布局坐标系不变形） ===== */
@media (max-width: 1024px) {
  .atlas-pos {
    opacity: 0.42;
  }
}
</style>
