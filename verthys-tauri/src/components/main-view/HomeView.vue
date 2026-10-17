<!--
  HomeView.vue — 主界面默认视图（深空巡天 · 引力星图）
  非对称构图（拒绝居中对称模板）：
    左 8%  — 品牌星晶棱镜体字标（BrandMark compact 级 — 与引导页
              同源字形库与运动表，跨场景品牌形态一致）+ 谱线回声 + 静默引导
    右侧   — 引力星图 HomeAtlas（非同心轨道 + 奇点 + 差速航点）
    对角视觉张力：Dock → 品牌 → 星图 → 深空（阅读动线成势）
  视差策略：本层内容（品牌/星图）不参与指针视差 — 深度感全部
    由 CosmicBackground 三层星场视差承担；内容层恒定静止保证
    品牌文字始终物理像素对齐（零亚像素栅格化 → 恒定锐利）。
 统一入场编排（三元素同刻起笔、一笔书写 — 单一权威见 animations.css 编排段）：
    品牌逐字凝聚（2D 平移 + 不透明度，递减加速扫掠）
    ‖ 谱线逐条自各自基线下升起（同通道同缓动）
    ‖ 副标显影（同通道同缓动）
    → 星图同步揭示（HomeAtlas 内部编排）— 一次性 backwards 零跳变。
    三者起笔时刻同为 TRANSITION.HUB_ENTRANCE_AT（与整层浮现可辨度对齐，
    避免动作被整层淡入掩盖 ⇒ 观感为直接出现）。
    全程零重采样：文字与矢量承载层只用 2D 平移与不透明度。
-->
<template>
  <div class="home-view" :style="{ '--hub-t0': hubT0 }">
    <!-- 引力星图（右侧 — 静态锚定） -->
    <div class="atlas-pos">
      <HomeAtlas />
    </div>

    <!-- 品牌区（左侧 — 静态锚定） -->
    <div class="brand-pos">
      <!-- 星晶棱镜体字标（compact 级 — 与引导页同源字形库/运动表，
           材质与幅度收敛；形制：棱镜口 V / 悬锤垂针 Y / 能量芯 H） -->
      <h1 class="brand-h1">
        <BrandMark level="compact" />
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

      <p class="hub-sub" :style="{ '--sub-d': subDelay + 'ms' }">选择模块</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import HomeAtlas from "./HomeAtlas.vue";
import BrandMark from "../common/BrandMark.vue";
import { useSpectraTicks } from "../../composables/useSpectraTicks";
import { TRANSITION } from "../../app/constants";

/* 品牌字标（common/BrandMark.vue — compact 级）：
 * 字形/四层叠材/运动参数由 useBrandTitle 唯一权威源直出，与引导页同源同轨，
 * 仅级别材质与幅度收敛（组件内部自持模型，此处零参数透传） */

/* 谱线回声参数 — echo 变体（与引导页充能组共享唯一权威源
 * useSpectraTicks：光谱色/时序/呼吸/微跳逐线差化） */
const ticks = useSpectraTicks("echo");

/* 三元素统一起笔时刻（单一权威 = TRANSITION.HUB_ENTRANCE_AT）：
 * 与整层浮现（materialize 组不透明度）的可辨度对齐，使入场动作全程
 * 落在整层已可辨的窗口内 —— 早于此刻动作会被整层淡入掩盖，观感为
 * 「直接出现」。品牌侧经 --hub-t0 注入 CSS；谱线/副标由各自数据派生。 */
const hubT0 = TRANSITION.HUB_ENTRANCE_AT + "ms";
const subDelay = TRANSITION.HUB_ENTRANCE_AT;

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
 * 品牌字标：全部复用全局共享体系（animations.css
 * .brand-wordmark + .wm-glyph + wm-crystallize — compact 级材质经
 * .brand-wordmark--compact 变量覆写：体宽/棱边与折射偏移/凝聚幅度收敛，
 * 与引导页引导级同源同轨）
 * ========================================================================== */

/* ===== 谱线回声（入场/驻留动效与统一令牌见全局 animations.css 编排段 —
 * 本文件只承载布局） ===== */
.hub-ticks {
  display: flex;
  align-items: flex-end;
  height: 14px;
  margin-top: 22px;
}

/* ===== 静默引导（无循环动画 — 安静驻留；相对品牌文字居中，
 * 负右距收缩 letter-spacing 尾距 → 精确视觉居中；
 * 入场见全局编排段第三幕） ===== */
.hub-sub {
  margin-top: 20px;
  margin-right: -0.58em;
  font-size: 11px;
  color: var(--text-secondary);
  letter-spacing: 0.58em;
  font-family: var(--font);
  opacity: 0;
}

/* ===== 窄窗口适配：星图降透明度让位品牌（布局坐标系不变形） ===== */
@media (max-width: 1024px) {
  .atlas-pos {
    opacity: 0.42;
  }
}
</style>
