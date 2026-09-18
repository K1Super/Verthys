<!--
  BrandMark.vue — 弹窗品牌字（VERTHYS mini 级雕刻排印）
  ★ 职责：安全弹窗（安全存储初始化/身份验证/初始化安全密钥）顶部的
    品牌标识 — 替代已删除的三个顶部图标（IconCore/IconShield/IconCrystal）。
  ★ 复用体系（零新样式语言）：
    - 参数：useBrandTitle({ mini: true }) — 同一确定性 hash 场的第三级
      幅度（intro 引导页 / compact 主界面 / mini 弹窗），品牌形态跨场景同源
    - 样式：全局共享 .brand-title--mini + .brand-char + brand-assemble
      （animations.css 品牌雕刻排印共享体系 — 三态着色/双层雕刻/组装曲线
      单轨复用，仅幅度变量覆写）
  入场：逐字轨道入射一次性组装（0.6-0.82s 差化）— 弹窗打开时品牌
    雕刻成型，替代原图标的 reveal 动画位。
  纯展示组件，无 props/emits。
-->
<template>
  <div class="brand-title brand-title--mini" aria-label="VERTHYS">
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
        '--ed': cv.ed + 'ms',
      }"
    >{{ cv.ch }}</span>
  </div>
</template>

<script setup lang="ts">
import { useBrandTitle } from "../../composables/useBrandTitle";

/* mini 级：字号 24-34px（弹窗内最大文字 — 高于 sc-title 16px）/
   基线 ±2.4px / 微倾 ±0.7° / 入射 13-28px */
const chars = useBrandTitle({ mini: true });
</script>
