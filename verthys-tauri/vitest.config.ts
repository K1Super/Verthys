import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';

// 单元测试配置：默认 node 环境（无 DOM 依赖，动画帧用注入的假调度器驱动）；
// 组件级测试通过文件级 environment 指令切换到 DOM 环境
export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'node',
    include: ['src/**/*.spec.ts'],
  },
});