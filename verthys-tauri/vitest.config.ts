import { defineConfig } from 'vitest/config';

// 感知层单元测试配置：node 环境（无 DOM 依赖，动画帧用注入的假调度器驱动）
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.spec.ts'],
  },
});