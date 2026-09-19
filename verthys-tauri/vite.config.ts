import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import obfuscatorPlugin from "rollup-plugin-obfuscator";
import { visualizer } from "rollup-plugin-visualizer";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(async ({ command }) => ({
  plugins: [
    vue(),
    // 代码混淆：仅在 build 时启用（dev 时保留可读性以支持热更新与 console）
    ...(command === "build"
      ? [
          obfuscatorPlugin({
            // 仅对 JS 产物应用混淆，不影响 CSS/HTML
            include: ["**/*.js", "**/*.mjs"],
            // ★ 性能审计修订：安全责任由 Rust/C 层承担（core/ 六层防护：
            //   anti_debug_v2 / anti_inject / integrity / tamper_destroy 等），
            //   前端混淆仅保留静态不可执行期保护（标识符重命名 + 压缩）。
            // 移除的高开销运行时选项及其代价：
            //   - debugProtection(interval 2000)：每 2s 常驻反调试轮询（隐藏周期性 CPU 任务）
            //   - selfDefending：每次加载执行格式自检（启动 CPU 脉冲）
            //   - controlFlowFlattening(0.75)：全部 JS 热路径状态机化，执行慢 2~5×
            //     （动画循环/粒子更新/弹簧积分等每帧代码全部被拖累）
            //   - deadCodeInjection(0.4)：产物膨胀 30~40%，常驻内存等比增加
            //   - transformObjectKeys：热路径对象属性访问去虚拟化
            options: {
              compact: true,
              controlFlowFlattening: false,
              deadCodeInjection: false,
              debugProtection: false,
              selfDefending: false,
              disableConsoleOutput: true,
              identifierNamesGenerator: "hexadecimal",
              renameGlobals: false,
              // stringArray 禁用：多 chunk 架构下 stringArray 会把动态 import()
              // 路径字符串提取并 RC4 加密，运行时解密时序可能导致组件 chunk 加载失败。
              stringArray: false,
              transformObjectKeys: false,
              unicodeEscapeSequence: false,
            },
          }),
          // 打包体积分析：构建后生成 stats.html，定位最大依赖
          visualizer({
            filename: "dist/stats.html",
            template: "treemap",
            gzipSize: true,
            brotliSize: true,
          }),
        ]
      : []),
  ],
  clearScreen: false,
  // 使用较新 target 以支持解构语法降级（esbuild-wasm 0.28 严格检查）
  build: {
    target: "esnext",
    rollupOptions: {
      output: {
        // 第三方依赖独立分包：@tauri-apps 全家桶从业务代码隔离，
        // 避免业务改动触发 vendor 缓存失效，同时缩小主包体积。
        manualChunks: {
          "tauri-vendor": [
            "@tauri-apps/api",
            "@tauri-apps/plugin-dialog",
            "@tauri-apps/plugin-fs",
            "@tauri-apps/plugin-opener",
            "@tauri-apps/plugin-process",
          ],
          // Vue runtime 独立分包：拆分后主包仅保留首屏组件 + 启动逻辑，
          // Vue 运行时由浏览器并行加载，加速首屏渲染。
          "vue-vendor": ["vue"],
          // ★ 项13：加密库独立分包（@noble 全家桶 + hash-wasm）
          // 密码学库体积较大（~200KB）且仅 PasswordTools/PhotoAlbum 等业务模块使用，
          // 拆分后主包不含加密代码，首屏加载更快；同时加密库版本稳定，
          // 业务改动不会触发该 chunk 失效，提升浏览器缓存命中率。
          "crypto-vendor": [
            "@noble/hashes",
            "@noble/ciphers",
            "hash-wasm",
          ],
          // ★ 项13：Three.js 独立分包（仅 PhotoAlbum 相册模块使用）
          // Three.js 体积约 600KB（gzip 后 ~150KB），是项目中最大的单一依赖。
          // 拆分后仅在用户进入"拾光"模块时按需加载，首屏无需下载，
          // 主包体积减少 60%+，首屏 TTI 显著降低。
          "photo-vendor": ["three"],
        },
      },
    },
  },
  esbuild: {
    target: "esnext",
  },
  // 依赖预构建也使用 esnext target（默认是 "modules" = es2020，会导致解构降级错误）
  optimizeDeps: {
    esbuildOptions: {
      target: "esnext",
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: { ignored: ["**/src-tauri/**", "**/verthys-worker/**"] },
  },
}));
