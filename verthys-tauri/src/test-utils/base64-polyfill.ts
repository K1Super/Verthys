/**
 * test-utils/base64-polyfill.ts — Node 测试环境的 atob/btoa 等价实现
 *
 * 浏览器提供原生 atob/btoa，Node 测试环境缺失；Vitest 单元测试中
 * 涉及 base64 编解码的生产代码（容器块转换、预览组装）依赖这两个全局函数，
 * 此处以纯 TS 实现补齐，避免引入 @types/node 污染前端 tsconfig 类型域。
 */

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** 安装 atob/btoa 全局桩（已存在则不覆盖浏览器原生实现） */
export function installBase64Polyfill(): void {
  if (typeof globalThis.atob !== "function") {
    globalThis.atob = (s: string) => {
      const clean = s.replace(/=+$/, "");
      let out = "";
      let bits = 0;
      let acc = 0;
      for (const c of clean) {
        const idx = BASE64_CHARS.indexOf(c);
        if (idx < 0) continue;
        acc = (acc << 6) | idx;
        bits += 6;
        while (bits >= 8) {
          bits -= 8;
          out += String.fromCharCode((acc >> bits) & 0xff);
        }
      }
      return out;
    };
  }
  if (typeof globalThis.btoa !== "function") {
    globalThis.btoa = (b: string) => {
      let out = "";
      let acc = 0;
      let bits = 0;
      for (let i = 0; i < b.length; i++) {
        acc = (acc << 8) | b.charCodeAt(i);
        bits += 8;
        while (bits >= 6) {
          bits -= 6;
          out += BASE64_CHARS[(acc >> bits) & 0x3f];
        }
      }
      if (bits > 0) {
        out += BASE64_CHARS[(acc << (6 - bits)) & 0x3f];
      }
      while (out.length % 4 !== 0) out += "=";
      return out;
    };
  }
}