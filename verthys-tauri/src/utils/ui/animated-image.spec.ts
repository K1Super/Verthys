/**
 * animated-image.spec.ts — 动图探测状态机回归测试
 *
 * 覆盖：
 * - GIF 图像描述符计数、扩展子块跳过、单帧循环扩展不误判
 * - 动态/静态 WebP 的 RIFF 块识别
 * - APNG acTL 帧数判定与 IDAT 收束
 * - 任意分块边界、畸形与截断输入不抛异常
 */
import { describe, it, expect } from "vitest";
import {
  createAnimatedImageProbe,
  detectAnimatedImage,
  detectAnimatedImageChunks,
  isAnimatedImageCandidate,
} from "./animated-image";

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function ascii(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function u8(...values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

const GIF_MAGIC = ascii("GIF89a");
/** 逻辑屏幕描述符：宽高 1×1，带全局颜色表（2 色 × 3 字节） */
const GIF_LSD = u8(1, 0, 1, 0, 0x80, 0, 0);
const GIF_GCT = u8(0, 0, 0, 255, 255, 255);
/** 图形控制扩展：标签 + 子块链（长度 4 + 数据 + 终止符） */
const GIF_GCE = u8(0x21, 0xf9, 0x04, 0x00, 0x0a, 0x00, 0x00, 0x00);
/** 单帧图像块：描述符 9 字节 + LZW 最小码长 + 数据子块 + 终止符 */
const GIF_IMAGE = u8(
  0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0x00,
  0x02,
  0x02, 0x44, 0x01,
  0x00,
);
const GIF_TRAILER = u8(0x3b);
/** 应用扩展：NETSCAPE2.0 循环标记，常见于单帧伪动图 */
const GIF_NETSCAPE = concat([
  u8(0x21, 0xff, 11), ascii("NETSCAPE2.0"),
  u8(3, 0x01, 0x00, 0x00), u8(0),
]);

function gif(images: number, options: { gce?: boolean; netscape?: boolean } = {}): Uint8Array {
  const parts: Uint8Array[] = [GIF_MAGIC, GIF_LSD, GIF_GCT];
  if (options.netscape) parts.push(GIF_NETSCAPE);
  for (let i = 0; i < images; i++) {
    if (options.gce) parts.push(GIF_GCE);
    parts.push(GIF_IMAGE);
  }
  parts.push(GIF_TRAILER);
  return concat(parts);
}

function riffChunk(type: string, payload: Uint8Array): Uint8Array {
  const pad = payload.length & 1;
  const out = new Uint8Array(8 + payload.length + pad);
  out.set(ascii(type), 0);
  new DataView(out.buffer).setUint32(4, payload.length, true);
  out.set(payload, 8);
  return out;
}

function webp(...chunks: Uint8Array[]): Uint8Array {
  const body = concat([ascii("WEBP"), ...chunks]);
  const out = new Uint8Array(8 + body.length);
  out.set(ascii("RIFF"), 0);
  new DataView(out.buffer).setUint32(4, body.length, true);
  out.set(body, 8);
  return out;
}

const PNG_SIGNATURE = u8(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + data.length);
  new DataView(out.buffer).setUint32(0, data.length, false);
  out.set(ascii(type), 4);
  out.set(data, 8);
  return out;
}

function apng(frames: number): Uint8Array {
  const actl = new Uint8Array(8);
  new DataView(actl.buffer).setUint32(0, frames, false);
  new DataView(actl.buffer).setUint32(4, 0, false);
  return concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", new Uint8Array(13)),
    pngChunk("acTL", actl),
    pngChunk("IDAT", u8(1, 2, 3)),
    pngChunk("IEND", new Uint8Array(0)),
  ]);
}

function staticPng(): Uint8Array {
  return concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", new Uint8Array(13)),
    pngChunk("IDAT", u8(1, 2, 3)),
    pngChunk("IEND", new Uint8Array(0)),
  ]);
}

describe("动图探测 — GIF", () => {
  it("单帧 GIF 不判定为动图", () => {
    expect(detectAnimatedImage("image/gif", gif(1))).toBe(false);
  });

  it("两帧 GIF 判定为动图", () => {
    expect(detectAnimatedImage("image/gif", gif(2, { gce: true }))).toBe(true);
  });

  it("带 NETSCAPE 循环扩展但仅单帧：不得误判", () => {
    expect(detectAnimatedImage("image/gif", gif(1, { netscape: true }))).toBe(false);
  });

  it("任意分块边界下结果一致", () => {
    const bytes = gif(2, { gce: true });
    for (let split = 1; split < bytes.length; split++) {
      const probe = createAnimatedImageProbe("image/gif");
      probe.push(bytes.subarray(0, split));
      probe.push(bytes.subarray(split));
      expect(probe.animated, `split=${split}`).toBe(true);
    }
  });

  it("截断输入不抛异常；未到达第二帧描述符前按未确认多帧收束", () => {
    const bytes = gif(2, { gce: true });
    for (const cut of [0, 1, 5, 13, 20, bytes.length - 1]) {
      expect(() => detectAnimatedImage("image/gif", bytes.subarray(0, cut))).not.toThrow();
    }
    for (const cut of [0, 1, 5, 13, 20]) {
      expect(detectAnimatedImage("image/gif", bytes.subarray(0, cut))).toBe(false);
    }
  });
});

describe("动图探测 — WebP", () => {
  it("静态 WebP 不判定为动图", () => {
    const bytes = webp(riffChunk("VP8 ", u8(1, 2, 3, 4)));
    expect(detectAnimatedImage("image/webp", bytes)).toBe(false);
  });

  it("含 ANIM 块的 WebP 判定为动图", () => {
    const bytes = webp(
      riffChunk("VP8X", new Uint8Array(10)),
      riffChunk("ANIM", new Uint8Array(6)),
    );
    expect(detectAnimatedImage("image/webp", bytes)).toBe(true);
  });

  it("含 ANMF 块的 WebP 判定为动图", () => {
    const bytes = webp(
      riffChunk("VP8X", new Uint8Array(10)),
      riffChunk("ANMF", new Uint8Array(16)),
    );
    expect(detectAnimatedImage("image/webp", bytes)).toBe(true);
  });

  it("奇数长度块按偶数字节对齐跳过", () => {
    const bytes = webp(
      riffChunk("VP8 ", u8(1, 2, 3)),
      riffChunk("ANIM", new Uint8Array(6)),
    );
    expect(detectAnimatedImage("image/webp", bytes)).toBe(true);
  });

  it("任意分块边界下结果一致", () => {
    const bytes = webp(
      riffChunk("VP8X", new Uint8Array(10)),
      riffChunk("ANIM", new Uint8Array(6)),
    );
    for (let split = 1; split < bytes.length; split++) {
      const probe = createAnimatedImageProbe("image/webp");
      probe.push(bytes.subarray(0, split));
      probe.push(bytes.subarray(split));
      expect(probe.animated, `split=${split}`).toBe(true);
    }
  });

  it("截断输入不抛异常；未到达 ANIM 块前按未确认多帧收束", () => {
    const bytes = webp(
      riffChunk("VP8X", new Uint8Array(10)),
      riffChunk("ANIM", new Uint8Array(6)),
    );
    for (const cut of [0, 4, 12, 20, bytes.length - 1]) {
      expect(() => detectAnimatedImage("image/webp", bytes.subarray(0, cut))).not.toThrow();
    }
    for (const cut of [0, 4, 12, 20]) {
      expect(detectAnimatedImage("image/webp", bytes.subarray(0, cut))).toBe(false);
    }
  });
});

describe("动图探测 — PNG / APNG", () => {
  it("普通 PNG 不判定为动图", () => {
    expect(detectAnimatedImage("image/png", staticPng())).toBe(false);
  });

  it("APNG 的 acTL 帧数 ≥ 2 判定为动图", () => {
    expect(detectAnimatedImage("image/png", apng(2))).toBe(true);
    expect(detectAnimatedImage("image/apng", apng(2))).toBe(true);
  });

  it("acTL 帧数为 1 不判定为动图", () => {
    expect(detectAnimatedImage("image/png", apng(1))).toBe(false);
  });

  it("任意分块边界下结果一致", () => {
    const bytes = apng(2);
    const probe = createAnimatedImageProbe("image/png");
    for (let i = 0; i < bytes.length; i++) probe.push(bytes.subarray(i, i + 1));
    expect(probe.animated).toBe(true);
  });

  it("分块列表入口与全量入口结果一致", () => {
    const bytes = apng(2);
    expect(detectAnimatedImageChunks("image/png", [bytes.subarray(0, 9), bytes.subarray(9)])).toBe(true);
  });

  it("截断输入不抛异常；未到达 acTL 前按未确认多帧收束", () => {
    const bytes = apng(2);
    for (const cut of [0, 4, 8, 20, bytes.length - 1]) {
      expect(() => detectAnimatedImage("image/png", bytes.subarray(0, cut))).not.toThrow();
    }
    for (const cut of [0, 4, 8, 20]) {
      expect(detectAnimatedImage("image/png", bytes.subarray(0, cut))).toBe(false);
    }
  });
});

describe("动图探测 — 入口守卫", () => {
  it("候选类型判定", () => {
    expect(isAnimatedImageCandidate("image/gif")).toBe(true);
    expect(isAnimatedImageCandidate("image/webp")).toBe(true);
    expect(isAnimatedImageCandidate("image/png")).toBe(true);
    expect(isAnimatedImageCandidate("image/apng")).toBe(true);
    expect(isAnimatedImageCandidate("image/jpeg")).toBe(false);
    expect(isAnimatedImageCandidate("application/octet-stream")).toBe(false);
  });

  it("非候选类型恒 false，且不消费字节", () => {
    expect(detectAnimatedImage("image/jpeg", u8(1, 2, 3))).toBe(false);
    expect(detectAnimatedImageChunks("image/bmp", [u8(1, 2, 3)])).toBe(false);
  });
});
