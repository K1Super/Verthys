/**
 * utils/animated-image.ts — 动图容器探测（纯函数 · 无 DOM · 无依赖）
 *
 * 职责：判断 GIF、动态 WebP、APNG 是否确实包含多帧。
 *
 * 约束：
 * - 流式状态机：调用方按任意分块喂入，跨块边界正确续解，内存占用与输入
 *   大小无关；
 * - 只解析容器结构，不解码像素；大块像素数据按长度跳过；
 * - 输入来自用户文件或外部容器，畸形与截断输入一律收敛为 false，不抛异常；
 * - false 只表示“未确认含多帧”，不得据此断言文件是静态图。
 */

/** 增量探测器：分块喂入，结果单调（一旦确认多帧不会回退） */
export interface AnimatedImageProbe {
  /** 追加一段字节；分块边界任意 */
  push(bytes: Uint8Array): void;
  /** 是否已确认包含多帧 */
  readonly animated: boolean;
}

const KIND_NONE = 0;
const KIND_GIF = 1;
const KIND_WEBP = 2;
const KIND_PNG = 3;
type FormatKind = typeof KIND_NONE | typeof KIND_GIF | typeof KIND_WEBP | typeof KIND_PNG;

/* GIF 状态 */
const GIF_MAGIC = 1;
const GIF_LSD = 2;
const GIF_BLOCK = 3;
const GIF_EXT_LABEL = 4;
const GIF_IMAGE_DESC = 5;
const GIF_IMAGE_DATA = 6;
const GIF_SUB_LEN = 7;

/* WebP 状态 */
const WEBP_HEADER = 11;
const WEBP_CHUNK_HEADER = 12;

/* PNG 状态 */
const PNG_SIGNATURE = 21;
const PNG_CHUNK_HEADER = 22;
const PNG_ACTL = 23;

/** 头部收集缓冲上界：最长需要 13 字节（GIF 逻辑屏幕描述符 + 魔数） */
const HEADER_CAPACITY = 16;

/**
 * 单文件探测器。
 *
 * 状态机由两种等待构成：等待固定长度头部（need/needPos），或跳过指定长度
 * 的载荷（skipRemaining）。跳过大块载荷时只做长度减法，不复制字节。
 */
class Probe implements AnimatedImageProbe {
  private state = 0;
  private need = 0;
  private needPos = 0;
  private skipRemaining = 0;
  private skipNext = 0;
  private readonly header = new Uint8Array(HEADER_CAPACITY);
  private animatedFlag = false;
  private finished = false;
  private gifImages = 0;
  private pngChunkDataLength = 0;

  constructor(kind: FormatKind) {
    if (kind === KIND_GIF) this.begin(GIF_MAGIC);
    else if (kind === KIND_WEBP) this.begin(WEBP_HEADER);
    else if (kind === KIND_PNG) this.begin(PNG_SIGNATURE);
    else this.finish(false);
  }

  get animated(): boolean {
    return this.animatedFlag;
  }

  push(bytes: Uint8Array): void {
    if (this.finished || bytes.length === 0) return;

    let i = 0;
    while (i < bytes.length && !this.finished) {
      // 跳过载荷：只推进长度游标，不搬运字节
      if (this.skipRemaining > 0) {
        const step = Math.min(this.skipRemaining, bytes.length - i);
        i += step;
        this.skipRemaining -= step;
        if (this.skipRemaining === 0) this.begin(this.skipNext);
        continue;
      }

      const step = Math.min(this.need - this.needPos, bytes.length - i);
      if (step <= 0) {
        // 状态机自洽性兜底：正常路径不会进入，防御畸形状态导致死循环
        this.finish(false);
        return;
      }
      this.header.set(bytes.subarray(i, i + step), this.needPos);
      this.needPos += step;
      i += step;

      if (this.needPos === this.need) {
        this.needPos = 0;
        this.onHeader();
      }
    }
  }

  /** 进入指定状态：设置该状态需要收集的头部长度 */
  private begin(state: number): void {
    if (this.finished) return;
    this.state = state;
    this.need = 0;
    this.needPos = 0;
    switch (state) {
      case GIF_MAGIC: this.need = 6; break;
      case GIF_LSD: this.need = 7; break;
      case GIF_BLOCK: this.need = 1; break;
      case GIF_EXT_LABEL: this.need = 1; break;
      case GIF_IMAGE_DESC: this.need = 9; break;
      case GIF_IMAGE_DATA: this.need = 1; break;
      case GIF_SUB_LEN: this.need = 1; break;
      case WEBP_HEADER: this.need = 12; break;
      case WEBP_CHUNK_HEADER: this.need = 8; break;
      case PNG_SIGNATURE: this.need = 8; break;
      case PNG_CHUNK_HEADER: this.need = 8; break;
      case PNG_ACTL: this.need = 8; break;
      default: this.finish(false);
    }
  }

  /** 跳过 length 字节后进入下一状态；length 为 0 时直接进入 */
  private skip(length: number, nextState: number): void {
    if (length <= 0) {
      this.begin(nextState);
      return;
    }
    this.skipRemaining = length;
    this.skipNext = nextState;
    this.need = 0;
    this.needPos = 0;
  }

  private finish(animated: boolean): void {
    if (this.finished) return;
    this.finished = true;
    this.animatedFlag = animated;
  }

  /** 一个完整头部已收集：按状态解析并转移 */
  private onHeader(): void {
    const h = this.header;
    switch (this.state) {
      case GIF_MAGIC: {
        const valid =
          h[0] === 0x47 && h[1] === 0x49 && h[2] === 0x46 && h[3] === 0x38 &&
          (h[4] === 0x37 || h[4] === 0x39) && h[5] === 0x61;
        if (!valid) {
          this.finish(false);
          return;
        }
        this.begin(GIF_LSD);
        return;
      }
      case GIF_LSD: {
        // 全局颜色表大小：3 × 2^(N+1)；无全局表时直接进入块循环
        const packed = h[4];
        const gctSize = (packed & 0x80) !== 0 ? 3 << ((packed & 0x07) + 1) : 0;
        this.skip(gctSize, GIF_BLOCK);
        return;
      }
      case GIF_BLOCK: {
        const introducer = h[0];
        if (introducer === 0x2c) {
          this.gifImages += 1;
          // 第二帧图像描述符即证明多帧；无需继续解析像素数据
          if (this.gifImages >= 2) this.finish(true);
          else this.begin(GIF_IMAGE_DESC);
          return;
        }
        if (introducer === 0x21) {
          this.begin(GIF_EXT_LABEL);
          return;
        }
        // 0x3B 尾部标记或无法识别的字节：按未确认多帧收束
        this.finish(false);
        return;
      }
      case GIF_EXT_LABEL:
        // 扩展数据统一为子块链，标签本身不参与多帧判定
        this.begin(GIF_SUB_LEN);
        return;
      case GIF_IMAGE_DESC: {
        const packed = h[8];
        const lctSize = (packed & 0x80) !== 0 ? 3 << ((packed & 0x07) + 1) : 0;
        this.skip(lctSize, GIF_IMAGE_DATA);
        return;
      }
      case GIF_IMAGE_DATA:
        // LZW 最小码长占 1 字节，之后才是图像数据子块链
        this.begin(GIF_SUB_LEN);
        return;
      case GIF_SUB_LEN: {
        const length = h[0];
        if (length === 0) this.begin(GIF_BLOCK);
        else this.skip(length, GIF_SUB_LEN);
        return;
      }
      case WEBP_HEADER: {
        const valid =
          h[0] === 0x52 && h[1] === 0x49 && h[2] === 0x46 && h[3] === 0x46 &&
          h[8] === 0x57 && h[9] === 0x45 && h[10] === 0x42 && h[11] === 0x50;
        if (!valid) {
          this.finish(false);
          return;
        }
        this.begin(WEBP_CHUNK_HEADER);
        return;
      }
      case WEBP_CHUNK_HEADER: {
        const isAnim = h[0] === 0x41 && h[1] === 0x4e && h[2] === 0x49 && h[3] === 0x4d;
        const isAnmf = h[0] === 0x41 && h[1] === 0x4e && h[2] === 0x4d && h[3] === 0x46;
        if (isAnim || isAnmf) {
          this.finish(true);
          return;
        }
        const size = ((h[4] | (h[5] << 8) | (h[6] << 16) | (h[7] << 24)) >>> 0);
        // RIFF 块按偶数字节对齐：奇数长度带 1 字节填充
        this.skip(size + (size & 1), WEBP_CHUNK_HEADER);
        return;
      }
      case PNG_SIGNATURE: {
        const valid =
          h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47 &&
          h[4] === 0x0d && h[5] === 0x0a && h[6] === 0x1a && h[7] === 0x0a;
        if (!valid) {
          this.finish(false);
          return;
        }
        this.begin(PNG_CHUNK_HEADER);
        return;
      }
      case PNG_CHUNK_HEADER: {
        const length = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
        const isActl = h[4] === 0x61 && h[5] === 0x63 && h[6] === 0x54 && h[7] === 0x4c;
        const isIdat = h[4] === 0x49 && h[5] === 0x44 && h[6] === 0x41 && h[7] === 0x54;
        const isIend = h[4] === 0x49 && h[5] === 0x45 && h[6] === 0x4e && h[7] === 0x44;
        if (isActl) {
          // 规范规定 acTL 数据为 8 字节；异常长度按普通块跳过，避免错位
          if (length < 8) {
            this.skip(length + 4, PNG_CHUNK_HEADER);
            return;
          }
          this.pngChunkDataLength = length;
          this.begin(PNG_ACTL);
          return;
        }
        // acTL 必须位于 IDAT 之前；到达图像数据仍未见到即按静态图收束
        if (isIdat || isIend) {
          this.finish(false);
          return;
        }
        this.skip(length + 4, PNG_CHUNK_HEADER);
        return;
      }
      case PNG_ACTL: {
        const frames = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
        if (frames >= 2) {
          this.finish(true);
          return;
        }
        // 单帧 acTL：跳过剩余数据与 CRC，继续寻找 IDAT
        this.skip(this.pngChunkDataLength - 8 + 4, PNG_CHUNK_HEADER);
        return;
      }
      default:
        this.finish(false);
    }
  }
}

function kindOf(mime: string): FormatKind {
  const normalized = mime.trim().toLowerCase();
  if (normalized === "image/gif") return KIND_GIF;
  if (normalized === "image/webp") return KIND_WEBP;
  if (normalized === "image/png" || normalized === "image/apng") return KIND_PNG;
  return KIND_NONE;
}

/** 是否为可能包含多帧的容器类型（其他类型无需启动探测） */
export function isAnimatedImageCandidate(mime: string): boolean {
  return kindOf(mime) !== KIND_NONE;
}

/**
 * 创建增量探测器。
 *
 * 非候选类型返回恒 false 的空探测器，调用方无需分支。
 */
export function createAnimatedImageProbe(mime: string): AnimatedImageProbe {
  return new Probe(kindOf(mime));
}

/** 全量探测：适合已完整持有字节的导入路径 */
export function detectAnimatedImage(mime: string, bytes: Uint8Array): boolean {
  const probe = createAnimatedImageProbe(mime);
  probe.push(bytes);
  return probe.animated;
}

/** 分块探测：适合备份还原与查看器按块持有的场景 */
export function detectAnimatedImageChunks(
  mime: string,
  chunks: readonly Uint8Array[],
): boolean {
  const probe = createAnimatedImageProbe(mime);
  for (const chunk of chunks) {
    probe.push(chunk);
    if (probe.animated) return true;
  }
  return probe.animated;
}
