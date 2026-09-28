/**
 * photo-album/utils.ts — 拾光模块纯工具函数
 *
 * 零业务依赖：纯函数与仅含模块级单调计数器的辅助工具，可独立测试
 */
import { isSlimPhotoMeta } from "../../constants/crypto_const";
import type { PhotoEntry } from "./types";

/** Uint8Array → ArrayBuffer（类型安全转换） */
export const toArrayBuffer = (buf: Uint8Array): ArrayBuffer => {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
};

/** 格式化文件大小 */
export const formatSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
};

/** 根据文件名猜测 MIME 类型 */
export const guessMime = (name: string): string => {
  const ext = name.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
    webp: "image/webp", gif: "image/gif", bmp: "image/bmp",
  };
  return map[ext] || "application/octet-stream";
};

/** 从文件名中提取不含扩展名的 basename */
export const getBaseName = (name: string): string => {
  const idx = name.lastIndexOf(".");
  return idx > 0 ? name.substring(0, idx) : name;
};

/** 跨平台文件名非法字符（Windows 保留字符 + 路径分隔符 + 控制字符） */
const INVALID_FILENAME_CHARS = /[<>:"/\\|?*\u0000-\u001f]/g;

/**
 * 文件名净化：隔离目录分隔符与跨平台非法字符，去除首尾空白与点，
 * 超长按 UTF-8 字节数截断（按码点截断，不割裂代理对），空结果回退占位名。
 *
 * 导出文件名可来自解密元数据（外部可构造输入），净化是写出前的最后防线；
 * 空名占位项（重启后未解密）由调用方在净化前确保已解密，此处仅兜底。
 */
export function sanitizeFileName(name: string, maxUtf8Bytes: number): string {
  const cleaned = name
    .replace(INVALID_FILENAME_CHARS, " ")
    .replace(/^[\s.]+|[\s.]+$/g, "")
    .trim();
  if (!cleaned) return "photo";

  const encoder = new TextEncoder();
  if (encoder.encode(cleaned).length <= maxUtf8Bytes) return cleaned;

  // 超长：按码点逐步累积直到逼近字节上限（避免割裂 surrogate pair）
  let out = "";
  for (const ch of Array.from(cleaned)) {
    if (encoder.encode(out + ch).length > maxUtf8Bytes) break;
    out += ch;
  }
  return out || "photo";
}

/**
 * 批次内文件名唯一化：与已注册名冲突时在扩展名前追加递增后缀（_1/_2…）。
 * 成功注册到 used 集合，保证同一次导出的输出文件互不覆盖。
 */
export function uniqueFileName(base: string, used: Set<string>): string {
  const idx = base.lastIndexOf(".");
  const stem = idx > 0 ? base.substring(0, idx) : base;
  const ext = idx > 0 ? base.substring(idx) : "";
  let candidate = base;
  let n = 0;
  while (used.has(candidate.toLowerCase())) {
    n += 1;
    candidate = `${stem}_${n}${ext}`;
  }
  used.add(candidate.toLowerCase());
  return candidate;
}

/** 浏览器模式：Blob 下载文件 */
export const downloadBlob = (data: Uint8Array, filename: string): void => {
  const blob = new Blob([toArrayBuffer(data)], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
};

/** Canvas 生成缩略图（最大 400×400，JPEG 0.85，内存中处理） */
export const generateThumbnail = async (dataB64: string, mime: string): Promise<string> => {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => {
      const maxW = 400, maxH = 400;
      let w = img.width, h = img.height;
      if (w > maxW) { h = h * (maxW / w); w = maxW; }
      if (h > maxH) { w = w * (maxH / h); h = maxH; }
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(w);
      canvas.height = Math.round(h);
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const thumbB64 = canvas.toDataURL("image/jpeg", 0.85).split(",")[1];
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      resolve(thumbB64);
    };
    img.onerror = () => resolve("");
    img.src = `data:${mime};base64,${dataB64}`;
  });
};

/**
 * 将图片字节转换为 PNG 格式（使用 Canvas 解码 → 重绘 → toBlob）
 * 支持所有浏览器原生支持的图片格式（JPEG/PNG/WebP/BMP/GIF 等）
 */
export const convertToPngBytes = (bytes: Uint8Array, mime: string): Promise<Uint8Array> => {
  return new Promise((resolve, reject) => {
    const blob = new Blob([toArrayBuffer(bytes)], { type: mime || "image/png" });
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext("2d");
      if (!ctx) { reject(new Error("Canvas 2D context 不可用")); return; }
      ctx.drawImage(img, 0, 0);
      canvas.toBlob((pngBlob) => {
        if (!pngBlob) { reject(new Error("PNG 转换失败")); return; }
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
        reader.onerror = () => reject(new Error("PNG 读取失败"));
        reader.readAsArrayBuffer(pngBlob);
      }, "image/png");
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("图片解码失败"));
    };
    img.src = url;
  });
};

/** 浏览器模式：隐藏文件输入打开文件选择对话框 */
export const openBrowserFileDialog = (): Promise<File[]> => {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.accept = "image/png,image/jpeg,image/webp,image/gif,image/bmp";
    input.style.display = "none";
    document.body.appendChild(input);
    input.onchange = () => {
      const files = input.files ? Array.from(input.files) : [];
      document.body.removeChild(input);
      resolve(files);
    };
    input.oncancel = () => {
      document.body.removeChild(input);
      resolve([]);
    };
    input.click();
  });
};

/** 内存照片 ID 单调计数器：以当前时间戳为起点，仅存于模块内存，重载即重置 */
let memoryIdCounter = Date.now();

/** 生成内存照片唯一 ID：单调递增，消除 Date.now()+i 在同毫秒批量构造时的碰撞隐患 */
export const nextMemoryPhotoId = (): number => {
  memoryIdCounter += 1;
  return memoryIdCounter;
};

/* ------------------------------------------------------------------ *
 * 列表装载纯函数（可单测）                                            *
 * ------------------------------------------------------------------ */

/** 记录名 → 展示名：剥离导入侧为 meta 记录附加的前缀，其余原样返回 */
export function stripMetaRecordPrefix(recordName: string): string {
  const prefix = "meta_";
  return recordName.startsWith(prefix) ? recordName.slice(prefix.length) : recordName;
}

/**
 * 缩略图 base64 → Blob URL。
 *
 * Why：缩略图此前以 data URL 字符串形式随列表常驻（每张约数十 KB 且同时存在
 * 于 meta 与渲染字段两处），字符串常驻会持续占用 JS 堆并加重 GC；Blob 的数据
 * 不进 JS 字符串，渲染只持有 URL 引用。代价是 URL 需要显式释放，因此释放点
 * 与生成点必须成对（替换/淘汰/卸载/密钥失效）。
 *
 * @returns Blob URL；空输入或解码失败返回空串（渲染层按无缩略图处理）
 */
export function makeThumbBlobUrl(thumbB64: string): string {
  if (!thumbB64) return "";
  try {
    const bin = atob(thumbB64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return URL.createObjectURL(new Blob([bytes], { type: "image/jpeg" }));
  } catch {
    return "";
  }
}

/** 缩略图字段（CSS `url(...)` 形式）→ 可直接作为 img src 的地址；空值返回空串 */
export function thumbUrlOf(thumb: string): string {
  return thumb.replace(/^url\((.*)\)$/, "$1").replace(/^['"]|['"]$/g, "");
}

/**
 * 缩略图 base64 → CSS background-image 值（Blob URL 形态）。
 *
 * 统一在此拼接 `url("...")`：渲染层（background-image）与预览层（img src）
 * 共用同一字段语义，避免调用方各自拼串造成形态不一致。
 */
export function makeThumbCssValue(thumbB64: string): string {
  const url = makeThumbBlobUrl(thumbB64);
  return url ? `url("${url}")` : "";
}

/**
 * 缩略图原始字节 → CSS background-image 值（Blob URL 形态）。
 *
 * 索引瘦身布局的缩略图以密文记录保存，解密产物即原始 JPEG 字节：
 * 直接由字节建 Blob，省去一次 base64 编码再解码（列表路径的字节量级虽小，
 * 但每张都做转码会在大库滚动时累积成可感知的字符串开销）。
 */
export function makeThumbCssValueFromBytes(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return "";
  const url = URL.createObjectURL(new Blob([toArrayBuffer(bytes)], { type: "image/jpeg" }));
  return url ? `url("${url}")` : "";
}

/** 释放缩略图 Blob URL（只释放 blob: 形态；data: 形态不占用对象存储） */
export function revokeThumbUrl(thumb: string): void {
  const url = thumbUrlOf(thumb);
  if (url.startsWith("blob:")) URL.revokeObjectURL(url);
}

/**
 * 模块缓存回灌：把缓存中的列表项还原为可渲染项。
 *
 * Why：「已加载」必须与「具备可渲染的缩略图来源」绑定。回灌曾无条件把每条
 * 置 loaded=true，未解密占位项因此在再次进入模块时被按需解密整体跳过，
 * 缩略图与名称永久空白（只能逐张点击恢复）。瘦身布局的缩略图存放在独立
 * 记录中（索引内恒为空），回灌无法就地重建，同类空白会以另一种形态复现，
 * 故此类项必须回到待解密态，由可视区按引用取数回填。
 *
 * @param rebuildThumb 缩略图重建器（可选）。缓存中的缩略图可能是上一会话
 *   已释放的 Blob URL（卸载时统一 revoke），回灌必须按 meta 内的缩略图数据
 *   重建；不传则沿用缓存字段（无 Blob 生命周期的场景），但不得为不可渲染项
 *   沿用——其地址可能已悬空。
 */
export function rehydrateEntries(
  cached: readonly PhotoEntry[],
  rebuildThumb?: (thumbB64: string) => string,
): PhotoEntry[] {
  return cached.map((p) => {
    const meta = p.meta;
    const decrypted = meta != null;
    // 瘦身布局且带缩略图引用的项：内联缩略图为空且地址需按引用回源，
    // 回到待解密态由可视区补齐，避免已加载短路造成永久空白。
    const needsThumbRefill = meta != null && isSlimPhotoMeta(meta);

    let thumb = "";
    if (decrypted && !needsThumbRefill) {
      const b64 = meta?.thumbB64 ?? "";
      thumb = rebuildThumb ? (b64 ? rebuildThumb(b64) : "") : p.thumb;
    }

    return {
      ...p,
      loaded: decrypted && !needsThumbRefill,
      failed: false,
      thumb,
      size: decrypted ? p.size : "",
    };
  });
}

/**
 * 增量差集：以已装载 ID 集合为准，返回全量 ID 中尚未装载的部分。
 *
 * Why：此前的增量过滤以"缓存中最大 ID"为界做单调判断，删掉中间 ID 后
 * 记录复用该 ID 时新照片永远不会出现在列表；集合差集与 ID 分配策略解耦。
 */
export function diffNewIds(allIds: readonly number[], knownIds: ReadonlySet<number>): number[] {
  const out: number[] = [];
  for (const id of allIds) {
    if (!knownIds.has(id)) out.push(id);
  }
  return out;
}

/** 按 metaId 升序排序（返回新数组；无 metaId 的项排在末尾并保持相对顺序） */
export function sortByMetaId(entries: readonly PhotoEntry[]): PhotoEntry[] {
  return [...entries].sort((a, b) => (a.metaId ?? Number.MAX_SAFE_INTEGER) - (b.metaId ?? Number.MAX_SAFE_INTEGER));
}

/**
 * 方向感知预取行窗口：在可视行窗口之外，按滚动方向返回需要提前解密的行号。
 *
 * Why：对称缓冲区在快速滚动时需要同时补齐上下两侧，并发额度被"已离开方向"
 * 的行占用；按方向加权可把额度优先给即将进入可视区的行。
 * 返回顺序即优先级：先运动方向（ahead 行），后反方向少量兜底（trail 行）。
 *
 * @param visible 当前可视行窗口（含缓冲区在内的实际参与行，供调用方传入）
 * @param totalRows 总行数（上界）
 * @param dir 滚动方向
 * @param ahead 运动方向预取行数
 * @param trail 反方向兜底行数
 */
export function prefetchRowIndices(
  visible: { startRow: number; endRow: number },
  totalRows: number,
  dir: "down" | "up",
  ahead: number,
  trail: number,
): number[] {
  const rows: number[] = [];
  const pushRange = (from: number, toExclusive: number) => {
    const lo = Math.max(0, from);
    const hi = Math.min(totalRows, toExclusive);
    for (let r = lo; r < hi; r++) rows.push(r);
  };
  if (dir === "down") {
    pushRange(visible.endRow, visible.endRow + ahead);
    pushRange(visible.startRow - trail, visible.startRow);
  } else {
    pushRange(visible.startRow - ahead, visible.startRow);
    pushRange(visible.endRow, visible.endRow + trail);
  }
  return [...new Set(rows)];
}
