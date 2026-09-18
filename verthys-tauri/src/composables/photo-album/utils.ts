/**
 * photo-album/utils.ts — 拾光模块纯工具函数
 *
 * 零业务依赖、零状态：仅纯函数，可独立测试
 */

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
