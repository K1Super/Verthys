/**
 * photo-album/types.ts — 拾光模块类型定义
 *
 * 入口文件单一职责：所有业务类型集中定义，供各 composable 共享
 */
import type { PhotoMeta } from "../../lib/crypto";

/** 照片列表项（渲染层数据结构） */
export interface PhotoEntry {
  id: number;
  metaId?: number;
  name: string;
  thumb: string;
  size: string;
  height: number;
  meta?: PhotoMeta;
  /** 是否已解密完整元数据（按需加载标志：false=占位项待解密，true=已解密可渲染缩略图） */
  loaded?: boolean;
  /** 浏览器模式下缓存原始 Blob URL（用于预览/导出） */
  blobUrl?: string;
  /** 浏览器模式下缓存原始字节（用于加密导出） */
  rawBytes?: Uint8Array;
}

/** 可视区域项目（带定位坐标，用于虚拟滚动绝对定位） */
export interface VisiblePhoto extends PhotoEntry {
  _left: number;
  _top: number;
}

/** 解密后的照片元数据渲染字段 */
export interface DecryptedPhotoMeta {
  name: string;
  thumb: string;
  size: string;
  meta: PhotoMeta;
}

/** 导出格式 */
export type ExportFormat = "single" | "multiple" | "png";

/** 解析预览项 */
export interface ParsedPhotoPreview {
  name: string;
  thumb: string;
  size: number;
  metaB64: string;
  chunkB64List: string[];
  meta: PhotoMeta | null;
}

/** 导出完成 Toast 类型 */
export interface ExportDoneToast {
  msg: string;
  type: "success" | "error";
}
