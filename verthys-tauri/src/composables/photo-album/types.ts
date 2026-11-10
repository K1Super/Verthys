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
  /** 该条按需解密曾失败（保留占位并提供重试入口；不参与 loaded 判定，避免永久跳过） */
  failed?: boolean;
  /** 浏览器模式下缓存原始 Blob URL（用于预览/导出） */
  blobUrl?: string;
  /** 浏览器模式下缓存原始字节（用于加密导出） */
  rawBytes?: Uint8Array;
}

/** 可视区域项目（带定位坐标，用于虚拟滚动绝对定位） */
export interface VisiblePhoto extends PhotoEntry {
  _left: number;
  _top: number;
  /** 预计算的内联样式字符串（行窗口重建时生成一次；模板直接消费，
   *  避免每次渲染重建 style 对象并逐键 diff——滚动路径零对象分配） */
  _style: string;
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

/** 解析预览项（只含清单字段，不携带块载荷） */
export interface ParsedPhotoPreview {
  /** 显示名 */
  name: string;
  /** 缩略图 CSS 值（无缩略图为空串） */
  thumb: string;
  /** 原始文件大小（字节） */
  size: number;
  /** MIME 类型 */
  mime: string;
  /** BLAKE3 文件哈希（内容身份，导入去重使用） */
  fileHash: string;
  /** 数据块总数 */
  chunkCount: number;
  /** 创建时间戳（毫秒） */
  createdAt: number;
}
