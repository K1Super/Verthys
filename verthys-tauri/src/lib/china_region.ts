/*
 * lib/china_region.ts — 行政区划路径的拼接与回解（纯函数）
 *
 * 用途：把「省 / 市 / 区」三级名称与落盘用的单值路径互相转换，供地区控件
 *   与卡片展示共用。落盘只存一个字符串（省/市/区），因此回解必须可靠：
 *   控件要靠它还原三个下拉框的选中项。
 *
 * 职责边界：只做字符串与区划树之间的映射，不持有区划数据、不发起加载、
 *   不触碰 DOM。区划树由调用方注入 —— 数据模块只在真正渲染地区控件时
 *   按需加载，本模块的类型引用在编译期擦除，不会把数据带入主包。
 *
 * 关键约束：
 *   1. 回解按「省 → 市 → 区」逐级在对应父级内匹配，不跨级全局搜索：
 *      区县名在不同地级单位下可能重名（如「大安区」），全局匹配会选错父级。
 *   2. 任何一段无法在父级内命中即判定为不可回解（matched=false），三个
 *      下拉框一律留空。不可回解的值（历史自由文本、区划更名）必须原样保留，
 *      直到用户显式重选 —— 部分回填再保存会把原文截断成残缺路径。
 *   3. 空值视为可回解的空路径（matched=true），避免把「尚未填写」误报为
 *      「历史值冲突」。
 *   4. 路径分隔符只用于展示与落盘；区划名称本身不含该分隔符（数据源已核验）。
 */

import type { ChinaRegionProvince } from "../constants/china_regions";

/** 落盘路径分隔符（省 / 市 / 区） */
export const CHINA_REGION_PATH_SEPARATOR = "/";

/** 三级区划路径的回解结果 */
export interface ChinaRegionPath {
  /** 命中时为省份名称；未命中为空串 */
  province: string;
  /** 命中时为地级名称；未选择或未命中为空串 */
  city: string;
  /** 命中时为区县名称；未选择或未命中为空串 */
  district: string;
  /**
   * 已存取值能否在当前区划树中完整回解。
   * 空值恒为 true；非空且任一段未命中为 false（调用方据此展示历史值提示）。
   */
  matched: boolean;
}

/** 空路径（未填写 / 不可回解时下拉框的初始态） */
export function emptyChinaRegionPath(): ChinaRegionPath {
  return { province: "", city: "", district: "", matched: true };
}

/**
 * 把「省/市/区」路径回解为三级名称。
 *
 * @param value 落盘取值（可能来自历史自由文本，按未知内容处理）
 * @param regions 区划树（由调用方按需加载后注入）
 * @returns 回解结果；不可回解时三个名称均为空串且 matched=false
 */
export function parseChinaRegionPath(
  value: string,
  regions: readonly ChinaRegionProvince[],
): ChinaRegionPath {
  const text = value.trim();
  if (!text) return emptyChinaRegionPath();

  const segments = text.split(CHINA_REGION_PATH_SEPARATOR).map((part) => part.trim());
  // 超过三级或出现空段（如「广东省//南山区」）不可能是本控件产出的路径
  if (segments.length > 3 || segments.some((part) => part.length === 0)) {
    return { province: "", city: "", district: "", matched: false };
  }

  const [provinceName, cityName = "", districtName = ""] = segments;
  const province = regions.find((item) => item.name === provinceName);
  if (!province) {
    return { province: "", city: "", district: "", matched: false };
  }
  if (!cityName) {
    return { province: province.name, city: "", district: "", matched: true };
  }

  const city = province.cities.find((item) => item.name === cityName);
  if (!city) {
    return { province: "", city: "", district: "", matched: false };
  }
  if (!districtName) {
    return { province: province.name, city: city.name, district: "", matched: true };
  }

  if (!city.districts.includes(districtName)) {
    return { province: "", city: "", district: "", matched: false };
  }
  return {
    province: province.name,
    city: city.name,
    district: districtName,
    matched: true,
  };
}

/**
 * 拼接落盘路径（空段自动丢弃）。
 *
 * @param parts 三级名称（可只填前两级）
 * @returns 以 {@link CHINA_REGION_PATH_SEPARATOR} 连接的路径；全部为空时为空串
 */
export function joinChinaRegionPath(parts: {
  province?: string;
  city?: string;
  district?: string;
}): string {
  return [parts.province, parts.city, parts.district]
    .map((part) => (part ?? "").trim())
    .filter((part) => part.length > 0)
    .join(CHINA_REGION_PATH_SEPARATOR);
}
