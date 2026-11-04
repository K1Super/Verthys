/*
 * devtools/marker.ts — 开发悬浮球的构建标记
 *
 * 单独成模块的原因：生产剔除门禁需要扫描构建产物中的稳定字符串；
 * 标记绑定到悬浮球根节点属性，不能只放在 console 输出，生产混淆会移除
 * console 调用，导致门禁失去检测信号。
 */
export const DEVDOCK_MARKER = "__VERTHYS_DEV_DOCK__";
