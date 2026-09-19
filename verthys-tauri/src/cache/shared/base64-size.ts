/*
 * cache/shared/base64-size.ts — Base64 原始字节大小精确估算（单一权威源）
 *
 * ★ cache-coordinator 重构实现 + batch-cache-coordinator 重构实现共同修正项：
 *   旧实现 `Math.floor(dataB64.length * 3 / 4)` 未处理 Base64 填充字符 `=`，
 *   末尾为 `==` 时估算偏大。两套实现各自定义了相同修正函数，此处收敛为
 *   共享模块（DRY），供两个协调器统一引用。
 *
 * 精确公式（标准 padded base64，长度恒为 4 的倍数）：
 *   bytes = floor(len × 3 / 4) − padding（'==' 记 2，'=' 记 1）
 *   例："AB==" → 3 − 2 = 1 字节；"ABC=" → 3 − 1 = 2 字节
 *
 * 防御式下限：对非法长度（非 4 的倍数的畸形输入）clamp 到 0，
 *   杜绝 dataSize 出现负数污染摘要显示。
 */
export function estimateBase64Size(base64: string): number {
  if (base64.length === 0) return 0;
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((base64.length * 3) / 4) - padding);
}
