/*
 * vty_blake3_avx2.h — BLAKE3 8 路 AVX2 chunk 压缩（内部，不导出）
 *
 * 只负责连续 8 个完整 chunk 的 CV 计算；树合并与根标志仍由标量路径处理。
 * 调用方必须先通过 CPU 特性检测确认 AVX2 可用。
 */
#ifndef VTY_BLAKE3_AVX2_H
#define VTY_BLAKE3_AVX2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * data8: 8 个连续完整 chunk（8 × 1024B）
 * first_chunk: 第一个 chunk 的全局序号（进入压缩计数器）
 * out_cvs: 8 × 32B 的 chunk CV
 * 返回 0 成功。
 */
int vty_blake3_chunk_cv8_avx2(const uint8_t *data8, uint32_t first_chunk,
                              uint8_t out_cvs[8][32]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_BLAKE3_AVX2_H */
