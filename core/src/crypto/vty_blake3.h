/*
 * vty_blake3.h — BLAKE3 32 字节摘要（内部，不导出）
 *
 * 为什么自实现：容器头部哈希与文件清单需要与规范一致的 BLAKE3；
 * 现有依赖只提供 BLAKE2b。实现范围限定为“一次性 32B 摘要”，
 * 不做流式与密钥模式，减少未使用代码的攻击面。
 */
#ifndef VTY_BLAKE3_H
#define VTY_BLAKE3_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* data 可为 NULL 仅当 len==0。返回 VtyResult。 */
int vty_blake3_32(const uint8_t *data, size_t len, uint8_t out[VTY_HASH_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_BLAKE3_H */
