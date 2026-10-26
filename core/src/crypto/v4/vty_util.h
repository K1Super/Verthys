/*
 * vty_util.h — v4 子系统的内存与常量时间工具（内部，不导出）
 */
#ifndef VTY_UTIL_H
#define VTY_UTIL_H

#include "vty_v4_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 敏感缓冲清零：调用系统级不可优化擦除，失败路径也须先擦再返回 */
void vty_secure_zero(void *p, size_t n);

/* 向下擦除约 64 KiB 栈：覆盖深层调用帧遗留的密钥溢出槽 */
void vty_wipe_stack(void);

/* 恒定时间比较：0=相等；非 0=不等（不提前返回） */
int vty_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* 小端编解码（长度以调用方校验后的常量传入） */
void vty_put_u16(uint8_t *p, uint16_t v);
void vty_put_u32(uint8_t *p, uint32_t v);
void vty_put_u64(uint8_t *p, uint64_t v);
uint16_t vty_get_u16(const uint8_t *p);
uint32_t vty_get_u32(const uint8_t *p);
uint64_t vty_get_u64(const uint8_t *p);

/* 安全分配：失败返回 NULL；成功时内容已清零 */
void *vty_alloc(size_t n);
void vty_free(void *p, size_t n);

/* 系统 CSPRNG；熵源失败时中止进程（libsodium 语义），调用方无需判错 */
void vty_random(uint8_t *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* VTY_UTIL_H */
