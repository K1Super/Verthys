/*
 * vty_util.h — 子系统的内存与常量时间工具（内部，不导出）
 */
#ifndef VTY_UTIL_H
#define VTY_UTIL_H

#include "vty_types.h"

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

/*
 * 长期密钥材料专用分配（进程级共享安全分配器 + memory_guard 注册）：
 *   - 独立 VirtualAlloc 区段 + NOACCESS 边界页 + VirtualLock；
 *   - 分配成功后登记到 memory_guard，应急 KILL 时统一零化；
 *   - 失败返回 NULL（调用方映射为 VTY_E_RESOURCE，禁止回退普通堆）。
 * 仅用于 VtyVault / VtyStore / 轮换口令等含密钥对象；临时解析缓冲
 * 继续使用 vty_alloc，避免把一次性数据抬进锁页预算。
 * guard_name 仅用于内部诊断，不含敏感数据，可为 NULL。
 */
void *vty_secure_alloc(size_t n, const char *guard_name);

/* 释放长期密钥材料：先注销 memory_guard 登记，再清零并归还安全区段。
 * 指针必须来自 vty_secure_alloc；NULL 为空操作。 */
void vty_secure_free(void *p);

/* 系统 CSPRNG；熵源失败时中止进程（libsodium 语义），调用方无需判错 */
void vty_random(uint8_t *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* VTY_UTIL_H */
