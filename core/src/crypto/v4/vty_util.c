/*
 * vty_util.c — v4 子系统的内存与常量时间工具实现
 */
#include "vty_util.h"
#include "verthys_internal.h"
#include "verthys_crypto.h"

#include <stdlib.h>

void vty_secure_zero(void *p, size_t n)
{
    verthys_secure_zero(p, n);
}

int vty_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    size_t i;
    if (a == NULL || b == NULL) return 1;
    for (i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    /* 把任意非零值收敛到 1，避免调用方按位判定时被部分匹配误导 */
    return diff != 0;
}

void vty_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

void vty_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

void vty_put_u64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

uint16_t vty_get_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

uint32_t vty_get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t vty_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

void *vty_alloc(size_t n)
{
    if (n == 0) return NULL;
    return calloc(1, n);
}

void vty_free(void *p, size_t n)
{
    if (p == NULL) return;
    vty_secure_zero(p, n);
    free(p);
}

void vty_random(uint8_t *p, size_t n)
{
    verthys_random_bytes(p, n);
}

/* 栈帧残留擦除。
 * 敏感数据除了出现在显式局部缓冲区，还可能被编译器溢出到栈槽位
 * （寄存器压力下的临时副本）；这些槽位不受任何缓冲区清零覆盖，
 * 解锁一次后会在未使用的栈区留下密钥。锁定/释放时向下擦除一段
 * 栈，覆盖此前深层调用帧用过的区域。
 * volatile 写入确保 Release 下不会被当作死存储优化掉。 */
#if defined(_MSC_VER)
#define VTY_NOINLINE __declspec(noinline)
#else
#define VTY_NOINLINE __attribute__((noinline))
#endif

static VTY_NOINLINE void wipe_stack_down(unsigned depth)
{
    volatile uint8_t buf[4096];
    size_t i;

    for (i = 0; i < sizeof(buf); i++) buf[i] = 0;
    if (depth > 1u) wipe_stack_down(depth - 1u);
    if (buf[0] != 0) return; /* 触碰首字节，确保缓冲区不被省略 */
}

void vty_wipe_stack(void)
{
    wipe_stack_down(16u);
}
