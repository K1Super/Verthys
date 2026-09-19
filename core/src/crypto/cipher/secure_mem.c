/*
 * secure_mem.c — 内存安全原语实现（内部，不导出）
 *
 * - verthys_secure_zero：基于 SecureZeroMemory，编译器不可优化消除
 * - verthys_lock_memory / verthys_unlock_memory：VirtualLock/VirtualUnlock，
 *   防止密钥所在内存页被换页到磁盘（内存保护要求）
 */
#include "verthys_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

void verthys_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) return;
    SecureZeroMemory(ptr, len);
}

int verthys_lock_memory(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) return 0;
    return VirtualLock(ptr, len) ? 0 : 1;
}

int verthys_unlock_memory(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) return 0;
    return VirtualUnlock(ptr, len) ? 0 : 1;
}
