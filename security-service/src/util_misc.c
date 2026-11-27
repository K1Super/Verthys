/*
 * util_misc.c — 时间与安全清零
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

uint64_t vty_utc_now_100ns(void)
{
    FILETIME ft;

    GetSystemTimePreciseAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
}

uint64_t vty_unix_seconds_now(void)
{
    const uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t ticks = vty_utc_now_100ns();

    if (ticks <= epoch_offset) return 0;
    return (ticks - epoch_offset) / 10000000ULL;
}

void vty_secure_zero(void *p, size_t n)
{
    if (p != NULL && n > 0) {
        SecureZeroMemory(p, n);
    }
}
