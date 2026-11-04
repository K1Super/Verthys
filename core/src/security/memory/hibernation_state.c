/*
 * hibernation_state.c — 系统休眠状态注册表查询
 *
 * 只使用 RegGetValueW（普通用户可读，KEY_WOW64_64KEY 固定 64 位视图），
 * 不打开/写入任何键。缺失或读取失败均返回 UNKNOWN，避免把"没有读到"
 * 误当成"休眠已禁用"而给出虚假阻断。
 */
#include "hibernation_state.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define HIB_POWER_KEY L"SYSTEM\\CurrentControlSet\\Control\\Power"

uint32_t hibernation_state_parse(int present, uint32_t value)
{
    if (!present) return HIBERNATION_STATE_UNKNOWN;
    return value != 0u ? HIBERNATION_STATE_ENABLED : HIBERNATION_STATE_DISABLED;
}

static int read_power_dword(const wchar_t *name, uint32_t *out_value)
{
    DWORD value = 0;
    DWORD cb = sizeof(value);

    if (name == NULL || out_value == NULL) return 0;

    LSTATUS st = RegGetValueW(HKEY_LOCAL_MACHINE, HIB_POWER_KEY, name,
                              RRF_RT_REG_DWORD | KEY_WOW64_64KEY,
                              NULL, &value, &cb);
    if (st != ERROR_SUCCESS || cb != sizeof(value)) {
        return 0;
    }
    *out_value = (uint32_t)value;
    return 1;
}

uint32_t hibernation_state_query(void)
{
    uint32_t value = 0;

    if (read_power_dword(L"HibernateEnabled", &value)) {
        return hibernation_state_parse(1, value);
    }
    if (read_power_dword(L"HibernateEnabledDefault", &value)) {
        return hibernation_state_parse(1, value);
    }
    return HIBERNATION_STATE_UNKNOWN;
}
