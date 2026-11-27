/*
 * util_registry.c — 注册表值读写与删除
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

int vty_registry_read_dword(HKEY key, const wchar_t *name, DWORD *out)
{
    DWORD type = 0;
    DWORD size = 0;
    DWORD value = 0;

    if (key == NULL || name == NULL || out == NULL) return -1;
    size = sizeof(value);
    if (RegQueryValueExW(key, name, NULL, &type, (LPBYTE)&value, &size) !=
            ERROR_SUCCESS ||
        type != REG_DWORD || size != sizeof(value)) {
        return -1;
    }
    *out = value;
    return 0;
}

int vty_registry_write_dword(HKEY key, const wchar_t *name, DWORD value)
{
    if (key == NULL || name == NULL) return -1;
    return RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&value,
                          sizeof(value)) == ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_read_qword(HKEY key, const wchar_t *name, uint64_t *out)
{
    DWORD type = 0;
    DWORD size = 0;
    uint64_t value = 0;

    if (key == NULL || name == NULL || out == NULL) return -1;
    size = sizeof(value);
    if (RegQueryValueExW(key, name, NULL, &type, (LPBYTE)&value, &size) !=
            ERROR_SUCCESS ||
        type != REG_QWORD || size != sizeof(value)) {
        return -1;
    }
    *out = value;
    return 0;
}

int vty_registry_write_qword(HKEY key, const wchar_t *name, uint64_t value)
{
    if (key == NULL || name == NULL) return -1;
    return RegSetValueExW(key, name, 0, REG_QWORD, (const BYTE *)&value,
                          sizeof(value)) == ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_read_string(HKEY key, const wchar_t *name,
                             wchar_t *out, size_t cap)
{
    DWORD type = 0;
    DWORD size = 0;

    if (key == NULL || name == NULL || out == NULL || cap == 0) return -1;
    size = (DWORD)(cap * sizeof(wchar_t));
    if (RegQueryValueExW(key, name, NULL, &type, (LPBYTE)out, &size) !=
            ERROR_SUCCESS ||
        type != REG_SZ || size < sizeof(wchar_t) ||
        size > cap * sizeof(wchar_t)) {
        return -1;
    }
    out[cap - 1u] = L'\0';
    return 0;
}

int vty_registry_write_string(HKEY key, const wchar_t *name,
                              const wchar_t *value)
{
    DWORD size;

    if (key == NULL || name == NULL || value == NULL) return -1;
    size = (DWORD)((wcslen(value) + 1u) * sizeof(wchar_t));
    return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, size) ==
                   ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_read_binary(HKEY key, const wchar_t *name,
                             uint8_t *out, DWORD cap, DWORD *len)
{
    DWORD type = 0;
    DWORD size = cap;

    if (key == NULL || name == NULL || out == NULL || len == NULL) return -1;
    if (RegQueryValueExW(key, name, NULL, &type, out, &size) != ERROR_SUCCESS ||
        type != REG_BINARY || size > cap) {
        return -1;
    }
    *len = size;
    return 0;
}

int vty_registry_write_binary(HKEY key, const wchar_t *name,
                              const uint8_t *data, DWORD len)
{
    if (key == NULL || name == NULL || data == NULL || len == 0) return -1;
    return RegSetValueExW(key, name, 0, REG_BINARY, data, len) == ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_delete_value(HKEY key, const wchar_t *name)
{
    LONG rc;

    if (key == NULL || name == NULL) return -1;
    rc = RegDeleteValueW(key, name);
    return (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) ? 0 : -1;
}
