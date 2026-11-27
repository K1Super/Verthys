/*
 * util_identity.c — SID 查询/比较/哈希与特权启用
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

int vty_get_well_known_sid(WELL_KNOWN_SID_TYPE type, PSID sid, DWORD *len)
{
    DWORD cap;

    if (sid == NULL || len == NULL) return -1;
    cap = *len;
    if (cap < SECURITY_MAX_SID_SIZE) return -1;
    if (!CreateWellKnownSid(type, NULL, sid, &cap)) return -1;
    *len = cap;
    return 0;
}

int vty_sid_equal(PSID a, PSID b)
{
    return (a != NULL && b != NULL && EqualSid(a, b)) ? 1 : 0;
}

int vty_sid_hash(PSID sid, uint8_t out[32])
{
    DWORD len;

    if (sid == NULL || out == NULL) return -1;
    len = GetLengthSid(sid);
    if (len == 0) return -1;
    return vty_sha256((const uint8_t *)sid, (size_t)len, out);
}

int vty_sid_hash_log_hex(const uint8_t hash[32],
                         wchar_t out[VTY_SID_LOG_HEX_CHARS + 1u])
{
    static const wchar_t hex[] = L"0123456789abcdef";
    size_t i;

    if (hash == NULL || out == NULL) return -1;
    for (i = 0; i < VTY_SID_LOG_HEX_CHARS / 2u; i++) {
        out[i * 2u] = hex[(hash[i] >> 4) & 0x0Fu];
        out[i * 2u + 1u] = hex[hash[i] & 0x0Fu];
    }
    out[VTY_SID_LOG_HEX_CHARS] = L'\0';
    return 0;
}

int vty_enable_privilege(const wchar_t *name)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    DWORD err;

    if (name == NULL) return -1;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return -1;
    }
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(token);
        return -1;
    }
    memset(&tp, 0, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(token);
        return -1;
    }
    err = GetLastError();
    CloseHandle(token);
    return err == ERROR_SUCCESS ? 0 : -1;
}
