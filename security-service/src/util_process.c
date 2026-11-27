/*
 * util_process.c — 进程映像路径查询
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

int vty_get_process_image_path(HANDLE process, wchar_t *out, size_t cap)
{
    DWORD size;

    if (process == NULL || out == NULL || cap == 0) return -1;
    size = (DWORD)cap;
    if (!QueryFullProcessImageNameW(process, 0, out, &size)) return -1;
    out[cap - 1u] = L'\0';
    return 0;
}

int vty_get_self_image_path(wchar_t *out, size_t cap)
{
    DWORD size;

    if (out == NULL || cap == 0) return -1;
    size = GetModuleFileNameW(NULL, out, (DWORD)cap);
    if (size == 0 || size >= cap) return -1;
    out[cap - 1u] = L'\0';
    return 0;
}
