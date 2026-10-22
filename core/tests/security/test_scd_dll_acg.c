/*
 * test_scd_dll_acg.c — 生产 DLL 在 ACG 下的防御状态验证
 *
 * 目标：
 *   在启用 ACG 的独立进程中加载 verthys.dll，调用 Verthys_Init 与
 *   Verthys_GetSecurityStatus，确认 IAT/Inline Hook 路径达到 BLOCKED。
 *
 * 前置条件：
 *   - 输入参数为 verthys.dll 的绝对路径；
 *   - 系统支持 ProcessDynamicCodePolicy；不支持时输出 SKIP。
 *
 * 通过判据：
 *   1. ACG 策略写入成功且读回确认；
 *   2. DLL 加载、Verthys_Init、状态查询均成功；
 *   3. path_state 的 IAT/Inline Hook 项为 BLOCKED。
 *
 * 独立性：
 *   本程序不链接核心对象库，只通过导出符号驱动生产 DLL，
 *   因此验证对象与 worker 实际加载的二进制一致。
 */
#include "verthys.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define SCD_POLICY_DYNAMIC_CODE 2

typedef BOOL (WINAPI *ScdSetMitigation_t)(int, PVOID, SIZE_T);
typedef BOOL (WINAPI *ScdGetMitigation_t)(HANDLE, int, PVOID, SIZE_T);

typedef struct ScdDynamicCodePolicy {
    DWORD Flags;
} ScdDynamicCodePolicy;

typedef VerthysResult (VERTHYS_CALL *ScdInitFn)(VerthysHandle *out_handle);
typedef VerthysResult (VERTHYS_CALL *ScdDeinitFn)(VerthysHandle handle);
typedef VerthysResult (VERTHYS_CALL *ScdStatusFn)(
    VerthysHandle handle, VerthysSecurityStatus *out_status);

/*
 * 启用 ACG。
 * 返回 1 = 策略已生效；0 = 当前系统不支持；-1 = 写入或读回失败。
 */
static int scd_enable_acg(DWORD *error_out)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32 == NULL) {
        *error_out = GetLastError();
        return -1;
    }

    ScdSetMitigation_t set_policy =
        (ScdSetMitigation_t)(void *)GetProcAddress(k32, "SetProcessMitigationPolicy");
    if (set_policy == NULL) {
        *error_out = ERROR_CALL_NOT_IMPLEMENTED;
        return 0;
    }

    ScdDynamicCodePolicy desired;
    desired.Flags = 1u;
    if (!set_policy(SCD_POLICY_DYNAMIC_CODE, &desired, sizeof(desired))) {
        *error_out = GetLastError();
        if (*error_out == ERROR_NOT_SUPPORTED ||
            *error_out == ERROR_INVALID_PARAMETER ||
            *error_out == ERROR_CALL_NOT_IMPLEMENTED) {
            return 0;
        }
        return -1;
    }

    ScdGetMitigation_t get_policy =
        (ScdGetMitigation_t)(void *)GetProcAddress(k32, "GetProcessMitigationPolicy");
    if (get_policy != NULL) {
        ScdDynamicCodePolicy actual;
        memset(&actual, 0, sizeof(actual));
        if (get_policy(GetCurrentProcess(), SCD_POLICY_DYNAMIC_CODE,
                       &actual, sizeof(actual))) {
            if ((actual.Flags & 1u) == 0) {
                *error_out = ERROR_INVALID_STATE;
                return -1;
            }
        }
    }
    return 1;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2 || argv[1] == NULL || argv[1][0] == L'\0') {
        printf("FAIL: missing verthys.dll path\n");
        return 1;
    }

    DWORD error = 0;
    int acg = scd_enable_acg(&error);
    if (acg == 0) {
        printf("SKIP: ACG unsupported (error=%lu)\n", (unsigned long)error);
        return 0;
    }
    if (acg < 0) {
        printf("FAIL: ACG enable error=%lu\n", (unsigned long)error);
        return 2;
    }

    HMODULE dll = LoadLibraryW(argv[1]);
    if (dll == NULL) {
        printf("FAIL: LoadLibraryW error=%lu\n", (unsigned long)GetLastError());
        return 3;
    }

    ScdInitFn init =
        (ScdInitFn)(void *)GetProcAddress(dll, "Verthys_Init");
    ScdDeinitFn deinit =
        (ScdDeinitFn)(void *)GetProcAddress(dll, "Verthys_Deinit");
    ScdStatusFn status =
        (ScdStatusFn)(void *)GetProcAddress(dll, "Verthys_GetSecurityStatus");
    if (init == NULL || deinit == NULL || status == NULL) {
        printf("FAIL: missing required exports\n");
        FreeLibrary(dll);
        return 4;
    }

    VerthysHandle handle = NULL;
    VerthysResult r = init(&handle);
    if (r != VERTHYS_OK || handle == NULL) {
        printf("FAIL: Verthys_Init result=0x%08X\n", (unsigned)r);
        FreeLibrary(dll);
        return 5;
    }

    VerthysSecurityStatus st;
    memset(&st, 0, sizeof(st));
    r = status(handle, &st);
    if (r != VERTHYS_OK) {
        printf("FAIL: Verthys_GetSecurityStatus result=0x%08X\n", (unsigned)r);
        (void)deinit(handle);
        FreeLibrary(dll);
        return 6;
    }

    VerthysDefenseState iat = st.path_state[VERTHYS_DEFENSE_IAT_HOOK];
    if (iat != VERTHYS_DEFENSE_BLOCKED) {
        printf("FAIL: IAT/Inline Hook state=%d (expected %d)\n",
               (int)iat, (int)VERTHYS_DEFENSE_BLOCKED);
        (void)deinit(handle);
        FreeLibrary(dll);
        return 7;
    }

    printf("PASS: production DLL under ACG reports IAT/Inline Hook BLOCKED\n");
    (void)deinit(handle);
    FreeLibrary(dll);
    return 0;
}
