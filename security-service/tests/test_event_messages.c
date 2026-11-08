/*
 * test_event_messages.c — 验证服务 exe 内嵌的事件日志消息表可被 FormatMessage 解析
 *
 * 消息表由 mc.exe 生成并链接进 VerthysSecuritySvc.exe；本用例直接加载
 * 服务 exe 的只读资源，检查所有已使用事件 ID 都能返回非空描述。
 */
#include "test_common.h"
#include "service_util.h"

#include <stdio.h>
#include <string.h>

static int locate_service_exe(wchar_t *out, size_t cap)
{
    wchar_t self[VTY_PATH_MAX];
    wchar_t config[64];
    wchar_t *p;

    if (GetModuleFileNameW(NULL, self, VTY_PATH_MAX) == 0) return -1;
    self[VTY_PATH_MAX - 1u] = L'\0';
    p = wcsrchr(self, L'\\');          /* 去掉 exe 文件名 */
    if (p == NULL) return -1;
    *p = L'\0';
    p = wcsrchr(self, L'\\');          /* 当前目录 Debug/Release */
    if (p == NULL) return -1;
    if (vty_wide_copy(config, 64, p + 1) != 0) return -1;
    *p = L'\0';
    p = wcsrchr(self, L'\\');          /* 去掉 tests */
    if (p == NULL) return -1;
    *p = L'\0';

    return swprintf_s(out, cap, L"%ls\\%ls\\VerthysSecuritySvc.exe",
                      self, config) > 0
               ? 0
               : -1;
}

int test_event_messages_run(void)
{
    static const DWORD ids[] = {1000u, 1001u, 1002u, 2001u, 2002u,
                                3001u, 3002u, 3003u, 3004u, 3005u};
    static const wchar_t *expected[] = {
        L"Service started", L"Service stopped", L"Machine state initialized",
        L"Per-user failure quota", L"Machine failure budget",
        L"Machine state failure", L"Client request denied",
        L"Signature or pipe failure", L"Clock rollback",
        L"Service warning"};
    wchar_t service[VTY_PATH_MAX];
    HMODULE module;
    size_t i;

    printf("[ MSG ] event log message table\n");
    if (locate_service_exe(service, VTY_PATH_MAX) != 0 ||
        !vty_path_exists(service)) {
        printf("  [SKIP] service exe not found: %ls\n", service);
        SKIP("service exe not built next to tests; message table check skipped");
        return 0;
    }
    module = LoadLibraryExW(service, NULL,
                            LOAD_LIBRARY_AS_DATAFILE |
                                LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (module == NULL) {
        CHECK(0);
        return 0;
    }
    for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        wchar_t text[512];
        DWORD len;

        memset(text, 0, sizeof(text));
        len = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             module, ids[i], 0, text, 512u, NULL);
        g_test_checks++;
        if (len == 0 || text[0] == L'\0' ||
            wcsstr(text, expected[i]) == NULL ||
            wcsstr(text, L"SymbolicName=") != NULL) {
            g_test_failures++;
            printf("  [FAIL] event message id %lu invalid: %ls\n",
                   (unsigned long)ids[i], text);
        }
    }
    FreeLibrary(module);
    return 0;
}
