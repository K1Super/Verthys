/*
 * tests/kernel-guard/kg_create_probe.c — SYSTEM child-process creation control.
 * Runs without loading or touching the driver.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static void json_escape(const char *src, char *dst, size_t cap)
{
    size_t out = 0;
    size_t i;
    if (dst == NULL || cap == 0) return;
    for (i = 0; src != NULL && src[i] != '\0' && out + 2 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\\' || c == '"') {
            dst[out++] = '\\';
            dst[out++] = (char)c;
        } else if (c < 0x20) {
            dst[out++] = '?';
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *dummy = NULL;
    const wchar_t *output = L"kg-create.json";
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD error = 0;
    int created = 0;
    int arg;
    FILE *file = NULL;
    char dummy_utf8[512];
    char dummy_json[1024];

    memset(&process, 0, sizeof(process));
    for (arg = 1; arg < argc; arg++) {
        if (_wcsicmp(argv[arg], L"--dummy") == 0 && arg + 1 < argc) {
            dummy = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--out") == 0 && arg + 1 < argc) {
            output = argv[++arg];
        }
    }
    if (dummy == NULL) return 2;

    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    created = CreateProcessW(dummy, NULL, NULL, NULL, FALSE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                             &startup, &process) ? 1 : 0;
    if (!created) error = GetLastError();
    if (created) {
        (void)TerminateProcess(process.hProcess, 0);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }

    if (_wfopen_s(&file, output, L"wb") != 0 || file == NULL) return 3;
    WideCharToMultiByte(CP_UTF8, 0, dummy, -1, dummy_utf8,
                        (int)sizeof(dummy_utf8), NULL, NULL);
    json_escape(dummy_utf8, dummy_json, sizeof(dummy_json));
    fprintf(file, "{\n");
    fprintf(file, "  \"status\": \"%s\",\n", created ? "PASS" : "FAIL");
    fprintf(file, "  \"dummy\": \"%s\",\n", dummy_json);
    fprintf(file, "  \"created\": %s,\n", created ? "true" : "false");
    fprintf(file, "  \"error\": %lu,\n", (unsigned long)error);
    fprintf(file, "  \"process_id\": %lu\n",
            (unsigned long)(created ? process.dwProcessId : 0));
    fprintf(file, "}\n");
    fclose(file);
    wprintf(L"kg_create_probe: created=%d error=%lu\n", created,
            (unsigned long)error);
    return created ? 0 : 1;
}
