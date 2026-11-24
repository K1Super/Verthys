/*
 * tests/kernel-guard/kg_a14_probe.c — same-user A14 first-moment probe.
 *
 * Polls for the suspended dummy image and attempts OpenProcess(VM_READ) +
 * ReadProcessMemory as soon as it appears. Runs as the normal user, not the
 * creator/parent.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef LONG NTSTATUS;
typedef struct _PROCESS_BASIC_INFORMATION_LOCAL {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_LOCAL;
typedef NTSTATUS(NTAPI *NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG,
                                                     PULONG);

static void write_marker(const wchar_t *path)
{
    FILE *file = NULL;
    if (path == NULL) return;
    if (_wfopen_s(&file, path, L"w, ccs=UTF-8") == 0 && file != NULL) {
        fwprintf(file, L"1\n");
        fclose(file);
    }
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *output = L"a14.json";
    const wchar_t *polling = NULL;
    const wchar_t *image = L"kg_dummy_worker.exe";
    DWORD timeout_ms = 30000;
    ULONGLONG start_tick = GetTickCount64();
    DWORD pid = 0;
    DWORD target_pid = 0;
    int found = 0;
    int open_ok = 0;
    int op_ok = 0;
    int peb_ok = 0;
    DWORD error = 0;
    ULONGLONG elapsed = 0;
    int arg;
    FILE *file = NULL;
    HMODULE ntdll;
    NtQueryInformationProcessFn query_info;
    PROCESS_BASIC_INFORMATION_LOCAL pbi;
    ULONG returned = 0;
    PVOID peb = NULL;

    for (arg = 1; arg < argc; arg++) {
        if (_wcsicmp(argv[arg], L"--out") == 0 && arg + 1 < argc) {
            output = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--polling") == 0 && arg + 1 < argc) {
            polling = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--image") == 0 && arg + 1 < argc) {
            image = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--timeout") == 0 && arg + 1 < argc) {
            timeout_ms = (DWORD)_wtoi(argv[++arg]) * 1000u;
        } else if (_wcsicmp(argv[arg], L"--pid") == 0 && arg + 1 < argc) {
            target_pid = (DWORD)_wtoi(argv[++arg]);
        }
    }

    write_marker(polling);
    ntdll = GetModuleHandleW(L"ntdll.dll");
    query_info = (NtQueryInformationProcessFn)GetProcAddress(
        ntdll, "NtQueryInformationProcess");

    while ((GetTickCount64() - start_tick) < timeout_ms) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snapshot, &entry)) {
                do {
                    if ((target_pid == 0 ||
                         entry.th32ProcessID == target_pid) &&
                        _wcsicmp(entry.szExeFile, image) == 0) {
                        pid = entry.th32ProcessID;
                        found = 1;
                        break;
                    }
                } while (Process32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
        if (found) break;
        Sleep(50);
    }

    if (found) {
        HANDLE query = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (query != NULL && query_info != NULL) {
            memset(&pbi, 0, sizeof(pbi));
            if (query_info(query, 0, &pbi, (ULONG)sizeof(pbi), &returned) >= 0 &&
                pbi.PebBaseAddress != NULL) {
                peb = pbi.PebBaseAddress;
                peb_ok = 1;
            }
            CloseHandle(query);
        }
        {
            HANDLE handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (handle == NULL) {
                error = GetLastError();
                open_ok = 0;
                op_ok = 0;
            } else {
                unsigned char buffer[32];
                SIZE_T read_bytes = 0;
                open_ok = 1;
                if (peb_ok) {
                    op_ok = ReadProcessMemory(handle, peb, buffer,
                                              sizeof(buffer), &read_bytes)
                                ? 1 : 0;
                    error = op_ok ? 0 : GetLastError();
                } else {
                    /*
                     * 目标地址不可得时无法证伪；按失败处理，避免把
                     * 无效地址导致的读取失败误判为保护生效。
                     */
                    op_ok = 1;
                    error = ERROR_INVALID_DATA;
                }
                CloseHandle(handle);
            }
        }
        elapsed = GetTickCount64() - start_tick;
    }

    if (_wfopen_s(&file, output, L"wb") == 0 && file != NULL) {
        fprintf(file, "{\n");
        fprintf(file, "  \"status\": \"%s\",\n",
                (found && (!open_ok || (peb_ok && !op_ok))) ? "PASS" : "FAIL");
        fprintf(file, "  \"found\": %s,\n", found ? "true" : "false");
        fprintf(file, "  \"pid\": %lu,\n", (unsigned long)pid);
        fprintf(file, "  \"peb_ok\": %s,\n", peb_ok ? "true" : "false");
        fprintf(file, "  \"open_ok\": %s,\n", open_ok ? "true" : "false");
        fprintf(file, "  \"op_ok\": %s,\n", op_ok ? "true" : "false");
        fprintf(file, "  \"error\": %lu,\n", (unsigned long)error);
        fprintf(file, "  \"elapsed_ms\": %llu\n", (unsigned long long)elapsed);
        fprintf(file, "}\n");
        fclose(file);
    }
    wprintf(L"kg_a14_probe: found=%d pid=%lu open=%d peb=%d op=%d error=%lu\n",
            found, (unsigned long)pid, open_ok, peb_ok, op_ok,
            (unsigned long)error);
    return (found && (!open_ok || (peb_ok && !op_ok))) ? 0 : 1;
}
