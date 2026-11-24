/*
 * tests/kernel-guard/kg_attack.c — same-user attack probes against a protected
 * suspended dummy. Runs with the normal user token, not the parent creator.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
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
typedef NTSTATUS(NTAPI *NtSuspendProcessFn)(HANDLE);
typedef NTSTATUS(NTAPI *NtResumeProcessFn)(HANDLE);
typedef BOOL(WINAPI *MiniDumpWriteDumpFn)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                          PVOID, PVOID, PVOID);

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

static void write_case(FILE *file, int *first, const char *id,
                       int open_ok, DWORD open_error, int op_ok,
                       DWORD op_error, const char *detail)
{
    char detail_json[256];
    int pass = (!open_ok) || (!op_ok);
    json_escape(detail, detail_json, sizeof(detail_json));
    if (!*first) fprintf(file, ",\n");
    *first = 0;
    fprintf(file,
            "    {\"id\":\"%s\",\"open_ok\":%s,\"open_error\":%lu,"
            "\"op_ok\":%s,\"op_error\":%lu,\"status\":\"%s\","
            "\"detail\":\"%s\"}",
            id, open_ok ? "true" : "false", (unsigned long)open_error,
            op_ok ? "true" : "false", (unsigned long)op_error,
            pass ? "PASS" : "FAIL", detail_json);
}

int wmain(int argc, wchar_t **argv)
{
    DWORD pid = 0;
    const wchar_t *output = L"attack.json";
    const wchar_t *done = NULL;
    HANDLE query = NULL;
    PROCESS_BASIC_INFORMATION_LOCAL pbi;
    ULONG returned = 0;
    PVOID peb = NULL;
    HMODULE ntdll;
    NtQueryInformationProcessFn query_info;
    NtSuspendProcessFn suspend_process;
    NtResumeProcessFn resume_process;
    FILE *file = NULL;
    int first = 1;
    int all_pass = 1;
    int arg;
    DWORD open_error;
    DWORD op_error;
    HANDLE handle;

    memset(&pbi, 0, sizeof(pbi));
    for (arg = 1; arg < argc; arg++) {
        if (_wcsicmp(argv[arg], L"--pid") == 0 && arg + 1 < argc) {
            pid = (DWORD)_wtoi(argv[++arg]);
        } else if (_wcsicmp(argv[arg], L"--out") == 0 && arg + 1 < argc) {
            output = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--done") == 0 && arg + 1 < argc) {
            done = argv[++arg];
        }
    }
    if (pid == 0) return 2;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    query_info = (NtQueryInformationProcessFn)GetProcAddress(
        ntdll, "NtQueryInformationProcess");
    suspend_process = (NtSuspendProcessFn)GetProcAddress(ntdll,
                                                         "NtSuspendProcess");
    resume_process = (NtResumeProcessFn)GetProcAddress(ntdll,
                                                       "NtResumeProcess");

    query = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (query != NULL && query_info != NULL) {
        if (query_info(query, 0, &pbi, (ULONG)sizeof(pbi), &returned) >= 0) {
            peb = pbi.PebBaseAddress;
        }
        CloseHandle(query);
    }

    if (_wfopen_s(&file, output, L"wb") != 0 || file == NULL) return 3;
    fprintf(file, "{\n  \"pid\": %lu,\n  \"cases\": [\n", (unsigned long)pid);

    {
        unsigned char buffer[32];
        SIZE_T read_bytes = 0;
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A1_read", 0, open_error, 0, 0,
                       "OpenProcess(PROCESS_VM_READ) denied");
        } else {
            BOOL ok = ReadProcessMemory(handle, peb, buffer, sizeof(buffer),
                                        &read_bytes);
            op_error = ok ? 0 : GetLastError();
            if (ok) all_pass = 0;
            write_case(file, &first, "A1_read", 1, 0, ok ? 1 : 0, op_error,
                       ok ? "ReadProcessMemory unexpectedly succeeded"
                          : "ReadProcessMemory denied");
            CloseHandle(handle);
        }
    }

    {
        unsigned char buffer[32];
        SIZE_T written = 0;
        memset(buffer, 0x41, sizeof(buffer));
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A2_write", 0, open_error, 0, 0,
                       "OpenProcess(VM_WRITE) denied");
        } else {
            BOOL ok = WriteProcessMemory(handle, peb, buffer, sizeof(buffer),
                                         &written);
            op_error = ok ? 0 : GetLastError();
            if (ok) all_pass = 0;
            write_case(file, &first, "A2_write", 1, 0, ok ? 1 : 0, op_error,
                       ok ? "WriteProcessMemory unexpectedly succeeded"
                          : "WriteProcessMemory denied");
            CloseHandle(handle);
        }
    }

    {
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                 PROCESS_VM_WRITE,
                             FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A3_remote_thread", 0, open_error, 0, 0,
                       "OpenProcess(CREATE_THREAD) denied");
        } else {
            HANDLE thread = CreateRemoteThread(
                handle, NULL, 0, (LPTHREAD_START_ROUTINE)peb, NULL,
                CREATE_SUSPENDED, NULL);
            op_error = thread ? 0 : GetLastError();
            if (thread) all_pass = 0;
            write_case(file, &first, "A3_remote_thread", 1, 0,
                       thread ? 1 : 0, op_error,
                       thread ? "CreateRemoteThread unexpectedly succeeded"
                              : "CreateRemoteThread denied");
            if (thread) CloseHandle(thread);
            CloseHandle(handle);
        }
    }

    {
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A5_suspend", 0, open_error, 0, 0,
                       "OpenProcess(SUSPEND_RESUME) denied");
        } else {
            NTSTATUS status = suspend_process ? suspend_process(handle) : -1;
            op_error = status >= 0 ? 0 : (DWORD)status;
            if (status >= 0) all_pass = 0;
            write_case(file, &first, "A5_suspend", 1, 0, status >= 0 ? 1 : 0,
                       op_error, status >= 0
                                     ? "NtSuspendProcess unexpectedly succeeded"
                                     : "NtSuspendProcess denied");
            if (status >= 0 && resume_process) (void)resume_process(handle);
            CloseHandle(handle);
        }
    }

    {
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A6_terminate", 0, open_error, 0, 0,
                       "OpenProcess(PROCESS_TERMINATE) denied");
        } else {
            BOOL ok = TerminateProcess(handle, 0);
            op_error = ok ? 0 : GetLastError();
            if (ok) all_pass = 0;
            write_case(file, &first, "A6_terminate", 1, 0, ok ? 1 : 0,
                       op_error, ok ? "TerminateProcess unexpectedly succeeded"
                                    : "TerminateProcess denied");
            CloseHandle(handle);
        }
    }

    {
        open_error = 0;
        op_error = 0;
        BOOL ok = DebugActiveProcess(pid);
        op_error = ok ? 0 : GetLastError();
        if (ok) {
            all_pass = 0;
            (void)DebugActiveProcessStop(pid);
        }
        write_case(file, &first, "A7_debug", 1, 0, ok ? 1 : 0, op_error,
                   ok ? "DebugActiveProcess unexpectedly succeeded"
                      : "DebugActiveProcess denied");
    }

    {
        THREADENTRY32 entry;
        DWORD thread_id = 0;
        HANDLE snapshot;
        open_error = 0;
        op_error = 0;
        entry.dwSize = sizeof(entry);
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID == pid) {
                        thread_id = entry.th32ThreadID;
                        break;
                    }
                } while (Thread32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
        if (thread_id == 0) {
            all_pass = 0;
            write_case(file, &first, "A4_queue_apc", 1, 0, 1,
                       ERROR_NOT_FOUND, "No target thread found");
        } else {
            handle = OpenThread(THREAD_SET_CONTEXT, FALSE, thread_id);
            if (handle == NULL) {
                open_error = GetLastError();
                write_case(file, &first, "A4_queue_apc", 0, open_error, 0, 0,
                           "OpenThread(THREAD_SET_CONTEXT) denied");
            } else {
                DWORD queued = QueueUserAPC((PAPCFUNC)peb, handle, 0);
                op_error = queued ? 0 : GetLastError();
                if (queued) all_pass = 0;
                write_case(file, &first, "A4_queue_apc", 1, 0, queued ? 1 : 0,
                           op_error,
                           queued ? "QueueUserAPC unexpectedly succeeded"
                                  : "QueueUserAPC denied");
                CloseHandle(handle);
            }
        }
    }

    {
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A8_minidump", 0, open_error, 0, 0,
                       "OpenProcess(VM_READ) denied");
        } else {
            HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
            MiniDumpWriteDumpFn dump_fn = dbghelp ?
                (MiniDumpWriteDumpFn)GetProcAddress(dbghelp, "MiniDumpWriteDump") : NULL;
            if (dump_fn == NULL) {
                all_pass = 0;
                write_case(file, &first, "A8_minidump", 1, 0, 1,
                           ERROR_PROC_NOT_FOUND, "dbghelp unavailable");
            } else {
                wchar_t dump_path[600];
                HANDLE dump_file;
                swprintf_s(dump_path, 600, L"%ls.dmp", output);
                dump_file = CreateFileW(dump_path, GENERIC_WRITE, 0, NULL,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY,
                                        NULL);
                if (dump_file == INVALID_HANDLE_VALUE) {
                    all_pass = 0;
                    write_case(file, &first, "A8_minidump", 1, 0, 1,
                               GetLastError(), "cannot create dump file");
                } else {
                    BOOL ok = dump_fn(handle, pid, dump_file, MiniDumpNormal,
                                      NULL, NULL, NULL);
                    op_error = ok ? 0 : GetLastError();
                    if (ok) all_pass = 0;
                    write_case(file, &first, "A8_minidump", 1, 0, ok ? 1 : 0,
                               op_error,
                               ok ? "MiniDumpWriteDump unexpectedly succeeded"
                                  : "MiniDumpWriteDump denied");
                    CloseHandle(dump_file);
                    DeleteFileW(dump_path);
                }
            }
            if (dbghelp) FreeLibrary(dbghelp);
            CloseHandle(handle);
        }
    }

    {
        HANDLE event;
        HANDLE duplicate = NULL;
        open_error = 0;
        op_error = 0;
        handle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (handle == NULL) {
            open_error = GetLastError();
            write_case(file, &first, "A9_duplicate_handle", 0, open_error, 0, 0,
                       "OpenProcess(PROCESS_DUP_HANDLE) denied");
        } else {
            event = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (event == NULL) {
                all_pass = 0;
                write_case(file, &first, "A9_duplicate_handle", 1, 0, 1,
                           GetLastError(), "cannot create source event");
            } else {
                BOOL ok = DuplicateHandle(GetCurrentProcess(), event, handle,
                                          &duplicate, 0, FALSE,
                                          DUPLICATE_SAME_ACCESS);
                op_error = ok ? 0 : GetLastError();
                if (ok) all_pass = 0;
                write_case(file, &first, "A9_duplicate_handle", 1, 0,
                           ok ? 1 : 0, op_error,
                           ok ? "DuplicateHandle unexpectedly succeeded"
                              : "DuplicateHandle denied");
                if (duplicate != NULL) CloseHandle(duplicate);
                CloseHandle(event);
            }
            CloseHandle(handle);
        }
    }

    fprintf(file, "\n  ],\n  \"status\": \"%s\"\n}\n",
            all_pass ? "PASS" : "FAIL");
    fclose(file);

    if (done != NULL) {
        HANDLE done_file = CreateFileW(done, GENERIC_WRITE, FILE_SHARE_READ,
                                       NULL, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL, NULL);
        if (done_file != INVALID_HANDLE_VALUE) CloseHandle(done_file);
    }
    wprintf(L"kg_attack: pid=%lu status=%hs\n", (unsigned long)pid,
            all_pass ? "PASS" : "FAIL");
    return all_pass ? 0 : 1;
}
