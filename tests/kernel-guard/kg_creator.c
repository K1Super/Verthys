/*
 * tests/kernel-guard/kg_creator.c — user-owned suspended dummy creator.
 *
 * Waits for the SYSTEM probe to ARM the driver, then creates the dummy
 * suspended. The probe REGISTERs it using the identity written here.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int file_exists(const wchar_t *path)
{
    DWORD attr = GetFileAttributesW(path);
    return attr != INVALID_FILE_ATTRIBUTES;
}

static int wait_file(const wchar_t *path, int seconds)
{
    int i;
    for (i = 0; i < seconds * 10; i++) {
        if (file_exists(path)) return 0;
        Sleep(100);
    }
    return -1;
}

static int dos_to_nt(const wchar_t *dos, wchar_t *out, size_t cap)
{
    wchar_t drive[3];
    wchar_t device[1024];
    size_t device_len;
    size_t suffix_len;

    if (dos == NULL || out == NULL || cap == 0 || wcslen(dos) < 3) return -1;
    if (!((dos[0] >= L'A' && dos[0] <= L'Z') ||
          (dos[0] >= L'a' && dos[0] <= L'z')) ||
        dos[1] != L':' || dos[2] != L'\\') return -1;
    drive[0] = dos[0];
    drive[1] = L':';
    drive[2] = L'\0';
    memset(device, 0, sizeof(device));
    if (QueryDosDeviceW(drive, device,
                        (DWORD)(sizeof(device) / sizeof(device[0]))) == 0) {
        return -1;
    }
    device_len = wcslen(device);
    suffix_len = wcslen(dos + 2);
    if (device_len + suffix_len + 1u > cap) return -1;
    wcscpy_s(out, cap, device);
    wcscat_s(out, cap, dos + 2);
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *dummy = NULL;
    const wchar_t *output = L"creator.json";
    const wchar_t *armed = NULL;
    const wchar_t *done = NULL;
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    HANDLE job = NULL;
    int job_ok = 0;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
    FILETIME creation, exit_time, kernel_time, user_time;
    ULARGE_INTEGER quad;
    wchar_t nt[520];
    FILE *file = NULL;
    DWORD error = 0;
    int created = 0;
    int arg;

    memset(&process, 0, sizeof(process));
    memset(&creation, 0, sizeof(creation));
    memset(&exit_time, 0, sizeof(exit_time));
    memset(&kernel_time, 0, sizeof(kernel_time));
    memset(&user_time, 0, sizeof(user_time));
    for (arg = 1; arg < argc; arg++) {
        if (_wcsicmp(argv[arg], L"--dummy") == 0 && arg + 1 < argc) {
            dummy = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--out") == 0 && arg + 1 < argc) {
            output = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--armed") == 0 && arg + 1 < argc) {
            armed = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--done") == 0 && arg + 1 < argc) {
            done = argv[++arg];
        }
    }
    if (dummy == NULL || armed == NULL || done == NULL) return 2;

    if (wait_file(armed, 30) != 0) {
        wprintf(L"kg_creator: armed signal timeout\n");
        return 1;
    }

    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    created = CreateProcessW(dummy, NULL, NULL, NULL, FALSE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                             &startup, &process) ? 1 : 0;
    if (!created) {
        error = GetLastError();
    } else {
        if (!GetProcessTimes(process.hProcess, &creation, &exit_time,
                             &kernel_time, &user_time) ||
            dos_to_nt(dummy, nt, 520) != 0) {
            error = ERROR_INVALID_DATA;
            created = 0;
            (void)TerminateProcess(process.hProcess, 0);
        }
    }

    if (created) {
        job = CreateJobObjectW(NULL, NULL);
        if (job != NULL) {
            memset(&job_info, 0, sizeof(job_info));
            job_info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                        &job_info, sizeof(job_info))) {
                job_ok = AssignProcessToJobObject(job, process.hProcess) ? 1 : 0;
            }
            if (!job_ok) {
                CloseHandle(job);
                job = NULL;
            }
        }
    }

    if (created) {
        /*
         * Give the A14 same-user probe a window to attempt the first handle
         * before this identity is published and REGISTER runs.
         */
        Sleep(500);
    }

    if (_wfopen_s(&file, output, L"w, ccs=UTF-8") == 0 && file != NULL) {
        quad.LowPart = creation.dwLowDateTime;
        quad.HighPart = creation.dwHighDateTime;
        if (created) {
            fwprintf(file, L"%lu\n%llu\n%ls\n%d\n",
                     (unsigned long)process.dwProcessId,
                     (unsigned long long)quad.QuadPart, nt, job_ok);
        } else {
            fwprintf(file, L"0\n0\n\n0\n");
        }
        fclose(file);
    }

    if (created) {
        while (!file_exists(done)) {
            Sleep(200);
        }
        if (job_ok && job != NULL) {
            CloseHandle(job);
            job = NULL;
        } else {
            (void)TerminateProcess(process.hProcess, 0);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    wprintf(L"kg_creator: created=%d job=%d pid=%lu error=%lu\n", created,
            job_ok, (unsigned long)(created ? process.dwProcessId : 0),
            (unsigned long)error);
    return (created && job_ok) ? 0 : 1;
}
