/*
 * tests/kernel-guard/kg_arm_probe.c — VerthysGuard ARM/REGISTER positive control.
 *
 * Runs as LocalSystem. Creates a suspended dummy worker, arms the driver,
 * registers the dummy, verifies ACTIVE/protected_count=1, disarms, then
 * terminates the dummy. No attack cases run here.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "vtg_ioctl.h"

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

static int dos_to_nt(const wchar_t *dos, wchar_t *out, size_t cap)
{
    wchar_t drive[3];
    wchar_t device[1024];
    size_t device_len;
    size_t suffix_len;

    if (dos == NULL || out == NULL || cap == 0 || wcslen(dos) < 3) return -1;
    if (!((dos[0] >= L'A' && dos[0] <= L'Z') ||
          (dos[0] >= L'a' && dos[0] <= L'z')) ||
        dos[1] != L':' || (dos[2] != L'\\' && dos[2] != L'/')) {
        return -1;
    }
    drive[0] = dos[0];
    drive[1] = L':';
    drive[2] = L'\0';
    memset(device, 0, sizeof(device));
    if (QueryDosDeviceW(drive, device, (DWORD)(sizeof(device) / sizeof(device[0]))) == 0) {
        return -1;
    }
    device_len = wcslen(device);
    suffix_len = wcslen(dos + 2);
    if (device_len + suffix_len + 1u > cap) return -1;
    wcscpy_s(out, cap, device);
    wcscat_s(out, cap, dos + 2);
    return 0;
}

static int get_identity(HANDLE process, VTG_PROCESS_IDENTITY *out)
{
    FILETIME creation;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    wchar_t dos[1024];
    wchar_t nt[VTG_MAX_IMAGE_PATH_CHARS];
    DWORD length = (DWORD)(sizeof(dos) / sizeof(dos[0]));
    ULARGE_INTEGER quad;

    if (process == NULL || out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    memset(dos, 0, sizeof(dos));
    memset(nt, 0, sizeof(nt));
    if (!GetProcessTimes(process, &creation, &exit_time, &kernel_time, &user_time)) {
        return -1;
    }
    if (!QueryFullProcessImageNameW(process, 0, dos, &length)) return -1;
    if (dos_to_nt(dos, nt, VTG_MAX_IMAGE_PATH_CHARS) != 0) return -1;
    quad.LowPart = creation.dwLowDateTime;
    quad.HighPart = creation.dwHighDateTime;
    out->ProcessId = GetProcessId(process);
    out->Reserved = 0;
    out->CreationTime = (VTG_U64)quad.QuadPart;
    if (wcscpy_s(out->ImagePath, VTG_MAX_IMAGE_PATH_CHARS, nt) != 0) return -1;
    return 0;
}

static int send_ioctl(HANDLE device, DWORD ioctl, const void *input,
                      DWORD input_len, VTG_STATUS_OUT *response,
                      DWORD *call_error, DWORD *bytes_out, int *call_ok)
{
    DWORD bytes = 0;
    BOOL ok;

    memset(response, 0, sizeof(*response));
    *call_error = 0;
    *bytes_out = 0;
    *call_ok = 0;
    ok = DeviceIoControl(device, ioctl, (LPVOID)input, input_len, response,
                         (DWORD)sizeof(*response), &bytes, NULL);
    *bytes_out = bytes;
    *call_ok = ok ? 1 : 0;
    if (!ok) {
        *call_error = GetLastError();
        return -1;
    }
    if (bytes != sizeof(*response)) {
        *call_error = ERROR_INVALID_DATA;
        return -1;
    }
    return 0;
}

static int response_ok(const VTG_STATUS_OUT *response, VTG_U32 command,
                       VTG_U64 request_id)
{
    return response->Header.Size == (VTG_U32)sizeof(*response) &&
           response->Header.Major == VTG_PROTOCOL_MAJOR &&
           response->Header.Minor == VTG_PROTOCOL_MINOR &&
           response->Header.Command == command &&
           response->Header.RequestId == request_id &&
           response->ProtocolMajor == VTG_PROTOCOL_MAJOR &&
           response->ProtocolMinor == VTG_PROTOCOL_MINOR &&
           response->Header.Status == VTG_STATUS_OK;
}

static void init_header(VTG_HEADER *header, VTG_U32 command, VTG_U64 request_id,
                        VTG_U32 size)
{
    memset(header, 0, size);
    header->Size = size;
    header->Major = VTG_PROTOCOL_MAJOR;
    header->Minor = VTG_PROTOCOL_MINOR;
    header->Command = command;
    header->RequestId = request_id;
}

static void send_query(HANDLE device, VTG_U64 request_id, VTG_STATUS_OUT *response,
                       DWORD *error_code, DWORD *bytes, int *call_ok)
{
    VTG_HEADER request;
    init_header(&request, VTG_CMD_QUERY_STATUS, request_id, (VTG_U32)sizeof(request));
    (void)send_ioctl(device, VTG_IOCTL_QUERY_STATUS, &request,
                     (DWORD)sizeof(request), response, error_code, bytes, call_ok);
}

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

static void write_marker(const wchar_t *path)
{
    FILE *file = NULL;
    if (path == NULL) return;
    if (_wfopen_s(&file, path, L"w, ccs=UTF-8") == 0 && file != NULL) {
        fwprintf(file, L"1\n");
        fclose(file);
    }
}

static void write_ready(const wchar_t *path, unsigned long pid)
{
    FILE *file = NULL;
    if (path == NULL) return;
    if (_wfopen_s(&file, path, L"w, ccs=UTF-8") == 0 && file != NULL) {
        fwprintf(file, L"%lu\n", pid);
        fclose(file);
    }
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *device_path = L"\\\\.\\VerthysGuard";
    const wchar_t *dummy_path = NULL;
    const wchar_t *output_path = L"kg-arm-probe.json";
    const wchar_t *armed_path = NULL;
    const wchar_t *creator_path = NULL;
    const wchar_t *ready_path = NULL;
    const wchar_t *done_path = NULL;
    int hold_mode = 0;
    HANDLE device = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION dummy;
    STARTUPINFOW startup;
    VTG_PROCESS_IDENTITY service_identity;
    VTG_PROCESS_IDENTITY dummy_identity;
    VTG_ARM_IN arm;
    VTG_REGISTER_IN register_in;
    VTG_HEADER disarm;
    VTG_STATUS_OUT initial_query;
    VTG_STATUS_OUT arm_response;
    VTG_STATUS_OUT register_response;
    VTG_STATUS_OUT active_query;
    VTG_STATUS_OUT disarm_response;
    VTG_STATUS_OUT final_query;
    VTG_STATUS_OUT forged_creation_response;
    VTG_STATUS_OUT forged_path_response;
    VTG_REGISTER_IN forged_register;
    VTG_PROCESS_IDENTITY forged_identity;
    wchar_t dummy_nt[VTG_MAX_IMAGE_PATH_CHARS];
    DWORD initial_error = 0, arm_error = 0, register_error = 0;
    DWORD active_error = 0, disarm_error = 0, final_error = 0;
    DWORD initial_bytes = 0, arm_bytes = 0, register_bytes = 0;
    DWORD active_bytes = 0, disarm_bytes = 0, final_bytes = 0;
    int initial_call = 0, arm_call = 0, register_call = 0;
    int active_call = 0, disarm_call = 0, final_call = 0;
    int open_ok;
    int dummy_created = 0;
    int arm_ok = 0;
    int register_ok = 0;
    int active_ok = 0;
    int disarm_ok = 0;
    int final_unarmed_ok = 0;
    int forged_creation_rejected = 0;
    int forged_path_rejected = 0;
    int service_ok = 0;
    DWORD forged_creation_error = 0;
    DWORD forged_path_error = 0;
    DWORD forged_creation_bytes = 0;
    DWORD forged_path_bytes = 0;
    int forged_creation_call = 0;
    int forged_path_call = 0;
    int arg;
    FILE *file = NULL;
    char dummy_json[512];
    char device_json[512];
    char dummy_utf8[512];
    char device_utf8[256];
    const char *status;

    memset(&dummy, 0, sizeof(dummy));
    memset(&service_identity, 0, sizeof(service_identity));
    memset(&dummy_identity, 0, sizeof(dummy_identity));
    memset(&arm, 0, sizeof(arm));
    memset(&register_in, 0, sizeof(register_in));
    memset(&disarm, 0, sizeof(disarm));
    memset(&initial_query, 0, sizeof(initial_query));
    memset(&arm_response, 0, sizeof(arm_response));
    memset(&register_response, 0, sizeof(register_response));
    memset(&active_query, 0, sizeof(active_query));
    memset(&disarm_response, 0, sizeof(disarm_response));
    memset(&final_query, 0, sizeof(final_query));
    memset(&forged_creation_response, 0, sizeof(forged_creation_response));
    memset(&forged_path_response, 0, sizeof(forged_path_response));
    memset(&forged_register, 0, sizeof(forged_register));
    memset(&forged_identity, 0, sizeof(forged_identity));

    for (arg = 1; arg < argc; arg++) {
        if (_wcsicmp(argv[arg], L"--dummy") == 0 && arg + 1 < argc) {
            dummy_path = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--out") == 0 && arg + 1 < argc) {
            output_path = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--hold") == 0) {
            hold_mode = 1;
        } else if (_wcsicmp(argv[arg], L"--armed") == 0 && arg + 1 < argc) {
            armed_path = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--creator") == 0 && arg + 1 < argc) {
            creator_path = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--ready") == 0 && arg + 1 < argc) {
            ready_path = argv[++arg];
        } else if (_wcsicmp(argv[arg], L"--done") == 0 && arg + 1 < argc) {
            done_path = argv[++arg];
        }
    }
    if (dummy_path == NULL) {
        wprintf(L"kg_arm_probe: --dummy is required\n");
        return 2;
    }
    if (hold_mode && (armed_path == NULL || creator_path == NULL ||
                      ready_path == NULL || done_path == NULL)) {
        wprintf(L"kg_arm_probe: hold mode requires --armed/--creator/--ready/--done\n");
        return 2;
    }

    device = CreateFileW(device_path, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    open_ok = (device != INVALID_HANDLE_VALUE);
    if (!open_ok) {
        initial_error = GetLastError();
    } else {
        send_query(device, 1, &initial_query, &initial_error, &initial_bytes,
                   &initial_call);
        if (get_identity(GetCurrentProcess(), &service_identity) != 0 ||
            dos_to_nt(dummy_path, dummy_nt, VTG_MAX_IMAGE_PATH_CHARS) != 0) {
            arm_error = ERROR_INVALID_DATA;
        } else {
            init_header(&arm.Header, VTG_CMD_ARM, 2, (VTG_U32)sizeof(arm));
            arm.Service = service_identity;
            if (wcscpy_s(arm.ProtectedImagePath, VTG_MAX_IMAGE_PATH_CHARS,
                         dummy_nt) != 0) {
                arm_error = ERROR_INVALID_DATA;
            } else {
                (void)send_ioctl(device, VTG_IOCTL_ARM, &arm, (DWORD)sizeof(arm),
                                 &arm_response, &arm_error, &arm_bytes, &arm_call);
                arm_ok = arm_call && response_ok(&arm_response, VTG_CMD_ARM, 2) &&
                    (arm_response.State == VTG_STATE_ARMED ||
                     arm_response.State == VTG_STATE_ACTIVE);
            }
        }

        if (arm_ok) {
            if (hold_mode) {
                write_marker(armed_path);
                if (wait_file(creator_path, 30) == 0) {
                    FILE *creator_file = NULL;
                    wchar_t line[600];
                    unsigned long creator_pid = 0;
                    unsigned long long creator_time = 0;
                    wchar_t creator_nt[VTG_MAX_IMAGE_PATH_CHARS];
                    memset(line, 0, sizeof(line));
                    memset(creator_nt, 0, sizeof(creator_nt));
                    if (_wfopen_s(&creator_file, creator_path, L"r, ccs=UTF-8") == 0 &&
                        creator_file != NULL) {
                        if (fgetws(line, 600, creator_file) != NULL) {
                            creator_pid = wcstoul(line, NULL, 10);
                        }
                        if (fgetws(line, 600, creator_file) != NULL) {
                            creator_time = _wcstoui64(line, NULL, 10);
                        }
                        if (fgetws(line, 600, creator_file) != NULL) {
                            size_t len = wcslen(line);
                            while (len > 0 && (line[len - 1] == L'\r' ||
                                               line[len - 1] == L'\n')) {
                                line[--len] = L'\0';
                            }
                            wcscpy_s(creator_nt, VTG_MAX_IMAGE_PATH_CHARS, line);
                        }
                        fclose(creator_file);
                    }
                    if (creator_pid != 0 && creator_time != 0 &&
                        _wcsicmp(creator_nt, dummy_nt) == 0) {
                        dummy_identity.ProcessId = (VTG_U32)creator_pid;
                        dummy_identity.Reserved = 0;
                        dummy_identity.CreationTime = (VTG_U64)creator_time;
                        wcscpy_s(dummy_identity.ImagePath,
                                 VTG_MAX_IMAGE_PATH_CHARS, creator_nt);
                        dummy_created = 1;
                        forged_identity = dummy_identity;
                        forged_identity.CreationTime += 1000;
                        init_header(&forged_register.Header,
                                    VTG_CMD_REGISTER_PROCESS, 30,
                                    (VTG_U32)sizeof(forged_register));
                        forged_register.Process = forged_identity;
                        (void)send_ioctl(device, VTG_IOCTL_REGISTER_PROCESS,
                                         &forged_register,
                                         (DWORD)sizeof(forged_register),
                                         &forged_creation_response,
                                         &forged_creation_error,
                                         &forged_creation_bytes,
                                         &forged_creation_call);
                        forged_creation_rejected = (!forged_creation_call) ||
                            (forged_creation_response.Header.Status != VTG_STATUS_OK);

                        forged_identity = dummy_identity;
                        {
                            size_t path_len = wcslen(forged_identity.ImagePath);
                            if (path_len > 0) {
                                forged_identity.ImagePath[path_len - 1] =
                                    (forged_identity.ImagePath[path_len - 1] == L'x')
                                        ? L'y' : L'x';
                            }
                        }
                        init_header(&forged_register.Header,
                                    VTG_CMD_REGISTER_PROCESS, 31,
                                    (VTG_U32)sizeof(forged_register));
                        forged_register.Process = forged_identity;
                        (void)send_ioctl(device, VTG_IOCTL_REGISTER_PROCESS,
                                         &forged_register,
                                         (DWORD)sizeof(forged_register),
                                         &forged_path_response,
                                         &forged_path_error,
                                         &forged_path_bytes,
                                         &forged_path_call);
                        forged_path_rejected = (!forged_path_call) ||
                            (forged_path_response.Header.Status != VTG_STATUS_OK);

                        init_header(&register_in.Header,
                                    VTG_CMD_REGISTER_PROCESS, 3,
                                    (VTG_U32)sizeof(register_in));
                        register_in.Process = dummy_identity;
                        (void)send_ioctl(device, VTG_IOCTL_REGISTER_PROCESS,
                                         &register_in,
                                         (DWORD)sizeof(register_in),
                                         &register_response, &register_error,
                                         &register_bytes, &register_call);
                        register_ok = register_call &&
                            response_ok(&register_response,
                                        VTG_CMD_REGISTER_PROCESS, 3);
                    } else {
                        register_error = ERROR_INVALID_DATA;
                    }
                } else {
                    register_error = ERROR_TIMEOUT;
                }
            } else {
                memset(&startup, 0, sizeof(startup));
                startup.cb = sizeof(startup);
                startup.dwFlags = STARTF_USESHOWWINDOW;
                startup.wShowWindow = SW_HIDE;
                dummy_created = CreateProcessW(dummy_path, NULL, NULL, NULL, FALSE,
                                               CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                               NULL, NULL, &startup, &dummy) ? 1 : 0;
                if (dummy_created) {
                    if (get_identity(dummy.hProcess, &dummy_identity) == 0) {
                        init_header(&register_in.Header, VTG_CMD_REGISTER_PROCESS, 3,
                                    (VTG_U32)sizeof(register_in));
                        register_in.Process = dummy_identity;
                        (void)send_ioctl(device, VTG_IOCTL_REGISTER_PROCESS,
                                         &register_in, (DWORD)sizeof(register_in),
                                         &register_response, &register_error,
                                         &register_bytes, &register_call);
                        register_ok = register_call &&
                            response_ok(&register_response,
                                        VTG_CMD_REGISTER_PROCESS, 3);
                    } else {
                        register_error = ERROR_INVALID_DATA;
                    }
                } else {
                    register_error = GetLastError();
                }
            }
        }

        if (register_ok) {
            send_query(device, 4, &active_query, &active_error, &active_bytes,
                       &active_call);
            active_ok = active_call &&
                response_ok(&active_query, VTG_CMD_QUERY_STATUS, 4) &&
                active_query.State == VTG_STATE_ACTIVE &&
                active_query.ProtectedCount == 1;
        }

        if (hold_mode) {
            HANDLE service_handle = NULL;
            if (register_ok && active_ok) {
                service_handle = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                    FALSE, dummy_identity.ProcessId);
                service_ok = service_handle != NULL;
                if (service_handle != NULL) CloseHandle(service_handle);
            }
            {
                unsigned long ready_pid = (register_ok && active_ok) ?
                    (unsigned long)dummy_identity.ProcessId : 0;
                write_ready(ready_path, ready_pid);
                if (ready_pid != 0) {
                    (void)wait_file(done_path, 180);
                }
            }
        }

        if (arm_ok) {
            init_header(&disarm, VTG_CMD_DISARM, 5, (VTG_U32)sizeof(disarm));
            (void)send_ioctl(device, VTG_IOCTL_DISARM, &disarm,
                             (DWORD)sizeof(disarm), &disarm_response,
                             &disarm_error, &disarm_bytes, &disarm_call);
            disarm_ok = disarm_call &&
                response_ok(&disarm_response, VTG_CMD_DISARM, 5);
            send_query(device, 6, &final_query, &final_error, &final_bytes,
                       &final_call);
            final_unarmed_ok = final_call &&
                response_ok(&final_query, VTG_CMD_QUERY_STATUS, 6) &&
                final_query.State == VTG_STATE_UNARMED &&
                final_query.ProtectedCount == 0;
        }

        if (!hold_mode && dummy_created) {
            (void)TerminateProcess(dummy.hProcess, 0);
            CloseHandle(dummy.hThread);
            CloseHandle(dummy.hProcess);
        }
        CloseHandle(device);
    }

    status = (open_ok && arm_ok && register_ok && active_ok && disarm_ok &&
              final_unarmed_ok &&
              (!hold_mode ||
               (forged_creation_rejected && forged_path_rejected && service_ok)))
        ? "PASS" : "FAIL";
    if (_wfopen_s(&file, output_path, L"wb") != 0 || file == NULL) {
        wprintf(L"kg_arm_probe: cannot write %ls\n", output_path);
        return 3;
    }
    WideCharToMultiByte(CP_UTF8, 0, device_path, -1, device_utf8,
                        (int)sizeof(device_utf8), NULL, NULL);
    json_escape(device_utf8, device_json, sizeof(device_json));
    WideCharToMultiByte(CP_UTF8, 0, dummy_path, -1, dummy_utf8,
                        (int)sizeof(dummy_utf8), NULL, NULL);
    json_escape(dummy_utf8, dummy_json, sizeof(dummy_json));

    fprintf(file, "{\n");
    fprintf(file, "  \"status\": \"%s\",\n", status);
    fprintf(file, "  \"device\": \"%s\",\n", device_json);
    fprintf(file, "  \"dummy\": \"%s\",\n", dummy_json);
    fprintf(file, "  \"service_pid\": %lu,\n",
            (unsigned long)GetCurrentProcessId());
    fprintf(file, "  \"open_ok\": %s,\n", open_ok ? "true" : "false");
    fprintf(file, "  \"initial_query_ok\": %s,\n",
            (initial_call && initial_query.State == VTG_STATE_UNARMED) ? "true" : "false");
    fprintf(file, "  \"initial_state\": %u,\n", (unsigned)initial_query.State);
    fprintf(file, "  \"initial_count\": %u,\n",
            (unsigned)initial_query.ProtectedCount);
    fprintf(file, "  \"initial_error\": %lu,\n", (unsigned long)initial_error);
    fprintf(file, "  \"arm_call_ok\": %s,\n", arm_call ? "true" : "false");
    fprintf(file, "  \"arm_ok\": %s,\n", arm_ok ? "true" : "false");
    fprintf(file, "  \"arm_error\": %lu,\n", (unsigned long)arm_error);
    fprintf(file, "  \"arm_header_status\": %u,\n", (unsigned)arm_response.Header.Status);
    fprintf(file, "  \"arm_state\": %u,\n", (unsigned)arm_response.State);
    fprintf(file, "  \"arm_count\": %u,\n", (unsigned)arm_response.ProtectedCount);
    fprintf(file, "  \"dummy_created\": %s,\n", dummy_created ? "true" : "false");
    fprintf(file, "  \"hold_mode\": %s,\n", hold_mode ? "true" : "false");
    fprintf(file, "  \"dummy_pid\": %lu,\n",
            (unsigned long)dummy_identity.ProcessId);
    fprintf(file, "  \"forged_creation_rejected\": %s,\n",
            forged_creation_rejected ? "true" : "false");
    fprintf(file, "  \"forged_path_rejected\": %s,\n",
            forged_path_rejected ? "true" : "false");
    fprintf(file, "  \"service_ok\": %s,\n", service_ok ? "true" : "false");
    fprintf(file, "  \"register_call_ok\": %s,\n", register_call ? "true" : "false");
    fprintf(file, "  \"register_ok\": %s,\n", register_ok ? "true" : "false");
    fprintf(file, "  \"register_error\": %lu,\n", (unsigned long)register_error);
    fprintf(file, "  \"register_header_status\": %u,\n",
            (unsigned)register_response.Header.Status);
    fprintf(file, "  \"register_state\": %u,\n", (unsigned)register_response.State);
    fprintf(file, "  \"register_count\": %u,\n",
            (unsigned)register_response.ProtectedCount);
    fprintf(file, "  \"active_ok\": %s,\n", active_ok ? "true" : "false");
    fprintf(file, "  \"active_state\": %u,\n", (unsigned)active_query.State);
    fprintf(file, "  \"active_count\": %u,\n", (unsigned)active_query.ProtectedCount);
    fprintf(file, "  \"disarm_call_ok\": %s,\n", disarm_call ? "true" : "false");
    fprintf(file, "  \"disarm_ok\": %s,\n", disarm_ok ? "true" : "false");
    fprintf(file, "  \"disarm_error\": %lu,\n", (unsigned long)disarm_error);
    fprintf(file, "  \"disarm_header_status\": %u,\n",
            (unsigned)disarm_response.Header.Status);
    fprintf(file, "  \"final_unarmed_ok\": %s,\n",
            final_unarmed_ok ? "true" : "false");
    fprintf(file, "  \"final_state\": %u,\n", (unsigned)final_query.State);
    fprintf(file, "  \"final_count\": %u,\n", (unsigned)final_query.ProtectedCount);
    fprintf(file, "  \"protocol_major\": %u,\n", (unsigned)active_query.ProtocolMajor);
    fprintf(file, "  \"protocol_minor\": %u\n", (unsigned)active_query.ProtocolMinor);
    fprintf(file, "}\n");
    fclose(file);

    wprintf(L"kg_arm_probe: %hs (open=%d arm=%d register=%d active=%d disarm=%d final=%d)\n",
            status, open_ok, arm_ok, register_ok, active_ok, disarm_ok,
            final_unarmed_ok);
    return (open_ok && arm_ok && register_ok && active_ok && disarm_ok &&
            final_unarmed_ok) ? 0 : 1;
}
