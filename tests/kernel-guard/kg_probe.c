/*
 * tests/kernel-guard/kg_probe.c — VerthysGuard user-mode probe.
 *
 * Runs as LocalSystem (scheduled task) because the device ACL only grants
 * SYSTEM. Only PING and QUERY_STATUS are issued here; ARM/REGISTER live in
 * a later phase.
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

static int send_status_ioctl(HANDLE device, DWORD ioctl, VTG_U32 command,
                             VTG_U64 request_id, VTG_STATUS_OUT *response,
                             DWORD *error_code, DWORD *bytes_out, int *call_ok)
{
    VTG_HEADER request;
    DWORD bytes = 0;
    BOOL ok;

    memset(&request, 0, sizeof(request));
    request.Size = (VTG_U32)sizeof(request);
    request.Major = VTG_PROTOCOL_MAJOR;
    request.Minor = VTG_PROTOCOL_MINOR;
    request.Command = command;
    request.RequestId = request_id;

    memset(response, 0, sizeof(*response));
    *error_code = 0;
    *bytes_out = 0;
    *call_ok = 0;
    ok = DeviceIoControl(device, ioctl, &request, (DWORD)sizeof(request),
                         response, (DWORD)sizeof(*response), &bytes, NULL);
    *bytes_out = bytes;
    *call_ok = ok ? 1 : 0;
    if (!ok) {
        *error_code = GetLastError();
        return -1;
    }
    if (bytes != sizeof(*response) ||
        response->Header.Size != (VTG_U32)sizeof(*response) ||
        response->Header.Major != VTG_PROTOCOL_MAJOR ||
        response->Header.Minor != VTG_PROTOCOL_MINOR ||
        response->Header.Command != command ||
        response->Header.RequestId != request_id ||
        response->ProtocolMajor != VTG_PROTOCOL_MAJOR ||
        response->ProtocolMinor != VTG_PROTOCOL_MINOR ||
        response->Header.Status != VTG_STATUS_OK) {
        *error_code = ERROR_INVALID_DATA;
        return -1;
    }
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *device_path = L"\\\\.\\VerthysGuard";
    const wchar_t *output_path = L"kg-probe.json";
    HANDLE device = INVALID_HANDLE_VALUE;
    VTG_STATUS_OUT ping;
    VTG_STATUS_OUT query;
    DWORD open_error = 0;
    DWORD ping_error = 0;
    DWORD query_error = 0;
    DWORD ping_bytes = 0;
    DWORD query_bytes = 0;
    int ping_call_ok = 0;
    int query_call_ok = 0;
    int open_ok;
    int ping_ok = 0;
    int query_ok = 0;
    int arg;
    FILE *file = NULL;
    wchar_t user[256];
    DWORD user_len = 256;
    char user_utf8[256];
    char user_json[512];
    char device_json[512];
    DWORD session_id = 0;
    const char *status;

    memset(&ping, 0, sizeof(ping));
    memset(&query, 0, sizeof(query));

    for (arg = 1; arg < argc; arg++) {
        if (_wcsicmp(argv[arg], L"--out") == 0 && arg + 1 < argc) {
            output_path = argv[++arg];
        }
    }

    device = CreateFileW(device_path, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    open_ok = (device != INVALID_HANDLE_VALUE);
    if (!open_ok) {
        open_error = GetLastError();
    } else {
        ping_ok = (send_status_ioctl(device, VTG_IOCTL_PING, VTG_CMD_PING, 1,
                                     &ping, &ping_error, &ping_bytes,
                                     &ping_call_ok) == 0);
        query_ok = (send_status_ioctl(device, VTG_IOCTL_QUERY_STATUS,
                                      VTG_CMD_QUERY_STATUS, 2, &query,
                                      &query_error, &query_bytes,
                                      &query_call_ok) == 0);
        CloseHandle(device);
    }

    status = (open_ok && ping_ok && query_ok) ? "PASS" : "FAIL";
    if (_wfopen_s(&file, output_path, L"wb") != 0 || file == NULL) {
        wprintf(L"kg_probe: cannot write %ls\n", output_path);
        return 3;
    }

    user[0] = L'\0';
    (void)GetUserNameW(user, &user_len);
    memset(user_utf8, 0, sizeof(user_utf8));
    (void)WideCharToMultiByte(CP_UTF8, 0, user, -1, user_utf8,
                              (int)sizeof(user_utf8), NULL, NULL);
    json_escape(user_utf8, user_json, sizeof(user_json));
    {
        char device_utf8[256];
        WideCharToMultiByte(CP_UTF8, 0, device_path, -1, device_utf8,
                            (int)sizeof(device_utf8), NULL, NULL);
        json_escape(device_utf8, device_json, sizeof(device_json));
    }
    (void)ProcessIdToSessionId(GetCurrentProcessId(), &session_id);

    fprintf(file, "{\n");
    fprintf(file, "  \"status\": \"%s\",\n", status);
    fprintf(file, "  \"device\": \"%s\",\n", device_json);
    fprintf(file, "  \"process_id\": %lu,\n", (unsigned long)GetCurrentProcessId());
    fprintf(file, "  \"session_id\": %lu,\n", (unsigned long)session_id);
    fprintf(file, "  \"user\": \"%s\",\n", user_json);
    fprintf(file, "  \"open_ok\": %s,\n", open_ok ? "true" : "false");
    fprintf(file, "  \"open_error\": %lu,\n", (unsigned long)open_error);
    fprintf(file, "  \"ping_ok\": %s,\n", ping_ok ? "true" : "false");
    fprintf(file, "  \"ping_error\": %lu,\n", (unsigned long)ping_error);
    fprintf(file, "  \"ping_call_ok\": %s,\n", ping_call_ok ? "true" : "false");
    fprintf(file, "  \"ping_bytes\": %lu,\n", (unsigned long)ping_bytes);
    fprintf(file, "  \"query_ok\": %s,\n", query_ok ? "true" : "false");
    fprintf(file, "  \"query_error\": %lu,\n", (unsigned long)query_error);
    fprintf(file, "  \"query_call_ok\": %s,\n", query_call_ok ? "true" : "false");
    fprintf(file, "  \"query_bytes\": %lu,\n", (unsigned long)query_bytes);
    fprintf(file, "  \"status_out_size\": %u,\n", (unsigned)sizeof(VTG_STATUS_OUT));
    fprintf(file, "  \"header_size\": %u,\n", (unsigned)sizeof(VTG_HEADER));
    if (ping_call_ok) {
        fprintf(file, "  \"ping_header_size\": %u,\n", (unsigned)ping.Header.Size);
        fprintf(file, "  \"ping_header_status\": %u,\n", (unsigned)ping.Header.Status);
        fprintf(file, "  \"ping_header_command\": %u,\n", (unsigned)ping.Header.Command);
        fprintf(file, "  \"ping_header_request_id\": %llu,\n",
                (unsigned long long)ping.Header.RequestId);
        fprintf(file, "  \"ping_protocol_major\": %u,\n",
                (unsigned)ping.ProtocolMajor);
        fprintf(file, "  \"ping_protocol_minor\": %u,\n",
                (unsigned)ping.ProtocolMinor);
    }
    if (ping_ok) {
        fprintf(file, "  \"ping_state\": %u,\n", (unsigned)ping.State);
        fprintf(file, "  \"ping_reason\": %u,\n", (unsigned)ping.Reason);
        fprintf(file, "  \"ping_capabilities\": %u,\n", (unsigned)ping.Capabilities);
        fprintf(file, "  \"ping_protected_count\": %u,\n",
                (unsigned)ping.ProtectedCount);
    }
    if (query_call_ok) {
        fprintf(file, "  \"query_header_size\": %u,\n", (unsigned)query.Header.Size);
        fprintf(file, "  \"query_header_status\": %u,\n", (unsigned)query.Header.Status);
        fprintf(file, "  \"query_header_command\": %u,\n", (unsigned)query.Header.Command);
        fprintf(file, "  \"query_header_request_id\": %llu,\n",
                (unsigned long long)query.Header.RequestId);
        fprintf(file, "  \"query_protocol_major\": %u,\n",
                (unsigned)query.ProtocolMajor);
        fprintf(file, "  \"query_protocol_minor\": %u,\n",
                (unsigned)query.ProtocolMinor);
    }
    if (query_ok) {
        fprintf(file, "  \"state\": %u,\n", (unsigned)query.State);
        fprintf(file, "  \"reason\": %u,\n", (unsigned)query.Reason);
        fprintf(file, "  \"capabilities\": %u,\n", (unsigned)query.Capabilities);
        fprintf(file, "  \"protected_count\": %u,\n",
                (unsigned)query.ProtectedCount);
        fprintf(file, "  \"protocol_major\": %u,\n",
                (unsigned)query.ProtocolMajor);
        fprintf(file, "  \"protocol_minor\": %u,\n",
                (unsigned)query.ProtocolMinor);
    }
    fprintf(file, "  \"expected_state_unarmed\": %s,\n",
            (query_ok && query.State == VTG_STATE_UNARMED) ? "true" : "false");
    fprintf(file, "  \"expected_protected_zero\": %s\n",
            (query_ok && query.ProtectedCount == 0) ? "true" : "false");
    fprintf(file, "}\n");
    fclose(file);

    wprintf(L"kg_probe: %hs (open=%d ping=%d query=%d)\n", status, open_ok,
            ping_ok, query_ok);
    return (open_ok && ping_ok && query_ok) ? 0 : 1;
}
