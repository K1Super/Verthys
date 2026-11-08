/*
 * probe_main.c — 协议探针（集成测试/攻击回归使用，不随生产分发）
 *
 * 用法示例：
 *   verthys_service_probe.exe --pipe \\.\pipe\VerthysSecuritySvcTest-1 \
 *       --registry-root Software\VerthysTest\SecurityService-1 \
 *       --command check --expect-status 0
 *
 * 退出码：0 期望匹配；10 连接失败；11 响应验签/字段不符；
 *         20 状态与期望不符；其余为实际状态码（1=LOCKED 等）。
 */
#include "protocol.h"
#include "service_state.h"
#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <stdio.h>
#include <string.h>

static int read_response(HANDLE pipe, uint8_t *buf, DWORD cap, DWORD *len,
                         DWORD timeout_ms)
{
    OVERLAPPED ov;
    HANDLE event;
    BOOL ok;
    DWORD err;
    DWORD transferred = 0;
    int rc = -1;

    memset(&ov, 0, sizeof(ov));
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) return -1;
    ov.hEvent = event;
    ok = ReadFile(pipe, buf, cap, &transferred, &ov);
    if (ok) {
        *len = transferred;
        rc = 0;
        goto done;
    }
    err = GetLastError();
    if (err == ERROR_MORE_DATA) {
        rc = -2;
        goto done;
    }
    if (err != ERROR_IO_PENDING) goto done;
    if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        (void)WaitForSingleObject(event, 1000u);
        goto done;
    }
    if (GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
        *len = transferred;
        rc = 0;
    } else if (GetLastError() == ERROR_MORE_DATA) {
        rc = -2;
    }

done:
    CloseHandle(event);
    return rc;
}

static int write_request(HANDLE pipe, const uint8_t *buf, DWORD len,
                         DWORD timeout_ms)
{
    OVERLAPPED ov;
    HANDLE event;
    BOOL ok;
    DWORD err;
    DWORD transferred = 0;
    int rc = -1;

    memset(&ov, 0, sizeof(ov));
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) return -1;
    ov.hEvent = event;
    ok = WriteFile(pipe, buf, len, &transferred, &ov);
    if (ok) {
        rc = (transferred == len) ? 0 : -1;
        goto done;
    }
    err = GetLastError();
    if (err != ERROR_IO_PENDING) goto done;
    if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        (void)WaitForSingleObject(event, 1000u);
        goto done;
    }
    if (GetOverlappedResult(pipe, &ov, &transferred, FALSE) &&
        transferred == len) {
        rc = 0;
    }

done:
    CloseHandle(event);
    return rc;
}

static int load_pubkey(const wchar_t *pubkey_file, const wchar_t *registry_root,
                       uint8_t *pub, DWORD cap, DWORD *pub_len)
{
    if (pubkey_file != NULL && pubkey_file[0] != L'\0') {
        return vty_read_file_any(pubkey_file, pub, cap, pub_len);
    }
    if (registry_root != NULL && registry_root[0] != L'\0') {
        HKEY key = NULL;
        int rc;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, registry_root, 0, KEY_READ,
                          &key) != ERROR_SUCCESS) {
            return -1;
        }
        rc = vty_registry_read_binary(key, VTY_SVC_REG_SERVER_PUBKEY, pub, cap,
                                      pub_len);
        RegCloseKey(key);
        return rc;
    }
    return -1;
}

static uint16_t command_from_name(const wchar_t *name)
{
    if (wcscmp(name, L"check") == 0) return (uint16_t)VTY_SVC_CMD_CHECK;
    if (wcscmp(name, L"record") == 0) {
        return (uint16_t)VTY_SVC_CMD_RECORD_FAILURE;
    }
    if (wcscmp(name, L"reset") == 0) return (uint16_t)VTY_SVC_CMD_RESET;
    return (uint16_t)VTY_SVC_CMD_PING;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t pipe_name[128];
    wchar_t pubkey_file[VTY_PATH_MAX];
    wchar_t registry_root[VTY_REGISTRY_TEXT_MAX];
    wchar_t command_name[32];
    wchar_t module_path[VTY_PATH_MAX];
    int expect_status = -1;
    int repeat = 1;
    int delay_ms = 0;
    int skip_verify = 0;
    int i;
    int attempt;
    unsigned __int64 request_id;
    uint64_t nonce_lo;
    uint64_t nonce_hi;
    uint8_t pub[VTY_ECC_BLOB_MAX];
    DWORD pub_len = 0;
    int last_status = 10;

    (void)vty_wide_copy(pipe_name, 128,
                        L"\\\\.\\pipe\\VerthysSecuritySvcTest");
    (void)vty_wide_copy(command_name, 32, L"ping");
    pubkey_file[0] = L'\0';
    registry_root[0] = L'\0';
    module_path[0] = L'\0';

    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--pipe") == 0 && i + 1 < argc) {
            (void)vty_wide_copy(pipe_name, 128, argv[++i]);
        } else if (wcscmp(argv[i], L"--pubkey-file") == 0 && i + 1 < argc) {
            (void)vty_wide_copy(pubkey_file, VTY_PATH_MAX, argv[++i]);
        } else if (wcscmp(argv[i], L"--registry-root") == 0 && i + 1 < argc) {
            (void)vty_wide_copy(registry_root, VTY_REGISTRY_TEXT_MAX,
                                argv[++i]);
        } else if (wcscmp(argv[i], L"--module-path") == 0 && i + 1 < argc) {
            (void)vty_wide_copy(module_path, VTY_PATH_MAX, argv[++i]);
        } else if (wcscmp(argv[i], L"--command") == 0 && i + 1 < argc) {
            (void)vty_wide_copy(command_name, 32, argv[++i]);
        } else if (wcscmp(argv[i], L"--expect-status") == 0 && i + 1 < argc) {
            expect_status = (int)wcstol(argv[++i], NULL, 10);
        } else if (wcscmp(argv[i], L"--repeat") == 0 && i + 1 < argc) {
            repeat = (int)wcstol(argv[++i], NULL, 10);
        } else if (wcscmp(argv[i], L"--delay-ms") == 0 && i + 1 < argc) {
            delay_ms = (int)wcstol(argv[++i], NULL, 10);
        } else if (wcscmp(argv[i], L"--skip-verify") == 0) {
            skip_verify = 1;
        } else {
            fprintf(stderr, "unknown argument: %ls\n", argv[i]);
            return 2;
        }
    }
    if (repeat < 1) repeat = 1;
    if (repeat > 10000) repeat = 10000;

    if (module_path[0] != L'\0') {
        HMODULE module = LoadLibraryW(module_path);
        if (module == NULL) {
            fprintf(stderr, "failed to load client module: %lu\n",
                    (unsigned long)GetLastError());
            return 12;
        }
    }

    if (!skip_verify) {
        if (load_pubkey(pubkey_file[0] ? pubkey_file : NULL,
                        registry_root[0] ? registry_root : NULL, pub,
                        VTY_ECC_BLOB_MAX, &pub_len) != 0 ||
            pub_len == 0) {
            fprintf(stderr, "failed to load server public key\n");
            return 11;
        }
    }

    for (attempt = 0; attempt < repeat; attempt++) {
        HANDLE pipe;
        uint8_t request[VTY_SVC_REQUEST_BYTES];
        uint8_t response[VTY_SVC_RESPONSE_BYTES];
        DWORD response_len = 0;
        VtySvcResponseFields fields;
        uint16_t decode_status;

        if (BCryptGenRandom(NULL, (PUCHAR)&request_id, sizeof(request_id),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            request_id = GetTickCount64();
        }
        if (BCryptGenRandom(NULL, (PUCHAR)&nonce_lo, sizeof(nonce_lo),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            nonce_lo = GetTickCount64();
        }
        if (BCryptGenRandom(NULL, (PUCHAR)&nonce_hi, sizeof(nonce_hi),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            nonce_hi = (uint64_t)GetCurrentProcessId();
        }
        vty_svc_request_encode(request, command_from_name(command_name),
                               (uint32_t)request_id, nonce_lo, nonce_hi);
        pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE &&
            GetLastError() == ERROR_PIPE_BUSY) {
            (void)WaitNamedPipeW(pipe_name, VTY_SVC_CLIENT_CONNECT_TIMEOUT_MS);
            pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0,
                               NULL, OPEN_EXISTING, 0, NULL);
        }
        if (pipe == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "connect failed: %lu\n",
                    (unsigned long)GetLastError());
            return 10;
        }
        {
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)) {
                CloseHandle(pipe);
                fprintf(stderr, "SetNamedPipeHandleState failed\n");
                return 10;
            }
        }
        if (write_request(pipe, request, sizeof(request),
                          VTY_SVC_CLIENT_REPLY_TIMEOUT_MS) != 0) {
            CloseHandle(pipe);
            fprintf(stderr, "write failed\n");
            return 10;
        }
        if (read_response(pipe, response, sizeof(response), &response_len,
                          VTY_SVC_CLIENT_REPLY_TIMEOUT_MS) != 0) {
            CloseHandle(pipe);
            fprintf(stderr, "read failed\n");
            return 10;
        }
        CloseHandle(pipe);
        if (response_len != VTY_SVC_RESPONSE_BYTES) {
            fprintf(stderr, "bad response length: %lu\n",
                    (unsigned long)response_len);
            return 11;
        }
        decode_status = vty_svc_response_decode(
            response, response_len, (uint32_t)request_id, nonce_lo, nonce_hi,
            &fields);
        if (decode_status != (uint16_t)VTY_SVC_STATUS_OK) {
            fprintf(stderr, "response header validation failed\n");
            return 11;
        }
        if (!skip_verify) {
            uint8_t hash[VTY_HASH_BYTES];
            if (vty_sha256(response, VTY_SVC_RESPONSE_HEADER_BYTES, hash) !=
                0) {
                return 11;
            }
            if (vty_ecc_verify(pub, pub_len, hash,
                               response + VTY_SVC_RESPONSE_HEADER_BYTES) != 0) {
                fprintf(stderr, "response signature verification failed\n");
                return 11;
            }
            vty_secure_zero(hash, sizeof(hash));
        }
        printf("status=%u retry=%lu remaining=%lu\n",
               (unsigned)fields.status,
               (unsigned long)fields.retry_after_sec,
               (unsigned long)fields.remaining_tokens);
        fflush(stdout);
        last_status = (int)fields.status;
        if (delay_ms > 0 && attempt + 1 < repeat) {
            Sleep((DWORD)delay_ms);
        }
    }

    if (expect_status >= 0 && last_status != expect_status) {
        fprintf(stderr, "expected status %d, got %d\n", expect_status,
                last_status);
        return 20;
    }
    if (expect_status >= 0) return 0;
    return last_status;
}
