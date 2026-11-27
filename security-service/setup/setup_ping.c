/*
 * setup_ping.c — 服务公钥读取、PING 往返与就绪探测
 */

#include "setup_internal.h"

static int read_pubkey_registry(HKEY key, uint8_t *pub, DWORD cap, DWORD *len)
{
    return vty_registry_read_binary(key, VTY_SVC_REG_SERVER_PUBKEY, pub, cap,
                                    len) == 0 &&
                   *len > 0
               ? 0
               : -1;
}

static int setup_ping(HKEY key, DWORD timeout_ms)
{
    uint8_t pub[VTY_ECC_BLOB_MAX];
    DWORD pub_len = 0;
    uint8_t request[VTY_SVC_REQUEST_BYTES];
    uint8_t response[VTY_SVC_RESPONSE_BYTES];
    DWORD response_len = 0;
    VtySvcResponseFields fields;
    uint32_t request_id = 0;
    uint64_t nonce_lo = 0;
    uint64_t nonce_hi = 0;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    OVERLAPPED ov;
    HANDLE event;
    BOOL ok;
    DWORD transferred = 0;
    int rc = -1;

    memset(pub, 0, sizeof(pub));
    memset(&fields, 0, sizeof(fields));
    if (read_pubkey_registry(key, pub, sizeof(pub), &pub_len) != 0) {
        return -1;
    }
    if (BCryptGenRandom(NULL, (PUCHAR)&request_id, sizeof(request_id),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        BCryptGenRandom(NULL, (PUCHAR)&nonce_lo, sizeof(nonce_lo),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        BCryptGenRandom(NULL, (PUCHAR)&nonce_hi, sizeof(nonce_hi),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        goto done;
    }
    vty_svc_request_encode(request, (uint16_t)VTY_SVC_CMD_PING, request_id,
                           nonce_lo, nonce_hi);

    pipe = CreateFileW(VTY_SVC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (pipe == INVALID_HANDLE_VALUE &&
        GetLastError() == ERROR_PIPE_BUSY) {
        (void)WaitNamedPipeW(VTY_SVC_PIPE_NAME,
                             VTY_SVC_CLIENT_CONNECT_TIMEOUT_MS);
        pipe = CreateFileW(VTY_SVC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                           NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    }
    if (pipe == INVALID_HANDLE_VALUE) goto done;
    {
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)) goto done;
    }

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) goto done;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = event;

    ok = WriteFile(pipe, request, VTY_SVC_REQUEST_BYTES, &transferred, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            CloseHandle(event);
            goto done;
        }
        ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
    }
    if (!ok || transferred != VTY_SVC_REQUEST_BYTES) {
        CloseHandle(event);
        goto done;
    }

    memset(&ov, 0, sizeof(ov));
    ResetEvent(event);
    ov.hEvent = event;
    ok = ReadFile(pipe, response, VTY_SVC_RESPONSE_BYTES, &transferred, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            CloseHandle(event);
            goto done;
        }
        ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
    }
    CloseHandle(event);
    if (!ok || transferred != VTY_SVC_RESPONSE_BYTES) goto done;
    response_len = transferred;

    if (vty_svc_response_decode(response, response_len, request_id, nonce_lo,
                                nonce_hi, &fields) !=
        (uint16_t)VTY_SVC_STATUS_OK) {
        goto done;
    }
    {
        uint8_t hash[VTY_HASH_BYTES];
        if (vty_sha256(response, VTY_SVC_RESPONSE_HEADER_BYTES, hash) != 0) {
            goto done;
        }
        if (vty_ecc_verify(pub, pub_len, hash,
                           response + VTY_SVC_RESPONSE_HEADER_BYTES) != 0) {
            vty_secure_zero(hash, sizeof(hash));
            goto done;
        }
        vty_secure_zero(hash, sizeof(hash));
    }
    rc = (fields.status == (uint16_t)VTY_SVC_STATUS_OK) ? 0 : -1;

done:
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    vty_secure_zero(pub, sizeof(pub));
    vty_secure_zero(request, sizeof(request));
    vty_secure_zero(response, sizeof(response));
    return rc;
}

int readiness(HKEY key, int skip_ping)
{
    DWORD waited = 0;
    DWORD value = 0;
    DWORD pub_len = 0;
    uint8_t pub[VTY_ECC_BLOB_MAX];

    while (waited < 30000u) {
        if (vty_registry_read_dword(key, VTY_SVC_REG_STATE_INITIALIZED,
                                    &value) == 0 &&
            value == 1u && read_pubkey_registry(key, pub, sizeof(pub), &pub_len) == 0) {
            if (skip_ping) return 0;
            if (setup_ping(key, VTY_SVC_CLIENT_REPLY_TIMEOUT_MS) == 0) return 0;
        }
        Sleep(200);
        waited += 200;
    }
    return -1;
}
