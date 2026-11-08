/*
 * fake_server_main.c — 攻击回归用伪造管道服务端（不随生产分发）
 *
 * 生成独立 ECDSA 密钥并对响应签名，或直接返回零签名；用于验证客户端
 * 对伪造服务端 fail-closed。仅接受一个连接后退出。
 */
#include "protocol.h"
#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <stdio.h>
#include <string.h>

int wmain(int argc, wchar_t **argv)
{
    wchar_t pipe_name[128];
    int unsigned_mode = 0;
    int i;
    HANDLE pipe;
    HANDLE client_connected = NULL;
    uint8_t request[VTY_SVC_REQUEST_BYTES];
    DWORD got = 0;
    VtySvcRequestFields fields;
    uint8_t response[VTY_SVC_RESPONSE_BYTES];
    uint8_t priv[VTY_ECC_BLOB_MAX];
    uint8_t pub[VTY_ECC_BLOB_MAX];
    DWORD priv_len = 0;
    DWORD pub_len = 0;
    BCRYPT_KEY_HANDLE key = NULL;
    uint8_t hash[VTY_HASH_BYTES];

    (void)vty_wide_copy(pipe_name, 128, L"\\\\.\\pipe\\VerthysFakeService");
    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--pipe") == 0 && i + 1 < argc) {
            (void)vty_wide_copy(pipe_name, 128, argv[++i]);
        } else if (wcscmp(argv[i], L"--unsigned") == 0) {
            unsigned_mode = 1;
        }
    }

    pipe = CreateNamedPipeW(
        pipe_name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 512, 512, 0,
        NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "fake server create failed: %lu\n",
                (unsigned long)GetLastError());
        return 1;
    }
    fprintf(stderr, "FAKE_READY\n");
    fflush(stderr);

    if (ConnectNamedPipe(pipe, NULL) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
        client_connected = (HANDLE)1;
    } else {
        fprintf(stderr, "fake server connect failed: %lu\n",
                (unsigned long)GetLastError());
        CloseHandle(pipe);
        return 2;
    }
    (void)client_connected;

    if (!ReadFile(pipe, request, sizeof(request), &got, NULL) ||
        got != VTY_SVC_REQUEST_BYTES) {
        CloseHandle(pipe);
        return 3;
    }
    memset(&fields, 0, sizeof(fields));
    (void)vty_svc_request_decode(request, got, &fields);

    if (!unsigned_mode) {
        if (vty_ecc_generate_keypair(priv, &priv_len, VTY_ECC_BLOB_MAX, pub,
                                     &pub_len, VTY_ECC_BLOB_MAX) != 0 ||
            vty_ecc_load_private(priv, priv_len, &key) != 0) {
            CloseHandle(pipe);
            return 4;
        }
    }

    vty_svc_response_encode(response, (uint16_t)VTY_SVC_STATUS_OK,
                            fields.request_id, 0u, fields.nonce_lo,
                            fields.nonce_hi, 10u, 0u);
    if (!unsigned_mode) {
        if (vty_sha256(response, VTY_SVC_RESPONSE_HEADER_BYTES, hash) != 0 ||
            vty_ecc_sign(key, hash, response + VTY_SVC_RESPONSE_HEADER_BYTES) !=
                0) {
            vty_ecc_free_key(&key);
            CloseHandle(pipe);
            return 5;
        }
    }
    (void)WriteFile(pipe, response, sizeof(response), &got, NULL);
    vty_ecc_free_key(&key);
    vty_secure_zero(priv, sizeof(priv));
    (void)DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}
