/*
 * test_machine_limiter.c
 *
 * 全部使用进程内伪服务端 + 环境变量测试钩子，不触碰真实 HKLM 服务键。
 */
#include <windows.h>
#include <bcrypt.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

#include "verthys_test.h"
#include "verthys.h"
#include "vty_kdf.h"
#include "vty_machine_limiter.h"
#include "vty_recovery.h"
#include "vty_svc_protocol.h"

#define ML_TEST_PRIV_MAX 256u
#define ML_TEST_PUB_MAX 256u

typedef struct FakePipeServer {
    wchar_t pipe_name[256];
    wchar_t pubkey_file[512];
    int mode;
    uint8_t priv[ML_TEST_PRIV_MAX];
    DWORD priv_len;
    uint8_t pub[ML_TEST_PUB_MAX];
    DWORD pub_len;
    uint8_t wrong_priv[ML_TEST_PRIV_MAX];
    DWORD wrong_priv_len;
    HANDLE thread;
    volatile LONG ready;
} FakePipeServer;

enum {
    FAKE_MODE_OK = 0,
    FAKE_MODE_LOCKED = 1,
    FAKE_MODE_BAD_SIGNATURE = 2,
    FAKE_MODE_BAD_NONCE = 3,
    FAKE_MODE_TIMEOUT = 4
};

static LONG g_pipe_counter = 0;

static int generate_keypair(uint8_t *priv, DWORD *priv_len, uint8_t *pub,
                            DWORD *pub_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;
    int rc = -1;

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return -1;
    status = BCryptGenerateKeyPair(alg, &key, 256, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptFinalizeKeyPair(key, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, priv,
                             ML_TEST_PRIV_MAX, priv_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, pub,
                             ML_TEST_PUB_MAX, pub_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    rc = 0;

done:
    if (key != NULL) BCryptDestroyKey(key);
    if (alg != NULL) BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

static int sign_response(const uint8_t *priv, DWORD priv_len,
                         uint8_t response[VTY_SVC_RESPONSE_BYTES])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    uint8_t hash[32];
    DWORD sig_len = 0;
    NTSTATUS status;
    int rc = -1;

    if (vty_sha256(hash, response, VTY_SVC_RESPONSE_HEADER_BYTES) != VTY_OK) {
        return -1;
    }
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &key,
                                 (PUCHAR)priv, priv_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptSignHash(key, NULL, hash, 32,
                            response + VTY_SVC_RESPONSE_HEADER_BYTES,
                            VTY_SVC_SIGNATURE_BYTES, &sig_len, 0);
    if (BCRYPT_SUCCESS(status) && sig_len == VTY_SVC_SIGNATURE_BYTES) rc = 0;

done:
    if (key != NULL) BCryptDestroyKey(key);
    if (alg != NULL) BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

static int write_file_bytes(const wchar_t *path, const uint8_t *data,
                            DWORD len)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    int rc = -1;

    if (file == INVALID_HANDLE_VALUE) return -1;
    if (WriteFile(file, data, len, &written, NULL) && written == len) rc = 0;
    CloseHandle(file);
    return rc;
}

static unsigned __stdcall fake_server_thread(void *arg)
{
    FakePipeServer *server = (FakePipeServer *)arg;
    HANDLE pipe;
    uint8_t request[VTY_SVC_REQUEST_BYTES];
    DWORD got = 0;
    VtySvcRequestFields fields;
    uint8_t response[VTY_SVC_RESPONSE_BYTES];

    pipe = CreateNamedPipeW(
        server->pipe_name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 512, 512, 0,
        NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        InterlockedExchange(&server->ready, 1);
        return 0;
    }
    InterlockedExchange(&server->ready, 1);
    if (!ConnectNamedPipe(pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(pipe);
        return 0;
    }
    if (!ReadFile(pipe, request, sizeof(request), &got, NULL) ||
        got != VTY_SVC_REQUEST_BYTES) {
        CloseHandle(pipe);
        return 0;
    }
    memset(&fields, 0, sizeof(fields));
    (void)vty_svc_request_decode(request, got, &fields);

    if (server->mode == FAKE_MODE_TIMEOUT) {
        Sleep(2000);
        CloseHandle(pipe);
        return 0;
    }

    vty_svc_response_encode(
        response,
        server->mode == FAKE_MODE_LOCKED ? (uint16_t)VTY_SVC_STATUS_LOCKED
                                         : (uint16_t)VTY_SVC_STATUS_OK,
        fields.request_id, server->mode == FAKE_MODE_LOCKED ? 5u : 0u,
        fields.nonce_lo,
        server->mode == FAKE_MODE_BAD_NONCE ? fields.nonce_hi + 1u
                                            : fields.nonce_hi,
        10u, 1700000000ULL);
    if (server->mode == FAKE_MODE_BAD_SIGNATURE) {
        if (server->wrong_priv_len != 0) {
            (void)sign_response(server->wrong_priv, server->wrong_priv_len,
                                response);
        }
    } else {
        (void)sign_response(server->priv, server->priv_len, response);
    }
    (void)WriteFile(pipe, response, sizeof(response), &got, NULL);
    Sleep(20);
    (void)DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

static int start_fake_server(FakePipeServer *server, int mode)
{
    memset(server, 0, sizeof(*server));
    server->mode = mode;
    if (swprintf_s(server->pipe_name, 256,
                   L"\\\\.\\pipe\\VerthysMLTest-%lu-%llu-%ld",
                   (unsigned long)GetCurrentProcessId(),
                   (unsigned long long)GetTickCount64(),
                   (long)InterlockedIncrement(&g_pipe_counter)) < 0) {
        return -1;
    }
    {
        wchar_t temp[MAX_PATH];
        if (GetTempPathW(MAX_PATH, temp) == 0 ||
            swprintf_s(server->pubkey_file, 512,
                       L"%lsverthys-ml-pub-%lu-%ld.bin", temp,
                       (unsigned long)GetCurrentProcessId(),
                       (long)InterlockedIncrement(&g_pipe_counter)) < 0) {
            return -1;
        }
    }
    if (generate_keypair(server->priv, &server->priv_len, server->pub,
                         &server->pub_len) != 0) {
        return -1;
    }
    if (mode == FAKE_MODE_BAD_SIGNATURE) {
        uint8_t dummy_pub[ML_TEST_PUB_MAX];
        DWORD dummy_pub_len = 0;
        if (generate_keypair(server->wrong_priv, &server->wrong_priv_len,
                             dummy_pub, &dummy_pub_len) != 0) {
            return -1;
        }
    }
    if (write_file_bytes(server->pubkey_file, server->pub, server->pub_len) !=
        0) {
        return -1;
    }
    server->thread = (HANDLE)_beginthreadex(NULL, 0, fake_server_thread, server,
                                            0, NULL);
    if (server->thread == NULL) return -1;
    for (int i = 0; i < 100; i++) {
        if (InterlockedCompareExchange(&server->ready, 0, 0) != 0) break;
        Sleep(10);
    }
    return 0;
}

static void stop_fake_server(FakePipeServer *server)
{
    if (server->thread != NULL) {
        WaitForSingleObject(server->thread, 5000);
        CloseHandle(server->thread);
        server->thread = NULL;
    }
    if (server->pubkey_file[0] != L'\0') {
        DeleteFileW(server->pubkey_file);
    }
}

static void clear_env(void)
{
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_INSTALLED", NULL);
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PIPE", NULL);
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PUBKEY_PATH", NULL);
    SetEnvironmentVariableW(L"VERTHYS_TEST_MACHINE_LIMITER_BYPASS", NULL);
}

static void set_env(const wchar_t *installed, const wchar_t *pipe,
                    const wchar_t *pubkey_file)
{
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_INSTALLED", installed);
    if (pipe != NULL) {
        SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PIPE", pipe);
    } else {
        SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PIPE", NULL);
    }
    if (pubkey_file != NULL) {
        SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PUBKEY_PATH",
                                pubkey_file);
    } else {
        SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PUBKEY_PATH", NULL);
    }
}

int machine_limiter_uninstalled_fail_closed(void)
{
    clear_env();
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_INSTALLED", L"0");
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PIPE",
                            L"\\\\.\\pipe\\VerthysMLTest-absent");
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_machine_limiter_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_machine_limiter_reset(), VTY_E_LOCKED);
    clear_env();
    return 0;
}

int machine_limiter_test_default_fail_closed(void)
{
    clear_env();
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_machine_limiter_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_machine_limiter_reset(), VTY_E_LOCKED);
    return 0;
}

int machine_limiter_pipe_unreachable(void)
{
    FakePipeServer key_source;
    memset(&key_source, 0, sizeof(key_source));
    if (generate_keypair(key_source.priv, &key_source.priv_len, key_source.pub,
                         &key_source.pub_len) != 0) {
        CHECK(0);
    }
    {
        wchar_t pub_file[512];
        wchar_t temp[MAX_PATH];
        if (GetTempPathW(MAX_PATH, temp) == 0 ||
            swprintf_s(pub_file, 512, L"%lsverthys-ml-pub-unreachable-%lu.bin",
                       temp, (unsigned long)GetCurrentProcessId()) < 0) {
            CHECK(0);
        }
        if (write_file_bytes(pub_file, key_source.pub, key_source.pub_len) !=
            0) {
            CHECK(0);
        }
        set_env(L"1", L"\\\\.\\pipe\\VerthysMLTest-absent", pub_file);
        CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
        clear_env();
        DeleteFileW(pub_file);
    }
    return 0;
}

int machine_limiter_pubkey_missing(void)
{
    set_env(L"1", L"\\\\.\\pipe\\VerthysMLTest-absent",
            L"Z:\\definitely-missing-pubkey.bin");
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    clear_env();
    return 0;
}

int machine_limiter_bad_signature(void)
{
    FakePipeServer server;

    if (start_fake_server(&server, FAKE_MODE_BAD_SIGNATURE) != 0) {
        clear_env();
        CHECK(0);
    }
    set_env(L"1", server.pipe_name, server.pubkey_file);
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    clear_env();
    stop_fake_server(&server);
    return 0;
}

int machine_limiter_nonce_mismatch(void)
{
    FakePipeServer server;

    if (start_fake_server(&server, FAKE_MODE_BAD_NONCE) != 0) {
        clear_env();
        CHECK(0);
    }
    set_env(L"1", server.pipe_name, server.pubkey_file);
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    clear_env();
    stop_fake_server(&server);
    return 0;
}

int machine_limiter_status_mapping(void)
{
    FakePipeServer ok_server;
    FakePipeServer locked_server;

    if (start_fake_server(&ok_server, FAKE_MODE_OK) != 0) {
        clear_env();
        CHECK(0);
    }
    set_env(L"1", ok_server.pipe_name, ok_server.pubkey_file);
    CHECK_EQ(vty_machine_limiter_check(), VTY_OK);
    clear_env();
    stop_fake_server(&ok_server);

    if (start_fake_server(&locked_server, FAKE_MODE_LOCKED) != 0) {
        clear_env();
        CHECK(0);
    }
    set_env(L"1", locked_server.pipe_name, locked_server.pubkey_file);
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_machine_limiter_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_machine_limiter_reset(), VTY_E_LOCKED);
    clear_env();
    stop_fake_server(&locked_server);
    return 0;
}

int machine_limiter_timeout(void)
{
    FakePipeServer server;
    ULONGLONG start;
    ULONGLONG elapsed;

    if (start_fake_server(&server, FAKE_MODE_TIMEOUT) != 0) {
        clear_env();
        CHECK(0);
    }
    set_env(L"1", server.pipe_name, server.pubkey_file);
    start = GetTickCount64();
    CHECK_EQ(vty_machine_limiter_check(), VTY_E_LOCKED);
    elapsed = GetTickCount64() - start;
    CHECK(elapsed < 1500u);
    clear_env();
    stop_fake_server(&server);
    return 0;
}

/* ------------------------------------------------------------------ *
 * 主路径接入验收
 *
 * 下面两个用例证明机器预算不是孤立的客户端实现，而是真正位于
 * V4 解锁与模块解锁的口令校验之前：服务未安装、管道不可达、预算
 * 耗尽三种情况下，正确口令也必须返回 RATE，且不得继续执行 Argon2id。
 * ------------------------------------------------------------------ */

static void set_bypass(int enabled)
{
    SetEnvironmentVariableW(L"VERTHYS_TEST_MACHINE_LIMITER_BYPASS",
                            enabled ? L"1" : NULL);
}

static int make_test_pubkey(wchar_t path[512], uint8_t *priv, DWORD *priv_len,
                            uint8_t *pub, DWORD *pub_len)
{
    wchar_t temp[MAX_PATH];

    if (GetTempPathW(MAX_PATH, temp) == 0 ||
        swprintf_s(path, 512, L"%lsverthys-ml-v4-pub-%lu.bin", temp,
                   (unsigned long)GetCurrentProcessId()) < 0) {
        return -1;
    }
    if (generate_keypair(priv, priv_len, pub, pub_len) != 0) return -1;
    return write_file_bytes(path, pub, *pub_len);
}

int v4_unlock_machine_gate_fail_closed(void)
{
    VerthysHandle h = NULL;
    char recovery[VTY_RECOVERY_TEXT_BUF];
    FakePipeServer server;
    wchar_t pub_file[512];
    uint8_t priv[ML_TEST_PRIV_MAX];
    uint8_t pub[ML_TEST_PUB_MAX];
    DWORD priv_len = 0;
    DWORD pub_len = 0;
    const char *path = "machine_limiter_v4.verthys";
    const char *pw = "ml-v4-password";
    int pub_written = 0;
    int server_started = 0;
    int failed = 0;

    memset(&server, 0, sizeof(server));
    clear_env();
    set_bypass(1);
    remove(path);

    if (Verthys_Init(&h) != VERTHYS_OK) {
        printf("  [FAIL] init\n");
        failed = 1;
        goto done;
    }
    if (Verthys_V4Create(h, path, pw, strlen(pw), recovery,
                         sizeof(recovery)) != VERTHYS_OK) {
        printf("  [FAIL] create\n");
        failed = 1;
        goto done;
    }
    if (Verthys_Lock(h) != VERTHYS_OK) {
        printf("  [FAIL] lock\n");
        failed = 1;
        goto done;
    }

    /* 1. 服务未安装：默认测试构建即 fail-closed。 */
    clear_env();
    if (Verthys_V4Unlock(h, path, pw, strlen(pw)) != VERTHYS_ERR_RATE) {
        printf("  [FAIL] uninstalled must return RATE\n");
        failed = 1;
        goto done;
    }

    /* 2. 服务已安装但管道不可达。 */
    if (make_test_pubkey(pub_file, priv, &priv_len, pub, &pub_len) != 0) {
        printf("  [FAIL] pubkey fixture\n");
        failed = 1;
        goto done;
    }
    pub_written = 1;
    set_env(L"1", L"\\\\.\\pipe\\VerthysMLTest-absent", pub_file);
    if (Verthys_V4Unlock(h, path, pw, strlen(pw)) != VERTHYS_ERR_RATE) {
        printf("  [FAIL] unreachable service must return RATE\n");
        failed = 1;
        goto done;
    }

    /* 3. 服务返回预算耗尽（LOCKED）。 */
    if (start_fake_server(&server, FAKE_MODE_LOCKED) != 0) {
        printf("  [FAIL] fake locked server\n");
        failed = 1;
        goto done;
    }
    server_started = 1;
    set_env(L"1", server.pipe_name, server.pubkey_file);
    if (Verthys_V4Unlock(h, path, pw, strlen(pw)) != VERTHYS_ERR_RATE) {
        printf("  [FAIL] exhausted budget must return RATE\n");
        failed = 1;
        goto done;
    }

    /* 4. 恢复测试旁路后同一口令可正常解锁：证明拦截点在预算门，
     *    而不是口令或容器路径被破坏。 */
    clear_env();
    set_bypass(1);
    if (Verthys_V4Unlock(h, path, pw, strlen(pw)) != VERTHYS_OK) {
        printf("  [FAIL] unlock with bypass rc\n");
        failed = 1;
        goto done;
    }

done:
    clear_env();
    set_bypass(1);
    if (h != NULL) Verthys_Deinit(h);
    if (server_started) stop_fake_server(&server);
    if (pub_written) DeleteFileW(pub_file);
    remove(path);
    return failed;
}

int v4_module_unlock_machine_gate_fail_closed(void)
{
    VerthysHandle h = NULL;
    char recovery[VTY_RECOVERY_TEXT_BUF];
    const char *path = "machine_limiter_module.verthys";
    const char *pw = "ml-module-vault";
    const char *mpw = "ml-module-password";
    int failed = 0;

    clear_env();
    set_bypass(1);
    remove(path);

    if (Verthys_Init(&h) != VERTHYS_OK) {
        printf("  [FAIL] init\n");
        failed = 1;
        goto done;
    }
    if (Verthys_V4Create(h, path, pw, strlen(pw), recovery,
                         sizeof(recovery)) != VERTHYS_OK) {
        printf("  [FAIL] create\n");
        failed = 1;
        goto done;
    }
    if (Verthys_V4ModuleEnable(h, VERTHYS_MODULE_PHOTO, mpw, strlen(mpw),
                               NULL) != VERTHYS_OK) {
        printf("  [FAIL] module enable\n");
        failed = 1;
        goto done;
    }
    if (Verthys_V4ModuleLock(h, VERTHYS_MODULE_PHOTO) != VERTHYS_OK) {
        printf("  [FAIL] module lock\n");
        failed = 1;
        goto done;
    }

    /* 服务未安装：模块口令校验前必须被机器预算拦截。 */
    clear_env();
    if (Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO, mpw,
                               strlen(mpw)) != VERTHYS_ERR_RATE) {
        printf("  [FAIL] module unlock must return RATE\n");
        failed = 1;
        goto done;
    }

    /* 恢复旁路后同一模块口令可正常解锁。 */
    set_bypass(1);
    if (Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO, mpw,
                               strlen(mpw)) != VERTHYS_OK) {
        printf("  [FAIL] module unlock with bypass rc\n");
        failed = 1;
        goto done;
    }

done:
    clear_env();
    set_bypass(1);
    if (h != NULL) Verthys_Deinit(h);
    remove(path);
    return failed;
}
