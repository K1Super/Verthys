/*
 * vty_machine_limiter.c
 *
 * 语义契约：
 *   - check 返回 VTY_OK 放行；VTY_E_LOCKED 表示机器级预算耗尽或服务不可信。
 *   - record_failure/reset 只发请求，不改变本地熔断与退避计数。
 *
 * 安全语义（无旧版本兼容路径）：
 *   - 服务是强制依赖；注册表 Installed != 1、公钥缺失、连接失败、超时、
 *     验签失败、字段不符全部映射为 VTY_E_LOCKED（fail-closed）。
 *   - 不允许在服务未安装/不可达时静默降级到仅本地熔断。
 *   - 测试构建在未显式注入 VERTHYS_TEST_SERVICE_INSTALLED 时默认按
 *     “未安装” fail-closed，避免单元测试触碰开发机上的真实服务预算。
 */
#define _WIN32_WINNT 0x0A00
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>
#include <string.h>

#include "vty_machine_limiter.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_svc_protocol.h"
#include "security_preset.h"

#define VTY_ML_PUBKEY_MAX 256u
#define VTY_ML_PIPE_MAX 512u

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static int ml_env_ascii(const char *name, char *out, size_t cap)
{
    DWORD n = GetEnvironmentVariableA(name, out, (DWORD)cap);
    return (n > 0 && n < (DWORD)cap) ? 1 : 0;
}

/*
 * 仅测试构建使用的本地熔断回归旁路：单元测试不启动真实服务，
 * 显式设置 VERTHYS_TEST_MACHINE_LIMITER_BYPASS=1 时跳过机器预算调用。
 * 生产构建不编译该分支，产品路径始终 fail-closed。
 */
static int ml_test_bypass(void)
{
    char env[8];
    return ml_env_ascii("VERTHYS_TEST_MACHINE_LIMITER_BYPASS", env,
                        sizeof(env)) == 1 &&
                   strcmp(env, "1") == 0
               ? 1
               : 0;
}
#endif

static int ml_svc_installed(int *installed_out)
{
    DWORD value = 0;
    DWORD type = 0;
    DWORD size = sizeof(value);
    HKEY key = NULL;
    LONG rc;

    if (installed_out == NULL) return -1;
    *installed_out = 0;

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        char env[8];
        if (ml_env_ascii("VERTHYS_TEST_SERVICE_INSTALLED", env, sizeof(env)) ==
            1) {
            if (strcmp(env, "1") == 0) {
                *installed_out = 1;
                return 0;
            }
            if (strcmp(env, "0") == 0) {
                *installed_out = 0;
                return 0;
            }
            return -1;
        }
        /*
         * 测试构建默认按未安装处理并 fail-closed；显式注入
         * VERTHYS_TEST_SERVICE_INSTALLED=1 时才连接测试服务。
         * 这样默认单元测试不会读取真实 HKLM 服务键。
         */
        *installed_out = 0;
        return 0;
    }
#endif

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, VTY_SVC_REGISTRY_KEY, 0,
                       KEY_READ | KEY_WOW64_64KEY, &key);
    if (rc == ERROR_FILE_NOT_FOUND) {
        *installed_out = 0;
        return 0;
    }
    if (rc != ERROR_SUCCESS) return -1;
    rc = RegQueryValueExW(key, VTY_SVC_REG_INSTALLED, NULL, &type,
                          (LPBYTE)&value, &size);
    RegCloseKey(key);
    if (rc == ERROR_FILE_NOT_FOUND) {
        *installed_out = 0;
        return 0;
    }
    if (rc != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(value)) {
        return -1;
    }
    *installed_out = (value == 1u) ? 1 : 0;
    return 0;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static int ml_env_wide(const char *name, wchar_t *out, size_t cap)
{
    char value[VTY_ML_PIPE_MAX];
    int n;

    if (out == NULL || cap == 0) return -1;
    out[0] = L'\0';
    if (ml_env_ascii(name, value, sizeof(value)) != 1) return 0;
    n = MultiByteToWideChar(CP_UTF8, 0, value, -1, out, (int)cap);
    return (n > 0) ? 1 : -1;
}
#endif

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static int ml_read_test_pubkey(const wchar_t *path, uint8_t *buf, DWORD cap,
                               DWORD *len)
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD total = 0;
    DWORD got = 0;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > (LONGLONG)cap) {
        CloseHandle(file);
        return -1;
    }
    while (total < (DWORD)size.QuadPart) {
        if (!ReadFile(file, buf + total, (DWORD)size.QuadPart - total, &got,
                      NULL) ||
            got == 0) {
            CloseHandle(file);
            return -1;
        }
        total += got;
    }
    CloseHandle(file);
    *len = total;
    return 0;
}
#endif

static int ml_read_pubkey(uint8_t *buf, DWORD cap, DWORD *len)
{
    HKEY key = NULL;
    DWORD type = 0;
    DWORD size = cap;
    LONG rc;

    if (buf == NULL || len == NULL || cap == 0) return -1;
    *len = 0;

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        wchar_t path[VTY_ML_PIPE_MAX];
        int present = ml_env_wide("VERTHYS_TEST_SERVICE_PUBKEY_PATH", path,
                                  VTY_ML_PIPE_MAX);
        if (present < 0) return -1;
        if (present == 1) {
            return ml_read_test_pubkey(path, buf, cap, len);
        }
    }
#endif

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, VTY_SVC_REGISTRY_KEY, 0,
                       KEY_READ | KEY_WOW64_64KEY, &key);
    if (rc != ERROR_SUCCESS) return -1;
    rc = RegQueryValueExW(key, VTY_SVC_REG_SERVER_PUBKEY, NULL, &type, buf,
                          &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_BINARY || size == 0 ||
        size > cap) {
        return -1;
    }
    *len = size;
    return 0;
}

static int ml_pipe_name(wchar_t *out, size_t cap)
{
    if (out == NULL || cap == 0) return -1;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        int present = ml_env_wide("VERTHYS_TEST_SERVICE_PIPE", out, cap);
        if (present < 0) return -1;
        if (present == 1) return 0;
    }
#endif
    if (wcslen(VTY_SVC_PIPE_NAME) >= cap) return -1;
    memcpy(out, VTY_SVC_PIPE_NAME,
           (wcslen(VTY_SVC_PIPE_NAME) + 1u) * sizeof(wchar_t));
    return 0;
}

static HANDLE ml_pipe_connect(const wchar_t *name)
{
    HANDLE pipe;
    DWORD mode = PIPE_READMODE_MESSAGE;

    pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (pipe == INVALID_HANDLE_VALUE &&
        GetLastError() == ERROR_PIPE_BUSY) {
        (void)WaitNamedPipeW(name, VTY_SVC_CLIENT_CONNECT_TIMEOUT_MS);
        pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    }
    if (pipe == INVALID_HANDLE_VALUE) return NULL;
    if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)) {
        CloseHandle(pipe);
        return NULL;
    }
    return pipe;
}

static int ml_io_write(HANDLE pipe, const uint8_t *buf, DWORD len)
{
    OVERLAPPED ov;
    HANDLE event;
    DWORD transferred = 0;
    BOOL ok;
    DWORD err;
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
    if (WaitForSingleObject(event, VTY_SVC_CLIENT_REPLY_TIMEOUT_MS) !=
        WAIT_OBJECT_0) {
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

static int ml_io_read(HANDLE pipe, uint8_t *buf, DWORD cap, DWORD *len)
{
    OVERLAPPED ov;
    HANDLE event;
    DWORD transferred = 0;
    BOOL ok;
    DWORD err;
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
    if (WaitForSingleObject(event, VTY_SVC_CLIENT_REPLY_TIMEOUT_MS) !=
        WAIT_OBJECT_0) {
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

static int ml_verify_signature(const uint8_t *pub, DWORD pub_len,
                               const uint8_t *response)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;
    uint8_t hash[VTY_HASH_BYTES];
    int rc = -1;

    if (vty_sha256(hash, response, VTY_SVC_RESPONSE_HEADER_BYTES) != VTY_OK) {
        return -1;
    }
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &key,
                                 (PUCHAR)pub, pub_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptVerifySignature(
        key, NULL, hash, VTY_HASH_BYTES,
        (PUCHAR)(response + VTY_SVC_RESPONSE_HEADER_BYTES),
        VTY_SVC_SIGNATURE_BYTES, 0);
    if (BCRYPT_SUCCESS(status)) rc = 0;

done:
    if (key != NULL) BCryptDestroyKey(key);
    if (alg != NULL) BCryptCloseAlgorithmProvider(alg, 0);
    vty_secure_zero(hash, sizeof(hash));
    return rc;
}

static int ml_request_fields(uint16_t command, int kernel_fields,
                             VtySvcResponseFields *out_fields)
{
    int installed = 0;
    uint8_t pub[VTY_ML_PUBKEY_MAX];
    DWORD pub_len = 0;
    wchar_t pipe_name[VTY_ML_PIPE_MAX];
    HANDLE pipe = NULL;
    uint8_t request[VTY_SVC_REQUEST_BYTES];
    uint8_t response[VTY_SVC_RESPONSE_BYTES];
    DWORD response_len = 0;
    VtySvcResponseFields fields;
    uint32_t request_id = 0;
    uint64_t nonce_lo = 0;
    uint64_t nonce_hi = 0;
    int result = VTY_E_LOCKED;

    memset(pub, 0, sizeof(pub));
    memset(&fields, 0, sizeof(fields));

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    if (ml_test_bypass()) return VTY_OK;
#endif
    if (ml_svc_installed(&installed) != 0) return VTY_E_LOCKED;
    if (!installed) return VTY_E_LOCKED;

    if (ml_read_pubkey(pub, sizeof(pub), &pub_len) != 0 || pub_len == 0) {
        goto done;
    }
    if (ml_pipe_name(pipe_name, VTY_ML_PIPE_MAX) != 0) goto done;
    pipe = ml_pipe_connect(pipe_name);
    if (pipe == NULL) goto done;

    vty_random((uint8_t *)&request_id, sizeof(request_id));
    vty_random((uint8_t *)&nonce_lo, sizeof(nonce_lo));
    vty_random((uint8_t *)&nonce_hi, sizeof(nonce_hi));
    vty_svc_request_encode(request, command, request_id, nonce_lo, nonce_hi);

    if (ml_io_write(pipe, request, VTY_SVC_REQUEST_BYTES) != 0) goto done;
    if (ml_io_read(pipe, response, VTY_SVC_RESPONSE_BYTES, &response_len) !=
        0) {
        goto done;
    }
    if (kernel_fields) {
        if (vty_svc_response_decode_kernel(response, response_len, request_id,
                                           nonce_lo, nonce_hi, &fields) !=
            (uint16_t)VTY_SVC_STATUS_OK) {
            goto done;
        }
    } else if (vty_svc_response_decode(response, response_len, request_id,
                                       nonce_lo, nonce_hi, &fields) !=
               (uint16_t)VTY_SVC_STATUS_OK) {
        goto done;
    }
    if (ml_verify_signature(pub, pub_len, response) != 0) goto done;
    if (out_fields != NULL) {
        *out_fields = fields;
    }
    result = (fields.status == (uint16_t)VTY_SVC_STATUS_OK) ? VTY_OK
                                                            : VTY_E_LOCKED;

done:
    if (pipe != NULL) CloseHandle(pipe);
    vty_secure_zero(pub, sizeof(pub));
    memset(request, 0, sizeof(request));
    memset(response, 0, sizeof(response));
    return result;
}

static int ml_request(uint16_t command)
{
    return ml_request_fields(command, 0, NULL);
}

int vty_machine_limiter_check(void)
{
    return ml_request((uint16_t)VTY_SVC_CMD_CHECK);
}

int vty_machine_limiter_record_failure(void)
{
    return ml_request((uint16_t)VTY_SVC_CMD_RECORD_FAILURE);
}

int vty_machine_limiter_reset(void)
{
    return ml_request((uint16_t)VTY_SVC_CMD_RESET);
}

int vty_machine_limiter_kernel_status(VtyKernelStatus *out)
{
    VtySvcResponseFields fields;
    int installed = 0;
    int rc;

    if (out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    out->state = (uint32_t)VTY_KERNEL_STATE_UNKNOWN;
    out->reason = (uint32_t)VTY_KERNEL_REASON_INTERNAL;
    memset(&fields, 0, sizeof(fields));

    rc = ml_request_fields((uint16_t)VTY_SVC_CMD_KERNEL_STATUS, 1, &fields);
    if (rc != VTY_OK) {
        if (ml_svc_installed(&installed) == 0 && !installed) {
            out->state = (uint32_t)VTY_KERNEL_STATE_NOT_INSTALLED;
            out->reason = (uint32_t)VTY_KERNEL_REASON_NOT_INSTALLED;
        } else {
            out->state = (uint32_t)VTY_KERNEL_STATE_UNHEALTHY;
            out->reason = (uint32_t)VTY_KERNEL_REASON_INTERNAL;
        }
        return VTY_OK;
    }

    out->state = fields.kernel_state;
    out->reason = fields.kernel_reason;
    out->capabilities = fields.kernel_capabilities;
    out->protocol_major = fields.kernel_protocol_major;
    out->protocol_minor = fields.kernel_protocol_minor;
    return VTY_OK;
}

int vty_machine_limiter_kernel_arm(void)
{
    return ml_request_fields((uint16_t)VTY_SVC_CMD_KERNEL_ARM, 1, NULL);
}

int vty_machine_limiter_kernel_register(void)
{
    return ml_request_fields((uint16_t)VTY_SVC_CMD_KERNEL_REGISTER, 1, NULL);
}

int vty_machine_limiter_kernel_disarm(void)
{
    return ml_request_fields((uint16_t)VTY_SVC_CMD_KERNEL_DISARM, 1, NULL);
}

/*
 * 进程级保护获取状态：仅在 arm+register 均成功后置位，避免每次解锁/切档
 * 重复 ARM 造成受保护表被清空。服务重启或驱动丢失时该标志不会自动复位，
 * 由锁定路径释放；运行中丢失的自动锁定属于后续健康检查范围。
 */
static volatile LONG g_kernel_guard_acquired;
static SRWLOCK g_kernel_guard_lock = SRWLOCK_INIT;

void vty_machine_limiter_kernel_guard_apply_preset(void)
{
    SecurityPreset preset = SEC_PRESET_BALANCED;

    if (security_active_preset(&preset) != 0) {
        /* 档位不可判定时不启用，也不拆除既有保护。 */
        return;
    }
    if (preset != SEC_PRESET_SECURE) {
        vty_machine_limiter_kernel_guard_release();
        return;
    }

    AcquireSRWLockExclusive(&g_kernel_guard_lock);
    if (InterlockedCompareExchange(&g_kernel_guard_acquired, 0, 0) == 0) {
        VtyKernelStatus status;
        int registered = 0;

        memset(&status, 0, sizeof(status));
        /*
         * 宿主预 ARM 后，驱动在 worker 创建通知中已把本进程加入受保护表
         * 并将状态置为 ARMED/ACTIVE。此时再次 ARM 会先执行 VtgStateDisarm，
         * 清空宿主预登记，因此只补 REGISTER 确认自身表项。
         * 状态查询或登记失败时回退完整 ARM+REGISTER（服务重启等场景）。
         */
        if (vty_machine_limiter_kernel_status(&status) == VTY_OK &&
            (status.state == (uint32_t)VTY_KERNEL_STATE_ACTIVE ||
             status.state == (uint32_t)VTY_KERNEL_STATE_ARMED) &&
            vty_machine_limiter_kernel_register() == VTY_OK) {
            registered = 1;
        }
        if (!registered &&
            vty_machine_limiter_kernel_arm() == VTY_OK &&
            vty_machine_limiter_kernel_register() == VTY_OK) {
            registered = 1;
        }

        if (registered) {
            InterlockedExchange(&g_kernel_guard_acquired, 1);
        } else {
            /* 未登记成功时回滚，避免留下半生效状态。 */
            (void)vty_machine_limiter_kernel_disarm();
        }
    }
    ReleaseSRWLockExclusive(&g_kernel_guard_lock);
}

void vty_machine_limiter_kernel_guard_release(void)
{
    LONG acquired;

    /*
     * 释放必须与获取串行：若在锁外发送 DISARM，另一个线程可能在本线程
     * 清标志后立即 ARM，随后被本线程的 DISARM 误撤销。
     */
    AcquireSRWLockExclusive(&g_kernel_guard_lock);
    acquired = InterlockedExchange(&g_kernel_guard_acquired, 0);
    if (acquired != 0) {
        (void)vty_machine_limiter_kernel_disarm();
    }
    ReleaseSRWLockExclusive(&g_kernel_guard_lock);
}
