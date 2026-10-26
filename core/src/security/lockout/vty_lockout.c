/*
 * vty_lockout.c — 持久化失败计数与熔断实现
 *
 * 状态布局（v2）：header(24) + MAC(32) + 设备根 blob(290) + 见证{slot(1), fp(32)}。
 * MAC 由设备根封装，覆盖 header、blob 与见证字节；篡改或跨机复制一律失败。
 * 见证密钥由 TPM 持久化密钥身份充当：每次计数变化轮换 A/B 槽，还原旧状态
 * 文件时指纹不符即熔断（fail-closed）。TPM NV 不可用时的最强替代。
 */
#include "vty_lockout.h"
#include "vty_util.h"
#include "vty_kdf.h"
#include "vty_device_root.h"
#include "vty_tpm_witness.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>

#define LK_MAGIC          0x4B4C5456u   /* 'VTLK'（小端） */
#define LK_VERSION        2u
#define LK_VERSION_LEGACY 1u
#define LK_HDR_BYTES      24u
#define LK_MAC_BYTES      32u
#define LK_KEY_BYTES      VTY_KEY_BYTES
#define LK_BLOB_BYTES     VTY_DEVICE_BLOB_BYTES
#define LK_MAC_OFFSET     LK_HDR_BYTES
#define LK_BLOB_OFFSET    (LK_HDR_BYTES + LK_MAC_BYTES)
#define LK_WITNESS_OFFSET (LK_BLOB_OFFSET + LK_BLOB_BYTES)
#define LK_WITNESS_BYTES   (1u + VTY_TPM_WITNESS_FP_BYTES)
#define LK_TOTAL_BYTES     (LK_WITNESS_OFFSET + LK_WITNESS_BYTES)
#define LK_TOTAL_BYTES_V1  (LK_BLOB_OFFSET + LK_BLOB_BYTES)
#define LK_MSG_BYTES       (LK_HDR_BYTES + LK_BLOB_BYTES + LK_WITNESS_BYTES)

static char g_state_path[1024];
static char g_default_path[1024];
static int g_initialized = 0;
static int g_enabled = 1;
static uint8_t g_witness_id[VTY_UUID_BYTES];
static int g_witness_id_ready = 0;

void vty_lockout_set_enabled(int enabled)
{
    g_enabled = enabled ? 1 : 0;
}

int vty_lockout_enabled(void)
{
    return g_enabled;
}

static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static int build_default_path(void)
{
    char base[768];
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, (DWORD)sizeof(base));
    if (n == 0 || n >= sizeof(base)) return VTY_E_POLICY;
    if (sprintf_s(g_default_path, sizeof(g_default_path), "%s\\Verthys", base) < 0) {
        return VTY_E_INVALID;
    }
    CreateDirectoryA(g_default_path, NULL);
    if (sprintf_s(g_default_path, sizeof(g_default_path), "%s\\Verthys\\lockout.state", base) < 0) {
        return VTY_E_INVALID;
    }
    return VTY_OK;
}

int vty_lockout_set_path(const char *path)
{
    size_t len;
    if (path == NULL) return VTY_E_INVALID;
    len = strlen(path);
    if (len == 0 || len >= sizeof(g_state_path)) return VTY_E_INVALID;
    memcpy(g_state_path, path, len + 1);
    g_witness_id_ready = 0;
    return VTY_OK;
}

static int ensure_witness_id(void)
{
    if (g_witness_id_ready) return VTY_OK;
    if (!g_initialized) {
        int rc = vty_lockout_init();
        if (rc != VTY_OK) return rc;
    }
    if (g_state_path[0] == '\0') return VTY_E_POLICY;
    if (vty_tpm_witness_id_from_string(g_state_path, g_witness_id) != VTY_OK) {
        return VTY_E_TPM;
    }
    g_witness_id_ready = 1;
    return VTY_OK;
}

int vty_lockout_init(void)
{
    int rc = vty_device_root_init();
    if (rc != VTY_OK) return rc;
    if (g_state_path[0] == '\0') {
        rc = build_default_path();
        if (rc != VTY_OK) return rc;
        memcpy(g_state_path, g_default_path, strlen(g_default_path) + 1);
    }
    g_initialized = 1;
    if (vty_tpm_witness_id_from_string(g_state_path, g_witness_id) != VTY_OK) {
        return VTY_E_TPM;
    }
    g_witness_id_ready = 1;
    return VTY_OK;
}

static int read_state(uint8_t buf[LK_TOTAL_BYTES], int *missing, int *legacy)
{
    wchar_t *w;
    HANDLE h;
    DWORD got = 0;
    LARGE_INTEGER size;
    int rc = VTY_OK;

    *missing = 0;
    *legacy = 0;
    memset(buf, 0, LK_TOTAL_BYTES);
    if (!g_initialized) return VTY_E_POLICY;
    w = to_wide(g_state_path);
    if (w == NULL) return VTY_E_INVALID;
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        /* 仅“文件/目录不存在”视为首次运行；权限/共享冲突等一律按损坏
         * 处理，否则一次 IO 故障就能把失败计数重置为 0。 */
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            *missing = 1;
            return VTY_E_IO;
        }
        return VTY_E_CORRUPT;
    }
    if (!GetFileSizeEx(h, &size)) {
        CloseHandle(h);
        return VTY_E_CORRUPT;
    }
    if (size.QuadPart == (LONGLONG)LK_TOTAL_BYTES) {
        *legacy = 0;
    } else if (size.QuadPart == (LONGLONG)LK_TOTAL_BYTES_V1) {
        *legacy = 1;
    } else {
        CloseHandle(h);
        return VTY_E_CORRUPT;
    }
    if (!ReadFile(h, buf, (DWORD)(*legacy ? LK_TOTAL_BYTES_V1 : LK_TOTAL_BYTES),
                  &got, NULL) ||
        got != (DWORD)(*legacy ? LK_TOTAL_BYTES_V1 : LK_TOTAL_BYTES)) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    return rc;
}

static int write_state(const uint8_t buf[LK_TOTAL_BYTES])
{
    wchar_t *w;
    wchar_t *wt;
    char temp[1100];
    HANDLE h;
    DWORD written = 0;
    int rc = VTY_OK;

    if (!g_initialized) return VTY_E_POLICY;
    if (strlen(g_state_path) + 32 >= sizeof(temp)) return VTY_E_INVALID;
    sprintf_s(temp, sizeof(temp), "%s.tmp%08lx", g_state_path,
              (unsigned long)GetCurrentProcessId());
    wt = to_wide(temp);
    if (wt == NULL) return VTY_E_INVALID;
    h = CreateFileW(wt, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(wt);
        return VTY_E_IO;
    }
    if (!WriteFile(h, buf, LK_TOTAL_BYTES, &written, NULL) || written != LK_TOTAL_BYTES) {
        rc = VTY_E_IO;
    }
    if (rc == VTY_OK && !FlushFileBuffers(h)) rc = VTY_E_IO;
    CloseHandle(h);

    if (rc == VTY_OK) {
        w = to_wide(g_state_path);
        if (w == NULL) {
            rc = VTY_E_INVALID;
        } else if (!MoveFileExW(wt, w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            rc = VTY_E_IO;
        }
        free(w);
    }
    if (rc != VTY_OK) DeleteFileW(wt);
    free(wt);
    return rc;
}

static void compute_mac(const uint8_t key[LK_KEY_BYTES],
                        const uint8_t buf[LK_TOTAL_BYTES],
                        uint8_t mac[LK_MAC_BYTES])
{
    uint8_t msg[LK_MSG_BYTES];
    size_t n = 0;

    memcpy(msg + n, buf, LK_HDR_BYTES); n += LK_HDR_BYTES;
    memcpy(msg + n, buf + LK_BLOB_OFFSET, LK_BLOB_BYTES); n += LK_BLOB_BYTES;
    memcpy(msg + n, buf + LK_WITNESS_OFFSET, LK_WITNESS_BYTES); n += LK_WITNESS_BYTES;
    if (vty_hmac_sha256(mac, key, LK_KEY_BYTES, msg, n) != VTY_OK) {
        memset(mac, 0, LK_MAC_BYTES);
    }
    vty_secure_zero(msg, sizeof(msg));
}

/* v1 与 v2 的 header/MAC/blob 偏移相同，仅多出见证字节；提升只改版本 */
static void promote_v1(uint8_t buf[LK_TOTAL_BYTES])
{
    vty_put_u32(buf + 4, LK_VERSION);
    buf[LK_WITNESS_OFFSET] = 0xFFu;   /* 0xFF=尚无见证 */
    memset(buf + LK_WITNESS_OFFSET + 1u, 0, VTY_TPM_WITNESS_FP_BYTES);
}

/* 读取并认证；文件不存在时 is_new=1。任何异常都返回 VTY_E_LOCKED。 */
static int load_authenticated(uint8_t buf[LK_TOTAL_BYTES], int *is_new,
                              int *legacy)
{
    uint8_t key[LK_KEY_BYTES];
    uint8_t mac[LK_MAC_BYTES];
    int missing = 0;
    int rc;
    int any;

    *is_new = 0;
    *legacy = 0;
    if (ensure_witness_id() != VTY_OK) return VTY_E_LOCKED;

    rc = read_state(buf, &missing, legacy);
    if (rc == VTY_E_IO && missing) {
        *is_new = 1;
        memset(buf, 0, LK_TOTAL_BYTES);
        /* 状态文件缺失但见证密钥仍在：视为删除/回滚 */
        any = vty_tpm_witness_any(g_witness_id);
        return (any == 0) ? VTY_OK : VTY_E_LOCKED;
    }
    if (rc != VTY_OK) return VTY_E_LOCKED;

    if (vty_get_u32(buf) != LK_MAGIC ||
        vty_get_u32(buf + 4) != (*legacy ? LK_VERSION_LEGACY : LK_VERSION)) {
        return VTY_E_LOCKED;
    }
    rc = vty_device_key_unseal(buf + LK_BLOB_OFFSET, LK_BLOB_BYTES, key);
    if (rc != VTY_OK) {
        vty_secure_zero(key, sizeof(key));
        return VTY_E_LOCKED;
    }
    if (*legacy) {
        uint8_t msg[LK_HDR_BYTES + LK_BLOB_BYTES];
        memcpy(msg, buf, LK_HDR_BYTES);
        memcpy(msg + LK_HDR_BYTES, buf + LK_BLOB_OFFSET, LK_BLOB_BYTES);
        rc = vty_hmac_sha256(mac, key, LK_KEY_BYTES, msg, sizeof(msg));
        if (rc != VTY_OK ||
            vty_ct_equal(mac, buf + LK_MAC_OFFSET, LK_MAC_BYTES) != 0) {
            rc = VTY_E_LOCKED;
        }
        vty_secure_zero(msg, sizeof(msg));
        if (rc == VTY_OK) {
            /* v1 无见证：只要出现见证密钥就说明状态被降级/回滚 */
            any = vty_tpm_witness_any(g_witness_id);
            if (any != 0) rc = VTY_E_LOCKED;
        }
        if (rc == VTY_OK) promote_v1(buf);
    } else {
        compute_mac(key, buf, mac);
        if (vty_ct_equal(mac, buf + LK_MAC_OFFSET, LK_MAC_BYTES) != 0) {
            rc = VTY_E_LOCKED;
        }
        if (rc == VTY_OK) {
            if (buf[LK_WITNESS_OFFSET] >= VTY_TPM_WITNESS_SLOTS ||
                vty_tpm_witness_verify(g_witness_id, buf[LK_WITNESS_OFFSET],
                                       buf + LK_WITNESS_OFFSET + 1u) != VTY_OK) {
                rc = VTY_E_LOCKED;
            }
        }
    }
    vty_secure_zero(key, sizeof(key));
    vty_secure_zero(mac, sizeof(mac));
    return (rc == VTY_OK) ? VTY_OK : VTY_E_LOCKED;
}

static int store(uint8_t buf[LK_TOTAL_BYTES])
{
    uint8_t key[LK_KEY_BYTES];
    uint8_t mac[LK_MAC_BYTES];
    size_t blob_len = LK_BLOB_BYTES;
    int rc;

    if (buf[0] == 0 && buf[LK_BLOB_OFFSET] == 0) {
        /* 新状态：生成 MAC 密钥并用设备根封装 */
        vty_random(key, sizeof(key));
        rc = vty_device_key_seal(key, buf + LK_BLOB_OFFSET, &blob_len);
        if (rc != VTY_OK) {
            vty_secure_zero(key, sizeof(key));
            return VTY_E_LOCKED;
        }
    } else {
        rc = vty_device_key_unseal(buf + LK_BLOB_OFFSET, LK_BLOB_BYTES, key);
        if (rc != VTY_OK) {
            vty_secure_zero(key, sizeof(key));
            return VTY_E_LOCKED;
        }
    }

    vty_put_u32(buf, LK_MAGIC);
    vty_put_u32(buf + 4, LK_VERSION);
    compute_mac(key, buf, mac);
    memcpy(buf + LK_MAC_OFFSET, mac, LK_MAC_BYTES);
    rc = write_state(buf);
    vty_secure_zero(key, sizeof(key));
    vty_secure_zero(mac, sizeof(mac));
    return rc == VTY_OK ? VTY_OK : VTY_E_LOCKED;
}

/* 计数是“读-改-写”：多进程并发失败会丢计数。用会话内命名互斥量串行化。 */
static HANDLE lock_state(void)
{
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\Verthys.LockoutState");
    if (mutex == NULL) return NULL;
    if (WaitForSingleObject(mutex, 5000) != WAIT_OBJECT_0) {
        CloseHandle(mutex);
        return NULL;
    }
    return mutex;
}

static void unlock_state(HANDLE mutex)
{
    if (mutex == NULL) return;
    ReleaseMutex(mutex);
    CloseHandle(mutex);
}

/* 轮换见证：创建另一槽并写回；调用方已持有状态锁 */
static int rotate(uint8_t buf[LK_TOTAL_BYTES], int current_slot,
                  int *next_slot)
{
    int next = (current_slot == 0) ? 1 : 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];

    if (vty_tpm_witness_create(g_witness_id, (uint8_t)next, fp) != VTY_OK) {
        return VTY_E_LOCKED;
    }
    buf[LK_WITNESS_OFFSET] = (uint8_t)next;
    memcpy(buf + LK_WITNESS_OFFSET + 1u, fp, VTY_TPM_WITNESS_FP_BYTES);
    vty_secure_zero(fp, sizeof(fp));
    *next_slot = next;
    return VTY_OK;
}

static void drop_stale(int current_slot, int next_slot)
{
    int stale = 1 - next_slot;
    if (stale != current_slot && stale >= 0) {
        (void)vty_tpm_witness_delete(g_witness_id, (uint8_t)stale);
    }
    if (current_slot >= 0) {
        (void)vty_tpm_witness_delete(g_witness_id, (uint8_t)current_slot);
    }
}

int vty_lockout_check(void)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    int legacy = 0;
    int rc = load_authenticated(buf, &is_new, &legacy);
    uint32_t failures;
    if (rc != VTY_OK) return VTY_E_LOCKED;
    if (is_new) return VTY_OK;
    failures = vty_get_u32(buf + 8);
    return failures >= VTY_LOCKOUT_MAX_FAILURES ? VTY_E_LOCKED : VTY_OK;
}

uint32_t vty_lockout_failures(void)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    int legacy = 0;
    if (load_authenticated(buf, &is_new, &legacy) != VTY_OK) {
        return VTY_LOCKOUT_MAX_FAILURES;
    }
    if (is_new) return 0;
    return vty_get_u32(buf + 8);
}

int vty_lockout_record_failure(void)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    int legacy = 0;
    uint32_t failures;
    FILETIME ft;
    ULARGE_INTEGER u;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    HANDLE lock;

    if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
    lock = lock_state();
    if (lock == NULL) return VTY_E_LOCKED;

    rc = load_authenticated(buf, &is_new, &legacy);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    failures = vty_get_u32(buf + 8);
    if (failures >= VTY_LOCKOUT_MAX_FAILURES) {
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    if (!is_new && !legacy && buf[LK_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS) {
        current_slot = (int)buf[LK_WITNESS_OFFSET];
    }

    if (rotate(buf, current_slot, &next_slot) != VTY_OK) {
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    failures++;
    vty_put_u32(buf + 8, failures);
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    vty_put_u64(buf + 12, (uint64_t)(u.QuadPart / 10000000ull) - 11644473600ull);
    vty_put_u32(buf + 20, 0);
    rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(g_witness_id, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    drop_stale(current_slot, next_slot);
    unlock_state(lock);
    return failures >= VTY_LOCKOUT_MAX_FAILURES ? VTY_E_LOCKED : VTY_OK;
}

int vty_lockout_reset(void)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    int legacy = 0;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    uint32_t failures;
    int force = 0;
    HANDLE lock;

    if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
    lock = lock_state();
    if (lock == NULL) return VTY_E_LOCKED;

    rc = load_authenticated(buf, &is_new, &legacy);
    if (rc != VTY_OK) {
        /* 状态损坏时允许在“已成功解锁/恢复码”之后重建：否则一次坏盘
         * 就会让用户永久锁死。 */
        memset(buf, 0, LK_TOTAL_BYTES);
        is_new = 1;
        legacy = 1;
        force = 1;
    }
    if (is_new && !force) {
        int any = vty_tpm_witness_any(g_witness_id);
        if (any == 0) {
            /* 首启且无失败记录：无需创建状态或密钥 */
            unlock_state(lock);
            return VTY_OK;
        }
    } else if (!legacy) {
        failures = vty_get_u32(buf + 8);
        if (failures == 0 && buf[LK_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS) {
            /* 已归零且见证有效：不轮换，避免每次成功解锁都付出建键成本 */
            unlock_state(lock);
            return VTY_OK;
        }
        current_slot = (int)buf[LK_WITNESS_OFFSET];
    }

    if (rotate(buf, current_slot, &next_slot) != VTY_OK) {
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    vty_put_u32(buf + 8, 0);
    vty_put_u64(buf + 12, 0);
    vty_put_u32(buf + 20, 0);
    rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(g_witness_id, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    drop_stale(current_slot, next_slot);
    unlock_state(lock);
    return VTY_OK;
}
