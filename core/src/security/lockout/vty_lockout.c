/*
 * vty_lockout.c — 持久化失败计数与熔断实现
 *
 * 状态布局（版本字段 3）：header(24) + MAC(32) + 设备根 blob(290)
 *                    + 见证{slot(1), fp(32)} + 模块锁表(8 × 32)。
 * MAC 由设备根封装，覆盖 header、blob、见证与模块锁表；篡改或跨机复制
 * 一律失败。
 *
 * 版本策略：只接受当前布局。其它任何尺寸都按损坏 fail-closed，不读取、
 * 不迁移旧格式，也不为旧应用版本提供反向兼容。
 *
 * 熔断分域：
 *   - 库锁（library_failures/library_last_fail）：仅容器口令路径使用；
 *     成功解锁清零。
 *   - 模块锁（module table）：按 SHA-256(vault_uuid || module_index) 前
 *     16 字节区分作用域；模块 A 失败不阻塞模块 B，模块失败不阻塞库解锁，
 *     库成功不清模块锁。
 *
 * 最小尝试间隔：`vty_lockout_begin_attempt` 在认证前执行（1 秒），
 * `vty_lockout_check` 保持纯查询语义（不消耗尝试额度）。
 */
#include "vty_lockout.h"
#include "vty_secure_state.h"
#include "vty_util.h"
#include "vty_kdf.h"
#include "vty_device_root.h"
#include "vty_tpm_witness.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define LK_MAGIC          0x4B4C5456u   /* 'VTLK'（小端） */
#define LK_VERSION        3u
#define LK_HDR_BYTES      24u
#define LK_MAC_BYTES      32u
#define LK_KEY_BYTES      VTY_KEY_BYTES
#define LK_BLOB_BYTES     VTY_DEVICE_BLOB_BYTES
#define LK_MAC_OFFSET     LK_HDR_BYTES
#define LK_BLOB_OFFSET    (LK_HDR_BYTES + LK_MAC_BYTES)
#define LK_WITNESS_OFFSET (LK_BLOB_OFFSET + LK_BLOB_BYTES)
#define LK_WITNESS_BYTES  (1u + VTY_TPM_WITNESS_FP_BYTES)
#define LK_MODULES_OFFSET (LK_WITNESS_OFFSET + LK_WITNESS_BYTES)
#define LK_MODULE_SLOTS   8u
#define LK_MODULE_STRIDE  32u
#define LK_MODULE_BYTES   (LK_MODULE_SLOTS * LK_MODULE_STRIDE)
/* 模块条目内偏移：scope_id(16) + failures(4) + last_fail_secs(8) + reserved(4) */
#define LK_MODULE_FAIL_OFF 16u
#define LK_MODULE_TIME_OFF 20u
#define LK_MODULE_RSV_OFF  28u
#define LK_TOTAL_BYTES     (LK_MODULES_OFFSET + LK_MODULE_BYTES)
/* MAC 覆盖：header + blob + witness + module table */
#define LK_MSG_BYTES       (LK_HDR_BYTES + LK_BLOB_BYTES + LK_WITNESS_BYTES + \
                            LK_MODULE_BYTES)
/* 库最小尝试间隔（秒）：认证前纵深防御 */
#define LK_MIN_ATTEMPT_SECS 1u

/* 测试隔离钩子：仅 VERTHYS_TEST_HOOKS=1 的攻击回归构建编译。
 * 生产构建不包含此代码，状态路径不可由环境变量改写。 */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static int g_test_env_hook = 0;
static char g_test_state_dir[VTY_SECURE_STATE_PATH_BYTES];
#endif

static char g_state_path[VTY_SECURE_STATE_PATH_BYTES];
static int g_test_path = 0;
static int g_initialized = 0;
static int g_enabled = 1;
static uint8_t g_witness_id[VTY_UUID_BYTES];
static int g_witness_ready = 0;
/* 测试注入时钟（UTC 秒）；0 = 使用系统时间。生产路径不得设置。 */
static uint64_t g_test_now_secs = 0;

int vty_lockout_set_test_clock(uint64_t now_secs)
{
    g_test_now_secs = now_secs;
    return VTY_OK;
}

static uint64_t lockout_now_secs(void)
{
    return (g_test_now_secs != 0) ? g_test_now_secs : (uint64_t)time(NULL);
}

uint32_t vty_lockout_backoff_secs(uint32_t failures)
{
    uint32_t secs;

    if (failures >= 12u) return 3600u;
    secs = 1u << failures;
    return (secs > 3600u) ? 3600u : secs;
}

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

/* 测试路径不经过默认目录 ACL 校验；生产路径每次打开前复核。 */
static int validate_path(const char *path, int allow_missing)
{
    if (g_test_path) return VTY_OK;
    return vty_secure_state_validate_path(path, allow_missing);
}

static int resolve_paths(void)
{
    int rc;

    if (g_state_path[0] != '\0') return VTY_OK; /* 测试注入路径 */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        char test_dir[VTY_SECURE_STATE_PATH_BYTES];
        DWORD test_len = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR",
                                                 test_dir, sizeof(test_dir));
        if (test_len > 0 && test_len < sizeof(test_dir)) {
            if (sprintf_s(g_state_path, sizeof(g_state_path),
                          "%s\\lockout.state", test_dir) < 0) {
                return VTY_E_INVALID;
            }
            g_test_path = 1;
            g_test_env_hook = 1;
            memcpy(g_test_state_dir, test_dir, (size_t)test_len + 1u);
            return VTY_OK;
        }
    }
#endif
    rc = vty_secure_state_file_path("lockout.state", g_state_path,
                                    sizeof(g_state_path));
    return rc;
}

int vty_lockout_set_path_for_test(const char *path)
{
    size_t len;
    if (path == NULL) return VTY_E_INVALID;
    len = strlen(path);
    if (len == 0 || len >= sizeof(g_state_path)) return VTY_E_INVALID;
    memcpy(g_state_path, path, len + 1);
    g_test_path = 1;
    g_witness_ready = 0;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    g_test_env_hook = 0;
    g_test_state_dir[0] = '\0';
#endif
    return VTY_OK;
}

static int compute_witness_id(void)
{
    if (g_witness_ready) return VTY_OK;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    if (g_test_env_hook) {
        /* 测试域按状态目录派生：同一轮攻击的多个进程共享同一见证域，
         * 不同 run 的临时目录互不干扰；生产构建不含此代码。 */
        char domain[VTY_SECURE_STATE_PATH_BYTES + 32u];
        if (sprintf_s(domain, sizeof(domain), "verthys/test/lockout:%s",
                      g_test_state_dir) < 0) {
            return VTY_E_INVALID;
        }
        if (vty_tpm_witness_id_from_string(domain, g_witness_id) != VTY_OK) {
            return VTY_E_TPM;
        }
        g_witness_ready = 1;
        return VTY_OK;
    }
#endif
    if (vty_secure_state_identity_lockout(g_witness_id) != VTY_OK) {
        return VTY_E_TPM;
    }
    g_witness_ready = 1;
    return VTY_OK;
}

static int ensure_witness_id(void)
{
    if (g_witness_ready) return VTY_OK;
    if (!g_initialized) {
        int rc = vty_lockout_init();
        if (rc != VTY_OK) return rc;
    }
    return compute_witness_id();
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
/* 若测试环境在首次默认解析之后才注入状态目录，丢弃默认路径并重新解析；
 * 显式 set_path_for_test 不受影响。 */
static void maybe_apply_test_dir(void)
{
    char dir[VTY_SECURE_STATE_PATH_BYTES];
    DWORD n;

    if (g_test_env_hook || g_test_path) return;
    n = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", dir, sizeof(dir));
    if (n == 0 || n >= sizeof(dir)) return;
    g_state_path[0] = '\0';
    g_witness_ready = 0;
    (void)resolve_paths();
}
#endif

int vty_lockout_init(void)
{
    int rc = vty_device_root_init();
    if (rc != VTY_OK) return rc;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    maybe_apply_test_dir();
#endif
    rc = resolve_paths();
    if (rc != VTY_OK) return rc;
    g_initialized = 1;
    g_witness_ready = 0;
    return compute_witness_id();
}

/* ------------------------------------------------------------------ *
 *  状态读写                                                            *
 * ------------------------------------------------------------------ */

/* 读取状态文件。文件不存在时 missing=1；其它任何尺寸按损坏 fail-closed。 */
static int read_state(uint8_t buf[LK_TOTAL_BYTES], int *missing)
{
    wchar_t *w;
    HANDLE h;
    DWORD got = 0;
    LARGE_INTEGER size;
    int rc = VTY_OK;

    *missing = 0;
    memset(buf, 0, LK_TOTAL_BYTES);
    if (!g_initialized) return VTY_E_POLICY;
    if (validate_path(g_state_path, 1) != VTY_OK) return VTY_E_CORRUPT;
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
    if (size.QuadPart != (LONGLONG)LK_TOTAL_BYTES) {
        /* 旧版本或未知尺寸：不读取、不迁移，按损坏 fail-closed。 */
        CloseHandle(h);
        return VTY_E_CORRUPT;
    }
    if (!ReadFile(h, buf, LK_TOTAL_BYTES, &got, NULL) || got != LK_TOTAL_BYTES) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    return rc;
}

static int write_state(const uint8_t buf[LK_TOTAL_BYTES])
{
    wchar_t *w = NULL;
    wchar_t *wt = NULL;
    char temp[1200];
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    DWORD tag = GetTickCount();
    int attempt;
    int rc = VTY_OK;

    if (!g_initialized) return VTY_E_POLICY;
    if (validate_path(g_state_path, 1) != VTY_OK) return VTY_E_IO;
    if (strlen(g_state_path) + 40 >= sizeof(temp)) return VTY_E_INVALID;

    /* CREATE_NEW + 多候选：拒绝沿既有临时文件/符号链接写入；同一 PID 的
     * 崩溃残留由 attempt 后缀避开。 */
    for (attempt = 0; attempt < 4; attempt++) {
        sprintf_s(temp, sizeof(temp), "%s.tmp%08lx%08lx", g_state_path,
                  (unsigned long)GetCurrentProcessId(),
                  (unsigned long)(tag + (DWORD)attempt));
        wt = to_wide(temp);
        if (wt == NULL) return VTY_E_INVALID;
        h = CreateFileW(wt, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        free(wt);
        wt = NULL;
        if (GetLastError() != ERROR_FILE_EXISTS) return VTY_E_IO;
    }
    if (h == INVALID_HANDLE_VALUE) return VTY_E_IO;

    if (!WriteFile(h, buf, LK_TOTAL_BYTES, &written, NULL) ||
        written != LK_TOTAL_BYTES) {
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
    memcpy(msg + n, buf + LK_MODULES_OFFSET, LK_MODULE_BYTES); n += LK_MODULE_BYTES;
    if (vty_hmac_sha256(mac, key, LK_KEY_BYTES, msg, n) != VTY_OK) {
        memset(mac, 0, LK_MAC_BYTES);
    }
    vty_secure_zero(msg, sizeof(msg));
}

/* 校验状态文件（magic/版本/MAC/见证/模块表）。
 * witness_missing 仅在“MAC/结构均有效、仅见证密钥被删除”时置 1：
 * 这是唯一允许隔离重建的路径；MAC 篡改/跨机复制/指纹不符一律 fail-closed。 */
static int verify_state(uint8_t buf[LK_TOTAL_BYTES], int *witness_missing)
{
    uint8_t key[LK_KEY_BYTES];
    uint8_t mac[LK_MAC_BYTES];
    int rc = VTY_E_LOCKED;
    size_t i;

    if (witness_missing != NULL) *witness_missing = 0;
    if (vty_get_u32(buf) != LK_MAGIC || vty_get_u32(buf + 4) != LK_VERSION) {
        return VTY_E_LOCKED;
    }
    if (vty_device_key_unseal(buf + LK_BLOB_OFFSET, LK_BLOB_BYTES, key) != VTY_OK) {
        vty_secure_zero(key, sizeof(key));
        return VTY_E_LOCKED;
    }
    compute_mac(key, buf, mac);
    if (vty_ct_equal(mac, buf + LK_MAC_OFFSET, LK_MAC_BYTES) != 0) goto out;

    if (buf[LK_WITNESS_OFFSET] >= VTY_TPM_WITNESS_SLOTS) goto out;
    if (vty_tpm_witness_verify(g_witness_id, buf[LK_WITNESS_OFFSET],
                               buf + LK_WITNESS_OFFSET + 1u) != VTY_OK) {
        /* 仅当该见证域两槽均不存在时才视为“见证整体丢失”。
         * 若另一槽仍在（状态回放/轮换中途），必须 fail-closed：旧状态
         * 指向的槽被轮换删除，但当前槽仍存在，属于可检测的回放。 */
        if (witness_missing != NULL &&
            vty_tpm_witness_exists(g_witness_id, buf[LK_WITNESS_OFFSET]) == 0 &&
            vty_tpm_witness_any(g_witness_id) == 0) {
            *witness_missing = 1;
        }
        goto out;
    }
    {
        uint32_t count = vty_get_u32(buf + 20);
        if (count > LK_MODULE_SLOTS) goto out;
        for (i = 0; i < (size_t)count; i++) {
            const uint8_t *e = buf + LK_MODULES_OFFSET + i * LK_MODULE_STRIDE;
            if (vty_get_u32(e + LK_MODULE_RSV_OFF) != 0) goto out;
            if (vty_get_u32(e + LK_MODULE_FAIL_OFF) > 32u) goto out;
        }
    }
    rc = VTY_OK;

out:
    vty_secure_zero(key, sizeof(key));
    vty_secure_zero(mac, sizeof(mac));
    return (rc == VTY_OK) ? VTY_OK : VTY_E_LOCKED;
}

/* 状态无法验证且见证密钥确实不存在时，把旧状态移入隔离名后重建。
 *
 * 安全边界：仅在“见证缺失”时允许重建——TPM 清理/系统维护/测试回收都会
 * 造成这种不可恢复的状态；若见证仍存在（指纹不符、MAC 篡改、文件删除），
 * 仍由 load_authenticated 维持 fail-closed，避免通过复制/篡改重置计数。
 * 隔离而非删除，便于事后取证。 */
static int quarantine_state(void)
{
    wchar_t *w = NULL;
    wchar_t *wq = NULL;
    char qpath[1200];
    DWORD err;
    int rc = VTY_E_LOCKED;

    if (!g_initialized) return VTY_E_POLICY;
    if (strlen(g_state_path) + 48 >= sizeof(qpath)) return VTY_E_INVALID;
    sprintf_s(qpath, sizeof(qpath), "%s.invalid%08lx%08lx", g_state_path,
              (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    w = to_wide(g_state_path);
    wq = to_wide(qpath);
    if (w == NULL || wq == NULL) goto done;
    if (MoveFileExW(w, wq, MOVEFILE_WRITE_THROUGH)) {
        rc = VTY_OK;
        goto done;
    }
    err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
        rc = VTY_OK;
    }

done:
    if (w != NULL) free(w);
    if (wq != NULL) free(wq);
    return rc;
}

/* 读取并认证。
 * allow_recover=0：纯查询，任何认证失败都返回 LOCKED，不产生副作用；
 * allow_recover=1：认证入口（begin_attempt/record_failure）在“状态本体
 * 可认证、仅见证整体丢失”时隔离旧状态并重建，避免 TPM 清理导致永久锁死。
 * 状态缺失时：当前见证仍存在 → 按删除/回滚锁定；否则首次运行。 */
static int load_authenticated_ex(uint8_t buf[LK_TOTAL_BYTES], int *is_new,
                                 int allow_recover)
{
    int missing = 0;
    int rc;

    *is_new = 0;
    if (ensure_witness_id() != VTY_OK) return VTY_E_LOCKED;

    rc = read_state(buf, &missing);
    if (rc == VTY_E_IO && missing) {
        memset(buf, 0, LK_TOTAL_BYTES);
        if (vty_tpm_witness_any(g_witness_id) != 0) return VTY_E_LOCKED;
        *is_new = 1;
        return VTY_OK;
    }
    if (rc != VTY_OK) return VTY_E_LOCKED;
    {
        int witness_missing = 0;
        rc = verify_state(buf, &witness_missing);
        if (rc == VTY_OK) return VTY_OK;
        /* 只有认证入口才允许隔离重建；纯查询保持无副作用并 fail-closed。 */
        if (allow_recover && witness_missing && quarantine_state() == VTY_OK) {
            memset(buf, 0, LK_TOTAL_BYTES);
            *is_new = 1;
            return VTY_OK;
        }
    }
    return VTY_E_LOCKED;
}

/* 纯查询包装：check/remaining/failures 不改变状态。 */
static int load_authenticated(uint8_t buf[LK_TOTAL_BYTES], int *is_new)
{
    return load_authenticated_ex(buf, is_new, 0);
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

static uint32_t library_lock_remaining(const uint8_t buf[LK_TOTAL_BYTES],
                                       int with_min_interval)
{
    uint32_t failures = vty_get_u32(buf + 8);
    uint64_t last_fail = vty_get_u64(buf + 12);
    uint64_t now;
    uint64_t remaining = 0;

    if (failures == 0 || last_fail == 0) return 0;
    now = lockout_now_secs();
    if (now < last_fail) {
        /* 时钟回拨：按一个退避窗口处理（fail-closed） */
        return vty_lockout_backoff_secs(failures);
    }
    if (failures >= VTY_LOCKOUT_MAX_FAILURES) {
        uint32_t backoff = vty_lockout_backoff_secs(failures);
        if (now - last_fail < (uint64_t)backoff) {
            remaining = (uint64_t)backoff - (now - last_fail);
        }
    }
    if (with_min_interval && now - last_fail < (uint64_t)LK_MIN_ATTEMPT_SECS) {
        uint64_t min_left = (uint64_t)LK_MIN_ATTEMPT_SECS - (now - last_fail);
        if (min_left > remaining) remaining = min_left;
    }
    return (remaining > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)remaining;
}

/* 库锁评估：rate_limit=1 时额外执行最小尝试间隔。 */
static int evaluate_library(int rate_limit)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    int rc = load_authenticated_ex(buf, &is_new, rate_limit);
    uint32_t remaining;

    if (rc != VTY_OK) return VTY_E_LOCKED;
    if (is_new) return VTY_OK;

    remaining = library_lock_remaining(buf, rate_limit);
    return (remaining > 0) ? VTY_E_LOCKED : VTY_OK;
}

int vty_lockout_check(void)
{
    return evaluate_library(0);
}

int vty_lockout_begin_attempt(void)
{
    return evaluate_library(1);
}

int vty_lockout_remaining_secs(uint32_t *out)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;

    if (out == NULL) return VTY_E_INVALID;
    *out = 0;
    if (load_authenticated(buf, &is_new) != VTY_OK) return VTY_E_LOCKED;
    if (is_new) return VTY_OK;
    *out = library_lock_remaining(buf, 1);
    return (*out > 0) ? VTY_E_LOCKED : VTY_OK;
}

uint32_t vty_lockout_failures(void)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    if (load_authenticated(buf, &is_new) != VTY_OK) {
        return VTY_LOCKOUT_MAX_FAILURES;
    }
    if (is_new) return 0;
    return vty_get_u32(buf + 8);
}

int vty_lockout_record_failure(void)
{
    uint8_t buf[LK_TOTAL_BYTES];
    int is_new = 0;
    uint32_t failures;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    HANDLE lock;

    if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
    lock = lock_state();
    if (lock == NULL) return VTY_E_LOCKED;

    rc = load_authenticated_ex(buf, &is_new, 1);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    failures = vty_get_u32(buf + 8);
    if (!is_new && buf[LK_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS) {
        current_slot = (int)buf[LK_WITNESS_OFFSET];
    }

    if (rotate(buf, current_slot, &next_slot) != VTY_OK) {
        unlock_state(lock);
        return VTY_E_LOCKED;
    }
    /* 阈值后继续累加（32 封顶），让退避窗口随次数增长并刷新时间戳。 */
    if (failures < 32u) failures++;
    vty_put_u32(buf + 8, failures);
    vty_put_u64(buf + 12, lockout_now_secs());
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
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    uint32_t failures;
    int force = 0;
    HANDLE lock;

    if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
    lock = lock_state();
    if (lock == NULL) return VTY_E_LOCKED;

    rc = load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        /* 状态损坏时允许在“已成功解锁/恢复码”之后重建：否则一次坏盘
         * 就会让用户永久锁死。 */
        memset(buf, 0, LK_TOTAL_BYTES);
        is_new = 1;
        force = 1;
    }
    if (is_new && !force && vty_tpm_witness_any(g_witness_id) == 0) {
        /* 首启且无失败记录：无需创建状态或密钥 */
        unlock_state(lock);
        return VTY_OK;
    }
    if (!is_new && !force) {
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
    /* 库成功只清库计数；模块锁表保持不变 */
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

/* ------------------------------------------------------------------ *
 *  模块锁表                                                            *
 * ------------------------------------------------------------------ */

static void module_scope_id(const uint8_t vault_uuid[VTY_UUID_BYTES],
                            uint32_t module_index,
                            uint8_t out[VTY_UUID_BYTES])
{
    uint8_t msg[VTY_UUID_BYTES + 4u];
    uint8_t digest[VTY_HASH_BYTES];

    memcpy(msg, vault_uuid, VTY_UUID_BYTES);
    vty_put_u32(msg + VTY_UUID_BYTES, module_index);
    if (vty_sha256(digest, msg, sizeof(msg)) != VTY_OK) {
        memset(out, 0, VTY_UUID_BYTES);
    } else {
        memcpy(out, digest, VTY_UUID_BYTES);
    }
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(msg, sizeof(msg));
}

static uint8_t *module_entry(uint8_t buf[LK_TOTAL_BYTES], uint32_t slot)
{
    return buf + LK_MODULES_OFFSET + (size_t)slot * LK_MODULE_STRIDE;
}

static int module_find(const uint8_t buf[LK_TOTAL_BYTES],
                       const uint8_t scope[VTY_UUID_BYTES])
{
    uint32_t count = vty_get_u32(buf + 20);
    uint32_t i;

    if (count > LK_MODULE_SLOTS) return -1;
    for (i = 0; i < count; i++) {
        const uint8_t *e = buf + LK_MODULES_OFFSET + (size_t)i * LK_MODULE_STRIDE;
        if (memcmp(e, scope, VTY_UUID_BYTES) == 0) return (int)i;
    }
    return -1;
}

/* 为新 scope 找写入槽：优先空槽；满时只在“未锁定且最久未失败”的记录中
 * 淘汰；若全部锁定则返回 -1（fail-closed，禁止用新 scope 洗掉锁定）。 */
static int module_slot_for_write(uint8_t buf[LK_TOTAL_BYTES],
                                 const uint8_t scope[VTY_UUID_BYTES])
{
    uint32_t count = vty_get_u32(buf + 20);
    uint32_t i;
    int victim = -1;
    uint64_t oldest = 0;

    if (count > LK_MODULE_SLOTS) return -1;
    if (count < LK_MODULE_SLOTS) {
        i = count;
        memset(module_entry(buf, i), 0, LK_MODULE_STRIDE);
        memcpy(module_entry(buf, i), scope, VTY_UUID_BYTES);
        vty_put_u32(buf + 20, count + 1u);
        return (int)i;
    }
    for (i = 0; i < LK_MODULE_SLOTS; i++) {
        uint8_t *e = module_entry(buf, i);
        uint32_t failures = vty_get_u32(e + LK_MODULE_FAIL_OFF);
        uint64_t last = vty_get_u64(e + LK_MODULE_TIME_OFF);
        if (failures >= VTY_LOCKOUT_MAX_FAILURES) continue;
        if (victim < 0 || last < oldest) {
            victim = (int)i;
            oldest = last;
        }
    }
    if (victim < 0) return -1;
    memset(module_entry(buf, (uint32_t)victim), 0, LK_MODULE_STRIDE);
    memcpy(module_entry(buf, (uint32_t)victim), scope, VTY_UUID_BYTES);
    return victim;
}

static uint32_t module_remaining(const uint8_t *e, int with_min_interval)
{
    uint32_t failures = vty_get_u32(e + LK_MODULE_FAIL_OFF);
    uint64_t last_fail = vty_get_u64(e + LK_MODULE_TIME_OFF);
    uint64_t now;
    uint64_t remaining = 0;

    if (failures == 0 || last_fail == 0) return 0;
    now = lockout_now_secs();
    if (now < last_fail) return vty_lockout_backoff_secs(failures);
    if (failures >= VTY_LOCKOUT_MAX_FAILURES) {
        uint32_t backoff = vty_lockout_backoff_secs(failures);
        if (now - last_fail < (uint64_t)backoff) {
            remaining = (uint64_t)backoff - (now - last_fail);
        }
    }
    if (with_min_interval && now - last_fail < (uint64_t)LK_MIN_ATTEMPT_SECS) {
        uint64_t min_left = (uint64_t)LK_MIN_ATTEMPT_SECS - (now - last_fail);
        if (min_left > remaining) remaining = min_left;
    }
    return (remaining > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)remaining;
}

int vty_lockout_module_begin_attempt(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                     uint32_t module_index)
{
    uint8_t buf[LK_TOTAL_BYTES];
    uint8_t scope[VTY_UUID_BYTES];
    int is_new = 0;
    int idx;

    if (vault_uuid == NULL || module_index >= 32u) return VTY_E_INVALID;
    if (ensure_witness_id() != VTY_OK) return VTY_E_MODULE_LOCKED;
    if (load_authenticated_ex(buf, &is_new, 1) != VTY_OK) return VTY_E_MODULE_LOCKED;
    if (is_new) return VTY_OK;
    module_scope_id(vault_uuid, module_index, scope);
    idx = module_find(buf, scope);
    if (idx < 0) return VTY_OK;
    return (module_remaining(module_entry(buf, (uint32_t)idx), 1) > 0)
               ? VTY_E_MODULE_LOCKED : VTY_OK;
}

int vty_lockout_module_remaining_secs(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                      uint32_t module_index, uint32_t *out)
{
    uint8_t buf[LK_TOTAL_BYTES];
    uint8_t scope[VTY_UUID_BYTES];
    int is_new = 0;
    int idx;

    if (vault_uuid == NULL || out == NULL) return VTY_E_INVALID;
    *out = 0;
    if (load_authenticated(buf, &is_new) != VTY_OK) return VTY_E_MODULE_LOCKED;
    if (is_new) return VTY_OK;
    module_scope_id(vault_uuid, module_index, scope);
    idx = module_find(buf, scope);
    if (idx < 0) return VTY_OK;
    *out = module_remaining(module_entry(buf, (uint32_t)idx), 1);
    return (*out > 0) ? VTY_E_MODULE_LOCKED : VTY_OK;
}

int vty_lockout_module_record_failure(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                      uint32_t module_index)
{
    uint8_t buf[LK_TOTAL_BYTES];
    uint8_t scope[VTY_UUID_BYTES];
    int is_new = 0;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    int idx;
    uint32_t failures;
    HANDLE lock;

    if (vault_uuid == NULL || module_index >= 32u) return VTY_E_INVALID;
    if (vty_lockout_init() != VTY_OK) return VTY_E_MODULE_LOCKED;
    lock = lock_state();
    if (lock == NULL) return VTY_E_MODULE_LOCKED;

    rc = load_authenticated_ex(buf, &is_new, 1);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return VTY_E_MODULE_LOCKED;
    }
    if (!is_new && buf[LK_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS) {
        current_slot = (int)buf[LK_WITNESS_OFFSET];
    }
    module_scope_id(vault_uuid, module_index, scope);
    idx = module_find(buf, scope);
    if (idx < 0) {
        idx = module_slot_for_write(buf, scope);
        if (idx < 0) {
            unlock_state(lock);
            return VTY_E_MODULE_LOCKED;
        }
    }
    failures = vty_get_u32(module_entry(buf, (uint32_t)idx) + LK_MODULE_FAIL_OFF);
    if (failures < 32u) failures++;
    vty_put_u32(module_entry(buf, (uint32_t)idx) + LK_MODULE_FAIL_OFF, failures);
    vty_put_u64(module_entry(buf, (uint32_t)idx) + LK_MODULE_TIME_OFF,
                lockout_now_secs());

    if (rotate(buf, current_slot, &next_slot) != VTY_OK) {
        unlock_state(lock);
        return VTY_E_MODULE_LOCKED;
    }
    rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(g_witness_id, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_MODULE_LOCKED;
    }
    drop_stale(current_slot, next_slot);
    unlock_state(lock);
    return failures >= VTY_LOCKOUT_MAX_FAILURES ? VTY_E_MODULE_LOCKED : VTY_OK;
}

int vty_lockout_module_reset(const uint8_t vault_uuid[VTY_UUID_BYTES],
                             uint32_t module_index)
{
    uint8_t buf[LK_TOTAL_BYTES];
    uint8_t scope[VTY_UUID_BYTES];
    int is_new = 0;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    int idx;
    HANDLE lock;

    if (vault_uuid == NULL || module_index >= 32u) return VTY_E_INVALID;
    if (vty_lockout_init() != VTY_OK) return VTY_E_MODULE_LOCKED;
    lock = lock_state();
    if (lock == NULL) return VTY_E_MODULE_LOCKED;

    rc = load_authenticated_ex(buf, &is_new, 1);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return VTY_E_MODULE_LOCKED;
    }
    if (is_new) {
        unlock_state(lock);
        return VTY_OK;
    }
    module_scope_id(vault_uuid, module_index, scope);
    idx = module_find(buf, scope);
    if (idx < 0) {
        unlock_state(lock);
        return VTY_OK;
    }
    if (vty_get_u32(module_entry(buf, (uint32_t)idx) + LK_MODULE_FAIL_OFF) == 0 &&
        vty_get_u64(module_entry(buf, (uint32_t)idx) + LK_MODULE_TIME_OFF) == 0) {
        unlock_state(lock);
        return VTY_OK;
    }
    if (buf[LK_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS) {
        current_slot = (int)buf[LK_WITNESS_OFFSET];
    }
    vty_put_u32(module_entry(buf, (uint32_t)idx) + LK_MODULE_FAIL_OFF, 0);
    vty_put_u64(module_entry(buf, (uint32_t)idx) + LK_MODULE_TIME_OFF, 0);

    if (rotate(buf, current_slot, &next_slot) != VTY_OK) {
        unlock_state(lock);
        return VTY_E_MODULE_LOCKED;
    }
    rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(g_witness_id, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_MODULE_LOCKED;
    }
    drop_stale(current_slot, next_slot);
    unlock_state(lock);
    return VTY_OK;
}

uint32_t vty_lockout_module_failures(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                     uint32_t module_index)
{
    uint8_t buf[LK_TOTAL_BYTES];
    uint8_t scope[VTY_UUID_BYTES];
    int is_new = 0;
    int idx;

    if (vault_uuid == NULL) return VTY_LOCKOUT_MAX_FAILURES;
    if (load_authenticated(buf, &is_new) != VTY_OK) {
        return VTY_LOCKOUT_MAX_FAILURES;
    }
    if (is_new) return 0;
    module_scope_id(vault_uuid, module_index, scope);
    idx = module_find(buf, scope);
    if (idx < 0) return 0;
    return vty_get_u32(module_entry(buf, (uint32_t)idx) + LK_MODULE_FAIL_OFF);
}
