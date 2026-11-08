/*
 * vty_rollback.c — 库文件版本回退检测实现
 *
 * 状态布局（版本字段 2）：header(16) + N×{uuid(16), generation(8), witnessSlot(1),
 * witnessFp(32)} + MAC(32) + 设备根 blob(290)。
 *
 * MAC 密钥由设备根封装，覆盖 header、条目与 blob——篡改任意字节或把状态
 * 文件拷到其它机器都会解封/比对失败，从而 fail-closed。
 *
 * 见证身份：SHA-256(domain || 设备根哈希 || 容器 UUID)，与状态文件路径无关。
 *
 * 状态文件固定落在 KnownFolder\Verthys\Security；旧布局与旧路径一律按
 * 损坏 fail-closed，不做迁移。
 * 状态缺失时：见证域仍有密钥，或容器 generation >= 2（已建立锚点），
 * 均按回退拒绝；只有 generation < 2 且无见证才视为首次运行。
 */
#include "vty_rollback.h"
#include "vty_secure_state.h"
#include "vty_util.h"
#include "vty_kdf.h"
#include "vty_device_root.h"
#include "vty_tpm_witness.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>

#define RB_MAGIC          0x42525456u   /* 'VTRB'（小端） */
#define RB_VERSION        2u
#define RB_HDR_BYTES      16u
#define RB_ENTRY_BYTES    57u
#define RB_MAC_BYTES      32u
#define RB_KEY_BYTES      VTY_KEY_BYTES
#define RB_BLOB_BYTES     VTY_DEVICE_BLOB_BYTES
#define RB_ENTRIES_OFFSET RB_HDR_BYTES
#define RB_ENTRY_WITNESS_OFFSET (VTY_UUID_BYTES + 8u)
#define RB_ENTRY_FP_OFFSET      (RB_ENTRY_WITNESS_OFFSET + 1u)

#define RB_ENTRIES_BYTES    (VTY_ROLLBACK_MAX_ENTRIES * RB_ENTRY_BYTES)
#define RB_MAC_OFFSET       (RB_HDR_BYTES + RB_ENTRIES_BYTES)
#define RB_BLOB_OFFSET      (RB_MAC_OFFSET + RB_MAC_BYTES)
#define RB_TOTAL_BYTES      (RB_BLOB_OFFSET + RB_BLOB_BYTES)
#define RB_MSG_BYTES        (RB_HDR_BYTES + RB_ENTRIES_BYTES + RB_BLOB_BYTES)

/* 容器已建立回滚锚点的最小代：创建成功后至少有一次 save_meta，
 * 磁盘代 >= 2；generation == 1 是未完成创建，允许首次运行。 */
#define RB_ANCHOR_MIN_GENERATION 2u

/* 测试隔离钩子：仅 VERTHYS_TEST_HOOKS=1 的攻击回归构建编译。
 * 生产构建不包含此代码，状态路径不可由环境变量改写。 */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static int g_test_env_hook = 0;
#endif

static char g_state_path[VTY_SECURE_STATE_PATH_BYTES];
static int g_test_path = 0;
static int g_initialized = 0;
static int g_enabled = 1;

void vty_rollback_set_enabled(int enabled)
{
    g_enabled = enabled ? 1 : 0;
}

int vty_rollback_enabled(void)
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

static int validate_path(const char *path, int allow_missing)
{
    if (g_test_path) return VTY_OK;
    return vty_secure_state_validate_path(path, allow_missing);
}

static int resolve_paths(void)
{
    int rc;

    if (g_state_path[0] != '\0') return VTY_OK;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        char test_dir[VTY_SECURE_STATE_PATH_BYTES];
        DWORD test_len = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR",
                                                 test_dir, sizeof(test_dir));
        if (test_len > 0 && test_len < sizeof(test_dir)) {
            if (sprintf_s(g_state_path, sizeof(g_state_path),
                          "%s\\rollback.state", test_dir) < 0) {
                return VTY_E_INVALID;
            }
            g_test_path = 1;
            g_test_env_hook = 1;
            return VTY_OK;
        }
    }
#endif
    rc = vty_secure_state_file_path("rollback.state", g_state_path,
                                    sizeof(g_state_path));
    if (rc != VTY_OK) return rc;
    return VTY_OK;
}

int vty_rollback_set_path_for_test(const char *path)
{
    size_t len;

    if (path == NULL) return VTY_E_INVALID;
    len = strlen(path);
    if (len == 0 || len >= sizeof(g_state_path)) return VTY_E_INVALID;
    memcpy(g_state_path, path, len + 1);
    g_test_path = 1;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    g_test_env_hook = 0;
#endif
    return VTY_OK;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
/* 若测试环境在首次默认解析之后才注入状态目录，把已解析的默认路径
 * 丢弃并重新按注入目录解析；显式 set_path_for_test 不受影响。 */
static void maybe_apply_test_dir(void)
{
    char dir[VTY_SECURE_STATE_PATH_BYTES];
    DWORD n;

    if (g_test_env_hook || g_test_path) return;
    n = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", dir, sizeof(dir));
    if (n == 0 || n >= sizeof(dir)) return;
    g_state_path[0] = '\0';
    (void)resolve_paths();
}
#endif

int vty_rollback_init(void)
{
    int rc = vty_device_root_init();

    if (rc != VTY_OK) return rc;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    maybe_apply_test_dir();
#endif
    rc = resolve_paths();
    if (rc != VTY_OK) return rc;
    g_initialized = 1;
    return VTY_OK;
}

static int witness_id(const uint8_t vault_uuid[VTY_UUID_BYTES],
                      uint8_t id[VTY_UUID_BYTES])
{
    /* 见证身份始终绑定设备根 + 容器 UUID；测试隔离只改状态目录，
     * 不改身份，否则同一次运行内创建/保存会落到不同见证域。 */
    return vty_secure_state_identity_rollback(vault_uuid, id);
}

/* 读取状态；文件不存在时 missing=1。只接受当前布局，其它尺寸一律
 * 按损坏处理（fail-closed），不做旧版本迁移。 */
static int read_state(uint8_t buf[RB_TOTAL_BYTES], int *missing)
{
    const char *path = g_state_path;
    wchar_t *w;
    HANDLE h;
    DWORD got = 0;
    LARGE_INTEGER size;
    int rc = VTY_OK;

    *missing = 0;
    memset(buf, 0, RB_TOTAL_BYTES);
    if (!g_initialized) return VTY_E_POLICY;
    rc = validate_path(path, 1);
    if (rc != VTY_OK) return VTY_E_CORRUPT;
    w = to_wide(path);
    if (w == NULL) return VTY_E_INVALID;
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        /* 只有“路径不存在”才是首次运行；权限/共享冲突/其它 IO 错误按
         * 损坏处理（fail-closed），否则一次读失败就能绕过锚点。 */
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
    if (size.QuadPart != (LONGLONG)RB_TOTAL_BYTES) {
        CloseHandle(h);
        return VTY_E_CORRUPT;
    }
    if (!ReadFile(h, buf, (DWORD)RB_TOTAL_BYTES, &got, NULL) ||
        got != (DWORD)RB_TOTAL_BYTES) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    return rc;
}

static int write_state(const uint8_t buf[RB_TOTAL_BYTES])
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

    if (!WriteFile(h, buf, RB_TOTAL_BYTES, &written, NULL) ||
        written != RB_TOTAL_BYTES) {
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

static void mac_message(const uint8_t buf[RB_TOTAL_BYTES],
                        uint8_t out[RB_MSG_BYTES])
{
    memcpy(out, buf, RB_HDR_BYTES + RB_ENTRIES_BYTES);
    memcpy(out + RB_HDR_BYTES + RB_ENTRIES_BYTES, buf + RB_BLOB_OFFSET,
           RB_BLOB_BYTES);
}

static int compute_mac(const uint8_t key[RB_KEY_BYTES],
                       const uint8_t buf[RB_TOTAL_BYTES],
                       uint8_t mac[RB_MAC_BYTES])
{
    uint8_t msg[RB_MSG_BYTES];
    int rc;

    mac_message(buf, msg);
    rc = vty_hmac_sha256(mac, key, RB_KEY_BYTES, msg, sizeof(msg));
    vty_secure_zero(msg, sizeof(msg));
    return rc;
}

/* 读取并认证；文件不存在时 is_new=1。任何异常都返回 VTY_E_ROLLBACK，
 * 调用方据此 fail-closed。 */
static int load_authenticated(uint8_t buf[RB_TOTAL_BYTES], int *is_new)
{
    uint8_t key[RB_KEY_BYTES];
    uint8_t mac[RB_MAC_BYTES];
    int missing = 0;
    int rc;

    *is_new = 0;
    rc = read_state(buf, &missing);
    if (rc == VTY_E_IO && missing) {
        *is_new = 1;
        memset(buf, 0, RB_TOTAL_BYTES);
        return VTY_OK;
    }
    if (rc != VTY_OK) return VTY_E_ROLLBACK;

    if (vty_get_u32(buf) != RB_MAGIC ||
        vty_get_u32(buf + 4) != RB_VERSION) {
        return VTY_E_ROLLBACK;
    }
    if (vty_get_u32(buf + 8) > VTY_ROLLBACK_MAX_ENTRIES ||
        vty_get_u32(buf + 12) != 0) {
        return VTY_E_ROLLBACK;
    }
    rc = vty_device_key_unseal(buf + RB_BLOB_OFFSET, RB_BLOB_BYTES, key);
    if (rc != VTY_OK) {
        vty_secure_zero(key, sizeof(key));
        return VTY_E_ROLLBACK;
    }
    rc = compute_mac(key, buf, mac);
    if (rc != VTY_OK ||
        vty_ct_equal(mac, buf + RB_MAC_OFFSET, RB_MAC_BYTES) != 0) {
        rc = VTY_E_ROLLBACK;
    }
    vty_secure_zero(key, sizeof(key));
    vty_secure_zero(mac, sizeof(mac));
    return (rc == VTY_OK) ? VTY_OK : VTY_E_ROLLBACK;
}

/* 按当前布局写入；调用前缓冲必须已是当前布局 */
static int store(uint8_t buf[RB_TOTAL_BYTES])
{
    uint8_t key[RB_KEY_BYTES];
    uint8_t mac[RB_MAC_BYTES];
    size_t blob_len = RB_BLOB_BYTES;
    int rc;

    if (buf[0] == 0 && buf[RB_BLOB_OFFSET] == 0) {
        vty_random(key, sizeof(key));
        rc = vty_device_key_seal(key, buf + RB_BLOB_OFFSET, &blob_len);
        if (rc != VTY_OK) {
            vty_secure_zero(key, sizeof(key));
            return VTY_E_ROLLBACK;
        }
    } else {
        rc = vty_device_key_unseal(buf + RB_BLOB_OFFSET, RB_BLOB_BYTES, key);
        if (rc != VTY_OK) {
            vty_secure_zero(key, sizeof(key));
            return VTY_E_ROLLBACK;
        }
    }

    vty_put_u32(buf, RB_MAGIC);
    vty_put_u32(buf + 4, RB_VERSION);
    rc = compute_mac(key, buf, mac);
    if (rc == VTY_OK) {
        memcpy(buf + RB_MAC_OFFSET, mac, RB_MAC_BYTES);
        rc = write_state(buf);
    }
    vty_secure_zero(key, sizeof(key));
    vty_secure_zero(mac, sizeof(mac));
    return rc == VTY_OK ? VTY_OK : VTY_E_ROLLBACK;
}

static int find_entry(const uint8_t buf[RB_TOTAL_BYTES],
                      const uint8_t uuid[VTY_UUID_BYTES])
{
    uint32_t count = vty_get_u32(buf + 8);
    uint32_t i;

    for (i = 0; i < count; i++) {
        const uint8_t *e = buf + RB_ENTRIES_OFFSET + (size_t)i * RB_ENTRY_BYTES;
        if (vty_ct_equal(e, uuid, VTY_UUID_BYTES) == 0) return (int)i;
    }
    return -1;
}

static uint8_t *entry_at(uint8_t buf[RB_TOTAL_BYTES], uint32_t index)
{
    return buf + RB_ENTRIES_OFFSET + (size_t)index * RB_ENTRY_BYTES;
}

static uint64_t entry_gen(const uint8_t *e)
{
    return vty_get_u64(e + VTY_UUID_BYTES);
}

static int entry_witness_valid(const uint8_t *e)
{
    return e[RB_ENTRY_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS;
}

/* 登记或更新条目；witness 参数为 -1 表示保持原槽位 */
static int upsert(uint8_t buf[RB_TOTAL_BYTES],
                  const uint8_t uuid[VTY_UUID_BYTES], uint64_t generation,
                  int allow_decrease, int witness_slot,
                  const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES], int *changed)
{
    int idx = find_entry(buf, uuid);
    uint8_t *e;
    uint32_t count;

    *changed = 0;
    if (idx >= 0) {
        uint64_t cur;
        e = entry_at(buf, (uint32_t)idx);
        cur = entry_gen(e);
        if (cur == generation && witness_slot < 0 &&
            (fp == NULL || memcmp(e + RB_ENTRY_FP_OFFSET, fp,
                                  VTY_TPM_WITNESS_FP_BYTES) == 0)) {
            return VTY_OK;
        }
        if (!allow_decrease && generation < cur) return VTY_E_ROLLBACK;
        vty_put_u64(e + VTY_UUID_BYTES, generation);
        if (witness_slot >= 0) {
            e[RB_ENTRY_WITNESS_OFFSET] = (uint8_t)witness_slot;
        }
        if (fp != NULL) {
            memcpy(e + RB_ENTRY_FP_OFFSET, fp, VTY_TPM_WITNESS_FP_BYTES);
        }
        *changed = 1;
        return VTY_OK;
    }

    count = vty_get_u32(buf + 8);
    if (count >= VTY_ROLLBACK_MAX_ENTRIES) return VTY_E_RESOURCE;
    e = entry_at(buf, count);
    memset(e, 0, RB_ENTRY_BYTES);
    memcpy(e, uuid, VTY_UUID_BYTES);
    vty_put_u64(e + VTY_UUID_BYTES, generation);
    e[RB_ENTRY_WITNESS_OFFSET] = (witness_slot >= 0) ? (uint8_t)witness_slot : 0xFFu;
    if (fp != NULL) {
        memcpy(e + RB_ENTRY_FP_OFFSET, fp, VTY_TPM_WITNESS_FP_BYTES);
    }
    vty_put_u32(buf + 8, count + 1u);
    *changed = 1;
    return VTY_OK;
}

static HANDLE lock_state(void)
{
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\Verthys.RollbackState");
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

static int rotate_witness(const uint8_t wid[VTY_UUID_BYTES], int current_slot,
                          int *next_slot,
                          uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    int next = (current_slot == 0) ? 1 : 0;

    if (vty_tpm_witness_create(wid, (uint8_t)next, fp) != VTY_OK) {
        return VTY_E_ROLLBACK;
    }
    *next_slot = next;
    return VTY_OK;
}

static void drop_stale_witness(const uint8_t wid[VTY_UUID_BYTES],
                               int current_slot, int next_slot)
{
    int stale = 1 - next_slot;

    if (stale != current_slot && stale >= 0) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)stale);
    }
    if (current_slot >= 0) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)current_slot);
    }
}

int vty_rollback_check(const uint8_t vault_uuid[VTY_UUID_BYTES],
                       uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    int is_new = 0;
    int idx;
    uint64_t stored;
    int rc = VTY_OK;
    int any_new;
    HANDLE lock;
    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_ROLLBACK;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    rc = load_authenticated(buf, &is_new);
    if (rc != VTY_OK) goto out;

    any_new = vty_tpm_witness_any(wid);
    if (is_new) {
        /* 状态缺失：见证仍在 = 删除/回滚；容器已有锚点（generation>=2）
         * 即使见证也被删除，仍拒绝，恢复码是唯一逃生通道。 */
        if (any_new != 0 || generation >= (uint64_t)RB_ANCHOR_MIN_GENERATION) {
            rc = VTY_E_ROLLBACK;
        }
        goto out;
    }

    idx = find_entry(buf, vault_uuid);
    if (idx >= 0) {
        const uint8_t *e = entry_at(buf, (uint32_t)idx);
        if (entry_witness_valid(e)) {
            if (vty_tpm_witness_verify(wid, e[RB_ENTRY_WITNESS_OFFSET],
                                       e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
                rc = VTY_E_ROLLBACK;
                goto out;
            }
        } else if (any_new != 0) {
            /* 条目尚未建立见证；出现密钥即拒绝 */
            rc = VTY_E_ROLLBACK;
            goto out;
        }
    } else {
        /* 状态存在但该库没有条目：等同缺失状态 */
        if (any_new != 0 || generation >= (uint64_t)RB_ANCHOR_MIN_GENERATION) {
            rc = VTY_E_ROLLBACK;
            goto out;
        }
        rc = VTY_OK;
        goto out;
    }

    stored = entry_gen(entry_at(buf, (uint32_t)idx));
    rc = (generation < stored) ? VTY_E_ROLLBACK : VTY_OK;

out:
    unlock_state(lock);
    return rc;
}

int vty_rollback_commit(const uint8_t vault_uuid[VTY_UUID_BYTES],
                        uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    int is_new = 0;
    int changed = 0;
    int idx;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    int had_witness = 0;
    int any_new;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    HANDLE lock;

    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_ROLLBACK;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    memset(fp, 0, sizeof(fp));
    rc = load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }

    any_new = vty_tpm_witness_any(wid);
    idx = find_entry(buf, vault_uuid);
    if (idx < 0) {
        /* 新登记的库：不允许已有见证密钥（否则状态被删/回滚） */
        if (any_new != 0) {
            unlock_state(lock);
            return VTY_E_ROLLBACK;
        }
    } else {
        const uint8_t *e = entry_at(buf, (uint32_t)idx);
        had_witness = entry_witness_valid(e);
        if (had_witness) {
            if (vty_tpm_witness_verify(wid, e[RB_ENTRY_WITNESS_OFFSET],
                                       e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
                unlock_state(lock);
                return VTY_E_ROLLBACK;
            }
            if (entry_gen(e) == generation) {
                /* 已是最新且见证有效：无需轮换 */
                unlock_state(lock);
                return VTY_OK;
            }
        }
        if (generation < entry_gen(e)) {
            unlock_state(lock);
            return VTY_E_ROLLBACK;
        }
        current_slot = had_witness ? (int)e[RB_ENTRY_WITNESS_OFFSET] : -1;
    }

    /* 先建新键，再写状态，最后删旧键：写失败时旧状态仍指向旧键，
     * 不会把库永久锁死。 */
    rc = rotate_witness(wid, current_slot, &next_slot, fp);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }
    rc = upsert(buf, vault_uuid, generation, 0, next_slot, fp, &changed);
    if (rc == VTY_OK) rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_ROLLBACK;
    }
    drop_stale_witness(wid, current_slot, next_slot);
    unlock_state(lock);
    return VTY_OK;
}

int vty_rollback_reset_anchor(const uint8_t vault_uuid[VTY_UUID_BYTES],
                              uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    int is_new = 0;
    int changed = 0;
    int idx;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    int had_witness = 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    HANDLE lock;

    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_ROLLBACK;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    memset(fp, 0, sizeof(fp));
    rc = load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }

    idx = find_entry(buf, vault_uuid);
    if (idx >= 0) {
        const uint8_t *e = entry_at(buf, (uint32_t)idx);
        had_witness = entry_witness_valid(e);
        if (had_witness) {
            if (vty_tpm_witness_verify(wid, e[RB_ENTRY_WITNESS_OFFSET],
                                       e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
                unlock_state(lock);
                return VTY_E_ROLLBACK;
            }
            current_slot = (int)e[RB_ENTRY_WITNESS_OFFSET];
        }
    }

    /* 恢复流程每次重设锚点都轮换见证，使此前所有状态副本失效 */
    rc = rotate_witness(wid, current_slot, &next_slot, fp);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }
    rc = upsert(buf, vault_uuid, generation, 1, next_slot, fp, &changed);
    if (rc == VTY_OK) rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_ROLLBACK;
    }
    drop_stale_witness(wid, current_slot, next_slot);
    unlock_state(lock);
    return VTY_OK;
}


