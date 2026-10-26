/*
 * vty_rollback.c — 库文件版本回退检测实现
 *
 * 状态布局（v2）：header(16) + N×{uuid(16), generation(8), witnessSlot(1),
 * witnessFp(32)} + MAC(32) + 设备根 blob(290)。
 *
 * MAC 密钥由设备根封装，覆盖 header、条目与 blob——篡改任意字节或把状态
 * 文件拷到其它机器都会解封/比对失败，从而 fail-closed。
 *
 * v2 额外用 TPM 持久化密钥作为“不可回滚见证”：每次提交创建另一槽的新
 * 密钥并记录公钥指纹，旧密钥随后删除。还原旧状态文件时其指纹指向已被
 * 覆盖的旧密钥，校验失败即拒绝。TPM NV 在本机不可用，这是可用的最强
 * 替代；残余缺口见偏差登记。
 */
#include "vty_rollback.h"
#include "vty_util.h"
#include "vty_kdf.h"
#include "vty_device_root.h"
#include "vty_tpm_witness.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>

#define RB_MAGIC          0x42525456u   /* 'VTRB'（小端） */
#define RB_VERSION        2u
#define RB_VERSION_LEGACY 1u
#define RB_HDR_BYTES      16u
#define RB_ENTRY_BYTES    57u
#define RB_ENTRY_BYTES_V1 24u
#define RB_MAC_BYTES      32u
#define RB_KEY_BYTES      VTY_KEY_BYTES
#define RB_BLOB_BYTES     VTY_DEVICE_BLOB_BYTES
#define RB_ENTRIES_OFFSET RB_HDR_BYTES
#define RB_ENTRY_WITNESS_OFFSET (VTY_UUID_BYTES + 8u)
#define RB_ENTRY_FP_OFFSET      (RB_ENTRY_WITNESS_OFFSET + 1u)

#define RB_ENTRIES_BYTES    (VTY_ROLLBACK_MAX_ENTRIES * RB_ENTRY_BYTES)
#define RB_ENTRIES_BYTES_V1 (VTY_ROLLBACK_MAX_ENTRIES * RB_ENTRY_BYTES_V1)
#define RB_MAC_OFFSET       (RB_HDR_BYTES + RB_ENTRIES_BYTES)
#define RB_BLOB_OFFSET      (RB_MAC_OFFSET + RB_MAC_BYTES)
#define RB_TOTAL_BYTES      (RB_BLOB_OFFSET + RB_BLOB_BYTES)
#define RB_MSG_BYTES        (RB_HDR_BYTES + RB_ENTRIES_BYTES + RB_BLOB_BYTES)

#define RB_MAC_OFFSET_V1 (RB_HDR_BYTES + RB_ENTRIES_BYTES_V1)
#define RB_BLOB_OFFSET_V1 (RB_MAC_OFFSET_V1 + RB_MAC_BYTES)
#define RB_TOTAL_BYTES_V1 (RB_BLOB_OFFSET_V1 + RB_BLOB_BYTES)

static char g_state_path[1024];
static char g_default_path[1024];
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

static int build_default_path(void)
{
    char base[768];
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, (DWORD)sizeof(base));

    if (n == 0 || n >= sizeof(base)) return VTY_E_POLICY;
    if (sprintf_s(g_default_path, sizeof(g_default_path), "%s\\Verthys", base) < 0) {
        return VTY_E_INVALID;
    }
    CreateDirectoryA(g_default_path, NULL);
    if (sprintf_s(g_default_path, sizeof(g_default_path),
                  "%s\\Verthys\\rollback.state", base) < 0) {
        return VTY_E_INVALID;
    }
    return VTY_OK;
}

int vty_rollback_set_path(const char *path)
{
    size_t len;

    if (path == NULL) return VTY_E_INVALID;
    len = strlen(path);
    if (len == 0 || len >= sizeof(g_state_path)) return VTY_E_INVALID;
    memcpy(g_state_path, path, len + 1);
    return VTY_OK;
}

int vty_rollback_init(void)
{
    int rc = vty_device_root_init();

    if (rc != VTY_OK) return rc;
    if (g_state_path[0] == '\0') {
        rc = build_default_path();
        if (rc != VTY_OK) return rc;
        memcpy(g_state_path, g_default_path, strlen(g_default_path) + 1);
    }
    g_initialized = 1;
    return VTY_OK;
}

/* 读取状态；legacy=1 表示 v1 布局。文件不存在时 missing=1。 */
static int read_state(uint8_t buf[RB_TOTAL_BYTES], int *missing, int *legacy)
{
    wchar_t *w;
    HANDLE h;
    DWORD got = 0;
    LARGE_INTEGER size;
    int rc = VTY_OK;

    *missing = 0;
    *legacy = 0;
    memset(buf, 0, RB_TOTAL_BYTES);
    if (!g_initialized) return VTY_E_POLICY;
    w = to_wide(g_state_path);
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
    if (size.QuadPart == (LONGLONG)RB_TOTAL_BYTES) {
        *legacy = 0;
    } else if (size.QuadPart == (LONGLONG)RB_TOTAL_BYTES_V1) {
        *legacy = 1;
    } else {
        CloseHandle(h);
        return VTY_E_CORRUPT;
    }
    if (!ReadFile(h, buf, (DWORD)(*legacy ? RB_TOTAL_BYTES_V1 : RB_TOTAL_BYTES),
                  &got, NULL) ||
        got != (DWORD)(*legacy ? RB_TOTAL_BYTES_V1 : RB_TOTAL_BYTES)) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    return rc;
}

static int write_state(const uint8_t buf[RB_TOTAL_BYTES])
{
    wchar_t *w = NULL;
    wchar_t *wt = NULL;
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

/* 把已通过 MAC 校验的 v1 布局提升为 v2 布局（旧条目与 blob 原样保留） */
static void promote_v1_to_v2(uint8_t buf[RB_TOTAL_BYTES])
{
    uint8_t tmp[RB_TOTAL_BYTES];
    uint32_t count = vty_get_u32(buf + 8);
    uint32_t i;

    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, buf, RB_HDR_BYTES);
    vty_put_u32(tmp + 4, RB_VERSION);
    if (count > VTY_ROLLBACK_MAX_ENTRIES) count = 0;
    for (i = 0; i < count; i++) {
        const uint8_t *src = buf + RB_ENTRIES_OFFSET + (size_t)i * RB_ENTRY_BYTES_V1;
        uint8_t *dst = tmp + RB_ENTRIES_OFFSET + (size_t)i * RB_ENTRY_BYTES;
        memcpy(dst, src, VTY_UUID_BYTES + 8u);
        dst[RB_ENTRY_WITNESS_OFFSET] = 0xFFu;   /* 0xFF=尚未建立见证 */
    }
    memcpy(tmp + RB_BLOB_OFFSET, buf + RB_BLOB_OFFSET_V1, RB_BLOB_BYTES);
    memcpy(buf, tmp, sizeof(tmp));
    vty_secure_zero(tmp, sizeof(tmp));
}

/* 读取并认证；文件不存在时 is_new=1。任何异常都返回 VTY_E_ROLLBACK，
 * 调用方据此 fail-closed。legacy 输出原始布局是否为 v1。 */
static int load_authenticated(uint8_t buf[RB_TOTAL_BYTES], int *is_new,
                              int *legacy)
{
    uint8_t key[RB_KEY_BYTES];
    uint8_t mac[RB_MAC_BYTES];
    int missing = 0;
    int rc;

    *is_new = 0;
    *legacy = 0;
    rc = read_state(buf, &missing, legacy);
    if (rc == VTY_E_IO && missing) {
        *is_new = 1;
        memset(buf, 0, RB_TOTAL_BYTES);
        return VTY_OK;
    }
    if (rc != VTY_OK) return VTY_E_ROLLBACK;

    if (vty_get_u32(buf) != RB_MAGIC ||
        vty_get_u32(buf + 4) != (*legacy ? RB_VERSION_LEGACY : RB_VERSION)) {
        return VTY_E_ROLLBACK;
    }
    if (vty_get_u32(buf + 8) > VTY_ROLLBACK_MAX_ENTRIES ||
        vty_get_u32(buf + 12) != 0) {
        return VTY_E_ROLLBACK;
    }
    rc = vty_device_key_unseal(buf + (*legacy ? RB_BLOB_OFFSET_V1 : RB_BLOB_OFFSET),
                               RB_BLOB_BYTES, key);
    if (rc != VTY_OK) {
        vty_secure_zero(key, sizeof(key));
        return VTY_E_ROLLBACK;
    }
    if (*legacy) {
        uint8_t msg[RB_HDR_BYTES + RB_ENTRIES_BYTES_V1 + RB_BLOB_BYTES];
        memcpy(msg, buf, RB_HDR_BYTES + RB_ENTRIES_BYTES_V1);
        memcpy(msg + RB_HDR_BYTES + RB_ENTRIES_BYTES_V1,
               buf + RB_BLOB_OFFSET_V1, RB_BLOB_BYTES);
        rc = vty_hmac_sha256(mac, key, RB_KEY_BYTES, msg, sizeof(msg));
        if (rc != VTY_OK ||
            vty_ct_equal(mac, buf + RB_MAC_OFFSET_V1, RB_MAC_BYTES) != 0) {
            rc = VTY_E_ROLLBACK;
        }
        vty_secure_zero(msg, sizeof(msg));
    } else {
        rc = compute_mac(key, buf, mac);
        if (rc != VTY_OK ||
            vty_ct_equal(mac, buf + RB_MAC_OFFSET, RB_MAC_BYTES) != 0) {
            rc = VTY_E_ROLLBACK;
        }
    }
    vty_secure_zero(key, sizeof(key));
    vty_secure_zero(mac, sizeof(mac));
    return (rc == VTY_OK) ? VTY_OK : VTY_E_ROLLBACK;
}

/* 按 v2 布局写入；调用前缓冲必须已是 v2 布局 */
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

/* 状态文件是“读-改-写”：多个进程同时打开不同库会互相覆盖条目，
 * 丢失的条目会让旧副本重新可用。用会话内命名互斥量串行化提交。 */
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

/* 选择另一槽并创建新见证；成功返回指纹与下一槽编号 */
static int rotate_witness(const uint8_t uuid[VTY_UUID_BYTES], int current_slot,
                          int *next_slot,
                          uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    int next = (current_slot == 0) ? 1 : 0;

    if (vty_tpm_witness_create(uuid, (uint8_t)next, fp) != VTY_OK) {
        return VTY_E_ROLLBACK;
    }
    *next_slot = next;
    return VTY_OK;
}

/* 成功写入后回收旧槽与可能残留的另一个槽，缩小旧状态可重放窗口 */
static void drop_stale_witness(const uint8_t uuid[VTY_UUID_BYTES],
                               int current_slot, int next_slot)
{
    int stale = 1 - next_slot;

    if (stale != current_slot && stale >= 0) {
        (void)vty_tpm_witness_delete(uuid, (uint8_t)stale);
    }
    if (current_slot >= 0) {
        (void)vty_tpm_witness_delete(uuid, (uint8_t)current_slot);
    }
}

int vty_rollback_check(const uint8_t vault_uuid[VTY_UUID_BYTES],
                       uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    int is_new = 0;
    int legacy = 0;
    int idx;
    uint64_t stored;
    int rc = VTY_OK;
    int any;
    HANDLE lock;

    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    rc = load_authenticated(buf, &is_new, &legacy);
    if (rc != VTY_OK) goto out;
    if (is_new) {
        /* 状态文件缺失但见证密钥仍在：视为被删除/回滚，拒绝 */
        any = vty_tpm_witness_any(vault_uuid);
        rc = (any == 0) ? VTY_OK : VTY_E_ROLLBACK;
        goto out;
    }

    if (legacy) {
        /* v1 无见证：只要出现该库的见证密钥就说明状态被降级/回滚 */
        any = vty_tpm_witness_any(vault_uuid);
        if (any != 0) {
            rc = VTY_E_ROLLBACK;
            goto out;
        }
        /* 认证后的 v1 布局提升为 v2，仅用于读取 generation */
        promote_v1_to_v2(buf);
    } else {
        idx = find_entry(buf, vault_uuid);
        if (idx >= 0) {
            const uint8_t *e = entry_at(buf, (uint32_t)idx);
            if (entry_witness_valid(e)) {
                if (vty_tpm_witness_verify(vault_uuid, e[RB_ENTRY_WITNESS_OFFSET],
                                           e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
                    rc = VTY_E_ROLLBACK;
                    goto out;
                }
            } else {
                /* 从 v1 整体迁移的条目：尚未为该库建立见证。MAC 有效时
                 * 只允许在没有任何见证密钥的情况下按老库规则放行，首次
                 * commit 会补建见证；出现密钥则说明状态被降级/回滚。 */
                any = vty_tpm_witness_any(vault_uuid);
                if (any != 0) {
                    rc = VTY_E_ROLLBACK;
                    goto out;
                }
            }
        } else {
            any = vty_tpm_witness_any(vault_uuid);
            rc = (any == 0) ? VTY_OK : VTY_E_ROLLBACK;
            goto out;
        }
    }

    idx = find_entry(buf, vault_uuid);
    if (idx < 0) {
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
    int is_new = 0;
    int legacy = 0;
    int changed = 0;
    int idx;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    int had_witness = 0;
    int any;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    HANDLE lock;

    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    memset(fp, 0, sizeof(fp));
    rc = load_authenticated(buf, &is_new, &legacy);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }
    if (legacy) promote_v1_to_v2(buf);

    idx = find_entry(buf, vault_uuid);
    if (idx < 0) {
        /* 新登记的库：不允许已有见证密钥（否则状态被删/回滚） */
        any = vty_tpm_witness_any(vault_uuid);
        if (any != 0) {
            unlock_state(lock);
            return VTY_E_ROLLBACK;
        }
    } else {
        const uint8_t *e = entry_at(buf, (uint32_t)idx);
        had_witness = !legacy && entry_witness_valid(e);
        if (had_witness) {
            if (vty_tpm_witness_verify(vault_uuid, e[RB_ENTRY_WITNESS_OFFSET],
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
    rc = rotate_witness(vault_uuid, current_slot, &next_slot, fp);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }
    rc = upsert(buf, vault_uuid, generation, 0, next_slot, fp, &changed);
    if (rc == VTY_OK) rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(vault_uuid, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_ROLLBACK;
    }
    drop_stale_witness(vault_uuid, current_slot, next_slot);
    unlock_state(lock);
    return VTY_OK;
}

int vty_rollback_reset_anchor(const uint8_t vault_uuid[VTY_UUID_BYTES],
                              uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    int is_new = 0;
    int legacy = 0;
    int changed = 0;
    int idx;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    HANDLE lock;

    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    memset(fp, 0, sizeof(fp));
    rc = load_authenticated(buf, &is_new, &legacy);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }
    if (legacy) promote_v1_to_v2(buf);

    idx = find_entry(buf, vault_uuid);
    if (idx >= 0 && !legacy) {
        const uint8_t *e = entry_at(buf, (uint32_t)idx);
        if (entry_witness_valid(e)) current_slot = (int)e[RB_ENTRY_WITNESS_OFFSET];
    }

    /* 恢复流程每次重设锚点都轮换见证，使此前所有状态副本失效 */
    rc = rotate_witness(vault_uuid, current_slot, &next_slot, fp);
    if (rc != VTY_OK) {
        unlock_state(lock);
        return rc;
    }
    rc = upsert(buf, vault_uuid, generation, 1, next_slot, fp, &changed);
    if (rc == VTY_OK) rc = store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(vault_uuid, (uint8_t)next_slot);
        unlock_state(lock);
        return VTY_E_ROLLBACK;
    }
    drop_stale_witness(vault_uuid, current_slot, next_slot);
    unlock_state(lock);
    return VTY_OK;
}
