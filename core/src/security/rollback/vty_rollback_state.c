/*
 * vty_rollback_state.c — 锚点状态文件的布局、读写与认证
 *
 * 负责状态缓冲的固定布局编解码、设备根封装、HMAC 认证与条目访问；
 * 尺寸异常或认证失败一律由调用方折叠为 fail-closed。
 */
#include "vty_rollback_internal.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "vty_kdf.h"

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
int vty_rb_load_authenticated(uint8_t buf[RB_TOTAL_BYTES], int *is_new)
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

/* 按当前布局写入；返回底层原始错误码。commit/check 路径必须使用
 * vty_rb_store() 包装，把任何写入失败折叠为 fail-closed 的 VTY_E_ROLLBACK；
 * 维护接口使用本函数，以便把状态读写失败与“文件回退”区分开。 */
int vty_rb_store_state(uint8_t buf[RB_TOTAL_BYTES])
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
    return rc;
}

int vty_rb_store(uint8_t buf[RB_TOTAL_BYTES])
{
    return vty_rb_store_state(buf) == VTY_OK ? VTY_OK : VTY_E_ROLLBACK;
}

int vty_rb_find_entry(const uint8_t buf[RB_TOTAL_BYTES],
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

uint8_t *vty_rb_entry_at(uint8_t buf[RB_TOTAL_BYTES], uint32_t index)
{
    return buf + RB_ENTRIES_OFFSET + (size_t)index * RB_ENTRY_BYTES;
}

uint64_t vty_rb_entry_gen(const uint8_t *e)
{
    return vty_get_u64(e + VTY_UUID_BYTES);
}

int vty_rb_entry_witness_valid(const uint8_t *e)
{
    return e[RB_ENTRY_WITNESS_OFFSET] < VTY_TPM_WITNESS_SLOTS;
}

/* 登记或更新条目；witness 参数为 -1 表示保持原槽位 */
int vty_rb_upsert(uint8_t buf[RB_TOTAL_BYTES],
                  const uint8_t uuid[VTY_UUID_BYTES], uint64_t generation,
                  int allow_decrease, int witness_slot,
                  const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES], int *changed)
{
    int idx = vty_rb_find_entry(buf, uuid);
    uint8_t *e;
    uint32_t count;

    *changed = 0;
    if (idx >= 0) {
        uint64_t cur;
        e = vty_rb_entry_at(buf, (uint32_t)idx);
        cur = vty_rb_entry_gen(e);
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
    if (count >= vty_rb_max_entries()) return VTY_E_RESOURCE;
    e = vty_rb_entry_at(buf, count);
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
