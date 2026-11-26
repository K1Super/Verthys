/*
 * vty_keymanager_journal.c — 轮换恢复日志
 */

#include "vty_keymanager_internal.h"

/* 轮换恢复日志布局（72 字节，字段固定偏移，全小端）：
 *   0..7 魔数；8..23 库 UUID；24..31 源代；32..35 PCR 位图；
 *   36..39 保留；40..71 PCR 策略摘要。 */
#define VTY_ROTATE_JOURNAL_MAGIC "VTYROTJ1"
#define VTY_ROTATE_JOURNAL_SUFFIX ".vtyrotj"
#define VTY_ROTATE_JOURNAL_SIZE 72u
#define VTY_ROTATE_JOURNAL_PATH_MAX 1040u

typedef struct {
    HANDLE h;
    char path[VTY_ROTATE_JOURNAL_PATH_MAX];
} VtyRotateJournalLease;


static int rotate_journal_path(const VtyVault *v, char *out, size_t cap)
{
    size_t len;

    if (v == NULL || out == NULL || cap == 0) return 0;
    len = strlen(v->path);
    if (len == 0 || len + sizeof(VTY_ROTATE_JOURNAL_SUFFIX) > cap) return 0;
    memcpy(out, v->path, len);
    memcpy(out + len, VTY_ROTATE_JOURNAL_SUFFIX, sizeof(VTY_ROTATE_JOURNAL_SUFFIX));
    return 1;
}

static int rotate_journal_pcr_slot(const VtyVault *v)
{
    if (v == NULL) return -1;
    if ((v->header.flags & VTY_FLAG_PCR) == 0) return -1;
    return vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
}

/* 读取日志并校验结构与库绑定；任何不一致一律视为不存在。 */
static int rotate_journal_read(const VtyVault *v, uint8_t buf[VTY_ROTATE_JOURNAL_SIZE])
{
    wchar_t *w;
    HANDLE h;
    LARGE_INTEGER size;
    DWORD got = 0;
    char jpath[VTY_ROTATE_JOURNAL_PATH_MAX];

    if (!rotate_journal_path(v, jpath, sizeof(jpath))) return 0;
    w = vty_km_utf8_to_wide(jpath);
    if (w == NULL) return 0;
    /* 共享模式只请求读：提交进程的排他句柄会让这里直接失败。 */
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(h, &size) || size.QuadPart != (LONGLONG)VTY_ROTATE_JOURNAL_SIZE ||
        !ReadFile(h, buf, (DWORD)VTY_ROTATE_JOURNAL_SIZE, &got, NULL) ||
        got != (DWORD)VTY_ROTATE_JOURNAL_SIZE) {
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);

    return (memcmp(buf, VTY_ROTATE_JOURNAL_MAGIC, 8) == 0) &&
           (memcmp(buf + 8, v->header.vault_uuid, VTY_UUID_BYTES) == 0);
}

static uint64_t rotate_journal_generation(const uint8_t *buf)
{
    uint64_t gen = 0;
    uint32_t i;

    for (i = 0; i < 8u; i++) gen |= (uint64_t)buf[24u + i] << (8u * i);
    return gen;
}

static uint32_t rotate_journal_select(const uint8_t *buf)
{
    uint32_t sel = 0;
    uint32_t i;

    for (i = 0; i < 4u; i++) sel |= (uint32_t)buf[32u + i] << (8u * i);
    return sel;
}

int vty_vault_rotate_journal_start(const VtyVault *v, void **token)
{
    VtyRotateJournalLease *lease;
    uint8_t buf[VTY_ROTATE_JOURNAL_SIZE];
    char jpath[VTY_ROTATE_JOURNAL_PATH_MAX];
    wchar_t *w;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    uint64_t gen;
    uint32_t sel;
    uint32_t i;
    int p_idx;

    if (token != NULL) *token = NULL;
    if (v == NULL || token == NULL || !v->unlocked) return VTY_E_INVALID;
    p_idx = rotate_journal_pcr_slot(v);
    if (p_idx < 0) return VTY_E_POLICY;
    if (!rotate_journal_path(v, jpath, sizeof(jpath))) return VTY_E_INVALID;

    lease = (VtyRotateJournalLease *)vty_alloc(sizeof(*lease));
    if (lease == NULL) return VTY_E_RESOURCE;

    /* CREATE_ALWAYS + 独占共享：覆盖后、替换前的窗口内，其他进程无法读取
     * 或删除日志，避免并发解锁误判并重封正在迁出的密钥。 */
    w = vty_km_utf8_to_wide(jpath);
    if (w != NULL) {
        h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        free(w);
    }
    if (h == INVALID_HANDLE_VALUE) {
        vty_free(lease, sizeof(*lease));
        return VTY_E_IO;
    }

    memset(buf, 0, sizeof(buf));
    memcpy(buf, VTY_ROTATE_JOURNAL_MAGIC, 8);
    memcpy(buf + 8, v->header.vault_uuid, VTY_UUID_BYTES);
    gen = v->header.generation;
    for (i = 0; i < 8u; i++) buf[24u + i] = (uint8_t)(gen >> (8u * i));
    sel = v->slots[p_idx].pcr_select;
    for (i = 0; i < 4u; i++) buf[32u + i] = (uint8_t)(sel >> (8u * i));
    memcpy(buf + 40, v->slots[p_idx].pcr_digest, VTY_HASH_BYTES);

    if (!WriteFile(h, buf, (DWORD)VTY_ROTATE_JOURNAL_SIZE, &written, NULL) ||
        written != (DWORD)VTY_ROTATE_JOURNAL_SIZE || !FlushFileBuffers(h)) {
        CloseHandle(h);
        vty_km_delete_file_utf8(jpath);
        vty_free(lease, sizeof(*lease));
        return VTY_E_IO;
    }

    memset(lease, 0, sizeof(*lease));
    lease->h = h;
    memcpy(lease->path, jpath, strlen(jpath) + 1u);
    *token = lease;
    return VTY_OK;
}

void vty_vault_rotate_journal_end(void **token, int delete_file)
{
    VtyRotateJournalLease *lease;

    if (token == NULL || *token == NULL) return;
    lease = (VtyRotateJournalLease *)*token;
    *token = NULL;
    if (lease->h != INVALID_HANDLE_VALUE) CloseHandle(lease->h);
    if (delete_file) vty_km_delete_file_utf8(lease->path);
    vty_free(lease, sizeof(*lease));
}

int vty_vault_rotate_journal_match(const VtyVault *v)
{
    uint8_t buf[VTY_ROTATE_JOURNAL_SIZE];
    uint8_t cur[VTY_HASH_BYTES];
    int p_idx;
    int ok;

    p_idx = rotate_journal_pcr_slot(v);
    if (p_idx < 0) return 0;
    if (!rotate_journal_read(v, buf)) return 0;
    if (rotate_journal_generation(buf) != v->header.generation) return 0;
    if (rotate_journal_select(buf) != v->slots[p_idx].pcr_select) return 0;
    if (vty_ct_equal(buf + 40, v->slots[p_idx].pcr_digest, VTY_HASH_BYTES) != 0) {
        return 0;
    }
    /* 平台状态必须仍等于策略摘要：状态变化时不得自动重绑，否则等于
     * 用一次崩溃恢复绕过 PCR 策略。 */
    if (vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, cur) != VTY_OK) return 0;
    ok = (vty_ct_equal(cur, buf + 40, VTY_HASH_BYTES) == 0);
    vty_secure_zero(cur, sizeof(cur));
    return ok;
}

int vty_vault_rotate_journal_stale(const VtyVault *v)
{
    uint8_t buf[VTY_ROTATE_JOURNAL_SIZE];

    if (v == NULL) return 0;
    if (!rotate_journal_read(v, buf)) return 0;
    return rotate_journal_generation(buf) < v->header.generation;
}

void vty_vault_rotate_journal_clear(const VtyVault *v)
{
    char jpath[VTY_ROTATE_JOURNAL_PATH_MAX];

    if (!rotate_journal_path(v, jpath, sizeof(jpath))) return;
    vty_km_delete_file_utf8(jpath);
}
