/*
 * test_v4_rotate.c — D9 全库 DEK 轮换验收
 *
 * 覆盖：恢复会话门禁、口令复核、源库只读、记录 ID/时间保真、文件/分片
 * 复制、模块口令与恢复槽重建、Keyfile 策略拒绝、PCR 保留、Abort 清理、
 * 提交后普通解锁与恢复码仍可用。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_keyfile.h"
#include "vty_keymanager_v4.h"
#include "vty_module_v4.h"
#include "vty_repo_v4.h"
#include "vty_recovery.h"
#include "vty_lockout.h"
#include "vty_device_root.h"
#include "vty_rollback.h"
#include "vty_tpm_pcr.h"
#include "vty_tpm_witness.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

static void rotate_cleanup_files(const char *a, const char *b)
{
    if (a != NULL) remove(a);
    if (b != NULL) remove(b);
}

#if defined(_WIN32)
/* keep_old 备份文件名为 <源路径>.old-<tick>-<rnd>，测试用通配符确认存在。 */
static int rotate_backup_exists(const char *base)
{
    wchar_t pattern[600];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int n;

    if (base == NULL) return 0;
    n = MultiByteToWideChar(CP_UTF8, 0, base, -1, pattern, 600);
    if (n <= 0 || n + 7 >= 600) return 0;
    wcscat_s(pattern, 600, L".old-*");
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    FindClose(h);
    return 1;
}

/* 取第一份备份的真实路径：源路径 + 目录内 .old-* 后缀。 */
static int rotate_find_backup(const char *base, char *out, size_t cap)
{
    wchar_t pattern[600];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    char name[600];
    const char *slash;
    size_t prefix;
    int n;

    if (base == NULL || out == NULL || cap == 0) return 0;
    n = MultiByteToWideChar(CP_UTF8, 0, base, -1, pattern, 600);
    if (n <= 0 || n + 7 >= 600) return 0;
    wcscat_s(pattern, 600, L".old-*");
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    n = WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name, 600, NULL, NULL);
    FindClose(h);
    if (n <= 0) return 0;

    if (strncmp(name, base, strlen(base)) == 0) {
        if (strlen(name) + 1u > cap) return 0;
        memcpy(out, name, strlen(name) + 1u);
        return 1;
    }
    slash = strrchr(base, '\\');
    if (slash == NULL) slash = strrchr(base, '/');
    prefix = (slash != NULL) ? (size_t)(slash - base) + 1u : 0u;
    if (prefix + strlen(name) + 1u > cap) return 0;
    if (prefix != 0u) memcpy(out, base, prefix);
    memcpy(out + prefix, name, strlen(name) + 1u);
    return 1;
}

static void rotate_remove_backups(const char *base)
{
    wchar_t pattern[600];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int n;

    if (base == NULL) return;
    n = MultiByteToWideChar(CP_UTF8, 0, base, -1, pattern, 600);
    if (n <= 0 || n + 7 >= 600) return;
    wcscat_s(pattern, 600, L".old-*");
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        (void)DeleteFileW(fd.cFileName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}
#endif

/* D9 恢复日志与库文件同目录：<库路径>.vtyrotj。 */
static int rotate_journal_exists(const char *base)
{
    char path[600];
    FILE *f;

    if (base == NULL || strlen(base) + 9u > sizeof(path)) return 0;
    memcpy(path, base, strlen(base));
    memcpy(path + strlen(base), ".vtyrotj", 9u);
    f = fopen(path, "rb");
    if (f == NULL) return 0;
    fclose(f);
    return 1;
}

static void rotate_remove_journal(const char *base)
{
    char path[600];

    if (base == NULL || strlen(base) + 9u > sizeof(path)) return;
    memcpy(path, base, strlen(base));
    memcpy(path + strlen(base), ".vtyrotj", 9u);
    (void)remove(path);
}

static uint32_t rotate_count_files(VtyVault *v)
{
    uint64_t n = 0;
    (void)vty_repo_file_list(v, NULL, NULL, &n);
    return (uint32_t)n;
}

static int rotate_collect(VtyVault *v, uint64_t *ids, uint64_t *times,
                          size_t cap, size_t *out)
{
    VtyRepoIter *it = NULL;
    size_t n = 0;
    int rc;

    rc = vty_repo_iter_open(v, 0u, &it);
    if (rc != VTY_OK) return rc;
    for (;;) {
        VtyRepoLeaf leaf;
        int done = 0;
        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK) break;
        if (done) break;
        if (n >= cap) { rc = VTY_E_RESOURCE; break; }
        ids[n] = leaf.record_id;
        times[n] = leaf.created_time;
        n++;
    }
    vty_repo_iter_close(it);
    if (rc == VTY_OK) *out = n;
    return rc;
}

static int rotate_progress_cb(void *user, const VerthysRotateInfo *info)
{
    int *calls = (int *)user;
    if (calls != NULL && info != NULL) (*calls)++;
    return 0;
}

/* 第一次进度回调即请求取消：验证 Run 进入 FAILED 且只能 Abort。 */
static int rotate_cancel_cb(void *user, const VerthysRotateInfo *info)
{
    int *calls = (int *)user;
    if (calls != NULL && info != NULL) (*calls)++;
    return 1;
}

TEST(v4_rotate_recovery_gate_and_readonly)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    uint64_t id = 0;
    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_gate.vty", "v4_rotate_gate.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_RECORD_PHOTO;
    rec.data = data;
    rec.data_len = sizeof(data);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_gate.vty", "gate-pw", 7,
                              code, sizeof(code)), VERTHYS_OK);

    /* 普通解锁会话不是合法源库。 */
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_gate.tmp.vty", "gate-pw", 7,
                                   0u, &info), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_gate.vty", code),
             VERTHYS_OK);

    /* 未持有正确容器口令时拒绝。 */
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_gate.tmp.vty", "bad-pw", 6,
                                   0u, &info), VERTHYS_ERR_AUTH);

    /* 目标已存在 / 跨目录（非原子替换）都必须在建库前拒绝。 */
    {
        FILE *f = fopen("v4_rotate_gate.exists", "wb");
        CHECK(f != NULL);
        fclose(f);
    }
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_gate.exists", "gate-pw", 7,
                                   0u, &info), VERTHYS_ERR_EXISTS);
    remove("v4_rotate_gate.exists");
    CHECK_EQ(Verthys_V4RotateBegin(h, "sub\\v4_rotate_gate.tmp.vty",
                                   "gate-pw", 7, 0u, &info),
             VERTHYS_ERR_INVALID);

    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_gate.tmp.vty", "gate-pw", 7,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(info.stage, VERTHYS_V4_ROTATE_STAGE_BEGUN);

    /* 作业期间源库只读；重复 Begin 返回 pending；Run 前不可 Commit。 */
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_gate.tmp.vty", "gate-pw", 7,
                                   0u, &info), VERTHYS_ERR_ROTATE_PENDING);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_ERR_ROTATE_PENDING);
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_ACCOUNTS,
                                    "mod-pw", 6, NULL),
             VERTHYS_ERR_ROTATE_PENDING);

    CHECK_EQ(Verthys_V4RotateAbort(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateAbort(h), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_OK);
    CHECK(id != 0u);
    CHECK(fopen("v4_rotate_gate.tmp.vty", "rb") == NULL);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_gate.vty", "v4_rotate_gate.tmp.vty");
    return 0;
}

TEST(v4_rotate_full_roundtrip_preserves_records_and_files)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VtyVault *v;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    uint8_t uuid_before[VTY_UUID_BYTES];
    uint64_t epoch_before;
    uint64_t gen_before;
    uint64_t ids[4];
    uint64_t times[4];
    size_t leaf_count = 0;
    uint64_t id0 = 0, id1 = 0, id2 = 0;
    const char *d0 = "photo-data";
    const char *d1 = "account-data";
    const char *d2 = "system-data";
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    VtyRepoFile f_before;
    VtyRepoFile f_after;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int calls = 0;
    size_t i;

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_full.vty", "v4_rotate_full.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(uuid_before, 0, sizeof(uuid_before));
    memset(file_uuid, 0, sizeof(file_uuid));
    memset(pt_hash, 0, sizeof(pt_hash));
    for (i = 0; i < sizeof(file_uuid); i++) file_uuid[i] = (uint8_t)(i + 1u);
    for (i = 0; i < sizeof(pt_hash); i++) pt_hash[i] = (uint8_t)(0xA0u + i);
    memset(&f_before, 0, sizeof(f_before));
    memset(&f_after, 0, sizeof(f_after));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_full.vty", "full-pw", 7,
                              code, sizeof(code)), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    v = ctx->v4;
    memcpy(uuid_before, v->header.vault_uuid, VTY_UUID_BYTES);
    epoch_before = v->header.epoch;
    gen_before = v->header.generation;

    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_RECORD_PHOTO;
    rec.name = "n0";
    rec.name_len = 2;
    rec.data = (const uint8_t *)d0;
    rec.data_len = strlen(d0);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id0), VERTHYS_OK);
    rec.type = VERTHYS_RECORD_ACCOUNT;
    rec.name = "n1";
    rec.name_len = 2;
    rec.data = (const uint8_t *)d1;
    rec.data_len = strlen(d1);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id1), VERTHYS_OK);
    rec.type = (VerthysRecordType)0x10;   /* 系统记录域 */
    rec.name = "n2";
    rec.name_len = 2;
    rec.data = (const uint8_t *)d2;
    rec.data_len = strlen(d2);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id2), VERTHYS_OK);
    CHECK(id0 != 0u && id1 != 0u && id2 != 0u);

    CHECK_EQ(vty_repo_file_put(v, file_uuid, pt_hash, 2u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 0u,
                                (const uint8_t *)"abc", 3u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 1u,
                                (const uint8_t *)"defgh", 5u), VTY_OK);
    CHECK_EQ(vty_repo_file_get(v, file_uuid, &f_before), VTY_OK);

    CHECK_EQ(rotate_collect(v, ids, times, 4, &leaf_count), VTY_OK);
    CHECK_EQ((long)leaf_count, 3L);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_full.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_full.tmp.vty", "full-pw", 7,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, rotate_progress_cb, &calls), VERTHYS_OK);
    CHECK(calls > 0);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);
    CHECK(fopen("v4_rotate_full.tmp.vty", "rb") == NULL);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    v = ctx->v4;
    CHECK(memcmp(v->header.vault_uuid, uuid_before, VTY_UUID_BYTES) == 0);
    CHECK(v->header.epoch == epoch_before + 1u);
    CHECK(v->header.generation > gen_before);

    rec.data = NULL;
    rec.data_len = 0;
    rec.name = NULL;
    rec.name_len = 0;
    CHECK_EQ(Verthys_GetRecord(h, id0, &rec), VERTHYS_OK);
    CHECK(rec.type == VERTHYS_RECORD_PHOTO);
    CHECK(rec.data_len == strlen(d0));
    CHECK(memcmp(rec.data, d0, rec.data_len) == 0);
    CHECK_EQ(Verthys_GetRecord(h, id1, &rec), VERTHYS_OK);
    CHECK(rec.type == VERTHYS_RECORD_ACCOUNT);
    CHECK(rec.data_len == strlen(d1));
    CHECK(memcmp(rec.data, d1, rec.data_len) == 0);
    CHECK_EQ(Verthys_GetRecord(h, id2, &rec), VERTHYS_OK);
    CHECK(rec.type == (VerthysRecordType)0x10);
    CHECK(rec.data_len == strlen(d2));
    CHECK(memcmp(rec.data, d2, rec.data_len) == 0);

    {
        uint64_t nids[4];
        uint64_t ntimes[4];
        size_t ncount = 0;
        CHECK_EQ(rotate_collect(v, nids, ntimes, 4, &ncount), VTY_OK);
        CHECK_EQ((long)ncount, 3L);
        for (i = 0; i < ncount; i++) {
            size_t j;
            int found = 0;
            for (j = 0; j < leaf_count; j++) {
                if (ids[j] == nids[i]) {
                    found = 1;
                    CHECK(ntimes[i] == times[j]);
                    break;
                }
            }
            CHECK(found);
        }
    }

    CHECK_EQ(vty_repo_file_get(v, file_uuid, &f_after), VTY_OK);
    CHECK(f_after.total == f_before.total);
    CHECK(f_after.created_time == f_before.created_time);
    CHECK(memcmp(f_after.pt_hash, f_before.pt_hash, VTY_HASH_BYTES) == 0);
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 0u, &pt, &pt_len), VTY_OK);
    CHECK(pt_len == 3u && memcmp(pt, "abc", 3) == 0);
    if (pt != NULL) { vty_secure_zero(pt, pt_len); vty_free(pt, pt_len); }
    pt = NULL;
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 1u, &pt, &pt_len), VTY_OK);
    CHECK(pt_len == 5u && memcmp(pt, "defgh", 5) == 0);
    if (pt != NULL) { vty_secure_zero(pt, pt_len); vty_free(pt, pt_len); }
    CHECK_EQ((long)rotate_count_files(v), 1L);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, "v4_rotate_full.vty", "full-pw", 7),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id1, &rec), VERTHYS_OK);
    CHECK(rec.data_len == strlen(d1) && memcmp(rec.data, d1, rec.data_len) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_full.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id2, &rec), VERTHYS_OK);
    CHECK(rec.data_len == strlen(d2) && memcmp(rec.data, d2, rec.data_len) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_full.vty", "v4_rotate_full.tmp.vty");
    return 0;
}

TEST(v4_rotate_modules_require_password_and_rebind_recovery)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    VerthysModuleStatus st;
    uint64_t id = 0;
    const char *acct = "acct-data";

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_mod.vty", "v4_rotate_mod.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(&st, 0, sizeof(st));
    memset(&rec, 0, sizeof(rec));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_mod.vty", "mod-vault-pw", 12,
                              code, sizeof(code)), VERTHYS_OK);
    /* 带恢复码启用模块：轮换后必须重建模块 recovery 槽。 */
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_ACCOUNTS,
                                    "acct-pw", 7, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_ACCOUNTS, &st),
             VERTHYS_OK);
    CHECK_EQ(st.enabled, 1u);
    CHECK_EQ(st.has_recovery, 1u);

    rec.type = VERTHYS_RECORD_ACCOUNT;
    rec.name = "a";
    rec.name_len = 1;
    rec.data = (const uint8_t *)acct;
    rec.data_len = strlen(acct);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_OK);
    CHECK(id != 0u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_mod.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_mod.tmp.vty", "mod-vault-pw",
                                   12, 0u, &info), VERTHYS_OK);

    /* 未登记模块口令时拒绝（源模块未解锁）。 */
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_ERR_MODULE_LOCKED);
    CHECK_EQ(Verthys_V4RotateUnlockModule(h, VERTHYS_MODULE_ACCOUNTS,
                                          "bad", 3, NULL), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4RotateUnlockModule(h, VERTHYS_MODULE_ACCOUNTS,
                                          "acct-pw", 7, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_ACCOUNTS, &st),
             VERTHYS_OK);
    CHECK_EQ(st.enabled, 1u);
    CHECK_EQ(st.unlocked, 1u);
    CHECK_EQ(st.has_recovery, 1u);
    CHECK_EQ(Verthys_GetRecord(h, id, &rec), VERTHYS_OK);
    CHECK(rec.data_len == strlen(acct) &&
          memcmp(rec.data, acct, rec.data_len) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, "v4_rotate_mod.vty", "mod-vault-pw", 12),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_ACCOUNTS, &st),
             VERTHYS_OK);
    CHECK_EQ(st.enabled, 1u);
    CHECK_EQ(st.unlocked, 0u);
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_ACCOUNTS,
                                    "acct-pw", 7), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &rec), VERTHYS_OK);
    CHECK(rec.data_len == strlen(acct) &&
          memcmp(rec.data, acct, rec.data_len) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_mod.vty", "v4_rotate_mod.tmp.vty");
    return 0;
}

TEST(v4_rotate_create_from_kc_never_deletes_foreign_target)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VtyVault *tmp_vault = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t kc[VTY_KEY_BYTES];
    uint8_t before[8];
    uint8_t after[8];
    FILE *f;
    size_t n;
    uint16_t flags;
    size_t i;

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_race.vty", "v4_rotate_race.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(kc, 0, sizeof(kc));
    memset(before, 0, sizeof(before));
    memset(after, 0, sizeof(after));

    /* 预先放置一个“他人文件”，再绕过 Begin 的存在性预检直接调用
     * 新库创建原语：CREATE_NEW 失败时绝不能删除该文件。 */
    for (i = 0; i < sizeof(before); i++) before[i] = (uint8_t)(0x40u + i);
    f = fopen("v4_rotate_race.tmp.vty", "wb");
    CHECK(f != NULL);
    CHECK(fwrite(before, 1, sizeof(before), f) == sizeof(before));
    fclose(f);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_race.vty", "race-pw", 7,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_race.vty", code),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    flags = (uint16_t)(ctx->v4->header.flags &
                       (uint16_t)~(VTY_FLAG_PCR | VTY_FLAG_MODULE_M1));
    vty_random(kc, sizeof(kc));
    CHECK_EQ(vty_vault_create_from_kc(ctx->v4, "v4_rotate_race.tmp.vty",
                                      "race-pw", kc, flags, NULL,
                                      &tmp_vault), VTY_E_IO);
    CHECK(tmp_vault == NULL);
    vty_secure_zero(kc, sizeof(kc));

    n = 0;
    f = fopen("v4_rotate_race.tmp.vty", "rb");
    CHECK(f != NULL);
    n = fread(after, 1, sizeof(after), f);
    fclose(f);
    CHECK(n == sizeof(after));
    CHECK(memcmp(before, after, sizeof(before)) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_race.vty", "v4_rotate_race.tmp.vty");
    return 0;
}

TEST(v4_rotate_rollback_anchor_advances)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t id = 0;
    uint64_t anchor_before;
    uint64_t gen_after;

    vty_lockout_set_enabled(0);
    rotate_cleanup_files("v4_rotate_rb.vty", "v4_rotate_rb.tmp.vty");
    remove("v4_rotate_rb.state");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(uuid, 0, sizeof(uuid));
    memset(&rec, 0, sizeof(rec));

    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path("v4_rotate_rb.state"), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_rb.vty", "rb-pw", 5,
                              code, sizeof(code)), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    memcpy(uuid, ctx->v4->header.vault_uuid, VTY_UUID_BYTES);

    rec.type = VERTHYS_RECORD_PHOTO;
    rec.name = "r";
    rec.name_len = 1;
    rec.data = (const uint8_t *)"x";
    rec.data_len = 1;
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    /* 恢复码解锁把锚点重设为当前源库代：这就是轮换前允许回退的窗口。 */
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_rb.vty", code),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    anchor_before = ctx->v4->header.generation;

    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_rb.tmp.vty", "rb-pw", 5,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    gen_after = ctx->v4->header.generation;
    CHECK(gen_after > anchor_before);

    /* Commit 必须把锚点推进到新库代，源库代随即被拒绝。 */
    CHECK_EQ(vty_rollback_check(uuid, gen_after), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, anchor_before), VTY_E_ROLLBACK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    vty_rollback_set_enabled(0);
    CHECK_EQ(vty_tpm_witness_delete_all(uuid), VTY_OK);
    rotate_cleanup_files("v4_rotate_rb.vty", "v4_rotate_rb.tmp.vty");
    remove("v4_rotate_rb.state");
    return 0;
}

TEST(v4_rotate_keyfile_session_rejected)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_kf.vty", "v4_rotate_kf.tmp.vty");
    remove("v4_rotate_kf.key");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4CreateKeyfile(h, "v4_rotate_kf.vty", "kf-pw", 5,
                                     "v4_rotate_kf.key",
                                     code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_kf.vty", code),
             VERTHYS_OK);
    /* 恢复会话不持有 keyfile 摘要：轮换必须在 Begin 拒绝，而不是生成
     * 一个只能靠新 keyfile 打开的库。 */
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_kf.tmp.vty", "kf-pw", 5,
                                   0u, &info), VERTHYS_ERR_POLICY);
    CHECK(fopen("v4_rotate_kf.tmp.vty", "rb") == NULL);

    /* 补录：非法路径 / 错误口令都不得写入会话摘要。 */
    CHECK_EQ(Verthys_V4RotateAttachKeyfile(h, "v4_rotate_kf_missing.key",
                                           "kf-pw", 5),
             VERTHYS_ERR_KEYFILE_INVALID);
    CHECK_EQ(Verthys_V4RotateAttachKeyfile(h, "v4_rotate_kf.key",
                                           "bad-pw", 6),
             VERTHYS_ERR_AUTH);

    /* 正确 keyfile + 当前容器口令：补录成功后 Begin 可继续。 */
    CHECK_EQ(Verthys_V4RotateAttachKeyfile(h, "v4_rotate_kf.key", "kf-pw", 5),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_kf.tmp.vty", "kf-pw", 5,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateAbort(h), VERTHYS_OK);
    CHECK(fopen("v4_rotate_kf.tmp.vty", "rb") == NULL);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_kf.vty", "v4_rotate_kf.tmp.vty");
    remove("v4_rotate_kf.key");
    return 0;
}

TEST(v4_rotate_run_cancel_callback)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    VerthysRecord got;
    uint64_t id = 0;
    int calls = 0;
    uint8_t data[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                         9, 10, 11, 12, 13, 14, 15, 16 };

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_cancel.vty", "v4_rotate_cancel.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(&rec, 0, sizeof(rec));
    memset(&got, 0, sizeof(got));
    rec.type = VERTHYS_RECORD_PHOTO;
    rec.name = "cancel-record";
    rec.name_len = strlen(rec.name);
    rec.data = data;
    rec.data_len = sizeof(data);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_cancel.vty", "cancel-pw", 9,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_cancel.vty", code),
             VERTHYS_OK);

    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_cancel.tmp.vty",
                                   "cancel-pw", 9, 0u, &info), VERTHYS_OK);
    /* 首次进度回调返回非 0：Run 必须进入 FAILED，源库不被替换。 */
    CHECK_EQ(Verthys_V4RotateRun(h, rotate_cancel_cb, &calls),
             VERTHYS_ERR_POLICY);
    CHECK(calls >= 1);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4RotateAbort(h), VERTHYS_OK);
    CHECK(fopen("v4_rotate_cancel.tmp.vty", "rb") == NULL);

    /* 中止后源库记录仍可读，内容未变。 */
    CHECK_EQ(Verthys_GetRecord(h, id, &got), VERTHYS_OK);
    CHECK_EQ(got.data_len, sizeof(data));
    CHECK(memcmp(got.data, data, sizeof(data)) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_cancel.vty", "v4_rotate_cancel.tmp.vty");
    return 0;
}

TEST(v4_rotate_pcr_binding_preserved)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    uint8_t uuid[VTY_UUID_BYTES];
    uint32_t enabled = 0xFFFFFFFFu;
    uint32_t select = 0xFFFFFFFFu;

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCR 不可用\n");
        return 0;
    }
    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_pcr.vty", "v4_rotate_pcr.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(uuid, 0, sizeof(uuid));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_pcr.vty", "pcr-pw", 6,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(select, (uint32_t)VTY_TPM_PCR_SELECT_DEFAULT);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    memcpy(uuid, ctx->v4->header.vault_uuid, VTY_UUID_BYTES);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_pcr.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_pcr.tmp.vty", "pcr-pw", 6,
                                   VERTHYS_V4_ROTATE_FLAG_DROP_PCR,
                                   &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);

    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(select, (uint32_t)VTY_TPM_PCR_SELECT_DEFAULT);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, "v4_rotate_pcr.vty", "pcr-pw", 6),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    CHECK(!rotate_journal_exists("v4_rotate_pcr.vty"));
    rotate_remove_journal("v4_rotate_pcr.vty");
    rotate_cleanup_files("v4_rotate_pcr.vty", "v4_rotate_pcr.tmp.vty");
    return 0;
}

/* D9 崩溃窗口自愈：Commit 已用新 K_c 覆盖 PCR 密钥、但进程在原子替换前
 * 被杀。残留恢复日志必须让源库口令解锁自愈；没有日志时保持 fail-closed。 */
TEST(v4_rotate_pcr_journal_crash_recovery)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t other_kc[VTY_KEY_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];
    void *lease = NULL;
    const char *path = "v4_rotate_journal.vty";

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCR 不可用\n");
        return 0;
    }
    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files(path, NULL);
    rotate_remove_journal(path);
    memset(code, 0, sizeof(code));
    memset(uuid, 0, sizeof(uuid));
    memset(other_kc, 0, sizeof(other_kc));
    memset(ct, 0, sizeof(ct));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, path, "journal-pw", 10, code, sizeof(code)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, code),
             VERTHYS_OK);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    memcpy(uuid, ctx->v4->header.vault_uuid, VTY_UUID_BYTES);

    /* 模拟 Commit 在覆盖前落盘日志：只关闭租约句柄，日志留在盘上。 */
    CHECK_EQ(vty_vault_rotate_journal_start(ctx->v4, &lease), VTY_OK);
    CHECK(lease != NULL);
    vty_vault_rotate_journal_end(&lease, 0);
    CHECK(rotate_journal_exists(path));
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 模拟覆盖后的残留状态：同名 TPM 密钥换成新 K_c，旧槽位不可解。 */
    vty_random(other_kc, sizeof(other_kc));
    CHECK_EQ(vty_tpm_pcr_key_create(uuid, VTY_TPM_PCR_SELECT_DEFAULT, NULL, 0),
             VTY_OK);
    CHECK_EQ(vty_tpm_pcr_seal(uuid, other_kc, ct), VTY_OK);

    CHECK_EQ(Verthys_V4Unlock(h, path, "journal-pw", 10), VERTHYS_OK);
    CHECK(!rotate_journal_exists(path));

    /* 自愈后制造同样状态但不留日志：必须 fail-closed。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    vty_random(other_kc, sizeof(other_kc));
    CHECK_EQ(vty_tpm_pcr_key_create(uuid, VTY_TPM_PCR_SELECT_DEFAULT, NULL, 0),
             VTY_OK);
    CHECK_EQ(vty_tpm_pcr_seal(uuid, other_kc, ct), VTY_OK);
    /* 覆盖后的私钥无法解封旧槽密文：PCR 门按 TPM 失败收口。 */
    CHECK_EQ(Verthys_V4Unlock(h, path, "journal-pw", 10), VERTHYS_ERR_TPM);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    vty_secure_zero(other_kc, sizeof(other_kc));
    vty_secure_zero(ct, sizeof(ct));
    rotate_remove_journal(path);
    rotate_cleanup_files(path, NULL);
    return 0;
}

/* keep_old=1 + PCR：旧备份的 PCR 槽随密钥覆盖失效（刻意反回滚设计），
 * 备份只能用恢复码打开，普通口令必须被 PCR 门拒绝。 */
TEST(v4_rotate_keep_old_pcr_backup_requires_recovery)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];
    VerthysRotateInfo info;
    char backup[600];
    const char *base = "v4_rotate_keep_pcr.vty";
    const char *tmp = "v4_rotate_keep_pcr.tmp.vty";
    const char *pw = "keep-pcr-pw";
    size_t pw_len = strlen("keep-pcr-pw");

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCR 不可用\n");
        return 0;
    }
    memset(code, 0, sizeof(code));
    memset(uuid, 0, sizeof(uuid));
    memset(&info, 0, sizeof(info));
    memset(backup, 0, sizeof(backup));
    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files(base, tmp);
    rotate_remove_journal(base);
#if defined(_WIN32)
    rotate_remove_backups(base);
#endif

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, base, pw, pw_len, code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, code), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    memcpy(uuid, ctx->v4->header.vault_uuid, VTY_UUID_BYTES);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, base, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, tmp, pw, pw_len, 0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 1u), VERTHYS_OK);
    CHECK(!rotate_journal_exists(base));

    /* 新库口令解锁不受影响。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, base, pw, pw_len), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

#if defined(_WIN32)
    CHECK(rotate_find_backup(base, backup, sizeof(backup)));
#endif
    /* 备份的 PCR 槽已被同名密钥覆盖：口令路径必须 fail-closed。 */
    CHECK(backup[0] != '\0');
    CHECK_EQ(Verthys_V4Unlock(h, backup, pw, pw_len), VERTHYS_ERR_TPM);
    /* 恢复码不经过 PCR 门，备份仍可用于灾难恢复。 */
    CHECK_EQ(Verthys_V4UnlockRecovery(h, backup, code), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
#if defined(_WIN32)
    rotate_remove_backups(base);
#endif
    rotate_remove_journal(base);
    rotate_cleanup_files(base, tmp);
    return 0;
}

/* keep_old=1 必须保留可独立打开的旧库备份，且源路径被新库替换。 */
TEST(v4_rotate_keep_old_preserves_backup)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    VerthysRecord got;
    uint64_t id = 0;
    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_keep.vty", "v4_rotate_keep.tmp.vty");
#if defined(_WIN32)
    rotate_remove_backups("v4_rotate_keep.vty");
#endif
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(&rec, 0, sizeof(rec));
    memset(&got, 0, sizeof(got));
    rec.type = VERTHYS_RECORD_PHOTO;
    rec.name = "keep-name";
    rec.name_len = strlen(rec.name);
    rec.data = data;
    rec.data_len = sizeof(data);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_keep.vty", "keep-pw", 7,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_OK);
    CHECK(id != 0u);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_keep.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_keep.tmp.vty", "keep-pw", 7,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 1u), VERTHYS_OK);

#if defined(_WIN32)
    CHECK(rotate_backup_exists("v4_rotate_keep.vty"));
#endif
    CHECK(fopen("v4_rotate_keep.tmp.vty", "rb") == NULL);
    CHECK(fopen("v4_rotate_keep.vty", "rb") != NULL);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, "v4_rotate_keep.vty", "keep-pw", 7),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &got), VERTHYS_OK);
    CHECK(got.data_len == sizeof(data));
    CHECK(memcmp(got.data, data, sizeof(data)) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
#if defined(_WIN32)
    rotate_remove_backups("v4_rotate_keep.vty");
#endif
    rotate_cleanup_files("v4_rotate_keep.vty", "v4_rotate_keep.tmp.vty");
    return 0;
}

/* 取消必须在分片边界生效：大文件复制期间不能等到整文件结束。 */
TEST(v4_rotate_cancel_during_chunk_copy)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VtyVault *v;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int calls = 0;
    size_t i;

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_chunk.vty", "v4_rotate_chunk.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(file_uuid, 0, sizeof(file_uuid));
    memset(pt_hash, 0, sizeof(pt_hash));
    for (i = 0; i < sizeof(file_uuid); i++) file_uuid[i] = (uint8_t)(i + 1u);
    for (i = 0; i < sizeof(pt_hash); i++) pt_hash[i] = (uint8_t)(0xB0u + i);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_chunk.vty", "chunk-pw", 8,
                              code, sizeof(code)), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    v = ctx->v4;
    CHECK_EQ(vty_repo_file_put(v, file_uuid, pt_hash, 2u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 0u,
                                (const uint8_t *)"abc", 3u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 1u,
                                (const uint8_t *)"defgh", 5u), VTY_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_chunk.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_chunk.tmp.vty",
                                   "chunk-pw", 8, 0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, rotate_cancel_cb, &calls),
             VERTHYS_ERR_POLICY);
    CHECK(calls >= 1);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4RotateAbort(h), VERTHYS_OK);
    CHECK(fopen("v4_rotate_chunk.tmp.vty", "rb") == NULL);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    CHECK_EQ(vty_repo_chunk_get(ctx->v4, file_uuid, 0u, &pt, &pt_len), VTY_OK);
    CHECK(pt_len == 3u && memcmp(pt, "abc", 3) == 0);
    if (pt != NULL) { vty_secure_zero(pt, pt_len); vty_free(pt, pt_len); }

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_chunk.vty", "v4_rotate_chunk.tmp.vty");
    return 0;
}

/* Begin / UnlockModule / AttachKeyfile 的口令复核必须服从统一熔断。 */
TEST(v4_rotate_password_attempts_follow_lockout)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    uint64_t base;
    uint32_t before, after;

    remove("v4_rotate_lock.state");
    vty_lockout_set_enabled(1);
    if (vty_device_root_init() != VTY_OK ||
        vty_lockout_set_path("v4_rotate_lock.state") != VTY_OK ||
        vty_lockout_init() != VTY_OK) {
        printf("  [SKIP] 设备根/熔断状态不可用\n");
        vty_lockout_set_enabled(0);
        return 0;
    }
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    base = (uint64_t)time(NULL);
    CHECK_EQ(vty_lockout_set_test_clock(base), VTY_OK);

    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_lock.vty", "v4_rotate_lock.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_lock.vty", "lock-pw", 7,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_lock.vty", code),
             VERTHYS_OK);

    before = vty_lockout_failures();
    for (uint32_t i = 0; i < 5u; i++) {
        CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_lock.tmp.vty", "bad-pw",
                                       6, 0u, &info), VERTHYS_ERR_AUTH);
    }
    after = vty_lockout_failures();
    CHECK(after >= before + 5u);

    /* 达到阈值后进入退避窗口：窗口内即使口令正确也必须被拒绝。 */
    CHECK_EQ(vty_lockout_set_test_clock(base + 1u), VTY_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_lock.tmp.vty", "lock-pw", 7,
                                   0u, &info), VERTHYS_ERR_RATE);
    CHECK_EQ(vty_lockout_set_test_clock(base + 40u), VTY_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_lock.tmp.vty", "lock-pw", 7,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(vty_lockout_failures(), 0u);
    CHECK_EQ(Verthys_V4RotateAbort(h), VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    vty_lockout_set_test_clock(0);
    vty_lockout_set_enabled(0);
    remove("v4_rotate_lock.state");
    rotate_cleanup_files("v4_rotate_lock.vty", "v4_rotate_lock.tmp.vty");
    return 0;
}

/* fileverthys 模块已删除（键空间只剩墓碑）时，轮换仍必须可用。 */
TEST(v4_rotate_with_deleted_file_module)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VtyVault *v;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    VerthysRecord got;
    uint64_t id = 0;
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t i;

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_delfile.vty", "v4_rotate_delfile.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(&rec, 0, sizeof(rec));
    memset(&got, 0, sizeof(got));
    memset(file_uuid, 0, sizeof(file_uuid));
    memset(pt_hash, 0, sizeof(pt_hash));
    for (i = 0; i < sizeof(file_uuid); i++) file_uuid[i] = (uint8_t)(i + 1u);
    for (i = 0; i < sizeof(pt_hash); i++) pt_hash[i] = (uint8_t)(0xC0u + i);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_delfile.vty", "df-pw", 5,
                              code, sizeof(code)), VERTHYS_OK);
    rec.type = VERTHYS_RECORD_PHOTO;
    rec.name = "keep";
    rec.name_len = 4;
    rec.data = data;
    rec.data_len = sizeof(data);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id), VERTHYS_OK);

    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_FILEVERTHYS,
                                    "file-pw", 7, NULL), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    v = ctx->v4;
    CHECK_EQ(vty_repo_file_put(v, file_uuid, pt_hash, 1u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 0u,
                                (const uint8_t *)"xyz", 3u), VTY_OK);

    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_FILEVERTHYS,
                                    "df-pw", 5, "DELETE"), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_delfile.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_delfile.tmp.vty",
                                   "df-pw", 5, 0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);
    CHECK(fopen("v4_rotate_delfile.tmp.vty", "rb") == NULL);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, "v4_rotate_delfile.vty", "df-pw", 5),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &got), VERTHYS_OK);
    CHECK(got.data_len == sizeof(data));
    CHECK(memcmp(got.data, data, sizeof(data)) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_delfile.vty",
                         "v4_rotate_delfile.tmp.vty");
    return 0;
}

/* 删除→重建→再删除：合法墓碑不得让 rekey/purge 误判为损坏。 */
TEST(v4_module_recreate_and_delete_tolerates_tombstones)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VtyVault *v;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    size_t i;

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_mod_recreate.vty", "v4_mod_recreate.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(file_uuid, 0, sizeof(file_uuid));
    memset(pt_hash, 0, sizeof(pt_hash));
    for (i = 0; i < sizeof(file_uuid); i++) file_uuid[i] = (uint8_t)(i + 1u);
    for (i = 0; i < sizeof(pt_hash); i++) pt_hash[i] = (uint8_t)(0xD0u + i);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_mod_recreate.vty", "mr-pw", 5,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_FILEVERTHYS,
                                    "file1-pw", 8, NULL), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    v = ctx->v4;
    CHECK_EQ(vty_repo_file_put(v, file_uuid, pt_hash, 1u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 0u,
                                (const uint8_t *)"abc", 3u), VTY_OK);
    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_FILEVERTHYS,
                                    "mr-pw", 5, "DELETE"), VERTHYS_OK);

    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_FILEVERTHYS,
                                    "file2-pw", 8, NULL), VERTHYS_OK);
    for (i = 0; i < sizeof(file_uuid); i++) file_uuid[i] = (uint8_t)(i + 0x21u);
    CHECK_EQ(vty_repo_file_put(ctx->v4, file_uuid, pt_hash, 1u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(ctx->v4, file_uuid, 0u,
                                (const uint8_t *)"def", 3u), VTY_OK);
    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_FILEVERTHYS,
                                    "mr-pw", 5, "DELETE"), VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_mod_recreate.vty", "v4_mod_recreate.tmp.vty");
    return 0;
}

/* 轮换不得复用源库已分配过的记录 ID（含已删除高位）。 */
TEST(v4_rotate_preserves_id_allocator_watermark)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysRotateInfo info;
    VerthysRecord rec;
    uint64_t id1 = 0, id2 = 0, id3 = 0, new_id = 0;
    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(0);
    rotate_cleanup_files("v4_rotate_id.vty", "v4_rotate_id.tmp.vty");
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));
    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_RECORD_PHOTO;
    rec.name = "r";
    rec.name_len = 1;
    rec.data = data;
    rec.data_len = sizeof(data);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "v4_rotate_id.vty", "id-pw", 5,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id2), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &id3), VERTHYS_OK);
    CHECK(id3 > id2 && id2 > id1);
    CHECK_EQ(Verthys_DeleteRecord(h, id3), VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, "v4_rotate_id.vty", code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateBegin(h, "v4_rotate_id.tmp.vty",
                                   "id-pw", 5, 0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->v4 != NULL);
    CHECK_EQ(Verthys_AddRecord(h, &rec, &new_id), VERTHYS_OK);
    CHECK(new_id != id3);
    CHECK(new_id >= id3 + 1u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    rotate_cleanup_files("v4_rotate_id.vty", "v4_rotate_id.tmp.vty");
    return 0;
}
