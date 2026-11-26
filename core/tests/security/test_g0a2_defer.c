/*
 * test_g0a2_defer.c — 批量导入锚点推迟验收（测试钩子构建）
 *
 * 覆盖安全评审前置条件：
 *   - Begin 先提交当前锚点，会话内保存不推进锚点
 *   - 硬上限（32 代 / 30s）由 C 层强制
 *   - 会话中拒绝删除/导入/改密/PCR/keyfile/模块/轮换
 *   - Flush 提交并保留会话；Commit 后回放窗口关闭
 *   - 提交失败锁定会话，重新解锁补推进锚点
 *   - 崩溃注入：导入中、上限提交中、Commit 中
 *
 * 依赖真实 PCP 的用例在不可用时打印 SKIP；纯状态机用例不需要 TPM。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_keymanager.h"
#include "vty_rollback.h"
#include "vty_secure_state.h"
#include "vty_tpm_witness.h"
#include "vty_types.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define G0A2_PW "g0a2-pw"

static int g0a2_new_vault(VerthysHandle *out, const char *path,
                          char *code, size_t cap)
{
    VerthysHandle h = NULL;

    *out = NULL;
    remove(path);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, path, G0A2_PW, strlen(G0A2_PW),
                              code, cap), VERTHYS_OK);
    *out = h;
    return 0;
}

static void g0a2_close(VerthysHandle h, const char *path)
{
    if (h != NULL) {
        (void)Verthys_Lock(h);
        (void)Verthys_Deinit(h);
    }
    remove(path);
}

static VtyVault *g0a2_vault(VerthysHandle h)
{
    return ((struct VerthysContext *)h)->vault;
}

static VerthysResult g0a2_add(VerthysHandle h, const char *name,
                              const char *data, uint64_t *id)
{
    VerthysRecord r;

    memset(&r, 0, sizeof(r));
    r.type = VERTHYS_RECORD_PHOTO;
    r.name = name;
    r.name_len = strlen(name);
    r.data = (const uint8_t *)data;
    r.data_len = strlen(data);
    return Verthys_AddRecord(h, &r, id);
}

static int g0a2_wid(const uint8_t uuid[VTY_UUID_BYTES],
                    uint8_t wid[VTY_UUID_BYTES])
{
    return vty_secure_state_identity_rollback(uuid, wid);
}

static void g0a2_clean_witness(const uint8_t uuid[VTY_UUID_BYTES])
{
    uint8_t derived[VTY_UUID_BYTES];

    if (g0a2_wid(uuid, derived) == VTY_OK) {
        (void)vty_tpm_witness_delete_all(derived);
    }
    (void)vty_tpm_witness_delete_all(uuid);
}

static int g0a2_rollback_on(const char *state_path)
{
    vty_tpm_witness_set_delete_fail_for_test(0);
    vty_tpm_witness_set_create_fail_for_test(0);
    remove(state_path);
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path_for_test(state_path), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);
    return 0;
}

static void g0a2_rollback_off(const uint8_t uuid[VTY_UUID_BYTES],
                              const char *state_path)
{
    vty_tpm_witness_set_delete_fail_for_test(0);
    vty_tpm_witness_set_create_fail_for_test(0);
    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove(state_path);
    g0a2_clean_witness(uuid);
}

TEST(g0a2_api_version_and_unlock_guard)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    const char *path = "g0a2_guard.vty";
    char code[128];

    CHECK_EQ(VERTHYS_API_VERSION, 0x0018u);

    remove(path);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    /* 未解锁：Begin/Commit 均拒绝。 */
    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_ERR_LOCKED);

    /* 非容器格式：白盒构造 UNLOCKED + NONE，验证格式门先于会话。 */
    ctx = (struct VerthysContext *)h;
    ctx->state = VERTHYS_STATE_UNLOCKED;
    ctx->fmt_version = VERTHYS_FMT_NONE;
    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_ERR_FORMAT);
    ctx->state = VERTHYS_STATE_UNINIT;
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    CHECK_EQ(Verthys_BulkImportBegin(NULL), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_BulkImportCommit(NULL), VERTHYS_ERR_INVALID);
    g0a2_close(h, path);
    return 0;
}

TEST(g0a2_begin_commit_idempotent)
{
    VerthysHandle h;
    VtyVault *v;
    const char *path = "g0a2_idem.vty";
    char code[128];

    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);
    CHECK(v != NULL);

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(v->defer_anchor, 1u);
    CHECK_EQ(v->anchor_floor_gen, v->header.generation);
    /* 重复 Begin 幂等，且不重置窗口起点。 */
    {
        uint64_t since = v->anchor_defer_since_ms;
        CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
        CHECK_EQ(v->anchor_defer_since_ms, since);
    }
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    CHECK_EQ(v->defer_anchor, 0u);
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    CHECK_EQ(v->defer_anchor, 0u);

    g0a2_close(h, path);
    return 0;
}

TEST(g0a2_flush_keeps_session)
{
    VerthysHandle h;
    VtyVault *v;
    uint64_t id = 0;
    const char *path = "g0a2_flush.vty";
    char code[128];

    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(g0a2_add(h, "a", "one", &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Flush(h), VERTHYS_OK);
    /* Flush 提交锚点但会话保留，窗口起点重置。 */
    CHECK_EQ(v->defer_anchor, 1u);
    CHECK_EQ(v->anchor_floor_gen, v->header.generation);
    CHECK_EQ(g0a2_add(h, "b", "two", &id), VERTHYS_OK);
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    CHECK_EQ(v->defer_anchor, 0u);

    g0a2_close(h, path);
    return 0;
}

TEST(g0a2_non_import_writes_rejected)
{
    VerthysHandle h;
    VtyVault *v;
    uint64_t id = 0;
    uint64_t ids[1];
    char code[128];
    char out_recovery[128];
    VerthysRotateInfo rot_info;
    const char *path = "g0a2_policy.vty";

    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(g0a2_add(h, "keep", "data", &id), VERTHYS_OK);

    CHECK_EQ(Verthys_DeleteRecord(h, id), VERTHYS_ERR_POLICY);
    ids[0] = id;
    CHECK_EQ(Verthys_DeleteRecords(h, ids, 1), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_Import(h, "g0a2_missing.vfmt", G0A2_PW,
                            strlen(G0A2_PW)), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_ChangePassword(h, G0A2_PW, strlen(G0A2_PW),
                                    G0A2_PW, strlen(G0A2_PW)),
             VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_V4KeyfileEnable(h, G0A2_PW, strlen(G0A2_PW),
                                     "g0a2.key"), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4KeyfileDisable(h, G0A2_PW, strlen(G0A2_PW), ""),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ResealDevice(h, G0A2_PW, strlen(G0A2_PW), NULL),
             VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_V4PcrEnable(h, 1u, code), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4PcrDisable(h, code), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4PcrReseal(h, code), VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_V4ModuleEnable(h, 0u, G0A2_PW, strlen(G0A2_PW), code),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ModuleRotatePassword(h, 0u, G0A2_PW, strlen(G0A2_PW),
                                            G0A2_PW, strlen(G0A2_PW)),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ModuleDisable(h, 0u, G0A2_PW, strlen(G0A2_PW)),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ModuleDelete(h, 0u, G0A2_PW, strlen(G0A2_PW),
                                    "DELETE"), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ModuleBindRecovery(h, 0u, G0A2_PW, strlen(G0A2_PW),
                                          code), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ModuleResealDevice(h, 0u, G0A2_PW, strlen(G0A2_PW)),
             VERTHYS_ERR_POLICY);

    memset(out_recovery, 0x7f, sizeof(out_recovery));
    CHECK_EQ(Verthys_V4RecoveryRotate(h, G0A2_PW, strlen(G0A2_PW), code,
                                      out_recovery, sizeof(out_recovery)),
             VERTHYS_ERR_POLICY);

    memset(&rot_info, 0, sizeof(rot_info));
    CHECK_EQ(Verthys_V4RotateBegin(h, "g0a2_rot.vty", G0A2_PW,
                                   strlen(G0A2_PW), 0, &rot_info),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4RotateAttachKeyfile(h, "g0a2.key", G0A2_PW,
                                           strlen(G0A2_PW)),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4RotateUnlockModule(h, 0u, G0A2_PW, strlen(G0A2_PW),
                                          code), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_ERR_POLICY);

    /* 会话内拒绝不得改变推迟状态；Commit 后删除恢复可用。 */
    CHECK_EQ(v->defer_anchor, 1u);
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    CHECK_EQ(Verthys_DeleteRecord(h, id), VERTHYS_OK);

    g0a2_close(h, path);
    return 0;
}

TEST(g0a2_begin_precommits_and_saves_defer)
{
    VerthysHandle h;
    VtyVault *v;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t id = 0;
    uint64_t gen;
    const char *path = "g0a2_anchor.vty";
    const char *state = "g0a2_anchor.state";
    char code[128];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);
    memcpy(uuid, v->header.vault_uuid, sizeof(uuid));
    gen = v->header.generation;
    CHECK_EQ(gen, 2u);
    CHECK_EQ(v->anchor_floor_gen, gen);

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(g0a2_add(h, "photo", "payload", &id), VERTHYS_OK);
    CHECK_EQ(v->header.generation, gen + 1u);
    CHECK_EQ(v->anchor_floor_gen, gen);
    /* 窗口内旧代副本仍被接受：这正是推迟的设计代价。 */
    CHECK_EQ(vty_rollback_check(uuid, (uint64_t)gen), VTY_OK);

    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    CHECK_EQ(v->anchor_floor_gen, gen + 1u);
    CHECK_EQ(vty_rollback_check(uuid, (uint64_t)gen), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, gen + 1u), VTY_OK);

    g0a2_close(h, path);
    g0a2_rollback_off(uuid, state);
    return 0;
}

TEST(g0a2_generation_limit_forces_commit)
{
    VerthysHandle h;
    VtyVault *v;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t id = 0;
    uint64_t gen;
    unsigned i;
    const char *path = "g0a2_gen.vty";
    const char *state = "g0a2_gen.state";
    char name[32];
    char code[128];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);
    memcpy(uuid, v->header.vault_uuid, sizeof(uuid));
    gen = v->header.generation;

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    for (i = 0; i < VTY_ANCHOR_DEFER_MAX_GENS - 1u; i++) {
        snprintf(name, sizeof(name), "g%u", i);
        CHECK_EQ(g0a2_add(h, name, "x", &id), VERTHYS_OK);
    }
    /* 31 代滞后仍未提交。 */
    CHECK_EQ(v->header.generation, gen + 31u);
    CHECK_EQ(v->anchor_floor_gen, gen);
    CHECK_EQ(vty_rollback_check(uuid, gen), VTY_OK);

    /* 第 32 代未推进保存触发强制提交。 */
    CHECK_EQ(g0a2_add(h, "g-last", "x", &id), VERTHYS_OK);
    CHECK_EQ(v->header.generation, gen + 32u);
    CHECK_EQ(v->anchor_floor_gen, gen + 32u);
    CHECK_EQ(vty_rollback_check(uuid, gen + 31u), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, gen + 32u), VTY_OK);

    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    g0a2_close(h, path);
    g0a2_rollback_off(uuid, state);
    return 0;
}

TEST(g0a2_time_limit_forces_commit)
{
    VerthysHandle h;
    VtyVault *v;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t id = 0;
    uint64_t gen;
    const char *path = "g0a2_time.vty";
    const char *state = "g0a2_time.state";
    char code[128];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);
    memcpy(uuid, v->header.vault_uuid, sizeof(uuid));
    gen = v->header.generation;

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(g0a2_add(h, "t0", "x", &id), VERTHYS_OK);
    /* 白盒把窗口起点回拨到超过 30s：等价于空闲 31s 后的首次保存。 */
    v->anchor_defer_since_ms -= (uint64_t)VTY_ANCHOR_DEFER_MAX_MS + 1000u;
    CHECK_EQ(g0a2_add(h, "t1", "x", &id), VERTHYS_OK);
    CHECK_EQ(v->header.generation, gen + 2u);
    CHECK_EQ(v->anchor_floor_gen, gen + 2u);
    CHECK_EQ(vty_rollback_check(uuid, gen + 1u), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, gen + 2u), VTY_OK);

    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    g0a2_close(h, path);
    g0a2_rollback_off(uuid, state);
    return 0;
}

TEST(g0a2_commit_failure_locks_session)
{
    VerthysHandle h;
    VtyVault *v;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t id = 0;
    const char *path = "g0a2_fail.vty";
    const char *state = "g0a2_fail.state";
    char code[128];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);
    memcpy(uuid, v->header.vault_uuid, sizeof(uuid));

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(g0a2_add(h, "f", "x", &id), VERTHYS_OK);

    /* 删除旧见证与撤销（OVERWRITE 重建）同时失败 → 提交失败 →
     * 会话锁定，不返回成功。计数取大值，覆盖预置键就绪前后的两条路径。 */
    vty_tpm_witness_set_delete_fail_for_test(100);
    vty_tpm_witness_set_create_fail_for_test(100);
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_ERR_TPM);
    CHECK_EQ(v->unlocked, 0);
    CHECK_EQ(v->defer_anchor, 0u);
    CHECK_EQ(g0a2_add(h, "after", "x", &id), VERTHYS_ERR_LOCKED);

    vty_tpm_witness_set_delete_fail_for_test(0);
    vty_tpm_witness_set_create_fail_for_test(0);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    /* 退役失败会把锚点标记为脏（进程内 fail-closed）；shutdown 等价于
     * 进程重启后的全新回滚模块，随后解锁补推进到当前容器代。 */
    vty_rollback_shutdown();
    CHECK_EQ(Verthys_V4Unlock(h, path, G0A2_PW, strlen(G0A2_PW)), VERTHYS_OK);
    v = g0a2_vault(h);
    CHECK(v != NULL);
    CHECK_EQ(vty_rollback_check(uuid, v->header.generation - 1u),
             VTY_E_ROLLBACK);
    CHECK_EQ(g0a2_add(h, "recovered", "x", &id), VERTHYS_OK);

    g0a2_close(h, path);
    g0a2_rollback_off(uuid, state);
    return 0;
}

TEST(g0a2_lock_commits_open_window)
{
    VerthysHandle h;
    VtyVault *v;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t id = 0;
    uint64_t gen;
    const char *path = "g0a2_lock.vty";
    const char *state = "g0a2_lock.state";
    char code[128];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);
    memcpy(uuid, v->header.vault_uuid, sizeof(uuid));
    gen = v->header.generation;

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    CHECK_EQ(g0a2_add(h, "l", "x", &id), VERTHYS_OK);
    CHECK_EQ(vty_rollback_check(uuid, gen), VTY_OK);
    /* Lock 在释放密钥前提交锚点。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(vty_rollback_check(uuid, gen), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, gen + 1u), VTY_OK);

    (void)Verthys_Deinit(h);
    remove(path);
    g0a2_rollback_off(uuid, state);
    return 0;
}

typedef struct {
    VerthysHandle h;
    unsigned base;
    unsigned count;
    int failed;
} G0a2ThreadArg;

static DWORD WINAPI g0a2_writer_thread(LPVOID param)
{
    G0a2ThreadArg *arg = (G0a2ThreadArg *)param;
    unsigned i;
    char name[32];
    uint64_t id = 0;

    for (i = 0; i < arg->count; i++) {
        snprintf(name, sizeof(name), "th%u-%u", arg->base, i);
        if (g0a2_add(arg->h, name, "x", &id) != VERTHYS_OK) {
            arg->failed = 1;
            return 0;
        }
    }
    return 0;
}

TEST(g0a2_concurrent_add_records_with_session)
{
    VerthysHandle h;
    VtyVault *v;
    G0a2ThreadArg args[2];
    HANDLE threads[2];
    uint64_t count = 0;
    const char *path = "g0a2_conc.vty";
    char code[128];
    int i;

    memset(code, 0, sizeof(code));
    CHECK_EQ(g0a2_new_vault(&h, path, code, sizeof(code)), 0);
    v = g0a2_vault(h);

    CHECK_EQ(Verthys_BulkImportBegin(h), VERTHYS_OK);
    memset(args, 0, sizeof(args));
    for (i = 0; i < 2; i++) {
        args[i].h = h;
        args[i].base = (unsigned)i;
        args[i].count = 8u;
        threads[i] = CreateThread(NULL, 0, g0a2_writer_thread, &args[i], 0, NULL);
        CHECK(threads[i] != NULL);
    }
    for (i = 0; i < 2; i++) {
        CHECK_EQ(WaitForSingleObject(threads[i], 60000), WAIT_OBJECT_0);
        CloseHandle(threads[i]);
        CHECK_EQ(args[i].failed, 0);
    }
    CHECK_EQ(Verthys_BulkImportCommit(h), VERTHYS_OK);
    CHECK_EQ(v->defer_anchor, 0u);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 16u);

    g0a2_close(h, path);
    return 0;
}

/* ------------------------------------------------------------------ *
 * 崩溃注入：子进程在真实容器上执行导入会话并 TerminateProcess，
 * 父进程验证锚点窗口与恢复后补推进。
 * ------------------------------------------------------------------ */

static int g0a2_tool_path(char *out, size_t cap)
{
    char self[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, self, sizeof(self));
    char *slash;

    if (n == 0 || n >= sizeof(self)) return 1;
    slash = strrchr(self, '\\');
    if (slash == NULL) return 1;
    *(slash + 1) = '\0';
    if (sprintf_s(out, cap, "%svty_g0a2_crash.exe", self) < 0) return 1;
    return 0;
}

/* 子进程把容器 UUID 写入 <container>.uuid，父进程据此做锚点检查。 */
static int g0a2_crash_spawn(const char *tool, const char *container,
                            const char *state, const char *mode, DWORD *code)
{
    char cmd[1024];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD wait_rc;

    if (sprintf_s(cmd, sizeof(cmd), "\"%s\" \"%s\" \"%s\" %s",
                  tool, container, state, mode) < 0) {
        return 1;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        return 1;
    }
    wait_rc = WaitForSingleObject(pi.hProcess, 120000);
    if (wait_rc != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, code)) {
        *code = 0xFFFFFFFFu;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (wait_rc == WAIT_OBJECT_0) ? 0 : 1;
}

static int g0a2_read_uuid(const char *container,
                          uint8_t uuid[VTY_UUID_BYTES])
{
    char path[MAX_PATH];
    FILE *f;
    char hex[VTY_UUID_BYTES * 2u + 2u];
    int i;

    if (sprintf_s(path, sizeof(path), "%s.uuid", container) < 0) return 1;
    f = fopen(path, "rb");
    if (f == NULL) return 1;
    if (fread(hex, 1, VTY_UUID_BYTES * 2u, f) != VTY_UUID_BYTES * 2u) {
        fclose(f);
        return 1;
    }
    fclose(f);
    hex[VTY_UUID_BYTES * 2u] = '\0';
    for (i = 0; i < (int)VTY_UUID_BYTES; i++) {
        unsigned hi = 0, lo = 0;
        if (sscanf(hex + i * 2, "%1x%1x", &hi, &lo) != 2) return 1;
        uuid[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int g0a2_reopen_and_check(const char *container,
                                 const uint8_t uuid[VTY_UUID_BYTES],
                                 uint64_t expect_old_rejected)
{
    VtyVault *v = NULL;
    uint64_t gen;

    CHECK_EQ(vty_vault_open(container, G0A2_PW, &v), VTY_OK);
    gen = v->header.generation;
    printf("  g0a2 reopen: generation=%llu\n", (unsigned long long)gen);
    vty_vault_free(v);
    /* 打开路径已把锚点推进到当前容器代：旧代副本必须被拒绝。 */
    CHECK_EQ(vty_rollback_check(uuid, expect_old_rejected), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, gen), VTY_OK);
    return 0;
}

TEST(g0a2_crash_during_import_recovers)
{
    uint8_t uuid[VTY_UUID_BYTES];
    char tool[MAX_PATH];
    DWORD code = 0;
    const char *container = "g0a2_crash_import.vty";
    const char *state = "g0a2_crash_import.state";

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    CHECK_EQ(g0a2_tool_path(tool, sizeof(tool)), 0);
    remove(container);
    remove("g0a2_crash_import.vty.uuid");
    CHECK_EQ(g0a2_crash_spawn(tool, container, state, "import", &code), 0);
    CHECK_EQ(code, 0xC0DE0011u);

    CHECK_EQ(g0a2_read_uuid(container, uuid), 0);
    /* 导入中崩溃：容器已到 gen5，锚点仍停在 gen2（窗口未关闭）。 */
    CHECK_EQ(vty_rollback_check(uuid, 2u), VTY_OK);
    CHECK_EQ(g0a2_reopen_and_check(container, uuid, 2u), 0);

    remove(container);
    remove("g0a2_crash_import.vty.uuid");
    g0a2_rollback_off(uuid, state);
    return 0;
}

TEST(g0a2_crash_during_limit_commit_recovers)
{
    uint8_t uuid[VTY_UUID_BYTES];
    char tool[MAX_PATH];
    DWORD code = 0;
    const char *container = "g0a2_crash_limit.vty";
    const char *state = "g0a2_crash_limit.state";

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    CHECK_EQ(g0a2_tool_path(tool, sizeof(tool)), 0);
    remove(container);
    remove("g0a2_crash_limit.vty.uuid");
    CHECK_EQ(g0a2_crash_spawn(tool, container, state, "limit", &code), 0);
    CHECK_EQ(code, 0xC0DE0002u);

    CHECK_EQ(g0a2_read_uuid(container, uuid), 0);
    /* 上限触发的提交在“新键已建、状态未写”处被杀：旧锚点仍有效。 */
    CHECK_EQ(vty_rollback_check(uuid, 2u), VTY_OK);
    CHECK_EQ(g0a2_reopen_and_check(container, uuid, 2u), 0);

    remove(container);
    remove("g0a2_crash_limit.vty.uuid");
    g0a2_rollback_off(uuid, state);
    return 0;
}

TEST(g0a2_crash_during_commit_recovers)
{
    uint8_t uuid[VTY_UUID_BYTES];
    char tool[MAX_PATH];
    DWORD code = 0;
    const char *container = "g0a2_crash_commit.vty";
    const char *state = "g0a2_crash_commit.state";

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    CHECK_EQ(g0a2_rollback_on(state), 0);
    CHECK_EQ(g0a2_tool_path(tool, sizeof(tool)), 0);
    remove(container);
    remove("g0a2_crash_commit.vty.uuid");
    CHECK_EQ(g0a2_crash_spawn(tool, container, state, "commit", &code), 0);
    CHECK_EQ(code, 0xC0DE0003u);

    CHECK_EQ(g0a2_read_uuid(container, uuid), 0);
    /* 状态已写、旧键未退役：新锚点（gen4）有效，旧代（gen3）被拒绝。 */
    CHECK_EQ(vty_rollback_check(uuid, 3u), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, 4u), VTY_OK);
    CHECK_EQ(g0a2_reopen_and_check(container, uuid, 3u), 0);

    remove(container);
    remove("g0a2_crash_commit.vty.uuid");
    g0a2_rollback_off(uuid, state);
    return 0;
}
