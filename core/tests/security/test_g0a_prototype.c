/*
 * test_g0a_prototype.c — G0-A 生产化原型验收（仅 VERTHYS_G0A_PROTOTYPE 构建）
 *
 * 覆盖安全评审要求：
 *   - 预置快路径真的使用预置键，且显著快于同步建键
 *   - 无预置键时等待后台或同步回退，提交不跳过锚点
 *   - 删除失败 → 撤销旧指纹；删除与撤销都失败 → 失败关闭
 *   - 已验证条目缓存不绕过状态 MAC，也不掩盖 TPM 键被删除
 *   - 新库首次提交前不得存在预置键
 *   - shutdown 后后台线程停止，且可重新启动
 *   - 多库并发提交
 *   - 真实容器 save 路径的端到端对比
 *
 * 需要 Platform Crypto Provider；环境不具备时打印 SKIP。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_util.h"
#include "vty_rollback.h"
#include "vty_tpm_witness.h"
#include "vty_witness_pool.h"
#include "vty_secure_state.h"
#include "vty_keymanager.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define G0A_FILE_MAX 4096u
#define G0A_VAULT_MAX (VTY_DATA_OFFSET + 65536u)

static int g0a_read_file(const char *path, uint8_t *buf, size_t cap,
                         size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *len = n;
    return 0;
}

static int g0a_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

static int g0a_wid(const uint8_t uuid[VTY_UUID_BYTES],
                   uint8_t wid[VTY_UUID_BYTES])
{
    return vty_secure_state_identity_rollback(uuid, wid);
}

/* 清理真实 TPM 中的两套见证（派生域 + 原始域），可跨轮次复用固定 uuid。 */
static int g0a_clean_witness(const uint8_t uuid[VTY_UUID_BYTES])
{
    uint8_t derived[VTY_UUID_BYTES];
    int rc1 = VTY_OK;
    int rc2;

    if (g0a_wid(uuid, derived) == VTY_OK) {
        rc1 = vty_tpm_witness_delete_all(derived);
    }
    rc2 = vty_tpm_witness_delete_all(uuid);
    return (rc1 == VTY_OK && rc2 == VTY_OK) ? VTY_OK : VTY_E_TPM;
}

static int g0a_enable(const char *state_path)
{
    vty_witness_pool_shutdown();
    vty_tpm_witness_set_delete_fail_for_test(0);
    vty_tpm_witness_set_create_fail_for_test(0);
    remove(state_path);
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path_for_test(state_path), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);
    vty_witness_pool_test_reset_stats();
    return 0;
}

static void g0a_finish(const uint8_t uuid[VTY_UUID_BYTES],
                       const char *state_path)
{
    vty_tpm_witness_set_delete_fail_for_test(0);
    vty_tpm_witness_set_create_fail_for_test(0);
    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove(state_path);
    (void)g0a_clean_witness(uuid);
}

static uint64_t g0a_now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

TEST(g0a_commit_fast_path_uses_preset)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    unsigned hits = 0;
    unsigned fallbacks = 0;
    unsigned waits = 0;
    uint64_t sync_ms;
    uint64_t fast_ms;
    uint64_t t;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x91, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_fast.state"), 0);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);

    t = g0a_now_ms();
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    sync_ms = g0a_now_ms() - t;

    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));
    t = g0a_now_ms();
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    fast_ms = g0a_now_ms() - t;

    vty_witness_pool_test_stats(&hits, &fallbacks, &waits);
    printf("  g0a fast: sync=%llums fast=%llums hits=%u fallbacks=%u waits=%u\n",
           (unsigned long long)sync_ms, (unsigned long long)fast_ms,
           hits, fallbacks, waits);

    CHECK(hits >= 1);
    CHECK_EQ(fallbacks, 0);
    CHECK(sync_ms >= 200);
    CHECK(fast_ms <= 250);

    /* 快路径提交后旧状态必须不可用，当前状态可校验。 */
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);

    g0a_finish(uuid, "g0a_fast.state");
    return 0;
}

TEST(g0a_commit_waits_for_background_creation)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t ms;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x92, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_wait.state"), 0);

    /* 第一次提交会立即调度后台建键；第二次不等就绪，验证
     * “释放状态锁 → 等待 → 重新加载”的路径不会失败或跳过锚点。 */
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    ms = g0a_now_ms();
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    ms = g0a_now_ms() - ms;
    printf("  g0a wait: second=%llums\n", (unsigned long long)ms);
    CHECK(ms < 3000);

    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);

    g0a_finish(uuid, "g0a_wait.state");
    return 0;
}

TEST(g0a_delete_failure_revokes_old_key)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t s1[G0A_FILE_MAX];
    uint8_t s2[G0A_FILE_MAX];
    size_t s1_len = 0;
    size_t s2_len = 0;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x93, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_revoke.state"), 0);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);

    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));
    CHECK_EQ(g0a_read_file("g0a_revoke.state", s1, sizeof(s1), &s1_len), 0);

    /* 下一次删除失败一次：提交必须走撤销（OVERWRITE 旧槽），
     * 旧指纹立即失效，提交本身仍成功。 */
    vty_tpm_witness_set_delete_fail_for_test(1);
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(g0a_read_file("g0a_revoke.state", s2, sizeof(s2), &s2_len), 0);

    /* 回放第一版状态：旧键已被撤销，指纹不再匹配。 */
    CHECK_EQ(g0a_write_file("g0a_revoke.state", s1, s1_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);

    CHECK_EQ(g0a_write_file("g0a_revoke.state", s2, s2_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    g0a_finish(uuid, "g0a_revoke.state");
    return 0;
}

TEST(g0a_delete_and_revoke_failure_fails_closed)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x94, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_dirty.state"), 0);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);

    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));

    /* 删除与撤销都失败：不得返回成功，且后续提交 fail-closed。 */
    vty_tpm_witness_set_delete_fail_for_test(1);
    vty_tpm_witness_set_create_fail_for_test(1);
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_E_TPM);
    CHECK_EQ(vty_rollback_commit(uuid, 3), VTY_E_ROLLBACK);

    /* shutdown 清除脏标记；恢复流程可重新建立锚点。 */
    vty_rollback_shutdown();
    CHECK_EQ(vty_rollback_reset_anchor(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_OK);

    g0a_finish(uuid, "g0a_dirty.state");
    return 0;
}

TEST(g0a_cached_verify_rejects_state_replay)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t s1[G0A_FILE_MAX];
    uint8_t s2[G0A_FILE_MAX];
    size_t s1_len = 0;
    size_t s2_len = 0;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x95, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_replay.state"), 0);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);

    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));
    CHECK_EQ(g0a_read_file("g0a_replay.state", s1, sizeof(s1), &s1_len), 0);

    /* 第二次提交走预置快路径，缓存被更新为 gen2。 */
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(g0a_read_file("g0a_replay.state", s2, sizeof(s2), &s2_len), 0);

    /* 回放 gen1：缓存字段不匹配 → 重新 TPM 校验 → 旧键已删 → 拒绝。 */
    CHECK_EQ(g0a_write_file("g0a_replay.state", s1, s1_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);

    /* 恢复 gen2：缓存命中仍要求键存在，校验通过。 */
    CHECK_EQ(g0a_write_file("g0a_replay.state", s2, s2_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    g0a_finish(uuid, "g0a_replay.state");
    return 0;
}

TEST(g0a_new_vault_has_no_preset_before_first_commit)
{
    uint8_t warm[VTY_UUID_BYTES];
    uint8_t warm_wid[VTY_UUID_BYTES];
    uint8_t fresh[VTY_UUID_BYTES];
    uint8_t fresh_wid[VTY_UUID_BYTES];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(warm, 0x96, sizeof(warm));
    memset(fresh, 0x97, sizeof(fresh));
    CHECK_EQ(g0a_clean_witness(warm), VTY_OK);
    CHECK_EQ(g0a_clean_witness(fresh), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_new.state"), 0);
    CHECK_EQ(g0a_wid(warm, warm_wid), VTY_OK);

    /* 先让池为另一个库工作，证明池处于运行状态。 */
    CHECK_EQ(vty_rollback_commit(warm, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(warm_wid, 5000));

    CHECK_EQ(g0a_wid(fresh, fresh_wid), VTY_OK);
    /* F2：首次提交前该库不允许存在任何见证键。 */
    CHECK_EQ(vty_tpm_witness_any(fresh_wid), 0);
    CHECK_EQ(vty_rollback_commit(fresh, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(fresh, 1), VTY_OK);

    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove("g0a_new.state");
    CHECK_EQ(g0a_clean_witness(warm), VTY_OK);
    CHECK_EQ(g0a_clean_witness(fresh), VTY_OK);
    return 0;
}

TEST(g0a_cache_never_bypasses_state_mac)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t state[G0A_FILE_MAX];
    size_t state_len = 0;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x98, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_mac.state"), 0);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);

    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    /* 缓存已持有 gen2 条目；篡改状态字节后 MAC 必须先行失败。 */
    CHECK_EQ(g0a_read_file("g0a_mac.state", state, sizeof(state), &state_len), 0);
    CHECK(state_len > 32);
    state[16] ^= 0x01u;
    CHECK_EQ(g0a_write_file("g0a_mac.state", state, state_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_E_ROLLBACK);

    g0a_finish(uuid, "g0a_mac.state");
    return 0;
}

TEST(g0a_shutdown_stops_and_restarts_pool)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint64_t ms;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0x99, sizeof(uuid));
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    CHECK_EQ(g0a_enable("g0a_shutdown.state"), 0);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);

    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));

    /* shutdown 必须 join；之后提交仍可用（同步回退并重启池）。 */
    vty_rollback_shutdown();
    ms = g0a_now_ms();
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    ms = g0a_now_ms() - ms;
    printf("  g0a shutdown: post-shutdown commit=%llums\n",
           (unsigned long long)ms);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    vty_rollback_shutdown();
    g0a_finish(uuid, "g0a_shutdown.state");
    return 0;
}

typedef struct {
    uint8_t uuid[VTY_UUID_BYTES];
    int rc;
} g0a_thread_arg;

static DWORD WINAPI g0a_thread_main(LPVOID param)
{
    g0a_thread_arg *arg = (g0a_thread_arg *)param;

    arg->rc = 0;
    if (vty_rollback_commit(arg->uuid, 1) != VTY_OK) arg->rc = 1;
    if (arg->rc == 0 && vty_rollback_commit(arg->uuid, 2) != VTY_OK) arg->rc = 2;
    if (arg->rc == 0 && vty_rollback_check(arg->uuid, 2) != VTY_OK) arg->rc = 3;
    return 0;
}

TEST(g0a_concurrent_vaults_commit)
{
    g0a_thread_arg args[3];
    HANDLE threads[3];
    int i;
    int rc;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(args, 0, sizeof(args));
    for (i = 0; i < 3; i++) {
        memset(args[i].uuid, 0xA0 + i, sizeof(args[i].uuid));
        CHECK_EQ(g0a_clean_witness(args[i].uuid), VTY_OK);
    }
    CHECK_EQ(g0a_enable("g0a_conc.state"), 0);

    memset(threads, 0, sizeof(threads));
    for (i = 0; i < 3; i++) {
        threads[i] = CreateThread(NULL, 0, g0a_thread_main, &args[i], 0, NULL);
        CHECK(threads[i] != NULL);
    }
    (void)WaitForMultipleObjects(3, threads, TRUE, 30000);
    for (i = 0; i < 3; i++) {
        CloseHandle(threads[i]);
        CHECK_EQ(args[i].rc, 0);
    }
    for (i = 0; i < 3; i++) {
        CHECK_EQ(vty_rollback_check(args[i].uuid, 2), VTY_OK);
    }

    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove("g0a_conc.state");
    for (i = 0; i < 3; i++) {
        CHECK_EQ(g0a_clean_witness(args[i].uuid), VTY_OK);
    }
    return 0;
}

TEST(g0a_vault_save_fast_path)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint64_t create_ms;
    uint64_t save1_ms;
    uint64_t save2_ms;
    uint64_t t;
    int rc;

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(uuid, 0, sizeof(uuid));
    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove("g0a_v.vty");
    remove("g0a_v.state");
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path_for_test("g0a_v.state"), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);

    t = g0a_now_ms();
    rc = vty_vault_create("g0a_v.vty", "g0a-pass", &v, code, sizeof(code));
    create_ms = g0a_now_ms() - t;
    CHECK_EQ(rc, VTY_OK);
    CHECK(v != NULL);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(g0a_wid(uuid, wid), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));

    t = g0a_now_ms();
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    save1_ms = g0a_now_ms() - t;

    t = g0a_now_ms();
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    save2_ms = g0a_now_ms() - t;

    printf("  g0a vault: create=%llums save1=%llums save2=%llums\n",
           (unsigned long long)create_ms, (unsigned long long)save1_ms,
           (unsigned long long)save2_ms);
    CHECK(create_ms >= 200);
    CHECK(save1_ms <= 300);

    vty_vault_free(v);
    v = NULL;
    CHECK_EQ(vty_vault_open("g0a_v.vty", "g0a-pass", &v), VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove("g0a_v.vty");
    remove("g0a_v.state");
    CHECK_EQ(g0a_clean_witness(uuid), VTY_OK);
    return 0;
}
