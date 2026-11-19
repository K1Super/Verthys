/*
 * test_g0a_crash.c — G0-A 崩溃注入验收（仅 VERTHYS_G0A_PROTOTYPE 构建）
 *
 * 覆盖 G0-A-DESIGN §6 崩溃一致性矩阵中的关键窗口：
 *   - 新键已建、状态未写（同步路径与预置路径）
 *   - 状态已写、旧键未退役
 *   - 旧键已退役、未补池
 *   - 预置键已就绪、提交尚未取用
 *   - 持久化键已创建、尚未 Finalize（半完成键）
 *
 * 子进程 vty_g0a_crash.exe 在指定阶段 TerminateProcess；父进程随后验证：
 * 当前状态仍可校验、旧状态回放被拒绝、残留未引用键不破坏恢复。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_rollback.h"
#include "vty_tpm_witness.h"
#include "vty_witness_pool.h"
#include "vty_secure_state.h"
#include "vty_util.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define G0A_CRASH_STATE_MAX 4096u
#define G0A_CRASH_EXIT(point) ((DWORD)(0xC0DE0000u | (unsigned)(point)))

static int g0a_crash_read(const char *path, uint8_t *buf, size_t cap,
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

static int g0a_crash_write(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

static int g0a_crash_wid(const uint8_t uuid[VTY_UUID_BYTES],
                         uint8_t wid[VTY_UUID_BYTES])
{
    return vty_secure_state_identity_rollback(uuid, wid);
}

static int g0a_crash_clean_witness(const uint8_t uuid[VTY_UUID_BYTES])
{
    uint8_t derived[VTY_UUID_BYTES];
    int rc1 = VTY_OK;
    int rc2;

    if (g0a_crash_wid(uuid, derived) == VTY_OK) {
        rc1 = vty_tpm_witness_delete_all(derived);
    }
    rc2 = vty_tpm_witness_delete_all(uuid);
    return (rc1 == VTY_OK && rc2 == VTY_OK) ? VTY_OK : VTY_E_TPM;
}

static void g0a_crash_uuid_hex(const uint8_t uuid[VTY_UUID_BYTES],
                               char out[VTY_UUID_BYTES * 2u + 1u])
{
    static const char digits[] = "0123456789abcdef";
    int i;

    for (i = 0; i < (int)VTY_UUID_BYTES; i++) {
        out[i * 2] = digits[(uuid[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = digits[uuid[i] & 0x0fu];
    }
    out[VTY_UUID_BYTES * 2u] = '\0';
}

/* 子进程工具与 verthys_tests.exe 位于同一目录。 */
static int g0a_crash_tool_path(char *out, size_t cap)
{
    char self[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, self, sizeof(self));
    char *slash;

    if (n == 0 || n >= sizeof(self)) return 1;
    slash = strrchr(self, '\\');
    if (slash == NULL) return 1;
    *(slash + 1) = '\0';
    if (sprintf_s(out, cap, "%svty_g0a_crash.exe", self) < 0) return 1;
    return 0;
}

static int g0a_crash_spawn(const char *tool, const char *state,
                           const uint8_t uuid[VTY_UUID_BYTES],
                           unsigned generation, int crash_point, int preset,
                           DWORD *exit_code)
{
    char uuid_hex[VTY_UUID_BYTES * 2u + 1u];
    char cmd[1024];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD wait_rc;

    g0a_crash_uuid_hex(uuid, uuid_hex);
    if (sprintf_s(cmd, sizeof(cmd), "\"%s\" \"%s\" %s %u %d %d",
                  tool, state, uuid_hex, generation, crash_point,
                  preset) < 0) {
        return 1;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        return 1;
    }
    wait_rc = WaitForSingleObject(pi.hProcess, 60000);
    if (wait_rc != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, exit_code)) {
        *exit_code = 0xFFFFFFFFu;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (wait_rc == WAIT_OBJECT_0) ? 0 : 1;
}

static int g0a_crash_enable(const char *state_path,
                            const uint8_t uuid[VTY_UUID_BYTES])
{
    vty_witness_pool_shutdown();
    remove(state_path);
    CHECK_EQ(g0a_crash_clean_witness(uuid), VTY_OK);
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path_for_test(state_path), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);
    return 0;
}

static void g0a_crash_finish(const uint8_t uuid[VTY_UUID_BYTES],
                             const char *state_path)
{
    vty_rollback_set_enabled(0);
    vty_rollback_shutdown();
    remove(state_path);
    (void)g0a_crash_clean_witness(uuid);
}

/* 建立 gen2 基线：state=gen2/slot1，并输出该状态快照。 */
static int g0a_crash_setup(const char *state_path,
                           const uint8_t uuid[VTY_UUID_BYTES],
                           uint8_t wid[VTY_UUID_BYTES],
                           uint8_t *s2, size_t cap, size_t *s2_len)
{
    CHECK_EQ(g0a_crash_enable(state_path, uuid), 0);
    CHECK_EQ(g0a_crash_wid(uuid, wid), VTY_OK);
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK(vty_witness_pool_test_wait_ready(wid, 5000));
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(g0a_crash_read(state_path, s2, cap, s2_len), 0);
    CHECK(*s2_len > 0);
    /* 子进程运行前停止父进程后台线程，避免双进程同时建键。 */
    vty_rollback_shutdown();
    return 0;
}

/* 崩溃在“新键已存在、状态未写”：当前状态必须仍可用。 */
static int g0a_crash_case_before_store(unsigned char seed, int crash_point,
                                       int preset, const char *state_path)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t s2[G0A_CRASH_STATE_MAX];
    size_t s2_len = 0;
    char tool[MAX_PATH];
    DWORD code = 0;

    memset(uuid, seed, sizeof(uuid));
    CHECK_EQ(g0a_crash_tool_path(tool, sizeof(tool)), 0);
    CHECK_EQ(g0a_crash_setup(state_path, uuid, wid, s2, sizeof(s2),
                             &s2_len), 0);
    CHECK_EQ(g0a_crash_spawn(tool, state_path, uuid, 3u, crash_point, preset,
                             &code), 0);
    CHECK_EQ(code, G0A_CRASH_EXIT(crash_point));

    /* 重启恢复：旧状态（gen2）仍是唯一有效锚点。 */
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);
    /* 恢复后的当前状态未被残留未引用键影响。 */
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    g0a_crash_finish(uuid, state_path);
    return 0;
}

/* 崩溃在“状态已写、旧键未退役”或“旧键已退役”：恢复后旧状态必须不可用。 */
static int g0a_crash_case_after_store(unsigned char seed, int crash_point,
                                      int preset, const char *state_path)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t s2[G0A_CRASH_STATE_MAX];
    size_t s2_len = 0;
    char tool[MAX_PATH];
    DWORD code = 0;

    memset(uuid, seed, sizeof(uuid));
    CHECK_EQ(g0a_crash_tool_path(tool, sizeof(tool)), 0);
    CHECK_EQ(g0a_crash_setup(state_path, uuid, wid, s2, sizeof(s2),
                             &s2_len), 0);
    CHECK_EQ(g0a_crash_spawn(tool, state_path, uuid, 3u, crash_point, preset,
                             &code), 0);
    CHECK_EQ(code, G0A_CRASH_EXIT(crash_point));

    /* 恢复：新状态可校验，启动清理使旧槽密钥失效。 */
    CHECK_EQ(vty_rollback_check(uuid, 3), VTY_OK);
    CHECK_EQ(g0a_crash_write(state_path, s2, s2_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_E_ROLLBACK);

    g0a_crash_finish(uuid, state_path);
    return 0;
}

/* 半完成键：现有状态仍有效，下一次提交必须能覆盖/清理残留键。 */
static int g0a_crash_case_halfkey_existing(unsigned char seed,
                                           const char *state_path)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t s2[G0A_CRASH_STATE_MAX];
    size_t s2_len = 0;
    char tool[MAX_PATH];
    DWORD code = 0;

    memset(uuid, seed, sizeof(uuid));
    CHECK_EQ(g0a_crash_tool_path(tool, sizeof(tool)), 0);
    CHECK_EQ(g0a_crash_setup(state_path, uuid, wid, s2, sizeof(s2),
                             &s2_len), 0);
    CHECK_EQ(g0a_crash_spawn(tool, state_path, uuid, 3u, 1000, 0, &code), 0);
    CHECK_EQ(code, 0xC0DE1001u);

    /* 残留键不可导出，不构成有效见证：当前状态仍可校验。 */
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);
    /* 下一次提交必须成功，不能因半完成键永久锁死。 */
    CHECK_EQ(vty_rollback_commit(uuid, 3), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 3), VTY_OK);

    /* 新状态生效后，旧状态回放仍必须被拒绝。 */
    CHECK_EQ(g0a_crash_write(state_path, s2, s2_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_E_ROLLBACK);

    g0a_crash_finish(uuid, state_path);
    return 0;
}

/* 首次提交半完成键：状态缺失且无有效见证，允许重建。 */
static int g0a_crash_case_halfkey_first(unsigned char seed,
                                        const char *state_path)
{
    uint8_t uuid[VTY_UUID_BYTES];
    char tool[MAX_PATH];
    DWORD code = 0;

    memset(uuid, seed, sizeof(uuid));
    CHECK_EQ(g0a_crash_tool_path(tool, sizeof(tool)), 0);
    CHECK_EQ(g0a_crash_enable(state_path, uuid), 0);
    vty_rollback_shutdown();
    CHECK_EQ(g0a_crash_spawn(tool, state_path, uuid, 1u, 1000, 0, &code), 0);
    CHECK_EQ(code, 0xC0DE1001u);

    /* 半完成键不是有效见证：gen1 首次初始化仍可继续。 */
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_OK);

    g0a_crash_finish(uuid, state_path);
    return 0;
}

TEST(g0a_crash_halfkey_existing_state)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_halfkey_existing(0xC1, "g0a_halfkey_s1.state");
}

TEST(g0a_crash_halfkey_first_commit)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_halfkey_first(0xC2, "g0a_halfkey_s2.state");
}

TEST(g0a_crash_sync_after_new_key)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_before_store(0xB1, VTY_RB_CRASH_AFTER_NEW_KEY, 0,
                                       "g0a_crash_s1.state");
}

TEST(g0a_crash_sync_after_store)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_after_store(0xB2, VTY_RB_CRASH_AFTER_STORE, 0,
                                      "g0a_crash_s2.state");
}

TEST(g0a_crash_sync_after_retire)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_after_store(0xB3, VTY_RB_CRASH_AFTER_RETIRE, 0,
                                      "g0a_crash_s3.state");
}

TEST(g0a_crash_preset_before_take)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_before_store(0xB4, VTY_RB_CRASH_COMMIT_ENTER, 1,
                                       "g0a_crash_p1.state");
}

TEST(g0a_crash_preset_after_take)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_before_store(0xB5, VTY_RB_CRASH_AFTER_NEW_KEY, 1,
                                       "g0a_crash_p2.state");
}

TEST(g0a_crash_preset_after_store)
{
    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    return g0a_crash_case_after_store(0xB6, VTY_RB_CRASH_AFTER_STORE, 1,
                                      "g0a_crash_p3.state");
}
