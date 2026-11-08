/*
 * test_rollback.c — 库文件版本回退检测验收
 *
 * 覆盖：
 *   - 锚点单调性：低于锚点的版本拒绝，未登记/首次运行放行
 *   - 整体还原旧库文件（保留新库锚点）被拒绝
 *   - 锚点状态文件篡改 → fail-closed
 *   - 恢复码打开旧副本成功并重设锚点（逃生通道）
 *   - 开关关闭时放行（仅测试/受控环境使用）
 *   - 伪造更大版本号但未重签 body → body 认证失败
 *
 * 全部状态文件与库文件写在测试沙箱相对路径，绝不触碰 %LOCALAPPDATA%。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_rollback.h"
#include "vty_format.h"
#include "vty_blake3.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

#include "vty_tpm_witness.h"
#include "vty_secure_state.h"

#define RB_FILE_MAX 4096u
/* 库文件至少含 A/B 两份 64 KiB 元数据；用 4 KiB 缓冲读取会把副本
 * 截断成非法文件，测试必须按真实布局取全量。 */
#define RB_VAULT_MAX (VTY_DATA_OFFSET + 65536u)

static int rb_read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *len = n;
    return 0;
}

static int rb_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

static int rb_clean_witness(const uint8_t raw[VTY_UUID_BYTES])
{
    uint8_t derived[VTY_UUID_BYTES];
    int rc1 = VTY_OK;
    int rc2;

    if (vty_secure_state_identity_rollback(raw, derived) == VTY_OK) {
        rc1 = vty_tpm_witness_delete_all(derived);
    }
    rc2 = vty_tpm_witness_delete_all(raw);
    return (rc1 == VTY_OK && rc2 == VTY_OK) ? VTY_OK : VTY_E_TPM;
}

static int rb_enable(const char *state_path)
{
    remove(state_path);
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path_for_test(state_path), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);
    return 0;
}

/* 创建失败必须删除半成品文件，并把真实错误码（这里是锚点认证失败）
 * 原样返回；不得因删除时仍有 store 句柄而改写成 E_IO（worker 会把 IO
 * 统一成 AUTH，上层只能看到误导性的认证失败）。 */
TEST(create_failure_removes_partial_and_keeps_error)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t junk[RB_FILE_MAX];
    const char *vault = "rb_create_fail.vty";
    const char *state = "rb_create_fail.state";

    remove(vault);
    remove(state);
    memset(code, 0, sizeof(code));
    memset(junk, 0xA5, sizeof(junk));
    CHECK_EQ(rb_write_file(state, junk, sizeof(junk)), 0);
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_set_path_for_test(state), VTY_OK);
    CHECK_EQ(vty_rollback_init(), VTY_OK);

    CHECK_EQ(vty_vault_create(vault, "rb-create-pw", &v, code, sizeof(code)),
             VTY_E_ROLLBACK);
    CHECK(v == NULL);
    CHECK(fopen(vault, "rb") == NULL);

    vty_rollback_set_enabled(0);
    remove(state);
    remove(vault);
    return 0;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
TEST(rollback_env_hook_vault_flow)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];

    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_vault_create("rb_env.vty", "env-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_env.vty", "env-pass", &v), VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    remove("rb_env.vty");
    return 0;
}
#endif

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
TEST(rollback_env_hook_isolated)
{
    uint8_t uuid[VTY_UUID_BYTES];

    /* 测试构建的 VERTHYS_TEST_STATE_DIR 由 test_runner 指向沙箱；
     * 不注入路径时也应完全隔离，不应触碰真实 KnownFolder。 */
    memset(uuid, 0x77, sizeof(uuid));
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    vty_rollback_set_enabled(1);
    CHECK_EQ(vty_rollback_init(), VTY_OK);
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);
    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}
#endif

TEST(rollback_module_monotonic_anchor)
{
    uint8_t uuid[VTY_UUID_BYTES];

    memset(uuid, 0x3C, sizeof(uuid));
    /* 固定 uuid 会跨轮次复用：先清掉上一轮遗留的见证密钥 */
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    CHECK_EQ(rb_enable("rb_m.state"), 0);

    /* 首次运行 / 未登记库：0 版本放行（加计数器前的老库） */
    CHECK_EQ(vty_rollback_check(uuid, 0), VTY_OK);
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 0), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, 9), VTY_OK);

    /* 单调：commit 不得把锚点改小 */
    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_E_ROLLBACK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);

    /* 恢复码路径允许回退并重设锚点 */
    CHECK_EQ(vty_rollback_reset_anchor(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 0), VTY_E_ROLLBACK);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}

TEST(rollback_restored_old_copy_rejected)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t old_copy[RB_VAULT_MAX];
    uint8_t uuid[VTY_UUID_BYTES];
    size_t old_len = 0;

    CHECK_EQ(rb_enable("rb_a.state"), 0);
    remove("rb_a.vty");
    remove("rb_old.vty");

    CHECK_EQ(vty_vault_create("rb_a.vty", "rollback-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    /* gen 1 → 2：这一份作为“旧副本”保存 */
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    CHECK_EQ(rb_read_file("rb_a.vty", old_copy, sizeof(old_copy), &old_len), 0);
    CHECK(old_len > 0);
    /* gen 2 → 3：当前库 */
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_a.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    /* 用旧副本整体覆盖：锚点已是 gen 3，必须拒绝 */
    CHECK_EQ(rb_write_file("rb_old.vty", old_copy, old_len), 0);
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_old.vty", "rollback-pass", &v), VTY_E_ROLLBACK);
    CHECK(v == NULL);

    /* 当前库不受影响 */
    CHECK_EQ(vty_vault_open("rb_a.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}

TEST(rollback_tampered_anchor_fails_closed)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t state[RB_FILE_MAX];
    uint8_t uuid[VTY_UUID_BYTES];
    size_t state_len = 0;

    CHECK_EQ(rb_enable("rb_t.state"), 0);
    remove("rb_t.vty");

    CHECK_EQ(vty_vault_create("rb_t.vty", "rollback-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_t.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    /* 改一条目的版本号 → MAC 失配，必须按锁定语义拒绝 */
    CHECK_EQ(rb_read_file("rb_t.state", state, sizeof(state), &state_len), 0);
    CHECK(state_len > 0);
    state[16 + VTY_UUID_BYTES] ^= 0x01u;
    CHECK_EQ(rb_write_file("rb_t.state", state, state_len), 0);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_t.vty", "rollback-pass", &v), VTY_E_ROLLBACK);
    CHECK(v == NULL);

    /* 状态文件删除不再视为首次运行：见证密钥仍在，必须 fail-closed */
    remove("rb_t.state");
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_t.vty", "rollback-pass", &v), VTY_E_ROLLBACK);
    CHECK(v == NULL);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}

TEST(rollback_recovery_resets_anchor)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t old_copy[RB_VAULT_MAX];
    uint8_t uuid[VTY_UUID_BYTES];
    size_t old_len = 0;

    CHECK_EQ(rb_enable("rb_r.state"), 0);
    remove("rb_r.vty");

    CHECK_EQ(vty_vault_create("rb_r.vty", "rollback-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    CHECK_EQ(rb_read_file("rb_r.vty", old_copy, sizeof(old_copy), &old_len), 0);
    CHECK(old_len > 0);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_r.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    /* 还原旧副本：普通打开被拒绝 */
    CHECK_EQ(rb_write_file("rb_r.vty", old_copy, old_len), 0);
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_r.vty", "rollback-pass", &v), VTY_E_ROLLBACK);
    CHECK(v == NULL);

    /* 恢复码是显式逃生通道：允许打开并把锚点重设为旧版本 */
    CHECK_EQ(vty_vault_open_recovery("rb_r.vty", code, &v), VTY_OK);
    vty_vault_free(v);
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_r.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}

TEST(rollback_rotated_copy_rejected)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t old_copy[RB_VAULT_MAX];
    uint8_t uuid[VTY_UUID_BYTES];
    size_t old_len = 0;

    CHECK_EQ(rb_enable("rb_rot.state"), 0);
    remove("rb_rot.vty");
    remove("rb_rot_old.vty");

    CHECK_EQ(vty_vault_create("rb_rot.vty", "old-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(rb_read_file("rb_rot.vty", old_copy, sizeof(old_copy), &old_len), 0);
    CHECK(old_len > 0);
    /* 轮换：epoch 不变（数据代不变），save 使 generation+1；
     * 恢复码是独立凭据，改密不再使其失效。 */
    CHECK_EQ(vty_vault_rotate_password(v, "new-pass"), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_rot.vty", "new-pass", &v), VTY_OK);
    vty_vault_free(v);

    /* 轮换前副本（旧 epoch/旧版本）整体还原也必须被拒绝 */
    CHECK_EQ(rb_write_file("rb_rot_old.vty", old_copy, old_len), 0);
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_rot_old.vty", "old-pass", &v), VTY_E_ROLLBACK);
    CHECK(v == NULL);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}

TEST(rollback_forged_generation_rejected)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t file[RB_VAULT_MAX];
    uint8_t hash[VTY_HASH_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    VtyHeader h;
    size_t file_len = 0;
    int rc;

    CHECK_EQ(rb_enable("rb_f.state"), 0);
    remove("rb_f.vty");
    remove("rb_f_forged.vty");

    CHECK_EQ(vty_vault_create("rb_f.vty", "rollback-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_f.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    CHECK_EQ(rb_read_file("rb_f.vty", file, sizeof(file), &file_len), 0);
    CHECK(file_len >= VTY_DATA_OFFSET);

    /* 把 A/B 两份的版本号都改大并重算无密钥头哈希：头校验会通过，
     * 但 body AAD 仍绑定旧 generation，必然失配。 */
    {
        uint32_t ci;
        for (ci = 0; ci < VTY_META_COPIES; ci++) {
            uint8_t *cp = file + (size_t)ci * VTY_META_COPY_BYTES;
            uint64_t bumped;
            CHECK_EQ(vty_header_parse(cp, VTY_META_COPY_BYTES, &h), VTY_OK);
            bumped = vty_header_generation(&h) + 100u;
            vty_put_u64(cp + VTY_GENERATION_OFFSET, bumped);
            CHECK_EQ(vty_blake3_32(cp, (size_t)h.header_len - VTY_HASH_BYTES,
                                   hash), VTY_OK);
            memcpy(cp + (size_t)h.header_len - VTY_HASH_BYTES, hash,
                   VTY_HASH_BYTES);
        }
    }
    CHECK_EQ(rb_write_file("rb_f_forged.vty", file, file_len), 0);

    v = NULL;
    rc = vty_vault_open("rb_f_forged.vty", "rollback-pass", &v);
    CHECK(rc != VTY_OK);
    CHECK(v == NULL);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    return 0;
}

TEST(rollback_state_replay_rejected)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t s1[RB_FILE_MAX];
    uint8_t s2[RB_FILE_MAX];
    size_t s1_len = 0;
    size_t s2_len = 0;

    memset(uuid, 0x7E, sizeof(uuid));
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    CHECK_EQ(rb_enable("rb_replay.state"), 0);

    CHECK_EQ(vty_rollback_commit(uuid, 1), VTY_OK);
    CHECK_EQ(rb_read_file("rb_replay.state", s1, sizeof(s1), &s1_len), 0);
    CHECK(s1_len > 0);

    CHECK_EQ(vty_rollback_commit(uuid, 2), VTY_OK);
    CHECK_EQ(rb_read_file("rb_replay.state", s2, sizeof(s2), &s2_len), 0);
    CHECK(s2_len > 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    /* 还原上一版状态文件：版本号仍合法，但见证指纹已指向被覆盖的旧键 */
    CHECK_EQ(rb_write_file("rb_replay.state", s1, s1_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 1), VTY_E_ROLLBACK);

    /* 当前状态仍可校验 */
    CHECK_EQ(rb_write_file("rb_replay.state", s2, s2_len), 0);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_OK);

    /* 见证密钥被删除：fail-closed */
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    CHECK_EQ(vty_rollback_check(uuid, 2), VTY_E_ROLLBACK);

    vty_rollback_set_enabled(0);
    return 0;
}

TEST(rollback_missing_state_anchor_fail_closed)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];
    const char *vault = "rb_missing.vty";
    const char *state = "rb_missing.state";

    remove(vault);
    remove(state);
    CHECK_EQ(rb_enable(state), 0);
    CHECK_EQ(vty_vault_create(vault, "rb-missing-pass", &v, code,
                              sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    /* 删除状态与两套见证：容器 generation >= 2 证明锚点已建立，
     * 即使见证也不在，普通打开必须 fail-closed。 */
    remove(state);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    v = NULL;
    CHECK_EQ(vty_vault_open(vault, "rb-missing-pass", &v), VTY_E_ROLLBACK);
    CHECK(v == NULL);

    /* 恢复码是显式逃生通道：允许打开并重设锚点，之后普通打开恢复。 */
    CHECK_EQ(vty_vault_open_recovery(vault, code, &v), VTY_OK);
    vty_vault_free(v);
    v = NULL;
    CHECK_EQ(vty_vault_open(vault, "rb-missing-pass", &v), VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    remove(state);
    remove(vault);
    return 0;
}

TEST(rollback_disabled_allows_old_copy)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t old_copy[RB_VAULT_MAX];
    size_t old_len = 0;

    CHECK_EQ(rb_enable("rb_d.state"), 0);
    remove("rb_d.vty");
    remove("rb_d_old.vty");

    CHECK_EQ(vty_vault_create("rb_d.vty", "rollback-pass", &v, code,
                              sizeof(code)), VTY_OK);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    CHECK_EQ(rb_read_file("rb_d.vty", old_copy, sizeof(old_copy), &old_len), 0);
    CHECK(old_len > 0);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_d.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);

    CHECK_EQ(rb_write_file("rb_d_old.vty", old_copy, old_len), 0);
    vty_rollback_set_enabled(0);
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_d_old.vty", "rollback-pass", &v), VTY_OK);
    vty_vault_free(v);
    return 0;
}

