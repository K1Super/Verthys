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
#include "verthys.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_rollback.h"
#include "vty_format.h"
#include "vty_blake3.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

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

/* 回滚锚点以 PCP 见证绑定容器；无 TPM 的 runner 无法建立见证，
 * 依赖真实见证的用例显式跳过，避免把硬件缺失误报为回退拒绝。 */
static int rb_skip_without_witness(void)
{
    if (vty_tpm_witness_available()) return 0;
    printf("  [SKIP] PCP witness backend unavailable\n");
    return 1;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
    memset(uuid, 0x3C, sizeof(uuid));
    /* 固定 uuid 会跨轮次复用：先清掉上一轮遗留的见证密钥 */
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    CHECK_EQ(rb_enable("rb_m.state"), 0);

    /* 首次运行 / 未登记库：0 版本放行（未记录锚点的库） */
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

    if (rb_skip_without_witness()) return 0;
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

/* ------------------------------------------------------------------ *
 * 生命周期与恢复逃生通道
 * ------------------------------------------------------------------ */

static uint32_t rb_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 从状态文件定位 UUID 对应条目的见证槽；仅测试使用。 */
static int rb_entry_slot(const char *state_path,
                         const uint8_t uuid[VTY_UUID_BYTES], uint8_t *slot)
{
    uint8_t buf[RB_FILE_MAX];
    size_t len = 0;
    uint32_t count;
    uint32_t i;

    if (rb_read_file(state_path, buf, sizeof(buf), &len) != 0) return 1;
    if (len < 16u) return 1;
    count = rb_u32(buf + 8);
    if (count > 64u) return 1;
    for (i = 0; i < count; i++) {
        const uint8_t *e = buf + 16u + (size_t)i * 57u;
        if (memcmp(e, uuid, VTY_UUID_BYTES) == 0) {
            *slot = e[24];
            return 0;
        }
    }
    return 1;
}

static int rb_find_info(const VtyAnchorInfo *info, uint32_t count,
                        const uint8_t uuid[VTY_UUID_BYTES])
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        if (memcmp(info[i].uuid, uuid, VTY_UUID_BYTES) == 0) return (int)i;
    }
    return -1;
}

TEST(rollback_recovery_resets_dead_anchor)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];

    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_dead_recovery.state"), 0);
    remove("rb_dead_recovery.vty");

    CHECK_EQ(vty_vault_create("rb_dead_recovery.vty", "rollback-pass", &v,
                              code, sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    /* 见证被删除：普通打开 fail-closed，恢复码必须仍能重设锚点。 */
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    v = NULL;
    CHECK_EQ(vty_vault_open("rb_dead_recovery.vty", "rollback-pass", &v),
             VTY_E_ROLLBACK);
    CHECK(v == NULL);
    CHECK_EQ(vty_vault_open_recovery("rb_dead_recovery.vty", code, &v),
             VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_dead_recovery.vty", "rollback-pass", &v),
             VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    remove("rb_dead_recovery.state");
    remove("rb_dead_recovery.vty");
    return 0;
}

TEST(rollback_recovery_resets_tampered_anchor)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t derived[VTY_UUID_BYTES];
    uint8_t slot = 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];

    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_tamper_recovery.state"), 0);
    remove("rb_tamper_recovery.vty");

    CHECK_EQ(vty_vault_create("rb_tamper_recovery.vty", "rollback-pass", &v,
                              code, sizeof(code)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    CHECK_EQ(rb_entry_slot("rb_tamper_recovery.state", uuid, &slot), 0);
    CHECK_EQ(vty_secure_state_identity_rollback(uuid, derived), VTY_OK);
    CHECK_EQ(vty_tpm_witness_create(derived, slot, fp), VTY_OK);
    CHECK_EQ(vty_tpm_witness_verify(derived, slot, fp), VTY_OK);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_tamper_recovery.vty", "rollback-pass", &v),
             VTY_E_ROLLBACK);
    CHECK(v == NULL);
    CHECK_EQ(vty_vault_open_recovery("rb_tamper_recovery.vty", code, &v),
             VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("rb_tamper_recovery.vty", "rollback-pass", &v),
             VTY_OK);
    vty_vault_free(v);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    remove("rb_tamper_recovery.state");
    remove("rb_tamper_recovery.vty");
    return 0;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
#if defined(VERTHYS_TEST_REQUIRE_ISOLATION) && VERTHYS_TEST_REQUIRE_ISOLATION
TEST(rollback_test_build_requires_isolation)
{
    char saved[512];
    DWORD n;

    memset(saved, 0, sizeof(saved));
    n = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", saved,
                                sizeof(saved));
    vty_rollback_set_enabled(1);
    vty_rollback_reset_path_for_test();
    SetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", NULL);
    /* 自动化测试构建缺少隔离目录时必须拒绝初始化，绝不回落生产目录。 */
    CHECK_EQ(vty_rollback_init(), VTY_E_POLICY);
    if (n > 0 && n < sizeof(saved)) {
        SetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", saved);
    }
    vty_rollback_reset_path_for_test();
    CHECK_EQ(vty_rollback_init(), VTY_OK);
    vty_rollback_set_enabled(0);
    return 0;
}
#endif

TEST(rollback_anchor_capacity_preserves_active)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t u3[VTY_UUID_BYTES];
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;
    int i;

    memset(u1, 0x11, sizeof(u1));
    memset(u2, 0x22, sizeof(u2));
    memset(u3, 0x33, sizeof(u3));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_cap.state"), 0);
    vty_rollback_set_max_entries_for_test(2);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);

    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);
    /* 表满且全是 ACTIVE：必须失败且不得删除任何条目/见证。 */
    CHECK_EQ(vty_rollback_commit(u3, 2), VTY_E_ANCHOR_FULL);
    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 2);
    CHECK_EQ(missing, 0);
    for (i = 0; i < (int)count; i++) {
        CHECK_EQ(info[i].state, VTY_ANCHOR_ACTIVE);
    }

    /* 制造一个 DEAD：只回收它，另一个 ACTIVE 必须保留。 */
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u3, 2), VTY_OK);
    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 2);
    CHECK(rb_find_info(info, count, u1) < 0);
    CHECK(rb_find_info(info, count, u2) >= 0);
    CHECK(rb_find_info(info, count, u3) >= 0);

    vty_rollback_set_max_entries_for_test(0);
    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);
    remove("rb_cap.state");
    return 0;
}

TEST(rollback_anchor_capacity_preserves_tampered)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t u3[VTY_UUID_BYTES];
    uint8_t derived[VTY_UUID_BYTES];
    uint8_t slot = 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;
    int idx;

    memset(u1, 0x44, sizeof(u1));
    memset(u2, 0x55, sizeof(u2));
    memset(u3, 0x66, sizeof(u3));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_cap_t.state"), 0);
    vty_rollback_set_max_entries_for_test(2);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);

    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);
    CHECK_EQ(rb_entry_slot("rb_cap_t.state", u1, &slot), 0);
    CHECK_EQ(vty_secure_state_identity_rollback(u1, derived), VTY_OK);
    CHECK_EQ(vty_tpm_witness_create(derived, slot, fp), VTY_OK);

    /* TAMPERED 不得被自动回收，容量错误必须独立返回。 */
    CHECK_EQ(vty_rollback_commit(u3, 2), VTY_E_ANCHOR_FULL);
    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 2);
    idx = rb_find_info(info, count, u1);
    CHECK(idx >= 0);
    if (idx >= 0) CHECK_EQ(info[idx].state, VTY_ANCHOR_TAMPERED);

    vty_rollback_set_max_entries_for_test(0);
    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);
    remove("rb_cap_t.state");
    return 0;
}

TEST(rollback_anchor_capacity_preserves_unknown)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t u3[VTY_UUID_BYTES];

    memset(u1, 0x77, sizeof(u1));
    memset(u2, 0x88, sizeof(u2));
    memset(u3, 0x99, sizeof(u3));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_cap_u.state"), 0);
    vty_rollback_set_max_entries_for_test(2);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);

    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);
    vty_tpm_witness_set_exists_override_for_test(-1);
    CHECK_EQ(vty_rollback_commit(u3, 2), VTY_E_ANCHOR_FULL);
    vty_tpm_witness_set_exists_override_for_test(-2);

    vty_rollback_set_max_entries_for_test(0);
    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);
    remove("rb_cap_u.state");
    return 0;
}

TEST(rollback_anchor_list_classifies)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t u3[VTY_UUID_BYTES];
    uint8_t derived[VTY_UUID_BYTES];
    uint8_t slot = 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;
    int idx;

    memset(u1, 0xA1, sizeof(u1));
    memset(u2, 0xA2, sizeof(u2));
    memset(u3, 0xA3, sizeof(u3));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_list.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);

    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u3, 2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_entry_slot("rb_list.state", u3, &slot), 0);
    CHECK_EQ(vty_secure_state_identity_rollback(u3, derived), VTY_OK);
    CHECK_EQ(vty_tpm_witness_create(derived, slot, fp), VTY_OK);

    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 3);
    idx = rb_find_info(info, count, u1);
    CHECK(idx >= 0);
    if (idx >= 0) CHECK_EQ(info[idx].state, VTY_ANCHOR_ACTIVE);
    idx = rb_find_info(info, count, u2);
    CHECK(idx >= 0);
    if (idx >= 0) CHECK_EQ(info[idx].state, VTY_ANCHOR_DEAD);
    idx = rb_find_info(info, count, u3);
    CHECK(idx >= 0);
    if (idx >= 0) CHECK_EQ(info[idx].state, VTY_ANCHOR_TAMPERED);

    /* 平台错误必须保持 UNKNOWN，不能被列表折叠成 DEAD/TAMPERED。 */
    vty_tpm_witness_set_probe_override_for_test(VTY_WITNESS_PROBE_UNKNOWN);
    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 3);
    for (idx = 0; idx < (int)count; idx++) {
        CHECK_EQ(info[idx].state, VTY_ANCHOR_UNKNOWN);
    }
    vty_tpm_witness_set_probe_override_for_test(-1);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);
    remove("rb_list.state");
    return 0;
}

TEST(rollback_anchor_release_preserves_other)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint32_t released = 0;
    uint32_t cleanup_failed = 0;
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;

    memset(u1, 0xB1, sizeof(u1));
    memset(u2, 0xB2, sizeof(u2));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_rel.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);

    CHECK_EQ(vty_rollback_anchor_release(u1, 0, &released, &cleanup_failed),
             VTY_E_INVALID);
    CHECK_EQ(vty_rollback_anchor_release(
                 u1, VTY_ROLLBACK_ANCHOR_CONFIRM, &released, &cleanup_failed),
             VTY_OK);
    CHECK_EQ(released, 1);
    CHECK_EQ(cleanup_failed, 0);

    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 1);
    CHECK(rb_find_info(info, count, u1) < 0);
    CHECK(rb_find_info(info, count, u2) >= 0);

    CHECK_EQ(vty_secure_state_identity_rollback(u1, wid), VTY_OK);
    CHECK_EQ(vty_tpm_witness_exists(wid, 0), 0);
    CHECK_EQ(vty_tpm_witness_exists(wid, 1), 0);
    CHECK_EQ(vty_secure_state_identity_rollback(u2, wid), VTY_OK);
    CHECK_EQ(vty_tpm_witness_exists(wid, 0) +
             vty_tpm_witness_exists(wid, 1), 1);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    remove("rb_rel.state");
    return 0;
}

TEST(rollback_anchor_release_batch_mixed)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t u3[VTY_UUID_BYTES];
    uint8_t ux[VTY_UUID_BYTES];
    uint8_t req[3 * VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    VtyAnchorReleaseResult out[3];
    uint32_t produced = 0;
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;

    memset(u1, 0xC1, sizeof(u1));
    memset(u2, 0xC2, sizeof(u2));
    memset(u3, 0xC3, sizeof(u3));
    memset(ux, 0xC9, sizeof(ux));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_batch.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);
    CHECK_EQ(rb_clean_witness(ux), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u3, 2), VTY_OK);

    memcpy(req, u1, VTY_UUID_BYTES);
    memcpy(req + VTY_UUID_BYTES, ux, VTY_UUID_BYTES);
    memcpy(req + 2 * VTY_UUID_BYTES, u2, VTY_UUID_BYTES);
    memset(out, 0, sizeof(out));
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 3, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 3, &produced),
             VTY_OK);
    CHECK_EQ(produced, 3);
    CHECK_EQ(out[0].released, 1);
    CHECK_EQ(out[1].released, 0);
    CHECK_EQ(out[2].released, 1);
    CHECK_EQ(out[1].cleanup_failed, 0);
    CHECK(memcmp(out[0].uuid, u1, VTY_UUID_BYTES) == 0);
    CHECK(memcmp(out[1].uuid, ux, VTY_UUID_BYTES) == 0);
    CHECK(memcmp(out[2].uuid, u2, VTY_UUID_BYTES) == 0);

    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 1);
    CHECK(rb_find_info(info, count, u1) < 0);
    CHECK(rb_find_info(info, count, u2) < 0);
    CHECK(rb_find_info(info, count, u3) >= 0);

    CHECK_EQ(vty_secure_state_identity_rollback(u1, wid), VTY_OK);
    CHECK_EQ(vty_tpm_witness_exists(wid, 0) + vty_tpm_witness_exists(wid, 1), 0);
    CHECK_EQ(vty_secure_state_identity_rollback(u2, wid), VTY_OK);
    CHECK_EQ(vty_tpm_witness_exists(wid, 0) + vty_tpm_witness_exists(wid, 1), 0);
    CHECK_EQ(vty_secure_state_identity_rollback(u3, wid), VTY_OK);
    CHECK(vty_tpm_witness_exists(wid, 0) + vty_tpm_witness_exists(wid, 1) >= 1);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(rb_clean_witness(u3), VTY_OK);
    CHECK_EQ(rb_clean_witness(ux), VTY_OK);
    remove("rb_batch.state");
    return 0;
}

TEST(rollback_witness_status_never_treats_platform_error_as_missing)
{
    CHECK_EQ(vty_tpm_witness_status_is_missing_for_test(0x80090011u), 1);
    CHECK_EQ(vty_tpm_witness_status_is_missing_for_test(0x80090016u), 1);
    CHECK_EQ(vty_tpm_witness_status_is_missing_for_test(0x80090026u), 0);
    CHECK_EQ(vty_tpm_witness_status_is_missing_for_test(0x80090000u), 0);
    return 0;
}

TEST(rollback_anchor_release_batch_rejects_invalid_input)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t zero[VTY_UUID_BYTES];
    uint8_t req[3 * VTY_UUID_BYTES];
    VtyAnchorReleaseResult out[3];
    uint32_t produced = 0;

    memset(u1, 0xC4, sizeof(u1));
    memset(u2, 0xC5, sizeof(u2));
    memset(zero, 0, sizeof(zero));
    memcpy(req, u1, VTY_UUID_BYTES);
    memcpy(req + VTY_UUID_BYTES, u2, VTY_UUID_BYTES);
    memcpy(req + 2 * VTY_UUID_BYTES, u1, VTY_UUID_BYTES);
    if (rb_skip_without_witness()) return 0;

    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 0, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 3, &produced),
             VTY_E_INVALID);
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 65, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 65, &produced),
             VTY_E_INVALID);
    CHECK_EQ(vty_rollback_anchor_release_batch(req, 1, 0, out, 1, &produced),
             VTY_E_INVALID);
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 2, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 1, &produced),
             VTY_E_INVALID);
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 3, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 3, &produced),
             VTY_E_INVALID);
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 zero, 1, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 1, &produced),
             VTY_E_INVALID);
    return 0;
}

TEST(rollback_anchor_release_batch_cleanup_failure_per_uuid)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t req[2 * VTY_UUID_BYTES];
    VtyAnchorReleaseResult out[2];
    uint32_t produced = 0;
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;

    memset(u1, 0xD1, sizeof(u1));
    memset(u2, 0xD2, sizeof(u2));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_batch_cleanup.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);

    memcpy(req, u1, VTY_UUID_BYTES);
    memcpy(req + VTY_UUID_BYTES, u2, VTY_UUID_BYTES);
    vty_tpm_witness_set_delete_fail_for_test(2);
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 2, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 2, &produced),
             VTY_OK);
    vty_tpm_witness_set_delete_fail_for_test(0);
    CHECK_EQ(produced, 2);
    CHECK_EQ(out[0].released, 1);
    CHECK_EQ(out[0].cleanup_failed, 1);
    CHECK_EQ(out[1].released, 1);
    CHECK_EQ(out[1].cleanup_failed, 0);

    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 0);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    remove("rb_batch_cleanup.state");
    return 0;
}

TEST(rollback_anchor_release_batch_store_failure_keeps_all)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t u2[VTY_UUID_BYTES];
    uint8_t req[2 * VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    VtyAnchorReleaseResult out[2];
    uint32_t produced = 0;
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;

    memset(u1, 0xE3, sizeof(u1));
    memset(u2, 0xE4, sizeof(u2));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_batch_store.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u2, 2), VTY_OK);

    memcpy(req, u1, VTY_UUID_BYTES);
    memcpy(req + VTY_UUID_BYTES, u2, VTY_UUID_BYTES);
    vty_rb_set_store_fail_for_test(1);
    CHECK_EQ(vty_rollback_anchor_release_batch(
                 req, 2, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 2, &produced),
             VTY_E_IO);
    vty_rb_set_store_fail_for_test(0);
    CHECK_EQ(produced, 0);

    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 2);
    CHECK(rb_find_info(info, count, u1) >= 0);
    CHECK(rb_find_info(info, count, u2) >= 0);

    CHECK_EQ(vty_secure_state_identity_rollback(u1, wid), VTY_OK);
    CHECK(vty_tpm_witness_exists(wid, 0) + vty_tpm_witness_exists(wid, 1) >= 1);
    CHECK_EQ(vty_secure_state_identity_rollback(u2, wid), VTY_OK);
    CHECK(vty_tpm_witness_exists(wid, 0) + vty_tpm_witness_exists(wid, 1) >= 1);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(rb_clean_witness(u2), VTY_OK);
    remove("rb_batch_store.state");
    return 0;
}

TEST(rollback_anchor_release_batch_state_missing_is_idempotent)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    VtyAnchorReleaseResult out[1];
    uint32_t produced = 0;

    memset(u1, 0xE5, sizeof(u1));
    memset(fp, 0, sizeof(fp));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_batch_missing.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(vty_secure_state_identity_rollback(u1, wid), VTY_OK);
    CHECK_EQ(vty_tpm_witness_create(wid, 0, fp), VTY_OK);

    CHECK_EQ(vty_rollback_anchor_release_batch(
                 u1, 1, VTY_ROLLBACK_ANCHOR_CONFIRM, out, 1, &produced),
             VTY_OK);
    CHECK_EQ(produced, 1);
    CHECK_EQ(out[0].released, 0);
    CHECK_EQ(out[0].cleanup_failed, 0);
    CHECK_EQ(vty_tpm_witness_exists(wid, 0), 0);
    CHECK_EQ(vty_tpm_witness_exists(wid, 1), 0);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    remove("rb_batch_missing.state");
    return 0;
}

TEST(rollback_anchor_release_cleanup_failure_reported)
{
    uint8_t u1[VTY_UUID_BYTES];
    uint32_t released = 0;
    uint32_t cleanup_failed = 0;
    VtyAnchorInfo info[8];
    uint32_t count = 0;
    int missing = 0;

    memset(u1, 0xD1, sizeof(u1));
    if (rb_skip_without_witness()) return 0;
    CHECK_EQ(rb_enable("rb_relfail.state"), 0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    CHECK_EQ(vty_rollback_commit(u1, 2), VTY_OK);

    vty_tpm_witness_set_delete_fail_for_test(2);
    CHECK_EQ(vty_rollback_anchor_release(
                 u1, VTY_ROLLBACK_ANCHOR_CONFIRM, &released, &cleanup_failed),
             VTY_OK);
    vty_tpm_witness_set_delete_fail_for_test(0);
    CHECK_EQ(released, 1);
    CHECK_EQ(cleanup_failed, 1);

    CHECK_EQ(vty_rollback_anchor_list(info, 8, &count, &missing), VTY_OK);
    CHECK_EQ(count, 0);

    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(u1), VTY_OK);
    remove("rb_relfail.state");
    return 0;
}

TEST(rollback_anchor_full_maps_to_public_error)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t header[28];
    size_t len = 0;
    uint8_t uuid[VTY_UUID_BYTES];

    if (rb_skip_without_witness()) return 0;
    remove("rb_api1.vty");
    remove("rb_api2.vty");
    CHECK_EQ(rb_enable("rb_api.state"), 0);
    vty_rollback_set_max_entries_for_test(1);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "rb_api1.vty", "rb-api-pw", 9, code,
                              sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, "rb_api2.vty", "rb-api-pw", 9, code,
                              sizeof(code)), VERTHYS_ERR_ANCHOR_FULL);
    CHECK(fopen("rb_api2.vty", "rb") == NULL);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    CHECK_EQ(rb_read_file("rb_api1.vty", header, sizeof(header), &len), 0);
    CHECK(len >= 28u);
    memcpy(uuid, header + 12, VTY_UUID_BYTES);

    vty_rollback_set_max_entries_for_test(0);
    vty_rollback_set_enabled(0);
    CHECK_EQ(rb_clean_witness(uuid), VTY_OK);
    remove("rb_api.state");
    remove("rb_api1.vty");
    remove("rb_api2.vty");
    return 0;
}
#endif

