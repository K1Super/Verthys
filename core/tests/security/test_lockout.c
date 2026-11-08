/*
 * test_lockout.c — 持久化失败计数与熔断验收
 *
 * 覆盖：
 *   - 首次运行（状态文件不存在）放行、失败计数递增
 *   - 达到阈值后进入退避窗口；窗口满允许重试，计数不清零
 *   - 阈值后继续失败会累加计数并延长窗口（上限 1 小时）
 *   - 成功解锁后 reset 清零
 *   - 状态文件被篡改 / 尺寸异常 / 机器绑定失配一律视为锁定
 *   - 测试注入路径隔离：状态路径切换不得创造新的熔断世界
 *   - 旧路径见证升级到设备根/用户见证（迁移后旧键失效）
 *
 * 全部状态文件写在测试沙箱相对路径，绝不触碰 %LOCALAPPDATA% 真实状态。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_lockout.h"
#include "vty_device_root.h"
#include "vty_kdf.h"
#include "vty_secure_state.h"
#include "vty_tpm_witness.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* 版本字段 3：header(24) + MAC(32) + 设备 blob(290) + 见证{slot(1), fp(32)}
 *     + 模块锁表(8 × 32) */
#define LK_FILE_BYTES (24u + 32u + 290u + 1u + 32u + 256u)

/* 见证密钥不在沙箱里：同一路径跨轮次复用，必须在用例前后清理。 */
static void lk_clean_witness(void)
{
    uint8_t id[VTY_UUID_BYTES];
    if (vty_secure_state_identity_lockout(id) == VTY_OK) {
        (void)vty_tpm_witness_delete_all(id);
    }
}

static int lk_write_raw(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

TEST(lockout_first_run_and_counting)
{
    uint32_t i;

    CHECK_EQ(vty_device_root_init(), VTY_OK);
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_a.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);

    /* 首次运行：状态文件不存在不得当作锁定 */
    CHECK_EQ(vty_lockout_check(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 0u);

    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 1u);
    CHECK_EQ(vty_lockout_check(), VTY_OK);

    /* 重启不清零：重新 init 后计数仍在（持久化语义） */
    CHECK_EQ(vty_lockout_init(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 1u);

    /* 成功解锁清零 */
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 0u);
    CHECK_EQ(vty_lockout_check(), VTY_OK);

    /* 阈值边界：前 4 次只计数，第 5 次进入退避 */
    for (i = 0; i < VTY_LOCKOUT_MAX_FAILURES - 1u; i++) {
        CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    }
    CHECK_EQ(vty_lockout_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), VTY_LOCKOUT_MAX_FAILURES);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);

    /* 阈值后继续失败：计数继续累加，退避窗口随次数增长（上限 1 小时） */
    CHECK_EQ(vty_lockout_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), VTY_LOCKOUT_MAX_FAILURES + 1u);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_backoff_secs(VTY_LOCKOUT_MAX_FAILURES), 32u);
    CHECK_EQ(vty_lockout_backoff_secs(11u), 2048u);
    CHECK_EQ(vty_lockout_backoff_secs(12u), 3600u);
    CHECK_EQ(vty_lockout_backoff_secs(32u), 3600u);
    lk_clean_witness();
    return 0;
}

/* 退避窗口语义：窗口内锁定、窗口满放行，且每次失败刷新时间戳。 */
TEST(lockout_backoff_window)
{
    const uint64_t base = 1700000000u;

    CHECK_EQ(vty_device_root_init(), VTY_OK);
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_w.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    CHECK_EQ(vty_lockout_set_test_clock(base), 0);

    /* 第 5 次失败：窗口 32 秒 */
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), 5u);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);

    CHECK_EQ(vty_lockout_set_test_clock(base + 31u), 0);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_set_test_clock(base + 32u), 0);
    CHECK_EQ(vty_lockout_check(), VTY_OK);

    /* 窗口满后再失败一次：窗口翻倍到 64 秒 */
    CHECK_EQ(vty_lockout_record_failure(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), 6u);
    CHECK_EQ(vty_lockout_set_test_clock(base + 32u + 63u), 0);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_set_test_clock(base + 32u + 64u), 0);
    CHECK_EQ(vty_lockout_check(), VTY_OK);
    CHECK_EQ(vty_lockout_backoff_secs(6u), 64u);

    /* 时钟回拨视为锁定（fail-closed） */
    CHECK_EQ(vty_lockout_set_test_clock(base), 0);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);

    /* 成功解锁清零后立即放行 */
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    CHECK_EQ(vty_lockout_check(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 0u);

    CHECK_EQ(vty_lockout_set_test_clock(0), 0);
    lk_clean_witness();
    return 0;
}

TEST(lockout_tampered_state_locked)
{
    uint8_t buf[LK_FILE_BYTES];

    CHECK_EQ(vty_device_root_init(), VTY_OK);
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_t.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);

    /* 全零文件：magic/版本失配 → 锁定，而不是“重置为 0 次” */
    memset(buf, 0, sizeof(buf));
    CHECK_EQ(lk_write_raw("lockout_t.state", buf, sizeof(buf)), 0);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), VTY_LOCKOUT_MAX_FAILURES);
    CHECK_EQ(vty_lockout_record_failure(), VTY_E_LOCKED);

    /* 尺寸不符 */
    CHECK_EQ(lk_write_raw("lockout_t.state", buf, sizeof(buf) - 1u), 0);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);

    /* 先建合法状态，再改计数 → MAC 失配 */
    remove("lockout_t.state");
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    {
        FILE *f = fopen("lockout_t.state", "rb");
        size_t n;
        CHECK(f != NULL);
        n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        CHECK_EQ(n, sizeof(buf));
        buf[8] ^= 0x01u;   /* 失败计数 */
        CHECK_EQ(lk_write_raw("lockout_t.state", buf, sizeof(buf)), 0);
    }
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    lk_clean_witness();
    return 0;
}

TEST(lockout_state_replay_rejected)
{
    uint8_t s1[LK_FILE_BYTES];
    uint8_t s2[LK_FILE_BYTES];
    size_t n1 = 0;
    size_t n2 = 0;
    FILE *f;
    uint8_t id[VTY_UUID_BYTES];

    CHECK_EQ(vty_device_root_init(), VTY_OK);
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_replay.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);
    CHECK_EQ(vty_lockout_reset(), VTY_OK);

    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    f = fopen("lockout_replay.state", "rb");
    CHECK(f != NULL);
    n1 = fread(s1, 1, sizeof(s1), f);
    fclose(f);
    CHECK_EQ(n1, (size_t)sizeof(s1));
    CHECK_EQ(vty_lockout_failures(), 1u);

    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    f = fopen("lockout_replay.state", "rb");
    CHECK(f != NULL);
    n2 = fread(s2, 1, sizeof(s2), f);
    fclose(f);
    CHECK_EQ(n2, (size_t)sizeof(s2));
    CHECK_EQ(vty_lockout_failures(), 2u);

    /* 还原上一版状态：计数仅 1（未达阈值），但见证指纹失效 → 锁定 */
    CHECK_EQ(lk_write_raw("lockout_replay.state", s1, n1), 0);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), VTY_LOCKOUT_MAX_FAILURES);

    /* 当前状态仍可校验 */
    CHECK_EQ(lk_write_raw("lockout_replay.state", s2, n2), 0);
    CHECK_EQ(vty_lockout_check(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 2u);

    /* 见证密钥删除：fail-closed；恢复路径可重建 */
    CHECK_EQ(vty_secure_state_identity_lockout(id), VTY_OK);
    CHECK_EQ(vty_tpm_witness_delete_all(id), VTY_OK);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    CHECK_EQ(vty_lockout_check(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 0u);

    lk_clean_witness();
    return 0;
}

TEST(lockout_path_change_locked)
{
    CHECK_EQ(vty_device_root_init(), VTY_OK);

    lk_clean_witness();
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_p1.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 2u);

    /* 切换注入路径不得创造新世界：见证域绑定设备根/用户 SID，
     * 新路径下状态缺失但见证仍在，必须继续锁定。 */
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_p2.state"), VTY_OK);
    CHECK_EQ(vty_lockout_check(), VTY_E_LOCKED);
    CHECK_EQ(vty_lockout_failures(), VTY_LOCKOUT_MAX_FAILURES);

    /* 非法注入路径 */
    CHECK_EQ(vty_lockout_set_path_for_test(NULL), VTY_E_INVALID);
    CHECK_EQ(vty_lockout_set_path_for_test(""), VTY_E_INVALID);
    lk_clean_witness();
    lk_clean_witness();
    return 0;
}

/* 认证前最小尝试间隔：check 纯查询，begin_attempt 才消耗额度。 */
TEST(lockout_begin_attempt_min_interval)
{
    const uint64_t base = 1700000100u;

    CHECK_EQ(vty_device_root_init(), VTY_OK);
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_attempt.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    CHECK_EQ(vty_lockout_set_test_clock(base), 0);

    CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    CHECK_EQ(vty_lockout_check(), VTY_OK);        /* 纯查询不消耗 */
    CHECK_EQ(vty_lockout_begin_attempt(), VTY_E_LOCKED);  /* 同一秒内拒绝 */
    CHECK_EQ(vty_lockout_set_test_clock(base + 1u), 0);
    CHECK_EQ(vty_lockout_begin_attempt(), VTY_OK);

    CHECK_EQ(vty_lockout_set_test_clock(0), 0);
    lk_clean_witness();
    return 0;
}

/* 模块锁隔离：模块失败不污染库锁；模块 A/B 独立；库成功不清模块锁。 */
TEST(lockout_module_isolation)
{
    uint8_t vault_uuid[VTY_UUID_BYTES];
    uint32_t i;

    for (i = 0; i < VTY_UUID_BYTES; i++) vault_uuid[i] = (uint8_t)(i + 1u);

    CHECK_EQ(vty_device_root_init(), VTY_OK);
    lk_clean_witness();
    CHECK_EQ(vty_lockout_set_path_for_test("lockout_module.state"), VTY_OK);
    CHECK_EQ(vty_lockout_init(), VTY_OK);
    CHECK_EQ(vty_lockout_reset(), VTY_OK);

    /* 库先累计 4 次（未达阈值） */
    for (i = 0; i < VTY_LOCKOUT_MAX_FAILURES - 1u; i++) {
        CHECK_EQ(vty_lockout_record_failure(), VTY_OK);
    }
    CHECK_EQ(vty_lockout_failures(), 4u);
    CHECK_EQ(vty_lockout_check(), VTY_OK);

    /* 模块 0 失败 5 次：只锁模块 0，库计数不受影响 */
    for (i = 0; i < VTY_LOCKOUT_MAX_FAILURES - 1u; i++) {
        CHECK_EQ(vty_lockout_module_record_failure(vault_uuid, 0u), VTY_OK);
    }
    CHECK_EQ(vty_lockout_module_record_failure(vault_uuid, 0u), VTY_E_MODULE_LOCKED);
    CHECK_EQ(vty_lockout_module_failures(vault_uuid, 0u), VTY_LOCKOUT_MAX_FAILURES);
    CHECK_EQ(vty_lockout_module_begin_attempt(vault_uuid, 0u), VTY_E_MODULE_LOCKED);
    CHECK_EQ(vty_lockout_module_begin_attempt(vault_uuid, 1u), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 4u);
    CHECK_EQ(vty_lockout_check(), VTY_OK);

    /* 模块 0 成功重置：清除自身锁 */
    CHECK_EQ(vty_lockout_module_reset(vault_uuid, 0u), VTY_OK);
    CHECK_EQ(vty_lockout_module_failures(vault_uuid, 0u), 0u);
    CHECK_EQ(vty_lockout_module_begin_attempt(vault_uuid, 0u), VTY_OK);

    /* 模块 1 失败 3 次，随后库成功重置：模块计数保留 */
    for (i = 0; i < 3u; i++) {
        CHECK_EQ(vty_lockout_module_record_failure(vault_uuid, 1u), VTY_OK);
    }
    CHECK_EQ(vty_lockout_reset(), VTY_OK);
    CHECK_EQ(vty_lockout_failures(), 0u);
    CHECK_EQ(vty_lockout_module_failures(vault_uuid, 1u), 3u);

    CHECK_EQ(vty_lockout_module_reset(vault_uuid, 1u), VTY_OK);
    CHECK_EQ(vty_lockout_module_failures(vault_uuid, 1u), 0u);

    lk_clean_witness();
    remove("lockout_module.state");
    return 0;
}
