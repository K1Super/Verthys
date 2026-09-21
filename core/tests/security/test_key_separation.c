/*
 * test_key_separation.c — 配套测试：CNG 内核托管密钥
 *
 * 覆盖：
 *   - install 消费密钥缓冲（明文即刻清零契约）
 *   - any_installed 查询（defense_closure MEM_DUMP 判据）
 *   - purge_all 后句柄失效（any_installed 归零、purge 幂等）
 *   - C 角色（超级块密钥）休眠强制：激活前 acquire 拒绝，
 *     激活后导出与安装字节一致，再次休眠后恢复拒绝
 */
#include "verthys_test.h"
#include "verthys.h"
#include "key_separation.h"

#include <string.h>

static uint8_t t_key_a[32] = {
    0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,
    0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0
};
static uint8_t t_key_c[32] = {
    0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0,
    0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0x00
};

/* install 消费调用方缓冲 + any_installed 判据 + purge 失效 */
TEST(keysep_install_consumes_and_reports)
{
    uint8_t key_copy[32];
    memcpy(key_copy, t_key_a, 32);
    CHECK_EQ(key_separation_install(KEY_ROLE_INDEX, key_copy), 0);
    /* install 消费调用方缓冲（明文即刻清零契约） */
    uint8_t zero[32] = {0};
    CHECK(memcmp(key_copy, zero, 32) == 0);
    CHECK_EQ(key_separation_any_installed(), 1);

    /* purge：句柄销毁、判据归零；幂等可重复 */
    key_separation_purge_all();
    CHECK_EQ(key_separation_any_installed(), 0);
    key_separation_purge_all();
    CHECK_EQ(key_separation_any_installed(), 0);

    /* purge 后模块可重新初始化并安装 */
    memcpy(key_copy, t_key_a, 32);
    CHECK_EQ(key_separation_install(KEY_ROLE_INDEX, key_copy), 0);
    CHECK(memcmp(key_copy, zero, 32) == 0);
    CHECK_EQ(key_separation_any_installed(), 1);

    key_separation_purge_all();
    CHECK_EQ(key_separation_any_installed(), 0);
    return 0;
}

/* C 角色休眠强制：激活前 acquire 拒绝；激活后导出一致；再休眠恢复拒绝 */
TEST(keysep_commit_sleep_enforced)
{
    uint8_t key_copy[32];
    memcpy(key_copy, t_key_c, 32);
    CHECK_EQ(key_separation_install(KEY_ROLE_COMMIT, key_copy), 0);
    CHECK(memcmp(key_copy, (uint8_t[32]){0}, 32) == 0);

    /* 休眠态：acquire 必须拒绝（逻辑隔离等价旧版 PAGE_NOACCESS） */
    uint8_t out[32];
    CHECK(key_separation_acquire(KEY_ROLE_COMMIT, out) != 0);

    /* 激活 → 导出与安装字节一致 */
    CHECK_EQ(key_separation_activate_commit(), 0);
    CHECK_EQ(key_separation_acquire(KEY_ROLE_COMMIT, out), 0);
    CHECK(memcmp(out, t_key_c, 32) == 0);
    key_separation_release(out);
    CHECK(memcmp(out, (uint8_t[32]){0}, 32) == 0);

    /* 再休眠 → 恢复拒绝 */
    CHECK_EQ(key_separation_deactivate_commit(), 0);
    CHECK(key_separation_acquire(KEY_ROLE_COMMIT, out) != 0);

    key_separation_purge_all();
    return 0;
}
