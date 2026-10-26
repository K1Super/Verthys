/*
 * test_v4_modules.c — v4 容器创建/解锁/轮换与模块密钥生命周期验收
 *
 * 覆盖：
 *   - 库创建落盘、口令 + 设备根双槽 AND 解锁
 *   - 错误口令拒绝；恢复码独立解锁
 *   - 口令轮换：旧口令失效、新口令与恢复码生效
 *   - 头部篡改拒绝（尾哈希）
 *   - 模块密钥文件：创建 / 解锁 / 错误口令 / 破坏设备槽后必失败
 *   - 模块口令轮换与显式销毁
 *
 * 全部落盘到测试沙箱相对路径，绝不触碰活动库。
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_keymanager_v4.h"
#include "vty_module_v4.h"
#include "vty_blake3.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

/* 模块文件布局（实现侧常量在测试独立复述，漂移即失配报警）：
 *   84B 头 + 口令槽(6+12+32+24+2+48=124) + 设备槽(6+0+32+24+2+290=354)
 *   设备槽密文起点 = 84 + 124 + 64 = 272 */
#define V4_T_MOD_DEV_CT_OFF 272u
#define V4_T_MOD_HASH_BYTES 32u

static int v4_t_read_file(const char *path, uint8_t *buf, size_t cap,
                          size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *out_len = n;
    return 0;
}

static int v4_t_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

TEST(v4_vault_create_open_e2e)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t k1[VTY_KEY_BYTES];
    uint8_t k2[VTY_KEY_BYTES];

    CHECK_EQ(vty_vault_create("v4_e2e.vty", "p@ssw0rd", &v, code,
                              sizeof(code)), VTY_OK);
    CHECK(v != NULL);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 3, uuid0), VTY_E_INVALID);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k1), VTY_OK);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    /* 错误口令 */
    v = NULL;
    CHECK(vty_vault_open("v4_e2e.vty", "wrong", &v) != VTY_OK);
    CHECK(v == NULL);

    /* 正确口令 + 设备根 */
    CHECK_EQ(vty_vault_open("v4_e2e.vty", "p@ssw0rd", &v), VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(v);

    /* 恢复码独立解锁（不依赖口令与设备根） */
    CHECK_EQ(vty_vault_open_recovery("v4_e2e.vty", code, &re), VTY_OK);
    CHECK_EQ(vty_vault_module_key(re, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(re);
    return 0;
}

TEST(v4_vault_wrong_recovery_rejected)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char other[VTY_RECOVERY_TEXT_BUF];
    uint8_t raw[VTY_RECOVERY_CODE_BYTES];

    CHECK_EQ(vty_vault_create("v4_rec.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    vty_vault_free(v);

    /* 格式合法但内容不同：必须解包失败，而不是“格式对就放行” */
    CHECK_EQ(vty_recovery_generate(raw, other, sizeof(other)), VTY_OK);
    CHECK(vty_vault_open_recovery("v4_rec.vty", other, &re) != VTY_OK);
    CHECK(re == NULL);

    /* 损坏的恢复码文本 */
    CHECK(vty_vault_open_recovery("v4_rec.vty", "not-a-code", &re) != VTY_OK);
    return 0;
}

TEST(v4_vault_rotate_password)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char new_code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t k1[VTY_KEY_BYTES];
    uint8_t k2[VTY_KEY_BYTES];

    CHECK_EQ(vty_vault_create("v4_rot.vty", "old-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k1), VTY_OK);

    /* 恢复槽存在时必须输出新恢复码；不给就拒绝 */
    CHECK_EQ(vty_vault_rotate_password(v, "new-pw", NULL, 0), VTY_E_INVALID);

    CHECK_EQ(vty_vault_rotate_password(v, "new-pw", new_code,
                                       sizeof(new_code)), VTY_OK);
    vty_vault_free(v);

    /* 旧口令失效 */
    v = NULL;
    CHECK(vty_vault_open("v4_rot.vty", "old-pw", &v) != VTY_OK);

    /* 新口令可用且模块密钥不变 */
    CHECK_EQ(vty_vault_open("v4_rot.vty", "new-pw", &v), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(v);

    /* 旧恢复码失效，新恢复码可用 */
    CHECK(vty_vault_open_recovery("v4_rot.vty", code, &re) != VTY_OK);
    re = NULL;
    CHECK_EQ(vty_vault_open_recovery("v4_rot.vty", new_code, &re), VTY_OK);
    CHECK_EQ(vty_vault_module_key(re, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(re);
    return 0;
}

TEST(v4_vault_header_tamper_rejected)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t buf[8192];
    size_t len = 0;

    CHECK_EQ(vty_vault_create("v4_tamper.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    vty_vault_free(v);

    CHECK_EQ(v4_t_read_file("v4_tamper.vty", buf, sizeof(buf), &len), 0);
    CHECK(len > VTY_V4_HEADER_FIXED_BYTES + VTY_V4_HEADER_HASH_BYTES);

    /* 槽区任意位翻转都会被头部尾哈希发现 */
    buf[VTY_V4_HEADER_FIXED_BYTES] ^= 0x01u;
    CHECK_EQ(v4_t_write_file("v4_tamper.vty", buf, len), 0);

    v = NULL;
    CHECK_EQ(vty_vault_open("v4_tamper.vty", "pw", &v), VTY_E_CORRUPT);
    CHECK(v == NULL);
    return 0;
}

TEST(v4_module_create_unlock_roundtrip)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t uuid_bad[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t unlocked[VTY_KEY_BYTES];

    memset(uuid_bad, 0xEE, sizeof(uuid_bad));

    CHECK_EQ(vty_vault_create("v4_mod.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, mdek), VTY_OK);

    /* 模块 UUID 不在 Keyring 中：拒绝 */
    CHECK_EQ(vty_module_create("v4_mod0.bin", v, uuid_bad, "mpw",
                               VTY_ARGON2_MEM_KIB_MIN, 3, 1), VTY_E_KEY_INVALID);

    CHECK_EQ(vty_module_create("v4_mod0.bin", v, uuid0, "mpw",
                               VTY_ARGON2_MEM_KIB_MIN, 3, 1), VTY_OK);

    CHECK_EQ(vty_module_unlock("v4_mod0.bin", v, uuid0, "mpw", unlocked),
             VTY_OK);
    CHECK_EQ(memcmp(unlocked, mdek, VTY_KEY_BYTES), 0);

    /* 模块口令错误 */
    memset(unlocked, 0, sizeof(unlocked));
    CHECK(vty_module_unlock("v4_mod0.bin", v, uuid0, "bad", unlocked) != VTY_OK);

    /* 模块口令轮换：旧口令失效，新口令可用 */
    CHECK_EQ(vty_module_rotate_password("v4_mod0.bin", v, uuid0, "mpw2",
                                        VTY_ARGON2_MEM_KIB_MIN, 3, 1), VTY_OK);
    CHECK(vty_module_unlock("v4_mod0.bin", v, uuid0, "mpw", unlocked) != VTY_OK);
    CHECK_EQ(vty_module_unlock("v4_mod0.bin", v, uuid0, "mpw2", unlocked),
             VTY_OK);
    CHECK_EQ(memcmp(unlocked, mdek, VTY_KEY_BYTES), 0);

    vty_vault_free(v);
    return 0;
}

TEST(v4_module_device_slot_break_fails)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t unlocked[VTY_KEY_BYTES];
    uint8_t buf[4096];
    uint8_t hash[VTY_HASH_BYTES];
    size_t len = 0;

    CHECK_EQ(vty_vault_create("v4_moddev.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_module_create("v4_moddev.bin", v, uuid0, "mpw",
                               VTY_ARGON2_MEM_KIB_MIN, 3, 1), VTY_OK);

    /* 先证明正常路径可用 */
    CHECK_EQ(vty_module_unlock("v4_moddev.bin", v, uuid0, "mpw", unlocked),
             VTY_OK);

    /* 破坏设备槽 RSA 密文并重算尾哈希：结构合法但设备根解封必失败，
     * 口令正确也不能绕过 AND */
    CHECK_EQ(v4_t_read_file("v4_moddev.bin", buf, sizeof(buf), &len), 0);
    CHECK(len > V4_T_MOD_DEV_CT_OFF + VTY_KEY_BYTES);
    buf[V4_T_MOD_DEV_CT_OFF] ^= 0x01u;
    CHECK_EQ(vty_blake3_32(buf, len - V4_T_MOD_HASH_BYTES, hash), VTY_OK);
    memcpy(buf + len - V4_T_MOD_HASH_BYTES, hash, VTY_HASH_BYTES);
    CHECK_EQ(v4_t_write_file("v4_moddev.bin", buf, len), 0);

    memset(unlocked, 0, sizeof(unlocked));
    CHECK_EQ(vty_module_unlock("v4_moddev.bin", v, uuid0, "mpw", unlocked),
             VTY_E_TPM);

    /* 销毁幂等：第二次返回成功，此后解锁 IO 失败 */
    CHECK_EQ(vty_module_destroy("v4_moddev.bin"), VTY_OK);
    CHECK_EQ(vty_module_destroy("v4_moddev.bin"), VTY_OK);
    CHECK_EQ(vty_module_unlock("v4_moddev.bin", v, uuid0, "mpw", unlocked),
             VTY_E_IO);

    vty_vault_free(v);
    return 0;
}
