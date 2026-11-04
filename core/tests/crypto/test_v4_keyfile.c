/*
 * test_v4_keyfile.c — D3 keyfile 因子验收
 *
 * 覆盖：VKFL 生成/解析/篡改拒绝、带 keyfile 的创建/解锁/口令轮换、
 * 缺 keyfile/坏 keyfile/错误 secret 的 fail-closed、启用/关闭 keyfile。
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_keyfile.h"
#include "vty_keymanager_v4.h"
#include "vty_recovery.h"

#include <stdio.h>
#include <string.h>

#define KF_VAULT "v4_keyfile.vty"
#define KF_BLOB "v4_keyfile.bin"
#define KF_WRONG "v4_keyfile_wrong.bin"
#define KF_PW "keyfile-pass"

static int kf_write(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return 1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return 1; }
    fclose(f);
    return 0;
}

TEST(v4_keyfile_generate_parse_roundtrip)
{
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    uint8_t secret[VTY_KEYFILE_SECRET_BYTES];
    uint8_t digest1[VTY_HASH_BYTES];
    uint8_t digest2[VTY_HASH_BYTES];

    CHECK_EQ(vty_keyfile_generate(blob), VTY_OK);
    CHECK_EQ(vty_keyfile_parse(blob, sizeof(blob), secret), VTY_OK);
    CHECK_EQ(vty_keyfile_digest(secret, digest1), VTY_OK);
    CHECK_EQ(vty_keyfile_digest(secret, digest2), VTY_OK);
    CHECK(vty_ct_equal(digest1, digest2, VTY_HASH_BYTES) == 0);
    CHECK_EQ(vty_keyfile_digest(secret, digest2), VTY_OK);
    return 0;
}

TEST(v4_keyfile_tamper_rejected)
{
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    uint8_t copy[VTY_KEYFILE_BLOB_BYTES];
    uint8_t secret[VTY_KEYFILE_SECRET_BYTES];

    CHECK_EQ(vty_keyfile_generate(blob), VTY_OK);
    memcpy(copy, blob, sizeof(copy));
    copy[0] ^= 0x01u;
    CHECK_EQ(vty_keyfile_parse(copy, sizeof(copy), secret), VTY_E_KEYFILE_INVALID);

    memcpy(copy, blob, sizeof(copy));
    copy[4] = 2u; /* version */
    CHECK_EQ(vty_keyfile_parse(copy, sizeof(copy), secret), VTY_E_KEYFILE_INVALID);

    memcpy(copy, blob, sizeof(copy));
    copy[6] = 1u; /* flags */
    CHECK_EQ(vty_keyfile_parse(copy, sizeof(copy), secret), VTY_E_KEYFILE_INVALID);

    memcpy(copy, blob, sizeof(copy));
    copy[VTY_KEYFILE_BLOB_BYTES - 1u] ^= 0x80u;
    CHECK_EQ(vty_keyfile_parse(copy, sizeof(copy), secret), VTY_E_KEYFILE_INVALID);

    CHECK_EQ(vty_keyfile_parse(blob, sizeof(blob) - 1u, secret),
             VTY_E_KEYFILE_INVALID);
    return 0;
}

TEST(v4_keyfile_vault_create_open_and_rotate)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    uint8_t wrong[VTY_KEYFILE_BLOB_BYTES];

    remove(KF_VAULT);
    remove(KF_BLOB);
    remove(KF_WRONG);
    memset(code, 0, sizeof(code));

    CHECK_EQ(vty_keyfile_generate(blob), VTY_OK);
    CHECK_EQ(kf_write(KF_BLOB, blob, sizeof(blob)), 0);
    CHECK_EQ(vty_keyfile_generate(wrong), VTY_OK);
    CHECK_EQ(kf_write(KF_WRONG, wrong, sizeof(wrong)), 0);

    CHECK_EQ(vty_vault_create_keyfile(KF_VAULT, KF_PW, blob, sizeof(blob),
                                      &v, code, sizeof(code)), VTY_OK);
    CHECK((v->header.flags & VTY_FLAG_KEYFILE) != 0);
    CHECK(v->keyfile_digest_set == 1);
    vty_vault_free(v);

    /* 缺 keyfile：显式失败，不回退为仅口令。 */
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile(KF_VAULT, KF_PW, NULL, &v),
             VTY_E_KEYFILE_REQUIRED);

    /* 错误 keyfile：VKFL 有效但 secret 不同，统一认证失败。 */
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile(KF_VAULT, KF_PW, KF_WRONG, &v),
             VTY_E_KEY_INVALID);

    /* 正确 keyfile：解锁成功。 */
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile(KF_VAULT, KF_PW, KF_BLOB, &v), VTY_OK);
    CHECK(v->keyfile_digest_set == 1);

    /* 口令轮换保留 keyfile 因子。 */
    CHECK_EQ(vty_vault_rotate_password(v, "new-keyfile-pass"), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile(KF_VAULT, "new-keyfile-pass", KF_BLOB, &v),
             VTY_OK);
    CHECK_EQ(vty_vault_keyfile_disable(v, "new-keyfile-pass", KF_BLOB), VTY_OK);
    CHECK((v->header.flags & VTY_FLAG_KEYFILE) == 0);
    CHECK(v->keyfile_digest_set == 0);
    vty_vault_free(v);

    /* 关闭后仅口令可开。 */
    v = NULL;
    CHECK_EQ(vty_vault_open(KF_VAULT, "new-keyfile-pass", &v), VTY_OK);

    /* 重新启用 keyfile 后缺文件再次 fail-closed。 */
    CHECK_EQ(vty_vault_keyfile_enable(v, "new-keyfile-pass", blob, sizeof(blob)),
             VTY_OK);
    vty_vault_free(v);
    v = NULL;
    CHECK_EQ(vty_vault_open(KF_VAULT, "new-keyfile-pass", &v),
             VTY_E_KEYFILE_REQUIRED);

    remove(KF_VAULT);
    remove(KF_BLOB);
    remove(KF_WRONG);
    return 0;
}
