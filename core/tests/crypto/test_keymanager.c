/*
 * test_keymanager.c — keymanager 行为测试（TDD 垂直切片）
 *
 * 测试通过 keymanager.h 接口验证四级密钥体系的行为契约：
 *   - 主密钥派生：确定性（同 pw+salt 同结果）、敏感性（pw 或 salt 变化结果变）
 *   - DEK 生成：随机性
 *   - DEK 包裹往返：wrap → unwrap 还原原 DEK
 *   - DEK 解包认证：错误 MEK / 篡改 wrapped 必失败
 *   - 记录级密钥：确定性 + 不同 ID 派生不同密钥
 *
 * 注意：Argon2id 64MiB/3iter 每次约 0.5–1s，测试用例尽量减少调用次数。
 */
#include "verthys_test.h"
#include "keymanager.h"
#include "verthys_crypto.h"
#include <string.h>

/* 同一主密码 + 同一盐 → 派生 MEK 必须一致（确定性） */
TEST(master_key_derive_deterministic)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk1[VERTHYS_KEY_BYTES], mk2[VERTHYS_KEY_BYTES];

    CHECK_EQ(keymanager_derive_master(mk1, (const uint8_t *)"password", 8, salt), 0);
    CHECK_EQ(keymanager_derive_master(mk2, (const uint8_t *)"password", 8, salt), 0);
    CHECK(memcmp(mk1, mk2, VERTHYS_KEY_BYTES) == 0);

    verthys_secure_zero(mk1, sizeof mk1);
    verthys_secure_zero(mk2, sizeof mk2);
    return 0;
}

/* 主密码变化 → MEK 必变化（敏感性） */
TEST(master_key_password_sensitive)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk1[VERTHYS_KEY_BYTES], mk2[VERTHYS_KEY_BYTES];

    CHECK_EQ(keymanager_derive_master(mk1, (const uint8_t *)"password", 8, salt), 0);
    CHECK_EQ(keymanager_derive_master(mk2, (const uint8_t *)"Password", 8, salt), 0);
    CHECK(memcmp(mk1, mk2, VERTHYS_KEY_BYTES) != 0);

    verthys_secure_zero(mk1, sizeof mk1);
    verthys_secure_zero(mk2, sizeof mk2);
    return 0;
}

/* 盐变化 → MEK 必变化（敏感性） */
TEST(master_key_salt_sensitive)
{
    uint8_t salt1[VERTHYS_SALT_BYTES] = {0};
    uint8_t salt2[VERTHYS_SALT_BYTES] = {0};
    verthys_random_bytes(salt2, sizeof salt2);

    uint8_t mk1[VERTHYS_KEY_BYTES], mk2[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_master(mk1, (const uint8_t *)"password", 8, salt1), 0);
    CHECK_EQ(keymanager_derive_master(mk2, (const uint8_t *)"password", 8, salt2), 0);
    CHECK(memcmp(mk1, mk2, VERTHYS_KEY_BYTES) != 0);

    verthys_secure_zero(mk1, sizeof mk1);
    verthys_secure_zero(mk2, sizeof mk2);
    return 0;
}

/* 拒绝空指针（参数校验） */
TEST(master_key_rejects_null)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk[VERTHYS_KEY_BYTES];

    /* password 允许 NULL 仅当 pw_len=0 */
    CHECK(keymanager_derive_master(NULL, (const uint8_t *)"p", 1, salt) != 0);
    CHECK(keymanager_derive_master(mk, (const uint8_t *)"p", 1, NULL) != 0);
    /* NULL password + 非零长度 → 非法 */
    CHECK(keymanager_derive_master(mk, NULL, 5, salt) != 0);
    /* 空口令应允许（不报错），仅校验返回 0 */
    CHECK_EQ(keymanager_derive_master(mk, NULL, 0, salt), 0);
    verthys_secure_zero(mk, sizeof mk);
    return 0;
}

/* DEK 生成：两次生成应不同（极大概率） */
TEST(dek_generate_random)
{
    uint8_t d1[VERTHYS_KEY_BYTES], d2[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(d1);
    keymanager_generate_dek(d2);
    CHECK(memcmp(d1, d2, VERTHYS_KEY_BYTES) != 0);
    verthys_secure_zero(d1, sizeof d1);
    verthys_secure_zero(d2, sizeof d2);
    return 0;
}

/* DEK 包裹往返：wrap → unwrap 还原原 DEK */
TEST(dek_wrap_roundtrip)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_master(mk, (const uint8_t *)"pw", 2, salt), 0);

    uint8_t dek[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t nonce[VERTHYS_AEAD_NONCE_BYTES];
    CHECK_EQ(keymanager_wrap_dek(wrapped, nonce, dek, mk), 0);

    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_unwrap_dek(dek_recovered, wrapped, nonce, mk), 0);
    CHECK(memcmp(dek, dek_recovered, VERTHYS_KEY_BYTES) == 0);

    /* wrapped 应不同于明文 DEK（已加密） */
    CHECK(memcmp(dek, wrapped, VERTHYS_KEY_BYTES) != 0);

    verthys_secure_zero(mk, sizeof mk);
    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(dek_recovered, sizeof dek_recovered);
    return 0;
}

/* 错误 MEK 解包必失败（认证失败 → 不返回任何 DEK） */
TEST(dek_unwrap_wrong_master_fails)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk_correct[VERTHYS_KEY_BYTES], mk_wrong[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_master(mk_correct, (const uint8_t *)"correct", 7, salt), 0);
    CHECK_EQ(keymanager_derive_master(mk_wrong, (const uint8_t *)"WRONG!!", 7, salt), 0);

    uint8_t dek[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t nonce[VERTHYS_AEAD_NONCE_BYTES];
    CHECK_EQ(keymanager_wrap_dek(wrapped, nonce, dek, mk_correct), 0);

    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK(keymanager_unwrap_dek(dek_recovered, wrapped, nonce, mk_wrong) != 0);

    verthys_secure_zero(mk_correct, sizeof mk_correct);
    verthys_secure_zero(mk_wrong, sizeof mk_wrong);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* wrapped 篡改 → 解包必失败 */
TEST(dek_unwrap_tampered_fails)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_master(mk, (const uint8_t *)"pw", 2, salt), 0);

    uint8_t dek[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t nonce[VERTHYS_AEAD_NONCE_BYTES];
    CHECK_EQ(keymanager_wrap_dek(wrapped, nonce, dek, mk), 0);

    /* 翻转密文首字节 */
    wrapped[0] ^= 0x01;
    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK(keymanager_unwrap_dek(dek_recovered, wrapped, nonce, mk) != 0);

    verthys_secure_zero(mk, sizeof mk);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* MAC 篡改 → 解包必失败 */
TEST(dek_unwrap_tampered_mac_fails)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_master(mk, (const uint8_t *)"pw", 2, salt), 0);

    uint8_t dek[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t nonce[VERTHYS_AEAD_NONCE_BYTES];
    CHECK_EQ(keymanager_wrap_dek(wrapped, nonce, dek, mk), 0);

    /* 翻转 MAC 末字节 */
    wrapped[VERTHYS_DEK_WRAPPED_BYTES - 1] ^= 0x80;
    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK(keymanager_unwrap_dek(dek_recovered, wrapped, nonce, mk) != 0);

    verthys_secure_zero(mk, sizeof mk);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* wrap 两次 nonce 应不同（极大概率） */
TEST(dek_wrap_nonce_unique)
{
    static const uint8_t salt[VERTHYS_SALT_BYTES] = {0};
    uint8_t mk[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_master(mk, (const uint8_t *)"pw", 2, salt), 0);

    uint8_t dek[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    uint8_t w1[VERTHYS_DEK_WRAPPED_BYTES], n1[VERTHYS_AEAD_NONCE_BYTES];
    uint8_t w2[VERTHYS_DEK_WRAPPED_BYTES], n2[VERTHYS_AEAD_NONCE_BYTES];
    CHECK_EQ(keymanager_wrap_dek(w1, n1, dek, mk), 0);
    CHECK_EQ(keymanager_wrap_dek(w2, n2, dek, mk), 0);
    CHECK(memcmp(n1, n2, VERTHYS_AEAD_NONCE_BYTES) != 0);
    /* 密文也应不同（nonce 不同） */
    CHECK(memcmp(w1, w2, VERTHYS_DEK_WRAPPED_BYTES) != 0);

    verthys_secure_zero(mk, sizeof mk);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* 记录级密钥：同一 DEK + 同一 ID → 同结果（确定性） */
TEST(record_key_derive_deterministic)
{
    uint8_t dek[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    uint8_t rk1[VERTHYS_KEY_BYTES], rk2[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_record_key(rk1, dek, (const uint8_t *)"rec1", 4), 0);
    CHECK_EQ(keymanager_derive_record_key(rk2, dek, (const uint8_t *)"rec1", 4), 0);
    CHECK(memcmp(rk1, rk2, VERTHYS_KEY_BYTES) == 0);

    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(rk1, sizeof rk1);
    verthys_secure_zero(rk2, sizeof rk2);
    return 0;
}

/* 记录级密钥：不同 ID → 不同密钥；不同 DEK → 不同密钥 */
TEST(record_key_id_and_dek_sensitive)
{
    uint8_t dek1[VERTHYS_KEY_BYTES], dek2[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek1);
    keymanager_generate_dek(dek2);

    uint8_t ra[VERTHYS_KEY_BYTES], rb[VERTHYS_KEY_BYTES], rc[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_derive_record_key(ra, dek1, (const uint8_t *)"rec1", 4), 0);
    CHECK_EQ(keymanager_derive_record_key(rb, dek1, (const uint8_t *)"rec2", 4), 0);
    CHECK_EQ(keymanager_derive_record_key(rc, dek2, (const uint8_t *)"rec1", 4), 0);

    CHECK(memcmp(ra, rb, VERTHYS_KEY_BYTES) != 0); /* 同 DEK 不同 ID */
    CHECK(memcmp(ra, rc, VERTHYS_KEY_BYTES) != 0); /* 不同 DEK 同 ID */

    verthys_secure_zero(dek1, sizeof dek1);
    verthys_secure_zero(dek2, sizeof dek2);
    verthys_secure_zero(ra, sizeof ra);
    verthys_secure_zero(rb, sizeof rb);
    verthys_secure_zero(rc, sizeof rc);
    return 0;
}

/* 记录级密钥派生：拒绝空指针 */
TEST(record_key_rejects_null)
{
    uint8_t dek[VERTHYS_KEY_BYTES], rk[VERTHYS_KEY_BYTES];
    keymanager_generate_dek(dek);

    CHECK(keymanager_derive_record_key(NULL, dek, (const uint8_t *)"x", 1) != 0);
    CHECK(keymanager_derive_record_key(rk, NULL, (const uint8_t *)"x", 1) != 0);
    /* record_id NULL + 非零长度 → 非法 */
    CHECK(keymanager_derive_record_key(rk, dek, NULL, 5) != 0);
    /* 空记录 ID 应允许 */
    CHECK_EQ(keymanager_derive_record_key(rk, dek, NULL, 0), 0);

    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(rk, sizeof rk);
    return 0;
}
