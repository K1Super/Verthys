/*
 * test_key_separation.c — 方案 4.1/§6.2 配套测试：CNG 内核托管密钥
 *
 * 覆盖（方案 §8.2 新增测试清单）：
 *   - init/install/aead 往返（AES-256-GCM 内核态运算）
 *   - C 角色（超级块密钥）休眠强制：激活前 AEAD 拒绝
 *   - install 消费密钥缓冲（明文即刻清零契约）
 *   - any_installed 查询（defense_closure MEM_DUMP 判据）
 *   - purge_all 后句柄失效（AEAD 拒绝）
 */
#include "verthys_test.h"
#include "verthys.h"
#include "key_separation.h"

#include <string.h>

static uint8_t t_key_a[32] = {
    0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,
    0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0
};
static uint8_t t_key_b[32] = {
    0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,0xD0,
    0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,0xE0
};
static uint8_t t_key_c[32] = {
    0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0,
    0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0x00
};

/* A 角色 AEAD 加解密往返 */
TEST(keysep_aead_roundtrip)
{
    uint8_t key_copy[32];
    memcpy(key_copy, t_key_a, 32);
    CHECK_EQ(key_separation_install(KEY_ROLE_INDEX, key_copy), 0);
    /* install 消费调用方缓冲（明文即刻清零契约） */
    uint8_t zero[32] = {0};
    CHECK(memcmp(key_copy, zero, 32) == 0);
    CHECK_EQ(key_separation_any_installed(), 1);

    uint8_t nonce[KEYSEP_AEAD_NONCE_BYTES] = {
        1,2,3,4,5,6,7,8,9,10,11,12
    };
    const char *ad = "verthys/test/a";
    const uint8_t pt[] = "key separation roundtrip payload";
    uint8_t ct[128];
    size_t ct_len = sizeof(ct);
    CHECK_EQ(key_separation_aead_encrypt(KEY_ROLE_INDEX, nonce,
                                         (const uint8_t *)ad, strlen(ad),
                                         pt, sizeof(pt), ct, &ct_len), 0);
    CHECK_EQ(ct_len, sizeof(pt) + KEYSEP_AEAD_TAG_BYTES);

    uint8_t rt[128];
    size_t rt_len = sizeof(rt);
    CHECK_EQ(key_separation_aead_decrypt(KEY_ROLE_INDEX, nonce,
                                         (const uint8_t *)ad, strlen(ad),
                                         ct, ct_len, rt, &rt_len), 0);
    CHECK_EQ(rt_len, sizeof(pt));
    CHECK(memcmp(rt, pt, sizeof(pt)) == 0);

    /* 篡改密文 → 认证失败 */
    ct[0] ^= 0x01;
    CHECK(key_separation_aead_decrypt(KEY_ROLE_INDEX, nonce,
                                      (const uint8_t *)ad, strlen(ad),
                                      ct, ct_len, rt, &rt_len) != 0);

    key_separation_purge_all();
    CHECK_EQ(key_separation_any_installed(), 0);
    return 0;
}

/* C 角色休眠强制：激活前 AEAD 拒绝；激活后可用 */
TEST(keysep_commit_sleep_enforced)
{
    uint8_t key_copy[32];
    memcpy(key_copy, t_key_c, 32);
    CHECK_EQ(key_separation_install(KEY_ROLE_COMMIT, key_copy), 0);

    uint8_t nonce[KEYSEP_AEAD_NONCE_BYTES] = { 9,8,7,6,5,4,3,2,1,0,1,2 };
    uint8_t pt[16] = "commit payload";
    uint8_t ct[64];
    size_t ct_len = sizeof(ct);

    /* 休眠态：AEAD 必须拒绝（逻辑隔离等价旧版 PAGE_NOACCESS） */
    CHECK(key_separation_aead_encrypt(KEY_ROLE_COMMIT, nonce, NULL, 0,
                                      pt, sizeof(pt), ct, &ct_len) != 0);
    CHECK_EQ(key_separation_activate_commit(), 0);
    CHECK_EQ(key_separation_aead_encrypt(KEY_ROLE_COMMIT, nonce, NULL, 0,
                                         pt, sizeof(pt), ct, &ct_len), 0);
    CHECK_EQ(key_separation_deactivate_commit(), 0);
    CHECK(key_separation_aead_encrypt(KEY_ROLE_COMMIT, nonce, NULL, 0,
                                      pt, sizeof(pt), ct, &ct_len) != 0);

    key_separation_purge_all();
    return 0;
}

/* purge_all 后 AEAD 拒绝（句柄失效） */
TEST(keysep_purge_invalidates)
{
    uint8_t key_copy[32];
    memcpy(key_copy, t_key_b, 32);
    CHECK_EQ(key_separation_install(KEY_ROLE_DATA, key_copy), 0);

    uint8_t nonce[KEYSEP_AEAD_NONCE_BYTES] = { 1,1,2,2,3,3,4,4,5,5,6,6 };
    uint8_t pt[8] = "payload";
    uint8_t ct[64];
    size_t ct_len = sizeof(ct);
    CHECK_EQ(key_separation_aead_encrypt(KEY_ROLE_DATA, nonce, NULL, 0,
                                         pt, sizeof(pt), ct, &ct_len), 0);

    key_separation_purge_all();
    CHECK(key_separation_aead_encrypt(KEY_ROLE_DATA, nonce, NULL, 0,
                                      pt, sizeof(pt), ct, &ct_len) != 0);
    return 0;
}
