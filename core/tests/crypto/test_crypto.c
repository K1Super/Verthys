/*
 * test_crypto.c — XChaCha20-Poly1305 AEAD 原语测试
 * 通过 verthys_crypto 内部接口验证行为（内部测试缝，符合深模块设计）。
 */
#include "verthys_test.h"
#include "verthys_crypto.h"
#include <string.h>

/* 加解密往返：解密结果 == 原始明文，密文含 16 字节 MAC */
TEST(aead_roundtrip)
{
    uint8_t key[VERTHYS_KEY_BYTES], nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(key, sizeof key);
    verthys_random_bytes(nonce, sizeof nonce);

    const uint8_t pt[] = "secret photo bytes";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ad[] = {0x01, 0x02, 0x03};
    uint8_t ct[64], out[64];
    size_t ct_len = 0, out_len = 0;

    CHECK(verthys_aead_encrypt(key, nonce, ad, sizeof ad, pt, pt_len, ct, &ct_len) == 0);
    CHECK_EQ(ct_len, pt_len + VERTHYS_AEAD_MAC_BYTES);

    CHECK(verthys_aead_decrypt(key, nonce, ad, sizeof ad, ct, ct_len, out, &out_len) == 0);
    CHECK_EQ(out_len, pt_len);
    CHECK(memcmp(out, pt, pt_len) == 0);
    return 0;
}

/* 篡改密文：解密必须失败（认证标签不匹配） */
TEST(aead_tamper_fails)
{
    uint8_t key[VERTHYS_KEY_BYTES], nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(key, sizeof key);
    verthys_random_bytes(nonce, sizeof nonce);

    const uint8_t pt[] = "integrity check";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ct[64], out[64];
    size_t ct_len = 0, out_len = 0;

    CHECK(verthys_aead_encrypt(key, nonce, NULL, 0, pt, pt_len, ct, &ct_len) == 0);
    ct[0] ^= 0xFF;  /* 翻转首个密文字节 */

    CHECK(verthys_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, out, &out_len) != 0);
    return 0;
}

/* 篡改认证标签：解密必须失败 */
TEST(aead_tamper_mac_fails)
{
    uint8_t key[VERTHYS_KEY_BYTES], nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(key, sizeof key);
    verthys_random_bytes(nonce, sizeof nonce);

    const uint8_t pt[] = "mac check";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ct[64], out[64];
    size_t ct_len = 0, out_len = 0;

    CHECK(verthys_aead_encrypt(key, nonce, NULL, 0, pt, pt_len, ct, &ct_len) == 0);
    ct[ct_len - 1] ^= 0x01;  /* 翻转标签末字节 */

    CHECK(verthys_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, out, &out_len) != 0);
    return 0;
}

/* 错误密钥：解密必须失败 */
TEST(aead_wrong_key_fails)
{
    uint8_t key[VERTHYS_KEY_BYTES], wrong[VERTHYS_KEY_BYTES], nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(key, sizeof key);
    verthys_random_bytes(wrong, sizeof wrong);
    verthys_random_bytes(nonce, sizeof nonce);

    const uint8_t pt[] = "key check";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ct[64], out[64];
    size_t ct_len = 0, out_len = 0;

    CHECK(verthys_aead_encrypt(key, nonce, NULL, 0, pt, pt_len, ct, &ct_len) == 0);
    CHECK(verthys_aead_decrypt(wrong, nonce, NULL, 0, ct, ct_len, out, &out_len) != 0);
    return 0;
}

/* 关联数据 AD 不匹配：解密必须失败 */
TEST(aead_wrong_ad_fails)
{
    uint8_t key[VERTHYS_KEY_BYTES], nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(key, sizeof key);
    verthys_random_bytes(nonce, sizeof nonce);

    const uint8_t pt[] = "ad check";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ad[] = {0xAA}, bad_ad[] = {0xBB};
    uint8_t ct[64], out[64];
    size_t ct_len = 0, out_len = 0;

    CHECK(verthys_aead_encrypt(key, nonce, ad, sizeof ad, pt, pt_len, ct, &ct_len) == 0);
    CHECK(verthys_aead_decrypt(key, nonce, bad_ad, sizeof bad_ad, ct, ct_len, out, &out_len) != 0);
    return 0;
}

/* CSPRNG 唯一性：两次调用产生不同 nonce */
TEST(random_bytes_unique)
{
    uint8_t a[VERTHYS_AEAD_NONCE_BYTES], b[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(a, sizeof a);
    verthys_random_bytes(b, sizeof b);
    CHECK(memcmp(a, b, sizeof a) != 0);
    return 0;
}

/* 空明文也能加解密（边界） */
TEST(aead_empty_plaintext)
{
    uint8_t key[VERTHYS_KEY_BYTES], nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(key, sizeof key);
    verthys_random_bytes(nonce, sizeof nonce);
    uint8_t ct[VERTHYS_AEAD_MAC_BYTES], out[8];
    size_t ct_len = 0, out_len = 0;

    CHECK(verthys_aead_encrypt(key, nonce, NULL, 0, NULL, 0, ct, &ct_len) == 0);
    CHECK_EQ(ct_len, VERTHYS_AEAD_MAC_BYTES);
    CHECK(verthys_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, out, &out_len) == 0);
    CHECK_EQ(out_len, 0u);
    return 0;
}
