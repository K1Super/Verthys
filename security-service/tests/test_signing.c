/*
 * test_signing.c — U2：SHA-256 / HMAC / ECDSA P-256 响应签名
 */
#include "test_common.h"
#include "state_crypto.h"
#include "service_util.h"

#include <string.h>

static void test_sha256_vector(void)
{
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest[32];

    CHECK_EQ_INT(vty_sha256((const uint8_t *)"abc", 3u, digest), 0);
    CHECK(memcmp(digest, expected, sizeof(expected)) == 0);
}

static void test_hmac(void)
{
    uint8_t key1[32];
    uint8_t key2[32];
    uint8_t mac1[32];
    uint8_t mac2[32];
    uint8_t mac3[32];
    size_t i;

    for (i = 0; i < 32u; i++) {
        key1[i] = (uint8_t)(i + 1u);
        key2[i] = (uint8_t)(i + 3u);
    }
    CHECK_EQ_INT(vty_hmac_sha256(key1, (const uint8_t *)"hmac-test", 9u,
                                 mac1),
                 0);
    CHECK_EQ_INT(vty_hmac_sha256(key1, (const uint8_t *)"hmac-test", 9u,
                                 mac2),
                 0);
    CHECK(memcmp(mac1, mac2, 32u) == 0);
    CHECK_EQ_INT(vty_hmac_sha256(key2, (const uint8_t *)"hmac-test", 9u,
                                 mac3),
                 0);
    CHECK(memcmp(mac1, mac3, 32u) != 0);
    CHECK_EQ_INT(vty_hmac_sha256(key1, (const uint8_t *)"hmac-test!", 10u,
                                 mac3),
                 0);
    CHECK(memcmp(mac1, mac3, 32u) != 0);
}

static void test_random(void)
{
    uint8_t a[32];
    uint8_t b[32];

    CHECK_EQ_INT(vty_random_bytes(a, sizeof(a)), 0);
    CHECK_EQ_INT(vty_random_bytes(b, sizeof(b)), 0);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

static void test_ecdsa(void)
{
    uint8_t priv[VTY_ECC_BLOB_MAX];
    uint8_t pub[VTY_ECC_BLOB_MAX];
    uint8_t wrong_priv[VTY_ECC_BLOB_MAX];
    uint8_t wrong_pub[VTY_ECC_BLOB_MAX];
    DWORD priv_len = 0;
    DWORD pub_len = 0;
    DWORD wrong_priv_len = 0;
    DWORD wrong_pub_len = 0;
    uint8_t header[64];
    uint8_t hash[32];
    uint8_t sig[VTY_ECC_SIGNATURE_BYTES];
    BCRYPT_KEY_HANDLE key = NULL;
    size_t i;

    for (i = 0; i < sizeof(header); i++) {
        header[i] = (uint8_t)i;
    }
    CHECK_EQ_INT(vty_ecc_generate_keypair(priv, &priv_len, sizeof(priv),
                                          pub, &pub_len, sizeof(pub)),
                 0);
    CHECK(priv_len > 0 && priv_len <= sizeof(priv));
    CHECK(pub_len > 0 && pub_len <= sizeof(pub));
    CHECK_EQ_INT(vty_ecc_load_private(priv, priv_len, &key), 0);
    CHECK_EQ_INT(vty_sha256(header, sizeof(header), hash), 0);
    CHECK_EQ_INT(vty_ecc_sign(key, hash, sig), 0);
    CHECK_EQ_INT(vty_ecc_verify(pub, pub_len, hash, sig), 0);

    sig[0] ^= 0x01u;
    CHECK(vty_ecc_verify(pub, pub_len, hash, sig) != 0);
    sig[0] ^= 0x01u;

    hash[0] ^= 0x01u;
    CHECK(vty_ecc_verify(pub, pub_len, hash, sig) != 0);
    hash[0] ^= 0x01u;

    CHECK_EQ_INT(vty_ecc_generate_keypair(wrong_priv, &wrong_priv_len,
                                          sizeof(wrong_priv), wrong_pub,
                                          &wrong_pub_len, sizeof(wrong_pub)),
                 0);
    CHECK(vty_ecc_verify(wrong_pub, wrong_pub_len, hash, sig) != 0);

    vty_ecc_free_key(&key);
    vty_secure_zero(priv, sizeof(priv));
    vty_secure_zero(wrong_priv, sizeof(wrong_priv));
}

static void test_const_time(void)
{
    uint8_t a[32];
    uint8_t b[32];
    size_t i;

    for (i = 0; i < 32u; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }
    CHECK_EQ_INT(vty_const_time_equal(a, b, 32u), 1);
    b[31] ^= 0x01u;
    CHECK_EQ_INT(vty_const_time_equal(a, b, 32u), 0);
}

int test_signing_run(void)
{
    printf("[ U2 ] response signing primitives\n");
    test_sha256_vector();
    test_hmac();
    test_random();
    test_ecdsa();
    test_const_time();
    return g_test_failures;
}
