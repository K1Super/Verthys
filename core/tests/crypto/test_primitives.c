/*
 * test_primitives.c — 密码学原语与恢复码闭环验收
 *
 * 覆盖：
 *   - BLAKE3 已知向量（空串 / "abc"）
 *   - HKDF-SHA256 RFC 5869 用例 1（32B PRK → 32B 输出）
 *   - HMAC-SHA256 确定性、密钥敏感性与密钥长度门
 *   - Argon2id 确定性与盐敏感性、参数下限拒绝
 *   - XChaCha20-Poly1305 密钥包裹往返与篡改拒绝
 *   - 恢复码格式化 / 解析 / 校验位 / 超长后缀
 *   - Keyring 序列化往返与非法结构拒绝
 *   - 恢复槽封装与解包
 *
 * 为什么用已知向量而不是“加密后再解密”：往返只能证明自洽，无法发现
 * 与规范漂移；已知向量能在算法实现被替换/误改时立刻失配。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_blake3.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_recovery.h"

#include <string.h>
#include <stdlib.h>

static int hex_to_bytes(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex);
    size_t i;

    if (n % 2u != 0 || n / 2u > cap) return 1;
    for (i = 0; i < n / 2u; i++) {
        unsigned int v = 0;
        if (sscanf(hex + i * 2u, "%2x", &v) != 1) return 1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

TEST(blake3_known_vectors)
{
    uint8_t out[VTY_HASH_BYTES];
    uint8_t expect[VTY_HASH_BYTES];

    CHECK_EQ(vty_blake3_32((const uint8_t *)"", 0, out), VTY_OK);
    CHECK_EQ(hex_to_bytes(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        expect, sizeof(expect)), 0);
    CHECK_EQ(memcmp(out, expect, VTY_HASH_BYTES), 0);

    CHECK_EQ(vty_blake3_32((const uint8_t *)"abc", 3, out), VTY_OK);
    CHECK_EQ(hex_to_bytes(
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        expect, sizeof(expect)), 0);
    CHECK_EQ(memcmp(out, expect, VTY_HASH_BYTES), 0);
    return 0;
}

TEST(hkdf_rfc5869_case1)
{
    /* RFC 5869 A.1：PRK 与 OKM 前 32 字节 */
    uint8_t prk[VTY_KEY_BYTES];
    uint8_t info[10];
    uint8_t out[VTY_KEY_BYTES];
    uint8_t expect[VTY_KEY_BYTES];
    size_t i;

    CHECK_EQ(hex_to_bytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        prk, sizeof(prk)), 0);
    for (i = 0; i < sizeof(info); i++) info[i] = (uint8_t)(0xf0u + i);

    CHECK_EQ(vty_hkdf_expand(out, prk, info, sizeof(info)), VTY_OK);
    CHECK_EQ(hex_to_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        expect, sizeof(expect)), 0);
    CHECK_EQ(memcmp(out, expect, VTY_KEY_BYTES), 0);
    return 0;
}

TEST(hmac_deterministic_and_key_sensitive)
{
    uint8_t key[VTY_KEY_BYTES];
    uint8_t key2[VTY_KEY_BYTES];
    uint8_t a[VTY_HASH_BYTES];
    uint8_t b[VTY_HASH_BYTES];

    memset(key, 0x0b, sizeof(key));
    memset(key2, 0x0c, sizeof(key2));

    CHECK_EQ(vty_hmac_sha256(a, key, sizeof(key),
                             (const uint8_t *)"Hi There", 8), VTY_OK);
    CHECK_EQ(vty_hmac_sha256(b, key, sizeof(key),
                             (const uint8_t *)"Hi There", 8), VTY_OK);
    CHECK_EQ(memcmp(a, b, VTY_HASH_BYTES), 0);

    CHECK_EQ(vty_hmac_sha256(b, key2, sizeof(key2),
                             (const uint8_t *)"Hi There", 8), VTY_OK);
    CHECK(memcmp(a, b, VTY_HASH_BYTES) != 0);

    /* 只接受 32B 密钥：20B 必须拒绝，避免短密钥被静默补齐 */
    CHECK_EQ(vty_hmac_sha256(b, key, 20,
                             (const uint8_t *)"Hi There", 8), VTY_E_INVALID);
    return 0;
}

TEST(argon2id_deterministic_and_salt_sensitive)
{
    uint8_t salt1[VTY_SALT_BYTES];
    uint8_t salt2[VTY_SALT_BYTES];
    uint8_t k1[VTY_KEY_BYTES];
    uint8_t k2[VTY_KEY_BYTES];
    const char *pwd = "correct horse battery staple";

    memset(salt1, 0x11, sizeof(salt1));
    memset(salt2, 0x11, sizeof(salt2));
    salt2[0] ^= 0x01u;

    CHECK_EQ(vty_kdf_argon2id(k1, (const uint8_t *)pwd, strlen(pwd), salt1,
                              VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN,
                              VTY_ARGON2_PARALLEL_MIN), VTY_OK);
    CHECK_EQ(vty_kdf_argon2id(k2, (const uint8_t *)pwd, strlen(pwd), salt1,
                              VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN,
                              VTY_ARGON2_PARALLEL_MIN), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);

    CHECK_EQ(vty_kdf_argon2id(k2, (const uint8_t *)pwd, strlen(pwd), salt2,
                              VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN,
                              VTY_ARGON2_PARALLEL_MIN), VTY_OK);
    CHECK(memcmp(k1, k2, VTY_KEY_BYTES) != 0);

    /* 口令敏感 */
    CHECK_EQ(vty_kdf_argon2id(k2, (const uint8_t *)"wrong", 5, salt1,
                              VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN,
                              VTY_ARGON2_PARALLEL_MIN), VTY_OK);
    CHECK(memcmp(k1, k2, VTY_KEY_BYTES) != 0);
    return 0;
}

TEST(kdf_param_floor_rejected)
{
    uint8_t out[VTY_KEY_BYTES];
    uint8_t salt[VTY_SALT_BYTES];

    memset(salt, 0x22, sizeof(salt));

    CHECK_EQ(vty_kdf_params_valid(VTY_ARGON2_MEM_KIB_MIN,
                                  VTY_ARGON2_ITERS_MIN,
                                  VTY_ARGON2_PARALLEL_MIN), VTY_OK);
    CHECK_EQ(vty_kdf_params_valid(VTY_ARGON2_MEM_KIB_MIN - 1u, 3, 1),
             VTY_E_KDF_WEAK);
    CHECK_EQ(vty_kdf_params_valid(VTY_ARGON2_MEM_KIB_MIN, 2, 1),
             VTY_E_KDF_WEAK);
    CHECK_EQ(vty_kdf_params_valid(VTY_ARGON2_MEM_KIB_MIN, 3, 0),
             VTY_E_KDF_WEAK);
    CHECK_EQ(vty_kdf_params_valid(VTY_ARGON2_MEM_KIB_MIN, 3, 65),
             VTY_E_KDF_WEAK);

    /* 弱参数必须在派生入口被拒绝，而不是只靠上层自觉 */
    CHECK_EQ(vty_kdf_argon2id(out, (const uint8_t *)"pw", 2, salt,
                              VTY_ARGON2_MEM_KIB_MIN - 1u, 3, 1),
             VTY_E_KDF_WEAK);
    return 0;
}

TEST(wrap_key32_roundtrip_and_tamper)
{
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t wrong[VTY_KEY_BYTES];
    uint8_t key[VTY_KEY_BYTES];
    uint8_t nonce[VTY_NONCE_BYTES];
    uint8_t ct[VTY_KEY_BYTES + VTY_TAG_BYTES];
    uint8_t back[VTY_KEY_BYTES];

    memset(kek, 0x33, sizeof(kek));
    memset(wrong, 0x34, sizeof(wrong));
    memset(key, 0x35, sizeof(key));

    CHECK_EQ(vty_wrap_key32(kek, key, (const uint8_t *)"aad", 3, nonce, ct),
             VTY_OK);
    CHECK_EQ(vty_unwrap_key32(kek, nonce, (const uint8_t *)"aad", 3,
                              ct, sizeof(ct), back), VTY_OK);
    CHECK_EQ(memcmp(back, key, VTY_KEY_BYTES), 0);

    CHECK(vty_unwrap_key32(wrong, nonce, (const uint8_t *)"aad", 3,
                           ct, sizeof(ct), back) != VTY_OK);
    CHECK(vty_unwrap_key32(kek, nonce, (const uint8_t *)"bad", 3,
                           ct, sizeof(ct), back) != VTY_OK);

    ct[0] ^= 0x01u;
    CHECK(vty_unwrap_key32(kek, nonce, (const uint8_t *)"aad", 3,
                           ct, sizeof(ct), back) != VTY_OK);
    return 0;
}

TEST(recovery_code_roundtrip)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t back[VTY_RECOVERY_CODE_BYTES];
    char text[VTY_RECOVERY_TEXT_BUF];

    CHECK_EQ(vty_recovery_generate(code, text, sizeof(text)), VTY_OK);
    CHECK_EQ(strlen(text), 69u);
    CHECK_EQ(vty_recovery_verify(text), VTY_OK);
    CHECK_EQ(vty_recovery_decode(text, back), VTY_OK);
    CHECK_EQ(memcmp(code, back, VTY_RECOVERY_CODE_BYTES), 0);

    /* 大小写、空格、连字符容错；易混字符 I/L→1、O→0 */
    {
        char lower[VTY_RECOVERY_TEXT_BUF];
        size_t i;
        for (i = 0; text[i] != '\0'; i++) {
            char c = text[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            lower[i] = c;
        }
        lower[i] = '\0';
        CHECK_EQ(vty_recovery_decode(lower, back), VTY_OK);
        CHECK_EQ(memcmp(code, back, VTY_RECOVERY_CODE_BYTES), 0);
    }
    return 0;
}

TEST(recovery_checksum_error_rejected)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t back[VTY_RECOVERY_CODE_BYTES];
    char text[VTY_RECOVERY_TEXT_BUF];
    size_t n;

    CHECK_EQ(vty_recovery_generate(code, text, sizeof(text)), VTY_OK);

    /* 改动最后一组校验位中的一个字符：校验位必须立刻拒绝 */
    n = strlen(text);
    text[n - 1] = (text[n - 1] == '0') ? '1' : '0';
    CHECK_EQ(vty_recovery_decode(text, back), VTY_E_INVALID);

    /* 改动数据区一个字符：由校验位发现抄写错误 */
    CHECK_EQ(vty_recovery_generate(code, text, sizeof(text)), VTY_OK);
    text[0] = (text[0] == '0') ? '1' : '0';
    CHECK_EQ(vty_recovery_decode(text, back), VTY_E_INVALID);
    return 0;
}

TEST(recovery_suffix_rejected)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t back[VTY_RECOVERY_CODE_BYTES];
    char text[VTY_RECOVERY_TEXT_BUF + 8];
    size_t n;

    CHECK_EQ(vty_recovery_generate(code, text, VTY_RECOVERY_TEXT_BUF), VTY_OK);
    n = strlen(text);
    /* 任意后缀都必须拒绝；截断式解析会静默接受攻击者追加的字符 */
    text[n] = '-';
    text[n + 1] = 'A';
    text[n + 2] = '\0';
    CHECK_EQ(vty_recovery_decode(text, back), VTY_E_INVALID);
    return 0;
}

static void keyring_fill(VtyKeyring *kr)
{
    memset(kr, 0, sizeof(*kr));
    kr->count = 4;
    kr->entries[0].kind = VTY_KEYKIND_KC;
    memset(kr->entries[0].key, 0xa1, VTY_KEY_BYTES);
    kr->entries[1].kind = VTY_KEYKIND_DATA_ROOT;
    kr->entries[1].id_len = VTY_DATA_ROOT_BYTES;
    memset(kr->entries[1].id, 0xa2, VTY_DATA_ROOT_BYTES);
    memset(kr->entries[1].key, 0xa7, VTY_KEY_BYTES);
    kr->entries[2].kind = VTY_KEYKIND_MDEK;
    kr->entries[2].id_len = VTY_UUID_BYTES;
    memset(kr->entries[2].id, 0xa3, VTY_UUID_BYTES);
    memset(kr->entries[2].key, 0xa4, VTY_KEY_BYTES);
    kr->entries[3].kind = VTY_KEYKIND_MDEK;
    kr->entries[3].id_len = VTY_UUID_BYTES;
    memset(kr->entries[3].id, 0xa5, VTY_UUID_BYTES);
    memset(kr->entries[3].key, 0xa6, VTY_KEY_BYTES);
}

TEST(keyring_serialize_parse_roundtrip)
{
    VtyKeyring kr;
    VtyKeyring back;
    uint8_t buf[VTY_KEYRING_MAX_BYTES];
    size_t len = 0;
    uint8_t key[VTY_KEY_BYTES];

    keyring_fill(&kr);
    CHECK_EQ(vty_keyring_serialize(&kr, buf, sizeof(buf), &len), VTY_OK);
    CHECK(len > 0 && len <= VTY_KEYRING_MAX_BYTES);
    CHECK_EQ(vty_keyring_parse(buf, len, &back), VTY_OK);
    CHECK_EQ(back.count, kr.count);
    CHECK_EQ(memcmp(back.entries, kr.entries,
                    sizeof(VtyKeyEntry) * kr.count), 0);

    CHECK_EQ(vty_keyring_find(&back, VTY_KEYKIND_KC, NULL, 0, key), VTY_OK);
    CHECK_EQ(key[0], 0xa1u);
    CHECK_EQ(vty_keyring_find(&back, VTY_KEYKIND_MDEK,
                              kr.entries[3].id, VTY_UUID_BYTES,
                              key), VTY_OK);
    CHECK_EQ(key[0], 0xa6u);
    CHECK(vty_keyring_find(&back, VTY_KEYKIND_MDEK,
                           kr.entries[2].id, VTY_UUID_BYTES,
                           key) == VTY_OK);

    /* DataRoot 必须能取到完整 32B locator，而不是只剩 key */
    {
        VtyKeyEntry e;
        memset(&e, 0, sizeof(e));
        CHECK_EQ(vty_keyring_find_entry(&back, VTY_KEYKIND_DATA_ROOT, NULL, 0, &e),
                 VTY_OK);
        CHECK_EQ(e.id_len, VTY_DATA_ROOT_BYTES);
        CHECK_EQ(memcmp(e.id, kr.entries[1].id, VTY_DATA_ROOT_BYTES), 0);
    }
    return 0;
}

TEST(keyring_parse_invalid_rejected)
{
    VtyKeyring back;
    uint8_t buf[256];
    size_t off = 1;

    /* 重复项：同一 kind + 同一 module uuid 不得重复出现 */
    memset(buf, 0, sizeof(buf));
    buf[0] = 2;
    buf[off++] = VTY_KEYKIND_KC;
    vty_put_u16(buf + off, 0); off += 2;
    buf[off++] = VTY_KEY_BYTES;
    memset(buf + off, 0x01, VTY_KEY_BYTES); off += VTY_KEY_BYTES;
    buf[off++] = VTY_KEYKIND_KC;
    vty_put_u16(buf + off, 0); off += 2;
    buf[off++] = VTY_KEY_BYTES;
    memset(buf + off, 0x02, VTY_KEY_BYTES); off += VTY_KEY_BYTES;
    CHECK_EQ(vty_keyring_parse(buf, off, &back), VTY_E_INVALID);

    /* MDEK 必须携带模块 UUID */
    memset(buf, 0, sizeof(buf));
    buf[0] = 1;
    off = 1;
    buf[off++] = VTY_KEYKIND_MDEK;
    vty_put_u16(buf + off, 0); off += 2;
    buf[off++] = VTY_KEY_BYTES;
    memset(buf + off, 0x03, VTY_KEY_BYTES); off += VTY_KEY_BYTES;
    CHECK_EQ(vty_keyring_parse(buf, off, &back), VTY_E_INVALID);

    /* 尾部多余字节 */
    keyring_fill(&back);
    {
        uint8_t big[VTY_KEYRING_MAX_BYTES + 1];
        size_t len = 0;
        CHECK_EQ(vty_keyring_serialize(&back, big, sizeof(big), &len), VTY_OK);
        big[len] = 0;
        CHECK_EQ(vty_keyring_parse(big, len + 1, &back), VTY_E_INVALID);
    }
    return 0;
}

TEST(recovery_slot_seal_open)
{
    VtyKeyring kr;
    VtyKeyring back;
    VtyHeader h;
    VtySlot slot;
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t other[VTY_RECOVERY_CODE_BYTES];
    char text[VTY_RECOVERY_TEXT_BUF];
    char other_text[VTY_RECOVERY_TEXT_BUF];

    memset(&h, 0, sizeof(h));
    memset(h.vault_uuid, 0x51, VTY_UUID_BYTES);
    h.epoch = 7;

    keyring_fill(&kr);
    CHECK_EQ(vty_recovery_generate(code, text, sizeof(text)), VTY_OK);
    CHECK_EQ(vty_recovery_slot_seal(&slot, kr.entries[0].key, code, &h, 2,
                                    VTY_ARGON2_MEM_KIB_MIN,
                                    VTY_ARGON2_ITERS_MIN, 1, NULL), VTY_OK);
    CHECK_EQ(slot.slot_type, VTY_SLOT_RECOVERY);
    CHECK_EQ(slot.ct_len, VTY_RECOVERY_PLAIN_BYTES + VTY_TAG_BYTES);

    /* 恢复槽只允许 K_c：不能顺带恢复 MDEK 或 DataRoot */
    CHECK_EQ(vty_recovery_slot_open(&slot, text, &h, 2, &back, NULL), VTY_OK);
    CHECK_EQ(back.count, 1u);
    CHECK_EQ(back.entries[0].kind, VTY_KEYKIND_KC);
    CHECK_EQ(memcmp(back.entries[0].key, kr.entries[0].key, VTY_KEY_BYTES), 0);

    /* AAD 绑定槽下标：换到别的下标必须失败 */
    CHECK(vty_recovery_slot_open(&slot, text, &h, 3, &back, NULL) != VTY_OK);

    /* 格式合法但内容不同的恢复码：不能靠“格式通过”就解包成功 */
    CHECK_EQ(vty_recovery_generate(other, other_text, sizeof(other_text)),
             VTY_OK);
    CHECK(vty_recovery_slot_open(&slot, other_text, &h, 2, &back, NULL) != VTY_OK);

    /* AAD 绑定 vault uuid / epoch：换头部字段必须解包失败 */
    h.epoch = 8;
    CHECK(vty_recovery_slot_open(&slot, text, &h, 2, &back, NULL) != VTY_OK);
    h.epoch = 7;
    h.vault_uuid[0] ^= 0x01u;
    CHECK(vty_recovery_slot_open(&slot, text, &h, 2, &back, NULL) != VTY_OK);
    return 0;
}
