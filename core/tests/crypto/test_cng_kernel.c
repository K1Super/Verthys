/*
 * test_cng_kernel.c — 验收：CNG 内核托管全量接线
 *
 * 覆盖：
 *   1. 导入/加解密 roundtrip（含空明文、AAD 绑定）
 *   2. nonce 单调性 + 唯一性 + 计数器恢复（防回退）
 *   3. 错误路径：篡改密文/标签、错误 AAD、错误密钥、句柄销毁后不可用
 *   4. keymanager_cng：批量导入（内核态解包）、状态机迁移、
 *      错误 MEK 整体回滚、wrapped 角色绑定、重入替换、句柄计数
 *   5. 失败路径密钥卫生：导入失败清零调用方缓冲、rotate_mek 失败旧槽
 *      原样驻留、长度域守卫（size_t→ULONG 截断防护）、共享提供者
 *      并发 init/deinit 压力（引用计数精确配对）
 */
#include "verthys_test.h"
#include "verthys_internal.h"
#include "verthys_crypto.h"
#include "verthys_crypto_cng.h"
#include "keymanager_cng.h"

#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <process.h>

/* ---------- 测试辅助 ---------- */

/*
 * 用临时 MEK 上下文内核态包裹子密钥（V3 wrapped 存储格式）。
 * 布局/AAD 构造与 keymanager_cng.c 完全一致：
 *   [12B nonce || 32B ct || 16B tag]，AAD = "verthys/wrap-v3" || role
 * 返回 0 成功。
 * 注意：verthys_cng_aead_import_key 会清零 key 入参，故先拷贝可清零副本。
 */
static int wrap_with_mek(const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
                         uint8_t role,
                         const uint8_t key[VERTHYS_CNG_KEY_BYTES],
                         uint8_t out[VERTHYS_CNG_WRAPPED_BYTES])
{
    static const uint8_t prefix[16] = {
        'v', 'e', 'r', 't', 'h', 'y', 's',
        '/', 'w', 'r', 'a', 'p', '-', 'v', '3'
    };
    uint8_t aad[17];
    uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t key_copy[VERTHYS_CNG_KEY_BYTES];
    VerthysCngAead m;
    size_t ctlen = VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES;
    int ok;

    memcpy(aad, prefix, sizeof(prefix));
    aad[16] = role;
    memcpy(mek_copy, mek, VERTHYS_CNG_KEY_BYTES);
    memcpy(key_copy, key, VERTHYS_CNG_KEY_BYTES);

    /* import_key 红线语义：清零入参密钥缓冲——必须传副本保护原件 */
    if (verthys_cng_aead_init(&m) != VERTHYS_OK ||
        verthys_cng_aead_import_key(&m, mek_copy, NULL) != VERTHYS_OK) {
        verthys_secure_zero(mek_copy, sizeof(mek_copy));
        verthys_secure_zero(key_copy, sizeof(key_copy));
        return -1;
    }
    ok = (verthys_cng_aead_encrypt(&m, key_copy, VERTHYS_CNG_KEY_BYTES,
                                 aad, sizeof(aad),
                                 out + VERTHYS_CNG_NONCE_BYTES, &ctlen,
                                 out) == VERTHYS_OK)
         && (ctlen == VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES);
    verthys_cng_aead_destroy(&m);
    verthys_secure_zero(mek_copy, sizeof(mek_copy));
    verthys_secure_zero(key_copy, sizeof(key_copy));
    return ok ? 0 : -1;
}

/* ---------- 1. AEAD 封装层 ---------- */

TEST(cng_aead_roundtrip)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES];
    uint8_t key_copy[VERTHYS_CNG_KEY_BYTES];
    const uint8_t aad[] = "verthys/test-v3";
    uint8_t pt[64], ct[64 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[64];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);
    unsigned i;

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));
    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 13 + 5);

    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    /* import 后 key_copy 已被清零（红线：明文仅存于 import 栈帧） */
    {
        uint8_t zero[VERTHYS_CNG_KEY_BYTES] = {0};
        CHECK(memcmp(key_copy, zero, sizeof(zero)) == 0);
    }
    CHECK(verthys_cng_aead_is_imported(&aead) == 1);

    CHECK(verthys_cng_aead_encrypt(&aead, pt, sizeof(pt), aad, sizeof(aad) - 1,
                                 ct, &ctlen, nonce) == VERTHYS_OK);
    CHECK(ctlen == sizeof(pt) + VERTHYS_CNG_TAG_BYTES);

    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen, aad, sizeof(aad) - 1,
                                 nonce, out, &outlen) == VERTHYS_OK);
    CHECK(outlen == sizeof(pt));
    CHECK(memcmp(out, pt, sizeof(pt)) == 0);

    verthys_cng_aead_destroy(&aead);
    CHECK(verthys_cng_aead_is_imported(&aead) == 0);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

/* ---------- init 契约回归（野句柄消毒） ---------- */

TEST(cng_aead_init_contract)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t ct[8 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    size_t ctlen = sizeof(ct);

    verthys_random_bytes(key, sizeof(key));

    /* 根因回归：未初始化栈内存（垃圾句柄模式）经 init 消毒后可安全导入。
     * 修复前：import_key 对垃圾 key 字段无条件 BCryptDestroyKey → 0xC0000005 */
    memset(&aead, 0xAA, sizeof(aead));
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_is_imported(&aead) == 0);
    CHECK(verthys_cng_aead_nonce_counter(&aead) == 0);

    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    CHECK(verthys_cng_aead_is_imported(&aead) == 1);

    /* destroy → init → 未导入态（init 不执行句柄销毁，契约第 2 条） */
    verthys_cng_aead_destroy(&aead);
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_is_imported(&aead) == 0);
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_LOCKED);

    /* 消毒 → 导入 → roundtrip 全链路无残留 */
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    ctlen = sizeof(ct);
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_OK);

    verthys_cng_aead_destroy(&aead);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_aead_empty_plaintext)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t ct[VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[8];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);

    /* 空明文：输出仅 16B 标签 */
    CHECK(verthys_cng_aead_encrypt(&aead, NULL, 0, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_OK);
    CHECK(ctlen == VERTHYS_CNG_TAG_BYTES);

    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen, NULL, 0,
                                 nonce, out, &outlen) == VERTHYS_OK);
    CHECK(outlen == 0);

    verthys_cng_aead_destroy(&aead);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_aead_nonce_unique_monotonic)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t last[VERTHYS_CNG_NONCE_BYTES] = {0};
    uint8_t ct[8 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    unsigned i;
    size_t ctlen = sizeof(ct);

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    CHECK(verthys_cng_aead_nonce_counter(&aead) == 0);

    for (i = 0; i < 100; i++) {
        ctlen = sizeof(ct);
        CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"abc", 3,
                                     NULL, 0, ct, &ctlen, nonce)
              == VERTHYS_OK);
        /* 12B 大端编码：严格递增（比较首差异字节） */
        CHECK(memcmp(nonce, last, VERTHYS_CNG_NONCE_BYTES) > 0);
        memcpy(last, nonce, VERTHYS_CNG_NONCE_BYTES);
    }
    CHECK(verthys_cng_aead_nonce_counter(&aead) == 100);

    verthys_cng_aead_destroy(&aead);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_aead_nonce_counter_restore)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t ct[8 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    size_t ctlen = sizeof(ct);

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);

    /* 模拟解锁恢复：计数器从持久化值继续（防回退语义） */
    CHECK(verthys_cng_aead_restore_nonce_counter(&aead, 1000) == VERTHYS_OK);
    CHECK(verthys_cng_aead_nonce_counter(&aead) == 1000);

    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1,
                                 NULL, 0, ct, &ctlen, nonce) == VERTHYS_OK);
    /* 下一个 nonce 必须从恢复值之后继续（counter=1001 → 大端编码低位 0xE9） */
    CHECK(nonce[VERTHYS_CNG_NONCE_BYTES - 1] == 0xE9);
    CHECK(verthys_cng_aead_nonce_counter(&aead) == 1001);

    /* 恢复值回退（小于当前值）必须被拒绝——历史 nonce 不得复用 */
    CHECK(verthys_cng_aead_restore_nonce_counter(&aead, 500)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_nonce_counter(&aead) == 1001);

    verthys_cng_aead_destroy(&aead);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_aead_tamper_rejected)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    const uint8_t aad[] = "verthys/test-v3";
    uint8_t pt[32], ct[32 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[32];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);
    unsigned i;

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));
    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i + 1);
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    CHECK(verthys_cng_aead_encrypt(&aead, pt, sizeof(pt), aad, sizeof(aad) - 1,
                                 ct, &ctlen, nonce) == VERTHYS_OK);

    /* 1) 篡改密文首字节 */
    ct[0] ^= 0x01;
    outlen = sizeof(out);
    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen, aad, sizeof(aad) - 1,
                                 nonce, out, &outlen) == VERTHYS_ERR_AUTH);
    ct[0] ^= 0x01;

    /* 2) 篡改标签 */
    ct[ctlen - 1] ^= 0x80;
    outlen = sizeof(out);
    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen, aad, sizeof(aad) - 1,
                                 nonce, out, &outlen) == VERTHYS_ERR_AUTH);
    ct[ctlen - 1] ^= 0x80;

    /* 3) 错误 AAD */
    outlen = sizeof(out);
    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen,
                                 (const uint8_t *)"other", 5,
                                 nonce, out, &outlen) == VERTHYS_ERR_AUTH);

    /* 4) 错误 nonce */
    nonce[0] ^= 0xFF;
    outlen = sizeof(out);
    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen, aad, sizeof(aad) - 1,
                                 nonce, out, &outlen) == VERTHYS_ERR_AUTH);
    nonce[0] ^= 0xFF;

    /* 原始密文仍可解（篡改均已复原） */
    outlen = sizeof(out);
    CHECK(verthys_cng_aead_decrypt(&aead, ct, ctlen, aad, sizeof(aad) - 1,
                                 nonce, out, &outlen) == VERTHYS_OK);

    verthys_cng_aead_destroy(&aead);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_aead_wrong_key_rejected)
{
    VerthysCngAead a, b;
    uint8_t key1[VERTHYS_CNG_KEY_BYTES], key2[VERTHYS_CNG_KEY_BYTES];
    uint8_t k1c[VERTHYS_CNG_KEY_BYTES], k2c[VERTHYS_CNG_KEY_BYTES];
    uint8_t pt[16], ct[16 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[16];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    verthys_random_bytes(key1, sizeof(key1));
    verthys_random_bytes(key2, sizeof(key2));
    memcpy(k1c, key1, sizeof(k1c));
    memcpy(k2c, key2, sizeof(k2c));

    CHECK(verthys_cng_aead_init(&a) == VERTHYS_OK);
    CHECK(verthys_cng_aead_init(&b) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&a, k1c, NULL) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&b, k2c, NULL) == VERTHYS_OK);

    CHECK(verthys_cng_aead_encrypt(&a, pt, sizeof(pt), NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_OK);
    /* 用另一把密钥解密 → 认证失败 */
    CHECK(verthys_cng_aead_decrypt(&b, ct, ctlen, NULL, 0,
                                 nonce, out, &outlen) == VERTHYS_ERR_AUTH);

    verthys_cng_aead_destroy(&a);
    verthys_cng_aead_destroy(&b);
    verthys_secure_zero(key1, sizeof(key1));
    verthys_secure_zero(key2, sizeof(key2));
    return 0;
}

TEST(cng_aead_destroy_invalidates)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t ct[8 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    size_t ctlen = sizeof(ct);

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    verthys_cng_aead_destroy(&aead);

    /* 句柄销毁后：任何 AEAD 运算必须失败（内核密钥材料已释放） */
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_LOCKED);

    /* 未导入上下文的运算同样拒绝 */
    {
        VerthysCngAead fresh;
        memset(&fresh, 0, sizeof(fresh));
        CHECK(verthys_cng_aead_encrypt(&fresh, (const uint8_t *)"x", 1, NULL, 0,
                                     ct, &ctlen, nonce) == VERTHYS_ERR_LOCKED);
    }

    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_aead_null_params_rejected)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t ct[8 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[8];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    verthys_random_bytes(key, sizeof(key));
    memcpy(key_copy, key, sizeof(key_copy));

    CHECK(verthys_cng_aead_init(NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_import_key(NULL, key_copy, NULL)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    CHECK(verthys_cng_aead_import_key(&aead, NULL, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);

    /* 加密参数校验 */
    CHECK(verthys_cng_aead_encrypt(NULL, (const uint8_t *)"x", 1, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                 NULL, &ctlen, nonce) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                 ct, NULL, nonce) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                 ct, &ctlen, NULL) == VERTHYS_ERR_INVALID);
    /* 容量不足 */
    {
        size_t small = 4;
        CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1, NULL, 0,
                                     ct, &small, nonce) == VERTHYS_ERR_INVALID);
    }

    /* 解密参数校验 */
    CHECK(verthys_cng_aead_decrypt(&aead, ct, 20, NULL, 0,
                                 NULL, out, &outlen) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_aead_decrypt(&aead, ct, 20, NULL, 0,
                                 nonce, NULL, &outlen) == VERTHYS_ERR_INVALID);
    /* 输入短于标签 */
    CHECK(verthys_cng_aead_decrypt(&aead, ct, VERTHYS_CNG_TAG_BYTES - 1, NULL, 0,
                                 nonce, out, &outlen) == VERTHYS_ERR_INVALID);

    verthys_cng_aead_destroy(&aead);
    verthys_cng_aead_destroy(NULL);  /* 幂等，不崩溃 */
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

/* ---------- 2. keymanager_cng：批量导入 + 生命周期 ---------- */

/* 构造一组随机密钥材料 + wrapped 三元组（mek/key_a/key_b/key_c 均为 32B 随机） */
static int km_build_keyset(uint8_t mek[VERTHYS_CNG_KEY_BYTES],
                           uint8_t ka[VERTHYS_CNG_KEY_BYTES],
                           uint8_t kb[VERTHYS_CNG_KEY_BYTES],
                           uint8_t kc[VERTHYS_CNG_KEY_BYTES],
                           uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES],
                           uint8_t wb[VERTHYS_CNG_WRAPPED_BYTES],
                           uint8_t wc[VERTHYS_CNG_WRAPPED_BYTES])
{
    verthys_random_bytes(mek, VERTHYS_CNG_KEY_BYTES);
    verthys_random_bytes(ka, VERTHYS_CNG_KEY_BYTES);
    verthys_random_bytes(kb, VERTHYS_CNG_KEY_BYTES);
    verthys_random_bytes(kc, VERTHYS_CNG_KEY_BYTES);
    if (wrap_with_mek(mek, (uint8_t)VERTHYS_CNG_KEY_A, ka, wa) != 0) return -1;
    if (wrap_with_mek(mek, (uint8_t)VERTHYS_CNG_KEY_B, kb, wb) != 0) return -1;
    if (wrap_with_mek(mek, (uint8_t)VERTHYS_CNG_KEY_C, kc, wc) != 0) return -1;
    return 0;
}

static void km_zero_keyset(uint8_t mek[VERTHYS_CNG_KEY_BYTES],
                           uint8_t ka[VERTHYS_CNG_KEY_BYTES],
                           uint8_t kb[VERTHYS_CNG_KEY_BYTES],
                           uint8_t kc[VERTHYS_CNG_KEY_BYTES])
{
    verthys_secure_zero(mek, VERTHYS_CNG_KEY_BYTES);
    verthys_secure_zero(ka, VERTHYS_CNG_KEY_BYTES);
    verthys_secure_zero(kb, VERTHYS_CNG_KEY_BYTES);
    verthys_secure_zero(kc, VERTHYS_CNG_KEY_BYTES);
}

TEST(km_batch_import_roundtrip)
{
    VerthysCngKeyManager km;
    uint8_t mek[VERTHYS_CNG_KEY_BYTES], ka[VERTHYS_CNG_KEY_BYTES],
            kb[VERTHYS_CNG_KEY_BYTES], kc[VERTHYS_CNG_KEY_BYTES];
    uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES], wb[VERTHYS_CNG_WRAPPED_BYTES],
            wc[VERTHYS_CNG_WRAPPED_BYTES];
    uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t pt[48], ct[48 + VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[48];
    size_t ctlen, outlen;
    unsigned i;

    CHECK(km_build_keyset(mek, ka, kb, kc, wa, wb, wc) == 0);
    memcpy(mek_copy, mek, sizeof(mek_copy));

    /* 状态机：init → UNINITIALIZED */
    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);
    CHECK(km.state == VERTHYS_CNG_KM_UNINITIALIZED);
    CHECK(verthys_cng_km_handle_count(&km) == 0);
    CHECK(verthys_cng_km_any_installed(&km) == 0);

    /* 批量导入（mek_copy 在 import 内部被清零——用副本保护原件） */
    CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_OK);
    CHECK(km.state == VERTHYS_CNG_KM_KERNEL_RESIDENT);
    CHECK(verthys_cng_km_handle_count(&km) == (int)VERTHYS_CNG_KEY_COUNT);
    CHECK(verthys_cng_km_any_installed(&km) == 1);
    {
        uint8_t zero[VERTHYS_CNG_KEY_BYTES] = {0};
        CHECK(memcmp(mek_copy, zero, sizeof(zero)) == 0);
    }

    /* 各角色均可内核态 AEAD roundtrip（V3 主路径语义） */
    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 7);
    {
        VerthysCngAead *pa = verthys_cng_km_get(&km, VERTHYS_CNG_KEY_A);
        VerthysCngAead *pb = verthys_cng_km_get(&km, VERTHYS_CNG_KEY_B);
        VerthysCngAead *pc = verthys_cng_km_get(&km, VERTHYS_CNG_KEY_C);
        CHECK(pa != NULL && pb != NULL && pc != NULL);

        ctlen = sizeof(ct); outlen = sizeof(out);
        CHECK(verthys_cng_aead_encrypt(pa, pt, sizeof(pt), NULL, 0,
                                     ct, &ctlen, nonce) == VERTHYS_OK);
        CHECK(verthys_cng_aead_decrypt(pa, ct, ctlen, NULL, 0,
                                     nonce, out, &outlen) == VERTHYS_OK);
        CHECK(memcmp(out, pt, sizeof(pt)) == 0);

        ctlen = sizeof(ct); outlen = sizeof(out);
        CHECK(verthys_cng_aead_encrypt(pb, pt, sizeof(pt), NULL, 0,
                                     ct, &ctlen, nonce) == VERTHYS_OK);
        CHECK(verthys_cng_aead_decrypt(pb, ct, ctlen, NULL, 0,
                                     nonce, out, &outlen) == VERTHYS_OK);
        CHECK(memcmp(out, pt, sizeof(pt)) == 0);

        ctlen = sizeof(ct); outlen = sizeof(out);
        CHECK(verthys_cng_aead_encrypt(pc, pt, sizeof(pt), NULL, 0,
                                     ct, &ctlen, nonce) == VERTHYS_OK);
        CHECK(verthys_cng_aead_decrypt(pc, ct, ctlen, NULL, 0,
                                     nonce, out, &outlen) == VERTHYS_OK);
        CHECK(memcmp(out, pt, sizeof(pt)) == 0);
    }

    /* 角色越界 / 未导入角色 → NULL */
    CHECK(verthys_cng_km_get(&km, (VerthysCngKeyRole)99) == NULL);
    CHECK(verthys_cng_km_get(NULL, VERTHYS_CNG_KEY_A) == NULL);

    /* 销毁：状态 DESTROYED，句柄清零，get 拒绝 */
    verthys_cng_km_destroy_all(&km);
    CHECK(km.state == VERTHYS_CNG_KM_DESTROYED);
    CHECK(verthys_cng_km_handle_count(&km) == 0);
    CHECK(verthys_cng_km_any_installed(&km) == 0);
    CHECK(verthys_cng_km_get(&km, VERTHYS_CNG_KEY_A) == NULL);

    /* DESTROYED 为终态：不经 init 不得重新导入 */
    CHECK(verthys_cng_km_import_batch(&km, mek,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_ERR_INVALID);

    /* init 后可重新导入（解锁重入语义） */
    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);
    memcpy(mek_copy, mek, sizeof(mek_copy));
    CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_OK);
    CHECK(verthys_cng_km_handle_count(&km) == (int)VERTHYS_CNG_KEY_COUNT);
    verthys_cng_km_destroy_all(&km);

    km_zero_keyset(mek, ka, kb, kc);
    return 0;
}

TEST(km_import_wrong_mek_rolls_back)
{
    VerthysCngKeyManager km;
    uint8_t mek[VERTHYS_CNG_KEY_BYTES], ka[VERTHYS_CNG_KEY_BYTES],
            kb[VERTHYS_CNG_KEY_BYTES], kc[VERTHYS_CNG_KEY_BYTES];
    uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES], wb[VERTHYS_CNG_WRAPPED_BYTES],
            wc[VERTHYS_CNG_WRAPPED_BYTES];
    uint8_t wrong_mek[VERTHYS_CNG_KEY_BYTES], wrong_copy[VERTHYS_CNG_KEY_BYTES];

    CHECK(km_build_keyset(mek, ka, kb, kc, wa, wb, wc) == 0);
    verthys_random_bytes(wrong_mek, sizeof(wrong_mek));
    memcpy(wrong_copy, wrong_mek, sizeof(wrong_copy));

    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);

    /* 错误 MEK → 第一个 wrapped 解包认证失败 → 整体回滚 */
    CHECK(verthys_cng_km_import_batch(&km, wrong_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_ERR_AUTH);
    CHECK(km.state == VERTHYS_CNG_KM_UNINITIALIZED);
    CHECK(verthys_cng_km_handle_count(&km) == 0);
    CHECK(verthys_cng_km_any_installed(&km) == 0);

    /* wrapped 长度非法 → INVALID + 回滚 */
    {
        uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];
        memcpy(mek_copy, mek, sizeof(mek_copy));
        CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                        wa, VERTHYS_CNG_WRAPPED_BYTES - 1,
                                        wb, VERTHYS_CNG_WRAPPED_BYTES,
                                        wc, VERTHYS_CNG_WRAPPED_BYTES)
              == VERTHYS_ERR_INVALID);
        CHECK(km.state == VERTHYS_CNG_KM_UNINITIALIZED);
        CHECK(verthys_cng_km_handle_count(&km) == 0);
    }

    /* 正确 MEK 重新导入成功（回滚后无残留） */
    {
        uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];
        memcpy(mek_copy, mek, sizeof(mek_copy));
        CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                        wa, VERTHYS_CNG_WRAPPED_BYTES,
                                        wb, VERTHYS_CNG_WRAPPED_BYTES,
                                        wc, VERTHYS_CNG_WRAPPED_BYTES)
              == VERTHYS_OK);
        CHECK(verthys_cng_km_handle_count(&km) == (int)VERTHYS_CNG_KEY_COUNT);
    }
    verthys_cng_km_destroy_all(&km);

    km_zero_keyset(mek, ka, kb, kc);
    verthys_secure_zero(wrong_mek, sizeof(wrong_mek));
    return 0;
}

TEST(km_wrapped_role_binding)
{
    VerthysCngKeyManager km;
    uint8_t mek[VERTHYS_CNG_KEY_BYTES], ka[VERTHYS_CNG_KEY_BYTES],
            kb[VERTHYS_CNG_KEY_BYTES], kc[VERTHYS_CNG_KEY_BYTES];
    uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES], wb[VERTHYS_CNG_WRAPPED_BYTES],
            wc[VERTHYS_CNG_WRAPPED_BYTES];
    uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];

    CHECK(km_build_keyset(mek, ka, kb, kc, wa, wb, wc) == 0);
    memcpy(mek_copy, mek, sizeof(mek_copy));

    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);

    /* 域分离角色绑定：wrapped_a 放入 B 槽位 → AAD 角色不匹配 → 认证失败 */
    CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,  /* B 位错放 A */
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_ERR_AUTH);
    CHECK(km.state == VERTHYS_CNG_KM_UNINITIALIZED);
    CHECK(verthys_cng_km_handle_count(&km) == 0);

    km_zero_keyset(mek, ka, kb, kc);
    return 0;
}

TEST(km_reimport_replaces_handles)
{
    VerthysCngKeyManager km;
    uint8_t mek[VERTHYS_CNG_KEY_BYTES], ka[VERTHYS_CNG_KEY_BYTES],
            kb[VERTHYS_CNG_KEY_BYTES], kc[VERTHYS_CNG_KEY_BYTES];
    uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES], wb[VERTHYS_CNG_WRAPPED_BYTES],
            wc[VERTHYS_CNG_WRAPPED_BYTES];
    uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];

    CHECK(km_build_keyset(mek, ka, kb, kc, wa, wb, wc) == 0);

    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);
    memcpy(mek_copy, mek, sizeof(mek_copy));
    CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_OK);

    /* KERNEL_RESIDENT 态重入导入：旧句柄整体退场，计数不累积（无句柄泄露） */
    memcpy(mek_copy, mek, sizeof(mek_copy));
    CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_OK);
    CHECK(km.state == VERTHYS_CNG_KM_KERNEL_RESIDENT);
    CHECK(verthys_cng_km_handle_count(&km) == (int)VERTHYS_CNG_KEY_COUNT);

    verthys_cng_km_destroy_all(&km);
    km_zero_keyset(mek, ka, kb, kc);
    return 0;
}

/* ---------- 5. 失败路径密钥卫生 ---------- */

/*
 * 导入失败的调用方密钥清零契约：import_key 是密钥明文唯一合法驻留点，
 * 调用方无法区分成败——零化责任一律在 import 内部，契约覆盖全部
 * 返回路径（key 非 NULL 即清零）。
 */
TEST(cng_aead_import_failure_zeroes_key)
{
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t zero[VERTHYS_CNG_KEY_BYTES] = {0};

    verthys_random_bytes(key, sizeof(key));

    /* 内核导入失败（注入）：失败返回后调用方密钥缓冲必须全零 */
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);
    verthys_cng_test_inject_import_failure();
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL)
          == VERTHYS_ERR_CNG_UNAVAILABLE);
    CHECK(memcmp(key_copy, zero, sizeof(zero)) == 0);
    CHECK(verthys_cng_aead_is_imported(&aead) == 0);

    /* aead == NULL：key 非 NULL 的所有返回路径均清零（契约完备性） */
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_import_key(NULL, key_copy, NULL)
          == VERTHYS_ERR_INVALID);
    CHECK(memcmp(key_copy, zero, sizeof(zero)) == 0);

    /* 注入一次性：后续导入恢复正常 */
    memcpy(key_copy, key, sizeof(key_copy));
    CHECK(verthys_cng_aead_import_key(&aead, key_copy, NULL) == VERTHYS_OK);
    CHECK(verthys_cng_aead_is_imported(&aead) == 1);
    verthys_cng_aead_destroy(&aead);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

/*
 * 长度域守卫：明文/密文/AAD 超出 CNG 的 32 位参数域必须显式拒绝，
 * 不得截断后进入内核调用（截断会导致长度错乱与越界标签写入）。
 * 边界注入以"容量给足"证明拒绝来自域守卫而非容量判定；
 * 域内最大值则须穿透域守卫抵达状态判定（不被误拒）。
 */
TEST(cng_aead_length_domain_guards)
{
    VerthysCngAead aead;
    uint8_t ct[VERTHYS_CNG_TAG_BYTES], nonce[VERTHYS_CNG_NONCE_BYTES];
    uint8_t out[8];
    size_t ctlen, outlen;

    CHECK(verthys_cng_aead_init(&aead) == VERTHYS_OK);  /* 未导入态 */

    /* 加密侧：明文上限 = ULONG_MAX - 16（密文 = 明文+标签须可表示） */
    ctlen = (size_t)-1;
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x",
                                 (size_t)0x100000000ull, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);
    ctlen = (size_t)-1;
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x",
                                 (size_t)0xFFFFFFFFull, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);
    ctlen = (size_t)-1;
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x",
                                 (size_t)0xFFFFFFF0ull, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);

    /* AAD 超域同样拒绝 */
    ctlen = (size_t)-1;
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x", 1,
                                 (const uint8_t *)"a",
                                 (size_t)0x100000000ull,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);

    /* 域内最大明文（ULONG_MAX-16）+ 容量给足：过域守卫与容量判定，
     * 抵达未导入判定 → LOCKED（证明边界值不被误拒） */
    ctlen = (size_t)-1;
    CHECK(verthys_cng_aead_encrypt(&aead, (const uint8_t *)"x",
                                 (size_t)0xFFFFFFEFull, NULL, 0,
                                 ct, &ctlen, nonce) == VERTHYS_ERR_LOCKED);

    /* 解密侧：密文上限 = ULONG_MAX（对应加密侧明文上限 ULONG_MAX-16） */
    outlen = (size_t)-1;
    CHECK(verthys_cng_aead_decrypt(&aead, ct, (size_t)0x100000000ull,
                                 NULL, 0, nonce, out, &outlen)
          == VERTHYS_ERR_INVALID);
    outlen = (size_t)-1;
    CHECK(verthys_cng_aead_decrypt(&aead, ct, (size_t)0xFFFFFFFFull,
                                 NULL, 0, nonce, out, &outlen)
          == VERTHYS_ERR_LOCKED);
    return 0;
}

/*
 * rotate_mek 失败原子性：新 MEK 导入失败（注入）时旧 MEK 槽必须
 * 原样驻留——临时槽先验证后切换，失败零变更（unwrap 语义保持）。
 */
TEST(km_rotate_mek_failure_keeps_old_slot)
{
    VerthysCngKeyManager km;
    uint8_t mek[VERTHYS_CNG_KEY_BYTES], ka[VERTHYS_CNG_KEY_BYTES],
            kb[VERTHYS_CNG_KEY_BYTES], kc[VERTHYS_CNG_KEY_BYTES];
    uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES], wb[VERTHYS_CNG_WRAPPED_BYTES],
            wc[VERTHYS_CNG_WRAPPED_BYTES];
    uint8_t new_mek[VERTHYS_CNG_KEY_BYTES], new_mek_copy[VERTHYS_CNG_KEY_BYTES];
    uint8_t key_material[VERTHYS_CNG_KEY_BYTES];
    size_t key_len;
    static const uint8_t wrap_prefix[16] = {
        'v', 'e', 'r', 't', 'h', 'y', 's',
        '/', 'w', 'r', 'a', 'p', '-', 'v', '3'
    };
    uint8_t aad[17];
    int base = verthys_cng_km_global_handle_total();

    CHECK(km_build_keyset(mek, ka, kb, kc, wa, wb, wc) == 0);
    verthys_random_bytes(new_mek, sizeof(new_mek));

    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);
    {
        uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];
        memcpy(mek_copy, mek, sizeof(mek_copy));
        CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                        wa, VERTHYS_CNG_WRAPPED_BYTES,
                                        wb, VERTHYS_CNG_WRAPPED_BYTES,
                                        wc, VERTHYS_CNG_WRAPPED_BYTES)
              == VERTHYS_OK);
    }
    CHECK(verthys_cng_km_global_handle_total()
          == base + (int)VERTHYS_CNG_KEY_COUNT);

    /* 新 MEK 导入失败（注入）：旧 MEK 槽必须原样驻留（零变更） */
    memcpy(new_mek_copy, new_mek, sizeof(new_mek_copy));
    verthys_cng_test_inject_import_failure();
    CHECK(verthys_cng_km_rotate_mek(&km, new_mek_copy)
          == VERTHYS_ERR_CNG_UNAVAILABLE);
    CHECK(verthys_cng_aead_is_imported(&km.keys[VERTHYS_CNG_KEY_MEK]) == 1);
    CHECK(verthys_cng_km_global_handle_total()
          == base + (int)VERTHYS_CNG_KEY_COUNT);

    /* 旧 MEK 槽依旧可用：wrapped_key_a 内核态解包成功且内容一致 */
    memcpy(aad, wrap_prefix, sizeof(wrap_prefix));
    aad[16] = (uint8_t)VERTHYS_CNG_KEY_A;
    key_len = sizeof(key_material);
    CHECK(verthys_cng_aead_decrypt(&km.keys[VERTHYS_CNG_KEY_MEK],
                                 wa + VERTHYS_CNG_NONCE_BYTES,
                                 VERTHYS_CNG_WRAPPED_BYTES
                                     - VERTHYS_CNG_NONCE_BYTES,
                                 aad, sizeof(aad), wa,
                                 key_material, &key_len) == VERTHYS_OK);
    CHECK(key_len == VERTHYS_CNG_KEY_BYTES);
    CHECK(memcmp(key_material, ka, VERTHYS_CNG_KEY_BYTES) == 0);
    verthys_secure_zero(key_material, sizeof(key_material));

    /* 注入恢复后轮换成功：MEK 槽换新，句柄总量配平不变 */
    memcpy(new_mek_copy, new_mek, sizeof(new_mek_copy));
    CHECK(verthys_cng_km_rotate_mek(&km, new_mek_copy) == VERTHYS_OK);
    CHECK(verthys_cng_aead_is_imported(&km.keys[VERTHYS_CNG_KEY_MEK]) == 1);
    CHECK(verthys_cng_km_global_handle_total()
          == base + (int)VERTHYS_CNG_KEY_COUNT);
    verthys_cng_km_destroy_all(&km);
    CHECK(verthys_cng_km_global_handle_total() == base);

    km_zero_keyset(mek, ka, kb, kc);
    verthys_secure_zero(new_mek, sizeof(new_mek));
    return 0;
}

/*
 * 共享提供者并发 init/deinit 压力：多线程循环配对调用下，
 * open 路径必须互斥（无双开句柄泄漏）、引用计数精确归零、
 * 全部导入成功（无"已认为就绪而句柄被关"竞态）。
 * 线程内错误仅原子累计，join 后统一断言。
 */
#define PCP_THREADS 4
#define PCP_ROUNDS  2000

typedef struct ProviderStormState {
    volatile LONG init_fails;    /* init_once 非预期失败累计 */
    volatile LONG import_fails;  /* 轮内导入失败累计 */
} ProviderStormState;

static unsigned __stdcall pcp_worker(void *arg)
{
    ProviderStormState *st = (ProviderStormState *)arg;
    VerthysCngAead aead;
    uint8_t key[VERTHYS_CNG_KEY_BYTES], key_copy[VERTHYS_CNG_KEY_BYTES];
    unsigned r;

    verthys_random_bytes(key, sizeof(key));
    for (r = 0; r < PCP_ROUNDS; r++) {
        memcpy(key_copy, key, sizeof(key_copy));
        if (verthys_cng_init_once() != VERTHYS_OK) {
            InterlockedIncrement(&st->init_fails);
            continue;
        }
        if (verthys_cng_aead_init(&aead) != VERTHYS_OK ||
            verthys_cng_aead_import_key(&aead, key_copy, NULL)
                != VERTHYS_OK) {
            InterlockedIncrement(&st->import_fails);
        } else {
            verthys_cng_aead_destroy(&aead);
        }
        verthys_cng_global_deinit();
    }
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(cng_provider_concurrent_init_deinit)
{
    ProviderStormState st;
    HANDLE threads[PCP_THREADS];
    int i, spawned = 0;

    /* 清零基线：此前测试遗留的未配对引用统一释放（提供者随引用归零
     * 关闭；此时无任何存活密钥句柄依赖它），风暴从真实零引用起跑 */
    while (verthys_cng_test_alg_refs() != 0) {
        verthys_cng_global_deinit();
    }

    memset(&st, 0, sizeof(st));
    for (i = 0; i < PCP_THREADS; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, pcp_worker, &st, 0, NULL);
        if (threads[i] == NULL) break;
        spawned++;
    }
    for (i = 0; i < spawned; i++) {
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
    }
    CHECK(spawned == PCP_THREADS);

    /* 断言后置：无失败、引用计数精确归零（init/deinit 严格配对，
     * 提供者已随最后一次 deinit 关闭） */
    CHECK(st.init_fails == 0);
    CHECK(st.import_fails == 0);
    CHECK(verthys_cng_test_alg_refs() == 0);

    /* 风暴后可正常重开（open 失败可重试、关闭后可重开的完整生命周期） */
    CHECK(verthys_cng_init_once() == VERTHYS_OK);
    CHECK(verthys_cng_test_alg_refs() == 1);
    verthys_cng_global_deinit();
    CHECK(verthys_cng_test_alg_refs() == 0);
    return 0;
}

TEST(km_null_params_rejected)
{
    CHECK(verthys_cng_km_init(NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_cng_km_state(NULL) == VERTHYS_CNG_KM_DESTROYED);
    CHECK(verthys_cng_km_handle_count(NULL) == 0);
    CHECK(verthys_cng_km_any_installed(NULL) == 0);
    CHECK(verthys_cng_km_import_batch(NULL, (const uint8_t *)"k",
                                    NULL, 0, NULL, 0, NULL, 0)
          == VERTHYS_ERR_INVALID);
    verthys_cng_km_destroy_all(NULL);  /* 幂等，不崩溃 */
    return 0;
}

TEST(km_global_handle_tracking)
{
    VerthysCngKeyManager km;
    uint8_t mek[VERTHYS_CNG_KEY_BYTES], ka[VERTHYS_CNG_KEY_BYTES],
            kb[VERTHYS_CNG_KEY_BYTES], kc[VERTHYS_CNG_KEY_BYTES];
    uint8_t wa[VERTHYS_CNG_WRAPPED_BYTES], wb[VERTHYS_CNG_WRAPPED_BYTES],
            wc[VERTHYS_CNG_WRAPPED_BYTES];
    uint8_t mek_copy[VERTHYS_CNG_KEY_BYTES];
    int base = verthys_cng_km_global_handle_total();

    CHECK(km_build_keyset(mek, ka, kb, kc, wa, wb, wc) == 0);
    CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);
    CHECK(verthys_cng_km_global_handle_total() == base);

    /* 成功导入：全局总量 +4（MEK + A/B/C），defense_closure MEM_DUMP 判据 */
    memcpy(mek_copy, mek, sizeof(mek_copy));
    CHECK(verthys_cng_km_import_batch(&km, mek_copy,
                                    wa, VERTHYS_CNG_WRAPPED_BYTES,
                                    wb, VERTHYS_CNG_WRAPPED_BYTES,
                                    wc, VERTHYS_CNG_WRAPPED_BYTES)
          == VERTHYS_OK);
    CHECK(verthys_cng_km_global_handle_total() == base + (int)VERTHYS_CNG_KEY_COUNT);

    /* 销毁：总量回落，无泄露 */
    verthys_cng_km_destroy_all(&km);
    CHECK(verthys_cng_km_global_handle_total() == base);

    /* 失败导入（错误 MEK）：回滚后总量不变 */
    {
        uint8_t wrong[VERTHYS_CNG_KEY_BYTES], wrong_copy[VERTHYS_CNG_KEY_BYTES];
        verthys_random_bytes(wrong, sizeof(wrong));
        memcpy(wrong_copy, wrong, sizeof(wrong_copy));
        CHECK(verthys_cng_km_init(&km) == VERTHYS_OK);
        CHECK(verthys_cng_km_import_batch(&km, wrong_copy,
                                        wa, VERTHYS_CNG_WRAPPED_BYTES,
                                        wb, VERTHYS_CNG_WRAPPED_BYTES,
                                        wc, VERTHYS_CNG_WRAPPED_BYTES)
              == VERTHYS_ERR_AUTH);
        CHECK(verthys_cng_km_global_handle_total() == base);
        verthys_secure_zero(wrong, sizeof(wrong));
    }

    km_zero_keyset(mek, ka, kb, kc);
    return 0;
}
