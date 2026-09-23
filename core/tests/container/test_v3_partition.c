/*
 * test_v3_partition.c — V3 分区管理验收（独立 AEAD 密钥 + 分区表持久化）
 *
 * 覆盖（验收标准）：
 *   1. 分区创建（随机密钥 → wrapping 包装 → CNG 内核导入）+ 字段登记
 *   2. 分区数据 AEAD：加解密 roundtrip、AAD 绑定（txid）、篡改拒绝、
 *      分区密钥隔离、空明文
 *   3. 分区扩展（2x 策略 + min_bytes 线性补足）
 *   4. 分区加载：wrapped 解包重导入 + nonce 计数器恢复（防回退，
 *      加载后 nonce 严格不回退）、错误 wrapping key 拒绝、参数校验
 *   5. 分区表：init/add（重复 id / 容量上限）/find/destroy
 *   6. 分区表持久化：save/load roundtrip（条目字段 + nonce 计数器 +
 *      重载后解密闭环）、帧篡改拒绝、错误表密钥拒绝、空区拒绝
 */
#include "verthys_test.h"
#include "verthys_partition.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"

#include <string.h>
#include <io.h>

#define V3P_TMP "test_v3_partition.tmp"
#define V3P_KEY_BYTES VERTHYS_CNG_KEY_BYTES

static void v3p_cleanup(void) { remove(V3P_TMP); }

/* 生成随机密钥并导入 CNG 内核（key_out 保留明文副本供重导入；测试专用） */
static int v3p_import_random(VerthysCngAead *a, uint8_t key_out[V3P_KEY_BYTES])
{
    uint8_t copy[V3P_KEY_BYTES];
    verthys_random_bytes(key_out, V3P_KEY_BYTES);
    memcpy(copy, key_out, V3P_KEY_BYTES);
    if (verthys_cng_aead_init(a) != VERTHYS_OK) return -1;
    if (verthys_cng_aead_import_key(a, copy, NULL) != VERTHYS_OK) return -1;
    return 0;
}

/* 以既有密钥重导入（新上下文；import 清零入参 → 传副本） */
static int v3p_reimport(VerthysCngAead *a, const uint8_t key[V3P_KEY_BYTES])
{
    uint8_t copy[V3P_KEY_BYTES];
    memcpy(copy, key, V3P_KEY_BYTES);
    if (verthys_cng_aead_init(a) != VERTHYS_OK) return -1;
    return verthys_cng_aead_import_key(a, copy, NULL) == VERTHYS_OK ? 0 : -1;
}

static void v3p_zero_key(uint8_t key[V3P_KEY_BYTES])
{
    verthys_secure_zero(key, V3P_KEY_BYTES);
}

/* ---------- 1. 分区生命周期 ---------- */

TEST(v3part_create_defaults)
{
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 1, VERTHYS_PARTITION_EXTENT,
                                 0x1400000u, 16u * 1024u * 1024u, 3,
                                 &wrap) == VERTHYS_OK);
    CHECK(p.id == 1);
    CHECK(p.type == VERTHYS_PARTITION_EXTENT);
    CHECK(p.offset == 0x1400000u);
    CHECK(p.size == 16u * 1024u * 1024u);
    CHECK(p.used == 0);
    CHECK(p.created_txid == 3);
    CHECK(p.wrapped_key_len == VERTHYS_PARTITION_WRAPPED_BYTES);
    CHECK(verthys_partition_nonce_counter(&p) == 0);
    /* 分区已具备独立内核密钥（可立即加密） */
    CHECK(verthys_cng_aead_is_imported(&p.aead) == 1);

    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);
    CHECK(verthys_cng_aead_is_imported(&p.aead) == 0);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

TEST(v3part_create_rejects_invalid)
{
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(NULL, 1, VERTHYS_PARTITION_INDEX,
                                 0, 1024, 0, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_create(&p, 1, VERTHYS_PARTITION_INDEX,
                                 0, 0, 0, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_create(&p, 1, (VerthysPartitionType)99,
                                 0, 1024, 0, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_create(&p, 1, VERTHYS_PARTITION_INDEX,
                                 0, 1024, 0, NULL) == VERTHYS_ERR_INVALID);

    /* wrapping 未导入 → LOCKED */
    {
        VerthysCngAead unimported;
        CHECK(verthys_cng_aead_init(&unimported) == VERTHYS_OK);
        CHECK(verthys_partition_create(&p, 1, VERTHYS_PARTITION_INDEX,
                                     0, 1024, 0, &unimported)
              == VERTHYS_ERR_LOCKED);
        verthys_cng_aead_destroy(&unimported);
    }

    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

/* ---------- 2. 分区数据 AEAD ---------- */

TEST(v3part_encrypt_decrypt_roundtrip)
{
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];
    uint8_t pt[256], ct[256 + VERTHYS_PARTITION_TAG_BYTES];
    uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES];
    uint8_t out[256];
    size_t ctlen, outlen;
    unsigned i;

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 5, VERTHYS_PARTITION_INDEX,
                                 0x400000u, 16u * 1024u * 1024u, 1,
                                 &wrap) == VERTHYS_OK);
    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 5 + 1);

    ctlen = sizeof(ct);
    CHECK(verthys_partition_encrypt(&p, 10, pt, sizeof(pt),
                                  ct, &ctlen, nonce) == VERTHYS_OK);
    CHECK(ctlen == sizeof(pt) + VERTHYS_PARTITION_TAG_BYTES);
    CHECK(verthys_partition_nonce_counter(&p) == 1);

    outlen = sizeof(out);
    CHECK(verthys_partition_decrypt(&p, 10, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_OK);
    CHECK(outlen == sizeof(pt));
    CHECK(memcmp(out, pt, sizeof(pt)) == 0);

    /* 空明文：仅 16B 标签 */
    ctlen = sizeof(ct);
    CHECK(verthys_partition_encrypt(&p, 10, NULL, 0,
                                  ct, &ctlen, nonce) == VERTHYS_OK);
    CHECK(ctlen == VERTHYS_PARTITION_TAG_BYTES);
    outlen = sizeof(out);
    CHECK(verthys_partition_decrypt(&p, 10, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_OK);
    CHECK(outlen == 0);

    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

TEST(v3part_decrypt_txid_binding_rejected)
{
    /* AAD 绑定 partition_id ‖ txid：txid 不符 → AUTH 失败 */
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];
    uint8_t pt[64], ct[64 + VERTHYS_PARTITION_TAG_BYTES];
    uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES];
    uint8_t out[64];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 5, VERTHYS_PARTITION_INDEX,
                                 0x400000u, 1024 * 1024, 1, &wrap) == VERTHYS_OK);

    CHECK(verthys_partition_encrypt(&p, 10, pt, sizeof(pt),
                                  ct, &ctlen, nonce) == VERTHYS_OK);
    CHECK(verthys_partition_decrypt(&p, 11, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_ERR_AUTH);
    /* 原 txid 仍可解 */
    CHECK(verthys_partition_decrypt(&p, 10, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_OK);

    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

TEST(v3part_tamper_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];
    uint8_t pt[128], ct[128 + VERTHYS_PARTITION_TAG_BYTES];
    uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES];
    uint8_t out[128];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 2, VERTHYS_PARTITION_AUDIT,
                                 0x2400000u, 1024 * 1024, 1, &wrap) == VERTHYS_OK);
    CHECK(verthys_partition_encrypt(&p, 4, pt, sizeof(pt),
                                  ct, &ctlen, nonce) == VERTHYS_OK);

    ct[0] ^= 0x01;
    CHECK(verthys_partition_decrypt(&p, 4, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_ERR_AUTH);
    ct[0] ^= 0x01;
    ct[ctlen - 1] ^= 0x80;
    CHECK(verthys_partition_decrypt(&p, 4, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_ERR_AUTH);
    ct[ctlen - 1] ^= 0x80;
    CHECK(verthys_partition_decrypt(&p, 4, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_OK);

    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

TEST(v3part_key_isolation)
{
    /* 每分区独立密钥：跨分区解密必须认证失败 */
    VerthysCngAead wrap;
    VerthysPartition p1, p2;
    uint8_t wk[V3P_KEY_BYTES];
    uint8_t pt[32], ct[32 + VERTHYS_PARTITION_TAG_BYTES];
    uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES];
    uint8_t out[32];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p1, 1, VERTHYS_PARTITION_INDEX,
                                 0x400000u, 1024 * 1024, 1, &wrap) == VERTHYS_OK);
    CHECK(verthys_partition_create(&p2, 2, VERTHYS_PARTITION_EXTENT,
                                 0x1400000u, 1024 * 1024, 1, &wrap) == VERTHYS_OK);
    CHECK(memcmp(p1.key_id, p2.key_id, VERTHYS_PARTITION_KEY_ID_BYTES) != 0);

    CHECK(verthys_partition_encrypt(&p1, 7, pt, sizeof(pt),
                                  ct, &ctlen, nonce) == VERTHYS_OK);
    CHECK(verthys_partition_decrypt(&p2, 7, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_ERR_AUTH);
    CHECK(verthys_partition_decrypt(&p1, 7, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_OK);

    CHECK(verthys_partition_destroy(&p1) == VERTHYS_OK);
    CHECK(verthys_partition_destroy(&p2) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

TEST(v3part_null_params_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];
    uint8_t ct[32 + VERTHYS_PARTITION_TAG_BYTES];
    uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES];
    uint8_t out[32];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 9, VERTHYS_PARTITION_WAL,
                                 0x10000u, 1024 * 1024, 1, &wrap) == VERTHYS_OK);

    CHECK(verthys_partition_encrypt(NULL, 1, (const uint8_t *)"x", 1,
                                  ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_encrypt(&p, 1, (const uint8_t *)"x", 1,
                                  NULL, &ctlen, nonce) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_encrypt(&p, 1, (const uint8_t *)"x", 1,
                                  ct, NULL, nonce) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_encrypt(&p, 1, (const uint8_t *)"x", 1,
                                  ct, &ctlen, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_encrypt(&p, 1, NULL, 1,
                                  ct, &ctlen, nonce) == VERTHYS_ERR_INVALID);

    CHECK(verthys_partition_decrypt(NULL, 1, nonce, ct, ctlen,
                                  out, &outlen) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_decrypt(&p, 1, NULL, ct, ctlen,
                                  out, &outlen) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_decrypt(&p, 1, nonce, ct, VERTHYS_PARTITION_TAG_BYTES - 1,
                                  out, &outlen) == VERTHYS_ERR_INVALID);

    CHECK(verthys_partition_grow(NULL, 1, 0x1000000ull) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_grow(&p, 0, 0x1000000ull) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_nonce_counter(NULL) == 0);
    CHECK(verthys_partition_destroy(NULL) == VERTHYS_OK);  /* 幂等 */

    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

/* ---------- 3. 分区扩展 ---------- */

TEST(v3part_grow_strategy)
{
    VerthysCngAead wrap;
    VerthysPartition p;
    uint8_t wk[V3P_KEY_BYTES];

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 1, VERTHYS_PARTITION_INDEX,
                                 0x400000u, 1024, 1, &wrap) == VERTHYS_OK);

    /* 2x 策略：1024 → 2048 */
    CHECK(verthys_partition_grow(&p, 1, 0x800000u) == VERTHYS_OK);
    CHECK(p.size == 2048);

    /* min_bytes 超过 2x：线性补足 2048+5000=7048 */
    CHECK(verthys_partition_grow(&p, 5000, 0x800000u) == VERTHYS_OK);
    CHECK(p.size == 7048);

    /* 2x 再次占优：7048 → 14096 */
    CHECK(verthys_partition_grow(&p, 100, 0x800000u) == VERTHYS_OK);
    CHECK(p.size == 14096);

    /* 区域上限（offset 0x400000，limit 0x404000，cap 16KB）：
     * 最小需求越界 → 拒绝且内存态不变 */
    CHECK(verthys_partition_grow(&p, 100000, 0x404000u) == VERTHYS_ERR_RESOURCE_LIMIT);
    CHECK(p.size == 14096);
    /* 需求合法但 2x 目标(28192)越界 16KB cap → 截断于上限 */
    CHECK(verthys_partition_grow(&p, 1, 0x404000u) == VERTHYS_OK);
    CHECK(p.size == 16384);

    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

/* ---------- 4. 分区加载（重开语义） ---------- */

TEST(v3part_load_nonce_no_reuse)
{
    /* 持久化形态重载：nonce 计数器恢复，历史 nonce 不得复用（防回退） */
    VerthysCngAead wrap;
    VerthysPartition p, reloaded;
    uint8_t wk[V3P_KEY_BYTES];
    uint8_t pt[96], ct[96 + VERTHYS_PARTITION_TAG_BYTES];
    uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES], nonce2[VERTHYS_PARTITION_NONCE_BYTES];
    uint8_t out[96];
    size_t ctlen = sizeof(ct), outlen = sizeof(out);
    uint8_t key_id[VERTHYS_PARTITION_KEY_ID_BYTES];
    uint8_t wrapped[VERTHYS_PARTITION_WRAPPED_BYTES];
    uint8_t wrap_nonce[VERTHYS_PARTITION_NONCE_BYTES];

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_create(&p, 7, VERTHYS_PARTITION_EXTENT,
                                 0x1400000u, 1024 * 1024, 2, &wrap) == VERTHYS_OK);

    /* 推进计数器到 3 并保留最后 nonce 与一份密文 */
    {
        unsigned i;
        for (i = 0; i < 3; i++) {
            ctlen = sizeof(ct);
            CHECK(verthys_partition_encrypt(&p, 2, pt, sizeof(pt),
                                          ct, &ctlen, nonce) == VERTHYS_OK);
        }
    }
    CHECK(verthys_partition_nonce_counter(&p) == 3);

    /* 快照持久化形态 */
    memcpy(key_id, p.key_id, sizeof(key_id));
    memcpy(wrapped, p.wrapped_key, sizeof(wrapped));
    memcpy(wrap_nonce, p.wrap_nonce, sizeof(wrap_nonce));
    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);

    /* 重开：新 wrapping 上下文（同一密钥）+ 重载分区 */
    {
        VerthysCngAead wrap2;
        CHECK(v3p_reimport(&wrap2, wk) == 0);
        CHECK(verthys_partition_load(&reloaded, 7, VERTHYS_PARTITION_EXTENT,
                                   0x1400000u, 1024 * 1024, 0,
                                   key_id, 3, 2,
                                   wrapped, VERTHYS_PARTITION_WRAPPED_BYTES,
                                   wrap_nonce, &wrap2) == VERTHYS_OK);
        CHECK(verthys_partition_nonce_counter(&reloaded) == 3);
        CHECK(reloaded.id == 7 && reloaded.created_txid == 2);

        /* 历史密文仍可解（密钥语境一致） */
        outlen = sizeof(out);
        CHECK(verthys_partition_decrypt(&reloaded, 2, nonce, ct, ctlen,
                                      out, &outlen) == VERTHYS_OK);

        /* 下一个 nonce 严格大于恢复点（大端计数器编码） */
        ctlen = sizeof(ct);
        CHECK(verthys_partition_encrypt(&reloaded, 2, pt, sizeof(pt),
                                      ct, &ctlen, nonce2) == VERTHYS_OK);
        CHECK(memcmp(nonce2, nonce, VERTHYS_PARTITION_NONCE_BYTES) > 0);
        CHECK(verthys_partition_nonce_counter(&reloaded) == 4);

        CHECK(verthys_partition_destroy(&reloaded) == VERTHYS_OK);
        verthys_cng_aead_destroy(&wrap2);
    }

    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

TEST(v3part_load_rejects_invalid)
{
    VerthysCngAead wrap, wrong, unimported;
    VerthysPartition p, out;
    uint8_t wk[V3P_KEY_BYTES], wk2[V3P_KEY_BYTES];

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(v3p_import_random(&wrong, wk2) == 0);
    CHECK(verthys_cng_aead_init(&unimported) == VERTHYS_OK);

    CHECK(verthys_partition_create(&p, 7, VERTHYS_PARTITION_INDEX,
                                 0x400000u, 1024 * 1024, 1, &wrap) == VERTHYS_OK);

    /* 错误 wrapping key → 解包认证失败 */
    CHECK(verthys_partition_load(&out, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 1024 * 1024, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &wrong) == VERTHYS_ERR_AUTH);
    /* wrapping 未导入 → LOCKED */
    CHECK(verthys_partition_load(&out, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 1024 * 1024, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &unimported) == VERTHYS_ERR_LOCKED);
    /* wrapped 长度非法 / used > size / size = 0 / type 越界 */
    CHECK(verthys_partition_load(&out, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 1024 * 1024, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES - 1,
                               p.wrap_nonce, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_load(&out, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 1024 * 1024, 1024 * 1024 + 1,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_load(&out, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 0, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_load(&out, 7, (VerthysPartitionType)99,
                               0x400000u, 1024 * 1024, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &wrap) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_load(NULL, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 1024 * 1024, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &wrap) == VERTHYS_ERR_INVALID);

    /* 同一 wrapping 重载成功（回环校验） */
    CHECK(verthys_partition_load(&out, 7, VERTHYS_PARTITION_INDEX,
                               0x400000u, 1024 * 1024, 0,
                               p.key_id, 0, 1,
                               p.wrapped_key, VERTHYS_PARTITION_WRAPPED_BYTES,
                               p.wrap_nonce, &wrap) == VERTHYS_OK);
    CHECK(verthys_partition_destroy(&out) == VERTHYS_OK);
    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);

    verthys_cng_aead_destroy(&wrap);
    verthys_cng_aead_destroy(&wrong);
    verthys_cng_aead_destroy(&unimported);
    v3p_zero_key(wk);
    v3p_zero_key(wk2);
    return 0;
}

/* ---------- 5. 分区表（内存态） ---------- */

TEST(v3part_table_add_find_limits)
{
    VerthysCngAead wrap;
    VerthysPartitionTable t;
    VerthysPartition p, found;
    uint8_t wk[V3P_KEY_BYTES];
    unsigned i;

    CHECK(v3p_import_random(&wrap, wk) == 0);
    CHECK(verthys_partition_table_init(&t, 1) == VERTHYS_OK);
    CHECK(t.count == 0 && t.txid == 1);
    CHECK(verthys_partition_table_init(NULL, 1) == VERTHYS_ERR_INVALID);

    /* 满表：VERTHYS_PARTITION_MAX 条 */
    for (i = 0; i < VERTHYS_PARTITION_MAX; i++) {
        CHECK(verthys_partition_create(&p, (VerthysPartitionId)(i + 1),
                                     VERTHYS_PARTITION_INDEX,
                                     0x400000u + i * 1024, 1024, 1,
                                     &wrap) == VERTHYS_OK);
        CHECK(verthys_partition_table_add(&t, &p) == VERTHYS_OK);
    }
    CHECK(t.count == VERTHYS_PARTITION_MAX);

    /* 容量上限：超限条目 → RESOURCE_LIMIT */
    CHECK(verthys_partition_create(&p, 99, VERTHYS_PARTITION_AUDIT,
                                 0x2400000u, 1024, 1, &wrap) == VERTHYS_OK);
    CHECK(verthys_partition_table_add(&t, &p) == VERTHYS_ERR_RESOURCE_LIMIT);
    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);  /* 未入表 → 独立销毁 */

    /* 重复 id → EXISTS */
    CHECK(verthys_partition_create(&p, 1, VERTHYS_PARTITION_EXTENT,
                                 0x1400000u, 1024, 1, &wrap) == VERTHYS_OK);
    CHECK(verthys_partition_table_add(&t, &p) == VERTHYS_ERR_EXISTS);
    CHECK(verthys_partition_destroy(&p) == VERTHYS_OK);

    /* find：命中与未命中 */
    CHECK(verthys_partition_table_find(&t, 3, &found) == VERTHYS_OK);
    CHECK(found.id == 3 && found.offset == 0x400000u + 2 * 1024);
    CHECK(verthys_partition_table_find(&t, 255, &found) == VERTHYS_ERR_NOTFOUND);
    CHECK(verthys_partition_table_find(NULL, 1, &found) == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_table_add(NULL, &p) == VERTHYS_ERR_INVALID);

    CHECK(verthys_partition_table_destroy(&t) == VERTHYS_OK);
    CHECK(t.count == 0);
    CHECK(verthys_partition_table_destroy(NULL) == VERTHYS_OK);  /* 幂等 */
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(wk);
    return 0;
}

/* ---------- 6. 分区表持久化 ---------- */

/*
 * 构造三分区表（INDEX/EXTENT/AUDIT）并推进各计数器。
 * wrap_key/table_key 保留明文副本（重开重导入用）。
 * 每分区留一份密文（txid=9）供重载后解密闭环。
 */
static int v3p_build_saved_table(VerthysPartitionTable *t,
                                 VerthysCngAead *wrap, VerthysCngAead *table_aead,
                                 uint8_t wk[V3P_KEY_BYTES],
                                 uint8_t tk[V3P_KEY_BYTES],
                                 uint8_t cts[3][64 + VERTHYS_PARTITION_TAG_BYTES],
                                 size_t ct_lens[3],
                                 uint8_t nonces[3][VERTHYS_PARTITION_NONCE_BYTES],
                                 uint64_t counters[3])
{
    static const struct {
        VerthysPartitionId id;
        VerthysPartitionType type;
    } meta[3] = {
        {1, VERTHYS_PARTITION_INDEX},
        {2, VERTHYS_PARTITION_EXTENT},
        {3, VERTHYS_PARTITION_AUDIT},
    };
    uint8_t pt[64];
    unsigned i;

    if (v3p_import_random(wrap, wk) != 0) return -1;
    if (v3p_import_random(table_aead, tk) != 0) return -1;
    if (verthys_partition_table_init(t, 9) != VERTHYS_OK) return -1;

    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 3 + 7);

    for (i = 0; i < 3; i++) {
        VerthysPartition p;
        if (verthys_partition_create(&p, meta[i].id, meta[i].type,
                                   0x400000u + (uint64_t)i * 0x1000000u,
                                   1024 * 1024, 5, wrap) != VERTHYS_OK) return -1;
        if (verthys_partition_table_add(t, &p) != VERTHYS_OK) return -1;
    }
    /* 推进各表项计数器并留密文（经表项句柄加密，持久化口径一致） */
    for (i = 0; i < 3; i++) {
        ct_lens[i] = 64 + VERTHYS_PARTITION_TAG_BYTES;
        if (verthys_partition_encrypt(&t->entries[i], 9, pt, sizeof(pt),
                                    cts[i], &ct_lens[i], nonces[i]) != VERTHYS_OK) {
            return -1;
        }
        counters[i] = verthys_partition_nonce_counter(&t->entries[i]);
    }
    return 0;
}

TEST(v3part_table_save_load_roundtrip)
{
    VerthysPartitionTable t, loaded;
    VerthysCngAead wrap, table_aead, wrap2, table_aead2;
    VerthysPartition found;
    uint8_t wk[V3P_KEY_BYTES], tk[V3P_KEY_BYTES];
    uint8_t cts[3][64 + VERTHYS_PARTITION_TAG_BYTES];
    size_t ct_lens[3];
    uint8_t nonces[3][VERTHYS_PARTITION_NONCE_BYTES];
    uint64_t counters[3];
    uint8_t out[64];
    size_t outlen;
    FILE *f;
    unsigned i;

    v3p_cleanup();
    CHECK(v3p_build_saved_table(&t, &wrap, &table_aead, wk, tk,
                                cts, ct_lens, nonces, counters) == 0);

    f = fopen(V3P_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_partition_table_save(f, 0, &t, &table_aead) == VERTHYS_OK);

    /* 模拟进程退出：销毁内存态（内核句柄全量退场） */
    CHECK(verthys_partition_table_destroy(&t) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    verthys_cng_aead_destroy(&table_aead);

    /* 重开：同一对密钥语境重导入 */
    CHECK(v3p_reimport(&table_aead2, tk) == 0);
    CHECK(v3p_reimport(&wrap2, wk) == 0);
    CHECK(verthys_partition_table_load(f, 0, &table_aead2, &wrap2, &loaded)
          == VERTHYS_OK);
    CHECK(loaded.count == 3);
    CHECK(loaded.txid == 9);

    for (i = 0; i < 3; i++) {
        CHECK(verthys_partition_table_find(&loaded, (VerthysPartitionId)(i + 1),
                                         &found) == VERTHYS_OK);
        CHECK(found.type == (VerthysPartitionType)i);
        CHECK(found.offset == 0x400000u + (uint64_t)i * 0x1000000u);
        CHECK(found.created_txid == 5);
        /* nonce 计数器按保存时值恢复 */
        CHECK(verthys_partition_nonce_counter(&found) == counters[i]);
        /* 重载密钥可解保存前密文（txid=9 AAD 绑定一致） */
        outlen = sizeof(out);
        CHECK(verthys_partition_decrypt(&found, 9, nonces[i], cts[i], ct_lens[i],
                                      out, &outlen) == VERTHYS_OK);
        CHECK(outlen == 64);
    }

    CHECK(verthys_partition_table_destroy(&loaded) == VERTHYS_OK);
    verthys_cng_aead_destroy(&table_aead2);
    verthys_cng_aead_destroy(&wrap2);
    fclose(f);

    v3p_zero_key(wk);
    v3p_zero_key(tk);
    v3p_cleanup();
    return 0;
}

TEST(v3part_table_load_tamper_rejected)
{
    VerthysPartitionTable t, loaded;
    VerthysCngAead wrap, table_aead, wrap2, table_aead2;
    uint8_t wk[V3P_KEY_BYTES], tk[V3P_KEY_BYTES], tk2[V3P_KEY_BYTES];
    uint8_t cts[3][64 + VERTHYS_PARTITION_TAG_BYTES];
    size_t ct_lens[3];
    uint8_t nonces[3][VERTHYS_PARTITION_NONCE_BYTES];
    uint64_t counters[3];
    FILE *f;
    int c;

    v3p_cleanup();
    CHECK(v3p_build_saved_table(&t, &wrap, &table_aead, wk, tk,
                                cts, ct_lens, nonces, counters) == 0);
    f = fopen(V3P_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_partition_table_save(f, 0, &t, &table_aead) == VERTHYS_OK);
    CHECK(verthys_partition_table_destroy(&t) == VERTHYS_OK);
    verthys_cng_aead_destroy(&wrap);
    verthys_cng_aead_destroy(&table_aead);

    CHECK(v3p_reimport(&table_aead2, tk) == 0);
    CHECK(v3p_reimport(&wrap2, wk) == 0);

    /* 1) 错误表密钥（干净帧）→ AEAD 认证失败（须先于帧篡改执行：
     *    篡改为累积式，magic 损坏后 load 在帧头校验即返回 FORMAT） */
    {
        VerthysCngAead wrong_table, wrap3;
        CHECK(v3p_import_random(&wrong_table, tk2) == 0);
        CHECK(v3p_reimport(&wrap3, wk) == 0);
        CHECK(verthys_partition_table_load(f, 0, &wrong_table, &wrap3, &loaded)
              == VERTHYS_ERR_AUTH);
        verthys_cng_aead_destroy(&wrong_table);
        verthys_cng_aead_destroy(&wrap3);
    }

    /* 2) 帧密文篡改 → AEAD 认证失败 */
    CHECK(_fseeki64(f, 8 + 10, SEEK_SET) == 0);
    c = fgetc(f);
    CHECK(c != EOF);
    CHECK(_fseeki64(f, 8 + 10, SEEK_SET) == 0);
    CHECK(fputc(c ^ 0x20, f) != EOF);
    fflush(f);
    CHECK(verthys_partition_table_load(f, 0, &table_aead2, &wrap2, &loaded)
          == VERTHYS_ERR_AUTH);

    /* 3) 帧头 magic 篡改 → FORMAT */
    CHECK(_fseeki64(f, 0, SEEK_SET) == 0);
    c = fgetc(f);
    CHECK(c != EOF);
    CHECK(_fseeki64(f, 0, SEEK_SET) == 0);
    CHECK(fputc(c ^ 0x10, f) != EOF);
    fflush(f);
    CHECK(verthys_partition_table_load(f, 0, &table_aead2, &wrap2, &loaded)
          == VERTHYS_ERR_FORMAT);

    verthys_cng_aead_destroy(&table_aead2);
    verthys_cng_aead_destroy(&wrap2);
    fclose(f);

    v3p_zero_key(wk);
    v3p_zero_key(tk);
    v3p_zero_key(tk2);
    v3p_cleanup();
    return 0;
}

TEST(v3part_table_load_empty_region_rejected)
{
    VerthysPartitionTable loaded;
    VerthysCngAead table_aead, wrap;
    uint8_t tk[V3P_KEY_BYTES], wk[V3P_KEY_BYTES];
    FILE *f;

    v3p_cleanup();
    CHECK(v3p_import_random(&table_aead, tk) == 0);
    CHECK(v3p_import_random(&wrap, wk) == 0);

    /* 空文件：帧头读取失败 → FORMAT */
    f = fopen(V3P_TMP, "wb");
    CHECK(f != NULL);
    fclose(f);
    f = fopen(V3P_TMP, "rb");
    CHECK(f != NULL);
    CHECK(verthys_partition_table_load(f, 0, &table_aead, &wrap, &loaded)
          == VERTHYS_ERR_FORMAT);
    fclose(f);

    /* 未导入密钥 → LOCKED */
    {
        VerthysCngAead unimported;
        CHECK(verthys_cng_aead_init(&unimported) == VERTHYS_OK);
        f = fopen(V3P_TMP, "rb");
        CHECK(f != NULL);
        CHECK(verthys_partition_table_load(f, 0, &unimported, &wrap, &loaded)
              == VERTHYS_ERR_LOCKED);
        fclose(f);
        verthys_cng_aead_destroy(&unimported);
    }

    verthys_cng_aead_destroy(&table_aead);
    verthys_cng_aead_destroy(&wrap);
    v3p_zero_key(tk);
    v3p_zero_key(wk);
    v3p_cleanup();
    return 0;
}

TEST(v3part_table_save_rejects_invalid)
{
    VerthysPartitionTable t;
    VerthysCngAead table_aead, unimported;
    uint8_t tk[V3P_KEY_BYTES];
    FILE *f;

    v3p_cleanup();
    CHECK(verthys_partition_table_init(&t, 1) == VERTHYS_OK);
    CHECK(v3p_import_random(&table_aead, tk) == 0);
    CHECK(verthys_cng_aead_init(&unimported) == VERTHYS_OK);

    f = fopen(V3P_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_partition_table_save(NULL, 0, &t, &table_aead)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_table_save(f, 0, NULL, &table_aead)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_partition_table_save(f, 0, &t, NULL) == VERTHYS_ERR_INVALID);
    /* 表 AEAD 未导入 → LOCKED */
    CHECK(verthys_partition_table_save(f, 0, &t, &unimported)
          == VERTHYS_ERR_LOCKED);
    fclose(f);

    verthys_cng_aead_destroy(&table_aead);
    verthys_cng_aead_destroy(&unimported);
    v3p_zero_key(tk);
    v3p_cleanup();
    return 0;
}
