/*
 * test_chunks.c — 分片与文件清单加密验收
 *
 * 覆盖：
 *   - 分片往返（含空分片）
 *   - seq / total / epoch / file_uuid 全部进入 AAD 与派生，任一不匹配即拒绝
 *   - 密文篡改与截断拒绝
 *   - 键控分片 ID：同文件同序号稳定，跨序号/跨文件/跨 MDEK 不可关联
 *   - 清单往返、篡改拒绝、长度预算拒绝
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_chunk.h"
#include "vty_blake3.h"
#include "vty_util.h"

#include <string.h>

static void chunk_inputs(uint8_t mdek[VTY_KEY_BYTES],
                         uint8_t uuid[VTY_UUID_BYTES], uint8_t seed)
{
    memset(mdek, seed, VTY_KEY_BYTES);
    memset(uuid, (uint8_t)(seed + 1u), VTY_UUID_BYTES);
}

TEST(chunk_roundtrip)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t uuid2[VTY_UUID_BYTES];
    uint8_t mdek2[VTY_KEY_BYTES];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    const char *payload = "chunk-payload-0123456789";

    chunk_inputs(mdek, uuid, 0x60);
    memset(uuid2, 0x63, VTY_UUID_BYTES);
    memset(mdek2, 0x64, VTY_KEY_BYTES);

    CHECK_EQ(vty_chunk_seal(mdek, uuid, 1, 4, 11,
                            (const uint8_t *)payload, strlen(payload),
                            &ct, &ct_len), VTY_OK);
    CHECK_EQ(vty_chunk_open(mdek, uuid, 1, 4, 11, ct, ct_len,
                            &pt, &pt_len), VTY_OK);
    CHECK_EQ(pt_len, strlen(payload));
    CHECK_EQ(memcmp(pt, payload, pt_len), 0);
    vty_free(pt, pt_len);
    vty_free(ct, ct_len);

    /* 空分片 */
    ct = NULL;
    CHECK_EQ(vty_chunk_seal(mdek, uuid, 0, 1, 11, NULL, 0, &ct, &ct_len),
             VTY_OK);
    CHECK_EQ(vty_chunk_open(mdek, uuid, 0, 1, 11, ct, ct_len,
                            &pt, &pt_len), VTY_OK);
    CHECK_EQ(pt_len, 0);
    vty_free(pt, 1);
    vty_free(ct, ct_len);

    /* 入参非法 */
    CHECK_EQ(vty_chunk_seal(mdek, uuid, 4, 4, 11,
                            (const uint8_t *)payload, 1, &ct, &ct_len),
             VTY_E_INVALID);
    CHECK_EQ(vty_chunk_seal(mdek, uuid, 0, 0, 11,
                            (const uint8_t *)payload, 1, &ct, &ct_len),
             VTY_E_INVALID);
    return 0;
}

TEST(chunk_aad_binding)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t other[VTY_UUID_BYTES];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    uint8_t bad[512];
    size_t i;

    chunk_inputs(mdek, uuid, 0x70);
    memset(other, 0x72, VTY_UUID_BYTES);

    CHECK_EQ(vty_chunk_seal(mdek, uuid, 2, 5, 13,
                            (const uint8_t *)"abcdef", 6, &ct, &ct_len),
             VTY_OK);

    /* 序号 / 总数 / epoch / 文件 UUID 不匹配 */
    CHECK(vty_chunk_open(mdek, uuid, 1, 5, 13, ct, ct_len, &pt, &pt_len) != VTY_OK);
    CHECK(vty_chunk_open(mdek, uuid, 2, 6, 13, ct, ct_len, &pt, &pt_len) != VTY_OK);
    CHECK(vty_chunk_open(mdek, uuid, 2, 5, 14, ct, ct_len, &pt, &pt_len) != VTY_OK);
    CHECK(vty_chunk_open(mdek, other, 2, 5, 13, ct, ct_len, &pt, &pt_len) != VTY_OK);

    /* 密文位翻转与截断 */
    CHECK(ct_len <= sizeof(bad));
    for (i = 0; i < ct_len; i++) {
        memcpy(bad, ct, ct_len);
        bad[i] ^= 0x01u;
        CHECK(vty_chunk_open(mdek, uuid, 2, 5, 13, bad, ct_len,
                             &pt, &pt_len) != VTY_OK);
    }
    CHECK(vty_chunk_open(mdek, uuid, 2, 5, 13, ct, ct_len - 1u,
                         &pt, &pt_len) != VTY_OK);

    vty_free(ct, ct_len);
    return 0;
}

TEST(chunk_id_unlinkable)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t uuid2[VTY_UUID_BYTES];
    uint8_t mdek2[VTY_KEY_BYTES];
    uint8_t a[VTY_HASH_BYTES];
    uint8_t b[VTY_HASH_BYTES];

    chunk_inputs(mdek, uuid, 0x80);
    memset(uuid2, 0x83, VTY_UUID_BYTES);
    memset(mdek2, 0x84, VTY_KEY_BYTES);

    CHECK_EQ(vty_chunk_id(mdek, uuid, 3, a), VTY_OK);
    CHECK_EQ(vty_chunk_id(mdek, uuid, 3, b), VTY_OK);
    CHECK_EQ(memcmp(a, b, VTY_HASH_BYTES), 0);

    CHECK_EQ(vty_chunk_id(mdek, uuid, 4, b), VTY_OK);
    CHECK(memcmp(a, b, VTY_HASH_BYTES) != 0);

    CHECK_EQ(vty_chunk_id(mdek, uuid2, 3, b), VTY_OK);
    CHECK(memcmp(a, b, VTY_HASH_BYTES) != 0);

    CHECK_EQ(vty_chunk_id(mdek2, uuid, 3, b), VTY_OK);
    CHECK(memcmp(a, b, VTY_HASH_BYTES) != 0);
    return 0;
}

TEST(manifest_roundtrip)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t ids[2 * VTY_HASH_BYTES];
    uint8_t got_hash[VTY_HASH_BYTES];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t *got_ids = NULL;
    uint32_t total = 0;

    chunk_inputs(mdek, uuid, 0x90);
    memset(pt_hash, 0x91, sizeof(pt_hash));
    memset(ids, 0x92, sizeof(ids));

    CHECK_EQ(vty_manifest_seal(mdek, uuid, 5, pt_hash, 2, ids,
                               &ct, &ct_len), VTY_OK);
    CHECK_EQ(vty_manifest_open(mdek, uuid, 5, ct, ct_len,
                               got_hash, &total, &got_ids), VTY_OK);
    CHECK_EQ(total, 2);
    CHECK_EQ(memcmp(got_hash, pt_hash, VTY_HASH_BYTES), 0);
    CHECK_EQ(memcmp(got_ids, ids, sizeof(ids)), 0);
    vty_free(got_ids, sizeof(ids));
    vty_free(ct, ct_len);

    /* 总数为 0 / 缺少 chunk_ids */
    CHECK_EQ(vty_manifest_seal(mdek, uuid, 5, pt_hash, 0, ids,
                               &ct, &ct_len), VTY_E_INVALID);
    CHECK_EQ(vty_manifest_seal(mdek, uuid, 5, pt_hash, 2, NULL,
                               &ct, &ct_len), VTY_E_INVALID);
    return 0;
}

TEST(manifest_tamper_rejected)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t ids[VTY_HASH_BYTES];
    uint8_t got_hash[VTY_HASH_BYTES];
    uint8_t bad[512];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t *got_ids = NULL;
    uint32_t total = 0;
    size_t i;

    chunk_inputs(mdek, uuid, 0xa0);
    memset(pt_hash, 0xa1, sizeof(pt_hash));
    memset(ids, 0xa2, sizeof(ids));

    CHECK_EQ(vty_manifest_seal(mdek, uuid, 1, pt_hash, 1, ids,
                               &ct, &ct_len), VTY_OK);
    CHECK(ct_len <= sizeof(bad));

    /* epoch / file_uuid 不匹配 */
    CHECK(vty_manifest_open(mdek, uuid, 2, ct, ct_len,
                            got_hash, &total, &got_ids) != VTY_OK);
    {
        uint8_t other[VTY_UUID_BYTES];
        memset(other, 0xa5, VTY_UUID_BYTES);
        CHECK(vty_manifest_open(mdek, other, 1, ct, ct_len,
                                got_hash, &total, &got_ids) != VTY_OK);
    }

    /* 密文任意位翻转与截断 */
    for (i = 0; i < ct_len; i++) {
        memcpy(bad, ct, ct_len);
        bad[i] ^= 0x01u;
        CHECK(vty_manifest_open(mdek, uuid, 1, bad, ct_len,
                                got_hash, &total, &got_ids) != VTY_OK);
    }
    CHECK(vty_manifest_open(mdek, uuid, 1, ct, ct_len - 1u,
                            got_hash, &total, &got_ids) != VTY_OK);

    /* 超长输入：按清单上限推导的长度预算先拒绝，避免巨量分配 */
    {
        size_t over = VTY_UUID_BYTES + VTY_HASH_BYTES + 4u +
                      (size_t)VTY_MANIFEST_MAX_CHUNKS * VTY_HASH_BYTES +
                      VTY_NONCE_BYTES + VTY_TAG_BYTES + 1u;
        uint8_t *huge = (uint8_t *)vty_alloc(over);
        CHECK(huge != NULL);
        memset(huge, 0, over);
        CHECK_EQ(vty_manifest_open(mdek, uuid, 1, huge, over,
                                   got_hash, &total, &got_ids),
                 VTY_E_INVALID);
        vty_free(huge, over);
    }

    vty_free(ct, ct_len);
    return 0;
}

/* 1GiB 往返：按 1MiB 分片流式封装/解封，验证随机访问（断点续传）与
 * 1024 项清单；只在内存保留单片明文与密文，避免峰值内存放大。 */
TEST(large_file_1gb_roundtrip)
{
    enum { CHUNK_BYTES = 1024 * 1024, CHUNK_COUNT = 1024 };
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t *pt = NULL;
    uint8_t *ids = NULL;
    uint8_t *ct = NULL;
    uint8_t *out = NULL;
    uint8_t *got_ids = NULL;
    size_t ct_len = 0;
    size_t out_len = 0;
    uint8_t h_in[VTY_HASH_BYTES];
    uint8_t h_out[VTY_HASH_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t got_hash[VTY_HASH_BYTES];
    uint32_t total = 0;
    uint32_t i;
    int ok = 1;

    chunk_inputs(mdek, uuid, 0xb0);
    memset(pt_hash, 0xb1, sizeof(pt_hash));

    pt = (uint8_t *)vty_alloc(CHUNK_BYTES);
    ids = (uint8_t *)vty_alloc((size_t)CHUNK_COUNT * VTY_HASH_BYTES);
    if (pt == NULL || ids == NULL) ok = 0;

    for (i = 0; ok && i < (uint32_t)CHUNK_COUNT; i++) {
        memset(pt, (int)(i & 0xFFu), CHUNK_BYTES);
        memcpy(pt, &i, sizeof(i));
        if (vty_blake3_32(pt, CHUNK_BYTES, h_in) != VTY_OK ||
            vty_chunk_seal(mdek, uuid, i, CHUNK_COUNT, 7,
                           pt, CHUNK_BYTES, &ct, &ct_len) != VTY_OK ||
            vty_chunk_open(mdek, uuid, i, CHUNK_COUNT, 7,
                           ct, ct_len, &out, &out_len) != VTY_OK ||
            out_len != CHUNK_BYTES) {
            ok = 0;
            break;
        }
        vty_blake3_32(out, out_len, h_out);
        if (memcmp(h_in, h_out, VTY_HASH_BYTES) != 0) ok = 0;
        if (ok && vty_chunk_id(mdek, uuid, i, ids + (size_t)i * VTY_HASH_BYTES)
                  != VTY_OK) {
            ok = 0;
        }
        vty_free(ct, ct_len); ct = NULL; ct_len = 0;
        vty_free(out, out_len); out = NULL; out_len = 0;
    }

    /* 随机访问：只解第 700 片也能成功（断点续传不要求顺序） */
    if (ok) {
        memset(pt, 0, CHUNK_BYTES);
        memcpy(pt, "resume", 6);
        if (vty_chunk_seal(mdek, uuid, 700, CHUNK_COUNT, 7,
                           pt, CHUNK_BYTES, &ct, &ct_len) != VTY_OK ||
            vty_chunk_open(mdek, uuid, 700, CHUNK_COUNT, 7,
                           ct, ct_len, &out, &out_len) != VTY_OK ||
            memcmp(out, "resume", 6) != 0) {
            ok = 0;
        }
        vty_free(ct, ct_len); ct = NULL; ct_len = 0;
        vty_free(out, out_len); out = NULL; out_len = 0;
    }

    /* 1024 项清单往返 */
    if (ok) {
        if (vty_manifest_seal(mdek, uuid, 7, pt_hash, CHUNK_COUNT, ids,
                              &ct, &ct_len) != VTY_OK ||
            vty_manifest_open(mdek, uuid, 7, ct, ct_len,
                              got_hash, &total, &got_ids) != VTY_OK ||
            total != CHUNK_COUNT ||
            memcmp(got_hash, pt_hash, VTY_HASH_BYTES) != 0 ||
            memcmp(got_ids, ids, (size_t)CHUNK_COUNT * VTY_HASH_BYTES) != 0) {
            ok = 0;
        }
    }

    vty_free(ct, ct_len);
    vty_free(out, out_len);
    vty_free(got_ids, (size_t)CHUNK_COUNT * VTY_HASH_BYTES);
    if (ids != NULL) vty_free(ids, (size_t)CHUNK_COUNT * VTY_HASH_BYTES);
    if (pt != NULL) vty_free(pt, CHUNK_BYTES);
    CHECK(ok);
    return 0;
}
