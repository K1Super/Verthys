/*
 * test_v4_records.c — v4 记录加密与名称盲索引验收
 *
 * 覆盖：
 *   - 名称/数据密封与打开往返（含空字段）
 *   - 模块 UUID / epoch / 记录 ID 的 AAD 绑定
 *   - 密文篡改一律拒绝，且失败不返回部分明文
 *   - 超长名称/数据在分配前拒绝
 *   - 盲索引：NFKC 等价写法同索引、跨模块不可关联、非法 UTF-8 拒绝
 *   - 明文回退开关显式拒绝
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_record_v4.h"
#include "vty_util.h"

#include <string.h>

static void rec_keys(uint8_t mdek[VTY_KEY_BYTES],
                     uint8_t uuid[VTY_UUID_BYTES], uint8_t seed)
{
    memset(mdek, seed, VTY_KEY_BYTES);
    memset(uuid, (uint8_t)(seed + 1u), VTY_UUID_BYTES);
}

static void rec_free(uint8_t *p, size_t n)
{
    vty_free(p, n);
}

static int rec_contains(const uint8_t *hay, size_t hay_len,
                        const char *needle, size_t needle_len)
{
    size_t i;

    if (needle_len == 0 || needle_len > hay_len) return 0;
    for (i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) return 1;
    }
    return 0;
}

TEST(v4_record_roundtrip)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t *name = NULL;
    uint8_t *data = NULL;
    size_t name_len = 0;
    size_t data_len = 0;
    const char *nm = "account-42";
    const char *dt = "{\"secret\":true}";

    rec_keys(mdek, uuid, 0x10);
    CHECK_EQ(vty_record_seal(mdek, uuid, 42, 3,
                             (const uint8_t *)nm, strlen(nm),
                             (const uint8_t *)dt, strlen(dt),
                             &blob, &blob_len), VTY_OK);
    CHECK(blob != NULL && blob_len > 0);

    /* 静态存储中不得出现名称/数据明文 */
    CHECK_EQ(rec_contains(blob, blob_len, nm, strlen(nm)), 0);
    CHECK_EQ(rec_contains(blob, blob_len, dt, strlen(dt)), 0);

    CHECK_EQ(vty_record_open(mdek, uuid, 3, blob, blob_len,
                             &name, &name_len, &data, &data_len), VTY_OK);
    CHECK_EQ(name_len, strlen(nm));
    CHECK_EQ(data_len, strlen(dt));
    CHECK_EQ(memcmp(name, nm, name_len), 0);
    CHECK_EQ(memcmp(data, dt, data_len), 0);

    rec_free(name, name_len);
    rec_free(data, data_len);
    rec_free(blob, blob_len);

    /* 空名称 + 空数据仍应往返成功 */
    blob = NULL;
    CHECK_EQ(vty_record_seal(mdek, uuid, 1, 3, NULL, 0, NULL, 0,
                             &blob, &blob_len), VTY_OK);
    CHECK_EQ(vty_record_open(mdek, uuid, 3, blob, blob_len,
                             &name, &name_len, &data, &data_len), VTY_OK);
    CHECK_EQ(name_len, 0);
    CHECK_EQ(data_len, 0);
    rec_free(name, 1);
    rec_free(data, 1);
    rec_free(blob, blob_len);
    return 0;
}

TEST(v4_record_aad_binding)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t other_uuid[VTY_UUID_BYTES];
    uint8_t other_mdek[VTY_KEY_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t *name = NULL;
    uint8_t *data = NULL;
    size_t name_len = 0;
    size_t data_len = 0;
    uint8_t bad[256];
    size_t i;

    rec_keys(mdek, uuid, 0x20);
    rec_keys(other_mdek, other_uuid, 0x30);
    CHECK_EQ(memcmp(mdek, other_mdek, VTY_KEY_BYTES) != 0, 1);

    CHECK_EQ(vty_record_seal(mdek, uuid, 7, 9,
                             (const uint8_t *)"n", 1,
                             (const uint8_t *)"d", 1, &blob, &blob_len),
             VTY_OK);

    /* 模块 UUID 不匹配 */
    CHECK(vty_record_open(mdek, other_uuid, 9, blob, blob_len,
                          &name, &name_len, &data, &data_len) != VTY_OK);
    /* epoch 不匹配 */
    CHECK(vty_record_open(mdek, uuid, 10, blob, blob_len,
                          &name, &name_len, &data, &data_len) != VTY_OK);
    /* MDEK 不匹配 */
    CHECK(vty_record_open(other_mdek, uuid, 9, blob, blob_len,
                          &name, &name_len, &data, &data_len) != VTY_OK);

    /* 前缀记录 ID 篡改：AAD 以存储值为准，必须认证失败 */
    CHECK(blob_len < sizeof(bad));
    memcpy(bad, blob, blob_len);
    bad[0] ^= 0x01u;
    CHECK(vty_record_open(mdek, uuid, 9, bad, blob_len,
                          &name, &name_len, &data, &data_len) != VTY_OK);

    /* 密文位翻转 */
    memcpy(bad, blob, blob_len);
    for (i = 40; i < blob_len; i++) {
        memcpy(bad, blob, blob_len);
        bad[i] ^= 0x01u;
        CHECK(vty_record_open(mdek, uuid, 9, bad, blob_len,
                              &name, &name_len, &data, &data_len) != VTY_OK);
    }
    /* 截断 */
    CHECK(vty_record_open(mdek, uuid, 9, blob, blob_len - 1u,
                          &name, &name_len, &data, &data_len) != VTY_OK);

    rec_free(blob, blob_len);
    return 0;
}

TEST(v4_record_size_guard_rejected)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t dummy[4] = {0};

    rec_keys(mdek, uuid, 0x40);

    CHECK_EQ(vty_record_seal(mdek, uuid, 1, 1, dummy,
                             (size_t)VTY_RECORD_MAX_NAME + 1u,
                             dummy, 1, &blob, &blob_len), VTY_E_INVALID);
    CHECK_EQ(vty_record_seal(mdek, uuid, 1, 1, dummy, 1, dummy,
                             (size_t)VTY_RECORD_MAX_DATA + 1u,
                             &blob, &blob_len), VTY_E_INVALID);
    CHECK_EQ(vty_record_seal(NULL, uuid, 1, 1, dummy, 1, dummy, 1,
                             &blob, &blob_len), VTY_E_INVALID);
    {
        uint8_t *name = NULL;
        uint8_t *data = NULL;
        size_t name_len = 0;
        size_t data_len = 0;
        CHECK_EQ(vty_record_open(mdek, uuid, 1, NULL, 10,
                                 &name, &name_len, &data, &data_len),
                 VTY_E_INVALID);
        CHECK(name == NULL && data == NULL);
    }
    return 0;
}

TEST(v4_name_index_nfkc_and_separation)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t uuid2[VTY_UUID_BYTES];
    uint8_t a[VTY_HASH_BYTES];
    uint8_t b[VTY_HASH_BYTES];

    rec_keys(mdek, uuid, 0x50);
    memset(uuid2, 0x52, VTY_UUID_BYTES);

    /* 全角 ABC 与 ASCII ABC 在 NFKC 下等价 */
    CHECK_EQ(vty_name_index(mdek, uuid,
                            (const uint8_t *)"\xEF\xBC\xA1\xEF\xBC\xA2\xEF\xBC\xA3",
                            9, a), VTY_OK);
    CHECK_EQ(vty_name_index(mdek, uuid, (const uint8_t *)"ABC", 3, b), VTY_OK);
    CHECK_EQ(memcmp(a, b, VTY_HASH_BYTES), 0);

    /* U+FB01 连字 ﬁ → fi */
    CHECK_EQ(vty_name_index(mdek, uuid, (const uint8_t *)"\xEF\xAC\x81", 3, a),
             VTY_OK);
    CHECK_EQ(vty_name_index(mdek, uuid, (const uint8_t *)"fi", 2, b), VTY_OK);
    CHECK_EQ(memcmp(a, b, VTY_HASH_BYTES), 0);

    /* 不同模块同一名称不可关联 */
    CHECK_EQ(vty_name_index(mdek, uuid, (const uint8_t *)"same", 4, a), VTY_OK);
    CHECK_EQ(vty_name_index(mdek, uuid2, (const uint8_t *)"same", 4, b), VTY_OK);
    CHECK(memcmp(a, b, VTY_HASH_BYTES) != 0);

    /* 非法 UTF-8 必须拒绝，而不是按字节近似处理后产生伪索引 */
    CHECK(vty_name_index(mdek, uuid, (const uint8_t *)"\xFF\xFE", 2, a) != VTY_OK);
    CHECK_EQ(vty_name_index(NULL, uuid, (const uint8_t *)"x", 1, a),
             VTY_E_INVALID);
    return 0;
}

TEST(v4_record_plaintext_fallback_forbidden)
{
    CHECK_EQ(vty_record_reject_plaintext(1), VTY_OK);
    CHECK_EQ(vty_record_reject_plaintext(0), VTY_E_PLAINTEXT_FORBIDDEN);
    return 0;
}
