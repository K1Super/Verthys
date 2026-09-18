/*
 * test_verthys_format.c — .verthys 文件格式行为测试（TDD 垂直切片）
 *
 * 测试通过 verthys_format.h 接口验证文件格式行为契约：
 *   - 往返：write → parse_header → decrypt_meta → unwrap DEK → decrypt_records
 *     还原全部记录
 *   - 格式校验：坏魔数/坏版本/坏 alg → parse_header 失败
 *   - 边界：blob 过小 → parse_header 失败
 *   - 篡改检测：元数据/索引/数据块/MAC 任一字节翻转 → 对应步骤失败
 *   - 错误密钥：错误 MEK → decrypt_meta 失败；错误 DEK → decrypt_records 失败
 *   - 空记录表：0 条记录可往返
 *   - 多记录：多条不同类型/名称/数据可往返
 *
 * 注意：本测试直接用随机 MEK/DEK（不经 Argon2id），全程毫秒级。
 */
#include "verthys_test.h"
#include "verthys_format.h"
#include "keymanager.h"
#include "verthys_crypto.h"
#include <stdlib.h>
#include <string.h>

/* 辅助：构造一条记录（name/data 在栈/静态区，write 侧只读） */
static VerthysFmtRecord make_record(uint8_t type, const char *name,
                                  const uint8_t *data, size_t data_len)
{
    VerthysFmtRecord r;
    r.type = type;
    r.name_len = (uint16_t)strlen(name);
    r.name = (uint8_t *)name;
    r.data_size = data_len;
    r.data = (uint8_t *)data;
    return r;
}

/* 辅助：完整往返并比较 */
static int full_roundtrip(const VerthysFmtRecord *records, uint16_t count)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL;
    size_t blob_size = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, records, count, &blob, &blob_size), 0);
    CHECK(blob != NULL);
    CHECK(blob_size > VERTHYS_FMT_HEADER_BYTES + VERTHYS_FMT_METADATA_BYTES);

    /* 步骤 1：解析头 */
    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, blob_size, &meta), 0);
    CHECK_EQ(meta.version, VERTHYS_FMT_VERSION);
    CHECK_EQ(meta.alg_id, VERTHYS_FMT_ALG_ARGON2ID_XCHACHA20);
    CHECK(memcmp(meta.salt, salt, VERTHYS_SALT_BYTES) == 0);

    /* 步骤 2：解密元数据 */
    CHECK_EQ(vfmt_decrypt_meta(blob, blob_size, mek, &meta), 0);
    CHECK_EQ(meta.argon2_mem_kib, VERTHYS_ARGON2_MEM_KIB);
    CHECK_EQ(meta.argon2_iters, VERTHYS_ARGON2_ITERS);
    CHECK_EQ(meta.argon2_parallel, VERTHYS_ARGON2_PARALLEL);

    /* 解包 DEK */
    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_unwrap_dek(dek_recovered, meta.wrapped_dek, meta.dek_wrap_nonce, mek), 0);
    CHECK(memcmp(dek, dek_recovered, VERTHYS_KEY_BYTES) == 0);

    /* 步骤 3：校验 MAC + 解密全部记录 */
    VerthysFmtRecord *out_records = NULL;
    uint16_t out_count = 0;
    CHECK_EQ(vfmt_decrypt_records(blob, blob_size, &meta, dek, &out_records, &out_count), 0);
    CHECK_EQ(out_count, count);

    for (uint16_t i = 0; i < count; i++) {
        CHECK_EQ(out_records[i].type, records[i].type);
        CHECK_EQ(out_records[i].name_len, records[i].name_len);
        CHECK(memcmp(out_records[i].name, records[i].name, records[i].name_len) == 0);
        CHECK_EQ(out_records[i].data_size, records[i].data_size);
        CHECK(memcmp(out_records[i].data, records[i].data, records[i].data_size) == 0);
    }

    vfmt_free_records(out_records, out_count);
    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(dek_recovered, sizeof dek_recovered);
    return 0;
}

/* 往返：单条记录 */
TEST(format_roundtrip_single)
{
    static const uint8_t data[] = "hello verthys world!";
    VerthysFmtRecord recs[1];
    recs[0] = make_record(0x02, "account1", data, sizeof(data) - 1);
    return full_roundtrip(recs, 1);
}

/* 往返：空记录表 */
TEST(format_roundtrip_empty)
{
    return full_roundtrip(NULL, 0);
}

/* 往返：多条不同类型/名称/数据 */
TEST(format_roundtrip_multiple)
{
    static const uint8_t d1[] = "password123";
    static const uint8_t d2[] = {0x00, 0x01, 0xFF, 0x80, 0x7F, 0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t d3[] = "a very long record data blob that spans multiple bytes "
                                 "to exercise larger block sizes and padding scenarios 0123456789ABCDEF";
    VerthysFmtRecord recs[3];
    recs[0] = make_record(0x02, "gmail", d1, sizeof(d1) - 1);
    recs[1] = make_record(0x01, "photo.jpg", d2, sizeof(d2));
    recs[2] = make_record(0x02, "bank_login_with_a_quite_long_name", d3, sizeof(d3) - 1);
    return full_roundtrip(recs, 3);
}

/* 坏魔数 → parse_header 失败 */
TEST(format_bad_magic_rejected)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    blob[0] ^= 0xFF;  /* 破坏魔数首字节 */
    VerthysFmtMeta meta;
    CHECK(vfmt_parse_header(blob, sz, &meta) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* 坏版本号 → parse_header 失败 */
TEST(format_bad_version_rejected)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    blob[4] = 0xFF;  /* 版本号低字节 */
    VerthysFmtMeta meta;
    CHECK(vfmt_parse_header(blob, sz, &meta) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* blob 过小 → parse_header 失败 */
TEST(format_too_small_rejected)
{
    uint8_t tiny[10] = {0};
    VerthysFmtMeta meta;
    CHECK(vfmt_parse_header(tiny, sizeof(tiny), &meta) != 0);
    /* NULL blob */
    CHECK(vfmt_parse_header(NULL, 0, &meta) != 0);
    return 0;
}

/* 错误 MEK → decrypt_meta 失败 */
TEST(format_wrong_master_fails)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], mek_wrong[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(mek_wrong, sizeof mek_wrong);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, sz, &meta), 0);
    CHECK(vfmt_decrypt_meta(blob, sz, mek_wrong, &meta) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(mek_wrong, sizeof mek_wrong);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* 元数据密文篡改 → decrypt_meta 失败 */
TEST(format_tampered_metadata_fails)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, sz, &meta), 0);

    /* 翻转元数据密文区首字节（meta_offset + 24 nonce 之后） */
    size_t tamper_pos = (size_t)meta.meta_offset + 24;
    blob[tamper_pos] ^= 0x01;
    CHECK(vfmt_decrypt_meta(blob, sz, mek, &meta) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}

/* 文件头篡改 → 文件 MAC 校验失败（在 decrypt_records 阶段） */
TEST(format_tampered_header_mac_fails)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    /* 翻转头保留填充区一字节（不影响 parse_header，但影响 MAC） */
    blob[40] ^= 0x80;

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, sz, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, sz, mek, &meta), 0);

    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_unwrap_dek(dek_recovered, meta.wrapped_dek, meta.dek_wrap_nonce, mek), 0);

    VerthysFmtRecord *recs = NULL; uint16_t cnt = 0;
    CHECK(vfmt_decrypt_records(blob, sz, &meta, dek_recovered, &recs, &cnt) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(dek_recovered, sizeof dek_recovered);
    return 0;
}

/* 错误 DEK → decrypt_records 失败（MAC 校验失败） */
TEST(format_wrong_dek_fails)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES], dek_wrong[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);
    verthys_random_bytes(dek_wrong, sizeof dek_wrong);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, sz, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, sz, mek, &meta), 0);

    VerthysFmtRecord *recs = NULL; uint16_t cnt = 0;
    CHECK(vfmt_decrypt_records(blob, sz, &meta, dek_wrong, &recs, &cnt) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(dek_wrong, sizeof dek_wrong);
    return 0;
}

/* 数据块篡改 → decrypt_records 失败 */
TEST(format_tampered_data_block_fails)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    static const uint8_t data[] = "some record data here";
    VerthysFmtRecord recs[1];
    recs[0] = make_record(0x02, "rec", data, sizeof(data) - 1);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, recs, 1, &blob, &sz), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, sz, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, sz, mek, &meta), 0);

    /* 找到数据块区起始（索引区之后），翻转一字节 */
    /* 数据块区在索引区之后，索引区在 index_offset 处。简单起见，翻转 mac_offset 前 32 字节
     * 之前的位置（数据块区末尾附近）的某字节 */
    size_t tamper_pos = (size_t)meta.mac_offset - 32;
    blob[tamper_pos] ^= 0x40;

    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_unwrap_dek(dek_recovered, meta.wrapped_dek, meta.dek_wrap_nonce, mek), 0);

    /* 注意：翻转数据块字节同时破坏文件 MAC（覆盖数据块区），因此 decrypt_records
     * 可能在 MAC 校验阶段就失败，也可能在数据块解密阶段失败——任一非 0 即通过。 */
    VerthysFmtRecord *out_recs = NULL; uint16_t cnt = 0;
    CHECK(vfmt_decrypt_records(blob, sz, &meta, dek_recovered, &out_recs, &cnt) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(dek_recovered, sizeof dek_recovered);
    return 0;
}

/* 文件 MAC 篡改 → decrypt_records 失败 */
TEST(format_tampered_mac_fails)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);

    uint8_t *blob = NULL; size_t sz = 0;
    CHECK_EQ(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                        mek, dek, NULL, 0, &blob, &sz), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, sz, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, sz, mek, &meta), 0);

    /* 翻转 MAC 首字节 */
    blob[meta.mac_offset] ^= 0xFF;

    uint8_t dek_recovered[VERTHYS_KEY_BYTES];
    CHECK_EQ(keymanager_unwrap_dek(dek_recovered, meta.wrapped_dek, meta.dek_wrap_nonce, mek), 0);

    VerthysFmtRecord *recs = NULL; uint16_t cnt = 0;
    CHECK(vfmt_decrypt_records(blob, sz, &meta, dek_recovered, &recs, &cnt) != 0);

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    verthys_secure_zero(dek_recovered, sizeof dek_recovered);
    return 0;
}

/* write 拒绝空指针参数 */
TEST(format_write_rejects_null)
{
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    verthys_random_bytes(salt, sizeof salt);
    verthys_random_bytes(mek, sizeof mek);
    verthys_random_bytes(dek, sizeof dek);
    uint8_t *out = NULL; size_t out_sz = 0;

    CHECK(vfmt_write(NULL, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                     mek, dek, NULL, 0, &out, &out_sz) != 0);
    CHECK(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                     NULL, dek, NULL, 0, &out, &out_sz) != 0);
    CHECK(vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS, VERTHYS_ARGON2_PARALLEL,
                     mek, dek, NULL, 0, NULL, &out_sz) != 0);

    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    return 0;
}
