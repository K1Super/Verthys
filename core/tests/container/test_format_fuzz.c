/*
 * test_format_fuzz.c — 文件格式变异 / 篡改检测测试
 *
 * 验证安全特性：
 *   - 防篡改体系：任何篡改均导致校验失败
 *   - 零明文结构：除文件头外全部加密或认证
 *
 * 两类测试：
 *   1. 端到端（通过 Verthys_Unlock）：header 级变异，不需 Argon2id
 *   2. 格式级（通过 vfmt_* 内部函数 + 已知密钥）：加密区变异，不需 Argon2id
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_format.h"
#include "verthys_crypto.h"
#include "keymanager.h"
#include "verthys_container_v3.h"   /* V3 三副本布局（帧头字段翻转） */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TMP_VERTHYS "test_fuzz_tmp.verthys"

static void cleanup_tmp(void) { remove(TMP_VERTHYS); }

/* 辅助：创建有效 verthys 文件（通过公共 API，含 1 次 Argon2id） */
static int create_valid_verthys_file(const char *password, size_t pw_len)
{
    cleanup_tmp();
    VerthysHandle h;
    if (Verthys_Init(&h) != VERTHYS_OK) return -1;
    if (Verthys_CreateWithPreset(h, TMP_VERTHYS, password, pw_len, VERTHYS_PRESET_BALANCED) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "test", 4, (const uint8_t *)"data1234", 8};
    uint64_t id;
    if (Verthys_AddRecord(h, &r, &id) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    int rc = Verthys_Lock(h);
    Verthys_Deinit(h);
    return rc == VERTHYS_OK ? 0 : -1;
}

/* 辅助：读文件到 buffer */
static int read_file_to_buf(const char *path, uint8_t **out_buf, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);
    *out_buf = buf;
    *out_size = sz;
    return 0;
}

/* 辅助：写 buffer 到文件 */
static int write_buf_to_file(const char *path, const uint8_t *buf, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, size, f) != size) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* =================== 端到端 header 变异（不需 Argon2id） =================== */

/* 空文件 → FORMAT */
TEST(fuzz_empty_file)
{
    cleanup_tmp();
    FILE *f = fopen(TMP_VERTHYS, "wb");
    CHECK(f != NULL);
    fclose(f);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 过小文件 → FORMAT */
TEST(fuzz_too_small)
{
    cleanup_tmp();
    FILE *f = fopen(TMP_VERTHYS, "wb");
    CHECK(f != NULL);
    fwrite("SMALL", 1, 5, f);
    fclose(f);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 全零文件（>= 56 字节）→ FORMAT */
TEST(fuzz_all_zero_file)
{
    cleanup_tmp();
    uint8_t zeros[128] = {0};
    CHECK_EQ(write_buf_to_file(TMP_VERTHYS, zeros, sizeof(zeros)), 0);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 随机垃圾 → FORMAT */
TEST(fuzz_random_garbage)
{
    cleanup_tmp();
    uint8_t garbage[256];
    for (int i = 0; i < 256; i++) garbage[i] = (uint8_t)(i * 7 + 13);
    CHECK_EQ(write_buf_to_file(TMP_VERTHYS, garbage, sizeof(garbage)), 0);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 魔数翻转 → FORMAT（不需 Argon2id，parse_header 直接拒绝） */
TEST(fuzz_bit_flip_magic)
{
    CHECK_EQ(create_valid_verthys_file("pw", 2), 0);

    uint8_t *buf = NULL;
    size_t size = 0;
    CHECK_EQ(read_file_to_buf(TMP_VERTHYS, &buf, &size), 0);

    /* 翻转 magic 第一字节 */
    buf[0] ^= 0x01;
    CHECK_EQ(write_buf_to_file(TMP_VERTHYS, buf, size), 0);
    free(buf);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 版本号翻转 → 拒绝 */
TEST(fuzz_bit_flip_version)
{
    CHECK_EQ(create_valid_verthys_file("pw", 2), 0);

    uint8_t *buf = NULL;
    size_t size = 0;
    CHECK_EQ(read_file_to_buf(TMP_VERTHYS, &buf, &size), 0);

    /* V3 适配（法定人数语义）：V3 无明文文件头，超块版本在 FlatBuffers 载荷
     * 内部（偏移随 schema 演化，不可稳定定位）。等价的头部字段变异 =
     * 三副本帧头 payload_len LSB（+4/+0x4004/+0x8004）各翻一位：帧结构
     * 仍合法（verifier 容忍尾部字节），但 HMAC 计算域随长度漂移 → 3 副本
     * 全败 → 口令正确探针判真损坏 → 拒绝（CORRUPT）。单副本翻转会被
     * 2/3 多数派票决出局、解锁照常成功——那是法定人数设计容错而非缺陷。 */
    for (unsigned rep = 0; rep < VERTHYS_V3_SB_REPLICA_COUNT; rep++) {
        buf[(size_t)(rep * 0x4000u) + 4u] ^= 0x01;
    }
    CHECK_EQ(write_buf_to_file(TMP_VERTHYS, buf, size), 0);
    free(buf);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    VerthysResult rc = Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0);
    CHECK(rc == VERTHYS_ERR_AUTH || rc == VERTHYS_ERR_CORRUPT ||
          rc == VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 截断到 header 大小 → FORMAT */
TEST(fuzz_truncated_header)
{
    CHECK_EQ(create_valid_verthys_file("pw", 2), 0);

    uint8_t *buf = NULL;
    size_t size = 0;
    CHECK_EQ(read_file_to_buf(TMP_VERTHYS, &buf, &size), 0);

    /* 截断到 56 字节（仅 header） */
    CHECK_EQ(write_buf_to_file(TMP_VERTHYS, buf, VERTHYS_FMT_HEADER_BYTES), 0);
    free(buf);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);
    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* =================== 格式级变异（已知密钥，不需 Argon2id） =================== */

/* 辅助：用固定密钥创建有效 blob */
static int create_valid_blob_with_keys(uint8_t **out_blob, size_t *out_size,
                                       uint8_t out_salt[VERTHYS_SALT_BYTES],
                                       uint8_t out_mek[VERTHYS_KEY_BYTES],
                                       uint8_t out_dek[VERTHYS_KEY_BYTES])
{
    /* 固定密钥（非秘密，仅测试用） */
    static const uint8_t salt[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    static const uint8_t mek[32] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
    };
    static const uint8_t dek[32] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50
    };

    VerthysFmtRecord rec = {0x02, 4, (uint8_t *)"test", 4, (uint8_t *)"data"};

    int rc = vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS,
                        VERTHYS_ARGON2_PARALLEL, mek, dek,
                        &rec, 1, out_blob, out_size);
    if (rc != 0) return -1;

    memcpy(out_salt, salt, 16);
    memcpy(out_mek, mek, 32);
    memcpy(out_dek, dek, 32);
    return 0;
}

/* 元数据区截断 → decrypt_meta 失败 */
TEST(fuzz_truncated_metadata)
{
    verthys_crypto_init();

    uint8_t *blob = NULL, salt[16], mek[32], dek[32];
    size_t size = 0;
    CHECK_EQ(create_valid_blob_with_keys(&blob, &size, salt, mek, dek), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, size, &meta), 0);

    /* 截断到 metadata 中间 */
    size_t truncated = meta.meta_offset + 100;
    CHECK(truncated < size);

    VerthysFmtMeta meta2;
    CHECK(vfmt_parse_header(blob, truncated, &meta2) != 0);

    free(blob);
    return 0;
}

/* 元数据区位翻转 → decrypt_meta 失败 */
TEST(fuzz_bit_flip_metadata)
{
    verthys_crypto_init();

    uint8_t *blob = NULL, salt[16], mek[32], dek[32];
    size_t size = 0;
    CHECK_EQ(create_valid_blob_with_keys(&blob, &size, salt, mek, dek), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, size, &meta), 0);

    /* 翻转 metadata 区的密文部分（nonce 之后） */
    size_t flip_offset = (size_t)meta.meta_offset + 24 + 10;
    CHECK(flip_offset < size);
    blob[flip_offset] ^= 0x01;

    /* parse_header 仍成功（header 未变） */
    VerthysFmtMeta meta2;
    CHECK_EQ(vfmt_parse_header(blob, size, &meta2), 0);

    /* decrypt_meta 失败（AEAD 认证失败） */
    CHECK(vfmt_decrypt_meta(blob, size, mek, &meta2) != 0);

    free(blob);
    return 0;
}

/* 全文件 MAC 位翻转 → decrypt_records 失败 */
TEST(fuzz_bit_flip_mac)
{
    verthys_crypto_init();

    uint8_t *blob = NULL, salt[16], mek[32], dek[32];
    size_t size = 0;
    CHECK_EQ(create_valid_blob_with_keys(&blob, &size, salt, mek, dek), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, size, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, size, mek, &meta), 0);

    /* 翻转 MAC 区域的第一字节 */
    size_t mac_off = (size_t)meta.mac_offset;
    CHECK(mac_off < size);
    blob[mac_off] ^= 0x01;

    /* decrypt_records 失败（HMAC 校验失败） */
    VerthysFmtRecord *recs = NULL;
    uint16_t count = 0;
    CHECK(vfmt_decrypt_records(blob, size, &meta, dek, &recs, &count) != 0);

    free(blob);
    return 0;
}

/* 索引区位翻转 → decrypt_records 失败 */
TEST(fuzz_bit_flip_index)
{
    verthys_crypto_init();

    uint8_t *blob = NULL, salt[16], mek[32], dek[32];
    size_t size = 0;
    CHECK_EQ(create_valid_blob_with_keys(&blob, &size, salt, mek, dek), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, size, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, size, mek, &meta), 0);

    /* 翻转索引区密文部分 */
    size_t flip_offset = (size_t)meta.index_offset + 24 + 5;
    CHECK(flip_offset < (size_t)meta.mac_offset);
    blob[flip_offset] ^= 0x01;

    /* decrypt_records 失败（索引 AEAD 认证失败） */
    VerthysFmtRecord *recs = NULL;
    uint16_t count = 0;
    CHECK(vfmt_decrypt_records(blob, size, &meta, dek, &recs, &count) != 0);

    free(blob);
    return 0;
}

/* 数据块区位翻转 → decrypt_records 失败 */
TEST(fuzz_bit_flip_data_block)
{
    verthys_crypto_init();

    uint8_t *blob = NULL, salt[16], mek[32], dek[32];
    size_t size = 0;
    CHECK_EQ(create_valid_blob_with_keys(&blob, &size, salt, mek, dek), 0);

    VerthysFmtMeta meta;
    CHECK_EQ(vfmt_parse_header(blob, size, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(blob, size, mek, &meta), 0);

    /* 翻转数据块区密文部分 */
    size_t flip_offset = (size_t)meta.data_blocks_offset + 10;
    CHECK(flip_offset < (size_t)meta.mac_offset);
    blob[flip_offset] ^= 0x01;

    /* decrypt_records 失败（数据块 AEAD 认证失败） */
    VerthysFmtRecord *recs = NULL;
    uint16_t count = 0;
    CHECK(vfmt_decrypt_records(blob, size, &meta, dek, &recs, &count) != 0);

    free(blob);
    return 0;
}

/* 有效文件追加额外数据 → MAC 仍校验通过（额外数据被忽略） */
TEST(fuzz_extended_file)
{
    verthys_crypto_init();

    uint8_t *blob = NULL, salt[16], mek[32], dek[32];
    size_t size = 0;
    CHECK_EQ(create_valid_blob_with_keys(&blob, &size, salt, mek, dek), 0);

    /* 追加 32 字节垃圾数据 */
    size_t ext_size = size + 32;
    uint8_t *ext_blob = malloc(ext_size);
    CHECK(ext_blob != NULL);
    memcpy(ext_blob, blob, size);
    memset(ext_blob + size, 0xAA, 32);
    free(blob);

    VerthysFmtMeta meta;
    /* parse_header 应成功（mac_offset 仍有效） */
    CHECK_EQ(vfmt_parse_header(ext_blob, ext_size, &meta), 0);
    CHECK_EQ(vfmt_decrypt_meta(ext_blob, ext_size, mek, &meta), 0);

    /* decrypt_records 应成功（HMAC 覆盖 [0..mac_offset-1]，不含追加部分） */
    VerthysFmtRecord *recs = NULL;
    uint16_t count = 0;
    CHECK_EQ(vfmt_decrypt_records(ext_blob, ext_size, &meta, dek, &recs, &count), 0);
    CHECK_EQ(count, 1u);

    vfmt_free_records(recs, count);
    free(ext_blob);
    return 0;
}
