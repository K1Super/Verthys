/*
 * test_v4_fuzz.c — v4 解析器确定式模糊与结构变异验收
 *
 * 目标（对应攻击面 A10/A11 的解析器健壮性前置）：
 *   - 头部 / 槽 / Keyring / 恢复码 / 清单 / 分片 解析器面对随机输入
 *     不崩溃、不越界、不成功放行未认证结构；
 *   - 合法头部逐字节翻转后必须一律被尾哈希拒绝。
 *
 * 采用固定种子 xorshift，保证失败可复现；不依赖外部 fuzz 工具即可在
 * 每次回归中执行，长时模糊仍由阶段门禁单独运行。
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_format_v4.h"
#include "vty_keyslot_v4.h"
#include "vty_recovery.h"
#include "vty_chunk_v4.h"
#include "vty_keyfile.h"
#include "vty_util.h"

#include <string.h>

static uint64_t g_fuzz_state = 0x9E3779B97F4A7C15ull;

static uint32_t fuzz_next(void)
{
    g_fuzz_state ^= g_fuzz_state << 13;
    g_fuzz_state ^= g_fuzz_state >> 7;
    g_fuzz_state ^= g_fuzz_state << 17;
    return (uint32_t)(g_fuzz_state >> 32);
}

TEST(v4_fuzz_header_parsers_never_crash)
{
    VtyV4Header out;
    uint8_t buf[512];
    uint32_t iter;

    for (iter = 0; iter < 3000; iter++) {
        uint32_t len = fuzz_next() % (uint32_t)sizeof(buf);
        uint32_t i;
        for (i = 0; i < len; i++) buf[i] = (uint8_t)fuzz_next();

        (void)vty_v4_header_parse(buf, len, &out);
        (void)vty_v4_header_parse(buf, 0, &out);
    }
    return 0;
}

TEST(v4_fuzz_slot_keyring_parsers_never_crash)
{
    VtyV4Header h;
    VtySlot slot;
    VtyKeyring kr;
    uint8_t buf[1024];
    size_t consumed;
    uint32_t iter;
    uint32_t i;

    memset(&h, 0, sizeof(h));
    h.magic = VTY_V4_MAGIC;
    h.version_major = VTY_V4_VERSION_MAJOR;
    h.version_minor = VTY_V4_VERSION_MINOR;
    h.epoch = 1;
    h.slot_count = 1;

    for (iter = 0; iter < 3000; iter++) {
        uint32_t len = fuzz_next() % (uint32_t)sizeof(buf);
        for (i = 0; i < len; i++) buf[i] = (uint8_t)fuzz_next();

        memset(&slot, 0, sizeof(slot));
        consumed = 0;
        (void)vty_slot_parse_at(buf, len, 0, 0, &h, &slot, &consumed);
        /* 解析成功时必须自洽：消耗长度 > 0 且不越过输入 */
        if (consumed > 0) CHECK(consumed <= len);

        (void)vty_keyring_parse(buf, len, &kr);
    }
    return 0;
}

TEST(v4_fuzz_keyfile_parser_never_crash)
{
    uint8_t secret[VTY_KEYFILE_SECRET_BYTES];
    uint8_t good[VTY_KEYFILE_BLOB_BYTES];
    uint8_t buf[128];
    uint32_t iter;
    uint32_t i;
    int rc;

    /* 随机长度/内容：只有恰好 72B 的合法 VKFL 才可能成功，其余必须 INVALID */
    for (iter = 0; iter < 3000; iter++) {
        uint32_t len = fuzz_next() % (uint32_t)sizeof(buf);

        for (i = 0; i < len; i++) buf[i] = (uint8_t)fuzz_next();
        memset(secret, 0, sizeof(secret));
        rc = vty_keyfile_parse(buf, len, secret);
        if (len != VTY_KEYFILE_BLOB_BYTES) {
            CHECK_EQ(rc, VTY_E_KEYFILE_INVALID);
        } else {
            CHECK(rc == VTY_OK || rc == VTY_E_KEYFILE_INVALID);
        }
        vty_secure_zero(secret, sizeof(secret));
    }

    /* 合法 VKFL 逐字节翻转：必须一律被 checksum 拒绝 */
    CHECK_EQ(vty_keyfile_generate(good), VTY_OK);
    memcpy(buf, good, sizeof(good));
    for (i = 0; i < VTY_KEYFILE_BLOB_BYTES; i++) {
        uint8_t saved = buf[i];
        buf[i] = (uint8_t)(saved ^ 0x01u);
        memset(secret, 0, sizeof(secret));
        rc = vty_keyfile_parse(buf, VTY_KEYFILE_BLOB_BYTES, secret);
        CHECK_EQ(rc, VTY_E_KEYFILE_INVALID);
        vty_secure_zero(secret, sizeof(secret));
        buf[i] = saved;
    }

    /* 正常 VKFL 仍可解析（正控） */
    memset(secret, 0, sizeof(secret));
    CHECK_EQ(vty_keyfile_parse(good, sizeof(good), secret), VTY_OK);
    vty_secure_zero(secret, sizeof(secret));
    return 0;
}

TEST(v4_fuzz_recovery_and_manifest_never_crash)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t key[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t *ids = NULL;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    uint32_t total = 0;
    uint8_t buf[512];
    uint32_t iter;
    uint32_t i;
    const char alphabet[] =
        "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghijkmnopqrstuvwxyz- ";

    memset(key, 0x5a, sizeof(key));
    memset(uuid, 0x5b, sizeof(uuid));

    for (iter = 0; iter < 3000; iter++) {
        uint32_t len = fuzz_next() % (uint32_t)sizeof(buf);
        for (i = 0; i < len; i++) buf[i] = (uint8_t)fuzz_next();
        /* 空字符结尾，避免读取越界（解码器按 C 字符串消费） */
        if (len > 0) buf[len - 1] = '\0';
        (void)vty_recovery_decode((const char *)buf, code);

        for (i = 0; i < len; i++) {
            buf[i] = (uint8_t)alphabet[fuzz_next() % (sizeof(alphabet) - 1u)];
        }
        if (len > 0) buf[len - 1] = '\0';
        (void)vty_recovery_decode((const char *)buf, code);

        (void)vty_manifest_open(key, uuid, 1, buf, len, pt_hash, &total, &ids);
        vty_free(ids, 0);
        ids = NULL;
        (void)vty_chunk_open(key, uuid, 0, 1, 1, buf, len, &pt, &pt_len);
        vty_free(pt, pt_len);
        pt = NULL;
        pt_len = 0;
    }
    return 0;
}

TEST(v4_fuzz_header_bitflip_always_rejected)
{
    VtyV4Header h;
    VtyV4Header out;
    uint8_t buf[VTY_V4_HEADER_FIXED_BYTES + VTY_V4_HEADER_HASH_BYTES];
    uint32_t i;

    memset(&h, 0, sizeof(h));
    h.magic = VTY_V4_MAGIC;
    h.version_major = VTY_V4_VERSION_MAJOR;
    h.version_minor = VTY_V4_VERSION_MINOR;
    h.epoch = 1;
    h.slot_count = 1;
    h.header_len = (uint16_t)sizeof(buf);

    memset(buf, 0, sizeof(buf));
    CHECK_EQ(vty_v4_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_v4_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_v4_header_parse(buf, sizeof(buf), &out), VTY_OK);

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] ^= 0x01u;
        CHECK(vty_v4_header_parse(buf, sizeof(buf), &out) != VTY_OK);
        buf[i] ^= 0x01u;
    }
    return 0;
}
