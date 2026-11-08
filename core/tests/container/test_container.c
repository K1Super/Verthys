/*
 * test_container.c — 明文头部与密钥槽编码验收
 *
 * 覆盖：
 *   - 固定头写入 / 尾哈希 / 解析往返
 *   - magic / 主版本 / 未知 flags / reserved / 截断 / 位翻转拒绝
 *   - 槽序列化与顺序解析（含 slot_count 一致性）
 *   - 槽 AAD 绑定：交换槽位后解包必须失败
 *   - 存储的 KDF 参数低于下限时拒绝解锁
 *   - 槽策略：必需槽缺失 / 声明恢复槽却不存在
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_format.h"
#include "vty_keyslot.h"
#include "vty_util.h"

#include <string.h>

#define T_HDR_MIN (VTY_HEADER_FIXED_BYTES + VTY_HEADER_HASH_BYTES)

static void hdr_init(VtyHeader *h, uint16_t slot_count)
{
    memset(h, 0, sizeof(*h));
    h->magic = VTY_MAGIC;
    h->version_major = VTY_VERSION_MAJOR;
    h->version_minor = VTY_VERSION_MINOR;
    h->flags = VTY_FLAG_RECOVERY;
    h->epoch = 1;
    h->slot_count = slot_count;
    memset(h->vault_uuid, 0x71, VTY_UUID_BYTES);
}

TEST(header_write_parse_roundtrip)
{
    VtyHeader h;
    VtyHeader back;
    uint8_t buf[T_HDR_MIN];

    hdr_init(&h, 1);
    h.header_len = (uint16_t)sizeof(buf);
    h.keyring_len = 1234;

    memset(buf, 0, sizeof(buf));
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);

    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_OK);
    CHECK_EQ(back.header_len, sizeof(buf));
    CHECK_EQ(back.slot_count, 1);
    CHECK_EQ(back.flags, VTY_FLAG_RECOVERY);
    CHECK_EQ(back.epoch, 1);
    CHECK_EQ(back.keyring_len, 1234);
    CHECK_EQ(memcmp(back.vault_uuid, h.vault_uuid, VTY_UUID_BYTES), 0);
    CHECK_EQ(vty_header_slots_len(&back), 0u);
    CHECK(vty_header_slots(buf, sizeof(buf)) == buf + VTY_HEADER_FIXED_BYTES);

    /* header_len 超出实际缓冲区：不能凭字段值越界读取 */
    h.header_len = (uint16_t)(sizeof(buf) + 10);
    memset(buf, 0, sizeof(buf));
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_INVALID);
    return 0;
}

TEST(header_tamper_rejected)
{
    VtyHeader h;
    VtyHeader back;
    uint8_t buf[T_HDR_MIN];

    hdr_init(&h, 1);
    h.header_len = (uint16_t)sizeof(buf);

    /* magic */
    memset(buf, 0, sizeof(buf));
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    buf[0] ^= 0x01u;
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_VERSION);

    /* 主版本 */
    memset(buf, 0, sizeof(buf));
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    buf[4] = 5;
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_VERSION);

    /* 未知 flags */
    memset(buf, 0, sizeof(buf));
    h.flags = 0x8000;
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_SLOT_UNKNOWN);

    /* reserved0 非零 */
    memset(buf, 0, sizeof(buf));
    h.flags = VTY_FLAG_RECOVERY;
    h.reserved0 = 1;
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_SLOT_UNKNOWN);

    /* 位翻转（被尾哈希覆盖的字段） */
    memset(buf, 0, sizeof(buf));
    h.reserved0 = 0;
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    buf[40] ^= 0x01u;   /* keyring_len */
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_CORRUPT);

    /* 截断 */
    CHECK_EQ(vty_header_parse(buf, T_HDR_MIN - 1u, &back), VTY_E_INVALID);
    return 0;
}

TEST(slot_seal_serialize_parse)
{
    VtyHeader h;
    VtySlot sealed;
    VtySlot parsed;
    uint8_t key[VTY_KEY_BYTES];
    uint8_t back[VTY_KEY_BYTES];
    uint8_t buf[512];
    size_t written = 0;
    size_t consumed = 0;

    hdr_init(&h, 2);
    memset(key, 0x81, sizeof(key));

    CHECK_EQ(vty_slot_seal_argon2id(&sealed, VTY_SLOT_USER_PASSWORD,
                                    VTY_SLOT_FLAG_REQUIRED,
                                    (const uint8_t *)"pw", 2, key, &h, 0,
                                    VTY_ARGON2_MEM_KIB_MIN,
                                    VTY_ARGON2_ITERS_MIN, 1), VTY_OK);
    CHECK_EQ(vty_slot_serialized_len(&sealed),
             6u + 12u + VTY_SALT_BYTES + VTY_NONCE_BYTES + 2u + 48u);

    CHECK_EQ(vty_slot_write(&sealed, 0, &h, buf, sizeof(buf), &written),
             VTY_OK);
    CHECK_EQ(written, vty_slot_serialized_len(&sealed));

    CHECK_EQ(vty_slot_parse_at(buf, written, 0, 0, &h, &parsed, &consumed),
             VTY_OK);
    CHECK_EQ(consumed, written);
    CHECK_EQ(parsed.slot_type, VTY_SLOT_USER_PASSWORD);
    CHECK_EQ(parsed.params_len, 12u);
    CHECK_EQ(parsed.m_cost, VTY_ARGON2_MEM_KIB_MIN);

    CHECK_EQ(vty_slot_open_argon2id(&parsed, (const uint8_t *)"pw", 2, &h, 0,
                                    back), VTY_OK);
    CHECK_EQ(memcmp(back, key, VTY_KEY_BYTES), 0);

    /* 口令错误 */
    CHECK(vty_slot_open_argon2id(&parsed, (const uint8_t *)"px", 2, &h, 0,
                                 back) != VTY_OK);

    /* 槽序进入 AAD：同一密文换到别的下标必须失败 */
    CHECK(vty_slot_open_argon2id(&parsed, (const uint8_t *)"pw", 2, &h, 1,
                                 back) != VTY_OK);

    /* 头部 epoch 进入 AAD */
    h.epoch = 2;
    CHECK(vty_slot_open_argon2id(&parsed, (const uint8_t *)"pw", 2, &h, 0,
                                 back) != VTY_OK);
    h.epoch = 1;

    /* 存储参数低于下限：拒绝解锁，而非按弱参数继续 */
    parsed.m_cost = VTY_ARGON2_MEM_KIB_MIN - 1u;
    CHECK_EQ(vty_slot_open_argon2id(&parsed, (const uint8_t *)"pw", 2, &h, 0,
                                    back), VTY_E_KDF_WEAK);
    return 0;
}

TEST(slots_parse_all_roundtrip)
{
    VtyHeader h;
    VtySlot s0, s1;
    VtySlot out[VTY_MAX_SLOTS];
    uint8_t key[VTY_KEY_BYTES];
    uint8_t buf[1024];
    size_t w0 = 0, w1 = 0;
    uint32_t count = 0;

    memset(key, 0x82, sizeof(key));
    memset(buf, 0, sizeof(buf));

    hdr_init(&h, 2);
    CHECK_EQ(vty_slot_seal_argon2id(&s0, VTY_SLOT_USER_PASSWORD,
                                    VTY_SLOT_FLAG_REQUIRED,
                                    (const uint8_t *)"pw", 2, key, &h, 0,
                                    VTY_ARGON2_MEM_KIB_MIN, 3, 1), VTY_OK);
    CHECK_EQ(vty_slot_seal_argon2id(&s1, VTY_SLOT_KEYFILE,
                                    VTY_SLOT_FLAG_REQUIRED,
                                    (const uint8_t *)"pw", 2, key, &h, 1,
                                    VTY_ARGON2_MEM_KIB_MIN, 3, 1), VTY_OK);

    h.header_len = (uint16_t)(VTY_HEADER_FIXED_BYTES +
                              vty_slot_serialized_len(&s0) +
                              vty_slot_serialized_len(&s1) +
                              VTY_HEADER_HASH_BYTES);
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_slot_write(&s0, 0, &h, buf + VTY_HEADER_FIXED_BYTES,
                            sizeof(buf) - VTY_HEADER_FIXED_BYTES, &w0),
             VTY_OK);
    CHECK_EQ(vty_slot_write(&s1, 1, &h, buf + VTY_HEADER_FIXED_BYTES + w0,
                            sizeof(buf) - VTY_HEADER_FIXED_BYTES - w0, &w1),
             VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, h.header_len), VTY_OK);

    CHECK_EQ(vty_slots_parse_all(buf, h.header_len, &h, out,
                                 VTY_MAX_SLOTS, &count), VTY_OK);
    CHECK_EQ(count, 2);
    CHECK_EQ(out[0].slot_type, VTY_SLOT_USER_PASSWORD);
    CHECK_EQ(out[1].slot_type, VTY_SLOT_KEYFILE);

    /* 槽交换：解包必须失败（AAD 下标绑定） */
    {
        uint8_t back[VTY_KEY_BYTES];
        CHECK(vty_slot_open_argon2id(&out[1], (const uint8_t *)"pw", 2, &h, 0,
                                     back) != VTY_OK);
        CHECK(vty_slot_open_argon2id(&out[0], (const uint8_t *)"pw", 2, &h, 1,
                                     back) != VTY_OK);
    }
    return 0;
}

TEST(slot_policy_check)
{
    /* 4 个槽位：用户口令、设备根、恢复、PCR/keyfile 互斥位 */
    VtySlot slots[4];

    memset(slots, 0, sizeof(slots));
    CHECK_EQ(vty_slot_policy_check(NULL, 0, 0), VTY_E_SLOT_MISSING);

    slots[0].slot_type = VTY_SLOT_USER_PASSWORD;
    CHECK_EQ(vty_slot_policy_check(slots, 1, 0), VTY_E_SLOT_MISSING);

    slots[1].slot_type = VTY_SLOT_DEVICE_ROOT;
    CHECK_EQ(vty_slot_policy_check(slots, 2, 0), VTY_OK);

    /* 声明了恢复槽但实体缺失 —— 声明与实体不一致视为损坏 */
    CHECK_EQ(vty_slot_policy_check(slots, 2, VTY_FLAG_RECOVERY),
             VTY_E_SLOT_MISSING);

    slots[2].slot_type = VTY_SLOT_RECOVERY;
    CHECK_EQ(vty_slot_policy_check(slots, 3, VTY_FLAG_RECOVERY), VTY_OK);

    /* 高安全模式：设备根仍必须在，且额外要求 keyfile 或 PCR 槽 */
    CHECK_EQ(vty_slot_policy_check(slots, 3, VTY_FLAG_HIGH_SECURITY),
             VTY_E_SLOT_MISSING);
    slots[3].slot_type = VTY_SLOT_DEVICE_PCR;
    /* PCR 槽必须在头部声明 VTY_FLAG_PCR；只声明 HIGH_SECURITY 视为不一致 */
    CHECK_EQ(vty_slot_policy_check(slots, 4, VTY_FLAG_HIGH_SECURITY),
             VTY_E_SLOT_UNKNOWN);
    CHECK_EQ(vty_slot_policy_check(slots, 4,
                                   VTY_FLAG_HIGH_SECURITY | VTY_FLAG_PCR), VTY_OK);
    /* keyfile 是用户槽 KDF 第二输入，不再写独立槽；出现 type 5 槽
     * 一律拒绝。高安全由 KEYFILE flag 或 PCR 槽满足。 */
    slots[3].slot_type = VTY_SLOT_KEYFILE;
    CHECK_EQ(vty_slot_policy_check(slots, 4, VTY_FLAG_HIGH_SECURITY),
             VTY_E_SLOT_UNKNOWN);
    CHECK_EQ(vty_slot_policy_check(slots, 3,
                                   VTY_FLAG_HIGH_SECURITY | VTY_FLAG_KEYFILE), VTY_OK);
    CHECK_EQ(vty_slot_policy_check(slots, 4,
                                   VTY_FLAG_HIGH_SECURITY | VTY_FLAG_KEYFILE),
             VTY_E_SLOT_UNKNOWN);
    return 0;
}

TEST(header_generation_and_minor_frozen)
{
    VtyHeader h;
    VtyHeader back;
    uint8_t buf[T_HDR_MIN];
    uint8_t digest1[VTY_HASH_BYTES];
    uint8_t digest2[VTY_HASH_BYTES];

    hdr_init(&h, 1);
    h.header_len = (uint16_t)sizeof(buf);
    h.generation = 7;
    memset(buf, 0, sizeof(buf));
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_OK);
    CHECK_EQ(vty_header_generation(&back), 7u);
    CHECK_EQ(buf[VTY_GENERATION_OFFSET + 8u], 0u);

    CHECK_EQ(vty_header_digest(buf, sizeof(buf), digest1), VTY_OK);
    h.generation = 8;
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_digest(buf, sizeof(buf), digest2), VTY_OK);
    CHECK(memcmp(digest1, digest2, VTY_HASH_BYTES) != 0);

    /* minor 0 与其它值都不接受：不存在双解析路径 */
    h.version_minor = 0;
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_E_VERSION);
    memcpy(buf, "\x56\x52\x54\x59", 4);
    vty_put_u16(buf + 4, VTY_VERSION_MAJOR);
    vty_put_u16(buf + 6, 0);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_VERSION);

    /* 保留区非零必须拒绝，不能当成未来字段带进认证范围 */
    h.version_minor = VTY_VERSION_MINOR;
    CHECK_EQ(vty_header_write_fixed(&h, buf, sizeof(buf)), VTY_OK);
    buf[VTY_GENERATION_OFFSET + 9u] = 1u;
    CHECK_EQ(vty_header_finalize(buf, sizeof(buf)), VTY_OK);
    CHECK_EQ(vty_header_parse(buf, sizeof(buf), &back), VTY_E_SLOT_UNKNOWN);
    return 0;
}

TEST(data_root_locator_codec)
{
    VtyDataRootLocator loc;
    VtyDataRootLocator back;
    uint8_t enc[VTY_DATA_ROOT_BYTES];

    memset(&loc, 0, sizeof(loc));
    loc.version = 1;
    loc.root_node_id = 0;
    loc.data_end = VTY_DATA_OFFSET;
    CHECK_EQ(vty_data_root_encode(&loc, enc), VTY_OK);
    CHECK_EQ(vty_data_root_decode(enc, &back), VTY_OK);
    CHECK_EQ(back.data_end, VTY_DATA_OFFSET);
    CHECK_EQ(back.root_node_id, 0u);

    loc.root_node_id = VTY_DATA_OFFSET;
    loc.root_offset = VTY_DATA_OFFSET;
    loc.root_len = 128;
    loc.level = 2;
    loc.data_end = VTY_DATA_OFFSET + 128;
    CHECK_EQ(vty_data_root_encode(&loc, enc), VTY_OK);
    CHECK_EQ(vty_data_root_decode(enc, &back), VTY_OK);
    CHECK_EQ(back.root_offset, VTY_DATA_OFFSET);

    /* data_end 不得低于数据区起点，空根不得带偏移 */
    loc.data_end = VTY_DATA_OFFSET - 1u;
    CHECK_EQ(vty_data_root_encode(&loc, enc), VTY_E_INVALID);
    loc.data_end = VTY_DATA_OFFSET;
    loc.root_node_id = 0;
    loc.root_offset = VTY_DATA_OFFSET;
    CHECK_EQ(vty_data_root_encode(&loc, enc), VTY_OK);
    CHECK_EQ(vty_data_root_decode(enc, &back), VTY_E_CORRUPT);
    return 0;
}

TEST(segment_header_codec)
{
    VtySegmentHeader h;
    VtySegmentHeader back;
    uint8_t buf[VTY_SEG_HEADER_BYTES];

    memset(&h, 0, sizeof(h));
    h.type = VTY_SEG_DIR;
    h.payload_len = 4096;
    h.seq = VTY_DATA_OFFSET;
    h.id = 2;
    CHECK_EQ(vty_segment_header_write(&h, buf), VTY_OK);
    CHECK_EQ(buf[0], 0x56u);
    CHECK_EQ(buf[1], 0x34u);
    CHECK_EQ(buf[2], 0x53u);
    CHECK_EQ(buf[3], 0x47u);
    CHECK_EQ(vty_segment_header_parse(buf, &back), VTY_OK);
    CHECK_EQ(back.seq, VTY_DATA_OFFSET);
    CHECK_EQ(back.id, 2u);
    CHECK_EQ(back.payload_len, 4096u);

    /* 段头保留位/填充非零或未知类型都必须拒绝 */
    buf[6] = 1u;
    CHECK_EQ(vty_segment_header_parse(buf, &back), VTY_E_CORRUPT);
    buf[6] = 0u;
    buf[28] = 1u;
    CHECK_EQ(vty_segment_header_parse(buf, &back), VTY_E_CORRUPT);
    buf[28] = 0u;
    buf[4] = 9u;
    CHECK_EQ(vty_segment_header_parse(buf, &back), VTY_E_CORRUPT);
    buf[4] = VTY_SEG_DIR;
    h.payload_len = 0;
    CHECK_EQ(vty_segment_header_write(&h, buf), VTY_E_INVALID);
    return 0;
}
