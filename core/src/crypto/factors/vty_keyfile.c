/*
 * vty_keyfile.c — keyfile 因子（VKFL v1）
 *
 * 固定布局：
 *   0..3   magic "VKFL"
 *   4..5   version u16 LE = 1
 *   6..7   flags u16 LE = 0
 *   8..39  secret 32B
 *   40..71 checksum 32B = BLAKE3("verthys/v4/keyfile-checksum" | bytes[0..39])
 */
#include "vty_keyfile.h"
#include "vty_blake3.h"
#include "vty_util.h"
#include "vty_types.h"

#include <string.h>

#define VKFL_MAGIC_0 0x56u /* 'V' */
#define VKFL_MAGIC_1 0x4bu /* 'K' */
#define VKFL_MAGIC_2 0x46u /* 'F' */
#define VKFL_MAGIC_3 0x4cu /* 'L' */
#define VKFL_VERSION 1u
#define VKFL_OFF_MAGIC 0u
#define VKFL_OFF_VERSION 4u
#define VKFL_OFF_FLAGS 6u
#define VKFL_OFF_SECRET 8u
#define VKFL_OFF_CHECKSUM 40u
#define VKFL_HEADER_BYTES VKFL_OFF_CHECKSUM

static const char VKFL_CHECKSUM_DOMAIN[] = "verthys/v4/keyfile-checksum";
static const char VKFL_DIGEST_DOMAIN[] = "verthys/v4/keyfile";

static void put_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value & 0xffu);
    p[1] = (uint8_t)((value >> 8) & 0xffu);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void keyfile_checksum(const uint8_t header[VKFL_HEADER_BYTES],
                             uint8_t out[VTY_HASH_BYTES])
{
    uint8_t input[sizeof(VKFL_CHECKSUM_DOMAIN) - 1u + VKFL_HEADER_BYTES];

    memcpy(input, VKFL_CHECKSUM_DOMAIN, sizeof(VKFL_CHECKSUM_DOMAIN) - 1u);
    memcpy(input + sizeof(VKFL_CHECKSUM_DOMAIN) - 1u, header, VKFL_HEADER_BYTES);
    (void)vty_blake3_32(input, sizeof(input), out);
    vty_secure_zero(input, sizeof(input));
}

int vty_keyfile_generate(uint8_t blob[VTY_KEYFILE_BLOB_BYTES])
{
    if (blob == NULL) return VTY_E_INVALID;

    memset(blob, 0, VTY_KEYFILE_BLOB_BYTES);
    blob[VKFL_OFF_MAGIC + 0] = VKFL_MAGIC_0;
    blob[VKFL_OFF_MAGIC + 1] = VKFL_MAGIC_1;
    blob[VKFL_OFF_MAGIC + 2] = VKFL_MAGIC_2;
    blob[VKFL_OFF_MAGIC + 3] = VKFL_MAGIC_3;
    put_u16(blob + VKFL_OFF_VERSION, VKFL_VERSION);
    put_u16(blob + VKFL_OFF_FLAGS, 0u);
    vty_random(blob + VKFL_OFF_SECRET, VTY_KEYFILE_SECRET_BYTES);
    keyfile_checksum(blob, blob + VKFL_OFF_CHECKSUM);
    return VTY_OK;
}

int vty_keyfile_parse(const uint8_t *buf, size_t len,
                      uint8_t secret[VTY_KEYFILE_SECRET_BYTES])
{
    uint8_t expect[VTY_HASH_BYTES];

    if (buf == NULL || secret == NULL) return VTY_E_INVALID;
    if (len != VTY_KEYFILE_BLOB_BYTES) return VTY_E_KEYFILE_INVALID;
    if (buf[VKFL_OFF_MAGIC + 0] != VKFL_MAGIC_0 ||
        buf[VKFL_OFF_MAGIC + 1] != VKFL_MAGIC_1 ||
        buf[VKFL_OFF_MAGIC + 2] != VKFL_MAGIC_2 ||
        buf[VKFL_OFF_MAGIC + 3] != VKFL_MAGIC_3) {
        return VTY_E_KEYFILE_INVALID;
    }
    if (get_u16(buf + VKFL_OFF_VERSION) != VKFL_VERSION) return VTY_E_KEYFILE_INVALID;
    if (get_u16(buf + VKFL_OFF_FLAGS) != 0u) return VTY_E_KEYFILE_INVALID;

    keyfile_checksum(buf, expect);
    if (vty_ct_equal(expect, buf + VKFL_OFF_CHECKSUM, VTY_HASH_BYTES) != 0) {
        vty_secure_zero(expect, sizeof(expect));
        return VTY_E_KEYFILE_INVALID;
    }
    memcpy(secret, buf + VKFL_OFF_SECRET, VTY_KEYFILE_SECRET_BYTES);
    vty_secure_zero(expect, sizeof(expect));
    return VTY_OK;
}

int vty_keyfile_digest(const uint8_t secret[VTY_KEYFILE_SECRET_BYTES],
                       uint8_t out[VTY_HASH_BYTES])
{
    uint8_t input[sizeof(VKFL_DIGEST_DOMAIN) - 1u + VTY_KEYFILE_SECRET_BYTES];

    if (secret == NULL || out == NULL) return VTY_E_INVALID;
    memcpy(input, VKFL_DIGEST_DOMAIN, sizeof(VKFL_DIGEST_DOMAIN) - 1u);
    memcpy(input + sizeof(VKFL_DIGEST_DOMAIN) - 1u, secret,
           VTY_KEYFILE_SECRET_BYTES);
    (void)vty_blake3_32(input, sizeof(input), out);
    vty_secure_zero(input, sizeof(input));
    return VTY_OK;
}
