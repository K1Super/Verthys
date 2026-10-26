/*
 * test_v4_pcr.c — PCR 槽与解锁策略验收
 *
 * 覆盖：
 *   - 位图与 PCR 槽编解码（含越界位、参数长度、密文长度）
 *   - PCR 绑定密钥加封/解封；错误策略摘要必须解封失败
 *   - 创建/保存/重开：PCR 匹配时正常解锁
 *   - 槽内策略摘要被篡改 → VTY_E_TPM
 *   - PCR 绑定密钥被换成错误策略 → 摘要匹配但 TPM 拒绝 → VTY_E_TPM
 *   - 槽内密文换成其它 K_c → VTY_E_KEY_INVALID
 *   - 密钥缺失时普通解锁 fail-closed，恢复码可解开并重密封
 *   - 已存在库上启用/关闭 PCR
 *
 * 需要 TPM 2.0 + Platform Crypto Provider；环境不具备时用例打印 SKIP 并跳过。
 * 所有库文件写在测试沙箱相对路径；测试期间临时关闭熔断，避免触碰真实用户状态。
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_keymanager_v4.h"
#include "vty_format_v4.h"
#include "vty_keyslot_v4.h"
#include "vty_tpm_pcr.h"
#include "vty_util.h"
#include "vty_lockout.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCR_PW "pcr-pass-2026"

static int pcr_open_quiet(const char *path, const char *pw, VtyVault **out)
{
    int saved = vty_lockout_enabled();
    int rc;

    vty_lockout_set_enabled(0);
    rc = vty_vault_open(path, pw, out);
    vty_lockout_set_enabled(saved);
    return rc;
}

static int pcr_open_recovery_quiet(const char *path, const char *code, VtyVault **out)
{
    int saved = vty_lockout_enabled();
    int rc;

    vty_lockout_set_enabled(0);
    rc = vty_vault_open_recovery(path, code, out);
    vty_lockout_set_enabled(saved);
    return rc;
}

static int pcr_read_all(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long size;
    uint8_t *buf;

    if (f == NULL) return 1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    size = ftell(f);
    if (size <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 1; }
    buf = (uint8_t *)malloc((size_t)size);
    if (buf == NULL) { fclose(f); return 1; }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);
    *out = buf;
    *out_len = (size_t)size;
    return 0;
}

static int pcr_write_all(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

/* 返回第 idx 个槽在文件中的字节偏移（槽区从固定头之后开始） */
static size_t pcr_slot_offset(const VtySlot *slots, int idx)
{
    size_t off = VTY_V4_HEADER_FIXED_BYTES;
    int i;

    for (i = 0; i < idx; i++) off += vty_slot_serialized_len(&slots[i]);
    return off;
}

TEST(v4_pcr_select_validation)
{
    CHECK_EQ(vty_tpm_pcr_select_valid(0), VTY_E_INVALID);
    CHECK_EQ(vty_tpm_pcr_select_valid(0x01000000u), VTY_E_INVALID);
    CHECK_EQ(vty_tpm_pcr_select_valid(0x00000880u), VTY_OK);
    CHECK_EQ(vty_tpm_pcr_select_valid(0x00FFFFFFu), VTY_OK);
    return 0;
}

TEST(v4_pcr_slot_codec)
{
    VtyV4Header h;
    VtySlot s;
    VtySlot back;
    uint8_t buf[512];
    size_t written = 0;

    memset(&h, 0, sizeof(h));
    h.magic = VTY_V4_MAGIC;
    h.version_major = VTY_V4_VERSION_MAJOR;
    h.flags = VTY_FLAG_RECOVERY | VTY_FLAG_PCR;
    h.epoch = 1;
    h.slot_count = 1;
    memset(h.vault_uuid, 0x21, sizeof(h.vault_uuid));

    memset(&s, 0, sizeof(s));
    s.slot_type = VTY_SLOT_DEVICE_PCR;
    s.slot_flags = VTY_SLOT_FLAG_REQUIRED;
    s.kdf_id = VTY_KDF_NONE;
    s.wrap_alg = VTY_WRAP_RSAOAEP;
    s.params_len = VTY_SLOT_PARAMS_PCR;
    s.pcr_select = 0x00000880u;
    memset(s.pcr_digest, 0x5A, sizeof(s.pcr_digest));
    s.ct_len = VTY_SLOT_PCR_CT_BYTES;
    memset(s.ct, 0x33, sizeof(s.ct));

    CHECK_EQ(vty_slot_serialized_len(&s), 356u);
    CHECK_EQ(vty_slot_write(&s, 0, &h, buf, sizeof(buf), &written), VTY_OK);
    CHECK_EQ(written, 356u);
    CHECK_EQ(vty_slot_parse_at(buf, written, 0, 0, &h, &back, &written), VTY_OK);
    CHECK_EQ(back.slot_type, VTY_SLOT_DEVICE_PCR);
    CHECK_EQ(back.params_len, VTY_SLOT_PARAMS_PCR);
    CHECK_EQ(back.pcr_select, 0x00000880u);
    CHECK_EQ(memcmp(back.pcr_digest, s.pcr_digest, VTY_HASH_BYTES), 0);
    CHECK_EQ(back.ct_len, VTY_SLOT_PCR_CT_BYTES);

    /* 位图超出 PCR23 / 为零：写路径直接拒绝，避免落盘不可解析的槽 */
    s.pcr_select = 0x01000880u;
    CHECK_EQ(vty_slot_write(&s, 0, &h, buf, sizeof(buf), &written), VTY_E_INVALID);

    s.pcr_select = 0;
    CHECK_EQ(vty_slot_write(&s, 0, &h, buf, sizeof(buf), &written), VTY_E_INVALID);

    /* 非 PCR 槽携带 PCR 参数：拒绝 */
    s.pcr_select = 0x00000880u;
    s.slot_type = VTY_SLOT_DEVICE_ROOT;
    CHECK_EQ(vty_slot_write(&s, 0, &h, buf, sizeof(buf), &written), VTY_E_SLOT_UNKNOWN);

    /* 策略：声明 PCR 标志但缺槽 / 有槽但无标志 / 重复槽 */
    {
        VtySlot slots[4];

        memset(slots, 0, sizeof(slots));
        slots[0].slot_type = VTY_SLOT_USER_PASSWORD;
        slots[1].slot_type = VTY_SLOT_DEVICE_ROOT;
        CHECK_EQ(vty_slot_policy_check(slots, 2, 0), VTY_OK);
        CHECK_EQ(vty_slot_policy_check(slots, 2, VTY_FLAG_PCR), VTY_E_SLOT_MISSING);

        s.slot_type = VTY_SLOT_DEVICE_PCR;
        slots[2] = s;
        CHECK_EQ(vty_slot_policy_check(slots, 3, 0), VTY_E_SLOT_UNKNOWN);
        CHECK_EQ(vty_slot_policy_check(slots, 3, VTY_FLAG_PCR), VTY_OK);

        slots[3] = s;
        CHECK_EQ(vty_slot_policy_check(slots, 4, VTY_FLAG_PCR), VTY_E_SLOT_MISSING);
    }
    return 0;
}

TEST(v4_tpm_pcr_key_roundtrip)
{
    static const uint8_t uuid[VTY_UUID_BYTES] = {
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
    };
    uint8_t key_in[VTY_KEY_BYTES];
    uint8_t key_out[VTY_KEY_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(key_in, 0x6A, sizeof(key_in));
    memset(key_out, 0, sizeof(key_out));
    memset(ct, 0, sizeof(ct));

    CHECK_EQ(vty_tpm_pcr_key_create(uuid, VTY_TPM_PCR_SELECT_DEFAULT, NULL, 0), VTY_OK);
    CHECK_EQ(vty_tpm_pcr_seal(uuid, key_in, ct), VTY_OK);
    CHECK_EQ(vty_tpm_pcr_unseal(uuid, ct, key_out), VTY_OK);
    CHECK_EQ(memcmp(key_in, key_out, VTY_KEY_BYTES), 0);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    vty_secure_zero(key_out, sizeof(key_out));
    return 0;
}

TEST(v4_tpm_pcr_key_wrong_digest_rejected)
{
    static const uint8_t uuid[VTY_UUID_BYTES] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F, 0x10
    };
    uint8_t zero_table[VTY_TPM_PCR_TABLE_BYTES];
    uint8_t key_in[VTY_KEY_BYTES];
    uint8_t key_out[VTY_KEY_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(zero_table, 0, sizeof(zero_table));
    memset(key_in, 0x77, sizeof(key_in));
    memset(key_out, 0, sizeof(key_out));
    memset(ct, 0, sizeof(ct));

    CHECK_EQ(vty_tpm_pcr_key_create(uuid, VTY_TPM_PCR_SELECT_DEFAULT,
                                    zero_table, sizeof(zero_table)), VTY_OK);
    CHECK_EQ(vty_tpm_pcr_seal(uuid, key_in, ct), VTY_OK);
    /* 绑定到全零摘要的密钥：TPM 策略校验必然失败 */
    CHECK_EQ(vty_tpm_pcr_unseal(uuid, ct, key_out), VTY_E_TPM);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    vty_secure_zero(key_out, sizeof(key_out));
    return 0;
}

TEST(v4_pcr_create_open_roundtrip)
{
    VtyVault *v = NULL;
    VtyVault *v2 = NULL;
    uint8_t uuid[VTY_UUID_BYTES];
    char rec[VTY_RECOVERY_TEXT_BUF];
    int p_idx;

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(rec, 0, sizeof(rec));
    remove("v4_pcr_rt.vty");

    CHECK_EQ(vty_vault_create_pcr("v4_pcr_rt.vty", PCR_PW,
                                  VTY_TPM_PCR_SELECT_DEFAULT,
                                  &v, rec, sizeof(rec)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK((v->header.flags & VTY_FLAG_PCR) != 0);
    CHECK_EQ(v->slot_count, 4u);
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    CHECK_EQ(p_idx, 3);
    CHECK_EQ(v->slots[p_idx].params_len, VTY_SLOT_PARAMS_PCR);
    CHECK_EQ(v->slots[p_idx].pcr_select, VTY_TPM_PCR_SELECT_DEFAULT);
    CHECK_EQ(v->slots[p_idx].ct_len, VTY_SLOT_PCR_CT_BYTES);

    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_lock(v);
    vty_vault_free(v);

    CHECK_EQ(pcr_open_quiet("v4_pcr_rt.vty", PCR_PW, &v2), VTY_OK);
    CHECK((v2->header.flags & VTY_FLAG_PCR) != 0);
    vty_vault_free(v2);

    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    remove("v4_pcr_rt.vty");
    return 0;
}

TEST(v4_pcr_tampered_digest_fails_closed)
{
    VtyVault *v = NULL;
    VtyVault *v2 = NULL;
    VtyV4Header h;
    VtySlot slots[VTY_V4_MAX_SLOTS];
    uint32_t count = 0;
    uint8_t uuid[VTY_UUID_BYTES];
    char rec[VTY_RECOVERY_TEXT_BUF];
    uint8_t *buf = NULL;
    size_t len = 0;
    size_t off;
    int p_idx;

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(rec, 0, sizeof(rec));
    remove("v4_pcr_tamper.vty");

    CHECK_EQ(vty_vault_create_pcr("v4_pcr_tamper.vty", PCR_PW,
                                  VTY_TPM_PCR_SELECT_DEFAULT,
                                  &v, rec, sizeof(rec)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    vty_vault_lock(v);
    vty_vault_free(v);

    CHECK_EQ(pcr_read_all("v4_pcr_tamper.vty", &buf, &len), 0);
    CHECK_EQ(vty_v4_header_parse(buf, len, &h), VTY_OK);
    CHECK_EQ(vty_slots_parse_all(buf, len, &h, slots, VTY_V4_MAX_SLOTS, &count), VTY_OK);
    p_idx = vty_slot_find(slots, count, VTY_SLOT_DEVICE_PCR);
    CHECK(p_idx >= 0);
    off = pcr_slot_offset(slots, p_idx);
    /* 槽内布局：base(6)+params(36) 后是 pcrDigest，首字节翻转让摘要不匹配 */
    buf[off + 6u + 4u] ^= 0x01u;
    CHECK_EQ(vty_v4_header_finalize(buf, h.header_len), VTY_OK);
    CHECK_EQ(pcr_write_all("v4_pcr_tamper.vty", buf, len), 0);
    free(buf);

    CHECK_EQ(pcr_open_quiet("v4_pcr_tamper.vty", PCR_PW, &v2), VTY_E_TPM);

    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    remove("v4_pcr_tamper.vty");
    return 0;
}

TEST(v4_pcr_wrong_tpm_key_fails_closed)
{
    VtyVault *v = NULL;
    VtyVault *v2 = NULL;
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t zero_table[VTY_TPM_PCR_TABLE_BYTES];
    char rec[VTY_RECOVERY_TEXT_BUF];

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(rec, 0, sizeof(rec));
    remove("v4_pcr_wrongkey.vty");

    CHECK_EQ(vty_vault_create_pcr("v4_pcr_wrongkey.vty", PCR_PW,
                                  VTY_TPM_PCR_SELECT_DEFAULT,
                                  &v, rec, sizeof(rec)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    vty_vault_lock(v);
    vty_vault_free(v);

    /* 覆盖为“绑定全零摘要”的密钥：槽内摘要仍与当前 PCR 匹配，
     * 只有 TPM 策略校验能拦下，验证门确实由 TPM 执行 */
    memset(zero_table, 0, sizeof(zero_table));
    CHECK_EQ(vty_tpm_pcr_key_create(uuid, VTY_TPM_PCR_SELECT_DEFAULT,
                                    zero_table, sizeof(zero_table)), VTY_OK);
    CHECK_EQ(pcr_open_quiet("v4_pcr_wrongkey.vty", PCR_PW, &v2), VTY_E_TPM);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    remove("v4_pcr_wrongkey.vty");
    return 0;
}

TEST(v4_pcr_foreign_ciphertext_rejected)
{
    VtyVault *v = NULL;
    VtyVault *v2 = NULL;
    VtyV4Header h;
    VtySlot slots[VTY_V4_MAX_SLOTS];
    uint32_t count = 0;
    char rec[VTY_RECOVERY_TEXT_BUF];
    uint8_t *buf = NULL;
    size_t len = 0;
    size_t off;
    uint8_t fake[VTY_KEY_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];
    int p_idx;

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(rec, 0, sizeof(rec));
    remove("v4_pcr_foreign.vty");

    CHECK_EQ(vty_vault_create_pcr("v4_pcr_foreign.vty", PCR_PW,
                                  VTY_TPM_PCR_SELECT_DEFAULT,
                                  &v, rec, sizeof(rec)), VTY_OK);
    vty_vault_lock(v);
    vty_vault_free(v);

    CHECK_EQ(pcr_read_all("v4_pcr_foreign.vty", &buf, &len), 0);
    CHECK_EQ(vty_v4_header_parse(buf, len, &h), VTY_OK);
    CHECK_EQ(vty_slots_parse_all(buf, len, &h, slots, VTY_V4_MAX_SLOTS, &count), VTY_OK);
    p_idx = vty_slot_find(slots, count, VTY_SLOT_DEVICE_PCR);
    CHECK(p_idx >= 0);
    off = pcr_slot_offset(slots, p_idx);

    /* 用本库公钥加封另一把 K_c：解封成功但与真实 K_c 不符 */
    memset(fake, 0x9D, sizeof(fake));
    CHECK_EQ(vty_tpm_pcr_seal(h.vault_uuid, fake, ct), VTY_OK);
    /* ct 位于 base(6)+params(36)+salt(32)+nonce(24)+ct_len(2)=100 字节后 */
    memcpy(buf + off + 100u, ct, VTY_TPM_PCR_CT_BYTES);
    CHECK_EQ(vty_v4_header_finalize(buf, h.header_len), VTY_OK);
    CHECK_EQ(pcr_write_all("v4_pcr_foreign.vty", buf, len), 0);
    free(buf);

    CHECK_EQ(pcr_open_quiet("v4_pcr_foreign.vty", PCR_PW, &v2), VTY_E_KEY_INVALID);
    CHECK_EQ(vty_tpm_pcr_key_delete(h.vault_uuid), VTY_OK);
    remove("v4_pcr_foreign.vty");
    return 0;
}

TEST(v4_pcr_recovery_reseal)
{
    VtyVault *v = NULL;
    VtyVault *v2 = NULL;
    uint8_t uuid[VTY_UUID_BYTES];
    char rec[VTY_RECOVERY_TEXT_BUF];

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(rec, 0, sizeof(rec));
    remove("v4_pcr_reseal.vty");

    CHECK_EQ(vty_vault_create_pcr("v4_pcr_reseal.vty", PCR_PW,
                                  VTY_TPM_PCR_SELECT_DEFAULT,
                                  &v, rec, sizeof(rec)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    vty_vault_lock(v);
    vty_vault_free(v);

    /* 模拟设备环境变化：绑定密钥不可用 → 普通解锁 fail-closed */
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    CHECK_EQ(pcr_open_quiet("v4_pcr_reseal.vty", PCR_PW, &v2), VTY_E_TPM);

    /* 恢复码通道不受 PCR 影响，可在解锁后重密封 */
    CHECK_EQ(pcr_open_recovery_quiet("v4_pcr_reseal.vty", rec, &v2), VTY_OK);
    CHECK_EQ(vty_vault_pcr_reseal(v2), VTY_OK);
    vty_vault_free(v2);
    v2 = NULL;

    CHECK_EQ(pcr_open_quiet("v4_pcr_reseal.vty", PCR_PW, &v2), VTY_OK);
    vty_vault_free(v2);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    remove("v4_pcr_reseal.vty");
    return 0;
}

TEST(v4_pcr_enable_disable)
{
    VtyVault *v = NULL;
    VtyVault *v2 = NULL;
    uint8_t uuid[VTY_UUID_BYTES];
    char rec[VTY_RECOVERY_TEXT_BUF];

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    memset(rec, 0, sizeof(rec));
    remove("v4_pcr_toggle.vty");

    CHECK_EQ(vty_vault_create("v4_pcr_toggle.vty", PCR_PW, &v,
                              rec, sizeof(rec)), VTY_OK);
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    CHECK((v->header.flags & VTY_FLAG_PCR) == 0);
    CHECK_EQ(vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR), -1);

    CHECK_EQ(vty_vault_pcr_enable(v, VTY_TPM_PCR_SELECT_DEFAULT), VTY_OK);
    CHECK((v->header.flags & VTY_FLAG_PCR) != 0);
    CHECK_EQ(vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR), 3);
    CHECK_EQ(vty_vault_pcr_enable(v, VTY_TPM_PCR_SELECT_DEFAULT), VTY_E_POLICY);
    vty_vault_lock(v);
    vty_vault_free(v);

    CHECK_EQ(pcr_open_quiet("v4_pcr_toggle.vty", PCR_PW, &v2), VTY_OK);
    CHECK((v2->header.flags & VTY_FLAG_PCR) != 0);
    CHECK_EQ(vty_vault_pcr_disable(v2), VTY_OK);
    CHECK((v2->header.flags & VTY_FLAG_PCR) == 0);
    CHECK_EQ(vty_slot_find(v2->slots, v2->slot_count, VTY_SLOT_DEVICE_PCR), -1);
    vty_vault_free(v2);
    v2 = NULL;

    CHECK_EQ(pcr_open_quiet("v4_pcr_toggle.vty", PCR_PW, &v2), VTY_OK);
    CHECK((v2->header.flags & VTY_FLAG_PCR) == 0);
    vty_vault_free(v2);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    remove("v4_pcr_toggle.vty");
    return 0;
}
