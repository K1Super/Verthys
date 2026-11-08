/*
 *
 * 覆盖：创建/打开/恢复/改密/头部篡改；模块表创建与校验；启用后的
 * MDEK 移出 Keyring、记录重写、策略位、锁定/解锁；口令轮换与禁用；
 * 恢复码绑定、轮换、recovery 槽解锁与设备重绑；重写失败回滚。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_module.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_recovery.h"
#include "vty_blake3.h"
#include "vty_chunk.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

#define T_MOD_HASH_BYTES 32u

static int mod_read_file(const char *path, uint8_t *buf, size_t cap,
                          size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *out_len = n;
    return 0;
}

static int mod_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

static int module_has_keyring_mdek(VtyVault *v, uint32_t index)
{
    uint8_t key[VTY_KEY_BYTES];
    return vty_keyring_find(&v->keyring, VTY_KEYKIND_MDEK,
                            v->modules[index].uuid, VTY_UUID_BYTES,
                            key) == VTY_OK;
}

static int module_get(VtyVault *v, uint64_t id, const uint8_t *expected,
                      size_t expected_len)
{
    VtyRepoRecord rec;
    int ok;

    memset(&rec, 0, sizeof(rec));
    if (vty_repo_get(v, id, &rec) != VTY_OK) return 0;
    ok = rec.data_len == expected_len &&
         memcmp(rec.data, expected, expected_len) == 0;
    if (rec.name != NULL) vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
    return ok;
}

/* 破坏模块 0 的 device 槽 RSA 密文：描述符在 K_dir 加密目录内，只能
 * 通过 store 读改写；保存后 DataRoot/元数据一起生效。 */
static int break_module_device(VtyVault *v)
{
    uint8_t key = 0u;
    uint8_t *val = NULL;
    size_t len = 0;
    size_t uoff = VTY_MODULE_DESC_FIXED;
    size_t doff, ct_off;
    uint16_t up, uct, dp, dct;
    int rc;

    rc = vty_store_get(v->store, VTY_KS_MODULE, &key, 1u, &val, &len);
    if (rc != VTY_OK) return rc;
    if (len < VTY_MODULE_DESC_FIXED + 6u) { vty_free(val, len); return VTY_E_CORRUPT; }

    up = vty_get_u16(val + uoff + 4u);
    if (len < uoff + 6u + up + 32u + 24u + 2u) { vty_free(val, len); return VTY_E_CORRUPT; }
    uct = vty_get_u16(val + uoff + 6u + up + 32u + 24u);
    doff = uoff + 6u + up + 32u + 24u + 2u + uct;
    if (len < doff + 6u + 32u + 24u + 2u) { vty_free(val, len); return VTY_E_CORRUPT; }
    dp = vty_get_u16(val + doff + 4u);
    if (len < doff + 6u + dp + 32u + 24u + 2u) { vty_free(val, len); return VTY_E_CORRUPT; }
    dct = vty_get_u16(val + doff + 6u + dp + 32u + 24u);
    ct_off = doff + 6u + dp + 32u + 24u + 2u;
    if (dct == 0u || len < ct_off + dct) { vty_free(val, len); return VTY_E_CORRUPT; }

    val[ct_off] ^= 0x01u;
    rc = vty_store_put(v->store, VTY_KS_MODULE, &key, 1u, val, len);
    vty_free(val, len);
    if (rc != VTY_OK) return rc;
    return vty_vault_save(v);
}

/* 破坏记录叶的 data_hash，使启用重写在读段时失败；不提交元数据。 */
static int corrupt_record_hash(VtyVault *v, uint64_t id)
{
    uint8_t key[8];
    uint8_t *val = NULL;
    size_t vlen = 0;
    uint8_t tmp[8];
    int i, rc;

    for (i = 0; i < 8; i++) key[i] = (uint8_t)(id >> (56 - 8 * i));
    rc = vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key), &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen != VTY_REPO_LEAF_BYTES) { vty_free(val, vlen); return VTY_E_CORRUPT; }
    memcpy(tmp, key, sizeof(tmp));
    val[116] ^= 0x01u; /* data_hash 偏移 */
    rc = vty_store_put(v->store, VTY_KS_RECORD, tmp, sizeof(tmp), val, vlen);
    vty_free(val, vlen);
    return rc;
}

TEST(vault_create_open_e2e)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t k1[VTY_KEY_BYTES];
    uint8_t k2[VTY_KEY_BYTES];

    vty_lockout_set_enabled(0);
    remove("e2e.vty");

    CHECK_EQ(vty_vault_create("e2e.vty", "p@ssw0rd", &v, code,
                              sizeof(code)), VTY_OK);
    CHECK(v != NULL);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 3, uuid0), VTY_E_INVALID);
    CHECK_EQ(vty_vault_module_key_index(v, 0, k1), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k1), VTY_OK);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    /* 错误口令 */
    v = NULL;
    CHECK(vty_vault_open("e2e.vty", "wrong", &v) != VTY_OK);
    CHECK(v == NULL);

    /* 正确口令 + 设备根 */
    CHECK_EQ(vty_vault_open("e2e.vty", "p@ssw0rd", &v), VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(v);

    /* 恢复码独立解锁（不依赖口令与设备根） */
    CHECK_EQ(vty_vault_open_recovery("e2e.vty", code, &re), VTY_OK);
    CHECK_EQ(vty_vault_module_key(re, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(re);
    return 0;
}

TEST(vault_wrong_recovery_rejected)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char other[VTY_RECOVERY_TEXT_BUF];
    uint8_t raw[VTY_RECOVERY_CODE_BYTES];

    vty_lockout_set_enabled(0);
    remove("rec.vty");

    CHECK_EQ(vty_vault_create("rec.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    vty_vault_free(v);

    CHECK_EQ(vty_recovery_generate(raw, other, sizeof(other)), VTY_OK);
    CHECK(vty_vault_open_recovery("rec.vty", other, &re) != VTY_OK);
    CHECK(re == NULL);
    CHECK(vty_vault_open_recovery("rec.vty", "not-a-code", &re) != VTY_OK);
    return 0;
}

TEST(vault_rotate_password)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t k1[VTY_KEY_BYTES];
    uint8_t k2[VTY_KEY_BYTES];

    vty_lockout_set_enabled(0);
    remove("rot.vty");

    CHECK_EQ(vty_vault_create("rot.vty", "old-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k1), VTY_OK);

    CHECK_EQ(vty_vault_rotate_password(v, "new-pw"), VTY_OK);
    vty_vault_free(v);

    /* 旧口令失效 */
    v = NULL;
    CHECK(vty_vault_open("rot.vty", "old-pw", &v) != VTY_OK);

    /* 新口令可用且模块密钥不变 */
    CHECK_EQ(vty_vault_open("rot.vty", "new-pw", &v), VTY_OK);
    CHECK_EQ(vty_vault_module_key(v, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(v);

    /* 恢复码是独立凭据：改密不再使其失效 */
    CHECK_EQ(vty_vault_open_recovery("rot.vty", code, &re), VTY_OK);
    CHECK_EQ(vty_vault_module_key(re, uuid0, k2), VTY_OK);
    CHECK_EQ(memcmp(k1, k2, VTY_KEY_BYTES), 0);
    vty_vault_free(re);
    return 0;
}

TEST(vault_header_tamper_rejected)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t buf[VTY_DATA_OFFSET + 65536u];
    size_t len = 0;

    vty_lockout_set_enabled(0);
    remove("tamper.vty");
    CHECK_EQ(vty_vault_create("tamper.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    vty_vault_free(v);

    CHECK_EQ(mod_read_file("tamper.vty", buf, sizeof(buf), &len), 0);
    CHECK(len > VTY_HEADER_FIXED_BYTES + VTY_HEADER_HASH_BYTES);

    buf[VTY_HEADER_FIXED_BYTES] ^= 0x01u;
    memcpy(buf + VTY_META_COPY_BYTES, buf, VTY_META_COPY_BYTES);
    CHECK_EQ(mod_write_file("tamper.vty", buf, len), 0);

    v = NULL;
    CHECK(vty_vault_open("tamper.vty", "pw", &v) != VTY_OK);
    CHECK(v == NULL);
    return 0;
}

TEST(module_table_create_and_tamper)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t uuids[VTY_MODULE_COUNT][VTY_UUID_BYTES];
    uint8_t key = 0u;
    uint8_t *val = NULL;
    size_t vlen = 0;
    uint32_t i;

    vty_lockout_set_enabled(0);
    remove("modtab.vty");
    CHECK_EQ(vty_vault_create("modtab.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        CHECK_EQ(vty_vault_module_uuid(v, i, uuids[i]), VTY_OK);
        CHECK_EQ(module_has_keyring_mdek(v, i), 1);
    }
    CHECK_EQ(vty_store_get(v->store, VTY_KS_MODULE, &key, 1u, &val, &vlen),
             VTY_OK);
    CHECK(vlen >= VTY_MODULE_DESC_FIXED);
    if (val != NULL) vty_free(val, vlen);
    vty_vault_free(v);

    /* 重新打开：模块表校验必须通过 */
    CHECK_EQ(vty_vault_open("modtab.vty", "pw", &v), VTY_OK);

    /* 篡改描述符 index 字段：结构完整但键/索引不一致 → E_CORRUPT */
    key = 0u;
    val = NULL;
    vlen = 0;
    CHECK_EQ(vty_store_get(v->store, VTY_KS_MODULE, &key, 1u, &val, &vlen),
             VTY_OK);
    val[2] = 1u;
    CHECK_EQ(vty_store_put(v->store, VTY_KS_MODULE, &key, 1u, val, vlen),
             VTY_OK);
    vty_free(val, vlen);
    CHECK_EQ(vty_vault_save(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("modtab.vty", "pw", &v), VTY_E_CORRUPT);
    CHECK(v == NULL);
    return 0;
}

TEST(module_m1_enable_rewrite_and_policy)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t photo[] = {0xAA, 0x01};
    uint8_t acct[] = {0xBB, 0x02};
    uint8_t file[] = {0xCC, 0x03};
    uint8_t old_mdek[VTY_KEY_BYTES];
    uint8_t new_mdek[VTY_KEY_BYTES];
    uint8_t acct_mdek[VTY_KEY_BYTES];
    uint64_t photo_id = 0, acct_id = 0, file_id = 0;
    VtyModuleStatus st;

    vty_lockout_set_enabled(0);
    remove("modm1.vty");
    CHECK_EQ(vty_vault_create("modm1.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"photo", 5,
                          photo, sizeof(photo), &photo_id), VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x02, (const uint8_t *)"acct", 4,
                          acct, sizeof(acct), &acct_id), VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x08, (const uint8_t *)"file", 4,
                          file, sizeof(file), &file_id), VTY_OK);
    CHECK_EQ(vty_vault_module_key_index(v, 0, old_mdek), VTY_OK);
    CHECK_EQ(vty_vault_module_key_index(v, 1, acct_mdek), VTY_OK);

    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);
    CHECK_EQ(module_has_keyring_mdek(v, 0), 0);
    CHECK_EQ(module_has_keyring_mdek(v, 1), 1);
    CHECK_EQ(vty_vault_module_key_index(v, 0, new_mdek), VTY_OK);
    CHECK(memcmp(old_mdek, new_mdek, VTY_KEY_BYTES) != 0);
    CHECK_EQ(vty_vault_module_key_index(v, 1, new_mdek), VTY_OK);
    CHECK_EQ(memcmp(acct_mdek, new_mdek, VTY_KEY_BYTES), 0);
    CHECK(module_get(v, photo_id, photo, sizeof(photo)));
    CHECK(module_get(v, acct_id, acct, sizeof(acct)));
    CHECK(module_get(v, file_id, file, sizeof(file)));
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.enabled, 1);
    CHECK_EQ(st.unlocked, 1);
    CHECK_EQ(st.has_recovery, 0);

    /* 锁定后只影响该模块；其他模块记录仍可读 */
    vty_module_lock(v, 0u);
    CHECK_EQ(vty_repo_get(v, photo_id, &(VtyRepoRecord){0}), VTY_E_POLICY);
    CHECK_EQ(vty_repo_delete(v, photo_id), VTY_E_POLICY);
    CHECK(module_get(v, acct_id, acct, sizeof(acct)));
    CHECK_EQ(vty_module_unlock(v, 0u, "wrong"), VTY_E_KEY_INVALID);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw"), VTY_OK);
    CHECK(module_get(v, photo_id, photo, sizeof(photo)));

    /* 口令轮换只重封 user 槽，数据不变 */
    CHECK_EQ(vty_module_rotate_password(v, 0u, "mpw", "mpw2"), VTY_OK);
    vty_module_lock(v, 0u);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw"), VTY_E_KEY_INVALID);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw2"), VTY_OK);
    CHECK(module_get(v, photo_id, photo, sizeof(photo)));

    /* 禁用：MDEK 回到 Keyring，数据不重写 */
    CHECK_EQ(vty_module_disable(v, 0u, "mpw2"), VTY_OK);
    CHECK_EQ(module_has_keyring_mdek(v, 0), 1);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.enabled, 0);
    CHECK_EQ((v->header.flags & VTY_FLAG_MODULE_M1), 0);
    CHECK(module_get(v, photo_id, photo, sizeof(photo)));
    vty_vault_free(v);
    return 0;
}

TEST(module_recovery_bind_rotate_reseal)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char new_code[VTY_RECOVERY_TEXT_BUF];
    uint8_t photo[] = {0xDD, 0x04};
    uint64_t photo_id = 0;
    VtyModuleStatus st;
    int rc;

    vty_lockout_set_enabled(0);
    remove("modrec.vty");
    CHECK_EQ(vty_vault_create("modrec.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"p", 1,
                          photo, sizeof(photo), &photo_id), VTY_OK);
    CHECK_EQ(vty_module_enable(v, 0u, "mpw", code), VTY_OK);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.has_recovery, 1);

    /* 恢复码轮换：旧码失效、新码可用，模块 recovery 槽同步重封 */
    CHECK_EQ(vty_vault_recovery_rotate(v, "pw", code, new_code,
                                       sizeof(new_code)), VTY_OK);
    vty_vault_free(v);

    re = NULL;
    CHECK(vty_vault_open_recovery("modrec.vty", code, &re) != VTY_OK);
    CHECK(re == NULL);
    CHECK_EQ(vty_vault_open_recovery("modrec.vty", new_code, &re), VTY_OK);
    CHECK_EQ(vty_module_unlock(re, 0u, "mpw"), VTY_OK);
    CHECK(module_get(re, photo_id, photo, sizeof(photo)));
    vty_vault_free(re);

    /* 破坏 device 槽：普通解锁只能 E_TPM，恢复会话用 recovery 槽解锁 */
    CHECK_EQ(vty_vault_open("modrec.vty", "pw", &v), VTY_OK);
    CHECK_EQ(break_module_device(v), VTY_OK);
    vty_vault_free(v);

    v = NULL;
    CHECK_EQ(vty_vault_open("modrec.vty", "pw", &v), VTY_OK);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw"), VTY_E_TPM);
    vty_vault_free(v);

    re = NULL;
    CHECK_EQ(vty_vault_open_recovery("modrec.vty", new_code, &re), VTY_OK);
    CHECK_EQ(vty_module_unlock(re, 0u, "mpw"), VTY_OK);
    CHECK(module_get(re, photo_id, photo, sizeof(photo)));
    CHECK_EQ(vty_module_reseal_device(re, 0u, "mpw"), VTY_OK);
    vty_vault_free(re);

    /* 重绑后普通会话恢复设备因子 */
    v = NULL;
    CHECK_EQ(vty_vault_open("modrec.vty", "pw", &v), VTY_OK);
    rc = vty_module_unlock(v, 0u, "mpw");
    CHECK_EQ(rc, VTY_OK);
    CHECK(module_get(v, photo_id, photo, sizeof(photo)));
    vty_vault_free(v);
    return 0;
}

TEST(module_m1_chunks_rekey)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t chunk0[] = {0x10, 0x11, 0x12};
    uint8_t chunk1[] = {0x20, 0x21};
    uint8_t *got = NULL;
    size_t got_len = 0;
    VtyRepoChunkEntry *manifest = NULL;
    uint32_t manifest_count = 0;
    VtyModuleStatus st;

    vty_lockout_set_enabled(0);
    remove("modchunk.vty");
    CHECK_EQ(vty_vault_create("modchunk.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    memset(file_uuid, 0x5A, sizeof(file_uuid));
    memset(pt_hash, 0x33, sizeof(pt_hash));
    CHECK_EQ(vty_repo_file_put(v, file_uuid, pt_hash, 2u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 0u, chunk0, sizeof(chunk0)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 1u, chunk1, sizeof(chunk1)), VTY_OK);

    /* 启用 fileverthys 模块：分片段/分片叶必须整体重写 */
    CHECK_EQ(vty_module_enable(v, 2u, "fmpw", NULL), VTY_OK);
    CHECK_EQ(vty_module_status(v, 2u, &st), VTY_OK);
    CHECK_EQ(st.enabled, 1u);

    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 0u, &got, &got_len), VTY_OK);
    CHECK_EQ(got_len, sizeof(chunk0));
    CHECK_EQ(memcmp(got, chunk0, sizeof(chunk0)), 0);
    vty_secure_zero(got, got_len);
    vty_free(got, got_len);
    got = NULL;
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 1u, &got, &got_len), VTY_OK);
    CHECK_EQ(got_len, sizeof(chunk1));
    CHECK_EQ(memcmp(got, chunk1, sizeof(chunk1)), 0);
    vty_secure_zero(got, got_len);
    vty_free(got, got_len);
    got = NULL;
    CHECK_EQ(vty_repo_file_manifest(v, file_uuid, &manifest, &manifest_count),
             VTY_OK);
    CHECK_EQ(manifest_count, 2u);
    vty_free(manifest, sizeof(VtyRepoChunkEntry) * manifest_count);

    /* 锁定 fileverthys 后分片读取按策略拒绝；解锁后恢复 */
    vty_module_lock(v, 2u);
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 0u, &got, &got_len),
             VTY_E_POLICY);
    CHECK_EQ(vty_module_unlock(v, 2u, "fmpw"), VTY_OK);
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 0u, &got, &got_len), VTY_OK);
    vty_secure_zero(got, got_len);
    vty_free(got, got_len);

    CHECK_EQ(vty_module_disable(v, 2u, "fmpw"), VTY_OK);
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 0u, &got, &got_len), VTY_OK);
    vty_secure_zero(got, got_len);
    vty_free(got, got_len);
    vty_vault_free(v);
    return 0;
}

TEST(module_delete_purge_and_recreate)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    uint8_t chunk[] = {0x77, 0x01};
    uint8_t photo[] = {0xAA, 0x01};
    uint8_t acct[] = {0xBB, 0x02};
    uint8_t old_uuid0[VTY_UUID_BYTES];
    uint8_t new_uuid0[VTY_UUID_BYTES];
    uint8_t old_uuid2[VTY_UUID_BYTES];
    uint8_t keytmp[VTY_KEY_BYTES];
    uint64_t photo_id = 0, acct_id = 0;
    uint8_t found = 0;
    uint64_t found_id = 0;
    VtyModuleStatus st;
    uint8_t *got = NULL;
    size_t got_len = 0;

    vty_lockout_set_enabled(0);
    remove("moddel.vty");
    CHECK_EQ(vty_vault_create("moddel.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"p", 1,
                          photo, sizeof(photo), &photo_id), VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x02, (const uint8_t *)"a", 1,
                          acct, sizeof(acct), &acct_id), VTY_OK);
    memset(file_uuid, 0x6A, sizeof(file_uuid));
    memset(pt_hash, 0x44, sizeof(pt_hash));
    memset(keytmp, 0, sizeof(keytmp));
    CHECK_EQ(vty_repo_file_put(v, file_uuid, pt_hash, 1u), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file_uuid, 0u, chunk, sizeof(chunk)), VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 0, old_uuid0), VTY_OK);
    CHECK_EQ(vty_vault_module_uuid(v, 2, old_uuid2), VTY_OK);
    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);

    /* confirm 与容器口令都是硬门槛 */
    CHECK_EQ(vty_module_delete(v, 0u, "pw", "delete"), VTY_E_INVALID);
    CHECK_EQ(vty_module_delete(v, 0u, "wrong", "DELETE"), VTY_E_KEY_INVALID);
    CHECK_EQ(module_has_keyring_mdek(v, 0), 0);

    CHECK_EQ(vty_module_delete(v, 0u, "pw", "DELETE"), VTY_OK);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.deleted, 1);
    CHECK_EQ(st.enabled, 0);
    CHECK_EQ(vty_vault_module_key_index(v, 0, keytmp), VTY_E_POLICY);
    CHECK_EQ(vty_repo_get(v, photo_id, &(VtyRepoRecord){0}), VTY_E_INVALID);
    CHECK(module_get(v, acct_id, acct, sizeof(acct)));
    CHECK_EQ(vty_repo_find_by_type(v, 0x01, &found, &found_id), VTY_E_POLICY);
    CHECK_EQ(vty_vault_module_uuid(v, 0, new_uuid0), VTY_OK);
    CHECK(memcmp(old_uuid0, new_uuid0, VTY_UUID_BYTES) != 0);

    /* 删除后重建：新 UUID/MDEK，旧记录不可读，新记录可写 */
    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.enabled, 1);
    CHECK_EQ(st.deleted, 0);
    CHECK_EQ(vty_repo_get(v, photo_id, &(VtyRepoRecord){0}), VTY_E_INVALID);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"p2", 2,
                          photo, sizeof(photo), &photo_id), VTY_OK);
    CHECK(module_get(v, photo_id, photo, sizeof(photo)));

    /* 未启用模块删除：MDEK 从 Keyring 销毁，记录清除 */
    CHECK_EQ(vty_module_delete(v, 1u, "pw", "DELETE"), VTY_OK);
    CHECK_EQ(vty_module_status(v, 1, &st), VTY_OK);
    CHECK_EQ(st.deleted, 1);
    CHECK_EQ(module_has_keyring_mdek(v, 1), 0);
    CHECK_EQ(vty_repo_get(v, acct_id, &(VtyRepoRecord){0}), VTY_E_INVALID);

    /* fileverthys：文件/分片叶一并清除 */
    CHECK_EQ(vty_module_delete(v, 2u, "pw", "DELETE"), VTY_OK);
    CHECK_EQ(vty_repo_file_get(v, file_uuid, &(VtyRepoFile){0}), VTY_E_POLICY);
    CHECK_EQ(vty_repo_chunk_get(v, file_uuid, 0u, &got, &got_len), VTY_E_POLICY);
    CHECK_EQ(vty_vault_module_uuid(v, 2, new_uuid0), VTY_OK);
    CHECK(memcmp(old_uuid2, new_uuid0, VTY_UUID_BYTES) != 0);
    CHECK_EQ(vty_module_enable(v, 2u, "fmpw", NULL), VTY_OK);
    CHECK_EQ(vty_repo_file_get(v, file_uuid, &(VtyRepoFile){0}), VTY_E_INVALID);
    vty_vault_free(v);

    /* 恢复会话可免口令删除，但 confirm 仍必须正确 */
    v = NULL;
    CHECK_EQ(vty_vault_open_recovery("moddel.vty", code, &re), VTY_OK);
    CHECK_EQ(vty_module_delete(re, 0u, NULL, "DELETE"), VTY_OK);
    CHECK_EQ(vty_module_status(re, 0, &st), VTY_OK);
    CHECK_EQ(st.deleted, 1);
    vty_vault_free(re);
    return 0;
}

/* 产品序列回归：启用→锁定→错误口令→解锁→轮换→旧口令失效→关闭→删除。
 * 删除前处于“已启用后又被关闭”的状态（MDEK 回 Keyring），必须仍可删除。 */
TEST(module_lifecycle_disable_then_delete)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyModuleStatus st;

    vty_lockout_set_enabled(0);
    remove("modlife.vty");
    CHECK_EQ(vty_vault_create("modlife.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);
    vty_module_lock(v, 0u);
    CHECK_EQ(vty_module_unlock(v, 0u, "wrong"), VTY_E_KEY_INVALID);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw"), VTY_OK);
    CHECK_EQ(vty_module_rotate_password(v, 0u, "mpw", "mpw2"), VTY_OK);
    vty_module_lock(v, 0u);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw"), VTY_E_KEY_INVALID);
    CHECK_EQ(vty_module_unlock(v, 0u, "mpw2"), VTY_OK);
    CHECK_EQ(vty_module_disable(v, 0u, "mpw2"), VTY_OK);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.enabled, 0);
    CHECK_EQ(st.deleted, 0);
    CHECK_EQ(module_has_keyring_mdek(v, 0), 1);

    /* 关闭后删除：容器口令仍是硬门槛；正确口令必须成功 */
    CHECK_EQ(vty_module_delete(v, 0u, "wrong", "DELETE"), VTY_E_KEY_INVALID);
    CHECK_EQ(vty_module_delete(v, 0u, "pw", "DELETE"), VTY_OK);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.deleted, 1);
    vty_vault_free(v);
    return 0;
}

TEST(module_crash_rekey_rollback)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t photo1[] = {0x11, 0x01};
    uint8_t photo2[] = {0x22, 0x02};
    uint64_t id1 = 0, id2 = 0;
    VtyModuleStatus st;
    int rc;

    vty_lockout_set_enabled(0);
    remove("modcrash.vty");
    CHECK_EQ(vty_vault_create("modcrash.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"a", 1,
                          photo1, sizeof(photo1), &id1), VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"b", 1,
                          photo2, sizeof(photo2), &id2), VTY_OK);

    /* 让一条记录段 hash 失配：启用重写在读段时失败，必须整体回滚 */
    CHECK_EQ(corrupt_record_hash(v, id1), VTY_OK);
    rc = vty_module_enable(v, 0u, "mpw", NULL);
    CHECK(rc != VTY_OK);
    CHECK_EQ(vty_module_status(v, 0, &st), VTY_OK);
    CHECK_EQ(st.enabled, 0);
    CHECK_EQ(module_has_keyring_mdek(v, 0), 1);
    CHECK_EQ((v->header.flags & VTY_FLAG_MODULE_M1), 0);
    CHECK(module_get(v, id2, photo2, sizeof(photo2)));
    vty_vault_free(v);
    return 0;
}

/* 回归：内容在落库前已用模块 MDEK 做分片封装，记录层又以同一 MDEK
 * 加密外层。模块启用轮换 MDEK 时必须同步换封内层信封，否则启用后全部
 * 内容认证失败（照片损坏、文件块不可读）。非内容记录载荷必须原样保留。 */
TEST(module_enable_rewraps_sealed_record_content)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t photo_uuid[VTY_UUID_BYTES];
    uint8_t file_uuid[VTY_UUID_BYTES];
    uint8_t photo_pt[] = {0x41, 0x42, 0x43, 0x44};
    uint8_t file_pt[] = {0x51, 0x52, 0x53};
    uint8_t plain[] = {0x7B, 0x22, 0x6E, 0x61, 0x6D, 0x65, 0x22, 0x7D};
    /* 结构吻合但无法认证的伪信封：不得被误判为内容而改写 */
    uint8_t fake[16 + 12 + 24 + 4 + 16];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    uint8_t *opened = NULL;
    size_t opened_len = 0;
    uint64_t photo_id = 0, file_id = 0, plain_id = 0, fake_id = 0;
    VtyRepoRecord rec;

    vty_lockout_set_enabled(0);
    remove("modwrap.vty");
    CHECK_EQ(vty_vault_create("modwrap.vty", "pw", &v, code, sizeof(code)),
             VTY_OK);

    memset(photo_uuid, 0x61, sizeof(photo_uuid));
    CHECK_EQ(vty_vault_module_key_index(v, 0u, mdek), VTY_OK);
    CHECK_EQ(vty_chunk_seal(mdek, photo_uuid, 1u, 3u, v->header.epoch,
                            photo_pt, sizeof(photo_pt), &sealed, &sealed_len),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"p", 1,
                          sealed, sealed_len, &photo_id), VTY_OK);
    vty_secure_zero(sealed, sealed_len);
    vty_free(sealed, sealed_len);
    sealed = NULL;

    memset(file_uuid, 0x71, sizeof(file_uuid));
    CHECK_EQ(vty_vault_module_key_index(v, 2u, mdek), VTY_OK);
    CHECK_EQ(vty_chunk_seal(mdek, file_uuid, 0u, 1u, v->header.epoch,
                            file_pt, sizeof(file_pt), &sealed, &sealed_len),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 0x04, (const uint8_t *)"f", 1,
                          sealed, sealed_len, &file_id), VTY_OK);
    vty_secure_zero(sealed, sealed_len);
    vty_free(sealed, sealed_len);
    sealed = NULL;

    /* 非内容记录（文件索引明文载荷）：启用后必须逐字节保持不变 */
    CHECK_EQ(vty_repo_add(v, 0x08, (const uint8_t *)"m", 1,
                          plain, sizeof(plain), &plain_id), VTY_OK);

    /* 结构吻合但认证失败的伪信封：必须按普通载荷原样保留 */
    memset(fake, 0xAB, sizeof(fake));
    memset(fake, 0x61, VTY_UUID_BYTES);
    vty_put_u32(fake + VTY_UUID_BYTES, 0u);
    vty_put_u32(fake + VTY_UUID_BYTES + 4u, 1u);
    vty_put_u32(fake + VTY_UUID_BYTES + 8u, 4u);
    CHECK_EQ(vty_repo_add(v, 0x01, (const uint8_t *)"x", 1,
                          fake, sizeof(fake), &fake_id), VTY_OK);

    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);
    CHECK_EQ(vty_module_enable(v, 2u, "fmpw", NULL), VTY_OK);

    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, photo_id, &rec), VTY_OK);
    CHECK_EQ(vty_vault_module_key_index(v, 0u, mdek), VTY_OK);
    CHECK_EQ(vty_chunk_open(mdek, photo_uuid, 1u, 3u, v->header.epoch,
                            rec.data, rec.data_len, &opened, &opened_len),
             VTY_OK);
    CHECK_EQ(opened_len, sizeof(photo_pt));
    CHECK(memcmp(opened, photo_pt, sizeof(photo_pt)) == 0);
    vty_secure_zero(opened, opened_len);
    vty_free(opened, opened_len);
    opened = NULL;
    vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);

    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, file_id, &rec), VTY_OK);
    CHECK_EQ(vty_vault_module_key_index(v, 2u, mdek), VTY_OK);
    CHECK_EQ(vty_chunk_open(mdek, file_uuid, 0u, 1u, v->header.epoch,
                            rec.data, rec.data_len, &opened, &opened_len),
             VTY_OK);
    CHECK_EQ(opened_len, sizeof(file_pt));
    CHECK(memcmp(opened, file_pt, sizeof(file_pt)) == 0);
    vty_secure_zero(opened, opened_len);
    vty_free(opened, opened_len);
    opened = NULL;
    vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);

    CHECK(module_get(v, plain_id, plain, sizeof(plain)));
    CHECK(module_get(v, fake_id, fake, sizeof(fake)));
    vty_vault_free(v);
    return 0;
}
