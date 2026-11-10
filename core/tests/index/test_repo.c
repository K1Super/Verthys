/*
 * test_repo.c — 记录仓库验收
 *
 * 覆盖：ID 单调分配、名称/类型盲索引、墓碑、批量删除、重复名称、
 * 空名称/空数据、关闭重开后持久化。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_module.h"
#include "vty_record.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_util.h"

#include <string.h>

#define REPO_PATH "repo.vty"

static int repo_add_str(VtyVault *v, uint8_t type, const char *name,
                        const char *data, uint64_t *out_id)
{
    return vty_repo_add(v, type,
                        (const uint8_t *)name, name != NULL ? strlen(name) : 0u,
                        (const uint8_t *)data, data != NULL ? strlen(data) : 0u,
                        out_id);
}

TEST(repo_add_get_delete_and_id_monotonic)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoRecord rec;
    uint64_t id1 = 0, id2 = 0, id3 = 0, id4 = 0;
    uint64_t count = 0;
    uint8_t found = 0;
    uint64_t found_id = 0;

    remove(REPO_PATH);
    CHECK_EQ(vty_vault_create(REPO_PATH, "repo-pw", &v, code, sizeof(code)),
             VTY_OK);

    CHECK_EQ(repo_add_str(v, 7, "alpha", "one", &id1), VTY_OK);
    CHECK_EQ(repo_add_str(v, 8, "dup", "two", &id2), VTY_OK);
    CHECK_EQ(repo_add_str(v, 7, "dup", "three", &id3), VTY_OK);
    CHECK_EQ(id1, 1u);
    CHECK_EQ(id2, 2u);
    CHECK_EQ(id3, 3u);

    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, id2, &rec), VTY_OK);
    CHECK_EQ(rec.id, id2);
    CHECK_EQ(rec.type, 8u);
    CHECK_EQ(rec.name_len, 3u);
    CHECK_EQ(memcmp(rec.name, "dup", 3), 0);
    CHECK_EQ(rec.data_len, 3u);
    CHECK_EQ(memcmp(rec.data, "two", 3), 0);
    vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);

    /* 删除：Get 立即 NOTFOUND（仓库层 E_INVALID），ID 不复用 */
    CHECK_EQ(vty_repo_delete(v, id2), VTY_OK);
    CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
    CHECK_EQ(count, 2u);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, id2, &rec), VTY_E_INVALID);

    CHECK_EQ(repo_add_str(v, 9, "after", NULL, &id4), VTY_OK);
    CHECK_EQ(id4, 4u);

    /* 重复删除/不存在删除必须幂等失败且不改状态 */
    CHECK_EQ(vty_repo_delete(v, id2), VTY_E_INVALID);
    CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
    CHECK_EQ(count, 3u);

    /* 类型索引：类型 8 的唯一记录已删除；类型 7 首条为 id1 */
    CHECK_EQ(vty_repo_find_by_type(v, 8, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 0u);
    CHECK_EQ(vty_repo_find_by_type(v, 7, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, id1);

    /* 批量删除：任一不存在整体拒绝（零副作用） */
    {
        uint64_t ids[3] = {id1, id3, 999u};
        CHECK_EQ(vty_repo_delete_many(v, ids, 3), VTY_E_INVALID);
        CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
        CHECK_EQ(count, 3u);
    }
    {
        uint64_t ids[2] = {id1, id3};
        CHECK_EQ(vty_repo_delete_many(v, ids, 2), VTY_OK);
        CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
        CHECK_EQ(count, 1u);
        CHECK_EQ(vty_repo_get(v, id1, &rec), VTY_E_INVALID);
        CHECK_EQ(vty_repo_get(v, id3, &rec), VTY_E_INVALID);
    }

    vty_vault_free(v);

    /* 关闭重开：DataRoot/Keyring/墓碑状态必须一致 */
    CHECK_EQ(vty_vault_open(REPO_PATH, "repo-pw", &re), VTY_OK);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(re, id4, &rec), VTY_OK);
    CHECK_EQ(rec.type, 9u);
    CHECK_EQ(rec.name_len, 5u);
    CHECK_EQ(memcmp(rec.name, "after", 5), 0);
    CHECK_EQ(rec.data_len, 0u);
    vty_free(rec.name, rec.name_len);
    CHECK_EQ(vty_repo_count(re, &count), VTY_OK);
    CHECK_EQ(count, 1u);
    vty_vault_free(re);

    remove(REPO_PATH);
    return 0;
}

TEST(repo_file_chunk_manifest)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t file1[VTY_UUID_BYTES];
    uint8_t file2[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    VtyRepoFile f;
    VtyRepoChunkEntry *man = NULL;
    uint32_t man_count = 0;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    const uint8_t c0[5] = {'h', 'e', 'l', 'l', 'o'};
    const uint8_t c1[5] = {'w', 'o', 'r', 'l', 'd'};

    remove(REPO_PATH);
    CHECK_EQ(vty_vault_create(REPO_PATH, "repo-pw", &v, code, sizeof(code)),
             VTY_OK);
    memset(file1, 0x71, sizeof(file1));
    memset(file2, 0x72, sizeof(file2));
    memset(pt_hash, 0x33, sizeof(pt_hash));

    CHECK_EQ(vty_repo_file_put(v, file1, pt_hash, 2), VTY_OK);
    memset(&f, 0, sizeof(f));
    CHECK_EQ(vty_repo_file_get(v, file1, &f), VTY_OK);
    CHECK_EQ(f.total, 2u);
    CHECK_EQ(memcmp(f.pt_hash, pt_hash, sizeof(pt_hash)), 0);

    CHECK_EQ(vty_repo_chunk_add(v, file1, 0, c0, sizeof(c0)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 1, c1, sizeof(c1)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_get(v, file1, 0, &pt, &pt_len), VTY_OK);
    CHECK_EQ(pt_len, sizeof(c0));
    CHECK_EQ(memcmp(pt, c0, sizeof(c0)), 0);
    vty_free(pt, pt_len);
    pt = NULL;

    CHECK_EQ(vty_repo_file_manifest(v, file1, &man, &man_count), VTY_OK);
    CHECK_EQ(man_count, 2u);
    CHECK_EQ(man[0].seq, 0u);
    CHECK_EQ(man[1].seq, 1u);
    CHECK(man[0].offset >= VTY_DATA_OFFSET);
    CHECK(man[1].offset > man[0].offset);
    CHECK_EQ(man[0].len > VTY_SEG_HEADER_BYTES, 1);
    vty_free(man, sizeof(VtyRepoChunkEntry) * man_count);
    man = NULL;

    /* 同一明文/序号在不同文件下 chunk_id 不可关联 */
    CHECK_EQ(vty_repo_file_put(v, file2, pt_hash, 1), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file2, 0, c0, sizeof(c0)), VTY_OK);
    CHECK_EQ(vty_repo_file_manifest(v, file2, &man, &man_count), VTY_OK);
    CHECK_EQ(man_count, 1u);
    {
        VtyRepoChunkEntry *man1 = NULL;
        uint32_t n1 = 0;
        CHECK_EQ(vty_repo_file_manifest(v, file1, &man1, &n1), VTY_OK);
        CHECK_EQ(n1, 2u);
        CHECK(memcmp(man[0].chunk_id, man1[0].chunk_id, VTY_HASH_BYTES) != 0);
        vty_free(man1, sizeof(VtyRepoChunkEntry) * n1);
    }
    vty_free(man, sizeof(VtyRepoChunkEntry) * man_count);
    man = NULL;

    /* 缺失文件/越界序号必须拒绝 */
    CHECK_EQ(vty_repo_chunk_add(v, file2, 1, c1, sizeof(c1)), VTY_E_INVALID);
    CHECK_EQ(vty_repo_chunk_get(v, file1, 5, &pt, &pt_len), VTY_E_INVALID);
    CHECK_EQ(vty_repo_file_get(v, file2, &f), VTY_OK);
    CHECK_EQ(f.total, 1u);

    vty_vault_free(v);

    /* 重开后分片仍可解，清单结构一致 */
    CHECK_EQ(vty_vault_open(REPO_PATH, "repo-pw", &re), VTY_OK);
    CHECK_EQ(vty_repo_chunk_get(re, file1, 1, &pt, &pt_len), VTY_OK);
    CHECK_EQ(pt_len, sizeof(c1));
    CHECK_EQ(memcmp(pt, c1, sizeof(c1)), 0);
    vty_free(pt, pt_len);
    CHECK_EQ(vty_repo_file_manifest(re, file1, &man, &man_count), VTY_OK);
    CHECK_EQ(man_count, 2u);
    vty_free(man, sizeof(VtyRepoChunkEntry) * man_count);
    vty_vault_free(re);

    remove(REPO_PATH);
    return 0;
}

/*
 * 直接落一条非系统域安全记录：数据用模块 0 的 MDEK 与模块 UUID 封装，
 * 索引也按模块令牌生成，用于验证启用事务中的原位迁移。
 * 叶编码与实现层一致：1B 版本 + 1B flags + 2B 保留 + id/uuid/名称索引/
 * 类型令牌/创建时间/偏移/长度/明文长度/哈希。
 */

/* 仓库键为 8B 大端；叶内字段与分配器值走 vty_put_* 的小端。 */
static void test_be64(uint8_t out[8], uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}

static int seed_legacy_security_record(VtyVault *v, uint8_t type,
                                       const char *name, const char *data,
                                       uint64_t *out_id)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t muuid[VTY_UUID_BYTES];
    uint8_t name_index[VTY_HASH_BYTES];
    uint8_t type_token[VTY_HASH_BYTES];
    uint8_t ikey[VTY_HASH_BYTES + 8u];
    uint8_t key[8];
    uint8_t leaf[VTY_REPO_LEAF_BYTES];
    uint8_t zero[8] = {0};
    uint8_t *val = NULL;
    uint8_t *plain = NULL;
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    size_t vlen = 0;
    size_t name_len = name != NULL ? strlen(name) : 0u;
    size_t data_len = data != NULL ? strlen(data) : 0u;
    VtySegmentLocator loc;
    uint64_t id = 0;
    int rc;

    memset(mdek, 0, sizeof(mdek));
    rc = vty_vault_module_key_index(v, 0u, mdek);
    if (rc != VTY_OK) return rc;
    rc = vty_vault_module_uuid(v, 0u, muuid);
    if (rc != VTY_OK) { vty_secure_zero(mdek, sizeof(mdek)); return rc; }

    rc = vty_store_get(v->store, VTY_KS_RECORD, zero, sizeof(zero), &val, &vlen);
    if (rc != VTY_OK) { vty_secure_zero(mdek, sizeof(mdek)); return rc; }
    if (vlen != 8u) {
        vty_free(val, vlen);
        vty_secure_zero(mdek, sizeof(mdek));
        return VTY_E_CORRUPT;
    }
    id = vty_get_u64(val);
    vty_free(val, vlen);
    val = NULL;

    plain = (uint8_t *)vty_alloc(data_len + 1u);
    if (plain == NULL) {
        vty_secure_zero(mdek, sizeof(mdek));
        return VTY_E_RESOURCE;
    }
    plain[0] = type;
    if (data_len != 0u) memcpy(plain + 1, data, data_len);
    rc = vty_record_seal(mdek, muuid, id, v->header.epoch,
                         (const uint8_t *)(name != NULL ? name : ""), name_len,
                         plain, data_len + 1u, &sealed, &sealed_len);
    vty_secure_zero(plain, data_len + 1u);
    vty_free(plain, data_len + 1u);
    if (rc != VTY_OK) { vty_secure_zero(mdek, sizeof(mdek)); return rc; }

    rc = vty_store_append_segment(v->store, VTY_SEG_RECORD, id, 0u,
                                 sealed, sealed_len, &loc);
    vty_secure_zero(sealed, sealed_len);
    vty_free(sealed, sealed_len);
    if (rc != VTY_OK) { vty_secure_zero(mdek, sizeof(mdek)); return rc; }

    rc = vty_name_index(mdek, muuid,
                        (const uint8_t *)(name != NULL ? name : ""), name_len,
                        name_index);
    if (rc == VTY_OK) {
        rc = vty_type_token(mdek, muuid, v->header.epoch, type, type_token);
    }
    vty_secure_zero(mdek, sizeof(mdek));
    if (rc != VTY_OK) return rc;

    memset(leaf, 0, sizeof(leaf));
    leaf[0] = 1u;
    leaf[1] = 0u;
    vty_put_u64(leaf + 4, id);
    memcpy(leaf + 12, muuid, VTY_UUID_BYTES);
    memcpy(leaf + 28, name_index, VTY_HASH_BYTES);
    memcpy(leaf + 60, type_token, VTY_HASH_BYTES);
    vty_put_u64(leaf + 92, 0u);
    vty_put_u64(leaf + 100, loc.offset);
    vty_put_u32(leaf + 108, (uint32_t)loc.total_len);
    vty_put_u32(leaf + 112, (uint32_t)data_len);
    memcpy(leaf + 116, loc.hash, VTY_HASH_BYTES);

    test_be64(key, id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf, sizeof(leaf));
    if (rc != VTY_OK) return rc;
    memcpy(ikey, name_index, VTY_HASH_BYTES);
    test_be64(ikey + VTY_HASH_BYTES, id);
    rc = vty_store_put(v->store, VTY_KS_NAME, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) return rc;
    memcpy(ikey, type_token, VTY_HASH_BYTES);
    test_be64(ikey + VTY_HASH_BYTES, id);
    rc = vty_store_put(v->store, VTY_KS_TYPE, ikey, sizeof(ikey), NULL, 0u);
    if (rc != VTY_OK) return rc;

    vty_put_u64(key, id + 1u);
    rc = vty_store_put(v->store, VTY_KS_RECORD, zero, sizeof(zero),
                       key, sizeof(key));
    if (rc != VTY_OK) return rc;
    *out_id = id;
    return VTY_OK;
}

/* 读取记录叶里的模块 UUID 字段（偏移 12，16B）。 */
static int read_leaf_module_uuid(VtyVault *v, uint64_t id, uint8_t out[VTY_UUID_BYTES])
{
    uint8_t key[8];
    uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    int rc;

    test_be64(key, id);
    rc = vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key),
                       &leaf, &leaf_len);
    if (rc != VTY_OK) return rc;
    if (leaf_len != VTY_REPO_LEAF_BYTES) {
        vty_free(leaf, leaf_len);
        return VTY_E_CORRUPT;
    }
    memcpy(out, leaf + 12, VTY_UUID_BYTES);
    vty_free(leaf, leaf_len);
    return VTY_OK;
}

TEST(repo_system_domain_survives_module_enable_and_delete)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t gid = 0, cid = 0, gid2 = 0;
    uint8_t found = 0;
    uint64_t found_id = 0;
    uint8_t leaf_uuid[VTY_UUID_BYTES];
    VtyRepoRecord rec;
    VtyModuleStatus st;

    remove(REPO_PATH);
    CHECK_EQ(vty_vault_create(REPO_PATH, "repo-pw", &v, code, sizeof(code)),
             VTY_OK);

    /* 新写入的安全记录直接落系统域，证书记录仍按业务路由到模块 0 */
    CHECK_EQ(repo_add_str(v, 0x10, "global-key", "gk", &gid), VTY_OK);
    CHECK_EQ(repo_add_str(v, 0x11, "cert", "c1", &cid), VTY_OK);
    CHECK_EQ(read_leaf_module_uuid(v, gid, leaf_uuid), VTY_OK);
    CHECK_EQ(memcmp(leaf_uuid, vty_system_module_uuid, VTY_UUID_BYTES), 0);
    CHECK_EQ(read_leaf_module_uuid(v, cid, leaf_uuid), VTY_OK);
    CHECK(memcmp(leaf_uuid, vty_system_module_uuid, VTY_UUID_BYTES) != 0);

    /* 启用并锁定模块 0：系统域记录必须仍可读写，模块记录必须被拒绝 */
    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);
    vty_module_lock(v, 0u);
    CHECK_EQ(vty_module_status(v, 0u, &st), VTY_OK);
    CHECK_EQ(st.enabled, 1u);
    CHECK_EQ(st.unlocked, 0u);
    CHECK_EQ(vty_repo_find_by_type(v, 0x10, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, gid);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, gid, &rec), VTY_OK);
    CHECK_EQ(rec.type, 0x10u);
    CHECK_EQ(rec.name_len, 10u);
    CHECK_EQ(memcmp(rec.name, "global-key", 10), 0);
    CHECK_EQ(rec.data_len, 2u);
    CHECK_EQ(memcmp(rec.data, "gk", 2), 0);
    vty_free(rec.name, rec.name_len);
    vty_free(rec.data, rec.data_len);
    CHECK_EQ(repo_add_str(v, 0x10, "global-key-2", "gk2", &gid2), VTY_OK);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, cid, &rec), VTY_E_POLICY);

    vty_vault_free(v);

    /* 重开后模块仍锁定，系统域记录不受影响 */
    CHECK_EQ(vty_vault_open(REPO_PATH, "repo-pw", &re), VTY_OK);
    CHECK_EQ(vty_repo_find_by_type(re, 0x10, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, gid);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(re, gid, &rec), VTY_OK);
    CHECK_EQ(rec.data_len, 2u);
    CHECK_EQ(memcmp(rec.data, "gk", 2), 0);
    vty_free(rec.name, rec.name_len);
    vty_free(rec.data, rec.data_len);

    /* 删除模块 0：业务记录清除，系统域记录保留 */
    CHECK_EQ(vty_module_delete(re, 0u, "repo-pw", "DELETE"), VTY_OK);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(re, gid, &rec), VTY_OK);
    vty_free(rec.name, rec.name_len);
    vty_free(rec.data, rec.data_len);
    CHECK_EQ(vty_repo_get(re, cid, &rec), VTY_E_INVALID);

    vty_vault_free(re);
    remove(REPO_PATH);
    return 0;
}

TEST(repo_legacy_security_record_migrates_on_module_enable)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t gid = 0;
    uint8_t found = 0;
    uint64_t found_id = 0;
    uint8_t leaf_uuid[VTY_UUID_BYTES];
    VtyRepoRecord rec;
    VtyModuleStatus st;

    remove(REPO_PATH);
    CHECK_EQ(vty_vault_create(REPO_PATH, "repo-pw", &v, code, sizeof(code)),
             VTY_OK);

    /* 模块未启用时按模块 0 密钥写入 */
    CHECK_EQ(seed_legacy_security_record(v, 0x10, "global-key", "gk", &gid),
             VTY_OK);
    CHECK_EQ(vty_repo_find_by_type(v, 0x10, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, gid);
    CHECK_EQ(read_leaf_module_uuid(v, gid, leaf_uuid), VTY_OK);
    CHECK(memcmp(leaf_uuid, vty_system_module_uuid, VTY_UUID_BYTES) != 0);

    /* 启用模块 0：启用事务内原位迁移到系统域，record_id 不变 */
    CHECK_EQ(vty_module_enable(v, 0u, "mpw", NULL), VTY_OK);
    vty_module_lock(v, 0u);
    CHECK_EQ(vty_module_status(v, 0u, &st), VTY_OK);
    CHECK_EQ(st.enabled, 1u);
    CHECK_EQ(st.unlocked, 0u);
    CHECK_EQ(vty_repo_find_by_type(v, 0x10, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, gid);
    CHECK_EQ(read_leaf_module_uuid(v, gid, leaf_uuid), VTY_OK);
    CHECK_EQ(memcmp(leaf_uuid, vty_system_module_uuid, VTY_UUID_BYTES), 0);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, gid, &rec), VTY_OK);
    CHECK_EQ(rec.type, 0x10u);
    CHECK_EQ(rec.data_len, 2u);
    CHECK_EQ(memcmp(rec.data, "gk", 2), 0);
    vty_free(rec.name, rec.name_len);
    vty_free(rec.data, rec.data_len);

    vty_vault_free(v);

    /* 重开：模块锁定不影响已迁移记录 */
    CHECK_EQ(vty_vault_open(REPO_PATH, "repo-pw", &re), VTY_OK);
    CHECK_EQ(vty_repo_find_by_type(re, 0x10, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, gid);
    vty_vault_free(re);

    remove(REPO_PATH);
    return 0;
}

TEST(repo_empty_name_and_tombstone_count)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t ids[4] = {0};
    uint64_t count = 0;
    VtyRepoRecord rec;

    remove(REPO_PATH);
    CHECK_EQ(vty_vault_create(REPO_PATH, "repo-pw", &v, code, sizeof(code)),
             VTY_OK);

    /* 空名称 + 空数据也必须能往返（名称 AEAD 内层长度 0） */
    CHECK_EQ(repo_add_str(v, 1, "", "", &ids[0]), VTY_OK);
    CHECK_EQ(repo_add_str(v, 1, NULL, NULL, &ids[1]), VTY_OK);
    CHECK_EQ(ids[0], 1u);
    CHECK_EQ(ids[1], 2u);

    memset(&rec, 0, sizeof(rec));
    CHECK_EQ(vty_repo_get(v, ids[1], &rec), VTY_OK);
    CHECK_EQ(rec.name_len, 0u);
    CHECK_EQ(rec.data_len, 0u);
    vty_free(rec.name, 1u);
    vty_free(rec.data, 1u);

    /* 未打开任何记录时计数仍要建立分配器语义：再写两条 */
    CHECK_EQ(repo_add_str(v, 2, "n3", "d3", &ids[2]), VTY_OK);
    CHECK_EQ(repo_add_str(v, 2, "n4", "d4", &ids[3]), VTY_OK);
    CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
    CHECK_EQ(count, 4u);

    CHECK_EQ(vty_repo_delete(v, ids[2]), VTY_OK);
    CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
    CHECK_EQ(count, 3u);

    /* 记录叶被改写为未知 flags：必须拒绝而不是静默接受 */
    {
        uint8_t key[8];
        uint8_t bad[VTY_REPO_LEAF_BYTES];
        uint8_t *leaf = NULL;
        size_t leaf_len = 0;
        int i;
        for (i = 0; i < 8; i++) key[i] = (uint8_t)(ids[3] >> (56 - 8 * i));
        CHECK_EQ(vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key),
                               &leaf, &leaf_len), VTY_OK);
        CHECK_EQ(leaf_len, VTY_REPO_LEAF_BYTES);
        memcpy(bad, leaf, sizeof(bad));
        vty_free(leaf, leaf_len);
        bad[1] = 0x80u;
        CHECK_EQ(vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                               bad, sizeof(bad)), VTY_OK);
        memset(&rec, 0, sizeof(rec));
        CHECK_EQ(vty_repo_get(v, ids[3], &rec), VTY_E_CORRUPT);
    }

    vty_vault_free(v);
    remove(REPO_PATH);
    return 0;
}
