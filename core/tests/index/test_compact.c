/*
 * test_compact.c — 容器空间压缩验收
 *
 * 覆盖：删除/墓碑后压缩确实缩小文件、活记录与文件分片可读、删除记录
 * 保持不可见、ID 水位与模块槽保持、重开后仍可正常解锁读取。
 */
#include "verthys_test.h"
#include "vty_compact.h"
#include "vty_keymanager.h"
#include "vty_module.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_types.h"
#include "vty_util.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define COMPACT_PATH "compact.vty"
#define COMPACT_TMP  "compact.vty.compact.tmp"
#define COMPACT_PW   "compact-pw"
#define COMPACT_REC_BYTES (64u * 1024u)

static uint64_t compact_file_size(const char *path)
{
    WIN32_FILE_ATTRIBUTE_DATA data;

    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &data)) return 0;
    return ((uint64_t)data.nFileSizeHigh << 32) | (uint64_t)data.nFileSizeLow;
}

static void compact_cleanup(void)
{
    remove(COMPACT_PATH);
    remove(COMPACT_TMP);
    remove(COMPACT_PATH ".vtycompact.bak");
}

TEST(compact_reclaims_deleted_space)
{
    VtyVault *v = NULL;
    VtyVault *nv = NULL;
    VtyVault *re = NULL;
    VtyCompactJob *job = NULL;
    const VtyCompactStats *cs = NULL;
    VtyStorageStats st;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t *data = NULL;
    uint64_t ids[40];
    uint64_t extra[10];
    uint64_t count = 0;
    uint64_t before_size = 0, after_size = 0;
    uint64_t next_before = 0, next_after = 0;
    uint64_t i;

    compact_cleanup();
    memset(&st, 0, sizeof(st));
    data = (uint8_t *)vty_alloc(COMPACT_REC_BYTES);
    CHECK(data != NULL);

    CHECK_EQ(vty_vault_create(COMPACT_PATH, COMPACT_PW, &v, code, sizeof(code)),
             VTY_OK);
    for (i = 0; i < 40u; i++) {
        char name[32];
        uint32_t j;
        snprintf(name, sizeof(name), "rec-%02llu", (unsigned long long)i);
        for (j = 0; j < COMPACT_REC_BYTES; j++) data[j] = (uint8_t)(i + j);
        CHECK_EQ(vty_repo_add(v, 0x10u, (const uint8_t *)name, strlen(name),
                              data, COMPACT_REC_BYTES, &ids[i]), VTY_OK);
    }
    /* 删除一半，制造墓碑与不可达记录段。 */
    for (i = 0; i < 40u; i += 2u) {
        CHECK_EQ(vty_repo_delete(v, ids[i]), VTY_OK);
    }
    /* 再新增并删除一部分，制造新一轮 COW 旧节点。 */
    for (i = 0; i < 10u; i++) {
        char name[32];
        snprintf(name, sizeof(name), "extra-%02llu", (unsigned long long)i);
        CHECK_EQ(vty_repo_add(v, 0x10u, (const uint8_t *)name, strlen(name),
                              data, COMPACT_REC_BYTES, &extra[i]), VTY_OK);
    }
    for (i = 0; i < 5u; i++) {
        CHECK_EQ(vty_repo_delete(v, extra[i]), VTY_OK);
    }
    CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
    CHECK_EQ(count, 25u);
    CHECK_EQ(vty_repo_storage_stats(v, &st), VTY_OK);
    CHECK(st.reclaimable_bytes > 0u);
    CHECK_EQ(vty_repo_next_id(v, &next_before), VTY_OK);
    before_size = compact_file_size(COMPACT_PATH);
    CHECK(before_size > 0u);

    CHECK_EQ(vty_compact_begin(v, COMPACT_TMP, &job), VTY_OK);
    CHECK(job != NULL);
    CHECK_EQ(vty_compact_run(job, NULL, NULL), VTY_OK);
    cs = vty_compact_stats(job);
    CHECK(cs != NULL);
    CHECK(cs->stage == VTY_COMPACT_STAGE_COPIED);
    CHECK(cs->after_bytes < before_size);
    CHECK(cs->reclaimed_bytes > 0u);

    CHECK_EQ(vty_compact_commit(job, &nv), VTY_OK);
    CHECK(nv != NULL);
    /* commit 已释放源库，后续只使用 nv。 */
    v = NULL;
    after_size = compact_file_size(COMPACT_PATH);
    CHECK(after_size > 0u);
    CHECK(after_size < before_size);

    CHECK_EQ(vty_repo_count(nv, &count), VTY_OK);
    CHECK_EQ(count, 25u);
    CHECK_EQ(vty_repo_next_id(nv, &next_after), VTY_OK);
    CHECK_EQ(next_after, next_before);
    {
        VtyRepoRecord rec;
        memset(&rec, 0, sizeof(rec));
        CHECK_EQ(vty_repo_get(nv, ids[1], &rec), VTY_OK);
        CHECK_EQ(rec.data_len, COMPACT_REC_BYTES);
        CHECK_EQ(rec.data[0], (uint8_t)(1u + 0u));
        vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
        memset(&rec, 0, sizeof(rec));
        CHECK_EQ(vty_repo_get(nv, ids[0], &rec), VTY_E_INVALID);
    }

    /* 关闭重开：slots/keyring/模块表与记录必须仍可用。 */
    vty_vault_free(nv);
    nv = NULL;
    CHECK_EQ(vty_vault_open(COMPACT_PATH, COMPACT_PW, &re), VTY_OK);
    CHECK_EQ(vty_repo_count(re, &count), VTY_OK);
    CHECK_EQ(count, 25u);
    {
        VtyRepoRecord rec;
        memset(&rec, 0, sizeof(rec));
        CHECK_EQ(vty_repo_get(re, ids[39], &rec), VTY_OK);
        CHECK_EQ(rec.data_len, COMPACT_REC_BYTES);
        vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
    }
    vty_vault_free(re);

    vty_free(data, COMPACT_REC_BYTES);
    compact_cleanup();
    return 0;
}

TEST(compact_bulk_builder_many_records)
{
    VtyVault *v = NULL;
    VtyVault *nv = NULL;
    VtyCompactJob *job = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t payload[128];
    uint64_t count = 0;
    uint64_t before_size = 0, after_size = 0;
    uint64_t i;

    compact_cleanup();
    memset(payload, 0x5C, sizeof(payload));
    CHECK_EQ(vty_vault_create(COMPACT_PATH, COMPACT_PW, &v, code, sizeof(code)),
             VTY_OK);
    for (i = 0; i < 3000u; i++) {
        char name[32];
        uint64_t id = 0;
        snprintf(name, sizeof(name), "many-%04llu", (unsigned long long)i);
        payload[0] = (uint8_t)i;
        CHECK_EQ(vty_repo_add(v, 0x10u, (const uint8_t *)name, strlen(name),
                              payload, sizeof(payload), &id), VTY_OK);
        if ((i % 3u) == 0u) {
            CHECK_EQ(vty_repo_delete(v, id), VTY_OK);
        }
    }
    CHECK_EQ(vty_repo_count(v, &count), VTY_OK);
    CHECK_EQ(count, 2000u);
    before_size = compact_file_size(COMPACT_PATH);
    CHECK(before_size > 0u);

    CHECK_EQ(vty_compact_begin(v, COMPACT_TMP, &job), VTY_OK);
    CHECK_EQ(vty_compact_run(job, NULL, NULL), VTY_OK);
    CHECK_EQ(vty_compact_commit(job, &nv), VTY_OK);
    v = NULL;
    after_size = compact_file_size(COMPACT_PATH);
    CHECK(after_size > 0u);
    CHECK(after_size < before_size);
    CHECK_EQ(vty_repo_count(nv, &count), VTY_OK);
    CHECK_EQ(count, 2000u);
    vty_vault_free(nv);
    compact_cleanup();
    return 0;
}

TEST(compact_copies_live_file_chunks_and_drops_tombstones)
{
    VtyVault *v = NULL;
    VtyVault *nv = NULL;
    VtyCompactJob *job = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t file1[VTY_UUID_BYTES];
    uint8_t file2[VTY_UUID_BYTES];
    uint8_t pt_hash[VTY_HASH_BYTES];
    const uint8_t c0[5] = {'h', 'e', 'l', 'l', 'o'};
    const uint8_t c1[5] = {'w', 'o', 'r', 'l', 'd'};
    const uint8_t c2[5] = {'t', 'h', 'i', 'r', 'd'};
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    uint64_t before_size = 0, after_size = 0;
    uint64_t files = 0, chunks = 0;

    compact_cleanup();
    memset(file1, 0x71, sizeof(file1));
    memset(file2, 0x72, sizeof(file2));
    memset(pt_hash, 0x33, sizeof(pt_hash));

    CHECK_EQ(vty_vault_create(COMPACT_PATH, COMPACT_PW, &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_file_put(v, file1, pt_hash, 3), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 0, c0, sizeof(c0)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 1, c1, sizeof(c1)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 2, c2, sizeof(c2)), VTY_OK);
    CHECK_EQ(vty_repo_file_put(v, file2, pt_hash, 2), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file2, 0, c0, sizeof(c0)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file2, 1, c1, sizeof(c1)), VTY_OK);

    /* 清空文件模块（全部变墓碑），再重建 file1：源库同时含活数据与垃圾。 */
    CHECK_EQ(vty_repo_module_purge(v, 2u, v->modules[2].uuid,
                                   NULL, &files, &chunks), VTY_OK);
    CHECK_EQ(files, 2u);
    CHECK_EQ(chunks, 5u);
    CHECK_EQ(vty_repo_file_put(v, file1, pt_hash, 3), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 0, c0, sizeof(c0)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 1, c1, sizeof(c1)), VTY_OK);
    CHECK_EQ(vty_repo_chunk_add(v, file1, 2, c2, sizeof(c2)), VTY_OK);

    before_size = compact_file_size(COMPACT_PATH);
    CHECK(before_size > 0u);
    CHECK_EQ(vty_compact_begin(v, COMPACT_TMP, &job), VTY_OK);
    CHECK_EQ(vty_compact_run(job, NULL, NULL), VTY_OK);
    CHECK_EQ(vty_compact_commit(job, &nv), VTY_OK);
    v = NULL;
    after_size = compact_file_size(COMPACT_PATH);
    CHECK(after_size > 0u);
    CHECK(after_size < before_size);

    CHECK_EQ(vty_repo_chunk_get(nv, file1, 1, &pt, &pt_len), VTY_OK);
    CHECK_EQ(pt_len, sizeof(c1));
    CHECK_EQ(memcmp(pt, c1, sizeof(c1)), 0);
    vty_free(pt, pt_len);
    pt = NULL;
    CHECK_EQ(vty_repo_chunk_get(nv, file2, 0, &pt, &pt_len), VTY_E_INVALID);

    vty_vault_free(nv);
    compact_cleanup();
    return 0;
}
