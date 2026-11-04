/*
 * test_v4_api_v4.c — v4 记录链路的公共 API 验收
 *
 * 覆盖：Add/Get/Delete/DeleteRecords/Count/Scan/Summary/Has/FindFirst/
 * Verify/Flush/改密/Lock→Unlock 持久化，以及借用指针契约。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_v4_types.h"
#include "vty_recovery.h"

#include <stdio.h>
#include <string.h>

#define V4_REC_PATH "v4_api_records.vty"
#define V4_REC_PW   "v4-rec-pw"
#define V4_REC_PW2  "v4-rec-pw-2"

static VerthysResult rec_add(VerthysHandle h, uint8_t type,
                             const char *name, const char *data, uint64_t *id)
{
    VerthysRecord r;

    memset(&r, 0, sizeof(r));
    r.type = (VerthysRecordType)type;
    r.name = name;
    r.name_len = name != NULL ? strlen(name) : 0u;
    r.data = (const uint8_t *)data;
    r.data_len = data != NULL ? strlen(data) : 0u;
    return Verthys_AddRecord(h, &r, id);
}

TEST(v4_api_records_roundtrip_and_scan)
{
    VerthysHandle h = NULL;
    VerthysContainerInfo info;
    VerthysRecord got;
    VerthysRecord batch[8];
    uint64_t lids[8];
    uint64_t failed[8];
    VerthysSummaryRecord sums[8];
    uint64_t id1 = 0, id2 = 0, id3 = 0;
    uint64_t count = 0, failed_count = 0;
    uint8_t found = 0;
    uint64_t found_id = 0;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysScanCursor *cur = NULL;

    remove(V4_REC_PATH);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, V4_REC_PATH, V4_REC_PW, strlen(V4_REC_PW),
                              code, sizeof(code)), VERTHYS_OK);

    CHECK_EQ(rec_add(h, VERTHYS_RECORD_ACCOUNT, "alpha", "one", &id1), VERTHYS_OK);
    CHECK_EQ(rec_add(h, VERTHYS_RECORD_ACCOUNT, "beta", "two-two", &id2), VERTHYS_OK);
    CHECK_EQ(rec_add(h, VERTHYS_RECORD_PHOTO, "gamma", "three", &id3), VERTHYS_OK);
    CHECK_EQ(id1, 1u);
    CHECK_EQ(id2, 2u);
    CHECK_EQ(id3, 3u);

    /* GetRecord：借用指针在下次 API 调用前有效 */
    memset(&got, 0, sizeof(got));
    CHECK_EQ(Verthys_GetRecord(h, id2, &got), VERTHYS_OK);
    CHECK_EQ(got.type, VERTHYS_RECORD_ACCOUNT);
    CHECK_EQ(got.name_len, 4u);
    CHECK_EQ(memcmp(got.name, "beta", 4), 0);
    CHECK_EQ(got.data_len, 7u);
    CHECK_EQ(memcmp(got.data, "two-two", 7), 0);
    CHECK_EQ(Verthys_GetRecord(h, 9999, &got), VERTHYS_ERR_NOTFOUND);
    CHECK_EQ(Verthys_ClearRecordCache(h), VERTHYS_OK);

    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 3u);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_V4);
    CHECK_EQ(info.record_count, 3u);

    /* 摘要扫描：名称解密，类型未知（0），data_size/offset/hash 透传 */
    CHECK_EQ(Verthys_ScanSummaryOpen(h, 0, 10, &cur), VERTHYS_OK);
    memset(sums, 0, sizeof(sums));
    CHECK_EQ(Verthys_ScanSummaryFetch(cur, sums, lids, 8, &count), VERTHYS_OK);
    CHECK_EQ(count, 3u);
    CHECK_EQ(sums[0].lid, id1);
    /* V4 摘要不读记录密文：类型恒为未知 0；类型过滤必须走
     * Verthys_ListIdsByType（类型盲索引）。 */
    CHECK_EQ(sums[0].type, 0u);
    CHECK_EQ(sums[0].name_len, 5u);
    CHECK_EQ(memcmp(sums[0].name, "alpha", 5), 0);
    CHECK_EQ(sums[0].data_size, 3u);
    CHECK(sums[0].physical_offset >= VTY_V4_DATA_OFFSET);
    CHECK_EQ(sums[0].slot_state, VERTHYS_SLOT_VALID);
    for (uint64_t i = 0; i < count; i++) {
        CHECK_EQ(Verthys_ScanSummaryRecordFree(&sums[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* 全量扫描 start_lid=2：返回 beta/gamma */
    memset(batch, 0, sizeof(batch));
    CHECK_EQ(Verthys_ScanOpenEx(h, 2, 10, VERTHYS_SCAN_PROJECT_FULL, 0, 0, &cur),
             VERTHYS_OK);
    CHECK_EQ(Verthys_ScanFetch(cur, batch, lids, 8, &count, failed, &failed_count),
             VERTHYS_OK);
    CHECK_EQ(count, 2u);
    CHECK_EQ(failed_count, 0u);
    CHECK_EQ(lids[0], id2);
    CHECK_EQ(lids[1], id3);
    CHECK_EQ(batch[0].data_len, 7u);
    CHECK_EQ(memcmp(batch[0].data, "two-two", 7), 0);
    CHECK_EQ(batch[1].type, VERTHYS_RECORD_PHOTO);
    for (uint64_t i = 0; i < count; i++) {
        CHECK_EQ(Verthys_ScanRecordFree(&batch[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* 类型索引 */
    CHECK_EQ(Verthys_HasRecordByType(h, VERTHYS_RECORD_PHOTO, &found), VERTHYS_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(Verthys_FindFirstLidByType(h, VERTHYS_RECORD_ACCOUNT, &found, &found_id),
             VERTHYS_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, id1);

    CHECK_EQ(Verthys_VerifyIntegrity(h, failed, 8, &failed_count), VERTHYS_OK);
    CHECK_EQ(failed_count, 0u);
    CHECK_EQ(Verthys_Flush(h), VERTHYS_OK);

    /* 删除与批量删除 */
    CHECK_EQ(Verthys_DeleteRecord(h, id2), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id2, &got), VERTHYS_ERR_NOTFOUND);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 2u);

    {
        uint64_t ids[2] = {id1, 12345u};
        CHECK_EQ(Verthys_DeleteRecords(h, ids, 2), VERTHYS_ERR_NOTFOUND);
        CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
        CHECK_EQ(count, 2u);        /* 整体拒绝，零副作用 */
    }
    {
        uint64_t ids[2] = {id1, id3};
        CHECK_EQ(Verthys_DeleteRecords(h, ids, 2), VERTHYS_OK);
        CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
        CHECK_EQ(count, 0u);
    }

    /* 写入后再改密：epoch 不变，数据仍可解 */
    CHECK_EQ(rec_add(h, VERTHYS_RECORD_ACCOUNT, "delta", "four", &id1), VERTHYS_OK);
    CHECK_EQ(id1, 4u);
    CHECK_EQ(Verthys_ChangePassword(h, V4_REC_PW, strlen(V4_REC_PW),
                                    V4_REC_PW2, strlen(V4_REC_PW2)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V4_REC_PATH, V4_REC_PW, strlen(V4_REC_PW), 0),
             VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_Unlock(h, V4_REC_PATH, V4_REC_PW2, strlen(V4_REC_PW2), 0),
             VERTHYS_OK);
    memset(&got, 0, sizeof(got));
    CHECK_EQ(Verthys_GetRecord(h, id1, &got), VERTHYS_OK);
    CHECK_EQ(got.name_len, 5u);
    CHECK_EQ(memcmp(got.name, "delta", 5), 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(V4_REC_PATH);
    return 0;
}

#define V4_LIST_PATH "v4_api_list_ids.vty"

TEST(v4_api_list_ids_by_type_and_verify_persist)
{
    VerthysHandle h = NULL;
    VerPersistVerifyResult verify;
    uint64_t ids[8];
    uint64_t count = 0;
    uint8_t exhausted = 0;
    uint64_t a1 = 0, p1 = 0, a2 = 0, a3 = 0;
    char code[VTY_RECOVERY_TEXT_BUF];

    remove(V4_LIST_PATH);
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, V4_LIST_PATH, V4_REC_PW,
                              strlen(V4_REC_PW), code, sizeof(code)),
             VERTHYS_OK);

    CHECK_EQ(rec_add(h, VERTHYS_RECORD_ACCOUNT, "a1", "1", &a1), VERTHYS_OK);
    CHECK_EQ(rec_add(h, VERTHYS_RECORD_PHOTO, "p1", "2", &p1), VERTHYS_OK);
    CHECK_EQ(rec_add(h, VERTHYS_RECORD_ACCOUNT, "a2", "3", &a2), VERTHYS_OK);
    CHECK_EQ(rec_add(h, VERTHYS_RECORD_ACCOUNT, "a3", "4", &a3), VERTHYS_OK);

    /* 首 页：账户类型严格升序 + 未耗尽 */
    CHECK_EQ(Verthys_ListIdsByType(h, VERTHYS_RECORD_ACCOUNT, 0, 2,
                                   ids, &count, &exhausted),
             VERTHYS_OK);
    CHECK_EQ(count, 2u);
    CHECK_EQ(ids[0], a1);
    CHECK_EQ(ids[1], a2);
    CHECK_EQ(exhausted, 0u);

    /* 第二页：从上一页末 ID 继续，末页 exhausted=1 */
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_ListIdsByType(h, VERTHYS_RECORD_ACCOUNT, a2, 2,
                                   ids, &count, &exhausted),
             VERTHYS_OK);
    CHECK_EQ(count, 1u);
    CHECK_EQ(ids[0], a3);
    CHECK_EQ(exhausted, 1u);

    /* 其他类型互不串扰 */
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_ListIdsByType(h, VERTHYS_RECORD_PHOTO, 0, 8,
                                   ids, &count, &exhausted),
             VERTHYS_OK);
    CHECK_EQ(count, 1u);
    CHECK_EQ(ids[0], p1);
    CHECK_EQ(exhausted, 1u);

    /* 无记录类型：空页 + 已耗尽 */
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_ListIdsByType(h, 0xFEu, 0, 8, ids, &count, &exhausted),
             VERTHYS_OK);
    CHECK_EQ(count, 0u);
    CHECK_EQ(exhausted, 1u);

    /* 落盘自查：V4 DataRoot 根段在盘且摘要一致 */
    memset(&verify, 0, sizeof(verify));
    CHECK_EQ(Verthys_VerifyPersist(h, &verify), VERTHYS_PERSIST_OK);
    CHECK(verify.file_size >= (uint64_t)(128u * 1024u));
    CHECK_EQ(verify.header_magic, VTY_V4_MAGIC);
    CHECK_EQ(verify.header_version, VTY_V4_VERSION_MAJOR);

    /* 关闭重开：类型盲索引与落盘自查仍然成立 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V4_LIST_PATH, V4_REC_PW,
                            strlen(V4_REC_PW), 0),
             VERTHYS_OK);
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_ListIdsByType(h, VERTHYS_RECORD_ACCOUNT, 0, 8,
                                   ids, &count, &exhausted),
             VERTHYS_OK);
    CHECK_EQ(count, 3u);
    CHECK_EQ(ids[0], a1);
    CHECK_EQ(ids[1], a2);
    CHECK_EQ(ids[2], a3);
    CHECK_EQ(exhausted, 1u);

    /* 删除后类型索引写墓碑：枚举必须跳过该 ID */
    CHECK_EQ(Verthys_DeleteRecord(h, a2), VERTHYS_OK);
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_ListIdsByType(h, VERTHYS_RECORD_ACCOUNT, 0, 8,
                                   ids, &count, &exhausted),
             VERTHYS_OK);
    CHECK_EQ(count, 2u);
    CHECK_EQ(ids[0], a1);
    CHECK_EQ(ids[1], a3);
    CHECK_EQ(exhausted, 1u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(V4_LIST_PATH);
    return 0;
}

TEST(v4_api_records_require_unlock)
{
    VerthysHandle h = NULL;
    VerthysRecord r;
    uint64_t id = 0;

    remove(V4_REC_PATH);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    memset(&r, 0, sizeof(r));
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_GetSummaryCount(h, &id), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* 批量新增：单次提交、ID 单调、逐条可读、重开持久，参数边界整批拒绝。 */
TEST(v4_api_add_records_batch_roundtrip)
{
    static const char *path = "v4_api_add_records.vty";
    VerthysHandle h = NULL;
    VerthysRecord recs[4];
    VerthysRecord got;
    VerthysContainerInfo info;
    uint64_t ids[4];
    uint64_t count = 0;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint32_t i;

    remove(path);
    memset(recs, 0, sizeof(recs));
    memset(ids, 0, sizeof(ids));
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, path, V4_REC_PW, strlen(V4_REC_PW),
                              code, sizeof(code)), VERTHYS_OK);

    for (i = 0u; i < 4u; i++) {
        recs[i].type = (i % 2u == 0u) ? VERTHYS_RECORD_ACCOUNT
                                     : VERTHYS_RECORD_PHOTO;
        recs[i].name = (i == 0u) ? "batch-a" : "batch-b";
        recs[i].name_len = strlen(recs[i].name);
        recs[i].data = (const uint8_t *)"payload";
        recs[i].data_len = 7u;
    }

    CHECK_EQ(Verthys_AddRecords(h, recs, 4, ids), VERTHYS_OK);
    for (i = 0u; i < 4u; i++) {
        CHECK(ids[i] > 0u);
        if (i > 0u) CHECK(ids[i] > ids[i - 1u]);
    }

    /* 逐条可读且类型/名称/数据与输入一致（借用指针即时读取） */
    for (i = 0u; i < 4u; i++) {
        memset(&got, 0, sizeof(got));
        CHECK_EQ(Verthys_GetRecord(h, ids[i], &got), VERTHYS_OK);
        CHECK_EQ((uint32_t)got.type, (uint32_t)recs[i].type);
        CHECK_EQ(got.name_len, recs[i].name_len);
        CHECK_EQ(memcmp(got.name, recs[i].name, recs[i].name_len), 0);
        CHECK_EQ(got.data_len, recs[i].data_len);
        CHECK_EQ(memcmp(got.data, recs[i].data, recs[i].data_len), 0);
        CHECK_EQ(Verthys_ClearRecordCache(h), VERTHYS_OK);
    }

    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 4u);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.record_count, 4u);

    /* 参数边界：空批 / 越限 / 空指针 / 非法长度均整批拒绝，且不产生写入 */
    CHECK_EQ(Verthys_AddRecords(h, recs, 0, ids), VERTHYS_ERR_INVALID);
    {
        VerthysRecord many[VERTHYS_ADD_RECORDS_MAX + 1u];
        memset(many, 0, sizeof(many));
        CHECK_EQ(Verthys_AddRecords(h, many, VERTHYS_ADD_RECORDS_MAX + 1u, ids),
                 VERTHYS_ERR_INVALID);
    }
    CHECK_EQ(Verthys_AddRecords(h, NULL, 1, ids), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_AddRecords(h, recs, 1, NULL), VERTHYS_ERR_INVALID);
    {
        VerthysRecord bad;
        memset(&bad, 0, sizeof(bad));
        bad.name = NULL;
        bad.name_len = 3u;
        ids[0] = 777u;
        CHECK_EQ(Verthys_AddRecords(h, &bad, 1, ids), VERTHYS_ERR_INVALID);
        CHECK_EQ(ids[0], 0u);
    }
    {
        VerthysRecord bad;
        memset(&bad, 0, sizeof(bad));
        bad.name = "x";
        bad.name_len = 1u;
        bad.data = (const uint8_t *)"d";
        bad.data_len = 10u * 1024u * 1024u;
        CHECK_EQ(Verthys_AddRecords(h, &bad, 1, ids), VERTHYS_ERR_RESOURCE_LIMIT);
    }
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 4u);

    /* 关闭重开：批量写入的记录与容器计数均持久 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, path, V4_REC_PW, strlen(V4_REC_PW), 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 4u);
    memset(&got, 0, sizeof(got));
    CHECK_EQ(Verthys_GetRecord(h, ids[3], &got), VERTHYS_OK);
    CHECK_EQ(got.name_len, recs[3].name_len);
    CHECK_EQ(memcmp(got.name, recs[3].name, recs[3].name_len), 0);

    CHECK_EQ(Verthys_ClearRecordCache(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(path);
    return 0;
}
