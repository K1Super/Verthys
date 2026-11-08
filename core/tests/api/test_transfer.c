/*
 * test_transfer.c — 导出/导入（v1 交换格式）验收
 *
 * 覆盖：导出全部记录 → 清空 → 导入恢复、错误口令拒绝、截断包拒绝，
 * 以及导出后原库记录保持不变。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_types.h"
#include "vty_recovery.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TR_PATH "transfer.vty"
#define TR_PW   "tr-pw"
#define TR_EXP  "transfer.exp"
#define TR_BAD  "transfer_bad.exp"

static VerthysResult tr_add(VerthysHandle h, uint8_t type,
                            const char *name, const char *data, uint64_t *id)
{
    VerthysRecord r;

    memset(&r, 0, sizeof(r));
    r.type = (VerthysRecordType)type;
    r.name = name;
    r.name_len = strlen(name);
    r.data = (const uint8_t *)data;
    r.data_len = strlen(data);
    return Verthys_AddRecord(h, &r, id);
}

static int tr_read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;

    if (f == NULL) return 1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return 1; }
    *out = (uint8_t *)malloc((size_t)n);
    if (*out == NULL) { fclose(f); return 1; }
    if (fread(*out, 1, (size_t)n, f) != (size_t)n) {
        free(*out);
        *out = NULL;
        fclose(f);
        return 1;
    }
    fclose(f);
    *len = (size_t)n;
    return 0;
}

static int tr_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return 1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return 1; }
    fclose(f);
    return 0;
}

TEST(transfer_export_import_roundtrip)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t ids[5] = {0};
    uint64_t count = 0;
    VerthysRecord batch[8];
    uint64_t lids[8];
    uint64_t failed[8];
    uint64_t failed_count = 0;
    VerthysScanCursor *cur = NULL;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int i;

    remove(TR_PATH);
    remove(TR_EXP);
    remove(TR_BAD);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, TR_PATH, TR_PW, strlen(TR_PW),
                              code, sizeof(code)), VERTHYS_OK);

    CHECK_EQ(tr_add(h, VERTHYS_RECORD_ACCOUNT, "mail", "user@example.com", &ids[0]), VERTHYS_OK);
    CHECK_EQ(tr_add(h, VERTHYS_RECORD_ACCOUNT, "bank", "acct-42", &ids[1]), VERTHYS_OK);
    CHECK_EQ(tr_add(h, VERTHYS_RECORD_PHOTO, "pic", "binary-ish", &ids[2]), VERTHYS_OK);
    CHECK_EQ(tr_add(h, VERTHYS_RECORD_CERT_MANAGER, "cert", "pem", &ids[3]), VERTHYS_OK);
    CHECK_EQ(tr_add(h, VERTHYS_RECORD_FILE_VERTHYS, "file", "payload", &ids[4]), VERTHYS_OK);

    CHECK_EQ(Verthys_Export(h, TR_EXP, "exp-pass", strlen("exp-pass")),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 5u);

    CHECK_EQ(Verthys_DeleteRecords(h, ids, 5), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 0u);

    /* 错误口令：导入必须拒绝且不写入任何记录 */
    CHECK_EQ(Verthys_Import(h, TR_EXP, "wrong-pass", strlen("wrong-pass")),
             VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 0u);

    CHECK_EQ(Verthys_Import(h, TR_EXP, "exp-pass", strlen("exp-pass")),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
    CHECK_EQ(count, 5u);

    /* 内容恢复：按名称读回 */
    memset(batch, 0, sizeof(batch));
    CHECK_EQ(Verthys_ScanOpenEx(h, 0, 10, VERTHYS_SCAN_PROJECT_FULL, 0, 0, &cur),
             VERTHYS_OK);
    CHECK_EQ(Verthys_ScanFetch(cur, batch, lids, 8, &count, failed, &failed_count),
             VERTHYS_OK);
    CHECK_EQ(count, 5u);
    CHECK_EQ(failed_count, 0u);
    for (i = 0; i < 5; i++) {
        if (batch[i].name_len == 4u && memcmp(batch[i].name, "bank", 4) == 0) {
            CHECK_EQ(batch[i].data_len, 7u);
            CHECK_EQ(memcmp(batch[i].data, "acct-42", 7), 0);
            CHECK_EQ(batch[i].type, VERTHYS_RECORD_ACCOUNT);
        }
        CHECK_EQ(Verthys_ScanRecordFree(&batch[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);

    /* 截断包：解析失败，不得部分导入 */
    CHECK_EQ(tr_read_file(TR_EXP, &blob, &blob_len), 0);
    CHECK(blob_len > 32u);
    CHECK_EQ(tr_write_file(TR_BAD, blob, blob_len / 2u), 0);
    {
        uint64_t before = 0;
        CHECK_EQ(Verthys_GetSummaryCount(h, &before), VERTHYS_OK);
        CHECK(Verthys_Import(h, TR_BAD, "exp-pass", strlen("exp-pass")) != VERTHYS_OK);
        CHECK_EQ(Verthys_GetSummaryCount(h, &count), VERTHYS_OK);
        CHECK_EQ(count, before);
    }
    free(blob);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(TR_PATH);
    remove(TR_EXP);
    remove(TR_BAD);
    return 0;
}
