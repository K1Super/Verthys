/*
 * test_v4_store.c — v4 追加数据区、COW 目录树与 DataRoot 验收
 *
 * 覆盖：空根绑定、put/get 往返、节点分裂、旧快照仍可读（COW）、
 * 跨 keyspace 隔离、根节点篡改与截断拒绝。
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_format_v4.h"
#include "vty_keymanager_v4.h"
#include "vty_store_v4.h"
#include "vty_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define V4_ST_PATH "v4_store.vty"

static int st_read_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long n;

    if (f == NULL) return 1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    n = ftell(f);
    if (n <= 0) { fclose(f); return 1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 1; }
    *out = (uint8_t *)malloc((size_t)n);
    if (*out == NULL) { fclose(f); return 1; }
    if (fread(*out, 1, (size_t)n, f) != (size_t)n) {
        free(*out);
        *out = NULL;
        fclose(f);
        return 1;
    }
    fclose(f);
    *out_len = (size_t)n;
    return 0;
}

static int st_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return 1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return 1; }
    fclose(f);
    return 0;
}

TEST(v4_store_empty_root_binds_uuid_epoch)
{
    VtyDataRootLocator loc;
    uint8_t h1[VTY_HASH_BYTES];
    uint8_t h2[VTY_HASH_BYTES];
    uint8_t uuid1[VTY_UUID_BYTES];
    uint8_t uuid2[VTY_UUID_BYTES];

    memset(uuid1, 0x11, sizeof(uuid1));
    memset(uuid2, 0x22, sizeof(uuid2));
    CHECK_EQ(vty_store_empty_locator(uuid1, 1, &loc, h1), VTY_OK);
    CHECK_EQ(loc.root_node_id, 0u);
    CHECK_EQ(loc.data_end, VTY_V4_DATA_OFFSET);
    CHECK_EQ(vty_store_empty_root(uuid1, 1, h2), VTY_OK);
    {
        uint8_t expect[VTY_HASH_BYTES];
        CHECK_EQ(vty_store_data_root(uuid1, 1, h2, expect), VTY_OK);
        CHECK_EQ(memcmp(h1, expect, VTY_HASH_BYTES), 0);
    }
    CHECK_EQ(vty_store_empty_locator(uuid2, 1, &loc, h2), VTY_OK);
    CHECK(memcmp(h1, h2, VTY_HASH_BYTES) != 0);
    CHECK_EQ(vty_store_empty_locator(uuid1, 2, &loc, h2), VTY_OK);
    CHECK(memcmp(h1, h2, VTY_HASH_BYTES) != 0);
    return 0;
}

TEST(v4_store_put_get_and_cow_snapshot)
{
    VtyVault *v = NULL;
    VtyStore *s = NULL;
    VtyStore *old = NULL;
    VtyDataRootLocator loc1, loc2;
    uint8_t hash1[VTY_HASH_BYTES];
    uint8_t hash2[VTY_HASH_BYTES];
    uint8_t value[96];
    uint8_t *got = NULL;
    size_t got_len = 0;
    char code[VTY_RECOVERY_TEXT_BUF];
    int rc;

    remove(V4_ST_PATH);
    CHECK_EQ(vty_vault_create(V4_ST_PATH, "store-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &s), VTY_OK);

    memset(value, 0x5A, sizeof(value));
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"alpha", 5,
                           value, sizeof(value)), VTY_OK);
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"beta", 4,
                           value, 32), VTY_OK);
    CHECK_EQ(vty_store_commit(s, &loc1, hash1), VTY_OK);
    CHECK(loc1.root_node_id != 0u);
    CHECK(loc1.data_end > VTY_V4_DATA_OFFSET);

    CHECK_EQ(vty_store_get(s, VTY_KS_RECORD, (const uint8_t *)"alpha", 5,
                           &got, &got_len), VTY_OK);
    CHECK_EQ(got_len, sizeof(value));
    CHECK_EQ(memcmp(got, value, sizeof(value)), 0);
    vty_secure_zero(got, got_len);
    vty_free(got, got_len);
    got = NULL;

    /* 同一字节键在不同 keyspace 下必须互不可见 */
    CHECK(vty_store_get(s, VTY_KS_NAME, (const uint8_t *)"alpha", 5,
                        &got, &got_len) != VTY_OK);

    /* 写入第二个键后提交；旧快照必须仍可独立打开且看不到新键 */
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"gamma", 5,
                           value, 48), VTY_OK);
    CHECK_EQ(vty_store_commit(s, &loc2, hash2), VTY_OK);
    CHECK(loc2.data_end > loc1.data_end);

    /* 当前句柄以读写方式独占打开；先关闭再开旧快照，否则共享模式冲突 */
    vty_store_close(s);
    s = NULL;
    rc = vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                        v->header.epoch, &loc1, hash1, &old);
    CHECK_EQ(rc, VTY_OK);
    CHECK_EQ(vty_store_get(old, VTY_KS_RECORD, (const uint8_t *)"alpha", 5,
                           &got, &got_len), VTY_OK);
    vty_secure_zero(got, got_len);
    vty_free(got, got_len);
    got = NULL;
    CHECK(vty_store_get(old, VTY_KS_RECORD, (const uint8_t *)"gamma", 5,
                        &got, &got_len) != VTY_OK);

    vty_store_close(old);
    vty_vault_free(v);
    remove(V4_ST_PATH);
    return 0;
}

TEST(v4_store_split_and_verify)
{
    VtyVault *v = NULL;
    VtyStore *s = NULL;
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    uint8_t *got = NULL;
    size_t got_len = 0;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint32_t i;

    remove(V4_ST_PATH);
    CHECK_EQ(vty_vault_create(V4_ST_PATH, "store-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &s), VTY_OK);

    for (i = 0; i < 260; i++) {
        char key[24];
        uint8_t val[64];
        sprintf_s(key, sizeof(key), "rec-%04u", (unsigned)i);
        memset(val, (int)(i & 0xFFu), sizeof(val));
        CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)key,
                               strlen(key), val, sizeof(val)), VTY_OK);
    }
    CHECK_EQ(vty_store_commit(s, &loc, hash), VTY_OK);
    CHECK(loc.level > 0u);
    CHECK_EQ(vty_store_verify(s), VTY_OK);

    for (i = 0; i < 260; i += 7) {
        char key[24];
        sprintf_s(key, sizeof(key), "rec-%04u", (unsigned)i);
        CHECK_EQ(vty_store_get(s, VTY_KS_RECORD, (const uint8_t *)key,
                               strlen(key), &got, &got_len), VTY_OK);
        CHECK_EQ(got_len, 64u);
        CHECK_EQ(got[0], (uint8_t)(i & 0xFFu));
        vty_secure_zero(got, got_len);
        vty_free(got, got_len);
        got = NULL;
    }

    vty_store_close(s);
    vty_vault_free(v);
    remove(V4_ST_PATH);
    return 0;
}

TEST(v4_store_segment_append_read_and_cursor)
{
    VtyVault *v = NULL;
    VtyStore *s = NULL;
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    VtySegmentLocator seg1, seg2, bad;
    VtyStoreCheckpoint cp;
    VtyStoreCursor *cur = NULL;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint8_t *key = NULL, *val = NULL;
    size_t key_len = 0, val_len = 0;
    uint64_t n = 0;
    int done = 0;
    char code[VTY_RECOVERY_TEXT_BUF];
    const uint8_t p1[5] = {1, 2, 3, 4, 5};
    const uint8_t p2[3] = {9, 8, 7};

    remove(V4_ST_PATH);
    CHECK_EQ(vty_vault_create(V4_ST_PATH, "store-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &s), VTY_OK);

    CHECK_EQ(vty_store_append_segment(s, VTY_SEG_RECORD, 1, 0,
                                      p1, sizeof(p1), &seg1), VTY_OK);
    CHECK_EQ(vty_store_append_segment(s, VTY_SEG_CHUNK, 2, 0,
                                      p2, sizeof(p2), &seg2), VTY_OK);
    CHECK(seg2.offset > seg1.offset);
    CHECK_EQ(vty_store_read_segment(s, &seg1, &payload, &payload_len), VTY_OK);
    CHECK_EQ(payload_len, sizeof(p1));
    CHECK_EQ(memcmp(payload, p1, sizeof(p1)), 0);
    vty_free(payload, payload_len);
    payload = NULL;

    /* 段头/哈希绑定：任一位翻转都不得返回 payload */
    bad = seg2;
    bad.hash[0] ^= 0x01u;
    CHECK_EQ(vty_store_read_segment(s, &bad, &payload, &payload_len),
             VTY_E_CORRUPT);
    bad = seg2;
    bad.type = VTY_SEG_RECORD;
    CHECK_EQ(vty_store_read_segment(s, &bad, &payload, &payload_len),
             VTY_E_CORRUPT);

    /* 空值条目与墓碑值都必须可见且可区分 */
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"k1", 2,
                           NULL, 0), VTY_OK);
    CHECK_EQ(vty_store_delete(s, VTY_KS_RECORD, (const uint8_t *)"k2", 2),
             VTY_OK);
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"k3", 2,
                           p2, sizeof(p2)), VTY_OK);
    CHECK_EQ(vty_store_commit(s, &loc, hash), VTY_OK);

    /* 创建时已写入记录分配器（keyspace 0 的 8B 零键），因此计数为 4。 */
    CHECK_EQ(vty_store_count(s, VTY_KS_RECORD, &n), VTY_OK);
    CHECK_EQ(n, 4u);

    CHECK_EQ(vty_store_cursor_open(s, VTY_KS_RECORD, NULL, 0, &cur), VTY_OK);
    n = 0;
    for (;;) {
        CHECK_EQ(vty_store_cursor_next(cur, &done, &key, &key_len,
                                       &val, &val_len), VTY_OK);
        if (done) break;
        n++;
        if (n == 1u) {
            /* 分配器条目：8B 零键 + 8B next_id */
            CHECK_EQ(key_len, 8u);
            CHECK_EQ(val_len, 8u);
        } else if (n == 2u) {
            CHECK_EQ(key_len, 2u);
            CHECK_EQ(memcmp(key, "k1", 2), 0);
            CHECK_EQ(val_len, 0u);
            CHECK(val == NULL);
        } else if (n == 3u) {
            CHECK_EQ(memcmp(key, "k2", 2), 0);
            CHECK_EQ(val_len, 1u);
            CHECK_EQ(val[0], VTY_STORE_TOMBSTONE_BYTE);
        } else if (n == 4u) {
            CHECK_EQ(memcmp(key, "k3", 2), 0);
            CHECK_EQ(val_len, sizeof(p2));
            CHECK_EQ(memcmp(val, p2, sizeof(p2)), 0);
        }
        if (key != NULL) vty_free(key, key_len);
        if (val != NULL) vty_free(val, val_len);
        key = NULL; val = NULL;
    }
    vty_store_cursor_close(cur);
    cur = NULL;
    CHECK_EQ(n, 4u);

    /* start_key 定位 k2 */
    CHECK_EQ(vty_store_cursor_open(s, VTY_KS_RECORD,
                                    (const uint8_t *)"k2", 2, &cur), VTY_OK);
    CHECK_EQ(vty_store_cursor_next(cur, &done, &key, &key_len, &val, &val_len),
             VTY_OK);
    CHECK_EQ(done, 0);
    CHECK_EQ(memcmp(key, "k2", 2), 0);
    vty_free(key, key_len);
    if (val != NULL) vty_free(val, val_len);
    vty_store_cursor_close(cur);
    cur = NULL;

    /* checkpoint/restore 丢弃未提交的根变更 */
    CHECK_EQ(vty_store_checkpoint(s, &cp), VTY_OK);
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"late", 4,
                           p1, sizeof(p1)), VTY_OK);
    CHECK_EQ(vty_store_get(s, VTY_KS_RECORD, (const uint8_t *)"late", 4,
                           &payload, &payload_len), VTY_OK);
    vty_free(payload, payload_len);
    payload = NULL;
    CHECK_EQ(vty_store_restore(s, &cp), VTY_OK);
    CHECK_EQ(vty_store_get(s, VTY_KS_RECORD, (const uint8_t *)"late", 4,
                           &payload, &payload_len), VTY_E_INVALID);

    vty_store_close(s);
    vty_vault_free(v);
    remove(V4_ST_PATH);
    return 0;
}

TEST(v4_store_tamper_and_truncate_rejected)
{
    VtyVault *v = NULL;
    VtyStore *s = NULL;
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    uint8_t value[32];
    uint8_t *file = NULL;
    size_t file_len = 0;
    char code[VTY_RECOVERY_TEXT_BUF];
    FILE *f;

    remove(V4_ST_PATH);
    CHECK_EQ(vty_vault_create(V4_ST_PATH, "store-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &s), VTY_OK);
    memset(value, 0x33, sizeof(value));
    CHECK_EQ(vty_store_put(s, VTY_KS_RECORD, (const uint8_t *)"k", 1,
                           value, sizeof(value)), VTY_OK);
    CHECK_EQ(vty_store_commit(s, &loc, hash), VTY_OK);
    vty_store_close(s);
    s = NULL;

    CHECK_EQ(st_read_file(V4_ST_PATH, &file, &file_len), 0);
    CHECK(file_len > loc.root_offset + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES);

    /* 根节点密文任意位翻转：段 hash/DataRoot 必然失配 */
    file[loc.root_offset + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES + 2u] ^= 0x01u;
    CHECK_EQ(st_write_file(V4_ST_PATH, file, file_len), 0);
    CHECK(vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                         v->header.epoch, &loc, hash, &s) != VTY_OK);

    /* 还原后截断到 data_end 之前：高水位之外的文件必须拒绝 */
    file[loc.root_offset + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES + 2u] ^= 0x01u;
    CHECK_EQ(st_write_file(V4_ST_PATH, file, file_len), 0);
    free(file);
    file = NULL;

    f = fopen(V4_ST_PATH, "r+b");
    CHECK(f != NULL);
    if (f != NULL) {
        CHECK_EQ(_chsize_s(_fileno(f), (long long)(loc.data_end - 1u)), 0);
        fclose(f);
    }
    CHECK(vty_store_open(V4_ST_PATH, v->kc, v->header.vault_uuid,
                         v->header.epoch, &loc, hash, &s) != VTY_OK);

    vty_vault_free(v);
    remove(V4_ST_PATH);
    return 0;
}
