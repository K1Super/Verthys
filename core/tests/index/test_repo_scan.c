/*
 * test_repo_scan.c — 目录叶游标与类型索引验收
 *
 * 覆盖：全量升序、start_id 过滤、墓碑跳过、COW 快照（打开后写入不
 * 影响已打开游标）、类型索引首条/存在性。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_repo.h"
#include "vty_util.h"

#include <string.h>

#define SCAN_PATH "repo_scan.vty"

static int scan_add(VtyVault *v, uint8_t type, const char *name, uint64_t *id)
{
    return vty_repo_add(v, type, (const uint8_t *)name,
                        name != NULL ? strlen(name) : 0u,
                        (const uint8_t *)name, name != NULL ? strlen(name) : 0u,
                        id);
}

TEST(repo_scan_cursor_and_start_id)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoIter *it = NULL;
    uint64_t ids[5] = {0};
    uint64_t seen[8];
    size_t n = 0;
    int done = 0;
    int i;

    remove(SCAN_PATH);
    CHECK_EQ(vty_vault_create(SCAN_PATH, "scan-pw", &v, code, sizeof(code)),
             VTY_OK);
    for (i = 0; i < 5; i++) {
        char name[16];
        sprintf_s(name, sizeof(name), "rec-%d", i + 1);
        CHECK_EQ(scan_add(v, (uint8_t)(1 + (i % 2)), name, &ids[i]), VTY_OK);
        CHECK_EQ(ids[i], (uint64_t)(i + 1));
    }

    CHECK_EQ(vty_repo_iter_open(v, 0, &it), VTY_OK);
    for (;;) {
        VtyRepoLeaf leaf;
        CHECK_EQ(vty_repo_iter_next(it, &leaf, &done), VTY_OK);
        if (done) break;
        CHECK(n < 5u);
        seen[n++] = leaf.record_id;
        CHECK_EQ(leaf.plain_size > 0u, 1);
    }
    vty_repo_iter_close(it);
    CHECK_EQ(n, 5u);
    for (i = 0; i < 5; i++) CHECK_EQ(seen[i], ids[i]);

    /* start_id 过滤：>= 4 的只剩 4、5 */
    n = 0;
    done = 0;
    CHECK_EQ(vty_repo_iter_open(v, 4, &it), VTY_OK);
    for (;;) {
        VtyRepoLeaf leaf;
        CHECK_EQ(vty_repo_iter_next(it, &leaf, &done), VTY_OK);
        if (done) break;
        if (n < 8u) seen[n] = leaf.record_id;
        n++;
    }
    vty_repo_iter_close(it);
    CHECK_EQ(n, 2u);
    CHECK_EQ(seen[0], 4u);
    CHECK_EQ(seen[1], 5u);

    /* COW 快照：打开旧游标后新增记录，旧游标不得看到新条目 */
    n = 0;
    done = 0;
    CHECK_EQ(vty_repo_iter_open(v, 0, &it), VTY_OK);
    {
        uint64_t extra = 0;
        CHECK_EQ(scan_add(v, 3, "late", &extra), VTY_OK);
        CHECK_EQ(extra, 6u);
    }
    for (;;) {
        VtyRepoLeaf leaf;
        CHECK_EQ(vty_repo_iter_next(it, &leaf, &done), VTY_OK);
        if (done) break;
        n++;
    }
    vty_repo_iter_close(it);
    CHECK_EQ(n, 5u);

    vty_vault_free(v);
    remove(SCAN_PATH);
    return 0;
}

TEST(repo_scan_skips_tombstone_and_type_index)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoIter *it = NULL;
    uint64_t ids[4] = {0};
    uint64_t seen[4];
    uint8_t found = 0;
    uint64_t found_id = 0;
    int done = 0;
    size_t n = 0;

    remove(SCAN_PATH);
    CHECK_EQ(vty_vault_create(SCAN_PATH, "scan-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(scan_add(v, 5, "a", &ids[0]), VTY_OK);
    CHECK_EQ(scan_add(v, 6, "b", &ids[1]), VTY_OK);
    CHECK_EQ(scan_add(v, 5, "c", &ids[2]), VTY_OK);
    CHECK_EQ(scan_add(v, 6, "d", &ids[3]), VTY_OK);

    CHECK_EQ(vty_repo_delete(v, ids[1]), VTY_OK);

    CHECK_EQ(vty_repo_iter_open(v, 0, &it), VTY_OK);
    for (;;) {
        VtyRepoLeaf leaf;
        CHECK_EQ(vty_repo_iter_next(it, &leaf, &done), VTY_OK);
        if (done) break;
        if (n < 4u) seen[n] = leaf.record_id;
        n++;
    }
    vty_repo_iter_close(it);
    CHECK_EQ(n, 3u);
    CHECK_EQ(seen[0], 1u);
    CHECK_EQ(seen[1], 3u);
    CHECK_EQ(seen[2], 4u);

    /* 类型 6 的首条（id2）已删除，FindFirst 必须返回 id4 */
    CHECK_EQ(vty_repo_find_by_type(v, 6, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, ids[3]);
    CHECK_EQ(vty_repo_find_by_type(v, 5, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 1u);
    CHECK_EQ(found_id, ids[0]);

    CHECK_EQ(vty_repo_delete_many(v, ids, 4), VTY_E_INVALID); /* id2 已删除 */
    {
        uint64_t rest[3] = {ids[0], ids[2], ids[3]};
        CHECK_EQ(vty_repo_delete_many(v, rest, 3), VTY_OK);
    }
    CHECK_EQ(vty_repo_find_by_type(v, 5, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 0u);
    CHECK_EQ(vty_repo_find_by_type(v, 6, &found, &found_id), VTY_OK);
    CHECK_EQ(found, 0u);

    vty_vault_free(v);
    remove(SCAN_PATH);
    return 0;
}
