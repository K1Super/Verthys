/*
 * test_v4_crash.c — v4 容器崩溃注入验收
 *
 * 覆盖：在 100 个切点截断库文件（模拟创建/写入/轮换过程中的崩溃），
 * 每个截断产物都必须拒绝打开（口令与恢复码两条路径），且原始库保持可用；
 * 残留临时文件不得被当作有效库。
 *
 * 依据：原子写（临时文件 + FlushFileBuffers + MoveFileEx）保证崩溃不损坏
 * 既有库；本用例验证"部分写入"永远不会被接受。
 */
#include "verthys_test.h"
#include "vty_v4_types.h"
#include "vty_keymanager_v4.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

#define V4_CRASH_CUTS 100

static int v4_c_read(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *len = n;
    return 0;
}

static int v4_c_write(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

TEST(v4_crash_injection_100_cuts)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t *orig = NULL;
    size_t len = 0;
    int cut;

    remove("v4_crash.vty");
    remove("v4_crash_cut.vty");
    remove("v4_crash_stray.tmp");

    CHECK_EQ(vty_vault_create("v4_crash.vty", "crash-pw", &v, code,
                              sizeof(code)), VTY_OK);
    vty_vault_free(v);

    orig = (uint8_t *)vty_alloc(64u * 1024u);
    CHECK(orig != NULL);
    CHECK_EQ(v4_c_read("v4_crash.vty", orig, 64u * 1024u, &len), 0);
    CHECK(len > VTY_V4_HEADER_FIXED_BYTES + VTY_V4_HEADER_HASH_BYTES);

    for (cut = 1; cut <= V4_CRASH_CUTS; cut++) {
        size_t at = (len * (size_t)cut) / (size_t)(V4_CRASH_CUTS + 1);

        CHECK_EQ(v4_c_write("v4_crash_cut.vty", orig, at), 0);

        v = NULL;
        CHECK(vty_vault_open("v4_crash_cut.vty", "crash-pw", &v) != VTY_OK);
        CHECK(v == NULL);

        re = NULL;
        CHECK(vty_vault_open_recovery("v4_crash_cut.vty", code, &re) != VTY_OK);
        CHECK(re == NULL);
    }

    /* 100 次截断尝试之后，原始库仍可正常打开 */
    v = NULL;
    CHECK_EQ(vty_vault_open("v4_crash.vty", "crash-pw", &v), VTY_OK);
    vty_vault_free(v);

    /* 崩溃残留的临时文件不是有效库 */
    CHECK_EQ(v4_c_write("v4_crash_stray.tmp", orig, len / 2u), 0);
    v = NULL;
    CHECK(vty_vault_open("v4_crash_stray.tmp", "crash-pw", &v) != VTY_OK);
    CHECK(v == NULL);

    vty_free(orig, 64u * 1024u);
    return 0;
}
