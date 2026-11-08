/*
 * test_crash.c — 容器崩溃注入验收
 *
 * 覆盖：在 100 个切点截断库文件（模拟创建/写入/轮换过程中的崩溃），
 * 每个截断产物都必须拒绝打开（口令与恢复码两条路径），且原始库保持可用；
 * 残留临时文件不得被当作有效库。
 *
 * 依据：原子写（临时文件 + FlushFileBuffers + MoveFileEx）保证崩溃不损坏
 * 既有库；本用例验证"部分写入"永远不会被接受。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_repo.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

#define CRASH_CUTS 100

static int crash_read(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *len = n;
    return 0;
}

static int crash_write(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;

    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : 1;
}

/* 文件复制：模拟“元数据提交前崩溃 → 保留旧库”的恢复场景 */
static int crash_copy(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    FILE *out;
    uint8_t buf[4096];
    size_t n;
    int ok = 1;

    if (in == NULL) return 1;
    out = fopen(dst, "wb");
    if (out == NULL) {
        fclose(in);
        return 1;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            ok = 0;
            break;
        }
    }
    fclose(in);
    fclose(out);
    return ok ? 0 : 1;
}

TEST(crash_injection_100_cuts)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t *orig = NULL;
    size_t len = 0;
    int cut;

    remove("crash.vty");
    remove("crash_cut.vty");
    remove("crash_stray.tmp");

    CHECK_EQ(vty_vault_create("crash.vty", "crash-pw", &v, code,
                              sizeof(code)), VTY_OK);
    vty_vault_free(v);

    orig = (uint8_t *)vty_alloc(64u * 1024u);
    CHECK(orig != NULL);
    CHECK_EQ(crash_read("crash.vty", orig, 64u * 1024u, &len), 0);
    CHECK(len > VTY_HEADER_FIXED_BYTES + VTY_HEADER_HASH_BYTES);

    for (cut = 1; cut <= CRASH_CUTS; cut++) {
        size_t at = (len * (size_t)cut) / (size_t)(CRASH_CUTS + 1);

        CHECK_EQ(crash_write("crash_cut.vty", orig, at), 0);

        v = NULL;
        CHECK(vty_vault_open("crash_cut.vty", "crash-pw", &v) != VTY_OK);
        CHECK(v == NULL);

        re = NULL;
        CHECK(vty_vault_open_recovery("crash_cut.vty", code, &re) != VTY_OK);
        CHECK(re == NULL);
    }

    /* 100 次截断尝试之后，原始库仍可正常打开 */
    v = NULL;
    CHECK_EQ(vty_vault_open("crash.vty", "crash-pw", &v), VTY_OK);
    vty_vault_free(v);

    /* 崩溃残留的临时文件不是有效库 */
    CHECK_EQ(crash_write("crash_stray.tmp", orig, len / 2u), 0);
    v = NULL;
    CHECK(vty_vault_open("crash_stray.tmp", "crash-pw", &v) != VTY_OK);
    CHECK(v == NULL);

    vty_free(orig, 64u * 1024u);
    return 0;
}

TEST(crash_keyfile_create_truncation)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t *orig = NULL;
    size_t len = 0;
    int cut;

    remove("crash_kf.vty");
    remove("crash_kf.vkf");
    remove("crash_kf_cut.vty");

    CHECK_EQ(vty_vault_create_keyfile_file("crash_kf.vty", "crash-kf-pw",
                                           "crash_kf.vkf", &v, code,
                                           sizeof(code)), VTY_OK);
    vty_vault_free(v);

    orig = (uint8_t *)vty_alloc(64u * 1024u);
    CHECK(orig != NULL);
    CHECK_EQ(crash_read("crash_kf.vty", orig, 64u * 1024u, &len), 0);
    CHECK(len > VTY_HEADER_FIXED_BYTES + VTY_HEADER_HASH_BYTES);

    /* 创建过程中任意截断：带/不带 keyfile 两条路径都必须拒绝 */
    for (cut = 1; cut <= CRASH_CUTS; cut++) {
        size_t at = (len * (size_t)cut) / (size_t)(CRASH_CUTS + 1);

        CHECK_EQ(crash_write("crash_kf_cut.vty", orig, at), 0);
        v = NULL;
        CHECK(vty_vault_open_keyfile("crash_kf_cut.vty", "crash-kf-pw",
                                     "crash_kf.vkf", &v) != VTY_OK);
        CHECK(v == NULL);
        v = NULL;
        CHECK(vty_vault_open("crash_kf_cut.vty", "crash-kf-pw", &v) != VTY_OK);
        CHECK(v == NULL);
    }

    /* 原始库：无 keyfile 显式要求；带 keyfile 正常打开 */
    v = NULL;
    CHECK_EQ(vty_vault_open("crash_kf.vty", "crash-kf-pw", &v),
             VTY_E_KEYFILE_REQUIRED);
    CHECK(v == NULL);
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile("crash_kf.vty", "crash-kf-pw",
                                    "crash_kf.vkf", &v), VTY_OK);
    vty_vault_free(v);

    vty_free(orig, 64u * 1024u);
    remove("crash_kf.vty");
    remove("crash_kf.vkf");
    remove("crash_kf_cut.vty");
    return 0;
}

TEST(crash_keyfile_file_tamper)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t buf[VTY_KEYFILE_BLOB_BYTES];
    static const size_t bad_sizes[] = { 0u, 1u, 8u, 40u, 71u, 73u, 144u };
    size_t i;

    remove("crash_kf2.vty");
    remove("crash_kf2.vkf");
    remove("crash_kf2_bad.vkf");
    remove("crash_kf2_flip.vkf");

    CHECK_EQ(vty_vault_create_keyfile_file("crash_kf2.vty", "crash-kf2-pw",
                                           "crash_kf2.vkf", &v, code,
                                           sizeof(code)), VTY_OK);
    vty_vault_free(v);

    memset(buf, 0, sizeof(buf));
    /* 长度不符：全部判为 KEYFILE_INVALID，不得回退到“仅口令”路径 */
    for (i = 0; i < sizeof(bad_sizes) / sizeof(bad_sizes[0]); i++) {
        CHECK_EQ(crash_write("crash_kf2_bad.vkf", buf, bad_sizes[i]), 0);
        v = NULL;
        CHECK_EQ(vty_vault_open_keyfile("crash_kf2.vty", "crash-kf2-pw",
                                        "crash_kf2_bad.vkf", &v),
                 VTY_E_KEYFILE_INVALID);
        CHECK(v == NULL);
    }

    /* 合法长度但内容/校验和被改：仍为 KEYFILE_INVALID */
    buf[20] ^= 0x01u;
    CHECK_EQ(crash_write("crash_kf2_flip.vkf", buf, sizeof(buf)), 0);
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile("crash_kf2.vty", "crash-kf2-pw",
                                    "crash_kf2_flip.vkf", &v),
             VTY_E_KEYFILE_INVALID);
    CHECK(v == NULL);

    /* 原 keyfile 不受影响 */
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile("crash_kf2.vty", "crash-kf2-pw",
                                    "crash_kf2.vkf", &v), VTY_OK);
    vty_vault_free(v);

    remove("crash_kf2.vty");
    remove("crash_kf2.vkf");
    remove("crash_kf2_bad.vkf");
    remove("crash_kf2_flip.vkf");
    return 0;
}

TEST(crash_keyfile_enable_rollback)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char vpath[64], vbak[64], kf1[64], kf2[64];

    strcpy_s(vpath, sizeof(vpath), "crash_kf3.vty");
    strcpy_s(vbak, sizeof(vbak), "crash_kf3_bak.vty");
    strcpy_s(kf1, sizeof(kf1), "crash_kf3_a.vkf");
    strcpy_s(kf2, sizeof(kf2), "crash_kf3_b.vkf");
    remove(vpath);
    remove(vbak);
    remove(kf1);
    remove(kf2);

    CHECK_EQ(vty_vault_create_keyfile_file(vpath, "crash-kf3-pw", kf1, &v, code,
                                           sizeof(code)), VTY_OK);
    vty_vault_free(v);

    /* 提交前快照：模拟 enable 写盘前崩溃 */
    CHECK_EQ(crash_copy(vpath, vbak), 0);

    CHECK_EQ(vty_vault_open_keyfile(vpath, "crash-kf3-pw", kf1, &v), VTY_OK);
    CHECK_EQ(vty_vault_keyfile_enable_file(v, "crash-kf3-pw", kf2), VTY_OK);
    vty_vault_free(v);

    /* 回到旧库：新 keyfile 与元数据不匹配，必须拒绝；旧 keyfile 仍可用 */
    CHECK_EQ(crash_copy(vbak, vpath), 0);
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile(vpath, "crash-kf3-pw", kf1, &v), VTY_OK);
    vty_vault_free(v);
    v = NULL;
    CHECK(vty_vault_open_keyfile(vpath, "crash-kf3-pw", kf2, &v) != VTY_OK);
    CHECK(v == NULL);
    v = NULL;
    CHECK_EQ(vty_vault_open_recovery(vpath, code, &v), VTY_OK);
    vty_vault_free(v);

    remove(vpath);
    remove(vbak);
    remove(kf1);
    remove(kf2);
    return 0;
}

TEST(crash_keyfile_disable_rollback)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char vpath[64], vbak[64], kf1[64];

    strcpy_s(vpath, sizeof(vpath), "crash_kf4.vty");
    strcpy_s(vbak, sizeof(vbak), "crash_kf4_bak.vty");
    strcpy_s(kf1, sizeof(kf1), "crash_kf4.vkf");
    remove(vpath);
    remove(vbak);
    remove(kf1);

    CHECK_EQ(vty_vault_create_keyfile_file(vpath, "crash-kf4-pw", kf1, &v, code,
                                           sizeof(code)), VTY_OK);
    vty_vault_free(v);
    CHECK_EQ(crash_copy(vpath, vbak), 0);

    CHECK_EQ(vty_vault_open_keyfile(vpath, "crash-kf4-pw", kf1, &v), VTY_OK);
    CHECK_EQ(vty_vault_keyfile_disable(v, "crash-kf4-pw", kf1), VTY_OK);
    vty_vault_free(v);

    /* 回到关闭前的旧库：仍必须要求 keyfile，且旧文件可开、恢复码可开 */
    CHECK_EQ(crash_copy(vbak, vpath), 0);
    v = NULL;
    CHECK_EQ(vty_vault_open_keyfile(vpath, "crash-kf4-pw", kf1, &v), VTY_OK);
    vty_vault_free(v);
    v = NULL;
    CHECK_EQ(vty_vault_open(vpath, "crash-kf4-pw", &v),
             VTY_E_KEYFILE_REQUIRED);
    CHECK(v == NULL);
    v = NULL;
    CHECK_EQ(vty_vault_open_recovery(vpath, code, &v), VTY_OK);
    vty_vault_free(v);

    remove(vpath);
    remove(vbak);
    remove(kf1);
    return 0;
}

TEST(crash_record_data_truncation_rejected)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t *buf = NULL;
    size_t len = 0;
    uint64_t data_end = 0;
    uint64_t id = 0;
    size_t rec_off = 0;
    int i;

    remove("crash_rec.vty");
    remove("crash_rec_cut.vty");
    CHECK_EQ(vty_vault_create("crash_rec.vty", "crash-rec-pw", &v, code,
                              sizeof(code)), VTY_OK);
    for (i = 0; i < 5; i++) {
        char name[16];
        uint8_t payload[64];
        sprintf_s(name, sizeof(name), "rec-%d", i);
        memset(payload, (int)i, sizeof(payload));
        CHECK_EQ(vty_repo_add(v, 2, (const uint8_t *)name, strlen(name),
                              payload, sizeof(payload), &id), VTY_OK);
    }
    data_end = v->data_root.data_end;
    {
        VtyRepoIter *it = NULL;
        VtyRepoLeaf leaf;
        int done = 0;
        CHECK_EQ(vty_repo_iter_open(v, 0, &it), VTY_OK);
        CHECK_EQ(vty_repo_iter_next(it, &leaf, &done), VTY_OK);
        CHECK_EQ(done, 0);
        rec_off = (size_t)leaf.data_offset;
        id = leaf.record_id;      /* 被破坏的记录（首条） */
        vty_repo_iter_close(it);
    }
    vty_vault_free(v);

    buf = (uint8_t *)vty_alloc(256u * 1024u);
    CHECK(buf != NULL);
    CHECK_EQ(crash_read("crash_rec.vty", buf, 256u * 1024u, &len), 0);
    CHECK(len >= (size_t)data_end);
    CHECK(data_end > VTY_DATA_OFFSET);

    /* 数据区高水位被截断：文件小于提交的 data_end，必须拒绝打开 */
    for (i = 1; i <= 8; i++) {
        size_t at = (size_t)data_end - (size_t)i;
        CHECK_EQ(crash_write("crash_rec_cut.vty", buf, at), 0);
        v = NULL;
        CHECK(vty_vault_open("crash_rec_cut.vty", "crash-rec-pw", &v) != VTY_OK);
        CHECK(v == NULL);
    }

    /* 记录段内任一位翻转：DataRoot/目录仍可打开，但 Get 必须失败 */
    {
        size_t pos = rec_off + VTY_SEG_HEADER_BYTES + 3u;
        CHECK(pos < len);
        buf[pos] ^= 0x01u;
        CHECK_EQ(crash_write("crash_rec_cut.vty", buf, len), 0);
        v = NULL;
        CHECK_EQ(vty_vault_open("crash_rec_cut.vty", "crash-rec-pw", &v),
                 VTY_OK);
        {
            VtyRepoRecord rec;
            memset(&rec, 0, sizeof(rec));
            CHECK(vty_repo_get(v, id, &rec) != VTY_OK);
        }
        vty_vault_free(v);
    }

    vty_free(buf, 256u * 1024u);
    remove("crash_rec.vty");
    remove("crash_rec_cut.vty");
    return 0;
}
