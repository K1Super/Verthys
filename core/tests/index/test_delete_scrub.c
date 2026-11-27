/*
 * test_delete_scrub.c — 删除即密钥销毁验收
 *
 * 覆盖：
 *   - 删除后 RKH 全零，持 MDEK + 原始密文仍无法解封；
 *   - 替换（replace）立即销毁上一版本密钥，历史版本不可恢复；
 *   - 崩溃补偿：跳过即时擦除时保留 PENDING，维护扫描后完成擦除；
 *   - 代际安全删除：派生文件零写删除；
 *   - 维护入口清理压缩/轮换残留。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_module.h"
#include "vty_record.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_secure_delete.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

#define SCRUB_PATH "scrub.vty"

static void id_key(uint8_t out[8], uint64_t id)
{
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(id >> (56 - 8 * i));
}

static int bytes_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != 0u) return 0;
    }
    return 1;
}

static uint64_t first_live_id(VtyVault *v, VtyRepoLeaf *out_leaf)
{
    VtyRepoIter *it = NULL;
    VtyRepoLeaf leaf;
    int done = 0;
    int rc;

    memset(&leaf, 0, sizeof(leaf));
    rc = vty_repo_iter_open(v, 0, &it);
    if (rc != VTY_OK) return 0;
    rc = vty_repo_iter_next(it, &leaf, &done);
    vty_repo_iter_close(it);
    if (rc != VTY_OK || done) return 0;
    *out_leaf = leaf;
    return leaf.record_id;
}

static int read_segment(VtyVault *v, const VtyRepoLeaf *leaf,
                        uint8_t **out, size_t *out_len)
{
    uint8_t *buf;

    if (leaf->data_offset == 0u || leaf->data_len == 0u) return VTY_E_INVALID;
    buf = (uint8_t *)vty_alloc(leaf->data_len);
    if (buf == NULL) return VTY_E_RESOURCE;
    if (vty_store_read_raw(v->store, leaf->data_offset, buf,
                           leaf->data_len) != VTY_OK) {
        vty_free(buf, leaf->data_len);
        return VTY_E_IO;
    }
    *out = buf;
    *out_len = leaf->data_len;
    return VTY_OK;
}

static int try_open_keyed(VtyVault *v, const VtyRepoLeaf *leaf,
                          const uint8_t *seg, size_t seg_len)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *name = NULL, *data = NULL;
    size_t name_len = 0, data_len = 0;
    int rc;

    if (seg_len <= VTY_SEG_HEADER_BYTES) return VTY_E_INVALID;
    rc = vty_vault_module_key(v, leaf->module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = vty_record_open_keyed(mdek, leaf->module_uuid, v->header.epoch,
                               seg + VTY_SEG_HEADER_BYTES,
                               seg_len - VTY_SEG_HEADER_BYTES,
                               &name, &name_len, &data, &data_len);
    vty_secure_zero(mdek, sizeof(mdek));
    if (name != NULL) {
        vty_secure_zero(name, name_len != 0 ? name_len : 1u);
        vty_free(name, name_len != 0 ? name_len : 1u);
    }
    if (data != NULL) {
        vty_secure_zero(data, data_len != 0 ? data_len : 1u);
        vty_free(data, data_len != 0 ? data_len : 1u);
    }
    return rc;
}

static int leaf_status(VtyVault *v, uint64_t id, uint8_t *flags,
                       uint64_t *data_offset)
{
    uint8_t key[8];
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    id_key(key, id);
    rc = vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key), &val, &vlen);
    if (rc != VTY_OK) return rc;
    if (vlen != VTY_REPO_LEAF_BYTES) {
        vty_free(val, vlen);
        return VTY_E_CORRUPT;
    }
    if (flags != NULL) *flags = val[1];
    if (data_offset != NULL) {
        uint64_t off = 0;
        int i;
        for (i = 0; i < 8; i++) off = (off << 8) | val[100 + i];
        *data_offset = off;
    }
    vty_free(val, vlen);
    return VTY_OK;
}

static int try_open_legacy(VtyVault *v, const VtyRepoLeaf *leaf,
                           const uint8_t *seg, size_t seg_len)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t *name = NULL, *data = NULL;
    size_t name_len = 0, data_len = 0;
    int rc;

    if (seg_len <= VTY_SEG_HEADER_BYTES) return VTY_E_INVALID;
    rc = vty_vault_module_key(v, leaf->module_uuid, mdek);
    if (rc != VTY_OK) return rc;
    rc = vty_record_open(mdek, leaf->module_uuid, v->header.epoch,
                         seg + VTY_SEG_HEADER_BYTES,
                         seg_len - VTY_SEG_HEADER_BYTES,
                         &name, &name_len, &data, &data_len);
    vty_secure_zero(mdek, sizeof(mdek));
    if (name != NULL) {
        vty_secure_zero(name, name_len != 0 ? name_len : 1u);
        vty_free(name, name_len != 0 ? name_len : 1u);
    }
    if (data != NULL) {
        vty_secure_zero(data, data_len != 0 ? data_len : 1u);
        vty_free(data, data_len != 0 ? data_len : 1u);
    }
    return rc;
}

static int legacy_ciphertext_broken(const uint8_t *seg, size_t seg_len)
{
    size_t payload;
    size_t head;

    if (seg_len <= VTY_SEG_HEADER_BYTES) return 0;
    payload = seg_len - VTY_SEG_HEADER_BYTES;
    head = payload < 64u ? payload : 64u;
    if (!bytes_all_zero(seg + VTY_SEG_HEADER_BYTES, head)) return 0;
    if (!bytes_all_zero(seg + VTY_SEG_HEADER_BYTES + payload - head, head)) {
        return 0;
    }
    return 1;
}

TEST(delete_zeroes_key_header_and_blocks_decrypt)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoLeaf leaf;
    uint8_t *seg = NULL;
    size_t seg_len = 0;
    uint64_t id = 0;
    uint8_t flags = 0;
    uint64_t off = 0;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"alpha", 5u,
                          (const uint8_t *)"one", 3u, &id), VTY_OK);
    CHECK_EQ(first_live_id(v, &leaf), id);
    CHECK_EQ((leaf.flags & VTY_REPO_FLAG_KEYED) != 0u, 1);

    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(try_open_keyed(v, &leaf, seg, seg_len), VTY_OK);
    vty_free(seg, seg_len);

    CHECK_EQ(vty_repo_delete(v, id), VTY_OK);
    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(bytes_all_zero(seg + VTY_SEG_HEADER_BYTES,
                            VTY_RECORD_KEY_HEADER_BYTES), 1);
    CHECK_EQ(try_open_keyed(v, &leaf, seg, seg_len),
             VTY_E_INVALID);
    vty_free(seg, seg_len);

    CHECK_EQ(leaf_status(v, id, &flags, &off), VTY_OK);
    CHECK_EQ((flags & VTY_REPO_FLAG_TOMBSTONE) != 0u, 1);
    CHECK_EQ((flags & VTY_REPO_FLAG_SCRUB_PENDING) != 0u, 0);
    CHECK_EQ(off, 0u);

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

TEST(replace_scrubs_previous_version)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoLeaf leaf;
    uint8_t *seg = NULL;
    size_t seg_len = 0;
    uint64_t id1 = 0, id2 = 0;
    uint8_t flags = 0;
    uint64_t off = 0;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"v1", 2u,
                          (const uint8_t *)"old", 3u, &id1), VTY_OK);
    CHECK_EQ(first_live_id(v, &leaf), id1);

    CHECK_EQ(vty_repo_replace(v, id1, 7u, (const uint8_t *)"v2", 2u,
                              (const uint8_t *)"new", 3u, &id2), VTY_OK);
    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(bytes_all_zero(seg + VTY_SEG_HEADER_BYTES,
                            VTY_RECORD_KEY_HEADER_BYTES), 1);
    CHECK_EQ(try_open_keyed(v, &leaf, seg, seg_len), VTY_E_INVALID);
    vty_free(seg, seg_len);

    CHECK_EQ(leaf_status(v, id1, &flags, &off), VTY_OK);
    CHECK_EQ((flags & VTY_REPO_FLAG_TOMBSTONE) != 0u, 1);
    CHECK_EQ(off, 0u);

    CHECK_EQ(first_live_id(v, &leaf), id2);
    CHECK_EQ(vty_repo_delete(v, id2), VTY_OK);
    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(bytes_all_zero(seg + VTY_SEG_HEADER_BYTES,
                            VTY_RECORD_KEY_HEADER_BYTES), 1);
    vty_free(seg, seg_len);

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

TEST(pending_scrub_is_compensated_on_maintain)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoLeaf leaf;
    uint8_t *seg = NULL;
    size_t seg_len = 0;
    uint64_t id = 0;
    uint64_t scrubbed = 0;
    uint64_t pending = 0;
    uint8_t flags = 0;
    uint64_t off = 0;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"p", 1u,
                          (const uint8_t *)"x", 1u, &id), VTY_OK);
    CHECK_EQ(first_live_id(v, &leaf), id);

    vty_repo_set_skip_scrub_for_test(1);
    CHECK_EQ(vty_repo_delete(v, id), VTY_OK);
    vty_repo_set_skip_scrub_for_test(0);

    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(bytes_all_zero(seg + VTY_SEG_HEADER_BYTES,
                            VTY_RECORD_KEY_HEADER_BYTES), 0);
    CHECK_EQ(try_open_keyed(v, &leaf, seg, seg_len), VTY_OK);
    vty_free(seg, seg_len);

    CHECK_EQ(leaf_status(v, id, &flags, &off), VTY_OK);
    CHECK_EQ((flags & VTY_REPO_FLAG_SCRUB_PENDING) != 0u, 1);

    CHECK_EQ(vty_repo_maintain_pending_scrub(v, 4096u, &scrubbed, &pending),
             VTY_OK);
    CHECK_EQ(scrubbed, 1u);
    CHECK_EQ(pending, 0u);

    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(bytes_all_zero(seg + VTY_SEG_HEADER_BYTES,
                            VTY_RECORD_KEY_HEADER_BYTES), 1);
    vty_free(seg, seg_len);
    CHECK_EQ(leaf_status(v, id, &flags, &off), VTY_OK);
    CHECK_EQ((flags & VTY_REPO_FLAG_SCRUB_PENDING) != 0u, 0);
    CHECK_EQ(off, 0u);

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

TEST(legacy_record_delete_breaks_ciphertext)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoLeaf leaf;
    uint8_t *seg = NULL;
    size_t seg_len = 0;
    uint64_t id = 0;
    uint8_t key[8];
    uint8_t *val = NULL;
    size_t vlen = 0;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"legacy", 6u,
                          (const uint8_t *)"payload", 7u, &id), VTY_OK);
    CHECK_EQ(first_live_id(v, &leaf), id);

    /* 模拟旧格式叶：清 KEYED 标志，删除路径必须整段零写。 */
    id_key(key, id);
    CHECK_EQ(vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key),
                           &val, &vlen), VTY_OK);
    CHECK_EQ(vlen, (size_t)VTY_REPO_LEAF_BYTES);
    val[1] = (uint8_t)(val[1] & (uint8_t)~VTY_REPO_FLAG_KEYED);
    CHECK_EQ(vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                           val, vlen), VTY_OK);
    vty_free(val, vlen);
    CHECK_EQ(vty_vault_commit_store(v), VTY_OK);
    CHECK_EQ(vty_vault_save_meta(v), VTY_OK);

    CHECK_EQ(vty_repo_delete(v, id), VTY_OK);
    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(legacy_ciphertext_broken(seg, seg_len), 1);
    CHECK(try_open_legacy(v, &leaf, seg, seg_len) != VTY_OK);
    vty_free(seg, seg_len);

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

TEST(bulk_delete_scrubs_all_key_headers)
{
    enum { N = 64 };
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoLeaf leaves[N];
    uint64_t ids[N];
    VtyRepoIter *it = NULL;
    size_t i;
    int done = 0;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    for (i = 0; i < N; i++) {
        CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"bulk", 4u,
                              (const uint8_t *)"x", 1u, &ids[i]), VTY_OK);
    }
    CHECK_EQ(vty_repo_iter_open(v, 0, &it), VTY_OK);
    i = 0;
    while (i < N) {
        CHECK_EQ(vty_repo_iter_next(it, &leaves[i], &done), VTY_OK);
        CHECK_EQ(done, 0);
        i++;
    }
    vty_repo_iter_close(it);

    CHECK_EQ(vty_repo_delete_many(v, ids, N), VTY_OK);
    for (i = 0; i < N; i++) {
        uint8_t *seg = NULL;
        size_t seg_len = 0;
        CHECK_EQ(read_segment(v, &leaves[i], &seg, &seg_len), VTY_OK);
        CHECK_EQ(bytes_all_zero(seg + VTY_SEG_HEADER_BYTES,
                                VTY_RECORD_KEY_HEADER_BYTES), 1);
        vty_free(seg, seg_len);
    }

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

TEST(maintenance_scrubs_legacy_tombstone)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VtyRepoLeaf leaf;
    uint8_t *seg = NULL;
    size_t seg_len = 0;
    uint64_t id = 0;
    uint64_t scrubbed = 0;
    uint64_t pending = 0;
    uint8_t key[8];
    uint8_t *val = NULL;
    size_t vlen = 0;
    uint8_t flags = 0;
    uint64_t off = 1;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"old", 3u,
                          (const uint8_t *)"secret", 6u, &id), VTY_OK);
    CHECK_EQ(first_live_id(v, &leaf), id);

    /* 新库创建事务已写入迁移完成标记；删除标记以模拟升级前旧库，
     * 否则遗留墓碑扫描会被正确地跳过。 */
    CHECK_EQ(vty_store_delete(v->store, VTY_KS_MAINT,
                              (const uint8_t *)"legacy-scrub-v1",
                              sizeof("legacy-scrub-v1") - 1u), VTY_OK);
    /* 构造升级前的遗留墓碑：无 KEYED、无 PENDING，但保留定位符。 */
    id_key(key, id);
    CHECK_EQ(vty_store_get(v->store, VTY_KS_RECORD, key, sizeof(key),
                           &val, &vlen), VTY_OK);
    val[1] = VTY_REPO_FLAG_TOMBSTONE;
    CHECK_EQ(vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                           val, vlen), VTY_OK);
    vty_free(val, vlen);
    CHECK_EQ(vty_vault_commit_store(v), VTY_OK);
    CHECK_EQ(vty_vault_save_meta(v), VTY_OK);

    CHECK_EQ(vty_repo_maintain_pending_scrub(v, 4096u, &scrubbed, &pending),
             VTY_OK);
    CHECK_EQ(scrubbed, 1u);
    CHECK_EQ(pending, 0u);
    CHECK_EQ(read_segment(v, &leaf, &seg, &seg_len), VTY_OK);
    CHECK_EQ(legacy_ciphertext_broken(seg, seg_len), 1);
    CHECK(try_open_legacy(v, &leaf, seg, seg_len) != VTY_OK);
    vty_free(seg, seg_len);
    CHECK_EQ(leaf_status(v, id, &flags, &off), VTY_OK);
    CHECK_EQ((flags & VTY_REPO_FLAG_SCRUB_PENDING) != 0u, 0);
    CHECK_EQ(off, 0u);

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

/* 待擦队列前部堆积大量已出队墓碑时，维护必须跳过墓碑并继续处理后面
 * 的待擦项；否则累计删除超过单次预算后补偿擦除永久失效。 */
TEST(scrub_queue_skips_tombstones_and_reaches_pending)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t id = 0;
    uint64_t scrubbed = 0;
    uint64_t pending = 0;
    uint8_t flags = 0;
    uint64_t off = 1;
    uint64_t i;

    remove(SCRUB_PATH);
    CHECK_EQ(vty_vault_create(SCRUB_PATH, "scrub-pw", &v, code, sizeof(code)),
             VTY_OK);
    /* 把目标记录 ID 推到所有墓碑键之后，复现“前 4096 个键全是墓碑”。 */
    CHECK_EQ(vty_repo_set_next_id(v, 4200u), VTY_OK);
    CHECK_EQ(vty_repo_add(v, 7u, (const uint8_t *)"late", 4u,
                          (const uint8_t *)"secret", 6u, &id), VTY_OK);
    CHECK_EQ(id, 4200u);

    for (i = 1u; i <= 4096u; i++) {
        uint8_t k[8];

        id_key(k, i);
        CHECK_EQ(vty_store_delete(v->store, VTY_KS_SCRUB, k, sizeof(k)),
                 VTY_OK);
    }
    CHECK_EQ(vty_vault_commit_store(v), VTY_OK);
    CHECK_EQ(vty_vault_save_meta(v), VTY_OK);

    vty_repo_set_skip_scrub_for_test(1);
    CHECK_EQ(vty_repo_delete(v, id), VTY_OK);
    vty_repo_set_skip_scrub_for_test(0);

    CHECK_EQ(vty_repo_maintain_pending_scrub(v, 4096u, &scrubbed, &pending),
             VTY_OK);
    CHECK_EQ(scrubbed, 1u);
    CHECK_EQ(pending, 0u);
    /* 擦除完成后墓碑定位符必须清空；段区间随提交回收，不能再按旧偏移
     * 读取（读得到反而说明空间没有参与回收）。 */
    CHECK_EQ(leaf_status(v, id, &flags, &off), VTY_OK);
    CHECK_EQ(off, 0u);
    CHECK_EQ((flags & VTY_REPO_FLAG_SCRUB_PENDING) != 0u, 0);

    /* 第二次维护不得重复擦除，也不得卡在同一批墓碑上。 */
    CHECK_EQ(vty_repo_maintain_pending_scrub(v, 4096u, &scrubbed, &pending),
             VTY_OK);
    CHECK_EQ(scrubbed, 0u);

    vty_vault_free(v);
    remove(SCRUB_PATH);
    return 0;
}

TEST(secure_delete_file_and_maintain)
{
    const char *tmp = "scrub_derive.bin";
    const char *bak = "scrub.vty.vtycompact.bak";
    FILE *f;

    remove(tmp);
    f = fopen(tmp, "wb");
    CHECK(f != NULL);
    if (f != NULL) {
        uint8_t buf[4096];
        memset(buf, 0x5A, sizeof(buf));
        CHECK_EQ(fwrite(buf, 1, sizeof(buf), f), sizeof(buf));
        fclose(f);
    }
    CHECK_EQ(vty_secure_delete_file(tmp), VTY_OK);
    CHECK(fopen(tmp, "rb") == NULL);
    CHECK_EQ(vty_secure_delete_file(tmp), VTY_OK);

    remove(bak);
    f = fopen(bak, "wb");
    CHECK(f != NULL);
    if (f != NULL) {
        CHECK_EQ(fwrite("leak", 1, 4, f), 4u);
        fclose(f);
    }
    {
        uint64_t deleted = 0;
        uint64_t failed = 0;
        CHECK_EQ(vty_secure_delete_maintain("scrub.vty", &deleted, &failed),
                 VTY_OK);
        CHECK_EQ(deleted, 1u);
        CHECK_EQ(failed, 0u);
    }
    CHECK(fopen(bak, "rb") == NULL);
    return 0;
}
