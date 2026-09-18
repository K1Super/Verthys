/*
 * gen_seeds.c — WP-10 模糊测试语料种子生成器
 *
 * 设计依据：docs/V3_UPGRADE_PLAYBOOK.md WP-10（"语料种子用测试生成的
 * 合法容器"）+ R-8（种子须为合法明文帧——libFuzzer 从合法基线出发
 * 才能有效探索解析器的深路径）。
 *
 * 产物（<root>/<target>/<target>_NNN.bin）：
 *   superblock/  合法 SuperBlockV3 FlatBuffer 明文（满字段 + 空扩展两档）
 *   partition/   合法 PartitionTableV3（4 分区满配 + 空表两档）
 *   extent/      合法 ExtentIndexV3（含一致性约束内条目 + 空索引两档）
 *   sstable/     合法 LSMManifestV3（多表 + 空表）与合法条目编码序列
 *   import/      vfmt_write 全链路合法 v1 交换信封
 *
 * 实现纪律：builder 调用逐行镜像生产序列化路径（verthys_superblock_v3.c /
 * verthys_partition.c / verthys_extent.c / verthys_lsm.c），仅以固定值替换
 * CNG 计数器——种子字段结构漂移在编译期被 schema 生成头拦截。
 *
 * 用法：gen_seeds <corpus_root>（退出码非 0 = 生成失败，CI 门）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>              /* _mkdir */

#include "superblock_v3_builder.h"
#include "partition_builder.h"
#include "extent_builder.h"
#include "sstable_builder.h"

#include "verthys.h"
#include "verthys_container_v3.h"
#include "verthys_partition.h"
#include "verthys_extent.h"
#include "verthys_lsm.h"
#include "verthys_lsm_internal.h"
#include "verthys_format.h"
#include "verthys_crypto.h"

/* ---------- 通用：种子落盘 ---------- */

static int write_seed(const char *root, const char *target,
                      const char *name, const uint8_t *buf, size_t len)
{
    char path[512];
    FILE *f;

    if (snprintf(path, sizeof(path), "%s\\%s", root, target) < 0) return -1;
    /* mkdir 不判存在（幂等；已存在时返回 -1 属预期） */
    _mkdir(path);
    if (snprintf(path, sizeof(path), "%s\\%s\\%s_%s.bin", root, target,
                 target, name) < 0) return -1;
    f = fopen(path, "wb");
    if (f == NULL) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    printf("[seed] %s (%zu bytes)\n", path, len);
    return 0;
}

static int write_seed_alloc(const char *root, const char *target,
                            const char *name, const uint8_t *buf, size_t len)
{
    int rc = write_seed(root, target, name, buf, len);
    return rc;
}

/* ---------- superblock ---------- */

static int gen_superblock(const char *root)
{
    flatcc_builder_t b;
    uint8_t *buf = NULL;
    size_t len = 0;
    int ok = 0;
    uint8_t cid[VERTHYS_V3_CONTAINER_ID_BYTES];
    uint8_t chain[VERTHYS_V3_STATE_CHAIN_BYTES];
    uint8_t salt[VERTHYS_V3_SALT_BYTES];
    uint8_t wrapped[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t keyid[VERTHYS_V3_KEY_ID_BYTES];
    uint8_t merkle[VERTHYS_V3_MERKLE_ROOT_BYTES];
    uint32_t bench[VERTHYS_V3_BENCHMARK_ITEMS] = {120, 95, 210, 150};
    uint8_t ext[8] = {0x01, 0x02, 'V', '3', 0x00, 0x00, 0x00, 0x00};

    /* 固定非秘密模式（种子仅结构合法性，无密钥语义） */
    for (size_t i = 0; i < sizeof(cid); i++)     cid[i]    = (uint8_t)(i * 3 + 1);
    for (size_t i = 0; i < sizeof(chain); i++)   chain[i]  = (uint8_t)(i * 5 + 2);
    for (size_t i = 0; i < sizeof(salt); i++)    salt[i]   = (uint8_t)(i * 7 + 3);
    for (size_t i = 0; i < sizeof(wrapped); i++) wrapped[i] = (uint8_t)(i * 11 + 4);
    for (size_t i = 0; i < sizeof(keyid); i++)   keyid[i]  = (uint8_t)(i * 13 + 5);
    for (size_t i = 0; i < sizeof(merkle); i++)  merkle[i] = (uint8_t)(i * 17 + 6);

    for (int variant = 0; variant < 2; variant++) {
        if (flatcc_builder_init(&b) != 0) return -1;
        do {
            flatbuffers_uint8_vec_ref_t r_cid, r_chain, r_salt,
                r_wa, r_wb, r_wc, r_ka, r_kb, r_kc, r_merkle, r_ext;

            if (SuperBlockV3_start_as_root(&b) != 0) break;
            if (SuperBlockV3_magic_add(&b, VERTHYS_V3_SB_MAGIC) != 0) break;
            if (SuperBlockV3_version_add(&b, VERTHYS_V3_VERSION) != 0) break;
            if (SuperBlockV3_created_at_add(&b, UINT64_C(0x01D9000000000000)) != 0) break;
            if (SuperBlockV3_updated_at_add(&b, UINT64_C(0x01D9000000000100)) != 0) break;
            if (SuperBlockV3_txid_add(&b, 7) != 0) break;
            if (SuperBlockV3_argon2_mem_kib_add(&b, 65536) != 0) break;
            if (SuperBlockV3_argon2_iters_add(&b, 3) != 0) break;
            if (SuperBlockV3_argon2_parallel_add(&b, 4) != 0) break;
            if (SuperBlockV3_argon2_tier_add(&b, 1) != 0) break;
            if (SuperBlockV3_pepper_source_add(&b, 1) != 0) break;
            if (SuperBlockV3_partition_table_offset_add(&b, 0xC000) != 0) break;
            if (SuperBlockV3_partition_table_size_add(&b, 0x100000) != 0) break;
            if (SuperBlockV3_index_partition_offset_add(&b, 0x10C000) != 0) break;
            if (SuperBlockV3_index_partition_size_add(&b, 0x5000000) != 0) break;
            if (SuperBlockV3_extent_partition_offset_add(&b, 0x510C000) != 0) break;
            if (SuperBlockV3_extent_partition_size_add(&b, 0x10000000) != 0) break;
            if (SuperBlockV3_audit_partition_offset_add(&b, 0x1510C000) != 0) break;
            if (SuperBlockV3_audit_partition_size_add(&b, 0x800000) != 0) break;
            if (SuperBlockV3_wal_head_offset_add(&b, 0) != 0) break;
            if (SuperBlockV3_wal_tail_offset_add(&b, 0) != 0) break;
            if (SuperBlockV3_wal_committed_txid_add(&b, 6) != 0) break;

            r_cid = flatbuffers_uint8_vec_create(&b, cid, sizeof(cid));
            r_chain = flatbuffers_uint8_vec_create(&b, chain, sizeof(chain));
            r_salt = flatbuffers_uint8_vec_create(&b, salt, sizeof(salt));
            r_wa = flatbuffers_uint8_vec_create(&b, wrapped, sizeof(wrapped));
            r_wb = flatbuffers_uint8_vec_create(&b, wrapped, sizeof(wrapped));
            r_wc = flatbuffers_uint8_vec_create(&b, wrapped, sizeof(wrapped));
            r_ka = flatbuffers_uint8_vec_create(&b, keyid, sizeof(keyid));
            r_kb = flatbuffers_uint8_vec_create(&b, keyid, sizeof(keyid));
            r_kc = flatbuffers_uint8_vec_create(&b, keyid, sizeof(keyid));
            r_merkle = flatbuffers_uint8_vec_create(&b, merkle, sizeof(merkle));
            if (!r_cid || !r_chain || !r_salt || !r_wa || !r_wb || !r_wc ||
                !r_ka || !r_kb || !r_kc || !r_merkle) break;
            if (SuperBlockV3_container_id_add(&b, r_cid) != 0) break;
            if (SuperBlockV3_state_chain_add(&b, r_chain) != 0) break;
            if (SuperBlockV3_salt_add(&b, r_salt) != 0) break;
            if (SuperBlockV3_wrapped_key_a_add(&b, r_wa) != 0) break;
            if (SuperBlockV3_wrapped_key_b_add(&b, r_wb) != 0) break;
            if (SuperBlockV3_wrapped_key_c_add(&b, r_wc) != 0) break;
            if (SuperBlockV3_key_a_id_add(&b, r_ka) != 0) break;
            if (SuperBlockV3_key_b_id_add(&b, r_kb) != 0) break;
            if (SuperBlockV3_key_c_id_add(&b, r_kc) != 0) break;
            if (SuperBlockV3_merkle_root_add(&b, r_merkle) != 0) break;
            /* 向量字段 _create 助手返回 int（0=成功/-1=失败），
             * 区别于返回 ref 的 vec_create（0=失败）——此处判失败须 != 0 */
            if (SuperBlockV3_argon2_benchmark_ms_create(
                    &b, bench, VERTHYS_V3_BENCHMARK_ITEMS) != 0) break;
            if (SuperBlockV3_superblock_hmac_add(&b,
                    flatbuffers_uint8_vec_create(&b, merkle, 32)) != 0) break;

            /* variant 1 带 TLV 扩展；variant 0 空（两者均须通过解析） */
            if (variant == 1) {
                r_ext = flatbuffers_uint8_vec_create(&b, ext, sizeof(ext));
                if (r_ext == 0 || SuperBlockV3_extensions_add(&b, r_ext) != 0) break;
            }

            if (SuperBlockV3_end_as_root(&b) == 0) break;
            buf = flatcc_builder_finalize_aligned_buffer(&b, &len);
            if (buf == NULL || len == 0) break;
            ok = 1;
        } while (0);
        flatcc_builder_clear(&b);
        if (!ok) { if (buf) flatcc_builder_aligned_free(buf); return -1; }
        if (write_seed_alloc(root, "superblock",
                             variant == 0 ? "full" : "ext", buf, len) != 0) {
            flatcc_builder_aligned_free(buf);
            return -1;
        }
        flatcc_builder_aligned_free(buf);
        buf = NULL;
    }
    return 0;
}

/* ---------- partition ---------- */

static int gen_partition(const char *root)
{
    flatcc_builder_t b;
    uint8_t *buf = NULL;
    size_t len = 0;
    int ok = 0;
    uint8_t keyid[VERTHYS_PARTITION_KEY_ID_BYTES];
    uint8_t wrapped[VERTHYS_PARTITION_WRAPPED_BYTES];
    uint8_t wrapnonce[VERTHYS_PARTITION_NONCE_BYTES];

    for (size_t i = 0; i < sizeof(keyid); i++)     keyid[i] = (uint8_t)(i + 0x40);
    for (size_t i = 0; i < sizeof(wrapped); i++)   wrapped[i] = (uint8_t)(i + 0x60);
    for (size_t i = 0; i < sizeof(wrapnonce); i++) wrapnonce[i] = (uint8_t)(i + 0x80);

    for (int variant = 0; variant < 2; variant++) {
        if (flatcc_builder_init(&b) != 0) return -1;
        do {
            if (PartitionTableV3_start_as_root(&b) != 0) break;
            if (PartitionTableV3_magic_add(&b, VERTHYS_PARTITION_TABLE_MAGIC) != 0) break;
            if (PartitionTableV3_version_add(&b, VERTHYS_PARTITION_TABLE_VERSION) != 0) break;
            if (PartitionTableV3_txid_add(&b, 9) != 0) break;

            if (variant == 1) {
                /* 4 分区满配（镜像生产 vsb 创建布局） */
                static const struct {
                    uint32_t id; uint8_t type;
                    uint64_t offset, size, used;
                } parts[4] = {
                    {1, 0, 0x10C000,  0x5000000, 0x1000},   /* INDEX */
                    {2, 1, 0x510C000, 0x10000000, 0x8000},  /* EXTENT */
                    {3, 2, 0x1510C000, 0x800000,  0x100},   /* AUDIT */
                    {4, 3, 0x1590C000, 0x100000,  0x0},     /* WAL */
                };
                int vec_ok = 1;
                if (PartitionEntryV3_vec_start(&b) != 0) break;
                for (int i = 0; i < 4; i++) {
                    flatbuffers_uint8_vec_ref_t rk, rw, rn;
                    PartitionEntryV3_ref_t e;
                    rk = flatbuffers_uint8_vec_create(&b, keyid, sizeof(keyid));
                    rw = flatbuffers_uint8_vec_create(&b, wrapped, sizeof(wrapped));
                    rn = flatbuffers_uint8_vec_create(&b, wrapnonce, sizeof(wrapnonce));
                    if (!rk || !rw || !rn) { vec_ok = 0; break; }
                    e = PartitionEntryV3_create(&b,
                        parts[i].id, (PartitionTypeV3_enum_t)parts[i].type,
                        parts[i].offset, parts[i].size, parts[i].used,
                        rk, 42 /* nonce_counter 固定值 */, 5,
                        rw, rn);
                    if (e == 0 || PartitionEntryV3_vec_push(&b, e) == NULL) {
                        vec_ok = 0;
                        break;
                    }
                }
                if (!vec_ok) break;
                {
                    PartitionEntryV3_vec_ref_t vec = PartitionEntryV3_vec_end(&b);
                    if (vec == 0 || PartitionTableV3_entries_add(&b, vec) != 0) break;
                }
            } /* variant 0：空表（entries 缺省 = NULL → count 0 合法） */

            if (PartitionTableV3_end_as_root(&b) == 0) break;
            buf = flatcc_builder_finalize_aligned_buffer(&b, &len);
            if (buf == NULL || len == 0) break;
            ok = 1;
        } while (0);
        flatcc_builder_clear(&b);
        if (!ok) { if (buf) flatcc_builder_aligned_free(buf); return -1; }
        if (write_seed_alloc(root, "partition",
                             variant == 0 ? "empty" : "four", buf, len) != 0) {
            flatcc_builder_aligned_free(buf);
            return -1;
        }
        flatcc_builder_aligned_free(buf);
        buf = NULL;
    }
    return 0;
}

/* ---------- extent ---------- */

static int gen_extent(const char *root)
{
    flatcc_builder_t b;
    uint8_t *buf = NULL;
    size_t len = 0;
    int ok = 0;
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t nonce[VERTHYS_EXTENT_NONCE_BYTES];

    for (size_t i = 0; i < sizeof(hash); i++)  hash[i] = (uint8_t)(i * 3 + 7);
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(i * 9 + 11);

    for (int variant = 0; variant < 2; variant++) {
        if (flatcc_builder_init(&b) != 0) return -1;
        do {
            if (ExtentIndexV3_start_as_root(&b) != 0) break;
            if (ExtentIndexV3_magic_add(&b, VERTHYS_EXTENT_INDEX_MAGIC) != 0) break;
            if (ExtentIndexV3_version_add(&b, VERTHYS_EXTENT_INDEX_VERSION) != 0) break;
            if (ExtentIndexV3_txid_add(&b, 11) != 0) break;
            if (ExtentIndexV3_next_offset_add(&b, 0x10000) != 0) break;
            if (ExtentIndexV3_nonce_counter_add(&b, 77) != 0) break;

            if (variant == 1) {
                /* 2 条目（一致性约束内：size ≥ 16、pt = size - 16、
                 * offset + size ≤ next_offset） */
                static const struct {
                    uint64_t offset; uint32_t size;
                } ents[2] = {
                    {0, 4112},        /* 4096 明文 + 16 tag */
                    {4112, 16 + 64},  /* 64 明文 + 16 tag */
                };
                int vec_ok = 1;
                if (ExtentEntryV3_vec_start(&b) != 0) break;
                for (int i = 0; i < 2; i++) {
                    flatbuffers_uint8_vec_ref_t rh, rn;
                    ExtentEntryV3_ref_t e;
                    rh = flatbuffers_uint8_vec_create(&b, hash, sizeof(hash));
                    rn = flatbuffers_uint8_vec_create(&b, nonce, sizeof(nonce));
                    if (!rh || !rn) { vec_ok = 0; break; }
                    e = ExtentEntryV3_create(&b, rh, rn,
                        ents[i].offset, ents[i].size,
                        ents[i].size - VERTHYS_EXTENT_TAG_BYTES, /* pt 自洽 */
                        2 /* ref_count */, 10, 10);
                    if (e == 0 || ExtentEntryV3_vec_push(&b, e) == NULL) {
                        vec_ok = 0;
                        break;
                    }
                }
                if (!vec_ok) break;
                {
                    ExtentEntryV3_vec_ref_t vec = ExtentEntryV3_vec_end(&b);
                    if (vec == 0 || ExtentIndexV3_entries_add(&b, vec) != 0) break;
                }
            }

            if (ExtentIndexV3_end_as_root(&b) == 0) break;
            buf = flatcc_builder_finalize_aligned_buffer(&b, &len);
            if (buf == NULL || len == 0) break;
            ok = 1;
        } while (0);
        flatcc_builder_clear(&b);
        if (!ok) { if (buf) flatcc_builder_aligned_free(buf); return -1; }
        if (write_seed_alloc(root, "extent",
                             variant == 0 ? "empty" : "two", buf, len) != 0) {
            flatcc_builder_aligned_free(buf);
            return -1;
        }
        flatcc_builder_aligned_free(buf);
        buf = NULL;
    }
    return 0;
}

/* ---------- sstable（Manifest + 条目编码序列） ---------- */

static int gen_sstable(const char *root)
{
    flatcc_builder_t b;
    uint8_t *buf = NULL;
    size_t len = 0;
    int ok;

    /* Manifest 两档：空 / 双表（L0 新表 + L1 旧表） */
    for (int variant = 0; variant < 2; variant++) {
        ok = 0;
        if (flatcc_builder_init(&b) != 0) return -1;
        do {
            if (LSMManifestV3_start_as_root(&b) != 0) break;
            if (LSMManifestV3_magic_add(&b, VERTHYS_LSM_MANIFEST_MAGIC) != 0) break;
            if (LSMManifestV3_version_add(&b, VERTHYS_LSM_VERSION) != 0) break;
            if (LSMManifestV3_txid_add(&b, 13) != 0) break;
            if (LSMManifestV3_next_seq_add(&b, 3) != 0) break;
            if (LSMManifestV3_next_data_offset_add(&b, 0x20000) != 0) break;
            if (LSMManifestV3_nonce_counter_add(&b, 99) != 0) break;

            if (variant == 1) {
                static const struct {
                    uint64_t seq; uint8_t level; uint64_t offset;
                    uint32_t size; uint32_t entries; uint32_t tombs;
                    uint64_t min_key, max_key; uint64_t created_txid;
                } tabs[2] = {
                    {2, 0, 0x10000, 0x8000, 500, 5,  1, 500, 12},
                    {1, 1, 0x18000, 0x4000, 900, 0,  1, 900, 8},
                };
                int vec_ok = 1;
                if (LSMTableMetaV3_vec_start(&b) != 0) break;
                for (int i = 0; i < 2; i++) {
                    LSMTableMetaV3_ref_t ref;
                    if (LSMTableMetaV3_start(&b) != 0) { vec_ok = 0; break; }
                    if (LSMTableMetaV3_seq_add(&b, tabs[i].seq) != 0 ||
                        LSMTableMetaV3_level_add(&b, tabs[i].level) != 0 ||
                        LSMTableMetaV3_offset_add(&b, tabs[i].offset) != 0 ||
                        LSMTableMetaV3_size_add(&b, tabs[i].size) != 0 ||
                        LSMTableMetaV3_entry_count_add(&b, tabs[i].entries) != 0 ||
                        LSMTableMetaV3_tombstone_count_add(&b, tabs[i].tombs) != 0 ||
                        LSMTableMetaV3_min_key_add(&b, tabs[i].min_key) != 0 ||
                        LSMTableMetaV3_max_key_add(&b, tabs[i].max_key) != 0 ||
                        LSMTableMetaV3_created_txid_add(&b, tabs[i].created_txid) != 0) {
                        vec_ok = 0;
                        break;
                    }
                    ref = LSMTableMetaV3_end(&b);
                    if (ref == 0 || LSMTableMetaV3_vec_push(&b, ref) == NULL) {
                        vec_ok = 0;
                        break;
                    }
                }
                if (!vec_ok) break;
                {
                    LSMTableMetaV3_vec_ref_t vec = LSMTableMetaV3_vec_end(&b);
                    if (vec == 0 || LSMManifestV3_tables_add(&b, vec) != 0) break;
                }
            }

            if (LSMManifestV3_end_as_root(&b) == 0) break;
            buf = flatcc_builder_finalize_aligned_buffer(&b, &len);
            if (buf == NULL || len == 0) break;
            ok = 1;
        } while (0);
        flatcc_builder_clear(&b);
        if (!ok) { if (buf) flatcc_builder_aligned_free(buf); return -1; }
        if (write_seed_alloc(root, "sstable",
                             variant == 0 ? "manifest_empty" : "manifest_two",
                             buf, len) != 0) {
            flatcc_builder_aligned_free(buf);
            return -1;
        }
        flatcc_builder_aligned_free(buf);
        buf = NULL;
    }

    /* 数据块明文：合法条目编码序列（verthys_lsm_entry_encode 生产编解码器） */
    {
        uint8_t block[4096];
        size_t off = 0;
        static const char *names[3] = {"acct-001", "note-αβγ", ""};
        for (int i = 0; i < 3; i++) {
            VerthysLsmEntry e;
            size_t need;
            memset(&e, 0, sizeof(e));
            e.lid = (uint64_t)(i + 1);
            e.type = 1;
            e.tombstone = (uint8_t)(i == 2);
            e.slot_state = 0;
            e.name_len = (uint16_t)strlen(names[i]);
            e.name = (const uint8_t *)names[i];
            e.data_size = 32 + (uint64_t)i;
            e.plaintext_size = 32 + (uint32_t)i;
            e.extent_size = 48 + (uint32_t)i;
            for (size_t k = 0; k < 32; k++) e.hash[k] = (uint8_t)(k + i);
            e.created_txid = 13;
            e.created_time = 0x01D9000000000000ULL + (uint64_t)i;

            need = verthys_lsm_entry_encoded_len(&e);
            if (need == 0 || off + need > sizeof(block)) return -1;
            if (verthys_lsm_entry_encode(block + off, sizeof(block) - off, &e) != 0) {
                return -1;
            }
            off += need;
        }
        if (write_seed(root, "sstable", "entries3", block, off) != 0) return -1;
    }
    return 0;
}

/* ---------- import（v1 交换信封，vfmt_write 全链路） ---------- */

static int gen_import(const char *root)
{
    static const uint8_t salt[16] = {
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
        0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0
    };
    static const uint8_t mek[32] = {
        0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0
    };
    static const uint8_t dek[32] = {
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
        0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
        0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0
    };
    VerthysFmtRecord rec = {0x01, 8, (uint8_t *)"seedname",
                          8, (uint8_t *)"seeddata"};
    uint8_t *blob = NULL;
    size_t size = 0;

    if (verthys_crypto_init() != 0) return -1;
    if (vfmt_write(salt, VERTHYS_ARGON2_MEM_KIB, VERTHYS_ARGON2_ITERS,
                   VERTHYS_ARGON2_PARALLEL, mek, dek,
                   &rec, 1, &blob, &size) != 0) {
        return -1;
    }
    if (write_seed_alloc(root, "import", "one", blob, size) != 0) {
        free(blob);
        return -1;
    }
    /* 头部前缀种子（仅 header 32B + 少量尾随密文——引导探索
     * meta_offset/mac_offset 边界分支） */
    if (size > 64) {
        if (write_seed(root, "import", "head", blob, 64) != 0) {
            free(blob);
            return -1;
        }
    }
    free(blob);
    return 0;
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *root = (argc > 1) ? argv[1] : "corpus";

    if (gen_superblock(root) != 0) {
        fprintf(stderr, "[gen_seeds] superblock 种子生成失败\n");
        return 1;
    }
    if (gen_partition(root) != 0) {
        fprintf(stderr, "[gen_seeds] partition 种子生成失败\n");
        return 1;
    }
    if (gen_extent(root) != 0) {
        fprintf(stderr, "[gen_seeds] extent 种子生成失败\n");
        return 1;
    }
    if (gen_sstable(root) != 0) {
        fprintf(stderr, "[gen_seeds] sstable 种子生成失败\n");
        return 1;
    }
    if (gen_import(root) != 0) {
        fprintf(stderr, "[gen_seeds] import 种子生成失败\n");
        return 1;
    }
    printf("[gen_seeds] 全部语料种子生成完成: %s\n", root);
    return 0;
}
