/*
 * verthys_lsm_sstable.c — LSM SSTable：写入/查找/迭代 + Bloom Filter
 *
 * 设计依据：docs/TARGET_ARCHITECTURE_V5.md §6.6
 * 落地依据：docs/V3_UPGRADE_PLAYBOOK.md WP-4
 *
 * 磁盘布局（schema/sstable.fbs；容器文件内一段连续 append-only 区域）：
 *   [Data Block 0..N-1][Index Block][Bloom Filter][Footer][Trailer 24B]
 *
 *   Data Block  = AEAD 帧，明文 = 条目记录序列（lid 升序），
 *                 AAD = "verthys/lsm-sstable-v3" ‖ u64le(seq) ‖ u32le(块号)
 *                 （块级绑定：密文块搬运 → 认证失败）；
 *   Index Block = AEAD 帧，明文 = SSTableIndexV3（每块 first_key/offset/
 *                 frame_len/entry_count，二分定位）；
 *   Bloom       = 明文位图（xxHash64 双重哈希），完整性由 Footer 内
 *                 BLAKE2b-256(bloom) 锚定（假阴性 = 查找漏数据，必须认证）；
 *   Footer      = AEAD 帧，明文 = SSTableFooterV3（FB schema）；
 *   Trailer     = [u64 footer 帧偏移][u64 created_txid][u32 'V3SS'][u32 保留]。
 *
 * 读路径惰性加载并缓存 Footer/Bloom/块索引（SSTable 移除时释放）。
 */
#include "sstable_builder.h"
#include "sstable_verifier.h"
#include "sstable_reader.h"

#include "verthys_lsm_internal.h"
#include "verthys_internal.h"     /* verthys_secure_zero */

#define XXH_INLINE_ALL
#include "xxhash.h"

#include <io.h>                 /* _commit / _fileno */
#include <stdlib.h>
#include <string.h>

/* ================== 小端读写 ================== */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

/* ================== AEAD 帧读写 ================== */

/* AAD 组装：label ‖ [u64le seq] ‖ [u32le idx]（按需追加） */
static size_t aad_build(uint8_t *buf, const char *label,
                        int with_seq, uint64_t seq, int with_idx, uint32_t idx)
{
    size_t len = strlen(label);
    memcpy(buf, label, len);
    if (with_seq) {
        put_u64le(buf + len, seq);
        len += 8;
    }
    if (with_idx) {
        put_u32le(buf + len, idx);
        len += 4;
    }
    return len;
}

/*
 * 帧写入：[u32 magic][u32 ct_len][ct||tag][12B nonce] → abs_off。
 * 布局：header 8B + 密文（pt_len + 16B tag）+ nonce 12B。
 * out_frame_len 可为 NULL。（全模块共用：WAL/Manifest/SSTable 帧）
 */
VerthysResult verthys_lsm_frame_write(FILE *f, uint64_t abs_off, uint32_t magic,
                                  VerthysCngAead *aead,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint32_t *out_frame_len)
{
    size_t ct_cap = pt_len + VERTHYS_CNG_TAG_BYTES;
    size_t frame_len = VERTHYS_LSM_FRAME_HEADER_BYTES + ct_cap +
                       VERTHYS_LSM_FRAME_TAIL_BYTES;
    uint8_t *frame;
    VerthysResult r;

    frame = (uint8_t *)malloc(frame_len);
    if (frame == NULL) return VERTHYS_ERR_INTERNAL;

    put_u32le(frame, magic);
    put_u32le(frame + 4, (uint32_t)ct_cap);

    r = verthys_cng_aead_encrypt(aead, pt, pt_len, aad, aad_len,
                               frame + VERTHYS_LSM_FRAME_HEADER_BYTES, &ct_cap,
                               frame + VERTHYS_LSM_FRAME_HEADER_BYTES + pt_len +
                               VERTHYS_CNG_TAG_BYTES);
    if (r == VERTHYS_OK) {
        if (ct_cap != pt_len + VERTHYS_CNG_TAG_BYTES) {
            r = VERTHYS_ERR_INTERNAL;     /* 长度契约破坏（理论不可达） */
        } else if (vio_pwrite64(f, abs_off, frame, frame_len) != 0) {
            r = VERTHYS_ERR_IO;
        } else if (out_frame_len != NULL) {
            *out_frame_len = (uint32_t)frame_len;
        }
    }

    verthys_secure_zero(frame, frame_len);
    free(frame);
    return r;
}

/*
 * 帧读取 + 解密：返回堆分配明文（调用方 free）。
 * max_ct：密文长度上限（容量防护，含 tag）。
 * frame_len_out 可为 NULL。（全模块共用：WAL/Manifest/SSTable 帧）
 */
VerthysResult verthys_lsm_frame_read_decrypt(FILE *f, uint64_t abs_off,
                                         uint32_t magic,
                                         const VerthysCngAead *aead,
                                         const uint8_t *aad, size_t aad_len,
                                         size_t max_ct,
                                         uint8_t **pt_out, size_t *pt_len_out,
                                         uint32_t *frame_len_out)
{
    uint8_t header[VERTHYS_LSM_FRAME_HEADER_BYTES];
    uint8_t *body = NULL;
    uint8_t *pt = NULL;
    uint32_t ct_len;
    size_t body_bytes, pt_cap;
    VerthysResult r;

    if (vio_pread64(f, abs_off, header, sizeof(header)) != 0) {
        return VERTHYS_ERR_FORMAT;
    }
    if (get_u32le(header) != magic) return VERTHYS_ERR_FORMAT;
    ct_len = get_u32le(header + 4);
    if (ct_len < VERTHYS_CNG_TAG_BYTES || (size_t)ct_len > max_ct) {
        return VERTHYS_ERR_FORMAT;
    }

    body_bytes = (size_t)ct_len + VERTHYS_LSM_FRAME_TAIL_BYTES;
    body = (uint8_t *)malloc(body_bytes);
    pt_cap = (size_t)ct_len;            /* 容量 ≥ 明文长度（tag 占 16B） */
    pt = (uint8_t *)malloc(pt_cap);
    if (body == NULL || pt == NULL) {
        free(body);
        free(pt);
        return VERTHYS_ERR_INTERNAL;
    }
    if (vio_pread64(f, abs_off + VERTHYS_LSM_FRAME_HEADER_BYTES, body, body_bytes) != 0) {
        free(body);
        free(pt);
        return VERTHYS_ERR_FORMAT;
    }

    r = verthys_cng_aead_decrypt(aead, body, ct_len, aad, aad_len,
                               body + ct_len, pt, &pt_cap);
    free(body);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(pt, ct_len);
        free(pt);
        return (r == VERTHYS_ERR_LOCKED) ? VERTHYS_ERR_LOCKED : VERTHYS_ERR_AUTH;
    }

    *pt_out = pt;
    *pt_len_out = pt_cap;
    if (frame_len_out != NULL) {
        *frame_len_out = VERTHYS_LSM_FRAME_HEADER_BYTES + ct_len +
                         VERTHYS_LSM_FRAME_TAIL_BYTES;
    }
    return VERTHYS_OK;
}

/* ================== Bloom Filter（xxHash64 双重哈希） ================== */

#define VERTHYS_LSM_BLOOM_SEED1  UINT64_C(0x5645525433564C31) /* "VERT3VL1" */
#define VERTHYS_LSM_BLOOM_SEED2  UINT64_C(0x4C534D33424C4F32) /* "LSM3BLO2" */

uint32_t verthys_lsm_bloom_bytes_for(size_t n)
{
    uint64_t bits = (uint64_t)n * VERTHYS_LSM_BLOOM_BITS_PER_KEY;
    uint32_t bytes = (uint32_t)((bits + 7u) / 8u);
    return (bytes != 0) ? bytes : 1u;
}

VerthysResult verthys_lsm_bloom_init(VerthysLsmBloom *b, size_t n)
{
    if (b == NULL) return VERTHYS_ERR_INVALID;
    b->bytes = verthys_lsm_bloom_bytes_for(n);
    b->k = VERTHYS_LSM_BLOOM_HASH_COUNT;
    b->bits = (uint8_t *)calloc(1, b->bytes);
    if (b->bits == NULL) return VERTHYS_ERR_INTERNAL;
    return VERTHYS_OK;
}

void verthys_lsm_bloom_free(VerthysLsmBloom *b)
{
    if (b == NULL) return;
    free(b->bits);
    b->bits = NULL;
    b->bytes = 0;
    b->k = 0;
}

static uint64_t bloom_bit_index(const VerthysLsmBloom *b, uint64_t key, unsigned i)
{
    uint64_t h1 = XXH64(&key, sizeof(key), VERTHYS_LSM_BLOOM_SEED1);
    uint64_t h2 = XXH64(&key, sizeof(key), VERTHYS_LSM_BLOOM_SEED2) | 1u;
    uint64_t bits_total = (uint64_t)b->bytes * 8u;
    return (h1 + (uint64_t)i * h2) % bits_total;
}

void verthys_lsm_bloom_add(VerthysLsmBloom *b, uint64_t key)
{
    if (b == NULL || b->bits == NULL) return;
    for (unsigned i = 0; i < b->k; i++) {
        uint64_t bit = bloom_bit_index(b, key, i);
        b->bits[bit / 8u] |= (uint8_t)(1u << (bit % 8u));
    }
}

int verthys_lsm_bloom_may_contain(const VerthysLsmBloom *b, uint64_t key)
{
    if (b == NULL || b->bits == NULL || b->k == 0) return 1;  /* 退化：恒可能 */
    for (unsigned i = 0; i < b->k; i++) {
        uint64_t bit = bloom_bit_index(b, key, i);
        if ((b->bits[bit / 8u] & (uint8_t)(1u << (bit % 8u))) == 0) return 0;
    }
    return 1;
}

/* ================== SSTable 写入 ================== */

/* 数据块明文构建器（单块 ≤ 块阈值 + 单条目上限） */
typedef struct BlockBuilder {
    uint8_t *pt;
    size_t len;
    size_t cap;
    uint32_t entry_count;
    uint64_t first_key;
} BlockBuilder;

static int blockbuilder_init(BlockBuilder *bb)
{
    bb->cap = VERTHYS_LSM_SSTABLE_BLOCK_BYTES + VERTHYS_LSM_ENTRY_HEADER_BYTES +
              VERTHYS_LSM_NAME_MAX_BYTES;
    bb->pt = (uint8_t *)malloc(bb->cap);
    if (bb->pt == NULL) return -1;
    bb->len = 0;
    bb->entry_count = 0;
    bb->first_key = 0;
    return 0;
}

static void blockbuilder_reset(BlockBuilder *bb)
{
    bb->len = 0;
    bb->entry_count = 0;
    bb->first_key = 0;
}

static void blockbuilder_free(BlockBuilder *bb)
{
    free(bb->pt);
    bb->pt = NULL;
}

/* 当前块落盘（AEAD 帧，AAD 绑定 seq + 块号），记录块索引 */
static VerthysResult blockbuilder_flush(FILE *f, VerthysPartition *part,
                                      BlockBuilder *bb,
                                      uint64_t seq, uint32_t block_no,
                                      uint64_t *abs_cursor,
                                      VerthysLsmBlockIdx *idx_out)
{
    uint8_t aad[64];
    size_t aad_len = aad_build(aad, VERTHYS_LSM_AAD_SSTABLE, 1, seq, 1, block_no);
    uint32_t frame_len = 0;
    VerthysResult r;

    r = verthys_lsm_frame_write(f, *abs_cursor, VERTHYS_LSM_BLOCK_MAGIC, &part->aead,
                    aad, aad_len, bb->pt, bb->len, &frame_len);
    if (r != VERTHYS_OK) return r;

    idx_out->first_key = bb->first_key;
    idx_out->offset = *abs_cursor;
    idx_out->frame_len = frame_len;
    idx_out->entry_count = bb->entry_count;
    *abs_cursor += frame_len;
    blockbuilder_reset(bb);
    return VERTHYS_OK;
}

/* 块索引数组扩容（×2，初始 16） */
static int blocks_reserve(VerthysLsmBlockIdx **blocks, size_t *cap, size_t need)
{
    if (need <= *cap) return 0;
    {
        size_t new_cap = (*cap == 0) ? 16 : *cap * 2;
        VerthysLsmBlockIdx *nb;
        while (new_cap < need) new_cap *= 2;
        nb = (VerthysLsmBlockIdx *)realloc(*blocks, new_cap * sizeof(*nb));
        if (nb == NULL) return -1;
        *blocks = nb;
        *cap = new_cap;
    }
    return 0;
}

VerthysResult verthys_lsm_sstable_write(FILE *f, VerthysPartition *part,
                                    VerthysLsmEntryIter *it, size_t total_hint,
                                    uint64_t txid, uint64_t seq, uint8_t level,
                                    uint64_t data_base,
                                    uint64_t *rel_cursor, uint64_t data_limit,
                                    VerthysLsmTableMeta *meta)
{
    VerthysResult r = VERTHYS_ERR_INTERNAL;
    VerthysLsmBloom bloom;
    BlockBuilder bb;
    VerthysLsmBlockIdx *blocks = NULL;
    size_t block_count = 0, block_cap = 0;
    uint64_t start_rel, abs_cursor;
    uint64_t min_key = 0, max_key = 0;
    uint32_t entry_count = 0, tombstone_count = 0;
    uint64_t bloom_off_abs = 0, index_off_abs = 0, footer_off_abs = 0;
    uint8_t bloom_digest[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t trailer[VERTHYS_LSM_SSTABLE_TRAILER_BYTES];
    uint8_t aad[64];
    size_t aad_len;
    int have_minmax = 0;

    if (f == NULL || part == NULL || it == NULL || it->next == NULL ||
        rel_cursor == NULL || meta == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;
    if (level >= VERTHYS_LSM_MAX_LEVELS) return VERTHYS_ERR_INVALID;

    start_rel = *rel_cursor;
    if (start_rel >= data_limit) return VERTHYS_ERR_RESOURCE_LIMIT;
    abs_cursor = data_base + start_rel;

    if (blockbuilder_init(&bb) != 0) return VERTHYS_ERR_INTERNAL;
    if (verthys_lsm_bloom_init(&bloom, total_hint) != VERTHYS_OK) {
        blockbuilder_free(&bb);
        return VERTHYS_ERR_INTERNAL;
    }

    /* ---- 数据块流式写入 ---- */
    for (;;) {
        const VerthysLsmEntry *e = NULL;
        int rc = it->next(it, &e);
        size_t enc_len;

        if (rc < 0) { r = VERTHYS_ERR_INTERNAL; goto fail; }
        if (rc == 0) break;
        if (e == NULL) { r = VERTHYS_ERR_INTERNAL; goto fail; }

        enc_len = verthys_lsm_entry_encoded_len(e);
        if (enc_len == 0 || bb.len + enc_len > bb.cap) {
            r = VERTHYS_ERR_INVALID;
            goto fail;
        }
        if (verthys_lsm_entry_encode(bb.pt + bb.len, bb.cap - bb.len, e) != 0) {
            r = VERTHYS_ERR_INTERNAL;
            goto fail;
        }
        if (bb.entry_count == 0) bb.first_key = e->lid;
        bb.len += enc_len;
        bb.entry_count++;

        verthys_lsm_bloom_add(&bloom, e->lid);
        entry_count++;
        if (e->tombstone) tombstone_count++;
        if (!have_minmax) {
            min_key = max_key = e->lid;
            have_minmax = 1;
        } else {
            if (e->lid < min_key) min_key = e->lid;
            if (e->lid > max_key) max_key = e->lid;
        }

        /* 达块阈值 → 落盘当前块 */
        if (bb.len >= VERTHYS_LSM_SSTABLE_BLOCK_BYTES) {
            if (blocks_reserve(&blocks, &block_cap, block_count + 1) != 0) {
                r = VERTHYS_ERR_INTERNAL;
                goto fail;
            }
            r = blockbuilder_flush(f, part, &bb, seq, (uint32_t)block_count,
                                   &abs_cursor, &blocks[block_count]);
            if (r != VERTHYS_OK) goto fail;
            block_count++;
        }
    }
    /* 尾块 */
    if (bb.entry_count != 0) {
        if (blocks_reserve(&blocks, &block_cap, block_count + 1) != 0) {
            r = VERTHYS_ERR_INTERNAL;
            goto fail;
        }
        r = blockbuilder_flush(f, part, &bb, seq, (uint32_t)block_count,
                               &abs_cursor, &blocks[block_count]);
        if (r != VERTHYS_OK) goto fail;
        block_count++;
    }

    /* ---- Bloom 位图（明文）+ BLAKE2b 锚定 ---- */
    if (verthys_extent_hash(bloom_digest, bloom.bits, bloom.bytes) != VERTHYS_OK) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail;
    }
    bloom_off_abs = abs_cursor;
    if (vio_pwrite64(f, bloom_off_abs, bloom.bits, bloom.bytes) != 0) {
        r = VERTHYS_ERR_IO;
        goto fail;
    }
    abs_cursor += bloom.bytes;

    /* ---- Index Block（FB → AEAD 帧）---- */
    {
        flatcc_builder_t builder;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int build_ok = 0;

        if (flatcc_builder_init(&builder) != 0) { r = VERTHYS_ERR_INTERNAL; goto fail; }
        do {
            if (SSTableIndexV3_start_as_root(&builder) != 0) break;
            if (SSTableIndexV3_magic_add(&builder, VERTHYS_LSM_INDEX_MAGIC) != 0) break;
            if (SSTableIndexV3_version_add(&builder, VERTHYS_LSM_VERSION) != 0) break;
            if (SSTableBlockIndexV3_vec_start(&builder) != 0) break;

            build_ok = 1;
            for (size_t i = 0; i < block_count; i++) {
                SSTableBlockIndexV3_ref_t ref;
                if (SSTableBlockIndexV3_start(&builder) != 0) { build_ok = 0; break; }
                if (SSTableBlockIndexV3_first_key_add(&builder, blocks[i].first_key) != 0 ||
                    SSTableBlockIndexV3_offset_add(&builder, blocks[i].offset) != 0 ||
                    SSTableBlockIndexV3_frame_len_add(&builder, blocks[i].frame_len) != 0 ||
                    SSTableBlockIndexV3_entry_count_add(&builder, blocks[i].entry_count) != 0) {
                    build_ok = 0;
                    break;
                }
                ref = SSTableBlockIndexV3_end(&builder);
                if (ref == 0 || SSTableBlockIndexV3_vec_push(&builder, ref) == NULL) {
                    build_ok = 0;
                    break;
                }
            }
            if (!build_ok) break;
            {
                SSTableBlockIndexV3_vec_ref_t vec = SSTableBlockIndexV3_vec_end(&builder);
                if (vec == 0 || SSTableIndexV3_blocks_add(&builder, vec) != 0) {
                    build_ok = 0;
                    break;
                }
            }
            if (SSTableIndexV3_end_as_root(&builder) == 0) { build_ok = 0; break; }
            pt = flatcc_builder_finalize_aligned_buffer(&builder, &pt_len);
            if (pt == NULL || pt_len == 0) { build_ok = 0; break; }
        } while (0);

        if (build_ok) {
            aad_len = aad_build(aad, VERTHYS_LSM_AAD_INDEX, 1, seq, 0, 0);
            index_off_abs = abs_cursor;
            r = verthys_lsm_frame_write(f, index_off_abs, VERTHYS_LSM_INDEX_MAGIC, &part->aead,
                            aad, aad_len, pt, pt_len, NULL);
            abs_cursor += VERTHYS_LSM_FRAME_HEADER_BYTES + pt_len +
                          VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES;
        } else {
            r = VERTHYS_ERR_INTERNAL;
        }
        if (pt != NULL) flatcc_builder_aligned_free(pt);
        flatcc_builder_clear(&builder);
        if (r != VERTHYS_OK) goto fail;
    }

    /* ---- Footer（FB → AEAD 帧）---- */
    {
        flatcc_builder_t builder;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int build_ok = 0;

        if (flatcc_builder_init(&builder) != 0) { r = VERTHYS_ERR_INTERNAL; goto fail; }
        do {
            if (SSTableFooterV3_start_as_root(&builder) != 0) break;
            if (SSTableFooterV3_magic_add(&builder, VERTHYS_LSM_SSTABLE_MAGIC) != 0) break;
            if (SSTableFooterV3_version_add(&builder, VERTHYS_LSM_VERSION) != 0) break;
            if (SSTableFooterV3_seq_add(&builder, seq) != 0) break;
            if (SSTableFooterV3_level_add(&builder, level) != 0) break;
            if (SSTableFooterV3_entry_count_add(&builder, entry_count) != 0) break;
            if (SSTableFooterV3_tombstone_count_add(&builder, tombstone_count) != 0) break;
            if (SSTableFooterV3_min_key_add(&builder, min_key) != 0) break;
            if (SSTableFooterV3_max_key_add(&builder, max_key) != 0) break;
            if (SSTableFooterV3_created_txid_add(&builder, txid) != 0) break;
            if (SSTableFooterV3_index_block_offset_add(&builder, index_off_abs) != 0) break;
            if (SSTableFooterV3_bloom_offset_add(&builder, bloom_off_abs) != 0) break;
            if (SSTableFooterV3_bloom_bytes_add(&builder, bloom.bytes) != 0) break;
            if (SSTableFooterV3_bloom_hash_count_add(&builder, bloom.k) != 0) break;
            {
                flatbuffers_uint8_vec_ref_t hv =
                    flatbuffers_uint8_vec_create(&builder, bloom_digest, 32);
                if (hv == 0 || SSTableFooterV3_bloom_hash_add(&builder, hv) != 0) break;
            }
            if (SSTableFooterV3_end_as_root(&builder) == 0) break;
            pt = flatcc_builder_finalize_aligned_buffer(&builder, &pt_len);
            if (pt == NULL || pt_len == 0) break;
            build_ok = 1;
        } while (0);

        if (build_ok) {
            aad_len = aad_build(aad, VERTHYS_LSM_AAD_FOOTER, 1, seq, 0, 0);
            footer_off_abs = abs_cursor;
            r = verthys_lsm_frame_write(f, footer_off_abs, VERTHYS_LSM_SSTABLE_MAGIC, &part->aead,
                            aad, aad_len, pt, pt_len, NULL);
            abs_cursor += VERTHYS_LSM_FRAME_HEADER_BYTES + pt_len +
                          VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES;
        } else {
            r = VERTHYS_ERR_INTERNAL;
        }
        if (pt != NULL) flatcc_builder_aligned_free(pt);
        flatcc_builder_clear(&builder);
        if (r != VERTHYS_OK) goto fail;
    }

    /* ---- Trailer（明文定位锚，24B）---- */
    put_u64le(trailer + 0, footer_off_abs);
    put_u64le(trailer + 8, txid);
    put_u32le(trailer + 16, VERTHYS_LSM_SSTABLE_MAGIC);
    put_u32le(trailer + 20, 0);
    if (vio_pwrite64(f, abs_cursor, trailer, sizeof(trailer)) != 0) {
        r = VERTHYS_ERR_IO;
        goto fail;
    }
    abs_cursor += sizeof(trailer);

    /* ---- 容量校验 + 物理落盘（SSTable 须先于 Manifest 引用持久化）---- */
    if ((uint64_t)(abs_cursor - (data_base + start_rel)) > data_limit - start_rel) {
        r = VERTHYS_ERR_RESOURCE_LIMIT;
        goto fail;
    }
    if (fflush(f) != 0 || _commit(_fileno(f)) != 0) {
        r = VERTHYS_ERR_IO;
        goto fail;
    }

    /* ---- meta 填充 ---- */
    memset(meta, 0, sizeof(*meta));
    meta->seq = seq;
    meta->level = level;
    meta->offset = data_base + start_rel;
    meta->size = (uint32_t)(abs_cursor - (data_base + start_rel));
    meta->entry_count = entry_count;
    meta->tombstone_count = tombstone_count;
    meta->min_key = min_key;
    meta->max_key = max_key;
    meta->created_txid = txid;
    meta->footer_loaded = 1;
    meta->index_block_offset = index_off_abs;
    meta->bloom_offset = bloom_off_abs;
    meta->bloom_bytes = bloom.bytes;
    meta->bloom_k = bloom.k;
    memcpy(meta->bloom_hash, bloom_digest, 32);

    *rel_cursor = start_rel + (uint64_t)meta->size;
    r = VERTHYS_OK;

fail:
    verthys_lsm_bloom_free(&bloom);
    blockbuilder_free(&bb);
    free(blocks);
    return r;
}

/* ================== SSTable 读取 ================== */

void verthys_lsm_sstable_meta_release(VerthysLsmTableMeta *meta)
{
    if (meta == NULL) return;
    free(meta->bloom_bits);
    meta->bloom_bits = NULL;
    free(meta->blocks);
    meta->blocks = NULL;
    meta->block_count = 0;
    meta->footer_loaded = 0;
}

/* 惰性加载 Footer（Trailer → Footer 帧解密 + verifier + 与 Manifest 一致性校验） */
static VerthysResult ensure_footer(FILE *f, VerthysPartition *part,
                                 VerthysLsmTableMeta *meta)
{
    VerthysResult r;
    uint8_t trailer[VERTHYS_LSM_SSTABLE_TRAILER_BYTES];
    uint8_t aad[64];
    size_t aad_len;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    uint64_t footer_off, footer_txid;
    SSTableFooterV3_table_t t;
    flatbuffers_uint8_vec_t hv;

    if (meta->footer_loaded) return VERTHYS_OK;

    if (meta->size < VERTHYS_LSM_SSTABLE_TRAILER_BYTES) return VERTHYS_ERR_FORMAT;
    if (vio_pread64(f, meta->offset + meta->size - sizeof(trailer),
                    trailer, sizeof(trailer)) != 0) {
        return VERTHYS_ERR_FORMAT;
    }
    if (get_u32le(trailer + 16) != VERTHYS_LSM_SSTABLE_MAGIC) {
        return VERTHYS_ERR_FORMAT;
    }
    footer_off = get_u64le(trailer + 0);
    footer_txid = get_u64le(trailer + 8);
    if (footer_off < meta->offset || footer_off >= meta->offset + meta->size) {
        return VERTHYS_ERR_FORMAT;
    }

    aad_len = aad_build(aad, VERTHYS_LSM_AAD_FOOTER, 1, meta->seq, 0, 0);
    r = verthys_lsm_frame_read_decrypt(f, footer_off, VERTHYS_LSM_SSTABLE_MAGIC,
                           &part->aead, aad, aad_len,
                           meta->size, &pt, &pt_len, NULL);
    if (r != VERTHYS_OK) return r;

    do {
        if (SSTableFooterV3_verify_as_root(pt, pt_len) != flatcc_verify_ok) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        t = SSTableFooterV3_as_root(pt);
        if (t == NULL ||
            SSTableFooterV3_magic(t) != VERTHYS_LSM_SSTABLE_MAGIC ||
            SSTableFooterV3_version(t) != VERTHYS_LSM_VERSION ||
            SSTableFooterV3_seq(t) != meta->seq ||
            SSTableFooterV3_created_txid(t) != footer_txid) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        if (SSTableFooterV3_entry_count(t) != meta->entry_count ||
            SSTableFooterV3_tombstone_count(t) != meta->tombstone_count ||
            SSTableFooterV3_min_key(t) != meta->min_key ||
            SSTableFooterV3_max_key(t) != meta->max_key) {
            r = VERTHYS_ERR_FORMAT;      /* Footer 与 Manifest 失配 */
            break;
        }

        meta->index_block_offset = SSTableFooterV3_index_block_offset(t);
        meta->bloom_offset = SSTableFooterV3_bloom_offset(t);
        meta->bloom_bytes = SSTableFooterV3_bloom_bytes(t);
        meta->bloom_k = SSTableFooterV3_bloom_hash_count(t);
        hv = SSTableFooterV3_bloom_hash(t);
        if (hv == NULL || flatbuffers_uint8_vec_len(hv) != 32 ||
            meta->bloom_bytes == 0 || meta->bloom_k == 0 ||
            meta->bloom_k > 64) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        for (size_t k = 0; k < 32; k++) {
            meta->bloom_hash[k] = flatbuffers_uint8_vec_at(hv, k);
        }

        /* 布局边界校验（防越界读） */
        if (meta->index_block_offset < meta->offset ||
            meta->index_block_offset >= meta->offset + meta->size ||
            meta->bloom_offset < meta->offset ||
            meta->bloom_offset + meta->bloom_bytes > meta->offset + meta->size) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        meta->footer_loaded = 1;
    } while (0);

    verthys_secure_zero(pt, pt_len);
    free(pt);
    return r;
}

/* 惰性加载 Bloom 位图（读取 + BLAKE2b 校验 + 缓存） */
static VerthysResult ensure_bloom(FILE *f, VerthysPartition *part,
                                VerthysLsmTableMeta *meta)
{
    uint8_t digest[VERTHYS_EXTENT_HASH_BYTES];
    VerthysResult r;

    (void)part;
    if (meta->bloom_bits != NULL) return VERTHYS_OK;

    meta->bloom_bits = (uint8_t *)malloc(meta->bloom_bytes);
    if (meta->bloom_bits == NULL) return VERTHYS_ERR_INTERNAL;
    if (vio_pread64(f, meta->bloom_offset, meta->bloom_bits, meta->bloom_bytes) != 0) {
        free(meta->bloom_bits);
        meta->bloom_bits = NULL;
        return VERTHYS_ERR_IO;
    }
    r = verthys_extent_hash(digest, meta->bloom_bits, meta->bloom_bytes);
    if (r != VERTHYS_OK || memcmp(digest, meta->bloom_hash, 32) != 0) {
        free(meta->bloom_bits);
        meta->bloom_bits = NULL;
        return VERTHYS_ERR_CORRUPT;    /* 位图被篡改（假阴性风险 → 拒绝） */
    }
    return VERTHYS_OK;
}

/* 惰性加载块索引（Index Block 帧解密 + verifier + 解析） */
static VerthysResult ensure_blocks(FILE *f, VerthysPartition *part,
                                 VerthysLsmTableMeta *meta)
{
    VerthysResult r;
    uint8_t aad[64];
    size_t aad_len;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    SSTableIndexV3_table_t t;
    SSTableBlockIndexV3_vec_t vec;
    size_t count, i;

    if (meta->blocks != NULL) return VERTHYS_OK;

    aad_len = aad_build(aad, VERTHYS_LSM_AAD_INDEX, 1, meta->seq, 0, 0);
    r = verthys_lsm_frame_read_decrypt(f, meta->index_block_offset, VERTHYS_LSM_INDEX_MAGIC,
                           &part->aead, aad, aad_len,
                           meta->size, &pt, &pt_len, NULL);
    if (r != VERTHYS_OK) return r;

    do {
        if (SSTableIndexV3_verify_as_root(pt, pt_len) != flatcc_verify_ok) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        t = SSTableIndexV3_as_root(pt);
        if (t == NULL ||
            SSTableIndexV3_magic(t) != VERTHYS_LSM_INDEX_MAGIC ||
            SSTableIndexV3_version(t) != VERTHYS_LSM_VERSION) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        vec = SSTableIndexV3_blocks(t);
        count = (vec == NULL) ? 0 : SSTableBlockIndexV3_vec_len(vec);
        if (count == 0) {
            r = VERTHYS_ERR_FORMAT;    /* 非空表必有块索引 */
            break;
        }
        meta->blocks = (VerthysLsmBlockIdx *)malloc(count * sizeof(VerthysLsmBlockIdx));
        if (meta->blocks == NULL) {
            r = VERTHYS_ERR_INTERNAL;
            break;
        }
        for (i = 0; i < count; i++) {
            SSTableBlockIndexV3_table_t bt = SSTableBlockIndexV3_vec_at(vec, i);
            if (bt == NULL) {
                r = VERTHYS_ERR_FORMAT;
                break;
            }
            meta->blocks[i].first_key = SSTableBlockIndexV3_first_key(bt);
            meta->blocks[i].offset = SSTableBlockIndexV3_offset(bt);
            meta->blocks[i].frame_len = SSTableBlockIndexV3_frame_len(bt);
            meta->blocks[i].entry_count = SSTableBlockIndexV3_entry_count(bt);
            /* 块边界校验：offset 落在 [表起始, 索引块起始) 且帧不越过
             * 索引块。回绕安全分解（同 verthys_extent.c 索引解析纪律）：
             * 朴素 offset+frame_len 在 uint64 溢出时回绕为小值绕过
             * 比较——先钳 offset ≤ index_block_offset，再以差值钳
             * frame_len（纵深防御：索引块本体另有 AEAD 认证） */
            if (meta->blocks[i].frame_len <
                    VERTHYS_LSM_FRAME_HEADER_BYTES + VERTHYS_CNG_TAG_BYTES +
                    VERTHYS_LSM_FRAME_TAIL_BYTES ||
                meta->blocks[i].offset < meta->offset ||
                meta->blocks[i].offset > meta->index_block_offset ||
                meta->blocks[i].frame_len >
                    meta->index_block_offset - meta->blocks[i].offset) {
                r = VERTHYS_ERR_FORMAT;
                break;
            }
        }
        if (r != VERTHYS_OK) {
            free(meta->blocks);
            meta->blocks = NULL;
            break;
        }
        meta->block_count = count;
    } while (0);

    verthys_secure_zero(pt, pt_len);
    free(pt);
    return r;
}

/* 解密指定数据块（AAD 绑定 seq + 块号） */
static VerthysResult read_block(FILE *f, VerthysPartition *part,
                              VerthysLsmTableMeta *meta, size_t block_no,
                              uint8_t **pt_out, size_t *pt_len_out)
{
    uint8_t aad[64];
    size_t aad_len = aad_build(aad, VERTHYS_LSM_AAD_SSTABLE, 1, meta->seq,
                               1, (uint32_t)block_no);
    const VerthysLsmBlockIdx *bi = &meta->blocks[block_no];

    return verthys_lsm_frame_read_decrypt(f, bi->offset, VERTHYS_LSM_BLOCK_MAGIC,
                              &part->aead, aad, aad_len,
                              bi->frame_len, pt_out, pt_len_out, NULL);
}

/* 块内扫描：定位 lid（命中 → out 填充；name 拷入 name_buf） */
static VerthysResult scan_block(const uint8_t *pt, size_t pt_len, uint64_t lid,
                              VerthysLsmEntry *out,
                              uint8_t *name_buf, size_t name_cap,
                              size_t *name_len_out)
{
    size_t pos = 0;

    while (pos < pt_len) {
        VerthysLsmEntry e;
        size_t used = verthys_lsm_entry_decode(pt + pos, pt_len - pos, &e);
        if (used == 0) return VERTHYS_ERR_FORMAT;
        if (e.lid == lid) {
            if (out != NULL) {
                *out = e;
                if (e.name_len != 0) {
                    if (name_buf == NULL || name_cap < e.name_len) {
                        return VERTHYS_ERR_INVALID;
                    }
                    memcpy(name_buf, e.name, e.name_len);
                    out->name = name_buf;
                } else {
                    out->name = NULL;
                }
            }
            if (name_len_out != NULL) *name_len_out = e.name_len;
            return VERTHYS_OK;    /* 键定位成功（out->tombstone 由调用方解释） */
        }
        if (e.lid > lid) break;    /* 块内升序：已越过 → 必不存在 */
        pos += used;
    }
    return VERTHYS_ERR_NOTFOUND;
}

/* ★ WP-5（UNLOCK_OPTIMIZATION §7/§9）：单表全量预热——ensure_* 链
 * 顺序强制加载（Footer → Bloom → Index Block），后续 get 零元数据 IO。
 * 幂等：各 ensure_* 自带缓存命中即返。 */
VerthysResult verthys_lsm_sstable_preheat(FILE *f, VerthysPartition *part,
                                      VerthysLsmTableMeta *meta)
{
    VerthysResult r;

    if (f == NULL || part == NULL || meta == NULL) return VERTHYS_ERR_INVALID;

    r = ensure_footer(f, part, meta);
    if (r != VERTHYS_OK) return r;
    r = ensure_bloom(f, part, meta);
    if (r != VERTHYS_OK) return r;
    return ensure_blocks(f, part, meta);
}

VerthysResult verthys_lsm_sstable_find(FILE *f, VerthysPartition *part,
                                   VerthysLsmTableMeta *meta, uint64_t lid,
                                   VerthysLsmEntry *out,
                                   uint8_t *name_buf, size_t name_cap,
                                   size_t *name_len_out)
{
    VerthysResult r;
    size_t lo, hi, target = (size_t)-1;
    uint8_t *pt = NULL;
    size_t pt_len = 0;

    if (f == NULL || part == NULL || meta == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    /* 键域排除 */
    if (lid < meta->min_key || lid > meta->max_key) return VERTHYS_ERR_NOTFOUND;

    r = ensure_footer(f, part, meta);
    if (r != VERTHYS_OK) return r;
    if (meta->entry_count == 0) return VERTHYS_ERR_NOTFOUND;

    /* Bloom 过滤（假阴性为零；位图篡改 → CORRUPT） */
    r = ensure_bloom(f, part, meta);
    if (r != VERTHYS_OK) return r;
    {
        VerthysLsmBloom b;
        b.bits = meta->bloom_bits;
        b.bytes = meta->bloom_bytes;
        b.k = meta->bloom_k;
        if (!verthys_lsm_bloom_may_contain(&b, lid)) return VERTHYS_ERR_NOTFOUND;
    }

    /* 块索引二分：最大 first_key ≤ lid 的块 */
    r = ensure_blocks(f, part, meta);
    if (r != VERTHYS_OK) return r;
    lo = 0;
    hi = meta->block_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (meta->blocks[mid].first_key <= lid) {
            target = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (target == (size_t)-1) return VERTHYS_ERR_NOTFOUND;

    /* 目标块解密 + 块内扫描 */
    r = read_block(f, part, meta, target, &pt, &pt_len);
    if (r != VERTHYS_OK) return r;
    r = scan_block(pt, pt_len, lid, out, name_buf, name_cap, name_len_out);
    verthys_secure_zero(pt, pt_len);
    free(pt);
    return r;
}

/* ================== SSTable 顺序迭代（compaction 输入） ================== */

struct VerthysLsmSstIter {
    FILE *f;
    VerthysPartition *part;
    VerthysLsmTableMeta *meta;
    size_t block_idx;        /* 待加载块号 */
    uint8_t *pt;             /* 当前块明文 */
    size_t pt_len;
    size_t pt_pos;
    int done;
    VerthysLsmEntry cur;       /* 借用条目（name 指向 pt，生存期至下次推进） */
};

static int sstable_iter_next(VerthysLsmEntryIter *it, const VerthysLsmEntry **out)
{
    VerthysLsmSstIter *si = (VerthysLsmSstIter *)it->ctx;
    VerthysResult r;
    size_t used;

    if (si == NULL || out == NULL) return -1;
    if (si->done) return 0;

    /* 当前块耗尽 → 加载下一块 */
    while (si->pt_pos >= si->pt_len) {
        free(si->pt);
        si->pt = NULL;
        si->pt_len = 0;
        si->pt_pos = 0;
        if (si->block_idx >= si->meta->block_count) {
            si->done = 1;
            return 0;
        }
        r = read_block(si->f, si->part, si->meta, si->block_idx,
                       &si->pt, &si->pt_len);
        if (r != VERTHYS_OK) return -1;
        si->block_idx++;
        si->pt_pos = 0;
    }

    used = verthys_lsm_entry_decode(si->pt + si->pt_pos, si->pt_len - si->pt_pos,
                                  &si->cur);
    if (used == 0) return -1;
    si->pt_pos += used;
    *out = &si->cur;
    return 1;
}

VerthysResult verthys_lsm_sstable_iter_open(FILE *f, VerthysPartition *part,
                                        VerthysLsmTableMeta *meta,
                                        VerthysLsmEntryIter *it,
                                        VerthysLsmSstIter **out)
{
    VerthysLsmSstIter *si;
    VerthysResult r;

    if (f == NULL || part == NULL || meta == NULL || it == NULL || out == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    r = ensure_footer(f, part, meta);
    if (r != VERTHYS_OK) return r;
    r = ensure_blocks(f, part, meta);
    if (r != VERTHYS_OK) return r;

    si = (VerthysLsmSstIter *)calloc(1, sizeof(*si));
    if (si == NULL) return VERTHYS_ERR_INTERNAL;
    si->f = f;
    si->part = part;
    si->meta = meta;

    it->next = sstable_iter_next;
    it->ctx = si;
    *out = si;
    return VERTHYS_OK;
}

void verthys_lsm_sstable_iter_close(VerthysLsmSstIter *si)
{
    if (si == NULL) return;
    if (si->pt != NULL) {
        verthys_secure_zero(si->pt, si->pt_len);
        free(si->pt);
    }
    free(si);
}
