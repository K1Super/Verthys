/*
 * verthys_extent.c — V3 内容寻址 Extent 实现
 *
 * 设计依据：docs/TARGET_ARCHITECTURE_V5.md §6.5 / §6.2
 * 落地依据：docs/V3_UPGRADE_PLAYBOOK.md WP-3
 *
 * 复用资产：
 *   - verthys_crypto.c verthys_generichash（libsodium BLAKE2b-256，E-3 零依赖）
 *   - verthys_crypto_cng.c（CNG 内核 AEAD：加密/解密/nonce 计数器）
 *   - verthys_partition.h（Extent 分区：独立密钥上下文 VerthysPartition）
 *   - verthys_io.c（vio_pread64/vio_pwrite64 统一 64 位偏移 I/O）
 *   - schema/extent.fbs（flatcc codegen：extent_builder/verifier/reader.h）
 *
 * 数据块 AEAD AAD 设计（去重关键约束）：
 *   AAD = partition_id(4B LE) ‖ hash(32B)，共 36 字节。
 *   不绑定 txid——去重语义下同一数据块跨事务被多个记录引用，若 AAD 绑定
 *   写入时 txid，后续事务读取将认证失败。绑定 hash 使密文与内容承诺
 *   （寻址键）强绑定：攻击者无法将 A 块密文搬运到 B 块槽位（认证失败）。
 */
#include "extent_builder.h"
#include "extent_verifier.h"
#include "extent_reader.h"

#include "verthys_extent.h"
#include "verthys_crypto.h"
#include "verthys_io.h"
#include "verthys_internal.h"     /* verthys_secure_zero */

#include <io.h>                 /* _commit / _fileno */
#include <string.h>
#include <stdlib.h>

/* ---------- 内部工具 ---------- */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 数据块 AAD：partition_id(4LE) ‖ hash(32B)（见文件头设计注记） */
#define VERTHYS_EXTENT_DATA_AAD_BYTES 36u

static void build_data_aad(uint8_t aad[VERTHYS_EXTENT_DATA_AAD_BYTES],
                           VerthysPartitionId partition_id,
                           const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES])
{
    put_u32le(aad, partition_id);
    memcpy(aad + 4, hash, VERTHYS_EXTENT_HASH_BYTES);
}

/* 索引内按哈希定位条目（线性扫描；命中返回下标，未命中返回 SIZE_MAX）。
 * 条目上限 4096，O(n) 查找的常数远小于哈希计算本身，LSM 层（WP-4）
 * 建立 hash→offset 内存映射后由上层接管热路径。 */
static size_t index_find_slot(const VerthysExtentIndex *idx,
                              const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES])
{
    for (size_t i = 0; i < idx->count; i++) {
        if (memcmp(idx->entries[i].hash, hash, VERTHYS_EXTENT_HASH_BYTES) == 0) {
            return i;
        }
    }
    return SIZE_MAX;
}

/* ---------- 哈希 ---------- */

VerthysResult verthys_extent_hash(uint8_t out[VERTHYS_EXTENT_HASH_BYTES],
                              const uint8_t *data, size_t data_len)
{
    if (out == NULL) return VERTHYS_ERR_INVALID;
    if (data == NULL && data_len != 0) return VERTHYS_ERR_INVALID;
    if (verthys_generichash(out, data, data_len) != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    return VERTHYS_OK;
}

/* ---------- 索引生命周期 ---------- */

VerthysResult verthys_extent_index_init(VerthysExtentIndex *idx, uint64_t txid)
{
    if (idx == NULL) return VERTHYS_ERR_INVALID;
    memset(idx, 0, sizeof(*idx));
    idx->txid = txid;
    return VERTHYS_OK;
}

VerthysResult verthys_extent_index_find(const VerthysExtentIndex *idx,
                                    const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                                    VerthysExtent *out)
{
    size_t slot;

    if (idx == NULL || hash == NULL) return VERTHYS_ERR_INVALID;
    slot = index_find_slot(idx, hash);
    if (slot == SIZE_MAX) return VERTHYS_ERR_NOTFOUND;
    if (out != NULL) {
        *out = idx->entries[slot];
    }
    return VERTHYS_OK;
}

/* ---------- 数据路径 ---------- */

VerthysResult verthys_extent_put(FILE *f, VerthysPartition *part,
                             VerthysExtentIndex *idx, uint64_t txid,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t hash_out[VERTHYS_EXTENT_HASH_BYTES],
                             int *stored)
{
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t aad[VERTHYS_EXTENT_DATA_AAD_BYTES];
    uint8_t *ct = NULL;
    size_t slot;
    VerthysResult r;

    if (f == NULL || part == NULL || idx == NULL) return VERTHYS_ERR_INVALID;
    if (pt == NULL && pt_len != 0) return VERTHYS_ERR_INVALID;
    if (pt_len > UINT32_MAX) return VERTHYS_ERR_INVALID;  /* 条目字段为 u32 */

    /* 1. 内容哈希（内容寻址键） */
    r = verthys_extent_hash(hash, pt, pt_len);
    if (r != VERTHYS_OK) return r;
    if (hash_out != NULL) {
        memcpy(hash_out, hash, VERTHYS_EXTENT_HASH_BYTES);
    }
    if (stored != NULL) {
        *stored = 0;
    }

    /* 2. 查重：命中 → ref_count++（零重写，去重收益核心） */
    slot = index_find_slot(idx, hash);
    if (slot != SIZE_MAX) {
        VerthysExtent *e = &idx->entries[slot];
        if (e->ref_count == UINT32_MAX) return VERTHYS_ERR_RESOURCE_LIMIT;
        e->ref_count++;
        e->last_ref_txid = txid;
        if (stored != NULL) {
            *stored = 0;
        }
        return VERTHYS_OK;
    }

    /* 3. 未命中：新数据块加密追加 */
    if (idx->count >= VERTHYS_EXTENT_INDEX_MAX) return VERTHYS_ERR_RESOURCE_LIMIT;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    build_data_aad(aad, part->id, hash);

    ct = (uint8_t *)malloc(pt_len + VERTHYS_EXTENT_TAG_BYTES);
    if (ct == NULL) return VERTHYS_ERR_INTERNAL;

    do {
        uint8_t nonce[VERTHYS_EXTENT_NONCE_BYTES];
        size_t ct_len = pt_len + VERTHYS_EXTENT_TAG_BYTES;  /* 容量（in/out） */
        uint64_t abs_offset;

        r = verthys_cng_aead_encrypt(&part->aead,
                                   pt, pt_len,
                                   aad, sizeof(aad),
                                   ct, &ct_len,
                                   nonce);
        if (r != VERTHYS_OK) break;
        if (ct_len != pt_len + VERTHYS_EXTENT_TAG_BYTES) {
            r = VERTHYS_ERR_INTERNAL;
            break;
        }

        /* 4. 追加写（数据区 = 分区偏移 + 索引区 + 游标）+ fsync */
        abs_offset = part->offset + VERTHYS_EXTENT_INDEX_REGION_BYTES +
                     idx->next_offset;
        if (abs_offset > INT64_MAX) {
            r = VERTHYS_ERR_INTERNAL;
            break;
        }
        if (vio_pwrite64(f, abs_offset, ct, ct_len) != 0) {
            r = VERTHYS_ERR_IO;
            break;
        }
        if (fflush(f) != 0 || _commit(_fileno(f)) != 0) {
            r = VERTHYS_ERR_IO;
            break;
        }

        /* 5. 索引更新（仅在数据块完整落盘之后——崩溃时孤儿块不可达） */
        {
            VerthysExtent *e = &idx->entries[idx->count];
            memset(e, 0, sizeof(*e));
            memcpy(e->hash, hash, VERTHYS_EXTENT_HASH_BYTES);
            memcpy(e->nonce, nonce, VERTHYS_EXTENT_NONCE_BYTES);
            e->offset = idx->next_offset;
            e->size = (uint32_t)ct_len;
            e->plaintext_size = (uint32_t)pt_len;
            e->ref_count = 1;
            e->created_txid = txid;
            e->last_ref_txid = txid;
            idx->count++;
            idx->next_offset += ct_len;
            part->used += ct_len;
        }
        if (stored != NULL) {
            *stored = 1;
        }
    } while (0);

    free(ct);
    return r;
}

VerthysResult verthys_extent_get(FILE *f, const VerthysPartition *part,
                             const VerthysExtentIndex *idx,
                             const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                             uint8_t *pt, size_t *pt_len)
{
    uint8_t aad[VERTHYS_EXTENT_DATA_AAD_BYTES];
    uint8_t *ct = NULL;
    const VerthysExtent *e;
    size_t slot;
    uint64_t abs_offset;
    size_t out_cap;
    VerthysResult r;

    if (f == NULL || part == NULL || idx == NULL || hash == NULL ||
        pt == NULL || pt_len == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    slot = index_find_slot(idx, hash);
    if (slot == SIZE_MAX) return VERTHYS_ERR_NOTFOUND;
    e = &idx->entries[slot];

    out_cap = *pt_len;
    if (out_cap < e->plaintext_size) return VERTHYS_ERR_INVALID;

    /* 1. 读密文（数据区相对偏移 → 绝对偏移） */
    abs_offset = part->offset + VERTHYS_EXTENT_INDEX_REGION_BYTES + e->offset;
    if (abs_offset > INT64_MAX) return VERTHYS_ERR_INTERNAL;

    ct = (uint8_t *)malloc(e->size);
    if (ct == NULL) return VERTHYS_ERR_INTERNAL;

    if (vio_pread64(f, abs_offset, ct, e->size) != 0) {
        free(ct);
        return VERTHYS_ERR_IO;
    }

    /* 2. 内核态解密（认证失败 → AUTH，输出清零） */
    build_data_aad(aad, part->id, hash);
    {
        size_t out_len = out_cap;  /* 容量（in/out） */
        r = verthys_cng_aead_decrypt(&part->aead,
                                   ct, e->size,
                                   aad, sizeof(aad),
                                   e->nonce, pt, &out_len);
        if (r != VERTHYS_OK) {
            verthys_secure_zero(pt, out_cap);
            free(ct);
            return (r == VERTHYS_ERR_LOCKED) ? VERTHYS_ERR_LOCKED : VERTHYS_ERR_AUTH;
        }
        if (out_len != e->plaintext_size) {
            /* 长度与索引记账不符：条目与密文不一致（纵深防御） */
            verthys_secure_zero(pt, out_cap);
            free(ct);
            return VERTHYS_ERR_CORRUPT;
        }
    }
    free(ct);

    /* 3. 内容哈希校验（BLAKE2b(明文) == hash，第二重完整性） */
    {
        uint8_t verify[VERTHYS_EXTENT_HASH_BYTES];
        r = verthys_extent_hash(verify, pt, e->plaintext_size);
        if (r != VERTHYS_OK) {
            verthys_secure_zero(pt, out_cap);
            return r;
        }
        if (memcmp(verify, e->hash, VERTHYS_EXTENT_HASH_BYTES) != 0) {
            verthys_secure_zero(pt, out_cap);
            return VERTHYS_ERR_CORRUPT;
        }
    }

    *pt_len = e->plaintext_size;
    return VERTHYS_OK;
}

VerthysResult verthys_extent_release(VerthysExtentIndex *idx,
                                 const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                                 uint64_t txid,
                                 uint32_t *out_ref_count)
{
    VerthysExtent *e;
    size_t slot;

    if (idx == NULL || hash == NULL) return VERTHYS_ERR_INVALID;
    slot = index_find_slot(idx, hash);
    if (slot == SIZE_MAX) return VERTHYS_ERR_NOTFOUND;

    e = &idx->entries[slot];
    /* 下限 0：重复 release 不回绕（防御性；正常流程由上层引用账本保证） */
    if (e->ref_count > 0) {
        e->ref_count--;
    }
    e->last_ref_txid = txid;
    if (out_ref_count != NULL) {
        *out_ref_count = e->ref_count;
    }
    return VERTHYS_OK;
}

VerthysResult verthys_extent_gc_eligible(const VerthysExtentIndex *idx,
                                     size_t *count)
{
    size_t eligible = 0;

    if (idx == NULL || count == NULL) return VERTHYS_ERR_INVALID;
    for (size_t i = 0; i < idx->count; i++) {
        if (idx->entries[i].ref_count == 0) {
            eligible++;
        }
    }
    *count = eligible;
    return VERTHYS_OK;
}

/* ---------- 索引持久化 ---------- */

/*
 * flatcc 序列化索引（返回 flatcc_builder_aligned_free 归属的对齐缓冲）。
 * 帧明文 = ExtentIndexV3 FlatBuffers；nonce_counter 取分区当前计数器（E-7）。
 */
static VerthysResult index_serialize(const VerthysExtentIndex *idx,
                                   const VerthysPartition *part,
                                   uint8_t **out_buf, size_t *out_len)
{
    flatcc_builder_t builder;
    uint8_t *buf = NULL;
    size_t size = 0;
    VerthysResult result = VERTHYS_ERR_INTERNAL;

    if (flatcc_builder_init(&builder) != 0) return VERTHYS_ERR_INTERNAL;

    do {
        if (ExtentIndexV3_start_as_root(&builder) != 0) break;
        if (ExtentIndexV3_magic_add(&builder, VERTHYS_EXTENT_INDEX_MAGIC) != 0) break;
        if (ExtentIndexV3_version_add(&builder, VERTHYS_EXTENT_INDEX_VERSION) != 0) break;
        if (ExtentIndexV3_txid_add(&builder, idx->txid) != 0) break;
        if (ExtentIndexV3_next_offset_add(&builder, idx->next_offset) != 0) break;
        /* 保存后值约定（与 WP-4 LSM Manifest 一致）：索引帧在序列化
         * 完成后由 save 路径加密，恰消耗 1 个 nonce（计数器 +1）。
         * 此前保存前值，重载 restore 回退到帧自身 nonce，下次
         * 加密重用该 nonce（AEAD 红线违规，E-7）。 */
        if (ExtentIndexV3_nonce_counter_add(
                &builder,
                verthys_cng_aead_nonce_counter(&part->aead) + 1u) != 0) break;

        if (ExtentEntryV3_vec_start(&builder) != 0) break;
        int entries_ok = 1;
        for (size_t i = 0; i < idx->count; i++) {
            const VerthysExtent *e = &idx->entries[i];
            flatbuffers_uint8_vec_ref_t hash_ref =
                flatbuffers_uint8_vec_create(&builder, e->hash,
                                             VERTHYS_EXTENT_HASH_BYTES);
            flatbuffers_uint8_vec_ref_t nonce_ref =
                flatbuffers_uint8_vec_create(&builder, e->nonce,
                                             VERTHYS_EXTENT_NONCE_BYTES);
            if (hash_ref == 0 || nonce_ref == 0) {
                entries_ok = 0;
                break;
            }

            ExtentEntryV3_ref_t entry = ExtentEntryV3_create(&builder,
                hash_ref, nonce_ref,
                e->offset, e->size, e->plaintext_size, e->ref_count,
                e->created_txid, e->last_ref_txid);
            if (entry == 0) {
                entries_ok = 0;
                break;
            }
            /* vec_push 返回 ref_t*（非 NULL=成功，NULL=失败） */
            if (ExtentEntryV3_vec_push(&builder, entry) == NULL) {
                entries_ok = 0;
                break;
            }
        }
        if (!entries_ok) break;
        {
            ExtentEntryV3_vec_ref_t vec = ExtentEntryV3_vec_end(&builder);
            if (vec == 0 || ExtentIndexV3_entries_add(&builder, vec) != 0) break;
        }
        if (ExtentIndexV3_end_as_root(&builder) == 0) break;

        buf = flatcc_builder_finalize_aligned_buffer(&builder, &size);
        if (buf == NULL || size == 0) break;

        *out_buf = buf;
        *out_len = size;
        result = VERTHYS_OK;
    } while (0);

    flatcc_builder_clear(&builder);
    if (result != VERTHYS_OK && buf != NULL) {
        flatcc_builder_aligned_free(buf);
    }
    return result;
}

VerthysResult verthys_extent_index_save(FILE *f, uint64_t region_offset,
                                    const VerthysExtentIndex *idx,
                                    VerthysPartition *part)
{
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    uint8_t *frame = NULL;
    size_t frame_bytes;
    VerthysResult r;

    if (f == NULL || idx == NULL || part == NULL) return VERTHYS_ERR_INVALID;
    if (idx->count > VERTHYS_EXTENT_INDEX_MAX) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    /* 1. flatcc 序列化 */
    r = index_serialize(idx, part, &pt, &pt_len);
    if (r != VERTHYS_OK) return r;

    /* 2. 帧组装容量校验（索引帧区上限） */
    frame_bytes = VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES +
                  pt_len + VERTHYS_EXTENT_TAG_BYTES +
                  VERTHYS_EXTENT_NONCE_BYTES;
    if (frame_bytes > VERTHYS_EXTENT_INDEX_REGION_BYTES) {
        flatcc_builder_aligned_free(pt);
        return VERTHYS_ERR_INVALID;
    }

    frame = (uint8_t *)calloc(1, frame_bytes);
    if (frame == NULL) {
        flatcc_builder_aligned_free(pt);
        return VERTHYS_ERR_INTERNAL;
    }

    do {
        put_u32le(frame, VERTHYS_EXTENT_INDEX_MAGIC);
        put_u32le(frame + 4, (uint32_t)(pt_len + VERTHYS_EXTENT_TAG_BYTES));

        {
            size_t ct_len = pt_len + VERTHYS_EXTENT_TAG_BYTES;  /* 容量（in/out） */
            r = verthys_cng_aead_encrypt(&part->aead,
                                       pt, pt_len,
                                       (const uint8_t *)VERTHYS_EXTENT_INDEX_AAD,
                                       strlen(VERTHYS_EXTENT_INDEX_AAD),
                                       frame + VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES,
                                       &ct_len,
                                       frame + VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES +
                                           pt_len + VERTHYS_EXTENT_TAG_BYTES);
            if (r != VERTHYS_OK) break;
            if (ct_len != pt_len + VERTHYS_EXTENT_TAG_BYTES) {
                r = VERTHYS_ERR_INTERNAL;
                break;
            }
        }

        /* 3. 索引帧区整帧覆写 + fsync */
        if (vio_pwrite64(f, region_offset, frame, frame_bytes) != 0) {
            r = VERTHYS_ERR_IO;
            break;
        }
        if (fflush(f) != 0 || _commit(_fileno(f)) != 0) {
            r = VERTHYS_ERR_IO;
            break;
        }
    } while (0);

    verthys_secure_zero(frame, frame_bytes);
    free(frame);
    flatcc_builder_aligned_free(pt);
    return r;
}

VerthysResult verthys_extent_index_parse_unverified(uint8_t *buf, size_t len,
                                                VerthysExtentIndex *idx,
                                                uint64_t *out_nonce_counter)
{
    if (buf == NULL || idx == NULL || out_nonce_counter == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    *out_nonce_counter = 0;

    /* 1. flatcc verifier 结构校验 */
    if (ExtentIndexV3_verify_as_root(buf, len) != flatcc_verify_ok) {
        return VERTHYS_ERR_FORMAT;
    }
    {
        ExtentIndexV3_table_t table = ExtentIndexV3_as_root(buf);
        size_t count;

        if (table == NULL ||
            ExtentIndexV3_magic(table) != VERTHYS_EXTENT_INDEX_MAGIC ||
            ExtentIndexV3_version(table) != VERTHYS_EXTENT_INDEX_VERSION) {
            return VERTHYS_ERR_FORMAT;
        }

        memset(idx, 0, sizeof(*idx));
        idx->txid = ExtentIndexV3_txid(table);
        idx->next_offset = ExtentIndexV3_next_offset(table);

        {
            ExtentEntryV3_vec_t entries = ExtentIndexV3_entries(table);
            count = (entries == NULL) ? 0 : ExtentEntryV3_vec_len(entries);
            if (count > VERTHYS_EXTENT_INDEX_MAX) {
                return VERTHYS_ERR_FORMAT;
            }
            for (size_t i = 0; i < count; i++) {
                ExtentEntryV3_table_t e = ExtentEntryV3_vec_at(entries, i);
                flatbuffers_uint8_vec_t hash_vec;
                flatbuffers_uint8_vec_t nonce_vec;
                VerthysExtent *dst;

                if (e == NULL) {
                    return VERTHYS_ERR_FORMAT;
                }
                hash_vec = ExtentEntryV3_hash(e);
                nonce_vec = ExtentEntryV3_nonce(e);
                if (hash_vec == NULL ||
                    flatbuffers_uint8_vec_len(hash_vec) != VERTHYS_EXTENT_HASH_BYTES ||
                    nonce_vec == NULL ||
                    flatbuffers_uint8_vec_len(nonce_vec) != VERTHYS_EXTENT_NONCE_BYTES) {
                    return VERTHYS_ERR_FORMAT;
                }

                dst = &idx->entries[idx->count];
                memset(dst, 0, sizeof(*dst));
                for (size_t k = 0; k < VERTHYS_EXTENT_HASH_BYTES; k++) {
                    dst->hash[k] = flatbuffers_uint8_vec_at(hash_vec, k);
                }
                for (size_t k = 0; k < VERTHYS_EXTENT_NONCE_BYTES; k++) {
                    dst->nonce[k] = flatbuffers_uint8_vec_at(nonce_vec, k);
                }
                dst->offset = ExtentEntryV3_offset(e);
                dst->size = ExtentEntryV3_size(e);
                dst->plaintext_size = ExtentEntryV3_plaintext_size(e);
                dst->ref_count = ExtentEntryV3_ref_count(e);
                dst->created_txid = ExtentEntryV3_created_txid(e);
                dst->last_ref_txid = ExtentEntryV3_last_ref_txid(e);

                /* 字段一致性校验：密文长度必须 > tag，明文长度自洽，
                 * offset + size 不越过追加游标（防越界读放大）。
                 * 回绕安全分解：朴素 offset+size 比较在 uint64 溢出时
                 * 绕过（如 offset=2^64-100, size=150 回绕为小值）——
                 * 先钳 offset ≤ next_offset（差值不回绕），再以差值
                 * 钳 size，溢出条目必然被拒（纵深防御：索引本体另有
                 * HMAC 认证，此处防御认证密钥泄露/实现缺陷场景） */
                if (dst->size < VERTHYS_EXTENT_TAG_BYTES ||
                    dst->plaintext_size != dst->size - VERTHYS_EXTENT_TAG_BYTES ||
                    dst->offset > idx->next_offset ||
                    dst->size > idx->next_offset - dst->offset) {
                    return VERTHYS_ERR_FORMAT;
                }
                idx->count++;
            }
        }

        *out_nonce_counter = ExtentIndexV3_nonce_counter(table);
    }
    return VERTHYS_OK;
}

VerthysResult verthys_extent_index_load(FILE *f, uint64_t region_offset,
                                    VerthysPartition *part,
                                    VerthysExtentIndex *idx)
{
    uint8_t header[VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES];
    uint8_t *body = NULL;
    uint8_t *pt = NULL;
    uint32_t ct_len;
    size_t body_bytes;
    size_t pt_len;
    VerthysResult r;

    if (f == NULL || part == NULL || idx == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    /* 1. 帧头读取与校验 */
    if (vio_pread64(f, region_offset, header, sizeof(header)) != 0) {
        return VERTHYS_ERR_FORMAT;
    }
    if (get_u32le(header) != VERTHYS_EXTENT_INDEX_MAGIC) {
        return VERTHYS_ERR_FORMAT;
    }
    ct_len = get_u32le(header + 4);
    if (ct_len < VERTHYS_EXTENT_TAG_BYTES ||
        ct_len > VERTHYS_EXTENT_INDEX_REGION_BYTES -
                     VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES -
                     VERTHYS_EXTENT_NONCE_BYTES) {
        return VERTHYS_ERR_FORMAT;
    }

    /* 2. 密文 + nonce 读取 */
    body_bytes = (size_t)ct_len + VERTHYS_EXTENT_NONCE_BYTES;
    body = (uint8_t *)malloc(body_bytes);
    if (body == NULL) return VERTHYS_ERR_INTERNAL;
    if (vio_pread64(f, region_offset + VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES,
                    body, body_bytes) != 0) {
        free(body);
        return VERTHYS_ERR_FORMAT;
    }

    /* 3. AEAD 解密（认证失败 → AUTH） */
    pt = (uint8_t *)malloc(ct_len);  /* ≥ 明文长度 */
    if (pt == NULL) {
        free(body);
        return VERTHYS_ERR_INTERNAL;
    }
    pt_len = ct_len;  /* 容量（in/out）：pt 缓冲容量 = ct_len ≥ 明文长 */
    r = verthys_cng_aead_decrypt(&part->aead,
                               body, ct_len,
                               (const uint8_t *)VERTHYS_EXTENT_INDEX_AAD,
                               strlen(VERTHYS_EXTENT_INDEX_AAD),
                               body + ct_len, pt, &pt_len);
    free(body);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(pt, ct_len);
        free(pt);
        return (r == VERTHYS_ERR_LOCKED) ? VERTHYS_ERR_LOCKED : VERTHYS_ERR_AUTH;
    }
    if (pt_len == 0) {
        verthys_secure_zero(pt, ct_len);
        free(pt);
        return VERTHYS_ERR_FORMAT;
    }

    /* 4. 明文帧解析（★ WP-10 提取：verifier + 字段边界 + 一致性校验，
     *     与 fuzz 共享同一解析路径，杜绝两份逻辑漂移） */
    {
        uint64_t nonce_counter = 0;

        r = verthys_extent_index_parse_unverified(pt, pt_len, idx, &nonce_counter);
        if (r != VERTHYS_OK) {
            verthys_secure_zero(pt, ct_len);
            free(pt);
            return r;
        }

        /* 5. 分区 nonce 计数器 restore（E-7 防回退：低于当前值即拒绝） */
        r = verthys_cng_aead_restore_nonce_counter(&part->aead, nonce_counter);
        if (r != VERTHYS_OK) {
            verthys_secure_zero(pt, ct_len);
            free(pt);
            return r;
        }
    }

    verthys_secure_zero(pt, ct_len);
    free(pt);
    return VERTHYS_OK;
}
