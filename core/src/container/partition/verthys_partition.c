/*
 * verthys_partition.c — V3 分区管理实现
 *
 * 复用资产：
 *   - verthys_crypto_cng.c（CNG 内核 AEAD：import/encrypt/decrypt/restore）
 *   - verthys_io.c（vio_pread64/vio_pwrite64 统一 64 位偏移 I/O）
 *   - schema/partition.fbs（flatcc codegen：partition_builder/verifier.h）
 *
 * 密钥生命周期纪律（红线级）：
 *   create：随机密钥 → 先包装持久化（wrapping key 内核态加密）→ 再
 *   import（import 内部 SecureZeroMemory 清零明文密钥）——用户态明文
 *   窗口仅限本函数栈帧。
 *   load：解包 → import（清零）→ restore nonce 计数器。
 */
/*
 * flatcc 头必须在 verthys_partition.h（经 verthys_crypto_cng.h 引入 Windows SDK
 * 头，定义 NTDDI_VERSION）之前处理：pstdint.h 在 NTDDI_VERSION 已定义时
 * 走全量自定义 typedef 路径，与 MSVC <stdint.h> 的 int_fast16_t 等 fast
 * 类型冲突（C2371）。先处理 flatcc → pstdint 委托给真实 <stdint.h> 并落
 * _PSTDINT_H_INCLUDED 守卫，后续 Windows 头不再触发该路径。
 */
#include "partition_builder.h"
#include "partition_verifier.h"

#include "verthys_partition.h"
#include "verthys_io.h"
#include "verthys_crypto.h"     /* verthys_random_bytes */
#include "verthys_internal.h"   /* verthys_secure_zero（secure_mem.c 实现声明） */

#include <io.h>               /* _commit / _fileno */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>            /* 调试诊断（fprintf） */

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

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

/* 分区数据 AAD：partition_id(4LE) ‖ txid(8LE)（同 verthys_partition.h 注记） */
#define VERTHYS_PARTITION_DATA_AAD_BYTES 12u

static void build_data_aad(uint8_t aad[VERTHYS_PARTITION_DATA_AAD_BYTES],
                           VerthysPartitionId id, uint64_t txid)
{
    put_u32le(aad, id);
    put_u64le(aad + 4, txid);
}

/* ---------- 分区生命周期 ---------- */

VerthysResult verthys_partition_create(VerthysPartition *p,
                                   VerthysPartitionId id,
                                   VerthysPartitionType type,
                                   uint64_t offset, uint64_t size,
                                   uint64_t created_txid,
                                   VerthysCngAead *wrapping)
{
    if (p == NULL || wrapping == NULL) return VERTHYS_ERR_INVALID;
    if (size == 0) return VERTHYS_ERR_INVALID;
    if ((unsigned)type > (unsigned)VERTHYS_PARTITION_WAL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(wrapping)) return VERTHYS_ERR_LOCKED;

    memset(p, 0, sizeof(*p));

    VerthysResult r;
    uint8_t key[VERTHYS_PARTITION_KEY_BYTES];
    uint8_t key_id[VERTHYS_PARTITION_KEY_ID_BYTES];
    uint8_t wrapped[VERTHYS_PARTITION_WRAPPED_BYTES];
    size_t wrapped_len = VERTHYS_PARTITION_WRAPPED_BYTES;  /* 容量（in/out） */
    uint8_t wrap_nonce[VERTHYS_PARTITION_NONCE_BYTES];

    verthys_random_bytes(key, sizeof(key));
    verthys_random_bytes(key_id, sizeof(key_id));

    /* 1. 先包装持久化形态（wrapping key 内核态加密，域分离 AAD） */
    r = verthys_cng_aead_encrypt(wrapping,
                               key, sizeof(key),
                               (const uint8_t *)VERTHYS_PARTITION_WRAP_AAD,
                               strlen(VERTHYS_PARTITION_WRAP_AAD),
                               wrapped, &wrapped_len, wrap_nonce);
    if (r != VERTHYS_OK) goto fail;
    if (wrapped_len != VERTHYS_PARTITION_WRAPPED_BYTES) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail;
    }

    /* 2. CNG 内核导入（import 内部清零明文密钥） */
    r = verthys_cng_aead_init(&p->aead);
    if (r != VERTHYS_OK) goto fail;
    r = verthys_cng_aead_import_key(&p->aead, key, key_id);
    if (r != VERTHYS_OK) goto fail;

    /* 3. 内存态登记 */
    p->id            = id;
    p->type          = type;
    p->offset        = offset;
    p->size          = size;
    p->used          = 0;
    p->created_txid  = created_txid;
    memcpy(p->key_id, key_id, sizeof(p->key_id));
    memcpy(p->wrapped_key, wrapped, VERTHYS_PARTITION_WRAPPED_BYTES);
    p->wrapped_key_len = VERTHYS_PARTITION_WRAPPED_BYTES;
    memcpy(p->wrap_nonce, wrap_nonce, VERTHYS_PARTITION_NONCE_BYTES);

    verthys_secure_zero(key, sizeof(key));
    verthys_secure_zero(key_id, sizeof(key_id));
    verthys_secure_zero(wrapped, sizeof(wrapped));
    return VERTHYS_OK;

fail:
    verthys_secure_zero(key, sizeof(key));
    verthys_secure_zero(key_id, sizeof(key_id));
    verthys_secure_zero(wrapped, sizeof(wrapped));
    verthys_cng_aead_destroy(&p->aead);
    memset(p, 0, sizeof(*p));
    return r;
}

VerthysResult verthys_partition_load(VerthysPartition *p,
                                 VerthysPartitionId id,
                                 VerthysPartitionType type,
                                 uint64_t offset, uint64_t size,
                                 uint64_t used,
                                 const uint8_t key_id[VERTHYS_PARTITION_KEY_ID_BYTES],
                                 uint64_t nonce_counter,
                                 uint64_t created_txid,
                                 const uint8_t *wrapped_key, size_t wrapped_key_len,
                                 const uint8_t wrap_nonce[VERTHYS_PARTITION_NONCE_BYTES],
                                 VerthysCngAead *wrapping)
{
    if (p == NULL || wrapping == NULL || key_id == NULL ||
        wrapped_key == NULL || wrap_nonce == NULL) return VERTHYS_ERR_INVALID;
    if (size == 0 || used > size) return VERTHYS_ERR_INVALID;
    if ((unsigned)type > (unsigned)VERTHYS_PARTITION_WAL) return VERTHYS_ERR_INVALID;
    if (wrapped_key_len != VERTHYS_PARTITION_WRAPPED_BYTES) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(wrapping)) return VERTHYS_ERR_LOCKED;

    memset(p, 0, sizeof(*p));

    VerthysResult r;
    uint8_t key[VERTHYS_PARTITION_KEY_BYTES];
    size_t key_len = VERTHYS_PARTITION_KEY_BYTES;  /* 容量（in/out） */

    /* 1. 解包分区密钥（认证失败 → AUTH，密钥缓冲清零） */
    r = verthys_cng_aead_decrypt(wrapping,
                               wrapped_key, wrapped_key_len,
                               (const uint8_t *)VERTHYS_PARTITION_WRAP_AAD,
                               strlen(VERTHYS_PARTITION_WRAP_AAD),
                               wrap_nonce,
                               key, &key_len);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key, sizeof(key));
        return (r == VERTHYS_ERR_LOCKED) ? VERTHYS_ERR_LOCKED : VERTHYS_ERR_AUTH;
    }
    if (key_len != VERTHYS_PARTITION_KEY_BYTES) {
        verthys_secure_zero(key, sizeof(key));
        return VERTHYS_ERR_FORMAT;
    }

    /* 2. CNG 内核导入（清零明文密钥） */
    r = verthys_cng_aead_init(&p->aead);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key, sizeof(key));
        return r;
    }
    r = verthys_cng_aead_import_key(&p->aead, key, key_id);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key, sizeof(key));
        return r;
    }

    /* 3. nonce 计数器恢复（防回退） */
    r = verthys_cng_aead_restore_nonce_counter(&p->aead, nonce_counter);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key, sizeof(key));
        verthys_cng_aead_destroy(&p->aead);
        memset(p, 0, sizeof(*p));
        return r;
    }

    /* 4. 内存态登记 */
    p->id            = id;
    p->type          = type;
    p->offset        = offset;
    p->size          = size;
    p->used          = used;
    p->created_txid  = created_txid;
    memcpy(p->key_id, key_id, sizeof(p->key_id));
    memcpy(p->wrapped_key, wrapped_key, wrapped_key_len);
    p->wrapped_key_len = wrapped_key_len;
    memcpy(p->wrap_nonce, wrap_nonce, VERTHYS_PARTITION_NONCE_BYTES);

    verthys_secure_zero(key, sizeof(key));
    return VERTHYS_OK;
}

VerthysResult verthys_partition_destroy(VerthysPartition *p)
{
    if (p == NULL) return VERTHYS_OK;
    verthys_cng_aead_destroy(&p->aead);
    memset(p, 0, sizeof(*p));
    return VERTHYS_OK;
}

/* ---------- 分区数据 AEAD ---------- */

VerthysResult verthys_partition_encrypt(VerthysPartition *p, uint64_t txid,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *ct, size_t *ct_len,
                                    uint8_t nonce_out[VERTHYS_PARTITION_NONCE_BYTES])
{
    if (p == NULL || ct == NULL || ct_len == NULL || nonce_out == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (pt == NULL && pt_len != 0) return VERTHYS_ERR_INVALID;

    uint8_t aad[VERTHYS_PARTITION_DATA_AAD_BYTES];
    build_data_aad(aad, p->id, txid);
    return verthys_cng_aead_encrypt(&p->aead, pt, pt_len,
                                  aad, sizeof(aad),
                                  ct, ct_len, nonce_out);
}

VerthysResult verthys_partition_decrypt(VerthysPartition *p, uint64_t txid,
                                    const uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES],
                                    const uint8_t *ct, size_t ct_len,
                                    uint8_t *pt, size_t *pt_len)
{
    if (p == NULL || nonce == NULL || ct == NULL || pt == NULL || pt_len == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (ct_len < VERTHYS_PARTITION_TAG_BYTES) return VERTHYS_ERR_INVALID;

    uint8_t aad[VERTHYS_PARTITION_DATA_AAD_BYTES];
    build_data_aad(aad, p->id, txid);
    return verthys_cng_aead_decrypt(&p->aead, ct, ct_len,
                                  aad, sizeof(aad),
                                  nonce, pt, pt_len);
}

VerthysResult verthys_partition_grow(VerthysPartition *p, uint64_t min_bytes,
                                     uint64_t region_limit)
{
    if (p == NULL || min_bytes == 0) return VERTHYS_ERR_INVALID;

    /* 区域硬上限（该分区区域终点绝对偏移，如其后 audit 分区起点）：
     * 容量不得越过其后分区区域，否则分区写会自重叠破坏布局。
     * 最小需求 size + min_bytes 放不下 → 拒绝且内存态不变
     * （调用方不得误以为 need 已满足后越界写入）。 */
    if (region_limit <= p->offset) return VERTHYS_ERR_RESOURCE_LIMIT;
    uint64_t cap = region_limit - p->offset;
    if (p->size >= cap || min_bytes > cap - p->size) {
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }

    /* 2x 增长策略；不足 min_bytes 时线性补足 */
    uint64_t doubled = p->size * 2;
    if (doubled < p->size) doubled = UINT64_MAX;  /* 溢出守卫 */
    uint64_t linear = p->size + min_bytes;
    if (linear < p->size) linear = UINT64_MAX;    /* 溢出守卫 */

    uint64_t target = (doubled >= linear) ? doubled : linear;
    if (target > cap) target = cap;  /* 2x 目标越界：截断于区域上限 */
    p->size = target;
    return VERTHYS_OK;
}

uint64_t verthys_partition_nonce_counter(const VerthysPartition *p)
{
    if (p == NULL) return 0;
    return verthys_cng_aead_nonce_counter(&p->aead);
}

/* ---------- 分区表 ---------- */

VerthysResult verthys_partition_table_init(VerthysPartitionTable *t, uint64_t txid)
{
    if (t == NULL) return VERTHYS_ERR_INVALID;
    memset(t, 0, sizeof(*t));
    t->txid = txid;
    return VERTHYS_OK;
}

VerthysResult verthys_partition_table_add(VerthysPartitionTable *t,
                                      const VerthysPartition *p)
{
    if (t == NULL || p == NULL) return VERTHYS_ERR_INVALID;

    /* id 冲突优先于容量检查：EXISTS 为更精确的可诊断错误（调用方可
     * 换 id 重试），不因表满而掩盖语义冲突 */
    for (size_t i = 0; i < t->count; i++) {
        if (t->entries[i].id == p->id) return VERTHYS_ERR_EXISTS;
    }
    if (t->count >= VERTHYS_PARTITION_MAX) return VERTHYS_ERR_RESOURCE_LIMIT;
    t->entries[t->count++] = *p;  /* 按值转移句柄归属 */
    return VERTHYS_OK;
}

VerthysResult verthys_partition_table_find(const VerthysPartitionTable *t,
                                       VerthysPartitionId id,
                                       VerthysPartition *out)
{
    if (t == NULL || out == NULL) return VERTHYS_ERR_INVALID;
    for (size_t i = 0; i < t->count; i++) {
        if (t->entries[i].id == id) {
            *out = t->entries[i];
            return VERTHYS_OK;
        }
    }
    return VERTHYS_ERR_NOTFOUND;
}

VerthysResult verthys_partition_table_destroy(VerthysPartitionTable *t)
{
    if (t == NULL) return VERTHYS_OK;
    for (size_t i = 0; i < t->count; i++) {
        verthys_cng_aead_destroy(&t->entries[i].aead);
    }
    memset(t, 0, sizeof(*t));
    return VERTHYS_OK;
}

/*
 * 序列化分区表（flatcc）→ 对齐缓冲出参（flatcc_builder_aligned_free 归还）。
 */
static VerthysResult table_serialize(const VerthysPartitionTable *t,
                                   uint8_t **out_buf, size_t *out_len)
{
    flatcc_builder_t builder;
    uint8_t *buf = NULL;
    size_t size = 0;
    VerthysResult result = VERTHYS_ERR_INTERNAL;

    *out_buf = NULL;
    *out_len = 0;

    if (flatcc_builder_init(&builder) != 0) return VERTHYS_ERR_INTERNAL;

    do {
        if (PartitionTableV3_start_as_root(&builder) != 0) break;
        if (PartitionTableV3_magic_add(&builder, VERTHYS_PARTITION_TABLE_MAGIC) != 0) break;
        if (PartitionTableV3_version_add(&builder, VERTHYS_PARTITION_TABLE_VERSION) != 0) break;
        if (PartitionTableV3_txid_add(&builder, t->txid) != 0) break;

        if (PartitionEntryV3_vec_start(&builder) != 0) break;
        int entries_ok = 1;
        for (size_t i = 0; i < t->count; i++) {
            const VerthysPartition *p = &t->entries[i];
            flatbuffers_uint8_vec_ref_t key_id_ref =
                flatbuffers_uint8_vec_create(&builder, p->key_id,
                                             VERTHYS_PARTITION_KEY_ID_BYTES);
            flatbuffers_uint8_vec_ref_t wrapped_ref =
                flatbuffers_uint8_vec_create(&builder, p->wrapped_key,
                                             VERTHYS_PARTITION_WRAPPED_BYTES);
            flatbuffers_uint8_vec_ref_t wrap_nonce_ref =
                flatbuffers_uint8_vec_create(&builder, p->wrap_nonce,
                                             VERTHYS_PARTITION_NONCE_BYTES);
            if (key_id_ref == 0 || wrapped_ref == 0 || wrap_nonce_ref == 0) {
                entries_ok = 0;
                break;
            }

            PartitionEntryV3_ref_t entry = PartitionEntryV3_create(&builder,
                p->id,
                (PartitionTypeV3_enum_t)p->type,
                p->offset, p->size, p->used,
                key_id_ref,
                verthys_cng_aead_nonce_counter(&p->aead),  /* 持久化 */
                p->created_txid,
                wrapped_ref, wrap_nonce_ref);
            if (entry == 0) {
                entries_ok = 0;
                break;
            }
            /* vec_push 返回 ref_t*（非 NULL=成功，NULL=失败） */
            if (PartitionEntryV3_vec_push(&builder, entry) == NULL) {
                entries_ok = 0;
                break;
            }
        }
        if (!entries_ok) break;
        {
            PartitionEntryV3_vec_ref_t vec = PartitionEntryV3_vec_end(&builder);
            if (vec == 0 || PartitionTableV3_entries_add(&builder, vec) != 0) break;
        }
        if (PartitionTableV3_end_as_root(&builder) == 0) break;

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

VerthysResult verthys_partition_table_save(FILE *f, uint64_t region_offset,
                                       const VerthysPartitionTable *t,
                                       VerthysCngAead *table_aead)
{
    if (f == NULL || t == NULL || table_aead == NULL) return VERTHYS_ERR_INVALID;
    if (t->count > VERTHYS_PARTITION_MAX) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(table_aead)) return VERTHYS_ERR_LOCKED;

    /* 1. flatcc 序列化 */
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    VerthysResult r = table_serialize(t, &pt, &pt_len);
    if (r != VERTHYS_OK) return r;

    /* 2. AEAD 加密（域分离 AAD） */
    uint8_t *frame = NULL;
    size_t frame_bytes = VERTHYS_PARTITION_FRAME_HEADER_BYTES +
                         pt_len + VERTHYS_PARTITION_TAG_BYTES +
                         VERTHYS_PARTITION_NONCE_BYTES;
    if (frame_bytes > VERTHYS_PARTITION_REGION_BYTES) {
        flatcc_builder_aligned_free(pt);
        return VERTHYS_ERR_INVALID;
    }

    frame = (uint8_t *)calloc(1, frame_bytes);
    if (frame == NULL) {
        flatcc_builder_aligned_free(pt);
        return VERTHYS_ERR_INTERNAL;
    }

    do {
        put_u32le(frame, VERTHYS_PARTITION_TABLE_MAGIC);
        put_u32le(frame + 4, (uint32_t)(pt_len + VERTHYS_PARTITION_TAG_BYTES));

        size_t ct_len = pt_len + VERTHYS_PARTITION_TAG_BYTES;  /* 容量（in/out） */
        r = verthys_cng_aead_encrypt(table_aead,
                                   pt, pt_len,
                                   (const uint8_t *)VERTHYS_PARTITION_TABLE_AAD,
                                   strlen(VERTHYS_PARTITION_TABLE_AAD),
                                   frame + VERTHYS_PARTITION_FRAME_HEADER_BYTES,
                                   &ct_len,
                                   frame + VERTHYS_PARTITION_FRAME_HEADER_BYTES +
                                       pt_len + VERTHYS_PARTITION_TAG_BYTES);
        if (r != VERTHYS_OK) break;
        if (ct_len != pt_len + VERTHYS_PARTITION_TAG_BYTES) {
            r = VERTHYS_ERR_INTERNAL;
            break;
        }

        /* 3. 帧写入 + fsync（分区表区整帧落盘） */
        if (vio_pwrite64(f, region_offset, frame, frame_bytes) != 0) {
            r = VERTHYS_ERR_IO;
            break;
        }
        if (fflush(f) != 0 || _commit(_fileno(f)) != 0) {
            r = VERTHYS_ERR_IO;
            break;
        }
    } while (0);

    flatcc_builder_aligned_free(pt);
    verthys_secure_zero(frame, frame_bytes);
    free(frame);
    return r;
}

VerthysResult verthys_partition_table_parse_unverified(
    uint8_t *buf, size_t len,
    uint64_t *out_txid,
    VerthysPartitionEntryRaw out_entries[VERTHYS_PARTITION_MAX],
    size_t *out_count)
{
    if (buf == NULL || out_txid == NULL || out_entries == NULL ||
        out_count == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    *out_count = 0;

    /* 1. flatcc verifier 结构校验 */
    if (PartitionTableV3_verify_as_root(buf, len) != flatcc_verify_ok) {
        return VERTHYS_ERR_FORMAT;
    }
    {
        PartitionTableV3_table_t table = PartitionTableV3_as_root(buf);
        if (table == NULL ||
            PartitionTableV3_magic(table) != VERTHYS_PARTITION_TABLE_MAGIC ||
            PartitionTableV3_version(table) != VERTHYS_PARTITION_TABLE_VERSION) {
            return VERTHYS_ERR_FORMAT;
        }
        *out_txid = PartitionTableV3_txid(table);

        PartitionEntryV3_vec_t entries = PartitionTableV3_entries(table);
        size_t count = (entries == NULL) ? 0 : PartitionEntryV3_vec_len(entries);
        if (count > VERTHYS_PARTITION_MAX) {
            return VERTHYS_ERR_FORMAT;
        }

        /* 2. 逐条目向量长度严格校验 + 字段提取（无 CNG 依赖） */
        for (size_t i = 0; i < count; i++) {
            PartitionEntryV3_table_t e = PartitionEntryV3_vec_at(entries, i);
            flatbuffers_uint8_vec_t key_id_vec;
            flatbuffers_uint8_vec_t wrapped_vec;
            flatbuffers_uint8_vec_t wrap_nonce_vec;
            VerthysPartitionEntryRaw *dst;

            if (e == NULL) return VERTHYS_ERR_FORMAT;
            key_id_vec = PartitionEntryV3_key_id(e);
            wrapped_vec = PartitionEntryV3_wrapped_key(e);
            wrap_nonce_vec = PartitionEntryV3_wrap_nonce(e);
            if (key_id_vec == NULL ||
                flatbuffers_uint8_vec_len(key_id_vec) != VERTHYS_PARTITION_KEY_ID_BYTES ||
                wrapped_vec == NULL ||
                flatbuffers_uint8_vec_len(wrapped_vec) != VERTHYS_PARTITION_WRAPPED_BYTES ||
                wrap_nonce_vec == NULL ||
                flatbuffers_uint8_vec_len(wrap_nonce_vec) != VERTHYS_PARTITION_NONCE_BYTES) {
                return VERTHYS_ERR_FORMAT;
            }

            dst = &out_entries[i];
            memset(dst, 0, sizeof(*dst));
            dst->id = PartitionEntryV3_id(e);
            dst->type = (VerthysPartitionType)PartitionEntryV3_type(e);
            dst->offset = PartitionEntryV3_offset(e);
            dst->size = PartitionEntryV3_size(e);
            dst->used = PartitionEntryV3_used(e);
            dst->created_txid = PartitionEntryV3_created_txid(e);
            dst->nonce_counter = PartitionEntryV3_nonce_counter(e);
            for (size_t k = 0; k < VERTHYS_PARTITION_KEY_ID_BYTES; k++) {
                dst->key_id[k] = flatbuffers_uint8_vec_at(key_id_vec, k);
            }
            for (size_t k = 0; k < VERTHYS_PARTITION_WRAPPED_BYTES; k++) {
                dst->wrapped_key[k] = flatbuffers_uint8_vec_at(wrapped_vec, k);
            }
            for (size_t k = 0; k < VERTHYS_PARTITION_NONCE_BYTES; k++) {
                dst->wrap_nonce[k] = flatbuffers_uint8_vec_at(wrap_nonce_vec, k);
            }
        }
        *out_count = count;
    }
    return VERTHYS_OK;
}

VerthysResult verthys_partition_table_load(FILE *f, uint64_t region_offset,
                                       VerthysCngAead *table_aead,
                                       VerthysCngAead *wrapping_aead,
                                       VerthysPartitionTable *t)
{
    if (f == NULL || table_aead == NULL || wrapping_aead == NULL || t == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (!verthys_cng_aead_is_imported(table_aead) ||
        !verthys_cng_aead_is_imported(wrapping_aead)) {
        return VERTHYS_ERR_LOCKED;
    }
    memset(t, 0, sizeof(*t));

    /* 1. 帧头读取与校验 */
    uint8_t header[VERTHYS_PARTITION_FRAME_HEADER_BYTES];
    if (vio_pread64(f, region_offset, header, sizeof(header)) != 0) {
        return VERTHYS_ERR_FORMAT;
    }
    if (get_u32le(header) != VERTHYS_PARTITION_TABLE_MAGIC) {
        return VERTHYS_ERR_FORMAT;
    }
    uint32_t ct_len = get_u32le(header + 4);
    if (ct_len < VERTHYS_PARTITION_TAG_BYTES ||
        ct_len > VERTHYS_PARTITION_REGION_BYTES -
                     VERTHYS_PARTITION_FRAME_HEADER_BYTES -
                     VERTHYS_PARTITION_NONCE_BYTES) {
        return VERTHYS_ERR_FORMAT;
    }

    /* 2. 密文 + nonce 读取 */
    size_t body_bytes = (size_t)ct_len + VERTHYS_PARTITION_NONCE_BYTES;
    uint8_t *body = (uint8_t *)malloc(body_bytes);
    if (body == NULL) return VERTHYS_ERR_INTERNAL;
    if (vio_pread64(f, region_offset + VERTHYS_PARTITION_FRAME_HEADER_BYTES,
                    body, body_bytes) != 0) {
        free(body);
        return VERTHYS_ERR_FORMAT;
    }
    const uint8_t *nonce = body + ct_len;

    /* 3. AEAD 解密（认证失败 → AUTH） */
    uint8_t *pt = (uint8_t *)malloc(ct_len);  /* ≥ 明文长度 */
    if (pt == NULL) {
        free(body);
        return VERTHYS_ERR_INTERNAL;
    }
    size_t pt_len = ct_len;  /* 容量（in/out）：pt 缓冲容量 = ct_len ≥ 明文长 */
    VerthysResult r = verthys_cng_aead_decrypt(table_aead,
                                           body, ct_len,
                                           (const uint8_t *)VERTHYS_PARTITION_TABLE_AAD,
                                           strlen(VERTHYS_PARTITION_TABLE_AAD),
                                           nonce, pt, &pt_len);
    if (r == VERTHYS_OK && pt_len == 0) r = VERTHYS_ERR_FORMAT;

    /*
     * table_aead 跨会话重导入后
     * 计数器归零——若不按帧 nonce 恢复下限，本会话首次 table_save 将
     * 复用历史 nonce（同密钥 GCM nonce 重用）。帧 nonce 为 12B 大端
     * 计数器（verthys_crypto_cng encode_nonce 约定，高 4 字节恒零）。
     * 恢复值小于当前值（同会话重载场景）时 restore 拒绝，属正常忽略。 */
    if (r == VERTHYS_OK) {
        uint64_t frame_counter =
            ((uint64_t)nonce[4] << 56) | ((uint64_t)nonce[5] << 48) |
            ((uint64_t)nonce[6] << 40) | ((uint64_t)nonce[7] << 32) |
            ((uint64_t)nonce[8] << 24) | ((uint64_t)nonce[9] << 16) |
            ((uint64_t)nonce[10] << 8) | (uint64_t)nonce[11];
        (void)verthys_cng_aead_restore_nonce_counter(
            table_aead, frame_counter + VERTHYS_PARTITION_NONCE_RESTORE_MARGIN);
    }

    free(body);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(pt, ct_len);
        free(pt);
        return (r == VERTHYS_ERR_LOCKED) ? VERTHYS_ERR_LOCKED : VERTHYS_ERR_AUTH;
    }

    /* 4. 明文帧解析（提取：verifier + 字段边界 + 材料提取，
     *     与 fuzz/早期流水线共享同一解析路径，杜绝两份逻辑漂移） */
    {
        uint64_t table_txid = 0;
        VerthysPartitionEntryRaw raw[VERTHYS_PARTITION_MAX];
        size_t raw_count = 0;

        r = verthys_partition_table_parse_unverified(pt, pt_len, &table_txid,
                                                   raw, &raw_count);
        if (r != VERTHYS_OK) {
            verthys_secure_zero(pt, ct_len);
            free(pt);
            return r;
        }
        t->txid = table_txid;

        /* 5. 逐条目加载（解包密钥 + CNG 导入 + nonce restore） */
        for (size_t i = 0; i < raw_count; i++) {
            const VerthysPartitionEntryRaw *src = &raw[i];
            r = verthys_partition_load(&t->entries[t->count],
                                     src->id,
                                     src->type,
                                     src->offset,
                                     src->size,
                                     src->used,
                                     src->key_id,
                                     src->nonce_counter,
                                     src->created_txid,
                                     src->wrapped_key,
                                     VERTHYS_PARTITION_WRAPPED_BYTES,
                                     src->wrap_nonce,
                                     wrapping_aead);
            if (r != VERTHYS_OK) break;
            t->count++;
        }
        /* raw 材料含 wrapped 密钥副本，作用域结束前清零（红线：明文/材料
         * 不出栈帧存续期；wrapped 非明文但保持同等纪律） */
        verthys_secure_zero(raw, sizeof(raw));
    }

    verthys_secure_zero(pt, ct_len);
    free(pt);
    if (r != VERTHYS_OK) {
        verthys_partition_table_destroy(t);
    }
    return r;
}
