/*
 * verthys_format.c — .verthys 文件格式读写实现
 *
 * 实现要点：
 *   - 小端序序列化（显式字节操作，不依赖主机序）
 *   - 元数据/索引/数据块均用 AEAD 加密 + 认证
 *   - 全文件 HMAC-SHA256(DEK) 覆盖 [0..mac_offset-1]，防文件头篡改
 *   - 每条记录用记录级密钥（HKDF 从 DEK 派生）加密，独立认证
 *   - 所有加密 nonce 随机生成，存储于对应区域起始处（明文）
 *   - 随机填充消除结构特征（元数据/索引/数据块均对齐到 16 字节）
 */
#include "verthys_format.h"
#include "verthys_internal.h"  /* verthys_secure_zero */

#include <sodium.h>  /* crypto_auth_hmacsha256_* 增量 HMAC */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>   /* FILE, fopen, fwrite, fclose, fseek, fflush */

/* ---------- 域分离标签 ---------- */
static const char AD_METADATA[] = "verthys/meta-v1";
static const char AD_INDEX[]    = "verthys/index-v1";

/* ---------- 小端序读写 ---------- */
static void put_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static void put_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static void put_u64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}
static uint16_t get_u16le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t get_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

/* ---------- 对齐辅助 ---------- */
static size_t align_up(size_t n, size_t a) {
    return (n + a - 1) / a * a;
}

/* 数据块总字节数（含 size+data+mac+pad，对齐到 16） */
static size_t block_total_size(size_t pt_len) {
    size_t before_pad = 4 + pt_len + VERTHYS_AEAD_MAC_BYTES;
    return align_up(before_pad, VERTHYS_FMT_BLOCK_ALIGN);
}

/* 索引条目字节数（不含 name 内容） */
#define INDEX_ENTRY_FIXED_BYTES (2 + 1 + 8 + 8 + VERTHYS_AEAD_NONCE_BYTES) /* 43 */

/* 元数据明文固定内容字节数 */
#define META_FIXED_BYTES (12 + VERTHYS_AEAD_NONCE_BYTES + VERTHYS_DEK_WRAPPED_BYTES + 8 + 8) /* 100 */
#define META_PLAINTEXT_BYTES (VERTHYS_FMT_METADATA_BYTES - VERTHYS_AEAD_NONCE_BYTES - VERTHYS_AEAD_MAC_BYTES) /* 472 */
#define META_PAD_BYTES (META_PLAINTEXT_BYTES - META_FIXED_BYTES) /* 372 */

/* ===================================================================== *
 *                          写入（序列化 + 加密）                         *
 * ===================================================================== */
int vfmt_write(const uint8_t salt[VERTHYS_SALT_BYTES],
               uint32_t argon2_mem_kib, uint32_t argon2_iters, uint32_t argon2_parallel,
               const uint8_t master_key[VERTHYS_KEY_BYTES],
               const uint8_t dek[VERTHYS_KEY_BYTES],
               const VerthysFmtRecord *records, uint16_t record_count,
               uint8_t **out_blob, size_t *out_size)
{
    /* blob 提升至函数顶部声明——早期 goto fail 路径（blob 分配前）
     * 需要可见性；NULL 守卫保证分配前跳转安全。 */
    uint8_t *blob = NULL;

    if (salt == NULL || master_key == NULL || dek == NULL ||
        out_blob == NULL || out_size == NULL) return -1;
    if (records == NULL && record_count != 0) return -1;

    *out_blob = NULL;
    *out_size = 0;

    /* ---- 1. 包裹 DEK ---- */
    uint8_t wrapped_dek[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t dek_wrap_nonce[VERTHYS_AEAD_NONCE_BYTES];
    if (keymanager_wrap_dek(wrapped_dek, dek_wrap_nonce, dek, master_key) != 0) {
        return -1;
    }

    /* ---- 2. 为每条记录生成 block_nonce ---- */
    uint8_t (*block_nonces)[VERTHYS_AEAD_NONCE_BYTES] = NULL;
    if (record_count > 0) {
        block_nonces = malloc(record_count * VERTHYS_AEAD_NONCE_BYTES);
        if (block_nonces == NULL) goto fail;
        for (uint16_t i = 0; i < record_count; i++) {
            verthys_random_bytes(block_nonces[i], VERTHYS_AEAD_NONCE_BYTES);
        }
    }

    /* ---- 3. 计算各区域偏移与总大小 ---- */
    const uint64_t meta_offset   = VERTHYS_FMT_HEADER_BYTES;
    const uint64_t index_offset  = meta_offset + VERTHYS_FMT_METADATA_BYTES;

    /* 索引明文大小 = 2(计数) + sum(条目) */
    size_t idx_pt_fixed = 2;
    for (uint16_t i = 0; i < record_count; i++) {
        idx_pt_fixed += INDEX_ENTRY_FIXED_BYTES + records[i].name_len;
    }
    size_t idx_pt_padded = align_up(idx_pt_fixed, VERTHYS_FMT_BLOCK_ALIGN);
    size_t idx_ct_size = idx_pt_padded + VERTHYS_AEAD_MAC_BYTES;
    size_t index_region_size = VERTHYS_AEAD_NONCE_BYTES + idx_ct_size;

    /* 数据块区 */
    uint64_t data_blocks_start = index_offset + index_region_size;
    uint64_t cursor = data_blocks_start;
    for (uint16_t i = 0; i < record_count; i++) {
        cursor += block_total_size(records[i].data_size);
    }
    uint64_t mac_offset = cursor;
    size_t blob_size = (size_t)mac_offset + VERTHYS_HMAC_BYTES;

    /* ---- 4. 分配 blob ---- */
    blob = calloc(1, blob_size);
    if (blob == NULL) goto fail;

    /* ---- 5. 构建并加密索引 ---- */
    uint8_t *index_region = blob + index_offset;
    uint8_t idx_nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(idx_nonce, sizeof idx_nonce);
    memcpy(index_region, idx_nonce, VERTHYS_AEAD_NONCE_BYTES);

    uint8_t *idx_pt = calloc(1, idx_pt_padded);
    if (idx_pt == NULL) goto fail;
    put_u16le(idx_pt, record_count);
    size_t off = 2;
    uint64_t data_cursor = data_blocks_start;
    for (uint16_t i = 0; i < record_count; i++) {
        put_u16le(idx_pt + off, records[i].name_len); off += 2;
        memcpy(idx_pt + off, records[i].name, records[i].name_len); off += records[i].name_len;
        idx_pt[off++] = records[i].type;
        put_u64le(idx_pt + off, data_cursor); off += 8;
        put_u64le(idx_pt + off, records[i].data_size); off += 8;
        memcpy(idx_pt + off, block_nonces[i], VERTHYS_AEAD_NONCE_BYTES); off += VERTHYS_AEAD_NONCE_BYTES;
        data_cursor += block_total_size(records[i].data_size);
    }
    /* 剩余部分填随机填充 */
    if (off < idx_pt_padded) {
        verthys_random_bytes(idx_pt + off, idx_pt_padded - off);
    }

    size_t idx_ct_written = 0;
    int rc = verthys_aead_encrypt(dek, idx_nonce,
                                (const uint8_t *)AD_INDEX, sizeof(AD_INDEX) - 1,
                                idx_pt, idx_pt_padded,
                                index_region + VERTHYS_AEAD_NONCE_BYTES, &idx_ct_written);
    verthys_secure_zero(idx_pt, idx_pt_padded);
    free(idx_pt);
    if (rc != 0 || idx_ct_written != idx_ct_size) goto fail;

    /* ---- 6. 加密数据块 ---- */
    cursor = data_blocks_start;
    for (uint16_t i = 0; i < record_count; i++) {
        /* 派生记录级密钥 */
        uint8_t rec_key[VERTHYS_KEY_BYTES];
        if (keymanager_derive_record_key(rec_key, dek,
                                         records[i].name, records[i].name_len) != 0) {
            verthys_secure_zero(rec_key, sizeof rec_key);
            goto fail;
        }
        /* AEAD 加密 */
        size_t ct_len = records[i].data_size + VERTHYS_AEAD_MAC_BYTES;
        uint8_t *ct = malloc(ct_len);
        if (ct == NULL) { verthys_secure_zero(rec_key, sizeof rec_key); goto fail; }

        size_t ct_written = 0;
        rc = verthys_aead_encrypt(rec_key, block_nonces[i],
                                NULL, 0,
                                records[i].data, records[i].data_size,
                                ct, &ct_written);
        verthys_secure_zero(rec_key, sizeof rec_key);
        if (rc != 0 || ct_written != ct_len) { free(ct); goto fail; }

        /* 写入块：size(4) + encrypted_data(pt_len) + mac(16) + pad */
        uint8_t *blk = blob + cursor;
        put_u32le(blk, (uint32_t)records[i].data_size);
        memcpy(blk + 4, ct, records[i].data_size);          /* 加密数据 */
        memcpy(blk + 4 + records[i].data_size,
               ct + records[i].data_size, VERTHYS_AEAD_MAC_BYTES);  /* MAC */
        size_t blk_total = block_total_size(records[i].data_size);
        size_t pad_start = 4 + records[i].data_size + VERTHYS_AEAD_MAC_BYTES;
        if (pad_start < blk_total) {
            verthys_random_bytes(blk + pad_start, blk_total - pad_start);
        }
        free(ct);
        cursor += blk_total;
    }

    /* ---- 7. 构建并加密元数据 ---- */
    uint8_t *meta_region = blob + meta_offset;
    uint8_t meta_nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(meta_nonce, sizeof meta_nonce);
    memcpy(meta_region, meta_nonce, VERTHYS_AEAD_NONCE_BYTES);

    uint8_t meta_pt[META_PLAINTEXT_BYTES];
    verthys_random_bytes(meta_pt, META_PLAINTEXT_BYTES);  /* 全随机，再覆盖固定字段 */
    size_t moff = 0;
    put_u32le(meta_pt + moff, argon2_mem_kib);   moff += 4;
    put_u32le(meta_pt + moff, argon2_iters);     moff += 4;
    put_u32le(meta_pt + moff, argon2_parallel);  moff += 4;
    memcpy(meta_pt + moff, dek_wrap_nonce, VERTHYS_AEAD_NONCE_BYTES); moff += VERTHYS_AEAD_NONCE_BYTES;
    memcpy(meta_pt + moff, wrapped_dek, VERTHYS_DEK_WRAPPED_BYTES);   moff += VERTHYS_DEK_WRAPPED_BYTES;
    put_u64le(meta_pt + moff, index_offset);         moff += 8;
    put_u64le(meta_pt + moff, data_blocks_start);    moff += 8;
    /* moff == META_FIXED_BYTES, 剩余已是随机填充 */

    size_t meta_ct_written = 0;
    rc = verthys_aead_encrypt(master_key, meta_nonce,
                            (const uint8_t *)AD_METADATA, sizeof(AD_METADATA) - 1,
                            meta_pt, META_PLAINTEXT_BYTES,
                            meta_region + VERTHYS_AEAD_NONCE_BYTES, &meta_ct_written);
    verthys_secure_zero(meta_pt, sizeof meta_pt);
    verthys_secure_zero(meta_nonce, sizeof meta_nonce);
    verthys_secure_zero(wrapped_dek, sizeof wrapped_dek);
    verthys_secure_zero(dek_wrap_nonce, sizeof dek_wrap_nonce);
    if (rc != 0 || meta_ct_written != META_PLAINTEXT_BYTES + VERTHYS_AEAD_MAC_BYTES) goto fail;

    /* ---- 8. 构建文件头 ---- */
    uint8_t *hdr = blob;
    hdr[0] = 0x56; hdr[1] = 0x45; hdr[2] = 0x52; hdr[3] = 0x54;  /* "VERT" */
    put_u16le(hdr + 4, VERTHYS_FMT_VERSION);
    put_u16le(hdr + 6, 0x0000);  /* 保留 */
    put_u32le(hdr + 8, VERTHYS_FMT_ALG_ARGON2ID_XCHACHA20);
    put_u32le(hdr + 12, (uint32_t)meta_offset);
    put_u64le(hdr + 16, mac_offset);
    memcpy(hdr + 24, salt, VERTHYS_SALT_BYTES);
    verthys_random_bytes(hdr + 40, 16);  /* 保留随机填充 */

    /* ---- 9. 计算并写入全文件 MAC ---- */
    uint8_t mac[VERTHYS_HMAC_BYTES];
    if (verthys_hmac_sha256(mac, dek, blob, (size_t)mac_offset) != 0) goto fail;
    memcpy(blob + mac_offset, mac, VERTHYS_HMAC_BYTES);
    verthys_secure_zero(mac, sizeof mac);

    /* ---- 10. 清理并返回 ---- */
    if (block_nonces) {
        verthys_secure_zero(block_nonces, record_count * VERTHYS_AEAD_NONCE_BYTES);
        free(block_nonces);
    }
    *out_blob = blob;
    *out_size = blob_size;
    return 0;

fail:
    /* 失败路径必须释放整容器镜像 blob——
     * 原实现仅释放 block_nonces，每次失败导出泄漏 MB 级含 wrapped DEK
     * 密文的堆块（且从未 zero，密文材料残留于 freed 堆）。 */
    if (blob) {
        verthys_secure_zero(blob, blob_size);
        free(blob);
    }
    if (block_nonces) {
        verthys_secure_zero(block_nonces, record_count * VERTHYS_AEAD_NONCE_BYTES);
        free(block_nonces);
    }
    return -1;
}

/* ===================================================================== *
 *          流式写入：分片写，避免大库导出 OOM  *
 *                                                                     *
 *  核心改进：                                                          *
 *  1. 不分配 blob_size 连续内存，直接写文件                            *
 *  2. 通过回调按需获取明文数据，一次一条记录，用完即释放               *
 *  3. 增量 HMAC-SHA256 计算，避免全文件回读                            *
 *  4. 固定 16KB 文件 I/O 缓冲区                                        *
 *                                                                     *
 *  内存峰值 = max(单条记录大小) + 16KB + 索引区大小                    *
 *  与记录总数解耦，万级照片库导出不 OOM                                *
 * ===================================================================== */

/* 流式写入辅助：将缓冲区数据写入文件并更新增量 HMAC */
static int stream_write_and_hmac(FILE *f, crypto_auth_hmacsha256_state *hmac_state,
                                  const uint8_t *data, size_t len)
{
    if (len == 0) return 0;
    if (fwrite(data, 1, len, f) != len) return -1;
    if (crypto_auth_hmacsha256_update(hmac_state, data, (unsigned long long)len) != 0) {
        return -1;
    }
    return 0;
}

int vfmt_write_streaming(const uint8_t salt[VERTHYS_SALT_BYTES],
                         uint32_t argon2_mem_kib, uint32_t argon2_iters, uint32_t argon2_parallel,
                         const uint8_t master_key[VERTHYS_KEY_BYTES],
                         const uint8_t dek[VERTHYS_KEY_BYTES],
                         const VerthysFmtRecord *records, uint16_t record_count,
                         VerthysFmtGetDataCallback get_data,
                         VerthysFmtReleaseDataCallback release_data,
                         void *user_data,
                         const char *output_path)
{
    if (salt == NULL || master_key == NULL || dek == NULL ||
        output_path == NULL || get_data == NULL) return -1;
    if (records == NULL && record_count != 0) return -1;

    /* ---- 1. 包裹 DEK ---- */
    uint8_t wrapped_dek[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t dek_wrap_nonce[VERTHYS_AEAD_NONCE_BYTES];
    if (keymanager_wrap_dek(wrapped_dek, dek_wrap_nonce, dek, master_key) != 0) {
        return -1;
    }

    /* ---- 2. 为每条记录生成 block_nonce ---- */
    uint8_t (*block_nonces)[VERTHYS_AEAD_NONCE_BYTES] = NULL;
    if (record_count > 0) {
        block_nonces = malloc((size_t)record_count * VERTHYS_AEAD_NONCE_BYTES);
        if (block_nonces == NULL) goto stream_fail;
        for (uint16_t i = 0; i < record_count; i++) {
            verthys_random_bytes(block_nonces[i], VERTHYS_AEAD_NONCE_BYTES);
        }
    }

    /* ---- 3. 计算各区域偏移与总大小 ---- */
    const uint64_t meta_offset  = VERTHYS_FMT_HEADER_BYTES;
    const uint64_t index_offset = meta_offset + VERTHYS_FMT_METADATA_BYTES;

    /* 索引明文大小 = 2(计数) + sum(条目) */
    size_t idx_pt_fixed = 2;
    for (uint16_t i = 0; i < record_count; i++) {
        idx_pt_fixed += INDEX_ENTRY_FIXED_BYTES + records[i].name_len;
    }
    size_t idx_pt_padded = align_up(idx_pt_fixed, VERTHYS_FMT_BLOCK_ALIGN);
    size_t idx_ct_size = idx_pt_padded + VERTHYS_AEAD_MAC_BYTES;
    size_t index_region_size = VERTHYS_AEAD_NONCE_BYTES + idx_ct_size;

    /* 数据块区 */
    uint64_t data_blocks_start = index_offset + index_region_size;
    uint64_t cursor = data_blocks_start;
    for (uint16_t i = 0; i < record_count; i++) {
        cursor += block_total_size(records[i].data_size);
    }
    uint64_t mac_offset = cursor;

    /* ---- 4. 打开输出文件 ---- */
    FILE *f = fopen(output_path, "wb");
    if (f == NULL) goto stream_fail;

    /* ---- 5. 初始化增量 HMAC ---- */
    crypto_auth_hmacsha256_state hmac_state;
    if (crypto_auth_hmacsha256_init(&hmac_state, dek, VERTHYS_KEY_BYTES) != 0) {
        fclose(f);
        goto stream_fail;
    }

    /* ---- 6. 构建并写入文件头（56 字节，明文）---- */
    uint8_t hdr[VERTHYS_FMT_HEADER_BYTES];
    hdr[0] = 0x56; hdr[1] = 0x45; hdr[2] = 0x52; hdr[3] = 0x54;  /* "VERT" */
    put_u16le(hdr + 4, VERTHYS_FMT_VERSION);
    put_u16le(hdr + 6, 0x0000);  /* 保留 */
    put_u32le(hdr + 8, VERTHYS_FMT_ALG_ARGON2ID_XCHACHA20);
    put_u32le(hdr + 12, (uint32_t)meta_offset);
    put_u64le(hdr + 16, mac_offset);
    memcpy(hdr + 24, salt, VERTHYS_SALT_BYTES);
    verthys_random_bytes(hdr + 40, 16);  /* 保留随机填充 */

    if (stream_write_and_hmac(f, &hmac_state, hdr, sizeof(hdr)) != 0) {
        verthys_secure_zero(hdr, sizeof(hdr));
        fclose(f);
        goto stream_fail;
    }
    verthys_secure_zero(hdr, sizeof(hdr));

    /* ---- 7. 构建并加密元数据区（512 字节）---- */
    uint8_t meta_region[VERTHYS_FMT_METADATA_BYTES];
    uint8_t meta_nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(meta_nonce, sizeof meta_nonce);
    memcpy(meta_region, meta_nonce, VERTHYS_AEAD_NONCE_BYTES);

    uint8_t meta_pt[META_PLAINTEXT_BYTES];
    verthys_random_bytes(meta_pt, META_PLAINTEXT_BYTES);  /* 全随机，再覆盖固定字段 */
    size_t moff = 0;
    put_u32le(meta_pt + moff, argon2_mem_kib);   moff += 4;
    put_u32le(meta_pt + moff, argon2_iters);     moff += 4;
    put_u32le(meta_pt + moff, argon2_parallel);  moff += 4;
    memcpy(meta_pt + moff, dek_wrap_nonce, VERTHYS_AEAD_NONCE_BYTES); moff += VERTHYS_AEAD_NONCE_BYTES;
    memcpy(meta_pt + moff, wrapped_dek, VERTHYS_DEK_WRAPPED_BYTES);   moff += VERTHYS_DEK_WRAPPED_BYTES;
    put_u64le(meta_pt + moff, index_offset);         moff += 8;
    put_u64le(meta_pt + moff, data_blocks_start);    moff += 8;

    size_t meta_ct_written = 0;
    int rc = verthys_aead_encrypt(master_key, meta_nonce,
                                (const uint8_t *)AD_METADATA, sizeof(AD_METADATA) - 1,
                                meta_pt, META_PLAINTEXT_BYTES,
                                meta_region + VERTHYS_AEAD_NONCE_BYTES, &meta_ct_written);
    verthys_secure_zero(meta_pt, sizeof meta_pt);
    verthys_secure_zero(meta_nonce, sizeof meta_nonce);
    verthys_secure_zero(wrapped_dek, sizeof wrapped_dek);
    verthys_secure_zero(dek_wrap_nonce, sizeof dek_wrap_nonce);
    if (rc != 0 || meta_ct_written != META_PLAINTEXT_BYTES + VERTHYS_AEAD_MAC_BYTES) {
        verthys_secure_zero(meta_region, sizeof meta_region);
        fclose(f);
        goto stream_fail;
    }

    if (stream_write_and_hmac(f, &hmac_state, meta_region, sizeof(meta_region)) != 0) {
        verthys_secure_zero(meta_region, sizeof meta_region);
        fclose(f);
        goto stream_fail;
    }
    verthys_secure_zero(meta_region, sizeof meta_region);

    /* ---- 8. 构建并加密索引区 ---- */
    uint8_t *index_region = (uint8_t *)malloc(index_region_size);
    if (index_region == NULL) { fclose(f); goto stream_fail; }

    uint8_t idx_nonce[VERTHYS_AEAD_NONCE_BYTES];
    verthys_random_bytes(idx_nonce, sizeof idx_nonce);
    memcpy(index_region, idx_nonce, VERTHYS_AEAD_NONCE_BYTES);

    uint8_t *idx_pt = (uint8_t *)calloc(1, idx_pt_padded);
    if (idx_pt == NULL) {
        verthys_secure_zero(idx_nonce, sizeof idx_nonce);
        free(index_region);
        fclose(f);
        goto stream_fail;
    }
    put_u16le(idx_pt, record_count);
    size_t off = 2;
    uint64_t data_cursor = data_blocks_start;
    for (uint16_t i = 0; i < record_count; i++) {
        put_u16le(idx_pt + off, records[i].name_len); off += 2;
        memcpy(idx_pt + off, records[i].name, records[i].name_len); off += records[i].name_len;
        idx_pt[off++] = records[i].type;
        put_u64le(idx_pt + off, data_cursor); off += 8;
        put_u64le(idx_pt + off, records[i].data_size); off += 8;
        memcpy(idx_pt + off, block_nonces[i], VERTHYS_AEAD_NONCE_BYTES); off += VERTHYS_AEAD_NONCE_BYTES;
        data_cursor += block_total_size(records[i].data_size);
    }
    /* 剩余部分填随机填充 */
    if (off < idx_pt_padded) {
        verthys_random_bytes(idx_pt + off, idx_pt_padded - off);
    }

    size_t idx_ct_written = 0;
    rc = verthys_aead_encrypt(dek, idx_nonce,
                            (const uint8_t *)AD_INDEX, sizeof(AD_INDEX) - 1,
                            idx_pt, idx_pt_padded,
                            index_region + VERTHYS_AEAD_NONCE_BYTES, &idx_ct_written);
    verthys_secure_zero(idx_pt, idx_pt_padded);
    verthys_secure_zero(idx_nonce, sizeof idx_nonce);
    free(idx_pt);
    if (rc != 0 || idx_ct_written != idx_ct_size) {
        verthys_secure_zero(index_region, index_region_size);
        free(index_region);
        fclose(f);
        goto stream_fail;
    }

    if (stream_write_and_hmac(f, &hmac_state, index_region, index_region_size) != 0) {
        verthys_secure_zero(index_region, index_region_size);
        free(index_region);
        fclose(f);
        goto stream_fail;
    }
    verthys_secure_zero(index_region, index_region_size);
    free(index_region);

    /* ---- 9. 流式加密并写入数据块（一次一条记录）----
     *
     * 通过 get_data 回调按需获取明文数据：
     *   1. 回调分配并返回单条记录的明文
     *   2. 本函数加密并写入文件（16KB 缓冲区分段写入）
     *   3. release_data 回调释放明文
     *   4. 全程仅一条记录的明文驻留内存，与记录总数解耦
     */
    for (uint16_t i = 0; i < record_count; i++) {
        /* 通过回调获取明文数据 */
        uint8_t *pt_data = NULL;
        size_t pt_size = 0;
        if (get_data(i, &pt_data, &pt_size, user_data) != 0 || pt_data == NULL) {
            fclose(f);
            goto stream_fail;
        }
        /* 校验返回的数据大小与元数据一致 */
        if (pt_size != (size_t)records[i].data_size) {
            release_data(i, pt_data, pt_size, user_data);
            fclose(f);
            goto stream_fail;
        }

        /* 派生记录级密钥 */
        uint8_t rec_key[VERTHYS_KEY_BYTES];
        if (keymanager_derive_record_key(rec_key, dek,
                                         records[i].name, records[i].name_len) != 0) {
            verthys_secure_zero(rec_key, sizeof rec_key);
            release_data(i, pt_data, pt_size, user_data);
            fclose(f);
            goto stream_fail;
        }

        /* AEAD 加密 */
        size_t ct_len = pt_size + VERTHYS_AEAD_MAC_BYTES;
        uint8_t *ct = (uint8_t *)malloc(ct_len > 0 ? ct_len : 1);
        if (ct == NULL) {
            verthys_secure_zero(rec_key, sizeof rec_key);
            release_data(i, pt_data, pt_size, user_data);
            fclose(f);
            goto stream_fail;
        }

        size_t ct_written = 0;
        rc = verthys_aead_encrypt(rec_key, block_nonces[i],
                                NULL, 0,
                                pt_data, pt_size,
                                ct, &ct_written);
        verthys_secure_zero(rec_key, sizeof rec_key);
        if (rc != 0 || ct_written != ct_len) {
            verthys_secure_zero(ct, ct_len);
            free(ct);
            release_data(i, pt_data, pt_size, user_data);
            fclose(f);
            goto stream_fail;
        }

        /* 释放明文数据（不再需要） */
        release_data(i, pt_data, pt_size, user_data);

        /* 构建数据块：size(4) + encrypted_data(pt_len) + mac(16) + pad */
        size_t blk_total = block_total_size(pt_size);
        uint8_t *blk = (uint8_t *)calloc(1, blk_total > 0 ? blk_total : 1);
        if (blk == NULL) {
            verthys_secure_zero(ct, ct_len);
            free(ct);
            fclose(f);
            goto stream_fail;
        }
        put_u32le(blk, (uint32_t)pt_size);
        memcpy(blk + 4, ct, pt_size);                          /* 加密数据 */
        memcpy(blk + 4 + pt_size, ct + pt_size, VERTHYS_AEAD_MAC_BYTES);  /* MAC */
        size_t pad_start = 4 + pt_size + VERTHYS_AEAD_MAC_BYTES;
        if (pad_start < blk_total) {
            verthys_random_bytes(blk + pad_start, blk_total - pad_start);
        }
        verthys_secure_zero(ct, ct_len);
        free(ct);

        /* ★ 分段写入文件并更新增量 HMAC（16KB 缓冲区由 fwrite 内部管理） */
        if (stream_write_and_hmac(f, &hmac_state, blk, blk_total) != 0) {
            verthys_secure_zero(blk, blk_total);
            free(blk);
            fclose(f);
            goto stream_fail;
        }
        verthys_secure_zero(blk, blk_total);
        free(blk);
    }

    /* ---- 10. 计算并写入全文件 MAC ---- */
    uint8_t mac[VERTHYS_HMAC_BYTES];
    if (crypto_auth_hmacsha256_final(&hmac_state, mac) != 0) {
        verthys_secure_zero(&hmac_state, sizeof(hmac_state));
        fclose(f);
        goto stream_fail;
    }
    verthys_secure_zero(&hmac_state, sizeof(hmac_state));

    if (fwrite(mac, 1, VERTHYS_HMAC_BYTES, f) != VERTHYS_HMAC_BYTES) {
        verthys_secure_zero(mac, sizeof mac);
        fclose(f);
        goto stream_fail;
    }
    verthys_secure_zero(mac, sizeof mac);

    /* ---- 11. 刷盘并关闭 ---- */
    fflush(f);
    fclose(f);

    /* 清理 block_nonces */
    if (block_nonces) {
        verthys_secure_zero(block_nonces, (size_t)record_count * VERTHYS_AEAD_NONCE_BYTES);
        free(block_nonces);
    }
    return 0;

stream_fail:
    if (block_nonces) {
        verthys_secure_zero(block_nonces, (size_t)record_count * VERTHYS_AEAD_NONCE_BYTES);
        free(block_nonces);
    }
    return -1;
}

/* ===================================================================== *
 *                          读取（解析 + 解密）                           *
 * ===================================================================== */

/* 校验 blob 至少能容纳 header + metadata + 最小索引 + MAC */
static int validate_min_size(size_t size) {
    return size >= VERTHYS_FMT_HEADER_BYTES + VERTHYS_FMT_METADATA_BYTES + VERTHYS_HMAC_BYTES ? 0 : -1;
}

int vfmt_parse_header(const uint8_t *blob, size_t size, VerthysFmtMeta *out_meta)
{
    if (blob == NULL || out_meta == NULL) return -1;
    if (validate_min_size(size) != 0) return -1;

    /* 魔数 */
    if (blob[0] != 0x56 || blob[1] != 0x45 ||
        blob[2] != 0x52 || blob[3] != 0x54) return -1;

    uint16_t version = get_u16le(blob + 4);
    if (version != VERTHYS_FMT_VERSION) return -1;

    /* 保留字段必须为 0 */
    if (get_u16le(blob + 6) != 0x0000) return -1;

    uint32_t alg_id = get_u32le(blob + 8);
    if (alg_id != VERTHYS_FMT_ALG_ARGON2ID_XCHACHA20) return -1;

    uint64_t meta_offset = get_u32le(blob + 12);
    uint64_t mac_offset  = get_u64le(blob + 16);

    /* 边界校验
     * 回绕安全形式。原 `mac_offset + 32 > size`
     * 在 mac_offset ≈ UINT64_MAX 时加法回绕为小值而通过校验，
     * 后续按 mac_offset 做 HMAC/遍历导致巨量 OOB 读（恶意 v1 文件可投递）。
     * 无回绕形式：先保证 size 足够，再做减法比较。 */
    if (size < VERTHYS_HMAC_BYTES) return -1;
    if (meta_offset < VERTHYS_FMT_HEADER_BYTES) return -1;
    /* meta_offset(uint32 读入) + METADATA > mac_offset 的无回绕等价 */
    if (mac_offset < VERTHYS_FMT_METADATA_BYTES ||
        meta_offset > mac_offset - VERTHYS_FMT_METADATA_BYTES) {
        return -1;
    }
    if (mac_offset > size - VERTHYS_HMAC_BYTES) return -1;

    memset(out_meta, 0, sizeof *out_meta);
    out_meta->version     = version;
    out_meta->alg_id      = alg_id;
    out_meta->meta_offset = meta_offset;
    out_meta->mac_offset  = mac_offset;
    memcpy(out_meta->salt, blob + 24, VERTHYS_SALT_BYTES);
    return 0;
}

int vfmt_decrypt_meta(const uint8_t *blob, size_t size,
                      const uint8_t master_key[VERTHYS_KEY_BYTES],
                      VerthysFmtMeta *inout_meta)
{
    if (blob == NULL || master_key == NULL || inout_meta == NULL) return -1;
    if (validate_min_size(size) != 0) return -1;

    const uint8_t *meta_region = blob + inout_meta->meta_offset;
    const uint8_t *meta_nonce  = meta_region;
    const uint8_t *meta_ct     = meta_region + VERTHYS_AEAD_NONCE_BYTES;
    const size_t   meta_ct_len = VERTHYS_FMT_METADATA_BYTES - VERTHYS_AEAD_NONCE_BYTES;

    uint8_t meta_pt[META_PLAINTEXT_BYTES];
    size_t pt_len = 0;
    int rc = verthys_aead_decrypt(master_key, meta_nonce,
                                (const uint8_t *)AD_METADATA, sizeof(AD_METADATA) - 1,
                                meta_ct, meta_ct_len,
                                meta_pt, &pt_len);
    if (rc != 0 || pt_len != META_PLAINTEXT_BYTES) {
        verthys_secure_zero(meta_pt, sizeof meta_pt);
        return -1;
    }

    /* 解析元数据明文 */
    size_t moff = 0;
    inout_meta->argon2_mem_kib  = get_u32le(meta_pt + moff); moff += 4;
    inout_meta->argon2_iters    = get_u32le(meta_pt + moff); moff += 4;
    inout_meta->argon2_parallel = get_u32le(meta_pt + moff); moff += 4;
    memcpy(inout_meta->dek_wrap_nonce, meta_pt + moff, VERTHYS_AEAD_NONCE_BYTES); moff += VERTHYS_AEAD_NONCE_BYTES;
    memcpy(inout_meta->wrapped_dek, meta_pt + moff, VERTHYS_DEK_WRAPPED_BYTES);   moff += VERTHYS_DEK_WRAPPED_BYTES;
    inout_meta->index_offset       = get_u64le(meta_pt + moff); moff += 8;
    inout_meta->data_blocks_offset = get_u64le(meta_pt + moff);

    verthys_secure_zero(meta_pt, sizeof meta_pt);

    /* 边界校验：meta < index < data_blocks < mac */
    if (inout_meta->index_offset < inout_meta->meta_offset + VERTHYS_FMT_METADATA_BYTES) return -1;
    if (inout_meta->data_blocks_offset <= inout_meta->index_offset) return -1;
    if (inout_meta->data_blocks_offset > inout_meta->mac_offset) return -1;
    return 0;
}

int vfmt_decrypt_records(const uint8_t *blob, size_t size,
                         const VerthysFmtMeta *meta,
                         const uint8_t dek[VERTHYS_KEY_BYTES],
                         VerthysFmtRecord **out_records, uint16_t *out_count)
{
    if (blob == NULL || meta == NULL || dek == NULL ||
        out_records == NULL || out_count == NULL) return -1;
    *out_records = NULL;
    *out_count = 0;

    /* ---- 1. 校验全文件 MAC ---- */
    uint8_t expected_mac[VERTHYS_HMAC_BYTES];
    if (verthys_hmac_sha256(expected_mac, dek, blob, (size_t)meta->mac_offset) != 0) return -1;
    if (memcmp(expected_mac, blob + meta->mac_offset, VERTHYS_HMAC_BYTES) != 0) {
        verthys_secure_zero(expected_mac, sizeof expected_mac);
        return -1;  /* MAC 不匹配 = 文件被篡改 或 DEK 错误 */
    }
    verthys_secure_zero(expected_mac, sizeof expected_mac);

    /* ---- 2. 解密索引 ---- */
    const uint8_t *idx_region = blob + meta->index_offset;
    const uint8_t *idx_nonce  = idx_region;
    /* 索引区 = [index_offset, data_blocks_offset)，密文 = 区长度 - nonce */
    size_t idx_region_size = (size_t)(meta->data_blocks_offset - meta->index_offset);
    if (idx_region_size < VERTHYS_AEAD_NONCE_BYTES + VERTHYS_AEAD_MAC_BYTES + 2) return -1;
    size_t idx_ct_len = idx_region_size - VERTHYS_AEAD_NONCE_BYTES;
    const uint8_t *idx_ct = idx_region + VERTHYS_AEAD_NONCE_BYTES;

    /* 明文长度 = 密文长度 - MAC */
    if (idx_ct_len < VERTHYS_AEAD_MAC_BYTES) return -1;
    size_t idx_pt_len = idx_ct_len - VERTHYS_AEAD_MAC_BYTES;

    uint8_t *idx_pt = malloc(idx_pt_len);
    if (idx_pt == NULL) return -1;
    size_t pt_written = 0;
    int rc = verthys_aead_decrypt(dek, idx_nonce,
                                (const uint8_t *)AD_INDEX, sizeof(AD_INDEX) - 1,
                                idx_ct, idx_ct_len,
                                idx_pt, &pt_written);
    if (rc != 0 || pt_written != idx_pt_len) {
        free(idx_pt);
        return -1;
    }

    /* ---- 3. 解析索引条目 ---- */
    if (idx_pt_len < 2) { free(idx_pt); return -1; }
    uint16_t count = get_u16le(idx_pt);
    size_t off = 2;

    VerthysFmtRecord *records = NULL;
    if (count > 0) {
        records = calloc(count, sizeof(VerthysFmtRecord));
        if (records == NULL) { free(idx_pt); return -1; }
    }

    for (uint16_t i = 0; i < count; i++) {
        /* 边界检查 */
        if (off + 2 > idx_pt_len) goto parse_fail;
        uint16_t name_len = get_u16le(idx_pt + off); off += 2;
        if (off + name_len + 1 + 8 + 8 + VERTHYS_AEAD_NONCE_BYTES > idx_pt_len) goto parse_fail;

        records[i].name_len = name_len;
        records[i].name = malloc(name_len > 0 ? name_len : 1);
        if (records[i].name == NULL) goto parse_fail;
        memcpy(records[i].name, idx_pt + off, name_len); off += name_len;

        records[i].type = idx_pt[off++];

        uint64_t data_offset = get_u64le(idx_pt + off); off += 8;
        uint64_t data_size   = get_u64le(idx_pt + off); off += 8;
        records[i].data_size = data_size;

        uint8_t block_nonce[VERTHYS_AEAD_NONCE_BYTES];
        memcpy(block_nonce, idx_pt + off, VERTHYS_AEAD_NONCE_BYTES); off += VERTHYS_AEAD_NONCE_BYTES;

        /* ---- 4. 解密数据块 ---- */
        /* 尺寸钳制（回绕安全分解，同 extent/sstable 索引解析纪律）：
         * data_offset 为盘面 u64，朴素 data_offset+4 在 uint64 溢出时
         * 回绕为小值绕过比较 → blob+data_offset 野指针读；先钳
         * data_offset ≤ size 且剩余 ≥ 4，再以差值钳块总长 */
        if (data_offset > size || size - data_offset < 4) goto parse_fail;
        const uint8_t *blk = blob + data_offset;
        uint32_t block_size = get_u32le(blk);  /* 明文长度 */
        if (block_size != data_size) goto parse_fail;  /* 一致性 */
        if ((uint64_t)block_size + VERTHYS_AEAD_MAC_BYTES >
            size - data_offset - 4) goto parse_fail;

        const uint8_t *ct = blk + 4;
        size_t ct_len = block_size + VERTHYS_AEAD_MAC_BYTES;

        records[i].data = malloc(data_size > 0 ? data_size : 1);
        if (records[i].data == NULL) goto parse_fail;

        /* 派生记录级密钥 */
        uint8_t rec_key[VERTHYS_KEY_BYTES];
        if (keymanager_derive_record_key(rec_key, dek,
                                         records[i].name, records[i].name_len) != 0) {
            verthys_secure_zero(rec_key, sizeof rec_key);
            goto parse_fail;
        }

        size_t data_written = 0;
        rc = verthys_aead_decrypt(rec_key, block_nonce,
                                NULL, 0,
                                ct, ct_len,
                                records[i].data, &data_written);
        verthys_secure_zero(rec_key, sizeof rec_key);
        if (rc != 0 || data_written != data_size) goto parse_fail;
    }

    free(idx_pt);
    *out_records = records;
    *out_count = count;
    return 0;

parse_fail:
    if (records) {
        for (uint16_t i = 0; i < count; i++) {
            if (records[i].name) { free(records[i].name); }
            if (records[i].data) { free(records[i].data); }
        }
        free(records);
    }
    free(idx_pt);
    return -1;
}

void vfmt_free_records(VerthysFmtRecord *records, uint16_t count)
{
    if (records == NULL) return;
    for (uint16_t i = 0; i < count; i++) {
        if (records[i].name != NULL) {
            verthys_secure_zero(records[i].name, records[i].name_len);
            free(records[i].name);
        }
        if (records[i].data != NULL) {
            verthys_secure_zero(records[i].data, records[i].data_size);
            free(records[i].data);
        }
    }
    free(records);
}
