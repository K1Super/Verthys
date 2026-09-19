/*
 * verthys_format.h — .verthys 交换格式读写（内部模块，不导出，V3-only）
 *
 * 交换格式文件结构（小端序）：
 *   ┌──────────────┬──────────┬──────────┬──────────┬──────────┐
 *   │ 文件头(56B)  │ 元数据区 │ 索引区   │ 数据块区 │ 文件MAC  │
 *   │ 明文         │ MEK加密  │ DEK加密  │ DEK加密  │ HMAC     │
 *   └──────────────┴──────────┴──────────┴──────────┴──────────┘
 *
 * 文件头（56 字节，明文）：
 *   [0..3]   魔数 "VERT" = 0x56 0x45 0x52 0x54
 *   [4..5]   版本号 0x0001
 *   [6..7]   保留 0x0000
 *   [8..11]  算法标识 0x00000001 (Argon2id + XChaCha20-Poly1305)
 *   [12..15] 元数据区偏移 (uint32 LE)
 *   [16..23] 文件 MAC 偏移 (uint64 LE)
 *   [24..39] 盐值 (16B, 随机) ← spec 保留区，盐本即 CSPRNG
 *   [40..55] 随机填充 (16B)
 *
 * 元数据区（512 字节）：
 *   [0..23]   元数据 AEAD nonce (24B, 明文)
 *   [24..511] AEAD 密文 = MEK 加密(argon2参数 + DEK包裹nonce + 包裹DEK + 索引偏移 + 随机填充)
 *
 * 索引区（变长，16 字节对齐）：
 *   [0..23]  索引 AEAD nonce (24B, 明文)
 *   [24..N]  AEAD 密文 = DEK 加密(记录数 + 记录条目数组 + 随机填充)
 *   每条目：name_len(2) + name(n) + type(1) + data_offset(8) + data_size(8) + block_nonce(24)
 *
 * 数据块区（每块 16 字节对齐）：
 *   [0..3]              block_size (uint32 LE) = 明文长度 = 加密数据长度
 *   [4..4+bs-1]         加密数据 (block_size 字节)
 *   [4+bs..4+bs+15]     Poly1305 MAC (16 字节)
 *   [4+bs+16..]         随机填充 (0-15 字节, 对齐到 16)
 *   每块用记录级密钥加密（keymanager_derive_record_key）
 *
 * 文件 MAC（32 字节，HMAC-SHA256）：
 *   HMAC-SHA256(DEK, blob[0 .. mac_offset-1])
 *
 * 深模块：接口隐藏全部字节布局与 AEAD 细节。
 */
#ifndef VERTHYS_FORMAT_H
#define VERTHYS_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include "verthys_crypto.h"
#include "keymanager.h"

/* ---------- 格式常量 ---------- */
#define VERTHYS_FMT_HEADER_BYTES   56u
#define VERTHYS_FMT_METADATA_BYTES 512u
#define VERTHYS_FMT_BLOCK_ALIGN    16u
#define VERTHYS_FMT_VERSION        1u
#define VERTHYS_FMT_ALG_ARGON2ID_XCHACHA20 1u

/* ---------- 内存记录（明文） ---------- */
typedef struct {
    uint8_t  type;        /* 记录类型：0x01 照片, 0x02 账号, ... */
    uint16_t name_len;
    uint8_t  *name;       /* UTF-8, 无终结符 (read 侧 heap 拥有, write 侧只读) */
    uint64_t data_size;
    uint8_t  *data;       /* 明文数据 (read 侧 heap 拥有, write 侧只读) */
} VerthysFmtRecord;

/* ---------- 解析后的元数据 ---------- */
typedef struct {
    /* 来自文件头（明文） */
    uint16_t version;
    uint32_t alg_id;
    uint8_t  salt[VERTHYS_SALT_BYTES];
    uint64_t meta_offset;
    uint64_t mac_offset;
    /* 来自解密后的元数据区 */
    uint32_t argon2_mem_kib;
    uint32_t argon2_iters;
    uint32_t argon2_parallel;
    uint8_t  wrapped_dek[VERTHYS_DEK_WRAPPED_BYTES];
    uint8_t  dek_wrap_nonce[VERTHYS_AEAD_NONCE_BYTES];
    uint64_t index_offset;
    uint64_t data_blocks_offset;  /* 索引区结束 = 数据块区起始 */
} VerthysFmtMeta;

/* ---------- 写：生成完整交换格式 blob ----------
 * salt/MEK/DEK 由调用方提供（调用方负责 keymanager 派生）。
 * out_blob 为 heap 分配，调用方 free()。
 *
 */
int vfmt_write(const uint8_t salt[VERTHYS_SALT_BYTES],
               uint32_t argon2_mem_kib, uint32_t argon2_iters, uint32_t argon2_parallel,
               const uint8_t master_key[VERTHYS_KEY_BYTES],
               const uint8_t dek[VERTHYS_KEY_BYTES],
               const VerthysFmtRecord *records, uint16_t record_count,
               uint8_t **out_blob, size_t *out_size);

/* ---------- 流式写入修复：分片写，避免大库导出 OOM ----------
 *
 * 原实现 vfmt_write 一次性分配 blob_size 连续内存，万级照片库导出直接 OOM。
 *
 * 流式处理：
 *   - records 数组仅含元数据（name/type/data_size），data 指针可为 NULL
 *   - 通过 get_data 回调按需获取每条记录的明文数据（一次一条，用完即释放）
 *   - 固定 16KB 文件 I/O 缓冲区，分段写入
 *   - 增量 HMAC-SHA256 计算，避免全文件回读
 *   - 全程峰值内存 = max(单条记录大小) + 16KB，与记录总数解耦
 *
 * 回调契约：
 *   get_data(idx, &data, &size, user_data) → 调用方分配 *data，
 *   vfmt_write_streaming 使用完毕后调用 release_data 释放
 *
 * 参数：
 *   salt, argon2_*, master_key, dek : 加密参数（同 vfmt_write）
 *   records        : 记录元数据数组（name/type/data_size 必填，data 可为 NULL）
 *   record_count   : 记录数
 *   get_data       : 按需获取明文数据的回调
 *   release_data   : 释放明文数据的回调
 *   user_data      : 回调上下文（传递给 get_data/release_data）
 *   output_path    : 输出文件路径
 * 返回 0=成功，<0=失败
 */
typedef int (*VerthysFmtGetDataCallback)(uint16_t idx,
                                       uint8_t **out_data, size_t *out_size,
                                       void *user_data);
typedef void (*VerthysFmtReleaseDataCallback)(uint16_t idx,
                                            uint8_t *data, size_t size,
                                            void *user_data);

int vfmt_write_streaming(const uint8_t salt[VERTHYS_SALT_BYTES],
                         uint32_t argon2_mem_kib, uint32_t argon2_iters, uint32_t argon2_parallel,
                         const uint8_t master_key[VERTHYS_KEY_BYTES],
                         const uint8_t dek[VERTHYS_KEY_BYTES],
                         const VerthysFmtRecord *records, uint16_t record_count,
                         VerthysFmtGetDataCallback get_data,
                         VerthysFmtReleaseDataCallback release_data,
                         void *user_data,
                         const char *output_path);

/* ---------- 读步骤 1：解析文件头（无解密） ----------
 * 校验魔数/版本/alg/边界，提取 salt 与各偏移。
 */
int vfmt_parse_header(const uint8_t *blob, size_t size, VerthysFmtMeta *out_meta);

/* ---------- 读步骤 2：用 MEK 解密元数据区 ----------
 * AEAD 认证失败 → 返回非 0（主密码错误或元数据被篡改）。
 */
int vfmt_decrypt_meta(const uint8_t *blob, size_t size,
                      const uint8_t master_key[VERTHYS_KEY_BYTES],
                      VerthysFmtMeta *inout_meta);

/* ---------- 读步骤 3：校验文件 MAC + 解密索引 + 解密全部记录 ----------
 * 先用 DEK 校验全文件 HMAC-SHA256，再解密索引与数据块。
 * 任一认证失败 → 返回非 0，不输出任何记录。
 * out_records 为 heap 数组（每条 name/data 各自 heap 分配），用 vfmt_free_records 释放。
 */
int vfmt_decrypt_records(const uint8_t *blob, size_t size,
                         const VerthysFmtMeta *meta,
                         const uint8_t dek[VERTHYS_KEY_BYTES],
                         VerthysFmtRecord **out_records, uint16_t *out_count);

/* 释放 vfmt_decrypt_records 返回的记录数组 */
void vfmt_free_records(VerthysFmtRecord *records, uint16_t count);

#endif /* VERTHYS_FORMAT_H */
