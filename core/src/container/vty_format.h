/*
 * vty_format.h — 容器明文头部（内部，不导出）
 *
 * 头部只承载定位所需的元数据，不含任何密钥。header_hash 仅用于
 * 损坏检测，安全边界由槽位 AAD 与记录 AEAD 提供。
 */
#ifndef VTY_FORMAT_H
#define VTY_FORMAT_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t header_len;      /* 固定头 + 槽区 + 尾哈希 */
    uint16_t flags;
    uint8_t  vault_uuid[VTY_UUID_BYTES];
    uint64_t epoch;           /* 数据密钥代；口令轮换不变 */
    uint16_t slot_count;
    uint16_t reserved0;
    uint32_t keyring_len;     /* body 中 Keyring 序列化长度 */
    uint64_t generation;      /* 每次落盘递增，参与 header_digest 与 body AAD */
    uint8_t  reserved1_tail[VTY_RESERVED_TAIL_BYTES];
} VtyHeader;

#define VTY_SLOT_AREA_OFFSET VTY_HEADER_FIXED_BYTES

/* DataRoot locator：32B，放在 Keyring kind 4 的 id 字段内。
 * 它由 body AEAD 认证，因此 data_end 不能被单独篡改。 */
typedef struct {
    uint8_t  version;         /* 1 */
    uint8_t  flags;           /* 0 */
    uint64_t root_node_id;    /* 0 = 空树 */
    uint64_t root_offset;
    uint32_t root_len;
    uint8_t  level;
    uint64_t data_end;        /* 已提交高水位，>= VTY_DATA_OFFSET */
    uint8_t  pad;             /* 0 */
} VtyDataRootLocator;

/* 数据区段头（明文 32B，大端）。seq/id 的业务含义由段类型决定，
 * 但都进入 AAD，避免把段搬移到别的树/文件后仍可解。 */
typedef struct {
    uint8_t  type;
    uint8_t  flags;
    uint32_t payload_len;
    uint64_t seq;
    uint64_t id;
} VtySegmentHeader;

int vty_data_root_encode(const VtyDataRootLocator *loc, uint8_t out[VTY_DATA_ROOT_BYTES]);
int vty_data_root_decode(const uint8_t in[VTY_DATA_ROOT_BYTES], VtyDataRootLocator *out);

int vty_segment_header_write(const VtySegmentHeader *h, uint8_t out[VTY_SEG_HEADER_BYTES]);
int vty_segment_header_parse(const uint8_t in[VTY_SEG_HEADER_BYTES], VtySegmentHeader *out);

/* 写固定 76 字节字段（不含槽与哈希）；buf 容量须 >= 76 */
int vty_header_write_fixed(const VtyHeader *h, uint8_t *buf, size_t cap);

/* 计算并回填尾部 32B 哈希；header_len 必须已包含哈希且 <= buf 容量 */
int vty_header_finalize(uint8_t *buf, size_t header_len);

/* 解析并校验：magic / 主版本 / flags / slot_count / header_len / 尾哈希 */
int vty_header_parse(const uint8_t *buf, size_t len, VtyHeader *out);

/* 槽区起点（固定头之后） */
const uint8_t *vty_header_slots(const uint8_t *buf, size_t len);

/* 槽区字节数 = header_len - 76 - 32 */
size_t vty_header_slots_len(const VtyHeader *h);

/* 版本计数器在固定头 44..52，小端。计数器进入 header_digest，
 * 再由 body AAD 认证——否则攻击者可以改写明文头并重算 BLAKE3
 * 来伪造“更新”的版本。 */
uint64_t vty_header_generation(const VtyHeader *h);

/* header_digest = BLAKE3(域串 | 固定头 76B | 槽区字节)。
 * 输入是完整 header（含尾部 header_hash）；摘要覆盖范围排除尾哈希。 */
int vty_header_digest(const uint8_t *header, size_t header_len,
                         uint8_t out[VTY_HASH_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_FORMAT_H */
