/*
 * vty_format_v4.h — v4 容器明文头部（内部，不导出）
 *
 * 头部只承载定位所需的元数据，不含任何密钥。header_hash 仅用于
 * 损坏检测，安全边界由槽位 AAD 与记录 AEAD 提供。
 */
#ifndef VTY_FORMAT_V4_H
#define VTY_FORMAT_V4_H

#include "vty_v4_types.h"

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
    uint64_t epoch;
    uint16_t slot_count;
    uint16_t reserved0;
    uint32_t keyring_len;     /* 恢复槽内 Keyring 序列化长度 */
    uint8_t  reserved1[32];
} VtyV4Header;

#define VTY_V4_SLOT_AREA_OFFSET VTY_V4_HEADER_FIXED_BYTES

/* 写固定 76 字节字段（不含槽与哈希）；buf 容量须 >= 76 */
int vty_v4_header_write_fixed(const VtyV4Header *h, uint8_t *buf, size_t cap);

/* 计算并回填尾部 32B 哈希；header_len 必须已包含哈希且 <= buf 容量 */
int vty_v4_header_finalize(uint8_t *buf, size_t header_len);

/* 解析并校验：magic / 主版本 / flags / slot_count / header_len / 尾哈希 */
int vty_v4_header_parse(const uint8_t *buf, size_t len, VtyV4Header *out);

/* 槽区起点（固定头之后） */
const uint8_t *vty_v4_header_slots(const uint8_t *buf, size_t len);

/* 槽区字节数 = header_len - 76 - 32 */
size_t vty_v4_header_slots_len(const VtyV4Header *h);

/* 版本计数器（reserved1 前 8 字节，小端）。
 * 放在既有保留区而不是新增字段：固定头长度与槽/体 AAD 布局保持不变，
 * 老库解析路径无需改动。计数器进入 body AAD，由 K_c 认证——否则
 * 攻击者可以改写明文头并重算 BLAKE3 来伪造“更新”的版本。 */
uint64_t vty_v4_header_generation(const VtyV4Header *h);
void vty_v4_header_set_generation(VtyV4Header *h, uint64_t generation);

#ifdef __cplusplus
}
#endif

#endif /* VTY_FORMAT_V4_H */
