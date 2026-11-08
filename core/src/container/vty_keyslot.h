/*
 * vty_keyslot.h — 密钥槽编解码与包裹（内部，不导出）
 *
 * 槽的顺序即 slot_index，并进入 AAD。因此交换、重排、跨库复制
 * 都会在解包时认证失败，无法被静默接受。
 */
#ifndef VTY_KEYSLOT_H
#define VTY_KEYSLOT_H

#include "vty_types.h"
#include "vty_format.h"
#include "vty_device_root.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_SLOT_FLAG_REQUIRED   0x01u
#define VTY_SLOT_FLAG_ROTATABLE  0x02u

/* 单槽包裹密钥上限：RSA-OAEP 2048 位密文 256B + 头信息 */
#define VTY_SLOT_CT_MAX 384u

typedef struct {
    uint8_t  slot_type;
    uint8_t  slot_flags;
    uint8_t  kdf_id;
    uint8_t  wrap_alg;
    uint16_t params_len;
    uint32_t m_cost;
    uint32_t t_cost;
    uint32_t p_cost;
    /* PCR 槽参数：位图（PCR0–23）与建槽时的策略摘要 */
    uint32_t pcr_select;
    uint8_t  pcr_digest[VTY_HASH_BYTES];
    uint8_t  salt[VTY_SALT_BYTES];
    uint8_t  nonce[VTY_NONCE_BYTES];
    uint16_t ct_len;
    uint8_t  ct[VTY_SLOT_CT_MAX];
} VtySlot;

/* 槽参数长度：无参数 / Argon2id（m,t,p）/ PCR（select + digest） */
#define VTY_SLOT_PARAMS_PCR 36u
/* PCR 槽密文：RSA-2048 加封的 32B 容器密钥 */
#define VTY_SLOT_PCR_CT_BYTES 256u

/* 槽 AAD 长度：域(15) + uuid(16) + epoch(8) + index(1) + type(1) */
#define VTY_SLOT_AAD_MAX 64u
int vty_slot_build_aad(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                       uint8_t slot_index, uint8_t slot_type,
                       uint8_t out[VTY_SLOT_AAD_MAX], size_t *out_len);

/* 序列化长度与写入 */
size_t vty_slot_serialized_len(const VtySlot *s);
int vty_slot_write(const VtySlot *s, uint32_t index, const VtyHeader *h,
                   uint8_t *buf, size_t cap, size_t *written);

/* 顺序解析一个槽；offset 为相对缓冲区起点的偏移，consumed 回传消耗字节数 */
int vty_slot_parse_at(const uint8_t *buf, size_t len, size_t offset,
                      uint32_t index, const VtyHeader *h,
                      VtySlot *out, size_t *consumed);

/* 解析全部槽到调用方数组；out_count 回传实际数量（不得超过 cap） */
int vty_slots_parse_all(const uint8_t *buf, size_t len,
                        const VtyHeader *h,
                        VtySlot *out, uint32_t cap, uint32_t *out_count);

/* 口令 / 恢复码槽的包裹与解包（Argon2id + XChaCha20-Poly1305） */
int vty_slot_seal_argon2id(VtySlot *s, uint8_t slot_type, uint8_t slot_flags,
                           const uint8_t *secret, size_t secret_len,
                           const uint8_t key[VTY_KEY_BYTES],
                           const VtyHeader *h, uint32_t index,
                           uint32_t mem_kib, uint32_t iters, uint32_t parallel);

int vty_slot_open_argon2id(const VtySlot *s,
                           const uint8_t *secret, size_t secret_len,
                           const VtyHeader *h, uint32_t index,
                           uint8_t key_out[VTY_KEY_BYTES]);

/* 设备根槽：ct 为设备根封装的 32B 分享 */
int vty_slot_seal_device(VtySlot *s, uint8_t slot_flags,
                         const uint8_t key[VTY_KEY_BYTES],
                         const VtyHeader *h, uint32_t index);

int vty_slot_open_device(const VtySlot *s, const VtyHeader *h, uint32_t index,
                         uint8_t key_out[VTY_KEY_BYTES]);

/* 按类型查找槽下标；找不到返回 -1 */
int vty_slot_find(const VtySlot *slots, uint32_t count, uint8_t slot_type);

/* 策略校验：必需槽齐全、类型合法；缺失返回 VTY_E_SLOT_MISSING */
int vty_slot_policy_check(const VtySlot *slots, uint32_t count, uint16_t flags);

#ifdef __cplusplus
}
#endif

#endif /* VTY_KEYSLOT_H */
