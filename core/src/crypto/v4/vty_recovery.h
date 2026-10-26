/*
 * vty_recovery.h — 恢复码与 RecoveryKeyring（内部，不导出）
 *
 * 恢复码只在生成时展示一次，不落盘；校验位用于在抄写阶段就发现
 * 错字，避免用户直到换机才发现无法恢复。
 */
#ifndef VTY_RECOVERY_H
#define VTY_RECOVERY_H

#include "vty_v4_types.h"
#include "vty_keyslot_v4.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_RECOVERY_CODE_BYTES 32u
#define VTY_RECOVERY_DATA_CHARS 52u
#define VTY_RECOVERY_SUM_CHARS  4u
#define VTY_RECOVERY_CHARS      (VTY_RECOVERY_DATA_CHARS + VTY_RECOVERY_SUM_CHARS)
#define VTY_RECOVERY_TEXT_BUF   80u
#define VTY_KEYRING_MAX_ENTRIES 8u
#define VTY_KEYRING_MODULE_ID_MAX 16u
#define VTY_KEYRING_MAX_BYTES  2048u

typedef struct {
    uint8_t kind;                                  /* 1=K_c 2=K_g 3=MDEK */
    uint8_t module_uuid[VTY_KEYRING_MODULE_ID_MAX];
    uint8_t module_uuid_len;                       /* 0 或 16 */
    uint8_t key[VTY_KEY_BYTES];
} VtyKeyEntry;

typedef struct {
    uint8_t count;
    VtyKeyEntry entries[VTY_KEYRING_MAX_ENTRIES];
} VtyKeyring;

/* 生成 32B 恢复码并格式化为 14 组 4 字符（含校验位），text 容量需 >= 80 */
int vty_recovery_generate(uint8_t code[VTY_RECOVERY_CODE_BYTES],
                          char *text, size_t text_cap);

/* 将已生成的码格式化（不含隐式随机） */
int vty_recovery_format(const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                        char *text, size_t text_cap);

/* 解析用户输入：大小写/连字符/空格容错，校验位必须匹配 */
int vty_recovery_decode(const char *text,
                        uint8_t code[VTY_RECOVERY_CODE_BYTES]);

/* 仅校验格式与校验位 */
int vty_recovery_verify(const char *text);

/* Keyring 序列化 / 解析 */
int vty_keyring_serialize(const VtyKeyring *kr, uint8_t *buf, size_t cap,
                          size_t *out_len);
int vty_keyring_parse(const uint8_t *buf, size_t len, VtyKeyring *out);

/* 按键种类与模块 UUID 取密钥；module_uuid 可为 NULL（长度 0） */
int vty_keyring_find(const VtyKeyring *kr, uint8_t kind,
                     const uint8_t *module_uuid, size_t module_uuid_len,
                     uint8_t key_out[VTY_KEY_BYTES]);

/* 恢复槽：用恢复码派生的 KEK 包裹整个 Keyring */
int vty_recovery_slot_seal(VtySlot *s, const VtyKeyring *kr,
                           const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                           const VtyV4Header *h, uint32_t index,
                           uint32_t mem_kib, uint32_t iters, uint32_t parallel);

int vty_recovery_slot_open(const VtySlot *s, const char *text,
                           const VtyV4Header *h, uint32_t index,
                           VtyKeyring *out);

#ifdef __cplusplus
}
#endif

#endif /* VTY_RECOVERY_H */
