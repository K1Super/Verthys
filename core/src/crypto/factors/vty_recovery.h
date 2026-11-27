/*
 * vty_recovery.h — 恢复码与 RecoveryKeyring（内部，不导出）
 *
 * 恢复码只在生成时展示一次，不落盘；校验位用于在抄写阶段就发现
 * 错字，避免用户直到换机才发现无法恢复。
 */
#ifndef VTY_RECOVERY_H
#define VTY_RECOVERY_H

#include "vty_types.h"
#include "vty_keyslot.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_RECOVERY_CODE_BYTES 32u
#define VTY_RECOVERY_DATA_CHARS 52u
#define VTY_RECOVERY_SUM_CHARS  4u
#define VTY_RECOVERY_CHARS      (VTY_RECOVERY_DATA_CHARS + VTY_RECOVERY_SUM_CHARS)
#define VTY_RECOVERY_TEXT_BUF   80u
#define VTY_KEYRING_MAX_ENTRIES 8u
#define VTY_KEYRING_MAX_BYTES  2048u

/* 条目 id：K_c 为 0B，MDEK 为 16B 模块 UUID，DataRoot 为 32B locator。 */
typedef struct {
    uint8_t kind;                                  /* 1=K_c 3=MDEK 4=DataRoot */
    uint8_t id[VTY_KEYRING_ID_MAX];
    uint8_t id_len;                                /* 0 / 16 / 32 */
    uint8_t key[VTY_KEY_BYTES];
} VtyKeyEntry;

typedef struct {
    uint8_t count;
    VtyKeyEntry entries[VTY_KEYRING_MAX_ENTRIES];
} VtyKeyring;

#define VTY_RECOVERY_PLAIN_BYTES (1u + 1u + 2u + 1u + VTY_KEY_BYTES)

/* 生成 32B 恢复码并格式化为 14 组 4 字符（含校验位），text 容量需 >= 80 */
int vty_recovery_generate(uint8_t code[VTY_RECOVERY_CODE_BYTES],
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

/* 按键种类与 id 取密钥；id 可为 NULL（长度 0） */
int vty_keyring_find(const VtyKeyring *kr, uint8_t kind,
                     const uint8_t *id, size_t id_len,
                     uint8_t key_out[VTY_KEY_BYTES]);

/* 取完整条目（含 id）。DataRoot 的 32B locator 必须走本接口，
 * 只返回 key 的查找接口会丢失定位信息。 */
int vty_keyring_find_entry(const VtyKeyring *kr, uint8_t kind,
                           const uint8_t *id, size_t id_len,
                           VtyKeyEntry *out);

/* 恢复槽只包裹 K_c：MDEK 轮换不应让恢复码失效，DataRoot 由 body 携带。 */
/* kek_out 可空；非空时返回恢复码经 Argon2id 派生的 32B KEK，
 * 供模块 recovery 槽做域分离派生，避免重复执行 Argon2id。 */
int vty_recovery_slot_seal(VtySlot *s, const uint8_t kc[VTY_KEY_BYTES],
                           const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                           const VtyHeader *h, uint32_t index,
                           uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                           uint8_t kek_out[VTY_KEY_BYTES]);

int vty_recovery_slot_open(const VtySlot *s, const char *text,
                           const VtyHeader *h, uint32_t index,
                           VtyKeyring *out,
                           uint8_t kek_out[VTY_KEY_BYTES]);

/* 轮换：用调用方持有的恢复 KEK 重封既有恢复槽（不重新执行 Argon2id）。
 * 保留 salt 与 KDF 参数，换新 nonce，包裹新的 K_c；AAD 使用新头部
 * （uuid 不变、epoch 已递增）。供全库 DEK 轮换在无恢复码明文时使用。 */
int vty_recovery_slot_reseal(VtySlot *s, const uint8_t kc[VTY_KEY_BYTES],
                             const uint8_t kek[VTY_KEY_BYTES],
                             const VtyHeader *h, uint32_t index);

#ifdef __cplusplus
}
#endif

#endif /* VTY_RECOVERY_H */
