/*
 * vty_tpm_pcr.h — TPM 2.0 PCR 读取与 PCR 绑定密钥（内部，不导出）
 *
 * 职责：
 *   - 经 TBS 读取指定 PCR 集合，按 PCR 索引升序拼接后计算 SHA-256 摘要；
 *   - 经 Windows Platform Crypto Provider 创建 PCR 绑定密钥，并用它
 *     加封/解封 32 字节容器密钥。
 *
 * 约束：
 *   - PCR 集合只允许 PCR0–PCR23（位图低 24 位），非零；
 *   - 任何 TPM/PCP 失败统一返回 VTY_E_TPM，不向调用方泄露细分原因；
 *   - 密钥材料只在栈上短暂出现，返回前清零。
 */
#ifndef VTY_TPM_PCR_H
#define VTY_TPM_PCR_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 默认集合：PCR[7]（安全启动状态）与 PCR[11]（BitLocker 访问控制） */
#define VTY_TPM_PCR_SELECT_DEFAULT 0x00000880u

/* PCR 位图允许范围：PCR0–PCR23 */
#define VTY_TPM_PCR_SELECT_MASK 0x00FFFFFFu

/* RSA-2048 加封密文长度；PCR 槽的 ct 固定为该长度 */
#define VTY_TPM_PCR_CT_BYTES 256u

/* PCR 值表：24 个 PCR 的 SHA-256 值，按索引 0..23 顺序排列 */
#define VTY_TPM_PCR_TABLE_BYTES (24u * VTY_HASH_BYTES)

/* 1=PCP 与 TPM 2.0 均可用且默认集合可读 */
int vty_tpm_pcr_available(void);

/* 位图校验：非零、仅低 24 位 */
int vty_tpm_pcr_select_valid(uint32_t select);

/* 读取选中 PCR 并返回 SHA-256(按索引升序拼接的 PCR 值) */
int vty_tpm_pcr_measure(uint32_t select, uint8_t digest[VTY_HASH_BYTES]);

/* 创建/覆盖该库的 PCR 绑定密钥。
 * expected24 非空时按其 24×32 值表绑定（测试用），否则使用当前 PCR 值；
 * expected_len 必须为 0 或 VTY_TPM_PCR_TABLE_BYTES。 */
int vty_tpm_pcr_key_create(const uint8_t vault_uuid[VTY_UUID_BYTES],
                           uint32_t select,
                           const uint8_t *expected24, size_t expected_len);

/* 删除该库的 PCR 绑定密钥；密钥不存在视为成功 */
int vty_tpm_pcr_key_delete(const uint8_t vault_uuid[VTY_UUID_BYTES]);

/* 用 PCR 绑定密钥的公钥加封 32B 密钥；PCR 不参与此步 */
int vty_tpm_pcr_seal(const uint8_t vault_uuid[VTY_UUID_BYTES],
                     const uint8_t key[VTY_KEY_BYTES],
                     uint8_t ct[VTY_TPM_PCR_CT_BYTES]);

/* 用 PCR 绑定私钥解封；PCR 不匹配或密钥缺失均返回 VTY_E_TPM */
int vty_tpm_pcr_unseal(const uint8_t vault_uuid[VTY_UUID_BYTES],
                       const uint8_t ct[VTY_TPM_PCR_CT_BYTES],
                       uint8_t key[VTY_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_TPM_PCR_H */
