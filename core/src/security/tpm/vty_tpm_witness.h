/*
 * vty_tpm_witness.h — TPM 持久化密钥见证（内部，不导出）
 *
 * 用途：在没有 TPM NV 单调计数器的平台上，用一个可轮换、不可复制的
 * TPM 持久化密钥身份充当“外部见证”。每次状态提交时创建另一槽的新密钥
 * 并记录其公钥指纹，旧密钥随后删除；还原旧状态文件时指纹必然不符，
 * 从而 fail-closed。
 *
 * 约束：
 *   - 见证密钥不绑定 PCR：PCR 变化不应影响回滚锚点；
 *   - 两个槽交替使用，保证“先写状态、后删旧键”的顺序在崩溃时仍可打开；
 *   - 密钥缺失、指纹不符、平台不可用一律由调用方按 fail-closed 处理；
 *   - 本模块只返回公开指纹，不导出私钥，不记录任何密钥材料。
 */
#ifndef VTY_TPM_WITNESS_H
#define VTY_TPM_WITNESS_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 公钥指纹长度（SHA-256） */
#define VTY_TPM_WITNESS_FP_BYTES 32u
/* 交替槽数量：A/B */
#define VTY_TPM_WITNESS_SLOTS 2u

/* 1=Platform Crypto Provider 可用（不保证单次建键必然成功） */
int vty_tpm_witness_available(void);

/* 创建/覆盖指定槽的见证密钥，并返回新公钥指纹 */
int vty_tpm_witness_create(const uint8_t id[VTY_UUID_BYTES], uint8_t slot,
                           uint8_t fp[VTY_TPM_WITNESS_FP_BYTES]);

/* 校验指定槽的当前公钥指纹；密钥缺失或不符返回 VTY_E_TPM */
int vty_tpm_witness_verify(const uint8_t id[VTY_UUID_BYTES], uint8_t slot,
                           const uint8_t expected[VTY_TPM_WITNESS_FP_BYTES]);

/* 删除指定槽；不存在视为成功 */
int vty_tpm_witness_delete(const uint8_t id[VTY_UUID_BYTES], uint8_t slot);

/* 两槽任一存在返回 1，均不存在返回 0，查询失败返回 -1 */
int vty_tpm_witness_any(const uint8_t id[VTY_UUID_BYTES]);

/* 删除两个槽（测试清理/状态重建） */
int vty_tpm_witness_delete_all(const uint8_t id[VTY_UUID_BYTES]);

/* 测试专用：由任意字符串派生见证 ID（SHA-256），仅供测试隔离钩子使用；
 * 生产构建不编译此函数。 */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
int vty_tpm_witness_id_from_string(const char *text,
                                   uint8_t id[VTY_UUID_BYTES]);
#endif

#ifdef __cplusplus
}
#endif

#endif /* VTY_TPM_WITNESS_H */
