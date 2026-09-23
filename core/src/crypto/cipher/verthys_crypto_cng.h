/*
 * verthys_crypto_cng.h — CNG 内核态 AEAD 封装（V3 主密码学路径）
 *
 *   密钥原始字节经 BCryptGenerateSymmetricKey 导入内核后，用户态仅持有
 *   BCRYPT_KEY_HANDLE 句柄值；AES-256-GCM 运算由 BCryptEncrypt/BCryptDecrypt
 *   在内核态完成。完整 Dump 进程内存只能拿到无映射意义的句柄 ID。
 *
 * 与 key_separation（安全层三权分立）的关系：
 *   本模块是 L0 密码学层的通用 CNG AEAD 封装（单上下文、可多实例、
 *   内部 nonce 单调计数器），keymanager_cng 在其上构建 V3 密钥组生命周期。
 *   GCM 内核母本（open_aes_gcm_provider / init_gcm_auth_info / AEAD 流程）
 *   与 key_separation.c 的实现语义一致。
 *
 * 算法参数：AES-256-GCM（CNG 原生）
 *   - 密钥：32 字节
 *   - Nonce：12 字节，封装层内部 96 位单调计数器生成
 *   - 认证标签：16 字节
 *   - 密文布局：[ciphertext || tag]
 *
 * nonce 管理（红线级）：
 *   - 加密侧 nonce 由封装层内部计数器原子递增生成并经 nonce_out 回传，
 *     调用方持久化（V3：随超级块分区表；过渡期：ctx 内存）
 *   - 计数器可经 verthys_cng_aead_restore_nonce_counter 从持久化值恢复
 *     （解锁 S3 阶段），恢复值须取 max(盘面值, WAL 重放值)
 *     + 安全裕量
 *   - 解密侧 nonce 由调用方传入（与加密时一致）
 *
 * nonce 字节布局（公共契约，全仓一致）：
 *   12 字节 nonce = counter 的 96 位大端编码；counter 为 uint64，
 *   高 4 字节恒零——即 nonce[0..3] == 0x00，counter 位于 nonce[4..11]
 *   （大端）。任何修改本布局的提交必须同步修正各 nonce 提取点。
 *   提取（持久化帧里的 nonce → 计数器）统一经
 *   verthys_cng_nonce_decode_counter，禁止各调用点自行解码。
 *
 * 域分离：V3 域分离标签（"verthys/...-v3"）由上层 HKDF/包装路径承担，
 *   本层 AAD 由调用方显式传入。
 */
#ifndef VERTHYS_CRYPTO_CNG_H
#define VERTHYS_CRYPTO_CNG_H

#include <stdint.h>
#include <stddef.h>
#include "verthys.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- AES-256-GCM 参数 ---------- */
#define VERTHYS_CNG_KEY_BYTES     32u   /* AES-256 密钥长度 */
#define VERTHYS_CNG_NONCE_BYTES   12u   /* GCM 标准 Nonce 长度 */
#define VERTHYS_CNG_TAG_BYTES     16u   /* GCM 认证标签长度 */
#define VERTHYS_CNG_KEY_ID_BYTES  16u   /* 密钥标识符长度（非敏感，诊断/轮换追踪） */

/* 内核态 AEAD 上下文——用户态仅持句柄 */
typedef struct VerthysCngAead {
    BCRYPT_ALG_HANDLE   alg;            /* BCRYPT_AES_ALGORITHM + CHAIN_MODE_GCM（模块共享提供者） */
    BCRYPT_KEY_HANDLE   key;            /* 内核态密钥句柄（不可导出，NULL=未导入） */
    uint64_t            nonce_counter;  /* 单调递增 nonce 计数器（Interlocked 原子递增） */
    uint8_t             key_id[VERTHYS_CNG_KEY_ID_BYTES]; /* 密钥标识符（非敏感） */
    int                 imported;       /* 1=key 已导入内核 */
} VerthysCngAead;

/*
 * 预创建共享 AES-GCM 算法提供者。
 * Verthys_Init 时机调用一次，避免解锁关键路径重复打开；幂等。
 * 并发安全：open/close 与引用计数增减由模块内互斥锁串行化；open 失败
 * 不改变状态，下次调用可重试。返回 VERTHYS_OK 或 VERTHYS_ERR_CNG_UNAVAILABLE。
 */
VerthysResult verthys_cng_init_once(void);

/*
 * 释放一次引用；末位引用释放时关闭共享算法提供者。
 * 须与 init_once 严格配对，且不得与密钥导入并发（关闭前提：已导入
 * 句柄先行销毁）。幂等（引用已为 0 时空转）。
 */
void verthys_cng_global_deinit(void);

/*
 * 初始化 AEAD 上下文（未导入任何密钥的干净状态）。
 * 契约：
 *   1. 栈上分配的 VerthysCngAead 必须先经本函数（或整体置零）初始化，方可
 *      调用 import_key——未初始化内存中的垃圾句柄值会被误判为 "已导入"
 *      而触发 BCryptDestroyKey 野句柄调用（0xC0000005）。
 *   2. init 仅做内存消毒，不执行内核句柄销毁（垃圾值与合法句柄不可区分）；
 *      已导入上下文须先 destroy 再 init，否则内核句柄泄露。
 */
VerthysResult verthys_cng_aead_init(VerthysCngAead *aead);

/*
 * 导入密钥到 CNG 内核态。
 * 红线：本函数是唯一允许密钥明文出现在用户态栈帧的
 *   函数——短暂、立即清零；调用后密钥字节只存在于内核地址空间。
 *   清零契约（const 消耗语义，同 key_separation_install）：key 非 NULL
 *   的所有返回路径（成功、内核导入失败、提供者不可用、上下文非法）
 *   均清零调用方缓冲——调用方无法区分成败，零化责任全部在本函数。
 * key_id：16 字节非敏感标识符（诊断/轮换追踪），可为 NULL（置零）。
 * 前置条件：上下文已经 verthys_cng_aead_init / 整体置零初始化。
 * 重复导入：仅当 imported 标志置位时销毁旧句柄再导入新句柄（句柄不泄露，
 * 且不对未初始化内存中的垃圾句柄值执行销毁）。
 */
__declspec(noinline) VerthysResult verthys_cng_aead_import_key(
    VerthysCngAead *aead,
    const uint8_t key[VERTHYS_CNG_KEY_BYTES],
    const uint8_t key_id[VERTHYS_CNG_KEY_ID_BYTES]
);

/*
 * 内核态加密：明文在用户态缓冲，GCM 运算在内核态完成。
 *   ciphertext 布局 [ct || tag]，容量 >= plaintext_len + 16，实际长度经
 *   *ciphertext_len 回传；nonce 由内部计数器生成并写入 nonce_out（12B，
 *   调用方持久化）。空明文（0 字节）合法，输出仅 16 字节标签。
 *   长度域：单条明文上限 = ULONG_MAX - 16、AAD 上限 = ULONG_MAX
 *   （CNG 32 位参数域），超限返回 VERTHYS_ERR_INVALID，更大场景由
 *   上层分块。nonce_counter 溢出（2^64 加密次数，理论边界）返回
 *   VERTHYS_ERR_INTERNAL。
 */
__declspec(noinline) VerthysResult verthys_cng_aead_encrypt(
    VerthysCngAead *aead,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len,  /* [ct‖tag] */
    uint8_t *nonce_out /* 12B */
);

/*
 * 内核态解密：标签在内核态校验，认证失败返回 VERTHYS_ERR_AUTH
 *   且输出缓冲被清零。ciphertext_len >= 16（空明文合法）。
 *   长度域：单条密文上限 = ULONG_MAX（对应加密侧明文上限 ULONG_MAX-16）、
 *   AAD 上限 = ULONG_MAX，超限返回 VERTHYS_ERR_INVALID。
 */
__declspec(noinline) VerthysResult verthys_cng_aead_decrypt(
    const VerthysCngAead *aead,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *nonce, /* 12B */
    uint8_t *plaintext, size_t *plaintext_len
);

/* 销毁：BCryptDestroyKey 使句柄失效，内核态密钥材料不可恢复。幂等。 */
void verthys_cng_aead_destroy(VerthysCngAead *aead);

/* 当前 nonce 计数器值（未导入返回 0） */
uint64_t verthys_cng_aead_nonce_counter(const VerthysCngAead *aead);

/*
 * 恢复 nonce 计数器（解锁 S3：从超级块/WAL 持久化值继续，
 * 严禁回退——调用方保证传入值 >= 历史已用最大值 + 安全裕量）。
 * 仅 imported 状态可恢复；恢复值小于当前值返回 VERTHYS_ERR_INVALID（防回退）。
 */
VerthysResult verthys_cng_aead_restore_nonce_counter(VerthysCngAead *aead,
                                                 uint64_t counter);

/*
 * nonce → 计数器解码（encode_nonce 对偶）：nonce[4..11] 大端
 * 读出 counter（前 4 字节契约恒零，不参与）。供 WAL/事务恢复等
 * 需从持久化帧 nonce 反推计数下界处使用。
 */
uint64_t verthys_cng_nonce_decode_counter(
    const uint8_t nonce[VERTHYS_CNG_NONCE_BYTES]);

/* 查询导入状态（1=已导入内核，0=未导入） */
int verthys_cng_aead_is_imported(const VerthysCngAead *aead);

/* ---------- 测试注入（只被测试 exe 使用，对象直链的内部符号；
 * 不在 DLL 导出清单中，发布面零变化） ---------- */

/* one-shot：令下一次内核密钥导入确定性失败（模拟 BCrypt 调用失败），
 * 用于验证导入失败路径的调用方密钥清零契约 */
void verthys_cng_test_inject_import_failure(void);

/* 当前共享提供者引用计数（并发 init/deinit 压力测试的终态断言） */
LONG verthys_cng_test_alg_refs(void);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_CRYPTO_CNG_H */
