/*
 * verthys_crypto.h — 密码学原语封装（内部，不导出）
 *
 * 基于 libsodium。仅暴露项目所需原语，隐藏 libsodium 细节。
 * 算法：
 *   - 对称加解密：XChaCha20-Poly1305（256位密钥/192位nonce/16字节MAC）
 *   - 密钥派生：Argon2id（64MiB/3次/并行1）
 *   - HKDF/HMAC-SHA256（主密钥派生与全文件 MAC）
 *   - 随机数：OS CSPRNG
 */
#ifndef VERTHYS_CRYPTO_H
#define VERTHYS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* 初始化底层密码库（libsodium）。幂等、线程安全。0=成功 */
int verthys_crypto_init(void);

/* ---------- 常量（与 .verthys 格式对齐） ---------- */
#define VERTHYS_KEY_BYTES        32u   /* 主密钥 / 数据密钥 / HKDF 输出 */
#define VERTHYS_AEAD_NONCE_BYTES 24u   /* XChaCha20-Poly1305 IETF nonce */
#define VERTHYS_AEAD_MAC_BYTES   16u   /* Poly1305 认证标签 */
#define VERTHYS_SALT_BYTES       16u   /* Argon2id 盐 */
#define VERTHYS_HMAC_BYTES       32u   /* HMAC-SHA256 全文件 MAC */
#define VERTHYS_ARGON2_MEM_KIB   65536u  /* 64 MiB（SECURE 预设） */
#define VERTHYS_ARGON2_ITERS     3u
#define VERTHYS_ARGON2_PARALLEL  1u

/* ★ 自适应 Argon2id 预设参数
 *
 *   BALANCED：32MiB / 2 iters / 1 parallel（单次派生 ~1.5s）
 *             日常推荐预设
 *   SECURE  ：64MiB / 3 iters / 1 parallel（单次派生 6-15s）
 *             涉密/合规场景，沿用 VERTHYS_ARGON2_MEM_KIB/ITERS/PARALLEL
 *
 * 旧容器超级块已存 64MiB/3/1，解锁时按超级块实际参数派生，向后兼容。
 * 新建 BALANCED 容器写入 32MiB/2/1，解锁 3s 目标的核心达标项。 */
#define VERTHYS_ARGON2_BALANCED_MEM_KIB   32768u  /* 32 MiB */
#define VERTHYS_ARGON2_BALANCED_ITERS     2u
#define VERTHYS_ARGON2_BALANCED_PARALLEL  1u
/* BALANCED 动态校准参数 */
#define VERTHYS_ARGON2_CALIBRATE_TARGET_MS 1200u  /* 创建期目标派生耗时 */
#define VERTHYS_ARGON2_BALANCED_ITERS_MAX   3u    /* 迭代上限（32MiB×3 ≈ 2.2s，守住 1~2s 预算） */

/* Argon2id 规范范围（解锁时校验超级块参数，越界回退默认值） */
#define VERTHYS_ARGON2_MEM_KIB_MIN        8u                /* 8 KiB */
#define VERTHYS_ARGON2_MEM_KIB_MAX        (4u * 1024u * 1024u)  /* 4 GiB */
#define VERTHYS_ARGON2_ITERS_MIN          1u
#define VERTHYS_ARGON2_PARALLEL_MIN       1u
#define VERTHYS_ARGON2_PARALLEL_MAX       64u

/* ---------- 随机数（OS CSPRNG，每次独立） ---------- */
__declspec(noinline) void verthys_random_bytes(uint8_t *buf, size_t len);

/* ---------- AEAD: XChaCha20-Poly1305 ----------
 * 密文长度 = 明文长度 + MAC(16)。
 * 调用方需保证 ciphertext 缓冲 >= pt_len + VERTHYS_AEAD_MAC_BYTES。
 * 返回 0 成功，非 0 失败。
 */
int verthys_aead_encrypt(const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, size_t *ct_len);

int verthys_aead_decrypt(const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext, size_t *pt_len);

/* ---------- Argon2id 密钥派生 ----------
 * password||pepper 作为口令输入，salt 作为盐。
 * 参数：64MiB / 3 次 / 并行 1。
 * 输出 32 字节派生密钥材料。
 *
 * 本函数为兼容封装，
 *   内部委托 verthys_argon2id_derive_ex 并传入默认硬编码参数。
 *   新代码应直接调用 verthys_argon2id_derive_ex，由调用方从超级块
 *   获取实际 Argon2id 参数后传入，彻底解耦代码与固定强度。
 */
int verthys_argon2id_derive(uint8_t out[VERTHYS_KEY_BYTES],
                          const uint8_t *password, size_t pw_len,
                          const uint8_t salt[VERTHYS_SALT_BYTES],
                          const uint8_t pepper[VERTHYS_KEY_BYTES]);

/* ---------- Argon2id 密钥派生（无胡椒） ----------
 * 仅用 password 作为口令输入，salt 作为盐。用于导出/导入文件
 *（导出密码不混入应用级胡椒，保证分包独立解密）。
 *
 * 本函数为兼容封装，内部委托 verthys_argon2id_derive_ex（pepper=NULL）。
 */
int verthys_argon2id_derive_raw(uint8_t out[VERTHYS_KEY_BYTES],
                              const uint8_t *password, size_t pw_len,
                              const uint8_t salt[VERTHYS_SALT_BYTES]);

/* ================================================================== *
 * Argon2id 动态校准（创建期跑分选参）
 * ================================================================== *
 * 以 mem_kib 固定、迭代次数为变量的两次探测（初始测量 + 换算确认），
 * 选择使单次派生耗时最接近 target_ms 的迭代次数，钳制在
 * [min_iters, max_iters]。选参结果由调用方写入超级块（解锁时按参数派生，
 * 与基准监控共用存储）。SECURE 预设不使用本函数（合规确定性要求，
 * 参数固定 64MiB/3/1）。
 *
 * 返回 0 成功（out_iters 写入选定迭代数），非 0 失败。
 */
int verthys_argon2_calibrate(const uint8_t *password, size_t pw_len,
                           const uint8_t salt[VERTHYS_SALT_BYTES],
                           const uint8_t pepper[VERTHYS_KEY_BYTES],
                           uint32_t mem_kib,
                           uint32_t target_ms,
                           uint32_t min_iters, uint32_t max_iters,
                           uint32_t *out_iters);

/* ================================================================== *
 * 完全参数化的密钥派生接口
 *                                                                    *
 * 设计目标：                                                          *
 *   Argon2id 参数（内存、迭代、并行度）不再硬编码于代码常量，          *
 *   由调用方从超级块读取后传入，支持自定义预设容器（PERFORMANCE/      *
 *   SECURE/CUSTOM 各档参数不同），彻底解耦代码与固定强度。            *
 *                                                                    *
 * 参数说明：                                                          *
 *   out            : 输出 32 字节派生密钥材料                         *
 *   password       : 用户口令（可为 NULL，仅当 pw_len==0）            *
 *   pw_len         : 口令字节数                                       *
 *   salt           : Argon2id 盐（16 字节，来自超级块）               *
 *   pepper         : 应用级胡椒（32 字节，可为 NULL=不混入胡椒）       *
 *   mem_kib        : 内存参数（KiB），如 65536=64MiB                  *
 *   iters          : 迭代次数（时间代价），如 3                       *
 *   parallel       : 并行度，如 1                                     *
 *                                                                    *
 * 安全约束：                                                          *
 *   - mem_kib 须 ≥ 8（Argon2id 最小 8 KiB），≤ 4*1024*1024（4 GiB）  *
 *   - iters    须 ≥ 1                                                *
 *   - parallel  须 ≥ 1 且 ≤ 64                                       *
 *   - 越界参数返回 -1，不调用 libsodium                               *
 *                                                                    *
 * 返回 0 成功，非 0 失败。                                            *
 * ================================================================== */
int verthys_argon2id_derive_ex(uint8_t out[VERTHYS_KEY_BYTES],
                             const uint8_t *password, size_t pw_len,
                             const uint8_t salt[VERTHYS_SALT_BYTES],
                             const uint8_t pepper[VERTHYS_KEY_BYTES],
                             uint32_t mem_kib,
                             uint32_t iters,
                             uint32_t parallel);

/* ================================================================== *
 * 独立完整性密钥派生
 *                                                                    *
 * 引入独立完整性密钥，与 DEK 完全隔离：                                *
 *   integrity_key = HKDF-SHA256(master_key, "verthys/integrity-key") *
 *                                                                    *
 * 用途：HMAC 计算（超级块偏移量 MAC、状态链、累积写入 HMAC 等），      *
 * 即使 DEK 泄露也不影响历史文件完整性验证。                            *
 *                                                                    *
 * 参数：                                                              *
 *   out         : 输出 32 字节完整性密钥                              *
 *   master_key  : 主密钥（Argon2id 派生输出或已解包的 MEK）           *
 *                                                                    *
 * 返回 0 成功，非 0 失败。                                            *
 * ================================================================== */
int verthys_derive_integrity_key(uint8_t out[VERTHYS_KEY_BYTES],
                               const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* 完整性密钥 HKDF 域分离标签 */
#define VERTHYS_INTEGRITY_KEY_INFO  "verthys/integrity-key"

/* ---------- HKDF-SHA256-Expand ----------
 * 从 PRK（如 Argon2id 输出）派生固定用途子密钥。
 * info 为用途标签（域分离）。
 */
int verthys_hkdf_expand(uint8_t out[VERTHYS_KEY_BYTES],
                      const uint8_t prk[VERTHYS_KEY_BYTES],
                      const uint8_t *info, size_t info_len);

/* ---------- HMAC-SHA256（一次性） ---------- */
__declspec(noinline) int verthys_hmac_sha256(uint8_t out[VERTHYS_HMAC_BYTES],
                      const uint8_t key[VERTHYS_KEY_BYTES],
                      const uint8_t *data, size_t data_len);

/* ---------- BLAKE2b-256 通用哈希（V3 内容寻址） ----------
 * libsodium crypto_generichash（BLAKE2b-256，无密钥模式）。
 * out：32 字节 digest；data 可为 NULL（仅当 data_len==0）。
 * 返回 0 成功，非 0 失败。
 */
#define VERTHYS_GENERICHASH_BYTES 32u
__declspec(noinline) int verthys_generichash(uint8_t out[VERTHYS_GENERICHASH_BYTES],
                      const uint8_t *data, size_t data_len);

#endif /* VERTHYS_CRYPTO_H */
