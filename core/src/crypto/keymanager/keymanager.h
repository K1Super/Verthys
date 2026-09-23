/*
 * keymanager.h — 四级密钥体系（内部模块，不导出）
 *
 * 层次：
 *   L1 主密码        ：用户输入的口令
 *   L2 派生密钥材料  ：Argon2id(password || pepper, salt) → 32B（瞬时，用后即擦）
 *   L3 主密钥 MEK    ：HKDF-Expand(L2, "verthys/master-key-v1") → 32B
 *                      仅解锁时驻留，Lock/Deinit 即刻安全清零
 *   L4 数据加密密钥 DEK：随机 32B，由 MEK 包裹（AEAD）后存于 .verthys 元数据
 *
 * 记录级密钥：HKDF-Expand(DEK, "verthys/record-v1" || record_id) → 32B
 *             细粒度隔离，防批量解密；每条记录独立。
 *
 * 胡椒：编译进 DLL 的 32 字节常量，文件内 static，不存储、不导出、不通过任何
 *      函数返回。主密码遗忘即永久丢失，与“无后门”设计完全兼容。胡椒仅提升
 *      离线暴力破解成本（攻击者即便拿到 .verthys 与盐，仍需枚举 DLL 内胡椒）。
 *
 * 深模块（codebase-design）：本模块对外仅暴露 5 个函数，隐藏胡椒常量、
 * Argon2id 参数、HKDF info 标签、AEAD AD 等内部细节。
 */
#ifndef VERTHYS_KEYMANAGER_H
#define VERTHYS_KEYMANAGER_H

#include <stdint.h>
#include <stddef.h>
#include "verthys_crypto.h"

/* DEK 包裹后的字节长度：32B 密文 + 16B Poly1305 MAC */
#define VERTHYS_DEK_WRAPPED_BYTES (VERTHYS_KEY_BYTES + VERTHYS_AEAD_MAC_BYTES)

/* ---------- L3：主密钥派生 ----------
 * 由用户主密码 + 文件盐派生 MEK。胡椒在内部混入，调用方不可见。
 * master_key  ：输出 32B 主密钥
 * password    ：用户主密码（可为空串，pw_len=0）
 * pw_len      ：主密码字节数
 * salt        ：16B 随机盐（与 .verthys 文件头一致）
 * 返回 0 成功，非 0 失败。
 *
 * 注意：本函数使用默认硬编码 Argon2id 参数（64MiB/3/1）。
 *       新代码应使用 keymanager_derive_master_ex 从超级块传入实际参数。
 */
int keymanager_derive_master(uint8_t master_key[VERTHYS_KEY_BYTES],
                             const uint8_t *password, size_t pw_len,
                             const uint8_t salt[VERTHYS_SALT_BYTES]);

/* ===================================================================== *
 * 优化：完全参数化的主密钥派生                                    *
 *                                                                    *
 * 与 keymanager_derive_master 相同，但 Argon2id 参数由调用方传入，      *
 * 支持从超级块读取实际参数（BALANCED 32MiB/2/1 / SECURE 64MiB/3/1）。   *
 *                                                                    *
 * 参数说明：                                                          *
 *   master_key  : 输出 32B 主密钥                                     *
 *   password    : 用户主密码（可为空串，pw_len=0）                     *
 *   pw_len      : 主密码字节数                                        *
 *   salt        : 16B 随机盐（来自超级块）                             *
 *   mem_kib     : Argon2id 内存参数（KiB），如 32768=32MiB            *
 *   iters       : Argon2id 迭代次数，如 2                             *
 *   parallel    : Argon2id 并行度，如 1                               *
 *                                                                    *
 * 安全下限（OWASP 2023 推荐）：                                        *
 *   - mem_kib  >= 19 * 1024（19 MiB）                                *
 *   - iters    >= 2                                                  *
 *   - parallel >= 1                                                  *
 *                                                                    *
 * 返回 0 成功，非 0 失败。                                            *
 * ===================================================================== */
int keymanager_derive_master_ex(uint8_t master_key[VERTHYS_KEY_BYTES],
                                const uint8_t *password, size_t pw_len,
                                const uint8_t salt[VERTHYS_SALT_BYTES],
                                uint32_t mem_kib,
                                uint32_t iters,
                                uint32_t parallel);

/* ---------- L3：主密钥派生（无胡椒，用于导出/导入文件） ----------
 * 与 keymanager_derive_master 相同，但不混入胡椒。
 * 导出密码不混入应用级胡椒，保证分包可独立解密。
 */
int keymanager_derive_master_export(uint8_t master_key[VERTHYS_KEY_BYTES],
                                    const uint8_t *password, size_t pw_len,
                                    const uint8_t salt[VERTHYS_SALT_BYTES]);

/* ---------- L4：DEK 生成 ----------
 * 生成随机 32B 数据加密密钥（OS CSPRNG）。
 */
void keymanager_generate_dek(uint8_t dek[VERTHYS_KEY_BYTES]);

/* ---------- L4：DEK 包裹（MEK 加密 DEK） ----------
 * 用 MEK 经 XChaCha20-Poly1305 加密 DEK。
 * wrapped    ：输出 48B（32B 密文 + 16B MAC）
 * nonce_out  ：输出 24B 随机 nonce（调用方需与 wrapped 一并持久化）
 * dek        ：输入 32B 明文 DEK
 * master_key ：输入 32B MEK
 * 返回 0 成功，非 0 失败。
 */
int keymanager_wrap_dek(uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES],
                        uint8_t nonce_out[VERTHYS_AEAD_NONCE_BYTES],
                        const uint8_t dek[VERTHYS_KEY_BYTES],
                        const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* ---------- L4：DEK 解包（MEK 解密 wrapped 还原 DEK） ----------
 * 解包失败即代表 MEK 错误（主密码错误）或 wrapped 被篡改。
 * dek_out    ：输出 32B 还原后的 DEK
 * wrapped    ：输入 48B 密文
 * nonce      ：输入 24B 对应 nonce
 * master_key ：输入 32B MEK
 * 返回 0 成功，非 0 失败（含认证失败）。
 */
int keymanager_unwrap_dek(uint8_t dek_out[VERTHYS_KEY_BYTES],
                          const uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES],
                          const uint8_t nonce[VERTHYS_AEAD_NONCE_BYTES],
                          const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* ---------- 记录级密钥派生 ----------
 * 从 DEK 派生单条记录的细粒度密钥。
 * record_key  ：输出 32B
 * dek         ：输入 32B
 * record_id   ：记录标识（如名称或序号字节串）
 * id_len      ：record_id 字节数
 * 返回 0 成功，非 0 失败。
 */
int keymanager_derive_record_key(uint8_t record_key[VERTHYS_KEY_BYTES],
                                 const uint8_t dek[VERTHYS_KEY_BYTES],
                                 const uint8_t *record_id, size_t id_len);

/* ===================================================================== *
 *                     三密钥分立                                       *
 * ===================================================================== *
 * 从 MEK 派生三个独立用途密钥：
 *   A 密钥（索引密钥）：仅解密索引区，权限为"读+写偏移"，由扫描模块持有
 *   B 密钥（数据密钥）：解密具体数据块，仅由文件浏览/导出模块持有
 *   C 密钥（超级块密钥）：仅用于容器创建和原子提交更新，扫描模块无权限修改
 *
 * 派生方式：HKDF-Expand(MEK, info_label)
 *   A = HKDF(MEK, "verthys/key-a-index-v2")
 *   B = HKDF(MEK, "verthys/key-b-data-v2")
 *   C = HKDF(MEK, "verthys/key-c-superblock-v2")
 */

/* 派生 A 密钥（索引密钥） */
int keymanager_derive_key_a(uint8_t key_a[VERTHYS_KEY_BYTES],
                            const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* 派生 B 密钥（数据密钥） */
int keymanager_derive_key_b(uint8_t key_b[VERTHYS_KEY_BYTES],
                            const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* 派生 C 密钥（超级块密钥） */
int keymanager_derive_key_c(uint8_t key_c[VERTHYS_KEY_BYTES],
                            const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* 一次性派生三密钥 */
int keymanager_derive_three_keys(uint8_t key_a[VERTHYS_KEY_BYTES],
                                 uint8_t key_b[VERTHYS_KEY_BYTES],
                                 uint8_t key_c[VERTHYS_KEY_BYTES],
                                 const uint8_t master_key[VERTHYS_KEY_BYTES]);

/* ---------- 生成 Mount Salt（防回滚） ----------
 * 生成 32B 随机 mount salt，用于防回滚/克隆攻击检测
 */
void keymanager_generate_mount_salt(uint8_t mount_salt[VERTHYS_KEY_BYTES]);

/* ===================================================================== *
 * V3 域分离派生（解锁流水线 S2）                                        *
 * ===================================================================== *
 * V3 密钥层次（与 V1/V2 标签严格隔离）：
 *   DKM  = Argon2id(password ‖ pepper, salt, 参数来自超级块) → 32B 瞬时
 *   MEK  = HKDF-Expand(DKM, "verthys/master-key-v3") → 32B
 *   integrity_key = HKDF-Expand(MEK, "verthys/integrity-key-v3") → 32B
 *（超级块 HMAC / 温缓存 HMAC 语境；DKM 与 MEK 派生后立即清零——
 *  MEK 仅在 S2→S3 交接栈帧瞬态存在，导入 CNG 后清零。）
 *
 * 返回码：0 成功 / -1 通用失败 / -2 pepper 来源错误
 *（上层映射 VERTHYS_ERR_PEPPER_SOURCE，S0/S2 快速失败）。
 */
int keymanager_derive_master_v3(uint8_t master_key[VERTHYS_KEY_BYTES],
                                const uint8_t *password, size_t pw_len,
                                const uint8_t salt[VERTHYS_SALT_BYTES],
                                uint32_t mem_kib,
                                uint32_t iters,
                                uint32_t parallel);

/* V3 完整性密钥：HKDF-Expand(MEK, "verthys/integrity-key-v3") → 32B。
 * 与历史完整性密钥派生标签隔离（域分离，防跨版本混用）。
 * 返回 0 成功，非 0 失败。 */
int keymanager_derive_integrity_key_v3(uint8_t out[VERTHYS_KEY_BYTES],
                                       const uint8_t master_key[VERTHYS_KEY_BYTES]);

#endif /* VERTHYS_KEYMANAGER_H */
