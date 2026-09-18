/*
 * cng_machine_key.h — CNG 机器密钥防导出加固（内部模块，不导出）
 *
 * 用户需求（三、固件与硬件绑定 — 1. CNG 机器密钥防导出加固）：
 *   - NCRYPT_MACHINE_KEY 禁用私钥导出
 *   - 密钥容器 ACL 仅 SYSTEM 可读写，管理员不可导出
 *   - GMK 盐值 RSA-OAEP 二次包装，绑定系统实例
 *
 * 设计原理：
 *   GMK 派生需要长期保存的盐值，明文存储易被提取后离线暴力破解。
 *   本模块使用 CNG 机器级密钥对（NCRYPT_MACHINE_KEY）对盐值进行
 *   RSA-OAEP 二次包装：
 *
 *     1. 首次部署：生成 2048-bit RSA 机器密钥对（NCRYPT_MACHINE_KEY_FLAG）
 *     2. 密钥容器 ACL 仅 SYSTEM 可读写，管理员 ACCESS_DENIED
 *     3. GMK 盐值经 RSA-OAEP 加密后存储，明文永不落盘
 *     4. 解密时调用 NCryptDecrypt，机器密钥不出内核
 *     5. 跨设备迁移时机器密钥不可用，盐值无法解密 → 防止跨设备迁移攻击
 *
 *   绑定系统实例：
 *     RSA-OAEP 加密时附加 system_instance 标识（来自 hardware_binding.h）
 *     作为 OAEP label，机器实例不匹配时解密失败。
 */
#ifndef VERTHYS_CNG_MACHINE_KEY_H
#define VERTHYS_CNG_MACHINE_KEY_H

#include <stdint.h>
#include <stddef.h>

/* RSA-2048 密文长度（256 字节） */
#define CMK_RSA_CIPHER_BYTES 256
/* GMK 盐值长度（32 字节） */
#define CMK_GMK_SALT_BYTES   32
/* OAEP label 长度（system_instance 哈希） */
#define CMK_OAEP_LABEL_BYTES 32

/*
 * 初始化 CNG 机器密钥模块。
 * 打开 NCRYPT_STORAGE_PROVIDER 并确保 RSA 密钥对存在。
 *
 * 优雅降级策略：
 *   机器级密钥（需 SYSTEM）失败时回退到用户级密钥，
 *   两者均失败时不阻塞 Verthys_Init，但密钥不可用。
 *   调用方应通过 cng_machine_key_is_available() 查询实际可用性。
 *
 * 返回 0 成功（始终，除非严重环境问题）。
 */
int cng_machine_key_init(void);

/*
 * 查询密钥是否实际可用。
 * 返回 1 可用（wrap/unwrap 可调用），0 不可用（已优雅降级）。
 */
int cng_machine_key_is_available(void);

/*
 * 包装（加密）GMK 盐值。
 *   salt: 32 字节 GMK 盐值明文
 *   cipher: 输出 256 字节 RSA-OAEP 密文
 *   label: 32 字节 system_instance 哈希（OAEP label）
 * 返回 0 成功，非 0 失败。
 */
int cng_machine_key_wrap(const uint8_t salt[CMK_GMK_SALT_BYTES],
                          uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                          const uint8_t label[CMK_OAEP_LABEL_BYTES]);

/*
 * 解包（解密）GMK 盐值。
 *   cipher: 256 字节 RSA-OAEP 密文
 *   salt: 输出 32 字节 GMK 盐值明文
 *   label: 32 字节 system_instance 哈希（必须与加密时一致）
 * 返回 0 成功，非 0 失败（机器不匹配或解密失败）。
 */
int cng_machine_key_unwrap(const uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                            uint8_t salt[CMK_GMK_SALT_BYTES],
                            const uint8_t label[CMK_OAEP_LABEL_BYTES]);

/*
 * 销毁机器密钥（仅用于应急销毁，正常路径不调用）。
 */
void cng_machine_key_destroy(void);

#endif /* VERTHYS_CNG_MACHINE_KEY_H */
