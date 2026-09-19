/*
 * cng_machine_key.h — CNG 机器密钥防导出加固（内部模块，不导出）
 *
 *
 * 设计原理：
 *   GMK 派生需要长期保存的盐值，明文存储易被提取后离线暴力破解。
 *   本模块使用 CNG 持久化 RSA 密钥对盐值进行 RSA-OAEP 二次包装：
 *
 *     1. 密钥容器按级别（用户级/机器级，CmkKeyLevel 取值）与 KSP
 *        （CmkKeyProvider）组成 4 槽位，槽序即封装策略序
 *     2. 机器级容器 ACL 仅 SYSTEM 可读写，管理员 ACCESS_DENIED
 *     3. GMK 盐值经 RSA-OAEP 加密后存储，明文永不落盘
 *     4. 解密时调用 NCryptDecrypt，密钥不出内核
 *     5. 跨设备迁移时密钥不可用，盐值无法解密 → 防止跨设备迁移攻击
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

/* 封装密钥级别（pepper 文件头记录该值，加载直达） */
typedef enum {
    CMK_KEY_LEVEL_UNKNOWN = 0,
    CMK_KEY_LEVEL_USER    = 1,   /* 用户级密钥容器（绑定当前用户） */
    CMK_KEY_LEVEL_MACHINE = 2    /* 机器级密钥容器（需 SYSTEM/管理员） */
} CmkKeyLevel;

/* 封装密钥所在 KSP（pepper 文件头记录该值，连同级别唯一定位容器） */
typedef enum {
    CMK_PROVIDER_UNKNOWN      = 0,
    CMK_PROVIDER_PLATFORM_KSP = 1,   /* 平台安全边界（TPM 支撑时绑定最强） */
    CMK_PROVIDER_SOFTWARE_KSP = 2    /* 软件 KSP（KeyIso 内核隔离托管） */
} CmkKeyProvider;

/*
 * 初始化 CNG 密钥槽位。
 *
 * 逐槽打开 provider 与密钥容器（仅 Open 不 Create）。全部容器不存在时，
 * 按策略序创建首个用户级密钥（机器级绝不隐式创建），维持"初始化完成后
 * 具备封装能力"的契约。任何失败均优雅降级，不阻塞调用方。
 *
 * 返回 0 成功（始终，除非严重环境问题）。
 */
int cng_machine_key_init(void);

/*
 * 查询模块是否具备封装能力。
 * 返回 1 可用（至少一个槽位的 provider 可打开），0 不可用（已优雅降级）。
 */
int cng_machine_key_is_available(void);

/*
 * 按策略序封装（加密）GMK 盐值。
 *   策略序：用户级优先（同级别内平台安全边界优先），机器级兜底。
 *   槽位容器缺失（NTE_BAD_KEYSET）时按加固规则创建；创建失败换下一槽。
 *
 *   salt: 32 字节 GMK 盐值明文
 *   cipher: 输出 256 字节 RSA-OAEP 密文
 *   label: 32 字节 system_instance 哈希（OAEP label）
 *   out_level / out_provider: 输出实际使用的级别与 KSP（允许传 NULL）
 * 返回 0 成功，非 0 失败。
 */
int cng_machine_key_seal(const uint8_t salt[CMK_GMK_SALT_BYTES],
                         uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                         const uint8_t label[CMK_OAEP_LABEL_BYTES],
                         int *out_level, int *out_provider);

/*
 * 按记录级别+KSP 直达解包（解密）GMK 盐值。
 *   仅 Open 绝不 Create：容器缺失或解包失败均原样返回错误，
 *   不跨级别回退（回退会掩盖密钥被替换）。
 *
 *   cipher: 256 字节 RSA-OAEP 密文
 *   salt: 输出 32 字节 GMK 盐值明文
 *   label: 32 字节 system_instance 哈希（必须与加密时一致）
 *   key_level / key_provider: 文件记录的级别与 KSP
 * 返回 0 成功，非 0 失败（容器缺失 / 机器不匹配 / 解密失败）。
 */
int cng_machine_key_unwrap_known(const uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                                 uint8_t salt[CMK_GMK_SALT_BYTES],
                                 const uint8_t label[CMK_OAEP_LABEL_BYTES],
                                 int key_level, int key_provider);

/*
 * 释放全部槽位句柄（仅销毁句柄，不删除持久化密钥；
 * 持久化密钥用于下次会话恢复；仅在应急销毁时调用 NCryptDeleteKey）。
 */
void cng_machine_key_destroy(void);

#endif /* VERTHYS_CNG_MACHINE_KEY_H */