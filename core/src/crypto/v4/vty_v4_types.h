/*
 * vty_v4_types.h — v4 容器与密钥体系的共享常量与错误码（内部，不导出）
 *
 * 为什么要独立成文件：容器格式层、密钥槽层、记录层与模块层共享同一套
 * 错误码与长度常量；若分散定义，任一处改动都会导致跨层判定漂移。
 */
#ifndef VTY_V4_TYPES_H
#define VTY_V4_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* 结果码：对外保持稳定，调用方按码分支，不解析文本。
 * 错误路径不得泄露“口令错 / 缺槽 / 设备状态”的细分差异——所有
 * 解包失败统一收敛到 VTY_E_KEY_INVALID / VTY_E_AEAD。 */
typedef enum {
    VTY_OK                   = 0,
    VTY_E_INVALID            = 1,   /* 入参非法、越界、格式自相矛盾 */
    VTY_E_VERSION            = 2,   /* 主版本不支持（含 v3 文件） */
    VTY_E_SLOT_UNKNOWN       = 3,   /* 未知槽类型 / 未知标志位 */
    VTY_E_SLOT_MISSING       = 4,   /* 策略要求的必需槽缺失 */
    VTY_E_KDF_WEAK           = 5,   /* KDF 参数低于下限 */
    VTY_E_KEY_INVALID        = 6,   /* 解包失败（统一错误） */
    VTY_E_AEAD               = 7,   /* 认证失败 */
    VTY_E_POLICY             = 8,   /* 策略拒绝（模式不具备先决条件） */
    VTY_E_TPM                = 9,   /* 设备根 / PCR 不可用 */
    VTY_E_LOCKED             = 10,  /* 熔断锁定中 */
    VTY_E_PLAINTEXT_FORBIDDEN= 11,  /* 拒绝明文回退写入 */
    VTY_E_RESOURCE           = 12,  /* 内存 / 句柄 / 长度预算不足 */
    VTY_E_IO                 = 13,  /* 读写失败 */
    VTY_E_CORRUPT            = 14,  /* 结构损坏 / 完整性校验失败 */
    VTY_E_ROLLBACK           = 15,  /* 库文件版本回退（状态锚点拒绝） */
    VTY_E_CALLER             = 16   /* 调用方未通过发布者签名校验 */
} VtyResult;

/* 固定长度 */
#define VTY_KEY_BYTES        32u
#define VTY_NONCE_BYTES      24u
#define VTY_TAG_BYTES        16u
#define VTY_SALT_BYTES       32u
#define VTY_UUID_BYTES       16u
#define VTY_HASH_BYTES       32u

/* 容器头部 */
#define VTY_V4_MAGIC         0x59545256u   /* 小端 0x56 'V' 0x52 'R' 0x54 'T' 0x59 'Y' */
#define VTY_V4_VERSION_MAJOR 4u
#define VTY_V4_VERSION_MINOR 0u
#define VTY_V4_HEADER_FIXED_BYTES 76u
#define VTY_V4_HEADER_HASH_BYTES  32u
#define VTY_V4_MAX_SLOTS     16u

/* flags 位 */
#define VTY_FLAG_MODULE_M1       0x0001u
#define VTY_FLAG_HIGH_SECURITY   0x0002u
#define VTY_FLAG_KEYFILE         0x0004u
#define VTY_FLAG_PCR             0x0008u
#define VTY_FLAG_RECOVERY        0x0010u
#define VTY_FLAG_KNOWN_MASK      (VTY_FLAG_MODULE_M1 | VTY_FLAG_HIGH_SECURITY | \
                                  VTY_FLAG_KEYFILE | VTY_FLAG_PCR | VTY_FLAG_RECOVERY)

/* 槽类型 */
typedef enum {
    VTY_SLOT_USER_PASSWORD = 1,
    VTY_SLOT_DEVICE_ROOT   = 2,
    VTY_SLOT_DEVICE_PCR    = 3,
    VTY_SLOT_RECOVERY      = 4,
    VTY_SLOT_KEYFILE       = 5,
    VTY_SLOT_FIDO2         = 6
} VtySlotType;

/* 槽 KDF / 包裹算法 */
#define VTY_KDF_NONE      0u
#define VTY_KDF_ARGON2ID  1u
#define VTY_WRAP_XCHACHA  1u
#define VTY_WRAP_AESGCM   2u
#define VTY_WRAP_RSAOAEP  3u

/* KDF 下限：低于该值拒绝解锁，不提供“兼容降低” */
#define VTY_ARGON2_MEM_KIB_MIN   65536u   /* 64 MiB */
#define VTY_ARGON2_ITERS_MIN     3u
#define VTY_ARGON2_PARALLEL_MIN  1u
#define VTY_ARGON2_PARALLEL_MAX  64u
#define VTY_ARGON2_MEM_KIB_MAX   (4u * 1024u * 1024u)

/* 域分离字符串（唯一且不可互换） */
#define VTY_DOMAIN_SLOT        "verthys/v4/slot"
#define VTY_DOMAIN_RECOVERY    "verthys/v4/recovery"
#define VTY_DOMAIN_RECORD      "verthys/v4/record"
#define VTY_DOMAIN_NAME        "verthys/v4/name"
#define VTY_DOMAIN_NAME_INDEX  "verthys/v4/name-index"
#define VTY_DOMAIN_CHUNK       "verthys/v4/chunk"
#define VTY_DOMAIN_CHUNK_ID    "verthys/v4/chunk-id"
#define VTY_DOMAIN_MANIFEST    "verthys/v4/manifest"
#define VTY_DOMAIN_KEYRING     "verthys/v4/keyring"
#define VTY_DOMAIN_MODULE      "verthys/v4/module"

/* 模块 kind（RecoveryKeyring 体内） */
#define VTY_KEYKIND_KC     1u
#define VTY_KEYKIND_KG     2u
#define VTY_KEYKIND_MDEK   3u

#endif /* VTY_V4_TYPES_H */
