/*
 * vty_types.h — 容器与密钥体系的共享常量与错误码（内部，不导出）
 *
 * 为什么要独立成文件：容器格式层、密钥槽层、记录层与模块层共享同一套
 * 错误码与长度常量；若分散定义，任一处改动都会导致跨层判定漂移。
 */
#ifndef VTY_TYPES_H
#define VTY_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include "verthys_version.h"   /* 容器格式版本唯一事实源 */

/* 结果码：对外保持稳定，调用方按码分支，不解析文本。
 * 错误路径不得泄露“口令错 / 缺槽 / 设备状态”的细分差异——所有
 * 解包失败统一收敛到 VTY_E_KEY_INVALID / VTY_E_AEAD。 */
typedef enum {
    VTY_OK                   = 0,
    VTY_E_INVALID            = 1,   /* 入参非法、越界、格式自相矛盾 */
    VTY_E_VERSION            = 2,   /* 主版本不支持（含异种格式文件） */
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
    VTY_E_CALLER             = 16,  /* 调用方未通过发布者签名校验 */
    VTY_E_KEYFILE_REQUIRED   = 17,  /* KEYFILE 标志置位但未提供 keyfile */
    VTY_E_KEYFILE_INVALID    = 18,  /* VKFL 格式/校验失败 */
    VTY_E_EXISTS             = 19,  /* 目标文件已存在（keyfile 新建必须独占） */
    VTY_E_ROTATE_PENDING     = 20,  /* DEK 全库轮换仍在进行（调用方应稍后重试） */
    VTY_E_MODULE_LOCKED      = 21,  /* 目标模块未解锁，操作被拒绝 */
    VTY_E_NO_SPACE           = 22,  /* 数据区/文件系统空间不足 */
    VTY_E_VERIFY             = 23   /* 完整性复核失败（与 AEAD 认证失败区分） */
} VtyResult;

/* 固定长度 */
#define VTY_KEY_BYTES        32u
#define VTY_NONCE_BYTES      24u
#define VTY_TAG_BYTES        16u
#define VTY_SALT_BYTES       32u
#define VTY_UUID_BYTES       16u
#define VTY_HASH_BYTES       32u

/* 容器头部 */
#define VTY_MAGIC         0x59545256u   /* 小端 0x56 'V' 0x52 'R' 0x54 'T' 0x59 'Y' */
#define VTY_VERSION_MAJOR VERTHYS_CONTAINER_FORMAT_VERSION
/* 数据区/数据根格式。只接受当前值，不提供双解析，
 * 否则攻击者可在同一文件里诱导解析器走不同语义。 */
#define VTY_VERSION_MINOR 2u
#define VTY_HEADER_FIXED_BYTES 76u
#define VTY_HEADER_HASH_BYTES  32u
#define VTY_MAX_SLOTS     16u

/* A/B 元数据副本与数据区。每个副本固定 64 KiB，数据区从 128 KiB 起，
 * 这样保存只需覆盖非活动副本，数据段追加不会触及元数据。 */
#define VTY_META_COPY_BYTES  65536u
#define VTY_META_COPIES      2u
#define VTY_DATA_OFFSET      (VTY_META_COPY_BYTES * VTY_META_COPIES)
/* 固定头内 generation 的偏移：44..52；其后 24B 保留区必须全零。 */
#define VTY_GENERATION_OFFSET 44u
#define VTY_RESERVED_TAIL_BYTES 24u

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

/* KDF 区间：低于下限拒绝（不提供“兼容降低”）；高于上限同样拒绝，
 * 否则恶意文件可用超高内存/迭代把解锁拖入不可控的资源消耗。 */
#define VTY_ARGON2_MEM_KIB_MIN   65536u          /* 64 MiB */
#define VTY_ARGON2_ITERS_MIN     3u
#define VTY_ARGON2_PARALLEL_MIN  1u
#define VTY_ARGON2_PARALLEL_MAX  4u
#define VTY_ARGON2_ITERS_MAX     8u
#define VTY_ARGON2_MEM_KIB_MAX   (256u * 1024u)  /* 256 MiB */

/* 域分离字符串（唯一且不可互换） */
#define VTY_DOMAIN_SLOT        "verthys/v4/slot"
#define VTY_DOMAIN_HEADER      "verthys/v4/header"
#define VTY_DOMAIN_RECOVERY    "verthys/v4/recovery"
#define VTY_DOMAIN_RECORD      "verthys/v4/record"
#define VTY_DOMAIN_NAME        "verthys/v4/name"
#define VTY_DOMAIN_NAME_INDEX  "verthys/v4/name-index"
#define VTY_DOMAIN_TYPE_INDEX  "verthys/v4/type-index"
#define VTY_DOMAIN_CHUNK       "verthys/v4/chunk"
#define VTY_DOMAIN_CHUNK_ID    "verthys/v4/chunk-id"
#define VTY_DOMAIN_MANIFEST    "verthys/v4/manifest"
#define VTY_DOMAIN_KEYRING     "verthys/v4/keyring"
#define VTY_DOMAIN_MODULE      "verthys/v4/module"
#define VTY_DOMAIN_MODULE_RECOVERY "verthys/v4/module-recovery"
#define VTY_DOMAIN_DIR         "verthys/v4/dir"
#define VTY_DOMAIN_DATA_ROOT   "verthys/v4/data-root"
#define VTY_DOMAIN_EMPTY_ROOT  "verthys/v4/empty-root"
#define VTY_DOMAIN_SYSTEM_RECORD "verthys/v4/system-record"

/* Keyring 条目种类：K_c、MDEK 与 DataRoot；GMK 不生成，
 * 以免在“口令 + 设备根”之外多出一条可被单独攻击的密钥层。 */
#define VTY_KEYKIND_KC        1u
#define VTY_KEYKIND_MDEK      3u
#define VTY_KEYKIND_DATA_ROOT 4u

/* 数据区段头：32B 大端，头后紧跟 nonce + 密文。 */
#define VTY_SEG_MAGIC        0x56345347u  /* 'V' '4' 'S' 'G'（大端字节序） */
#define VTY_SEG_HEADER_BYTES 32u
#define VTY_SEG_RECORD       1u
#define VTY_SEG_CHUNK        2u
#define VTY_SEG_DIR          3u

/* 目录键空间：0=记录，1=名称，2=类型，3=文件，4=分片，5=模块表。
 * 分开编号使任何跨空间拼接在字节层就不可互换。 */
#define VTY_KS_RECORD 0u
#define VTY_KS_NAME   1u
#define VTY_KS_TYPE   2u
#define VTY_KS_FILE   3u
#define VTY_KS_CHUNK  4u
#define VTY_KS_MODULE 5u

/* 模块表固定三槽；module_index 是公开枚举（photo/accounts/fileverthys），
 * 不依赖 Keyring 条目顺序。 */
#define VTY_MODULE_COUNT 3u
#define VTY_MODULE_DESC_FIXED 64u
#define VTY_MODULE_RECOVERY_BYTES 76u
#define VTY_MODULE_DESC_MAX 1024u
#define VTY_MODULE_EPOCH_DISABLED 0u
#define VTY_MODULE_EPOCH_ENABLED  1u
#define VTY_MODULE_FLAG_ENABLED   0x01u
#define VTY_MODULE_FLAG_DELETED   0x02u
#define VTY_MODULE_SLOT_USER     0u
#define VTY_MODULE_SLOT_DEVICE   1u
#define VTY_MODULE_SLOT_RECOVERY 2u

/* DataRoot locator 固定 32B；Keyring 条目 id 缓冲随之为 32B。 */
#define VTY_DATA_ROOT_BYTES   32u
#define VTY_KEYRING_ID_MAX    32u

#endif /* VTY_TYPES_H */
