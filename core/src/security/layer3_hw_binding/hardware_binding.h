/*
 * hardware_binding.h — 机器实例指纹绑定（内部模块，不导出）
 *
 * ★ 弃用 CPUID/SMBIOS/UEFI 变量，改用 MachineGuid。

 * 原实现缺陷：
 *   - CPUID leaf 1 是 family/model/stepping + feature flags，同型号所有
 *     CPU 完全相同，不构成任何唯一性（"硬件绑定"名不符实）；
 *   - SMBIOS UUID 在大量主板/虚拟机上为全 0/全 FF，此时绑定退化为静态盐；
 *   - UEFI 变量读取需要 SE_SYSTEM_ENVIRONMENT_PRIVILEGE，普通用户进程
 *     必然失败，UEFI 分支在现实中几乎不生效。
 *
 * 新实现：
 *   MachineGuid = HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
 *   （OS 安装时生成、随系统持久、克隆检测友好），指纹 =
 *   HMAC-SHA256(domain_key, MachineGuid)，跨同型号机器区分度由
 *   MachineGuid 唯一性保障。可选的 TPM EK 增强由 cng_machine_key 的
 *   TPM 绑定路径承担（pepper 包装已绑定机器）。
 */
#ifndef VERTHYS_HARDWARE_BINDING_H
#define VERTHYS_HARDWARE_BINDING_H

#include <stdint.h>
#include <stddef.h>

/* system_instance 哈希长度（SHA-256 = 32 字节） */
#define HW_INSTANCE_HASH_BYTES 32

/* 绑定模式 */
typedef enum {
    HW_BIND_UEFI_SECUREBOOT = 0,  /* （已弃用取值，保留枚举 ABI） */
    HW_BIND_BIOS_FALLBACK   = 1,  /* （已弃用取值，保留枚举 ABI） */
    HW_BIND_MACHINE_GUID    = 2,  /* MachineGuid 指纹（唯一生效模式） */
} HwBindMode;

/*
 * 初始化硬件绑定模块。
 * 读取 MachineGuid 并预计算 system_instance 指纹（HMAC-SHA256）。
 * 返回 0 成功，非 0 失败（注册表不可读等）。
 */
int hardware_binding_init(void);

/*
 * 获取 system_instance 哈希（用于 CNG OAEP label 和 verthys 绑定）。
 *   hash: 输出 32 字节 SHA-256 哈希
 */
int hardware_binding_get_hash(uint8_t hash[HW_INSTANCE_HASH_BYTES]);

/*
 * 获取当前绑定模式。
 */
HwBindMode hardware_binding_get_mode(void);

/*
 * 验证给定哈希是否匹配当前机器。
 *   expected: 期望的 32 字节哈希
 * 返回 0=匹配，非 0=不匹配（迁移失败）。
 */
int hardware_binding_verify(const uint8_t expected[HW_INSTANCE_HASH_BYTES]);

#endif /* VERTHYS_HARDWARE_BINDING_H */
