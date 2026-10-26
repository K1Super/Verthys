/*
 * vty_keymanager_v4.h — v4 库创建、解锁与会话（内部，不导出）
 *
 * 双包裹采用“异或分享”实现真正的 AND：口令槽只解出一半，设备槽
 * 解出另一半；任一单边都不足以还原容器 DEK。恢复槽独立承载完整
 * Keyring，仅用于换机与灾难恢复。
 */
#ifndef VTY_KEYMANAGER_V4_H
#define VTY_KEYMANAGER_V4_H

#include "vty_v4_types.h"
#include "vty_format_v4.h"
#include "vty_keyslot_v4.h"
#include "vty_recovery.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_V4_MAX_MODULES 4u

typedef struct {
    VtyV4Header header;
    VtySlot slots[VTY_V4_MAX_SLOTS];
    uint32_t slot_count;
    uint8_t *header_buf;      /* 序列化后的头部（含槽与尾哈希），保存时复用 */
    size_t header_len;
    char path[1024];          /* 库文件路径，保存/轮换时原子替换 */
    uint8_t kc[VTY_KEY_BYTES];
    uint8_t kg[VTY_KEY_BYTES];
    VtyKeyring keyring;
    int unlocked;
    uint32_t mem_kib;
    uint32_t iters;
    uint32_t parallel;
} VtyVault;

/* 创建：默认 Argon2id 参数（64 MiB / 3 / 1），生成恢复码文本 */
int vty_vault_create(const char *path, const char *password,
                     VtyVault **out,
                     char *recovery_text, size_t recovery_cap);

/* 创建：自定义 KDF 参数；低于下限直接 VTY_E_KDF_WEAK */
int vty_vault_create_ex(const char *path, const char *password,
                        uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                        VtyVault **out,
                        char *recovery_text, size_t recovery_cap);

/* 创建：额外启用 PCR 绑定（pcr_select 为 PCR0–23 位图，需 TPM 可用）。
 * 无 TPM/PCR 不可读时返回 VTY_E_TPM，且不留下半成品库。 */
int vty_vault_create_pcr(const char *path, const char *password,
                         uint32_t pcr_select,
                         VtyVault **out,
                         char *recovery_text, size_t recovery_cap);

/* 在已解锁库上启用 PCR 绑定。调用方必须先完成恢复码二次认证；
 * 本函数只负责密码学操作，不承担用户确认职责。 */
int vty_vault_pcr_enable(VtyVault *v, uint32_t pcr_select);

/* 关闭 PCR 绑定（保留设备根槽）。调用方必须先完成口令 + 恢复码二次认证。 */
int vty_vault_pcr_disable(VtyVault *v);

/* 用当前 PCR 重新绑定：供恢复码解锁后、设备环境已变化时使用。
 * 成功后才更新槽并落盘；失败时槽保持旧值，需再次用恢复码重试。 */
int vty_vault_pcr_reseal(VtyVault *v);

/* 标准解锁：口令 + 设备根（AND），失败不产生任何持久副作用 */
int vty_vault_open(const char *path, const char *password, VtyVault **out);

/* 恢复解锁：仅恢复码 */
int vty_vault_open_recovery(const char *path, const char *recovery_text,
                            VtyVault **out);

/* 轮换口令：epoch+1，重写全部槽；返回新的恢复码文本 */
int vty_vault_rotate_password(VtyVault *v, const char *new_password,
                              char *recovery_text, size_t recovery_cap);

/* 落盘（原子替换）；锁定时拒绝。成功写盘后同步推进回退锚点，
 * 使“打开→保存→关闭”窗口内的新写入不能被会话开始的旧副本覆盖。 */
int vty_vault_save(VtyVault *v);

/* 取模块 MDEK；模块 UUID 必须存在于 Keyring */
int vty_vault_module_key(const VtyVault *v, const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint8_t key_out[VTY_KEY_BYTES]);

/* 枚举第 n 个模块 UUID；越界返回 VTY_E_INVALID */
int vty_vault_module_uuid(const VtyVault *v, uint32_t index,
                          uint8_t out[VTY_UUID_BYTES]);

void vty_vault_lock(VtyVault *v);
void vty_vault_free(VtyVault *v);

#ifdef __cplusplus
}
#endif

#endif /* VTY_KEYMANAGER_V4_H */
