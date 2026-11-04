/*
 * vty_module_v4.h — 模块 M1 模块表与密钥生命周期（内部，不导出）
 *
 * 模块表存放在 v4 目录 keyspace 5；未启用模块的 MDEK 在 body Keyring，
 * 启用后移出 Keyring，只以 share_u/share_d 形式存于模块描述符槽。
 * 因此启用后仅持有 K_c 无法取得 MDEK，模块口令与设备根构成真实边界。
 */
#ifndef VTY_MODULE_V4_H
#define VTY_MODULE_V4_H

#include "vty_v4_types.h"
#include "vty_keymanager_v4.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_MODULE_ALL          0xFFFFFFFFu
#define VTY_MODULE_PASSWORD_MAX 4096u

typedef struct {
    uint8_t enabled;      /* 描述符 bit0 */
    uint8_t unlocked;     /* 仅当前会话 */
    uint8_t has_recovery; /* 已绑定 recovery 槽 */
    uint8_t deleted;      /* 描述符 bit1；无 MDEK/无数据 */
} VtyModuleStatus;

/* 记录类型到模块 index 的冻结映射；未知类型归 0（photo）。 */
uint32_t vty_module_index_for_type(uint8_t type);

/* 创建库：写入 3 条未启用描述符并提交数据区；不写元数据。 */
int vty_module_table_init(VtyVault *v);

/* 打开库：加载并校验模块表与 Keyring kind 3 的一致性。 */
int vty_module_table_load(VtyVault *v);

/* 启用模块：轮换 MDEK、创建 user/device 槽（recovery_code 非空时同时
 * 验证并创建 recovery 槽），单事务重写该模块全部记录与索引。
 * 从 deleted 状态启用时使用描述符中的新 UUID，不查旧 Keyring、不重写记录。 */
int vty_module_enable(VtyVault *v, uint32_t index, const char *password,
                      const char *recovery_code);

/* 删除模块：密码学销毁 MDEK、清除该模块记录/文件/分片叶，描述符进入
 * deleted 状态并轮换 UUID。confirm 必须为 "DELETE"；password 是当前容器
 * 口令（恢复会话可空）。 */
int vty_module_delete(VtyVault *v, uint32_t index,
                      const char *password, const char *confirm);

/* 为已启用模块绑定/更新 recovery 槽；要求模块口令 + 当前恢复码。 */
int vty_module_bind_recovery(VtyVault *v, uint32_t index,
                             const char *password, const char *recovery_code);

/* 解锁模块：口令 + 设备因子（恢复会话可用 recovery 槽替代设备）。 */
__declspec(noinline) int vty_module_unlock(VtyVault *v, uint32_t index,
                                           const char *password);

/* 清除模块密钥缓存；index 为 VTY_MODULE_ALL 时清除全部。无法失败。 */
void vty_module_lock(VtyVault *v, uint32_t index);

/* 模块口令轮换：只重封 user 槽，不重写数据。 */
int vty_module_rotate_password(VtyVault *v, uint32_t index,
                               const char *old_password,
                               const char *new_password);

/* 禁用模块：保留 MDEK 与数据，MDEK 回到 Keyring kind 3。 */
int vty_module_disable(VtyVault *v, uint32_t index, const char *password);

/* 恢复会话中把 device 槽重绑到当前设备根；普通会话调用返回 E_POLICY。 */
int vty_module_reseal_device(VtyVault *v, uint32_t index, const char *password);

/* 查询状态；不返回任何密钥。 */
int vty_module_status(const VtyVault *v, uint32_t index, VtyModuleStatus *out);

/* 恢复码轮换：用旧 K_recovery 解出 share_d，再用新 K_recovery 重封
 * 全部已有 recovery 槽的已启用模块。只写数据区，不提交元数据；
 * 失败时调用方恢复 checkpoint。 */
int vty_module_recovery_reseal_all(VtyVault *v,
                                   const uint8_t k_recovery_old[VTY_KEY_BYTES],
                                   const uint8_t k_recovery_new[VTY_KEY_BYTES]);

/* D9：为已启用但尚未绑定恢复槽的模块创建 recovery 槽。
 * 从 device 槽解出 share_d，用调用方持有的恢复 KEK 重封；只写数据区，
 * 不提交。要求模块已启用且当前 has_recovery=0。 */
int vty_module_recovery_seal(VtyVault *v, uint32_t index,
                             const uint8_t k_recovery[VTY_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_MODULE_V4_H */
