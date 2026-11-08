/*
 * vty_secure_state.h — 安全状态的固定位置与身份派生（内部，不导出）
 *
 * 职责边界：
 *   1. 状态目录只由 KnownFolder 解析，禁止读取 LOCALAPPDATA 等可改写环境变量；
 *   2. 目录使用受保护 DACL，拒绝重解析点与非当前用户 owner；
 *   3. 见证域 ID 绑定设备根哈希与主体（熔断为用户 SID，回滚为容器 UUID），
 *      禁止再以状态文件路径作为身份；旧路径与旧路径见证 ID 已废弃。
 *
 * 约束：
 *   - 任何路径/ACL/身份解析失败都返回 VTY_E_POLICY / VTY_E_TPM，调用方必须
 *     fail-closed；本模块不做软件降级。
 *   - 测试注入路径不经过本模块的默认路径，调用方需显式跳过默认路径校验。
 */
#ifndef VTY_SECURE_STATE_H
#define VTY_SECURE_STATE_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_SECURE_STATE_PATH_BYTES 1024u

/* 解析并确保安全状态目录，返回 "<KnownFolder>\\Verthys\\Security\\<name>"。
 * name 只允许不含分隔符的固定文件名；目录不存在时创建并施加受保护 DACL。 */
int vty_secure_state_file_path(const char *name, char *out, size_t cap);

/* N2：安全状态目录预检（解析/创建/ACL 加固与复核，不写状态文件）。
 * 成功返回 VTY_OK；失败返回 VTY_E_POLICY / VTY_E_IO，调用方映射专用错误码。 */
int vty_secure_state_preflight(void);

/* 校验路径：父目录必须是已加固的安全目录；文件存在时拒绝重解析点。
 * allow_missing=1 允许文件尚不存在（写入前调用）。 */
int vty_secure_state_validate_path(const char *path, int allow_missing);

/* 见证域派生：domain + 设备根哈希 + 主体。输出取 SHA-256 前 16 字节。 */
int vty_secure_state_identity_lockout(uint8_t id[VTY_UUID_BYTES]);
int vty_secure_state_identity_rollback(
    const uint8_t vault_uuid[VTY_UUID_BYTES],
    uint8_t id[VTY_UUID_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_SECURE_STATE_H */
