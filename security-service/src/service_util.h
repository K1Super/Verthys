/*
 * service_util.h — 路径、ACL、注册表、事件日志与安全清零工具
 *
 * 所有路径均使用宽字符与 W 系列 API，避免 ANSI 代码页截断非 ASCII 目录。
 * ACL 轮廓集中定义在本模块，服务、安装器与测试共用同一份事实源。
 */
#ifndef VTY_SERVICE_UTIL_H
#define VTY_SERVICE_UTIL_H

#include <windows.h>
#include <shlobj.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_PATH_MAX 512u
#define VTY_SID_BUF_BYTES 256u
#define VTY_REGISTRY_TEXT_MAX 512u
#define VTY_SID_LOG_HEX_CHARS 16u

/*
 * ACL 轮廓：
 *   PARENT         %ProgramData%\Verthys：SYSTEM/Administrators 完全控制，Users 读+执行
 *   SECURITY_DIR   %ProgramData%\Verthys\Security：SYSTEM 完全控制，Administrators 只读
 *   INSTALL_DIR    %ProgramFiles%\Verthys\SecurityService：SYSTEM/Administrators 完全控制，Users 读+执行
 *   STATE_FILE     状态/密钥文件：SYSTEM 完全控制，Administrators 只读
 *   REGISTRY       HKLM 服务键：SYSTEM/Administrators 完全控制，Users 只读
 */
typedef enum VtyAclProfile {
    VTY_ACL_PROFILE_PARENT = 0,
    VTY_ACL_PROFILE_SECURITY_DIR = 1,
    VTY_ACL_PROFILE_INSTALL_DIR = 2,
    VTY_ACL_PROFILE_STATE_FILE = 3,
    VTY_ACL_PROFILE_REGISTRY = 4
} VtyAclProfile;

int vty_wide_copy(wchar_t *dst, size_t cap, const wchar_t *src);
int vty_path_join(wchar_t *out, size_t cap, const wchar_t *dir,
                  const wchar_t *name);
int vty_known_folder(REFKNOWNFOLDERID folder, wchar_t *out, size_t cap);
int vty_path_exists(const wchar_t *path);
int vty_path_is_directory(const wchar_t *path);
int vty_path_has_reparse(const wchar_t *path, int allow_missing);

/* 读取文件并要求大小精确等于 expected；拒绝重解析点与目录。 */
int vty_read_file_exact(const wchar_t *path, uint8_t *buf, DWORD expected,
                        DWORD cap);

/* 读取任意大小文件（上限 cap）；拒绝重解析点与目录。 */
int vty_read_file_any(const wchar_t *path, uint8_t *buf, DWORD cap, DWORD *len);

/* 同目录临时文件 + FlushFileBuffers + 原子替换。 */
int vty_write_file_atomic(const wchar_t *dir, const wchar_t *name,
                          const uint8_t *data, DWORD len);

/* 显式指定临时文件名（状态文件需要固定 machine_rate.tmp）。 */
int vty_write_file_atomic_named(const wchar_t *dir, const wchar_t *final_name,
                                const wchar_t *temp_name,
                                const uint8_t *data, DWORD len);

uint64_t vty_utc_now_100ns(void);
uint64_t vty_unix_seconds_now(void);
void vty_secure_zero(void *p, size_t n);

int vty_get_well_known_sid(WELL_KNOWN_SID_TYPE type, PSID sid, DWORD *len);
int vty_sid_equal(PSID a, PSID b);
int vty_sid_hash(PSID sid, uint8_t out[32]);
/* 输出 SHA-256 前 8 字节的 16 位小写十六进制，用于事件日志。 */
int vty_sid_hash_log_hex(const uint8_t hash[32],
                         wchar_t out[VTY_SID_LOG_HEX_CHARS + 1u]);

int vty_enable_privilege(const wchar_t *name);

const wchar_t *vty_acl_sddl(VtyAclProfile profile);

/* 生产路径：施加 ACL 并校验 owner 为 SYSTEM。 */
int vty_acl_apply_path(const wchar_t *path, VtyAclProfile profile);
int vty_acl_verify_path(const wchar_t *path, VtyAclProfile profile);

/*
 * 测试/受限环境变体：require_system_owner=0 时允许当前用户持有 owner，
 * 仅用于非 SYSTEM 身份下的 ACL 单元测试；生产路径不得使用。
 */
int vty_acl_apply_path_ex(const wchar_t *path, VtyAclProfile profile,
                          int require_system_owner);
int vty_acl_verify_path_ex(const wchar_t *path, VtyAclProfile profile,
                           int require_system_owner);

int vty_acl_apply_registry(HKEY key, VtyAclProfile profile);
int vty_acl_verify_registry(HKEY key, VtyAclProfile profile);
int vty_acl_apply_registry_ex(HKEY key, VtyAclProfile profile,
                              int require_system_owner);
int vty_acl_verify_registry_ex(HKEY key, VtyAclProfile profile,
                               int require_system_owner);

/* 卸载/重置状态：临时接管所有权并授予管理员完全控制。 */
int vty_acl_force_admin_full(const wchar_t *path);

int vty_registry_read_dword(HKEY key, const wchar_t *name, DWORD *out);
int vty_registry_write_dword(HKEY key, const wchar_t *name, DWORD value);
int vty_registry_read_qword(HKEY key, const wchar_t *name, uint64_t *out);
int vty_registry_write_qword(HKEY key, const wchar_t *name, uint64_t value);
int vty_registry_read_string(HKEY key, const wchar_t *name,
                             wchar_t *out, size_t cap);
int vty_registry_write_string(HKEY key, const wchar_t *name,
                              const wchar_t *value);
int vty_registry_read_binary(HKEY key, const wchar_t *name,
                             uint8_t *out, DWORD cap, DWORD *len);
int vty_registry_write_binary(HKEY key, const wchar_t *name,
                              const uint8_t *data, DWORD len);
int vty_registry_delete_value(HKEY key, const wchar_t *name);

int vty_get_process_image_path(HANDLE process, wchar_t *out, size_t cap);
int vty_get_self_image_path(wchar_t *out, size_t cap);

void vty_event_log(WORD type, DWORD id, const wchar_t *detail);

#ifdef __cplusplus
}
#endif

#endif /* VTY_SERVICE_UTIL_H */
