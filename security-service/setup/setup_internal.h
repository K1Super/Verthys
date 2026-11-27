/*
 * setup_internal.h — 安装/卸载子命令的跨文件契约
 *
 * 仅供 security-service/setup 下的 .c 使用；对外入口仍是 setup_entry.h 的
 * vty_service_setup_main。领域划分：
 *   setup_common.c    输出、管理员判定、版本与路径解析、注册表备份
 *   setup_service.c   服务生命周期、事件源、exe 备份替换、安装目录
 *   setup_fs.c        目录删除、SHA-256、根证书导入/删除、目录归档
 *   setup_ping.c      服务公钥读取、PING 往返与就绪探测
 *   setup_driver.c    内核驱动载荷安装/移除与状态文本
 *   setup_commands.c  /install /uninstall /repair /reset-state
 *                     /repair-keys /status 子命令
 *   setup_main.c      入口参数分发与环境前置校验
 */
#ifndef VERTHYS_SETUP_INTERNAL_H
#define VERTHYS_SETUP_INTERNAL_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <winver.h>

#include "client_auth.h"
#include "protocol.h"
#include "service_state.h"
#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#define SETUP_EXIT_OK 0
#define SETUP_EXIT_ARGS 2
#define SETUP_EXIT_NOT_ADMIN 3
#define SETUP_EXIT_SIGNATURE 4
#define SETUP_EXIT_INSTALL 5
#define SETUP_EXIT_START 6
#define SETUP_EXIT_READY 7
#define SETUP_EXIT_ROLLBACK 8

#define SETUP_SERVICE_DACL L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" \
    L"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" \
    L"(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" \
    L"S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

#ifndef VERTHYS_SERVICE_PUBLISHER_SHA256
#define VERTHYS_SERVICE_PUBLISHER_SHA256 ""
#endif
#ifndef VERTHYS_ROOT_CA_SHA256
#define VERTHYS_ROOT_CA_SHA256 ""
#endif

#define SETUP_REG_ROOT_CA_SHA256 L"RootCaSha256"
#define SETUP_REG_DRIVER_RESULT L"DriverInstallResult"
#define SETUP_DRIVER_SERVICE_NAME L"VerthysGuard"
#define SETUP_DRIVER_DIR_NAME L"driver"
#define SETUP_DRIVER_SYS_NAME L"VerthysGuard.sys"
#define SETUP_DRIVER_CAT_NAME L"VerthysGuard.cat"
#define SETUP_DRIVER_INF_NAME L"VerthysGuard.inf"
#define SETUP_EVENT_SOURCE_KEY \
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" \
    L"VerthysSecuritySvc"

typedef enum SetupCommand {
    SETUP_INSTALL = 0,
    SETUP_UNINSTALL = 1,
    SETUP_REPAIR = 2,
    SETUP_RESET_STATE = 3,
    SETUP_REPAIR_KEYS = 4,
    SETUP_STATUS = 5
} SetupCommand;

typedef struct SetupOptions {
    SetupCommand command;
    int quiet;
    int keep_state;
    int test_allow_unsigned;
    int test_skip_ping;
} SetupOptions;

typedef struct SetupRegistryBackup {
    int installed_present;
    DWORD installed;
    int version_present;
    wchar_t version[64];
    int install_path_present;
    wchar_t install_path[VTY_PATH_MAX];
} SetupRegistryBackup;

/* ---------- setup_common.c ---------- */

extern int g_quiet;

void setup_print(const wchar_t *format, ...);
int is_admin(void);
DWORD os_build_number(void);
int get_file_version(const wchar_t *path, DWORD *major, DWORD *minor,
                     DWORD *patch);
int parse_version_text(const wchar_t *text, DWORD *major, DWORD *minor,
                       DWORD *patch);
int version_compare(DWORD a1, DWORD a2, DWORD a3, DWORD b1, DWORD b2,
                    DWORD b3);
int build_paths(wchar_t *setup_dir_out, VtyServicePaths *paths);
void read_registry_backup(HKEY key, SetupRegistryBackup *backup);
void restore_registry_backup(HKEY key, const SetupRegistryBackup *backup);

/* ---------- setup_service.c ---------- */

int stop_service(SC_HANDLE service);
int start_service(SC_HANDLE service);
int register_event_source(const wchar_t *exe_path);
int unregister_event_source(void);
int backup_existing_exe(const wchar_t *exe_path, wchar_t *backup_path,
                        size_t cap, int *had_exe);
int replace_service_exe(const wchar_t *source, const wchar_t *dest);
int ensure_install_dir(const VtyServicePaths *paths);
int install_or_update_service(SC_HANDLE scm, const wchar_t *exe_path,
                              SC_HANDLE *service, int *created);
void rollback_service(SC_HANDLE scm, SC_HANDLE service, int created,
                      const wchar_t *exe_path, const wchar_t *backup_path,
                      int had_exe, HKEY key,
                      const SetupRegistryBackup *registry_backup,
                      const wchar_t *security_dir, int had_anchor,
                      PCCERT_CONTEXT *ca_ctx, int ca_new);

/* ---------- setup_fs.c ---------- */

void delete_tree(const wchar_t *path);
int sha256_file_hex(const wchar_t *path, wchar_t out[65]);
int root_ca_pin_matches(const wchar_t *sha_hex);
int delete_root_cert_by_sha256(const wchar_t *sha_hex);
void remove_parent_if_empty(const wchar_t *security_dir);
int fail_with_ca(PCCERT_CONTEXT *ctx, int newly_added, int code);
int archive_security_dir(const wchar_t *security_dir, const wchar_t *suffix);
int import_bundled_root_ca(const wchar_t *setup_dir, wchar_t root_sha[65],
                           PCCERT_CONTEXT *added_ctx, int *newly_added);

/* ---------- setup_ping.c ---------- */

int readiness(HKEY key, int skip_ping);

/* ---------- setup_driver.c ---------- */

int driver_install_payload(const VtyServicePaths *paths,
                           const wchar_t *setup_dir, int allow_unsigned,
                           wchar_t *result, size_t result_cap);
int driver_remove_payload(const VtyServicePaths *paths, wchar_t *result,
                          size_t result_cap);
const wchar_t *driver_state_text(void);

/* ---------- setup_commands.c ---------- */

int do_install(const SetupOptions *options);
int do_uninstall(const SetupOptions *options);
int do_reset_state(void);
int do_repair_keys(void);
int do_repair(void);
int do_status(void);

#endif /* VERTHYS_SETUP_INTERNAL_H */
