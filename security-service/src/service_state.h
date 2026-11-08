/*
 * service_state.h — 服务路径、目录 ACL、注册表锚点与启动引导
 *
 * 启动结果分三类：
 *   OK          服务正常提供预算
 *   FAIL_CLOSED 服务运行但拒绝所有预算请求（状态缺失/损坏/锚点不一致）
 *   REFUSE      服务拒绝启动（ACL 放宽、签名密钥不可用、目录被重解析）
 */
#ifndef VTY_SERVICE_STATE_H
#define VTY_SERVICE_STATE_H

#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>
#include <stdint.h>

#include "machine_state.h"
#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_SERVICE_EXE_NAME L"VerthysSecuritySvc.exe"
#define VTY_SERVICE_INSTALL_SUFFIX L"Verthys\\SecurityService"
#define VTY_SIGNING_KEY_FILE_NAME L"service_signing.key"

/* 注册表值名统一引用 vty_svc_protocol.h 的单点定义。 */

#define VTY_STATE_GENERATION_CURRENT 1u

typedef struct VtyServicePaths {
    wchar_t programdata[VTY_PATH_MAX];
    wchar_t parent_dir[VTY_PATH_MAX];
    wchar_t security_dir[VTY_PATH_MAX];
    wchar_t state_file[VTY_PATH_MAX];
    wchar_t state_key_file[VTY_PATH_MAX];
    wchar_t signing_key_file[VTY_PATH_MAX];
    wchar_t temp_file[VTY_PATH_MAX];
    wchar_t program_files[VTY_PATH_MAX];
    wchar_t install_dir[VTY_PATH_MAX];
    wchar_t service_exe[VTY_PATH_MAX];
} VtyServicePaths;

typedef struct VtyRegistryLocation {
    HKEY hive;
    wchar_t root[VTY_REGISTRY_TEXT_MAX];
    DWORD view;
} VtyRegistryLocation;

typedef struct VtyServiceAnchors {
    int installed_present;
    DWORD installed;
    int state_initialized_present;
    DWORD state_initialized;
    int generation_present;
    DWORD generation;
    int protocol_present;
    DWORD protocol;
    int created_present;
    uint64_t created_utc;
    int pubkey_present;
    uint8_t pubkey[VTY_ECC_BLOB_MAX];
    DWORD pubkey_len;
} VtyServiceAnchors;

typedef struct VtyServiceRuntimeConfig {
    wchar_t pipe_name[128];
    wchar_t registry_root[VTY_REGISTRY_TEXT_MAX];
    wchar_t test_state_dir[VTY_PATH_MAX];
    int test_mode;
    int test_ignore_client_auth;
    int test_ignore_user_quota;
    int64_t test_utc_offset_100ns;
    int64_t test_ms_offset;
    int test_run_seconds;
    wchar_t publisher_sha256[65];
} VtyServiceRuntimeConfig;

typedef struct VtyServiceContext {
    VtyServiceRuntimeConfig cfg;
    VtyServicePaths paths;
    VtyRegistryLocation registry;
    VtyServiceAnchors anchors;
    VtyMachineState state;
    BCRYPT_KEY_HANDLE signing_key;
    uint8_t signing_pub_blob[VTY_ECC_BLOB_MAX];
    DWORD signing_pub_len;
    volatile LONG fail_closed;
    HANDLE stop_event;
} VtyServiceContext;

typedef enum VtyServiceInitResult {
    VTY_SERVICE_INIT_OK = 0,
    VTY_SERVICE_INIT_FAIL_CLOSED = 1,
    VTY_SERVICE_INIT_REFUSE = 2
} VtyServiceInitResult;

/* 解析 %ProgramData%\Verthys\Security 下全部固定路径。 */
int vty_service_paths_resolve(VtyServicePaths *paths);

/* 解析 %ProgramFiles%\Verthys\SecurityService 安装路径。 */
int vty_service_paths_resolve_install(VtyServicePaths *paths);

/* 创建/加固目录并复核。test_mode 跳过 ACL 施加（仅临时目录测试）。 */
int vty_service_paths_ensure_dirs(const VtyServicePaths *paths, int test_mode);
int vty_service_paths_verify_dirs(const VtyServicePaths *paths, int test_mode);

/* 对已存在的状态/密钥文件施加 STATE_FILE ACL。 */
int vty_service_paths_harden_files(const VtyServicePaths *paths, int test_mode);

/* 打开/创建注册表键；生产模式同时加固 ACL。 */
int vty_service_registry_open(const VtyRegistryLocation *location, int create,
                              PHKEY key_out);
int vty_service_registry_harden(HKEY key);

void vty_service_registry_location_production(VtyRegistryLocation *location);
void vty_service_registry_location_test(VtyRegistryLocation *location,
                                        const wchar_t *root);

int vty_service_anchors_read(HKEY key, VtyServiceAnchors *anchors);
int vty_service_write_pubkey(HKEY key, const uint8_t *blob, DWORD len);
int vty_service_write_initial_anchors(HKEY key, const uint8_t *pubkey,
                                      DWORD pubkey_len, uint64_t created_utc);

/* 生产运行时配置：HKLM 64 位视图、生产管道名、编译期发布者指纹。 */
void vty_service_runtime_config_production(VtyServiceRuntimeConfig *cfg);

/*
 * 初始化服务上下文：路径、CLI/ACL、密钥、状态与锚点。
 * 失败语义见文件头三分类。成功时 ctx->signing_key 可用，ctx->state 已初始化。
 */
VtyServiceInitResult vty_service_context_init(VtyServiceContext *ctx,
                                              const VtyServiceRuntimeConfig *cfg);

void vty_service_context_cleanup(VtyServiceContext *ctx);

int vty_service_context_is_fail_closed(VtyServiceContext *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VTY_SERVICE_STATE_H */
