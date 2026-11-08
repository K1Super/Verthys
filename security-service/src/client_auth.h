/*
 * client_auth.h — 客户端进程身份认证
 *
 * 认证链：管道客户端 PID → 进程映像 Authenticode 发布者指纹 → 用户 SID 哈希
 * → 预算类命令额外校验已加载 verthys.dll 的发布者指纹。
 * 不依赖 PID/路径等可伪造信息作为身份，只把签名发布者作为信任根。
 */
#ifndef VTY_CLIENT_AUTH_H
#define VTY_CLIENT_AUTH_H

#include <windows.h>
#include <stdint.h>

#include "service_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VtyClientIdentity {
    DWORD pid;
    uint8_t sid_hash[32];
    wchar_t image_path[VTY_PATH_MAX];
} VtyClientIdentity;

/*
 * 校验 PE 文件的 Authenticode 签名与签名证书 SHA-256 钉扎值。
 * expected_sha256 为 64 位小写十六进制；为空或任何不匹配返回非 0。
 * 离线可用：禁用吊销检查与在线 URL 检索。
 */
int vty_auth_verify_authenticode(const wchar_t *path,
                                 const wchar_t *expected_sha256);

/*
 * 认证管道客户端进程：
 *   - 拒绝 PID 等于服务自身；
 *   - OpenProcess 保持句柄到请求结束；
 *   - verify_image=1 时校验映像发布者指纹；
 *   - 始终派生用户 SID 哈希（用于每用户配额与审计）。
 * 成功返回 0 并回填 identity/process；失败返回非 0，process 为 NULL。
 */
int vty_auth_client_process(HANDLE pipe, const wchar_t *expected_sha256,
                            int verify_image, VtyClientIdentity *identity,
                            HANDLE *process);

/*
 * 校验客户端进程已加载的 verthys.dll：必须至少存在一个匹配模块，
 * 且全部匹配模块的发布者指纹一致通过。
 */
int vty_auth_check_module(HANDLE process, const wchar_t *expected_sha256);

/* 事件日志：PID + SID 哈希前 8 字节 + 固定原因，不含完整 SID/路径/密钥。 */
void vty_auth_log_denied(const VtyClientIdentity *identity,
                         const wchar_t *reason);

#ifdef __cplusplus
}
#endif

#endif /* VTY_CLIENT_AUTH_H */
