/* 调用方身份校验。
 *
 * 仅当构建期打开 VERTHYS_REQUIRE_CALLER_SIG 时生效：Verthys_Init 在任何
 * 密钥/文件操作之前确认「宿主进程主模块」与「本 DLL」都由发布者证书签名。
 * 校验失败一律拒绝，不降级为警告——否则任意进程加载 DLL 即可调用解锁接口。
 *
 * 发布者指纹由构建系统注入（-DVERTHYS_PUBLISHER_SHA256），不写在源码里：
 * 源码常量一旦泄漏就无法在不重新发版的情况下更换信任根。
 */
#ifndef VTY_CALLER_AUTH_H
#define VTY_CALLER_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

/* 当前构建是否启用了强制调用方签名（VTY_OK 语义：1=启用，0=未启用） */
int vty_caller_auth_required(void);

/* VTY_OK：放行；VTY_E_CALLER：拒绝（无签名、签名无效或指纹不匹配） */
int vty_caller_auth_check(void);

#ifdef __cplusplus
}
#endif

#endif /* VTY_CALLER_AUTH_H */
