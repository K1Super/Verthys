/*
 * protocol.h — 响应构造与 ECDSA 签名（服务端/测试探针共用）
 */
#ifndef VTY_SVC_PROTOCOL_IMPL_H
#define VTY_SVC_PROTOCOL_IMPL_H

#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>

#include "vty_svc_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 构造 128 字节响应并签名：
 *   - 前 64 字节由 vty_svc_response_encode 生成；
 *   - SHA-256(前 64 字节) 交给 ECDSA P-256 签名；
 *   - 签名写入偏移 64..127。
 * 返回 0 成功；key 为空或签名失败返回非 0。
 */
int vty_svc_build_signed_response(BCRYPT_KEY_HANDLE key,
                                  const VtySvcRequestFields *request,
                                  uint16_t status, uint32_t retry_after_sec,
                                  uint32_t remaining_tokens,
                                  uint64_t server_time_sec,
                                  uint8_t raw[VTY_SVC_RESPONSE_BYTES]);

/* 用已导入公钥校验响应签名；返回 0 成功。 */
int vty_svc_verify_response_signature(BCRYPT_KEY_HANDLE key,
                                      const uint8_t raw[VTY_SVC_RESPONSE_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_SVC_PROTOCOL_IMPL_H */
