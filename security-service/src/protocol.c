/*
 * protocol.c — 响应构造与签名
 */
#include "protocol.h"
#include "state_crypto.h"

#include <string.h>

int vty_svc_build_signed_response(BCRYPT_KEY_HANDLE key,
                                  const VtySvcRequestFields *request,
                                  uint16_t status, uint32_t retry_after_sec,
                                  uint32_t remaining_tokens,
                                  uint64_t server_time_sec,
                                  uint8_t raw[VTY_SVC_RESPONSE_BYTES])
{
    uint8_t hash[VTY_HASH_BYTES];
    int rc;

    if (key == NULL || request == NULL || raw == NULL) return -1;
    vty_svc_response_encode(raw, status, request->request_id,
                            retry_after_sec, request->nonce_lo,
                            request->nonce_hi, remaining_tokens,
                            server_time_sec);
    if (vty_sha256(raw, VTY_SVC_RESPONSE_HEADER_BYTES, hash) != 0) return -1;
    rc = vty_ecc_sign(key, hash, raw + VTY_SVC_RESPONSE_HEADER_BYTES);
    vty_secure_zero(hash, sizeof(hash));
    return rc;
}

int vty_svc_verify_response_signature(BCRYPT_KEY_HANDLE key,
                                      const uint8_t raw[VTY_SVC_RESPONSE_BYTES])
{
    uint8_t hash[VTY_HASH_BYTES];
    int rc;

    if (key == NULL || raw == NULL) return -1;
    if (vty_sha256(raw, VTY_SVC_RESPONSE_HEADER_BYTES, hash) != 0) return -1;
    rc = vty_ecc_verify_with_key(
        key, hash, raw + VTY_SVC_RESPONSE_HEADER_BYTES);
    vty_secure_zero(hash, sizeof(hash));
    return rc;
}
