/*
 * vty_device_root.c — 设备根密钥封装实现（复用 CNG 机器密钥与实例指纹）
 */
#include "vty_device_root.h"
#include "vty_util.h"
#include "cng_machine_key.h"
#include "hardware_binding.h"

#include <string.h>

int vty_device_root_init(void)
{
    if (hardware_binding_init() != 0) return VTY_E_TPM;
    if (cng_machine_key_init() != 0) return VTY_E_TPM;
    if (!cng_machine_key_is_available()) return VTY_E_TPM;
    return VTY_OK;
}

int vty_device_root_available(void)
{
    uint8_t hash[HW_INSTANCE_HASH_BYTES];
    if (hardware_binding_get_hash(hash) != 0) return 0;
    return cng_machine_key_is_available() ? 1 : 0;
}

int vty_device_key_seal(const uint8_t key[VTY_KEY_BYTES],
                        uint8_t *blob, size_t *blob_len)
{
    uint8_t label[CMK_OAEP_LABEL_BYTES];
    uint8_t cipher[CMK_RSA_CIPHER_BYTES];
    int level = CMK_KEY_LEVEL_UNKNOWN;
    int provider = CMK_PROVIDER_UNKNOWN;

    if (key == NULL || blob == NULL || blob_len == NULL) return VTY_E_INVALID;
    if (*blob_len < VTY_DEVICE_BLOB_BYTES) return VTY_E_INVALID;
    if (hardware_binding_get_hash(label) != 0) return VTY_E_TPM;

    if (cng_machine_key_seal(key, cipher, label, &level, &provider) != 0) {
        vty_secure_zero(cipher, sizeof(cipher));
        return VTY_E_TPM;
    }

    blob[0] = (uint8_t)level;
    blob[1] = (uint8_t)provider;
    memcpy(blob + 2, label, CMK_OAEP_LABEL_BYTES);
    memcpy(blob + 2 + CMK_OAEP_LABEL_BYTES, cipher, CMK_RSA_CIPHER_BYTES);
    *blob_len = VTY_DEVICE_BLOB_BYTES;

    vty_secure_zero(cipher, sizeof(cipher));
    return VTY_OK;
}

int vty_device_key_unseal(const uint8_t *blob, size_t blob_len,
                          uint8_t key[VTY_KEY_BYTES])
{
    uint8_t label[HW_INSTANCE_HASH_BYTES];
    int level;
    int provider;

    if (blob == NULL || key == NULL) return VTY_E_INVALID;
    if (blob_len != VTY_DEVICE_BLOB_BYTES) return VTY_E_INVALID;

    level = (int)blob[0];
    provider = (int)blob[1];
    if (level != CMK_KEY_LEVEL_USER && level != CMK_KEY_LEVEL_MACHINE) return VTY_E_TPM;
    if (provider != CMK_PROVIDER_PLATFORM_KSP && provider != CMK_PROVIDER_SOFTWARE_KSP) {
        return VTY_E_TPM;
    }

    if (hardware_binding_get_hash(label) != 0) return VTY_E_TPM;
    if (vty_ct_equal(label, blob + 2, HW_INSTANCE_HASH_BYTES) != 0) {
        /* 换了机器：直接拒绝，不尝试跨实例解封 */
        return VTY_E_TPM;
    }

    if (cng_machine_key_unwrap_known(blob + 2 + CMK_OAEP_LABEL_BYTES,
                                     key, label, level, provider) != 0) {
        vty_secure_zero(key, VTY_KEY_BYTES);
        return VTY_E_TPM;
    }
    return VTY_OK;
}
