/*
 * vty_module_internal.h — 模块子系统的共享契约（内部，不导出）
 *
 * 汇集描述符布局常量、ModuleDesc 结构与跨文件函数声明。模块表存放在
 * 目录 keyspace 5；未启用模块的 MDEK 仍在 body Keyring，启用后只以
 * share_u/share_d 形式存于描述符槽。
 */
#ifndef VTY_MODULE_INTERNAL_H
#define VTY_MODULE_INTERNAL_H

#include "vty_module.h"
#include "vty_repo.h"
#include "vty_keyslot.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_blake3.h"
#include "vty_device_root.h"
#include "vty_lockout.h"
#include "vty_machine_limiter.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MOD_DESC_VER 1u
#define MOD_REC_VER  1u
#define MOD_REC_CT   (VTY_KEY_BYTES + VTY_TAG_BYTES)

#define MOD_DESC_OFF_VER        0u
#define MOD_DESC_OFF_FLAGS      1u
#define MOD_DESC_OFF_INDEX      2u
#define MOD_DESC_OFF_RESERVED   3u
#define MOD_DESC_OFF_UUID       4u
#define MOD_DESC_OFF_EPOCH      20u
#define MOD_DESC_OFF_VERIFIER   28u
#define MOD_DESC_OFF_SLOT_COUNT 60u
#define MOD_DESC_OFF_RESERVED2  61u
#define MOD_DESC_OFF_SLOTS      64u

typedef struct {
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t enabled;
    uint8_t deleted;
    uint8_t has_recovery;
    uint64_t module_epoch;
    uint8_t verifier[VTY_HASH_BYTES];
    VtySlot user;
    VtySlot device;
    uint8_t rec_nonce[VTY_NONCE_BYTES];
    uint8_t rec_ct[MOD_REC_CT];
} ModuleDesc;

int vty_mod_all_zero(const uint8_t *p,
                     size_t n);

void vty_mod_desc_clear(ModuleDesc *d);

void vty_mod_desc_init_disabled(ModuleDesc *d,
                                const uint8_t uuid[VTY_UUID_BYTES]);

int vty_mod_desc_load(VtyVault *v,
                      uint32_t index,
                      ModuleDesc *out);

int vty_mod_desc_store(VtyVault *v,
                       uint32_t index,
                       const ModuleDesc *d);

int vty_mod_rec_aad(const VtyVault *v,
                    const ModuleDesc *d,
                    uint8_t out[96],
                    size_t *out_len);

int vty_mod_rec_key(const VtyVault *v,
                    const ModuleDesc *d,
                    const uint8_t krec[VTY_KEY_BYTES],
                    uint8_t out[VTY_KEY_BYTES]);

int vty_mod_verifier(const uint8_t mdek[VTY_KEY_BYTES],
                     const uint8_t module_uuid[VTY_UUID_BYTES],
                     uint8_t out[VTY_HASH_BYTES]);

int vty_mod_desc_seal_user(VtyVault *v,
                           ModuleDesc *d,
                           const char *password,
                           const uint8_t share_u[VTY_KEY_BYTES]);

int vty_mod_desc_seal_recovery(VtyVault *v,
                               ModuleDesc *d,
                               const uint8_t krec[VTY_KEY_BYTES],
                               const uint8_t share_d[VTY_KEY_BYTES]);

int vty_mod_desc_open_shares(VtyVault *v,
                             uint32_t module_index,
                             const ModuleDesc *d,
                             const char *password,
                             uint8_t share_u[VTY_KEY_BYTES],
                             uint8_t share_d[VTY_KEY_BYTES],
                             uint8_t mdek[VTY_KEY_BYTES]);

int vty_mod_krec_from_code(VtyVault *v,
                           const char *recovery_text,
                           uint8_t krec_out[VTY_KEY_BYTES]);

int vty_mod_keyring_find_mdek(const VtyKeyring *kr,
                              const uint8_t uuid[VTY_UUID_BYTES],
                              uint8_t out[VTY_KEY_BYTES]);

int vty_mod_keyring_remove_mdek(VtyKeyring *kr,
                                const uint8_t uuid[VTY_UUID_BYTES]);

int vty_mod_free_space_ok(const VtyVault *v,
                          uint64_t need);

#endif /* VTY_MODULE_INTERNAL_H */
