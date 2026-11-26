/*
 * vty_keymanager_internal.h — 密钥管理跨文件内部契约（不导出）
 *
 * 元数据采用 A/B 两份 64 KiB 副本：保存只覆盖非活动副本，回读并由 K_c
 * 认证通过后才推进回退锚点。以下声明确保各实现文件共享同一组
 * 槽位、元数据与 IO 原语，不复制实现。
 */
#ifndef VTY_KEYMANAGER_INTERNAL_H
#define VTY_KEYMANAGER_INTERNAL_H

#include "vty_keymanager.h"
#include "vty_keyfile.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_device_root.h"
#include "vty_lockout.h"
#include "vty_machine_limiter.h"
#include "vty_rollback.h"
#include "vty_tpm_pcr.h"
#include "vty_store.h"
#include "vty_module.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

typedef struct {
    int valid;
    uint32_t index;
    const uint8_t *header_buf;      /* 指向 64 KiB 副本起点 */
    VtyHeader h;
    VtySlot slots[VTY_MAX_SLOTS];
    uint32_t slot_count;
    uint8_t digest[VTY_HASH_BYTES];
    const uint8_t *body;
    size_t body_len;
} VtyMetaCopy;

/* 路径与编码 */
wchar_t *vty_km_utf8_to_wide(const char *s);
void vty_km_delete_file_utf8(const char *path);

/* 用户密钥与槽位 */
int vty_km_make_user_secret(const char *password, const uint8_t *keyfile_digest,
                            uint8_t **owned, const uint8_t **secret,
                            size_t *secret_len);
void vty_km_free_user_secret(uint8_t *owned);
int vty_km_seal_user_slot(VtySlot *s, uint8_t slot_type, uint8_t slot_flags,
                          const char *password, const uint8_t *keyfile_digest,
                          const uint8_t key[VTY_KEY_BYTES],
                          const VtyHeader *h, uint32_t index,
                          uint32_t mem_kib, uint32_t iters, uint32_t parallel);
int vty_km_open_user_slot(const VtySlot *s, const char *password,
                          const uint8_t *keyfile_digest,
                          const VtyHeader *h, uint32_t index,
                          uint8_t key_out[VTY_KEY_BYTES]);

/* keyfile 与文件范围 IO */
int vty_km_load_keyfile_digest(const char *path,
                               uint8_t digest[VTY_KEY_BYTES]);
int vty_km_write_keyfile_file(const char *path,
                              const uint8_t *blob, size_t blob_len);
int vty_km_read_range(const char *path, uint64_t offset,
                      uint8_t *buf, size_t len, uint64_t *file_size);
int vty_km_write_range_locked(const char *path, uint64_t offset,
                              const uint8_t *buf, size_t len);

/* Keyring DataRoot 与元数据副本 */
int vty_km_keyring_set_data_root(VtyKeyring *kr,
                                 const uint8_t hash[VTY_HASH_BYTES],
                                 const VtyDataRootLocator *loc);
int vty_km_keyring_take_data_root(const VtyKeyring *kr,
                                  const uint8_t uuid[VTY_UUID_BYTES],
                                  uint64_t epoch, VtyDataRootLocator *loc,
                                  uint8_t hash[VTY_HASH_BYTES]);
int vty_km_build_meta_copy(const VtyVault *v, uint8_t *copy,
                           size_t *body_len_out);
int vty_km_parse_meta_copy(uint8_t *header_buf, uint32_t index,
                           VtyMetaCopy *out);
int vty_km_open_body_copy(const VtyHeader *h,
                          const uint8_t digest[VTY_HASH_BYTES],
                          const uint8_t *body, size_t body_len,
                          const uint8_t kc[VTY_KEY_BYTES], VtyKeyring *out);
int vty_km_load_meta(const char *path, uint8_t **meta_out, uint64_t *file_size,
                     VtyMetaCopy copies[VTY_META_COPIES]);

#endif /* VTY_KEYMANAGER_INTERNAL_H */
