/*
 * vty_keymanager_v4.c — v4 库创建、解锁与会话实现
 *
 * PCR 槽语义：槽内只保存“当前 PCR 策略摘要 + 用 PCR 绑定 TPM 私钥加封的
 * 容器密钥”。解锁时既比对摘要，又要求 TPM 在 PCR 匹配的前提下解封出与
 * 用户口令/设备根还原的 K_c 相同的值；任一不符即 fail-closed。
 */
#include "vty_keymanager_v4.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_device_root.h"
#include "vty_lockout.h"
#include "vty_rollback.h"
#include "vty_tpm_pcr.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define VTY_FILE_MAX_BYTES (64u * 1024u * 1024u)
#define VTY_BODY_AAD_MAX 64u
#define VTY_BODY_NONCE VTY_NONCE_BYTES

static wchar_t *utf8_to_wide(const char *s)
{
    int n;
    wchar_t *w;

    if (s == NULL) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static int read_all(const char *path, uint8_t **out, size_t *out_len)
{
    wchar_t *wpath;
    HANDLE h;
    LARGE_INTEGER size;
    uint8_t *buf;
    DWORD got = 0;
    int rc = VTY_OK;

    if (path == NULL || out == NULL || out_len == NULL) return VTY_E_INVALID;
    *out = NULL;
    *out_len = 0;

    wpath = utf8_to_wide(path);
    if (wpath == NULL) return VTY_E_INVALID;
    h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) return VTY_E_IO;

    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > VTY_FILE_MAX_BYTES) {
        CloseHandle(h);
        return VTY_E_INVALID;
    }

    buf = (uint8_t *)malloc((size_t)size.QuadPart);
    if (buf == NULL) {
        CloseHandle(h);
        return VTY_E_RESOURCE;
    }
    if (!ReadFile(h, buf, (DWORD)size.QuadPart, &got, NULL) ||
        got != (DWORD)size.QuadPart) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);

    if (rc != VTY_OK) {
        vty_free(buf, (size_t)size.QuadPart);
        return rc;
    }
    *out = buf;
    *out_len = got;
    return VTY_OK;
}

static int write_atomic(const char *path, const uint8_t *data, size_t len, int replace)
{
    wchar_t *wpath = NULL;
    wchar_t *wtemp = NULL;
    HANDLE h = INVALID_HANDLE_VALUE;
    char temp_path[1024];
    DWORD written = 0;
    int rc = VTY_OK;

    if (path == NULL || data == NULL) return VTY_E_INVALID;
    if (strlen(path) + 40 >= sizeof(temp_path)) return VTY_E_INVALID;
    if (!replace) {
        wpath = utf8_to_wide(path);
        if (wpath == NULL) return VTY_E_INVALID;
        if (GetFileAttributesW(wpath) != INVALID_FILE_ATTRIBUTES) {
            free(wpath);
            return VTY_E_INVALID;   /* 已存在：拒绝覆盖，避免误伤现有库 */
        }
        free(wpath);
    }

    sprintf_s(temp_path, sizeof(temp_path), "%s.tmp%08lx", path,
              (unsigned long)GetCurrentProcessId());
    wtemp = utf8_to_wide(temp_path);
    if (wtemp == NULL) return VTY_E_INVALID;

    h = CreateFileW(wtemp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(wtemp);
        return VTY_E_IO;
    }
    if (!WriteFile(h, data, (DWORD)len, &written, NULL) || written != (DWORD)len) {
        rc = VTY_E_IO;
    }
    if (rc == VTY_OK && !FlushFileBuffers(h)) rc = VTY_E_IO;
    CloseHandle(h);

    if (rc == VTY_OK) {
        wpath = utf8_to_wide(path);
        if (wpath == NULL) {
            rc = VTY_E_INVALID;
        } else {
            DWORD flags = MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0u);
            if (!MoveFileExW(wtemp, wpath, flags)) rc = VTY_E_IO;
            free(wpath);
        }
    }
    if (rc != VTY_OK) DeleteFileW(wtemp);
    free(wtemp);
    return rc;
}

/* body AAD = 域串 || uuid || epoch || generation || plain_len。
 * generation 参与 AAD，使“把旧库头改成更大的版本号并重算 BLAKE3”
 * 无法绕过外部锚点：body 认证失败即拒绝。 */
static void body_aad(const uint8_t uuid[VTY_UUID_BYTES], uint64_t epoch,
                     uint64_t generation, uint32_t plain_len,
                     uint8_t out[VTY_BODY_AAD_MAX],
                     size_t *out_len)
{
    const char *domain = VTY_DOMAIN_KEYRING;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES, epoch);
    vty_put_u64(out + dlen + VTY_UUID_BYTES + 8u, generation);
    vty_put_u32(out + dlen + VTY_UUID_BYTES + 16u, plain_len);
    *out_len = dlen + VTY_UUID_BYTES + 16u + 4u;
}

static int rebuild_header(VtyVault *v)
{
    uint8_t *buf;
    size_t slots_len = 0;
    size_t off;
    size_t total;
    uint32_t i;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    for (i = 0; i < v->slot_count; i++) {
        slots_len += vty_slot_serialized_len(&v->slots[i]);
    }
    total = VTY_V4_HEADER_FIXED_BYTES + slots_len + VTY_V4_HEADER_HASH_BYTES;
    if (total > 0xFFFFu) return VTY_E_INVALID;

    buf = (uint8_t *)vty_alloc(total);
    if (buf == NULL) return VTY_E_RESOURCE;

    v->header.header_len = (uint16_t)total;
    v->header.slot_count = (uint16_t)v->slot_count;
    rc = vty_v4_header_write_fixed(&v->header, buf, total);
    if (rc != VTY_OK) {
        vty_free(buf, total);
        return rc;
    }

    off = VTY_V4_HEADER_FIXED_BYTES;
    for (i = 0; i < v->slot_count; i++) {
        size_t w = 0;
        rc = vty_slot_write(&v->slots[i], i, &v->header, buf + off,
                            total - off - VTY_V4_HEADER_HASH_BYTES, &w);
        if (rc != VTY_OK) {
            vty_free(buf, total);
            return rc;
        }
        off += w;
    }
    rc = vty_v4_header_finalize(buf, total);
    if (rc != VTY_OK) {
        vty_free(buf, total);
        return rc;
    }

    if (v->header_buf != NULL) vty_free(v->header_buf, v->header_len);
    v->header_buf = buf;
    v->header_len = total;
    return VTY_OK;
}

/* body = nonce(24) || AEAD(K_c, keyring 序列化) */
static int seal_body(const VtyVault *v, uint8_t **out, size_t *out_len)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t aad[VTY_BODY_AAD_MAX];
    uint8_t *buf;
    size_t plain_len = 0;
    size_t aad_len = 0;
    size_t ct_len = 0;
    int rc;

    if (v == NULL || out == NULL || out_len == NULL) return VTY_E_INVALID;
    rc = vty_keyring_serialize(&v->keyring, plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) return rc;

    buf = (uint8_t *)vty_alloc(VTY_BODY_NONCE + plain_len + VTY_TAG_BYTES);
    if (buf == NULL) {
        vty_secure_zero(plain, sizeof(plain));
        return VTY_E_RESOURCE;
    }
    vty_random(buf, VTY_BODY_NONCE);
    body_aad(v->header.vault_uuid, v->header.epoch,
             vty_v4_header_generation(&v->header), (uint32_t)plain_len,
             aad, &aad_len);
    rc = vty_aead_seal(v->kc, buf, aad, aad_len, plain, plain_len,
                       buf + VTY_BODY_NONCE, plain_len + VTY_TAG_BYTES, &ct_len);
    if (rc != VTY_OK) {
        vty_free(buf, VTY_BODY_NONCE + plain_len + VTY_TAG_BYTES);
        vty_secure_zero(plain, sizeof(plain));
        return rc;
    }

    *out = buf;
    *out_len = VTY_BODY_NONCE + ct_len;
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    return VTY_OK;
}

static int open_body(VtyVault *v, const uint8_t *body, size_t body_len)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t aad[VTY_BODY_AAD_MAX];
    size_t aad_len = 0;
    size_t plain_len = 0;
    uint32_t pt_len;
    int rc;

    if (v == NULL || body == NULL) return VTY_E_INVALID;
    if (body_len < VTY_BODY_NONCE + VTY_TAG_BYTES) return VTY_E_INVALID;
    pt_len = (uint32_t)(body_len - VTY_BODY_NONCE - VTY_TAG_BYTES);
    if (pt_len > sizeof(plain)) return VTY_E_INVALID;

    body_aad(v->header.vault_uuid, v->header.epoch,
             vty_v4_header_generation(&v->header), pt_len, aad, &aad_len);
    rc = vty_aead_open(v->kc, body, aad, aad_len,
                       body + VTY_BODY_NONCE, body_len - VTY_BODY_NONCE,
                       plain, sizeof(plain), &plain_len);
    if (rc == VTY_OK) {
        rc = vty_keyring_parse(plain, plain_len, &v->keyring);
    }
    if (rc == VTY_OK) {
        uint8_t kc_check[VTY_KEY_BYTES];
        rc = vty_keyring_find(&v->keyring, VTY_KEYKIND_KC, NULL, 0, kc_check);
        if (rc == VTY_OK) {
            if (vty_ct_equal(kc_check, v->kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
            vty_secure_zero(kc_check, sizeof(kc_check));
        }
    }
    if (rc == VTY_OK) {
        rc = vty_keyring_find(&v->keyring, VTY_KEYKIND_KG, NULL, 0, v->kg);
    }

    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

static int build_and_write(const VtyVault *v, const char *path, int replace)
{
    uint8_t *body = NULL;
    size_t body_len = 0;
    uint8_t *file;
    size_t file_len;
    int rc;

    rc = seal_body(v, &body, &body_len);
    if (rc != VTY_OK) return rc;

    file_len = v->header_len + body_len;
    file = (uint8_t *)malloc(file_len);
    if (file == NULL) {
        vty_free(body, body_len);
        return VTY_E_RESOURCE;
    }
    memcpy(file, v->header_buf, v->header_len);
    memcpy(file + v->header_len, body, body_len);
    rc = write_atomic(path, file, file_len, replace);

    vty_secure_zero(file, file_len);
    free(file);
    vty_free(body, body_len);
    return rc;
}

static int add_module_entries(VtyKeyring *kr, uint8_t *uuids_out)
{
    uint32_t i;
    uint8_t count = kr->count;

    for (i = 0; i < VTY_V4_MAX_MODULES - 1u; i++) {
        VtyKeyEntry *e = &kr->entries[count];
        if (count >= VTY_KEYRING_MAX_ENTRIES) return VTY_E_INVALID;
        memset(e, 0, sizeof(*e));
        e->kind = VTY_KEYKIND_MDEK;
        e->module_uuid_len = VTY_KEYRING_MODULE_ID_MAX;
        vty_random(e->module_uuid, VTY_KEYRING_MODULE_ID_MAX);
        vty_random(e->key, VTY_KEY_BYTES);
        if (uuids_out != NULL) {
            memcpy(uuids_out + i * VTY_UUID_BYTES, e->module_uuid, VTY_UUID_BYTES);
        }
        count++;
    }
    kr->count = count;
    return VTY_OK;
}

/* 创建公共实现：pcr_select 非 0 时追加 PCR 槽并启用 PCR 标志 */
static int vault_create_internal(const char *path, const char *password,
                                 uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                                 uint32_t pcr_select,
                                 VtyVault **out,
                                 char *recovery_text, size_t recovery_cap)
{
    VtyVault *v;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t code[VTY_RECOVERY_CODE_BYTES] = {0};
    VtySlot *u_slot;
    VtySlot *d_slot;
    VtySlot *r_slot;
    int pcr_key_created = 0;
    int rc;

    if (path == NULL || password == NULL || out == NULL) return VTY_E_INVALID;
    if (password[0] == '\0') return VTY_E_INVALID;
    if (recovery_text == NULL) return VTY_E_INVALID;
    if (recovery_cap < VTY_RECOVERY_TEXT_BUF) return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;
    if (pcr_select != 0) {
        rc = vty_tpm_pcr_select_valid(pcr_select);
        if (rc != VTY_OK) return rc;
        if (!vty_tpm_pcr_available()) return VTY_E_TPM;
    }
    rc = vty_device_root_init();
    if (rc != VTY_OK) return rc;

    v = (VtyVault *)vty_alloc(sizeof(VtyVault));
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    v->mem_kib = mem_kib;
    v->iters = iters;
    v->parallel = parallel;
    v->header.magic = VTY_V4_MAGIC;
    v->header.version_major = VTY_V4_VERSION_MAJOR;
    v->header.version_minor = VTY_V4_VERSION_MINOR;
    v->header.flags = VTY_FLAG_RECOVERY | VTY_FLAG_MODULE_M1;
    if (pcr_select != 0) v->header.flags |= VTY_FLAG_PCR;
    v->header.epoch = 1;
    /* 版本计数器从 1 起：0 留给“加计数器之前生成的老库” */
    vty_v4_header_set_generation(&v->header, 1u);
    vty_random(v->header.vault_uuid, VTY_UUID_BYTES);
    vty_random(v->kc, VTY_KEY_BYTES);
    vty_random(v->kg, VTY_KEY_BYTES);

    memset(&v->keyring, 0, sizeof(v->keyring));
    v->keyring.count = 0;
    v->keyring.entries[0].kind = VTY_KEYKIND_KC;
    memcpy(v->keyring.entries[0].key, v->kc, VTY_KEY_BYTES);
    v->keyring.entries[1].kind = VTY_KEYKIND_KG;
    memcpy(v->keyring.entries[1].key, v->kg, VTY_KEY_BYTES);
    v->keyring.count = 2;
    rc = add_module_entries(&v->keyring, NULL);
    if (rc != VTY_OK) goto fail;

    vty_random(share_u, VTY_KEY_BYTES);
    {
        size_t i;
        for (i = 0; i < VTY_KEY_BYTES; i++) {
            share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
        }
    }

    u_slot = &v->slots[0];
    d_slot = &v->slots[1];
    r_slot = &v->slots[2];
    v->slot_count = 3;

    rc = vty_slot_seal_argon2id(u_slot, VTY_SLOT_USER_PASSWORD,
                                VTY_SLOT_FLAG_REQUIRED,
                                (const uint8_t *)password, strlen(password),
                                share_u, &v->header, 0, mem_kib, iters, parallel);
    if (rc != VTY_OK) goto fail;

    rc = vty_slot_seal_device(d_slot, VTY_SLOT_FLAG_REQUIRED, share_d,
                              &v->header, 1);
    if (rc != VTY_OK) goto fail;

    rc = vty_recovery_generate(code, recovery_text, recovery_cap);
    if (rc != VTY_OK) goto fail;
    rc = vty_recovery_slot_seal(r_slot, &v->keyring, code, &v->header, 2,
                                mem_kib, iters, parallel);
    vty_secure_zero(code, sizeof(code));
    if (rc != VTY_OK) goto fail;

    if (pcr_select != 0) {
        VtySlot *p_slot = &v->slots[3];

        memset(p_slot, 0, sizeof(*p_slot));
        rc = vty_tpm_pcr_key_create(v->header.vault_uuid, pcr_select, NULL, 0);
        if (rc != VTY_OK) goto fail;
        pcr_key_created = 1;
        p_slot->slot_type = VTY_SLOT_DEVICE_PCR;
        p_slot->slot_flags = VTY_SLOT_FLAG_REQUIRED;
        p_slot->kdf_id = VTY_KDF_NONE;
        p_slot->wrap_alg = VTY_WRAP_RSAOAEP;
        p_slot->params_len = VTY_SLOT_PARAMS_PCR;
        p_slot->pcr_select = pcr_select;
        rc = vty_tpm_pcr_measure(pcr_select, p_slot->pcr_digest);
        if (rc != VTY_OK) goto fail;
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, p_slot->ct);
        if (rc != VTY_OK) goto fail;
        p_slot->ct_len = VTY_SLOT_PCR_CT_BYTES;
        v->slot_count = 4;
    }

    rc = rebuild_header(v);
    if (rc != VTY_OK) goto fail;
    rc = build_and_write(v, path, 0);
    if (rc != VTY_OK) goto fail;

    v->unlocked = 1;
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    *out = v;
    return VTY_OK;

fail:
    if (pcr_key_created) {
        (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(code, sizeof(code));
    vty_vault_free(v);
    return rc;
}

int vty_vault_create_ex(const char *path, const char *password,
                        uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                        VtyVault **out,
                        char *recovery_text, size_t recovery_cap)
{
    return vault_create_internal(path, password, mem_kib, iters, parallel, 0,
                                 out, recovery_text, recovery_cap);
}

int vty_vault_create_pcr(const char *path, const char *password,
                         uint32_t pcr_select,
                         VtyVault **out,
                         char *recovery_text, size_t recovery_cap)
{
    return vault_create_internal(path, password,
                                 VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                 pcr_select, out, recovery_text, recovery_cap);
}

int vty_vault_create(const char *path, const char *password,
                     VtyVault **out,
                     char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_ex(path, password,
                               VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                               out, recovery_text, recovery_cap);
}

static int load_header(const char *path, uint8_t **file, size_t *file_len,
                       VtyVault *v)
{
    int rc = read_all(path, file, file_len);
    if (rc != VTY_OK) return rc;

    rc = vty_v4_header_parse(*file, *file_len, &v->header);
    if (rc != VTY_OK) return rc;

    rc = vty_slots_parse_all(*file, *file_len, &v->header,
                             v->slots, VTY_V4_MAX_SLOTS, &v->slot_count);
    if (rc != VTY_OK) return rc;

    v->header_len = v->header.header_len;
    v->header_buf = (uint8_t *)vty_alloc(v->header_len);
    if (v->header_buf == NULL) return VTY_E_RESOURCE;
    memcpy(v->header_buf, *file, v->header_len);

    /* 头部之后必须还有 body（nonce + 密文 + tag） */
    if (*file_len <= v->header_len + VTY_BODY_NONCE + VTY_TAG_BYTES) {
        return VTY_E_INVALID;
    }
    return VTY_OK;
}

/* PCR 门：比对当前策略摘要，并要求 TPM 解封出与 K_c 相同的值。
 * 设备环境变化返回 VTY_E_TPM；槽被替换/密钥不符返回 VTY_E_KEY_INVALID。 */
static int check_pcr_gate(const VtyVault *v)
{
    int p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    uint8_t cur[VTY_HASH_BYTES];
    uint8_t pcr_kc[VTY_KEY_BYTES];
    int rc;

    memset(cur, 0, sizeof(cur));
    vty_secure_zero(pcr_kc, sizeof(pcr_kc));
    if (p_idx < 0) return VTY_E_SLOT_MISSING;

    rc = vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, cur);
    if (rc != VTY_OK) {
        rc = VTY_E_TPM;
    } else if (vty_ct_equal(cur, v->slots[p_idx].pcr_digest, VTY_HASH_BYTES) != 0) {
        rc = VTY_E_TPM;
    } else {
        rc = vty_tpm_pcr_unseal(v->header.vault_uuid, v->slots[p_idx].ct, pcr_kc);
        if (rc != VTY_OK) {
            rc = VTY_E_TPM;
        } else if (vty_ct_equal(pcr_kc, v->kc, VTY_KEY_BYTES) != 0) {
            rc = VTY_E_KEY_INVALID;
        }
    }
    vty_secure_zero(cur, sizeof(cur));
    vty_secure_zero(pcr_kc, sizeof(pcr_kc));
    return rc;
}

int vty_vault_open(const char *path, const char *password, VtyVault **out)
{
    VtyVault *v;
    uint8_t *file = NULL;
    size_t file_len = 0;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;
    size_t i;

    if (path == NULL || password == NULL || out == NULL) return VTY_E_INVALID;
    if (password[0] == '\0') return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    /* 熔断前置：损坏的状态/机器不匹配/已达阈值一律拒绝；
     * 恢复码路径不在此处受熔断影响（它是防永久锁死的逃生通道）。 */
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
        if (vty_lockout_check() == VTY_E_LOCKED) return VTY_E_LOCKED;
    }

    v = (VtyVault *)vty_alloc(sizeof(VtyVault));
    if (v == NULL) return VTY_E_RESOURCE;

    rc = load_header(path, &file, &file_len, v);
    if (rc != VTY_OK) goto fail;
    memcpy(v->path, path, strlen(path) + 1);

    rc = vty_slot_policy_check(v->slots, v->slot_count, v->header.flags);
    if (rc != VTY_OK) goto fail;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) {
        rc = VTY_E_SLOT_MISSING;
        goto fail;
    }

    rc = vty_slot_open_argon2id(&v->slots[u_idx],
                                (const uint8_t *)password, strlen(password),
                                &v->header, (uint32_t)u_idx, share_u);
    if (rc != VTY_OK) {
        /* 只把“口令认证失败”计入熔断；文件损坏/IO 错误不应被当作
         * 口令猜测，否则一次坏盘就会把用户永久锁死。 */
        if (rc == VTY_E_KEY_INVALID && vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_record_failure();
        }
        goto fail;
    }

    rc = vty_slot_open_device(&v->slots[d_idx], &v->header, (uint32_t)d_idx,
                              share_d);
    if (rc != VTY_OK) goto fail;

    for (i = 0; i < VTY_KEY_BYTES; i++) {
        v->kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));

    /* PCR 门在拿到 K_c 之后、解 body 之前：先比对当前策略摘要，再要求
     * TPM 在 PCR 匹配下解封出同一 K_c。两者任一不符都按设备环境变化处理。 */
    if ((v->header.flags & VTY_FLAG_PCR) != 0) {
        rc = check_pcr_gate(v);
        if (rc != VTY_OK) goto fail;
    }

    rc = open_body(v, file + v->header_len, file_len - v->header_len);
    if (rc != VTY_OK) goto fail;

    /* 版本回退检测放在 body 认证之后：generation 已被 K_c 绑定，
     * 此处才可信；与外部锚点比对可拦下“整体还原旧库文件”。 */
    if (vty_rollback_enabled()) {
        rc = vty_rollback_check(v->header.vault_uuid,
                                vty_v4_header_generation(&v->header));
        if (rc != VTY_OK) goto fail;
        rc = vty_rollback_commit(v->header.vault_uuid,
                                 vty_v4_header_generation(&v->header));
        if (rc != VTY_OK) goto fail;
    }

    v->mem_kib = v->slots[u_idx].m_cost;
    v->iters = v->slots[u_idx].t_cost;
    v->parallel = v->slots[u_idx].p_cost;
    v->unlocked = 1;
    if (vty_lockout_enabled()) {
        (void)vty_lockout_init();
        (void)vty_lockout_reset();
    }
    vty_free(file, file_len);
    *out = v;
    return VTY_OK;

fail:
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    if (file != NULL) vty_free(file, file_len);
    vty_vault_free(v);
    return rc;
}

int vty_vault_open_recovery(const char *path, const char *recovery_text,
                            VtyVault **out)
{
    VtyVault *v;
    uint8_t *file = NULL;
    size_t file_len = 0;
    int r_idx;
    int rc;

    if (path == NULL || recovery_text == NULL || out == NULL) return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    v = (VtyVault *)vty_alloc(sizeof(VtyVault));
    if (v == NULL) return VTY_E_RESOURCE;

    rc = load_header(path, &file, &file_len, v);
    if (rc != VTY_OK) goto fail;
    memcpy(v->path, path, strlen(path) + 1);
    if ((v->header.flags & VTY_FLAG_RECOVERY) == 0) {
        rc = VTY_E_SLOT_MISSING;
        goto fail;
    }

    r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (r_idx < 0) {
        rc = VTY_E_SLOT_MISSING;
        goto fail;
    }

    rc = vty_recovery_slot_open(&v->slots[r_idx], recovery_text,
                                &v->header, (uint32_t)r_idx, &v->keyring);
    if (rc != VTY_OK) goto fail;

    rc = vty_keyring_find(&v->keyring, VTY_KEYKIND_KC, NULL, 0, v->kc);
    if (rc != VTY_OK) goto fail;
    rc = vty_keyring_find(&v->keyring, VTY_KEYKIND_KG, NULL, 0, v->kg);
    if (rc != VTY_OK) goto fail;

    /* 恢复路径同样要校验 body：否则 body 被截断/损坏的库仍会“成功打开”，
     * 掩盖数据损坏。open_body 会同时验证 K_c 与恢复槽内 Keyring 一致。 */
    rc = open_body(v, file + v->header_len, file_len - v->header_len);
    if (rc != VTY_OK) goto fail;

    /* 恢复码是用户显式选择的逃生通道：允许打开较旧副本，并把锚点
     * 重设为该副本的版本；否则被回滚的库会永久无法恢复。 */
    if (vty_rollback_enabled()) {
        rc = vty_rollback_reset_anchor(v->header.vault_uuid,
                                       vty_v4_header_generation(&v->header));
        if (rc != VTY_OK) goto fail;
    }

    /* 恢复码解锁成功等同身份成立，清零整机失败计数；否则被熔断的库
     * 之后只能一直靠恢复码打开，等于把唯一的逃生通道也锁死。 */
    if (vty_lockout_enabled()) (void)vty_lockout_reset();

    v->mem_kib = v->slots[r_idx].m_cost;
    v->iters = v->slots[r_idx].t_cost;
    v->parallel = v->slots[r_idx].p_cost;
    v->unlocked = 1;
    vty_free(file, file_len);
    *out = v;
    return VTY_OK;

fail:
    if (file != NULL) vty_free(file, file_len);
    vty_vault_free(v);
    return rc;
}

int vty_vault_rotate_password(VtyVault *v, const char *new_password,
                              char *recovery_text, size_t recovery_cap)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t code[VTY_RECOVERY_CODE_BYTES] = {0};
    int u_idx, d_idx, r_idx;
    int rc;
    size_t i;

    if (v == NULL || new_password == NULL || new_password[0] == '\0') return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (strlen(v->path) == 0) return VTY_E_INVALID;
    if (recovery_text != NULL && recovery_cap < VTY_RECOVERY_TEXT_BUF) return VTY_E_INVALID;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;
    /* 恢复槽存在时必须输出新恢复码：否则槽内旧码失效而用户拿不到新码，
     * 等于悄悄破坏唯一的换机恢复通道。 */
    if (r_idx >= 0 && recovery_text == NULL) return VTY_E_INVALID;

    v->header.epoch = v->header.epoch + 1u;

    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }

    rc = vty_slot_seal_argon2id(&v->slots[u_idx], VTY_SLOT_USER_PASSWORD,
                                VTY_SLOT_FLAG_REQUIRED,
                                (const uint8_t *)new_password, strlen(new_password),
                                share_u, &v->header, (uint32_t)u_idx,
                                v->mem_kib, v->iters, v->parallel);
    if (rc != VTY_OK) goto out;
    rc = vty_slot_seal_device(&v->slots[d_idx], VTY_SLOT_FLAG_REQUIRED, share_d,
                              &v->header, (uint32_t)d_idx);
    if (rc != VTY_OK) goto out;

    if (r_idx >= 0) {
        rc = vty_recovery_generate(code, recovery_text, recovery_cap);
        if (rc != VTY_OK) goto out;
        rc = vty_recovery_slot_seal(&v->slots[r_idx], &v->keyring, code,
                                    &v->header, (uint32_t)r_idx,
                                    v->mem_kib, v->iters, v->parallel);
        if (rc != VTY_OK) goto out;
    }

    rc = rebuild_header(v);
    if (rc != VTY_OK) goto out;
    rc = vty_vault_save(v);

out:
    if (rc != VTY_OK) {
        /* 轮换在中途失败时，内存里的 epoch/槽位可能已与磁盘不一致；
         * 继续允许 Save 会把半套槽位写盘彻底毁库。这里强制回到锁定态，
         * 让调用方重新 Open 以任一失败分支为准。 */
        v->unlocked = 0;
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(code, sizeof(code));
    return rc;
}

int vty_vault_save(VtyVault *v)
{
    uint64_t generation;
    int rc;

    if (v == NULL || v->header_buf == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->path[0] == '\0') return VTY_E_INVALID;

    /* 每次落盘递增版本：旧副本的 generation 会低于外部锚点，从而被拒绝。
     * 计数器耗尽即拒绝写入——回绕会把旧库伪装成新库。 */
    generation = vty_v4_header_generation(&v->header);
    if (generation == UINT64_MAX) return VTY_E_RESOURCE;
    vty_v4_header_set_generation(&v->header, generation + 1u);
    rc = rebuild_header(v);
    if (rc != VTY_OK) return rc;
    rc = build_and_write(v, v->path, 1);
    if (rc != VTY_OK) return rc;

    /* 写盘成功即推进锚点，而不是等下一次 Open：
     * 否则“本次会话打开时 commit 旧版本 → 又保存了新版本 → 关闭”，
     * 攻击者用会话开始时的副本整体覆盖，版本号恰好等于锚点而被放行，
     * 本次会话删除/修改的内容会复活。 */
    if (vty_rollback_enabled()) {
        rc = vty_rollback_commit(v->header.vault_uuid,
                                 vty_v4_header_generation(&v->header));
    }
    return rc;
}

/* 填充一个可用的 PCR 槽：建键、读当前 PCR、加封 K_c。
 * 失败时删除半成品键，避免后续解封误用一张未绑定完成的密钥。 */
static int pcr_slot_prepare(VtyVault *v, uint32_t select, VtySlot *slot)
{
    int rc;

    memset(slot, 0, sizeof(*slot));
    rc = vty_tpm_pcr_select_valid(select);
    if (rc != VTY_OK) return rc;
    rc = vty_tpm_pcr_key_create(v->header.vault_uuid, select, NULL, 0);
    if (rc != VTY_OK) return rc;

    slot->slot_type = VTY_SLOT_DEVICE_PCR;
    slot->slot_flags = VTY_SLOT_FLAG_REQUIRED;
    slot->kdf_id = VTY_KDF_NONE;
    slot->wrap_alg = VTY_WRAP_RSAOAEP;
    slot->params_len = VTY_SLOT_PARAMS_PCR;
    slot->pcr_select = select;
    rc = vty_tpm_pcr_measure(select, slot->pcr_digest);
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, slot->ct);
    }
    if (rc != VTY_OK) {
        (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
        memset(slot, 0, sizeof(*slot));
        return VTY_E_TPM;
    }
    slot->ct_len = VTY_SLOT_PCR_CT_BYTES;
    return VTY_OK;
}

int vty_vault_pcr_enable(VtyVault *v, uint32_t pcr_select)
{
    VtySlot slot;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR) >= 0) {
        return VTY_E_POLICY;
    }
    if (v->slot_count >= VTY_V4_MAX_SLOTS) return VTY_E_RESOURCE;
    if (!vty_tpm_pcr_available()) return VTY_E_TPM;

    rc = pcr_slot_prepare(v, pcr_select, &slot);
    if (rc != VTY_OK) return rc;

    v->slots[v->slot_count] = slot;
    v->slot_count++;
    v->header.flags |= VTY_FLAG_PCR;
    /* 落盘失败时无法确定磁盘是否已更新：强制回到锁定态，调用方重新打开
     * 以实际落盘内容为准；密钥保留，供“已写入”的分支继续使用。 */
    rc = vty_vault_save(v);
    if (rc != VTY_OK) v->unlocked = 0;
    return rc;
}

int vty_vault_pcr_disable(VtyVault *v)
{
    int p_idx;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) return VTY_E_POLICY;
    /* PCR 槽始终追加在末尾；不是末尾说明头部被重排或伪造 */
    if ((uint32_t)p_idx != v->slot_count - 1u) return VTY_E_CORRUPT;
    if ((v->header.flags & VTY_FLAG_HIGH_SECURITY) != 0 &&
        vty_slot_find(v->slots, v->slot_count, VTY_SLOT_KEYFILE) < 0) {
        return VTY_E_POLICY;
    }

    v->slot_count--;
    v->header.flags &= (uint16_t)~VTY_FLAG_PCR;
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        /* 磁盘状态不确定：锁定并要求重新打开；密钥不删除，避免“已写入”
         * 的分支失去解封能力。 */
        v->unlocked = 0;
        return rc;
    }
    (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
    return VTY_OK;
}

int vty_vault_pcr_reseal(VtyVault *v)
{
    int p_idx;
    uint8_t digest[VTY_HASH_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];
    uint8_t check[VTY_KEY_BYTES];
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) return VTY_E_POLICY;
    if (!vty_tpm_pcr_available()) return VTY_E_TPM;

    memset(digest, 0, sizeof(digest));
    memset(ct, 0, sizeof(ct));
    vty_secure_zero(check, sizeof(check));

    /* 先建新键并做一次加封/解封自检，确认新策略可用后再更新槽 */
    rc = vty_tpm_pcr_key_create(v->header.vault_uuid,
                                v->slots[p_idx].pcr_select, NULL, 0);
    if (rc != VTY_OK) return rc;
    rc = vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, digest);
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, ct);
    }
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_unseal(v->header.vault_uuid, ct, check);
    }
    if (rc == VTY_OK && vty_ct_equal(check, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_TPM;
    }
    vty_secure_zero(check, sizeof(check));
    if (rc != VTY_OK) {
        /* 新键已覆盖旧键：本次重密封失败后需再次用恢复码重试 */
        vty_secure_zero(digest, sizeof(digest));
        vty_secure_zero(ct, sizeof(ct));
        return VTY_E_TPM;
    }

    memcpy(v->slots[p_idx].pcr_digest, digest, VTY_HASH_BYTES);
    memcpy(v->slots[p_idx].ct, ct, VTY_TPM_PCR_CT_BYTES);
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(ct, sizeof(ct));
    rc = vty_vault_save(v);
    if (rc != VTY_OK) v->unlocked = 0;
    return rc;
}

int vty_vault_module_key(const VtyVault *v, const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint8_t key_out[VTY_KEY_BYTES])
{
    if (v == NULL || module_uuid == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    return vty_keyring_find(&v->keyring, VTY_KEYKIND_MDEK,
                            module_uuid, VTY_UUID_BYTES, key_out);
}

int vty_vault_module_uuid(const VtyVault *v, uint32_t index,
                          uint8_t out[VTY_UUID_BYTES])
{
    uint32_t i, n = 0;
    if (v == NULL || out == NULL) return VTY_E_INVALID;
    for (i = 0; i < v->keyring.count; i++) {
        if (v->keyring.entries[i].kind != VTY_KEYKIND_MDEK) continue;
        if (n == index) {
            memcpy(out, v->keyring.entries[i].module_uuid, VTY_UUID_BYTES);
            return VTY_OK;
        }
        n++;
    }
    return VTY_E_INVALID;
}

void vty_vault_lock(VtyVault *v)
{
    if (v == NULL) return;
    vty_secure_zero(v->kc, sizeof(v->kc));
    vty_secure_zero(v->kg, sizeof(v->kg));
    vty_secure_zero(&v->keyring, sizeof(v->keyring));
    v->unlocked = 0;
    /* Keyring 的 32 字节条目会被编译器溢出到栈槽位，缓冲区清零无法覆盖 */
    vty_wipe_stack();
}

void vty_vault_free(VtyVault *v)
{
    if (v == NULL) return;
    vty_vault_lock(v);
    if (v->header_buf != NULL) {
        vty_free(v->header_buf, v->header_len);
        v->header_buf = NULL;
    }
    vty_free(v, sizeof(VtyVault));
}
