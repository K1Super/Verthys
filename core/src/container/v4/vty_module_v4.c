/*
 * vty_module_v4.c — 模块 M1 密钥生命周期实现
 */
#include "vty_module_v4.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_blake3.h"
#include "vty_device_root.h"
#include "vty_lockout.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MOD_VERSION 1u
#define MOD_HDR_BYTES 84u
#define MOD_HASH_BYTES 32u
#define MOD_MAX_BYTES 65536u

typedef struct {
    uint8_t vault_uuid[VTY_UUID_BYTES];
    uint8_t module_uuid[VTY_UUID_BYTES];
    uint64_t epoch;
    uint8_t verifier[VTY_HASH_BYTES];
    VtySlot slots[2];
    uint32_t slot_count;
} ModuleFile;

static wchar_t *mod_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static int mod_read(const char *path, uint8_t **out, size_t *out_len)
{
    wchar_t *w;
    HANDLE h;
    LARGE_INTEGER size;
    uint8_t *buf;
    DWORD got = 0;
    int rc = VTY_OK;

    if (path == NULL || out == NULL || out_len == NULL) return VTY_E_INVALID;
    *out = NULL; *out_len = 0;
    w = mod_wide(path);
    if (w == NULL) return VTY_E_INVALID;
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return VTY_E_IO;
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > MOD_MAX_BYTES) {
        CloseHandle(h);
        return VTY_E_INVALID;
    }
    buf = (uint8_t *)malloc((size_t)size.QuadPart);
    if (buf == NULL) { CloseHandle(h); return VTY_E_RESOURCE; }
    if (!ReadFile(h, buf, (DWORD)size.QuadPart, &got, NULL) || got != (DWORD)size.QuadPart) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    if (rc != VTY_OK) { free(buf); return rc; }
    *out = buf;
    *out_len = got;
    return VTY_OK;
}

static int mod_write(const char *path, const uint8_t *data, size_t len, int replace)
{
    wchar_t *w;
    wchar_t *wt;
    char temp[1100];
    HANDLE h;
    DWORD written = 0;
    int rc = VTY_OK;

    if (path == NULL || data == NULL) return VTY_E_INVALID;
    if (strlen(path) + 32 >= sizeof(temp)) return VTY_E_INVALID;
    if (!replace) {
        w = mod_wide(path);
        if (w == NULL) return VTY_E_INVALID;
        if (GetFileAttributesW(w) != INVALID_FILE_ATTRIBUTES) {
            free(w);
            return VTY_E_INVALID;
        }
        free(w);
    }
    sprintf_s(temp, sizeof(temp), "%s.tmp%08lx", path,
              (unsigned long)GetCurrentProcessId());
    wt = mod_wide(temp);
    if (wt == NULL) return VTY_E_INVALID;
    h = CreateFileW(wt, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { free(wt); return VTY_E_IO; }
    if (!WriteFile(h, data, (DWORD)len, &written, NULL) || written != (DWORD)len) {
        rc = VTY_E_IO;
    }
    if (rc == VTY_OK && !FlushFileBuffers(h)) rc = VTY_E_IO;
    CloseHandle(h);
    if (rc == VTY_OK) {
        w = mod_wide(path);
        if (w == NULL) {
            rc = VTY_E_INVALID;
        } else if (!MoveFileExW(wt, w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            rc = VTY_E_IO;
        }
        free(w);
    }
    if (rc != VTY_OK) DeleteFileW(wt);
    free(wt);
    return rc;
}

static int module_aad(const uint8_t vault_uuid[VTY_UUID_BYTES],
                      const uint8_t module_uuid[VTY_UUID_BYTES],
                      uint64_t epoch, uint8_t index, uint8_t slot_type,
                      uint8_t out[64], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_MODULE;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, vault_uuid, VTY_UUID_BYTES);
    memcpy(out + dlen + VTY_UUID_BYTES, module_uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES * 2u, epoch);
    out[dlen + VTY_UUID_BYTES * 2u + 8u] = index;
    out[dlen + VTY_UUID_BYTES * 2u + 8u + 1u] = slot_type;
    *out_len = dlen + VTY_UUID_BYTES * 2u + 8u + 2u;
    return VTY_OK;
}

static int module_verifier(const uint8_t mdek[VTY_KEY_BYTES],
                           const uint8_t module_uuid[VTY_UUID_BYTES],
                           uint8_t out[VTY_HASH_BYTES])
{
    uint8_t info[64];
    size_t llen = strlen(VTY_DOMAIN_MODULE);
    uint8_t vk[VTY_KEY_BYTES];
    int rc;

    memcpy(info, VTY_DOMAIN_MODULE, llen);
    memcpy(info + llen, module_uuid, VTY_UUID_BYTES);
    rc = vty_hkdf_expand(vk, mdek, info, llen + VTY_UUID_BYTES);
    if (rc == VTY_OK) {
        rc = vty_hmac_sha256(out, vk, VTY_KEY_BYTES,
                             (const uint8_t *)"verify", 6);
    }
    vty_secure_zero(vk, sizeof(vk));
    vty_secure_zero(info, sizeof(info));
    return rc;
}

static int module_serialize(const ModuleFile *m, uint8_t **out, size_t *out_len)
{
    size_t slots_len = 0;
    size_t total;
    uint8_t *buf;
    size_t off;
    uint32_t i;
    int rc;

    for (i = 0; i < m->slot_count; i++) slots_len += vty_slot_serialized_len(&m->slots[i]);
    total = MOD_HDR_BYTES + slots_len + MOD_HASH_BYTES;
    if (total > 0xFFFFu) return VTY_E_INVALID;

    buf = (uint8_t *)vty_alloc(total);
    if (buf == NULL) return VTY_E_RESOURCE;

    vty_put_u32(buf + 0, VTY_MODULE_MAGIC);
    vty_put_u32(buf + 4, MOD_VERSION);
    memcpy(buf + 8, m->vault_uuid, VTY_UUID_BYTES);
    memcpy(buf + 24, m->module_uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + 40, m->epoch);
    vty_put_u16(buf + 48, (uint16_t)m->slot_count);
    vty_put_u16(buf + 50, 0);
    memcpy(buf + 52, m->verifier, VTY_HASH_BYTES);

    off = MOD_HDR_BYTES;
    {
        VtyV4Header fake;
        memset(&fake, 0, sizeof(fake));
        for (i = 0; i < m->slot_count; i++) {
            size_t w = 0;
            rc = vty_slot_write(&m->slots[i], i, &fake, buf + off,
                                total - off - MOD_HASH_BYTES, &w);
            if (rc != VTY_OK) { vty_free(buf, total); return rc; }
            off += w;
        }
    }

    rc = vty_blake3_32(buf, off, buf + off);
    if (rc != VTY_OK) { vty_free(buf, total); return rc; }

    *out = buf;
    *out_len = total;
    return VTY_OK;
}

static int module_parse(const uint8_t *buf, size_t len, ModuleFile *out)
{
    uint8_t hash[VTY_HASH_BYTES];
    size_t slots_len;
    size_t off = 0;
    uint32_t count, i;
    VtyV4Header fake;

    if (buf == NULL || out == NULL || len < MOD_HDR_BYTES + MOD_HASH_BYTES) {
        return VTY_E_INVALID;
    }
    if (vty_get_u32(buf) != VTY_MODULE_MAGIC) return VTY_E_VERSION;
    if (vty_get_u32(buf + 4) != MOD_VERSION) return VTY_E_VERSION;
    if (vty_blake3_32(buf, len - MOD_HASH_BYTES, hash) != VTY_OK) return VTY_E_INVALID;
    if (vty_ct_equal(hash, buf + len - MOD_HASH_BYTES, VTY_HASH_BYTES) != 0) {
        return VTY_E_CORRUPT;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->vault_uuid, buf + 8, VTY_UUID_BYTES);
    memcpy(out->module_uuid, buf + 24, VTY_UUID_BYTES);
    out->epoch = vty_get_u64(buf + 40);
    count = vty_get_u16(buf + 48);
    memcpy(out->verifier, buf + 52, VTY_HASH_BYTES);
    if (count != 2) return VTY_E_INVALID;

    slots_len = len - MOD_HDR_BYTES - MOD_HASH_BYTES;
    memset(&fake, 0, sizeof(fake));
    for (i = 0; i < count; i++) {
        size_t consumed = 0;
        int rc = vty_slot_parse_at(buf + MOD_HDR_BYTES, slots_len, off, i,
                                   &fake, &out->slots[i], &consumed);
        if (rc != VTY_OK) return rc;
        off += consumed;
    }
    if (off != slots_len) return VTY_E_INVALID;
    out->slot_count = count;
    return VTY_OK;
}

static int seal_module(ModuleFile *m, const uint8_t mdek[VTY_KEY_BYTES],
                       const uint8_t share_u[VTY_KEY_BYTES],
                       const uint8_t share_d[VTY_KEY_BYTES],
                       const char *password,
                       uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    uint8_t aad[64];
    size_t aad_len = 0;
    uint8_t kek[VTY_KEY_BYTES];
    VtySlot *u_slot;
    VtySlot *d_slot;
    int rc;

    rc = module_verifier(mdek, m->module_uuid, m->verifier);
    if (rc != VTY_OK) return rc;
    if (vty_kdf_params_valid(mem_kib, iters, parallel) != VTY_OK) return VTY_E_KDF_WEAK;

    u_slot = &m->slots[0];
    d_slot = &m->slots[1];

    memset(u_slot, 0, sizeof(*u_slot));
    u_slot->slot_type = VTY_SLOT_USER_PASSWORD;
    u_slot->slot_flags = VTY_SLOT_FLAG_REQUIRED | VTY_SLOT_FLAG_ROTATABLE;
    u_slot->kdf_id = VTY_KDF_ARGON2ID;
    u_slot->wrap_alg = VTY_WRAP_XCHACHA;
    u_slot->params_len = 12u;
    u_slot->m_cost = mem_kib;
    u_slot->t_cost = iters;
    u_slot->p_cost = parallel;
    vty_random(u_slot->salt, VTY_SALT_BYTES);

    rc = vty_kdf_argon2id(kek, (const uint8_t *)password, strlen(password),
                          u_slot->salt, mem_kib, iters, parallel);
    if (rc != VTY_OK) { vty_secure_zero(kek, sizeof(kek)); return rc; }

    module_aad(m->vault_uuid, m->module_uuid, m->epoch, 0,
               VTY_SLOT_USER_PASSWORD, aad, &aad_len);
    rc = vty_wrap_key32(kek, share_u, aad, aad_len, u_slot->nonce, u_slot->ct);
    vty_secure_zero(kek, sizeof(kek));
    if (rc != VTY_OK) return rc;
    u_slot->ct_len = VTY_KEY_BYTES + VTY_TAG_BYTES;

    rc = vty_slot_seal_device(d_slot, VTY_SLOT_FLAG_REQUIRED, share_d,
                              NULL, 0);
    return rc;
}

static int open_module_slot(const ModuleFile *m, const char *password,
                            uint8_t share_u[VTY_KEY_BYTES])
{
    uint8_t aad[64];
    size_t aad_len = 0;
    uint8_t kek[VTY_KEY_BYTES];
    int rc;

    if (m->slots[0].slot_type != VTY_SLOT_USER_PASSWORD) return VTY_E_SLOT_UNKNOWN;
    rc = vty_kdf_params_valid(m->slots[0].m_cost, m->slots[0].t_cost,
                              m->slots[0].p_cost);
    if (rc != VTY_OK) return rc;

    rc = vty_kdf_argon2id(kek, (const uint8_t *)password, strlen(password),
                          m->slots[0].salt, m->slots[0].m_cost,
                          m->slots[0].t_cost, m->slots[0].p_cost);
    if (rc != VTY_OK) { vty_secure_zero(kek, sizeof(kek)); return rc; }

    module_aad(m->vault_uuid, m->module_uuid, m->epoch, 0,
               VTY_SLOT_USER_PASSWORD, aad, &aad_len);
    rc = vty_unwrap_key32(kek, m->slots[0].nonce, aad, aad_len,
                          m->slots[0].ct, m->slots[0].ct_len, share_u);
    vty_secure_zero(kek, sizeof(kek));
    return rc;
}

int vty_module_create(const char *path, const VtyVault *v,
                      const uint8_t module_uuid[VTY_UUID_BYTES],
                      const char *password,
                      uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    ModuleFile m;
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc;
    size_t i;

    if (path == NULL || v == NULL || module_uuid == NULL || password == NULL) {
        return VTY_E_INVALID;
    }
    if (password[0] == '\0') return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (vty_kdf_params_valid(mem_kib, iters, parallel) != VTY_OK) return VTY_E_KDF_WEAK;

    rc = vty_vault_module_key(v, module_uuid, mdek);
    if (rc != VTY_OK) return rc;

    memset(&m, 0, sizeof(m));
    memcpy(m.vault_uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    memcpy(m.module_uuid, module_uuid, VTY_UUID_BYTES);
    m.epoch = v->header.epoch;
    m.slot_count = 2;

    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(mdek[i] ^ share_u[i]);
    }

    rc = seal_module(&m, mdek, share_u, share_d, password, mem_kib, iters, parallel);
    if (rc == VTY_OK) {
        rc = module_serialize(&m, &blob, &blob_len);
    }
    if (rc == VTY_OK) {
        rc = mod_write(path, blob, blob_len, 0);
    }

    if (blob != NULL) vty_free(blob, blob_len);
    vty_secure_zero(mdek, sizeof(mdek));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

int vty_module_unlock(const char *path, const VtyVault *v,
                      const uint8_t module_uuid[VTY_UUID_BYTES],
                      const char *password,
                      uint8_t mdek_out[VTY_KEY_BYTES])
{
    ModuleFile m;
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t verifier[VTY_HASH_BYTES];
    int rc;
    size_t i;

    if (path == NULL || v == NULL || module_uuid == NULL ||
        password == NULL || mdek_out == NULL) {
        return VTY_E_INVALID;
    }

    /* 模块切换与库解锁共用持久化熔断：错误模块口令累计达阈值后拒绝 */
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
        if (vty_lockout_check() == VTY_E_LOCKED) return VTY_E_LOCKED;
    }

    rc = mod_read(path, &buf, &buf_len);
    if (rc != VTY_OK) return rc;
    rc = module_parse(buf, buf_len, &m);
    if (rc == VTY_OK) {
        if (memcmp(m.vault_uuid, v->header.vault_uuid, VTY_UUID_BYTES) != 0 ||
            memcmp(m.module_uuid, module_uuid, VTY_UUID_BYTES) != 0 ||
            m.epoch != v->header.epoch) {
            rc = VTY_E_KEY_INVALID;
        }
    }
    if (rc == VTY_OK) rc = open_module_slot(&m, password, share_u);
    if (rc == VTY_OK) {
        rc = vty_slot_open_device(&m.slots[1], NULL, 1, share_d);
    }
    if (rc == VTY_OK) {
        for (i = 0; i < VTY_KEY_BYTES; i++) {
            mdek_out[i] = (uint8_t)(share_u[i] ^ share_d[i]);
        }
        rc = module_verifier(mdek_out, module_uuid, verifier);
        if (rc == VTY_OK &&
            vty_ct_equal(verifier, m.verifier, VTY_HASH_BYTES) != 0) {
            rc = VTY_E_KEY_INVALID;
        }
        if (rc != VTY_OK) vty_secure_zero(mdek_out, VTY_KEY_BYTES);
    }

    if (vty_lockout_enabled()) {
        (void)vty_lockout_init();
        if (rc == VTY_E_KEY_INVALID) {
            /* 口令/绑定校验失败计入熔断；IO/资源错误不计入 */
            (void)vty_lockout_record_failure();
        }
        /* 注意：模块解锁成功不清零计数。计数是整机维度、库口令与模块
         * 口令共用；若“任一成功即清零”，只掌握某个低价值模块口令的人
         * 就能反复用该模块解锁洗掉库口令的失败次数，形成无限次猜测通道。
         * 清零只发生在库解锁成功或恢复码解锁成功。 */
    }

    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(verifier, sizeof(verifier));
    if (buf != NULL) vty_free(buf, buf_len);
    return rc;
}

int vty_module_rotate_password(const char *path, const VtyVault *v,
                               const uint8_t module_uuid[VTY_UUID_BYTES],
                               const char *new_password,
                               uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    ModuleFile m;
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc;
    size_t i;

    if (path == NULL || v == NULL || module_uuid == NULL || new_password == NULL) {
        return VTY_E_INVALID;
    }
    if (new_password[0] == '\0' || !v->unlocked) return VTY_E_POLICY;

    rc = mod_read(path, &buf, &buf_len);
    if (rc != VTY_OK) return rc;
    rc = module_parse(buf, buf_len, &m);
    if (rc == VTY_OK) {
        if (memcmp(m.vault_uuid, v->header.vault_uuid, VTY_UUID_BYTES) != 0 ||
            memcmp(m.module_uuid, module_uuid, VTY_UUID_BYTES) != 0) {
            rc = VTY_E_KEY_INVALID;
        }
    }
    if (rc == VTY_OK) rc = vty_vault_module_key(v, module_uuid, mdek);
    if (rc == VTY_OK) {
        /* 容器 epoch 可能在口令轮换后前移；模块包裹必须跟随当前 epoch */
        m.epoch = v->header.epoch;
        vty_random(share_u, VTY_KEY_BYTES);
        for (i = 0; i < VTY_KEY_BYTES; i++) {
            share_d[i] = (uint8_t)(mdek[i] ^ share_u[i]);
        }
        rc = seal_module(&m, mdek, share_u, share_d, new_password,
                         mem_kib, iters, parallel);
    }
    if (rc == VTY_OK) rc = module_serialize(&m, &blob, &blob_len);
    if (rc == VTY_OK) rc = mod_write(path, blob, blob_len, 1);

    if (blob != NULL) vty_free(blob, blob_len);
    if (buf != NULL) vty_free(buf, buf_len);
    vty_secure_zero(mdek, sizeof(mdek));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

int vty_module_destroy(const char *path)
{
    wchar_t *w;
    if (path == NULL) return VTY_E_INVALID;
    w = mod_wide(path);
    if (w == NULL) return VTY_E_INVALID;
    if (!DeleteFileW(w)) {
        DWORD err = GetLastError();
        free(w);
        return (err == ERROR_FILE_NOT_FOUND) ? VTY_OK : VTY_E_IO;
    }
    free(w);
    return VTY_OK;
}
