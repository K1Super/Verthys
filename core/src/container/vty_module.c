/*
 * vty_module.c — 模块 M1 模块表与密钥生命周期
 *
 * 模块表存放在目录 keyspace 5。未启用模块的 MDEK 仍在 body Keyring；
 * 启用后 MDEK 移出 Keyring，只以 share_u/share_d 形式存于描述符槽。
 * 因此启用后仅持有 K_c 无法取得 MDEK，模块口令与设备根构成真实边界。
 *
 * 事务边界：所有写操作先写数据区（COW），再提交一次数据区，最后
 * 写一次元数据。提交前的失败恢复 store checkpoint；元数据提交失败
 * 一律锁定会话，避免代际不确定时继续写。
 */
#include "vty_module_internal.h"

int vty_mod_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

void vty_mod_desc_clear(ModuleDesc *d)
{
    if (d != NULL) vty_secure_zero(d, sizeof(*d));
}

void vty_mod_desc_init_disabled(ModuleDesc *d,
                                const uint8_t uuid[VTY_UUID_BYTES])
{
    memset(d, 0, sizeof(*d));
    memcpy(d->uuid, uuid, VTY_UUID_BYTES);
    d->enabled = 0u;
    d->deleted = 0u;
    d->has_recovery = 0u;
    d->module_epoch = VTY_MODULE_EPOCH_DISABLED;
}

static int desc_serialize(const ModuleDesc *d, uint32_t index,
                          uint8_t **out, size_t *out_len)
{
    uint8_t *buf;
    size_t total = MOD_DESC_OFF_SLOTS;
    size_t off;
    uint32_t slot_count;
    VtyHeader fake;
    int rc;

    if (d == NULL || out == NULL || out_len == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (d->enabled && d->deleted) return VTY_E_INVALID;
    if (d->enabled && d->module_epoch != VTY_MODULE_EPOCH_ENABLED) {
        return VTY_E_INVALID;
    }
    if (!d->enabled) {
        total = MOD_DESC_OFF_SLOTS;
    } else {
        total += vty_slot_serialized_len(&d->user);
        total += vty_slot_serialized_len(&d->device);
        if (d->has_recovery) total += VTY_MODULE_RECOVERY_BYTES;
    }
    if (total > VTY_MODULE_DESC_MAX) return VTY_E_INVALID;

    buf = (uint8_t *)vty_alloc(total);
    if (buf == NULL) return VTY_E_RESOURCE;

    buf[MOD_DESC_OFF_VER] = MOD_DESC_VER;
    buf[MOD_DESC_OFF_FLAGS] = d->enabled ? VTY_MODULE_FLAG_ENABLED :
                              (d->deleted ? VTY_MODULE_FLAG_DELETED : 0u);
    buf[MOD_DESC_OFF_INDEX] = (uint8_t)index;
    buf[MOD_DESC_OFF_RESERVED] = 0u;
    memcpy(buf + MOD_DESC_OFF_UUID, d->uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + MOD_DESC_OFF_EPOCH, d->module_epoch);
    if (d->enabled) {
        memcpy(buf + MOD_DESC_OFF_VERIFIER, d->verifier, VTY_HASH_BYTES);
    }
    slot_count = d->enabled ? (d->has_recovery ? 3u : 2u) : 0u;
    buf[MOD_DESC_OFF_SLOT_COUNT] = (uint8_t)slot_count;
    memset(buf + MOD_DESC_OFF_RESERVED2, 0, 3u);

    if (!d->enabled) {
        *out = buf;
        *out_len = total;
        return VTY_OK;
    }

    memset(&fake, 0, sizeof(fake));
    off = MOD_DESC_OFF_SLOTS;
    {
        size_t w = 0;
        rc = vty_slot_write(&d->user, VTY_MODULE_SLOT_USER, &fake, buf + off,
                            total - off, &w);
        if (rc != VTY_OK) { vty_free(buf, total); return rc; }
        off += w;
        rc = vty_slot_write(&d->device, VTY_MODULE_SLOT_DEVICE, &fake, buf + off,
                            total - off, &w);
        if (rc != VTY_OK) { vty_free(buf, total); return rc; }
        off += w;
    }
    if (d->has_recovery) {
        if (total - off != VTY_MODULE_RECOVERY_BYTES) {
            vty_free(buf, total);
            return VTY_E_INVALID;
        }
        buf[off] = MOD_REC_VER;
        buf[off + 1u] = 0u;
        buf[off + 2u] = 0u;
        buf[off + 3u] = 0u;
        memcpy(buf + off + 4u, d->rec_nonce, VTY_NONCE_BYTES);
        memcpy(buf + off + 4u + VTY_NONCE_BYTES, d->rec_ct, MOD_REC_CT);
        off += VTY_MODULE_RECOVERY_BYTES;
    }
    if (off != total) { vty_free(buf, total); return VTY_E_INVALID; }

    *out = buf;
    *out_len = total;
    return VTY_OK;
}

static int desc_parse(const uint8_t *buf, size_t len, uint32_t expected_index,
                      ModuleDesc *out)
{
    VtyHeader fake;
    uint8_t slot_count;
    size_t off;
    int rc;

    if (buf == NULL || out == NULL || len < MOD_DESC_OFF_SLOTS) {
        return VTY_E_INVALID;
    }
    if (buf[MOD_DESC_OFF_VER] != MOD_DESC_VER) return VTY_E_VERSION;
    if ((buf[MOD_DESC_OFF_FLAGS] & (uint8_t)~0x03u) != 0) return VTY_E_SLOT_UNKNOWN;
    if (buf[MOD_DESC_OFF_INDEX] != (uint8_t)expected_index) return VTY_E_CORRUPT;
    if (buf[MOD_DESC_OFF_RESERVED] != 0) return VTY_E_CORRUPT;
    if (buf[MOD_DESC_OFF_RESERVED2] != 0 ||
        buf[MOD_DESC_OFF_RESERVED2 + 1u] != 0 ||
        buf[MOD_DESC_OFF_RESERVED2 + 2u] != 0) {
        return VTY_E_CORRUPT;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->uuid, buf + MOD_DESC_OFF_UUID, VTY_UUID_BYTES);
    if (vty_mod_all_zero(out->uuid, VTY_UUID_BYTES)) return VTY_E_CORRUPT;
    out->enabled = (uint8_t)(buf[MOD_DESC_OFF_FLAGS] & VTY_MODULE_FLAG_ENABLED);
    out->deleted = (uint8_t)((buf[MOD_DESC_OFF_FLAGS] & VTY_MODULE_FLAG_DELETED) != 0);
    if (out->enabled && out->deleted) {
        vty_mod_desc_clear(out);
        return VTY_E_CORRUPT;
    }
    out->module_epoch = vty_get_u64(buf + MOD_DESC_OFF_EPOCH);
    memcpy(out->verifier, buf + MOD_DESC_OFF_VERIFIER, VTY_HASH_BYTES);
    slot_count = buf[MOD_DESC_OFF_SLOT_COUNT];

    if (!out->enabled) {
        if (len != MOD_DESC_OFF_SLOTS || slot_count != 0u ||
            out->module_epoch != VTY_MODULE_EPOCH_DISABLED ||
            !vty_mod_all_zero(out->verifier, VTY_HASH_BYTES)) {
            vty_mod_desc_clear(out);
            return VTY_E_CORRUPT;
        }
        return VTY_OK;
    }

    if (out->module_epoch != VTY_MODULE_EPOCH_ENABLED) {
        vty_mod_desc_clear(out);
        return VTY_E_CORRUPT;
    }
    if (slot_count != 2u && slot_count != 3u) {
        vty_mod_desc_clear(out);
        return VTY_E_CORRUPT;
    }
    if (vty_mod_all_zero(out->verifier, VTY_HASH_BYTES)) {
        vty_mod_desc_clear(out);
        return VTY_E_CORRUPT;
    }

    memset(&fake, 0, sizeof(fake));
    off = MOD_DESC_OFF_SLOTS;
    {
        size_t consumed = 0;
        rc = vty_slot_parse_at(buf, len, off, VTY_MODULE_SLOT_USER, &fake,
                               &out->user, &consumed);
        if (rc != VTY_OK) { vty_mod_desc_clear(out); return rc; }
        off += consumed;
        if (out->user.slot_type != VTY_SLOT_USER_PASSWORD ||
            out->user.kdf_id != VTY_KDF_ARGON2ID ||
            out->user.wrap_alg != VTY_WRAP_XCHACHA ||
            (out->user.slot_flags & VTY_SLOT_FLAG_REQUIRED) == 0 ||
            vty_kdf_params_valid(out->user.m_cost, out->user.t_cost,
                                 out->user.p_cost) != VTY_OK) {
            vty_mod_desc_clear(out);
            return VTY_E_SLOT_UNKNOWN;
        }
        rc = vty_slot_parse_at(buf, len, off, VTY_MODULE_SLOT_DEVICE, &fake,
                               &out->device, &consumed);
        if (rc != VTY_OK) { vty_mod_desc_clear(out); return rc; }
        off += consumed;
        if (out->device.slot_type != VTY_SLOT_DEVICE_ROOT ||
            out->device.kdf_id != VTY_KDF_NONE ||
            out->device.wrap_alg != VTY_WRAP_RSAOAEP) {
            vty_mod_desc_clear(out);
            return VTY_E_SLOT_UNKNOWN;
        }
    }

    if (slot_count == 3u) {
        size_t rec_len = VTY_MODULE_RECOVERY_BYTES;
        if (len - off != rec_len) { vty_mod_desc_clear(out); return VTY_E_CORRUPT; }
        if (buf[off] != MOD_REC_VER || buf[off + 1u] != 0u ||
            buf[off + 2u] != 0u || buf[off + 3u] != 0u) {
            vty_mod_desc_clear(out);
            return VTY_E_CORRUPT;
        }
        memcpy(out->rec_nonce, buf + off + 4u, VTY_NONCE_BYTES);
        memcpy(out->rec_ct, buf + off + 4u + VTY_NONCE_BYTES, MOD_REC_CT);
        out->has_recovery = 1u;
        off += rec_len;
    } else {
        out->has_recovery = 0u;
    }
    if (off != len) { vty_mod_desc_clear(out); return VTY_E_CORRUPT; }
    return VTY_OK;
}

int vty_mod_desc_load(VtyVault *v, uint32_t index, ModuleDesc *out)
{
    uint8_t key = (uint8_t)index;
    uint8_t *value = NULL;
    size_t value_len = 0;
    int rc;

    if (v == NULL || v->store == NULL || out == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    rc = vty_store_get(v->store, VTY_KS_MODULE, &key, 1u, &value, &value_len);
    if (rc != VTY_OK) return VTY_E_CORRUPT;
    rc = desc_parse(value, value_len, index, out);
    if (value != NULL) vty_free(value, value_len);
    return rc;
}

int vty_mod_desc_store(VtyVault *v, uint32_t index, const ModuleDesc *d)
{
    uint8_t key = (uint8_t)index;
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc;

    if (v == NULL || v->store == NULL || d == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    rc = desc_serialize(d, index, &buf, &len);
    if (rc != VTY_OK) return rc;
    rc = vty_store_put(v->store, VTY_KS_MODULE, &key, 1u, buf, len);
    vty_free(buf, len);
    return rc;
}

uint32_t vty_module_index_for_type(uint8_t type)
{
    switch (type) {
    case 0x02: case 0x03: case 0x0A: case 0x20:
        return 1u; /* accounts */
    case 0x04: case 0x08:
        return 2u; /* fileverthys */
    default:
        return 0u; /* photo / 未知 */
    }
}

int vty_module_table_init(VtyVault *v)
{
    uint32_t i, n = 0;
    ModuleDesc d;
    int rc;

    if (v == NULL || v->store == NULL || !v->unlocked) return VTY_E_POLICY;

    memset(v->modules, 0, sizeof(v->modules));
    for (i = 0; i < v->keyring.count; i++) {
        VtyKeyEntry *e = &v->keyring.entries[i];
        if (e->kind != VTY_KEYKIND_MDEK) continue;
        if (n >= VTY_MODULE_COUNT) return VTY_E_CORRUPT;
        vty_mod_desc_init_disabled(&d, e->id);
        rc = vty_mod_desc_store(v, n, &d);
        vty_mod_desc_clear(&d);
        if (rc != VTY_OK) return rc;
        memcpy(v->modules[n].uuid, e->id, VTY_UUID_BYTES);
        n++;
    }
    if (n != VTY_MODULE_COUNT) return VTY_E_CORRUPT;
    /* 模块表使新库目录非空；同时建立记录分配器，避免首次 Add
     * 把“目录非空但没有分配器”误判为 E_CORRUPT。 */
    rc = vty_repo_init_allocator(v);
    if (rc != VTY_OK) return rc;
    return vty_vault_commit_store(v);
}

int vty_module_table_load(VtyVault *v)
{
    ModuleDesc descs[VTY_MODULE_COUNT];
    uint32_t i, j, disabled_count = 0, enabled_count = 0;
    int rc;

    if (v == NULL || v->store == NULL || !v->unlocked) return VTY_E_POLICY;

    memset(descs, 0, sizeof(descs));
    memset(v->modules, 0, sizeof(v->modules));

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        rc = vty_mod_desc_load(v, i, &descs[i]);
        if (rc != VTY_OK) goto fail;
        if (descs[i].enabled) enabled_count++;
        else if (!descs[i].deleted) disabled_count++;
        memcpy(v->modules[i].uuid, descs[i].uuid, VTY_UUID_BYTES);
        v->modules[i].enabled = descs[i].enabled;
        v->modules[i].deleted = descs[i].deleted;
        v->modules[i].has_recovery = descs[i].has_recovery;
        v->modules[i].unlocked = 0u;
        vty_secure_zero(v->modules[i].mdek, VTY_KEY_BYTES);
        for (j = 0; j < i; j++) {
            if (memcmp(descs[j].uuid, descs[i].uuid, VTY_UUID_BYTES) == 0) {
                rc = VTY_E_CORRUPT;
                goto fail;
            }
        }
    }

    if (((v->header.flags & VTY_FLAG_MODULE_M1) != 0) != (enabled_count != 0)) {
        rc = VTY_E_CORRUPT;
        goto fail;
    }

    {
        uint32_t kind3 = 0;
        for (i = 0; i < v->keyring.count; i++) {
            VtyKeyEntry *e = &v->keyring.entries[i];
            int found = 0;
            if (e->kind != VTY_KEYKIND_MDEK) continue;
            kind3++;
            for (j = 0; j < VTY_MODULE_COUNT; j++) {
                if (e->id_len == VTY_UUID_BYTES &&
                    memcmp(e->id, descs[j].uuid, VTY_UUID_BYTES) == 0) {
                    found = 1;
                    if (descs[j].enabled || descs[j].deleted ||
                        vty_mod_all_zero(e->key, VTY_KEY_BYTES)) {
                        rc = VTY_E_CORRUPT;
                        goto fail;
                    }
                    break;
                }
            }
            if (!found) { rc = VTY_E_CORRUPT; goto fail; }
        }
        if (kind3 != disabled_count) { rc = VTY_E_CORRUPT; goto fail; }
    }

    for (i = 0; i < VTY_MODULE_COUNT; i++) vty_mod_desc_clear(&descs[i]);
    return VTY_OK;

fail:
    for (i = 0; i < VTY_MODULE_COUNT; i++) vty_mod_desc_clear(&descs[i]);
    memset(v->modules, 0, sizeof(v->modules));
    return rc;
}

void vty_module_lock(VtyVault *v, uint32_t index)
{
    uint32_t i;

    if (v == NULL) return;
    if (index == VTY_MODULE_ALL) {
        for (i = 0; i < VTY_MODULE_COUNT; i++) {
            v->modules[i].unlocked = 0u;
            vty_secure_zero(v->modules[i].mdek, VTY_KEY_BYTES);
        }
        return;
    }
    if (index >= VTY_MODULE_COUNT) return;
    v->modules[index].unlocked = 0u;
    vty_secure_zero(v->modules[index].mdek, VTY_KEY_BYTES);
}

int vty_module_status(const VtyVault *v, uint32_t index, VtyModuleStatus *out)
{
    if (v == NULL || out == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    out->enabled = v->modules[index].enabled;
    out->unlocked = v->modules[index].unlocked;
    out->has_recovery = v->modules[index].has_recovery;
    out->deleted = v->modules[index].deleted;
    return VTY_OK;
}

