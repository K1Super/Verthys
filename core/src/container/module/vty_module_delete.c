/*
 * vty_module_delete.c — 模块删除、清除与写盘配额
 *
 * 删除以密码学销毁 MDEK 为前提，清除该模块记录/文件/分片叶后写入
 * deleted 描述符并轮换 UUID；写盘前以卷剩余空间作为配额门。
 */
#include "vty_module_internal.h"

static void desc_init_deleted(ModuleDesc *d,
                              const uint8_t uuid[VTY_UUID_BYTES])
{
    memset(d, 0, sizeof(*d));
    memcpy(d->uuid, uuid, VTY_UUID_BYTES);
    d->enabled = 0u;
    d->deleted = 1u;
    d->has_recovery = 0u;
    d->module_epoch = VTY_MODULE_EPOCH_DISABLED;
}

/* 卷剩余空间必须覆盖模块重写追加量与余量；不足时在写盘前拒绝。 */
int vty_mod_free_space_ok(const VtyVault *v, uint64_t need)
{
    wchar_t wpath[1024];
    wchar_t volume[1024];
    ULARGE_INTEGER free_bytes;
    int n;
    uint64_t required;

    if (v->path[0] == '\0') return VTY_E_INVALID;
    n = MultiByteToWideChar(CP_UTF8, 0, v->path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0])));
    if (n <= 0) return VTY_E_INVALID;
    if (!GetVolumePathNameW(wpath, volume,
                            (DWORD)(sizeof(volume) / sizeof(volume[0])))) {
        return VTY_E_IO;
    }
    if (!GetDiskFreeSpaceExW(volume, &free_bytes, NULL, NULL)) return VTY_E_IO;
    if (need > UINT64_MAX - (1024u * 1024u)) return VTY_E_RESOURCE;
    required = need + need / 10u + (1024u * 1024u);
    return (free_bytes.QuadPart >= required) ? VTY_OK : VTY_E_RESOURCE;
}

int vty_module_delete(VtyVault *v, uint32_t index,
                      const char *password, const char *confirm)
{
    ModuleDesc desc;
    ModuleDesc deleted_desc;
    VtyStoreCheckpoint cp;
    VtyKeyring old_kr;
    VtyKeyring new_kr;
    VtyModuleState old_state;
    uint16_t old_flags;
    uint8_t old_uuid[VTY_UUID_BYTES];
    uint8_t new_uuid[VTY_UUID_BYTES];
    uint8_t check_key[VTY_KEY_BYTES];
    uint64_t records = 0, files = 0, chunks = 0;
    uint32_t i;
    int any_enabled = 0;
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(&deleted_desc, 0, sizeof(deleted_desc));
    memset(&old_kr, 0, sizeof(old_kr));
    memset(&new_kr, 0, sizeof(new_kr));
    memset(&old_state, 0, sizeof(old_state));
    memset(old_uuid, 0, sizeof(old_uuid));
    memset(new_uuid, 0, sizeof(new_uuid));
    memset(check_key, 0, sizeof(check_key));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (confirm == NULL || strcmp(confirm, "DELETE") != 0) return VTY_E_INVALID;

    /* 普通会话必须重新验证容器口令；恢复会话已由恢复码根认证，
     * 允许空口令，但提供了口令时仍必须正确。 */
    if (password != NULL && password[0] != '\0') {
        rc = vty_vault_verify_user_password(v, password);
        if (rc != VTY_OK) return rc;
    } else if (!v->recovery_mode) {
        return VTY_E_INVALID;
    }

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (desc.deleted) {
        vty_mod_desc_clear(&desc);
        return VTY_E_POLICY;
    }
    if (memcmp(desc.uuid, v->modules[index].uuid, VTY_UUID_BYTES) != 0) {
        vty_mod_desc_clear(&desc);
        return VTY_E_CORRUPT;
    }
    memcpy(old_uuid, desc.uuid, VTY_UUID_BYTES);

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) { vty_mod_desc_clear(&desc); return rc; }
    old_kr = v->keyring;
    old_state = v->modules[index];
    old_flags = v->header.flags;

    rc = vty_repo_module_purge(v, index, old_uuid, &records, &files, &chunks);
    if (rc != VTY_OK) goto fail;

    do {
        vty_random(new_uuid, VTY_UUID_BYTES);
    } while (vty_mod_all_zero(new_uuid, VTY_UUID_BYTES));
    desc_init_deleted(&deleted_desc, new_uuid);
    rc = vty_mod_desc_store(v, index, &deleted_desc);
    if (rc != VTY_OK) goto fail;

    /* 销毁旧 MDEK：未启用模块必须存在 kind 3；已启用模块应当不存在。
     * 若存在则一并删除，确保任何残留副本都不再可解。 */
    new_kr = v->keyring;
    rc = vty_mod_keyring_find_mdek(&new_kr, old_uuid, check_key);
    if (rc == VTY_OK) {
        rc = vty_mod_keyring_remove_mdek(&new_kr, old_uuid);
        if (rc != VTY_OK) goto fail;
    } else if (!old_state.enabled) {
        /* 未启用状态缺失 MDEK 说明库已不一致 */
        rc = VTY_E_CORRUPT;
        goto fail;
    } else {
        rc = VTY_OK;
    }
    vty_secure_zero(check_key, sizeof(check_key));

    rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) goto fail;

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (i != index && v->modules[i].enabled) any_enabled = 1;
    }
    v->keyring = new_kr;
    v->header.flags = any_enabled
                          ? (uint16_t)(v->header.flags | VTY_FLAG_MODULE_M1)
                          : (uint16_t)(v->header.flags & ~VTY_FLAG_MODULE_M1);
    memset(&v->modules[index], 0, sizeof(v->modules[index]));
    memcpy(v->modules[index].uuid, new_uuid, VTY_UUID_BYTES);
    v->modules[index].deleted = 1u;

    /* 第一次写新代；第二次覆盖另一副本，移除仍含旧 MDEK 的低代副本。 */
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;

    /* 旧 MDEK 已销毁，记录密钥头不可解；补偿擦除只做纵深防御，
     * 失败不改变模块销毁结论。 */
    (void)vty_repo_maintain_pending_scrub(v, 4096u, NULL, NULL);

    vty_mod_desc_clear(&desc);
    vty_mod_desc_clear(&deleted_desc);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(old_uuid, sizeof(old_uuid));
    vty_secure_zero(new_uuid, sizeof(new_uuid));
    vty_secure_zero(check_key, sizeof(check_key));
    (void)records; (void)files; (void)chunks;
    return VTY_OK;

fail:
    (void)vty_store_restore(v->store, &cp);
    v->keyring = old_kr;
    v->header.flags = old_flags;
    v->modules[index] = old_state;
    vty_mod_desc_clear(&desc);
    vty_mod_desc_clear(&deleted_desc);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(old_uuid, sizeof(old_uuid));
    vty_secure_zero(new_uuid, sizeof(new_uuid));
    vty_secure_zero(check_key, sizeof(check_key));
    if (rc != VTY_OK && v->unlocked == 0) return rc;
    return rc;
}

