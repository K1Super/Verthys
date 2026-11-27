/*
 * vty_keymanager_create.c — 库创建、恢复码重建与压缩克隆
 */

#include "vty_keymanager_internal.h"


static int create_meta_file(const char *path, const uint8_t copy[VTY_META_COPY_BYTES])
{
    wchar_t *wpath;
    HANDLE h;
    uint8_t *file;
    DWORD written = 0;
    int rc = VTY_OK;

    if (path == NULL || copy == NULL) return VTY_E_INVALID;
    file = (uint8_t *)vty_alloc(VTY_DATA_OFFSET);
    if (file == NULL) return VTY_E_RESOURCE;
    memcpy(file, copy, VTY_META_COPY_BYTES);
    memcpy(file + VTY_META_COPY_BYTES, copy, VTY_META_COPY_BYTES);

    wpath = vty_km_utf8_to_wide(path);
    if (wpath == NULL) {
        vty_free(file, VTY_DATA_OFFSET);
        return VTY_E_INVALID;
    }
    h = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) {
        vty_free(file, VTY_DATA_OFFSET);
        return VTY_E_IO;
    }
    if (!WriteFile(h, file, (DWORD)VTY_DATA_OFFSET, &written, NULL) ||
        written != (DWORD)VTY_DATA_OFFSET || !FlushFileBuffers(h)) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    vty_free(file, VTY_DATA_OFFSET);
    if (rc != VTY_OK) {
        wchar_t *w = vty_km_utf8_to_wide(path);
        if (w != NULL) {
            DeleteFileW(w);
            free(w);
        }
    }
    return rc;
}

static int add_module_entries(VtyKeyring *kr)
{
    uint32_t i;
    uint8_t count = kr->count;

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        VtyKeyEntry *e;
        if (count >= VTY_KEYRING_MAX_ENTRIES) return VTY_E_INVALID;
        e = &kr->entries[count];
        memset(e, 0, sizeof(*e));
        e->kind = VTY_KEYKIND_MDEK;
        e->id_len = VTY_UUID_BYTES;
        vty_random(e->id, VTY_UUID_BYTES);
        vty_random(e->key, VTY_KEY_BYTES);
        count++;
    }
    kr->count = count;
    return VTY_OK;
}

/* 非 static：发布构建需以外部符号哈希覆盖创建/解锁主路径；
 * 公开 wrapper 仅 16–49 字节，单独哈希无保护意义。本符号不导出
 *（verthys.def 白名单外），外部不可达。noinline 是"被哈希代码体 =
 * 实际执行代码体"的语义前提。 */
__declspec(noinline) int vty_vault_create_internal(const char *path,
                                 const char *password,
                                 uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                                 uint32_t pcr_select,
                                 const uint8_t *keyfile_blob, size_t keyfile_len,
                                 VtyVault **out,
                                 char *recovery_text, size_t recovery_cap)
{
    VtyVault *v;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t code[VTY_RECOVERY_CODE_BYTES] = {0};
    uint8_t keyfile_secret[VTY_KEYFILE_SECRET_BYTES];
    uint8_t keyfile_digest[VTY_KEY_BYTES];
    const uint8_t *kdf_keyfile = NULL;
    uint8_t *copy = NULL;
    size_t body_len = 0;
    VtySlot *u_slot;
    VtySlot *d_slot;
    VtySlot *r_slot;
    int pcr_key_created = 0;
    int rc;

    memset(keyfile_secret, 0, sizeof(keyfile_secret));
    memset(keyfile_digest, 0, sizeof(keyfile_digest));
    if (path == NULL || password == NULL || out == NULL) return VTY_E_INVALID;
    if (keyfile_blob == NULL && keyfile_len != 0) return VTY_E_INVALID;
    if (keyfile_blob != NULL && keyfile_len != VTY_KEYFILE_BLOB_BYTES) {
        return VTY_E_KEYFILE_INVALID;
    }
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
    if (keyfile_blob != NULL) {
        rc = vty_keyfile_parse(keyfile_blob, keyfile_len, keyfile_secret);
        if (rc != VTY_OK) return rc;
        rc = vty_keyfile_digest(keyfile_secret, keyfile_digest);
        if (rc != VTY_OK) return rc;
        kdf_keyfile = keyfile_digest;
    }
    rc = vty_device_root_init();
    if (rc != VTY_OK) return rc;

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    v->mem_kib = mem_kib;
    v->iters = iters;
    v->parallel = parallel;
    v->header.magic = VTY_MAGIC;
    v->header.version_major = VTY_VERSION_MAJOR;
    v->header.version_minor = VTY_VERSION_MINOR;
    /* 模块 MDEK 只是载体；未启用模块策略前不置位，避免把“有 MDEK”
     * 误当成“模块隔离已交付”。 */
    v->header.flags = VTY_FLAG_RECOVERY;
    if (pcr_select != 0) v->header.flags |= VTY_FLAG_PCR;
    if (kdf_keyfile != NULL) v->header.flags |= VTY_FLAG_KEYFILE;
    v->header.epoch = 1;
    v->header.generation = 1;
    vty_random(v->header.vault_uuid, VTY_UUID_BYTES);
    vty_random(v->kc, VTY_KEY_BYTES);

    memset(&v->keyring, 0, sizeof(v->keyring));
    v->keyring.count = 1;
    v->keyring.entries[0].kind = VTY_KEYKIND_KC;
    v->keyring.entries[0].id_len = 0;
    memcpy(v->keyring.entries[0].key, v->kc, VTY_KEY_BYTES);
    rc = add_module_entries(&v->keyring);
    if (rc != VTY_OK) goto fail;

    memset(&v->data_root, 0, sizeof(v->data_root));
    rc = vty_store_empty_locator(v->header.vault_uuid, v->header.epoch,
                                 &v->data_root, v->data_root_hash);
    if (rc != VTY_OK) goto fail;
    rc = vty_km_keyring_set_data_root(&v->keyring, v->data_root_hash, &v->data_root);
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

    rc = vty_km_seal_user_slot(u_slot, VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, password, kdf_keyfile,
                        share_u, &v->header, 0, mem_kib, iters, parallel);
    if (rc != VTY_OK) goto fail;

    rc = vty_slot_seal_device(d_slot, VTY_SLOT_FLAG_REQUIRED, share_d,
                              &v->header, 1);
    if (rc != VTY_OK) goto fail;

    rc = vty_recovery_generate(code, recovery_text, recovery_cap);
    if (rc != VTY_OK) goto fail;
    rc = vty_recovery_slot_seal(r_slot, v->kc, code, &v->header, 2,
                                mem_kib, iters, parallel, NULL);
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

    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL) { rc = VTY_E_RESOURCE; goto fail; }
    rc = vty_km_build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;
    /* 回填权威头字段（header_len/keyring_len），避免会话内后续保存
     * 用创建前的零值参与预算计算。 */
    rc = vty_header_parse(copy, VTY_META_COPY_BYTES, &v->header);
    if (rc != VTY_OK) goto fail;
    rc = create_meta_file(path, copy);
    if (rc != VTY_OK) goto fail;

    /* 创建后即建立数据区会话：空 DataRoot 也要能被 store 校验，
     * 否则第一次写入前无法复用同一提交路径。 */
    rc = vty_store_open(v->path, v->kc, v->header.vault_uuid, v->header.epoch,
                        &v->data_root, v->data_root_hash, &v->store);
    if (rc != VTY_OK) goto fail;

    v->active_copy = 0;
    v->unlocked = 1;

    /* 模块表必须在创建时落盘：模块 UUID 不能依赖 Keyring 条目顺序，
     * 且启用后 kind 3 条目会被删除。先提交数据区，再写一次元数据。 */
    rc = vty_module_table_init(v);
    if (rc == VTY_OK) rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;

    if (kdf_keyfile != NULL) {
        memcpy(v->keyfile_digest, kdf_keyfile, VTY_KEY_BYTES);
        v->keyfile_digest_set = 1;
    }
    vty_free(copy, VTY_META_COPY_BYTES);
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(keyfile_secret, sizeof(keyfile_secret));
    vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
    *out = v;
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    if (pcr_key_created) {
        (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
    }
    /* 创建中途失败不得留下不可打开的半成品库。必须先释放会话（关闭
     * store 句柄）再删除文件：Windows 上以共享读写打开的句柄会让
     * DeleteFileW 失败，既留下孤儿文件、又把真实错误改写成 E_IO
     * （worker 再把 IO 统一成 AUTH，上层就看不到根因）。删除失败只
     * 记为残留，不覆盖原始错误码。 */
    {
        wchar_t *w = NULL;
        if (v != NULL && v->path[0] != '\0') w = vty_km_utf8_to_wide(v->path);
        vty_vault_free(v);
        if (w != NULL) {
            (void)DeleteFileW(w);
            free(w);
        }
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(code, sizeof(code));
    vty_secure_zero(keyfile_secret, sizeof(keyfile_secret));
    vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
    return rc;
}

int vty_vault_create_ex(const char *path, const char *password,
                        uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                        VtyVault **out,
                        char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_internal(path, password, mem_kib, iters, parallel, 0,
                                 NULL, 0, out, recovery_text, recovery_cap);
}

int vty_vault_create_keyfile(const char *path, const char *password,
                             const uint8_t *keyfile_blob, size_t keyfile_len,
                             VtyVault **out,
                             char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_internal(path, password,
                                 VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                 0, keyfile_blob, keyfile_len,
                                 out, recovery_text, recovery_cap);
}

int vty_vault_create_keyfile_file(const char *path, const char *password,
                                  const char *keyfile_path, VtyVault **out,
                                  char *recovery_text, size_t recovery_cap)
{
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    int rc;

    memset(blob, 0, sizeof(blob));
    if (keyfile_path == NULL) return VTY_E_KEYFILE_REQUIRED;
    rc = vty_keyfile_generate(blob);
    if (rc == VTY_OK) {
        rc = vty_km_write_keyfile_file(keyfile_path, blob, sizeof(blob));
    }
    if (rc == VTY_OK) {
        rc = vty_vault_create_internal(path, password,
                                   VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                   0, blob, sizeof(blob), out,
                                   recovery_text, recovery_cap);
        /* 库没有建成时不得留下一个“孤儿 keyfile”：用户会误以为它
         * 对应某个库。 */
        if (rc != VTY_OK) vty_km_delete_file_utf8(keyfile_path);
    }
    vty_secure_zero(blob, sizeof(blob));
    return rc;
}

int vty_vault_create_pcr(const char *path, const char *password,
                         uint32_t pcr_select,
                         VtyVault **out,
                         char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_internal(path, password,
                                 VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                 pcr_select, NULL, 0,
                                 out, recovery_text, recovery_cap);
}

int vty_vault_create(const char *path, const char *password,
                     VtyVault **out,
                     char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_ex(path, password,
                               VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                               out, recovery_text, recovery_cap);
}

static int bytes_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* 轮换：以恢复会话的 K_recovery 与源库槽参数重建一个新库文件。
 * 只用于全库 DEK 轮换；调用方负责生命周期与原子替换。 */
int vty_vault_create_from_kc(const VtyVault *src, const char *path,
                             const char *password,
                             const uint8_t kc[VTY_KEY_BYTES],
                             uint16_t flags,
                             const uint8_t *keyfile_digest_or_null,
                             VtyVault **out)
{
    VtyVault *v = NULL;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t digest[VTY_KEY_BYTES];
    uint8_t *copy = NULL;
    size_t body_len = 0;
    int u_idx, r_idx;
    uint32_t mem_kib, iters, parallel;
    size_t i;
    int file_created = 0;
    int rc;

    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(digest, 0, sizeof(digest));
    if (out != NULL) *out = NULL;
    if (src == NULL || path == NULL || password == NULL || kc == NULL ||
        out == NULL) {
        return VTY_E_INVALID;
    }
    if (!src->unlocked || !src->recovery_mode) return VTY_E_POLICY;
    if (path[0] == '\0' || password[0] == '\0') return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;
    if ((flags & (uint16_t)~VTY_FLAG_KNOWN_MASK) != 0) return VTY_E_INVALID;
    if ((flags & VTY_FLAG_RECOVERY) == 0) return VTY_E_INVALID;
    if ((flags & VTY_FLAG_KEYFILE) != 0 && keyfile_digest_or_null == NULL) {
        return VTY_E_KEYFILE_REQUIRED;
    }
    if ((flags & VTY_FLAG_KEYFILE) == 0 && keyfile_digest_or_null != NULL) {
        return VTY_E_INVALID;
    }
    /* 没有恢复 KEK 就无法把同一恢复码延续到新库；降级为“恢复码失效”的
     * 换库不在本阶段允许范围内。 */
    if (bytes_all_zero(src->k_recovery, VTY_KEY_BYTES)) return VTY_E_POLICY;
    if (src->header.epoch == UINT64_MAX ||
        src->header.generation == UINT64_MAX) {
        return VTY_E_RESOURCE;
    }

    u_idx = vty_slot_find(src->slots, src->slot_count, VTY_SLOT_USER_PASSWORD);
    r_idx = vty_slot_find(src->slots, src->slot_count, VTY_SLOT_RECOVERY);
    if (u_idx < 0 || r_idx < 0) return VTY_E_SLOT_MISSING;

    /* 用户槽 KDF 参数必须沿用源库实际槽值，而不是恢复槽参数：两者
     * 可能不同，沿用错误参数会让新库只能用另一个代价打开。 */
    mem_kib = src->slots[u_idx].m_cost;
    iters = src->slots[u_idx].t_cost;
    parallel = src->slots[u_idx].p_cost;
    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;
    if (keyfile_digest_or_null != NULL) {
        memcpy(digest, keyfile_digest_or_null, VTY_KEY_BYTES);
    }

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);
    v->mem_kib = mem_kib;
    v->iters = iters;
    v->parallel = parallel;

    v->header.magic = VTY_MAGIC;
    v->header.version_major = VTY_VERSION_MAJOR;
    v->header.version_minor = VTY_VERSION_MINOR;
    v->header.flags = flags;
    v->header.epoch = src->header.epoch + 1u;
    v->header.generation = src->header.generation + 1u;
    memcpy(v->header.vault_uuid, src->header.vault_uuid, VTY_UUID_BYTES);
    memcpy(v->kc, kc, VTY_KEY_BYTES);

    memset(&v->keyring, 0, sizeof(v->keyring));
    v->keyring.count = 1;
    v->keyring.entries[0].kind = VTY_KEYKIND_KC;
    v->keyring.entries[0].id_len = 0;
    memcpy(v->keyring.entries[0].key, v->kc, VTY_KEY_BYTES);
    rc = add_module_entries(&v->keyring);
    if (rc != VTY_OK) goto fail;

    memset(&v->data_root, 0, sizeof(v->data_root));
    rc = vty_store_empty_locator(v->header.vault_uuid, v->header.epoch,
                                 &v->data_root, v->data_root_hash);
    if (rc != VTY_OK) goto fail;
    rc = vty_km_keyring_set_data_root(&v->keyring, v->data_root_hash, &v->data_root);
    if (rc != VTY_OK) goto fail;

    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }

    v->slot_count = 3;
    rc = vty_km_seal_user_slot(&v->slots[0], VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, password,
                        keyfile_digest_or_null != NULL ? digest : NULL,
                        share_u, &v->header, 0, mem_kib, iters, parallel);
    if (rc != VTY_OK) goto fail;
    rc = vty_slot_seal_device(&v->slots[1], VTY_SLOT_FLAG_REQUIRED, share_d,
                              &v->header, 1);
    if (rc != VTY_OK) goto fail;

    /* 恢复槽复用源槽的 salt 与 KDF 参数（KEK 才能与旧恢复码一致），
     * 换新 nonce 并用 KEK 包裹新 K_c。 */
    v->slots[2] = src->slots[r_idx];
    rc = vty_recovery_slot_reseal(&v->slots[2], v->kc, src->k_recovery,
                                  &v->header, 2u);
    if (rc != VTY_OK) goto fail;

    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL) { rc = VTY_E_RESOURCE; goto fail; }
    rc = vty_km_build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;
    rc = vty_header_parse(copy, VTY_META_COPY_BYTES, &v->header);
    if (rc != VTY_OK) goto fail;
    rc = create_meta_file(path, copy);
    if (rc != VTY_OK) goto fail;
    file_created = 1;

    /* 从这里开始写入的都是临时库：禁止推进回退锚点，直到提交完成。 */
    v->no_rollback_anchor = 1;

    rc = vty_store_open(v->path, v->kc, v->header.vault_uuid, v->header.epoch,
                        &v->data_root, v->data_root_hash, &v->store);
    if (rc != VTY_OK) goto fail;
    v->active_copy = 0;
    v->unlocked = 1;

    rc = vty_module_table_init(v);
    if (rc == VTY_OK) rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;

    if (keyfile_digest_or_null != NULL) {
        memcpy(v->keyfile_digest, digest, VTY_KEY_BYTES);
        v->keyfile_digest_set = 1;
    }
    vty_free(copy, VTY_META_COPY_BYTES);
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(digest, sizeof(digest));
    *out = v;
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    /* 先释放会话（关闭数据区句柄），再删除半成品文件；反序会因句柄
     * 仍打开而删除失败。只有本函数独占创建的文件才允许删除——
     * CreateFile(CREATE_NEW) 因目标被并发抢占而失败时不得删他人文件。 */
    vty_vault_free(v);
    if (file_created) {
        wchar_t *w = vty_km_utf8_to_wide(path);
        if (w != NULL) {
            (void)DeleteFileW(w);
            free(w);
        }
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

/* 压缩克隆：同一 K_c/epoch/uuid/slots/keyring，仅 generation+1 与空数据区。
 * 不重新派生 K_c，也不重封槽，因此不需要口令与设备根。 */
int vty_vault_clone_for_compaction(const VtyVault *src, const char *path,
                                   VtyVault **out)
{
    VtyVault *v = NULL;
    uint8_t *copy = NULL;
    size_t body_len = 0;
    int file_created = 0;
    int rc;

    if (out != NULL) *out = NULL;
    if (src == NULL || path == NULL || out == NULL) return VTY_E_INVALID;
    if (!src->unlocked || src->store == NULL) return VTY_E_POLICY;
    if (src->rotate_pending) return VTY_E_ROTATE_PENDING;
    /* 批量导入窗口内锚点被推迟，源库不应同时做全量压缩。 */
    if (src->defer_anchor) return VTY_E_POLICY;
    if (path[0] == '\0' ||
        strlen(path) >= sizeof(((VtyVault *)0)->path)) {
        return VTY_E_INVALID;
    }
    if (src->slot_count == 0u || src->slot_count > VTY_MAX_SLOTS) {
        return VTY_E_CORRUPT;
    }
    if (src->header.epoch == UINT64_MAX ||
        src->header.generation == UINT64_MAX) {
        return VTY_E_RESOURCE;
    }

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault_compact");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);
    v->mem_kib = src->mem_kib;
    v->iters = src->iters;
    v->parallel = src->parallel;

    v->header = src->header;
    v->header.generation = src->header.generation + 1u;
    memcpy(v->kc, src->kc, VTY_KEY_BYTES);
    v->slot_count = src->slot_count;
    memcpy(v->slots, src->slots, sizeof(VtySlot) * src->slot_count);
    v->keyring = src->keyring;
    v->recovery_mode = src->recovery_mode;
    memcpy(v->k_recovery, src->k_recovery, VTY_KEY_BYTES);
    memcpy(v->keyfile_digest, src->keyfile_digest, VTY_KEY_BYTES);
    v->keyfile_digest_set = src->keyfile_digest_set;
    memcpy(v->modules, src->modules, sizeof(v->modules));

    memset(&v->data_root, 0, sizeof(v->data_root));
    rc = vty_store_empty_locator(v->header.vault_uuid, v->header.epoch,
                                 &v->data_root, v->data_root_hash);
    if (rc != VTY_OK) goto fail;
    rc = vty_km_keyring_set_data_root(&v->keyring, v->data_root_hash,
                               &v->data_root);
    if (rc != VTY_OK) goto fail;

    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL) { rc = VTY_E_RESOURCE; goto fail; }
    rc = vty_km_build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;
    rc = vty_header_parse(copy, VTY_META_COPY_BYTES, &v->header);
    if (rc != VTY_OK) goto fail;
    rc = create_meta_file(path, copy);
    if (rc != VTY_OK) goto fail;
    file_created = 1;

    /* 临时库构建期间禁止推进回退锚点；提交替换后再由调用方推进。 */
    v->no_rollback_anchor = 1;
    rc = vty_store_open(v->path, v->kc, v->header.vault_uuid,
                        v->header.epoch, &v->data_root,
                        v->data_root_hash, &v->store);
    if (rc != VTY_OK) goto fail;
    v->active_copy = 0;
    v->unlocked = 1;

    vty_free(copy, VTY_META_COPY_BYTES);
    *out = v;
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    vty_vault_free(v);
    if (file_created) {
        wchar_t *w = vty_km_utf8_to_wide(path);
        if (w != NULL) {
            (void)DeleteFileW(w);
            free(w);
        }
    }
    return rc;
}
