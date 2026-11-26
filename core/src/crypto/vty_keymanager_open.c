/*
 * vty_keymanager_open.c — 解锁、口令/恢复码核验与设备重封
 */

#include "vty_keymanager_internal.h"


static int slot_area_equal(const VtyMetaCopy *a, const VtyMetaCopy *b)
{
    size_t alen, blen;
    if (!a->valid || !b->valid) return 0;
    alen = vty_header_slots_len(&a->h);
    blen = vty_header_slots_len(&b->h);
    if (alen != blen) return 0;
    return memcmp(a->header_buf + VTY_HEADER_FIXED_BYTES,
                  b->header_buf + VTY_HEADER_FIXED_BYTES, alen) == 0;
}

/* PCR 门：先比对策略摘要，再要求 TPM 在 PCR 匹配下解封出同一 K_c。 */
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

/* 从一份已认证的副本装入会话；调用方已确认 body AEAD 成功。 */
static int adopt_copy(VtyVault *v, const VtyMetaCopy *c, const VtyKeyring *kr,
                      const uint8_t kc[VTY_KEY_BYTES], uint64_t file_size)
{
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    int rc;

    rc = vty_km_keyring_take_data_root(kr, c->h.vault_uuid, c->h.epoch, &loc, hash);
    if (rc != VTY_OK) return rc;
    if (loc.data_end > file_size) return VTY_E_CORRUPT;
    if (loc.root_node_id != 0u) {
        if (loc.root_offset < VTY_DATA_OFFSET ||
            loc.root_offset > loc.data_end ||
            loc.root_len > loc.data_end - loc.root_offset) {
            return VTY_E_CORRUPT;
        }
    }

    v->header = c->h;
    v->slot_count = c->slot_count;
    memcpy(v->slots, c->slots, sizeof(c->slots));
    v->keyring = *kr;
    v->data_root = loc;
    memcpy(v->data_root_hash, hash, VTY_HASH_BYTES);
    memcpy(v->kc, kc, VTY_KEY_BYTES);
    v->active_copy = c->index;
    v->unlocked = 1;
    return VTY_OK;
}

/* 非 static：发布构建需覆盖标准/keyfile 解锁主路径（wrapper 过薄） */
__declspec(noinline) int vty_vault_open_internal(const char *path,
                               const char *password,
                               const char *keyfile_path, VtyVault **out)
{
    VtyVault *v;
    uint8_t *meta = NULL;
    uint64_t file_size = 0;
    VtyMetaCopy copies[VTY_META_COPIES];
    uint8_t kc_cached[VTY_KEY_BYTES];
    uint8_t keyfile_digest[VTY_KEY_BYTES];
    int keyfile_loaded = 0;
    int keyfile_required = 0;
    int kc_cached_valid = 0;
    int last_slot_rc = VTY_E_KEY_INVALID;
    int any_slot_ok = 0;
    int slot_fail = 0;
    int pcr_pending = 0;
    int rc = VTY_OK;
    uint32_t ci;

    memset(keyfile_digest, 0, sizeof(keyfile_digest));

    if (path == NULL || password == NULL || out == NULL) return VTY_E_INVALID;
    if (password[0] == '\0') return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    /* 机器级预算先于本地熔断：服务未安装/不可达/预算耗尽一律 fail-closed，
     * 不允许通过本地状态或服务不可达绕过全机节流。 */
    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
        if (vty_lockout_begin_attempt() == VTY_E_LOCKED) return VTY_E_LOCKED;
    }

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    rc = vty_km_load_meta(path, &meta, &file_size, copies);
    if (rc != VTY_OK) goto fail;

    for (ci = 0; ci < VTY_META_COPIES; ci++) {
        uint8_t share_u[VTY_KEY_BYTES];
        uint8_t share_d[VTY_KEY_BYTES];
        uint8_t kc[VTY_KEY_BYTES];
        VtyKeyring kr;
        int u_idx, d_idx;
        int slot_rc;

        memset(share_u, 0, sizeof(share_u));
        memset(share_d, 0, sizeof(share_d));
        memset(&kr, 0, sizeof(kr));
        if (!copies[ci].valid) continue;

        v->header = copies[ci].h;
        v->slot_count = copies[ci].slot_count;
        memcpy(v->slots, copies[ci].slots, sizeof(copies[ci].slots));

        rc = vty_slot_policy_check(v->slots, v->slot_count, v->header.flags);
        if (rc != VTY_OK) goto fail;

        keyfile_required = (v->header.flags & VTY_FLAG_KEYFILE) != 0;
        if (keyfile_required) {
            if (keyfile_path == NULL) {
                rc = VTY_E_KEYFILE_REQUIRED;
                break;
            }
            if (!keyfile_loaded) {
                rc = vty_km_load_keyfile_digest(keyfile_path, keyfile_digest);
                if (rc != VTY_OK) break;
                keyfile_loaded = 1;
            }
        }

        u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
        d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
        if (u_idx < 0 || d_idx < 0) {
            rc = VTY_E_SLOT_MISSING;
            goto fail;
        }

        /* A/B 槽区相同时只做一次 KDF；否则同一口令会被迫连续
         * 计算两次 Argon2id，既慢又给离线猜测提供额外样本。 */
        if (ci > 0 && slot_area_equal(&copies[ci], &copies[ci - 1])) {
            if (kc_cached_valid) {
                memcpy(kc, kc_cached, VTY_KEY_BYTES);
                slot_rc = VTY_OK;
            } else {
                /* 相同槽区已失败过一次，重复 KDF 只会再失败并放大开销。 */
                slot_rc = last_slot_rc;
            }
        } else {
            slot_rc = vty_km_open_user_slot(&v->slots[u_idx], password,
                                      keyfile_required ? keyfile_digest : NULL,
                                      &v->header, (uint32_t)u_idx, share_u);
            if (slot_rc == VTY_OK) {
                slot_rc = vty_slot_open_device(&v->slots[d_idx], &v->header,
                                               (uint32_t)d_idx, share_d);
            }
            if (slot_rc == VTY_OK) {
                size_t i;
                for (i = 0; i < VTY_KEY_BYTES; i++) {
                    kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
                }
                memcpy(kc_cached, kc, VTY_KEY_BYTES);
                kc_cached_valid = 1;
            }
            vty_secure_zero(share_u, sizeof(share_u));
            vty_secure_zero(share_d, sizeof(share_d));
            last_slot_rc = slot_rc;
        }

        if (slot_rc != VTY_OK) {
            /* 结构完整的新代副本已经存在时，槽解包失败就是口令/设备根
             * 不匹配，不能降级去试更旧的副本——否则旧口令在轮换后仍可
             * 打开上一代文件，等于撤销失效。只有新代副本结构损坏或
             * body 认证失败时才回退。 */
            slot_fail++;
            rc = slot_rc;
            break;
        }
        any_slot_ok = 1;
        memcpy(v->kc, kc, VTY_KEY_BYTES);

        if ((v->header.flags & VTY_FLAG_PCR) != 0) {
            rc = check_pcr_gate(v);
            if (rc != VTY_OK) {
                /* 轮换提交在 PCR 重封后、原子替换前被杀：日志与当前文件代
                 * 严格匹配且平台状态未变时，推迟 PCR 门到会话建立后，
                 * 用口令解出的 K_c 重封；不匹配则维持 fail-closed。 */
                if (vty_vault_rotate_journal_match(v)) {
                    pcr_pending = 1;
                    rc = VTY_OK;
                } else {
                    /* 替换已完成但日志未删的残留：源代小于文件代，清掉。 */
                    if (vty_vault_rotate_journal_stale(v)) {
                        vty_vault_rotate_journal_clear(v);
                    }
                    goto fail;
                }
            }
        }

        rc = vty_km_open_body_copy(&copies[ci].h, copies[ci].digest, copies[ci].body,
                            copies[ci].body_len, kc, &kr);
        if (rc != VTY_OK) {
            vty_secure_zero(kc, sizeof(kc));
            continue;
        }

        rc = adopt_copy(v, &copies[ci], &kr, kc, file_size);
        vty_secure_zero(kc, sizeof(kc));
        if (rc != VTY_OK) goto fail;

        if (vty_rollback_enabled()) {
            rc = vty_rollback_check(v->header.vault_uuid, v->header.generation);
            if (rc != VTY_OK) goto fail;
            rc = vty_rollback_commit(v->header.vault_uuid, v->header.generation);
            if (rc != VTY_OK) goto fail;
        }
        /* 打开路径已把锚点推进到当前代，推迟窗口基线同步。 */
        v->anchor_floor_gen = v->header.generation;

        rc = vty_store_open(v->path, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &v->store);
        if (rc != VTY_OK) goto fail;

        v->mem_kib = v->slots[u_idx].m_cost;
        v->iters = v->slots[u_idx].t_cost;
        v->parallel = v->slots[u_idx].p_cost;
        if (keyfile_required) {
            memcpy(v->keyfile_digest, keyfile_digest, VTY_KEY_BYTES);
            v->keyfile_digest_set = 1;
        }
        v->unlocked = 1;
        rc = vty_module_table_load(v);
        if (rc != VTY_OK) goto fail;
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_reset();
        }
        (void)vty_machine_limiter_reset();
        if ((v->header.flags & VTY_FLAG_PCR) != 0) {
            if (pcr_pending) {
                /* 会话与会话密钥均已建立：用当前 K_c 重封后重新验证门。
                 * 重封失败时保持日志，下一次解锁继续尝试。 */
                rc = vty_vault_pcr_reseal(v);
                if (rc != VTY_OK) goto fail;
                rc = check_pcr_gate(v);
                if (rc != VTY_OK) goto fail;
            }
            /* 到这里日志已无待恢复语义（替换已完成或重封已完成）。 */
            vty_vault_rotate_journal_clear(v);
        }
        vty_free(meta, VTY_DATA_OFFSET);
        vty_secure_zero(kc_cached, sizeof(kc_cached));
        vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
        *out = v;
        return VTY_OK;
    }

    /* 只有“所有可解析副本都无法解包槽”才计入熔断；body 认证失败
     * 说明口令/设备根已正确，是文件损坏，不应把用户锁死。 */
    if (!any_slot_ok && slot_fail > 0) {
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_record_failure();
        }
        (void)vty_machine_limiter_record_failure();
    }
    if (rc == VTY_OK) rc = VTY_E_KEY_INVALID;

fail:
    if (meta != NULL) vty_free(meta, VTY_DATA_OFFSET);
    vty_secure_zero(kc_cached, sizeof(kc_cached));
    vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
    vty_vault_free(v);
    return rc;
}

int vty_vault_open(const char *path, const char *password, VtyVault **out)
{
    return vty_vault_open_internal(path, password, NULL, out);
}

int vty_vault_open_keyfile(const char *path, const char *password,
                           const char *keyfile_path, VtyVault **out)
{
    return vty_vault_open_internal(path, password, keyfile_path, out);
}

int vty_vault_open_recovery(const char *path, const char *recovery_text,
                            VtyVault **out)
{
    VtyVault *v;
    uint8_t *meta = NULL;
    uint64_t file_size = 0;
    VtyMetaCopy copies[VTY_META_COPIES];
    int rc;
    uint32_t ci;

    if (path == NULL || recovery_text == NULL || out == NULL) return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    /* 恢复码解锁同样是全机可猜解入口，必须先过机器预算再计算 Argon2id。 */
    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    rc = vty_km_load_meta(path, &meta, &file_size, copies);
    if (rc != VTY_OK) goto fail;

    for (ci = 0; ci < VTY_META_COPIES; ci++) {
        VtyKeyring rk;
        VtyKeyring body_kr;
        uint8_t kc[VTY_KEY_BYTES];
        int r_idx;

        memset(&rk, 0, sizeof(rk));
        memset(&body_kr, 0, sizeof(body_kr));
        memset(kc, 0, sizeof(kc));
        if (!copies[ci].valid) continue;

        v->header = copies[ci].h;
        v->slot_count = copies[ci].slot_count;
        memcpy(v->slots, copies[ci].slots, sizeof(copies[ci].slots));
        if ((v->header.flags & VTY_FLAG_RECOVERY) == 0) {
            rc = VTY_E_SLOT_MISSING;
            break;
        }
        r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
        if (r_idx < 0) {
            rc = VTY_E_SLOT_MISSING;
            break;
        }

        /* 新代副本存在时，恢复槽解包失败就是恢复码本身失效；
         * 降级去试旧副本会让轮换前的恢复码继续可用。 */
        rc = vty_recovery_slot_open(&v->slots[r_idx], recovery_text,
                                    &v->header, (uint32_t)r_idx, &rk,
                                    v->k_recovery);
        if (rc != VTY_OK) break;
        rc = vty_keyring_find(&rk, VTY_KEYKIND_KC, NULL, 0, kc);
        if (rc != VTY_OK) break;

        rc = vty_km_open_body_copy(&copies[ci].h, copies[ci].digest, copies[ci].body,
                            copies[ci].body_len, kc, &body_kr);
        if (rc != VTY_OK) {
            vty_secure_zero(kc, sizeof(kc));
            continue;
        }

        rc = adopt_copy(v, &copies[ci], &body_kr, kc, file_size);
        vty_secure_zero(kc, sizeof(kc));
        if (rc != VTY_OK) goto fail;

        /* 恢复码是显式逃生通道：允许打开较旧副本，并把锚点重设为
         * 该副本的代；否则被回滚的库会永久无法恢复。 */
        if (vty_rollback_enabled()) {
            rc = vty_rollback_reset_anchor(v->header.vault_uuid,
                                           v->header.generation);
            if (rc != VTY_OK) goto fail;
        }
        if (vty_lockout_enabled()) (void)vty_lockout_reset();
        rc = vty_store_open(v->path, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &v->store);
        if (rc != VTY_OK) goto fail;

        v->mem_kib = v->slots[r_idx].m_cost;
        v->iters = v->slots[r_idx].t_cost;
        v->parallel = v->slots[r_idx].p_cost;
        v->unlocked = 1;
        v->recovery_mode = 1;
        rc = vty_module_table_load(v);
        if (rc != VTY_OK) goto fail;
        (void)vty_machine_limiter_reset();
        vty_free(meta, VTY_DATA_OFFSET);
        *out = v;
        return VTY_OK;
    }

    /* 恢复码格式错误在 KDF 之前即被拒绝，不计入预算；格式合法但认证失败
     * （AEAD/密钥不符）属于真实猜解尝试，必须记账。 */
    if (rc == VTY_OK) rc = VTY_E_KEY_INVALID;
    if (rc == VTY_E_AEAD || rc == VTY_E_KEY_INVALID) {
        (void)vty_machine_limiter_record_failure();
    }

fail:
    if (meta != NULL) vty_free(meta, VTY_DATA_OFFSET);
    vty_vault_free(v);
    return rc;
}

/* 只验证 user 槽：恢复/换机场景设备根不可用时仍需确认当前口令。
 * AEAD 认证通过即证明口令正确，不依赖设备槽。 */
int vty_vault_verify_user_password(const VtyVault *v, const char *password)
{
    uint8_t share_u[VTY_KEY_BYTES];
    int u_idx, rc;

    if (v == NULL || password == NULL || password[0] == '\0') return VTY_E_INVALID;
    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    if (u_idx < 0) return VTY_E_SLOT_MISSING;
    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0 && !v->keyfile_digest_set) {
        return VTY_E_KEYFILE_REQUIRED;
    }
    /* 口令复核同样是猜解入口（轮换 Begin / 恢复码轮换）：必须服从统一的
     * 机器预算与失败退避，否则可绕过登录熔断无限触发 Argon2。 */
    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
        if (vty_lockout_begin_attempt() == VTY_E_LOCKED) return VTY_E_LOCKED;
    }
    memset(share_u, 0, sizeof(share_u));
    rc = vty_km_open_user_slot(&v->slots[u_idx], password,
                        (v->header.flags & VTY_FLAG_KEYFILE) != 0
                            ? v->keyfile_digest : NULL,
                        &v->header, (uint32_t)u_idx, share_u);
    vty_secure_zero(share_u, sizeof(share_u));
    if (rc == VTY_E_KEY_INVALID) {
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_record_failure();
        }
        (void)vty_machine_limiter_record_failure();
    } else if (rc == VTY_OK) {
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_reset();
        }
        (void)vty_machine_limiter_reset();
    }
    return rc;
}

/* 轮换补录：恢复会话未持有 keyfile 摘要时，用当前容器口令 + keyfile 验证
 * user 槽；认证通过后才把摘要写入会话缓存。失败路径不修改任何会话字段。 */
int vty_vault_attach_keyfile(VtyVault *v, const char *keyfile_path,
                             const char *password)
{
    uint8_t digest[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    int u_idx;
    int rc;

    if (v == NULL || keyfile_path == NULL || password == NULL ||
        password[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if ((v->header.flags & VTY_FLAG_KEYFILE) == 0) return VTY_E_POLICY;

    memset(digest, 0, sizeof(digest));
    rc = vty_km_load_keyfile_digest(keyfile_path, digest);
    if (rc != VTY_OK) {
        vty_secure_zero(digest, sizeof(digest));
        return rc;
    }

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    if (u_idx < 0) {
        vty_secure_zero(digest, sizeof(digest));
        return VTY_E_SLOT_MISSING;
    }
    if (vty_machine_limiter_check() != VTY_OK) {
        vty_secure_zero(digest, sizeof(digest));
        return VTY_E_LOCKED;
    }
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) {
            vty_secure_zero(digest, sizeof(digest));
            return VTY_E_LOCKED;
        }
        if (vty_lockout_begin_attempt() == VTY_E_LOCKED) {
            vty_secure_zero(digest, sizeof(digest));
            return VTY_E_LOCKED;
        }
    }

    memset(share_u, 0, sizeof(share_u));
    rc = vty_km_open_user_slot(&v->slots[u_idx], password, digest, &v->header,
                        (uint32_t)u_idx, share_u);
    vty_secure_zero(share_u, sizeof(share_u));
    if (rc != VTY_OK) {
        /* VKFL 合法但 keyfile 或口令不匹配：统一认证失败，不写会话。 */
        if (rc == VTY_E_KEY_INVALID) {
            if (vty_lockout_enabled()) {
                (void)vty_lockout_init();
                (void)vty_lockout_record_failure();
            }
            (void)vty_machine_limiter_record_failure();
        }
        vty_secure_zero(digest, sizeof(digest));
        return rc;
    }
    if (vty_lockout_enabled()) {
        (void)vty_lockout_init();
        (void)vty_lockout_reset();
    }
    (void)vty_machine_limiter_reset();

    memcpy(v->keyfile_digest, digest, sizeof(digest));
    v->keyfile_digest_set = 1;
    vty_secure_zero(digest, sizeof(digest));
    return VTY_OK;
}

int vty_vault_verify_recovery(const VtyVault *v, const char *recovery_text)
{
    VtyKeyring rk;
    uint8_t kc[VTY_KEY_BYTES];
    int r_idx, rc;

    if (v == NULL || recovery_text == NULL || recovery_text[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if ((v->header.flags & VTY_FLAG_RECOVERY) == 0) return VTY_E_SLOT_MISSING;
    r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (r_idx < 0) return VTY_E_SLOT_MISSING;

    memset(&rk, 0, sizeof(rk));
    memset(kc, 0, sizeof(kc));
    rc = vty_recovery_slot_open(&v->slots[r_idx], recovery_text,
                                &v->header, (uint32_t)r_idx, &rk, NULL);
    if (rc == VTY_OK) {
        rc = vty_keyring_find(&rk, VTY_KEYKIND_KC, NULL, 0, kc);
    }
    if (rc == VTY_OK &&
        vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_KEY_INVALID;
    }
    vty_secure_zero(&rk, sizeof(rk));
    vty_secure_zero(kc, sizeof(kc));
    return rc;
}

int vty_vault_pcr_info(const VtyVault *v,
                       uint32_t *out_enabled, uint32_t *out_select)
{
    int p_idx;

    if (v == NULL || out_enabled == NULL || out_select == NULL) {
        return VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;

    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) {
        /* 标志与槽必须一致：声明 PCR 却没有槽属于结构损坏。 */
        if ((v->header.flags & VTY_FLAG_PCR) != 0) return VTY_E_CORRUPT;
        *out_enabled = 0;
        *out_select = 0;
        return VTY_OK;
    }
    if ((v->header.flags & VTY_FLAG_PCR) == 0) return VTY_E_CORRUPT;

    *out_enabled = 1;
    *out_select = v->slots[p_idx].pcr_select;
    return VTY_OK;
}

int vty_vault_rotate_password(VtyVault *v, const char *new_password)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;
    size_t i;

    if (v == NULL || new_password == NULL || new_password[0] == '\0') return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;

    /* epoch 是数据代：口令轮换不改变记录、名称、分片与目录的派生参数，
     * 因此绝不能递增。恢复码是独立凭据，本函数不再重封恢复槽。 */
    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }

    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0 && !v->keyfile_digest_set) {
        vty_secure_zero(share_u, sizeof(share_u));
        vty_secure_zero(share_d, sizeof(share_d));
        return VTY_E_KEYFILE_REQUIRED;
    }
    rc = vty_km_seal_user_slot(&v->slots[u_idx], VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, new_password,
                        (v->header.flags & VTY_FLAG_KEYFILE) != 0
                            ? v->keyfile_digest : NULL,
                        share_u, &v->header, (uint32_t)u_idx,
                        v->mem_kib, v->iters, v->parallel);
    if (rc == VTY_OK) {
        rc = vty_slot_seal_device(&v->slots[d_idx], VTY_SLOT_FLAG_REQUIRED,
                                  share_d, &v->header, (uint32_t)d_idx);
    }
    if (rc == VTY_OK) rc = vty_vault_save(v);

    if (rc != VTY_OK) {
        /* 轮换中途失败时内存槽位可能已与磁盘不一致；继续允许保存
         * 会把半套槽位写盘彻底毁库，强制回到锁定态。 */
        v->unlocked = 0;
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

int vty_vault_verify_password(VtyVault *v, const char *password)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t kc[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;

    if (v == NULL || password == NULL || password[0] == '\0') return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;
    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0 && !v->keyfile_digest_set) {
        return VTY_E_KEYFILE_REQUIRED;
    }

    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    rc = vty_km_open_user_slot(&v->slots[u_idx], password,
                        (v->header.flags & VTY_FLAG_KEYFILE) != 0
                            ? v->keyfile_digest : NULL,
                        &v->header, (uint32_t)u_idx, share_u);
    if (rc == VTY_OK) {
        rc = vty_slot_open_device(&v->slots[d_idx], &v->header,
                                  (uint32_t)d_idx, share_d);
    }
    if (rc == VTY_OK) {
        size_t i;
        for (i = 0; i < VTY_KEY_BYTES; i++) kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
        if (vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(kc, sizeof(kc));
    return rc;
}
