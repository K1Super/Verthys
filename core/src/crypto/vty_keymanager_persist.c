/*
 * vty_keymanager_persist.c — 元数据保存与批量提交
 */

#include "vty_keymanager_internal.h"


static int save_internal(VtyVault *v, int commit_store)
{
    uint8_t *copy = NULL;
    size_t body_len = 0;
    uint32_t target;
    uint8_t *readback = NULL;
    VtyMetaCopy check;
    VtyKeyring kr;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (v->path[0] == '\0') return VTY_E_INVALID;
    if (v->header.generation == UINT64_MAX) return VTY_E_RESOURCE;

    /* 先提交数据区（flush 追加段并生成新 DataRoot），再写元数据；
     * 反序会让元数据引用未落盘的段。模块事务在调用 save_meta 前
     * 已单独提交，避免同一逻辑提交重复生成目录根。 */
    if (commit_store && v->store != NULL) {
        VtyDataRootLocator loc;
        uint8_t hash[VTY_HASH_BYTES];
        rc = vty_store_commit(v->store, &loc, hash);
        if (rc != VTY_OK) return rc;
        v->data_root = loc;
        memcpy(v->data_root_hash, hash, VTY_HASH_BYTES);
    }

    rc = vty_km_keyring_set_data_root(&v->keyring, v->data_root_hash, &v->data_root);
    if (rc != VTY_OK) return rc;

    v->header.generation++;
    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    readback = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL || readback == NULL) {
        rc = VTY_E_RESOURCE;
        goto fail;
    }
    rc = vty_km_build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;

    target = v->active_copy ^ 1u;
    rc = vty_km_write_range_locked(v->path, (uint64_t)target * VTY_META_COPY_BYTES,
                            copy, VTY_META_COPY_BYTES);
    if (rc != VTY_OK) goto fail;

    /* 回读并认证非活动副本：只有确认 K_c 能解开新 body，才允许
     * 推进回退锚点；否则“文件已新、锚点未推进”会留下静默窗口。 */
    rc = vty_km_read_range(v->path, (uint64_t)target * VTY_META_COPY_BYTES,
                    readback, VTY_META_COPY_BYTES, NULL);
    if (rc != VTY_OK) goto fail;
    memset(&check, 0, sizeof(check));
    rc = vty_km_parse_meta_copy(readback, target, &check);
    if (rc != VTY_OK) goto fail;
    if (check.h.generation != v->header.generation) {
        rc = VTY_E_CORRUPT;
        goto fail;
    }
    memset(&kr, 0, sizeof(kr));
    rc = vty_km_open_body_copy(&check.h, check.digest, check.body, check.body_len,
                        v->kc, &kr);
    if (rc != VTY_OK) goto fail;

    /* 轮换临时库构建期间不推进锚点：提交前的新库代可能低于源库锚点，
     * 提前推进会让源库在回滚路径上被锚点拒绝。 */
    if (!v->no_rollback_anchor) {
        uint64_t now_ms = (uint64_t)GetTickCount64();
        int commit_anchor = 1;

        /* 批量导入会话中只在越过硬上限（代数或时长）时提交；
         * 上限编译进本层，调用方无法放大窗口。 */
        if (v->defer_anchor) {
            uint64_t lag = v->header.generation - v->anchor_floor_gen;
            uint64_t elapsed = now_ms - v->anchor_defer_since_ms;
            commit_anchor = (lag >= (uint64_t)VTY_ANCHOR_DEFER_MAX_GENS ||
                             elapsed >= (uint64_t)VTY_ANCHOR_DEFER_MAX_MS) ? 1 : 0;
        }
        if (commit_anchor) {
            if (vty_rollback_enabled()) {
                rc = vty_rollback_commit(v->header.vault_uuid,
                                         v->header.generation);
                if (rc != VTY_OK) goto fail;
            }
            v->anchor_floor_gen = v->header.generation;
            if (v->defer_anchor) v->anchor_defer_since_ms = now_ms;
        }
    }

    /* 回读副本是本次提交的权威头：把长度/槽数/Keyring 长度同步回会话，
     * 避免后续 PCR 开关等操作沿用上一次保存的旧预算。 */
    v->header.header_len = check.h.header_len;
    v->header.slot_count = check.h.slot_count;
    v->header.keyring_len = check.h.keyring_len;
    v->active_copy = target;
    vty_free(copy, VTY_META_COPY_BYTES);
    vty_free(readback, VTY_META_COPY_BYTES);
    vty_secure_zero(&kr, sizeof(kr));
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    if (readback != NULL) vty_free(readback, VTY_META_COPY_BYTES);
    /* 磁盘状态不确定或锚点未推进：锁定会话，调用方重新打开以实际
     * 落盘内容为准。 */
    v->unlocked = 0;
    return rc;
}

int vty_vault_commit_store(VtyVault *v)
{
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    int rc;

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    rc = vty_store_commit(v->store, &loc, hash);
    if (rc != VTY_OK) return rc;
    v->data_root = loc;
    memcpy(v->data_root_hash, hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_vault_verify_persist(const VtyVault *v, VtyPersistCheck *out)
{
    int rc;

    if (v == NULL || out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    if (!v->unlocked || v->store == NULL) return VTY_E_POLICY;
    out->header_magic = v->header.magic;
    out->header_version = v->header.version_major;
    rc = vty_store_verify_data_root(v->store, &v->data_root,
                                    v->data_root_hash, &out->file_size,
                                    &out->mtime_ms);
    return rc;
}

int vty_vault_save(VtyVault *v)
{
    return save_internal(v, 1);
}

int vty_vault_save_meta(VtyVault *v)
{
    return save_internal(v, 0);
}

int vty_vault_bulk_active(const VtyVault *v)
{
    return (v != NULL && v->unlocked && v->defer_anchor) ? 1 : 0;
}

int vty_vault_bulk_begin(VtyVault *v)
{
    int rc;

    if (v == NULL || !v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending || v->no_rollback_anchor) return VTY_E_POLICY;
    if (v->defer_anchor) return VTY_OK;

    /* 先提交当前锚点：窗口不得覆盖导入开始前的任何写入。 */
    if (vty_rollback_enabled()) {
        rc = vty_rollback_commit(v->header.vault_uuid, v->header.generation);
        if (rc != VTY_OK) return rc;
    }
    v->defer_anchor = 1;
    v->anchor_floor_gen = v->header.generation;
    v->anchor_defer_since_ms = (uint64_t)GetTickCount64();
    return VTY_OK;
}

int vty_vault_bulk_commit(VtyVault *v)
{
    int rc;

    if (v == NULL || !v->unlocked) return VTY_E_POLICY;
    if (!v->defer_anchor) return VTY_OK;

    if (vty_rollback_enabled() && !v->no_rollback_anchor) {
        rc = vty_rollback_commit(v->header.vault_uuid, v->header.generation);
        if (rc != VTY_OK) {
            /* 提交失败不得继续接受写入：清除会话并锁定，由下次解锁
             * 检查容器代并按“容器代 >= 锚点”补推进。 */
            v->defer_anchor = 0;
            v->unlocked = 0;
            return rc;
        }
    }
    v->defer_anchor = 0;
    v->anchor_floor_gen = v->header.generation;
    return VTY_OK;
}

int vty_vault_bulk_flush(VtyVault *v)
{
    int rc;

    if (v == NULL || !v->unlocked) return VTY_E_POLICY;
    if (!v->defer_anchor) return VTY_OK;
    if (v->anchor_floor_gen != v->header.generation) {
        if (vty_rollback_enabled() && !v->no_rollback_anchor) {
            rc = vty_rollback_commit(v->header.vault_uuid,
                                     v->header.generation);
            if (rc != VTY_OK) {
                v->defer_anchor = 0;
                v->unlocked = 0;
                return rc;
            }
        }
        v->anchor_floor_gen = v->header.generation;
    }
    v->anchor_defer_since_ms = (uint64_t)GetTickCount64();
    return VTY_OK;
}
