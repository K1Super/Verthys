/*
 * vty_repo_scrub.c — 删除、墓碑与密钥擦除补偿
 */

#include "vty_repo_internal.h"

#define REPO_SCRUB_CHAIN_MAX 64u
#define VTY_MAINT_LEGACY_TAG "legacy-scrub-v1"


static int repo_leaf_key(VtyVault *v, const VtyRepoLeaf *leaf,
                         uint8_t mdek[VTY_KEY_BYTES])
{
    return vty_vault_module_key(v, leaf->module_uuid, mdek);
}

/* 模块 UUID 已不在模块表中：模块销毁已移除 MDEK，密钥材料不可恢复。 */
static int repo_leaf_module_gone(const VtyVault *v, const VtyRepoLeaf *leaf)
{
    uint32_t i;

    if (memcmp(leaf->module_uuid, vty_system_module_uuid,
               VTY_UUID_BYTES) == 0) {
        return 0;
    }
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (memcmp(leaf->module_uuid, v->modules[i].uuid,
                   VTY_UUID_BYTES) == 0) {
            return 0;
        }
    }
    return 1;
}

static int repo_leaf_is_all_zero(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0u) return 0;
    }
    return 1;
}

/* 擦除一条记录（含版本链）的密钥材料。out_scrubbed=1 表示本条目已无
 * 可用密钥（新格式 RKH 已擦除，或 legacy 段已整段零写，或模块密钥
 * 已销毁）。失败返回 IO/CORRUPT，调用方保留 PENDING。 */
static int repo_scrub_leaf(VtyVault *v, const VtyRepoLeaf *leaf,
                           int *out_scrubbed)
{
    VtyRepoLeaf cur;
    uint64_t guard;

    if (v == NULL || leaf == NULL || out_scrubbed == NULL) return VTY_E_INVALID;
    *out_scrubbed = 0;
    cur = *leaf;
    if ((cur.flags & VTY_REPO_FLAG_TOMBSTONE) == 0) return VTY_E_INVALID;

    for (guard = 0; guard < REPO_SCRUB_CHAIN_MAX; guard++) {
        uint8_t mdek[VTY_KEY_BYTES];
        int rc;

        if (repo_leaf_module_gone(v, &cur)) {
            *out_scrubbed = 1;
            return VTY_OK;
        }
        rc = repo_leaf_key(v, &cur, mdek);
        if (rc != VTY_OK) {
            /* 模块存在但当前未解锁：保留 PENDING，模块解锁后再次维护。
             * 不能把“暂时拿不到密钥”当作已完成擦除。 */
            vty_secure_zero(mdek, sizeof(mdek));
            return rc;
        }

        if ((cur.flags & VTY_REPO_FLAG_KEYED) != 0) {
            uint8_t seg[VTY_SEG_HEADER_BYTES + VTY_RECORD_KEY_HEADER_BYTES];
            uint64_t prev_id = 0;
            int parse_rc;

            if (cur.data_offset == 0u ||
                cur.data_len < sizeof(seg)) {
                vty_secure_zero(mdek, sizeof(mdek));
                *out_scrubbed = 1;
                return VTY_OK;
            }
            rc = vty_store_read_raw(v->store, cur.data_offset, seg, sizeof(seg));
            if (rc != VTY_OK) {
                vty_secure_zero(mdek, sizeof(mdek));
                return rc;
            }
            if (repo_leaf_is_all_zero(seg + VTY_SEG_HEADER_BYTES,
                                      VTY_RECORD_KEY_HEADER_BYTES)) {
                vty_secure_zero(mdek, sizeof(mdek));
                *out_scrubbed = 1;
                return VTY_OK;
            }
            parse_rc = vty_record_key_header_parse(
                mdek, cur.module_uuid, cur.record_id, v->header.epoch,
                seg + VTY_SEG_HEADER_BYTES, &prev_id);
            vty_secure_zero(mdek, sizeof(mdek));

            /* 无论密钥头能否认证都执行零写：半写/损坏的 RKH 也必须清除；
             * 认证失败只意味着无法继续沿链追溯，不是跳过擦除的理由。 */
            rc = vty_store_scrub_range(v->store, cur.data_offset, cur.data_len,
                                       VTY_SEG_HEADER_BYTES,
                                       VTY_RECORD_KEY_HEADER_BYTES);
            if (rc == VTY_E_CORRUPT) {
                rc = vty_store_scrub_raw(v->store,
                                         cur.data_offset + VTY_SEG_HEADER_BYTES,
                                         VTY_RECORD_KEY_HEADER_BYTES);
            }
            if (rc != VTY_OK) return rc;
            *out_scrubbed = 1;
            if (parse_rc != VTY_OK) return VTY_OK;

            if (prev_id == 0u) return VTY_OK;
            {
                VtyRepoLeaf prev;
                int found = 0;
                rc = repo_get_leaf_raw(v, prev_id, &prev, &found);
                if (rc != VTY_OK) return rc;
                if (!found) return VTY_OK;
                /* 链目标必须仍是墓碑；指向存活记录说明目录已不一致，
                 * 拒绝继续，避免误擦其它记录。 */
                if ((prev.flags & VTY_REPO_FLAG_TOMBSTONE) == 0) return VTY_OK;
                cur = prev;
            }
        } else {
            uint32_t payload;
            uint32_t head;
            uint32_t tail;
            uint32_t nonce_off = 0;
            uint8_t prefix[40];

            vty_secure_zero(mdek, sizeof(mdek));
            if (cur.data_offset == 0u || cur.data_len <= VTY_SEG_HEADER_BYTES) {
                *out_scrubbed = 1;
                return VTY_OK;
            }
            payload = cur.data_len - VTY_SEG_HEADER_BYTES;
            head = payload < 64u ? payload : 64u;
            tail = payload < 64u ? 0u : 64u;

            /* 旧格式没有可销毁的密钥槽：MDEK 是全局的，必须让密文本身
             * 不可解。AEAD 的 nonce 是流密钥的唯一输入，擦掉 24B nonce
             * 后名称与数据都无法恢复；首尾 64B 同时清零作为纵深防御。
             * 只写 128B/条，不再整段覆写，删除代价与载荷大小无关。 */
            if (payload >= 40u) {
                size_t need = payload < sizeof(prefix) ? payload : sizeof(prefix);
                if (vty_store_read_raw(v->store,
                                       cur.data_offset + VTY_SEG_HEADER_BYTES,
                                       prefix, need) == VTY_OK &&
                    need >= 40u) {
                    uint32_t name_ct = vty_get_u16(prefix + 32);
                    uint32_t cand = 34u + name_ct + 4u;
                    if (cand <= payload && payload - cand >= VTY_NONCE_BYTES) {
                        nonce_off = cand;
                    }
                }
            }
            if (nonce_off == 0u) {
                /* 结构不可信：整段零写，绝不把无法定位 nonce 的密文留下。 */
                head = payload;
                tail = 0u;
            }

            rc = vty_store_scrub_range(v->store, cur.data_offset, cur.data_len,
                                       VTY_SEG_HEADER_BYTES, head);
            if (rc == VTY_E_CORRUPT) {
                rc = vty_store_scrub_raw(v->store,
                                         cur.data_offset + VTY_SEG_HEADER_BYTES,
                                         head);
            }
            if (rc != VTY_OK) return rc;
            if (tail != 0u) {
                rc = vty_store_scrub_range(
                    v->store, cur.data_offset, cur.data_len,
                    VTY_SEG_HEADER_BYTES + payload - tail, tail);
                if (rc == VTY_E_CORRUPT) {
                    rc = vty_store_scrub_raw(
                        v->store,
                        cur.data_offset + VTY_SEG_HEADER_BYTES + payload - tail,
                        tail);
                }
                if (rc != VTY_OK) return rc;
            }
            if (nonce_off != 0u) {
                rc = vty_store_scrub_range(
                    v->store, cur.data_offset, cur.data_len,
                    VTY_SEG_HEADER_BYTES + nonce_off, VTY_NONCE_BYTES);
                if (rc == VTY_E_CORRUPT) {
                    rc = vty_store_scrub_raw(
                        v->store,
                        cur.data_offset + VTY_SEG_HEADER_BYTES + nonce_off,
                        VTY_NONCE_BYTES);
                }
                if (rc != VTY_OK) return rc;
            }
            *out_scrubbed = 1;
            return VTY_OK;
        }
    }
    return VTY_OK;
}

/* 清除墓碑定位符与待擦标志：密钥已不可解，目录不再保留任何可定位
 * 残段的引用。失败不回滚删除。 */
static int repo_clear_scrub_marker(VtyVault *v, const VtyRepoLeaf *leaf)
{
    RepoLeafRaw raw;
    uint8_t leaf_buf[VTY_REPO_LEAF_BYTES];
    uint8_t key[8];
    int rc;

    memset(&raw, 0, sizeof(raw));
    raw.record_id = leaf->record_id;
    memcpy(raw.module_uuid, leaf->module_uuid, VTY_UUID_BYTES);
    raw.flags = (uint8_t)((leaf->flags & (uint8_t)~VTY_REPO_FLAG_SCRUB_PENDING)
                          | VTY_REPO_FLAG_TOMBSTONE);
    memcpy(raw.name_index, leaf->name_index, VTY_HASH_BYTES);
    memcpy(raw.type_token, leaf->type_token, VTY_HASH_BYTES);
    raw.created_time = leaf->created_time;
    raw.data_offset = 0u;
    raw.data_len = 0u;
    raw.plain_size = 0u;
    rc = repo_leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) return rc;
    repo_record_key(key, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf_buf, sizeof(leaf_buf));
    if (rc != VTY_OK) return rc;
    /* 密钥已不可解，出队；下一次维护不再重复处理。 */
    return vty_store_delete(v->store, VTY_KS_SCRUB, key, sizeof(key));
}

/* 擦除后收尾：成功时清定位符并提交；失败保留 PENDING。删除本身已提交，
 * 因此本函数任何失败都不改变“记录已删除”的结论。 */
void repo_finish_scrub(VtyVault *v, const VtyRepoLeaf *leaf,
                              int *any_cleared)
{
    VtyRepoLeaf tomb;
    int scrubbed = 0;
    int rc;

    tomb = *leaf;
    tomb.flags = (uint8_t)(tomb.flags | VTY_REPO_FLAG_TOMBSTONE |
                           VTY_REPO_FLAG_SCRUB_PENDING);
    rc = repo_scrub_leaf(v, &tomb, &scrubbed);
    if (rc == VTY_OK && scrubbed) {
        if (repo_clear_scrub_marker(v, &tomb) == VTY_OK) {
            if (any_cleared != NULL) (*any_cleared)++;
        }
    }
}

int repo_delete_one(VtyVault *v, const VtyRepoLeaf *leaf)
{
    RepoLeafRaw raw;
    uint8_t leaf_buf[VTY_REPO_LEAF_BYTES];
    uint8_t key[8];
    uint8_t ikey[VTY_HASH_BYTES + 8u];
    int rc;

    memset(&raw, 0, sizeof(raw));
    raw.record_id = leaf->record_id;
    memcpy(raw.module_uuid, leaf->module_uuid, VTY_UUID_BYTES);
    raw.flags = (uint8_t)(leaf->flags | VTY_REPO_FLAG_TOMBSTONE |
                          VTY_REPO_FLAG_SCRUB_PENDING);
    memcpy(raw.name_index, leaf->name_index, VTY_HASH_BYTES);
    memcpy(raw.type_token, leaf->type_token, VTY_HASH_BYTES);
    raw.created_time = leaf->created_time;
    raw.data_offset = leaf->data_offset;
    raw.data_len = leaf->data_len;
    raw.plain_size = leaf->plain_size;
    memcpy(raw.data_hash, leaf->data_hash, VTY_HASH_BYTES);
    rc = repo_leaf_encode(&raw, leaf_buf);
    if (rc != VTY_OK) return rc;

    repo_record_key(key, leaf->record_id);
    rc = vty_store_put(v->store, VTY_KS_RECORD, key, sizeof(key),
                       leaf_buf, sizeof(leaf_buf));
    if (rc != VTY_OK) return rc;

    repo_index_key(ikey, leaf->name_index, leaf->record_id);
    rc = vty_store_delete(v->store, VTY_KS_NAME, ikey, sizeof(ikey));
    if (rc != VTY_OK) return rc;
    repo_index_key(ikey, leaf->type_token, leaf->record_id);
    rc = vty_store_delete(v->store, VTY_KS_TYPE, ikey, sizeof(ikey));
    if (rc != VTY_OK) return rc;

    /* 待擦队列与墓碑同事务落盘：崩溃后即使还没开始擦除，也能从队列
     * 精确找到目标，不依赖全库扫描。 */
    return vty_store_put(v->store, VTY_KS_SCRUB, key, sizeof(key), NULL, 0u);
}

int vty_repo_delete(VtyVault *v, uint64_t id)
{
    VtyStoreCheckpoint cp;
    VtyRepoLeaf leaf;
    int found = 0;
    int rc;

    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    if (id == 0u) return VTY_E_INVALID;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;
    rc = repo_get_leaf_raw(v, id, &leaf, &found);
    if (rc != VTY_OK) return rc;
    if (!found || (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0) return VTY_E_INVALID;
    rc = repo_require_leaf_module(v, &leaf);
    if (rc != VTY_OK) return rc;

    rc = repo_delete_one(v, &leaf);
    if (rc != VTY_OK) goto fail;
    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;

    /* 删除已持久化；密钥擦除失败不改变删除结论，PENDING 由解锁维护补偿。 */
    if (!repo_skip_scrub()) {
        int cleared = 0;
        repo_finish_scrub(v, &leaf, &cleared);
        (void)vty_store_flush(v->store);
        if (cleared) (void)repo_commit(v);
    }
    return VTY_OK;

fail:
    vty_store_restore(v->store, &cp);
    return rc;
}

int vty_repo_delete_many(VtyVault *v, const uint64_t *ids, size_t count)
{
    VtyStoreCheckpoint cp;
    VtyRepoLeaf *leaves = NULL;
    size_t i;
    int rc;

    rc = repo_write_ready(v);
    if (rc != VTY_OK) return rc;
    if (ids == NULL && count != 0) return VTY_E_INVALID;
    if (count == 0) return VTY_OK;

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) return rc;
    leaves = (VtyRepoLeaf *)vty_alloc(sizeof(VtyRepoLeaf) * count);
    if (leaves == NULL) return VTY_E_RESOURCE;

    /* 先全量探测：任一不存在整体 NOTFOUND（零副作用）。 */
    for (i = 0; i < count; i++) {
        int found = 0;
        if (ids[i] == 0u) { rc = VTY_E_INVALID; goto fail; }
        rc = repo_get_leaf_raw(v, ids[i], &leaves[i], &found);
        if (rc != VTY_OK) goto fail;
        if (!found || (leaves[i].flags & VTY_REPO_FLAG_TOMBSTONE) != 0) {
            rc = VTY_E_INVALID;
            goto fail;
        }
        rc = repo_require_leaf_module(v, &leaves[i]);
        if (rc != VTY_OK) goto fail;
    }

    for (i = 0; i < count; i++) {
        rc = repo_delete_one(v, &leaves[i]);
        if (rc != VTY_OK) goto fail;
    }

    rc = repo_commit(v);
    if (rc != VTY_OK) goto fail;

    if (!repo_skip_scrub()) {
        int cleared = 0;
        for (i = 0; i < count; i++) {
            repo_finish_scrub(v, &leaves[i], &cleared);
        }
        /* 批量删除只刷盘一次：单文件上千分片时逐条 fsync 会把删除拖到秒级。 */
        (void)vty_store_flush(v->store);
        if (cleared) (void)repo_commit(v);
    }
    vty_free(leaves, sizeof(VtyRepoLeaf) * count);
    return VTY_OK;

fail:
    if (leaves != NULL) vty_free(leaves, sizeof(VtyRepoLeaf) * count);
    vty_store_restore(v->store, &cp);
    return rc;
}

/* 升级前已存在的墓碑没有待擦队列条目。首次维护做一次全目录扫描，把仍带
 * 定位符的墓碑加入队列并写入完成标记；之后维护只处理队列，解锁开销与
 * 容器规模解耦。扫描中途崩溃则标记未写，下次重做（幂等）。 */
static int repo_queue_legacy_tombstones(VtyVault *v)
{
    static const char tag[] = VTY_MAINT_LEGACY_TAG;
    VtyStoreCursor *c = NULL;
    uint8_t *val = NULL;
    size_t vlen = 0;
    int rc;

    rc = vty_store_get(v->store, VTY_KS_MAINT, (const uint8_t *)tag,
                       sizeof(tag) - 1u, &val, &vlen);
    if (rc == VTY_OK) {
        if (val != NULL) vty_free(val, vlen);
        return VTY_OK;
    }
    if (rc != VTY_E_INVALID) return rc;

    rc = vty_store_cursor_open(v->store, VTY_KS_RECORD, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *vv = NULL;
        size_t klen = 0, vlen2 = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &vv, &vlen2);
        if (rc != VTY_OK) {
            vty_free(k, klen);
            vty_free(vv, vlen2);
            break;
        }
        if (done) {
            vty_free(k, klen);
            vty_free(vv, vlen2);
            break;
        }
        if (klen == 8u && !repo_leaf_is_all_zero(k, klen) &&
            vlen2 == VTY_REPO_LEAF_BYTES) {
            VtyRepoLeaf leaf;
            if (repo_leaf_decode(vv, vlen2, &leaf) == VTY_OK &&
                (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) != 0 &&
                leaf.data_offset != 0u) {
                rc = vty_store_put(v->store, VTY_KS_SCRUB, k, klen, NULL, 0u);
            }
        }
        vty_free(k, klen);
        vty_free(vv, vlen2);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    if (rc != VTY_OK) return rc;

    rc = vty_store_put(v->store, VTY_KS_MAINT, (const uint8_t *)tag,
                       sizeof(tag) - 1u, NULL, 0u);
    if (rc != VTY_OK) return rc;
    return repo_commit(v);
}

int vty_repo_maintain_pending_scrub(VtyVault *v, uint64_t max_records,
                                    uint64_t *out_scrubbed,
                                    uint64_t *out_pending)
{
    VtyStoreCursor *c = NULL;
    uint8_t *keys = NULL;
    uint64_t *ids = NULL;
    size_t cap;
    size_t n = 0;
    size_t i;
    uint64_t scrubbed = 0;
    uint64_t pending = 0;
    uint64_t stale = 0;
    uint64_t cleared = 0;
    int rc;

    if (out_scrubbed != NULL) *out_scrubbed = 0;
    if (out_pending != NULL) *out_pending = 0;
    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (max_records == 0u) max_records = 4096u;
    if (max_records > 4096u) max_records = 4096u;
    cap = (size_t)max_records;

    rc = repo_queue_legacy_tombstones(v);
    if (rc != VTY_OK) return rc;

    keys = (uint8_t *)vty_alloc(8u * cap);
    ids = (uint64_t *)vty_alloc(sizeof(uint64_t) * cap);
    if (keys == NULL || ids == NULL) {
        if (keys != NULL) vty_free(keys, 8u * cap);
        if (ids != NULL) vty_free(ids, sizeof(uint64_t) * cap);
        return VTY_E_RESOURCE;
    }

    /* 队列只含待擦记录，读取量直接受预算约束，不再扫全目录树。 */
    rc = vty_store_cursor_open(v->store, VTY_KS_SCRUB, NULL, 0, &c);
    if (rc != VTY_OK) {
        vty_free(keys, 8u * cap);
        vty_free(ids, sizeof(uint64_t) * cap);
        return rc;
    }
    while (n < cap) {
        int done = 0;
        uint8_t *k = NULL, *val = NULL;
        size_t klen = 0, vlen = 0;

        rc = vty_store_cursor_next(c, &done, &k, &klen, &val, &vlen);
        if (rc != VTY_OK) {
            vty_free(k, klen);
            vty_free(val, vlen);
            break;
        }
        if (done) {
            vty_free(k, klen);
            vty_free(val, vlen);
            break;
        }
        if (klen == 8u) {
            memcpy(keys + n * 8u, k, 8u);
            ids[n] = repo_get_be64(k);
            n++;
        } else {
            /* 非法队列键：直接清除，避免阻塞后续处理。 */
            rc = vty_store_delete(v->store, VTY_KS_SCRUB, k, klen);
            if (rc == VTY_OK) stale++;
        }
        vty_free(k, klen);
        vty_free(val, vlen);
        if (rc != VTY_OK) break;
    }
    vty_store_cursor_close(c);
    if (rc != VTY_OK) {
        vty_free(keys, 8u * cap);
        vty_free(ids, sizeof(uint64_t) * cap);
        return rc;
    }

    for (i = 0; i < n; i++) {
        VtyRepoLeaf leaf;
        uint8_t *qkey = keys + i * 8u;
        int found = 0;
        int did = 0;

        rc = repo_get_leaf_raw(v, ids[i], &leaf, &found);
        if (rc != VTY_OK) {
            pending++;
            continue;
        }
        if (!found ||
            (leaf.flags & VTY_REPO_FLAG_TOMBSTONE) == 0 ||
            (leaf.data_offset == 0u &&
             (leaf.flags & VTY_REPO_FLAG_SCRUB_PENDING) == 0)) {
            /* 已被压缩淘汰、已收尾或键指向存活记录：出队，不误擦。 */
            if (vty_store_delete(v->store, VTY_KS_SCRUB, qkey, 8u) == VTY_OK) {
                stale++;
            }
            continue;
        }
        rc = repo_scrub_leaf(v, &leaf, &did);
        if (rc == VTY_OK && did) {
            scrubbed++;
            if (repo_clear_scrub_marker(v, &leaf) == VTY_OK) cleared++;
        } else {
            pending++;
        }
    }

    if (cleared > 0u || stale > 0u) {
        (void)vty_store_flush(v->store);
        rc = repo_commit(v);
        if (rc != VTY_OK) {
            /* 密钥已擦除但目录未提交：保持队列，下次打开重试收尾。 */
            pending += cleared;
            scrubbed -= cleared;
        }
    }
    vty_free(keys, 8u * cap);
    vty_free(ids, sizeof(uint64_t) * cap);
    if (out_scrubbed != NULL) *out_scrubbed = scrubbed;
    if (out_pending != NULL) *out_pending = pending;
    return VTY_OK;
}
