/*
 * vty_rotate_copy.c — 全量复制、内容层换封与完整性复核
 *
 * 逐记录、逐文件分片复制新库并回读比对；内容层信封按新旧库各自代数
 * 换封，换封结果必须能用新库密钥解封。Run 在此编排模块启用、复制、
 * ID 水位保持与落盘，任一失败进入 FAILED。
 */

#include "vty_rotate_internal.h"

static int rot_records_equal(const VtyRepoRecord *a, const VtyRepoRecord *b)
{
    if (a->type != b->type || a->name_len != b->name_len ||
        a->data_len != b->data_len) {
        return 0;
    }
    if (a->name_len != 0u &&
        memcmp(a->name, b->name, a->name_len) != 0) {
        return 0;
    }
    if (a->data_len != 0u &&
        memcmp(a->data, b->data, a->data_len) != 0) {
        return 0;
    }
    return 1;
}

static void rot_free_record(VtyRepoRecord *rec)
{
    if (rec->name != NULL) {
        vty_secure_zero(rec->name, rec->name_len != 0 ? rec->name_len : 1u);
        vty_free(rec->name, rec->name_len != 0 ? rec->name_len : 1u);
        rec->name = NULL;
    }
    if (rec->data != NULL) {
        vty_secure_zero(rec->data, rec->data_len != 0 ? rec->data_len : 1u);
        vty_free(rec->data, rec->data_len != 0 ? rec->data_len : 1u);
        rec->data = NULL;
    }
}

/* 旧/新库 MDEK 与 epoch 分离：轮换跨代，内层信封必须按各自代数解封/重封。 */
static int rot_rewrap_content_record(VtyRotateJob *job, int module_index,
                                     uint8_t type,
                                     const uint8_t *in, size_t in_len,
                                     uint8_t **out, size_t *out_len,
                                     int *rewrapped)
{
    uint8_t old_mdek[VTY_KEY_BYTES];
    uint8_t new_mdek[VTY_KEY_BYTES];
    int rc;

    *out = NULL;
    *out_len = 0;
    *rewrapped = 0;
    if (module_index < 0 || module_index >= (int)VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (job->old->modules[module_index].deleted) return VTY_OK;

    memset(old_mdek, 0, sizeof(old_mdek));
    memset(new_mdek, 0, sizeof(new_mdek));
    rc = vty_vault_module_key(job->old, job->old->modules[module_index].uuid,
                              old_mdek);
    if (rc == VTY_OK) {
        rc = vty_vault_module_key(job->newv,
                                  job->newv->modules[module_index].uuid,
                                  new_mdek);
    }
    if (rc == VTY_OK) {
        rc = vty_repo_rewrap_content(type, module_index,
                                     old_mdek, job->old->header.epoch,
                                     new_mdek, job->newv->header.epoch,
                                     in, in_len, out, out_len, rewrapped);
    }
    vty_secure_zero(old_mdek, sizeof(old_mdek));
    vty_secure_zero(new_mdek, sizeof(new_mdek));
    return rc;
}

/* 换封后的记录必须能用新库 MDEK/新 epoch 解封；否则回滚整个作业。 */
static int rot_verify_rewrapped_record(VtyRotateJob *job, int module_index,
                                       const uint8_t *data, size_t data_len)
{
    uint8_t new_mdek[VTY_KEY_BYTES];
    int openable = 0;
    int rc;

    if (module_index < 0 || module_index >= (int)VTY_MODULE_COUNT) {
        return VTY_E_INVALID;
    }
    memset(new_mdek, 0, sizeof(new_mdek));
    rc = vty_vault_module_key(job->newv,
                              job->newv->modules[module_index].uuid,
                              new_mdek);
    if (rc == VTY_OK) {
        rc = vty_repo_content_envelope_check(new_mdek, job->newv->header.epoch,
                                             data, data_len, &openable);
    }
    vty_secure_zero(new_mdek, sizeof(new_mdek));
    if (rc != VTY_OK) return rc;
    return openable ? VTY_OK : VTY_E_VERIFY;
}

static int rot_copy_records(VtyRotateJob *job, VtyRotateProgressFn cb,
                            void *user)
{
    VtyRepoIter *it = NULL;
    int rc;

    rc = vty_repo_iter_open(job->old, 0u, &it);
    if (rc != VTY_OK) return rc;

    for (;;) {
        VtyRepoLeaf leaf;
        VtyRepoRecord rec;
        VtyRepoRecord check;
        uint64_t new_id = 0;
        int done = 0;
        int module_index = -1;
        uint8_t *inner = NULL;
        size_t inner_len = 0;
        int rewrapped = 0;
        uint32_t mi;

        memset(&leaf, 0, sizeof(leaf));
        memset(&rec, 0, sizeof(rec));
        memset(&check, 0, sizeof(check));
        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK || done) break;

        for (mi = 0; mi < VTY_MODULE_COUNT; mi++) {
            if (memcmp(leaf.module_uuid, job->old->modules[mi].uuid,
                       VTY_UUID_BYTES) == 0) {
                module_index = (int)mi;
                break;
            }
        }

        rc = vty_repo_read(job->old, &leaf, &rec);
        if (rc == VTY_OK && (module_index == 0 || module_index == 2)) {
            rc = rot_rewrap_content_record(job, module_index, rec.type,
                                           rec.data, rec.data_len,
                                           &inner, &inner_len, &rewrapped);
            if (rc == VTY_OK && rewrapped) {
                vty_secure_zero(rec.data, rec.data_len);
                vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
                rec.data = inner;
                rec.data_len = inner_len;
                inner = NULL;
                inner_len = 0;
            }
            /* rewrapped=0：该记录不是内容层信封（账户/明文记录），
             * 按普通记录复制即可，不据此判定源库损坏。 */
        }
        if (inner != NULL) {
            vty_secure_zero(inner, inner_len != 0 ? inner_len : 1u);
            vty_free(inner, inner_len != 0 ? inner_len : 1u);
            inner = NULL;
        }
        if (rc == VTY_OK) {
            rc = vty_repo_add_ex(job->newv, rec.type, rec.name, rec.name_len,
                                 rec.data, rec.data_len, leaf.record_id,
                                 leaf.created_time, &new_id);
        }
        if (rc != VTY_OK) {
            rot_free_record(&rec);
            break;
        }
        if (new_id != leaf.record_id) {
            rot_free_record(&rec);
            rc = VTY_E_VERIFY;
            break;
        }
        /* 逐条回读新库：提交前证明“复制出的内容与源库逐字节一致”，
         * 而不是只相信计数。内层信封换封后还须能用新密钥解封。 */
        rc = vty_repo_get(job->newv, new_id, &check);
        if (rc == VTY_OK && !rot_records_equal(&rec, &check)) {
            rc = VTY_E_VERIFY;
        }
        if (rc == VTY_OK && rewrapped) {
            rc = rot_verify_rewrapped_record(job, module_index,
                                             check.data, check.data_len);
        }
        rot_free_record(&check);
        if (rc != VTY_OK) {
            rot_free_record(&rec);
            break;
        }

        job->stats.records++;
        job->stats.bytes += (uint64_t)rec.name_len + (uint64_t)rec.data_len;
        rot_free_record(&rec);
        rc = vty_rot_progress(job, cb, user);
        if (rc != VTY_OK) break;
    }

    vty_repo_iter_close(it);
    return rc;
}

/* 文件模块仓库分片同样可能承载内容层信封；换封失败
 * 不代表损坏（纯明文分片），因此此处按认证结果可选换封，不 fail-closed。 */
static int rot_rewrap_file_chunk(VtyRotateJob *job,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t **out, size_t *out_len,
                                 int *rewrapped)
{
    uint8_t old_mdek[VTY_KEY_BYTES];
    uint8_t new_mdek[VTY_KEY_BYTES];
    int rc;

    *out = NULL;
    *out_len = 0;
    *rewrapped = 0;
    if (job->old->modules[2].deleted) return VTY_OK;

    memset(old_mdek, 0, sizeof(old_mdek));
    memset(new_mdek, 0, sizeof(new_mdek));
    rc = vty_vault_module_key(job->old, job->old->modules[2].uuid, old_mdek);
    if (rc == VTY_OK) {
        rc = vty_vault_module_key(job->newv, job->newv->modules[2].uuid,
                                  new_mdek);
    }
    if (rc == VTY_OK) {
        rc = vty_repo_rewrap_content(0x04, 2, old_mdek, job->old->header.epoch,
                                     new_mdek, job->newv->header.epoch,
                                     in, in_len, out, out_len, rewrapped);
    }
    vty_secure_zero(old_mdek, sizeof(old_mdek));
    vty_secure_zero(new_mdek, sizeof(new_mdek));
    return rc;
}

static int rot_copy_file(void *user, const uint8_t file_uuid[VTY_UUID_BYTES],
                         const VtyRepoFile *file)
{
    RotFileCtx *ctx = (RotFileCtx *)user;
    VtyRotateJob *job = ctx->job;
    VtyRepoFile check_file;
    uint32_t seq;
    int rc;

    rc = vty_repo_file_put_ex(job->newv, file_uuid, file->pt_hash,
                              file->total, file->created_time);
    if (rc != VTY_OK) return rc;
    memset(&check_file, 0, sizeof(check_file));
    rc = vty_repo_file_get(job->newv, file_uuid, &check_file);
    if (rc == VTY_OK &&
        (check_file.total != file->total ||
         check_file.created_time != file->created_time ||
         memcmp(check_file.pt_hash, file->pt_hash, VTY_HASH_BYTES) != 0)) {
        rc = VTY_E_VERIFY;
    }
    if (rc != VTY_OK) return rc;
    job->expected_chunks += (uint64_t)file->total;

    for (seq = 0; seq < file->total; seq++) {
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        uint8_t *rewrapped_pt = NULL;
        size_t rewrapped_pt_len = 0;
        const uint8_t *payload = NULL;
        size_t payload_len = 0;
        int rewrapped = 0;
        uint8_t *rt = NULL;
        size_t rt_len = 0;

        rc = vty_repo_chunk_get(job->old, file_uuid, seq, &pt, &pt_len);
        if (rc == VTY_OK) {
            rc = rot_rewrap_file_chunk(job, pt, pt_len, &rewrapped_pt,
                                       &rewrapped_pt_len, &rewrapped);
        }
        if (rc == VTY_OK) {
            payload = rewrapped ? rewrapped_pt : pt;
            payload_len = rewrapped ? rewrapped_pt_len : pt_len;
            rc = vty_repo_chunk_add(job->newv, file_uuid, seq,
                                    payload, payload_len);
        }
        if (rc == VTY_OK) {
            rc = vty_repo_chunk_get(job->newv, file_uuid, seq, &rt, &rt_len);
            if (rc == VTY_OK &&
                (rt_len != payload_len ||
                 memcmp(rt, payload, payload_len) != 0)) {
                rc = VTY_E_VERIFY;
            }
        }
        if (rt != NULL) {
            vty_secure_zero(rt, rt_len != 0 ? rt_len : 1u);
            vty_free(rt, rt_len != 0 ? rt_len : 1u);
        }
        if (rewrapped_pt != NULL) {
            vty_secure_zero(rewrapped_pt,
                            rewrapped_pt_len != 0 ? rewrapped_pt_len : 1u);
            vty_free(rewrapped_pt,
                     rewrapped_pt_len != 0 ? rewrapped_pt_len : 1u);
        }
        if (pt != NULL) {
            vty_secure_zero(pt, pt_len != 0 ? pt_len : 1u);
            vty_free(pt, pt_len != 0 ? pt_len : 1u);
        }
        if (rc != VTY_OK) return rc;
        job->stats.chunks++;
        /* 分片级回调：大文件复制期间也能在下一分片边界响应取消请求。 */
        rc = vty_rot_progress(job, ctx->cb, ctx->user);
        if (rc != VTY_OK) return rc;
    }

    job->stats.files++;
    return vty_rot_progress(job, ctx->cb, ctx->user);
}

static int rot_verify(VtyRotateJob *job)
{
    uint64_t old_count = 0;
    uint64_t new_count = 0;
    uint64_t old_files = 0;
    uint64_t new_files = 0;
    int rc;

    rc = vty_repo_count(job->old, &old_count);
    if (rc != VTY_OK) return rc;
    rc = vty_repo_count(job->newv, &new_count);
    if (rc != VTY_OK) return rc;
    if (old_count != new_count || new_count != job->stats.records) {
        return VTY_E_VERIFY;
    }

    if (job->old->modules[2].deleted) {
        /* fileverthys 已删除：键空间只剩墓碑，不依赖模块密钥统计存活文件；
         * 若仍存在存活文件叶，说明删除未清空数据，必须 fail-closed。 */
        uint64_t live = 0;
        rc = vty_repo_file_count_live(job->old, &live);
        if (rc != VTY_OK) return rc;
        if (live != 0) return VTY_E_CORRUPT;
        old_files = 0;
    } else {
        rc = vty_repo_file_list(job->old, NULL, NULL, &old_files);
        if (rc != VTY_OK) return rc;
    }
    rc = vty_repo_file_list(job->newv, NULL, NULL, &new_files);
    if (rc != VTY_OK) return rc;
    if (old_files != new_files || new_files != job->stats.files) {
        return VTY_E_VERIFY;
    }
    if (job->stats.chunks != job->expected_chunks) return VTY_E_VERIFY;
    return VTY_OK;
}

int vty_rotate_run(VtyRotateJob *job, VtyRotateProgressFn cb, void *user)
{
    uint32_t i;
    int rc;

    if (job == NULL || job->newv == NULL || job->old == NULL) {
        return VTY_E_INVALID;
    }
    if (job->stage != VTY_ROTATE_STAGE_BEGUN) return VTY_E_POLICY;

    /* 所有已启用模块必须具备口令与已解锁的源 MDEK，否则复制出的记录
     * 无法解密。 */
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (!job->old->modules[i].enabled) continue;
        if (job->module_pw[i] == NULL || !job->old->modules[i].unlocked) {
            return VTY_E_MODULE_LOCKED;
        }
    }

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (!job->old->modules[i].enabled) continue;
        rc = vty_module_enable(job->newv, i, job->module_pw[i], NULL);
        if (rc != VTY_OK) goto fail;
        if (job->old->modules[i].has_recovery) {
            rc = vty_module_recovery_seal(job->newv, i, job->old->k_recovery);
            if (rc != VTY_OK) goto fail;
        }
        job->stats.modules_ready++;
        rc = vty_rot_progress(job, cb, user);
        if (rc != VTY_OK) goto fail;
    }

    rc = rot_copy_records(job, cb, user);
    if (rc != VTY_OK) goto fail;

    {
        RotFileCtx ctx;
        ctx.job = job;
        ctx.cb = cb;
        ctx.user = user;
        if (job->old->modules[2].deleted) {
            /* 文件模块已删除：只验证键空间无存活文件，不执行复制。 */
            uint64_t live = 0;
            rc = vty_repo_file_count_live(job->old, &live);
            if (rc != VTY_OK) goto fail;
            if (live != 0) { rc = VTY_E_CORRUPT; goto fail; }
        } else {
            rc = vty_repo_file_list(job->old, rot_copy_file, &ctx, NULL);
            if (rc != VTY_OK) goto fail;
        }
    }

    /* 保留源库 ID 水位：新库不得复用源库已分配过的 ID（含已删除记录）。 */
    if (job->source_next_id != 0u) {
        uint64_t new_next = 0;
        rc = vty_repo_next_id(job->newv, &new_next);
        if (rc != VTY_OK) goto fail;
        if (job->source_next_id > new_next) {
            rc = vty_repo_set_next_id(job->newv, job->source_next_id);
            if (rc != VTY_OK) goto fail;
        }
    }

    rc = vty_store_verify(job->newv->store);
    if (rc != VTY_OK) goto fail;
    rc = rot_verify(job);
    if (rc != VTY_OK) goto fail;

    /* 最后一次落盘：提交数据区并写元数据；锚点仍被抑制。 */
    rc = vty_vault_save(job->newv);
    if (rc != VTY_OK) goto fail;

    vty_rot_set_stage(job, VTY_ROTATE_STAGE_COPIED);
    return VTY_OK;

fail:
    vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
    return rc;
}
