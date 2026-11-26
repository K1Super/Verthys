/*
 * verthys_api_container.c — 记录 CRUD/校验/改密与共享 API 辅助
 *
 * 所有函数要求调用方已持有 api_mutex（公共入口负责），内部不再加锁；
 * GetRecord 的借用指针缓存规则：下次查询/写/Lock 前有效；
 * 口令复制、会话解析、api_mutex 串行化与入口参数校验供各分片复用。
 */
#include "verthys_api_container_internal.h"
#include "vty_util.h"                  /* vty_free / vty_secure_zero */
#include "vty_repo.h"
#include "vty_store.h"

#include <stdlib.h>
#include <string.h>

VerthysResult verthys_api_container_map(int vty_rc)
{
    /* 记录域覆盖：vty_repo 以 VTY_E_INVALID 表示“不存在/已墓碑”。
     * 其余错误码统一走全 API 底表，禁止各自维护第二份映射。 */
    if (vty_rc == VTY_E_INVALID) return VERTHYS_ERR_NOTFOUND;
    return verthys_api_map_vty(vty_rc);
}

static int vault_ready(struct VerthysContext *ctx, VtyVault **out)
{
    if (ctx == NULL) return 0;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER || ctx->vault == NULL) return 0;
    if (!ctx->vault->unlocked || ctx->vault->store == NULL) return 0;
    *out = ctx->vault;
    return 1;
}

static uint8_t *dup_bytes(const uint8_t *src, size_t n)
{
    uint8_t *p;

    if (n == 0) return NULL;
    p = (uint8_t *)malloc(n);
    if (p != NULL) memcpy(p, src, n);
    return p;
}

VerthysResult verthys_api_container_add(struct VerthysContext *ctx,
                                 const VerthysRecord *record,
                                 uint64_t *out_id)
{
    VtyVault *v;
    int rc;

    if (record == NULL || out_id == NULL) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    rc = vty_repo_add(v, (uint8_t)record->type,
                      (const uint8_t *)record->name, record->name_len,
                      record->data, record->data_len, out_id);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_add_many(struct VerthysContext *ctx,
                                      const VerthysRecord *records,
                                      uint32_t count,
                                      uint64_t *out_ids)
{
    VtyVault *v;
    VtyRepoInput *in;
    uint32_t i;
    int rc;

    if (records == NULL || out_ids == NULL) return VERTHYS_ERR_INVALID;
    if (count == 0u || count > VERTHYS_ADD_RECORDS_MAX) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    in = (VtyRepoInput *)calloc((size_t)count, sizeof(*in));
    if (in == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;

    /* out_ids 先归零：批量失败时不向调用方暴露部分分配结果。 */
    memset(out_ids, 0, (size_t)count * sizeof(uint64_t));
    for (i = 0u; i < count; i++) {
        in[i].type = (uint8_t)records[i].type;
        in[i].name = (const uint8_t *)records[i].name;
        in[i].name_len = records[i].name_len;
        in[i].data = records[i].data;
        in[i].data_len = records[i].data_len;
    }

    rc = vty_repo_add_many(v, in, (size_t)count, out_ids);
    free(in);
    if (rc != VTY_OK) {
        memset(out_ids, 0, (size_t)count * sizeof(uint64_t));
    }
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_get(struct VerthysContext *ctx, uint64_t id,
                                 VerthysRecord *out_record)
{
    VtyVault *v;
    VtyRepoRecord rec;
    uint8_t *name = NULL;
    uint8_t *data = NULL;
    int rc;

    if (out_record == NULL) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    memset(&rec, 0, sizeof(rec));
    rc = vty_repo_get(v, id, &rec);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    /* 仓库返回 vty_alloc 缓冲；借用缓存统一用 malloc/free，必须复制
     * 后再按各自分配器释放，避免跨分配器 free。 */
    name = dup_bytes(rec.name, rec.name_len);
    data = dup_bytes(rec.data, rec.data_len);
    if ((rec.name_len != 0 && name == NULL) ||
        (rec.data_len != 0 && data == NULL)) {
        free(name);
        free(data);
        if (rec.name != NULL) vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
        return VERTHYS_ERR_INTERNAL;
    }
    if (rec.name != NULL) vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);

    ctx_free_getrecord_cache(ctx);
    ctx->last_getrecord_name = name;
    ctx->last_getrecord_name_len = rec.name_len;
    ctx->last_getrecord_data = data;
    ctx->last_getrecord_data_size = rec.data_len;

    out_record->type = (VerthysRecordType)rec.type;
    out_record->name = (const char *)name;
    out_record->name_len = rec.name_len;
    out_record->data = data;
    out_record->data_len = rec.data_len;
    return VERTHYS_OK;
}

VerthysResult verthys_api_container_delete(struct VerthysContext *ctx, uint64_t id)
{
    VtyVault *v;
    int rc;

    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;
    rc = vty_repo_delete(v, id);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_replace(struct VerthysContext *ctx,
                                     uint64_t old_id,
                                     const VerthysRecord *record,
                                     uint64_t *out_new_id)
{
    VtyVault *v;
    int rc;

    if (record == NULL || out_new_id == NULL) return VERTHYS_ERR_INVALID;
    *out_new_id = 0u;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    rc = vty_repo_replace(v, old_id, (uint8_t)record->type,
                          (const uint8_t *)record->name, record->name_len,
                          record->data, record->data_len, out_new_id);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_delete_many(struct VerthysContext *ctx,
                                         const uint64_t *ids, size_t count)
{
    VtyVault *v;
    int rc;

    if (ids == NULL && count != 0) return VERTHYS_ERR_INVALID;
    if (count == 0) return VERTHYS_OK;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;
    rc = vty_repo_delete_many(v, ids, count);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_count(struct VerthysContext *ctx,
                                   uint64_t *out_count)
{
    VtyVault *v;
    int rc;

    if (out_count == NULL) return VERTHYS_ERR_INVALID;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;
    rc = vty_repo_count(v, out_count);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_verify(struct VerthysContext *ctx,
                                    uint64_t *out_failed_lids,
                                    uint64_t max_failed,
                                    uint64_t *out_failed_count)
{
    VtyVault *v;
    VtyRepoIter *it = NULL;
    uint64_t failed = 0;
    int rc;

    if (out_failed_count == NULL) return VERTHYS_ERR_INVALID;
    *out_failed_count = 0;
    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    /* 目录结构/DataRoot 级损坏无法逐条报告，整体拒绝（与既有迭代器
     * 中途损坏同纪律）。记录级解密失败记入 failed_lids 并继续。 */
    rc = vty_store_verify(v->store);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    rc = vty_repo_iter_open(v, 0, &it);
    if (rc != VTY_OK) return verthys_api_container_map(rc);

    for (;;) {
        VtyRepoLeaf leaf;
        VtyRepoRecord rec;
        int done = 0;

        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK) break;
        if (done) break;

        memset(&rec, 0, sizeof(rec));
        if (vty_repo_read(v, &leaf, &rec) != VTY_OK) {
            if (out_failed_lids != NULL && failed < max_failed) {
                out_failed_lids[failed] = leaf.record_id;
            }
            failed++;
            continue;
        }
        if (rec.name != NULL) {
            vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        }
        if (rec.data != NULL) vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
    }

    vty_repo_iter_close(it);
    if (rc != VTY_OK) return verthys_api_container_map(rc);
    *out_failed_count = failed;
    return VERTHYS_OK;
}

/* 公共入口接受显式长度；本层按 NUL 终结串取口令，长度不符时复制
 * （不把调用方内存当作 C 字符串直接读取）。 */
char *vty_api_pw_copy(const char *pw, size_t len)
{
    char *copy;

    if (pw == NULL || len == 0) return NULL;
    copy = (char *)malloc(len + 1u);
    if (copy == NULL) return NULL;
    memcpy(copy, pw, len);
    copy[len] = '\0';
    return copy;
}

VerthysResult verthys_api_container_change_password(struct VerthysContext *ctx,
                                             const char *old_pw, size_t old_len,
                                             const char *new_pw, size_t new_len)
{
    VtyVault *v;
    char *old_copy = NULL;
    char *new_copy = NULL;
    int rc;

    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    old_copy = vty_api_pw_copy(old_pw, old_len);
    new_copy = vty_api_pw_copy(new_pw, new_len);
    if (old_copy == NULL || new_copy == NULL) {
        free(old_copy);
        free(new_copy);
        return VERTHYS_ERR_INVALID;
    }

    /* 旧口令先验证：会话已解锁并不代表调用方知道当前口令。 */
    rc = vty_vault_verify_password(v, old_copy);
    if (rc != VTY_OK) {
        verthys_secure_zero(old_copy, old_len);
        verthys_secure_zero(new_copy, new_len);
        free(old_copy);
        free(new_copy);
        return verthys_api_container_map(rc);
    }

    /* 改密只轮换口令/设备槽；恢复码是独立凭据，由 RecoveryRotate 管理。 */
    rc = vty_vault_rotate_password(v, new_copy);
    verthys_secure_zero(old_copy, old_len);
    verthys_secure_zero(new_copy, new_len);
    free(old_copy);
    free(new_copy);
    return verthys_api_container_map(rc);
}

VerthysResult verthys_api_container_flush(struct VerthysContext *ctx)
{
    VtyVault *v;
    int rc;

    if (!vault_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    /* Flush 的持久化对象是“尚无记录变更但目录可能脏”的会话；仓库
     * 每次写已提交，此处再走一次 DataRoot/元数据保存保证幂等落盘。 */
    rc = vty_vault_save(v);
    /* 推迟会话中 Flush 强制推进锚点但保留会话，重置窗口计时；否则
     * 与普通保存一样提交锚点。 */
    if (rc == VTY_OK) rc = vty_vault_bulk_flush(v);
    return verthys_api_container_map(rc);
}

/* ------------------------------------------------------------------ *
 * 共享上下文、口令复制与入口参数校验                                   *
 * ------------------------------------------------------------------ */

struct VerthysContext *vty_api_module_ctx(VerthysHandle handle)
{
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    if (ctx == NULL) return NULL;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return NULL;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER || ctx->vault == NULL) return NULL;
    if (!ctx->vault->unlocked) return NULL;
    return ctx;
}

void vty_api_module_lock_ctx(struct VerthysContext *ctx)
{
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#else
    (void)ctx;
#endif
}

void vty_api_module_unlock_ctx(struct VerthysContext *ctx)
{
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#else
    (void)ctx;
#endif
}

int vty_api_recovery_arg_ok(const char *text, int required)
{
    if (text == NULL || text[0] == '\0') return required ? 0 : 1;
    return strlen(text) <= 256u;
}

int vty_api_module_id_ok(uint32_t module_id)
{
    return module_id < VTY_MODULE_COUNT;
}
