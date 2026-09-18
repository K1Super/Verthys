/*
 * verthys_v3_lifecycle.c — V3 容器生命周期（创建/打开/锁定）+ 运行时上下文
 *
 * 设计依据：
 *   - docs/TARGET_ARCHITECTURE_V5.md §5（密钥层次）/ §6.2（文件布局）/
 *     §6.3（超级块法定人数）/ §10.1（事务协议）
 *   - docs/V3_UPGRADE_PLAYBOOK.md WP-5（校准/并行流水线/进度回调自
 *     v2_lifecycle 迁移）
 *   - docs/UNLOCK_OPTIMIZATION.md §7.2（温缓存写入时机）/ §8（流水线）/
 *     §9（渐进式解锁）/ §11.3（错误处理规范）
 *
 * 创建路径密钥流（与解锁流水线 S2/S3 严格互逆，红线级一致性）：
 *   salt 随机 → 三档校准选参 → MEK = keymanager_derive_master_v3
 *   （Argon2id(pw‖pepper) + HKDF 域分离，与 S2 同函数同参数）→
 *   integrity_key = HKDF(MEK) → A/B/C 随机 + MEK 内核态 wrap
 *   （verthys_cng_km_generate_keyset）→ import_batch 正式导入
 *   （KERNEL_RESIDENT，与 S3 同路径）。
 *   任何参数/标签漂移都将导致"创建可写、解锁失败"——全部经共享常量与
 *   共享函数闭合，无本地复述。
 *
 * 打开路径：verthys_unlock_pipeline_run 全权承担（本文件仅编排薄壳）；
 * 锁定路径：事务收尾 → LSM flush → 温缓存导出/保存 → 子系统销毁。
 *
 * 失败路径资源纪律（§11.3，红线）：
 *   - 创建任一步失败 → subsystems_close（含 CNG 句柄销毁 + 密钥清零），
 *     半写盘面由读侧法定人数 + HMAC + WAL 重放兜底；
 *   - LSM 中止式关闭（verthys_lsm_destroy_abort）：未提交 MemTable 条目
 *     绝不 flush 落 SSTable（rebuild_excluding 仅 MemTable，落表即永久可见）。
 */
#include "verthys_v3_lifecycle.h"
#include "verthys_unlock_pipeline.h"
#include "verthys_warmcache_v3.h"
#include "verthys_io.h"              /* vio_pread64 */
#include "keymanager.h"            /* keymanager_derive_master_v3 */
#include "verthys_pepper.h"
#include "verthys_crypto.h"          /* Argon2 常量 / 校准 */
#include "verthys_api_utils.h"       /* verthys_monotonic_ms */
#include "verthys_rekey_auto.h"      /* ★ WP-6：解锁后自动轮换编排 */

#include <io.h>                    /* _chsize_s / _fileno / _commit */
#include <stdlib.h>
#include <string.h>
#include <time.h>                  /* time（add_record_in_txn 时间戳） */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

/* ---------- Argon2id 三档（迁移自 v2，基准档位编码与 v2 flags[4] 一致） ---------- */

#define VERTHYS_V3_ARGON2_TIER_SECURE       0u
#define VERTHYS_V3_ARGON2_TIER_BALANCED     1u
#define VERTHYS_V3_ARGON2_TIER_PERFORMANCE  2u

/* PERFORMANCE 档固定参数（轻量：32MiB/1/1，交互优先场景） */
#define VERTHYS_V3_ARGON2_PERF_MEM_KIB      32768u
#define VERTHYS_V3_ARGON2_PERF_ITERS        1u
#define VERTHYS_V3_ARGON2_PERF_PARALLEL     1u

/* ================== 上下文分配 / 释放 ================== */

VerthysContextV3 *verthys_v3_ctx_create(VerthysCngKeyManager *km,
                                    FILE *f, const char *verthys_path)
{
    VerthysContextV3 *ctx3;
    size_t path_len;
    char *path_copy = NULL;

    if (km == NULL || f == NULL) return NULL;

    ctx3 = (VerthysContextV3 *)calloc(1, sizeof(*ctx3));
    if (ctx3 == NULL) return NULL;

    if (verthys_path != NULL) {
        path_len = strlen(verthys_path) + 1;
        path_copy = (char *)malloc(path_len);
        if (path_copy == NULL) {
            free(ctx3);
            return NULL;
        }
        memcpy(path_copy, verthys_path, path_len);
    }

    ctx3->f = f;
    ctx3->km = km;
    ctx3->verthys_path = path_copy;
    ctx3->preset = VERTHYS_PRESET_BALANCED;   /* 缺省；创建/解锁时覆写 */
    return ctx3;
}

void verthys_v3_ctx_subsystems_close(VerthysContextV3 *ctx3)
{
    if (ctx3 == NULL) return;

    /* 0. 后台预热线程汇合（MINIMAL_FIRST 场景；线程只读 lsm，
     *    汇合后销毁子系统安全） */
    if (ctx3->bg_preheat_thread != NULL) {
        WaitForSingleObject(ctx3->bg_preheat_thread, INFINITE);
        CloseHandle(ctx3->bg_preheat_thread);
        ctx3->bg_preheat_thread = NULL;
    }
    InterlockedExchange(&ctx3->bg_preheat_running, 0);

    /* 1. 事务上下文（integrity_key 拷贝清零；借用子系统不触碰） */
    verthys_txn_v3_deinit(&ctx3->txn);

    /* 2. 事务 WAL（内存态清零 + 释放堆；不触碰盘面） */
    verthys_wal_destroy(ctx3->wal);
    ctx3->wal = NULL;

    /* 3. LSM——中止式（红线：未提交条目不得落 SSTable，见文件头） */
    verthys_lsm_destroy_abort(ctx3->lsm);
    ctx3->lsm = NULL;

    /* 4. Extent 索引（纯内存态：清零 + 释放） */
    if (ctx3->ext_idx != NULL) {
        verthys_secure_zero(ctx3->ext_idx, sizeof(*ctx3->ext_idx));
        free(ctx3->ext_idx);
        ctx3->ext_idx = NULL;
    }

    /* 5. 分区表（逐条目销毁内核句柄） */
    verthys_partition_table_destroy(&ctx3->ptable);

    /* 6. CNG 密钥组（全部内核句柄销毁，密钥材料不可恢复） */
    if (ctx3->km != NULL) {
        verthys_cng_km_destroy_all(ctx3->km);
    }

    /* 7. 驻留密钥 + 超级块内存态清零 + 状态复位 */
    verthys_secure_zero(ctx3->integrity_key, sizeof(ctx3->integrity_key));
    verthys_secure_zero(&ctx3->sb, sizeof(ctx3->sb));
    ctx3->subsystems_open = 0;
    ctx3->minimal_mode = 0;
    ctx3->preheated = 0;
}

void verthys_v3_ctx_destroy(VerthysContextV3 *ctx3)
{
    if (ctx3 == NULL) return;

    verthys_v3_ctx_subsystems_close(ctx3);

    if (ctx3->verthys_path != NULL) {
        free(ctx3->verthys_path);
        ctx3->verthys_path = NULL;
    }
    verthys_secure_zero(ctx3, sizeof(*ctx3));
    free(ctx3);
}

/* ================== 预设 TLV 编解码 ================== */

VerthysResult verthys_v3_preset_encode(uint8_t *buf, size_t cap,
                                   uint32_t *out_len, VerthysPreset preset)
{
    if (buf == NULL || out_len == NULL || cap < 3) return VERTHYS_ERR_INVALID;
    if ((uint32_t)preset > (uint32_t)VERTHYS_PRESET_CUSTOM) {
        return VERTHYS_ERR_INVALID;
    }
    buf[0] = (uint8_t)VERTHYS_V3_TLV_TAG_PRESET;
    buf[1] = 1u;
    buf[2] = (uint8_t)preset;
    *out_len = 3u;
    return VERTHYS_OK;
}

VerthysResult verthys_v3_preset_decode(const uint8_t *extensions, uint32_t len,
                                   VerthysPreset *out)
{
    if (out == NULL) return VERTHYS_ERR_INVALID;
    *out = VERTHYS_PRESET_BALANCED;           /* 缺省 */
    if (extensions == NULL || len == 0) return VERTHYS_OK;

    uint32_t off = 0;
    while (off < len) {
        uint8_t tag = extensions[off];
        uint8_t vlen;
        if (off + 2u > len) return VERTHYS_ERR_FORMAT;   /* 头部截断 */
        vlen = extensions[off + 1];
        if (off + 2u + (uint32_t)vlen > len) return VERTHYS_ERR_FORMAT; /* len 越界 */

        if (tag == (uint8_t)VERTHYS_V3_TLV_TAG_PRESET) {
            if (vlen != 1u) return VERTHYS_ERR_FORMAT;
            if (extensions[off + 2] > (uint8_t)VERTHYS_PRESET_CUSTOM) {
                return VERTHYS_ERR_FORMAT;
            }
            *out = (VerthysPreset)extensions[off + 2];
            return VERTHYS_OK;
        }
        off += 2u + (uint32_t)vlen;        /* 未知 tag 跳过（前向兼容） */
    }
    return VERTHYS_OK;                       /* 未携带 → 缺省 BALANCED */
}

/* ================== 创建 ================== */

/*
 * 三档校准（迁移自 v2 verthys_v2_create_new，方案 §4.5 精神）：
 *   SECURE      固定 64MiB/3/1（合规确定性，不动态校准）
 *   PERFORMANCE 固定 32MiB/1/1（交互优先）
 *   BALANCED/CUSTOM 32MiB 校准，目标 1200ms，迭代 ∈ [1,3]
 *（失败回退静态默认值，不阻断创建。）
 */
static void v3_argon2_choose_params(VerthysPreset preset,
                                    const char *password, size_t pw_len,
                                    const uint8_t salt[VERTHYS_V3_SALT_BYTES],
                                    uint32_t *mem_kib, uint32_t *iters,
                                    uint32_t *parallel, uint32_t *tier)
{
    switch (preset) {
    case VERTHYS_PRESET_SECURE:
        *mem_kib  = VERTHYS_ARGON2_MEM_KIB;      /* 64MiB */
        *iters    = VERTHYS_ARGON2_ITERS;        /* 3 */
        *parallel = VERTHYS_ARGON2_PARALLEL;     /* 1 */
        *tier     = VERTHYS_V3_ARGON2_TIER_SECURE;
        return;
    case VERTHYS_PRESET_PERFORMANCE:
        *mem_kib  = VERTHYS_V3_ARGON2_PERF_MEM_KIB;
        *iters    = VERTHYS_V3_ARGON2_PERF_ITERS;
        *parallel = VERTHYS_V3_ARGON2_PERF_PARALLEL;
        *tier     = VERTHYS_V3_ARGON2_TIER_PERFORMANCE;
        return;
    default:  /* BALANCED / CUSTOM */
        *mem_kib  = VERTHYS_ARGON2_BALANCED_MEM_KIB;   /* 32MiB */
        *parallel = VERTHYS_ARGON2_BALANCED_PARALLEL;  /* 1 */
        *tier     = VERTHYS_V3_ARGON2_TIER_BALANCED;
        if (verthys_argon2_calibrate((const uint8_t *)password, pw_len,
                                   salt, NULL, *mem_kib,
                                   VERTHYS_ARGON2_CALIBRATE_TARGET_MS,
                                   1u, VERTHYS_ARGON2_BALANCED_ITERS_MAX,
                                   iters) != 0) {
            *iters = VERTHYS_ARGON2_BALANCED_ITERS;   /* 校准失败回退 */
        }
        return;
    }
}

VerthysResult verthys_v3_create_new(VerthysContextV3 *ctx3,
                                const char *password, size_t pw_len,
                                VerthysPreset preset)
{
    uint8_t salt[VERTHYS_V3_SALT_BYTES];
    uint8_t mek[VERTHYS_KEY_BYTES];
    uint8_t mek_copy[VERTHYS_KEY_BYTES];   /* generate_keyset 专用（import 清零原件） */
    uint8_t integrity_key[VERTHYS_KEY_BYTES];
    uint32_t mem_kib = 0, iters = 0, parallel = 0, tier = 0;
    uint64_t t_derive;
    uint32_t derive_ms, calibrate_ms = 0;
    uint32_t ext_len = 0;
    VerthysResult r;
    VerthysCngAead *key_a;
    VerthysCngAead *key_c;
    VerthysPartitionTable ptable;
    VerthysPartition *index_part = NULL;
    VerthysPartition *extent_part = NULL;
    uint8_t probe[8];
    int fresh_guard;

    if (ctx3 == NULL || ctx3->f == NULL || ctx3->km == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (password == NULL && pw_len != 0) return VERTHYS_ERR_INVALID;
    if ((uint32_t)preset > (uint32_t)VERTHYS_PRESET_CUSTOM) {
        return VERTHYS_ERR_INVALID;
    }

    /* 全新文件守卫（纵深防御：正式 TOCTOU 防护由调用方 CREATE_NEW 承担；
     * 此处拒绝在已有 V3 容器上重复创建） */
    fresh_guard = (vio_pread64(ctx3->f, 0, probe, sizeof(probe)) == 0 &&
                   probe[0] == 0x56 && probe[1] == 0x33 &&   /* 'V3' (LE 'V3RP') */
                   probe[2] == 0x52 && probe[3] == 0x50);
    if (fresh_guard) return VERTHYS_ERR_EXISTS;
    if (_fseeki64(ctx3->f, 0, SEEK_SET) != 0) return VERTHYS_ERR_IO;

    ctx3->preset = preset;
    memset(&ptable, 0, sizeof(ptable));

    /* ---- 1. 密钥组前置（pepper / CNG） ---- */
    if (verthys_pepper_init() != 0 || verthys_pepper_source_error()) {
        return VERTHYS_ERR_PEPPER_SOURCE;
    }
    r = verthys_cng_km_init(ctx3->km);
    if (r != VERTHYS_OK) return r;

    /* ---- 2. Argon2id 三档校准（迁移自 v2） ---- */
    verthys_random_bytes(salt, sizeof(salt));
    t_derive = verthys_monotonic_ms();
    v3_argon2_choose_params(preset, password, pw_len, salt,
                            &mem_kib, &iters, &parallel, &tier);
    calibrate_ms = (uint32_t)(verthys_monotonic_ms() - t_derive);

    /* ---- 3. 超级块内存态初始化 + 字段填充 ---- */
    r = vsb_v3_init_new(&ctx3->sb);
    if (r != VERTHYS_OK) goto fail;

    memcpy(ctx3->sb.salt, salt, sizeof(salt));
    ctx3->sb.argon2_mem_kib  = mem_kib;
    ctx3->sb.argon2_iters    = iters;
    ctx3->sb.argon2_parallel = parallel;
    ctx3->sb.argon2_tier     = tier;
    ctx3->sb.pepper_source   = (uint8_t)verthys_pepper_get_source();
    verthys_random_bytes(ctx3->sb.key_a_id, sizeof(ctx3->sb.key_a_id));
    verthys_random_bytes(ctx3->sb.key_b_id, sizeof(ctx3->sb.key_b_id));
    verthys_random_bytes(ctx3->sb.key_c_id, sizeof(ctx3->sb.key_c_id));

    r = verthys_v3_preset_encode(ctx3->sb.extensions,
                               sizeof(ctx3->sb.extensions), &ext_len, preset);
    if (r != VERTHYS_OK) goto fail;
    ctx3->sb.extensions_len = ext_len;

    /* ---- 4. MEK / integrity_key 派生（与解锁 S2/S3 同函数同参数） ---- */
    t_derive = verthys_monotonic_ms();
    if (keymanager_derive_master_v3(mek, (const uint8_t *)password, pw_len,
                                    salt, mem_kib, iters, parallel) != 0) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail;
    }
    derive_ms = (uint32_t)(verthys_monotonic_ms() - t_derive);
    if (keymanager_derive_integrity_key_v3(integrity_key, mek) != 0) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail_zero;
    }
    /* 基准跑分（方案七迁移）：[0]=创建期派生耗时 [1]=校准耗时 */
    ctx3->sb.argon2_benchmark_ms[0] = derive_ms;
    ctx3->sb.argon2_benchmark_ms[1] = calibrate_ms;

    /* ---- 5. 密钥组生成（A/B/C 随机 + MEK 内核态 wrap）+ 正式导入 ----
     * import_key 的 const 契约：入参在导入完成后被清零。generate_keyset
     * 内部临时代入 MEK 会清零入参原件，故传独立副本；import_batch 为
     * 正式导入（原件消耗语义），两份副本各用一次，无驻留窗口放大。 */
    memcpy(mek_copy, mek, sizeof(mek_copy));
    r = verthys_cng_km_generate_keyset(ctx3->km, mek_copy,
                                     ctx3->sb.wrapped_key_a,
                                     (uint32_t)sizeof(ctx3->sb.wrapped_key_a),
                                     ctx3->sb.wrapped_key_b,
                                     (uint32_t)sizeof(ctx3->sb.wrapped_key_b),
                                     ctx3->sb.wrapped_key_c,
                                     (uint32_t)sizeof(ctx3->sb.wrapped_key_c));
    if (r != VERTHYS_OK) goto fail_zero;

    r = verthys_cng_km_import_batch(ctx3->km, mek,
                                  ctx3->sb.wrapped_key_a,
                                  (uint32_t)sizeof(ctx3->sb.wrapped_key_a),
                                  ctx3->sb.wrapped_key_b,
                                  (uint32_t)sizeof(ctx3->sb.wrapped_key_b),
                                  ctx3->sb.wrapped_key_c,
                                  (uint32_t)sizeof(ctx3->sb.wrapped_key_c));
    if (r != VERTHYS_OK) goto fail_zero;

    memcpy(ctx3->integrity_key, integrity_key, VERTHYS_KEY_BYTES);

    /* ---- 6. 文件预分配（超块/分区表/WAL/三分区一次性到位） ---- */
    {
        __int64 end_off = (__int64)(ctx3->sb.audit_partition_offset +
                                    ctx3->sb.audit_partition_size);
        int fd = _fileno(ctx3->f);
        if (_chsize_s(fd, end_off) != 0) {
            r = VERTHYS_ERR_IO;
            goto fail_zero;
        }
        _commit(fd);
    }

    /* ---- 7. 超级块法定人数提交（首版 txid=0） ---- */
    r = vsb_v3_commit_quorum(ctx3->f, &ctx3->sb, integrity_key);
    if (r != VERTHYS_OK) goto fail_zero;

    /* ---- 8. 分区表创建（INDEX/EXTENT/AUDIT，独立随机密钥） ---- */
    key_a = verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_A);
    if (key_a == NULL) {
        r = VERTHYS_ERR_CNG_UNAVAILABLE;
        goto fail_zero;
    }
    r = verthys_partition_table_init(&ptable, 0);
    if (r != VERTHYS_OK) goto fail_zero;
    {
        VerthysPartition p;
        r = verthys_partition_create(&p, 1u, VERTHYS_PARTITION_INDEX,
                                   ctx3->sb.index_partition_offset,
                                   ctx3->sb.index_partition_size,
                                   0u, key_a);
        if (r != VERTHYS_OK) goto fail_ptable;
        r = verthys_partition_table_add(&ptable, &p);
        if (r != VERTHYS_OK) goto fail_ptable;

        r = verthys_partition_create(&p, 2u, VERTHYS_PARTITION_EXTENT,
                                   ctx3->sb.extent_partition_offset,
                                   ctx3->sb.extent_partition_size,
                                   0u, key_a);
        if (r != VERTHYS_OK) goto fail_ptable;
        r = verthys_partition_table_add(&ptable, &p);
        if (r != VERTHYS_OK) goto fail_ptable;

        r = verthys_partition_create(&p, 3u, VERTHYS_PARTITION_AUDIT,
                                   ctx3->sb.audit_partition_offset,
                                   ctx3->sb.audit_partition_size,
                                   0u, key_a);
        if (r != VERTHYS_OK) goto fail_ptable;
        r = verthys_partition_table_add(&ptable, &p);
        if (r != VERTHYS_OK) goto fail_ptable;
    }
    /* 持久化（表帧 AEAD = A 角色语境，与解锁 S4 table_load 一致） */
    r = verthys_partition_table_save(ctx3->f, ctx3->sb.partition_table_offset,
                                   &ptable, key_a);
    if (r != VERTHYS_OK) goto fail_ptable;

    /* 按值移交句柄归属（local ptable 不再 destroy） */
    ctx3->ptable = ptable;
    for (size_t i = 0; i < ctx3->ptable.count; i++) {
        if (ctx3->ptable.entries[i].type == VERTHYS_PARTITION_INDEX) {
            index_part = &ctx3->ptable.entries[i];
        } else if (ctx3->ptable.entries[i].type == VERTHYS_PARTITION_EXTENT) {
            extent_part = &ctx3->ptable.entries[i];
        }
    }
    if (index_part == NULL || extent_part == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail_zero;
    }

    /* ---- 9. 子系统打开（空态初始化，与解锁 S5 同构） ---- */
    ctx3->lsm = verthys_lsm_create();
    if (ctx3->lsm == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail_zero;
    }
    r = verthys_lsm_open(ctx3->lsm, ctx3->f, index_part,
                       index_part->offset, index_part->size, 1);
    if (r != VERTHYS_OK) goto fail_zero;

    key_c = verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_C);
    if (key_c == NULL) {
        r = VERTHYS_ERR_CNG_UNAVAILABLE;
        goto fail_zero;
    }
    ctx3->wal = verthys_wal_create();
    if (ctx3->wal == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail_zero;
    }
    r = verthys_wal_open(ctx3->wal, ctx3->f, VERTHYS_V3_WAL_REGION_OFFSET,
                       key_c, NULL, NULL);
    if (r != VERTHYS_OK) goto fail_zero;

    ctx3->ext_idx = (VerthysExtentIndex *)calloc(1, sizeof(VerthysExtentIndex));
    if (ctx3->ext_idx == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail_zero;
    }
    r = verthys_extent_index_init(ctx3->ext_idx, 0);
    if (r != VERTHYS_OK) goto fail_zero;
    /* 空索引首帧持久化（解锁 S5 extent_index_load 依赖帧存在） */
    r = verthys_extent_index_save(ctx3->f, extent_part->offset,
                                ctx3->ext_idx, extent_part);
    if (r != VERTHYS_OK) goto fail_zero;

    r = verthys_txn_v3_init(&ctx3->txn, ctx3->f, ctx3->wal, &ctx3->sb,
                          ctx3->lsm, ctx3->ext_idx, extent_part,
                          &ctx3->ptable, key_a, integrity_key);
    if (r != VERTHYS_OK) goto fail_zero;

    ctx3->subsystems_open = 1;
    ctx3->preheated = 1;      /* 空容器无 SSTable，预热即完成 */

    verthys_secure_zero(salt, sizeof(salt));
    verthys_secure_zero(mek, sizeof(mek));
    verthys_secure_zero(mek_copy, sizeof(mek_copy));
    verthys_secure_zero(integrity_key, sizeof(integrity_key));
    return VERTHYS_OK;

fail_ptable:
    /* 局部分区表句柄销毁（尚未移交 ctx3） */
    verthys_partition_table_destroy(&ptable);
fail_zero:
    verthys_secure_zero(mek, sizeof(mek));
    verthys_secure_zero(mek_copy, sizeof(mek_copy));
    verthys_secure_zero(integrity_key, sizeof(integrity_key));
fail:
    verthys_secure_zero(salt, sizeof(salt));
    verthys_v3_ctx_subsystems_close(ctx3);
    return r;
}

/* ================== 打开（解锁） ================== */

VerthysResult verthys_v3_open_existing(VerthysContextV3 *ctx3,
                                   const char *password, size_t pw_len,
                                   uint32_t flags,
                                   void (*progress_cb)(uint32_t stage,
                                                       uint32_t percent,
                                                       void *user),
                                   void *progress_user)
{
    VerthysResult r;

    if (ctx3 == NULL) return VERTHYS_ERR_INVALID;
    /* 密码错误退避由上层 Verthys_Unlock 统一处理，本层不感知 */
    r = verthys_unlock_pipeline_run(ctx3, password, pw_len, flags, 0u,
                                  progress_cb, progress_user);

    /* ★ WP-6：解锁成功后自动密钥轮换编排（best-effort 深化，失败吞错
     * ——下次解锁重试）。仅全量解锁路径接线：MINIMAL_FIRST 的后台预热
     * 线程持有 ctx3->f 读姿势，轮换写盘（分区表帧 + 超级块法定人数）
     * 将破坏 FILE* 单写者纪律——顺延至下次非最小解锁（DEGRADE 强制
     * 标志持久化于 TLV，不会因顺延丢失）。 */
    if (r == VERTHYS_OK && !ctx3->minimal_mode) {
        int rotated = 0;
        (void)verthys_rekey_auto_maybe_rotate(ctx3, &rotated);
    }
    return r;
}

/* ================== 锁定 ================== */

VerthysResult verthys_v3_lock(VerthysContextV3 *ctx3)
{
    VerthysResult r_txn = VERTHYS_OK;

    if (ctx3 == NULL) return VERTHYS_ERR_INVALID;
    if (!ctx3->subsystems_open) return VERTHYS_ERR_LOCKED;

    /* 1. 后台预热线程汇合（MINIMAL_FIRST 场景） */
    if (ctx3->bg_preheat_thread != NULL) {
        WaitForSingleObject(ctx3->bg_preheat_thread, INFINITE);
        CloseHandle(ctx3->bg_preheat_thread);
        ctx3->bg_preheat_thread = NULL;
    }
    InterlockedExchange(&ctx3->bg_preheat_running, 0);
    ctx3->minimal_mode = 0;

    /* 2. 事务收尾：COMMITTED → CONFIRM；ACTIVE/PREPARED → 回滚
     *    （错误上抛但不阻断锁定——密钥清除无条件执行） */
    switch (verthys_txn_v3_state(&ctx3->txn)) {
    case VERTHYS_TXN_V3_COMMITTED:
        r_txn = verthys_txn_v3_confirm(&ctx3->txn);
        break;
    case VERTHYS_TXN_V3_ACTIVE:
    case VERTHYS_TXN_V3_PREPARED:
        r_txn = verthys_txn_v3_rollback(&ctx3->txn);
        break;
    default:
        break;  /* IDLE / CONFIRMED / ABORTED：无收尾动作 */
    }

    /* 3. 温缓存（§7.2 时机 1：Lock 同步写；SECURE 跳过并清除残留）。
     *    失败不影响锁定语义（持久化优化，非正确性依赖）。
     *    快照纪律：flush（快照 = 刷盘后空 MemTable）→ export → save。 */
    if (ctx3->lsm != NULL && ctx3->verthys_path != NULL) {
        if (verthys_v3_warmcache_disabled_by_preset(ctx3->preset)) {
            (void)verthys_warmcache_v3_delete(ctx3->verthys_path);
        } else {
            uint8_t *tables_pt = NULL, *memtable_pt = NULL;
            size_t tables_len = 0, memtable_len = 0;

            if (verthys_lsm_flush(ctx3->lsm) == VERTHYS_OK &&
                verthys_lsm_export_warm(ctx3->lsm, &tables_pt, &tables_len,
                                      &memtable_pt, &memtable_len) == VERTHYS_OK) {
                (void)verthys_warmcache_v3_save(ctx3->verthys_path,
                                              ctx3->sb.container_id,
                                              ctx3->sb.txid,
                                              ctx3->integrity_key,
                                              tables_pt, tables_len,
                                              memtable_pt, memtable_len);
            }
            if (tables_pt != NULL) {
                verthys_secure_zero(tables_pt, tables_len);
                free(tables_pt);
            }
            if (memtable_pt != NULL) {
                verthys_secure_zero(memtable_pt, memtable_len);
                free(memtable_pt);
            }
        }
    }

    /* 4. LSM 正常关闭（flush no-op——步骤 3 已刷；Manifest 终态保存） */
    verthys_lsm_destroy(ctx3->lsm);
    ctx3->lsm = NULL;

    /* 5. 其余子系统销毁 + 密钥全量清零（幂等收口） */
    verthys_v3_ctx_subsystems_close(ctx3);

    return r_txn;
}

/* ================== V3 单调用事务收口（★ WP-5：API 编排层共享） ================== */

VerthysResult verthys_v3_txn_finish(VerthysContextV3 *ctx3)
{
    VerthysResult rc;

    if (ctx3 == NULL) return VERTHYS_ERR_INVALID;

    rc = verthys_txn_v3_prepare(&ctx3->txn);
    if (rc != VERTHYS_OK) return rc;
    rc = verthys_txn_v3_commit(&ctx3->txn);
    if (rc != VERTHYS_OK) return rc;
    return verthys_txn_v3_confirm(&ctx3->txn);
}

void verthys_v3_txn_abort(VerthysContextV3 *ctx3)
{
    if (ctx3 == NULL) return;

    switch (verthys_txn_v3_state(&ctx3->txn)) {
    case VERTHYS_TXN_V3_ACTIVE:
    case VERTHYS_TXN_V3_PREPARED:
        (void)verthys_txn_v3_rollback(&ctx3->txn);
        break;
    case VERTHYS_TXN_V3_COMMITTED:
        (void)verthys_txn_v3_confirm(&ctx3->txn);
        break;
    default:
        break;
    }
}

/* ================== V3 单记录事务内写入（★ WP-5：AddRecord / Import 共用） ================== */

VerthysResult verthys_v3_add_record_in_txn(VerthysContextV3 *ctx3,
                                       uint8_t type,
                                       const uint8_t *name, size_t name_len,
                                       const uint8_t *data, size_t data_size,
                                       uint64_t *out_lid)
{
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    VerthysExtent ext;
    VerthysLsmEntry e;
    VerthysResult rc;

    if (ctx3 == NULL || !ctx3->subsystems_open) return VERTHYS_ERR_LOCKED;
    if (verthys_txn_v3_state(&ctx3->txn) != VERTHYS_TXN_V3_ACTIVE) {
        return VERTHYS_ERR_INVALID;
    }
    if (name == NULL && name_len != 0) return VERTHYS_ERR_INVALID;
    if (name_len > VERTHYS_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (data == NULL && data_size != 0) return VERTHYS_ERR_INVALID;

    /* Phase 2：Extent 写入（去重命中零重写；hash 回传供索引条目关联） */
    rc = verthys_txn_v3_write_extent(&ctx3->txn, data, data_size, hash, NULL);
    if (rc != VERTHYS_OK) return rc;

    /* 权威尺寸回查（去重命中共用同一条目；NOTFOUND = 刚写入即不可见，
     * 索引交叉异常 → INTERNAL 而非 NOTFOUND，避免语义误传） */
    rc = verthys_extent_index_find(ctx3->ext_idx, hash, &ext);
    if (rc != VERTHYS_OK) {
        return (rc == VERTHYS_ERR_NOTFOUND) ? VERTHYS_ERR_INTERNAL : rc;
    }

    memset(&e, 0, sizeof(e));
    e.lid            = verthys_lsm_max_lid(ctx3->lsm) + 1;
    e.type           = type;
    e.slot_state     = VERTHYS_SLOT_VALID;   /* 出生即有效（红线修复：
                                            * scan_v3_fetch/summary/find_by_type
                                            * 按 VALID/FREE 过滤，缺省 0=FREE
                                            * 会使全部 V3 记录对扫描不可见） */
    e.name_len       = (uint16_t)name_len;
    e.name           = name;    /* put 内部拷贝（借用） */
    e.data_size      = (uint64_t)data_size;
    e.plaintext_size = ext.plaintext_size;
    e.extent_size    = ext.size;
    memcpy(e.hash, hash, sizeof(hash));
    e.created_time   = (uint64_t)time(NULL);

    /* Phase 3：UPDATE_INDEX（created_txid 由事务层统一置本事务 txid） */
    rc = verthys_txn_v3_update_index(&ctx3->txn, &e);
    if (rc != VERTHYS_OK) return rc;

    if (out_lid != NULL) *out_lid = e.lid;
    return VERTHYS_OK;
}

/* ================== 修改主密码（V3，★ WP-5：ChangePassword 分支） ================== */

/*
 * integrity_key 切换收尾（static）：驻留值 + 事务上下文拷贝同步更新。
 * 前置：事务终态（IDLE/CONFIRMED/ABORTED）——deinit 安全释放 Extent
 * 引用账本后，以原有借用子系统 + 新密钥重建（state 归零回 IDLE）。
 * 失败路径：init 参数全部来自既有存活子系统，仅理论不可达的参数
 * 非法可触发；此时 integrity_key 驻留值已更新而事务上下文失效，
 * 由调用方按致命错误上抛。
 */
static VerthysResult v3_update_integrity_key(VerthysContextV3 *ctx3,
                                            const uint8_t new_key[VERTHYS_KEY_BYTES])
{
    VerthysPartition *extent_part = NULL;
    VerthysCngAead *key_a;
    VerthysResult rc;

    for (size_t i = 0; i < ctx3->ptable.count; i++) {
        if (ctx3->ptable.entries[i].type == VERTHYS_PARTITION_EXTENT) {
            extent_part = &ctx3->ptable.entries[i];
            break;
        }
    }
    key_a = verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_A);
    if (extent_part == NULL || key_a == NULL) return VERTHYS_ERR_INTERNAL;

    memcpy(ctx3->integrity_key, new_key, VERTHYS_KEY_BYTES);
    verthys_txn_v3_deinit(&ctx3->txn);
    rc = verthys_txn_v3_init(&ctx3->txn, ctx3->f, ctx3->wal, &ctx3->sb,
                           ctx3->lsm, ctx3->ext_idx, extent_part,
                           &ctx3->ptable, key_a, new_key);
    return rc;
}

VerthysResult verthys_v3_change_password(VerthysContextV3 *ctx3,
                                      const char *old_pw, size_t old_len,
                                      const char *new_pw, size_t new_len)
{
    uint8_t old_mek[VERTHYS_KEY_BYTES];
    uint8_t new_salt[VERTHYS_V3_SALT_BYTES];
    uint8_t new_mek[VERTHYS_KEY_BYTES];
    uint8_t new_mek_copy[VERTHYS_KEY_BYTES];  /* rotate 专用（rekey 消耗原件） */
    uint8_t new_integrity[VERTHYS_KEY_BYTES];
    uint8_t new_wa[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t new_wb[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t new_wc[VERTHYS_V3_WRAPPED_KEY_BYTES];
    VsbTxnV3 sb_txn;
    VerthysTxnV3State st;
    FILETIME ft;
    ULARGE_INTEGER now;
    VerthysResult r;
    int derive_rc;

    if (ctx3 == NULL) return VERTHYS_ERR_INVALID;
    if (old_pw == NULL && old_len != 0) return VERTHYS_ERR_INVALID;
    if (new_pw == NULL && new_len != 0) return VERTHYS_ERR_INVALID;
    if (!ctx3->subsystems_open) return VERTHYS_ERR_LOCKED;

    /* 事务终态守卫：V3 单调用事务在 API 间隙必为终态；ACTIVE/PREPARED
     * 为编排缺陷（不可静默丢弃用户数据）→ INTERNAL；COMMITTED 幂等
     * 补 confirm 后拒绝本次改密（数据已持久，调用方重试即可）。 */
    st = verthys_txn_v3_state(&ctx3->txn);
    if (st == VERTHYS_TXN_V3_ACTIVE || st == VERTHYS_TXN_V3_PREPARED) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (st == VERTHYS_TXN_V3_COMMITTED) {
        r = verthys_txn_v3_confirm(&ctx3->txn);
        if (r != VERTHYS_OK) return r;
    }

    /* 1. 旧口令验证：V3 域分离派生（超块参数，与解锁 S2 同函数同参数）+
     *    wrapped_key_a 内核态解包试探（AEAD 认证即口令正确——密钥仅
     *    瞬态，无驻留 memcmp）。派生失败同映射解锁 S2 语义。 */
    derive_rc = keymanager_derive_master_v3(old_mek, (const uint8_t *)old_pw,
                                             old_len, ctx3->sb.salt,
                                             ctx3->sb.argon2_mem_kib,
                                             ctx3->sb.argon2_iters,
                                             ctx3->sb.argon2_parallel);
    if (derive_rc == -2) return VERTHYS_ERR_PEPPER_SOURCE;
    if (derive_rc != 0) return VERTHYS_ERR_INTERNAL;

    r = verthys_cng_km_verify_mek(old_mek, ctx3->sb.wrapped_key_a,
                                (uint32_t)sizeof(ctx3->sb.wrapped_key_a));
    /* verify_mek 的 import 失败路径不清零入参（import_key 仅成功清零），
     * 无条件补清覆盖全部分支 */
    verthys_secure_zero(old_mek, sizeof(old_mek));
    if (r == VERTHYS_ERR_AUTH) return VERTHYS_ERR_AUTH;   /* 旧口令错误 */
    if (r != VERTHYS_OK) return r;

    /* 2. 新口令派生：新盐随机；Argon2id 参数沿用超块现值（改密不调档，
     *    与 v2 路径语义一致——参数变更属独立流程）→ 新 MEK + 新
     *    integrity_key。rekey 的 import_key 消耗（清零）new_mek 原件，
     *    rotate_mek 需独立副本（密钥经 import 进入内核后用户态副本
     *    即刻清零，两份副本各用一次，无驻留窗口放大）。 */
    verthys_random_bytes(new_salt, sizeof(new_salt));
    derive_rc = keymanager_derive_master_v3(new_mek, (const uint8_t *)new_pw,
                                             new_len, new_salt,
                                             ctx3->sb.argon2_mem_kib,
                                             ctx3->sb.argon2_iters,
                                             ctx3->sb.argon2_parallel);
    if (derive_rc == 0) {
        derive_rc = keymanager_derive_integrity_key_v3(new_integrity, new_mek);
    }
    if (derive_rc == -2) {
        r = VERTHYS_ERR_PEPPER_SOURCE;
        goto out_zero;
    }
    if (derive_rc != 0) {
        r = VERTHYS_ERR_INTERNAL;
        goto out_zero;
    }
    memcpy(new_mek_copy, new_mek, sizeof(new_mek_copy));

    /* 3. 密钥组重包裹：A/B/C 明文不变仅换 MEK 包装（km 句柄零变更，
     *    失败原子性见 keymanager_cng.h；new_mek 原件被内部消耗清零） */
    r = verthys_cng_km_rekey(ctx3->km, new_mek,
                           ctx3->sb.wrapped_key_a,
                           (uint32_t)sizeof(ctx3->sb.wrapped_key_a),
                           ctx3->sb.wrapped_key_b,
                           (uint32_t)sizeof(ctx3->sb.wrapped_key_b),
                           ctx3->sb.wrapped_key_c,
                           (uint32_t)sizeof(ctx3->sb.wrapped_key_c),
                           new_wa, (uint32_t)sizeof(new_wa),
                           new_wb, (uint32_t)sizeof(new_wb),
                           new_wc, (uint32_t)sizeof(new_wc));
    if (r != VERTHYS_OK) goto out_zero;

    /* 4. 超级块事务（VsbTxnV3）：备份 → 字段变更 → 法定人数原子提交。
     *    HMAC 以新 integrity_key 计算（新口令派生语境）；失败回滚内存
     *    态（盐值/包裹整体恢复改密前——盘面半写由读侧法定人数 +
     *    HMAC 兜底，回滚后 km 仍为旧 MEK 驻留，内存/盘面自洽）。 */
    r = vsb_txn_v3_begin(&sb_txn, &ctx3->sb);
    if (r != VERTHYS_OK) goto out_zero;

    memcpy(ctx3->sb.salt, new_salt, sizeof(new_salt));
    memcpy(ctx3->sb.wrapped_key_a, new_wa, sizeof(new_wa));
    memcpy(ctx3->sb.wrapped_key_b, new_wb, sizeof(new_wb));
    memcpy(ctx3->sb.wrapped_key_c, new_wc, sizeof(new_wc));
    GetSystemTimeAsFileTime(&ft);
    now.LowPart  = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;
    ctx3->sb.updated_at = now.QuadPart;

    r = vsb_txn_v3_commit(&sb_txn, &ctx3->sb, ctx3->f, new_integrity);
    if (r != VERTHYS_OK) {
        (void)vsb_txn_v3_rollback(&sb_txn, &ctx3->sb);
        goto out_zero;
    }

    /* 5. 提交成功收尾：盘面已持新口令语境（回滚不可行）。顺序保证
     *    任一步失败后内存态仍与新盘面 HMAC 自洽。 */
    /* 5.1 integrity_key 先行更新（驻留值 + 事务上下文拷贝）——后续
     *     任何超级块提交（数据事务）必须以新口令语境签名，否则下次
     *     解锁 HMAC 校验失败； */
    r = v3_update_integrity_key(ctx3, new_integrity);
    if (r != VERTHYS_OK) goto out_zero;

    /* 5.2 温缓存失效（HMAC 绑定旧 integrity_key，跨口令必失效）——
     *     best-effort：缓存仅影响启动速度，不影响正确性 */
    if (ctx3->verthys_path != NULL) {
        (void)verthys_warmcache_v3_delete(ctx3->verthys_path);
    }

    /* 5.3 MEK 句柄轮换（旧销毁 → 新导入）：失败仅致 MEK 角色空缺
     *     （运行态 A/B/C 不受影响，下次解锁按新口令重建全组），
     *     错误上抛供上层感知（坦诚直报原则）。 */
    r = verthys_cng_km_rotate_mek(ctx3->km, new_mek_copy);

out_zero:
    verthys_secure_zero(new_salt, sizeof(new_salt));
    verthys_secure_zero(new_mek, sizeof(new_mek));
    verthys_secure_zero(new_mek_copy, sizeof(new_mek_copy));
    verthys_secure_zero(new_integrity, sizeof(new_integrity));
    verthys_secure_zero(new_wa, sizeof(new_wa));
    verthys_secure_zero(new_wb, sizeof(new_wb));
    verthys_secure_zero(new_wc, sizeof(new_wc));
    return r;
}

/* ================== 格式探测 ================== */

int verthys_v3_detect(FILE *f)
{
    uint8_t hdr[8];
    uint32_t magic, plen;

    if (f == NULL) return 0;
    if (vio_pread64(f, 0, hdr, sizeof(hdr)) != 0) {
        (void)_fseeki64(f, 0, SEEK_SET);
        return 0;
    }
    (void)_fseeki64(f, 0, SEEK_SET);

    magic = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
            ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (magic != VERTHYS_V3_REPLICA_FRAME_MAGIC) return 0;

    plen = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
           ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
    if (plen == 0 ||
        plen > VERTHYS_V3_SB_REPLICA_BYTES - 8u) {
        return 0;
    }
    return 1;
}

/* ================== 预设查询 ================== */

int verthys_v3_warmcache_disabled_by_preset(VerthysPreset preset)
{
    return preset == VERTHYS_PRESET_SECURE;
}
