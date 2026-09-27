/*
 * test_v3_lifecycle.c — V3 生命周期验收：全链路 + 解锁流水线 + 温缓存 + WAL 崩溃恢复
 *
 * 验收标准全覆盖：
 *   1. V3 全链路（创建→写→读→删→改密→导出→重开）——公共 API 垂直切片，
 *      含导出/导入合并语义（墓碑不导出、导入 LID 重分配）；
 *   2. 解锁流水线：fail_mask 逐阶段注入（S0-S6 位序）
 *      + MINIMAL_FIRST 渐进式解锁（PARTIAL_UNLOCK 返回 + 数据可操作）；
 *   3. 温缓存：命中（HMAC+txid 双校验通过）/ 未命中（缓存文件缺失）/
 *      损坏回退（载荷篡改 → HMAC 拒绝 → 冷启动，数据无损）；
 *   4. WAL 崩溃注入矩阵（回放规则三分支）：
 *      a. 未提交组（BEGIN/EXTENT/INDEX 后崩溃，无 PREPARE/COMMIT）
 *         → 恢复丢弃（记录不可见，已提交数据不受影响，LID 不复用）；
 *      b. COMMIT 已落笔、CONFIRM 未执行（运行态半途崩溃）
 *         → 恢复重放（数据可见，幂等收尾）；
 *      c. 法定人数已提交、Extent 索引/分区表/WAL COMMIT 未落盘
 *         （PREPARE-only + sb_txid ≥ txid 窗口）
 *         → 恢复重放（EXTENT 按记录补注册 + 索引重放 + 落盘补齐）。
 *
 * 崩溃模拟原理（白盒注入）：verthys_v3_ctx_destroy 为中止式收口——内存态
 * 全灭（密钥清零/内核句柄销毁/MemTable 丢弃），盘面 WAL 半写痕迹原样
 * 保留，与真实进程崩溃的盘面状态等价；重开经解锁流水线 S5 的
 * verthys_txn_v3_recover 按回放规则幂等裁决。拆除后 VerthysContext 复位
 * LOCKED 态（等价应急 DEGRADE 残留实例语义），Verthys_Deinit 安全收口。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"          /* VerthysContext / VerthysState */
#include "verthys_api_utils.h"         /* verthys_backoff_reset（跨测试清退避记账） */
#include "verthys_v3_lifecycle.h"       /* VerthysContextV3 / 事务共享骨架 */
#include "verthys_unlock_pipeline.h"   /* verthys_unlock_pipeline_run / UnlockStage */
#include "verthys_container_v3.h"      /* VsbTxnV3 / vsb_txn_v3_* */
#include "verthys_wal.h"               /* verthys_wal_head/tail_offset */
#include "verthys_io.h"                /* vio_pread64/pwrite64（篡改注入） */
#include "verthys_lsm.h"               /* verthys_lsm_preheat_full_ex（预热中断契约） */

#include <string.h>
#include <stdio.h>

#define V3L_VERTHYS  "test_v3life.verthys"
#define V3L_CACHE  "test_v3life.verthys.idx_cache"
#define V3L_EXPORT "test_v3life_export.verthys"
#define V3L_IMP    "test_v3life_imp.verthys"
#define V3L_PW     "v3life-pass"
#define V3L_PW_LEN 11

static void v3life_cleanup(void)
{
    remove(V3L_VERTHYS);
    remove(V3L_CACHE);
    remove(V3L_EXPORT);
    remove(V3L_IMP);
}

/*
 * 崩溃模拟：以"进程在事务中途死亡"语义拆除 V3 上下文。
 * verthys_v3_ctx_destroy → verthys_v3_ctx_subsystems_close 为中止式收口
 * （WAL/LSM/Extent 索引均不触碰盘面）——盘面保留崩溃现场。
 * 拆除后 ctx 复位 LOCKED（v3 残留指针清除 + 文件句柄关闭），
 * 后续 Verthys_Deinit 走 LOCKED 态收口路径。
 */
static void v3life_crash_abort(struct VerthysContext *ctx)
{
    VerthysContextV3 *v3 = ctx->v3;
    FILE *f = v3->f;

    ctx->v3 = NULL;
    ctx->state = VERTHYS_STATE_LOCKED;
    verthys_v3_ctx_destroy(v3);    /* 中止式：盘面 WAL 半写保留 */
    if (f != NULL) fclose(f);
}

/*
 * 造一个已锁定的 V3 容器（count 条记录，PERFORMANCE 预设——固定
 * Argon2id 参数，测试时延可控；记录内容 = "data-<i>"）。
 * out_ids 可为 NULL；返回 0 成功。
 */
static int v3life_make_locked(const char *path, const char *pw, size_t pw_len,
                              VerthysPreset preset, size_t count,
                              uint64_t *out_ids)
{
    VerthysHandle h;
    VerthysRecord out;
    char name[16];
    uint8_t data[32];

    v3life_cleanup();
    if (Verthys_Init(&h) != VERTHYS_OK) return -1;
    if (Verthys_CreateWithPreset(h, path, pw, pw_len, preset) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        uint64_t id = 0;
        int n = sprintf_s(name, sizeof(name), "rec-%zu", i);
        int d = sprintf_s((char *)data, sizeof(data), "data-%zu", i);
        VerthysRecord r = {VERTHYS_RECORD_ACCOUNT,
                         name, (size_t)n, data, (size_t)d};
        if (Verthys_AddRecord(h, &r, &id) != VERTHYS_OK || id == 0) {
            Verthys_Deinit(h);
            return -1;
        }
        if (out_ids != NULL) out_ids[i] = id;
    }
    if (count > 0) {
        /* 写路径冒烟：提交后立即可读（MemTable 就绪） */
        if (Verthys_GetRecord(h, out_ids[0], &out) != VERTHYS_OK) {
            Verthys_Deinit(h);
            return -1;
        }
    }
    if (Verthys_Lock(h) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    Verthys_Deinit(h);
    return 0;
}

/* ================== 1. V3 全链路（验收主链） ================== */

/*
 * 创建(BALANCED 三档校准) → 写×2 → 读 → 删 → 改密 → 锁 → 新口令重开 →
 * 读(数据经改密/重开仍完整) → 导出(独立口令) → 导入第二容器(批量单事务)。
 */
TEST(v3life_full_chain_roundtrip)
{
    VerthysHandle h;
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "gmail", 5,
                      (const uint8_t *)"pass123", 7};
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "bank", 4,
                      (const uint8_t *)"secret99", 8};
    uint64_t id1 = 0, id2 = 0;
    VerthysRecord out;
    const char *new_pw = "new-master-pw";

    v3life_cleanup();
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 创建：唯一合法新建入口 → V3 编排（校准 + 密钥组 + 法定人数首版） */
    CHECK_EQ(Verthys_CreateWithPreset(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                    VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 写：六阶段单调用事务，LID 顺序分配（max_lid + 1，不复用） */
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);
    CHECK(id1 > 0);
    CHECK_EQ(id2, id1 + 1);

    /* 读：MemTable 命中 + Extent 按需解密 */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK_EQ(out.type, VERTHYS_RECORD_ACCOUNT);
    CHECK_EQ(out.name_len, 5u);
    CHECK(memcmp(out.name, "gmail", 5) == 0);
    CHECK_EQ(out.data_len, 7u);
    CHECK(memcmp(out.data, "pass123", 7) == 0);

    /* 删：单调用事务（墓碑遮蔽） */
    CHECK_EQ(Verthys_DeleteRecord(h, id1), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_ERR_NOTFOUND);
    CHECK_EQ(Verthys_GetRecord(h, id2, &out), VERTHYS_OK);   /* 幸存者不受影响 */

    /* 改密：重派生 + A/B/C 重包裹 + 法定人数原子提交 */
    CHECK_EQ(Verthys_ChangePassword(h, V3L_PW, V3L_PW_LEN,
                                  new_pw, strlen(new_pw)), VERTHYS_OK);
    /* 改密后运行态数据可读（km 句柄轮换 + integrity_key 语境切换） */
    CHECK_EQ(Verthys_GetRecord(h, id2, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "secret99", 8) == 0);

    /* 锁 → 新口令重开：S1-S4 以新口令派生语境闭环（CP 提交顺序验证） */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, new_pw, strlen(new_pw), 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id2, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "secret99", 8) == 0);

    /* 导出：v1 跨设备格式 + 独立口令（墓碑不导出——快照迭代器语义） */
    CHECK_EQ(Verthys_Export(h, V3L_EXPORT, "exp-pw", 6), VERTHYS_OK);
    Verthys_Deinit(h);

    /* 导入第二容器：单事务批量合并，LID 在目标容器重新分配 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, V3L_IMP, V3L_PW, V3L_PW_LEN,
                                    VERTHYS_PRESET_PERFORMANCE), VERTHYS_OK);
    CHECK_EQ(Verthys_Import(h, V3L_EXPORT, "exp-pw", 6), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, 1, &out), VERTHYS_OK);     /* 唯一幸存记录 → LID 1 */
    CHECK(memcmp(out.data, "secret99", 8) == 0);
    CHECK_EQ(Verthys_GetRecord(h, 2, &out), VERTHYS_ERR_NOTFOUND);  /* 删除记录不复活 */

    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * 改密后旧口令必须失效：旧口令解锁 → AUTH（进程级退避记账随之
 * 开启，测试内主动清零）；新口令解锁 → OK 且数据完整。
 */
TEST(v3life_cp_old_password_rejected)
{
    VerthysHandle h;
    VerthysRecord out;
    uint64_t ids[1] = {0};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    /* 改密（解锁态操作） */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_ChangePassword(h, V3L_PW, V3L_PW_LEN, "rotated-pw", 11), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);

    /* 旧口令 → AUTH（wrapped_key_a 已绑定新口令语境）；
     * AUTH 记账为进程级，主动清零避免退避窗口拦截下步验证 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_ERR_AUTH);
    verthys_backoff_reset();
    Verthys_Deinit(h);

    /* 新口令 → OK + 数据完整 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, "rotated-pw", 11, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    Verthys_Deinit(h);

    v3life_cleanup();
    return 0;
}

/* ================== 1b. 收尾：GetContainerInfo / VerifyIntegrity V3 ================== */

/*
 * GetContainerInfo V3 分支（超级块/LSM/分区表现值直读）：
 *   - fmt_version=3 / preset 回显 / record_count 与 LSM 现值一致（删除递减）；
 *   - 分区容量与已用字节非零；last_modified_time 为可信 Unix 秒；
 *   - container_id（32B 截前 16B）非全零；V3 无记账字段如实为 0
 *     （mount_count / cumulative_write_bytes / merkle_pending）；
 *   - VerifyIntegrity 成功后 last_fullscan_time 由 0 转 >0；
 *   - 参数与状态契约：NULL 参 → INVALID；LOCKED 态 → LOCKED。
 */
TEST(v3life_container_info_v3)
{
    VerthysHandle h;
    VerthysContainerInfo info;
    uint64_t ids[3] = {0, 0, 0};
    uint64_t failed_count = 0;
    int id_nonzero = 0;

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 3, ids), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 参数契约（锁定态下一并验证 NULL 参优先） */
    CHECK_EQ(Verthys_GetContainerInfo(NULL, &info), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_GetContainerInfo(h, NULL), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_VerifyIntegrity(NULL, NULL, 0, &failed_count),
             VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_VerifyIntegrity(h, NULL, 0, NULL), VERTHYS_ERR_INVALID);

    /* 锁定态：版本头部可读（加载方预检语义），其余字段如实归零 */
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.api_version, VERTHYS_API_VERSION);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_V3);
    CHECK_EQ(info.record_count, 0u);
    CHECK_EQ(Verthys_VerifyIntegrity(h, NULL, 0, &failed_count), VERTHYS_ERR_LOCKED);

    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.api_version, VERTHYS_API_VERSION);
    CHECK_EQ(info.fmt_version, 3u);
    CHECK_EQ(info.preset, (uint16_t)VERTHYS_PRESET_PERFORMANCE);
    CHECK_EQ(info.record_count, 3u);
    CHECK(info.txid > 0);                    /* sb.txid 现值（创建+3 事务） */
    CHECK(info.index_region_size > 0);       /* sb.index_partition_size */
    CHECK(info.data_region_size > 0);        /* sb.extent_partition_size */
    CHECK(info.data_used_bytes > 0);         /* Extent 分区 used（3 条已写） */
    CHECK(info.last_modified_time > UINT64_C(1600000000)); /* 可信 Unix 秒 */
    CHECK_EQ(info.last_fullscan_time, 0u);   /* 尚未执行全量校验 */
    CHECK_EQ(info.merkle_pending, 0u);       /* V3 无后台重建窗口 */
    CHECK_EQ(info.mount_count, 0u);          /* V3 无挂载记账（如实 0） */
    for (int i = 0; i < 16; i++) {
        if (info.container_id[i] != 0) { id_nonzero = 1; break; }
    }
    CHECK(id_nonzero);

    /* 删除后 record_count 现值递减（非解锁时快照） */
    CHECK_EQ(Verthys_DeleteRecord(h, ids[0]), VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.record_count, 2u);

    /* 全量校验成功 → last_fullscan_time 翻转 */
    CHECK_EQ(Verthys_VerifyIntegrity(h, NULL, 0, &failed_count), VERTHYS_OK);
    CHECK_EQ(failed_count, 0u);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK(info.last_fullscan_time > 0);

    Verthys_Lock(h);
    /* 锁定态：版本头部仍可读，统计归零（预检语义） */
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_V3);
    CHECK_EQ(info.record_count, 0u);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * VerifyIntegrity V3 分支（LSM 快照遍历 + Extent 双重完整性）：
 *   - 干净容器 → VERTHYS_OK + failed_count=0；
 *   - 白盒翻转 ids[1] Extent 密文一字节 → GetRecord 即 AUTH，
 *     VerifyIntegrity 返回 VERTHYS_OK 且精确上报该 LID（检查类惯例）；
 *   - 幸存记录不受影响（ids[0] 仍可读）。
 */
TEST(v3life_verify_integrity_tamper)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    uint64_t ids[3] = {0, 0, 0};
    uint64_t failed[4] = {0, 0, 0, 0};
    uint64_t failed_count = 0;
    VerthysRecord out;
    VerthysLsmEntry e;
    VerthysExtent ext;
    uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
    size_t name_len = 0;
    uint8_t byte = 0;
    uint64_t abs_off;

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 3, ids), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);

    /* 干净容器：校验通过，零损坏 */
    CHECK_EQ(Verthys_VerifyIntegrity(h, failed, 4, &failed_count), VERTHYS_OK);
    CHECK_EQ(failed_count, 0u);

    /* 白盒定位 ids[1] 的 Extent（LSM 现值哈希 → 索引条目 → 绝对偏移） */
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open);
    CHECK_EQ(verthys_lsm_get(v3->lsm, ids[1], &e,
                           name_buf, sizeof(name_buf), &name_len), VERTHYS_OK);
    CHECK_EQ(verthys_extent_index_find(v3->ext_idx, e.hash, &ext), VERTHYS_OK);
    abs_off = v3->sb.extent_partition_offset + VERTHYS_EXTENT_INDEX_REGION_BYTES
              + ext.offset + (ext.size / 2);   /* 密文体中部，必破 AEAD */

    /* 读-翻转-写（会话句柄直写，deny-none 共享语义允许） */
    CHECK_EQ(vio_pread64(v3->f, abs_off, &byte, 1), 0);
    byte ^= 0xFF;
    CHECK_EQ(vio_pwrite64(v3->f, abs_off, &byte, 1), 0);
    CHECK_EQ(fflush(v3->f), 0);

    /* 读路径先拒绝：AEAD 认证失败 */
    CHECK_EQ(Verthys_GetRecord(h, ids[1], &out), VERTHYS_ERR_AUTH);

    /* 校验类惯例：整体 VERTHYS_OK + 精确上报损坏 LID */
    memset(failed, 0, sizeof failed);
    failed_count = 0;
    CHECK_EQ(Verthys_VerifyIntegrity(h, failed, 4, &failed_count), VERTHYS_OK);
    CHECK_EQ(failed_count, 1u);
    CHECK_EQ(failed[0], ids[1]);

    /* 幸存记录不受影响 */
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    Verthys_Lock(h);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * V3 扫描家族回归（slot_state 出生值红线修复的验收）：
 * 修复前 V3 条目 slot_state 缺省 0（=VERTHYS_SLOT_FREE），而
 * scan_v3_fetch（要求 VALID）/ scan_v3_summary_fetch 与
 * scan_v3_find_by_type（跳过 FREE）全部过滤——V3 下全量扫描、
 * 摘要扫描、类型查找一律空转（零记录/假阴性），且历史测试零覆盖。
 *
 * 矩阵（锁定重开后跑——条目已 flush 入 SSTable，跨 MemTable/SSTable
 * 两级数据源验证）：
 *   - GetSummaryCount / GetContainerInfo.record_count 同源同值；
 *   - ScanSummaryOpen/Fetch：批量分页（2+1）、lid 升序、墓碑不可见、
 *     start_lid 定位、元数据（type/name/data_size）正确；
 *   - ScanOpen/Fetch：完整解密数据正确；
 *   - HasRecordByType / FindFirstLidByType：命中 + 最小 lid + 空类型
 *     假阴性消除。
 */
TEST(v3life_scan_family_v3)
{
    VerthysHandle h;
    uint64_t ids[4] = {0, 0, 0, 0};
    VerthysScanCursor *cur = NULL;
    VerthysSummaryRecord srecs[4];
    uint64_t slids[4];
    uint64_t scount = 0;
    VerthysRecord frecs[4];
    uint64_t flids[4];
    uint64_t fcount = 0;
    uint64_t ffailed = 0;
    uint8_t found = 0;
    uint64_t first_lid = 0;
    size_t got = 0;

    v3life_cleanup();
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                    VERTHYS_PRESET_PERFORMANCE), VERTHYS_OK);
    {
        struct { uint8_t type; const char *name; const char *data; } defs[4] = {
            {VERTHYS_RECORD_ACCOUNT,     "acc-0",   "account-zero"},
            {VERTHYS_RECORD_ACCOUNT,     "acc-1",   "account-one"},
            {VERTHYS_RECORD_PHOTO,       "photo",   "photo-bytes"},
            {VERTHYS_RECORD_CERT_MANAGER,"cert",    "cert-blob"},
        };
        for (int i = 0; i < 4; i++) {
            VerthysRecord r = {(VerthysRecordType)defs[i].type, defs[i].name,
                             strlen(defs[i].name),
                             (const uint8_t *)defs[i].data,
                             strlen(defs[i].data)};
            CHECK_EQ(Verthys_AddRecord(h, &r, &ids[i]), VERTHYS_OK);
        }
    }
    CHECK_EQ(Verthys_DeleteRecord(h, ids[1]), VERTHYS_OK);   /* 删 acc-1（墓碑） */

    /* 锁定重开：MemTable → SSTable（VALID 状态随条目持久化） */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);

    /* 计数同源：GetSummaryCount == record_count == 3（墓碑不计） */
    CHECK_EQ(Verthys_GetSummaryCount(h, &scount), VERTHYS_OK);
    CHECK_EQ(scount, 3u);
    {
        VerthysContainerInfo info;
        CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
        CHECK_EQ(info.record_count, 3u);
    }

    /* 摘要扫描：max_count=2 分页（2 + 1 + 0），lid 升序，acc-1 不可见 */
    CHECK_EQ(Verthys_ScanSummaryOpen(h, 1, 2, &cur), VERTHYS_OK);
    memset(srecs, 0, sizeof(srecs));
    CHECK_EQ(Verthys_ScanSummaryFetch(cur, srecs, slids, 2, &scount), VERTHYS_OK);
    CHECK_EQ(scount, 2u);
    CHECK_EQ(Verthys_ScanSummaryFetch(cur, srecs + 2, slids + 2, 2, &scount), VERTHYS_OK);
    CHECK_EQ(scount, 1u);
    CHECK_EQ(Verthys_ScanSummaryFetch(cur, srecs + 3, slids + 3, 2, &scount), VERTHYS_OK);
    CHECK_EQ(scount, 0u);                       /* 耗尽 */
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;
    got = 0;
    for (size_t i = 0; i < 3; i++) {
        CHECK(slids[i] != ids[1]);              /* 墓碑不可见 */
        if (i > 0) CHECK(slids[i] > slids[i - 1]);   /* lid 升序 */
        CHECK_EQ(srecs[i].slot_state, (uint8_t)VERTHYS_SLOT_VALID);
        CHECK_EQ(srecs[i].data_size,
                 (uint64_t)strlen(srecs[i].lid == ids[2] ? "photo-bytes"
                              : srecs[i].lid == ids[3] ? "cert-blob"
                              : "account-zero"));
        CHECK(srecs[i].name_len > 0 && srecs[i].name != NULL);
        CHECK_EQ(Verthys_ScanSummaryRecordFree(&srecs[i]), VERTHYS_OK);
        got++;
    }
    CHECK_EQ(got, 3u);
    CHECK_EQ(slids[0], ids[0]);                 /* 首条 = acc-0 */
    CHECK_EQ(srecs[0].type, (uint8_t)VERTHYS_RECORD_ACCOUNT);

    /* start_lid 定位：从 photo 起 → 仅 photo + cert */
    CHECK_EQ(Verthys_ScanSummaryOpen(h, ids[2], 10, &cur), VERTHYS_OK);
    CHECK_EQ(Verthys_ScanSummaryFetch(cur, srecs, slids, 4, &scount), VERTHYS_OK);
    CHECK_EQ(scount, 2u);
    CHECK_EQ(slids[0], ids[2]);
    CHECK_EQ(slids[1], ids[3]);
    for (size_t i = 0; i < 2; i++) {
        CHECK_EQ(Verthys_ScanSummaryRecordFree(&srecs[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* 全量解密扫描：数据内容逐字节正确 */
    CHECK_EQ(Verthys_ScanOpen(h, 1, 10, &cur), VERTHYS_OK);
    memset(frecs, 0, sizeof(frecs));
    CHECK_EQ(Verthys_ScanFetch(cur, frecs, flids, 4, &fcount, NULL, &ffailed),
             VERTHYS_OK);
    CHECK_EQ(fcount, 3u);
    CHECK_EQ(ffailed, 0u);
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;
    for (size_t i = 0; i < 3; i++) {
        if (flids[i] == ids[0]) {
            CHECK_EQ(frecs[i].data_len, 12u);
            CHECK(memcmp(frecs[i].data, "account-zero", 12) == 0);
        } else if (flids[i] == ids[2]) {
            CHECK_EQ(frecs[i].data_len, 11u);
            CHECK(memcmp(frecs[i].data, "photo-bytes", 11) == 0);
        } else if (flids[i] == ids[3]) {
            CHECK_EQ(frecs[i].data_len, 9u);
            CHECK(memcmp(frecs[i].data, "cert-blob", 9) == 0);
        } else {
            CHECK(0);   /* 未知 LID = 扫描泄漏 */
        }
        CHECK_EQ(Verthys_ScanRecordFree(&frecs[i]), VERTHYS_OK);
    }

    /* 类型查找：命中 + 最小 lid + 空类型假阴性消除 */
    CHECK_EQ(Verthys_HasRecordByType(h, VERTHYS_RECORD_ACCOUNT, &found), VERTHYS_OK);
    CHECK_EQ(found, 1);
    CHECK_EQ(Verthys_FindFirstLidByType(h, VERTHYS_RECORD_ACCOUNT, &found,
                                      &first_lid), VERTHYS_OK);
    CHECK_EQ(found, 1);
    CHECK_EQ(first_lid, ids[0]);    /* acc-1 已删 → 首条 ACCOUNT = acc-0 */
    CHECK_EQ(Verthys_HasRecordByType(h, VERTHYS_RECORD_FILE_VERTHYS, &found), VERTHYS_OK);
    CHECK_EQ(found, 0);             /* 不存在类型：明确不命中 */

    Verthys_Lock(h);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * 扫描投影与取批预算（Verthys_ScanOpenEx）：
 *
 * 矩阵：
 *   - INDEX 投影 + 内联阈值：不超过阈值的记录解密并返回数据，超过阈值的
 *     记录仍按序返回索引条目（data=NULL/data_len=0）——"只取索引"的调用
 *     不再为 MB 级载荷付出解密与内存代价；
 *   - INDEX + 阈值 0：纯索引（任何记录都不附带数据）；
 *   - 取批预算：累计输出字节（名称 + 数据）达预算即提前收批，续批不丢
 *     条目、不重复遍历（游标停在未取记录之前）；
 *   - FULL 投影与既有 Verthys_ScanOpen 等价（全部记录完整解密）；
 *   - 未知投影取值拒绝（INVALID）。
 */
#define V3LP_SMALL_LEN  16
#define V3LP_BIG_LEN    4096
#define V3LP_INLINE     64      /* 内联阈值：小记录（16B）命中，大记录（4096B）超出 */
#define V3LP_RECS       5

TEST(v3life_scan_projection)
{
    VerthysHandle h;
    uint64_t ids[V3LP_RECS] = {0};
    VerthysScanCursor *cur = NULL;
    VerthysRecord recs[V3LP_RECS];
    uint64_t lids[V3LP_RECS];
    uint64_t count = 0;
    uint64_t failed = 0;
    uint8_t small[V3LP_SMALL_LEN];
    uint8_t big[V3LP_BIG_LEN];
    char name[8];
    size_t i;

    v3life_cleanup();
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                      VERTHYS_PRESET_PERFORMANCE), VERTHYS_OK);

    /* 交替大小记录：小-大-小-大-小（内容含序号，避免内容寻址去重合并） */
    memset(small, 0x41, sizeof(small));
    memset(big, 0x42, sizeof(big));
    for (i = 0; i < V3LP_RECS; i++) {
        VerthysRecord r;
        int is_small = (i % 2) == 0;
        snprintf(name, sizeof(name), "sp-%u", (unsigned)i);
        r.type     = VERTHYS_RECORD_ACCOUNT;
        r.name     = name;
        r.name_len = strlen(name);
        if (is_small) {
            small[0] = (uint8_t)(0x30 + i);
            r.data     = small;
            r.data_len = sizeof(small);
        } else {
            big[0] = (uint8_t)(0x30 + i);
            r.data     = big;
            r.data_len = sizeof(big);
        }
        CHECK_EQ(Verthys_AddRecord(h, &r, &ids[i]), VERTHYS_OK);
    }

    /* === 1. INDEX 投影 + 内联阈值：大记录只回索引，小记录回数据 === */
    CHECK_EQ(Verthys_ScanOpenEx(h, 1, 10, VERTHYS_SCAN_PROJECT_INDEX,
                                V3LP_INLINE, 0, &cur), VERTHYS_OK);
    memset(recs, 0, sizeof(recs));
    CHECK_EQ(Verthys_ScanFetch(cur, recs, lids, 10, &count, NULL, &failed),
             VERTHYS_OK);
    CHECK_EQ(count, (uint64_t)V3LP_RECS);
    CHECK_EQ(failed, 0u);
    for (i = 0; i < V3LP_RECS; i++) {
        int is_small = (i % 2) == 0;
        CHECK_EQ(lids[i], ids[i]);                       /* 顺序与写入一致 */
        CHECK_EQ(recs[i].type, (VerthysRecordType)VERTHYS_RECORD_ACCOUNT);
        CHECK(recs[i].name != NULL);
        CHECK(memcmp(recs[i].name, "sp-", 3) == 0);
        CHECK_EQ((int)recs[i].name[3], (int)('0' + i));
        if (is_small) {
            CHECK_EQ(recs[i].data_len, (size_t)V3LP_SMALL_LEN);
            CHECK(recs[i].data != NULL);
            CHECK_EQ((int)recs[i].data[0], (int)(0x30 + i));  /* 序号字节 */
            CHECK_EQ((int)recs[i].data[1], 0x41);             /* 填充字节未被改写 */
            CHECK_EQ((int)recs[i].data[V3LP_SMALL_LEN - 1], 0x41);
        } else {
            /* 超阈值：不解密、不分配，仅索引条目 */
            CHECK(recs[i].data == NULL);
            CHECK_EQ(recs[i].data_len, (size_t)0);
        }
        CHECK_EQ(Verthys_ScanRecordFree(&recs[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanFetch(cur, recs, lids, 10, &count, NULL, &failed),
             VERTHYS_OK);
    CHECK_EQ(count, 0u);                                 /* 已耗尽 */
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* === 2. INDEX + 阈值 0：纯索引（任何记录都不附带数据） === */
    CHECK_EQ(Verthys_ScanOpenEx(h, 1, 10, VERTHYS_SCAN_PROJECT_INDEX,
                                0, 0, &cur), VERTHYS_OK);
    memset(recs, 0, sizeof(recs));
    CHECK_EQ(Verthys_ScanFetch(cur, recs, lids, 10, &count, NULL, &failed),
             VERTHYS_OK);
    CHECK_EQ(count, (uint64_t)V3LP_RECS);
    for (i = 0; i < V3LP_RECS; i++) {
        CHECK(recs[i].data == NULL);
        CHECK_EQ(recs[i].data_len, (size_t)0);
        CHECK(recs[i].name != NULL);
        CHECK_EQ(Verthys_ScanRecordFree(&recs[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* === 3. 取批预算截批（软水位线）：续批不丢条目、不重复 === */
    /* 每批输出字节 = 名称(4) + 数据（小记录 16 / 大记录 0）
     * 序列 20,4,20,4,20；预算 40 → 越过预算即收批：
     *   首批 20+4+20 = 44（第 3 条越过 40 后收批），次批 4+20 = 24（遍历自然结束） */
    CHECK_EQ(Verthys_ScanOpenEx(h, 1, 10, VERTHYS_SCAN_PROJECT_INDEX,
                                V3LP_INLINE, 40, &cur), VERTHYS_OK);
    {
        uint64_t seen = 0;
        uint64_t seq = 0;
        int round;
        for (round = 0; round < 3; round++) {
            uint64_t got = 0;
            memset(recs, 0, sizeof(recs));
            CHECK_EQ(Verthys_ScanFetch(cur, recs, lids, 10, &got, NULL, &failed),
                     VERTHYS_OK);
            if (round == 0)      CHECK_EQ(got, 3u);
            else if (round == 1) CHECK_EQ(got, 2u);
            else                 CHECK_EQ(got, 0u);
            for (i = 0; i < got; i++) {
                CHECK_EQ(lids[i], ids[seq]);             /* 严格按序推进，无重复 */
                seq++;
                seen++;
                CHECK_EQ(Verthys_ScanRecordFree(&recs[i]), VERTHYS_OK);
            }
        }
        CHECK_EQ(seen, (uint64_t)V3LP_RECS);             /* 批次合计 = 全部记录 */
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* === 4. FULL 投影与既有入口等价：全部记录完整解密 === */
    CHECK_EQ(Verthys_ScanOpenEx(h, 1, 10, VERTHYS_SCAN_PROJECT_FULL,
                                0, 0, &cur), VERTHYS_OK);
    memset(recs, 0, sizeof(recs));
    CHECK_EQ(Verthys_ScanFetch(cur, recs, lids, 10, &count, NULL, &failed),
             VERTHYS_OK);
    CHECK_EQ(count, (uint64_t)V3LP_RECS);
    for (i = 0; i < V3LP_RECS; i++) {
        int is_small = (i % 2) == 0;
        CHECK_EQ(recs[i].data_len,
                 is_small ? (size_t)V3LP_SMALL_LEN : (size_t)V3LP_BIG_LEN);
        CHECK(recs[i].data != NULL);
        CHECK_EQ((int)recs[i].data[0], (int)(0x30 + i));
        CHECK_EQ(Verthys_ScanRecordFree(&recs[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    CHECK_EQ(Verthys_ScanOpen(h, 1, 10, &cur), VERTHYS_OK);
    memset(recs, 0, sizeof(recs));
    CHECK_EQ(Verthys_ScanFetch(cur, recs, lids, 10, &count, NULL, &failed),
             VERTHYS_OK);
    CHECK_EQ(count, (uint64_t)V3LP_RECS);
    for (i = 0; i < V3LP_RECS; i++) {
        CHECK(recs[i].data_len > 0);                     /* 既有入口仍是全量解密 */
        CHECK_EQ(Verthys_ScanRecordFree(&recs[i]), VERTHYS_OK);
    }
    CHECK_EQ(Verthys_ScanClose(cur), VERTHYS_OK);
    cur = NULL;

    /* === 5. 未知投影取值：拒绝而非静默按 FULL 处理 === */
    CHECK_EQ(Verthys_ScanOpenEx(h, 1, 10, (VerthysScanProject)7,
                                0, 0, &cur), VERTHYS_ERR_INVALID);
    CHECK(cur == NULL);

    Verthys_Lock(h);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * fail_mask 逐阶段注入（bit i = 阶段 i 强制失败）：
 *   - 整体返回 INTERNAL（注入语义约定）；
 *   - 阶段结果记录命中（S1-S6；S0 失败先于结果记录，仅验证返回值）；
 *   - 失败路径资源纪律：subsystems_open == 0（可重试初态）。
 * 每轮独立句柄 + 手工装配 VerthysContextV3（镜像 verthys_api_v3_unlock
 * 编排：ctx_create → pipeline_run → destroy + fclose）。
 */
TEST(v3life_pipeline_fail_mask_stages)
{
    uint64_t ids[1] = {0};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    for (unsigned stage = 0; stage < UNLOCK_STAGE_COUNT; stage++) {
        VerthysHandle h;
        struct VerthysContext *ctx;
        FILE *f = NULL;
        VerthysContextV3 *v3;
        VerthysResult rc;

        CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
        ctx = (struct VerthysContext *)h;

        fopen_s(&f, V3L_VERTHYS, "r+b");
        CHECK(f != NULL);
        v3 = verthys_v3_ctx_create(&ctx->cng_keys, f, V3L_VERTHYS);
        CHECK(v3 != NULL);

        rc = verthys_unlock_pipeline_run(v3, V3L_PW, V3L_PW_LEN, 0,
                                       1u << stage, NULL, NULL);
        CHECK_EQ(rc, VERTHYS_ERR_INTERNAL);
        /* 阶段结果命中注入位（S0 在结果记录前 break，豁免） */
        if (stage >= UNLOCK_STAGE_S1) {
            CHECK_EQ(v3->pipeline.stages[stage].result, VERTHYS_ERR_INTERNAL);
        }
        /* 资源纪律：失败路径回到可重试初态（无半开子系统） */
        CHECK(v3->subsystems_open == 0);

        verthys_v3_ctx_destroy(v3);
        fclose(f);
        Verthys_Deinit(h);
    }

    /* 注入后容器本体无损：正常解锁仍成功（可重试语义验证） */
    {
        VerthysHandle h;
        VerthysRecord out;
        CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
        CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
        CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
        CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
        Verthys_Deinit(h);
    }

    v3life_cleanup();
    return 0;
}

/*
 * MINIMAL_FIRST 渐进式解锁：
 *   - 返回 PARTIAL_UNLOCK（后台预热线程已排程；线程创建失败兜底 OK）；
 *   - 最小可操作态数据立即可读（S5 最小部分 + Extent 按需解密）；
 *   - Lock 汇合后台线程后正常收口（无悬挂线程/句柄）。
 */
TEST(v3life_unlock_minimal_first)
{
    VerthysHandle h;
    VerthysRecord out;
    uint64_t ids[1] = {0};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    {
        VerthysResult rc = Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                      VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST);
        CHECK(rc == VERTHYS_ERR_PARTIAL_UNLOCK || rc == VERTHYS_OK);
    }

    /* 渐进式解锁的最小可操作态：立即可读（预热转后台不阻塞数据访问） */
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    /* Lock：汇合后台预热线程 + 正常收口 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    /* 锁定后不可操作 */
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_ERR_LOCKED);

    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * 可中断预热契约 + 销毁汇合竞态回归：
 *   a. 白盒 preheat_full_ex：stop_flag 预置位 → 首张表边界即折返
 *      （VERTHYS_ERR_LOCKED），复位后幂等续跑返回 OK；
 *   b. MINIMAL_FIRST 解锁后不等待预热完成即锁定——销毁汇合在预热线程
 *      仍持有子系统期间发起；多轮循环放大竞态窗口，每轮必须正常收口
 *      （停止标志复位 / 专用流生命周期完整 / 无悬挂线程）。
 */
TEST(v3life_preheat_interrupt_and_join)
{
    VerthysHandle h;
    VerthysRecord out;
    uint64_t ids[2] = {0, 0};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 2, ids), 0);

    /* --- a. 可中断预热契约（低层装配，复用 fail_mask 测试模式） --- */
    {
        struct VerthysContext *ctx;
        FILE *f = NULL;
        VerthysContextV3 *v3;
        volatile LONG stop;

        CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
        ctx = (struct VerthysContext *)h;

        fopen_s(&f, V3L_VERTHYS, "r+b");
        CHECK(f != NULL);
        v3 = verthys_v3_ctx_create(&ctx->cng_keys, f, V3L_VERTHYS);
        CHECK(v3 != NULL);
        CHECK_EQ(verthys_unlock_pipeline_run(v3, V3L_PW, V3L_PW_LEN, 0,
                                             0, NULL, NULL), VERTHYS_OK);

        /* 停止标志预置位：不加载任何表，直接以锁定语义折返。
         * f 传 NULL：由 preheat_full_ex 内部回退共享流（VerthysLsm 为
         * 不透明句柄，测试侧不触及内部字段） */
        stop = 1;
        CHECK_EQ(verthys_lsm_preheat_full_ex(v3->lsm, NULL, &stop),
                 VERTHYS_ERR_LOCKED);
        /* 复位后幂等续跑（惰性缓存已就绪或补加载均返回 OK） */
        stop = 0;
        CHECK_EQ(verthys_lsm_preheat_full_ex(v3->lsm, NULL, &stop),
                 VERTHYS_OK);
        /* 常规入口与委托版等价（幂等） */
        CHECK_EQ(verthys_lsm_preheat_full(v3->lsm), VERTHYS_OK);

        verthys_v3_ctx_destroy(v3);
        fclose(f);
        Verthys_Deinit(h);
    }

    /* --- b. MINIMAL_FIRST 解锁后立即锁定（多轮放大汇合竞态窗口） --- */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    for (int round = 0; round < 8; round++) {
        VerthysResult rc = Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                      VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST);
        CHECK(rc == VERTHYS_ERR_PARTIAL_UNLOCK || rc == VERTHYS_OK);
        /* 最小可操作态读验证后立即锁定（不等预热完成） */
        CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
        CHECK(memcmp(out.data, "data-0", 6) == 0);
        CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    }
    Verthys_Deinit(h);

    v3life_cleanup();
    return 0;
}

/* ================== 3. 温缓存（命中 / 缺失 / 损坏回退） ================== */

/*
 * 温缓存三态：
 *   a. 命中：Lock 同步写缓存 → 带 ALLOW_CACHE 解锁 → hits ≥ 1 + 数据完整；
 *   b. 缺失：缓存文件删除 → ALLOW_CACHE 解锁 → miss（冷启动）+ 数据完整；
 *   c. 损坏：缓存载荷篡改 → HMAC 拒绝 → miss 回退冷启动 + 数据完整
 *      （红线：缓存损坏绝不中断解锁、绝不静默错读）。
 * 每轮 Lock 重写缓存（时机 1），状态互不干扰。
 */
TEST(v3life_warmcache_hit_miss_tamper)
{
    VerthysHandle h;
    VerthysRecord out;
    VerthysDiagnostics diag;
    uint64_t ids[1] = {0};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);
    CHECK(ids[0] > 0);

    /* --- a. 命中（Lock 已写缓存：非 SECURE 预设） --- */
    {
        FILE *cf = fopen(V3L_CACHE, "rb");
        CHECK(cf != NULL);        /* Lock 同步写缓存（时机 1）已落盘 */
        fclose(cf);
    }
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                          VERTHYS_UNLOCK_FLAG_ALLOW_CACHE), VERTHYS_OK);
    memset(&diag, 0, sizeof(diag));
    CHECK_EQ(Verthys_GetDiagnostics(h, &diag), VERTHYS_OK);
    CHECK_EQ(diag.warm_cache_hits, 1u);
    CHECK_EQ(diag.warm_cache_misses, 0u);
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);      /* 重写缓存，供下轮状态 */
    Verthys_Deinit(h);

    /* --- b. 缺失（缓存文件不存在 → miss 冷启动） --- */
    CHECK_EQ(remove(V3L_CACHE), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                          VERTHYS_UNLOCK_FLAG_ALLOW_CACHE), VERTHYS_OK);
    memset(&diag, 0, sizeof(diag));
    CHECK_EQ(Verthys_GetDiagnostics(h, &diag), VERTHYS_OK);
    CHECK_EQ(diag.warm_cache_hits, 0u);
    CHECK_EQ(diag.warm_cache_misses, 1u);
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);

    /* --- c. 损坏（载荷字节翻转 → HMAC 整文件校验拒绝 → 冷启动回退） --- */
    {
        FILE *cf = fopen(V3L_CACHE, "r+b");
        CHECK(cf != NULL);
        /* 定位到 header（160B）之后的载荷区中部翻转一字节 */
        CHECK(_fseeki64(cf, 256, SEEK_SET) == 0);
        {
            int c = fgetc(cf);
            CHECK(c != EOF);
            CHECK(_fseeki64(cf, 256, SEEK_SET) == 0);
            CHECK(fputc(c ^ 0x5A, cf) != EOF);
        }
        CHECK(fflush(cf) == 0);
        fclose(cf);
    }
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                          VERTHYS_UNLOCK_FLAG_ALLOW_CACHE), VERTHYS_OK);
    memset(&diag, 0, sizeof(diag));
    CHECK_EQ(Verthys_GetDiagnostics(h, &diag), VERTHYS_OK);
    CHECK_EQ(diag.warm_cache_hits, 0u);     /* 篡改 → miss（不中断解锁） */
    CHECK_EQ(diag.warm_cache_misses, 1u);
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);      /* 重写缓存：损坏缓存被替换 */
    Verthys_Deinit(h);

    v3life_cleanup();
    return 0;
}

/* ================== 4. WAL 崩溃注入矩阵 ================== */

/*
 * 分支 a：未提交组丢弃。
 * 崩溃窗口 = 索引更新后（WAL 含 BEGIN/EXTENT/INDEX，无 PREPARE/COMMIT，
 * 超块 txid 未推进）→ 整组回滚，记录不可见；
 * 已提交数据不受影响；后续写入 LID 不复用（单调红线）。
 */
TEST(v3life_crash_uncommitted_discarded)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t ids[1] = {0};
    uint64_t crash_lid = 0, next_lid = 0;
    VerthysRecord cr = {VERTHYS_RECORD_ACCOUNT, "crashrec", 8,
                      (const uint8_t *)"crash-secret", 12};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    /* 解锁 → 驱动事务至崩溃窗口（索引更新完成后） */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    CHECK_EQ(verthys_txn_v3_begin(&v3->txn), VERTHYS_OK);
    CHECK_EQ(verthys_v3_add_record_in_txn(v3, (uint8_t)cr.type,
                                        cr.name, cr.name_len,
                                        cr.data, cr.data_len, &crash_lid),
             VERTHYS_OK);
    CHECK(crash_lid == ids[0] + 1);

    /* 崩溃：中止式拆除（盘面 WAL 保留未提交组） */
    v3life_crash_abort(ctx);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    /* 重开：S5 崩溃恢复裁决未提交组 → 丢弃 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);

    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);   /* 已提交数据完好 */
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    CHECK_EQ(Verthys_GetRecord(h, crash_lid, &out), VERTHYS_ERR_NOTFOUND);

    /* LID 永不复用：崩溃记录的 LID 不被后续写入回收 */
    {
        VerthysRecord nr = {VERTHYS_RECORD_ACCOUNT, "postcrash", 9,
                          (const uint8_t *)"fresh-data", 10};
        CHECK_EQ(Verthys_AddRecord(h, &nr, &next_lid), VERTHYS_OK);
        CHECK_EQ(next_lid, crash_lid + 1);
    }

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * 分支 b：COMMIT 已落笔、CONFIRM 未执行。
 * 崩溃窗口 = COMMIT 完成后（法定人数已持久 + WAL COMMIT 记录在场）→
 * 整组重放（幂等收尾：超块补 wal_committed_txid +
 * MemTable flush）→ 记录可见，数据完整。
 */
TEST(v3life_crash_committed_replayed)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t ids[1] = {0};
    uint64_t crash_lid = 0;
    VerthysRecord cr = {VERTHYS_RECORD_ACCOUNT, "comrec", 6,
                      (const uint8_t *)"committed-secret", 16};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    /* 六阶段推进至 COMMITTED（PREPARE → COMMIT；不做 CONFIRM） */
    CHECK_EQ(verthys_txn_v3_begin(&v3->txn), VERTHYS_OK);
    CHECK_EQ(verthys_v3_add_record_in_txn(v3, (uint8_t)cr.type,
                                        cr.name, cr.name_len,
                                        cr.data, cr.data_len, &crash_lid),
             VERTHYS_OK);
    CHECK_EQ(verthys_txn_v3_prepare(&v3->txn), VERTHYS_OK);
    CHECK_EQ(verthys_txn_v3_commit(&v3->txn), VERTHYS_OK);
    CHECK_EQ(verthys_txn_v3_state(&v3->txn), VERTHYS_TXN_V3_COMMITTED);

    /* 崩溃：COMMITTED 态拆除（盘面 = 法定人数 + WAL COMMIT 在场） */
    v3life_crash_abort(ctx);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    /* 重开：规则 4 重放 → 已提交数据可见 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, crash_lid, &out), VERTHYS_OK);
    CHECK_EQ(out.name_len, 6u);
    CHECK(memcmp(out.name, "comrec", 6) == 0);
    CHECK_EQ(out.data_len, 16u);
    CHECK(memcmp(out.data, "committed-secret", 16) == 0);
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);   /* 既有数据完好 */
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/*
 * 分支 c：PREPARE-only + sb_txid ≥ txid（法定人数后、落盘前崩溃）。
 * 崩溃窗口 = 法定人数提交后、落盘前（超块法定人数已含 txid；Extent 索引 /
 * 分区表 / WAL COMMIT 均未落盘）→ 整组重放收尾
 * （EXTENT 按 WAL 记录补注册含 nonce + 索引重放 + 索引/分区表补存 +
 * 超块补 wal_committed_txid）→ 记录可见，数据完整可解密。
 *
 * 窗口构造：复刻 commit 步骤 1-2 的超块候选字段与法定人数提交
 * （verthys_txn_v3_commit 同一调用不可中断，步骤 0 分区扩展对本测试
 * 数据量无必要——默认 Extent 分区容量充足）。
 */
TEST(v3life_crash_prepare_only_replayed)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t ids[1] = {0};
    uint64_t crash_lid = 0;
    VerthysRecord cr = {VERTHYS_RECORD_ACCOUNT, "prep", 4,
                      (const uint8_t *)"prepare-window-secret", 20};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    /* 事务推进至 PREPARE（WAL：BEGIN/EXTENT/INDEX/PREPARE） */
    CHECK_EQ(verthys_txn_v3_begin(&v3->txn), VERTHYS_OK);
    CHECK_EQ(verthys_v3_add_record_in_txn(v3, (uint8_t)cr.type,
                                        cr.name, cr.name_len,
                                        cr.data, cr.data_len, &crash_lid),
             VERTHYS_OK);
    CHECK_EQ(verthys_txn_v3_prepare(&v3->txn), VERTHYS_OK);
    CHECK(v3->txn.has_prepare == 1);

    /* 复刻法定人数提交前两步：超块候选字段 + 法定人数提交（此后即崩溃） */
    {
        VsbTxnV3 vtxn;
        CHECK_EQ(vsb_txn_v3_begin(&vtxn, &v3->sb), VERTHYS_OK);
        v3->sb.txid = verthys_txn_v3_txid(&v3->txn);
        v3->sb.updated_at += 1;
        v3->sb.wal_head_offset = verthys_wal_head_offset(v3->wal);
        v3->sb.wal_tail_offset = verthys_wal_tail_offset(v3->wal);
        memcpy(v3->sb.merkle_root, v3->txn.prepare.merkle_root,
               VERTHYS_V3_MERKLE_ROOT_BYTES);
        CHECK_EQ(vsb_txn_v3_commit(&vtxn, &v3->sb, v3->f,
                                  v3->integrity_key), VERTHYS_OK);
    }

    /* 崩溃：Extent 索引/分区表/WAL COMMIT 全部缺席 */
    v3life_crash_abort(ctx);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    /* 重开：规则 5 重放（EXTENT 补注册 + 索引重放 + 落盘补齐） */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, crash_lid, &out), VERTHYS_OK);
    CHECK_EQ(out.name_len, 4u);
    CHECK(memcmp(out.name, "prep", 4) == 0);
    CHECK_EQ(out.data_len, 20u);
    CHECK(memcmp(out.data, "prepare-window-secret", 20) == 0);
    CHECK_EQ(Verthys_GetRecord(h, ids[0], &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    /* 重放收尾后再写一条：LID 严格递增（重放不回退 max_lid） */
    {
        VerthysRecord nr = {VERTHYS_RECORD_ACCOUNT, "postreplay", 10,
                          (const uint8_t *)"post-replay-data", 15};
        uint64_t next_lid = 0;
        CHECK_EQ(Verthys_AddRecord(h, &nr, &next_lid), VERTHYS_OK);
        CHECK_EQ(next_lid, crash_lid + 1);
        CHECK_EQ(Verthys_GetRecord(h, next_lid, &out), VERTHYS_OK);
        CHECK(memcmp(out.data, "post-replay-data", 15) == 0);
    }

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}

/* ================== 5. 落盘自查（持锁句柄 C 层校验） ================== */

/*
 * Verthys_VerifyPersist：解锁态用会话持锁句柄自查盘面结构 → OK，
 * 且 file_size>0、帧头 magic 与版本正确、wal_offset 为 WAL 区起点；
 * 锁定后无会话（ctx->v3 已收口）→ INTERNAL 且不崩溃；空句柄/空出参同。
 */
TEST(v3life_verify_persist_selfcheck)
{
    VerthysHandle h;
    VerPersistVerifyResult res;
    uint64_t ids[1] = {0};

    CHECK_EQ(v3life_make_locked(V3L_VERTHYS, V3L_PW, V3L_PW_LEN,
                                VERTHYS_PRESET_PERFORMANCE, 1, ids), 0);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, V3L_VERTHYS, V3L_PW, V3L_PW_LEN, 0), VERTHYS_OK);

    /* 解锁态：持锁句柄自查应全绿 */
    memset(&res, 0, sizeof(res));
    CHECK_EQ(Verthys_VerifyPersist(h, &res), VERTHYS_PERSIST_OK);
    CHECK_EQ(res.status, VERTHYS_PERSIST_OK);
    CHECK(res.file_size > 0);
    CHECK_EQ(res.header_magic, (long)VERTHYS_V3_REPLICA_FRAME_MAGIC);
    CHECK_EQ(res.header_version, VERTHYS_V3_VERSION);
    CHECK_EQ(res.wal_offset, (long)VERTHYS_V3_WAL_REGION_OFFSET);
    CHECK(res.last_error[0] == '\0');

    /* 幂等：重复调用结果一致（只读、无副作用） */
    memset(&res, 0, sizeof(res));
    CHECK_EQ(Verthys_VerifyPersist(h, &res), VERTHYS_PERSIST_OK);
    CHECK_EQ(res.header_magic, (long)VERTHYS_V3_REPLICA_FRAME_MAGIC);

    /* 锁定后无会话：INTERNAL，且不得崩溃 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    memset(&res, 0, sizeof(res));
    CHECK_EQ(Verthys_VerifyPersist(h, &res), VERTHYS_PERSIST_E_INTERNAL);

    /* 空句柄 / 空出参：不崩溃，返回 INTERNAL */
    CHECK_EQ(Verthys_VerifyPersist(NULL, &res), VERTHYS_PERSIST_E_INTERNAL);
    CHECK_EQ(Verthys_VerifyPersist(h, NULL), VERTHYS_PERSIST_E_INTERNAL);

    Verthys_Deinit(h);
    v3life_cleanup();
    return 0;
}
