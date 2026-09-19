/*
 * test_final_repair.c — 全量回归测试
 *
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_io.h"
#include "verthys_format.h"
#include "verthys_container_v3.h"   /* VsbTxnV3 / vsb_v3_*（vsb_txn 等价原语） */
#include "verthys_v3_lifecycle.h"    /* VerthysContextV3（改密回滚 V3 白盒） */
#include "verthys_lsm.h"             /* verthys_lsm_put（导出上限/大批量 V3 白盒注入） */

#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>   /* FSCTL_SET_SPARSE（稀疏文件测试） */
#endif

/* 测试内本地小端序写入（与实现层各自独立，避免耦合静态函数） */
static void tput_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static void tput_u32le(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}
static void tput_u64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}

#define FR_VERTHYS "test_final_repair_tmp.verthys"

static void fr_cleanup(void) { remove(FR_VERTHYS); }

/* ------------------------------------------------------------------ *
 * 池扩展上界——先占 MEDIUM 槽 0，再压满 SMALL 池（64 条）触发
 * 扩展路径；修复前扩展零写会覆盖 MEDIUM 槽 0 的数据。
 * ------------------------------------------------------------------ */
TEST(repair_pool_extend_boundary)
{
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 1. 占据 MEDIUM 池槽 0（512KB 数据 → 选 MEDIUM 池） */
    uint8_t *big = (uint8_t *)malloc(512 * 1024);
    CHECK(big != NULL);
    memset(big, 0x5A, 512 * 1024);
    VerthysRecord big_rec = {VERTHYS_RECORD_PHOTO, "big", 3, big, 512 * 1024};
    uint64_t big_id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &big_rec, &big_id), VERTHYS_OK);

    /* 2. 压满 SMALL 池：64 条小记录（SMALL 池初始 64 槽） */
    char namebuf[32];
    for (int i = 0; i < 64; i++) {
        VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "s", 1,
                         (const uint8_t *)"pw", 2};
        namebuf[0] = (char)('a' + (i % 26));
        r.name = namebuf;
        uint64_t id = 0;
        CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    }
    /* 第 65 条：SMALL 满 → 修复后回退 MEDIUM 池（不再越界覆写） */
    VerthysRecord r65 = {VERTHYS_RECORD_ACCOUNT, "s65", 3, (const uint8_t *)"pw", 2};
    uint64_t id65 = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r65, &id65), VERTHYS_OK);

    /* 3. MEDIUM 槽 0 数据必须完好（修复前此处被扩展零写破坏） */
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, big_id, &out), VERTHYS_OK);
    CHECK_EQ(out.data_len, 512 * 1024);
    CHECK(((const uint8_t *)out.data)[0] == 0x5A);
    CHECK(((const uint8_t *)out.data)[512 * 1024 - 1] == 0x5A);

    /* 4. 锁定-重开-全量可读（磁盘一致性） */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, FR_VERTHYS, "pw", 2, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, big_id, &out), VERTHYS_OK);
    CHECK_EQ(out.data_len, 512 * 1024);

    Verthys_Lock(h);
    Verthys_Deinit(h);
    free(big);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * LSM 索引 5000 条插入 → 全量扫描 → 强制 flush（SSTable 序列化
 * 往返）→ 再全量扫描 → 删除半数（墓碑遮蔽）→ 扫描/点查校验。
 * （原 B+ 树内部分裂丢失子树用例随 verthys_btree 删除退役；等价 V3
 * 路径 = MemTable 跳表批量插入 + L0 SSTable 落盘往返 + 新旧版本遮蔽。
 * 修复前高位 LID 区间 find 假 NOTFOUND 的对应形态 = 扫描计数缺失。）
 * ------------------------------------------------------------------ */
TEST(repair_lsm_large_insert)
{
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->fmt_version, VERTHYS_FMT_V3);
    VerthysLsm *lsm = ctx->v3->lsm;
    CHECK(lsm != NULL);

    const uint64_t N = 5000;
    char namebuf[32];

    /* 1. 5000 条插入（MemTable 跳表；未达 10000 条阈值不自动 flush） */
    for (uint64_t i = 1; i <= N; i++) {
        VerthysLsmEntry e;
        memset(&e, 0, sizeof e);
        e.lid = i;
        e.type = VERTHYS_RECORD_ACCOUNT;
        e.slot_state = 1;
        namebuf[0] = 'n';
        snprintf(namebuf + 1, sizeof(namebuf) - 1, "%llu", (unsigned long long)i);
        e.name_len = (uint16_t)strlen(namebuf);
        e.name = (const uint8_t *)namebuf;
        e.data_size = i;
        e.plaintext_size = 1;
        e.extent_size = 17;
        e.created_txid = 1;
        CHECK_EQ(verthys_lsm_put(lsm, 1, &e), VERTHYS_OK);
    }
    CHECK_EQ(verthys_lsm_memtable_count(lsm), (size_t)N);
    CHECK_EQ(verthys_lsm_estimate_records(lsm), N);

    /* 2. 强制 flush：MemTable → L0 SSTable（原用例"序列化"的等价路径） */
    CHECK_EQ(verthys_lsm_flush(lsm), VERTHYS_OK);
    CHECK_EQ(verthys_lsm_memtable_count(lsm), 0u);
    CHECK_EQ(verthys_lsm_table_count(lsm), 1u);   /* L0 单表 */

    /* 3. 全量扫描（原用例"反序列化后全量查找"的等价路径） */
    {
        VerthysLsmScanIter *it = NULL;
        CHECK_EQ(verthys_lsm_scan_open(lsm, &it), VERTHYS_OK);
        uint64_t count = 0, expect_lid = 1;
        VerthysLsmEntry e;
        uint8_t nb[32];
        size_t nl = 0;
        VerthysResult rc;
        while ((rc = verthys_lsm_scan_next(it, &e, nb, sizeof nb, &nl)) == VERTHYS_OK) {
            CHECK_EQ(e.lid, expect_lid);        /* lid 升序无缺失 */
            count++; expect_lid++;
        }
        CHECK_EQ(rc, VERTHYS_ERR_NOTFOUND);       /* 正常耗尽 */
        CHECK_EQ(count, N);
        verthys_lsm_scan_close(it);
    }

    /* 4. 点查抽查（首/中/尾——原用例 find 假 NOTFOUND 回归点） */
    {
        VerthysLsmEntry e;
        uint8_t nb[32];
        size_t nl = 0;
        CHECK_EQ(verthys_lsm_get(lsm, 1, &e, nb, sizeof nb, &nl), VERTHYS_OK);
        CHECK_EQ(e.data_size, 1u);
        CHECK_EQ(verthys_lsm_get(lsm, N / 2, &e, nb, sizeof nb, &nl), VERTHYS_OK);
        CHECK_EQ(e.data_size, N / 2);
        CHECK_EQ(verthys_lsm_get(lsm, N, &e, nb, sizeof nb, &nl), VERTHYS_OK);
        CHECK_EQ(e.data_size, N);
    }

    /* 5. 删除偶数键（墓碑）→ flush → 全量扫描仅剩奇数 */
    for (uint64_t i = 2; i <= N; i += 2) {
        CHECK_EQ(verthys_lsm_delete(lsm, 1, i), VERTHYS_OK);
    }
    CHECK_EQ(verthys_lsm_flush(lsm), VERTHYS_OK);
    {
        VerthysLsmScanIter *it = NULL;
        CHECK_EQ(verthys_lsm_scan_open(lsm, &it), VERTHYS_OK);
        uint64_t count = 0, expect_lid = 1;
        VerthysLsmEntry e;
        uint8_t nb[32];
        size_t nl = 0;
        VerthysResult rc;
        while ((rc = verthys_lsm_scan_next(it, &e, nb, sizeof nb, &nl)) == VERTHYS_OK) {
            CHECK_EQ(e.lid, expect_lid);        /* 偶数键被墓碑遮蔽 */
            CHECK(expect_lid % 2 == 1);
            count++; expect_lid += 2;
        }
        CHECK_EQ(rc, VERTHYS_ERR_NOTFOUND);
        CHECK_EQ(count, (N + 1) / 2);
        verthys_lsm_scan_close(it);
    }

    /* 6. 删除键点查 NOTFOUND，未删键仍命中 */
    {
        VerthysLsmEntry e;
        uint8_t nb[32];
        size_t nl = 0;
        CHECK_EQ(verthys_lsm_get(lsm, 2, &e, nb, sizeof nb, &nl), VERTHYS_ERR_NOTFOUND);
        CHECK_EQ(verthys_lsm_get(lsm, 3, &e, nb, sizeof nb, &nl), VERTHYS_OK);
    }

    Verthys_Lock(h);
    Verthys_Deinit(h);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * 改密落盘失败（超块区字节锁注入）→ 超级块盐值回滚，
 * 后续解锁仍用旧口令成功（修复前：内存盐值残留新值，后续提交锁库）。
 * ------------------------------------------------------------------ */
TEST(repair_changepw_fail_rollback)
{
    fr_cleanup();
    VerthysHandle h;
#ifdef _WIN32
    HANDLE hInj = INVALID_HANDLE_VALUE;   /* 超块区字节锁注入句柄 */
#endif
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "old-pw", 6, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"d", 1};
    uint64_t id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;
    uint8_t salt_before[VERTHYS_V3_SALT_BYTES];
    CHECK_EQ(Verthys_Unlock(h, FR_VERTHYS, "old-pw", 6, 0), VERTHYS_OK);
    memcpy(salt_before, ctx->v3->sb.salt, VERTHYS_V3_SALT_BYTES);

#ifdef _WIN32
    /* 注入：超块区独占字节锁（第二句柄）——VsbTxnV3 提交三副本
     * 写入 [0,64KB) 全部 LOCK_VIOLATION → IO → 回滚。READONLY 属性
     * 注入对 V3 无效：ctx3->f 解锁时已以 r+b 打开，只读属性不撤销
     * 既有句柄的写权限（属性仅在打开时校验）。 */
    hInj = CreateFileA(FR_VERTHYS, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(hInj != INVALID_HANDLE_VALUE);
    LARGE_INTEGER li; li.QuadPart = 0;
    OVERLAPPED ov = {0}; ov.Offset = (DWORD)li.LowPart;
    CHECK(LockFileEx(hInj, LOCKFILE_EXCLUSIVE_LOCK, 0,
                     (DWORD)VERTHYS_V3_SB_REGION_END, 0, &ov));
#endif

    /* 改密：序列化成功但落盘失败 → 必须返回错误且超级块回滚 */
    VerthysResult cp_rc = Verthys_ChangePassword(h, "old-pw", 6, "new-pw", 6);
    CHECK(cp_rc != VERTHYS_OK);

#ifdef _WIN32
    {
        LARGE_INTEGER li; li.QuadPart = 0;
        OVERLAPPED ov = {0}; ov.Offset = (DWORD)li.LowPart;
        CHECK(UnlockFileEx(hInj, 0, (DWORD)VERTHYS_V3_SB_REGION_END, 0, &ov));
        CloseHandle(hInj);
    }
#endif

    /* ★ 核心断言：内存超级块盐值必须恢复为旧值（回滚修复点） */
    CHECK(memcmp(ctx->v3->sb.salt, salt_before, sizeof salt_before) == 0);

    /* 旧口令仍可解锁（会话内提交不会落盘毒化状态） */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, FR_VERTHYS, "old-pw", 6, 0), VERTHYS_OK);
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    Verthys_Lock(h);
    Verthys_Deinit(h);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * 64 位文件偏移——稀疏文件 2GB+ 偏移读写往返。
 * ------------------------------------------------------------------ */
TEST(repair_large_file_offset)
{
    const char *path = "test_vio_sparse.tmp";
#ifdef _WIN32
    HANDLE hf = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(hf != INVALID_HANDLE_VALUE);
    /* NTFS 稀疏化，避免真实占用 2GB 磁盘 */
    DWORD dummy = 0;
    DeviceIoControl(hf, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &dummy, NULL);
    CloseHandle(hf);
#endif

    FILE *f = fopen(path, "r+b");
    CHECK(f != NULL);

    const uint64_t far_off = 2147487744ULL;  /* 2GB + 1KB */
    uint8_t wbuf[64], rbuf[64];
    for (int i = 0; i < 64; i++) wbuf[i] = (uint8_t)(i ^ 0xA5);

    CHECK_EQ(vio_pwrite64(f, far_off, wbuf, sizeof wbuf), 0);
    CHECK_EQ(vio_pread64(f, far_off, rbuf, sizeof rbuf), 0);
    CHECK(memcmp(wbuf, rbuf, sizeof wbuf) == 0);

    /* 文件大小应已扩展到远偏移处（64 位定位生效的直接证据） */
    CHECK_EQ(vio_fseek64(f, 0, SEEK_END), 0);
    CHECK(vio_ftell64(f) > (int64_t)far_off);

    fclose(f);
    remove(path);
    return 0;
}

/* ------------------------------------------------------------------ *
 * 恶意 v1 头 mac_offset 整数回绕 → 解析必须拒绝。
 * ------------------------------------------------------------------ */
TEST(repair_v1_mac_offset_overflow)
{
    /* 构造最小头：magic 'VERT'（字节序）/版本/保留/alg 正确，
     * mac_offset ≈ UINT64_MAX（+HMAC_BYTES 加法回绕为小值——修复前
     * 该值通过边界校验，后续按其 HMAC 产生巨量 OOB 读） */
    size_t sz = VERTHYS_FMT_HEADER_BYTES + VERTHYS_FMT_METADATA_BYTES + VERTHYS_HMAC_BYTES;
    uint8_t *blob = (uint8_t *)calloc(1, sz);
    CHECK(blob != NULL);

    blob[0] = 0x56; blob[1] = 0x45; blob[2] = 0x52; blob[3] = 0x54;  /* 'VERT' */
    tput_u16le(blob + 4, VERTHYS_FMT_VERSION);
    tput_u16le(blob + 6, 0x0000);               /* 保留必须为 0 */
    tput_u32le(blob + 8, VERTHYS_FMT_ALG_ARGON2ID_XCHACHA20);
    tput_u32le(blob + 12, VERTHYS_FMT_HEADER_BYTES);
    tput_u64le(blob + 16, 0xFFFFFFFFFFFFFFDFULL);  /* UINT64_MAX - 32 */

    VerthysFmtMeta meta;
    CHECK(vfmt_parse_header(blob, sz, &meta) != 0);  /* 必须拒绝 */

    free(blob);
    return 0;
}

/* ------------------------------------------------------------------ *
 * vfmt_write 失败路径清理——重复失败不崩溃（泄漏由 ASAN CI 甄别）。
 * ------------------------------------------------------------------ */
TEST(repair_vfmt_write_fail_cleanup)
{
    /* 通过公共 API 触发流式写失败：导出到不存在目录 */
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"d", 1};
    uint64_t id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    for (int i = 0; i < 3; i++) {
        VerthysResult rc = Verthys_Export(h, "Z:\\no_such_dir\\out.bin", "ep", 2);
        CHECK(rc == VERTHYS_ERR_IO || rc == VERTHYS_ERR_INTERNAL);
    }

    /* 原容器不受影响 */
    {
        VerthysRecord out;
        CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    }

    Verthys_Lock(h);
    Verthys_Deinit(h);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * records 容量回绕——V1 内存记录表（records_ensure_capacity 的
 * 32768 翻倍截断悬垂）随删除清单退役：V3 记录账本 = LSM 索引
 * （MemTable 跳表动态分配，无数组容量语义），回绕缺陷类别整体消除。
 * 以编译期删除为验收（同死代码删除）。
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * vsb_txn_v3 原语——begin/mutate/rollback 恢复，commit 保留
 * （V3 三副本法定人数提交 + 终态后不可复用语义，原 V2 vsb_txn 等价）。
 * ------------------------------------------------------------------ */
TEST(repair_vsb_txn_v3_rollback)
{
    /* 内存态回滚路径 */
    VerthysSuperBlockV3 sb;
    CHECK_EQ(vsb_v3_init_new(&sb), VERTHYS_OK);
    sb.txid = 7;
    sb.salt[0] = 0xAB;
    sb.salt[1] = 0xCD;

    VsbTxnV3 txn;
    CHECK_EQ(vsb_txn_v3_begin(&txn, &sb), VERTHYS_OK);
    sb.txid = 99;
    sb.salt[0] = 0x11;
    CHECK_EQ(vsb_txn_v3_rollback(&txn, &sb), VERTHYS_OK);
    CHECK_EQ(sb.txid, 7);
    CHECK(sb.salt[0] == 0xAB && sb.salt[1] == 0xCD);

    /* 终态后不可复用（幂等保护）：二次 rollback 拒绝且内存态不变 */
    CHECK_EQ(vsb_txn_v3_rollback(&txn, &sb), VERTHYS_ERR_INVALID);
    CHECK_EQ(sb.txid, 7);

    /* commit 路径：法定人数提交（3 副本写盘）后变更保留 */
    const char *sb_path = "test_final_repair_vsb.tmp";
    FILE *f = fopen(sb_path, "wb+");
    CHECK(f != NULL);
    uint8_t ikey[VERTHYS_KEY_BYTES];
    for (int i = 0; i < VERTHYS_KEY_BYTES; i++) ikey[i] = (uint8_t)(i + 1);

    CHECK_EQ(vsb_txn_v3_begin(&txn, &sb), VERTHYS_OK);
    sb.txid = 99;
    CHECK_EQ(vsb_txn_v3_commit(&txn, &sb, f, ikey), VERTHYS_OK);
    CHECK_EQ(sb.txid, 99);

    /* 法定人数读回验证（≥2 副本 HMAC 一致 → 最高 txid 生效） */
    VerthysSuperBlockV3 rb;
    CHECK_EQ(vsb_v3_read_quorum(f, ikey, &rb, NULL), VERTHYS_OK);
    CHECK_EQ(rb.txid, 99);
    CHECK(rb.salt[0] == 0xAB && rb.salt[1] == 0xCD);

    /* 提交终态后事务不可复用 */
    CHECK_EQ(vsb_txn_v3_commit(&txn, &sb, f, ikey), VERTHYS_ERR_INVALID);

    fclose(f);
    remove(sb_path);
    return 0;
}

/* ------------------------------------------------------------------ *
 * 提交路径 tail log/bitmap 检查接入后的成功路径回归。
 * ------------------------------------------------------------------ */
TEST(repair_tail_log_commit_regression)
{
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "t", 1, (const uint8_t *)"d", 1};
    uint64_t id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);   /* commit 全链路 OK */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, FR_VERTHYS, "pw", 2, 0), VERTHYS_OK);
    {
        VerthysRecord out;
        CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    }
    Verthys_Lock(h);
    Verthys_Deinit(h);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * 导出条数超交换格式容量上限 → VERTHYS_ERR_EXPORT_TOO_MANY（不再静默截断）。
 * 直接向索引注入 70000 条（绕开逐条事务的耗时），触发导出上限分支：
 *   V3：LSM 索引（verthys_lsm_put——WAL 先行 + MemTable，阈值自动
 *   flush 落 L0 SSTable，墓碑为 0 全部可数）；导出第一遍快照迭代
 *   计数 > 65535 即拒绝，不触达任何 Extent 数据（伪造哈希安全）。
 * ------------------------------------------------------------------ */
TEST(repair_export_too_many)
{
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->fmt_version, VERTHYS_FMT_V3);
    char namebuf[16];
    /* V3 白盒：直接 LSM 注入（70000 条 ≈ 7 轮阈值 flush） */
    for (uint64_t i = 1; i <= 70000; i++) {
        VerthysLsmEntry e;
        memset(&e, 0, sizeof e);
        e.lid = i;
        e.type = 1;
        e.slot_state = 1;
        namebuf[0] = 'n';
        snprintf(namebuf + 1, sizeof(namebuf) - 1, "%llu", (unsigned long long)i);
        e.name_len = (uint16_t)strlen(namebuf);
        e.name = (const uint8_t *)namebuf;
        e.data_size = 1;
        e.plaintext_size = 1;
        e.extent_size = 17;
        e.created_txid = 1;
        CHECK_EQ(verthys_lsm_put(ctx->v3->lsm, 1, &e), VERTHYS_OK);
    }

    /* 导出必须显式拒绝（修复前：静默截断返回 OK） */
    VerthysResult rc = Verthys_Export(h, "test_export_cap.bin", "ep", 2);
    CHECK_EQ(rc, VERTHYS_ERR_EXPORT_TOO_MANY);
    remove("test_export_cap.bin");

    Verthys_Lock(h);
    Verthys_Deinit(h);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * name_len 超限在 API 边界拒绝。
 * ------------------------------------------------------------------ */
TEST(repair_name_len_clamp)
{
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    static char bigname[VERTHYS_NAME_MAX_BYTES + 1];
    memset(bigname, 'x', sizeof bigname);

    VerthysRecord over = {VERTHYS_RECORD_ACCOUNT, bigname, sizeof bigname,
                        (const uint8_t *)"d", 1};
    uint64_t id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &over, &id), VERTHYS_ERR_INVALID);  /* 超限拒绝 */

    VerthysRecord at_limit = {VERTHYS_RECORD_ACCOUNT, bigname, VERTHYS_NAME_MAX_BYTES,
                            (const uint8_t *)"d", 1};
    CHECK_EQ(Verthys_AddRecord(h, &at_limit, &id), VERTHYS_OK);       /* 上限内允许 */

    Verthys_Lock(h);
    Verthys_Deinit(h);
    fr_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ *
 * watcher / progress 线程高频启停回归（修复后停机无限等待，
 * 不再有超时后的悬垂释放窗口）。
 * ------------------------------------------------------------------ */
TEST(repair_thread_shutdown_cycles)
{
    fr_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, FR_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"d", 1};
    uint64_t id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    /* 进度回调注册 + 10 轮 Lock/Unlock（每轮 watcher 启停 + 进度环复用） */
    for (int i = 0; i < 10; i++) {
        CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
        CHECK_EQ(Verthys_Unlock(h, FR_VERTHYS, "pw", 2, 0), VERTHYS_OK);
    }
    {
        VerthysRecord out;
        CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    }
    Verthys_Lock(h);
    Verthys_Deinit(h);   /* Deinit 触发 progress ring destroy + watcher stop */
    fr_cleanup();
    return 0;
}
