/*
 * test_scan_concurrent.c — 扫描读路径与并发写路径的竞争压力测试
 *
 * 验证目标：容器解锁态下，读侧（全量/摘要扫描游标、按类型探测）与
 * 写侧（AddRecord 落盘）并发执行时，共享 FILE* 上的定位与读写不发生
 * 交错竞争——读者不得出现错位读取导致的解密失败或内部错误，写者
 * 不得出现写入失败，最终条目计数与数据完整性不受影响。
 *
 * 隔离设计：
 *   - 快照语义：游标绑定打开瞬间的 LSM 快照，读侧不感知中途新写入
 *     条目（计数按 seed+writes 全量校验，拉取循环仅以耗尽收尾）；
 *   - 内容唯一：seed 与写线程的每条记录 name/data 均含唯一序号，
 *     杜绝内容寻址去重导致的 IO 压力失真；
 *   - 断言后置：线程内错误仅原子累计（CHECK 会立即 return 跳过清理，
 *     多线程下不可用），全部线程 join 与句柄回收完成后统一断言。
 *
 * 线程拓扑（三个工作线程由主测试线程 spawn 并 join）：
 *   - writer ：循环 AddRecord 唯一记录，完成后置 stop 标志；
 *   - reader ：循环 摘要 Open/Fetch/Close + 全量 Open/Fetch/Close
 *              （全量路径触发数据块读取与写者落盘的真实竞争窗口）；
 *   - prober ：循环 HasRecordByType / FindFirstLidByType 轻量探测。
 */
#include "verthys_test.h"
#include "verthys.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <process.h>

#define SC_PATH      "test_scan_conc.verthys"
#define SC_PW        "scan-conc-pass"
#define SC_PW_LEN    13
#define SC_SEED      32      /* 并发开始前预置记录条数 */
#define SC_WRITES    256     /* 写线程追加记录条数 */
#define SC_BATCH_S   64      /* 摘要扫描单批容量 */
#define SC_BATCH_F   32      /* 全量扫描单批容量 */
#define SC_NAME_LEN  15      /* "w-item-" + 8 位十六进制序号 */
#define SC_DATA_LEN  20

static void sc_cleanup(void) { remove(SC_PATH); }

/*
 * 跨线程共享状态：错误仅原子累计（首个错误码经 CAS 抢位留档），
 * stop 为写侧完成标志（LONG 原子写读，读侧据此收尾退出循环）。
 * last_lid 仅写线程写入、主线程 join 后读取（等待关系保证可见性）。
 */
typedef struct ScanConcState {
    VerthysHandle   h;
    volatile LONG   stop;           /* 1 = 写线程已完成 */
    volatile LONG   writer_ok;      /* 写线程成功条数 */
    volatile LONG   writer_fail;    /* 写线程失败次数 */
    volatile LONG   reader_errs;    /* 读线程未预期错误码次数 */
    volatile LONG   prober_errs;    /* 探测线程未预期错误码次数 */
    volatile LONG   fetch_failed;   /* 全量扫描解密失败条目累计 */
    volatile LONG   first_err;      /* 首个未预期错误码（0=未发生） */
    uint64_t        last_lid;       /* 写线程最后成功写入的 lid */
} ScanConcState;

/* 记录首个非零错误码（多线程抢位，仅首个留档） */
static void sc_record_err(ScanConcState *st, LONG code)
{
    InterlockedCompareExchange(&st->first_err, code, 0);
}

/*
 * 唯一记录内容生成：写入调用方持有的稳定缓冲（AddRecord 返回前
 * 完成深拷贝，缓冲生命周期由调用方保证）。name/data 由序号唯一化，
 * 内容寻址去重不合并。
 */
typedef struct ScanConcItem {
    char    name[SC_NAME_LEN];
    uint8_t data[SC_DATA_LEN];
} ScanConcItem;

static void sc_make_item(ScanConcItem *item, uint32_t seq)
{
    static const char hex[] = "0123456789abcdef";
    int i;

    item->name[0] = 'w'; item->name[1] = '-'; item->name[2] = 'i';
    item->name[3] = 't'; item->name[4] = 'e'; item->name[5] = 'm';
    item->name[6] = '-';
    for (i = 0; i < 8; i++) {
        item->name[7 + i] = hex[(seq >> (28 - 4 * i)) & 0xf];
    }

    memcpy(item->data, "scan-conc-", 10);
    for (i = 0; i < 8; i++) {
        item->data[10 + i] = hex[(seq >> (28 - 4 * i)) & 0xf];
    }
    item->data[18] = 'x';
    item->data[19] = 'y';
}

static void sc_fill_record(VerthysRecord *r, const ScanConcItem *item)
{
    r->type     = VERTHYS_RECORD_ACCOUNT;
    r->name     = item->name;
    r->name_len = SC_NAME_LEN;
    r->data     = item->data;
    r->data_len = SC_DATA_LEN;
}

/* 写线程：循环 AddRecord 唯一记录，失败即停（计数由共享状态承载） */
static unsigned __stdcall sc_writer(void *arg)
{
    ScanConcState *st = (ScanConcState *)arg;
    uint32_t i;

    for (i = 0; i < SC_WRITES; i++) {
        ScanConcItem item;
        VerthysRecord r;
        uint64_t id = 0;
        VerthysResult rc;

        sc_make_item(&item, i);
        sc_fill_record(&r, &item);
        rc = Verthys_AddRecord(st->h, &r, &id);
        if (rc != VERTHYS_OK) {
            InterlockedIncrement(&st->writer_fail);
            sc_record_err(st, (LONG)rc);
            break;
        }
        InterlockedIncrement(&st->writer_ok);
        st->last_lid = id;
    }
    InterlockedExchange(&st->stop, 1);
    return 0;
}

/*
 * 读线程：交替执行摘要扫描与全量扫描完整游标周期。全量路径的
 * 数据块读取（解密）与写线程落盘在共享文件上并发——即本测试
 * 的核心竞争窗口；绿态语义下任何错误码均为竞争暴露。
 */
static unsigned __stdcall sc_reader(void *arg)
{
    ScanConcState *st = (ScanConcState *)arg;
    VerthysSummaryRecord srecs[SC_BATCH_S];
    VerthysRecord frecs[SC_BATCH_F];
    uint64_t lids_s[SC_BATCH_S];
    uint64_t lids_f[SC_BATCH_F];
    uint64_t cnt = 0;
    uint64_t fcnt = 0;
    uint64_t j;
    VerthysScanCursor *cur;
    VerthysResult rc;

    while (st->stop == 0) {
        /* 摘要游标周期（元数据直读） */
        cur = NULL;
        rc = Verthys_ScanSummaryOpen(st->h, 0, SC_BATCH_S, &cur);
        if (rc != VERTHYS_OK) {
            InterlockedIncrement(&st->reader_errs);
            sc_record_err(st, (LONG)rc);
        } else {
            for (;;) {
                rc = Verthys_ScanSummaryFetch(cur, srecs, lids_s,
                                              SC_BATCH_S, &cnt);
                if (rc != VERTHYS_OK) {
                    InterlockedIncrement(&st->reader_errs);
                    sc_record_err(st, (LONG)rc);
                    break;
                }
                for (j = 0; j < cnt; j++) {
                    Verthys_ScanSummaryRecordFree(&srecs[j]);
                }
                if (cnt == 0) break;    /* 快照耗尽 */
            }
            if (Verthys_ScanClose(cur) != VERTHYS_OK) {
                InterlockedIncrement(&st->reader_errs);
            }
        }

        if (st->stop != 0) break;

        /* 全量游标周期（数据块解密读取，竞争核心路径） */
        cur = NULL;
        rc = Verthys_ScanOpen(st->h, 0, SC_BATCH_F, &cur);
        if (rc != VERTHYS_OK) {
            InterlockedIncrement(&st->reader_errs);
            sc_record_err(st, (LONG)rc);
        } else {
            for (;;) {
                rc = Verthys_ScanFetch(cur, frecs, lids_f,
                                       SC_BATCH_F, &cnt, NULL, &fcnt);
                if (rc != VERTHYS_OK) {
                    InterlockedIncrement(&st->reader_errs);
                    sc_record_err(st, (LONG)rc);
                    break;
                }
                if (fcnt > 0) {
                    InterlockedExchangeAdd(&st->fetch_failed, (LONG)fcnt);
                }
                for (j = 0; j < cnt; j++) {
                    Verthys_ScanRecordFree(&frecs[j]);
                }
                if (cnt == 0) break;    /* 快照耗尽 */
            }
            if (Verthys_ScanClose(cur) != VERTHYS_OK) {
                InterlockedIncrement(&st->reader_errs);
            }
        }

        Sleep(0);    /* 让出时间片，写线程得以推进 */
    }
    return 0;
}

/* 探测线程：按类型轻量探测（无游标状态，纯快照遍历） */
static unsigned __stdcall sc_prober(void *arg)
{
    ScanConcState *st = (ScanConcState *)arg;

    while (st->stop == 0) {
        uint8_t found = 0;
        uint64_t lid = 0;
        VerthysResult rc;

        rc = Verthys_HasRecordByType(st->h, VERTHYS_RECORD_ACCOUNT, &found);
        if (rc != VERTHYS_OK) {
            InterlockedIncrement(&st->prober_errs);
            sc_record_err(st, (LONG)rc);
        } else if (found == 0) {
            /* seed 阶段已预置 ACCOUNT 记录，探测恒命中 */
            InterlockedIncrement(&st->prober_errs);
            sc_record_err(st, -1);
        }

        rc = Verthys_FindFirstLidByType(st->h, VERTHYS_RECORD_ACCOUNT,
                                        &found, &lid);
        if (rc != VERTHYS_OK) {
            InterlockedIncrement(&st->prober_errs);
            sc_record_err(st, (LONG)rc);
        } else if (found == 0 || lid == 0) {
            InterlockedIncrement(&st->prober_errs);
            sc_record_err(st, -2);
        }
        Sleep(0);
    }
    return 0;
}

/*
 * 主测试：seed → 三线程并发 → join → 后置统一断言。
 * 断言覆盖：写侧零失败、读侧零未预期错误、零解密失败条目、
 * 计数一致（seed+writes）、最后写入记录内容完整往返。
 */
TEST(scan_concurrent_readers_vs_writer)
{
    VerthysHandle h;
    VerthysResult rc;
    ScanConcState st;
    uint64_t total = 0;
    uint64_t expect = 0;
    uint32_t i;
    HANDLE threads[3];
    VerthysRecord last_out;

    sc_cleanup();
    memset(&st, 0, sizeof(st));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, SC_PATH, SC_PW, SC_PW_LEN,
                                      VERTHYS_PRESET_PERFORMANCE), VERTHYS_OK);
    st.h = h;

    /* 预置唯一记录（探测线程依赖至少一条 ACCOUNT 记录存在；
     * 序号自 0x10000 起，与写线程 0..SC_WRITES-1 空间不重叠） */
    for (i = 0; i < SC_SEED; i++) {
        ScanConcItem item;
        VerthysRecord r;
        uint64_t id = 0;

        sc_make_item(&item, 0x10000u + i);
        sc_fill_record(&r, &item);
        CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
        CHECK(id > 0);
    }

    /* 启动写/读/探测三线程（写线程生命周期覆盖整个读侧循环） */
    threads[0] = (HANDLE)_beginthreadex(NULL, 0, sc_writer, &st, 0, NULL);
    threads[1] = (HANDLE)_beginthreadex(NULL, 0, sc_reader, &st, 0, NULL);
    threads[2] = (HANDLE)_beginthreadex(NULL, 0, sc_prober, &st, 0, NULL);
    CHECK(threads[0] != NULL && threads[1] != NULL && threads[2] != NULL);

    CHECK_EQ(WaitForMultipleObjects(3, threads, TRUE, INFINITE),
             WAIT_OBJECT_0);
    CloseHandle(threads[0]);
    CloseHandle(threads[1]);
    CloseHandle(threads[2]);

    /* ---- 以下为 join 后统一断言（先完成全部操作与句柄清理） ---- */
    if (st.writer_fail != 0) {
        printf("  [FAIL] writer failures=%ld first_err=%ld\n",
               (long)st.writer_fail, (long)st.first_err);
        Verthys_Deinit(h);
        sc_cleanup();
        return 1;
    }
    CHECK_EQ((long)st.writer_ok, (long)SC_WRITES);
    if (st.reader_errs != 0) {
        printf("  [FAIL] reader errors=%ld first_err=%ld\n",
               (long)st.reader_errs, (long)st.first_err);
        Verthys_Deinit(h);
        sc_cleanup();
        return 1;
    }
    if (st.prober_errs != 0) {
        printf("  [FAIL] prober errors=%ld first_err=%ld\n",
               (long)st.prober_errs, (long)st.first_err);
        Verthys_Deinit(h);
        sc_cleanup();
        return 1;
    }
    if (st.fetch_failed != 0) {
        printf("  [FAIL] decrypted-record failures=%ld (misaligned reads)\n",
               (long)st.fetch_failed);
        Verthys_Deinit(h);
        sc_cleanup();
        return 1;
    }

    /* 计数一致性：seed + 写线程全量落库 */
    rc = Verthys_GetSummaryCount(h, &total);
    CHECK_EQ(rc, VERTHYS_OK);
    expect = (uint64_t)SC_SEED + (uint64_t)SC_WRITES;
    if (total != expect) {
        printf("  [FAIL] summary count=%llu != expected=%llu\n",
               (unsigned long long)total, (unsigned long long)expect);
        Verthys_Deinit(h);
        sc_cleanup();
        return 1;
    }

    /* 最后写入记录内容完整往返（确定性重构写线程末条内容） */
    {
        ScanConcItem expect_item;
        sc_make_item(&expect_item, SC_WRITES - 1);
        memset(&last_out, 0, sizeof(last_out));
        rc = Verthys_GetRecord(h, st.last_lid, &last_out);
        CHECK_EQ(rc, VERTHYS_OK);
        if (last_out.name_len != SC_NAME_LEN ||
            memcmp(last_out.name, expect_item.name, SC_NAME_LEN) != 0 ||
            last_out.data_len != SC_DATA_LEN ||
            memcmp(last_out.data, expect_item.data, SC_DATA_LEN) != 0) {
            printf("  [FAIL] last written record content mismatch\n");
            Verthys_Deinit(h);
            sc_cleanup();
            return 1;
        }
    }

    Verthys_Deinit(h);
    sc_cleanup();
    return 0;
}
