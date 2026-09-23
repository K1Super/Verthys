/*
 * runtime_hash.c — 运行时函数级哈希校验实现（内部模块，不导出）
 *
 * V3 升级：防运行时代码补丁。设计全文位于 runtime_hash.h。
 *
 * 关键实现纪律：
 *   - 重定位掩码双侧归一：构建期（rhash_gen，文件视角）与本文件（内存
 *     视角）对 .reloc 覆盖槽位同样清零——这是跨启动稳定性的前提
 *     （.vsec 的"节内存哈希跨启动不稳定"教训的函数级解法）；
 *   - 基础设施异常不阻断不误报（PE 解析失败/哈希失败/条目越界 → 返回
 *     通过），仅哈希失配计数——与 integrity.c / anti_debug.c 惯例一致；
 *   - 失配的应急响应只发生在 verify（生产入口），scan 保持纯检查
 *     （测试断言依赖无副作用语义）；
 *   - 本模块无任何秘密材料（被哈希对象与基准均非机密），无 secure_zero
 *     义务。
 *
 * .rhat 节由构建期 rhash_gen 工具补丁（core/tools/rhash_gen.c）：
 *   开发构建全零 = 未配置 = scan 空操作；verthys_tests.exe 由 POST_BUILD
 *   步骤同样补丁——真表路径在每轮开发测试中持续验证（构建期文件哈希 ≡
 *   运行期内存哈希，含重定位掩码正确性）。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "runtime_hash.h"
#include "verthys_crypto.h"      /* verthys_generichash（BLAKE2b-256） */
#include "emergency.h"         /* emergency_report / KILL */
#include <windows.h>
#include <string.h>
#include <stdlib.h>

/* ===================================================================== *
 *                          .rhat 节布局                                  *
 * ===================================================================== *
 * 二进制布局结构（VerthysRhatBlob/VerthysRhatEntry）单一事实源在
 * runtime_hash.h —— 与构建期工具 rhash_gen 共享，逐字节一致。
 */

/* 节定义（只读；scan volatile 引用其地址防 /OPT:REF 剪除——.vsec 同模式） */
#pragma section(".rhat", read)
__declspec(allocate(".rhat"))
static const VerthysRhatBlob g_rhat = { 0 };

/* ---------- 测试白盒 overlay ---------- */

typedef struct OverlayEntry {
    const uint8_t *addr;    /* 安装时目标区间基址 */
    size_t         len;
    int            valid;
    uint8_t        hash[32];
} OverlayEntry;

static OverlayEntry s_overlay[VERTHYS_RUNTIME_HASH_MAX];
static int s_overlay_count = 0;

/* ---------- 模块状态 ---------- */

/* 周期门控时间戳（GetTickCount64；0 = 进程启动后尚未扫描 → 首调即全量） */
static volatile ULONGLONG s_last_verify_ms = 0;

/* 扫描单飞标志：并发调用直接返回（API 层已持 api_mutex 串行化，
 * 此处仅防御应急线程/看门狗路径的交叉进入） */
static volatile LONG s_scanning = 0;

static int s_crypto_ready = 0;

/* 掩码哈希输入缓冲：标签 ‖ 掩码后函数字节（≤ 23 + 64KB，BSS 非秘密） */
static uint8_t s_hbuf[sizeof(VERTHYS_RHASH_LABEL) - 1u +
                      VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES];

/* ===================================================================== *
 *                     重定位槽位收集（内存视角 .reloc）                   *
 * ===================================================================== */

typedef struct RhSpot {
    uint32_t rva;      /* 重定位目标 RVA */
    uint8_t  width;    /* 掩码字节数（DIR64=8 / HIGHLOW=4 / HIGH|LOW=2） */
} RhSpot;

/* qsort 比较器：按 RVA 升序（掩码扫描依赖升序提前终止） */
static int spot_cmp(const void *a, const void *b)
{
    uint32_t ra = ((const RhSpot *)a)->rva;
    uint32_t rb = ((const RhSpot *)b)->rva;
    return (ra < rb) ? -1 : (ra > rb) ? 1 : 0;
}

/*
 * 解析自身内存映像的 .reloc 目录，收集全部重定位槽位。
 *   out_spots / out_count：动态分配结果（调用方 free；*out_spots 初始可为 NULL）。
 * 返回 0 成功；-1 = 基础设施异常（无重定位目录不算异常，返回 0 条；
 *   恶意块边界 / 未知重定位类型 / 内存不足）——调用方按"不误报"惯例
 *   放弃本次扫描。
 * 容量说明：x64 .rdata 的 vtable/RTTI 指针普遍携带 DIR64 重定位，总数
 *   可达数万，远超任何固定上限——必须动态增长（倍增 realloc），
 *   否则"缓冲不足 → 放弃扫描"会让校验静默失效（红线）。
 *   .reloc 目录天然按页升序；仍以 qsort 兜底防御异常映像。
 */
static int collect_reloc_spots(const BYTE *base, const IMAGE_NT_HEADERS *nt,
                               RhSpot **out_spots, size_t *out_count)
{
    *out_spots = NULL;
    *out_count = 0;

    const IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        return 0;  /* 无重定位（固定基址映像）：掩码为空集，合法 */
    }
    if ((uint64_t)dir->VirtualAddress + dir->Size > nt->OptionalHeader.SizeOfImage) {
        return -1; /* 目录越界：异常映像 */
    }

    const uint8_t *p    = base + dir->VirtualAddress;
    const uint8_t *pend = p + dir->Size;
    RhSpot *spots = NULL;
    size_t  n = 0, cap = 0;

    while (p + 8 <= pend) {
        uint32_t page_rva   = *(const uint32_t *)(const void *)p;
        uint32_t block_size = *(const uint32_t *)(const void *)(p + 4);
        if (block_size < 8 || p + block_size > pend) {
            free(spots);
            return -1; /* 恶意块边界 */
        }
        for (uint32_t off = 8; off + sizeof(uint16_t) <= block_size;
             off += sizeof(uint16_t)) {
            uint16_t e = *(const uint16_t *)(const void *)(p + off);
            uint16_t type = (uint16_t)(e >> 12);
            uint16_t roff = (uint16_t)(e & 0x0FFF);
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue; /* 填充 */

            uint8_t width;
            if (type == IMAGE_REL_BASED_DIR64)        width = 8;
            else if (type == IMAGE_REL_BASED_HIGHLOW) width = 4;
            else if (type == IMAGE_REL_BASED_HIGH ||
                     type == IMAGE_REL_BASED_LOW)      width = 2;
            else return -1; /* 未知类型：无法归一化，放弃（不误报） */

            if (n == cap) {
                size_t ncap = cap ? cap * 2 : 4096;
                RhSpot *grown = (RhSpot *)realloc(spots, ncap * sizeof(RhSpot));
                if (grown == NULL) { free(spots); return -1; }
                spots = grown;
                cap = ncap;
            }
            spots[n].rva   = page_rva + roff;
            spots[n].width = width;
            n++;
        }
        p += block_size;
    }

    /* 升序排序兜底（目录本已有序，此处防御异常映像；n log n 恒定复杂度） */
    if (n > 1) {
        qsort(spots, n, sizeof(RhSpot), spot_cmp);
    }
    *out_spots = spots;
    *out_count = n;
    return 0;
}

/* ===================================================================== *
 *                     掩码哈希（双侧一致的归一化核心）                    *
 * ===================================================================== */

/*
 * 对 [mem, mem+len) 计算域标签前缀 + 重定位槽位掩码后的 BLAKE2b-256。
 *   base / spots / spot_count：自身映像基与已收集槽位（spots 按 RVA 升序）。
 *   mem 不在映像内（测试 overlay 的任意地址）→ 无槽位可掩（rva 判越界）。
 * 返回 0 成功；非 0 = 基础设施异常（哈希失败 / 超出缓冲上限）。
 */
static int masked_hash(const BYTE *base, const RhSpot *spots, size_t spot_count,
                       const uint8_t *mem, size_t len, uint8_t out[32])
{
    if (mem == NULL || len == 0 || len > VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES) {
        return -1;
    }

    /* 缓冲布局：[0, label_len) 标签 ‖ [label_len, +len) 掩码后字节 */
    static const uint8_t label[] = VERTHYS_RHASH_LABEL;
    const size_t label_len = sizeof(label) - 1u;
    memcpy(s_hbuf, label, label_len);
    memcpy(s_hbuf + label_len, mem, len);

    /* 掩码：与区间相交的槽位清零（部分相交按交集裁剪） */
    if (base != NULL) {
        uint64_t rva = (uint64_t)(mem - base);
        uint64_t end = rva + len;
        if (rva < ((uint64_t)1 << 32)) { /* 32 位 RVA 域内才可能命中槽位 */
            for (size_t i = 0; i < spot_count; i++) {
                uint64_t s_start = spots[i].rva;
                uint64_t s_end   = s_start + spots[i].width;
                if (s_start >= end) break;   /* 升序，后续更远 */
                uint64_t o_lo = (s_start > rva) ? s_start : rva;
                uint64_t o_hi = (s_end   < end) ? s_end   : end;
                if (o_hi > o_lo) {
                    memset(s_hbuf + label_len + (size_t)(o_lo - rva), 0,
                           (size_t)(o_hi - o_lo));
                }
            }
        }
    }

    return verthys_generichash(out, s_hbuf, label_len + len);
}

/* ===================================================================== *
 *                              公共接口                                  *
 * ===================================================================== */

int runtime_hash_configured(void)
{
    const volatile VerthysRhatBlob *t = &g_rhat; /* volatile 防优化剪除节引用 */
    if (t->magic[0] != VERTHYS_RHAT_MAGIC0 || t->magic[1] != VERTHYS_RHAT_MAGIC1 ||
        t->magic[2] != VERTHYS_RHAT_MAGIC2 || t->magic[3] != VERTHYS_RHAT_MAGIC3) {
        return 0;
    }
    return (t->version == VERTHYS_RHAT_VERSION && t->count > 0 &&
            t->count <= VERTHYS_RUNTIME_HASH_MAX) ? 1 : 0;
}

int runtime_hash_scan(void)
{
    /* 单飞：并发进入直接返回通过（API 层 api_mutex 已串行化写路径） */
    if (InterlockedCompareExchange(&s_scanning, 1, 0) != 0) {
        return 0;
    }

    int mismatches = 0;

    do {
        if (!s_crypto_ready) {
            if (verthys_crypto_init() != 0) break;      /* libsodium 不可用 */
            s_crypto_ready = 1;
        }

        /* 1. 定位自身模块与 NT 头（基础设施异常 → 不阻断不误报） */
        HMODULE hSelf = NULL;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)&runtime_hash_scan, &hSelf) ||
            hSelf == NULL) {
            break;
        }
        const BYTE *base = (const BYTE *)hSelf;
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) break;
        const IMAGE_NT_HEADERS *nt =
            (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) break;
        const uint32_t image_size = nt->OptionalHeader.SizeOfImage;

        /* 2. 收集重定位槽位（未知类型/越界/超量 → 放弃本次扫描不误报） */
        RhSpot *spots = NULL;
        size_t spot_count = 0;
        if (collect_reloc_spots(base, nt, &spots, &spot_count) != 0) {
            free(spots);
            break;
        }

        /* 3. .rhat 表项逐条校验 */
        const volatile VerthysRhatBlob *t = &g_rhat;
        int abort_scan = 0;
        if (t->magic[0] == VERTHYS_RHAT_MAGIC0 &&
            t->magic[1] == VERTHYS_RHAT_MAGIC1 &&
            t->magic[2] == VERTHYS_RHAT_MAGIC2 &&
            t->magic[3] == VERTHYS_RHAT_MAGIC3 &&
            t->version == VERTHYS_RHAT_VERSION) {
            uint16_t count = t->count;
            if (count > VERTHYS_RUNTIME_HASH_MAX) { free(spots); break; }
            for (uint16_t i = 0; i < count; i++) {
                /* 表项快照：表为 volatile 限定（防编译器缓存读取），
                 * 逐字段 volatile 读入本地副本后再操作——既保持读取
                 * 语义，又杜绝后续memcmp/取址的限定符丢失（C4090） */
                VerthysRhatEntry ent;
                ent.rva     = t->entry[i].rva;
                ent.size    = t->entry[i].size;
                ent.x_index = t->entry[i].x_index;
                for (size_t k = 0; k < sizeof(ent.hash); k++) {
                    ent.hash[k] = t->entry[i].hash[k];
                }
                /* 边界防御（伪造表）：RVA/长度越界映像 → 放弃本次扫描
                 * （仅跳出本层 for；spots 释放收口统一在下方 abort_scan） */
                if (ent.size == 0 || ent.size > VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES ||
                    ent.rva < 0x1000u ||
                    (uint64_t)ent.rva + ent.size > image_size) {
                    abort_scan = 1;
                    break;
                }
                uint8_t hash[32];
                if (masked_hash(base, spots, spot_count,
                                base + ent.rva, ent.size, hash) != 0) {
                    continue; /* 单条计算失败：基础设施异常，不计失配 */
                }
                if (memcmp(hash, ent.hash, 32) != 0) mismatches++;
            }
        }
        if (abort_scan) { free(spots); break; }

        /* 4. overlay 测试基准逐条校验（白盒机制，与表无关） */
        for (int i = 0; i < s_overlay_count; i++) {
            if (!s_overlay[i].valid) continue;
            uint8_t hash[32];
            if (masked_hash(base, spots, spot_count,
                            s_overlay[i].addr, s_overlay[i].len, hash) != 0) {
                continue;
            }
            if (memcmp(hash, s_overlay[i].hash, 32) != 0) mismatches++;
        }

        free(spots);
    } while (0);

    InterlockedExchange(&s_scanning, 0);
    return mismatches;
}

void runtime_hash_verify(void)
{
    if (runtime_hash_scan() > 0) {
        /* 进程内存被篡改（高置信度）→ KILL（应急模块终止进程） */
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_PROCESS_TAMPER);
    }
}

void runtime_hash_verify_periodic(void)
{
    ULONGLONG now = GetTickCount64();
    if (now - s_last_verify_ms < VERTHYS_RUNTIME_HASH_INTERVAL_MS) return;
    s_last_verify_ms = now;
    runtime_hash_verify();
}

/* ---------- 测试白盒 ---------- */

int runtime_hash_test_install(const void *addr, size_t len)
{
    if (addr == NULL || len == 0 || len > VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES) {
        return -1;
    }

    /* 与 verify 路径同锁：进入 s_scanning 单飞区，串行化 s_hbuf 共享掩码
     * 缓冲与 s_overlay 表的写入，杜绝与并发 scan 的双写撕裂 */
    if (InterlockedCompareExchange(&s_scanning, 1, 0) != 0) {
        return -1;  /* 已有扫描在途：调用方稍后重试 */
    }

    int rc = -1;
    do {
        if (s_overlay_count >= VERTHYS_RUNTIME_HASH_MAX) break;

        /* 自基线：以当前内存内容计算掩码哈希作为基准 */
        if (!s_crypto_ready) {
            if (verthys_crypto_init() != 0) break;
            s_crypto_ready = 1;
        }
        HMODULE hSelf = NULL;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)&runtime_hash_scan, &hSelf) ||
            hSelf == NULL) {
            break;
        }
        const BYTE *base = (const BYTE *)hSelf;
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) break;
        const IMAGE_NT_HEADERS *nt =
            (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) break;

        RhSpot *spots = NULL;
        size_t spot_count = 0;
        if (collect_reloc_spots(base, nt, &spots, &spot_count) == 0) {
            OverlayEntry *o = &s_overlay[s_overlay_count];
            if (masked_hash(base, spots, spot_count,
                            (const uint8_t *)addr, len, o->hash) == 0) {
                o->addr  = (const uint8_t *)addr;
                o->len   = len;
                o->valid = 1;
                s_overlay_count++;
                rc = 0;
            }
        }
        free(spots);
    } while (0);

    InterlockedExchange(&s_scanning, 0);
    return rc;
}

int runtime_hash_lookup(const void *func,
                        const void **out_base, size_t *out_len)
{
    if (func == NULL) return 0;

    HMODULE hSelf = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&runtime_hash_scan, &hSelf) ||
        hSelf == NULL) {
        return 0;
    }
    const BYTE *base = (const BYTE *)hSelf;
    uint64_t rva = (uint64_t)((const BYTE *)func - base);

    /* .rhat 表精确起点匹配 */
    const volatile VerthysRhatBlob *t = &g_rhat;
    if (t->magic[0] == VERTHYS_RHAT_MAGIC0 &&
        t->magic[1] == VERTHYS_RHAT_MAGIC1 &&
        t->magic[2] == VERTHYS_RHAT_MAGIC2 &&
        t->magic[3] == VERTHYS_RHAT_MAGIC3 &&
        t->version == VERTHYS_RHAT_VERSION &&
        t->count <= VERTHYS_RUNTIME_HASH_MAX) {
        for (uint16_t i = 0; i < t->count; i++) {
            if (t->entry[i].rva == rva) {
                if (out_base) *out_base = base + t->entry[i].rva;
                if (out_len)  *out_len  = t->entry[i].size;
                return 1;
            }
        }
    }

    /* overlay 基址匹配 */
    for (int i = 0; i < s_overlay_count; i++) {
        if (s_overlay[i].valid && s_overlay[i].addr == func) {
            if (out_base) *out_base = s_overlay[i].addr;
            if (out_len)  *out_len  = s_overlay[i].len;
            return 1;
        }
    }
    return 0;
}

void runtime_hash_test_clear(void)
{
    /* 与 verify 路径同锁：s_overlay 表写入须串行化于 s_scanning 单飞区，
     * 防与并发 scan 的 overlay 读取产生撕裂 */
    if (InterlockedCompareExchange(&s_scanning, 1, 0) != 0) {
        return;  /* 已有扫描在途：跳过本次清空（单线程 teardown 不会触发） */
    }
    for (int i = 0; i < s_overlay_count; i++) {
        s_overlay[i].valid = 0;
        s_overlay[i].addr  = NULL;
        s_overlay[i].len   = 0;
    }
    s_overlay_count = 0;
    InterlockedExchange(&s_scanning, 0);
}
