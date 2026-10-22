/*
 * syscall_direct.c — 直连系统调用传输实现
 *
 * 实现结构：
 *   1. 模块状态与目标表
 *   2. ntdll 导出表防御性解析
 *   3. SSN 排序法提取（RVA 升序 + 仿射一致性 + 双锚点插值互证）
 *   4. 映像内 thunk 激活（SSN 写数据槽 + 完全屏障发布）
 *   5. 公共包装（thunk 优先 / GetProcAddress 回退 / NOT_IMPLEMENTED 兜底）
 *
 * 关键约束：
 *   - 不申请运行期可执行内存：ACG 禁止把非映像内存变为可执行页。
 *   - thunk 仅被包装函数直接调用，不进入间接调用路径。
 *   - SSN 槽写入完成前不得发布激活标志；标志发布后槽位不再修改。
 */
#include "syscall_direct.h"
#include "emergency.h"

#include <string.h>
#include <stdlib.h>

/* ===================================================================== *
 *                        1. 模块状态与目标表                            *
 * ===================================================================== */

/*
 * 直接系统调用目标（仅检测器实际使用的两个入口）。
 *   zw_name — SSN 提取用（Zw 存根与 Nt 共享实现，读取 Zw 导出 RVA）
 *   nt_name — GetProcAddress 回退解析名
 *   fn      — 回退传输函数；激活后包装函数优先直调映像内 thunk
 * 新增目标需要同步增加目标表项、SSN 数据槽与 thunk；
 * 数量一致性由编译期断言约束。
 */
typedef struct ScdTarget {
    const char *zw_name;
    const char *nt_name;
    void       *fn;
} ScdTarget;

static ScdTarget s_targets[] = {
    { "ZwQueryInformationProcess", "NtQueryInformationProcess", NULL },
    { "ZwQuerySystemInformation",  "NtQuerySystemInformation",  NULL },
};
#define SCD_TARGET_COUNT (sizeof(s_targets) / sizeof(s_targets[0]))

#if defined(VERTHYS_SCD_INLINE_THUNK)
#if !defined(_M_AMD64)
#error "VERTHYS_SCD_INLINE_THUNK requires an x64 target"
#endif

/* 映像内 thunk 与 SSN 数据槽；定义位于 MASM 源文件。 */
extern volatile uint32_t verthys_scd_ssn0;
extern volatile uint32_t verthys_scd_ssn1;
extern LONG NTAPI verthys_scd_thunk0(HANDLE, ULONG, PVOID, ULONG, PULONG);
extern LONG NTAPI verthys_scd_thunk1(ULONG, PVOID, ULONG, PULONG);

_Static_assert(SCD_TARGET_COUNT == 2,
               "inline thunk set must match the syscall target table");
#endif

/* 激活标志：1 = 映像内 thunk 可用；0 = 回退 ntdll 导出 */
static volatile LONG s_active = 0;

/* Zw 存根机器码特征（x64：mov r10,rcx; mov eax,SSN）
 * x86 映像在导出表收集阶段被拒绝，本特征与 thunk 实现均为 x64 专用。 */
static const BYTE SCD_ZW_STUB_SIG[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };

/* SSN 合法上界（x64 系统调用号实际 < 0x300；上界同时兜底捕获无符号
 * 插值回绕产生的 0xFFFFxxxx 类垃圾值） */
#define SCD_SSN_MAX 0x1000u

/* PE 头部合法域上界（真实 PE e_lfanew < 0x200；0x400 + NT 头 0x108
 * 仍 < 0x1000 ≤ SizeOfImage，保证 NT 头读取必在映像界内） */
#define SCD_LFANEW_MAX 0x400

/* 映像大小上界（真实 ntdll 数 MB；防御畸形 PE 声明超大映像） */
#define SCD_IMAGE_SIZE_MAX (256u << 20)

/* -------------------------------------------------------------------- *
 * 初始化一次执行（InitOnceExecuteOnce 回调）                            *
 * -------------------------------------------------------------------- */

static BOOL WINAPI scd_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx);
static INIT_ONCE s_init_once = INIT_ONCE_STATIC_INIT;

/* ===================================================================== *
 *                     2. ntdll 导出表防御性解析                          *
 * ===================================================================== */

/* Zw* 导出条目（提取用中间结构） */
typedef struct ScdZwEntry {
    uint32_t rva;       /* 存根 RVA（映像基相对） */
    uint32_t ssn;       /* 特征命中时读出的系统调用号 */
    int      valid;     /* 1 = 特征命中（存根未被 Hook），0 = 特征不符 */
} ScdZwEntry;

/* qsort 比较器：按 RVA 升序 */
static int zw_entry_cmp(const void *a, const void *b)
{
    uint32_t ra = ((const ScdZwEntry *)a)->rva;
    uint32_t rb = ((const ScdZwEntry *)b)->rva;
    return (ra < rb) ? -1 : (ra > rb) ? 1 : 0;
}

/*
 * 带上限的导出名比较（目标名匹配专用）。
 *   返回 0 = 完全相等；非 0 = 不等或名字越界（防御未终止字符串）。
 */
static int name_equals_bounded(const BYTE *base, uint32_t name_rva,
                               uint32_t image_size, const char *expect)
{
    if (name_rva >= image_size) return 1;
    size_t len = strlen(expect);
    /* 名字与结尾 NUL 均须在映像界内（uint64 加法防回绕） */
    if ((uint64_t)name_rva + len + 1 > image_size) return 1;
    return (memcmp(base + name_rva, expect, len + 1) == 0) ? 0 : 1;
}

/*
 * 解析 ntdll 导出表，收集全部 Zw* 存根条目。
 *   out_entries / out_count：堆分配结果（调用方 free）。
 *   out_target_rva[i]：第 i 个目标 Zw 存根的 RVA（0 = 导出表无此名）。
 *   （记录 RVA 而非下标：qsort 原地重排后 RVA 仍是稳定键。）
 * 返回 0 成功；非 0 = PE 结构异常（调用方降级）。
 */
static int collect_zw_entries(const BYTE *base, ScdZwEntry **out_entries,
                              size_t *out_count,
                              uint32_t out_target_rva[SCD_TARGET_COUNT])
{
    *out_entries = NULL;
    *out_count = 0;
    for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
        out_target_rva[t] = 0;
    }

    /* ---- PE 头防御性校验：所有偏移与长度必须先落到映像声明的边界内 ---- */
    if (base == NULL) return -1;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    if (dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
        dos->e_lfanew > SCD_LFANEW_MAX) {
        return -1;
    }
    const IMAGE_NT_HEADERS *nt_hdr =
        (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) return -1;
    if (nt_hdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return -1;

    const uint32_t image_size = nt_hdr->OptionalHeader.SizeOfImage;
    if (image_size < 0x1000 || image_size > SCD_IMAGE_SIZE_MAX) return -1;

    /* ---- 导出目录 ---- */
    const IMAGE_DATA_DIRECTORY *dir =
        &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0 || dir->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return -1;
    }
    if ((uint64_t)dir->VirtualAddress + dir->Size > image_size) return -1;
    const IMAGE_EXPORT_DIRECTORY *exp =
        (const IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);

    if (exp->NumberOfNames == 0 || exp->NumberOfNames > 0x10000u) return -1;
    if (exp->AddressOfNames == 0 || exp->AddressOfNameOrdinals == 0 ||
        exp->AddressOfFunctions == 0) {
        return -1;
    }
    /* 三个数组整体在映像界内（uint64 宽度加法，防 DWORD 回绕） */
    if ((uint64_t)exp->AddressOfNames +
            (uint64_t)exp->NumberOfNames * 4 > image_size ||
        (uint64_t)exp->AddressOfNameOrdinals +
            (uint64_t)exp->NumberOfNames * 2 > image_size ||
        (uint64_t)exp->AddressOfFunctions +
            (uint64_t)exp->NumberOfFunctions * 4 > image_size) {
        return -1;
    }
    const DWORD *names = (const DWORD *)(base + exp->AddressOfNames);
    const WORD  *ords  = (const WORD  *)(base + exp->AddressOfNameOrdinals);
    const DWORD *funcs = (const DWORD *)(base + exp->AddressOfFunctions);

    /* ---- 收集 Zw* 条目 ---- */
    ScdZwEntry *entries =
        (ScdZwEntry *)malloc(exp->NumberOfNames * sizeof(ScdZwEntry));
    if (entries == NULL) return -1;

    size_t count = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        uint32_t name_rva = names[i];
        if (name_rva >= image_size) continue;        /* 越界/回绕防御 */
        if (name_rva + 3 >= image_size) continue;    /* "ZwX\0" 最小长度不足 */

        const BYTE *name = base + name_rva;
        if (name[0] != 'Z' || name[1] != 'w') continue;

        WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions) continue; /* 序号越界 */
        uint32_t fn_rva = funcs[ord];
        if (fn_rva == 0 || fn_rva >= image_size) continue;
        if (fn_rva + 8 > image_size) continue;       /* 8 字节特征窗口不足 */

        const BYTE *stub = base + fn_rva;
        entries[count].rva = fn_rva;
        entries[count].valid =
            (memcmp(stub, SCD_ZW_STUB_SIG, sizeof(SCD_ZW_STUB_SIG)) == 0) ? 1 : 0;
        if (entries[count].valid) {
            /* mov eax, imm32：SSN 在 +4 偏移 */
            uint32_t ssn;
            memcpy(&ssn, stub + 4, sizeof(ssn));
            entries[count].ssn = ssn;
        } else {
            entries[count].ssn = 0;
        }

        /* 目标名匹配（记录 RVA 稳定键） */
        for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
            if (out_target_rva[t] == 0 &&
                name_equals_bounded(base, name_rva, image_size,
                                    s_targets[t].zw_name) == 0) {
                out_target_rva[t] = fn_rva;
            }
        }
        count++;
    }

    if (count == 0) {
        free(entries);
        return -1;
    }
    *out_entries = entries;
    *out_count = count;
    return 0;
}

/* ===================================================================== *
 *                     3. SSN 排序法提取                                  *
 * ===================================================================== */

/*
 * 排序法提取。
 *   entries 已按 RVA 升序。位次（sorted position）语义：
 *   SSN[pos] = SSN[anchor] + (pos - anchor_pos)。
 *
 * 校验层次（宁降级不误算）：
 *   a. 全表仿射一致性：任意相邻有效锚点对必须满足
 *      SSN 差 == 位次差——任何布局异常（间隙/乱序/别名占据位次）
 *      都会破坏该等式，整体降级；
 *   b. 目标未被 Hook：直接读取值必须与两侧锚点插值一致；
 *   c. 目标被 Hook：双侧锚点插值互证，单侧锚点单证；
 *   d. 结果 SSN 上界检查（兜底捕获无符号回绕垃圾值）。
 * 返回 0 = 全部目标均提取且自洽；非 0 = 不可信（降级）。
 */
static int extract_ssns_sorted(ScdZwEntry *entries, size_t count,
                               const uint32_t target_rva[SCD_TARGET_COUNT],
                               uint32_t out_ssn[SCD_TARGET_COUNT])
{
    qsort(entries, count, sizeof(ScdZwEntry), zw_entry_cmp);

    /* ---- 排序后按 RVA 定位目标位次 ---- */
    int target_pos[SCD_TARGET_COUNT];
    for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
        target_pos[t] = -1;
    }
    for (size_t i = 0; i < count; i++) {
        for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
            if (target_pos[t] < 0 && entries[i].rva == target_rva[t]) {
                target_pos[t] = (int)i;
            }
        }
    }
    for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
        if (target_pos[t] < 0) return -1;
    }

    /* ---- a. 全表仿射一致性（相邻有效锚点对） ----
     * 无符号减法回绕时差值巨大 ≠ 位次差，天然命中降级分支。 */
    int prev = -1;
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].valid) continue;
        if (prev >= 0 &&
            entries[i].ssn - entries[prev].ssn != (uint32_t)(i - (size_t)prev)) {
            return -1;
        }
        prev = (int)i;
    }
    if (prev < 0) return -1;   /* 全表无有效特征锚点 */

    /* ---- b/c. 逐目标提取 ---- */
    for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
        int pos = target_pos[t];
        int before = -1, after = -1;
        for (int i = pos - 1; i >= 0; i--) {
            if (entries[i].valid) { before = i; break; }
        }
        for (size_t i = (size_t)pos + 1; i < count; i++) {
            if (entries[i].valid) { after = (int)i; break; }
        }

        uint32_t ssn;
        if (entries[pos].valid) {
            /* 目标未被 Hook：直接读取为准，锚点插值互证 */
            if (before >= 0 &&
                entries[pos].ssn !=
                    entries[before].ssn + (uint32_t)(pos - before)) {
                return -1;
            }
            if (after >= 0 &&
                entries[after].ssn !=
                    entries[pos].ssn + (uint32_t)(after - pos)) {
                return -1;
            }
            ssn = entries[pos].ssn;
        } else {
            /* 目标被 Hook（或非标准存根）：锚点插值 */
            if (before >= 0 && after >= 0) {
                uint32_t lo = entries[before].ssn + (uint32_t)(pos - before);
                uint32_t hi = entries[after].ssn - (uint32_t)(after - pos);
                if (lo != hi) return -1;     /* 双侧互证失败 */
                ssn = lo;
            } else if (before >= 0) {
                ssn = entries[before].ssn + (uint32_t)(pos - before);
            } else if (after >= 0) {
                ssn = entries[after].ssn - (uint32_t)(after - pos);
            } else {
                return -1;                   /* 目标附近无任何锚点 */
            }
        }

        if (ssn > SCD_SSN_MAX) return -1;    /* d. 上界兜底 */
        out_ssn[t] = ssn;
    }
    return 0;
}

/* ===================================================================== *
 *                     4. 映像内 thunk 激活                               *
 * ===================================================================== */

/*
 * 发布映像内 thunk。
 *   - SSN 先写入可写数据槽，再以 InterlockedExchange 形成完全屏障并置激活标志；
 *   - 激活后槽位不再修改，包装函数可无锁读取；
 *   - 无内置 thunk 的构建返回非 0，调用方保持 GetProcAddress 回退。
 * 返回 0 成功；非 0 = 当前构建不提供 thunk。
 */
static int activate_inline_thunks(const uint32_t ssns[SCD_TARGET_COUNT])
{
#if defined(VERTHYS_SCD_INLINE_THUNK)
    verthys_scd_ssn0 = ssns[0];
    verthys_scd_ssn1 = ssns[1];
    InterlockedExchange(&s_active, 1);
    return 0;
#else
    (void)ssns;
    return -1;
#endif
}

/* ===================================================================== *
 *                       初始化编排                                       *
 * ===================================================================== */

static BOOL WINAPI scd_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;

    /* 回退指针先行解析：无论提取成败，包装函数都需要可用传输 */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != NULL) {
        for (size_t i = 0; i < SCD_TARGET_COUNT; i++) {
            s_targets[i].fn = (void *)GetProcAddress(ntdll, s_targets[i].nt_name);
        }
    }

    const BYTE *base = (const BYTE *)ntdll;

    ScdZwEntry *entries = NULL;
    size_t count = 0;
    uint32_t target_rva[SCD_TARGET_COUNT];
    uint32_t ssns[SCD_TARGET_COUNT];
    for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
        target_rva[t] = 0;
        ssns[t] = 0;
    }

    if (base == NULL) goto degrade;
    if (collect_zw_entries(base, &entries, &count, target_rva) != 0) {
        goto degrade;
    }
    for (size_t t = 0; t < SCD_TARGET_COUNT; t++) {
        if (target_rva[t] == 0) goto degrade_free;  /* 导出表缺目标名 */
    }

    /* 排序 + 提取（extract_ssns_sorted 内含全部自洽校验） */
    if (extract_ssns_sorted(entries, count, target_rva, ssns) != 0) {
        goto degrade_free;
    }
    free(entries);
    entries = NULL;

    /* 全部目标 SSN 自洽后才发布 thunk；失败保持回退传输 */
    if (activate_inline_thunks(ssns) != 0) goto degrade;
    return TRUE;

degrade_free:
    free(entries);
degrade:
    /* TELEMETRY 留痕（低置信度基础设施异常，无处置） */
    emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_SYSCALL_EXTRACT_FAIL);
    return TRUE;
}

/* ===================================================================== *
 *                     5. 公共包装                                        *
 * ===================================================================== */

/*
 * 初始化入口。
 * 幂等：InitOnceExecuteOnce 保证进程内只执行一次；并发调用者阻塞到初始化完成。
 * 返回值固定为 0，激活结果由 syscall_direct_available() 判断。
 */
int syscall_direct_init(void)
{
    InitOnceExecuteOnce(&s_init_once, scd_init_once, NULL, NULL);
    return 0;
}

/*
 * 激活状态查询。
 * 读取发生在初始化屏障之后；激活标志只在初始化期间单向置位，此后不再变化。
 */
int syscall_direct_available(void)
{
    syscall_direct_init();
    return (InterlockedCompareExchange(&s_active, 0, 0) != 0) ? 1 : 0;
}

/*
 * NtQueryInformationProcess 传输。
 * 激活时直接调用映像内 thunk；未激活时调用回退函数指针。
 * 直接调用不经过间接分支校验；两种传输保持同一 NT 语义。
 */
LONG syscall_NtQueryInformationProcess(
    HANDLE process, ULONG info_class, PVOID info, ULONG len, PULONG ret_len)
{
    syscall_direct_init();
#if defined(VERTHYS_SCD_INLINE_THUNK)
    if (InterlockedCompareExchange(&s_active, 0, 0) != 0) {
        return verthys_scd_thunk0(process, info_class, info, len, ret_len);
    }
#endif
    VerthysNtQueryInformationProcess_t fn =
        (VerthysNtQueryInformationProcess_t)s_targets[0].fn;
    if (fn == NULL) return STATUS_NOT_IMPLEMENTED;
    return fn(process, info_class, info, len, ret_len);
}

/*
 * NtQuerySystemInformation 传输。
 * 传输策略与 syscall_NtQueryInformationProcess 一致。
 */
LONG syscall_NtQuerySystemInformation(
    ULONG info_class, PVOID info, ULONG len, PULONG ret_len)
{
    syscall_direct_init();
#if defined(VERTHYS_SCD_INLINE_THUNK)
    if (InterlockedCompareExchange(&s_active, 0, 0) != 0) {
        return verthys_scd_thunk1(info_class, info, len, ret_len);
    }
#endif
    VerthysNtQuerySystemInformation_t fn =
        (VerthysNtQuerySystemInformation_t)s_targets[1].fn;
    if (fn == NULL) return STATUS_NOT_IMPLEMENTED;
    return fn(info_class, info, len, ret_len);
}
