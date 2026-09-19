/*
 * syscall_direct.h — 设计规格与红线均位于同名头文件。
 *
 * 实现结构（自顶向下）：
 *   1. 模块状态与目标表（表驱动：两条 Zw/Nt 目标）
 *   2. ntdll 导出表防御性解析（边界纪律照文件头超级块反序列化样板）
 *   3. SSN 排序法提取（RVA 升序 + 仿射一致性 + 双锚点插值互证）
 *   4. stub 页构建（W^X：RW 写入 → RX 收紧；Strict CFG 检测）
 *   5. 公共包装（stub 优先 / GetProcAddress 回退 / NOT_IMPLEMENTED 兜底）
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
 *   zw_name — SSN 提取用（Zw 存根与 Nt 共享实现，读 Zw 导出 RVA）
 *   nt_name — GetProcAddress 回退解析名
 * 扩展新入口：本表追加一行（提取与 stub 生成均按表长循环，无需他处改动）。
 */
typedef struct ScdTarget {
    const char *zw_name;
    const char *nt_name;
    uint32_t    ssn;      /* 提取结果（激活时有效） */
    void       *fn;       /* 当前传输函数指针（stub 或回退导出） */
} ScdTarget;

static ScdTarget s_targets[] = {
    { "ZwQueryInformationProcess", "NtQueryInformationProcess", 0, NULL },
    { "ZwQuerySystemInformation",  "NtQuerySystemInformation",  0, NULL },
};
#define SCD_TARGET_COUNT (sizeof(s_targets) / sizeof(s_targets[0]))

/* 激活标志：1 = 全部 stub 均构建成功；0 = 整体降级（回退指针仍可用） */
static volatile LONG s_active = 0;

/* stub 页基址（激活时有效；进程级存续，无释放路径——同 job_isolation） */
static BYTE *s_stub_page = NULL;

/* 每条 stub 的槽位间距（11 字节代码 + 对齐填充） */
#define SCD_STUB_STRIDE 16u

/* Zw 存根机器码特征（x64：mov r10,rcx; mov eax,SSN）
 * 注：x86 进程下 ntdll Machine 为 I386，collect 阶段即拒绝（见下），
 * 本特征与 stub 构建代码在 x86 下不可达。 */
static const BYTE SCD_STUB_SIG[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };

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

    /* ---- PE 头防御性校验（边界纪律照文件头超级块反序列化样板） ---- */
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
            (memcmp(stub, SCD_STUB_SIG, sizeof(SCD_STUB_SIG)) == 0) ? 1 : 0;
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
 * 排序法提取（文件头 SSN 提取步骤）。
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
 *                     4. stub 页构建                                     *
 * ===================================================================== */

/*
 * 构建全部 stub（W^X 纪律：RW 写入 → RX 收紧）。
 * 返回 0 成功；非 0 = 内存不可得或收紧失败（调用方降级并释放页）。
 */
static int build_stub_page(const uint32_t ssns[SCD_TARGET_COUNT])
{
    BYTE *page = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (page == NULL) return -1;

    for (size_t i = 0; i < SCD_TARGET_COUNT; i++) {
        BYTE *stub = page + i * SCD_STUB_STRIDE;
        /* mov r10,rcx; mov eax,SSN; syscall; ret; int3 填充 */
        stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;
        stub[3] = 0xB8;
        memcpy(stub + 4, &ssns[i], sizeof(uint32_t));
        stub[8] = 0x0F; stub[9] = 0x05;
        stub[10] = 0xC3;
        memset(stub + 11, 0xCC, SCD_STUB_STRIDE - 11);
    }

    DWORD old_prot = 0;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return -1;
    }

    s_stub_page = page;
    return 0;
}

/*
 * Strict CFG 检测（文件头 stub 构建：Strict 模式下动态内存默认非法
 * 间接调用目标，激活将冒 fast-fail 风险 → 拒绝激活并降级）。
 * 返回 1 = 安全可激活（非 Strict 或策略查询失败按非 Strict 处理，
 *   查询失败仅存在于极老系统，彼时 Strict 模式尚不存在）；
 * 返回 0 = 检测到 Strict CFG，拒绝激活。
 */
static int cfg_allows_dynamic_targets(void)
{
    typedef BOOL (WINAPI *GetPolicy_t)(HANDLE, ULONG, PVOID, SIZE_T);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32 == NULL) return 1;

    GetPolicy_t get_policy =
        (GetPolicy_t)GetProcAddress(k32, "GetProcessMitigationPolicy");
    if (get_policy == NULL) return 1;  /* Win8 之前：无 CFG，无 Strict */

    /* ProcessControlFlowGuardPolicy = 6（winbase.h 枚举值，显式数值
     * 以避免老 SDK 头缺枚举成员；此处 SDK 10.0.26100 已含，双保险） */
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy;
    memset(&policy, 0, sizeof(policy));
    if (!get_policy(GetCurrentProcess(), 6, &policy, sizeof(policy))) {
        return 1;  /* 查询失败：按默认（非 Strict）处理 */
    }
    return policy.StrictMode ? 0 : 1;
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

    /* Strict CFG 环境直接降级（不构建 stub） */
    if (!cfg_allows_dynamic_targets()) goto degrade;

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

    if (build_stub_page(ssns) != 0) goto degrade;

    /* 激活：替换传输指针为 stub（x64 对齐指针写入原子，并发读者
     * 所见旧值 ntdll 导出 / 新值 stub 均为合法调用目标） */
    for (size_t i = 0; i < SCD_TARGET_COUNT; i++) {
        s_targets[i].ssn = ssns[i];
        s_targets[i].fn = s_stub_page + i * SCD_STUB_STRIDE;
    }
    InterlockedExchange(&s_active, 1);
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

int syscall_direct_init(void)
{
    InitOnceExecuteOnce(&s_init_once, scd_init_once, NULL, NULL);
    return 0;
}

int syscall_direct_available(void)
{
    syscall_direct_init();
    return s_active ? 1 : 0;
}

LONG syscall_NtQueryInformationProcess(
    HANDLE process, ULONG info_class, PVOID info, ULONG len, PULONG ret_len)
{
    syscall_direct_init();
    VerthysNtQueryInformationProcess_t fn =
        (VerthysNtQueryInformationProcess_t)s_targets[0].fn;
    if (fn == NULL) return STATUS_NOT_IMPLEMENTED;
    return fn(process, info_class, info, len, ret_len);
}

LONG syscall_NtQuerySystemInformation(
    ULONG info_class, PVOID info, ULONG len, PULONG ret_len)
{
    syscall_direct_init();
    VerthysNtQuerySystemInformation_t fn =
        (VerthysNtQuerySystemInformation_t)s_targets[1].fn;
    if (fn == NULL) return STATUS_NOT_IMPLEMENTED;
    return fn(info_class, info, len, ret_len);
}
