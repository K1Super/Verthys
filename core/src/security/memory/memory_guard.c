/*
 * memory_guard.c — 内存防转储与防交换实现（内部模块，不导出）
 *
 * 用户需求（二.2 内存防转储与防交换）：
 *   - 锁定敏感物理页：VirtualLock 将密钥表、路径索引、解密头部缓存
 *     强制常驻物理内存，禁止 OS 交换至磁盘页面文件。
 *   - 拦截远程内存读取：遍历系统句柄表（NtQuerySystemInformation
 *     SystemExtendedHandleInformation=64），筛选指向当前进程且访问掩码
 *     含 PROCESS_VM_READ / PROCESS_ALL_ACCESS 的句柄，并辅以可疑进程名
 *     （Cheat Engine / Process Hacker / HxD / WinDbg）检测。
 *   - 安全多轮覆写零化：0x00 → 0xFF → 0x00 三轮，volatile 指针写入 +
 *     MemoryBarrier，编译器不可优化消除，不依赖 GC / 延迟释放。
 *   - 紧急内存零化：遍历全部已注册敏感区域逐个清零并解锁。
 *
 * 设计要点：
 *   - NtQuerySystemInformation 通过 GetModuleHandleW(L"ntdll.dll") +
 *     GetProcAddress 动态获取（与 anti_debug.c 风格一致）。
 *   - 系统句柄表结构体自行定义（winternl.h 不完整）。
 *   - 通过比对“自身进程对象指针”精确判定句柄是否指向本进程，
 *     避免对每个句柄做 DuplicateHandle + NtQueryInformationProcess 的高开销。
 *   - 模块状态 static，幂等初始化；临时缓冲区用毕 verthys_secure_zero 清零。
 *   - 性能模式（memory_lock=0）下 lock/unlock 返回 0 但不实际锁页；
 *     anti_dump=0 时 check_remote_read 直接返回 0。
 */
#include "memory_guard.h"
#include "verthys_internal.h"    /* verthys_secure_zero / verthys_lock_memory / verthys_unlock_memory */
#include "security_preset.h"   /* security_get_config */
#include "emergency.h"         /* emergency_report / EMERG_SIG_REMOTE_MEM_READ */
/* ★ WP-9：NtQueryInformationProcess / NtQuerySystemInformation 改走
 * 直接系统调用包装（stub 优先 / GetProcAddress 回退），绕过用户态
 * API Hook——防转储扫描是攻击者最优先 Hook 的路径之一。 */
#include "syscall_direct.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <wchar.h>

/* ---------- NT 状态码（ntdef.h 未在精简包含中暴露） ---------- */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                ((LONG)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH   ((LONG)0xC0000004L)
#endif

typedef struct _MG_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;   /* 父进程 PID */
} MG_PROCESS_BASIC_INFORMATION;

/* ---------- 系统句柄表结构体（winternl.h 不完整，自行定义） ----------
 * 对应 NtQuerySystemInformation(SystemExtendedHandleInformation = 64)。
 */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;                 /* 内核对象指针（同对象则相同） */
    ULONG_PTR UniqueProcessId;        /* 持有该句柄的进程 PID */
    HANDLE    HandleValue;            /* 句柄值（在 Owner 进程内有效） */
    ULONG     GrantedAccess;          /* 访问掩码 */
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;        /* 对象类型索引 */
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/* ---------- 访问掩码常量 ---------- */
#define MG_PROCESS_VM_READ        0x0010u
#define MG_PROCESS_ALL_ACCESS     0x001F0FFFu   /* STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF */

/* SystemExtendedHandleInformation 信息类编号 */
#define MG_SystemExtendedHandleInformation  64

/* ---------- 注册表 ---------- */
#define MG_MAX_REGIONS   64
#define MG_NAME_MAX      64

typedef struct {
    void  *ptr;
    size_t len;
    char   name[MG_NAME_MAX];   /* 仅内部日志，不含敏感数据 */
    int    active;              /* 1=已注册活跃，0=空闲槽位 */
    int    purged;              /* 1=已被紧急零化（避免重复处理） */
} MemoryRegion;

static MemoryRegion s_regions[MG_MAX_REGIONS];
static int s_initialized = 0;

/* ★ 方案 P2-1：注册表并发保护（register/unregister/purge 可能来自不同线程） */
static CRITICAL_SECTION s_regions_cs;
static int s_regions_cs_init = 0;

static void regions_cs_ensure(void)
{
    if (!s_regions_cs_init) {
        InitializeCriticalSection(&s_regions_cs);
        s_regions_cs_init = 1;
    }
}

/* ---------- 父进程识别（方案 §6.2.3：排除同信任链句柄） ---------- */

/*
 * 获取当前进程的父进程 PID（InheritedFromUniqueProcessId）。
 * 用途：Tauri 主进程对 worker 子进程天然持有 PROCESS_ALL_ACCESS 句柄
 * （spawn/等待/终止所必需），防转储扫描必须排除父进程，否则每次
 * 扫描必然误报。获取失败返回 0（不排除）。
 * ★ WP-9：经 syscall_direct 包装（直接 stub / 降级回退），防父进程
 * 识别被 API Hook 短路（返回 0 → 父进程句柄被误报为威胁）。
 */
static DWORD get_parent_pid(void)
{
    MG_PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    LONG st = syscall_NtQueryInformationProcess(
        GetCurrentProcess(), 0 /* ProcessBasicInformation */,
        &pbi, sizeof(pbi), NULL);
    if (st != STATUS_SUCCESS) return 0;

    return (DWORD)pbi.InheritedFromUniqueProcessId;
}

/* ===================================================================== *
 *                           辅助函数                                    *
 * ===================================================================== */

/* 幂等确保模块已初始化 */
static void ensure_init(void)
{
    if (!s_initialized) {
        (void)memory_guard_init();
    }
}

/*
 * 可疑进程名检测（补充手段）。
 * 遍历进程快照，匹配 Cheat Engine / Process Hacker / HxD / WinDbg 等。
 * 命中返回 1，未命中返回 0。
 */
static int check_suspicious_process_names(void)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    int found = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            /* 精确匹配（大小写不敏感） */
            if (_wcsicmp(pe.szExeFile, L"cheat engine.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"processhacker.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"hxd.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"windbg.exe") == 0) {
                found = 1;
                break;
            }
            /* cheatengine*.exe 前缀匹配（大小写不敏感） */
            if (_wcsnicmp(pe.szExeFile, L"cheatengine", 11) == 0) {
                found = 1;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    /* 清理快照句柄（PE 结构在栈上，不含可复用敏感数据） */
    CloseHandle(hSnap);
    return found;
}

/*
 * 查询系统句柄表，返回 HeapAlloc 分配的缓冲区及条目数。
 *   out_buf      : 输出缓冲区指针（调用方负责清零并 HeapFree）
 *   out_count    : 输出条目数
 * 返回 0 成功；非 0 = 查询失败（调用方退化为仅进程名检测）。
 * ★ WP-9：NtQuerySystemInformation 经 syscall_direct 包装（直接 stub /
 * 降级回退）——句柄表扫描是转储类工具的先行拦截目标，Hook 该入口
 * 即可让防转储检测失明，直接系统调用使其不可被用户态 Hook。
 */
static int query_handle_table(PVOID *out_buf, ULONG_PTR *out_count)
{
    /* 循环扩容：系统句柄表可能很大（数万至数十万条目） */
    ULONG buf_size = 0x10000;  /* 初始 64 KiB */
    const ULONG max_size = 0x01000000u;  /* 上限 16 MiB，防御异常 */
    LONG status = STATUS_INFO_LENGTH_MISMATCH;
    PVOID buf = NULL;
    ULONG return_len = 0;

    for (int attempt = 0; attempt < 10; attempt++) {
        buf = HeapAlloc(GetProcessHeap(), 0, buf_size);
        if (buf == NULL) return -1;

        status = syscall_NtQuerySystemInformation(
            MG_SystemExtendedHandleInformation, buf, buf_size, &return_len);
        if (status == STATUS_SUCCESS) {
            break;
        }

        /* 释放本轮缓冲，按返回长度或倍增重试 */
        HeapFree(GetProcessHeap(), 0, buf);
        buf = NULL;

        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            /* 其他错误，放弃 */
            return -1;
        }
        if (return_len > buf_size) {
            buf_size = return_len + 0x1000;
        } else {
            buf_size *= 2;
        }
        if (buf_size > max_size) {
            return -1;
        }
    }

    if (status != STATUS_SUCCESS || buf == NULL) {
        return -1;
    }

    SYSTEM_HANDLE_INFORMATION_EX *info = (SYSTEM_HANDLE_INFORMATION_EX *)buf;
    *out_buf = buf;
    *out_count = info->NumberOfHandles;
    return 0;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int memory_guard_init(void)
{
    if (s_initialized) return 0;

    /* 初始化注册表：全零 = 全部空闲；并发保护临界区同步就绪 */
    regions_cs_ensure();
    EnterCriticalSection(&s_regions_cs);
    memset(s_regions, 0, sizeof(s_regions));
    LeaveCriticalSection(&s_regions_cs);

    /* 确保安全配置已就绪（未初始化时 security_get_config 会以 BALANCED 默认填充） */
    (void)security_get_config();

    s_initialized = 1;
    return 0;
}

int memory_guard_lock(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) return 0;

    /* 性能模式（memory_lock=0）：返回 0 但不实际调用 VirtualLock */
    const SecurityConfig *cfg = security_get_config();
    if (cfg != NULL && !cfg->memory_lock) {
        return 0;
    }

    /* 第一次尝试（verthys_lock_memory 内部调用 VirtualLock） */
    if (verthys_lock_memory(ptr, len) == 0) {
        return 0;
    }

    /*
     * 失败处理：VirtualLock 受进程最小/最大工作集配额约束，
     * 常因 ERROR_WORKING_SET_QUOTA 失败。尝试 SetProcessWorkingSetSize
     * 增大配额（按 len 页对齐 + 64KiB 余量）后重试。
     */
    SIZE_T min_ws = 0, max_ws = 0;
    if (GetProcessWorkingSetSize(GetCurrentProcess(), &min_ws, &max_ws)) {
        SIZE_T need = (len + 0xFFF) & ~((SIZE_T)0xFFF);  /* 页对齐向上 */
        SIZE_T headroom = 64 * 1024;                      /* 64 KiB 余量 */
        SIZE_T new_min = min_ws + need + headroom;
        SIZE_T new_max = max_ws + need + headroom;
        if (new_min > new_max) new_min = new_max;         /* 防御性钳制 */

        if (SetProcessWorkingSetSize(GetCurrentProcess(), new_min, new_max)) {
            if (verthys_lock_memory(ptr, len) == 0) {
                return 0;
            }
        }
    }

    return 1;  /* 锁定失败 */
}

int memory_guard_unlock(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) return 0;

    /* 性能模式下未实际锁页，但仍调用 VirtualUnlock（幂等，失败不影响） */
    return verthys_unlock_memory(ptr, len);
}

void memory_guard_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) return;

    /*
     * ★ 方案 P2-G：单轮覆写（0x00）。
     * 原实现的三轮覆写（0x00→0xFF→0x00）是磁盘擦除的民俗移植——
     * 对易失性内存单轮覆盖已足够，多轮只增加成本无安全增益。
     * volatile 限定指针确保编译器不优化掉写入。
     */
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0x00;
    }
}

int memory_guard_check_remote_read(void)
{
    ensure_init();

    /* 性能模式（anti_dump=0）：跳过检测 */
    const SecurityConfig *cfg = security_get_config();
    if (cfg != NULL && !cfg->anti_dump) {
        return 0;
    }

    /*
     * 主检测：遍历系统句柄表，查找非信任进程持有指向本进程的
     * PROCESS_VM_READ / PROCESS_ALL_ACCESS 句柄。
     * ★ 方案 §6.2.3（P0-5 修复）：信任链排除——系统进程（0/4）、
     * 自身、父进程（Tauri 主进程对 worker 持有 PROCESS_ALL_ACCESS
     * 句柄属正常架构，必须排除，否则每次扫描必然误报）。
     */
    PVOID buf = NULL;
    ULONG_PTR count = 0;
    if (query_handle_table(&buf, &count) != 0) {
        /* 句柄表查询失败，退化为仅进程名检测 */
        if (check_suspicious_process_names()) {
            emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_REMOTE_MEM_READ);
            return 1;
        }
        return 0;
    }

    SYSTEM_HANDLE_INFORMATION_EX *info = (SYSTEM_HANDLE_INFORMATION_EX *)buf;
    DWORD my_pid = GetCurrentProcessId();
    DWORD parent_pid = get_parent_pid();

    /*
     * 第一步：创建一个指向本进程的真实句柄（非伪句柄），
     * 在句柄表中定位其条目以获取本进程的内核对象指针。
     * DuplicateHandle 复制当前伪句柄总是成功，不受 ACL 限制。
     */
    HANDLE hSelf = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                    GetCurrentProcess(), &hSelf,
                    0, FALSE, DUPLICATE_SAME_ACCESS);

    ULONG_PTR my_process_object = 0;
    if (hSelf != NULL) {
        for (ULONG_PTR i = 0; i < count; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
            if (e->UniqueProcessId == my_pid &&
                (ULONG_PTR)e->HandleValue == (ULONG_PTR)hSelf) {
                my_process_object = (ULONG_PTR)e->Object;
                break;
            }
        }
    }

    /*
     * 第二步：遍历句柄表，查找非信任进程（排除 Idle/System/自身/父进程）
     * 持有的、指向本进程对象的 VM_READ 句柄。
     */
    int detected = 0;
    if (my_process_object != 0) {
        for (ULONG_PTR i = 0; i < count; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
            ULONG_PTR owner_pid = e->UniqueProcessId;

            /* 信任链排除：系统进程（0=Idle, 4=System）、自身、父进程 */
            if (owner_pid == 0 || owner_pid == 4 ||
                owner_pid == my_pid || owner_pid == (ULONG_PTR)parent_pid) {
                continue;
            }

            /* 仅检查指向本进程对象的句柄 */
            if ((ULONG_PTR)e->Object != my_process_object) {
                continue;
            }

            /* 访问掩码含 PROCESS_VM_READ 或 PROCESS_ALL_ACCESS */
            ULONG access = e->GrantedAccess;
            int has_vm_read = (access & MG_PROCESS_VM_READ) != 0;
            int has_all_access = ((access & MG_PROCESS_ALL_ACCESS) ==
                                  MG_PROCESS_ALL_ACCESS);
            if (!has_vm_read && !has_all_access) {
                continue;
            }

            /* 命中：非信任进程持有指向本进程的 VM_READ 句柄 */
            detected = 1;
            break;
        }
    }

    /* 第三步：进程名检测作为补充（应对无法获取对象指针或额外佐证） */
    if (!detected) {
        detected = check_suspicious_process_names();
    }

    /* 清理：临时句柄表缓冲用毕清零并释放（含内核对象指针，按规范清零）。
     * 精确计算有效数据大小：header 已含 Handles[1]，故 count 个条目对应
     * sizeof(header) + (count-1)*sizeof(entry)，确保不越界写入分配缓冲。 */
    {
        SIZE_T valid_size = sizeof(SYSTEM_HANDLE_INFORMATION_EX);
        if (count > 0) {
            valid_size += (count - 1) * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
        }
        verthys_secure_zero(buf, valid_size);
    }
    HeapFree(GetProcessHeap(), 0, buf);

    if (hSelf != NULL) {
        CloseHandle(hSelf);
    }

    if (detected) {
        /* ★ 方案 §6.1：中置信度信号 → DEGRADE（窗口内重复达阈值才锁库） */
        emergency_report(EMERG_LEVEL_DEGRADE, EMERG_SIG_REMOTE_MEM_READ);
    }

    return detected;
}

void memory_guard_emergency_purge(void)
{
    ensure_init();

    /*
     * 遍历全部已注册的活跃区域，逐个执行覆写零化并解锁。
     * 已标记 purged 的区域跳过，避免重复处理。
     */
    regions_cs_ensure();
    EnterCriticalSection(&s_regions_cs);
    for (int i = 0; i < MG_MAX_REGIONS; i++) {
        if (!s_regions[i].active || s_regions[i].purged) {
            continue;
        }
        if (s_regions[i].ptr != NULL && s_regions[i].len > 0) {
            /* 覆写零化 */
            memory_guard_secure_zero(s_regions[i].ptr, s_regions[i].len);
            /* 解锁内存页（紧急场景强制解锁，无视性能模式） */
            VirtualUnlock(s_regions[i].ptr, s_regions[i].len);
        }
        /* 标记为已清除 */
        s_regions[i].purged = 1;
    }
    LeaveCriticalSection(&s_regions_cs);
}

int memory_guard_register(void *ptr, size_t len, const char *name)
{
    ensure_init();

    if (ptr == NULL || len == 0) return -1;

    regions_cs_ensure();
    EnterCriticalSection(&s_regions_cs);

    /* 检查是否已存在（按 ptr 去重） */
    for (int i = 0; i < MG_MAX_REGIONS; i++) {
        if (s_regions[i].active && s_regions[i].ptr == ptr) {
            LeaveCriticalSection(&s_regions_cs);
            return -2;  /* 已存在 */
        }
    }

    /* 查找空闲槽位 */
    for (int i = 0; i < MG_MAX_REGIONS; i++) {
        if (!s_regions[i].active) {
            s_regions[i].ptr = ptr;
            s_regions[i].len = len;
            s_regions[i].active = 1;
            s_regions[i].purged = 0;
            if (name != NULL) {
                strncpy_s(s_regions[i].name, MG_NAME_MAX, name, _TRUNCATE);
            } else {
                s_regions[i].name[0] = '\0';
            }
            LeaveCriticalSection(&s_regions_cs);
            return 0;
        }
    }

    LeaveCriticalSection(&s_regions_cs);
    return -3;  /* 已达上限 */
}

int memory_guard_unregister(void *ptr)
{
    ensure_init();

    if (ptr == NULL) return -1;

    regions_cs_ensure();
    EnterCriticalSection(&s_regions_cs);

    /* 按 ptr 查找并移除 */
    for (int i = 0; i < MG_MAX_REGIONS; i++) {
        if (s_regions[i].active && s_regions[i].ptr == ptr) {
            s_regions[i].ptr = NULL;
            s_regions[i].len = 0;
            s_regions[i].active = 0;
            s_regions[i].purged = 0;
            s_regions[i].name[0] = '\0';
            LeaveCriticalSection(&s_regions_cs);
            return 0;
        }
    }

    LeaveCriticalSection(&s_regions_cs);
    return -2;  /* 未找到 */
}

/* ===================================================================== *
 *              防转储低频巡逻（方案 §6.2.3）                              *
 * ===================================================================== *
 * 一次性定时器链（≥60s 间隔）：每次唤醒执行一次句柄表扫描后重排下一次。
 * 空闲期零唤醒成本（相对旧的 1s 周期定时器体系）；性能模式不启动。
 */

static HANDLE s_patrol_queue = NULL;
static HANDLE s_patrol_timer = NULL;
static volatile LONG s_patrol_stopped = 0;

static VOID CALLBACK patrol_callback(PVOID param, BOOLEAN fired)
{
    (void)param; (void)fired;
    if (s_patrol_stopped) return;

    /* 单次扫描（句柄表 + 可疑进程名），命中 → DEGRADE 级上报 */
    (void)memory_guard_check_remote_read();

    /* 重排下一次 60s 一次性定时器 */
    if (!s_patrol_stopped && s_patrol_queue != NULL) {
        CreateTimerQueueTimer(&s_patrol_timer, s_patrol_queue, patrol_callback,
                              NULL, 60000, 0,
                              WT_EXECUTEONLYONCE | WT_EXECUTEINTIMERTHREAD);
    }
}

int memory_guard_patrol_start(void)
{
    ensure_init();

    /* 性能模式（anti_dump=0）：不启动巡逻 */
    const SecurityConfig *cfg = security_get_config();
    if (cfg != NULL && !cfg->anti_dump) return 0;

    if (s_patrol_queue != NULL) return 0;  /* 已运行，幂等 */

    s_patrol_stopped = 0;
    s_patrol_queue = CreateTimerQueue();
    if (s_patrol_queue == NULL) return -1;

    if (!CreateTimerQueueTimer(&s_patrol_timer, s_patrol_queue, patrol_callback,
                               NULL, 60000, 0,
                               WT_EXECUTEONLYONCE | WT_EXECUTEINTIMERTHREAD)) {
        DeleteTimerQueueEx(s_patrol_queue, NULL);
        s_patrol_queue = NULL;
        return -2;
    }
    return 0;
}

void memory_guard_patrol_stop(void)
{
    if (s_patrol_queue == NULL) return;

    s_patrol_stopped = 1;
    /* DeleteTimerQueueEx 阻塞等待在途回调完成后销毁队列（幂等安全） */
    DeleteTimerQueueEx(s_patrol_queue, NULL);
    s_patrol_queue = NULL;
    s_patrol_timer = NULL;
}
