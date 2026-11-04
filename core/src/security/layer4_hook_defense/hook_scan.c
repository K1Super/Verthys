/*
 * hook_scan.c — ntdll 导出基线扫描与 IAT 校验实现
 *
 * 基线来源：磁盘 System32\ntdll.dll 的导出表 + 目标函数入口字节。
 * 比较对象：内存 ntdll 模块基址 + 同一 RVA 的入口字节。
 * IAT：自身 PE 导入表中指向 ntdll 目标函数名的槽值必须等于
 *      内存 ntdll 基址 + 磁盘导出 RVA。
 *
 * 基线解析失败只降级为"不可用"，不拒绝启动；首次 Hook 特征只遥测，
 * 连续两次才终止。标准 stub 与磁盘基线不一致（热补丁）按证据过期处理。
 */
#include "hook_scan.h"
#include "emergency.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define HOOK_TARGET_COUNT   2u
#define HOOK_PROLOGUE_BYTES 16u

typedef struct {
    const char *name;
    uint32_t    rva;
    uint8_t     disk[HOOK_PROLOGUE_BYTES];
    int         baseline_ok;
} HookTarget;

/* 安全模块实际使用的 NT 查询入口（syscall_direct 目标表同源） */
static HookTarget s_targets[HOOK_TARGET_COUNT] = {
    { "NtQueryInformationProcess", 0, { 0 }, 0 },
    { "NtQuerySystemInformation",  0, { 0 }, 0 },
};

static INIT_ONCE        s_init_once = INIT_ONCE_STATIC_INIT;
static int              s_initialized = 0;

/* 状态锁：run_once / get_state 并发安全 */
static SRWLOCK          s_lock = SRWLOCK_INIT;
static uint32_t         s_state = HOOK_SCAN_UNAVAILABLE;
static uint64_t         s_last_scan_ms = 0;
static uint32_t         s_mem_streak[HOOK_TARGET_COUNT];
static uint32_t         s_iat_streak[HOOK_TARGET_COUNT];

/* 定时器生命周期锁（stop 不得持状态锁等待回调） */
static SRWLOCK          s_timer_lock = SRWLOCK_INIT;
static HANDLE           s_timer_queue = NULL;
static HANDLE           s_timer = NULL;

/* ---------- 文件与 PE 解析 ---------- */

static int read_whole_file(const wchar_t *path, uint8_t **out, size_t *out_len)
{
    HANDLE h;
    LARGE_INTEGER size;
    uint8_t *buf;
    DWORD read_bytes = 0;

    if (path == NULL || out == NULL || out_len == NULL) return -1;
    *out = NULL;
    *out_len = 0;

    h = CreateFileW(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 ||
        size.QuadPart > (LONGLONG)(64u * 1024u * 1024u)) {
        CloseHandle(h);
        return -1;
    }
    buf = (uint8_t *)malloc((size_t)size.QuadPart);
    if (buf == NULL) {
        CloseHandle(h);
        return -1;
    }
    if (!ReadFile(h, buf, (DWORD)size.QuadPart, &read_bytes, NULL) ||
        read_bytes != (DWORD)size.QuadPart) {
        free(buf);
        CloseHandle(h);
        return -1;
    }
    CloseHandle(h);
    *out = buf;
    *out_len = (size_t)size.QuadPart;
    return 0;
}

static int rva_to_offset(const IMAGE_NT_HEADERS *nt, uint32_t rva,
                         size_t file_len, size_t *out_offset)
{
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    uint16_t i;

    if (rva < nt->OptionalHeader.SizeOfHeaders) {
        *out_offset = (size_t)rva;
        return 0;
    }
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        uint32_t va = sec->VirtualAddress;
        uint32_t raw_size = sec->SizeOfRawData;
        if (raw_size == 0) continue;
        if (rva >= va && rva < va + raw_size) {
            size_t off = (size_t)sec->PointerToRawData + (size_t)(rva - va);
            if (off >= file_len) return -1;
            *out_offset = off;
            return 0;
        }
    }
    return -1;
}

static int find_export_rva(const uint8_t *file, size_t file_len,
                           const char *name, uint32_t *out_rva)
{
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_EXPORT_DIRECTORY *exp;
    const uint32_t *names;
    const uint16_t *ordinals;
    const uint32_t *functions;
    size_t exp_off = 0;
    uint32_t i;

    if (file == NULL || name == NULL || out_rva == NULL) return -1;
    if (file_len < sizeof(IMAGE_DOS_HEADER)) return -1;
    dos = (const IMAGE_DOS_HEADER *)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > file_len) return -1;
    nt = (const IMAGE_NT_HEADERS *)(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return -1;
    }
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return -1;
    }
    if (rva_to_offset(nt,
                      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                      file_len, &exp_off) != 0) {
        return -1;
    }
    exp = (const IMAGE_EXPORT_DIRECTORY *)(file + exp_off);
    if (exp->NumberOfNames == 0 || exp->AddressOfNames == 0 ||
        exp->AddressOfNameOrdinals == 0 || exp->AddressOfFunctions == 0) {
        return -1;
    }
    if (rva_to_offset(nt, exp->AddressOfNames, file_len, &exp_off) != 0) return -1;
    names = (const uint32_t *)(file + exp_off);
    if (rva_to_offset(nt, exp->AddressOfNameOrdinals, file_len, &exp_off) != 0) return -1;
    ordinals = (const uint16_t *)(file + exp_off);
    if (rva_to_offset(nt, exp->AddressOfFunctions, file_len, &exp_off) != 0) return -1;
    functions = (const uint32_t *)(file + exp_off);

    for (i = 0; i < exp->NumberOfNames; i++) {
        size_t name_off = 0;
        if (names[i] == 0) continue;
        if (rva_to_offset(nt, names[i], file_len, &name_off) != 0) continue;
        if (strcmp((const char *)(file + name_off), name) == 0) {
            uint16_t ord = ordinals[i];
            if (ord >= exp->NumberOfFunctions) continue;
            *out_rva = functions[ord];
            return 0;
        }
    }
    return -1;
}

static void load_disk_baseline(void)
{
    wchar_t sysdir[MAX_PATH];
    wchar_t path[MAX_PATH];
    uint8_t *file = NULL;
    size_t file_len = 0;
    uint32_t i;

    if (GetSystemDirectoryW(sysdir, MAX_PATH) == 0) return;
    if (_snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\ntdll.dll", sysdir) < 0) {
        return;
    }
    if (read_whole_file(path, &file, &file_len) != 0) return;

    for (i = 0; i < HOOK_TARGET_COUNT; i++) {
        uint32_t rva = 0;
        size_t off = 0;
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)file;
        const IMAGE_NT_HEADERS *nt;
        if (find_export_rva(file, file_len, s_targets[i].name, &rva) != 0) continue;
        if (file_len < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) continue;
        nt = (const IMAGE_NT_HEADERS *)(file + dos->e_lfanew);
        if (rva_to_offset(nt, rva, file_len, &off) != 0) continue;
        if (off + HOOK_PROLOGUE_BYTES > file_len) continue;
        memcpy(s_targets[i].disk, file + off, HOOK_PROLOGUE_BYTES);
        s_targets[i].rva = rva;
        s_targets[i].baseline_ok = 1;
    }
    free(file);
}

/* ---------- 内存读取与特征判定 ---------- */

static int safe_read_memory(uintptr_t addr, uint8_t out[HOOK_PROLOGUE_BYTES])
{
    __try {
        memcpy(out, (const void *)addr, HOOK_PROLOGUE_BYTES);
        return 0;
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH) {
        return -1;
    }
}

static int hook_shaped(const uint8_t *b)
{
    if (b[0] == 0xE9 || b[0] == 0xEB) return 1;
    if (b[0] == 0xFF && b[1] == 0x25) return 1;
    if (b[0] == 0x68 && b[5] == 0xC3) return 1;
    if (b[0] == 0x48 && b[1] == 0xB8) {
        /* mov rax, imm64; jmp rax */
        for (int i = 2; i + 1 < (int)HOOK_PROLOGUE_BYTES; i++) {
            if (b[i] == 0xFF && b[i + 1] == 0xE0) return 1;
        }
    }
    return 0;
}

/* 自身模块导入表中，目标函数名的 IAT 槽是否等于 ntdll_base + rva。
 * 未导入该目标时返回 1（无覆盖项不构成异常）。 */
static int iat_slot_matches(uintptr_t ntdll_base, const char *target,
                            uint32_t rva)
{
    HMODULE self = NULL;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_IMPORT_DESCRIPTOR *desc;
    uintptr_t self_base = 0;

    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)(uintptr_t)&s_state, &self) || self == NULL) {
        return 1;
    }
    self_base = (uintptr_t)self;
    dos = (const IMAGE_DOS_HEADER *)self_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 1;
    nt = (const IMAGE_NT_HEADERS *)(self_base + dos->e_lfanew);

    desc = (const IMAGE_IMPORT_DESCRIPTOR *)(self_base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
        return 1;
    }

    for (; desc->Name != 0; desc++) {
        const IMAGE_THUNK_DATA *ilt;
        const IMAGE_THUNK_DATA *iat;
        const char *dll = (const char *)(self_base + desc->Name);
        if (_stricmp(dll, "ntdll.dll") != 0) continue;
        if (desc->OriginalFirstThunk == 0) continue;

        ilt = (const IMAGE_THUNK_DATA *)(self_base + desc->OriginalFirstThunk);
        iat = (const IMAGE_THUNK_DATA *)(self_base + desc->FirstThunk);
        for (; ilt->u1.AddressOfData != 0; ilt++, iat++) {
            const IMAGE_IMPORT_BY_NAME *ibn;
            if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)) continue;
            ibn = (const IMAGE_IMPORT_BY_NAME *)(self_base + ilt->u1.AddressOfData);
            if (strcmp((const char *)ibn->Name, target) == 0) {
                return ((uintptr_t)iat->u1.Function == ntdll_base + (uintptr_t)rva)
                           ? 1 : 0;
            }
        }
    }
    return 1;
}

/* ---------- 纯判定 ---------- */

uint32_t hook_scan_evaluate(const HookScanTargetObs *obs, uint32_t count,
                            uint32_t *mem_streak, uint32_t *iat_streak,
                            int *kill)
{
    uint32_t state = HOOK_SCAN_CLEAN;
    int any_baseline = 0;
    uint32_t i;

    if (kill != NULL) *kill = 0;
    if (obs == NULL || count == 0) return HOOK_SCAN_UNAVAILABLE;

    for (i = 0; i < count; i++) {
        if (!obs[i].baseline_ok) continue;
        any_baseline = 1;
        if (obs[i].mem_matches && obs[i].iat_matches) {
            if (mem_streak != NULL) mem_streak[i] = 0;
            if (iat_streak != NULL) iat_streak[i] = 0;
            continue;
        }
        if (!obs[i].mem_matches && obs[i].mem_hook_shaped) {
            if (mem_streak != NULL) {
                mem_streak[i]++;
                if (mem_streak[i] >= 2u && kill != NULL) *kill = 1;
            }
            state = HOOK_SCAN_ANOMALY;
            continue;
        }
        if (!obs[i].iat_matches) {
            if (iat_streak != NULL) {
                iat_streak[i]++;
                if (iat_streak[i] >= 2u && kill != NULL) *kill = 1;
            }
            state = HOOK_SCAN_ANOMALY;
            continue;
        }
        /* 字节不一致但仍是标准 stub（热补丁/更新未重启）：证据过期。 */
        if (state == HOOK_SCAN_CLEAN) state = HOOK_SCAN_STALE;
    }

    return any_baseline ? state : HOOK_SCAN_UNAVAILABLE;
}

/* ---------- 扫描 ---------- */

int hook_scan_run_once(void)
{
    HookScanTargetObs obs[HOOK_TARGET_COUNT];
    HMODULE ntdll = NULL;
    uintptr_t ntdll_base = 0;
    uint32_t state;
    int kill = 0;
    uint32_t i;

    if (!s_initialized) return -1;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    ntdll_base = (uintptr_t)ntdll;
    memset(obs, 0, sizeof(obs));

    for (i = 0; i < HOOK_TARGET_COUNT; i++) {
        uint8_t mem[HOOK_PROLOGUE_BYTES];
        obs[i].baseline_ok = s_targets[i].baseline_ok;
        if (!s_targets[i].baseline_ok || ntdll_base == 0) continue;
        if (safe_read_memory(ntdll_base + s_targets[i].rva, mem) != 0) continue;
        obs[i].mem_matches =
            memcmp(mem, s_targets[i].disk, HOOK_PROLOGUE_BYTES) == 0;
        obs[i].mem_hook_shaped = !obs[i].mem_matches && hook_shaped(mem);
        obs[i].iat_matches = iat_slot_matches(ntdll_base, s_targets[i].name,
                                              s_targets[i].rva);
    }

    AcquireSRWLockExclusive(&s_lock);
    state = hook_scan_evaluate(obs, HOOK_TARGET_COUNT,
                               s_mem_streak, s_iat_streak, &kill);
    s_state = state;
    s_last_scan_ms = GetTickCount64();
    ReleaseSRWLockExclusive(&s_lock);

    if (kill) {
        /* 连续两次 Hook 特征：高置信度，终止进程（内存绝育在内）。 */
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_HOOK_DETECTED);
    } else if (state == HOOK_SCAN_ANOMALY || state == HOOK_SCAN_STALE) {
        emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_HOOK_DETECTED);
    }
    return 0;
}

uint32_t hook_scan_get_state(void)
{
    uint32_t state;
    uint64_t last;

    AcquireSRWLockShared(&s_lock);
    state = s_state;
    last = s_last_scan_ms;
    ReleaseSRWLockShared(&s_lock);

    if (state == HOOK_SCAN_UNAVAILABLE) return state;
    if (last == 0) return HOOK_SCAN_UNAVAILABLE;
    if (state == HOOK_SCAN_CLEAN &&
        GetTickCount64() - last > HOOK_SCAN_EVIDENCE_TTL_MS) {
        return HOOK_SCAN_STALE;
    }
    return state;
}

uint64_t hook_scan_get_last_scan_ms(void)
{
    uint64_t last;
    AcquireSRWLockShared(&s_lock);
    last = s_last_scan_ms;
    ReleaseSRWLockShared(&s_lock);
    return last;
}

/* ---------- 生命周期与定时器 ---------- */

static BOOL CALLBACK hook_init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    load_disk_baseline();
    s_initialized = 1;
    return TRUE;
}

int hook_scan_init(void)
{
    InitOnceExecuteOnce(&s_init_once, hook_init_cb, NULL, NULL);
    return 0;
}

static VOID CALLBACK hook_timer_cb(PVOID param, BOOLEAN fired)
{
    (void)param;
    (void)fired;
    (void)hook_scan_run_once();
}

int hook_scan_start_periodic(void)
{
    int rc = 0;

    if (!s_initialized) return -1;
    AcquireSRWLockExclusive(&s_timer_lock);
    if (s_timer_queue != NULL) {
        ReleaseSRWLockExclusive(&s_timer_lock);
        return 0;
    }
    s_timer_queue = CreateTimerQueue();
    if (s_timer_queue == NULL) {
        ReleaseSRWLockExclusive(&s_timer_lock);
        return -1;
    }
    if (!CreateTimerQueueTimer(&s_timer, s_timer_queue, hook_timer_cb,
                               NULL, HOOK_SCAN_PERIOD_MS, HOOK_SCAN_PERIOD_MS, 0)) {
        CloseHandle(s_timer_queue);
        s_timer_queue = NULL;
        s_timer = NULL;
        rc = -1;
    }
    ReleaseSRWLockExclusive(&s_timer_lock);
    return rc;
}

void hook_scan_stop_periodic(void)
{
    HANDLE queue = NULL;
    HANDLE timer = NULL;

    /* 先摘除句柄再释放锁：DeleteTimerQueueEx 会等待在途回调，而回调
     * 需要获取 s_lock；持 s_timer_lock 不影响回调，但持 s_lock 会死锁。 */
    AcquireSRWLockExclusive(&s_timer_lock);
    queue = s_timer_queue;
    timer = s_timer;
    s_timer_queue = NULL;
    s_timer = NULL;
    ReleaseSRWLockExclusive(&s_timer_lock);

    if (queue == NULL) return;
    if (timer != NULL) {
        (void)DeleteTimerQueueTimer(NULL, timer, NULL);
        CloseHandle(timer);
    }
    (void)DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE);
}
