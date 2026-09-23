/*
 * emergency.c — 应急兜底与连锁响应机制实现
 *
 * 应急响应模型分级实现。

 * 原模型缺陷：
 *   - 信号终身累积，任意两个不同信号位即 TerminateProcess；
 *   - 唯一重置函数 emergency_clear_signals 无调用点；
 *   - 多个结构性可误报的检测器接在不可逆响应上 → 自毁放大器。
 *
 * 新模型实现要点：
 *   1. 三级响应（TELEMETRY/DEGRADE/KILL），检测与响应解耦。
 *   2. 信号窗口：8 槽环形历史（QPC 时间戳 + 信号位），10 分钟滑动窗口，
 *      过期条目自动失效；DEGRADE 需窗口内同一信号累计 ≥2 次（防单次误报）。
 *   3. DEGRADE 动作：置熔断闩锁 → 调用 API 层注册的降级处理器
 *      （清密钥 + 锁库），进程存活、可恢复。幂等：闩锁保证仅回调一次。
 *   4. KILL 动作：原有内存绝育 + 匿名故障码 + TerminateProcess 全保留，
 *      仅限高置信度信号调用。
 *   5. 触发在临界区外执行，临界区保持短小（与原实现一致的锁纪律）。
 *
 * 安全策略：
 *   - KILL 路径严格按 极速熔断→内存绝育→故障码上报→退出 顺序执行。
 *   - 故障码仅匿名类型码，不含任何用户隐私数据。
 *   - emergency_circuit 配置在三档模式下恒为 1，应急逻辑无条件启用。
 */
#include "emergency.h"
#include "memory_guard.h"
#include "key_separation.h"
#include "security_preset.h"
#include "verthys_crypto.h"     /* verthys_random_bytes（事件名随机后缀） */
#include "verthys_internal.h"  /* verthys_secure_zero */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* ---------- 常量 ---------- */

/* 看门狗事件名：前缀 + PID + 随机后缀（防同用户进程预占/监听命名事件） */
#define EMERG_WATCHDOG_EVENT_PREFIX_W  L"Verthys_Emergency_"

/* 事件名随机后缀字节数（hex 编码后双倍宽字符） */
#define EMERG_EVENT_RAND_BYTES  8u

/* 看门狗事件名缓冲最大长度（宽字符） */
#define EMERG_EVENT_NAME_MAX  64

/* 信号滑动窗口时长（毫秒） */
#define EMERG_WINDOW_MS  (10u * 60u * 1000u)

/* 信号窗口历史槽位数 */
#define EMERG_HISTORY_SLOTS 8u

/* ---------- 模块状态 ---------- */

/* 临界区：保护信号窗口、熔断闩锁与降级处理器（线程安全） */
static CRITICAL_SECTION s_lock;
static int s_lock_initialized = 0;

/* 信号窗口历史环形槽（时间戳 + 信号位；tick=0 表示空槽） */
typedef struct {
    ULONGLONG     tick;      /* QPC 采样时刻（0=空槽） */
    uint32_t      signal;    /* EmergencySignal 位 */
} EmergHistorySlot;

static EmergHistorySlot s_history[EMERG_HISTORY_SLOTS];
static size_t s_history_next = 0;

/* 熔断闩锁：0=未触发，1=降级态（进程存活），2=KILL 态（即将终止） */
static volatile LONG s_triggered = 0;

/* 降级处理器（API 层注入；DEGRADE 触发时调用） */
static void (*s_degrade_handler)(void) = NULL;

/* 看门狗事件句柄（命名事件，跨进程可见；emergency_exit 时 SetEvent 通知） */
static HANDLE s_watchdog_event = NULL;

/* 模块是否已初始化（幂等） */
static int s_initialized = 0;

/* QPC 频率缓存（一次初始化，只读） */
static LONGLONG s_qpf = 0;

/* ---------- 辅助函数 ---------- */

/* 当前 QPC 毫秒刻度（窗口计算用；QPC 失败时降级 GetTickCount64） */
static ULONGLONG emerg_now_ms(void)
{
    LARGE_INTEGER pc;
    if (s_qpf > 0 && QueryPerformanceCounter(&pc)) {
        return (ULONGLONG)(pc.QuadPart * 1000 / s_qpf);
    }
    return GetTickCount64();
}

/*
 * 构建看门狗事件名：L"Verthys_Emergency_<PID>_<16 hex 随机后缀>"。
 * 手动拼接前缀、PID 十进制与随机后缀十六进制，避免依赖 swprintf
 * 的可移植性差异。随机后缀（CSPRNG 8 字节）杜绝同用户恶意进程
 * 预占（event squatting）或监听该命名事件；后缀仅影响名字形态，
 * 事件语义（创建/SetEvent）不变。
 */
static void build_event_name(wchar_t *buf, size_t cap)
{
    static const wchar_t prefix[] = EMERG_WATCHDOG_EVENT_PREFIX_W;
    static const wchar_t hex_chars[] = L"0123456789abcdef";
    uint8_t rnd[EMERG_EVENT_RAND_BYTES];
    DWORD pid = GetCurrentProcessId();
    size_t i = 0;
    size_t j;
    int k;

    /* 复制前缀 */
    for (j = 0; prefix[j] != L'\0' && i + 1 < cap; j++) {
        buf[i++] = prefix[j];
    }

    /* 追加 PID 数字（十进制） */
    if (pid == 0) {
        if (i + 1 < cap) buf[i++] = L'0';
    } else {
        wchar_t tmp[16];
        int n = 0;
        while (pid > 0 && n < 16) {
            tmp[n++] = (wchar_t)(L'0' + (pid % 10));
            pid /= 10;
        }
        for (int k2 = n - 1; k2 >= 0 && i + 1 < cap; k2--) {
            buf[i++] = tmp[k2];
        }
    }

    /* 分隔符 + 随机后缀（hex 编码） */
    if (i + 1 < cap) buf[i++] = L'_';
    verthys_random_bytes(rnd, sizeof(rnd));
    for (k = 0; k < (int)sizeof(rnd) && i + 1 < cap; k++) {
        if (i + 1 < cap) buf[i++] = hex_chars[rnd[k] >> 4];
        if (i + 1 < cap) buf[i++] = hex_chars[rnd[k] & 0x0F];
    }
    verthys_secure_zero(rnd, sizeof(rnd));

    buf[i] = L'\0';
}

/*
 * 根据累积信号选择匿名故障类型码。
 * 故障码仅标识威胁类别，不含任何用户隐私数据。
 */
static uint32_t select_fault_code(uint32_t signals)
{
    int categories = 0;
    uint32_t code = 0;

    /* 类别 1：索引损坏 —— 超级块 HMAC 校验失败 */
    if (signals & EMERG_SIG_SUPERBLOCK_HMAC) {
        code = EMERGENCY_CODE_INDEX_CORRUPTION;
        categories++;
    }

    /* 类别 2：注入阻断 —— frida 注入痕迹或未知第三方 DLL */
    if (signals & (EMERG_SIG_FRIDA_INJECTION | EMERG_SIG_UNKNOWN_DLL)) {
        code = EMERGENCY_CODE_INJECTION_BLOCK;
        categories++;
    }

    /* 类别 3：调试阻断 —— 硬件断点 DR0-DR3 或调试器活跃 */
    if (signals & (EMERG_SIG_HARDWARE_BP | EMERG_SIG_DEBUGGER_ACTIVE)) {
        code = EMERGENCY_CODE_DEBUG_BLOCK;
        categories++;
    }

    /* 类别 4：内存篡改 —— 远程内存读取或进程内存被篡改 */
    if (signals & (EMERG_SIG_REMOTE_MEM_READ | EMERG_SIG_PROCESS_TAMPER)) {
        code = EMERGENCY_CODE_MEMORY_TAMPER;
        categories++;
    }

    /* 类别 5：完整性失败 —— 静态本体 / 锚点校验未通过 */
    if (signals & EMERG_SIG_INTEGRITY_FAIL) {
        code = EMERGENCY_CODE_INTEGRITY_FAIL;
        categories++;
    }

    /* 多类信号叠加（≥2 类命中）→ 多威胁码 */
    if (categories >= 2) {
        return EMERGENCY_CODE_MULTI_THREAT;
    }

    /*
     * 仅触发但无已知类别映射（如仅 mtime 回拨 + hook 检测叠加触发，
     * 或手动 trigger 且无累积信号）→ 统一归为多威胁，确保故障码恒非 0。
     */
    if (categories == 0) {
        return EMERGENCY_CODE_MULTI_THREAT;
    }

    return code;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int emergency_init(void)
{
    if (s_initialized) return 0;

    /* 初始化临界区（保护信号窗口与触发状态，幂等） */
    if (!s_lock_initialized) {
        InitializeCriticalSection(&s_lock);
        s_lock_initialized = 1;
    }

    LARGE_INTEGER freq;
    if (QueryPerformanceFrequency(&freq) && freq.QuadPart > 0) {
        s_qpf = freq.QuadPart;
    }

    /* 重置模块状态（防御动态加载场景下的脏页复用） */
    memset(s_history, 0, sizeof(s_history));
    s_history_next = 0;
    s_triggered = 0;
    s_degrade_handler = NULL;

    /*
     * 读取安全配置：确认应急熔断连锁响应已启用。
     * 三档模式均设置 emergency_circuit=1，应急逻辑无条件启用。
     */
    (void)security_get_config();

    /*
     * 创建看门狗事件对象（命名、手动复位、初始未触发）。
     * 事件名含 CSPRNG 随机后缀：同用户恶意进程无法预占或监听；
     * 跨进程可见语义保留——看门狗进程经继承的事件名或进程间约定
     * 的传递渠道可 WaitForSingleObject 监控。创建失败不视为致命：
     * emergency_exit 仍可通过 TerminateProcess 终止进程，
     * 仅丢失看门狗通知通道。
     */
    if (s_watchdog_event == NULL) {
        wchar_t name[EMERG_EVENT_NAME_MAX];
        build_event_name(name, EMERG_EVENT_NAME_MAX);
        s_watchdog_event = CreateEventW(NULL,   /* 默认安全描述符 */
                                        TRUE,   /* 手动复位事件 */
                                        FALSE,  /* 初始为未触发态 */
                                        name);  /* 命名事件，跨进程可见 */
    }

    s_initialized = 1;
    return 0;
}

void emergency_set_degrade_handler(void (*handler)(void))
{
    /* init 幂等保障（Verthys_Init 先于任何信号源启用） */
    if (!s_initialized) {
        emergency_init();
    }
    s_degrade_handler = handler;
}

void emergency_report(EmergencyLevel level, EmergencySignal signal)
{
    ULONGLONG now;
    size_t count;
    size_t i;
    int should_degrade = 0;

    if (!s_initialized) {
        emergency_init();
    }
    if (signal == EMERG_SIG_NONE) return;

    now = emerg_now_ms();

    /*
     * KILL 级快速路径：高置信度信号无需窗口判定，
     * 直接进入终止性响应（闩锁防重入，同 emergency_trigger）。
     */
    if (level >= EMERG_LEVEL_KILL) {
        emergency_trigger();
        return;
    }

    EnterCriticalSection(&s_lock);

    /* 1. 记入窗口历史（TELEMETRY/DEGRADE 共用） */
    s_history[s_history_next].tick   = now;
    s_history[s_history_next].signal = (uint32_t)signal;
    s_history_next = (s_history_next + 1) % EMERG_HISTORY_SLOTS;

    if (level == EMERG_LEVEL_TELEMETRY || s_triggered != 0) {
        /* 遥测仅记录；已熔断（降级/终止）后不再重复处置 */
        LeaveCriticalSection(&s_lock);
        return;
    }

    /* 2. DEGRADE 判定：窗口内同一信号累计次数（含过期清理） */
    count = 0;
    for (i = 0; i < EMERG_HISTORY_SLOTS; i++) {
        if (s_history[i].tick == 0) continue;
        if (now - s_history[i].tick > EMERG_WINDOW_MS) {
            /* 过期条目就地失效（窗口滑动语义） */
            s_history[i].tick = 0;
            s_history[i].signal = 0;
            continue;
        }
        if (s_history[i].signal & (uint32_t)signal) {
            count++;
        }
    }

    if (count >= EMERG_DEGRADE_THRESHOLD) {
        /* 置闩锁在临界区内（原子化判定与置位），动作在锁外执行 */
        s_triggered = 1;
        should_degrade = 1;
    }

    LeaveCriticalSection(&s_lock);

    /*
     * 3. 降级动作在锁外执行：
     *    调用 API 层注入的处理器（清密钥 + 锁库，进程存活可恢复）。
     *    处理器缺失时保持熔断闩锁 —— IO 门控（emergency_is_triggered）
     *    仍然生效，功能上等价于"锁库"，后续 unlock 成功可清除。
     */
    if (should_degrade) {
        void (*handler)(void) = s_degrade_handler;
        if (handler != NULL) {
            handler();
        }
    }
}

uint32_t emergency_get_signals(void)
{
    ULONGLONG now;
    uint32_t snapshot;

    if (!s_initialized) return 0;

    now = emerg_now_ms();
    snapshot = 0;

    EnterCriticalSection(&s_lock);
    for (size_t i = 0; i < EMERG_HISTORY_SLOTS; i++) {
        if (s_history[i].tick == 0) continue;
        if (now - s_history[i].tick > EMERG_WINDOW_MS) continue;
        snapshot |= s_history[i].signal;
    }
    LeaveCriticalSection(&s_lock);
    return snapshot;
}

int emergency_is_triggered(void)
{
    /*
     * 单标志读：x86/x64 上对齐 LONG 读为原子操作。
     * volatile 防止编译器缓存到寄存器，保证读到最新值。
     * 此为高频查询路径（IO 前检查句柄可用性），不加锁以避免热路径开销。
     */
    return s_triggered ? 1 : 0;
}

int emergency_is_degraded(void)
{
    return (InterlockedCompareExchange(&s_triggered, 0, 0) == 1) ? 1 : 0;
}

void emergency_trigger(void)
{
    uint32_t signals_snapshot;
    uint32_t code;

    if (!s_initialized) {
        emergency_init();
    }

    /* ---- a) 极速熔断 ---- */
    EnterCriticalSection(&s_lock);
    if (s_triggered) {
        /* 已触发：避免并发线程重复执行内存绝育（purge 应幂等，此处兜底拦截） */
        LeaveCriticalSection(&s_lock);
        return;
    }
    /* 标记 KILL 态：句柄不可用，所有 IO 应立即拒绝 */
    s_triggered = 2;
    /* 捕获窗口内信号并集快照（绝育后仍需用于故障码选择） */
    signals_snapshot = 0;
    {
        ULONGLONG now = emerg_now_ms();
        for (size_t i = 0; i < EMERG_HISTORY_SLOTS; i++) {
            if (s_history[i].tick == 0) continue;
            if (now - s_history[i].tick > EMERG_WINDOW_MS) continue;
            signals_snapshot |= s_history[i].signal;
        }
    }
    LeaveCriticalSection(&s_lock);

    /* ---- b) 内存绝育 ---- */
    /*
     * 清零所有已注册敏感内存区域（密钥表、路径索引、解密头部缓存）：
     * memory_guard 内部对每个注册区域执行覆写清零。
     */
    memory_guard_emergency_purge();

    /*
     * 销毁 CNG 内核密钥句柄（A/B/C 三权分立密钥，
     * 唯一密钥存放位置；内核释放密钥材料，用户态无任何路径可达）。
     */
    key_separation_purge_all();

    /* ---- c) 故障码上报 ---- */
    code = select_fault_code(signals_snapshot);

    /* ---- d) 安全退出 ---- */
    emergency_exit(code);
}

void emergency_exit(uint32_t code)
{
    /*
     * 通知看门狗进程（若存在）：通过命名事件对象传递故障信号。
     * 看门狗经 WaitForSingleObject 捕获此事件后，读取本进程退出码即可
     * 获取匿名故障类型码（TerminateProcess 的退出码即 code）。
     */
    if (s_watchdog_event != NULL) {
        SetEvent(s_watchdog_event);
    }

    /*
     * 立即终止进程：
     * - TerminateProcess 不会触发 atexit 处理器 / DllMain detach，不写 minidump
     * - 不弹窗、不生成崩溃转储
     * - 退出码即匿名故障类型码，仅标识威胁类别，不含隐私数据
     * 严禁使用 exit()/ExitProcess()：前者运行 atexit 处理器可能写 dump，
     * 后者仍可能触发部分清理路径；TerminateProcess 是最干脆的终止方式。
     */
    TerminateProcess(GetCurrentProcess(), (UINT)code);

    /*
     * TerminateProcess 对自身调用必然成功，理论上不返回。
     * 此自旋为防御性兜底：若因极端权限问题未终止，绝不落入后续代码。
     */
    for (;;) {
        /* 等待进程被 OS 终止，绝不返回到调用方 */
    }
}

void emergency_clear_signals(void)
{
    if (!s_initialized) return;

    EnterCriticalSection(&s_lock);
    /* KILL 态不可清除（进程即将终止）；降级态允许经正常解锁流程恢复 */
    if (s_triggered != 2) {
        memset(s_history, 0, sizeof(s_history));
        s_history_next = 0;
        s_triggered = 0;
    }
    LeaveCriticalSection(&s_lock);
}
