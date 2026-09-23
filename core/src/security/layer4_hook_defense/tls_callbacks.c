/*
 * tls_callbacks.c — TLS 回调注册（仅写入 TLS_INIT_MARKER）
 *
 *
 *   完整 IAT 校验逻辑在 tls_loader_init()（DLL_PROCESS_ATTACH 中）执行。
 *
 * 注册方式：
 *   通过 #pragma alloc_text 将 tls_callback 注册到 .CRT$XLB 节，
 *   PE 加载器会自动调用此回调。
 */
#include "tls_loader.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* TLS 回调函数原型 */
typedef VOID (WINAPI *PIMAGE_TLS_CALLBACK)(
    PVOID DllHandle, DWORD Reason, PVOID Reserved);

/* ---------- TLS 回调实现 ---------- */

static VOID WINAPI tls_callback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    (void)DllHandle;
    (void)Reserved;

    /* 仅处理 DLL_PROCESS_ATTACH 和 DLL_THREAD_ATTACH */
    if (Reason == DLL_PROCESS_ATTACH || Reason == DLL_THREAD_ATTACH) {
        /* 仅写入 TLS_INIT_MARKER，不做任何其他操作 */
        InterlockedExchange(&g_tls_init_marker, 1);
    }
    /* DLL_PROCESS_DETACH / DLL_THREAD_DETACH 不处理 */
}

/* ---------- 将回调注册到 .CRT$XLB 节 ---------- */

/*
 * _tls_index —— TLS 槽索引变量
 *
 * PE 加载器在处理 TLS 目录时，会为本 DLL 分配一个 TLS 槽索引，
 * 并将该索引写入 *_tls_used.AddressOfIndex 指向的变量。
 *
 * 即使本 DLL 不使用 __declspec(thread)，也必须提供一个有效的
 * AddressOfIndex 指针。若 AddressOfIndex 为 NULL(0)，部分
 * Windows 加载器实现仍会尝试解引用写入，导致 ACCESS_VIOLATION
 * (错误 998 ERROR_NOACCESS)，DLL 加载失败。
 *
 * 标准实践：声明 ULONG _tls_index = 0; 并在 _tls_used 中指向它。
 */
/* ==========================================================================
 * TLS 回调注册（MSVC 与 MinGW 双路径）
 *   MSVC（_MSC_VER）：手动定义 _tls_index / _tls_used / .CRT$XLB 节
 *   MinGW（else）：CRT（libgcc/libcrt）已自带 _tls_used / _tls_index，
 *                 仅将回调注册到 .CRT$XLB 节，_tls_used 自动引用该节
 *   MinGW 下严禁定义 _tls_index / _tls_used，否则与 CRT 多重定义链接错误
 * ========================================================================== */
#ifdef _MSC_VER
ULONG _tls_index = 0;

/*
 * p_tls_callback —— TLS 回调函数指针（位于 .CRT$XLB 节）
 *
 * .CRT$XLB 是 MSVC 约定的 TLS 回调注册节。链接器将 .CRT$XLA
 * (NULL 起始)、.CRT$XLB (用户回调)、.CRT$XLZ (NULL 终止) 合并
 * 为一个 NULL 终止的回调数组。AddressOfCallBacks 指向 &p_tls_callback
 * 时，加载器读取 [tls_callback, NULL] —— CRT 提供的 .CRT$XLZ NULL
 * 终止符紧随其后。
 *
 * 不能加 static：虽然内部链接不影响地址取值，但部分链接器优化
 * 配置下 static 变量可能被合并/丢弃，导致 .CRT$XLB 节为空。
 */
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;

/* MSVC 链接器识别的特殊符号 _tls_used（x64）/ __tls_used（x86）：
 *   - x64：C 符号无前导下划线，变量名 _tls_used 直接对应符号 _tls_used
 *   - x86：C 符号自动加一个前导下划线，变量名 _tls_used 对应符号 __tls_used
 * 链接器识别到此符号后，将 IMAGE_TLS_DIRECTORY 写入 PE 头的 TLS 目录。
 *
 * /INCLUDE 强制链接器保留此符号（否则 /OPT:REF 会丢弃），变量必须具有
 * 外部链接（不能是 static），否则 /INCLUDE 无法找到该符号。 */
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

/*
 * _tls_used —— IMAGE_TLS_DIRECTORY（PE 头 TLS 目录入口）
 *
 * 必须放在可写节（.data$T）—— 加载器需要应用基址重定位到
 * AddressOfIndex 和 AddressOfCallBacks 字段（都是 VA 指针）。
 * 若放在 .rdata 只读节，部分加载器实现的重定位写入会被
 * Copy-on-Write 机制处理，但显式可写节更可靠。
 *
 * 字段说明（IMAGE_TLS_DIRECTORY64）：
 *   StartAddressOfRawData / EndAddressOfRawData = 0：不使用 __declspec(thread)，
 *     无 TLS 原始数据需要复制到新线程的 TLS 槽
 *   AddressOfIndex = &_tls_index：加载器将分配的 TLS 槽索引写入此变量
 *   AddressOfCallBacks = &p_tls_callback：回调数组起始地址
 *     加载器从此地址开始读取函数指针并调用，直到遇到 NULL
 *   SizeOfZeroFill = 0：无零填充
 *   Characteristics = 0：无特殊属性
 */
#pragma data_seg(push)
#pragma section(".data$T", long, read, write)
__declspec(allocate(".data$T"))
IMAGE_TLS_DIRECTORY _tls_used = {
    0,                          /* StartAddressOfRawData (无 __declspec(thread)) */
    0,                          /* EndAddressOfRawData */
    (ULONG_PTR)&_tls_index,     /* AddressOfIndex —— 加载器写入 TLS 槽索引 */
    (ULONG_PTR)&p_tls_callback, /* AddressOfCallBacks —— 回调数组起始 */
    0,                          /* SizeOfZeroFill */
    0,                          /* Characteristics */
};
#pragma data_seg(pop)

#else  /* !_MSC_VER —— MinGW 路径 */
/*
 * MinGW-w64：CRT（libgcc/libcrt）已自带 _tls_used 与 _tls_index，
 * 仅需将回调指针放入 .CRT$XLB 节，MinGW 的 _tls_used（IMAGE_TLS_DIRECTORY）
 * 会自动引用 .CRT$XLB 节的回调数组，PE 加载器据此调用 tls_callback。
 *
 * __attribute__((section(".CRT$XLB")))：
 *   MinGW-w64 链接器将 .CRT$XLA（NULL 起始）/ .CRT$XLB（用户回调）/
 *   .CRT$XLZ（NULL 终止）合并为回调数组，与 MSVC 机制一致。
 *
 * __attribute__((used))：
 *   防止 -ffunction-sections / --gc-sections 优化丢弃该符号，
 *   确保链接器保留 .CRT$XLB 节。
 *
 * 不定义 _tls_index / _tls_used：复用 MinGW CRT 自带的，避免多重定义。
 */
__attribute__((section(".CRT$XLB"), used))
PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#endif /* _MSC_VER */
