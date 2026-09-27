#ifndef VERTHYS_DIAG_H
#define VERTHYS_DIAG_H
/*
 * verthys_diag.h — DLL 诊断输出统一编译门
 *
 * 规格（诊断输出规范延续）：C 源文件不得直接调用
 * printf / fprintf / OutputDebugString*；诊断一律经 VERTHYS_DIAG_LOG。
 *
 * 语义：
 *   - 生产构建（默认，VERTHYS_DIAG 未定义）：宏为空操作，Release DLL
 *     对调试器/DebugView 完全静默，消除运行时行为指纹泄露面；
 *     空操作形态用 sizeof(逗号表达式) 引用全部实参——参数表达式
 *     不求值，同时避免"仅用于诊断的变量"触发未使用警告。
 *   - 诊断构建（cmake -DVERTHYS_DIAG=ON）：格式化输出（Windows 经
 *     OutputDebugStringA、其余经 stderr），供开发环境捕获。
 *
 * 宏为可变参数形态（fmt 后可变实参），定长缓冲截断超出部分，
 * 保证任意长度实参不越界。
 *
 * 注意：Event Log（RegisterEventSourceW）为产品正式排查通道，
 * 不受本门控制（同 job_isolation.c）。
 */
#ifdef VERTHYS_DIAG
#  if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#      define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
#    include <stdio.h>
#    define VERTHYS_DIAG_LOG(fmt, ...) \
        do { \
            char _vdiag_buf[512]; \
            _snprintf_s(_vdiag_buf, sizeof(_vdiag_buf), _TRUNCATE, \
                        fmt, ##__VA_ARGS__); \
            OutputDebugStringA(_vdiag_buf); \
        } while (0)
#  else
#    include <stdio.h>
#    define VERTHYS_DIAG_LOG(fmt, ...) \
        do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#  endif
#else
#  define VERTHYS_DIAG_LOG(fmt, ...) \
        do { (void)sizeof((fmt, ##__VA_ARGS__)); } while (0)
#endif

#endif /* VERTHYS_DIAG_H */