#ifndef VERTHYS_DIAG_H
#define VERTHYS_DIAG_H
/*
 * verthys_diag.h — DLL 诊断输出统一编译门（P2-5 修复，2026-09-19）
 *
 * 规格（error_codes.h 治理条款延续）：C 源文件不得直接调用
 * printf / fprintf / OutputDebugString*；诊断一律经 VERTHYS_DIAG_LOG。
 *
 * 语义：
 *   - 生产构建（默认，VERTHYS_DIAG 未定义）：宏为空操作，Release DLL
 *     对调试器/DebugView 完全静默，消除运行时行为指纹泄露面。
 *   - 诊断构建（cmake -DVERTHYS_DIAG=ON）：输出经 OutputDebugStringA，
 *     供开发环境（调试器/DebugView）捕获。
 *
 * 注意：Event Log（RegisterEventSourceW）为产品正式排查通道，
 * 不受本门控制（见 job_isolation.c）。
 */
#ifdef VERTHYS_DIAG
#  if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#      define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
#    define VERTHYS_DIAG_LOG(msg) OutputDebugStringA(msg)
#  else
#    define VERTHYS_DIAG_LOG(msg) ((void)(msg))
#  endif
#else
#  define VERTHYS_DIAG_LOG(msg) ((void)(msg))
#endif

#endif /* VERTHYS_DIAG_H */
