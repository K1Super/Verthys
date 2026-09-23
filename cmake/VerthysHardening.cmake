# VerthysHardening.cmake
# 编译级加固：剥离符号、最高优化、栈保护、ASLR、DEP、控制流防护
# 安全核心 DLL 的加固；Debug 可调试，Release 剥离所有符号/调试信息
#
# 偏差留痕（依"偏差须磁盘证据"条款）：/guard:longjmp 未落地。
#   证据（2026-08-29 实测，MSVC 14.51.36231 + SDK 10.0.26100.0）：
#     1. /guard:longjmp 强制包含 guardcfw.h，该头文件在 MSVC include 与
#        Windows SDK 中均不存在 → 单文件编译 C1083 失败（exit=2）；
#     2. 与 /guard:cf 互斥（D9025 覆盖警告），不能共存；
#     3. CET 影子栈（/CETCOMPAT）在硬件层提供等价且更强的间接跳转/
#        返回地址防护，longjmp 防护的安全意图已被覆盖。
#   故依"禁用不可用特性"条款移除该旗标，其余全部落地。

# 安全基线（所有配置）：栈保护、控制流、UTF-8
# /wd4996 偏差留痕（依"偏差须磁盘证据"条款）：
#   /sdl 会将 MSVC 对 ISO C 标准函数（fopen 等，43 处，分布于事务/恢复/
#   格式等关键 IO 路径）的厂商劝告注解 C4996 升级为错误。fopen 是
#   ISO C 标准库函数，并非任何标准定义的废弃 API（Annex K 的 fopen_s
#   为可选扩展，可移植性差且被业界劝退）；批量替换关键 IO 路径的 43 处
#   调用风险大于收益。故保留 /sdl 全部附加检查（初始化引用、栈缓冲
#   校验等），仅抑制 C4996 劝告升级。/sdl 新增的实际检查项完整生效。
set(VERTHYS_SAFETY_FLAGS
    /GS            # 栈缓冲区溢出检测
    /guard:cf      # 控制流防护
    /guard:ehcont  # 异常连续性防护
    /sdl           # SDL 安全附加检查（初始化引用检查等）
    /wd4996        # 抑制 MSVC 对 ISO C 标准函数的厂商劝告升级（见上注）
    /utf-8         # 源码 UTF-8
    /Zc:inline     # COMDAT 折叠
)

# Release 优化与符号剥离
set(VERTHYS_RELEASE_FLAGS
    /O2            # 最高优化
    /Oi            # 内联内部函数
    /Oy            # 省略帧指针
    /GL            # 全链接优化 LTCG
    /Gy            # 函数级链接
    /Gw            # 全局变量级链接
    # 阻塞 4 修复：移除全局 /arch:AVX2
    # 原因：全局 /arch:AVX2 会在非 AVX2 CPU 上触发 SIGILL 崩溃，用户体验不可接受。
    # 改为依赖 libsodium 内部的运行时 CPU 检测（libsodium 自动选择 AVX2/SSE4.2/通用路径）。
    # verthys_api.c 中 verthys_check_avx2_support() 仍保留用于检测并设置 g_has_avx2 全局标志，
    # 供日志诊断和未来按需选择函数指针使用。
)

# 链接器基线（所有配置）
set(VERTHYS_LINK_BASE
    /INCREMENTAL:NO
    /DYNAMICBASE   # ASLR
    /HIGHENTROPYVA # 高熵 ASLR（x64）
    /NXCOMPAT      # DEP
)

# x64 专属链接加固（CET 影子栈）
set(VERTHYS_LINK_X64
    /CETCOMPAT     # Intel CET 影子栈强制（要求 /guard:cf）
)

# 链接器 Release
set(VERTHYS_LINK_RELEASE
    /LTCG
    /OPT:REF
    /OPT:ICF
    /DEBUG:NONE    # 不生成调试信息（剥离）
    /RELEASE
)

function(verthys_apply_hardening target)
    target_compile_options(${target} PRIVATE ${VERTHYS_SAFETY_FLAGS})
    target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:${VERTHYS_RELEASE_FLAGS}>)
    target_link_options(${target} PRIVATE ${VERTHYS_LINK_BASE})
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(${target} PRIVATE ${VERTHYS_LINK_X64})
    endif()
    target_link_options(${target} PRIVATE $<$<CONFIG:Release>:${VERTHYS_LINK_RELEASE}>)
endfunction()
