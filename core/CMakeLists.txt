# core/CMakeLists.txt — 核心安全 DLL 与测试
#
# 深模块设计：所有加密/格式/内存/反逆向逻辑封闭在此，
# 对外仅通过 include/verthys.h 的 C ABI 函数暴露（.def 白名单导出）。
#
# 模块化组织：
#   include/        公共接口区（唯一对外契约，自包含）
#   src/            实现区（子域 → 功能组件，组件实现 + 私有头同目录）
#   tests/          测试区（按被测子域镜像组织）
#   tools/          构建工具区（rhash_gen）
#   examples/       示例区
#   schema/         FlatBuffers 契约 + codegen 产物
#
# 业务分层（依赖方向 L5→L0 单向，无循环）：
#
#   L5  api/           公共 C ABI（lifecycle/scan/transfer/progress/shared）
#   L2  index/         记录仓库、COW 目录树与追加数据区
#   L1  container/     容器格式（format/密钥槽/模块/分片/shared）
#   L0  crypto/        密码学原语（cipher/keymanager/pepper/kdf）
#   L6  security/      深度安全防护（精简后的模块集）
#                      preset/       — 三档安全预设
#                      integrity/    — 完整性校验（构建期基准验签）
#                      anti_analysis/— 反调试 + 反注入
#                      memory/       — 内存防护 + 三权分立 CNG 密钥
#                      emergency/    — 应急分级响应（TELEMETRY/DEGRADE/KILL）
#                      layer1_process_guard/    — 双层 Job 隔离
#                      layer3_hw_binding/       — CNG 机器密钥 + System32 优先 + 机器指纹
#                      layer4_hook_defense/     — TLS 标志验证 + 联动销毁
#                      layer5_sandbox/          — Mitigation Policy
#                      layer6_closure/          — 闭环防御能力验证（7 项攻击路径）
#
#
# 构建策略：
#   - verthys_core_shared_obj：OBJECT 库，共享安全/密码学基础设施
#   - verthys_core_obj：OBJECT 库，产品 API
#   - verthys_core：SHARED DLL，共享对象库 + 产品 API + .def（仅导出公共函数）
#   - verthys_tests：测试 exe，链接共享 + 产品 API（直接调用实现）
# .def 文件在链接器层面强制最小接口，确保内部符号不泄露。

# 容器格式版本（构建契约与运行时唯一事实值）。
# 该常量写入构建产物契约（build/core/verthys.artifacts.json），并须与
# core/include/verthys_version.h 的 `VERTHYS_CONTAINER_FORMAT_VERSION`
# 保持同步——契约消费方按此校验 DLL 与主程序/worker 的格式兼容性，
# 不一致即为契约失效。
set(VERTHYS_FMT_VERSION 4)

# ASAN 构建开关（-DVERTHYS_ENABLE_ASAN=ON）
option(VERTHYS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(VERTHYS_ENABLE_ASAN AND MSVC)
    add_compile_options(/fsanitize=address)
    add_link_options(/fsanitize=address)
endif()

# DLL 诊断输出编译门（-DVERTHYS_DIAG=ON）
#   生产构建（默认 OFF）：VERTHYS_DIAG_LOG 为空操作，Release DLL 对
#   调试器/DebugView 完全静默，消除运行时行为指纹泄露面。
#   诊断构建（ON）：诊断经 OutputDebugStringA 输出，供开发环境捕获。
#   注意：Event Log（job_isolation.c）为产品正式排查通道，不受本门控制。
option(VERTHYS_DIAG "Enable DLL diagnostic output via OutputDebugStringA" OFF)
if(VERTHYS_DIAG)
    add_compile_definitions(VERTHYS_DIAG)
endif()

# 编译内嵌胡椒开关（-DVERTHYS_ENABLE_COMPILED_PEPPER=ON）
#   默认 OFF：零熵胡椒常量与回退路径完全从构建移除——常量随源码
#   公开，任何拿到二进制的人都能还原，走该来源的容器离线爆破
#   退化为纯口令熵。OS 托管不可用且未注入时 verthys_pepper_init
#   直接失败（禁止静默降级）。
#   显式开启仅限受控调试构建（例如在无 CNG 环境验证降级流程），
#   发布构建禁止携带。
option(VERTHYS_ENABLE_COMPILED_PEPPER
       "Compile zero-entropy fallback pepper constant (debug builds only)" OFF)
if(VERTHYS_ENABLE_COMPILED_PEPPER)
    add_compile_definitions(VERTHYS_ENABLE_COMPILED_PEPPER)
endif()

# ---------- 分层源文件 ----------
#   src/ 各子域内按功能组件拆分子目录（组件实现 + 私有头同目录），
#   模块内子目录不再平铺源文件；公共接口唯一保留 include/verthys.h。
#
# 对象库边界：
#   VERTHYS_SHARED_SOURCES  共享安全/密码学基础设施 —— 产品与测试共用
#   VERTHYS_API_SOURCES     API 门面
set(VERTHYS_SHARED_SOURCES
    # L0 crypto/ — 密码学原语（AEAD/HMAC/随机数/Argon2id/HKDF/密钥包裹）
    src/crypto/cipher/verthys_crypto.c
    src/crypto/cipher/secure_mem.c
    src/crypto/keymanager/keymanager.c
    src/crypto/pepper/verthys_pepper.c
    # L1 container/ — 交换信封（导出/导入共用）
    src/container/format/verthys_format.c
    # 容器格式与密钥体系（双包裹 AND + 恢复码 + 模块 + 分片）
    src/crypto/vty_util.c
    src/crypto/vty_blake3.c
    src/crypto/vty_kdf.c
    src/crypto/vty_device_root.c
    src/crypto/vty_recovery.c
    src/crypto/vty_keyfile.c
    src/crypto/vty_keymanager.c
    # D9 全库 DEK 轮换作业（新文件全量重建 + 原子替换）
    src/crypto/vty_rotate.c
    src/container/vty_format.c
    src/container/vty_keyslot.c
    src/container/vty_chunk.c
    src/container/vty_module.c
    src/index/vty_record.c
    src/index/vty_store.c
    src/index/vty_repo.c
    src/security/lockout/vty_lockout.c
    # 库文件版本回退检测（外部单调锚点 + 设备根 MAC）
    src/security/rollback/vty_rollback.c
    # 安全状态固定位置/ACL/见证身份派生（KnownFolder + 设备根）
    src/security/state/vty_secure_state.c
    # 机器级速率限制扩展点（经特权服务实现）
    src/security/state/vty_machine_limiter.c
    # TPM 2.0 PCR 读取与 PCR 绑定密钥（高安全模式）
    src/security/tpm/vty_tpm_pcr.c
    # TPM 持久化密钥见证（NV 不可用时的回滚/熔断替代）
    src/security/tpm/vty_tpm_witness.c
    # L6 security/ — 深度安全防护（按功能 + 防御层级分子目录组织）
    #   preset/ — 三档安全预设
    src/security/preset/security_preset.c
    #   integrity/ — 完整性校验（构建期基准验签）
    src/security/integrity/integrity.c
    # 运行时函数级哈希校验（.rhat 表，防内存补丁）
    src/security/integrity/runtime_hash.c
    #   anti_analysis/ — 反调试 + 反注入
    src/security/anti_analysis/anti_debug.c
    src/security/anti_analysis/anti_inject.c
    # 直接系统调用（SSN 排序法提取 + 映像内 thunk +
    #   优雅降级；anti_debug / memory_guard 检测器唯一 NT 查询传输）
    src/security/anti_analysis/syscall_direct.c
    #   memory/ — 内存防护 + 三权分立密钥
    src/security/memory/memory_guard.c
    # 系统休眠状态（hiberfil 取证判据：禁用/启用/未知三态）
    src/security/memory/hibernation_state.c
    # 密钥相关结构专用安全分配器 + 全局内存预算记账
    src/security/memory/secure_allocator.c
    #   emergency/ — 应急分级响应
    src/security/emergency/emergency.c
    #   layer1_process_guard/ — Layer 1: 进程不可触碰化（双层 Job）
    src/security/layer1_process_guard/job_isolation.c
    #   layer3_hw_binding/ — Layer 3: 固件与硬件绑定
    src/security/layer3_hw_binding/cng_machine_key.c
    src/security/layer3_hw_binding/system32_loader.c
    src/security/layer3_hw_binding/hardware_binding.c
    #   layer4_hook_defense/ — Layer 4: TLS 标志验证
    src/security/layer4_hook_defense/tls_loader.c
    src/security/layer4_hook_defense/tls_callbacks.c
    # ntdll 导出基线 + Inline Hook/IAT 扫描（60s 周期，首次异常仅遥测）
    src/security/layer4_hook_defense/hook_scan.c
    #   layer5_sandbox/ — Layer 5: 进程无菌沙盒（Mitigation Policy）
    src/security/layer5_sandbox/process_sandbox.c
    #   layer6_closure/ — Layer 6: 闭环防御能力验证
    src/security/layer6_closure/defense_closure.c
    #   caller_auth/ — 调用方签名校验（Verthys_Init 前置门，A2）
    src/security/caller_auth/vty_caller_auth.c
    # L5 api/ — 非容器格式相关的公共模块
    src/api/verthys_api_container.c
    src/api/lifecycle/dllmain.c
)

# API 门面（产品与测试共用同一编译定义）
set(VERTHYS_API_SOURCES
    src/api/lifecycle/verthys_api.c
    src/api/shared/verthys_api_utils.c
    src/api/transfer/verthys_export_import.c
    src/api/scan/verthys_scan.c
)

# 直连系统调用 thunk：ACG 兼容实现依赖映像内固定的 syscall 指令序列。
# 仅 MSVC 工具链提供 MASM；其他工具链不生成 thunk，模块保持 GetProcAddress 回退。
if(MSVC)
    list(APPEND VERTHYS_SHARED_SOURCES
        src/security/anti_analysis/syscall_thunk_x64.asm
    )
endif()

# 相对路径 → 绝对路径一次性转换：跨目录消费时按定义处目录解析，
# 避免基准错位。
list(TRANSFORM VERTHYS_SHARED_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
list(TRANSFORM VERTHYS_API_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

# 所有子目录加入 include 路径（扁平 include 兼容，如 #include "verthys_crypto.h"）
# 目录表随组件拆分更新——新增组件目录即在此登记；
#   源代码 #include "xxx.h" 全部保持扁平形式零改动。
set(VERTHYS_SRC_SUBDIRS
    src/crypto
    src/crypto/cipher
    src/crypto/keymanager
    src/crypto/pepper
    src/container
    src/container/format
    src/container/shared
    src/index
    src/security/lockout
    src/security/rollback
    src/security/state
    src/security/tpm
    src/api
    src/api/lifecycle
    src/api/scan
    src/api/transfer
    src/api/shared
    src/security
    src/security/preset
    src/security/integrity
    src/security/anti_analysis
    src/security/memory
    src/security/emergency
    src/security/layer1_process_guard
    src/security/layer3_hw_binding
    src/security/layer4_hook_defense
    src/security/layer5_sandbox
    src/security/layer6_closure
    src/security/caller_auth
)
# 同源文件分组——tests 子目录复用时相对基准不错位。
list(TRANSFORM VERTHYS_SRC_SUBDIRS PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

# schema codegen 自定义命令（flatc -a：reader/builder/verifier 全量）
#   core/schema/*.fbs → core/schema/generated/
#   flatcc_generate 目标保证 schema 变更时自动重新生成（依赖 vendored flatcc_cli）
set(VERTHYS_SCHEMA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/schema)
set(VERTHYS_SCHEMA_GEN_DIR ${VERTHYS_SCHEMA_DIR}/generated)
file(MAKE_DIRECTORY ${VERTHYS_SCHEMA_GEN_DIR})
set(VERTHYS_SCHEMA_FILES
    ${VERTHYS_SCHEMA_DIR}/demo.fbs
)
set(VERTHYS_SCHEMA_GEN_FILES
    ${VERTHYS_SCHEMA_GEN_DIR}/demo_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/demo_builder.h
    ${VERTHYS_SCHEMA_GEN_DIR}/demo_verifier.h
    ${VERTHYS_SCHEMA_GEN_DIR}/flatbuffers_common_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/flatbuffers_common_builder.h
)
add_custom_command(
    OUTPUT ${VERTHYS_SCHEMA_GEN_FILES}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${VERTHYS_SCHEMA_GEN_DIR}
    COMMAND $<TARGET_FILE:flatcc_cli> -a -o ${VERTHYS_SCHEMA_GEN_DIR} ${VERTHYS_SCHEMA_FILES}
    DEPENDS flatcc_cli ${VERTHYS_SCHEMA_FILES}
    COMMENT "[schema] flatcc codegen: ${VERTHYS_SCHEMA_FILES} -> schema/generated/"
    VERBATIM
)
add_custom_target(flatcc_generate DEPENDS ${VERTHYS_SCHEMA_GEN_FILES})

# ---------- 对象库 ----------
# 共享对象库：安全/密码学基础设施（产品与测试共用）
add_library(verthys_core_shared_obj OBJECT ${VERTHYS_SHARED_SOURCES})
# 产品 API 对象库
add_library(verthys_core_obj OBJECT ${VERTHYS_API_SOURCES})

# 两个对象库共用编译/链接设置：任一新增对象库必须经本循环，
# 避免 include 路径或加固旗标在某个库上静默缺失。
foreach(_verthys_obj
        verthys_core_shared_obj
        verthys_core_obj)
    # 仅当构建包含 MASM thunk 时才允许 C 代码引用该符号，
    # 避免其他工具链在链接阶段出现未解析外部符号。
    if(MSVC)
        target_compile_definitions(${_verthys_obj} PRIVATE VERTHYS_SCD_INLINE_THUNK)
    endif()
    # schema 生成头（sstable_builder.h 等）→ 编译前必须完成 codegen
    add_dependencies(${_verthys_obj} flatcc_generate)
    # 不定义 VERTHYS_EXPORTS：VERTHYS_API 为空宏，
    #   导出面仅由 /DEF:verthys.def 白名单决定。
    # /FS：允许多个 cl.exe 进程并发写入同一 .PDB 文件（并行编译必需）
    target_compile_options(${_verthys_obj} PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:/FS>)
    target_include_directories(${_verthys_obj}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
                ${VERTHYS_SRC_SUBDIRS}
                ${CMAKE_SOURCE_DIR}/security-service/include
                ${VERTHYS_SCHEMA_GEN_DIR}
    )
    target_link_libraries(${_verthys_obj} PRIVATE flatccrt libsodium)
    if(WIN32)
        # user32: 窗口/消息 API（反调试、窗口钩子检测）
        # wintrust crypt32: Authenticode 数字签名验证（模块白名单巡检）
        # shlwapi: SetSearchPathMode（DLL 搜索顺序加固）
        # psapi: 进程/模块信息查询（防注入巡检、栈自校验）
        # bcrypt: CNG (Cryptography Next Generation) — BCryptGenerateSymmetricKey / BCryptDecrypt / BCryptDestroyKey
        # ncrypt: CNG 机器密钥 — NCryptOpenStorageProvider / NCryptCreatePersistedKey / NCryptEncrypt / NCryptDecrypt
        # tbs: TPM Base Services — Tbsi_Context_Create / Tbsip_Submit_Command（PCR 读取）
        target_link_libraries(${_verthys_obj} PRIVATE
            user32 wintrust crypt32 shlwapi psapi bcrypt ncrypt tbs)
    endif()
    verthys_apply_hardening(${_verthys_obj})
endforeach()

# A2 调用方签名门：默认关闭，只有签名流水线就绪的发布通道才打开。
# 打开时强制要求发布者指纹；指纹缺失就配置失败，避免“开关打开但所有
# 调用方都被拒绝”这种只在运行期才暴露的部署事故。
# 定义落在 shared 对象库（vty_caller_auth.c 所在库）。
option(VERTHYS_REQUIRE_CALLER_SIG
    "Require publisher Authenticode signature for the caller process and verthys.dll" OFF)
# 测试隔离钩子：仅攻击回归测试构建使用。打开后允许
# VERTHYS_TEST_STATE_DIR 覆盖熔断/回滚状态目录；生产构建必须显式 OFF。
option(VERTHYS_TEST_HOOKS
    "Enable test-only state path override (never enable for production)" OFF)
if(VERTHYS_TEST_HOOKS)
    target_compile_definitions(verthys_core_shared_obj PRIVATE
        VERTHYS_TEST_HOOKS=1)
    message(STATUS "[test-hooks] state path override enabled")
endif()
set(VERTHYS_PUBLISHER_SHA256 "" CACHE STRING
    "SHA-256 fingerprint of the publisher code-signing certificate (64 hex chars)")
if(VERTHYS_REQUIRE_CALLER_SIG)
    if(VERTHYS_PUBLISHER_SHA256 STREQUAL "")
        message(FATAL_ERROR
            "VERTHYS_REQUIRE_CALLER_SIG=ON requires -DVERTHYS_PUBLISHER_SHA256=<cert sha256>")
    endif()
    target_compile_definitions(verthys_core_shared_obj PRIVATE
        VERTHYS_REQUIRE_CALLER_SIG=1
        "VERTHYS_PUBLISHER_SHA256=\"${VERTHYS_PUBLISHER_SHA256}\"")
    message(STATUS "[caller-auth] enforced, publisher=${VERTHYS_PUBLISHER_SHA256}")
endif()

# 生产 DLL：仅导出 .def 列出的公共函数。
# 链接边界：共享对象库（安全基础设施）+ 产品 API。
add_library(verthys_core SHARED
    $<TARGET_OBJECTS:verthys_core_shared_obj>
    $<TARGET_OBJECTS:verthys_core_obj>)
target_include_directories(verthys_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${VERTHYS_SRC_SUBDIRS}
            ${CMAKE_SOURCE_DIR}/security-service/include
)
set_target_properties(verthys_core PROPERTIES
    OUTPUT_NAME verthys
    PREFIX ""          # 输出 verthys.dll 而非 libverthys.dll
)
# $<TARGET_OBJECTS:> 不传播对象库的链接依赖，DLL 需显式链接 libsodium 与 flatccrt
target_link_libraries(verthys_core PRIVATE flatccrt libsodium)
if(WIN32)
    # 与对象库一致的 Windows 依赖（见上方注释）
    # bcrypt: CNG (Cryptography Next Generation) — BCryptGenerateSymmetricKey / BCryptDecrypt / BCryptDestroyKey
    # ncrypt: CNG 机器密钥 — NCryptOpenStorageProvider / NCryptCreatePersistedKey / NCryptEncrypt / NCryptDecrypt
    # tbs: TPM Base Services — PCR 读取
    target_link_libraries(verthys_core PRIVATE user32 wintrust crypt32 shlwapi psapi bcrypt ncrypt tbs)
endif()
target_link_options(verthys_core PRIVATE
    /DEF:${CMAKE_CURRENT_SOURCE_DIR}/verthys.def
)
verthys_apply_hardening(verthys_core)
# .rhat 生成仅覆盖产品实际保留的共享关键函数（--xlist core）。

# ===================================================================== *
# rhash_gen 构建期 .rhat 补丁工具 + POST_BUILD 接线
#
# 闭环（构建期→运行期）：
#   1. 链接器 /MAP 产出 map 文件（符号名 → RVA）；
#   2. POST_BUILD 运行 rhash_gen：解析 map + .pdata（函数精确边界）+
#      .reloc（重定位槽位），对 X 清单关键函数计算
#      BLAKE2b-256（掩码归一），补丁 PE 的 .rhat 只读节；
#   3. 运行期 runtime_hash.c scan 重算内存映像哈希比对（双侧一致的
#      掩码归一保证跨 ASLR 基稳定）。
# 依赖：/INCREMENTAL:NO（VERTHYS_LINK_BASE 基线已含）——增量链接的 ILT
#   thunk 会让符号 RVA 指向跳板而非函数体，掩码归一失去意义。
# 红线：X 清单任一符号缺失 → rhash_gen 退出码 1 → 构建失败（禁静默降级）。
#   --xlist core：产品 DLL 的共享关键函数清单。
# ===================================================================== *
add_executable(rhash_gen tools/rhash_gen.c)
target_include_directories(rhash_gen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/security/integrity
)
target_link_libraries(rhash_gen PRIVATE libsodium)
if(MSVC)
    # 源码 UTF-8（中文诊断输出防乱码）
    target_compile_options(rhash_gen PRIVATE /utf-8)
endif()

# DLL：/MAP + POST_BUILD .rhat 补丁（Debug/Release 全配置生效——
# 每轮构建产物即真表，测试与生产链路共用同一验证路径）
target_link_options(verthys_core PRIVATE
    /MAP:$<TARGET_FILE_DIR:verthys_core>/verthys.map
)
add_dependencies(verthys_core rhash_gen)
add_custom_command(TARGET verthys_core POST_BUILD
    COMMAND $<TARGET_FILE:rhash_gen> --patch $<TARGET_FILE:verthys_core>
            --xlist core
    # 产物契约必须在 .rhat 补丁完成之后生成（同一脚本内顺序执行）：
    # 契约哈希覆盖最终交付的 DLL 字节，消费方校验才不会误判
    COMMAND ${CMAKE_COMMAND}
        -DVER_DLL_PATH=$<TARGET_FILE:verthys_core>
        -DVER_OUT_PATH=${CMAKE_BINARY_DIR}/core/verthys.artifacts.json
        -DVER_VERSION=${PROJECT_VERSION}
        -DVER_FMT_VERSION=${VERTHYS_FMT_VERSION}
        -DVER_GENERATOR=${CMAKE_GENERATOR}
        -DVER_CONFIG=$<CONFIG>
        -DVER_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_SOURCE_DIR}/cmake/write_artifacts.cmake
    COMMENT "[rhash] rhash_gen: verthys.dll .rhat 运行时哈希表补丁 + 产物契约生成"
    VERBATIM
)

# 测试（enable_testing 上提至根 CMakeLists.txt——构建根需生成
# CTestTestfile.cmake 供 ctest --test-dir <build_root> 发现测试）
add_subdirectory(tests)