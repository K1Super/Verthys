# core/CMakeLists.txt — 核心安全 DLL 与测试
#
# 深模块（codebase-design）：所有加密/格式/内存/反逆向逻辑封闭在此，
# 对外仅通过 include/verthys.h 的 C ABI 函数暴露（.def 白名单导出）。
#
# 模块化组织（C 层模块化与接口隔离标准规范）：
#   include/        公共接口区（唯一对外契约，自包含）
#   src/            实现区（子域 → 功能组件，组件实现 + 私有头同目录）
#   tests/          测试区（按被测子域镜像组织）
#   tools/          构建工具区（rhash_gen）
#   examples/       示例区
#   schema/         FlatBuffers 契约 + codegen 产物
#
# 业务分层（依赖方向 L5→L0 单向，无循环）：
#
#   L5  api/           公共 C ABI（lifecycle/unlock/scan/transfer/progress/shared）
#   L3  transaction/   事务一致（wal/txn — V3 六 Phase + WAL 环形双区）
#   L2  index/         索引数据（lsm 四件套 + warmcache）
#   L1  container/     容器格式（format/superblock/partition/extent/io/shared）
#   L0  crypto/        密码学原语（cipher/keymanager/pepper/rekey）
#   L6  security/      深度安全防护（方案 §6.4 精简后的模块集）
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
#   - verthys_core_obj：OBJECT 库，源码编译一次
#   - verthys_core：SHARED DLL，链接对象 + .def（仅导出公共函数）
#   - verthys_tests：测试 exe，链接对象 + 测试源（直接调用实现，不走 DLL 边界）
# .def 文件在链接器层面强制最小接口，确保内部符号不泄露。

# ★ 最终修复方案 §6.2：ASAN 构建开关（-DVERTHYS_ENABLE_ASAN=ON）
option(VERTHYS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(VERTHYS_ENABLE_ASAN AND MSVC)
    add_compile_options(/fsanitize=address)
    add_link_options(/fsanitize=address)
endif()

# ★ V3 升级 WP-10：模糊测试构建开关（-DVERTHYS_ENABLE_FUZZ=ON）
#   5 个 libFuzzer 目标（superblock/partition/extent/sstable/import）
#   + 插桩核心对象库 + 语料种子生成器。默认 OFF——插桩重编译核心
#   全量源码，仅模糊测试专项构建开启（scripts/build_core.fuzz.ps1）。
option(VERTHYS_ENABLE_FUZZ "Build libFuzzer fuzz targets (WP-10)" OFF)

# ★ P2-5 修复（2026-09-19）：DLL 诊断输出编译门（-DVERTHYS_DIAG=ON）
#   生产构建（默认 OFF）：VERTHYS_DIAG_LOG 为空操作，Release DLL 对
#   调试器/DebugView 完全静默，消除运行时行为指纹泄露面。
#   诊断构建（ON）：诊断经 OutputDebugStringA 输出，供开发环境捕获。
#   注意：Event Log（job_isolation.c）为产品正式排查通道，不受本门控制。
option(VERTHYS_DIAG "Enable DLL diagnostic output via OutputDebugStringA" OFF)
if(VERTHYS_DIAG)
    add_compile_definitions(VERTHYS_DIAG)
endif()

# ---------- 分层源文件 ----------
# ★ 模块化重构（C 层模块化与接口隔离标准规范）：
#   src/ 各子域内按功能组件拆分子目录（组件实现 + 私有头同目录），
#   模块内子目录不再平铺源文件；公共接口唯一保留 include/verthys.h。
set(VERTHYS_CORE_SOURCES
    # L0 crypto/ — 密码学原语（AEAD/HMAC/随机数/Argon2id/HKDF/密钥包裹）
    src/crypto/cipher/verthys_crypto.c
    src/crypto/cipher/secure_mem.c
    src/crypto/keymanager/keymanager.c
    src/crypto/pepper/verthys_pepper.c
    # ★ V3 升级 WP-1：CNG 内核态 AEAD 封装 + 密钥组生命周期（V3 主路径）
    src/crypto/cipher/verthys_crypto_cng.c
    src/crypto/keymanager/keymanager_cng.c
    # ★ V3 升级 WP-6：自动密钥轮换状态机（90 天/10k ops/DEGRADE 触发）
    src/crypto/rekey/verthys_rekey_auto.c
    # L1 container/ — 容器格式与交换信封（§1.4 V2 退役：V2 超级块已删）
    src/container/format/verthys_format.c
    src/container/io/verthys_io.c
    # ★ V3 升级 WP-2：V3 超级块（多副本法定人数）+ 分区管理
    src/container/superblock/verthys_superblock_v3.c
    src/container/partition/verthys_partition.c
    # ★ V3 升级 WP-3：内容寻址 Extent（去重 + 完整性）
    src/container/extent/verthys_extent.c
    # L2 index/ — 索引与数据管理（§1.4 V2 退役：btree/datablock/merkle 已删）
    # ★ V3 升级 WP-4：LSM 索引（MemTable 跳表 + SSTable + Compaction）
    src/index/lsm/verthys_lsm.c
    src/index/lsm/verthys_lsm_memtable.c
    src/index/lsm/verthys_lsm_sstable.c
    src/index/lsm/verthys_lsm_compaction.c
    # ★ V3 升级 WP-5：温启动缓存 V3（'V3IC'，HMAC+txid 双校验）
    src/index/warmcache/verthys_warmcache_v3.c
    # L3 transaction/ — 事务与一致性（§1.4 V2 退役：transaction/garbage/recovery 已删）
    # ★ V3 升级 WP-5：事务 WAL（环形 512KB×2）+ transaction_v3（六 Phase）
    src/transaction/wal/verthys_wal.c
    src/transaction/txn/verthys_transaction_v3.c
    # ★ 模块化重构：runtime/anti_debug（v1）为死代码——生产路径零调用
    #   （anti_debug_v2 为唯一生产检测器），随重构删除清单移除。
    # L6 security/ — 深度安全防护（按功能 + 防御层级分子目录组织）
    #   preset/ — 三档安全预设
    src/security/preset/security_preset.c
    #   integrity/ — 完整性校验（构建期基准验签）
    src/security/integrity/integrity.c
    # ★ V3 升级 WP-8：运行时函数级哈希校验（.rhat 表，防内存补丁）
    src/security/integrity/runtime_hash.c
    #   anti_analysis/ — 反调试 + 反注入
    src/security/anti_analysis/anti_debug_v2.c
    src/security/anti_analysis/anti_inject.c
    # ★ V3 升级 WP-9：直接系统调用（SSN 排序法提取 + W^X stub 页 +
    #   优雅降级；anti_debug_v2 / memory_guard 检测器唯一 NT 查询传输）
    src/security/anti_analysis/syscall_direct.c
    #   memory/ — 内存防护 + 三权分立密钥
    src/security/memory/memory_guard.c
    src/security/memory/key_separation.c
    # ★ V3 升级 WP-7：密钥相关结构专用安全分配器 + 全局内存预算记账
    src/security/memory/secure_allocator.c
    #   emergency/ — 应急分级响应
    src/security/emergency/emergency.c
    #   layer1_process_guard/ — Layer 1: 进程不可触碰化（双层 Job）
    src/security/layer1_process_guard/job_isolation.c
    #   layer3_hw_binding/ — Layer 3: 固件与硬件绑定
    src/security/layer3_hw_binding/cng_machine_key.c
    src/security/layer3_hw_binding/system32_loader.c
    src/security/layer3_hw_binding/hardware_binding.c
    #   layer4_hook_defense/ — Layer 4: TLS 标志验证 + 联动销毁
    src/security/layer4_hook_defense/tls_loader.c
    src/security/layer4_hook_defense/tls_callbacks.c
    src/security/layer4_hook_defense/tamper_destroy.c
    #   layer5_sandbox/ — Layer 5: 进程无菌沙盒（Mitigation Policy）
    src/security/layer5_sandbox/process_sandbox.c
    #   layer6_closure/ — Layer 6: 闭环防御能力验证
    src/security/layer6_closure/defense_closure.c
    # L5 api/ — 公共 C ABI（瘦门面 + 拆分模块；§1.4 V2 退役：v2_lifecycle/migration 已删）
    src/api/lifecycle/verthys_api.c
    src/api/shared/verthys_api_utils.c
    src/api/progress/verthys_progress.c
    # ★ V3 升级 WP-5：V3 生命周期 + 解锁流水线（S0-S6）
    src/api/lifecycle/verthys_v3_lifecycle.c
    src/api/unlock/verthys_unlock_pipeline.c
    src/api/transfer/verthys_export_import.c
    src/api/scan/verthys_scan.c
    src/api/lifecycle/dllmain.c
)

# ★ WP-10：相对路径 → 绝对路径一次性转换。相对源路径按使用处的
# CMAKE_CURRENT_SOURCE_DIR 解析（非定义处）——tests/fuzz 复用本清单
# 时（verthys_core_fuzz_obj 插桩重编译）基准错位会报"Cannot find source
# file"；本目录内 add_library(verthys_core_obj) 用绝对路径行为不变。
list(TRANSFORM VERTHYS_CORE_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

# 所有子目录加入 include 路径（扁平 include 兼容，如 #include "verthys_crypto.h"）
# ★ 模块化重构：目录表随组件拆分更新——新增组件目录即在此登记；
#   源代码 #include "xxx.h" 全部保持扁平形式零改动。
set(VERTHYS_SRC_SUBDIRS
    src/crypto/cipher
    src/crypto/keymanager
    src/crypto/pepper
    src/crypto/rekey
    src/container/format
    src/container/superblock
    src/container/partition
    src/container/extent
    src/container/io
    src/container/shared
    src/index/lsm
    src/index/warmcache
    src/transaction/wal
    src/transaction/txn
    src/api/lifecycle
    src/api/unlock
    src/api/scan
    src/api/transfer
    src/api/progress
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
)
# ★ WP-10：同 VERTHYS_CORE_SOURCES——子目录作用域（tests/fuzz）复用时
# 相对基准错位，一次性转绝对路径。
list(TRANSFORM VERTHYS_SRC_SUBDIRS PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

# ★ WP-0：schema codegen 自定义命令（flatc -a：reader/builder/verifier 全量）
#   core/schema/*.fbs → core/schema/generated/
#   flatcc_generate 目标保证 schema 变更时自动重新生成（依赖 vendored flatcc_cli）
set(VERTHYS_SCHEMA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/schema)
set(VERTHYS_SCHEMA_GEN_DIR ${VERTHYS_SCHEMA_DIR}/generated)
file(MAKE_DIRECTORY ${VERTHYS_SCHEMA_GEN_DIR})
# ★ WP-2：superblock_v3 / partition 业务 schema 加入 codegen
# ★ WP-3：extent（内容寻址索引）schema 加入 codegen
# ★ WP-4：sstable（SSTable Footer/Index Block + LSM Manifest）schema 加入 codegen
set(VERTHYS_SCHEMA_FILES
    ${VERTHYS_SCHEMA_DIR}/demo.fbs
    ${VERTHYS_SCHEMA_DIR}/superblock_v3.fbs
    ${VERTHYS_SCHEMA_DIR}/partition.fbs
    ${VERTHYS_SCHEMA_DIR}/extent.fbs
    ${VERTHYS_SCHEMA_DIR}/sstable.fbs
)
set(VERTHYS_SCHEMA_GEN_FILES
    ${VERTHYS_SCHEMA_GEN_DIR}/demo_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/demo_builder.h
    ${VERTHYS_SCHEMA_GEN_DIR}/demo_verifier.h
    ${VERTHYS_SCHEMA_GEN_DIR}/superblock_v3_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/superblock_v3_builder.h
    ${VERTHYS_SCHEMA_GEN_DIR}/superblock_v3_verifier.h
    ${VERTHYS_SCHEMA_GEN_DIR}/partition_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/partition_builder.h
    ${VERTHYS_SCHEMA_GEN_DIR}/partition_verifier.h
    ${VERTHYS_SCHEMA_GEN_DIR}/extent_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/extent_builder.h
    ${VERTHYS_SCHEMA_GEN_DIR}/extent_verifier.h
    ${VERTHYS_SCHEMA_GEN_DIR}/sstable_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/sstable_builder.h
    ${VERTHYS_SCHEMA_GEN_DIR}/sstable_verifier.h
    ${VERTHYS_SCHEMA_GEN_DIR}/flatbuffers_common_reader.h
    ${VERTHYS_SCHEMA_GEN_DIR}/flatbuffers_common_builder.h
)
add_custom_command(
    OUTPUT ${VERTHYS_SCHEMA_GEN_FILES}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${VERTHYS_SCHEMA_GEN_DIR}
    COMMAND $<TARGET_FILE:flatcc_cli> -a -o ${VERTHYS_SCHEMA_GEN_DIR} ${VERTHYS_SCHEMA_FILES}
    DEPENDS flatcc_cli ${VERTHYS_SCHEMA_FILES}
    COMMENT "[WP-0] flatcc codegen: ${VERTHYS_SCHEMA_FILES} -> schema/generated/"
    VERBATIM
)
add_custom_target(flatcc_generate DEPENDS ${VERTHYS_SCHEMA_GEN_FILES})

# 对象库：编译一次，供 DLL 与测试共用
add_library(verthys_core_obj OBJECT ${VERTHYS_CORE_SOURCES})
# ★ WP-4：LSM 源文件直接 include flatcc 生成头（sstable_builder.h 等）→
#   编译前必须完成 schema codegen（此前仅 verthys_tests 声明该依赖，
#   verthys_core_obj 先于 verthys_tests 构建时生成头尚不存在 → C1083）
add_dependencies(verthys_core_obj flatcc_generate)
# ★ 方案 §7（P0-A 治理）：不再定义 VERTHYS_EXPORTS —— VERTHYS_API 为空宏，
#   导出面唯一由 /DEF:verthys.def 白名单决定（见 verthys.h 宏注释）。
# /FS：允许多个 cl.exe 进程并发写入同一 .PDB 文件（并行编译必需）
target_compile_options(verthys_core_obj PRIVATE /FS)
target_include_directories(verthys_core_obj
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${VERTHYS_SRC_SUBDIRS}
            ${VERTHYS_SCHEMA_GEN_DIR}
            ${VERTHYS_XXHASH_INCLUDE_DIR}   # ★ WP-4：LSM Bloom Filter（xxHash64 双重哈希）
)
# ★ WP-0：V3 容器 FlatBuffers 运行时（flatccrt）链入核心；
#   schema 生成头（schema/generated/）供 V3 容器层（WP-2+）消费
target_link_libraries(verthys_core_obj PRIVATE flatccrt libsodium)
if(WIN32)
    # user32: 窗口/消息 API（反调试、窗口钩子检测）
    # wintrust crypt32: Authenticode 数字签名验证（模块白名单巡检）
    # shlwapi: SetSearchPathMode（DLL 搜索顺序加固）
    # psapi: 进程/模块信息查询（防注入巡检、栈自校验）
    # bcrypt: CNG (Cryptography Next Generation) — BCryptGenerateSymmetricKey / BCryptDecrypt / BCryptDestroyKey
    # ncrypt: CNG 机器密钥 — NCryptOpenStorageProvider / NCryptCreatePersistedKey / NCryptEncrypt / NCryptDecrypt
    target_link_libraries(verthys_core_obj PRIVATE user32 wintrust crypt32 shlwapi psapi bcrypt ncrypt)
endif()
verthys_apply_hardening(verthys_core_obj)

# 生产 DLL：仅导出 .def 列出的公共函数
add_library(verthys_core SHARED $<TARGET_OBJECTS:verthys_core_obj>)
target_include_directories(verthys_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${VERTHYS_SRC_SUBDIRS}
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
    target_link_libraries(verthys_core PRIVATE user32 wintrust crypt32 shlwapi psapi bcrypt ncrypt)
endif()
target_link_options(verthys_core PRIVATE
    /DEF:${CMAKE_CURRENT_SOURCE_DIR}/verthys.def
)
verthys_apply_hardening(verthys_core)

# ===================================================================== *
# ★ V3 升级 WP-8：rhash_gen 构建期 .rhat 补丁工具 + POST_BUILD 接线
#
# 闭环（v5.0 §9.3 构建期→运行期）：
#   1. 链接器 /MAP 产出 map 文件（符号名 → RVA）；
#   2. POST_BUILD 运行 rhash_gen：解析 map + .pdata（函数精确边界）+
#      .reloc（重定位槽位），对 X 清单 32 个关键函数计算
#      BLAKE2b-256（掩码归一），补丁 PE 的 .rhat 只读节；
#   3. 运行期 runtime_hash.c scan 重算内存映像哈希比对（双侧一致的
#      掩码归一保证跨 ASLR 基稳定）。
# 依赖：/INCREMENTAL:NO（VERTHYS_LINK_BASE 基线已含）——增量链接的 ILT
#   thunk 会让符号 RVA 指向跳板而非函数体，掩码归一失去意义。
# 红线：X 清单任一符号缺失 → rhash_gen 退出码 1 → 构建失败（禁静默降级）。
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
    COMMENT "[WP-8] rhash_gen: verthys.dll .rhat 运行时哈希表补丁"
    VERBATIM
)

# 测试（★ WP-10：enable_testing 上提至根 CMakeLists.txt——构建根需生成
# CTestTestfile.cmake 供 ctest --test-dir <build_root> 发现测试）
add_subdirectory(tests)

# ★ WP-10：模糊测试子树（默认 OFF；开启时插桩核心 + 5 目标 + 语料种子）
if(VERTHYS_ENABLE_FUZZ)
    add_subdirectory(tests/fuzz)
endif()
