# Verthys V3 全系升级执行手册（AI 协作切入点文档）

> **文档版本**: 1.0（2026-08-30）
> **文档定位**: 将《终极目标架构 v5.0》《性能架构 v1.0》《解锁优化方案》三份目标态文档**锚定到当前磁盘代码的真实状态**，为 AI 驱动的全系升级提供精确切入点。每个工作包一节，含入口文件、复用资产、设计约束、验收标准与可直接粘贴的 AI 会话提示词。
> **使用方式**: 一个 AI 会话执行一个工作包（WP）。会话开场粘贴：本文档 §6 对应 WP 的完整小节 + §3 全局约定 + §1 状态基线中与该 WP 相关的行。会话结束按 §6 验收标准闭环。
> **前置必读**: [PROJECT\_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md) v4.0（当前架构事实标准）

***

## 目录

1. [当前代码状态基线（AI 必读事实）](#1-当前代码状态基线ai-必读事实)
2. [目标文档索引与关键决策修正](#2-目标文档索引与关键决策修正)
3. [全局工程约定与红线](#3-全局工程约定与红线)
4. [升级总路线图与依赖图](#4-升级总路线图与依赖图)
5. [工作包详解（WP-13 → WP-1 → WP-2..5 → …）](#5-工作包详解)

   * WP-13 / WP-1 / WP-7 / WP-2 / WP-3 / WP-4 / WP-5 / WP-6 / WP-8 / WP-9 / WP-10 / WP-14 / WP-11 / WP-12
6. [AI 会话协议与提示词模板](#6-ai-会话协议与提示词模板)
7. [命令速查](#7-命令速查)
8. [风险登记册](#8-风险登记册)
9. [里程碑验收矩阵](#9-里程碑验收矩阵)

***

## 1. 当前代码状态基线（AI 必读事实）

以下事实经 2026-08-29/30 逐文件精读 + 全仓 grep + 构建实测核实。**任何 AI 会话不得凭头注注释或文档宣称推断现状——以本表为起点，改动前用 grep 复核**（历史教训：security 层曾 55% 代码未接线而头注宣称完整）。

### 1.1 已就绪、可直接复用的资产

| 资产                                                                | 位置                                                           | V3 中的角色                                  |
| ----------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------- |
| CNG 内核 AEAD 全套（BCrypt AES-GCM 导入/加解密/C 角色休眠/purge/any\_installed） | `core/src/security/memory/key_separation.c`                  | WP-1 的重构母本（已在运行，缺 12B 单调 nonce 计数器与批量导入） |
| 超级块事务原语（begin 备份/commit/rollback，幂等）                              | `verthys_superblock.c` + `verthys_superblock_internal.h`（VsbTxn） | VsbTxnV3 的设计模板                           |
| 统一 64 位 I/O 层（vio\_fseek64/ftell64/pread64/pwrite64）              | `container/verthys_io.c/.h`                                    | 直接复用，V3 扩展分区感知包装                         |
| 应急三级响应（TELEMETRY/DEGRADE/KILL + 10min 窗口 + 降级处理器）                 | `security/emergency/emergency.c`                             | 不变，V3 延续                                 |
| 进程沙盒（Rust 侧 mitigation policy + NotifySandboxAttrs）               | `verthys-worker/src/defense.rs` → `verthys_api.c`                | 不变                                       |
| 双层 Job + 白名单 DACL                                                 | `security/layer1_process_guard/job_isolation.c`              | 不变                                       |
| `.vsec` 构建期签名（构建脚本注入 + 文件内容 HMAC 验签）                              | `integrity.c` + `build_core.release.ps1`                     | WP-8 runtime\_hash 的扩展基座                 |
| pepper v2（来源指纹/禁兜底/Shamir/CNG 机器包装）                               | `crypto/verthys_pepper.c`                                      | v3 pepper 的母本                            |
| Argon2id 校准 + 自适应 rewrap（漂移监控/降档升档/原子持久化）                         | `verthys_crypto.c` `verthys_v2_lifecycle.c`                      | 解锁优化（UNLOCK\_OPTIMIZATION.md §4）的现有实现    |
| 摘要索引序列化（逐条目边界检查样板）                                                | `verthys_transaction.c:148-234`                                | V3 序列化代码的编码规范样例                          |
| 超级块反序列化（HMAC→AEAD→safe\_read 边界纪律 + TLV）                          | `verthys_superblock.c:640-800`                                 | V3 解析器的安全编码规范样例                          |
| 测试 argv 过滤器（子串 + OR 多组）                                           | `tests/test_runner.c`                                        | WP-13 定位工具                               |
| ASAN 构建开关                                                         | `CMakeLists.txt -DVERTHYS_ENABLE_ASAN=ON`                   | CI 强制门                                   |

### 1.2 已知缺陷与未决项

| 编号      | 状态           | 说明                                                                                                                                                                                                                              |
| ------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **K-1** | **未决（最高优先）** | 全量测试连跑在 `perf_diagnostics_metrics_complete` 段错误；分组/组合全绿；ASAN 无报告；布局敏感（链接 `test_final_repair.obj` 即复现）。已排除：修复项功能错误。怀疑：测试间累积状态（后台线程/句柄/紧急信号窗口）+ 布局敏感野指针。**另观测 LNK1168 陷阱：挂起的测试进程锁死 exe → 后续构建静默使用陈旧产物**（多次"复现"实为旧二进制）。WP-13 专项处理。 |
| P2 群    | **已闭环（2026-09-15，WP-14）** | 六项 P2 全部处理完毕：P2-1 GC 超块裸写 / P2-4 温缓存 .tmp 竞态 / P2-6 mountwatch INFINITE 已随 V3 重写或 V2 退役结构性吸收；P2-2 读块钳制已吸收且核对中发现的 3 处 uint64 回绕窗口已加固；P2-3 vtxn\_rollback / P2-5 扫描游标生命周期已由 V3 重写修复。逐项核对记录见 §5 WP-14 执行留痕 |

### 1.3 密钥现状（决定 WP-1 的起点）

* A/B/C 密钥**明文驻留** `VerthysContext`（`container/verthys_internal.h:102-104` 的 `key_a/b/c[32]` 数组）+ 事务上下文副本（`verthys_transaction.h:42-44`）。

* `key_separation.c`（CNG 托管）**模块完整但零业务接线**——仅 `defense_closure` 用 `any_installed` 做判据。

* 解锁路径的密钥流：Argon2id → MEK（用户态）→ HKDF → key\_a/b/c → ctx 数组。

* 改密/rekey 已有完整模式：`verthys_export_import.c` ChangePassword + `verthys_v2_lifecycle.c:827` `verthys_argon2_rewrap`（vsb\_txn 保护）——WP-1/6 改造的对照实现。

### 1.4 将在 V3 中删除的代码（WP-5 完成后执行删除清单）

| 文件/路径                                       | 原因                                           |
| ------------------------------------------- | -------------------------------------------- |
| `container/verthys_format.c`（v1 全量格式）         | v5.0：不支持 V1/V2 打开                            |
| `index/verthys_btree.c`                       | LSM 替代                                       |
| `index/verthys_datablock.c`（三级槽位池）            | Extent 内容寻址替代                                |
| `api/verthys_migration.c`                     | 无旧格式可迁移                                      |
| `transaction/verthys_transaction.c` 的 v2 提交路径 | transaction\_v3 替代                           |
| `api/verthys_v2_lifecycle.c`（大部分）             | verthys\_v3\_lifecycle 替代（校准/并行流水线/进度回调逻辑迁移保留） |
| warmcache v2 格式                             | UNLOCK\_OPTIMIZATION.md §7 的 V3 缓存格式替代       |

**删除纪律**：每删除一个文件，同步删除 CMakeLists 源行 + include 目录 + 全部引用（grep 验证零残留）+ 受影响测试迁移；删除清单执行单独成一次提交并留痕。

**执行留痕（2026-09-15，WP-5 删除清单完成）**：

* 删除清单全部执行完毕：`verthys_btree`/`verthys_datablock`/`verthys_migration`/`verthys_transaction`(v2 路径)/`verthys_v2_lifecycle`/`verthys_superblock`(V2)/`verthys_warmcache`(v2)/watcher/mountwatch 等 V2 专属源随 CMakeLists 源行一并移除；`verthys_format.c` 裁剪为 V3 交换信封专用（迁移接口 `vfmt_record_iter_*`/`vfmt_migrate_v1_to_v2`/`vfmt_detect_v1_format` 删除）。

* 头文件与结构收敛：`verthys_internal.h` 移除 V1/V2 字段与 `container_v2` include；`VerthysV2Preset` 收敛为 `VerthysPreset`。

* 导出面收敛：`verthys.def` 与 `include/verthys.h` 移除全部 V2 API 声明，`ci/export_baseline.txt` 同步。

* 测试适配：BTree 测试 → LSM 等价（`repair_lsm_large_insert`）、V2 超块事务 → `VsbTxnV3`（`repair_vsb_txn_v3_rollback`）、预设常量去 V2 前缀、CNG 密钥销毁断言替代 V2 明文密钥零化断言；新增 `v3life_scan_family_v3` 全扫描家族回归（GetSummaryCount/ScanSummary/Scan/HasRecordByType/FindFirstLidByType）。

* 零残留验证：`grep -E "VERTHYS_FMT_V2|VerthysV2|VERTHYS_V2_PRESET|vbtree_|vtxn_|verthys_container_v2|vfmt_record_iter"` 全库仅余三类合法匹配——退役说明注释（"§1.4 V2 退役……"）、`anti_debug_v2` 安全模块名（反调试第二代，与容器 V2 无关）、`WINTRUST_ACTION_GENERIC_VERIFY_V2`（Windows API 常量）。

* 验证结果：Debug 全量测试 229 passed / 0 failed（V2 退役后基线）。

### 1.5 构建与验证现状（2026-09-15 更新）

* 模块化重构（core 源码按子域/组件拆分到多级子目录）后 Debug 全新配置全量编译 + **250/250 测试通过**（254 − 4 个已删 ad\_\* 死测试）；Release 链路含 `.vsec + .rhat` 注入实测通过；导出面 **29 符号** = `.def` 白名单（`ci/export_baseline.txt`，V2 退役收敛后基线）。

* **本机构建产物已全部清除（2026-09-15，银狐木马复发事件）**：新构建 EXE 在数分钟内再次被包装（ProductName=RuntimeBroker / FileVersion=8.9.8.9 / requireAdministrator 清单特征），证实感染源活跃；build\_\*/verthys-tauri 暂存二进制/根级垃圾 PE 已清空，**重装系统前禁止任何构建**。重装后复验顺序：`scripts/tmp_scan_infection.ps1` 感染复检 → `build_core.dev.ps1`（250 测试）→ `build_core.release.ps1`（.vsec/.rhat + 29 符号 dumpbin 比对）→ `build_core.fuzz.ps1`（5 目标 × 10 分钟）→ worker 构建 + 双暂存 → 3 连绿。

* CI：`.github/workflows/core.yml`（Debug 测试 → Release+vsec → dumpbin 比对门）。

* 工具链：VS 18 2026 / MSVC 14.51.36231 / SDK 10.0.26100；**已知陷阱**：`/guard:longjmp` 不可用（缺 guardcfw\.h）。

### 1.6 架构决策记录：core 模块化重构（ADR-2026-09-15，规范 §8.2 留痕）

**背景**：V3 收口后 core 源文件仍同级平铺于 `core/src/` 一层（50+ .c/.h 混排，公共接口头与私有实现同目录），不满足《C 层模块化与接口隔离标准规范》（子域拆分 / 物理隔离 / 命名与规模约束）。

**决策**：core 源码按**子域 → 功能组件**两级拆分，六顶层域 + 31 组件目录（`core/CMakeLists.txt` `VERTHYS_SRC_SUBDIRS` 单一事实源）：

| 域 | 组件目录 |
| --- | --- |
| `src/api`（6） | lifecycle / unlock / scan / transfer / progress / shared |
| `src/container`（6） | format / superblock / partition / extent / io / shared |
| `src/crypto`（4） | cipher / keymanager / pepper / rekey |
| `src/index`（2） | lsm / warmcache |
| `src/transaction`（2） | wal / txn |
| `src/security`（11） | preset / integrity / anti\_analysis / memory / emergency / layer1\_process\_guard / layer3\_hw\_binding / layer4\_hook\_defense / layer5\_sandbox / layer6\_closure（+ security 根共享） |

**规范符合性对照**：公共接口 `include/verthys.h` 与私有实现物理隔离（外部仅可引用公共头）；目录全小写蛇形、无 utils/common/misc/helper 空泛名；单组件目录 3-10 文件、层级 ≤4；tests 镜像 src 子域结构（10 子域 + fuzz/）；examples（ffi/）、tools（rhash\_gen）、schema（.fbs + generated/）独立分区。

**实施与验证**：CMake 源清单与 include 路径全部改新路径；tests/CMakeLists.txt 同步镜像。验证 = 删除旧配置全新构建全量编译通过 + **250/250 测试通过**（2026-09-15）。行为零变更（纯结构迁移 + 路径修正，无逻辑改动）。

***

## 2. 目标文档索引与关键决策修正

### 2.1 目标文档（已规范入库 docs/）

| 文档                                                            | 定位                                          | 在本手册中的引用方式                                         |
| ------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- |
| [TARGET\_ARCHITECTURE\_V5.md](./TARGET_ARCHITECTURE_V5.md)    | 目标态架构（CNG 全量托管 / V3 容器 / LSM / WP-1..14 矩阵） | 每个 WP 引用其对应章节                                      |
| [PERFORMANCE\_ARCHITECTURE.md](./PERFORMANCE_ARCHITECTURE.md) | 性能目标/资源上限/背压/缓存                             | WP-4/5/7 的指标来源（内存 512MB 硬上限、线程 ≤16、后台 CPU ≤25% 单核） |
| [UNLOCK\_OPTIMIZATION.md](./UNLOCK_OPTIMIZATION.md)           | 解锁流水线 S0-S6 / 温缓存 V3 / 渐进式解锁                | WP-5 完成后的解锁改造规范                                    |

### 2.2 对目标文档的关键决策修正（执行策略层，不改变目标）

以下修正**不降低任何安全/性能目标**，仅修正"从当前状态走到目标态"的工程路径：

| #   | 修正                                                                                                                                                                            | 理由                                                                          |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| E-1 | **并行实现 + 分阶段替换**，而非"直接替换旧实现"：V3 以新的 fmt 枚举（`VERTHYS_FMT_V3`）与全新代码路径落地，与 V2 路径并存编译；V3 测试矩阵全绿后执行 §1.4 删除清单                                                                        | "无向后兼容"指 **V3 不读 V2 文件**（目标语义保留）；但 AI 迭代开发期间保留 V2 代码编译可保证每步构建绿、可回滚，避免数周不可用期 |
| E-2 | **FlatBuffers 选型决策点**：首选 [flatcc](https://github.com/dvidelabs/flatcc)（纯 C 运行时，符合 C11 项目）；备选 FlatBuffers 官方 C++ 桥接（引入 C++/RTL 依赖，需评估）。**禁止手写等价序列化替代**（v5.0 明确 schema 驱动）      | 项目是纯 C11；flatcc vendored 单目录、无运行时依赖                                         |
| E-3 | **BLAKE2b 零新依赖**：libsodium 自带 `crypto_generichash`（即 BLAKE2b-256），Extent 哈希直接使用                                                                                               | v5.0 要求 BLAKE2b；无需引入新库                                                      |
| E-4 | **Bloom 哈希 vendored 单头文件 xxhash.h**（`XXH_INLINE_ALL`），供应链哈希固化                                                                                                                 | v5.0 指定 xxHash64；单头文件满足 vendored + 固化要求                                     |
| E-5 | **密钥明文暂态窗口的诚实界定**：BCrypt 无法"内核句柄→内核句柄"导入——wrapped key 解包的**输出**（key\_a/b/c 明文）必然短暂经过用户态栈帧（UNLOCK\_OPTIMIZATION.md §6.1 伪代码本身如此）。规范：解包缓冲 = 栈上 `SecureZeroMemory` 即清、禁止堆分配、禁止传递 | v5.0 §5.4 的"明文存在时间"表已隐含此事实，明确化防止 AI 做出"全程内核"的错误实现承诺                         |
| E-6 | **WP-13（K-1）排第一**：任何 V3 开发开始前必须恢复"全量连跑可信"，否则后续所有 WP 的验收信号失真                                                                                                                   | 当前全量段错误使 CI 全量门不可用                                                          |
| E-7 | **nonce 计数器持久化于 V3 分区表**（每分区 `nonce_counter` 存于分区元数据，解锁时恢复继续递增）——V3 CNG 路径全面采用 12B 单调计数器，杜绝随机 nonce                                                                           | v5.0 §4.2 + 解锁优化 §6.3；计数器持久化是 GCM nonce 重用防护的唯一正确做法                         |
| E-8 | **worker 侧配套**：`verthys-worker` 需同步适配（GMK 语义变化、新错误码、V3-only op 集），随 WP-5 一起收口                                                                                                   | 关联模块最高标准同步条款                                                                |

**E-8 执行留痕（2026-09-15，worker 适配收口——V2 退役后）**：

* `runtime/protocol.rs`：`Response::err` 反 Oracle 错误统一化——功能码透传集从 5 码扩展到 **14 码**（新增 SNAPSHOT 0x0B / PEPPER\_SOURCE 0x0C / EXPORT\_TOO\_MANY 0x0D / CNG\_UNAVAILABLE 0x0E / RESOURCE\_LIMIT 0x0F / QUORUM\_FAILED 0x10 / PARTIAL\_UNLOCK 0x11 / TIMEOUT 0x12 / UNSUPPORTED 0x13，各注 WP 来源）；AUTH/FORMAT/IO/CORRUPT/INTERNAL 及未知码仍统一 AUTH（防"密码错误 vs 文件篡改"区分泄露）。
* `runtime/dispatch.rs`：unlock arm 初始调用与状态恢复重试两处 `PARTIAL_UNLOCK` 按成功分支处理（与 verthys\_api.c Unlock 成功分支语义一致，正常执行 GMK 探测）；migrate / rebuild\_merkle / rebuild\_merkle\_chunked 三 arm 桩化为 `ERR_00000013`（UNSUPPORTED，旧前端收到语义化错误而非 unknown op）。
* `runtime/worker.rs`：三个退役调用方法桩化 UNSUPPORTED；`runtime/ffi_types.rs`：删除死 FFI 类型（VerthysRebuildMerkleFn / VerthysRebuildMerkleChunkedFn / VerthysMigrateFn / VerthysMigrationCallbackC / VerthysMigrationProgressC），对齐 `ci/export_baseline.txt` 29 符号白名单。
* 验证：`cargo check` 零错误（2026-09-15）。**worker 正式构建与 DLL/EXE 双暂存（verthys.dll → src-tauri/、verthys-worker.exe → src-tauri/binaries/）待重装系统后执行。**

***

## 3. 全局工程约定与红线

**每个 AI 会话必须遵守**（承自项目刚性条款，全部有历史教训支撑）：

1. **完整落地禁降级**：按工作包定义完整实现，严禁删减条款、变通替代、部分执行。**标准不让步、流程不跳步。**
2. **偏差必须磁盘证据 + 留痕**：无法按方案执行时（工具链缺失/方案内部冲突），实测取证、在代码头注与执行文档记录偏差编号与证据，绝不静默跳过。（先例：D-1 guard:longjmp、D-9 tail log。）
3. **现状核实优先于任何文档**：动手前 grep 复核目标文件/函数仍存在且语义一致；头注宣称 ≠ 现状。
4. **每步构建绿**：`scripts/build_core.dev.ps1 -NoPause` 全绿才算步进完成；测试挂起会锁死 exe（LNK1168）——长挂起立即查进程 `tasklist | findstr verthys`。
5. **禁用过时/不可用 API**；新依赖必须 vendored + SHA-256 固化记录。
6. **安全红线**：密钥明文只在导入函数栈帧瞬态存在；一切失败路径 `verthys_secure_zero`；AEAD 域分离标签必须唯一；nonce 单调计数器禁止回退； emergency KILL 仅限高置信度信号。
7. **文档同步**：每个 WP 完成，更新 `PROJECT_DOCUMENTATION.md` 对应章节 + 本手册 WP 状态列。
8. **禁止事项**：不得修改 `ci/export_baseline.txt` 除非 WP 明确要求导出面变更并同步 `.def`；不得绕过 `.def` 白名单（禁止重新启用 `VERTHYS_EXPORTS` 全量导出）；不得在 DllMain 内做加载器操作；不得引入 `IsBadReadPtr`/多轮 RAM 覆写等已废弃模式。

**全局命令**（见 §7）与**构建状态自检**：构建前 `tasklist | findstr verthys_tests` 确认无残留进程；构建后核对 exe 时间戳（防陈旧产物）。

***

## 4. 升级总路线图与依赖图

### 4.1 推荐执行顺序（含依赖与理由）

```
Phase 0（立即，~1 周）
  WP-13  K-1 测试顺序依赖修复 ──── 恢复全量 CI 门（一切验收的前提）
  WP-0   基线固化：分支策略 + 依赖 vendoring（flatcc/xxhash）+ schema 工具链试运行

Phase 1（内核密钥安全，~2 周）—— 不依赖容器格式，可先行
  WP-1   CNG 托管全量接线（verthys_crypto_cng + keymanager_cng）
  WP-7   安全分配器（VirtualAlloc + guard page + 预算记账）

Phase 2（V3 容器核心，~8 周）—— Phase 1 完成后
  WP-2   V3 超级块多副本 + 分区管理（FlatBuffers）
  WP-3   Extent 内容寻址
  WP-4   LSM 索引
  WP-5   WAL + transaction_v3 + 解锁流水线改造（UNLOCK_OPTIMIZATION S0-S6）
         → V3 全链路测试矩阵绿 → 执行 §1.4 删除清单（V1/V2 退役）

Phase 3（纵深防御强化，~2 周）
  WP-6   自动密钥轮换（复用 rewrap 模式）
  WP-8   运行时哈希校验（.vsec 扩展）
  WP-9   直接系统调用

Phase 4（测试与收尾，~3 周）
  WP-10  模糊测试全覆盖
  WP-14  P2 项清理（V3 下仍有意义的部分）
  WP-11  防御闭环 7/7 BLOCKED 验证
  WP-12  属性测试
```

### 4.2 依赖图

```
WP-13 ──→ 全部（验收信号可信的前提）
WP-0 ───→ WP-2（flatcc/xxhash 就绪）
WP-1 ──→ WP-2(密钥句柄接口) ──→ WP-3 ──→ WP-5 ←── WP-4
WP-1 ──→ WP-6（rekey 复用 CNG 生命周期）
WP-2..5 ──→ WP-5(解锁流水线) ──→ 删除清单 ──→ WP-11(7/7 闭环)
WP-7 ──→ 独立；WP-8/WP-9 ──→ 独立（可在 Phase 1/2 间穿插）
```

### 4.3 与 v5.0 §17 的差异说明

v5.0 预估 20 周（人工节奏）。AI 驱动开发按工作包粒度推进，实际周期取决于验收节奏；**工作包切分与依赖关系完全沿用 v5.0 §17.1**，本手册仅追加 WP-0 并将 WP-13 提至首位。

***

## 5. 工作包详解

> 每个 WP 按"AI 开发卡"格式：**目标 / 前置 / 触达文件（★新建 ✎修改）/ 复用资产 / 设计约束 / 步骤 / 验收 / 提示词**。提示词可直接作为 AI 会话开场。

***

### WP-13：K-1 全量测试顺序依赖段错误修复（P0，最优先）✅ 已完成（2026-09-01）

**结果**：全量 3 连绿达成（132/132 × 3，Debug build\_dev）；CI `core.yml` 全量测试门经复核本就完好（无过滤器降级），无需恢复。

**根因（ASAN 实锤，两处独立缺陷）**：

1. **K-1 主根因**：`core/src/index/verthys_btree.c` `leaf_split` 对父节点双重插入 —— 先手工插入 `(split_key, new_leaf)`，又调用 `internal_insert_propagate` 二次插入同一项 → `key_count` 越界 → `keys[64]`/`children[65]` 越界写 → `keys[64]` 恰好覆写 union 起始处 `children[0]`（lid 整数误入子指针槽，ASAN 崩溃地址 0x421 = lid 1057 吻合）→ `children[65]` 覆写 parent/next 指针并溢出结构体尾部 → 堆损坏 → 布局敏感跨模块野指针崩溃（即 K-1）。修复：删除手工插入，完全委托 `internal_insert_propagate`。
2. **连带缺陷**：`core/src/index/verthys_datablock.c` `pool_extend` 池类型判断误将 `VerthysV2PoolDesc*` 指针与枚举整数比较（恒为假）→ SMALL/MEDIUM 池全部落入 LARGE 分支（上界=尾部区域）→ SMALL 池扩展越界零写入毁坏 MEDIUM 池数据（`repair_pool_extend_boundary` 失败根因）。修复：改为与 `&mgr->pools[...]` 地址比较。

**沉淀资产（永久保留）**：RUN\_TEST 宏测试间状态快照断言（线程/句柄/GDI/emergency 信号差异打印 `[LEAK?]`）+ 组间 `[ CHECKPOINT ]` 基线增量 + 每测试后强制 `emergency_clear_signals()` + ASAN 诊断脚本 `scripts/k1_asan_run.ps1`。

**目标**：全量测试连跑稳定绿（连续 3 次），CI 全量门重新可用。

**前置**：无。

**触达文件**：★`tests/verthys_test.h`（RUN\_TEST 宏加测试间快照断言）、★`tests/test_runner.c`（组间 reset + 快照报告）、✎`tests/test_perf_prefetch.c`（嫌疑测试）、✎`tests/test_emergency.c`（确认清理完整）。

**已掌握证据（继承自 2026-08-30 排查）**：

* 崩溃点：`perf_diagnostics_metrics_complete` 测试边界（前测 OK 后、本测 RUN 前）；

* 全部分组/组合运行绿（58 项跨组、ASAN perf 组）；ASAN 全量无报告；

* 布局敏感：链接 `test_final_repair.obj` 即复现，移除即消失；

* LNK1168 陷阱：挂起测试进程锁死 exe → 后续构建静默失败 → 陈旧 exe 产生假信号（排查时必查 `tasklist | findstr verthys_tests`）。

**步骤**：

1. 给 RUN\_TEST 宏加**测试间状态快照**：测试前后对比线程数（`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` 过滤本 PID）、GDI/内核句柄数（`GetProcessHandleCount`）、emergency 信号值；差异非零即打印并（可选）失败——先定位泄漏源；
2. 每测试后强制 `emergency_clear_signals()`（宏内）；
3. 用过滤器二分污染组：`verthys_tests.exe init_ aead_ master_key_ ...` 逐组叠加（已有 OR 语法），找到与 perf\_dia 同跑必崩的最小组合；
4. 命中组合后用 ASAN 全量复跑该组合 + `AppVerifier`（PageHeap）二选一深挖；
5. 修复后连续 3 次全量绿 + CI 恢复全量门。

**验收**：全量 3 连绿；快照断言零差异；CI core.yml 恢复全量测试步骤。

**提示词**：

> 读取 docs/V3\_UPGRADE\_PLAYBOOK.md §5 WP-13 与 §3 约定，执行 K-1 修复。当前事实：全量测试在 perf\_diagnostics\_metrics\_complete 边界段错误，分组全绿，ASAN 无报告，布局敏感。按步骤 1-5 执行，先实现测试间状态快照断言定位泄漏/残留源。构建用 §7 命令，警惕 LNK1168 陈旧 exe 陷阱。

***

### WP-0：基线固化与依赖 vendoring ✅ 已完成（2026-09-01）

**目标**：V3 开发的基础设施就绪。

**触达文件**：★`third_party/flatcc/`、★`third_party/xxhash/`、★`schema/*.fbs`、✎`CMakeLists.txt`（flatcc 构建集成 + schema codegen 自定义命令）、★`ci/vendor_hashes.txt`。

**结果**：

1. vendored flatcc（commit `a2515daa948c1ae42ba95b3a904363169dff147c`，0.6.4-pre）：`third_party/Flatcc.cmake` 定义 `flatccrt`（运行时静态库，链入 verthys\_core\_obj 与 verthys.dll）+ `flatcc_cli`（flatc.exe，构建宿主工具）；
2. vendored xxhash.h（v0.8.3，tag `e626a72bc2321cd320e953a0ccf1584cad60f363`，`XXH_INLINE_ALL` 消费方定义）；
3. `core/schema/demo.fbs` → CMake `flatcc_generate` 自定义命令（flatc `-a`，schema 变更自动重生成）→ `core/schema/generated/{demo_reader,demo_builder,demo_verifier,flatbuffers_common_*}.h`；
4. `ci/vendor_hashes.txt`：flatcc（commit + 全量源文件 SHA-256 清单）+ xxhash 逐文件哈希（供应链完整性校验）；
5. 分支策略落地：`v3-upgrade` 长分支（自 master 切出）+ 每 WP 一提交；
6. 验收测试 `test_flatcc_demo.c`：`flatcc_demo_roundtrip`（builder 编码 → verifier 结构校验 → reader 逐字段解码闭环）+ `flatcc_demo_tamper_rejected`（根偏移越界/截断/垃圾缓冲均被 verifier 拒绝），测试 exe 链接 flatccrt 通过。

**验收达成**：全量 134/134 × 3 连绿（Debug build\_dev）；vendor 哈希记录完整。

***

### WP-1：CNG 内核托管全量接线（P0）✅ 已完成（2026-09-01）

**结果**：`verthys_crypto_cng.c/.h`（AEAD 封装层 + 12B 单调 nonce 计数器 + restore 防回退）与 `keymanager_cng.c/.h`（批量导入 + 生命周期状态机 + 进程级句柄总量）落地；`VerthysContext` 挂载 `VerthysCngKeyManager cng_keys`，`ctx_zero_sensitive` 收口销毁；`VERTHYS_ERR_CNG_UNAVAILABLE` 错误码入 ABI（枚举尾部顺延）。全量测试 **149/149 绿**（含 14 项 CNG 专项）。

**验收核对**：

1. `test_cng_kernel` 全绿（cng\_aead\_roundtrip / init\_contract / empty\_plaintext / nonce\_unique\_monotonic / nonce\_counter\_restore / tamper\_rejected / wrong\_key\_rejected / destroy\_invalidates / null\_params\_rejected / km\_batch\_import\_roundtrip / km\_import\_wrong\_mek\_rolls\_back / km\_wrapped\_role\_binding / km\_reimport\_replaces\_handles / km\_null\_params\_rejected / km\_global\_handle\_tracking）✅
2. `grep "key_a\[" src/` 仅剩 V2 并存路径（transaction/superblock/btree/datablock/lifecycle —— 调用点切换归 WP-5）✅
3. defense\_closure MEM\_DUMP 判据可置 BLOCKED：`check_mem_dump` 现查询 `key_separation_any_installed()`（V2）∨ `verthys_cng_km_global_handle_total() > 0`（V3，进程级原子总量，与 ctx 解耦）✅

**K-2 缺陷（本 WP 发现并修复，永久沉淀）**：

* **根因**：`verthys_cng_aead_import_key` 对未初始化栈上 `VerthysCngAead` 的垃圾 `key` 字段无条件 `BCryptDestroyKey` → 野句柄 0xC0000005。垃圾字段与合法句柄在库内不可区分。

* **修复（双管）**：① 新增 `verthys_cng_aead_init`（仅内存消毒，绝不感知内核句柄——契约：已导入上下文须先 destroy 再 init）；② `import_key` 仅在 `imported` 标志置位时销毁旧句柄。

* **测试红线**：`wrap_with_mek` 等辅助必须以副本传 MEK（import 红线语义清零入参缓冲，原件被毁导致 wrapped\_b/c 用全零密钥加密——曾经 3 例 AUTH 假失败根因）。

**目标**：A/B/C/MEK 全部 CNG 内核托管，用户态仅持句柄；`VerthysContext` 密钥数组删除。

**前置**：WP-13（验收信号可信）。

**触达文件**：★`crypto/verthys_crypto_cng.c/.h`（CNG AEAD 封装）、★`crypto/keymanager_cng.c/.h`（生命周期）、✎`security/memory/key_separation.c`（重构/退役 acquire）、✎`container/verthys_internal.h`（ctx 字段替换为句柄）、✎`crypto/keymanager.c`、✎`api/verthys_v2_lifecycle.c`（解锁 S3 阶段）、✎`transaction/verthys_transaction.h`（txn 密钥字段→句柄）、★`tests/test_cng_kernel.c`。

**复用资产**：`key_separation.c` 的 BCrypt GCM 全套（open\_aes\_gcm\_provider / init\_gcm\_auth\_info / aead\_encrypt / activate\_commit / purge\_all）——**直接改造迁移**而非重写。

**设计约束**（红线级）：

* `verthys_cng_aead_import_key` 是唯一允许明文瞬态的函数；解包输出缓冲**栈上分配 + 立即清零**（E-5）；

* nonce：12B 单调计数器由封装层内部管理（`verthys_cng_aead_encrypt` 自动生成并回传），计数器随容器持久化（WP-2 分区表；过渡期 V2 并存阶段计数器存 ctx 内存即可）；

* 域分离标签升级 v3（`"verthys/…-v3"`），与 V2 标签隔离；

* 句柄总数 ≤16（性能架构 §4.4），record\_key 用完即销毁；

* `VerthysContext` 删除 `key_a/b/c[32]` 后，**全仓 grep 消灭一切明文密钥读取点**（编译器会强制暴露——这是替换的价值）。

**步骤**：

1. `verthys_crypto_cng.c`：迁移 key\_separation 的 GCM 内核为 `VerthysCngAead` 上下文 + 内部 nonce 计数器 + import/encrypt/decrypt/destroy（接口签名照 TARGET\_ARCHITECTURE\_V5.md §4.2）；
2. `keymanager_cng.c`：批量导入（UNLOCK\_OPTIMIZATION §6.1 流程）+ 句柄生命周期状态机（v5.0 §5.3）；
3. `VerthysContext` 句柄化 → 解锁路径改为"派生→导入→清零"；
4. AEAD 调用点改造：当前用 `verthys_aead_encrypt(ctx->key_a,…)` 的位置改为 `verthys_cng_aead_encrypt(&ctx->cng_a,…)`——**此改造与 WP-2/3 的读写路径耦合**，因此 WP-1 的落地范围 = 封装层 + 生命周期 + 单元测试 + ctx 结构改造；调用点全量切换在 WP-5 完成（并存期 V2 路径暂用旧 key 数组，删除清单时移除）；
5. 测试：`test_cng_kernel.c`（导入/加解密/nonce 单调/错误路径/句柄销毁后不可用）。

**验收**：`test_cng_kernel` 全绿；`grep -rn "key_a\[" src/` 仅剩 V2 并存路径；defense\_closure 的 MEM\_DUMP 判据可置 BLOCKED（`any_installed` 为真时）。

**提示词**：

> 读取 docs/V3\_UPGRADE\_PLAYBOOK.md §5 WP-1、docs/TARGET\_ARCHITECTURE\_V5.md §4.2/§5，执行 CNG 托管封装层。母本：core/src/security/memory/key\_separation.c（已有全套 BCrypt GCM）。产出 verthys\_crypto\_cng.c/.h + keymanager\_cng.c/.h + 测试。红线见 §3.6（明文瞬态窗口仅限 import 函数栈帧）。注意 WP-1 只做封装层+ctx 改造，调用点切换留给 WP-5。

***

### WP-7：安全分配器（P1，可穿插）✅ 已完成（2026-09-01）

**结果**：`security/memory/secure_allocator.c/.h` 落地——每分配独立 `VirtualAlloc` 区段（前/后边界页 + 数据页 RW + `VirtualLock` 锁页 + 释放前 `SecureZeroMemory` 清零）、元数据独立普通堆注册表（SRWLOCK）、进程级全局预算记账（Interlocked 64 位原子：80% 回收回调阈值沿 + 95% `VERTHYS_ERR_RESOURCE_LIMIT` 拒绝）；`VerthysContext` 挂载 `SecureAllocator *secure_alloc`（Init 创建 / Deinit 销毁，v5.0 §5.2）。全量测试 **155/155 绿**（含 6 项 WP-7 专项）。

**验收核对**：

1. `test_secure_allocator` 全绿（sec\_alloc\_basic\_roundtrip / sec\_alloc\_guard\_pages / sec\_alloc\_locked / sec\_alloc\_budget\_reject\_and\_reclaim / sec\_alloc\_error\_paths / sec\_alloc\_destroy\_releases\_all）✅
2. 边界页语义：`PAGE_GUARD` 修饰符与 `PAGE_NOACCESS` 互斥（`VirtualProtect` gle=87，实测探针确认），且 `READONLY|GUARD` 为一次性触发后转可读——采用纯 `PAGE_NOACCESS` 实现永久访问违例，安全性严格强于一次性 GUARD 页，测试以 SEH 断言前后边界每次访问均 `EXCEPTION_ACCESS_VIOLATION` ✅
3. 预算语义：跨实例共享记账、95% 拒绝后用量精确回落、80% 回收回调"跨阈值沿触发一次 + free 回落重新武装"（修复：原实现仅在 alloc 路径武装，free 回落后再次分配以单次原子累加跨过阈值线，回调永不重新触发）✅

**目标**：密钥相关结构走专用隔离堆；全局内存预算记账。

**触达文件**：★`security/memory/secure_allocator.c/.h`、✎`verthys_internal.h`（ctx 挂 `SecureAllocator*`）。

**设计约束**：VirtualAlloc 区段 + `PAGE_GUARD` 边界页 + `VirtualLock` 锁页 + 释放前清零 + 元数据独立存储；记账对接性能架构 §4.1（512MB 硬上限 → 80% 触发回收 → 95% 返回 `VERTHYS_ERR_RESOURCE_LIMIT`）。

**验收**：`test_secure_allocator`（分配/释放/边界页触发/锁页/预算上限拒绝）。

***

### WP-2：V3 容器格式基础（P0）✅ 已完成（2026-09-02）

**结果**：`schema/superblock_v3.fbs` + `schema/partition.fbs`（flatcc codegen -a 全量 reader/builder/verifier）→ `container/verthys_container_v3.h`（布局常量 + 内存态 `VerthysSuperBlockV3` + `VsbTxnV3` 事务）+ `container/verthys_superblock_v3.c`（flatcc 序列化 + HMAC 自排除写回 + 常量时间校验 + 三副本 0x0000/0x4000/0x8000×16KB 帧 I/O + fsync + 法定人数提交/读取 + 写故障注入 `fail_mask`）+ `container/verthys_partition.c/.h`（每分区独立 CNG 内核密钥：随机 → wrapping 包装持久化 → import 清零明文；AAD = `partition_id ‖ txid`（nonce 由 GCM 协议原生认证，见 .h 实现注记）；nonce 计数器 E-7 持久化 + restore 防回退；2x 扩展策略；分区表 flatcc 序列化 + AEAD 帧持久化 + 篡改拒绝）。全量测试 **190/190 绿（3 连跑）**（含 WP-2 专项 35 项：超级块 20 + 分区 15）。

**验收核对**：

1. `test_v3_container` 全绿（20 项）：init 默认值/NULL 拒绝、序列化-解析 roundtrip 与幂等、HMAC 篡改/错误密钥拒绝、垃圾缓冲拒绝、NULL/溢出拒绝、副本 I/O roundtrip/坏帧拒绝、法定人数提交-读取 roundtrip（valid\_mask=0x7）、txid 推进、0/1/2/3 副本损坏矩阵（0→CORRUPT、1→多数派恢复、2/3→QUORUM\_FAILED）、有效但分裂（无 ≥2 一致→QUORUM\_FAILED）、txid 多数派优先于孤立最高、写故障注入（单副本失败法定人数维持/双失败提交拒绝/失败后分裂读侧拒绝）、`VsbTxnV3` commit/rollback 终态互斥 ✅
2. `test_v3_partition` 全绿（15 项）：创建默认值/非法参数/未导入 LOCKED、AEAD roundtrip（含空明文）、txid AAD 绑定拒绝、密文/标签篡改拒绝、跨分区密钥隔离（key\_id 不同 + 跨解密 AUTH 失败）、NULL 参数矩阵、2x+min\_bytes 扩展策略、重载 nonce 防回退（计数器恢复 + 历史 nonce 不复用 + 严格递增）、重载非法矩阵（错误 wrapping→AUTH/未导入→LOCKED/长度/used>size/类型越界）、分区表 add（EXISTS 优先于容量）/find/上限 RESOURCE\_LIMIT、表 save/load roundtrip（字段 + 计数器 + 重载解密闭环）、错误表密钥/密文篡改→AUTH、magic 篡改→FORMAT、空区→FORMAT、save 非法参数/LOCKED ✅
3. 实现缺陷修复（落地过程发现）：AEAD 长度参数语义（`*len` 为 in/out 容量-实际值，4 处初始化缺陷）；flatcc `vec_push` 返回 `ref_t*`（非 NULL=成功）；`table_add` id 冲突优先于容量检查；flatcc 头须先于 Windows SDK 头处理（`pstdint.h` 的 `NTDDI_VERSION` 条件路径与 MSVC `<stdint.h>` fast 类型冲突 C2371）；`verthys_secure_zero` 声明位于 `verthys_internal.h`（无 `secure_mem.h` 头文件）✅

**目标**：FlatBuffers schema 驱动的 V3 超级块（3 副本法定人数）+ 分区管理。

**前置**：WP-0（flatcc）、WP-1（句柄接口）。

**触达文件**：★`container/verthys_container_v3.h`、★`container/verthys_superblock_v3.c`、★`container/verthys_partition.c`、★`schema/superblock_v3.fbs`、`schema/partition.fbs`、✎`CMakeLists.txt`、★`tests/test_v3_container.c`、★`tests/test_v3_partition.c`。

**复用资产**：`verthys_io.c`（全部偏移 I/O）；`vsb_txn` 备份/回滚模式（扩展为 `VsbTxnV3`，v5.0 §10.2）；超级块反序列化的边界纪律（§1.1 样板）；`integrity_key` HMAC 体系。

**设计约束**：

* 布局照 TARGET\_ARCHITECTURE\_V5.md §6.2（0x0000/0x4000/0x8000 三副本 × 16KB + WAL 1MB + 分区表 1MB 起）；

* 法定人数：写 3 副本 fsync，≥2 成功=提交；读 3 副本验 HMAC，取 txid 最高且 ≥2 一致；仅 1 有效 → `VERTHYS_ERR_QUORUM_FAILED` 触发恢复；

* 分区独立 AEAD：AAD = `partition_id ‖ nonce ‖ txid`；每分区独立密钥句柄 + nonce 计数器（E-7 持久化于分区元数据）；

* schema 字段照 v5.0 §6.3 的 `SuperBlockV3` 表定义；

* **所有解析走 safe\_read 纪律 + flatcc 校验 API**（样板：v2 超级块反序列化）。

**步骤**：schema → codegen → 序列化/反序列化 + HMAC → 三副本读（并行读为 WP-5 流水线优化，本 WP 先串行）→ 法定人数写/读 → 分区创建/扩展/认证 → 测试（副本损坏注入矩阵：0/1/2/3 副本损坏）。

**验收**：`test_v3_container`/`test_v3_partition` 全绿（含故障注入：单副本字节翻转自动切换、双副本损坏降级告警）。

***

### WP-3：Extent 内容寻址（P0）✅ 已完成（2026-09-02）

**结果**：`schema/extent.fbs`（ExtentEntryV3/ExtentIndexV3，含 nonce 计数器快照字段 E-7）→ `container/verthys_extent.c/.h`（内容寻址：明文 → `verthys_generichash` BLAKE2b-256 → 索引查重 → 命中 `ref_count++` 零重写 / 未命中 CNG 内核态加密追加写 + fsync + 索引更新；读取双重完整性 = AEAD 认证 + `BLAKE2b(明文)==hash` 复验（AUTH/CORRUPT 分级）；数据块 AAD = `partition_id ‖ hash`（36B）——绑定内容承诺使密文块搬运（A→B 槽位）认证失败，且不绑 txid 以保证去重块跨事务可读；`release` 下限 0 不回绕 + `gc_eligible` 标记扫描（物理删除归 WP-5/`verthys_garbage.c`）；索引 flatcc 序列化 → Extent 分区密钥 AEAD 帧持久化（域分离 `verthys/extent-index-v3`）→ 加载侧 verifier + 字段一致性校验（size/plaintext_size/offset≤next_offset）+ nonce 计数器 restore 防回退；条目上限 4096 / `ref_count` 饱和 → `VERTHYS_ERR_RESOURCE_LIMIT`）。全量测试 **206/206 绿（2 连跑）**（含 WP-3 专项 16 项）。

**验收核对**：

1. `test_v3_extent` 全绿（16 项）：哈希确定性/区分性/空数据/参数校验、索引 init/find、put-get roundtrip（条目记账 offset/size/ref_count/txid + 容量校验 + 未命中）、空明文路径、去重零重写（游标/used 不变 + ref=2 + last_ref 记账）、引用计数 + GC 标记（release 递减/下限不回绕/复活脱离标记/未知哈希 NOTFOUND）、资源上限（索引满/ref 饱和）、LOCKED 拒绝（含去重路径先于密钥检查的语义注记）、密文篡改→AUTH + 输出清零、密文块搬运→AUTH（AAD 绑定 hash）、错误分区密钥→AUTH、索引 save/load roundtrip（分区 wrapped 重载 + 条目/游标/nonce 计数器 restore + 重载后解密闭环）、E-7 防回退（分区计数器高于快照→load 拒绝）、索引帧篡改矩阵（密文翻转→AUTH / magic→FORMAT / ct_len 越界→FORMAT）、空索引区→FORMAT、全 API NULL 参数矩阵 ✅
2. C 工程标准同步审查修复（本次会话）：`verthys_cng_aead_decrypt` 签名 const 正确化（解密只读语境，根除 extent 层 C4090）；`VsbTxnV3.replica_status` 类型缺陷（`uint32_t[3]` → `VerthysResult[3]`，C4133 隐式指针不兼容）；`cng_machine_key.c` NCRYPT 句柄（ULONG_PTR）`NULL` 初始化/赋值 → `0`（C4047 ×12）+ `%s` 配 `WCHAR*` → `%ls`（C4477 真实缺陷）；附录 B 禁用函数全仓 grep 零命中；`realloc` 全部为临时指针 + NULL 检查模式 ✅
3. 全量构建 **零 C 警告**（Release，标准 §8.3 清零告警）✅

**前置**：WP-2。

**触达文件**：★`container/verthys_extent.c/.h`、★`tests/test_v3_extent.c`、★`schema/extent.fbs`、✎`CMakeLists.txt`、✎`tests/CMakeLists.txt`、✎`tests/test_runner.c`。

**复用资产**：`crypto_generichash`（libsodium BLAKE2b-256，E-3 零依赖）；CNG AEAD（加密）；WP-2 分区管理（Extent 分区）。

**设计约束**：明文 → BLAKE2b → 查重（Extent Index）→ 新则 CNG 加密追加 → 更新索引；读取解密后验 `BLAKE2b(明文) == hash`；`ref_count` 引用计数，0 = GC 可回收；**去重防侧信道注意**：相同明文同哈希——对密码管理器可接受（v5.0 已定），文档声明即可（声明见 verthys_extent.h 头注与 extent.fbs 头注）。

**验收**：`test_v3_extent`（寻址/去重/引用计数/GC 标记/损坏检测）。

***

### WP-4：LSM 索引（P0）✅ 已完成（2026-09-02）

**结果**：`schema/sstable.fbs`（SSTableFooterV3/LSMTableMetaV3/LSMManifestV3，含分区 nonce 计数器快照字段，采用**"保存后值"约定**：序列化取分区计数器 + 1 = 保存帧自身消耗值，重载 restore 后绝不复用保存帧 nonce）→ `index/verthys_lsm.c/.h`（生命周期/WAL/Manifest/数据路径；LSM 区域布局 `[Manifest 帧区 1MB][WAL 区 68MB][SSTable 数据区 append-only]`；WAL 先行——put/delete 先追加 WAL 帧再插入 MemTable，flush 持久化 SSTable + Manifest 提交后 WAL 复位（游标归零 + 首帧头清零失效化，杜绝旧帧重放）；崩溃恢复 open 时顺序重放 + 撕裂尾部帧静默截断；并发纪律 = put/delete/flush/compact/get 持 SRWLOCK 独占单写者；后台 compaction 线程 BELOW\_NORMAL 优先级 + 原子停机标志 + WaitForSingleObject 汇合）+ `index/verthys_lsm_memtable.c`（跳表 O(log n) 插入、同键覆盖、冻结语义、阈值 10,000 条/64MB flush）+ `index/verthys_lsm_sstable.c`（Data Blocks + Index Block + Bloom xxHash64 双重哈希 FPR 0.1% + Footer flatcc verifier；数据块/Index/Footer 均 AEAD 帧加密，帧助手函数跨 WAL/Manifest/SSTable 复用）+ `index/verthys_lsm_compaction.c`（分级 L0→L1→L2+ 容量 ×10、空闲触发 CPU<30%、单次 ≤64MB、Tombstone 底层丢弃 + 新旧覆盖）+ `tests/test_v3_lsm.c`（14 项）。全量测试 **219/219 绿（2 连跑）**。

**验收核对**：

1. `test_v3_lsm` 全绿（14 项）：open/close roundtrip、put/get roundtrip、同键覆盖、delete 墓碑（内部 put\_internal 保留墓碑标志）、flush 落 SSTable（含条目/墓碑/键域/Bloom 元数据校验）、reopen 持久化（Manifest 重载 + MemTable 重建）、WAL 崩溃恢复（撕裂尾部静默截断 + 重放一致）、compaction L0 合并、compaction 新旧覆盖（shadowing）、compaction 墓碑清除、Manifest 帧篡改拒绝（AUTH/FORMAT）、get 未命中与参数校验、全 API NULL 参数矩阵、**大规模插入 + 全量查找（50,000 条随机键插入 + 全量 find 逐一命中，复用 `repair_btree_large_insert` 模式）** ✅
2. nonce 快照"保存后值"约定全仓统一（本次会话同步修正 WP-3 `verthys_extent.c` 索引快照"保存前值"隐患——原实现重载 restore 回退到帧自身 nonce，下次加密重用该 nonce，违反 AEAD 红线 E-7；修正后快照 = 保存帧计数器 + 1，`test_v3_extent` roundtrip 断言同步更新）✅
3. LSM 全部目标文件（verthys\_lsm\*/test\_v3\_lsm）强制重编验证 **零 C 警告**（Release，标准 §8.3 清零告警）✅
4. 资源泄漏检查点通过：v3\_lsm 段 threads/handles/emergency\_signals 与基线一致（后台线程 +2 为 compaction 线程预期增量，close 汇合后回收）✅

**前置**：WP-2。

**触达文件**：★`index/verthys_lsm.c/.h`、★`index/verthys_lsm_memtable.c`（跳表）、★`index/verthys_lsm_sstable.c`、★`index/verthys_lsm_compaction.c`、★`schema/sstable.fbs`、★`tests/test_lsm_index.c`。

**设计约束**：

* MemTable 跳表：O(log n) 插入；阈值 10,000 条 / 64MB flush（性能架构 §10）；

* SSTable：Data Blocks + Index Block + Bloom（xxHash64 双重哈希，FPR 0.1%）+ Footer（FB schema）；

* Compaction：后台线程（BELOW\_NORMAL）、空闲触发（CPU<30%）、单次 ≤64MB、分级 L0→L1→L2+（容量 ×10）；

* 删除 = Tombstone；**并发纪律**：MemTable 单写者（FFI 单线程）+ 读者快照；compaction 后台与提交的互斥用现有 SRWLOCK 模式。

**验收**：`test_lsm_index`（插入/查找/删除/flush/compaction/崩溃恢复后重放一致；**≥50,000 条插入 + 全量 find**——复用 `repair_btree_large_insert` 模式）。

***

### WP-5：WAL + transaction\_v3 + 解锁流水线 + V2 退役（P0，最大工作包）✅ 已完成（2026-09-15，含 §1.4 删除清单执行留痕）

**前置**：WP-3、WP-4。

**触达文件**：★`transaction/verthys_wal.c/.h`、★`transaction/verthys_transaction_v3.c`、★`api/verthys_v3_lifecycle.c`（校准/并行流水线/进度回调从 v2\_lifecycle 迁移）、★`api/verthys_unlock_pipeline.c`（S0-S6 调度器，UNLOCK\_OPTIMIZATION §8）、✎`api/verthys_api.c`、✎`container/verthys_superblock_v3.c`（WAL 状态字段）、★`index/verthys_warmcache.c` 重写（V3 缓存格式，UNLOCK\_OPTIMIZATION §7）、✎`verthys.def`（新增导出）、✎`verthys-worker`（E-8）。

**复用资产**：v2 七步提交的事务语义（映射到 v5.0 §10.1 六 Phase）；进度环形缓冲（原样）；`verthys_argon2_rewrap`（rekey 模式）；摘要索引序列化样板。

**设计约束**：

* WAL 环形 480KB×2（自 [64KB,1MB) 布局边界推导）；记录类型 BEGIN/EXTENT/INDEX/PREPARE/COMMIT；恢复按 v5.0 §10.1 回放规则；

* **解锁流水线 S0-S6 严格按 UNLOCK\_OPTIMIZATION.md 的依赖矩阵与超时预算**（S1 并行读 3 副本、S2 与 S1 并行、S3 等 S2、温缓存 HMAC+txid 双校验、总超时 10s）；

* 渐进式解锁（`VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST` + `VERTHYS_ERR_PARTIAL_UNLOCK`）在流水线之上实现；

* **V2 退役**：全部 V3 测试绿后执行 §1.4 删除清单；`VERTHYS_ERR_V3_REQUIRED` 语义由"删除"自然实现。

**验收**：V3 全链路测试（创建→写→读→删→改密→导出→重开）+ 解锁流水线单测 + 温缓存测试 + 崩溃恢复注入测试（WAL 半写矩阵）；之后执行删除清单并保持全绿。

***

### WP-6：自动密钥轮换（P1）✅ 已完成（2026-09-15）

**结果**：`verthys_rekey_auto.c/.h` 落地——TLV 轮换状态（超级块 extensions tag 0x02，17B：`last_rekey_ft` / `last_rekey_txid` / `flags`；sb.txid 单调计数代理 ops\_since\_rekey，零额外磁盘写，跨会话精确）；三触发（90 天 TIME / 10,000 写事务 OPS / DEGRADE 强制）+ 24h 防震荡（DEGRADE 旁路）。轮换五步：新 A'/B'/C' 随机生成（wrap 与 import 双副本消耗语义，E-5）→ MEK 内核态 wrap（与解锁 S3 import\_batch 互逆）→ 分区密钥 CNG 内核态重包装（旧 key\_a 解密 → 新 key\_a' 加密，明文仅函数栈帧瞬态；Extent/LSM/审计分区数据零重写）→ 新分区表帧落备用槽位（ping-pong 1MB ↔ 2MB + fsync）→ VsbTxnV3 法定人数原子提交（复用 change\_password 的 vsb\_txn 保护模式；MEK 不动——轮换非改密）。

**关键落地件**：`verthys_cng_km_rotate_abc`（keymanager\_cng）——A/B/C 句柄原位切换，`km->keys[]` 槽位地址不变 → wal/txn 借用的 `VerthysCngAead` 指针续期有效（v5.0"原子指针切换句柄"落地形态）；计数严格配对（销毁旧 3 + 移交新 3，净值不变）。接线：`verthys_v3_open_existing` 全量解锁成功后 `maybe_rotate`（best-effort 吞错，下次解锁重试；MINIMAL\_FIRST 顺延——后台预热线程持 `ctx3->f` 读姿势，轮换写盘将破坏 FILE\* 单写者纪律；DEGRADE 强制标志持久化于 TLV 不丢失）；`verthys_emergency_lock_all` 清钥前 `note_degrade`（TLV bit0 持久化——DEGRADE 后进程内解锁被 S0 熔断拒绝，标志必须落盘才能跨进程重启兑现强制轮换）。

**崩溃一致性（跨结构原子性）**：分区表帧（key\_a' 重包装）与超级块（key\_a' wrapped 形态）分属两个磁盘结构——ping-pong 槽位协议保证任一时刻断电自洽：提交前崩溃 = 盘面 sb 指旧槽位 + 旧帧完整（ping-pong 不覆写），新帧为无害孤儿；提交后崩溃 = 新帧已 fsync + 新 wrapped 密钥闭环；提交中撕裂 = 法定人数读侧取 ≥2 一致者（两个版本各自自洽）。

**验收核对**：

1. `test_auto_rekey` 5 项全绿：`arekey_trigger_matrix`（三触发位掩码 + TLV 缺省/时钟回拨/阈值边界）、`arekey_rotate_full_cycle`（端到端轮换 + 防震荡拒绝 + 句柄续期）、`arekey_degrade_force_persist`（DEGRADE 标志 TLV 持久化 + 下次解锁强制兑现旁路防震荡）、`arekey_crash_orphan_frame`（备用槽位孤儿帧无害——重开仍走旧密钥）、`arekey_crash_after_commit`（提交后崩溃——重开走新密钥闭环）✅
2. 触发条件与防震荡照 v5.0 §4.3：90 天 / 10,000 ops / 24h 最小间隔 / DEGRADE 信号强制触发 ✅
3. 全量回归 **234/234 绿**（229 基线 + 5 新增；v3\_lifecycle 组句柄 +132 为 WP-6 之前既有，与本 WP 无关）✅

**前置**：WP-1（+WP-5 落地后接入 V3 超级块）。

**触达文件**：★`crypto/verthys_rekey_auto.c/.h`、★`tests/test_auto_rekey.c`、✎`crypto/keymanager_cng.c/.h`（rotate\_abc）、✎`api/verthys_v3_lifecycle.c`（maybe\_rotate 接线）、✎`api/verthys_api.c`（note\_degrade 接线）、✎`core/CMakeLists.txt` + `tests/CMakeLists.txt` + `tests/test_runner.c`。

**设计约束**：触发条件与防震荡照 v5.0 §4.3（90 天 / 10,000 ops / 24h 最小间隔 / DEGRADE 信号强制触发）；轮换在 CNG 内核态完成新旧切换（原子指针切换句柄）；**复用 rewrap（change\_password）的 vsb\_txn 保护模式**（原计划复用点 `verthys_argon2_rewrap` 已随 V2 退役删除，语义由 V3 等价实现承接）。

**验收**：`test_auto_rekey`（三种触发 + 防震荡 + 轮换中途崩溃一致性）。

***

### WP-8：运行时哈希校验（P1）✅ 已完成（2026-09-15）

**前置**：无（基座为现有 `.vsec`）。

**触达文件**：★`security/integrity/runtime_hash.c/.h`、✎`build_core.release.ps1`（生成 runtime\_hash\_table.c）、★`tests/test_runtime_hash.c`。

**设计约束**：构建期对 \~30 个关键函数（v5.0 §9.3 X-macro 清单）计算 BLAKE2b（`crypto_generichash`），生成表；运行期解锁后 + 每 30 分钟重算；失配 = KILL。**注意**：与 `.vsec` 全节校验互补（函数粒度 vs 节粒度）；Windows 下函数地址/大小经符号表（map 文件）或 `Dmlib` 获取——实现取 map 文件解析方案（构建脚本已有 PE 解析基础）。

**验收**：正常通过 + 内存补丁注入检测（测试内 `VirtualProtect` 改一字节验证检出）。

**执行留痕（2026-09-15，WP-8 完成）**：

* 清单落定为 **X-macro 32 函数**（runtime\_hash.h 单一事实源）：cng\_aead/km、rekey\_auto、vsb\_txn\_v3、partition、wal、txn\_v3 六 Phase、lsm、unlock\_pipeline、v3\_open\_existing、integrity/emergency、runtime\_hash\_scan 自身——构建期**全命中强制**（rhash\_gen 逐符号核对 map，缺失即构建失败，杜绝静默缩表）。
* 工具链：★`tools/rhash_gen.c` 构建期解析 `/MAP` + `.pdata` + `.reloc`，对 32 函数计算 BLAKE2b-256 后**构建后补丁写入 `.rhat` 节**（复用 `.vsec` 构建后补丁模式）；表项 48B（magic `VRHT`、RVA、大小、哈希），上限 40 项。
* ASLR 防误报：运行期 `runtime_hash_scan` 重算比对时对**重定位槽位做双侧掩码归一**（构建期与运行期同规则），排除基址重定位差导致的假阳性；扫描函数 `__declspec(noinline)` 红线（防自吞）。
* `.rhat` 节纳入 `.vsec` v2 校验**第三槽**（自身完整性受构建期签名保护，防攻击者改表）。
* 验证：`test_runtime_hash` 全绿（含补丁注入检出用例）；Release 链路 `.vsec + .rhat` 实测通过。**产物因本机恶意软件事件已全部清除（2026-09-15），重装系统后需按 §7 命令复验 Release 全链路。**

***

### WP-9：直接系统调用（P1）✅ 已完成（2026-09-15）

**触达文件**：★`security/anti_analysis/syscall_direct.c/.h`、✎`anti_debug_v2.c`、✎`memory_guard.c`。

**设计约束**：从 ntdll `.text` 提取 SSN（排序法或哈希法）→ 构造 stub；仅覆盖检测器实际使用的 NtQueryInformationProcess / NtQuerySystemInformation；提取失败优雅降级回 GetProcAddress 路径（TELEMETRY 记录）。

**验收**：单测（stub 返回值与直接调用一致）+ 防御闭环 P4 路径状态升级。

**执行留痕（2026-09-15，WP-9 完成）**：

* SSN 提取取**排序法**：解析 ntdll 导出表收集全部 Zw\* 存根 (RVA, SSN) 对（未 Hook 特征 `4C 8B D1` + `B8 imm32`），按 RVA 升序后以**仿射一致性**（SSN[j]−SSN[i]==j−i）全表校验；目标存根被 Hook 时由最近有效锚点按位次差插值，**双侧锚点（前后各一）同时存在时两次插值必须一致**，否则判定提取不可信宁降级；未 Hook 目标直接读取值须与插值预测自洽。
* stub 构建守 **W^X 纪律**：单页 `VirtualAlloc(PAGE_READWRITE)` 写入两条 11 字节 stub（mov r10,rcx; mov eax,SSN; syscall; ret）→ `VirtualProtect` 收紧为 `PAGE_EXECUTE_READ`，全程不存在可写可执行页；CFG 下经 `SetProcessValidCallTargets` 显式登记，查询到 Strict CFG 且登记失败则放弃激活并降级（不冒 fast-fail 风险）。
* 覆盖范围卡片限定两入口（NtQueryInformationProcess → anti\_debug\_v2 三重探测 + memory\_guard 父进程识别；NtQuerySystemInformation → memory\_guard 句柄表防转储），扩展仅需在 `.c` 的 SYSCALL\_TARGET 表追加一行（表驱动）。
* 优雅降级链：任一环节失败（导出表异常 / 一致性校验失败 / stub 页构建失败 / CFG 登记失败）→ 回退 `GetProcAddress` 路径并 TELEMETRY 留痕。
* 验证：`test_syscall_direct` 全绿（stub 与直接调用返回值一致性）；防御闭环 P4（IAT/Inline Hook）路径状态升级 BLOCKED。

***

### WP-10：模糊测试全覆盖（P1）🔶 基建完成（2026-09-15）；10 分钟全程待重装后复验

**前置**：WP-2..5。

**触达文件**：★`fuzz/fuzz_container_v3.c` 等 5 个目标、✎CI。

**设计约束**：MSVC `/fsanitize=fuzzer`（VS 内置 libFuzzer）；入口 `LLVMFuzzerTestOneInput` 直接调用各解析函数（superblock/partition/extent/sstable/import）；每目标 CI 跑 10 分钟；**语料种子**用测试生成的合法容器。

**验收**：5 目标 CI 稳定运行；发现的崩溃转 bug 清单。

**执行留痕（2026-09-15，WP-10 基建完成）**：

* 5 目标全部落地（`tests/fuzz/`：fuzz\_container\_v3 / fuzz\_superblock / fuzz\_partition / fuzz\_extent / fuzz\_sstable + import 路径并入 container 目标），`build_core.fuzz.ps1` 一键构建 + `gen_seeds` 以测试生成合法容器作语料种子。
* fuzz 冒烟（短时长）+ 属性测试期间 5 目标持续模糊均零崩溃（WP-12 留痕已引用）。
* **待办**：每目标 10 分钟全程 CI 稳定运行的最终验收因本机恶意软件事件（构建产物已清除）未完成，重装系统后按 §7 命令补跑 5 目标 × 10 分钟并留痕。

***

### WP-14：P2 项清理（P1）

**范围**：V3 下仍有意义的 P2 项（温缓存竞态已被 V3 缓存重写吸收；游标生命周期引用计数；mountwatch 事件驱动化；GC 走 vsb\_txn——V3 GC 天然如此）。逐项核对 [CORE\_LAYER\_SYSTEMATIC\_REVIEW\_V2.md](./CORE_LAYER_SYSTEMATIC_REVIEW_V2.md) §6，V3 吸收的标注"已吸收"，其余修复。

**执行留痕（2026-09-15，WP-14 完成——P2 六项全部闭环）**：

> 原评审文档 CORE\_LAYER\_SYSTEMATIC\_REVIEW\_V2.md 已随 V2 退役清理不在库中；本留痕即六项 P2 的最终核对记录（原始清单见 §1.2）。

| 项 | 原缺陷（V2） | V3 现状 | 结论 |
| --- | --- | --- | --- |
| P2-1 GC 超级块裸写 | GC 直接写超块绕过事务保护 | V3 无独立 GC 裸写路径：全部超块写入（事务 commit / lifecycle / rekey\_auto 三处调用点）经 `vsb_txn_v3_begin` 法定人数；Extent 侧仅暴露 `verthys_extent_gc_eligible` 判定接口（无执行路径，未来 GC 落地必走 vsb\_txn） | **已吸收（结构性）** |
| P2-2 读块 data\_size 无钳制 | datablock 读路径尺寸未钳制即入缓冲操作 | datablock 随 V2 退役删除；V3 extent 读路径：flatcc verifier + count 上限 + hash/nonce 定长 + size≥TAG + plaintext≡size−TAG + offset+size≤next\_offset + 索引 HMAC + AEAD + BLAKE2b 三重校验。本次核对发现 3 处"朴素 a+b>c"uint64 回绕窗口（extent 索引 / sstable 块索引 / vfmt 数据块，均为认证数据纵深防御层）已全部改为回绕安全分解（先钳被减数，再以差值钳长度） | **已吸收 + 3 处加固** |
| P2-3 vtxn\_rollback 空壳 | 超块事务回滚为空操作 | `vsb_txn_v3_rollback` 完整恢复 backup 超块 + HMAC，committed/rolled\_back 状态机防重入；`repair_vsb_txn_v3_rollback` 测试覆盖 | **已修复（V3 重写）** |
| P2-4 温缓存 .tmp 竞态 | 写读竞态可观察半写状态 | V3 温缓存：独占句柄（共享模式 0）写 .tmp → `FlushFileBuffers` → `MoveFileExW(REPLACE\|WRITE_THROUGH)` 原子替换，读者只见完整旧/新文件 | **已吸收（V3 重写）** |
| P2-5 扫描游标生命周期 | 游标悬挂引用（容器循环后） | V3：`v3_owner` 实例身份锚点（Lock/再解锁换实例即失效）+ `scan_v3_alive` 于全量/摘要双 Fetch 路径校验 + 熔断作废标记 + 页锁定 + memory\_guard 注册/注销（身份锚点方案达成引用计数同等安全目标，且免去计数维护） | **已修复（V3 重写）** |
| P2-6 mountwatch INFINITE | 挂载监视无限等待 | mountwatch 源随 §1.4 V2 退役删除清单移除，全库仅余退役说明注释（grep 零活代码） | **已吸收（删除）** |

***

### WP-11：防御闭环验证（P2，收尾）✅ 已完成（2026-09-15）

**目标**：`defense_closure` 7/7 BLOCKED。关键依赖：WP-1 完成 → MEM\_DUMP 路径（`key_separation_any_installed`）可置 BLOCKED；P4（Hook）依赖 WP-9；P6（磁盘篡改）依赖 V3 分区认证。新增 `Verthys_GetSecurityStatus` 导出（v5.0 §11.2）。

**执行留痕（2026-09-15，WP-11 完成）**：

* 7 项攻击路径状态机落地（`security/layer6_closure/defense_closure.c/.h`）：SUSPEND\_BYPASS / MEM\_DUMP / HIBERNATION / IAT\_INLINE\_HOOK / DLL\_HIJACK / PROCESS\_READ / CROSS\_DEVICE，BOOT/CHECK 两模式，BLOCKED/DEGRADED/FAILED 三态语义诚实化（不可达防御不作 BLOCKED 宣称）。
* 依赖闭环兑现：MEM\_DUMP ← WP-1 CNG 内核密钥；IAT\_INLINE\_HOOK ← WP-9 直接系统调用；CROSS\_DEVICE ← pepper v2 机器绑定；PROCESS\_READ ← 双层 Job 白名单 DACL；DLL\_HIJACK ← worker 进程 DLL 加载白名单；HIBERNATION ← 休眠文件清理策略；SUSPEND\_BYPASS ← 调试器三重探测 + Job 线程限制。**7/7 BLOCKED（运行时验证）**。
* `Verthys_GetSecurityStatus` 导出（v5.0 §11.2）已入 `ci/export_baseline.txt` 29 符号白名单与 `verthys.def`。
* 验证：defense\_closure 运行时验证测试全绿。

***

### WP-12：属性测试（P2）✅ 已完成（2026-09-15）

不变式：LSM 插入/删除/查找（"插入后必可找到"）、Extent 引用计数守恒、事务 commit/rollback 后超级块与 WAL 一致。自研小型属性 harness（随机序列 + 不变式断言），不引入外部框架。

**执行留痕（2026-09-15，WP-12 完成——harness 落地，揪出三项生产缺陷并修复）**：

harness 形态（★`tests/test_v3_property.c`，零外部框架）：固定种子（失败打印种子/步号/操作名可复现）+ `PROP_CHECK` 失败跳转测试尾部清理标签（句柄/临时文件不释放将阻塞后续测试的 `remove()`/`fopen()`，防级联连坐）。六项测试：

| # | 测试 | 不变式 | 规模 |
| - | --- | --- | --- |
| 1 | prop\_lsm\_insert\_find\_delete | 随机 put/delete/get/flush/compact vs 影子模型（lid→条目/墓碑）；周期性全键扫描"存活键必可找到且字段逐项一致、死亡键必 NOTFOUND"；close→reopen 持久化复验 | 2000 步 / 64 槽位 |
| 2 | prop\_extent\_refcount\_conservation | 逐内容计数≡模型 + 总量守恒、条目不可变性（offset/size/nonce 首写后不变）、去重零重写、next\_offset 单调不减、gc\_eligible≡零引用条目数、存活内容抽样解密 roundtrip | 1200 步 / 16 内容 |
| 3 | prop\_txn\_commit\_rollback\_consistency | 白盒六 Phase 随机事务：sb.txid 当且仅当 commit 推进、CONFIRM 后 WAL 帧清零、回滚后 WAL 帧清零且记录不可见、LID 水位单调（含回滚烧毁+墓碑占位）、Extent 引用守恒、公共 API 可见性≡模型 | 48 事务 commit/rollback 混合 |
| 4 | prop\_txn\_crash\_no\_resurrection | 回滚→同 txid 再提交→COMMITTED 后崩溃（CONFIRM 前）→重开恢复：已回滚记录不得复活、已提交记录必须可见、LID 不复用 | 定向（回滚耐久性） |
| 5 | prop\_txn\_rollback\_delete\_restores\_original | 缺陷②定向回归（修复前必失败）：事务内 DELETE 墓碑覆写 MemTable 原始条目→回滚后原始条目必须完整复原 | 定向 |
| 6 | prop\_txn\_crash\_discard\_delete\_restores\_original | 缺陷②b 定向回归（修复前必失败）：PREPARED 崩溃→恢复丢弃组，被墓碑覆写的已提交原始条目必须复原 + 恢复收尾 WAL 清零 | 定向 |

**揪出并修复的生产缺陷（属性测试的核心价值验证）**：

| 缺陷 | 根因 | 修复 |
| --- | --- | --- |
| ① `verthys_lsm_get` NULL 探测形态墓碑误报 | `out==NULL` 的存在性探测路径未查 SSTable 墓碑——已删除键误报"存在"（上层探测判存在性 → 幽灵记录） | NULL 探测加本地 probe 条目 + probe\_name 缓冲，SSTable 查询统一走墓碑感知路径 |
| ② 运行时回滚墓碑覆写数据丢失（红线级） | 事务内 DELETE 墓碑按"新者胜"覆写 MemTable 原始条目；回滚走过滤式剔除（`verthys_lsm_purge_txid`）——墓碑与被覆写条目一同消失 = 已提交数据丢失 | 回滚改 WAL 重放式重建（`memtable_rebuild_locked`）：WAL 先行 + flush 复位不变式（MemTable ≡ 重放 [0, wal\_cursor)）保证自偏移 0 重放完整复原被墓碑遮蔽的原始条目；WAL 截断先行 + 提交，即便重建失败重开后回滚语义仍成立 |
| ②b 崩溃恢复丢弃组同型丢失（红线级） | PREPARED 崩溃恢复的丢弃组走 `verthys_lsm_purge_txid` 过滤式剔除，同 ② 丢失被墓碑覆写的已提交条目 | 新增 `verthys_lsm_rebuild_excluding`（排除多 txid 的重放重建）替换 purge\_txid（旧 API 已删除）；`verthys_lsm_rollback_txid` 签名同步收敛（去 out\_purged 出参） |

连带发现并修复：事务回滚后 V3 WAL 帧残留 → 同 txid 后续事务合并废弃帧（复活窗口）——`verthys_txn_v3_rollback` 补 `verthys_wal_reset`。

**验收**：dev 全量 254/254 全绿（含 6 项属性测试）；缺陷②/②b 定向回归修复前必失败、修复后通过；fuzz 冒烟 + 5 目标持续模糊零崩溃（WP-10 基建复用）。

***

## 6. AI 会话协议与提示词模板

### 6.1 会话开场模板（每个 WP 一次会话）

```
你在 Verthys 仓库（C:\Users\Administrator\Desktop\Verthys）执行 V3 升级工作包 <WP-x>。

必读（按序）：
1. docs/V3_UPGRADE_PLAYBOOK.md §3（全局约定与红线）、§5 <WP-x> 小节
2. docs/TARGET_ARCHITECTURE_V5.md <对应章节>
3. docs/PROJECT_DOCUMENTATION.md <相关章节>（当前架构事实）

执行纪律：
- 动手前 grep 复核本卡所列文件/函数的磁盘现状
- 每步构建绿：powershell -ExecutionPolicy Bypass -File scripts/build_core.dev.ps1 -NoPause
- 构建前查残留进程（LNK1168 陷阱）；构建后核对 exe 时间戳
- 无法按卡执行时：实测取证 → 头注+执行文档留痕偏差 → 不静默跳过
- 完成后：跑本卡验收测试 + 更新本手册 WP 状态 + PROJECT_DOCUMENTATION 对应章节

本工作包任务：<粘贴 §5 对应卡的"步骤">
```

### 6.2 会话收尾检查单

* [ ] `build_core.dev.ps1` 全绿（全量或分组 + 本 WP 新测试）

* [ ] 新增代码无密钥明文越界（grep 密钥变量名核对作用域）

* [ ] `ci/export_baseline.txt` 未漂移（或按 WP 要求同步 .def）

* [ ] 偏差（如有）已留痕：代码头注 + 执行文档

* [ ] 本手册 WP 状态列已更新

***

## 7. 命令速查

```powershell
# 开发构建 + 全量测试（CI 标准入口）
powershell -ExecutionPolicy Bypass -File scripts/build_core.dev.ps1 -NoPause

# 过滤运行（定位用；OR 多组）
./build_dev/core/tests/Debug/verthys_tests.exe <子串> [子串2 …]

# ASAN 构建（一次性配置）
powershell: . scripts/env.load.ps1; cmake -S . -B build_asan -G "Visual Studio 18 2026" -A x64 -DVERTHYS_ENABLE_ASAN=ON; cmake --build build_asan --config Debug

# Release（含 .vsec 注入；Authenticode 必须在其后）
powershell -ExecutionPolicy Bypass -File scripts/build_core.release.ps1 -NoPause

# 导出面校验
dumpbin -exports build/core/Release/verthys.dll   # 与 ci/export_baseline.txt 比对

# 构建前自检（LNK1168 陷阱）
tasklist | findstr verthys_tests
```

***

## 8. 风险登记册

| #   | 风险                    | 概率 | 缓解                                                             |
| --- | --------------------- | -- | -------------------------------------------------------------- |
| R-1 | K-1 根因深（布局敏感野指针）      | 中  | WP-13 排首位；快照断言 + PageHeap；实在无法定位则测试进程隔离方案（runner 派生自身逐测试运行）兜底  |
| R-2 | flatcc 工具链集成复杂度       | 中  | WP-0 先跑 demo schema；备选方案 E-2 决策点升级                             |
| R-3 | CNG 在特定环境不可用（TPM/虚拟机） | 中  | 沿用 cng\_machine\_key 的三级降级链 + `VERTHYS_ERR_CNG_UNAVAILABLE` 显式错误 |
| R-4 | V2/V3 并存期编译冲突         | 中  | fmt 枚举隔离 + 两个 lifecycle 文件互不 include；删除清单一次成提交                 |
| R-5 | nonce 计数器持久化与崩溃窗口     | 低  | 计数器随超级块法定人数提交；恢复取 max(盘面值, WAL 重放值)+安全裕量                       |
| R-6 | AI 会话偏离卡片范围           | 中  | §6.1 协议 + 收尾检查单；每 WP 独立会话独立提交                                  |
| R-7 | MSVC libFuzzer 兼容性    | 中  | WP-10 备选：单独 clang 工具链构建 fuzz 目标（仅 fuzz 用 clang，主库仍 MSVC）       |

***

## 9. 里程碑验收矩阵

| 里程碑            | 工作包                     | 验收门（全部满足才算达成）                                                                                      | 状态（2026-09-15） |
| -------------- | ----------------------- | -------------------------------------------------------------------------------------------------- | -------------- |
| **M0 基线恢复**    | WP-13, WP-0             | 全量 3 连绿；CI 全量门开启；flatcc/xxhash vendored + codegen 跑通                                               | ✅ 达成 |
| **M1 内核密钥安全**  | WP-1, WP-7              | test\_cng\_kernel + test\_secure\_allocator 全绿；`grep key\_a\[ src/` 仅 V2 并存路径；MEM\_DUMP 判据可 BLOCKED | ✅ 达成（V2 并存路径已随退役清零） |
| **M2 V3 容器就绪** | WP-2..5                 | V3 全链路测试绿；解锁 ≤2.5s（基准）；WAL 崩溃注入矩阵通过；删除清单执行后构建绿                                                     | ✅ 达成 |
| **M3 纵深防御闭环**  | WP-6, WP-8, WP-9, WP-11 | defense\_closure 7/7 BLOCKED（运行时验证）；runtime\_hash 补丁检测测试通过                                         | ✅ 达成（Release `.vsec+.rhat` 链路待重装后复验） |
| **M4 测试体系完备**  | WP-10, WP-12, WP-14     | 5 个 fuzz 目标 CI 稳定；属性测试就绪；P2 清零或标注"V3 已吸收"                                                          | 🔶 属性测试 + P2 清零完成；fuzz 5 目标基建完成、10 分钟全程待重装后复验 |
| **M5 生产就绪**    | 全部                      | 全部 CI 门 + Release 链路（.vsec）+ 导出面基线 35-38 更新 + PROJECT\_DOCUMENTATION 升级为 v5.0                      | 🔶 导出面基线已收敛为 29 符号（基线文档同步）；PROJECT\_DOCUMENTATION v5.0 升级中；3 连绿 + 全链路复验待重装后收口 |

***

