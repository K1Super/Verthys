# 架构决策记录（ADR 索引）

> 按编号索引 Verthys 已核实的真实架构决策，每条含上下文/备选项/结论/后果四段式。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档只记录**能从代码或注释中核实的决策**，无依据的决策不收录。佐证以 `core/`、`verthys-tauri/`、`third_party/` 为相对根。决策源主要来自 `archive/TARGET_ARCHITECTURE_V5.md` §2.2（D-1..D-6）与 `archive/V3_UPGRADE_PLAYBOOK.md` §2.2（E-1..E-8）及代码注释。

## 摘要表

| 编号 | 决策 | 一句话结论 | 佐证 |
|---|---|---|---|
| ADR-001 | 抛弃 V1/V2 容器，唯一 V3 | V3 为唯一格式，不保留任何旧容器读路径 | `verthys_container_v3.h`、WP-5 删除清单 |
| ADR-002 | 依赖 vendored 而非 vcpkg | flatcc/libsodium/xxhash 全部 vendored 静态链接 | `third_party/Flatcc.cmake`、`Libsodium.cmake` |
| ADR-003 | C ABI + libloading 动态加载 | worker 运行时按名解析 29 白名单符号，不做 raw-dylib 静态链接 | `verthys-worker/Cargo.toml`、`verthys.def` |
| ADR-004 | worker 子进程隔离模型 | 密钥/明文隔离到独立子进程，锁库即杀进程 | `verthys-worker/src/main.rs` |
| ADR-005 | FlatBuffers/flatcc 选型（E-2） | 纯 C11 flatcc，禁手写序列化 | `third_party/Flatcc.cmake`、`core/schema/` |
| ADR-006 | 超级块法定人数提交（D-3） | 3 副本写/读 ≥2 一致才成立 | `verthys_superblock_v3.c` |
| ADR-007 | CNG 内核密钥托管（D-1） | 密钥仅在 import 栈帧瞬态，其余驻内核句柄 | `key_separation.c`、`verthys_crypto_cng.c` |
| ADR-008 | 内容寻址 Extent + BLAKE2b（E-3） | libsodium generichash 零新依赖 | `verthys_extent.c`、`verthys_crypto.h` |
| ADR-009 | 直接系统调用（D-4） | SSN 排序法 + W^X stub，失败降级 | `syscall_direct.c` |
| ADR-010 | 密钥自动轮换（D-5） | 90 天/10k ops/DEGRADE 三触发，CNG 内核切换 | `verthys_rekey_auto.c` |
| ADR-011 | 导出面唯一由 .def 白名单（P0-A） | `VERTHYS_API` 为空宏，29 符号唯一管控 | `verthys.h`、`verthys.def` |
| ADR-012 | 反 Oracle 错误码统一化（E-8） | 功能码透传、AUTH/FORMAT/IO/CORRUPT 统一 AUTH | `dispatch.rs`、`protocol.rs` |
| ADR-013 | 测试注册上提根目录（WP-10） | enable_testing 置于根，避免 ctest 假绿 | 根 `CMakeLists.txt` |
| ADR-014 | core 模块化重构（六域 31 组件） | 子域→组件两级拆分，公共/私有物理隔离 | `core/CMakeLists.txt` |

---

### ADR-001 抛弃 V1/V2 容器，唯一 V3

- **上下文**：V2 容器（B+ 树 + 槽位池 + 迁移引擎）历史包袱重，V1/V2 迁移链路为失效死路径（核验报告 P1-1）。V3 以分区认证 + 内容寻址 + LSM 取代。
- **备选项**：① 保留 V2 并存 + 引导迁移；② 彻底删除 V1/V2，只认 V3。
- **结论**：选 ②。删除清单移除 btree/datablock/migration/v2_lifecycle/V2 超级块等；`verthys_format.c` 裁剪为 V3 交换信封专用；非 V3 文件 C 层 open 即拒绝。
- **后果**：无旧容器迁移路径；磁盘旧 `.vault`/旧魔数文件不可打开（见 [MIGRATION.md](MIGRATION.md)）。佐证：`core/src/container/shared/verthys_container_v3.h`、`archive/应用功能全量核验报告.md` §7。

### ADR-002 依赖 vendored 而非 vcpkg

- **上下文**：核心 DLL 需自包含黑盒，依赖版本须可复现且供应链可审计；vcpkg.json 声明 libsodium 但构建实际不消费。
- **备选项**：① vcpkg 统一管依赖；② vendored + SHA-256 固化。
- **结论**：选 ②。flatcc（commit a2515daa…）与 libsodium 1.0.20 vendored 静态链入；xxhash.h 单头文件 vendored；`ci/vendor_hashes.txt` 固化哈希。
- **后果**：零外部 DLL 依赖（除系统 API）；升级需同步更新 vendor 哈希。佐证：`third_party/Flatcc.cmake`、`third_party/Libsodium.cmake`。

### ADR-003 C ABI + libloading 动态加载

- **上下文**：worker（Rust）与核心（C DLL）的边界，需最小导出面且版本可验证。
- **备选项**：① raw-dylib 静态链接导入库；② libloading 运行时按名解析。
- **结论**：选 ②。worker 以 `libloading = "0.8"` 按名解析 `.def` 白名单符号；raw-dylib 仅用于 `windows` crate（系统 API 绑定），与 verthys.dll 边界无关。
- **后果**：加载失败可显式降级；符号集与 `ci/export_baseline.txt` 29 符号对齐。佐证：`verthys-worker/Cargo.toml`、`src-tauri/Cargo.toml` LNK1181 注释、`core/verthys.def`。

### ADR-004 worker 子进程隔离模型

- **上下文**：密钥/明文必须与 UI 主进程隔离；"锁库即杀进程"是密钥最终归宿。
- **备选项**：① 主进程直接加载 DLL；② 独立 worker 子进程转发。
- **结论**：选 ②。worker 以 BELOW_NORMAL 应用 mitigation policy → 加载 DLL → 单线程 FFI；GMK 仅存 worker（Zeroizing）。
- **后果**：主进程/前端零密钥接触；多一次进程边界成本换取隔离。佐证：`verthys-tauri/verthys-worker/src/main.rs`、`gmk.rs`。

### ADR-005 FlatBuffers/flatcc 选型（E-2）

- **上下文**：V3 容器序列化要求 schema 驱动、零拷贝、前向兼容。
- **备选项**：① flatcc（纯 C11）；② FlatBuffers 官方 C++ 桥接；③ 手写序列化。
- **结论**：选 ①，禁手写。构建期 `flatc -a` 生成 reader/builder/verifier。
- **后果**：解析纪律为 HMAC→AEAD→flatcc verifier 三层纵深。佐证：`third_party/Flatcc.cmake`、`core/CMakeLists.txt` schema codegen。

### ADR-006 超级块法定人数提交（D-3）

- **上下文**：超级块单点损坏将导致整库丢失。
- **备选项**：① 单副本；② 3 副本 + 2/3 法定人数。
- **结论**：选 ②。写 3 副本 fsync，≥2 成功=提交；读取取 txid 最高且 ≥2 一致；仅 1 有效返回 `QUORUM_FAILED`。
- **后果**：容单副本损坏；空耗 3 倍超级块空间。佐证：`verthys_superblock_v3.c`、`verthys_container_v3.h` 法定人数注释。

### ADR-007 CNG 内核密钥托管（D-1）

- **上下文**：目标态要求密钥明文"永不出现在用户态可寻址内存"。
- **备选项**：① 用户态数组持有 A/B/C；② CNG `BCryptGenerateSymmetricKey` 导入内核句柄。
- **结论**：选 ②，`verthys_cng_aead_import_key` 是唯一允许明文瞬态的函数（栈上即清）。
- **后果**：密钥仅在栈帧瞬态；防内存转储依赖 MEM_DUMP 判据。佐证：`core/src/crypto/cipher/verthys_crypto_cng.c`、`keymanager_cng.c`。

### ADR-008 内容寻址 Extent + BLAKE2b 零新依赖（E-3）

- **上下文**：V3 数据区需去重 + 完整性。
- **备选项**：① 引入新哈希库；② 复用 libsodium `crypto_generichash`（BLAKE2b-256）。
- **结论**：选 ②。明文 → BLAKE2b → 查重 → CNG 加密追加；读取验 `BLAKE2b(明文)==hash`。
- **后果**：去重零重写 + 读路径三重校验。佐证：`verthys_extent.c`、`verthys_crypto.h`（`verthys_generichash`）。

### ADR-009 直接系统调用（D-4）

- **上下文**：反调试/防转储检测器的 `Nt*` 查询易被用户态 Hook。
- **备选项**：① GetProcAddress 常规调用；② 直接系统调用 stub。
- **结论**：选 ②（关键路径），失败优雅降级 ①。SSN 排序法提取 + W^X stub 页 + CFG 登记。
- **后果**：绕过 IAT/EAT Hook；降级链留遥测。佐证：`core/src/security/anti_analysis/syscall_direct.c`。

### ADR-010 密钥自动轮换（D-5）

- **上下文**：限制单密钥生命周期内的密文暴露量。
- **备选项**：① 仅手动改密轮换；② 时间/操作计数/DEGRADE 自动触发。
- **结论**：选 ②。90 天 / 10,000 ops / DEGRADE + 24h 防震荡，轮换在 CNG 内核态新旧切换。
- **后果**：轮换透明；崩溃一致性靠 ping-pong 槽位 + VsbTxnV3。佐证：`core/src/crypto/rekey/verthys_rekey_auto.c`。

### ADR-011 导出面唯一由 .def 白名单（P0-A）

- **上下文**：历史用 `VERTHYS_EXPORTS` 全量导出，"最小导出面"失效。
- **备选项**：① 头文件 dllexport；② `.def` 唯一白名单。
- **结论**：选 ②。`VERTHYS_API` 为空宏，导出唯一由 `/DEF:verthys.def` 决定。
- **后果**：实测 `dumpbin -exports` = 29 符号逐一相等。佐证：`core/include/verthys.h`、`core/verthys.def`、`ci/export_baseline.txt`。

### ADR-012 反 Oracle 错误码统一化（E-8）

- **上下文**：区分"密码错误 vs 文件篡改"会向攻击者泄露信息。
- **备选项**：① 错误码全量透传；② 功能码透传、分类码统一 AUTH。
- **结论**：选 ②。功能码（INVALID/NOTFOUND/…/UNSUPPORTED 14 码）透传前端；AUTH/FORMAT/IO/CORRUPT/INTERNAL 及未知码统一 AUTH。
- **后果**：防枚举探测，牺牲部分错误粒度。佐证：`verthys-worker/src/runtime/protocol.rs`、`dispatch.rs`。

### ADR-013 测试注册上提根目录（WP-10）

- **上下文**：enable_testing 置于子目录时，构建根无 CTestTestfile.cmake，`ctest --test-dir <build_root>` 报 "No tests were found" 且退出码 0（假绿）。
- **备选项**：① 子目录 enable_testing；② 上提根 CMakeLists.txt。
- **结论**：选 ②，`enable_testing()` 在 `add_subdirectory(core)` 之前调用。
- **后果**：fuzz 冒烟门与 CI 从构建根即可发现全部测试。佐证：根 `CMakeLists.txt`（WP-10 注释）。

### ADR-014 core 模块化重构（六域 31 组件）

- **上下文**：V3 收口后 core/src 仍同级平铺 50+ 文件，公共头与实现混放。
- **备选项**：① 平铺；② 子域→功能组件两级拆分，公共头 `include/` 物理隔离。
- **结论**：选 ②。六顶层域 + 31 组件目录，`VERTHYS_SRC_SUBDIRS` 单一事实源；目录全小写蛇形、无空泛名。
- **后果**：公共/私有物理隔离；单组件 3-10 文件、层级 ≤4。佐证：`core/CMakeLists.txt`、`archive/V3_UPGRADE_PLAYBOOK.md` §1.6。