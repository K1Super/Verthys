# Verthys 全量代码审查报告

- 审查日期：2026-09-19
- 审查范围：全量代码（core C DLL + ci/scripts + verthys-tauri Rust/Vue3 + verthys-worker + 构建链 + CI/CD + 仓储结构）
- 审查方式：源码逐行阅读（关键路径全读）+ 静态 grep 交叉验证 + 测试实测（Release 构建）+ git 仓储核验。未执行任何破坏性命令，未修改任何代码。
- 分级：P0 阻断/高危，P1 严重，P2 中等，P3 改进。每项标注性质：**[确认缺陷]** / **[疑似风险]** / **[改进建议]**；无证据处标注 **[需验证]**。

---

## 0. 结论先行

1. **核心 C DLL 工程质量高**。加密（Argon2id + XChaCha20-Poly1305 + HKDF）、超级块法定人数、WAL 回放/撕裂截断、LSM manifest 解析、FlatBuffers 全部 "verifier 先行"，未发现可利用的密码学误用、越界读写或事务一致性缺陷。
2. **测试真实可信**：本地实测 Release 构建 `verthys_tests.exe` → **250 passed, 0 failed**，含属性测试（种子化）、故障注入与崩溃恢复用例，非伪造测试。
3. **唯一 P0**：`third_party/libsodium` 是无 `.gitmodules` 的 gitlink（嵌套 .git 仓库），父仓库未跟踪其任何文件 → **干净克隆/CI 检出后将无法构建**。
4. **1 个 P1**：编译内嵌胡椒兜底常量公开于源码（设计权衡，需治理与文档化）。另有 7 项 P2、8 项 P3，详见下文。
5. 版本身份存在冲突：CMake/Cargo/package.json/tauri.conf/worker 均为 2.6.1，唯独 `vcpkg.json` 为 3.2.6，且该文件全项目 0 处引用（死清单）。
6. **[2026-09-19 修复更新]** P0-1 / P1-1 / P2-1~P2-7 / P3-5 已全部修复并实测验证（C 250/250、src-tauri 296/296、双 crate clippy 零告警、前端 type-check + build 通过），详见 **§11 修复状态与验证记录**。

---

## 1. 项目测绘

### 1.1 技术栈与版本

| 层 | 语言/框架 | 版本 | 证据 |
|---|---|---|---|
| 核心 DLL | C11（MSVC） | 产品 2.6.1 | 根 CMakeLists.txt:6 |
| 密码学 | libsodium（vendored 静态） | 1.0.20 | third_party/libsodium/configure.ac:2 |
| 序列化 | flatcc（vendored）+ xxHash 单头 | vendored | third_party/ |
| C++ 标准 | C++17（预留） | - | 根 CMakeLists.txt:14 |
| 桌面壳 | Tauri v2 | =2.11.5（锁定） | src-tauri/Cargo.toml:112 |
| Rust 后端 | Rust + windows-rs 0.58 | crate 2.6.1 | src-tauri/Cargo.toml:87 + Cargo.lock 存在 |
| 前端 | Vue3 + TypeScript + Vite | 2.6.1 | package.json:4 |
| Worker | Rust（独立 crate） | 2.6.1 | verthys-worker/Cargo.toml |
| 构建 | CMake ≥3.20 + MSVC + Ninja/VS | - | 根 CMakeLists.txt:1 |

### 1.2 模块分层（单向依赖，无循环——已在 core/CMakeLists.txt 注释中显式声明）

```
L5  api/           公共 C ABI（lifecycle/unlock/scan/transfer/progress）
L3  transaction/   WAL 环形 512KB×2 + 六 Phase 事务
L2  index/         LSM（跳表 MemTable + SSTable + Compaction）+ 温缓存 V3
L1  container/     容器格式（superblock 三副本法定人数/extent/partition/io）
L0  crypto/        Argon2id/HKDF/XChaCha20-Poly1305(CNG)/pepper/rekey
L6  security/      反分析/内存防护/进程隔离/硬件绑定/Hook 防御/沙盒/闭环
```

- 导出面：`core/verthys.def` 白名单强制最小接口（P0-A 治理）。
- UI 层：verthys-tauri（Tauri + Vue3，60+ `#[tauri::command]`）+ verthys-worker（独立进程，SHM 契约经 `shm_schema.rs` 单源 `include!` 共享）。
- 数据流：前端 → IPC 命令（含一次性 auth_token 的高安全命令）→ Rust 控制器 → C DLL FFI → 加密容器（.verthys，AEAD 加密 + WAL + LSM）。

### 1.3 构建/部署

- 开发：`build_dev.ps1` → build_dev（Debug）；生产：`build_production.ps1`/`scripts/build_core.release.ps1` → build（Release）。
- 加固：`cmake/VerthysHardening.cmake`：/GS、/guard:cf、/guard:ehcont、/sdl、ASLR、DEP、CETCOMPAT、/LTCG、Release 剥离符号。偏差留痕（/guard:longjmp 未落地、/wd4996）均有磁盘注释，符合治理规范。
- CI：`.github/workflows/core.yml`（windows-latest：Debug 构建 + 250 项测试 + Release 构建 + dumpbin 导出面白名单门 + libFuzzer 5 目标各 10 分钟）。本地双引擎静态检查：`ci/run_ci.ps1`（regex + Rust AST 工具）。
- 依赖锁定：Cargo.lock ✓、package-lock.json ✓、C 侧 vendored ✓；`vcpkg.json` 未使用（见 P2-1）。

---

## 2. 风险总览

| 级别 | 数量 | 性质 |
|---|---|---|
| P0 | 1 | 仓储完整性缺陷（克隆/CI 无法构建） |
| P1 | 1 | 安全设计权衡（公开胡椒兜底常量） |
| P2 | 7 | 版本冲突/供应链门/CI 覆盖缺口/日志管道 |
| P3 | 8 | 工程化改进（告警门/版本单一源/健康观测等） |

---

## 3. 详细发现

### P0-1 [确认缺陷｜置信度：高] libsodium gitlink 导致干净克隆与 CI 无法构建

- **证据**：
  - `git ls-tree HEAD third_party/libsodium` → `160000 commit 93a7d0d41fe2e32409b5d00386946f491750b7de`（gitlink，非普通文件）。
  - 仓库根无 `.gitmodules`（`Test-Path .gitmodules` = False）。
  - `git ls-files third_party/libsodium` 仅 1 行（gitlink 本身，无任何源文件被跟踪）；本地磁盘文件来自嵌套仓库自己的 `.git`（`third_party/libsodium/.git` 存在，commit 与 gitlink 一致）。
  - 构建直接依赖该目录：`third_party/Libsodium.cmake:12,26` 以 `file(GLOB_RECURSE ... libsodium/src/libsodium/*.c)` 收集源文件。
- **触发条件**：`git clone <remote> && cmake -S . -B build` 或 GitHub Actions `actions/checkout`（

 不可递归检出一个未注册的 gitlink）。
- **影响**：fresh clone 中 libsodium 目录为空 → GLOB 到 0 个 .c → `add_library(libsodium STATIC)` 无源报错，configure 失败；`.github/workflows/core.yml` 的 build-and-test 与 fuzz 两个 job 全部必失败。对比：flatcc/xxhash 以普通文件 vendored（299 个文件被跟踪），不受影响。
- **修复建议**（二选一）：
  1. 正规化子模块：`git rm --cached third_party/libsodium && git submodule add <libsodium-URL> third_party/libsodium`，CI 校验 `submodules: recursive`；
  2. 与 flatcc 对齐，扁平化 vendored：删除嵌套 `.git` 后 `git add third_party/libsodium` 全量入库（当前已在磁盘，成本最低）。
- **验证方式**：`git clone . <tmp> && cmake -S <tmp> -B <tmp>/build_verify -G Ninja`，修复前预期 configure 失败（GLOB 0 源）；修复后预期 configure 成功。

### P1-1 [疑似风险｜置信度：高] 编译内嵌胡椒兜底常量公开于源码

- **证据**：[verthys_pepper.c](core/src/crypto/pepper/verthys_pepper.c#L41-L46) 定义 32 字节 `VERTHYS_PEPPER_COMPILED`；`verthys_pepper_init()` L484 在"注入胡椒不可用、OS 托管不可用"时回退该常量；`verthys_pepper_load_from_os()` L243-250 在"首次生成胡椒但持久化失败"时亦回退该常量。
- **触发条件**：零配置场景（无 `verthys_pepper_inject`、CNG 机器密钥不可用或 pepper.bin 持久化失败）。
- **影响**：兜底模式下 pepper 熵 = 0（常量随源码公开，任何攻击者可得），pepper 对弱口令的加固增益完全失效；此时安全强度退化为纯 Argon2id(password, salt)。设计上已处理一致性（来源写入容器 flags 并解锁校验，不会锁库，源码注释明确），属**有意的可诊断权衡**，而非静默漂移缺陷。
- **修复建议**：
  1. 首选：取消编译内嵌兜底，改为"首次运行强制生成随机 pepper 并持久化"（保留注入通道供分发），持久化失败即失败并明确报错，不降级；
  2. 或维持现状但将风险文档化于 `SECURITY_DESIGN.md`（当前该文件未见此风险说明），并在前端对"编译内嵌胡椒来源"显式向用户提示低安全档。
- **验证方式**：删除 `%APPDATA%\Verthys\pepper.bin` 与 CNG 机器密钥后创建容器，观察来源标志与用户提示；回归：现有 250 项测试 + pepper 来源相关用例。

### P2-1 [确认缺陷｜置信度：高] vcpkg.json 为死清单且版本为全项目唯一冲突值 3.2.6

- **证据**：`vcpkg.json` 声明 `version-string: 3.2.6` 且 `builtin-baseline` 全 0（未锁定）；全项目脚本/CI 对 "vcpkg" 引用计数 = 0（实测 grep 全部 ps1/yml 文件）；libsodium 实际经 `third_party/Libsodium.cmake` vendored 构建；其他 5 处版本声明均为 2.6.1（CMake/Cargo/package.json/tauri.conf/worker）。
- **影响**：供应链审计误判（认为依赖经 vcpkg 且版本 3.2.6）；若将来有人以 manifest 模式运行 vcpkg，全零 baseline 属非法/不可复现状态。
- **修复建议**：删除 `vcpkg.json`，或将版本同步为 2.6.1 并在 `BUILD.md` 说明"vcpkg manifest 仅声明用途不参与构建"；建议直接删除（YAGNI）。
- **验证方式**：删除后全量构建 + 250 测试通过。

### P2-2 [确认缺陷｜置信度：高] 供应链哈希门未执行校验，且未覆盖 libsodium

- **证据**：`ci/vendor_hashes.txt` 覆盖 flatcc + xxhash（文件头自述），**无 libsodium 条目**；全项目无任何脚本/CMake/CI 步骤实际执行该清单校验（grep 引用仅出现在文档 `docs/archive/V3_UPGRADE_PLAYBOOK.md` 与 `docs/ARCHITECTURE_DECISIONS.md:41`，后者声称"ci/vendor_hashes.txt 固化哈希"——与实现不符）。`ci/run_ci.ps1` 两级检查不含哈希比对。
- **影响**：vendored 依赖被篡改（供应链攻击）时无任何自动化发现手段；ADR 声明与实现不一致。
- **修复建议**：补 libsodium 全量文件 SHA-256 清单；在 `core.yml` 增加 `Get-FileHash` 比对步骤（或在 run_ci.ps1 增加第三级），每个 vendored 文件新增/变更时门自动变红。
- **验证方式**：篡改任意第三方文件后运行校验步骤 → 预期失败。

### P2-3 [确认缺陷｜置信度：高] CI path filter 未包含 third_party/**，供应链变更不触发构建门

- **证据**：`.github/workflows/core.yml` L17/L19 的 `paths:` 仅含 `core/**、cmake/**、scripts/build_core.*、ci/**、.github/workflows/core.yml`；`third_party/**`（libsodium/flatcc/xxhash）与根 `CMakeLists.txt`、`dep-versions.txt` 变更均不触发 CI。
- **影响**：升级/替换 vendored 依赖的 PR 可绕过编译与 250 项测试门。
- **修复建议**：paths 增加 `third_party/**`、`CMakeLists.txt`、`dep-versions.txt`（或改为全触发）。
- **验证方式**：仅修改 third_party 下文件提交 → 当前无 CI job；修复后 job 触发。

### P2-4 [确认缺陷｜置信度：高] Rust/前端测试未接入任何 CI

- **证据**：`.github/workflows/` 仅 `core.yml` 一个工作流；其注释自述"Rust 测试与类型检查、前端 security-test.ts 由上层仓库工作流（或本工作流扩展 job）承接"。实测 src-tauri 存在 38 处 `#[cfg(test)]` 单元测试块、`ci/` 无 Rust 相关执行。本地 git 仅 3 个 commit，无上层仓库信号。
- **影响**：Rust 侧 FFI/命令/控制器逻辑、前端 security-test 无自动回归，变更风险不可见。
- **修复建议**：扩展 core.yml 或新增 `rust.yml`：`cargo test`、`cargo clippy -- -D warnings`、`npm run type-check`、前端 security-test、`cargo build --release` 冒烟。
- **验证方式**：本机先跑通 `cargo test --manifest-path verthys-tauri/src-tauri/Cargo.toml` 与 `npm run type-check`（记录基线通过率），再接线 CI。

### P2-5 [疑似风险｜置信度：中][需验证] 生产 DLL 携带 OutputDebugStringA 诊断输出

- **证据**：`core/src/security/layer1_process_guard/job_isolation.c:56`、`core/src/api/scan/verthys_scan.c:446-451`、`core/src/security/layer3_hw_binding/cng_machine_key.c:81`（注释声明日志经 OutputDebugStringA 输出）。Release 构建不剥离这些调用（无条件编译门）。
- **影响**：任何具备调试权限或装载的监控工具（DebugView/自定义调试器）可捕获生产进程的诊断串，形成情报泄露面。**本次抽查未见密钥字节/口令入日志**，但未逐点审查全部诊断内容 → 需验证。
- **修复建议**：诊断输出收敛为内部开关（`#ifdef VERTHYS_DIAG`）或统一到受控日志管道（对齐 Rust 侧 JSON LogEntry），Release 默认静默。
- **验证方式**：DebugView 挂接 Release DLL 运行解锁流程 → 预期无任何输出。

### P2-6 [疑似风险｜置信度：中] panic hook 向调试通道输出 payload + backtrace

- **证据**：`src-tauri/src/middleware/panic_hook.rs:115-151`：panic payload 原文 + file:line:col + 强制 backtrace → JSON 日志管道 + OutputDebugString。
- **影响**：若 panic 发生在含敏感上下文的调用栈（如密钥派生中间状态被断言/索引越界 panic 携带字符串），payload 可能经调试通道/日志文件泄露。
- **修复建议**：日志前对 payload 做 sanitize（仅保留 panic 位置与类型，截断用户数据字段）；确认日志文件落地位置与权限。
- **验证方式**：在含敏感字符串的模块内注入 panic → 检查日志/调试输出不含原文。

### P2-7 [需验证｜置信度：低] Argon2id 校准路径的触发频率与成本未确认

- **证据**：`core/src/crypto/cipher/verthys_crypto.c:259-309` 存在"两次派生测量耗时并钳制迭代次数"的校准逻辑。
- **疑点**：若每次解锁都执行校准（两次 Argon2 派生），解锁延迟翻倍；若是"首次基准写入超级块（benchmark_ms 4 项向量）后复用"，则无问题。超级块 schema 含 `argon2_benchmark_ms` 固定 4 项向量（superblock_v3.c:378-385），暗示基准持久化——但校准触发条件未在本轮逐行确认。
- **建议**：阅读校准调用方，确认触发条件；若每次解锁重跑，改为基准缓存 + 参数变更时重校准。

### P3-1 [改进建议] 自研代码未启用高告警等级，.clang-tidy 配置未接线

- **证据**：`verthys_apply_hardening` 无 `/W4`；根目录 `.clang-tidy`（10.9KB）全项目 0 引用（脚本/CI grep 均为 0）；仅对 third_party libsodium 做了告警抑制。
- **建议**：core 与 tests 启用 `/W4 /WX`（先修存量告警）；CI 加 `clang-tidy`（或 MSVC Code Analysis `/analyze`）步骤。

### P3-2 [改进建议] 版本号 5+1 处多源手工维护

- **证据**：2.6.1 分散于 CMakeLists.txt、Cargo.toml、package.json、tauri.conf.json、verthys-worker/Cargo.toml、README；vcpkg.json 已漂移为 3.2.6（历史教训已发生）。
- **建议**：单一版本源（如根 `VERSION` 文件）+ 构建期注入 + `ci/version_check` 门（对比全部声明与 git tag）。

### P3-3 [改进建议] C 侧无结构化日志/追踪 ID

- **证据**：C 侧诊断全部走 OutputDebugStringA 散点（见 P2-5），无级别/追踪 ID；Rust 侧有 JSON LogEntry 管道。两端日志体系不一致，跨层排障（FFI 调用链）困难。
- **建议**：C 侧引入极简结构化日志（级别 + trace_id + 模块），trace_id 由 FFI 边界传入贯通前后端；关键路径耗时埋点（对齐观测规范）。

### P3-4 [改进建议] 单元测试不经过 DLL 导出边界

- **证据**：core/CMakeLists.txt:42 注释明确 tests 直接链对象库"不走 DLL 边界"；导出契约仅由 CI dumpbin 白名单比对承担（符号存在性，非运行期可达性）。
- **建议**：增设一个链接 `verthys.dll` import lib 的 FFI 冒烟测试，验证导出符号可解析 + 主流程可运行。

### P3-5 [改进建议] 调试残留文件入库

- **证据**：`git ls-files` 确认 `verthys-tauri/__blur_lab.html` 被跟踪（疑似动效调试页）。
- **建议**：确认无引用后删除并加入 .gitignore。

### P3-6 [改进建议] 版本历史与发布标签缺失

- **证据**：`git log --oneline` 仅 3 commit（"updata"、"init"、"Initial commit"——含拼写与语义不明的提交信息）；无 tag；docs/RELEASE.md 与 CHANGELOG 机制未对接该现实。
- **建议**：规范 commit 格式 + 每个发布打 tag + CI 生成/校验 CHANGELOG。

### P3-7 [改进建议] 依赖漏洞扫描与 SBOM 缺失

- **证据**：无 cargo audit / npm audit / osv-scanner 接入；`dep-versions.txt`（Rust crate 清单）为静态文档，未见自动生成/校验步骤（新鲜度需验证）。
- **建议**：CI 接入 osv-scanner（覆盖 Rust + npm）并生成 CycloneDX SBOM；dep-versions.txt 改为 `cargo clippy`/lockfile 派生生成 + 门校验。

### P3-8 [改进建议] WAL 每记录一次 fsync，吞吐需评估

- **证据**：`verthys_wal.c:496-497`：`verthys_wal_append` 每帧结束即 `wal_fsync`（fflush + _commit）。
- **说明**：耐久性优先的正确设计；若批量写入场景（导入/compaction 紧邻）出现吞吐瓶颈，评估组提交（group commit）或"事务内批帧 fsync"。属性能优化备选项，非缺陷。

---

## 4. 冲突矩阵

| 类别 | 冲突项 | 位置 | 证据 | 处理建议 |
|---|---|---|---|---|
| 仓储结构 | gitlink vs 无 .gitmodules | third_party/libsodium / 仓库根 | `160000 commit 93a7d0d…` + `.gitmodules` 缺失 | 子模块正规化或扁平 vendored（P0-1） |
| 版本 | vcpkg 3.2.6 vs 全局 2.6.1 | vcpkg.json | 5 处 2.6.1 + 1 处 3.2.6 | 删除或同步（P2-1） |
| 依赖双源 | vcpkg 声明 libsodium vs vendored 静态链 | vcpkg.json / Libsodium.cmake | manifest 0 引用 | 删除死清单（P2-1） |
| 供应链 | ADR 声称哈希固化 vs 清单缺 libsodium 且无执行步骤 | ARCHITECTURE_DECISIONS.md:41 / ci/vendor_hashes.txt | 文档-实现不一致 | 补清单 + 接门（P2-2） |
| CI 触发面 | third_party/** 不在 path filter | .github/workflows/core.yml:17,19 | 供应链变更不触发 CI | 扩展 paths（P2-3） |
| CI 覆盖 | core 有 CI、Rust/前端无 CI | .github/workflows/（仅 core.yml） | 38 个 cfg(test) 无 runner | 新增 rust/frontend job（P2-4） |
| 工具链 | .clang-tidy 配置存在但 0 引用 | 根 .clang-tidy / 全部脚本 | 无执行入口 | 接入 CI（P3-1） |
| 日志体系 | C 侧散点 DebugString vs Rust 侧 JSON 管道 | job_isolation.c / panic_hook.rs | 双体系无统一级别/追踪 | 统一日志方案（P2-5/P3-3） |
| 命名语义 | 容器格式 "V3"（superblock_v3 等）与产品版本 2.6.1 易混淆 | schema/*.fbs / CMakeLists | 格式世代 vs 产品版本两套编号 | 在 README/GLOSSARY 明确两者关系（非代码冲突，防误解） |

---

## 5. 健康点清单（确认无疑的正面事实）

1. 密码学路径全部经 libsodium/CNG：Argon2id 参数上下限校验（防损坏容器触发超大内存 DoS）、XChaCha20-Poly1305 MAC 先行认证、随机 nonce。
2. 密钥材料生命周期：DKM/MEK/pepper/分片等敏感缓冲 `verthys_secure_zero` 覆盖主路径与失败路径（keymanager.c、unlock_pipeline.c、rekey_auto.c、pepper.c 已逐读确认）；CNG 导入后用户态副本清零（key_separation.c）。
3. 常量时间比较 `ct_memcmp` 用于超级块 HMAC 判定（superblock_v3.c:43-49）。
4. FlatBuffers 全部 "verifier → 语义校验 → 字段读取" 分层，向量长度漂移即拒（superblock/LSM manifest/温缓存三处已逐读确认）。
5. WAL：帧边界/ct_len/记录长度全校验；撕裂尾部静默截断且游标不越过；nonce 计数器恢复带裕量（防回退、防复用）；组分终结分类（commit/prepare+sb_txid/丢弃）完备。
6. 超级块三副本法定人数 + 故障注入（fail_mask）+ 写后读验证 + fsync(_commit)。
7. `.def` 白名单导出 + CI dumpbin 比对 + python/Rust AST 双重静态门。
8. 编译加固落地：CFG/CET/ASLR/DEP/GS/sdl/LTCG/符号剥离；偏差留痕注释规范。
9. 测试基建：250 项全部真实断言（含 AEAD 篡改、密钥敏感性、UAF 回归 8 项、属性/种子化、崩溃无复活、quorum 故障注入）；临时文件沙箱 `<exe_dir>test_scratch_<pid>` + atexit 自动清理。
10. Rust 侧：`Zeroizing<String>`/`SecuredString`（Drop zeroize）、DPAPI 绑机绑用户、高安全命令一次性 auth_token 校验、PBKDF2-HMAC-SHA256 100k（仅状态文件用途，主加密在 C 核）。
11. 前端：localStorage 仅存非敏感项（feature flags/预设代号/熔断状态），未发现密钥/口令驻留；v-html 仅 1 处且为静态模板（vTip.ts）。
12. 依赖锁定：Cargo.lock、package-lock.json、C 侧全 vendored（flatcc/xxhash 全量入库）。
13. 文档：25 篇 docs（ADR/安全设计/测试/部署/数据流等），治理条款（留痕、门禁）成体系。
14. 仓库卫生：build 产物、.webview-data、appdata、dist、binaries 均未被 git 跟踪。

---

## 6. 修复优先级

| 优先级 | 编号 | 项 | 性质 | 成本估计 |
|---|---|---|---|---|
| 立即 | P0-1 | libsodium 仓储结构修复 | 阻断一切协作/CI | 低（半小时内可完成） |
| 本周 | P2-3 | CI paths 补 third_party | 门绕过 | 极低 |
| 本周 | P2-1 | vcpkg.json 处置 + 版本统一入口 | 供应链误导 | 低 |
| 本周 | P2-2 | vendor 哈希清单补全 + 校验门 | 供应链 | 低 |
| 两周内 | P2-4 | Rust/前端 CI job | 回归覆盖 | 中 |
| 两周内 | P2-5 | 诊断输出收敛（需先验证内容） | 情报面 | 低-中 |
| 迭代 | P1-1 | 胡椒兜底策略治理（设计决策 + 文档 + 前端提示） | 安全权衡 | 中 |
| 迭代 | P2-6 | panic payload 脱敏 | 深度防御 | 低 |
| 迭代 | P2-7 | Argon2 校准触发条件核验 | 需验证 | 低 |
| 规划 | P3-1~P3-8 | 告警门/clang-tidy/统一日志/FFI 冒烟/SBOM/版本单一源/清理残留/tag 管理 | 工程化 | 中 |

---

## 7. 回归测试建议

- **P0-1 修复后回归**：干净克隆 → `cmake configure`（预期成功）→ 全量构建 → `verthys_tests.exe` 250/250 → dumpbin 导出面基线比对通过（命令行见 §9）。
- **P2-2 落地后**：篡改 flatcc/xxhash/libsodium 任一文件 → 哈希门预期红。
- **P1-1 若改策略**：新增用例——首启生成 pepper 持久化成功/失败两分支；pepper.bin 损坏时解锁返回 `VERTHYS_ERR_PEPPER_SOURCE`（现有语义回归）；旧容器（记录 compiled 来源）解锁兼容。
- **P2-5 收敛后**：DebugView 挂接 Release DLL 主流程 → 零输出断言（可作为冒烟脚本）。
- **通用门**：`core.yml` 现门（250 测试 + 5 目标 fuzz 冒烟 + 导出面）保持全绿；新增 Rust job 以首次跑通基线为准。

---

## 8. 工程化改进路线

- **短期（1-2 周）**：P0-1/P2-1~2-3 完成 → 协作与供应链基线恢复。
- **中期（1 个月）**：P2-4 Rust/前端 CI、P2-5 日志收敛、P1-1 胡椒策略、P3-1 告警门 + clang-tidy、P3-2 版本单一源 + 一致性门。
- **长期（季度）**：统一追踪日志（跨 C/Rust/前端 trace_id）、FFI 边界运行期契约测试、SBOM+CVE 自动扫描、git tag/CHANGELOG 自动化、WAL 组提交性能评估、`.clang-tidy` 全量清零。

---

## 9. 可执行验证命令与预期结果（本机已实测部分标 ）

```powershell
# 测试套件（已实测通过）
.\build\core\tests\Release\verthys_tests.exe
# 预期: === Summary: 250 passed, 0 failed ===  exit 0

# P0-1 证据（已实测）
git ls-tree HEAD third_party/libsodium
# 预期: 160000 commit 93a7d0d…（gitlink）
git ls-files third_party/libsodium
# 预期: 仅 1 行（gitlink），无源文件

# P0-1 修复验证（模拟干净克隆，不修改现有仓库）
git clone . <tmp> ; cmake -S <tmp> -B <tmp>/build_verify -G Ninja
# 修复前预期: configure 失败（libsodium 无源）；修复后: 成功

# 版本一致性自检
(cmake --version | Out-Null) ; Select-String -Path `
  CMakeLists.txt, verthys-tauri/src-tauri/Cargo.toml, verthys-tauri/package.json, `
  verthys-tauri/src-tauri/tauri.conf.json, verthys-tauri/verthys-worker/Cargo.toml, vcpkg.json `
  -Pattern '2\.6\.1|3\.2\.6|version'
# 预期: 除 vcpkg.json(3.2.6) 外全部 2.6.1

# Rust 侧基线（接线 CI 前先跑通）
cargo test --manifest-path verthys-tauri/src-tauri/Cargo.toml
npm --prefix verthys-tauri run type-check   # 以 package.json scripts 为准

# 静态双引擎（本地 CI）
.\ci\run_ci.ps1
# 预期: 第一级仅警告；第二级 AST 0 违规
```

---

## 10. 假设与待确认项

1. [需验证] 远端（GitHub 等）是否存在、是否已推送——本地仅 3 commits；core.yml 在远端是否曾成功运行未确认（按 gitlink 事实推断必失败）。
2. [需验证] vcpkg.json 的 3.2.6 是否有历史语义（如内部大版本计划）——当前结论按"全项目唯一冲突值且零引用"判定为死清单。
3. [需验证] OutputDebugStringA 全部输出点内容的敏感性（本次抽查未见密钥字节）。
4. [需验证] Argon2 校准触发频率（每次解锁 vs 基准复用）。
5. [需验证] `dep-versions.txt` 的生成方式与新鲜度（未见自动生成脚本）。
6. [需验证] `__blur_lab.html` 是否仍有引用（若无引用建议删除）。
7. 本报告未逐行覆盖：security/ 下全部 Windows API 交互细节（反注入路径的 API 参数正确性）、前端全部 .vue 组件的业务逻辑正确性（抽查重点为安全边界）；L2 index 的 compaction 全分支与 sstable 读取路径（抽查 manifest 解析）。建议下轮按"安全层全部 Windows API 调用"+"compaction 全量"做专项复核。
8. 性能类未做基准实测（无基准数据），perf 测试目录存在（tests/perf）——建议在 CI 接 perf_baseline 后于同机构建基线图。

---

## 11. 修复状态与验证记录（2026-09-19 严格修复）

本节记录按本报告执行的修复处置与实测验证。**所有结论均来自本机实测，无估算值。**

### 11.1 验证汇总（交付门禁实测）

| 验证项 | 命令 | 实测结果 | 状态 |
|---|---|---|---|
| C 测试套件 | `.\build\core\tests\Release\verthys_tests.exe` | 250 passed, 0 failed | ✅ |
| src-tauri 单测 | `cargo test --manifest-path verthys-tauri/src-tauri/Cargo.toml` | 296 passed, 0 failed（3.04s） | ✅ |
| worker 单测 | `cargo test --manifest-path verthys-tauri/verthys-worker/Cargo.toml` | 0 个测试（crate 无单测，纯 FFI 派发层，编译验证通过——如实记录，非伪造） | ⚠️ 如实 |
| clippy src-tauri | `cargo clippy --manifest-path verthys-tauri/src-tauri/Cargo.toml --all-targets -- -D warnings` | exit 0，零告警 | ✅ |
| clippy worker | `cargo clippy --manifest-path verthys-tauri/verthys-worker/Cargo.toml --all-targets -- -D warnings` | exit 0，零告警 | ✅ |
| clippy 双模式 | 上述两 crate × 默认 targets / `--all-targets` | 4 组合全部 exit 0 | ✅ |
| 前端类型检查 | `npm --prefix verthys-tauri run type-check`（vue-tsc --noEmit） | exit 0 | ✅ |
| 前端构建 | `npm --prefix verthys-tauri run build` | exit 0（vite build 5.00s） | ✅ |
| vendor 哈希门 | `.\ci\verify_vendor_hashes.ps1` | 819 文件哈希全一致 | ✅ |
| 打包素材门禁 | `build.rs`（release 规则 1-3） | verthys.dll 与 worker exe 哈希一致、源码不晚于产物 | ✅ |

### 11.2 逐项处置明细

**P0-1 libsodium 仓储结构** — ✅ 已修复（扁平化 vendored）
- 移除无 `.gitmodules` 的 gitlink，libsodium 1.0.20 源码 523 文件扁平入库（`third_party/libsodium/`），干净克隆即可构建。
- 配套：`ci/vendor_hashes.txt` 补全 + `ci/verify_vendor_hashes.ps1` 校验门（见 P2-2）。

**P1-1 胡椒兜底策略** — ✅ 已修复
- `core/src/crypto/pepper/verthys_pepper.c` + `core/src/api/lifecycle/verthys_v3_lifecycle.c`：**新建容器禁止 compiled pepper 降级**（新容器必须持久化 pepper，杜绝兜底常量进入新容器密钥派生）；解锁路径保留对历史容器（记录 compiled 来源）的兼容。回归：C 250/250 全绿。

**P2-1 vcpkg.json 死清单** — ✅ 已删除（git rm）。

**P2-2 vendor 哈希清单 + 校验门** — ✅ 已落地
- `ci/vendor_hashes.txt` 补全（819 文件）+ `ci/verify_vendor_hashes.ps1`；接入 core.yml 与 rust-frontend.yml 双 CI 首步（供应链门）。

**P2-3 core.yml paths 触发面** — ✅ 已补全（third_party/**、CMakeLists.txt、dep-versions.txt、ci/**、scripts/build_core.*）。

**P2-4 Rust/前端 CI + clippy 双 crate 清零** — ✅ 已完成
- 新建 `.github/workflows/rust-frontend.yml`：Rust 单测 + clippy `--all-targets -D warnings` 双 crate + npm ci + vue-tsc + vite build。
- clippy 清零统计：src-tauri **62（lib）+ 13（test target）→ 0**；worker **16 → 0**。共 25 类 lint，涉及约 60+ 文件，全部按语义等价原则修复（典型：`needless_borrow`/`redundant_closure`/`collapsible_if`/`derivable_impls`/`bool_assert_comparison`/恒真断言清除/`&[x.clone()]` → `slice::from_ref`/defense.rs Win32 命名镜像豁免 + `CStr` 规范化）。
- 修复过程发现并处理 2 处恒真断言（background_patrol.rs `assert!(r <= u64::MAX)`、secured_string.rs `assert_eq!(x, true)`）——此类为无效测试代码，已替换为有效断言或显式注释说明意图。

**P2-5 诊断输出收敛** — ✅ 已修复
- 新建 `core/include/verthys_diag.h`（`VERTHYS_DIAG` 编译门宏）+ `core/CMakeLists.txt` 增加 `VERTHYS_DIAG` option；5 处 C 文件的散点 `OutputDebugStringA` 收敛至编译门控制，Release 默认零诊断输出。

**P2-6 panic_hook.rs payload 脱敏** — ✅ 已修复（payload 截断/脱敏，不泄露敏感上下文）。

**P2-7 Argon2 校准触发条件核验** — ✅ 已核验，**无需修复**
- 实证（verthys_v3_lifecycle.c:203-237）：校准仅在**创建期**跑分一次（BALANCED/CUSTOM 档，目标 1200ms，迭代 ∈ [1,3]），参数持久化于超级块；解锁按存储参数派生，不重复校准；SECURE 档固定 64MiB/3/1 合规确定性；校准失败回退 `VERTHYS_ARGON2_BALANCED_ITERS` 兜底。设计正确。

**P3-5 调试残留文件** — ✅ `verthys-tauri/__blur_lab.html` 已删除。

### 11.3 CI 素材硬依赖实证（修复过程中发现的阻断性问题）

对 rust-frontend.yml 首版做"模拟干净检出"实验（隐藏 verthys.dll / worker exe / dist 后 `cargo check`）：

| 素材 | tauri.conf.json 声明 | 隐藏后 cargo check | 结论 |
|---|---|---|---|
| `verthys.dll` | resources | **失败**：`resource path ... doesn't exist` | 编译期硬依赖 |
| `binaries/verthys-worker-*.exe` | externalBin | **失败**：`resource path ... doesn't exist` | 编译期硬依赖 |
| `dist/`（前端产物） | frontendDist | 通过（dev profile 下 `cfg=dev` 豁免） | 非硬依赖 |

四素材均为 gitignore 的本地构建产物（.gitignore:33-34、verthys-tauri/.gitignore:11），CI 全新检出必然缺失 → **rust-frontend.yml 已重写**：Rust 测试/clippy 之前依次执行 vendor 哈希门 → MSVC x64 → CMake Ninja Release 构建 verthys.dll → `cargo build --release` 构建 worker exe → 双素材就位至 src-tauri。本地模拟实验后素材已全部恢复（RESTORED 验证）。

### 11.4 遗留项声明（未修复，移交后续迭代）

| 项 | 状态 | 说明 |
|---|---|---|
| P3-1 clang-tidy 告警门 | 遗留 | .clang-tidy 已配置但无执行入口，建议接入 CI |
| P3-2 版本号单一源 | 遗留 | 6 处多源维护，建议根 VERSION 文件 + 构建期注入 |
| P3-3 C 侧结构化日志/trace_id | 遗留 | P2-5 已收敛输出面，结构化改造待做 |
| P3-4 FFI 边界冒烟测试 | 遗留 | 测试仍直链对象库，不经 DLL 导出边界 |
| P3-6 git tag/CHANGELOG 规范 | 遗留 | 历史仅 3 commit 无 tag |
| P3-7 依赖漏洞扫描/SBOM | 遗留 | 未接 osv-scanner/cargo-audit |
| P3-8 WAL 组提交性能评估 | 遗留 | 耐久性优先设计，非缺陷，待基准数据 |
| CI 远端首跑 | **待验证** | rust-frontend.yml 为新建流程，远端（GitHub Actions windows-latest）首跑结果待推送后确认；本地已按干净检出语义模拟验证素材前置完备 |

### 11.5 安全与兼容性影响

- **P1-1 行为变更**：新建容器不再允许 compiled pepper 降级（若 pepper 持久化失败，创建显式失败而非静默降级）——这是有意的安全收紧；历史容器解锁兼容不受影响。C 250 测试含 pepper 分支用例全绿。
- **P2-5 行为变更**：Release DLL 默认不再输出任何 OutputDebugStringA 诊断（VERTHYS_DIAG 编译门，默认关闭），缩小运行期情报面。
- **clippy 修复**：全部为语义等价重构（恒等 map_err 移除依赖 `PrefetchTaskHandle::drop` 的 cancel+关闭通道安全网，scan_pipeline.rs:259-265 已核验），无行为变更；296 单测全绿佐证。
- **素材同步**：本地 verthys.dll / verthys-worker.exe 已按 release 重建并就位，build.rs 三规则门禁通过。