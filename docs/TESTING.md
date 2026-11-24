# 测试说明（TESTING）

> 测试分层、全量/单项跑法、覆盖率现状与要求、关键场景用例与 Rust 侧测试。
>
> Last updated: 2026-11-17 · 维护人：K1Super

C 核心测试为单一聚合可执行文件 `verthys_tests`（`core/tests/CMakeLists.txt` 的 `add_executable` 汇总当前测试源文件），与两个独立进程的 ACG 专项共注册为 3 个 ctest 测试项（主测试 + `verthys_scd_acg` + `verthys_scd_dll_acg`）。用例数量随代码变化，以实际运行输出为准，不在文档中抄录固定值。

## 1. 测试分层（按 `core/tests/` 实际目录）

| 目录 | 目的 | 代表用例 |
|---|---|---|
| `api/` | 公共 C ABI：容器创建/解锁/扫描/导出导入/轮换 | `api_*`、`transfer_*`、`rotate_*` |
| `crypto/` | 密码学原语、胡椒、keyfile | `aead_roundtrip`、`pepper_*`、`keyfile_*` |
| `container/` | 容器格式、模块槽、分片 | `container_*`、`modules_*`、`chunks_*` |
| `index/` | 记录/存储/仓库 | `records_*`、`store_*`、`repo_*` |
| `security/` | 预设/完整性/反调试/内存/应急/六层防御/熔断/回滚/见证 | `lockout_*`、`rollback_*`、`witness_*`、`rhat_*`、`dcl_*` |
| `perf/` | 性能基准与回归 | `perf_*` |
| `schema/` | vendored flatcc 工具链全链路 | `flatcc_demo_*` |

前端全量：`Set-Location verthys-tauri; npx vitest run`（用例数量以实际输出为准）。

## 2. 如何跑全部测试

```powershell
# 生产构建目录（Release）：3 个 ctest 测试项（主测试 + 两个 ACG 专项）
ctest --test-dir build -C Release --output-on-failure

# 或直接运行测试 exe（Release 配置，输出以 "=== Summary: N passed, M failed ===" 结尾）
& ".\build\core\tests\Release\verthys_tests.exe"

# 开发构建（Debug）：scripts/build/build_core.dev.ps1 会 configure + build + 强制运行测试
powershell -ExecutionPolicy Bypass -File .\scripts\build\build_core.dev.ps1 -Clean -NoPause
```

CI（`.github/workflows/core.yml`）用 `ctest --test-dir build_ci -C Debug --output-on-failure --no-tests=error` 跑全部已注册测试（Ninja 布局的测试可执行文件位于 `build_ci/core/` 与 `build_ci/core/tests/`）、退出码非 0 判失败。

## 3. 单项测试运行法

`verthys_tests.exe` 支持 argv 子串过滤器（`core/tests/test_runner.c` 的 `test_filter_match` 与 argv 解析段）：第一个参数为子串，`argv[2..]` 为额外 OR 过滤器；无参数全量运行。

```powershell
# 只运行名称含 "aead" 的用例
& ".\build\core\tests\Release\verthys_tests.exe" aead

# 多组联合（OR）
& ".\build\core\tests\Release\verthys_tests.exe" repo lockout
```

ctest 层级仅能按注册名过滤（主测试 1 项 + 两个 ACG 专项）：

```powershell
ctest --test-dir build -C Release -R verthys_tests
```

## 4. 已删除的旧代测试

旧代容器、LSM、WAL、事务、超级块、温缓存与属性测试已随旧实现整体删除；
当前测试只覆盖容器与共享安全/密码学能力。历史用例清单已随旧代审计文档删除。

## 5. 覆盖率要求

- 要求：核心逻辑单元测试覆盖率 ≥ 80%（对应 `docs/REQUIREMENTS.md` NFR-04“生产级标准”）。
- 现状：当前未配置覆盖率采集。全仓仅 `VERTHYS_ENABLE_ASAN` 一个构建开关（`core/CMakeLists.txt` 的 ASAN 段），无 gcov/`--coverage`/代码覆盖率选项，无覆盖率报告产物。
- 接入建议：新增 CMake 开关（如 `VERTHYS_ENABLE_COVERAGE`）对 `verthys_core_obj` + `verthys_tests` 启用 MSVC `/PROFILE` 或 LLVM source-based coverage，配合覆盖率工具产出报告，并将“core/src 核心逻辑覆盖率 ≥ 80%”接入 CI 质量门。

## 6. 关键场景用例表（以实际测试名称为准）

| 场景 | 用例 |
|---|---|
| 解锁（成功/失败/锁定） | `api_*`、`lockout_*`、`security_state_*` |
| 加解密（AEAD/胡椒/keyfile/密钥派生） | `aead_roundtrip`、`aead_tamper_fails`、`pepper_*`、`keyfile_*` |
| 容器格式/模块/分片 | `container_*`、`modules_*`、`chunks_*`、`fuzz_*` |
| 仓库读写/扫描 | `repo_*`、`store_*`、`records_*` |
| 完整性/防篡改 | `integrity_*`、`rhat_*`、`rollback_*`、`witness_*` |
| 七路径事实判定 | `dcl_facts_*` |
| Hook 扫描状态机 | `hook_scan_*` |
| 挂起看门狗 | `suspend_watchdog_terminates_suspended_worker`（A18S，需 `VERTHYS_A18=1`） |

## 7. Rust 侧测试

```powershell
# 主应用 crate（src-tauri）：测试数量以实际输出为准，含 2 个 ignored
Set-Location .\verthys-tauri\src-tauri
cargo test
```

主应用 Rust 单元测试含 `verthys_wal.rs` 断点续传/压缩/续传去重（需 `[dev-dependencies] tempfile`，见 `src-tauri/Cargo.toml`）。

```powershell
# verthys-worker：测试数量以实际输出为准（#[cfg(test)] mod tests，分布于 runtime/gmk、main_loop、scan_shm、worker）
Set-Location .\verthys-tauri\verthys-worker
cargo test
```

## 7.1 挂起看门狗端到端用例（A18S）

```powershell
# 真实 worker + 心跳 + 挂起看门狗；健康期不得误杀，挂起全部线程后 3s 级触发处置并终止 worker
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile standard -OutDir build/security-vault
```

统一入口的 `VAULT-A18S` 覆盖该用例。需要单独复现时仍可运行执行器 `tests/attack/a18-suspend.ps1`，但该脚本不作为 CI/门禁事实源。执行器设置 `VERTHYS_A18=1` 后驱动 `suspend_watchdog_terminates_suspended_worker`，输出 `RESULT A18S PASS|FAIL <detail>` 与实测毫秒；常规 `cargo test` 不执行该进程级实验。

## 8. 更新域测试

```powershell
# Rust 更新服务：清单解析、签名复验、PE 版本、标记、灰度桶
Set-Location .\verthys-tauri\src-tauri
cargo test updater

# 前端更新状态机与锁库闸门
Set-Location .\verthys-tauri
npx vitest run src/composables/useAppUpdater.spec.ts src/session/security-session.spec.ts

# 清单生成脚本与 profile 静态门
node --check scripts/release/make_updater_manifest.mjs
node scripts/gates/check_updater_profile.mjs verthys-tauri/src-tauri/tauri.local.conf.json --profile local
```

更新域 E2E 使用本机运行时矩阵：旧版基线安装包、新版真实签名物料、本机回环服务与 `scripts/updater/updater_e2e_matrix.mjs`；正向升级后必须核对容器可解锁与记录数一致，负向用例必须复核旧版仍可启动。

## 9. 攻击回归

非内核攻击回归统一走 `tests/security/run.ps1`，入口、profile、退出码与 ID 映射见 `tests/security/README.md`。`tests/attack/**` 与 `tests/service/attack.ps1` 仍是执行器，由 `tests/security/suites/*.ps1` 适配，不再直接作为 CI 事实源。

```powershell
# 容器/核心全量（standard）
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile standard -OutDir build/security-vault

# harness 正控（仅 CTRL-BC1）
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile baseline -OutDir build/security-baseline

# P2 服务控制台子集（S-A3/A4/A5/A6/A8/A9）
pwsh -NoProfile -File tests/security/run.ps1 -Suite service -Profile standard `
  -OutDir build/security-service -ServiceBuildDir build_security_service_ci

# vTPM 能力证据
pwsh -NoProfile -File tests/security/run.ps1 -Suite tpm -Profile standard `
  -OutDir build/security-tpm -TpmProbe build/core/tests/Release/vty_tpm_probe.exe

# 离机证据：源机 prepare，目标机 verify
pwsh -NoProfile -File tests/security/run.ps1 -Suite offmachine -OffmachineMode prepare -OffmachineDir C:\A6
pwsh -NoProfile -File tests/security/run.ps1 -Suite offmachine -OffmachineMode verify -OffmachineDir C:\A6
```

- 每次运行输出 `result.json`、`result.junit.xml`、`result.sarif`、`summary.md`；执行器原始 JSON 复制到 `evidence/<runId>/`。
- `release` 下必需项必须 PASS；`VAULT-A06` 缺失离机报告为 `BLOCKED`，`VAULT-A08`/`VAULT-A18S` 不得 SKIP。CI 使用 `standard`，发布签署在具备离机证据与非提权会话的主机上执行 `release`。
- `A17`/`A20`/`A20b` 注册为 `static`，只证明静态约束在场，不计入行为覆盖率。
- `A18` 为 keyfile 因子绕过，`A18S` 为 worker 挂起处置；两者编号独立，避免覆盖。
- `A18S` 使用真实 worker + 心跳 + 挂起看门狗，健康期误杀与 3s 级处置均纳入判定。
- `A6`（离机 + 已知模块口令）只有绑定当前 DLL/worker 哈希的合格报告才计 PASS，否则在统一模型中为 `BLOCKED`。
- 桌面 `attack-forge` / `AttackTest` 是外部演练工具，不纳入 CI，也不作为发布证据。

## 10. P2 机器级安全服务测试

```powershell
# 独立工程单元测试（U1–U12；需测试钩子构建）
pwsh -NoProfile -File scripts/build/build_security_service.ps1 `
  -BuildDir build_security_service_ci -Profile local -TestHooks -RunTests -NoSign

# 控制台集成 I0–I12（不安装 SCM，不触碰真实 ProgramData/HKLM）
pwsh -NoProfile -File tests/service/integration.ps1 -BuildDir build_security_service_ci

# P2 攻击回归控制台子集（统一入口）
pwsh -NoProfile -File tests/security/run.ps1 -Suite service -Profile standard `
  -OutDir build/security-service -ServiceBuildDir build_security_service_ci

# 干净 VM 提权 E2E（默认 SKIP；需 -AllowElevatedE2E）
pwsh -NoProfile -File tests/service/e2e-install.ps1 -Artifacts build_security_service_ci\Debug -AllowElevatedE2E
```

`tests/service/attack.ps1` 仍可直接运行，支持 `-OutJson` 与 `-ResultIdPrefix`，但 CI 与门禁读取统一入口的结构化结果。

- 服务安装/卸载通过 `VerthysSecuritySvc.exe /install /quiet`、`/uninstall /quiet` 子命令执行；独立 `VerthysSecurityServiceSetup.exe` 已淘汰。
- 应用安装包 E2E：干净 VM 标准用户双击 perMachine 安装包 → 一次 UAC → 安装器 POSTINSTALL 安装服务并 Running；取消 UAC 后无 Program Files 目录、服务、注册表、根 CA；卸载后服务、CA、事件源、ProgramData、卸载项全部清除且用户加密库保留。

- core 客户端 C1–C8 与 V4 接入级用例在 `VERTHYS_TEST_HOOKS=ON` 构建中注册；默认测试钩子构建不访问真实服务，未显式注入 `VERTHYS_TEST_SERVICE_INSTALLED` 时按“未安装”fail-closed。P1 回归由 `test_runner` 显式设置测试旁路；进入机器预算用例组时撤销旁路，验证服务未安装、管道不可达、预算耗尽三种情况下 V4 解锁与模块解锁均返回 RATE，组结束后恢复旁路。产品构建不包含旁路。
- `tests/e2e/worker-smoke.ps1` 与 `tests/e2e/rotate-host.ps1` 使用测试钩子 DLL，显式设置 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS=1` 与 `VERTHYS_TEST_STATE_DIR`；熔断/回滚状态走 KnownFolder，仅覆盖 `LOCALAPPDATA` 不足以隔离。自动化测试构建（`VERTHYS_TEST_REQUIRE_ISOLATION=ON`）缺少隔离目录会直接拒绝初始化；dev 运行构建不强制隔离，以便操作真实容器。
- 服务单元测试含事件日志消息表校验：10 个事件 ID 通过 `FormatMessage` 解析，共 446 断言通过。
- 生产 OFF 钩子测试可执行文件链接缺陷已修复（`test_witness.c` 仅在测试钩子构建调用派生函数）；执行仍需要已安装服务或测试夹具。
- 本机实测（测试钩子构建）：机器预算客户端 8/8、V4 解锁/模块解锁接入 2/2、`api_` 15/15、`format_` 15/15、`module_` 15/15；生产 OFF 钩子 core DLL 与测试 exe 构建/链接通过，生产 DLL 不含测试钩子字符串。
- P1 全量 + 新增接入用例实测 280 passed / 0 failed（2026-11-11 快照，测试钩子构建，Release）。lockout 用例对测试机 CNG 见证键累积与残留线程敏感，复跑异常时先用 `tests/gate.ps1` 的 hygiene 流程回收见证键，再复核全量。
- P1 攻击回归以当前测试钩子构建经统一入口执行：PASS=23、BLOCKED=2（A2 需要管理员写入 Root 存储；A6 缺少绑定当前构建的离机报告）、FAIL=0。standard 退出码 0；release 需在提权且具备离机证据的主机执行。
- 正向 Authenticode 认证需要把测试证书导入 `CurrentUser\Root`；无交互桌面环境无法完成信任导入，本机只执行了未签名拒绝与伪造服务端拒绝的负向用例。正向签名探针与模块校验在干净 VM E2E 中验证。
- S-A1/S-A2/S-A7/S-A10 与 E1–E8 需要真实 SCM 安装、管理员权限或第二台机器，只在干净 VM 执行并保存 `sc query`、`icacls`、事件日志与探针输出证据。

## 11. AST 架构门禁与基线治理

`ci/run_ci.ps1` 第二级执行 `ci/ast_analyze`，按分层契约阻断反向导入、入口危险调用、静默吞错与 C 输出函数。

- 基线格式：`category|file|detail|count`，指纹不含行号；行号漂移不会产生新违规。
- 新增违规阻断；基线条目已不存在时按 `STALE` 阻断，避免豁免腐烂。
- 重写基线：`cargo run --release --manifest-path ci\ast_analyze\Cargo.toml -- --write-baseline ci\ast_baseline.txt`；命令会打印新增/移除条目，必须在评审中逐条说明。
- 当前基线为 0 条豁免；新增豁免必须同时说明原因与退出条件。

## 12. 第一级文本门禁

`ci/regex_scan.py` 先剥离注释、字符串与字符字面量，并整体屏蔽 `#[cfg(test)]` 代码，再检查入口危险关键词、Rust 直写 stdout/stderr 与 C 输出函数。

- `run_ci.ps1` 先执行 `python ci\regex_scan.py --self-test`，自检失败按 CI 失败处理。
- 扫描结果仍只告警、不阻断；依赖方向由第二级 AST 统一判定，第一级不重复实现。