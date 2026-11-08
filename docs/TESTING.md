# 测试说明（TESTING）

> 测试分层、全量/单项跑法、覆盖率现状与要求、关键场景用例与 Rust 侧测试。
>
> Last updated: 2026-11-03 · 维护人：K1Super

C 核心测试为单一聚合可执行文件 `verthys_tests`（`core/tests/CMakeLists.txt` 的 `add_executable` 汇总当前测试源文件），与两个独立进程的 ACG 专项共注册为 3 个 ctest 测试项（主测试 + `verthys_scd_acg` + `verthys_scd_dll_acg`）；主测试当前 270 个 `TEST()` 用例。

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

前端全量：`Set-Location verthys-tauri; npx vitest run`（当前 74 文件 / 795 用例）。

## 2. 如何跑全部测试

```powershell
# 生产构建目录（Release）：3 个 ctest 测试项（主测试 270 用例 + 两个 ACG 专项）
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
# 主应用 crate（src-tauri）：555 个测试通过 + 2 ignored，分布于 controller/*、service/*、util/* 等
Set-Location .\verthys-tauri\src-tauri
cargo test
```

主应用 Rust 单元测试含 `verthys_wal.rs` 断点续传/压缩/续传去重（需 `[dev-dependencies] tempfile`，`src-tauri/Cargo.toml:196-199`）。

```powershell
# verthys-worker：68 个测试用例（#[cfg(test)] mod tests，分布于 runtime/gmk、main_loop、scan_shm、worker）
Set-Location .\verthys-tauri\verthys-worker
cargo test
```

## 7.1 挂起看门狗端到端用例（A18S）

```powershell
# 真实 worker + 心跳 + 挂起看门狗；健康期不得误杀，挂起全部线程后 3s 级触发处置并终止 worker
pwsh -NoProfile -File tests/attack/a18-suspend.ps1
```

该脚本设置 `VERTHYS_A18=1` 后驱动 `suspend_watchdog_terminates_suspended_worker`，输出 `RESULT A18S PASS|FAIL <detail>` 与实测毫秒；常规 `cargo test` 不执行该进程级实验。

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

```powershell
# 全量攻击回归（A1/A2/A3/A4/A5/A6b/A7/A8/A9/A10~A18/A20/A20b/A18S），输出机器可读证据
pwsh -NoProfile -File tests/attack/run.ps1 -OutJson build/attack-final.json
```

- `A18` 为 keyfile 因子绕过，`A18S` 为 worker 挂起处置；两者编号独立，避免覆盖。
- `A18S` 使用真实 worker + 心跳 + 挂起看门狗，健康期误杀与 3s 级处置均纳入判定。
- `A6`（离机 + 已知模块口令）只有绑定当前 DLL/worker 哈希的合格报告才计 PASS，否则保持 SKELETON。

## 10. P2 机器级安全服务测试

```powershell
# 独立工程单元测试（U1–U12；需测试钩子构建）
pwsh -NoProfile -File scripts/build/build_security_service.ps1 `
  -BuildDir build_security_service_ci -Profile local -TestHooks -RunTests -NoSign

# 控制台集成 I0–I12（不安装 SCM，不触碰真实 ProgramData/HKLM）
pwsh -NoProfile -File tests/service/integration.ps1 -BuildDir build_security_service_ci

# P2 攻击回归控制台子集（S-A3/A4/A5/A6/A8/A9）
pwsh -NoProfile -File tests/service/attack.ps1 -BuildDir build_security_service_ci

# 干净 VM 提权 E2E（默认 SKIP；需 -AllowElevatedE2E）
pwsh -NoProfile -File tests/service/e2e-install.ps1 -Artifacts build_security_service_ci\Debug -AllowElevatedE2E
```

- 服务安装/卸载通过 `VerthysSecuritySvc.exe /install /quiet`、`/uninstall /quiet` 子命令执行；独立 `VerthysSecurityServiceSetup.exe` 已淘汰。
- 应用安装包 E2E：干净 VM 标准用户双击 perMachine 安装包 → 一次 UAC → 安装器 POSTINSTALL 安装服务并 Running；取消 UAC 后无 Program Files 目录、服务、注册表、根 CA；卸载后服务、CA、事件源、ProgramData、卸载项全部清除且用户加密库保留。

- core 客户端 C1–C8 与 V4 接入级用例在 `VERTHYS_TEST_HOOKS=ON` 构建中注册；默认测试钩子构建不访问真实服务，未显式注入 `VERTHYS_TEST_SERVICE_INSTALLED` 时按“未安装”fail-closed。P1 回归由 `test_runner` 显式设置测试旁路；进入机器预算用例组时撤销旁路，验证服务未安装、管道不可达、预算耗尽三种情况下 V4 解锁与模块解锁均返回 RATE，组结束后恢复旁路。产品构建不包含旁路。
- `tests/e2e/worker-smoke.ps1` 与 `tests/e2e/rotate-host.ps1` 使用测试钩子 DLL，显式设置 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS=1` 与 `VERTHYS_TEST_STATE_DIR`；熔断/回滚状态走 KnownFolder，仅覆盖 `LOCALAPPDATA` 不足以隔离。
- 服务单元测试含事件日志消息表校验：10 个事件 ID 通过 `FormatMessage` 解析，共 446 断言通过。
- 生产 OFF 钩子测试可执行文件链接缺陷已修复（`test_witness.c` 仅在测试钩子构建调用派生函数）；执行仍需要已安装服务或测试夹具。
- 本机实测（测试钩子构建）：机器预算客户端 8/8、V4 解锁/模块解锁接入 2/2、`api_` 15/15、`format_` 15/15、`module_` 15/15；生产 OFF 钩子 core DLL 与测试 exe 构建/链接通过，生产 DLL 不含测试钩子字符串。
- P1 全量 + 新增接入用例实测 280 passed / 0 failed（测试钩子构建，Release）。lockout 用例对测试机 CNG 见证键累积与残留线程敏感，复跑异常时先用 `tests/gate.ps1` 的 hygiene 流程回收见证键，再复核全量。
- P1 攻击回归以当前测试钩子构建执行：PASS=20、FAIL=4（A2/A8/A18S，依赖签名宿主/内存转储/worker 产物）、SKIP=1；属于 P1 既有门禁环境，不是 P2 回归。
- 正向 Authenticode 认证需要把测试证书导入 `CurrentUser\Root`；无交互桌面环境无法完成信任导入，本机只执行了未签名拒绝与伪造服务端拒绝的负向用例。正向签名探针与模块校验在干净 VM E2E 中验证。
- S-A1/S-A2/S-A7/S-A10 与 E1–E8 需要真实 SCM 安装、管理员权限或第二台机器，只在干净 VM 执行并保存 `sc query`、`icacls`、事件日志与探针输出证据。