# 测试说明（TESTING）

> 测试分层、全量/单项跑法、覆盖率现状与要求、关键场景用例与 Rust 侧测试。
>
> Last updated: 2026-09-22 · 维护人：K1Super

C 核心测试为单一聚合可执行文件 `verthys_tests`（`core/tests/CMakeLists.txt:7-47` 编译 39 个源文件），注册为 1 个 ctest 测试项（`core/tests/CMakeLists.txt:90`），内含 296 个 `TEST()` 用例（`test_runner.c` 中 296 个 `RUN_TEST` 与之一一对应）。模糊测试在 `-DVERTHYS_ENABLE_FUZZ=ON` 时额外注册 5 个冒烟测试项。

## 1. 测试分层（按 `core/tests/` 实际目录）

| 目录 | 目的（对应 core/CMakeLists.txt 分层注释 :14-31） | 代表用例 |
|---|---|---|
| `api/` | L5 公共 C ABI：lifecycle/unlock/scan/transfer | `api_full_roundtrip`、`v3life_full_chain_roundtrip` |
| `crypto/` | L0 密码学原语：AEAD/HMAC/密钥派生/CNG | `aead_roundtrip`、`master_key_derive_deterministic`、`cng_aead_roundtrip` |
| `container/` | L1 容器格式：format/superblock/partition/extent | `v3sb_serialize_parse_roundtrip`、`v3part_encrypt_decrypt_roundtrip`、`v3ext_put_get_roundtrip` |
| `index/` | L2 索引：LSM（MemTable+SSTable+Compaction） | `v3lsm_put_get_roundtrip`、`v3lsm_wal_crash_recovery` |
| `transaction/` | L3 事务一致：WAL 环形双区 + 六阶段事务 | `inject_sb_ciphertext_bitflip_rejected` |
| `security/` | L6 深度安全：预设/完整性/反调试/内存/应急/六层防御 | `keysep_aead_roundtrip`、`rhat_virtualprotect_patch_detected`、`dcl_all_seven_blocked_when_unlocked` |
| `property/` | 属性测试（自研 harness，无外部框架）：随机序列 + 不变式断言 | `prop_lsm_insert_find_delete`、`prop_txn_commit_rollback_consistency` |
| `perf/` | 性能基准与回归 | `perf_baseline_unlock_write_read`、`perf_warm_cache_hit_on_second_unlock` |
| `regression/` | 缺陷回归（最终修复方案 §6.1） | `repair_pool_extend_boundary` |
| `schema/` | vendored flatcc 工具链全链路 | `flatcc_demo_roundtrip` |
| `fuzz/` | libFuzzer 模糊测试（独立构建） | `fuzz_superblock`、`fuzz_partition`、`fuzz_extent`、`fuzz_sstable`、`fuzz_import` |

## 2. 如何跑全部测试

```powershell
# 生产构建目录（Release），单一聚合测试 verthys_tests（296 用例）
ctest --test-dir build -C Release --output-on-failure

# 或直接运行测试 exe（Release 配置，输出以 "=== Summary: N passed, M failed ===" 结尾）
& ".\build\core\tests\Release\verthys_tests.exe"

# 开发构建（Debug）：scripts/build_core.dev.ps1 会 configure + build + 强制运行测试
powershell -ExecutionPolicy Bypass -File .\scripts\build_core.dev.ps1 -Clean -NoPause
```

CI（`.github/workflows/core.yml:93-97`）直接运行 `.\build_ci\core\verthys_tests.exe`（Ninja 布局）、退出码非 0 判失败。

### 模糊测试冒烟门

```powershell
# 独立构建目录 build_fuzz（-DVERTHYS_ENABLE_FUZZ=ON，MSVC /fsanitize=fuzzer+address）
powershell -ExecutionPolicy Bypass -File .\scripts\build_core.fuzz.ps1 -SmokeOnly -NoPause
# 等价底层命令（scripts/build_core.fuzz.ps1:54-57）
ctest -C Debug --test-dir build_fuzz -R "fuzz_.*_smoke" --output-on-failure --no-tests=error
```

## 3. 单项测试运行法

`verthys_tests.exe` 支持 argv 子串过滤器（`core/tests/test_runner.c:400-428`）：第一个参数为子串，`argv[2..]` 为额外 OR 过滤器；无参数全量运行。

```powershell
# 只运行名称含 "aead" 的用例
& ".\build\core\tests\Release\verthys_tests.exe" aead

# 多组联合（OR）
& ".\build\core\tests\Release\verthys_tests.exe" v3sb quorum
```

ctest 层级仅能按注册名过滤（主测试仅 1 项）：

```powershell
ctest --test-dir build -C Release -R verthys_tests
# 模糊目标单项冒烟
ctest --test-dir build_fuzz -C Debug -R fuzz_superblock_smoke --output-on-failure
```

## 4. fuzz / property 说明

- fuzz（`core/tests/fuzz/`，5 目标）：测试各容器解析器在认证闭环之外的独立内存安全（“解析层缺陷不得依赖加密层兜底”，`fuzz_superblock.c:1-20`）。语料由 `gen_seeds` 按生产序列化路径镜像生成合法明文帧；判定“任何崩溃/ASAN 报告/挂起 = 失败”，harness 不断言返回值。工具链为 MSVC `libFuzzer` + `/fsanitize=address`（须写成两个独立选项，不能用逗号组合，`core/tests/fuzz/CMakeLists.txt:16-18`）。持续模糊每目标 10 分钟（`-max_total_time=600`，CI `core.yml:109-122`）。
- property（`core/tests/property/test_v3_property.c:1-39`）：自研 harness（splitmix64 确定性 PRNG + 不变式断言 + 失败种子/步号可复现），覆盖 LSM“插入后必可找到”、Extent 引用计数守恒、事务 commit/rollback 后超级块与 WAL 一致、回滚耐久性（复活窗口回归）四类不变式。

## 5. 覆盖率要求

- 要求：核心逻辑单元测试覆盖率 ≥ 80%（`docs/ENGINEERING_CONSTRAINTS.md` 1.4“生产级标准”）。
- 现状：当前未配置覆盖率采集。全仓仅两个 CMake 开关 `VERTHYS_ENABLE_ASAN`、`VERTHYS_ENABLE_FUZZ`（`core/CMakeLists.txt:45-56`），无 gcov/`--coverage`/代码覆盖率选项，无覆盖率报告产物。
- 接入建议：新增 CMake 开关（如 `VERTHYS_ENABLE_COVERAGE`）对 `verthys_core_obj` + `verthys_tests` 启用 MSVC `/PROFILE` 或 LLVM source-based coverage，配合覆盖率工具产出报告，并将“core/src 核心逻辑覆盖率 ≥ 80%”接入 CI 质量门。

## 6. 关键场景用例表（以实际测试名称为准）

| 场景 | 用例 |
|---|---|
| 解锁（成功/失败/锁定/温缓存） | `api_wrong_password`、`api_lock_unlock_same_file`、`v3life_unlock_minimal_first`、`v3life_warmcache_hit_miss_tamper` |
| 加解密（AEAD/CNG/密钥派生/篡改） | `aead_roundtrip`、`aead_tamper_fails`、`cng_aead_roundtrip`、`keysep_aead_roundtrip`、`master_key_derive_deterministic` |
| 事务提交/回滚 | `v3sb_txn_commit_rollback`、`prop_txn_commit_rollback_consistency` |
| WAL 重放 | `v3lsm_wal_crash_recovery`、`v3life_crash_committed_replayed`、`v3life_crash_uncommitted_discarded` |
| 容器魔数/schema 校验 | `format_bad_magic_rejected`、`v3sb_parse_garbage_rejected`、`inject_bad_magic_rejected` |
| 完整性/防篡改 | `integrity_verify_unconfigured_passes`、`v3life_verify_integrity_tamper`、`rhat_virtualprotect_patch_detected` |

## 7. Rust 侧测试

```powershell
# 主应用 crate（src-tauri）：单元测试分布于 controller/*、service/*、util/* 等
Set-Location .\verthys-tauri\src-tauri
cargo test
```

主应用 Rust 单元测试含 `verthys_wal.rs` 断点续传/压缩/续传去重（需 `[dev-dependencies] tempfile`，`src-tauri/Cargo.toml:196-199`）。

```powershell
# verthys-worker：18 个测试用例（#[cfg(test)] mod tests，分布于 runtime/gmk、main_loop、scan_shm、worker）
Set-Location .\verthys-tauri\verthys-worker
cargo test
```