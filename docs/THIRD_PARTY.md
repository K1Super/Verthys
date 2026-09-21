# 第三方依赖与供应链
> 第三方库清单、版本来源、引入理由、许可证、升级策略与供应链安全关联。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档按“单一事实来源”原则：版本/依赖以 `vcpkg.json`、`dep-versions.txt`、`third_party/`
下实际文件、`verthys-tauri/src-tauri/Cargo.toml`（及 Cargo.lock）、`verthys-tauri/package.json` 为准，
文档只引用文件路径，不整表抄录版本清单。

## 1. 版本来源总览

| 域 | 事实来源文件 |
|---|---|
| C/C++ 包声明 | 根 `vcpkg.json`（`name: verthys`、`version-string: 3.2.6`、依赖 `libsodium`、`builtin-baseline` 全 0） |
| C/C++ vendored 源码 | `third_party/libsodium`、`third_party/flatcc`、`third_party/xxhash/xxhash.h` |
| Rust 锁定版本 | `verthys-tauri/src-tauri/Cargo.toml`（直接依赖 `=x.y.z` 锁定）+ `verthys-tauri/src-tauri/Cargo.lock` 及根 `dep-versions.txt`（Cargo.lock 镜像，`version = 4` 为 lock 格式版本） |
| 前端依赖 | `verthys-tauri/package.json`（+ `package-lock.json`） |

> 版本差异照实说明：项目版本 2.6.1（CMakeLists.txt / package.json / Cargo.toml 一致）；
> `vcpkg.json` 的 `version-string` 为 `3.2.6`，二者不一致，引用时按各自文件原值记录。

## 2. C/C++ 依赖

### 2.1 vendored（构建脚本直接集成，见 `third_party/*.cmake` 注释）
| 依赖 | 版本（来源） | 许可证（随仓库文件） | 引入理由 | 用途模块 |
|---|---|---|---|---|
| libsodium | `1.0.20`（`third_party/Libsodium.cmake` `VERSION` 与 `SODIUM_LIBRARY_VERSION_MAJOR=26/MINOR=2`） | ISC（`third_party/libsodium/LICENSE`） | XSalsa20-Poly1305 / Argon2 / 常数时间原语，静态链入 `verthys.dll` | `core/src/crypto/`（cipher/keymanager/pepper） |
| flatcc | commit `a2515daa948c1ae42ba95b3a904363169dff147c`（`third_party/Flatcc.cmake` 注释） | Apache-2.0（`third_party/flatcc/LICENSE` + `NOTICE`） | V3 容器 FlatBuffers 编解码运行时（flatccrt）；`flatc` 为 schema codegen 宿主工具（不进产物） | `core/schema/` 生成头 + `core/src/container/` |
| xxHash | `v0.8.3`（tag `e626a72bc2321cd320e953a0ccf1584cad60f363`，`third_party/Flatcc.cmake` 注释，含 SHA-256） | BSD-2-Clause（`third_party/xxhash/LICENSE`） | LSM Bloom Filter 哈希（单头文件 `XXH_INLINE_ALL`） | `core/src/index/lsm/` |

### 2.2 vcpkg 声明（`vcpkg.json`）
- 声明依赖 `libsodium`、`builtin-baseline` 为全 0 占位（`0000...0000`），即未固定 vcpkg baseline。
- 主 CMake 构建（`CMakeLists.txt` + `third_party/Libsodium.cmake`）实际使用 **vendored** libsodium，
  `vcpkg.json` 是否仍在主构建链路中被消费属待确认项（构建脚本 `build_production.ps1` 未引用 vcpkg toolchain）。

## 3. Rust 依赖（`src-tauri/Cargo.toml` 直接依赖，节选大类）
| 类别 | 依赖（版本来源） | 引入理由 |
|---|---|---|
| Tauri 核心/插件 | tauri `=2.11.5`、tauri-build `=2.6.3`、tauri-plugin-opener `=2.5.4`、tauri-plugin-dialog `=2.7.1`、tauri-plugin-process `=2.3.1`（Cargo.toml） | 桌面壳与系统集成 |
| 序列化 | serde/serde_json `=1.0.151`（Rust 1.96+ 兼容修复）、ts-rs `10` | IPC 契约 + 前端 TS 绑定生成 |
| 加密原语 | zeroize `1.4`、subtle `2.5`、hmac `0.12`、pbkdf2 `0.12`、getrandom `0.2`、base64 `0.22`、sha2 `0.10` | 敏感内存清零、常数时间比较、密钥派生、CSPRNG、哈希 |
| Windows 绑定 | windows `0.58`（多 feature，仅 Windows） | Win32/CNG/进程/文件系统等系统调用 |
| 异步/并发 | tokio `1`、tokio-util `0.7`、crossbeam-channel `0.5` | IPC/后台任务/日志管道 |
| 其它 | chrono、regex、percent-encoding、log、tempfile（dev） | 时间/校验/路径头解码/日志/测试 |
| 本地补丁 | `keyboard-types`（`[patch.crates-io]` → `../keyboard-types-patched`） | 修复 0.7.0 bitflags! serde 语法；`proc-macro2 =1.0.106` 经 rustflags 强制 `span_locations` |

## 4. 前端依赖（`verthys-tauri/package.json`，节选大类）
| 类别 | 依赖 |
|---|---|
| 运行时加密 | `@noble/ciphers`、`@noble/hashes`、`hash-wasm`（Web 侧加解密/哈希） |
| Tauri | `@tauri-apps/api`、`plugin-dialog`、`plugin-fs`、`plugin-opener`、`plugin-process` |
| UI/渲染 | `vue`、`three`（粒子/3D 背景） |
| 构建/混淆 | vite、typescript、vue-tsc；`javascript-obfuscator`、`rollup-plugin-obfuscator`、`esbuild-wasm`、`rollup-plugin-visualizer`（dev） |

> 前端 `package.json` 使用 `^` 范围（精确版本见 `package-lock.json`）。

## 5. 许可证核查结果
- 已随仓库提供许可证文件：libsodium（ISC）、flatcc（Apache-2.0 + NOTICE）、xxHash（BSD-2-Clause）。
- Rust/npm 依赖为注册表拉取，非 vendored，仓库未随附其许可证文件者标注
  “未随仓库提供许可证文件”；其许可证以其各自 crate/包元数据为准。

## 6. 升级策略
- **vcpkg**：`vcpkg.json` 的 `builtin-baseline` 为全 0 占位，未固定；如需重挂 vcpkg 基线须显式写入
  具体 baseline 并复跑依赖解析（当前主构建不依赖 vcpkg）。
- **cargo**：直接依赖在 `Cargo.toml` 用 `=x.y.z` 钉死；补丁类升级后执行
  `cargo update -p keyboard-types`（`build_production.ps1` / `build_dev.ps1` 阶段 0.6 已内置该步骤重新锁定
  Cargo.lock）；升级前须评估 `patches/` 与 `.cargo/config.toml` 的 rustflags 是否仍需保留（见 Cargo.toml 注释）。
- **vendored（libsodium/flatcc/xxHash）**：
  - libsodium：`Libsodium.cmake` 照搬官方 MSVC 构建（SSE2、SODIUM_STATIC、RtlGenRandom）；升级须同步
    `version.h.in` 渲染参数（`VERSION` / `SODIUM_LIBRARY_VERSION_MAJOR` / `SODIUM_LIBRARY_VERSION_MINOR`）。
  - flatcc：`Flatcc.cmake` **直接定义目标**，不复用其自带 CMakeLists（避免污染全局 `CMAKE_C_FLAGS`、
    `CMAKE_DEBUG_POSTFIX`、`LIBRARY_OUTPUT_PATH`）；升级须同步源文件清单与编译定义
    （`FLATCC_PORTABLE` / `FLATCC_REFLECTION=1` / `_CRT_SECURE_NO_WARNINGS`），并复核 `flatc` 生成的
    `core/schema/generated/*` 是否需重新 codegen。
  - xxHash：单头文件升级后须更新 `Flatcc.cmake` 中的版本 tag 与 SHA-256 注释，并回归 LSM Bloom Filter 测试。

## 7. 供应链安全关联
- 启动期前端资源完整性：`resource_guard::verify_resource_hashes()`（release 阻断、dev 警告），哈希清单由
  build.rs 生成（`src/infrastructure/resource_guard.rs`）。
- DLL/worker 完整性：DLL SHA-256 由 build.rs 生成（`dll_hash`），`worker_init` 与启动期校验
  （`BINARY_ARCH_MISMATCH` / `BINARY_LOAD_FAILED` / `INTEGRITY_FAILED`）。
- 运行时哈希/恶意篡改校验：`core/src/security/integrity/`（runtime_hash.c / integrity.c）与防御闭环
  7 路径（`Verthys_GetSecurityStatus`），详见 `SECURITY_DESIGN.md`。
- 依赖审查红线：工程刚性约束条款（`docs/ENGINEERING_CONSTRAINTS.md`）要求第三方依赖安全审查、禁引已知高危组件，
  详见 `SECURITY_DESIGN.md`。

## 8. 已知观察（照实记录，未改代码）
- `vcpkg.json` `version-string = 3.2.6` 与项目版本 2.6.1 不一致。
- `dep-versions.txt` 含 `name = "valt-tauri" version = "2.6.1"`（旧品牌残留），而 Cargo.toml 包名为
  `verthys-tauri`；`verthys-tauri/node_modules/.package-lock.json` 亦有旧名痕迹（第三方生成物）。
- `vcpkg.json` 声明 `libsodium` 但主构建使用 `third_party/libsodium`；二者关系待确认。

## 9. 交叉引用
- C 接口：`CORE_API.md`；桥接：`TAURI_BRIDGE.md`；构建配置：`CONFIGURATION.md`；安全设计：`SECURITY_DESIGN.md`。