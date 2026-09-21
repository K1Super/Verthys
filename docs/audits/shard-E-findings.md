# Shard-E Findings — 前端 + 构建/部署/CI/依赖/配置一致性

> 审查范围：`verthys-tauri/src/` (Vue3+TS)、前端构建配置、Rust Cargo 清单、根 CMake、build_dev/production.ps1、.github/workflows、ci/、scripts/、dep-versions.txt、.clang-tidy、CONTRIBUTING.md、tauri.conf.json。
> 证据均经 Grep/Read 实际定位；`target/` 构建产物已排除。

## 摘要计数

| 级别 | 数量 |
|------|------|
| P0   | 1    |
| P1   | 2    |
| P2   | 7    |
| P3   | 5    |

**最高级别发现一句话摘要**：`usePhotoExport.ts:71` 仍用旧 base64 JSON-args 协议调用 `write_user_file`，而 Rust 端已迁移到 raw IPC（x-path 头 + raw body），导致 Tauri 模式下拾光模块导出照片到磁盘 100% 失败。

---

## P0 — 阻断性缺陷（运行时必现）

| 文件:行 | 问题 | 证据 | 触发 | 影响 | 置信度 | 修复 | 验证 |
|---------|------|------|------|------|--------|------|------|
| `verthys-tauri/src/composables/photo-album/usePhotoExport.ts:69-72`（调用点 322/350/400/461；Rust 端 `verthys-tauri/src-tauri/src/controller/file_controller.rs:1056-1074`） | **`write_user_file` IPC 协议错配：前端用旧 JSON-args，后端已迁 raw IPC**。前端 `writeVencFile` 执行 `invoke("write_user_file", { path, dataB64: b64 })`；但 Rust 函数签名为 `write_user_file(app, request: Request<'_>)`，路径从 `x-path` HTTP 头解码（`decode_x_path_header`），字节从 `InvokeBody::Raw(bytes)` 提取。前端既未发 `x-path` 头，body 也是 JSON 而非 raw bytes。 | 正确实现见 `verthys.ts:1188-1196` `writeUserFile()`：`invokeWithTimeout("write_user_file", data, undefined, { headers: { "x-path": encodeURIComponent(path) } })`。Rust `file_controller.rs:1062` 无 x-path 头直接 `return Err(InvalidPath)`；:1068-1073 非 Raw body 也报错。 | Tauri 模式下用户在拾光模块执行任意导出（单个打包/多文件/PNG），`writeVencFile` 被调用。 | 导出写盘必然失败：Rust 侧返回 `Err`，前端 `await` 抛错，导出功能完全不可用。注释（:67-68）自称"使用 write_user_file 而非 write_file_bytes"，但迁移时只换了命令名没换调用协议。 | 确认 | 将 `writeVencFile` 改为调用 `writeUserFile(path, bytes)`（verthys.ts 已导出），删除本地 `invoke("write_user_file", {path,dataB64})` 与 `bytesToBase64` 编码。 | Tauri 模式导出一张照片，确认文件落盘；在 Rust 侧加断点确认 `decode_x_path_header` 成功。 |

---

## P1 — 高严重（静默失败 / 文档损坏）

| 文件:行 | 问题 | 证据 | 触发 | 影响 | 置信度 | 修复 | 验证 |
|---------|------|------|------|------|--------|------|------|
| `verthys-tauri/src/app/error-handler.ts:58`（Rust 侧全仓 0 匹配；混淆配置 `verthys-tauri/vite.config.ts:33`） | **生产环境致命错误上报通道完全静默**。前端 `invoke("log_fatal", { entry: ... })` 在生产分支执行，但全仓 Rust 源码 Grep `log_fatal` 0 匹配——`generate_handler!`（`src-tauri/src/lib.rs:388-467`）未注册该命令，也无对应 `#[tauri::command] fn log_fatal`。`.catch()` 降级为 `console.error`，但生产构建 `javascript-obfuscator` 设 `disableConsoleOutput: true`（vite.config.ts:33）。 | Grep `log_fatal` over `src-tauri/` → 0 结果；generate_handler 列表 76 项无 `log_fatal`；vite.config.ts:33 `disableConsoleOutput: true`。 | 生产构建中任何未捕获异常 / unhandledrejection。 | 致命错误既不会写后端日志管道，也不会显示在 console（被混淆器禁用），应用崩溃时完全无诊断信息，对安全产品是可观测性黑洞。 | 确认 | 二选一：(a) 在 Rust 侧补 `#[tauri::command] fn log_fatal(entry: String)` 并加入 generate_handler；或 (b) 前端改为已存在的日志通道（确认后端实际暴露的日志命令名）。同时评估 `disableConsoleOutput` 是否会吞掉该 fallback。 | 触发一个 `throw`，确认后端日志文件出现 FATAL 记录。 |
| `README.md:1,322,324` | **未解决的 git 合并冲突标记残留**。第 1 行 `<<<<<<< HEAD`，第 322 行 `=======`，第 324 行 `>>>>>>> c6ba26a814220d32222af14509b35f1e4a38895b`。冲突块覆盖整份文档（HEAD 侧 1–321 行，对侧仅 323 行 `# Verthys`）。 | Grep `^(<<<<<<<\|=======\|>>>>>>>)` over README.md → 3 匹配。无其它文件存在冲突标记变体（已全仓确认仅 README）。 | 任何人打开 README。 | README 是对外交付文档，冲突标记未删除说明上次合并未真正解决；文档内容对访客是损坏的。 | 确认 | 手动解决冲突：保留 HEAD 版（1–321 行），删除 1/322/324 三行标记与对侧空壳行。 | Grep 确认 README 无冲突标记；`git diff` 确认工作树干净。 |

---

## P2 — 中严重（一致性 / 可复现性 / 门控缺失）

| 文件:行 | 问题 | 证据 | 触发 | 影响 | 置信度 | 修复 | 验证 |
|---------|------|------|------|------|--------|------|------|
| `dep-versions.txt:561`（对照 `verthys-tauri/src-tauri/Cargo.lock:2954-2955`、`src-tauri/Cargo.toml:118`） | **dep-versions.txt 快照过期**：记录 `serde_json 1.0.150`，但 Cargo.lock 实际为 `1.0.151`，Cargo.toml 钉 `=1.0.151`。 | dep-versions.txt:561 `version = "1.0.150"`；Cargo.lock:2955 `version = "1.0.151"`。 | 任何依赖审计 / 供应链比对。 | 文档声称的权威版本清单与实际 lockfile 不一致，误导安全审计；说明该快照未在 serde_json 升级后重新生成。 | 确认 | 升级后重新生成 dep-versions.txt（对照 `cargo tree` / Cargo.lock 实际值）。 | 重新生成后 diff serde_json 行应等于 1.0.151。 |
| `build_production.ps1:155` + `scripts/env.load.ps1:47-50`（对照 `.github/workflows/core.yml:35-38`、`rust-frontend.yml:54-57`） | **本地构建脚本与 CI 使用完全不同的 MSVC 环境注入机制**。本地脚本 dot-source `env.load.ps1`，强制要求 `VERTHYS_VS_ROOT`/`VERTHYS_MSVC_VER`/`VERTHYS_SDK_ROOT`/`VERTHYS_SDK_VER` 四个自定义环境变量（缺失即 fail-fast throw）；GitHub CI 用 `ilammy/msvc-dev-cmd@v1`，不设置这些变量。 | env.load.ps1:47-50 `Assert-EnvVar` 四次；build_production.ps1:155 `. env.load.ps1`；core.yml:35 `uses: ilammy/msvc-dev-cmd@v1`。 | 在干净的 GitHub runner 上跑 `build_production.ps1`（或新员工无自定义 env 的机器）。 | 本地构建路径（env.load.ps1 的 INCLUDE/LIB/PATH 注入、CC/CXX 覆盖）从未在 CI 中执行；CI 绿不代表本地一键脚本能跑通，"it works on CI" 不等于 "it works on dev"。 | 确认 | 让 CI 也走 env.load.ps1（在 runner 上导出等价 env），或让本地脚本兼容 `ilammy/msvc-dev-cmd` 产物；至少在 README 记录两套路径差异。 | 在 CI matrix 加一步 `build_production.ps1 -SkipTauri -NoPause` 验证。 |
| `ci/run_ci.ps1`（对照 `.github/workflows/core.yml`、`rust-frontend.yml`） | **架构红线 AST 双引擎门（regex_scan.py + ast_analyze）未接入 GitHub Actions**。CONTRIBUTING.md:53-57 称其为"CI 静态校验第一级+第二级"，但两个 workflow 均只跑 cmake/cargo/npm/clippy，从不调用 `ci/run_ci.ps1`。 | Grep `run_ci` over `.github/workflows/` → 0 匹配；run_ci.ps1:76 执行 `verthys-ci-ast.exe`。 | 任何 PR。 | 声称阻断构建的 AST 红线检查（UAF/指针裸露等）只在开发者本地手动运行，PR 合入不强制——门控形同虚设。 | 确认 | 在 core.yml 加一步 `pwsh: ci\run_ci.ps1 -Level2Only`（编译 ast_analyze 后执行），或拆分 Level1/Level2 到独立 job。 | 提一个含红线违规的 PR，确认 CI 变红。 |
| `.clang-tidy:15,196`（对照 core.yml/rust-frontend.yml） | **clang-tidy 已配置但 CI 从不启用**；且文档示例路径与实际构建目录不符。`.clang-tidy:15` 示例 `clang-tidy -p build_ninja`，但 CI 实际用 `build_ci`/`build`。`-DVERTHYS_ENABLE_CLANG_TIDY=ON` 在两个 workflow 中均未出现。 | Grep `VERTHYS_ENABLE_CLANG_TIDY` over `.github/workflows/` → 0 匹配；.clang-tidy:15 `build_ninja`。 | 任何构建。 | 精心配置的 `WarningsAsErrors`（UAF/StackAddressEscape/Malloc）左移门未在 CI 执行；文档路径误导。 | 确认 | 在 core.yml Release 步骤加 `-DVERTHYS_ENABLE_CLANG_TIDY=ON`（或独立 job）；修正 .clang-tidy 注释中的 `build_ninja` → `build_ci`。 | 触发 clang-tidy 检查，确认违规会红。 |
| `src-tauri/src/lib.rs:389-466`（对照前端全仓 Grep） | **5 个 Tauri 命令已注册但前端从不调用**（死命令，扩大攻击面）：`diag_info`、`verthys_scan_abort`、`verthys_scan_summary_abort`、`verthys_derive_subkey`、`security_generate_auth_token`。前端 Grep 这些字符串均 0 匹配。 | lib.rs:389 `diag_info`、:414 `verthys_scan_abort`、:418 `verthys_scan_summary_abort`、:430 `verthys_derive_subkey`、:466 `security_commands::security_generate_auth_token`；前端 Grep 0 结果。 | IPC 攻击面（恶意 webview / 被注入前端可调用）。 | 每个注册命令都是一个可被前端 invoke 的入口；从未被调用的命令无谓增加攻击面与维护负担，`verthys_derive_subkey`/`security_generate_auth_token` 名字敏感。 | 确认 | 确认无调用方后从 generate_handler 移除（或补前端调用）；至少标注 `#[allow(dead_code)]` 并记录保留理由。 | 移除后 `cargo build` 确认无未使用警告；前端回归确认功能无损。 |
| `build_dev.ps1:126`、`build_production.ps1:178`（对照 `rust-frontend.yml:104`） | **本地用 `npm install`，CI 用 `npm ci`**，依赖解析不严格对齐 lockfile。本地两脚本均在 node_modules 缺失时跑 `npm install`（可升级 semver 范围内包），CI `npm ci` 严格按 lock。 | build_dev.ps1:126 `& npm install`；build_production.ps1:178 `& npm install`；rust-frontend.yml:104 `npm ci`。 | 新机器首次本地构建。 | 本地安装的依赖版本可能与 CI/发布构建不一致，产生"本地过、CI 挂"或反之的漂移。 | 确认 | 统一为 `npm ci`（CI 已用）；本地脚本也应 `npm ci` 以严格对齐 package-lock.json。 | `npm ci` 在本地可复现安装。 |
| `build_dev.ps1:152`、`build_production.ps1:215` | **每次启动/构建都执行 `cargo update -p keyboard-types`，会改写 Cargo.lock**。虽该 crate 被本地 `[patch]` 指向 `keyboard-types-patched/`，但 `cargo update` 仍会刷新 lock 条目，破坏构建可复现性。 | build_dev.ps1:152 `& cargo update -p keyboard-types`；build_production.ps1:215 同。 | 每次 dev 启动 / 生产构建。 | 开发者机器的 Cargo.lock 可能被静默改动并误提交；与"所有依赖严格锁定"的设计意图（Cargo.toml:34-38 注释）矛盾。 | 确认 | 改为 `cargo metadata --no-deps` 或 `cargo check` 验证 patch 生效，避免 `cargo update` 写 lock；或提交后用 `git diff` 检查 lock 是否被改。 | 运行后 `git status` 确认 Cargo.lock 无改动。 |

---

## P3 — 低严重（卫生 / 建议）

| 文件:行 | 问题 | 证据 | 触发 | 影响 | 置信度 | 修复 | 验证 |
|---------|------|------|------|------|--------|------|------|
| `CONTRIBUTING.md:68` | **悬空引用 `vcpkg.json`**：称"版本号、依赖版本以 vcpkg.json / dep-versions.txt 为准"，但全仓 Glob `**/vcpkg.json` → 0 结果，文件不存在。 | CONTRIBUTING.md:68；Glob vcpkg.json → No files found。 | 新人按文档查依赖。 | 误导读者去查一个不存在的清单；实际依赖由 Cargo.toml + package.json 管理。 | 确认 | 删除 `vcpkg.json` 引用，或实际创建该文件。 | Grep 确认文档不再引用。 |
| `verthys-tauri/src-tauri/tauri.conf.json:29` | **CSP `connect-src` 放行未使用的本地端口 7778**：`connect-src 'self' http://127.0.0.1:7778 http://localhost:7778`，但全仓 Grep `7778` 仅命中此 CSP 行，无任何代码连接该端口。 | Grep `7778` over 全仓 → 仅 tauri.conf.json:29。 | 任何连接尝试。 | 多放行两个本地端点扩大 CSP 攻击面（虽为 localhost，无实际用途）；疑似遗留调试端点配置。 | 确认 | 删除 `connect-src` 中两个 7778 来源，或补注释说明用途。 | CSP 审查确认无业务依赖。 |
| `.github/workflows/rust-frontend.yml:37` | **Rust 工具链未钉版本**：`dtolnay/rust-toolchain@stable` 用浮动 latest stable，非可复现。 | rust-frontend.yml:37 `uses: dtolnay/rust-toolchain@stable`。 | 每次 CI 运行。 | 不同时间跑的 CI 可能用不同 Rust 版本，行为不可复现（Rust 常带 lint/错误变更）。 | 确认 | 钉为具体版本（如 `@1.8x.0`），或用 `rust-toolchain.toml`。 | 确认 runner 上 `rustc --version` 固定。 |
| `.github/workflows/rust-frontend.yml:44`（对照 `package.json:26`） | **CI Node 22 vs `@types/node ^26` 不一致**：CI `node-version: 22`，但 devDependencies `@types/node: ^26.0.1`。 | rust-frontend.yml:44 `node-version: 22`；package.json:26 `"@types/node": "^26.0.1"`。 | CI 类型检查。 | Node 26 类型在 Node 22 运行时上做 vue-tsc，类型与运行时 API 可能漂移。 | 疑似 | 对齐：CI 升级到 Node 24/26，或把 `@types/node` 降到与 CI Node 大版本一致。 | CI 与本地 `node --version` 一致。 |
| `CONTRIBUTING.md:24` | **PR CI 门描述不全**：仅提 `.github/workflows/core.yml`，漏了 `rust-frontend.yml`（Rust/前端测试、clippy、vue-tsc、vite build 均在此）。 | CONTRIBUTING.md:24 "PR 需通过 CI（见 .github/workflows/core.yml）"。 | 新人理解 CI 覆盖范围。 | 文档低估 CI 覆盖面，可能误以为只跑 core。 | 确认 | 改为"见 .github/workflows/ 下 core.yml 与 rust-frontend.yml"。 | 文档审查。 |

---

## 已核查为无问题的项（负向结论，避免重复劳动）

- **v-html XSS**：4 处 `v-html`（`DockNav.vue:30`、`FileVerthys.vue:60/89/115`）数据源均为硬编码 SVG 字符串（`useModuleNavigation.ts:91-116`）或 `getFileIcon()`（FileVerthys.vue:286-298，mime 白名单查表返回固定 SVG，不插值用户输入）。**无 XSS**。
- **localStorage**：8 处仅存 feature-flags / security-preset / custom-features / circuit-breaker 状态（`feature-flags.ts:70`、`key_state.ts:176-219`、`promise_utils.ts:125-143`），**未存密码/密钥/明文敏感数据**。
- **console.log 敏感数据**：Grep `console.(log|debug|info)` + password/secret/key/token → **0 匹配**。
- **外部远程 URL**：Grep `https?://` → 仅 SVG `xmlns` 命名空间与 data: URI，**无外部网络 URL 被引入前端**。
- **CMake 加固**：`VerthysHardening.cmake` 覆盖 /GS、/guard:cf、/guard:ehcont、/sdl、/DYNAMICBASE、/HIGHENTROPYVA、/NXCOMPAT、/CETCOMPAT、/LTCG、/OPT:REF/ICF；`/guard:longjmp` 未落地但有磁盘偏差证据（:9-16）。**加固选项真实生效**。
- **Tauri 安全配置**：`tauri.conf.json` 无 `dangerousRemoteDomainIpcAccess`；`devtools: false`；`script-src 'self'`（无 unsafe-inline/unsafe-eval）。
- **版本号一致性**：package.json / Cargo.toml / tauri.conf.json / CMakeLists 均为 `2.6.1`，一致。
- **前后端命名契约**：`verthys_import_begin`（前端 `verthysPath` camelCase → Rust `verthys_path` snake_case）等经 Tauri 自动转换，抽样核对一致。
- **Cargo.lock**：两个 lock 均存在（src-tauri + verthys-worker）。
