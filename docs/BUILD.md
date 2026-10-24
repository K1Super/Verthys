# 构建指南（BUILD）

> 全量/增量构建矩阵、四阶段构建流程、产物落点与常见构建错误的排查修复。
>
> Last updated: 2026-09-19 · 维护人：K1Super

构建由根目录 `build_production.ps1`（生产）与 `build_dev.ps1`（开发）驱动，另有两支 core 专用脚本：`scripts/build/build_core.dev.ps1`、`scripts/build/build_core.release.ps1`。本文件聚焦生产构建链路，依赖安装见 [GETTING_STARTED.md](GETTING_STARTED.md)。

## 1. 仅 Windows 平台

Verthys 仅支持 Windows / MSVC / x64。工具链来源有两种：本地 `VERTHYS_*` 变量显式注入（CMake Visual Studio 生成器，`VERTHYS_VS_GENERATOR` 默认 `Visual Studio 18 2026`，`-A x64`）；或复用已注入的 MSVC 开发者环境（CI `ilammy/msvc-dev-cmd@v1`、`arch: x64`、开发者命令提示符），此时由 `env.load.ps1` 反推路径并经 `vswhere` 探测真实 VS 版本。生成器选择按脚本职责：`build_production.ps1` 在注入环境下用 Ninja 单配置，`build_core.release.ps1` 与 `build_core.dev.ps1` 始终用 Visual Studio 多配置（`core.yml` 的 Release 步骤依赖 `build/core/Release/verthys.dll`）。产物命名含 `x86_64-pc-windows-msvc`；不存在其他平台的构建脚本。

## 2. 构建矩阵（参数定义见 `build_production.ps1` 的 `param` 块）

| 参数组合 | 适用场景 |
|---|---|
| （无参数） | 全量：stage 0/0.5/0.6 前置 + C 核心 + worker(release+debug) + 部署复制与哈希校验 + 前端类型检查 + Rust 检查 + NSIS 打包 + 产物校验 |
| `-Clean` | 构建前清理所有构建目录（`build/`、`verthys-worker/target`、`src-tauri/target`） |
| `-SkipCore` | C DLL 已存在且无需重编（跳过阶段 1，仅校验 `verthys.dll` 存在） |
| `-SkipWorker` | worker 二进制已存在（跳过阶段 2，仅校验 `verthys-worker.exe` 存在） |
| `-SkipTauri` | 仅构建组件、不打包（`build_dev.ps1` 预检回调即用此参数） |
| `-NoPause` | 失败/成功后不暂停等待 Enter（CI 场景；双击运行不传以查看输出） |

## 3. 四阶段流程

### 前置步骤（阶段 0 / 0.1 / 0.5 / 0.6）

1. `阶段 0`：清理僵尸进程（`cargo/rustc/Verthys/verthys-worker`）与 `.cargo-lock` 锁文件。
2. `阶段 0.1`：更新域边界门（`ci/check_updater_boundary.ps1`）：WebView 不得获得安装类命令权限。
3. `阶段 0.5`：探测已注入的 MSVC 环境（`VCToolsInstallDir` + `INCLUDE` + `LIB` + PATH 中的 `cl.exe`）。已注入则沿用并选 Ninja；未注入时 dot-source `scripts/lib/env.load.ps1`（`VERTHYS_*` 四变量，选 Visual Studio 生成器）。
4. `阶段 0.6`：清理旧 `build_err.log`、校验 `node_modules`（缺失时以 `package-lock.json` 为唯一事实源执行 `npm ci`）、校验 `keyboard-types-patched` 本地补丁、只读校验 Cargo 锁文件中的本地补丁条目。

### 阶段 1：C 核心安全 DLL（CMake Release）

```powershell
# 已注入 MSVC 环境（CI）：Ninja 单配置
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 本地 VERTHYS_* 路径：Visual Studio 多配置
& $VERTHYS_CMAKE_EXE -S . -B build -G $VERTHYS_VS_GENERATOR -A x64
& $VERTHYS_CMAKE_EXE --build build --config Release
```

编译加固 `/O2 /GL /GS /guard:cf`；`rhash_gen` POST_BUILD 注入 `.rhat` 运行时哈希表。DLL 位置由 `build/core/verthys.artifacts.json` 契约给出（Ninja 为 `build/core/verthys.dll`，Visual Studio 为 `build/core/Release/verthys.dll`），脚本不按生成器猜路径。

### 阶段 1.1：.vsec 完整性基准注入 + 契约刷新

`build_production.ps1` 在 DLL 产出后统一调用 `scripts/lib/vsec.ps1` 的 `Update-VsecBaseline`（与 `scripts/build/build_core.release.ps1` 共用同一实现），把 `.text / .rdata / .rhat` 的文件内容 HMAC-SHA256 写入 DLL 的 `.vsec` 只读节。注入改写 DLL 字节，因此随后由 `scripts/lib/artifacts.ps1` 的 `Write-VerthysArtifactContract` 按最终字节重生成产物契约，并校验 SHA256、版本、格式版本与生成器一致。

`.vsec` 全零会被运行时视为开发构建而跳过验签，所以生产链路不允许跳过此步；`-SkipCore` 同样执行（注入幂等）。Authenticode 签名（若有）必须在注入之后进行。两条生产链路（一键打包与独立 core Release 脚本）使用同一注入器与同一契约写入器，口径完全一致。

### 阶段 2：verthys-worker（Rust release + debug）

```powershell
$env:CARGO_INCREMENTAL = "0"
cargo build --release      # 阶段 2 主线
cargo build                # debug（开发环境用，失败仅告警不影响打包）
```

`$env:CARGO_INCREMENTAL = "0"` 为阶段 2 内的纵深防御，与 `Cargo.toml [profile.dev] incremental=false` 共同规避 LNK1181。

### 阶段 3：部署复制 + 哈希校验

- 复制 `verthys-worker.exe` → `src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe`（Tauri `externalBin` 基准目录）。
- 复制 `verthys.dll` → `src-tauri/verthys.dll`：副本是已完成 `.vsec` 注入与契约刷新的最终字节（Tauri `resources` 从 `src-tauri/` 查找）。
- 同步 worker 到 Tauri `target/{release,debug}/`（防旧副本“worker 就绪超时”）。
- `Get-FileSha256` 比对 binaries/ 与 target 副本，哈希漂移即失败。

### 阶段 4：Tauri 打包（NSIS 安装包，含两个前置门）

1. 前端类型检查：`npx vue-tsc --noEmit`。
2. Rust 编译检查：`cargo check`（在 `src-tauri/`）。
3. Tauri 打包：`npm run tauri build`，NSIS 安装包落到 `src-tauri/target/release/bundle/nsis/*.exe`。

## 4. 产物落点与命名

| 产物 | 路径 |
|---|---|
| C 核心 DLL | `build/core/verthys.dll`（Ninja）或 `build/core/Release/verthys.dll`（Visual Studio）；以 `build/core/verthys.artifacts.json` 的 `dll` 字段为准 |
| worker（release） | `verthys-tauri/verthys-worker/target/release/verthys-worker.exe` |
| worker（debug） | `verthys-tauri/verthys-worker/target/debug/verthys-worker.exe` |
| worker 打包名 | `verthys-tauri/src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe` |
| DLL 打包副本 | `verthys-tauri/src-tauri/verthys.dll` |
| NSIS 安装包 | `verthys-tauri/src-tauri/target/release/bundle/nsis/*.exe` |
| 前端产物 | `verthys-tauri/dist/`（`tauri.conf.json` 的 `frontendDist` 指向 `../dist`） |

## 5. 常见构建错误（症状 → 根因 → 修复，注明脚本阶段而非易漂移的行号）

| 症状 | 根因 | 修复 | 来源 |
|---|---|---|---|
| 双击构建脚本窗口一闪而过、无任何错误（`ParseError`） | 脚本未保存为 UTF-8 with BOM，PowerShell 5.1 按 ANSI/GBK 解码，中文注释乱码破坏字符串/括号配对；解析错误发生在任何代码执行前，`try/catch` 与 `Read-Host` 失效 | 用支持 BOM 的编辑器将脚本另存为 UTF-8 with BOM，确认文件头 3 字节 `EF BB BF` | `build_production.ps1` 头注释；三支 core 脚本与 `scripts/lib/*.ps1` 同 |
| cl 链接报 `LNK2019`：`vswhom_find_visual_studio_and_windows_sdk` 未解析 | `cl.exe` 不在 PATH，cc crate 无法编译 `vswhom-sys` 的 C++ 源 | 先 dot-source `scripts/lib/env.load.ps1`（设置 CC/CXX=cl.exe 及 INCLUDE/LIB/PATH），覆盖 vswhere/注册表探测 | `scripts/lib/env.load.ps1`；`build_dev.ps1` 阶段 0；`build_production.ps1` 阶段 0.5 |
| `LNK1181`：无法打开输入文件 `windows.0.52.0.lib` / `windows.x.xx.x.lib` | dev profile 增量编译与 raw-dylib 导入库生成竞态：增量编译复用缓存 metadata 时 build script 的 `rustc-link-search` 输出未生效 | `[profile.dev] incremental=false`（主修复）+ `$env:CARGO_INCREMENTAL=0`（纵深）+ `.cargo/config.toml` 的 `--cfg=windows_raw_dylib` | `build_production.ps1` 阶段 2；`verthys-worker/Cargo.toml` 的 `[profile.dev]`；`src-tauri/Cargo.toml`；`src-tauri/.cargo/config.toml` |
| cargo 构建因残留锁文件异常 | 上次未正常退出的 `.cargo-lock` 残留 | 构建已自动清理（阶段 0 + 阶段 5 收尾） | `build_production.ps1` 阶段 0 预清理与收尾 |
| `npm ci` 触发“stderr 被包装为 ErrorRecord”导致脚本终止 | `$ErrorActionPreference="Stop"` 下 npm 把进度/警告写到 stderr | 已改为变量捕获模式（先捕获再逐行处理） | `build_production.ps1` 阶段 0.6 |
| `keyboard-types-patched 目录缺失` / 补丁内容不完整 | `Cargo.toml [patch.crates-io]` 指向 `../keyboard-types-patched`，用于修复 bitflags! 内 serde 派生语法 | 确保该目录及 `Cargo.toml`、`src/modifiers.rs` 存在 | `build_production.ps1` 阶段 0.6 |
| 前端 vite 构建报“文件被另一进程占用” | `node`/`esbuild` 残留进程持有 `dist/` 或缓存文件句柄 | 定位占用进程并结束：`Get-Process node,esbuild`，找到后 `Stop-Process -Id <PID> -Force`，再重试；与阶段 0 杀死僵尸进程同源机制 | 通用诊断法；关联 `build_production.ps1` 阶段 0 |
| dev 模式“worker 就绪信号超时” | `src-tauri/target/{debug,release}/` 下存在旧版 worker 副本被旧 `resolve_worker_path` 优先匹配 | 阶段 3 已把新 worker 同步到 target 树并做哈希校验，覆盖 fallback 路径 | `build_production.ps1` 阶段 3 |
| CI 构建与本地行为差异 | CI 的 core Release 步骤走 `build_core.release.ps1` → Visual Studio 多配置（`build/core/Release/verthys.dll`）；`build_production.ps1` 注入环境走 Ninja；本地 `VERTHYS_*` 路径为 Visual Studio 多配置；测试 exe 布局随生成器不同 | 按各自上下文使用对应命令；产物路径一律以 `build/core/verthys.artifacts.json` 为准 | `.github/workflows/core.yml`；`scripts/lib/env.load.ps1` 来源 2 |

## 6. 相关文档

- 依赖安装：`GETTING_STARTED.md`
- 打包/分发/签名现状：`DEPLOYMENT.md`
- 测试分层与跑法：`TESTING.md`