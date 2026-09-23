# 快速开始（GETTING_STARTED）

> 从零搭建 Windows 环境、完成首次构建、启动开发调试并验证构建成功的最小步骤。
>
> Last updated: 2026-09-19 · 维护人：K1Super

Verthys 2.6.1 仅支持 Windows（x64）。构建入口为根目录 `build_production.ps1`（生产，含 NSIS 安装包）与 `build_dev.ps1`（开发运行）。本文所有命令均抄自脚本实文，参数含义以脚本顶部注释为准。

## 1. 前置依赖：装什么、为什么

| 依赖 | 要求 | 用途与依据 |
|---|---|---|
| Visual Studio + MSVC x64 工具集 + Windows SDK | VS 2019+（清单生成器默认 `Visual Studio 18 2026`，工具链 MSVC 14.51） | 编译 C 核心 DLL 与 Rust 原生依赖；工具路径由 `scripts/env.load.ps1` 从环境变量注入 |
| CMake | ≥ 3.20（`CMakeLists.txt` 首行 `cmake_minimum_required(VERSION 3.20)`） | 生成并构建 C 核心；实际使用 VS 自带 `cmake.exe`（`env.load.ps1` 派生 `VERTHYS_CMAKE_EXE`） |
| Node.js + npm | 无硬性版本号；前端栈 vite 6 / vue-tsc / typescript / `@tauri-apps/cli` ^2 | 前端构建、类型检查与 Tauri 打包（脚本执行 `npm install`、`npx vue-tsc --noEmit`） |
| Rust | stable，宿主目标 `x86_64-pc-windows-msvc`；`src-tauri/.cargo/config.toml` 注释引用 Rust 1.96 / rustc≥80，raw-dylib 需 Rust 1.71+ | 编译 verthys-worker 与 Tauri 主应用（`cargo build` / `cargo check` / `cargo update`） |
| vcpkg | 不要求 | 构建不使用 vcpkg：C 依赖为 vendored `third_party/`（Libsodium / Flatcc），本地脚本与 CI 均无 vcpkg 步骤 |

CI 实际安装的工具以 `.github/workflows/core.yml` 为准：`actions/checkout@v4` + `ilammy/msvc-dev-cmd@v1`（`arch: x64`）+ Ninja 生成器（`cmake -G Ninja`）；`ci/run_ci.ps1` 额外使用 `python`（正则扫描）与 `cargo`（AST 分析器）。core 工作流不涉及 Node/npm/Tauri 打包。

### 1.1 必需环境变量（scripts/env.load.ps1 强制校验）

构建前必须设置以下环境变量（缺失时脚本 fail-fast，见 `env.load.ps1:11-19`）：

| 变量 | 含义 |
|---|---|
| `VERTHYS_VS_ROOT` | Visual Studio 安装根目录 |
| `VERTHYS_MSVC_VER` | MSVC 工具链版本号 |
| `VERTHYS_SDK_ROOT` | Windows SDK 安装目录 |
| `VERTHYS_SDK_VER` | Windows SDK 版本号 |

可选变量（`env.load.ps1:52-61`）：`VERTHYS_GH_MIRROR`（GitHub 镜像，供 Tauri 下载 NSIS 工具，映射为 `TAURI_BUNDLER_TOOLS_GITHUB_MIRROR`）、`VERTHYS_VS_GENERATOR`（MSVC 生成器名，默认 `Visual Studio 18 2026`）。

永久设置示例（PowerShell）：

```powershell
[System.Environment]::SetEnvironmentVariable('VERTHYS_VS_ROOT', '<VS 根目录>', 'User')
[System.Environment]::SetEnvironmentVariable('VERTHYS_MSVC_VER', '<MSVC 版本号>', 'User')
[System.Environment]::SetEnvironmentVariable('VERTHYS_SDK_ROOT', '<Windows SDK 根目录>', 'User')
[System.Environment]::SetEnvironmentVariable('VERTHYS_SDK_VER', '<SDK 版本号>', 'User')
```

## 2. 首次构建（三步）

### 步骤 1：干净构建（生产，含 NSIS 安装包）

```powershell
powershell -ExecutionPolicy Bypass -File build_production.ps1 -Clean -NoPause
```

参数抄自 `build_production.ps1:22-29`：`-Clean` 构建前清理所有构建目录；`-NoPause` 失败/成功后不暂停等待 Enter（CI 场景）。脚本严格按顺序执行：阶段 0 清理僵尸进程与锁文件 → 阶段 0.5 加载 MSVC 环境 → 阶段 0.6 依赖与补丁校验 → 阶段 1 C 核心 DLL → 阶段 2 worker → 阶段 3 部署复制与哈希校验 → 阶段 4 前端类型检查 + Rust 编译检查 + Tauri NSIS 打包 → 阶段 5 产物校验。失败立即终止（脚本 `try/catch` 顶层保护，双击运行会暂停显示错误）。

### 步骤 2：开发构建与运行（build_dev.ps1）

```powershell
powershell -ExecutionPolicy Bypass -File build_dev.ps1
```

该脚本（`build_dev.ps1`）依次：加载 MSVC 环境（修复 vswhom LNK2019，见脚本 `:30-60`）→ 清理残留进程 → 检查端口 1420 → 校验依赖与补丁 → 预检核心二进制（`verthys.dll` + `verthys-worker.exe` 缺失时自动回调 `build_production.ps1 -SkipTauri -NoPause`）→ 最后执行 `npx tauri dev`。

### 步骤 3：验证构建成功（最小命令组）

```powershell
# 运行 C 核心测试（生产构建目录，单一聚合测试 verthys_tests，内含 296 个用例）
ctest --test-dir build -C Release --output-on-failure

# 或直接运行测试可执行文件（Release 配置）
& ".\build\core\tests\Release\verthys_tests.exe"

# 产物落位检查（构建成功即应存在）
Test-Path ".\build\core\Release\verthys.dll"
Test-Path ".\verthys-tauri\src-tauri\binaries\verthys-worker-x86_64-pc-windows-msvc.exe"
Test-Path ".\verthys-tauri\src-tauri\target\release\bundle\nsis\*.exe"
```

测试输出以 `=== Summary: <N> passed, <M> failed ===` 结尾，退出码非 0 表示有失败（见 [TESTING.md](TESTING.md)）。

## 3. 运行与调试

- 开发模式前端地址：`http://localhost:1420`（`verthys-tauri/src-tauri/tauri.conf.json` 的 `devUrl`）。
- Vite 端口：`1420`，`strictPort: true`（`verthys-tauri/vite.config.ts`，HMR WebSocket 用 `1421`）。
- 直接启动开发：在 `verthys-tauri/` 下执行 `npx tauri dev`（`build_dev.ps1` 末尾即此命令；它已处理残留进程与端口 1420 占用）。
- 开发模式下核心二进制解析规则（`build_dev.ps1` 注释 `:12-19`）：`verthys.dll` 固定用 `build/core/Release/verthys.dll`（始终 Release）；worker 优先用 `verthys-worker/target/{release,debug}/verthys-worker.exe`（release 优先）。

## 4. 常见首次构建问题

首次构建的典型失败（BOM 解析错误、vswhom LNK2019、LNK1181 windows.lib、端口 1420 占用、cargo 锁文件、worker 就绪超时等）按症状→根因→排查→解决四列见 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)；构建矩阵与四阶段流程细节见 [BUILD.md](BUILD.md)。