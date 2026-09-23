# 配置项说明（构建 / 运行 / 打包）
> 全部构建环境变量、脚本参数、Tauri 配置与运行时开关的含义、默认值与影响。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档覆盖 `scripts/env.load.ps1`（环境变量唯一来源）、根 `build_production.ps1` /
`build_dev.ps1`（参数）、`verthys-tauri/src-tauri/tauri.conf.json`、`verthys-tauri/package.json`
以及 C/Rust 源码中读写的运行时环境变量。每项标注 **构建期 / 运行期 / 仅 Windows**。

## 1. 构建环境变量（`scripts/env.load.ps1`，零硬编码）

`env.load.ps1` 只从系统环境变量读取，脚本内不含绝对路径/版本号/密钥/镜像 URL；缺失必需变量立即 fail-fast。

### 1.1 必需环境变量（用户系统预设，构建期，仅 Windows）
| 变量 | 含义 | 默认值 | 缺失行为 |
|---|---|---|---|
| `VERTHYS_VS_ROOT` | Visual Studio 安装根目录 | 无（必需） | 抛出并拒绝构建 |
| `VERTHYS_MSVC_VER` | MSVC 工具链版本号 | 无（必需） | 抛出并拒绝构建 |
| `VERTHYS_SDK_ROOT` | Windows SDK 安装目录 | 无（必需） | 抛出并拒绝构建 |
| `VERTHYS_SDK_VER` | Windows SDK 版本号 | 无（必需） | 抛出并拒绝构建 |

### 1.2 可选环境变量
| 变量 | 含义 | 默认值 | 影响 |
|---|---|---|---|
| `VERTHYS_GH_MIRROR` | GitHub 镜像（Tauri 下载 NSIS/WiX 工具用，国内可设 ghproxy） | 空（不生效） | 非空时写出 `TAURI_BUNDLER_TOOLS_GITHUB_MIRROR` |
| `VERTHYS_VS_GENERATOR` | MSVC 生成器名（CMake `-G`） | `Visual Studio 18 2026` | 决定 CMake 生成器 |

### 1.3 内部派生变量（脚本拼接，非环境输入；仅 Windows）
| 变量 | 派生规则 |
|---|---|
| `VERTHYS_MSVC_ROOT` | `{VS_ROOT}\VC\Tools\MSVC\{MSVC_VER}` |
| `VERTHYS_CMAKE_EXE` | `{VS_ROOT}\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe` |
| `VERTHYS_CL_EXE` | `{MSVC_ROOT}\bin\Hostx64\x64\cl.exe` |
| `VERTHYS_LINK_EXE` / `VERTHYS_LIB_EXE` | `{MSVC_ROOT}\bin\Hostx64\x64\link.exe` / `lib.exe` |
| `VERTHYS_INCLUDE` / `VERTHYS_LIB` | MSVC + Windows SDK 的 include/lib 路径（um/ucrt/shared） |
| `VERTHYS_PATH_PREFIX` | MSVC `bin\Hostx64\x64` + SDK `bin\{SDK_VER}\x64` |

### 1.4 应用到进程的变量（env.load 内 `$env:*` 写出，构建期）
| 变量 | 值来源 | 用途 |
|---|---|---|
| `INCLUDE` / `LIB` / `PATH` | 1.3 派生 | cl.exe 头文件/库/工具查找 |
| `CC` / `CXX` | `VERTHYS_CL_EXE` | 强制 cc crate（vswhom-sys 的 C++ 源）用 cl.exe，规避 vswhere/注册表探测失败 |
| `LD` / `AR` | link.exe / lib.exe | 链接/归档工具 |
| `CMAKE_C_COMPILER` / `CMAKE_CXX_COMPILER` | `VERTHYS_CL_EXE` | CMake 编译器固定 |
| `TAURI_BUNDLER_TOOLS_GITHUB_MIRROR` | `VERTHYS_GH_MIRROR`（非空时） | Tauri bundler 工具下载镜像 |

> 注：`VERTHYS_CMAKE_EXE` 是**派生**变量（非用户直接设置），由 `build_production.ps1:232` 以
> `& $VERTHYS_CMAKE_EXE -S ... -B ... -G $VERTHYS_VS_GENERATOR -A x64` 消费。

## 2. 构建脚本参数

### 2.1 `build_production.ps1`（生产一键构建，构建期）
用法：`powershell -ExecutionPolicy Bypass -File build_production.ps1 [-Clean] [-SkipCore] [-SkipWorker] [-SkipTauri] [-NoPause]`
| 参数 | 含义 |
|---|---|
| `-Clean` | 构建前清理所有构建目录（build/、worker target/、src-tauri/target/） |
| `-SkipCore` | 跳过 C 核心 DLL 构建（DLL 已存在时） |
| `-SkipWorker` | 跳过 worker 构建（二进制已存在时） |
| `-SkipTauri` | 跳过 Tauri 打包（仅构建组件时） |
| `-NoPause` | 失败/成功不暂停等待 Enter（CI 场景） |

流程：阶段 0 清进程 → 0.5 加载 env → 0.6 依赖/补丁校验 → 1 C 核心 DLL → 2 worker（release+debug）
→ 3 部署二进制 + 哈希校验 → 4 Tauri（NSIS）→ 5 产物校验。构建期额外设置 `$env:CARGO_INCREMENTAL="0"`（纵深防御 LNK1181）。

### 2.2 `build_dev.ps1`（开发启动器，构建期 + 运行期）
无命令行参数。步骤：加载 env → 清残留进程 → 检查端口 1420 → 校验依赖/补丁 → 校验核心二进制
（缺失时回退 `build_production.ps1 -SkipTauri -NoPause`）→ `npx tauri dev`。
开发运行期消费生产构建产物：`build/core/Release/verthys.dll` 与 `verthys-worker/target/{release,debug}`。

## 3. Tauri 配置（`src-tauri/tauri.conf.json`）

| 键 | 值 | 说明 |
|---|---|---|
| `productName` | `Verthys`（品牌仅 Verthys） | 安装包/窗口名 |
| `version` | `2.6.1` | 与 CMakeLists、package.json、Cargo.toml 一致 |
| `identifier` | `com.verthys.app` | 包标识 |
| `build.devUrl` | `http://localhost:1420` | 开发服务器（Vite） |
| `build.frontendDist` | `../dist` | 前端产物目录 |
| `build.beforeDevCommand` | `npm run dev` | 开发前命令 |
| `build.beforeBuildCommand` | `npm run build` | 打包前命令 |
| `app.windows[0]` | 1100×720，min 900×600，`decorations:false`，`transparent:true`，`resizable:true`，`center:true`，`devtools:false` | 主窗口（无边框透明） |
| `app.windows[0].additionalBrowserArgs` | `--enable-gpu-rasterization --enable-zero-copy --ignore-gpu-blocklist --js-flags="--max-old-space-size=1024 --expose-gc"` | WebView2 渲染参数 |
| `app.security.csp` | `default-src 'self'` 等（见源码） | 内容安全策略，仅 Windows WebView2 |
| `bundle.active` | `true` | 启用打包 |
| `bundle.targets` | `["nsis"]` | 仅 NSIS 安装包（Windows） |
| `bundle.useLocalToolsDir` | `true` | 使用本地工具目录 |
| `bundle.icon` | 32/128/128@2x PNG + icns + ico | 图标 |
| `bundle.resources` | `["verthys.dll"]` | 打包 DLL（从 src-tauri/ 查找） |
| `bundle.externalBin` | `["binaries/verthys-worker"]` | 外部 worker 二进制（src-tauri/binaries/） |

## 4. 前端脚本（`verthys-tauri/package.json`，构建期/开发期）
| script | 命令 | 用途 |
|---|---|---|
| `dev` | `vite` | 启动 Vite 开发服务器 |
| `build` | `vue-tsc --noEmit && vite build` | 类型检查 + 前端产物构建 |
| `preview` | `vite preview` | 本地预览构建产物 |
| `tauri` | `tauri` | 调用 `@tauri-apps/cli`（`npm run tauri build` 打包） |

## 5. 运行时环境变量（运行期）

**结论：代码中不读取任何 `VERTHYS_` 前缀的运行时环境变量**（经对 `core/` 与 `src-tauri/`
C/Rust 源码的 `getenv` / `std::env::var` 检索确认），也不对 WebView2 / GPU 参数做任何
运行时环境变量写出。运行时读取的环境变量仅有以下事实：

- 运行期**读取**的标准系统变量（仅 Windows 相关路径/指纹逻辑，非 VERTHYS_ 前缀）：
  `HOME` / `XDG_DATA_HOME`（非 Windows 路径分支）、`USERPROFILE`、`APPDATA`、`ProgramFiles`、
  `ProgramFiles(x86)`、`HOSTNAME`、`SystemRoot`、`PATH`、`TEMP`（`std::env::temp_dir`）。
- `core/src/crypto/pepper/verthys_pepper.c:212` 读取 `HOME`（POSIX pepper 来源回退分支，Windows 不使用）。
- 便携模式：数据目录由 Cargo feature `portable_mode`（编译期固化，**禁用**运行时环境变量切换 `%LOCALAPPDATA%`），
  仅接受受信命令行参数 `--data-dir`（入口层校验）。命令行参数解析见 `src/main.rs` / `middleware/context.rs`。

## 6. 交叉引用

- 依赖版本与升级：`THIRD_PARTY.md`。
- 构建产物/部署：根 `build_production.ps1` 注释；`GETTING_STARTED.md`。
- 安全边界：`SECURITY_DESIGN.md`。