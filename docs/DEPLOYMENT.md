# 部署与打包（DEPLOYMENT）

> 打包流程、产物清单与命名、签名现状、分发升级方式与安装后验证清单。
>
> Last updated: 2026-09-19 · 维护人：K1Super

Verthys 2.6.1 仅 Windows（x64）。打包统一由 `build_production.ps1` 阶段 4 完成，产出 NSIS 安装包；本文件描述产物、签名现状、分发与安装验证。构建细节与错误排查见 [BUILD.md](BUILD.md)。

## 1. 打包流程（阶段 4 全貌）

`build_production.ps1` 阶段 4（`build_production.ps1:394-471`）按序执行三个步骤：

1. 前端类型检查：`npx vue-tsc --noEmit`（提前捕获 TypeScript 错误）。
2. Rust 编译检查：`cargo check`（在 `verthys-tauri/src-tauri/`，提前捕获 Rust 错误）。
3. Tauri 打包：`npm run tauri build` → NSIS 安装包。

其中 `npm run build`（`package.json` 的 `build` 脚本）本身为 `vue-tsc --noEmit && vite build`；Tauri 的 `beforeBuildCommand` 即 `npm run build`，`bundle.targets` 仅 `["nsis"]`，`useLocalToolsDir: true`（`tauri.conf.json:32-49`）。

## 2. 产物清单与命名

| 产物 | 路径 | 说明 |
|---|---|---|
| C 核心 DLL | `build/core/Release/verthys.dll` | 随安装包以 `resources: ["verthys.dll"]` 打包（副本在 `src-tauri/verthys.dll`） |
| worker | `verthys-tauri/src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe` | 随安装包以 `externalBin: ["binaries/verthys-worker"]` 打包（Tauri 自动追加目标三元组后缀） |
| NSIS 安装包 | `verthys-tauri/src-tauri/target/release/bundle/nsis/*.exe` | 最终分发件 |

说明：`tauri.conf.json` 中 `externalBin` 相对 `src-tauri/` 解析，副本必须落在 `src-tauri/binaries/`（`build_production.ps1:47-52`）；`resources` 从 `src-tauri/` 查找 `verthys.dll`（`build_production.ps1:325-331`）。

## 3. 签名现状

当前构建未配置代码签名，属已知缺口：

- `build_production.ps1` 与 `ci/`、`.github/workflows/core.yml` 均无签名（signtool / Authenticode）步骤。
- `scripts/build_core.release.ps1:69` 注释仅声明“Authenticode 签名（若有）必须在本步骤【之后】进行”（即 `.vsec` 完整性基准注入之后），并未实际执行签名。

建议补全步骤（供后续落地，非当前事实）：用 `signtool sign /fd SHA256 /a /f <证书> /p <密码>` 对 `verthys.dll`、`verthys-worker-x86_64-pc-windows-msvc.exe` 及 NSIS 安装包逐一签名，签名放在 `.vsec` 注入之后、打包之前；并在 CI 中配置 EV 证书的受控下发。

## 4. 分发方式与升级机制

- 分发：NSIS 安装包（`*.exe`），手动分发/安装，无内置下载渠道。
- 升级机制：无自动更新。`tauri.conf.json` 未配置 updater 插件，`src-tauri/Cargo.toml` 的依赖中无 `tauri-plugin-updater`；升级靠手动安装新版本 NSIS 包，数据迁移语义见 [MIGRATION.md](MIGRATION.md)。

## 5. 安装验证清单

安装后按以下顺序验证核心二进制已正确部署（命令在 PowerShell 执行）：

1. 检查安装目录（默认 `%LOCALAPPDATA%\Verthys` 或安装时指定目录）下存在 `verthys.dll` 与 `verthys-worker-x86_64-pc-windows-msvc.exe`。
2. 哈希一致性：以构建产物为基准比对安装副本。

```powershell
Get-FileHash -Algorithm SHA256 ".\build\core\Release\verthys.dll"
Get-FileHash -Algorithm SHA256 "<安装目录>\verthys.dll"
Get-FileHash -Algorithm SHA256 ".\verthys-tauri\src-tauri\binaries\verthys-worker-x86_64-pc-windows-msvc.exe"
Get-FileHash -Algorithm SHA256 "<安装目录>\verthys-worker-x86_64-pc-windows-msvc.exe"
```

3. 完整性自校验：DLL 内部 `.vsec` 基准（`.text/.rdata/.rhat` 的 HMAC-SHA256）与 `.rhat` 运行时函数哈希由核心 `integrity_verify_startup` / `runtime_hash` 在启动时自检；若被篡改将触发应急响应（详见 [SECURITY_DESIGN.md](SECURITY_DESIGN.md)）。构建期 worker 副本哈希对比如 `build_production.ps1:365-391`（`Get-FileSha256`），可作为“副本未被破坏”的构建侧依据。