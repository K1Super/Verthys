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

当前构建未配置 Authenticode 代码签名，属本机阶段已知缺口：

- `build_production.ps1` 与 `ci/`、`.github/workflows/core.yml` 均无 signtool 签名步骤。
- `scripts/build_core.release.ps1:69` 注释声明 Authenticode 必须在本步骤之后进行，但未实际执行。
- 本机 `local` profile 接受 Windows 未知发布者提示；外部分发前必须接入 Authenticode，并确保 NSIS 的 Authenticode 先于 updater `.sig` 生成。

建议补全步骤（外部分发前）：用 `signtool sign /fd SHA256 /tr <时间戳服务> /td SHA256 /sha1 <证书指纹>` 对 `verthys.dll`、worker、主程序及 NSIS 安装包逐一签名；NSIS 签名后重新生成 updater `.sig`，再生成清单。

## 4. 分发方式与升级机制

- 分发：NSIS 安装包（`*.exe`）；本机阶段使用 `build/updater/` 物料与本机回环服务完成更新验证。
- 升级机制：Tauri updater 插件已注册；`local` profile 从 `http://127.0.0.1:8765/latest.json` 获取清单，安装前完成安装包签名、SHA256、PE 版本、兼容区间与锁库闸门校验。
- 构建 profile：`build_production.ps1 -Profile local|production`；production 由 `tauri.production.conf.json` 覆盖端点，禁止回环与明文许可；local 由 `tauri.local.conf.json` 覆盖。
- 更新失败不覆盖旧版程序；健康自检失败时保留旧版物料并提示修复，数据目录不在安装替换范围。数据迁移语义见 [MIGRATION.md](MIGRATION.md)。

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