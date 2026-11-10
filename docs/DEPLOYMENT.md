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

说明：`tauri.conf.json` 中 `externalBin` 相对 `src-tauri/` 解析，副本必须落在 `src-tauri\binaries\`（`build_production.ps1` 的 `$BinariesDir`）；`resources` 从 `src-tauri/` 查找 `verthys.dll`（`$DllTarget`）。

## 3. 签名与调用方认证

production 发布链路要求发布者 Authenticode 代码签名证书，构建期把证书 DER 的 SHA-256 钉扎进 `verthys.dll`，运行期 `Verthys_Init` 在初始化任何状态之前校验「宿主主模块 + DLL 自身」两条签名：

- `build_production.ps1 -Profile production` 强制要求 `VERTHYS_SIGNING_THUMBPRINT` 或 `VERTHYS_SIGNING_PFX`；缺失即 fail-fast，不允许产出未签名发布候选。
- `verthys.dll`、`verthys-worker.exe`、`Verthys.exe` 三件均完成 Authenticode 签名并通过构建期指纹复核；`Verthys.exe` 由 Tauri `bundle.windows.signCommand` 在 bundle type 补丁之后签名，安装包内嵌的是已签名字节。
- 构建期功能门禁使用真实证书对临时宿主做正负对照：未签名进程调用 `Verthys_Init` 必须返回 `UNAUTHORIZED`，目标发布者签名宿主必须放行。
- `-Profile local` 未提供证书时不启用调用方认证并显式告警；该产物只用于本机复现，禁止分发。
- 证书必须在目标系统信任（公共 CA 或企业预置根）；链不受信时应用按 fail-closed 拒绝启动。
- NSIS 安装包、卸载器与随包 NSIS 插件副本均由同一发布者证书签名，构建完成即校验安装包 Authenticode 与钉扎指纹；更新完整性仍叠加清单签名、安装包 minisign 签名、SHA256、size 与 PE 版本。

安装包签名会改写文件字节，`build_production.ps1` 在打包完成后重新生成 updater `.sig`；任何手工改写安装包或三件可执行产物的操作都会同时破坏 Authenticode、minisign 签名与 worker/DLL 哈希基线，必须重新走完整构建链。

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

3. 完整性自校验：DLL 内部 `.vsec` 基准（`.text/.rdata/.rhat` 的 HMAC-SHA256）与 `.rhat` 运行时函数哈希由核心 `integrity_verify_startup` / `runtime_hash` 在启动时自检；若被篡改将触发应急响应（详见 [SECURITY_DESIGN.md](SECURITY_DESIGN.md)）。生产链路在打包前由 `scripts/lib/vsec.ps1` 注入 `.vsec` 基准（`build_production.ps1` 阶段 1.1 与 `scripts/build/build_core.release.ps1` 共用同一实现），注入后按最终字节重生成产物契约；构建期 worker 与 DLL 副本哈希对比见 `build_production.ps1` 阶段 3（`Get-FileSha256`），可作为“副本未被破坏”的构建侧依据。

## 6. P2 安全服务部署与安装

P2 服务是应用的强制依赖。应用安装器为 perMachine：标准用户双击安装包时由 Windows 弹一次 UAC，确认后同一安装流程内完成应用、SYSTEM 服务与根 CA；取消 UAC 时安装器进程不启动，零写入。应用安装包不再包含独立的 `VerthysSecurityServiceSetup.exe`，应用内也不再触发任何提权安装。

- 前置：Windows 10 1809+ x64；一次管理员授权；服务 exe 由发布者证书签名并钉扎 SHA-256。
- 安装：安装器 POSTINSTALL 从 `service-payload\VerthysSecuritySvc.exe` 执行 `/install /quiet`；服务 Running、`Installed=1` 后才完成安装。任一失败：全新安装回滚并清理，升级安装恢复旧服务并提示重跑安装器。
- 应用内只保留只读服务状态检测；服务缺失时 Gate 提示重新运行安装程序，不再执行用户可写二进制或 UAC 安装。
- 自签名发布链：构建期从证书链导出根 CA 并把 DER SHA-256 编入服务 exe；`/install` 先按固定指纹校验随包 `VerthysRootCA.cer` 并写入 `LocalMachine\Root`，再校验服务 exe 发布者签名。服务以 LocalSystem 运行，WinVerifyTrust 只认机器根；缺少该步骤会因 Event 3003“self signature verification failed”拒绝启动。
- 卸载：应用卸载器 PREUNINSTALL 调 `service-payload\VerthysSecuritySvc.exe /uninstall /quiet`，失败即中止（此时尚未删除应用文件）；成功后清理服务、安装目录、`.bak`、HKLM 锚点、事件源、`%ProgramData%\Verthys` 与根 CA。用户加密库默认保留；卸载器“Delete app data”仅在显式勾选时删除执行卸载的管理员用户自身数据。机器密钥材料 `container.secret` 在删除应用数据前转移到 `%LOCALAPPDATA%\Verthys\KeyMaterial` 并保留：它是打开既有加密库的必要材料，删除会使库永久无法普通解锁；复制失败时卸载中止。
- 手动维护：管理员可从 `%ProgramFiles%\Verthys\service-payload\VerthysSecuritySvc.exe` 执行 `/repair`、`/reset-state`、`/repair-keys`、`/status`；不要把 `/install` 从已安装服务目录（`SecurityService`）执行。
- 退出码：0 成功、2 参数、3 非管理员、4 签名/根 CA 指纹校验失败、5 安装失败、6 启动失败、7 就绪检查失败、8 回滚失败。
- 服务状态目录 `%ProgramData%\Verthys\Security` 与安装目录 `%ProgramFiles%\Verthys\SecurityService` 不得手工放宽 ACL；服务每次启动复核，放宽即拒绝启动。
- 升级：perMachine 安装/升级各一次 UAC；安装器停旧服务、备份旧 exe 为 `.bak`、替换并重启，失败恢复旧服务。若应用已更新而服务升级失败，应用启动 fail-closed 并提示重跑安装器。
- 开发构建使用测试钩子 core 与机器预算旁路，不触发生产服务引导。