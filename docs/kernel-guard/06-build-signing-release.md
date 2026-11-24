# 06 构建、签名与发布

| 项目 | 内容 |
| --- | --- |
| 状态 | 评审稿 |
| 范围 | WDK 工程、构建脚本、CI、测试签名、EV + attestation、发布与回滚 |
| 关联 | [03-driver-design.md](03-driver-design.md)、[05-test-and-verification.md](05-test-and-verification.md)、[07-operations-maintenance.md](07-operations-maintenance.md) |

> Last updated: 2026-11-22

---

## 1. 工具链

| 项 | 要求 |
| --- | --- |
| Visual Studio | VS 2026 Community 18.10.1（已验证） |
| Windows SDK | 驱动构建 10.0.28000.0；现有 C 核心保持 10.0.26100.0 |
| WDK | 10.0.28000.0（已验证，工具版本 10.0.28000.3231） |
| 编译 | MSVC x64，`/W4 /WX` |
| MSBuild | 必须使用 64 位 `MSBuild\Current\Bin\amd64\MSBuild.exe` |
| 静态分析 | MSVC Code Analysis、SAL、CodeQL |
| 打包 | `Inf2Cat`、`Signtool`、`MakeCab`（如提交微软签名） |
| 调试 | WinDbg Preview、Kernel Debugging、Driver Verifier |

本机 SDK/WDK 根目录为 `D:\Windows Kits\10\`，已安装 SDK 10.0.26100.0 与 10.0.28000.0、WDK 10.0.28000.0；KMDF 1.35 x64 头文件与库存在；`Inf2Cat`（x86）、`stampinf`/`signtool`/`mc`（x64）与系统 `makecab` 可用。

2026-11-21 已完成临时 KMDF Universal 驱动冒烟验证：编译、链接、InfVerif、ApiValidator、Inf2Cat、catalog 生成与 WDK 测试签名全部通过。冒烟项目位于系统临时目录，验证后已清理，不属于仓库代码。

构建约束：

- **必须链接 `/integritycheck`**：`ObRegisterCallbacks` 与 `PsSetCreateProcessNotifyRoutineEx` 要求驱动带 `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`；构建后检查 PE `DllCharacteristics`，缺失即阻断
- **必须使用 64 位 MSBuild**。32 位 MSBuild 会按自身进程架构选择 x86 工具，而 WDK 28000 未提供 x86 `InfVerif.dll`/`ApiValidator`，会以 `0x8007007E` 或 `aitstatic` 退出码 193 失败
- 构建脚本显式设置 `WDKContentRoot=D:\Windows Kits\10\`，不依赖用户环境变量
- 驱动工程固定 `PlatformToolset=WindowsKernelModeDriver10.0`、`WindowsTargetPlatformVersion=10.0.28000.0`、`DriverType=KMDF`
- WDK VSIX 清单目标为 VS 17.x（`[17.0,18.0)`）；VS 2026 的 WDK 项目向导/IDE 扩展可能不可用，但命令行 MSBuild 已验证可用。K1 以命令行构建为准；若必须使用 VS IDE，需另行确认支持 VS 2026 的 WDK VSIX

---

## 2. 目录与构建

```text
kernel/
├── VerthysGuard.vcxproj            # WDK MSBuild 工程，不使用 CMake
├── VerthysGuard.inf
├── include/vtg_protocol.h
├── src/*.c
└── tests/

scripts/build/build_driver.ps1
tests/kernel-guard/                  # VM 脚本与用户态测试夹具
```

### 2.1 独立构建

- `kernel/` 不进入根 `CMakeLists.txt` 的 `add_subdirectory`
- `scripts/build/build_driver.ps1` 独立构建，支持：

| 参数 | 说明 |
| --- | --- |
| `-BuildDir` | 默认 `build_driver`，`.gitignore` 覆盖 |
| `-Profile local/production` | local 可测试签名；production 强制正式签名 |
| `-TestHooks` | 构建测试钩子版本，仅 VM 使用 |
| `-RunTests` | 构建后运行用户态协议/状态测试 |
| `-NoSign` | 仅本地调试；产物标记不可分发 |
| `-Clean` | 清理构建目录 |
| `-MSBuildPath` | 默认 VS 2026 `MSBuild\Current\Bin\amd64\MSBuild.exe`；禁止使用 32 位 MSBuild |

```powershell
$msbuild = 'D:\IDE\Visual Studio 2026\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$env:WDKContentRoot = 'D:\Windows Kits\10\'
& $msbuild kernel\VerthysGuard.vcxproj /t:Rebuild `
  /p:Configuration=Release /p:Platform=x64 `
  /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal /nologo
```

- 产物：`VerthysGuard.sys`、`VerthysGuard.inf`、`VerthysGuard.cat`、`driver.artifacts.json`
- `driver.artifacts.json` 记录：版本、协议版本、SHA-256、签名状态、构建时间、是否测试钩子

### 2.2 与主构建的关系

- K1 阶段不默认接入 `build_production.ps1`，避免影响现有发布链
- K1 通过门禁后，新增可选阶段 3.7（P2 服务阶段 3.6 之后、Tauri 打包之前）：
  - `-WithDriver`：构建并签名驱动，复制到 `src-tauri/driver-payload`
  - `-SkipDriver`：跳过驱动，现有产物不变
- 默认策略在 K1 评审时确定；未确定前不改变主构建默认行为
- 驱动构建失败不得破坏现有 C/Rust/Tauri 构建产物；失败应明确终止并保留日志

### 2.3 版本

- 版本单一权威仍是根 `VERSION`
- 驱动构建固定 SDK/WDK `10.0.28000.0`；现有 C 核心继续使用 `10.0.26100.0`，两套构建互不覆盖
- 驱动版本资源由 `VERSION` 生成，禁止手工写死；K1 将驱动版本纳入 `ci/sync_version.ps1` 或构建期生成校验，避免漂移
- 协议版本独立（`VTG_PROTOCOL_MAJOR/MINOR`），不跟随应用版本
- 驱动与服务必须同版本部署；版本不匹配按 [04-service-and-preset.md](04-service-and-preset.md) 处理
- 降级一律拒绝；不提供 N-1 协议兼容承诺

### 2.4 本地生命周期脚本

`scripts/kernel/` 提供 K1 内部测试机的驱动生命周期入口，全部需要管理员会话：

| 脚本 | 行为 |
| --- | --- |
| `install_kernel_guard.ps1` | 校验包哈希/协议/签名后安装；拒绝覆盖既有安装 |
| `upgrade_kernel_guard.ps1` | 快照当前包 → 替换 → 重启服务；失败自动回滚 |
| `rollback_kernel_guard.ps1` | 恢复指定或最近快照；恢复前先反向快照当前包 |
| `uninstall_kernel_guard.ps1` | 停止并删除服务与驱动包，不触碰用户数据 |
| `collect_kernel_gate.ps1` | 输出门禁证据 JSON；不加载驱动、不执行攻击用例 |

- 安装目录默认 `%ProgramFiles%\Verthys\SecurityService\driver`；可覆盖，但必须位于 `%ProgramFiles%` 下
- 包校验以 `driver.artifacts.json` 的 SHA-256 与协议主版本为准
- 测试签名包必须显式 `-AllowTestSigned`，且主机已启用 TESTSIGNING、关闭 Secure Boot、关闭 HVCI/VBS；脚本对 WDKTestCert 做显式识别，证书已进 Root 也不能绕过
- 生产打包 `-IncludeDriver` 在 `production` profile 下拒绝 WDKTestCert 签名驱动
- 脚本不进入主构建；安装器集成在后续轮次完成

---

## 3. CI

| 阶段 | 内容 | 是否默认 |
| --- | --- | --- |
| `kernel-guard-compile` | WDK 编译、`/W4 /WX`、静态分析、无测试钩子检查 | 是，仅编译 |
| `kernel-guard-unit` | 用户态协议/状态测试 | 是 |
| `kernel-guard-vm` | 加载/卸载、攻击回归、Driver Verifier | 否，手动/专用 VM |
| `kernel-guard-sign` | 生产签名与哈希校验 | 否，发布机 |

约束：

- 普通 CI 不加载驱动、不安装服务、不触碰真实设备
- CI 与本地构建统一使用 `MSBuild\Current\Bin\amd64\MSBuild.exe`，并在脚本中校验路径
- CI 产物不得包含测试证书或私钥
- VM 门禁使用专用 runner 或维护人手动执行，证据归档
- 驱动编译失败阻断合并；VM 门禁失败阻断发布

---

## 4. 签名路线

### 4.1 本地开发

- 自签名测试证书 + `TESTSIGNING`
- `bcdedit /set testsigning on`
- 关闭 Secure Boot
- 关闭 HVCI（测试签名驱动通常无法在 HVCI 开启时加载；以目标系统验证为准）
- WDK 构建会自动创建 `WDKTestCert` 并对 `.sys`/`.cat` 测试签名；该证书默认不在受信任根中，加载前需启用 TESTSIGNING 或导入受信任存储
- 仅用于开发机/测试 VM；不得分发
- 测试证书私钥只存在于构建机，不进入仓库、日志、安装包
- 首次实机加载必须使用按需启动的生命周期脚本；安装器的 `SERVICE_AUTO_START` 路径在驱动稳定性验证通过前不得启用

### 4.2 内部受控机器

| 方案 | 适用 | 代价 |
| --- | --- | --- |
| 测试签名包 | 少量、可控、技术人员 | 每台关闭 Secure Boot、开启 TESTSIGNING、关闭 HVCI（如冲突） |
| EV + attestation 微软签名 | 较多、非技术用户 | EV 证书费用与提交流程；安装干净 |

- 不推荐在生产环境长期开启 TESTSIGNING
- 测试签名模式下 UI 必须显示明确提示
- 企业策略/EDR 可能阻止测试签名，需提前验证

### 4.3 正式发布

```text
构建驱动包
  → Inf2Cat 生成 catalog
  → 用 EV 证书签名 CAB
  → 提交 Microsoft Hardware Dev Center
  → Attestation 签名（简单 KMDF 驱动）
  → 或 WHQL/HLK（文件系统微过滤等更严格类别）
  → 下载微软签名产物
  → 校验签名链与哈希
  → 随 perMachine 安装包分发
```

- Windows 10 1607+ 不加载未经 Microsoft Hardware Dev Center 签名的新内核驱动
- EV 证书是注册 Hardware Dev Center 账户的前提；attestation 的 CAB 必须用 EV 证书签名
- K3 minifilter 通常需要更严格的认证路径，具体以微软当前 Dashboard 要求为准
- 驱动必须 HVCI 兼容；HLK 的 HVCI Readiness 测试按目标类别执行
- 签名私钥离线/HSM 保存，不进入构建日志与产物

### 4.4 签名验证

- `signtool verify /pa /v` 验证 `.sys`/`.cat`/安装包
- 校验发布者证书 SHA-256 钉扎
- 校验 `driver.artifacts.json` 哈希与最终产物一致
- 生产构建复核无测试钩子字符串与符号
- `build_production.ps1 -IncludeDriver` 在打包前复核 manifest 哈希与 `.sys`/`.cat` 签名，任一不符即终止构建
- 安装器安装前再次校验驱动签名，失败回滚

---

## 5. 安装与卸载

### 5.1 安装

- K1 验证阶段可独立安装驱动；生产安装包通过 `-IncludeDriver` 显式打包已签名驱动，随 perMachine 安装器在同一提权流程分发
- 服务安装阶段校验驱动 `.sys`/`.cat` 的 Authenticode 签名，通过后复制到 `%ProgramFiles%\Verthys\SecurityService\driver`
- 服务 `CreateServiceW` 创建内核驱动服务（`SERVICE_KERNEL_DRIVER`，随系统自动启动）
- 启动驱动；启动失败回滚本次驱动变更并写 `DriverInstallResult`，应用仍可安装（`preferred` 降级）
- 载荷不完整或签名不受信时中止安装并回滚服务，不留下半安装状态
- 不创建第二个安装器，不要求首启二次安装
- 无驱动载荷时服务安装路径与行为保持不变

### 5.2 升级

```text
停止应用与服务
  → 卸载驱动（DeleteService）
  → 替换 .sys/.inf/.cat
  → 重新创建服务并启动
  → Ping/版本/能力校验
  → 失败恢复上一版驱动包
```

- 驱动被占用时安排重启替换；不得强制删除正在使用的 `.sys`
- 升级保留 P2 状态与用户容器；不改数据格式
- 驱动与服务版本不一致时按失败语义处理

### 5.3 回滚

- 保留上一版已签名驱动包与 `driver.artifacts.json`
- 新驱动启动失败/健康检查失败：停止新服务，恢复旧 `.sys`，重新创建服务
- 回滚不触碰 P2 机器状态、用户容器、预设文件
- 回滚后 UI 状态更新；审计记录版本变化

### 5.4 卸载

- 停止应用与服务
- 停止并删除驱动服务
- 删除驱动文件、INF/CAT、设备符号链接
- 删除测试证书（若为测试安装）
- 不删除用户容器与 P2 状态（除非用户明确选择）
- 卸载后无服务、无驱动、无设备、无注册表残留

---

## 6. 发布检查清单

- [ ] 根 `VERSION` 已更新，`ci/sync_version.ps1` 无漂移
- [ ] WDK/SDK 版本与 CI/发布机一致
- [ ] `build_driver.ps1 -Profile production` 成功
- [ ] `driver.artifacts.json` 哈希、版本、协议版本正确
- [ ] `.sys/.cat` 微软签名有效，发布者钉扎一致
- [ ] HVCI/Secure Boot 环境加载验证
- [ ] VM 攻击回归与状态机门禁通过
- [ ] 无测试钩子、无测试证书、无调试符号进入安装包
- [ ] 安装/升级/回滚/卸载在干净 VM 通过
- [ ] 现有 C/Rust/TS 全量测试通过（无驱动环境）
- [ ] 文档与 CHANGELOG 同步
- [ ] 回滚驱动包可用

---

## 7. 风险

| 编号 | 风险 | 对策 |
| --- | --- | --- |
| B1 | WDK VSIX 只声明 VS 17.x，VS 2026 的 IDE 向导/扩展可能不可用 | 命令行 MSBuild 已验证；K1 以命令行构建；若必须使用 IDE，安装支持 VS 2026 的 WDK VSIX |
| B2 | 微软签名周期不可控 | 提前准备 EV 与 Dashboard 流程；内部先用测试签名 |
| B3 | HVCI 阻止加载 | 从 K1 开始按 HVCI 兼容开发；CI 编译检查 |
| B4 | 驱动升级影响现有发布链 | K1 独立构建；通过门禁后再接入主构建 |
| B5 | 测试签名产物误分发 | 构建脚本标记、发布门禁扫描、UI 提示 |
| B6 | 私钥泄露 | 离线/HSM、最小权限、审计；不进入仓库与日志 |
| B7 | 回滚失败导致保护中断 | 保留旧包、失败恢复、运行中丢失立即锁定 |
| B8 | 32 位 MSBuild 选择 x86 工具导致 InfVerif/ApiValidator 失败 | 固定 64 位 MSBuild；构建脚本校验路径并在缺失时 fail-fast |
| B9 | SDK 26100 与 WDK 28000 混用 | 驱动固定 28000；现有 C 核心保持 26100；使用独立构建目录 |
| B10 | WDK 测试证书未受信任导致驱动无法加载 | 启用 TESTSIGNING 或导入测试证书；生产使用微软签名 |

---

## 8. 关联文档

- [BUILD.md](../BUILD.md)：现有 C/Rust/Tauri 构建链
- [RELEASE.md](../RELEASE.md)：现有发布与回滚流程
- [TESTING.md](../TESTING.md)：现有测试入口
- [P2_SECURITY_SERVICE_PLAN.md](../P2_SECURITY_SERVICE_PLAN.md)：服务安装/卸载模式
