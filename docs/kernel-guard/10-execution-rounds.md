# 10 执行轮次与回归记录

| 项目 | 内容 |
| --- | --- |
| 状态 | 执行中：Round 1/2 完成；Round 3 服务侧完成；Round 4 状态透传完成；Round 5 `preferred` 降级展示完成；Round 6 降级审计、驱动生命周期脚本与门禁取证完成；Round 7 服务侧 ARM/REGISTER/DISARM 与 C 核心激活完成；Round 8 宿主预创建 ARM、REGISTER 目标校验与运行中丢失自动锁定完成（代码/单测）；Round 9 安装器一次 UAC 驱动集成完成（代码/构建/静态校验）；A14 运行期、驱动实机安装、VM 攻击回归未验证 |
| 范围 | 内核加固 K1 的分轮实施、回归证据与产品断裂防护 |
| 关联 | [README.md](README.md)、[06-build-signing-release.md](06-build-signing-release.md)、[08-roadmap-adr.md](08-roadmap-adr.md) |

> Last updated: 2026-11-22

---

## 1. 执行原则

1. 每轮只引入一个可独立回退的关注点，不把驱动、服务、UI 混在同一轮
2. 任何一轮不得改变现有产品的默认运行路径；驱动未集成前，产品行为必须与执行前一致
3. 每轮完成后执行构建、静态检查、现有测试或明确的范围回归，并在本文记录证据
4. 运行期驱动加载、HVCI、攻击回归必须在 VM 执行；未执行项标注“未验证”，不写成通过
5. 发现方案缺陷先修文档，再进入该轮编码

---

## 2. Round 0：方案复核与备份

### 2.1 方案复核修正

| 项 | 修正 |
| --- | --- |
| Ob 回调注册时机 | 统一为“驱动加载即注册，未 ARM 时直接放行”，避免切档时反复注册/注销与进程创建竞态 |
| 驱动工程形态 | 明确为 WDK `.vcxproj`，不使用 CMake，避免与现有 C 核心构建链混用 |
| 审核清单 | 增加 Ob 回调注册时机、WDK 环境验证确认项 |

### 2.2 源码备份

| 项 | 值 |
| --- | --- |
| 备份路径 | `C:\Users\Administrator\Desktop\Verthys-src-backup-20261121-175704` |
| Git HEAD | `cc78479` |
| 文件数 | 2335 |
| 大小 | 60.4 MB |
| 排除 | `.git`、`build`、`build_dev`、`build_security_service`、`build_driver`、`node_modules`、`target`、`dist`、`.vs`、`.screenshots` |
| 校验 | `core/include/verthys.h`、`security-service/src/service_main.c`、`docs/kernel-guard/README.md`、`README.md`、`VERSION` 的 SHA-256 与源文件一致 |

说明：备份反映执行前的工作树状态；工作树中存在并发的 `docs/photo-engine` 删除与未跟踪的 `docs/kernel-guard/`，备份按原样保留，未修改该并发状态。

---

## 3. Round 1：内核工程骨架与最小驱动

### 3.1 范围

- 新增 `kernel/` WDK 工程、共享协议头、最小 KMDF 非 PnP 控制设备
- 只实现 `Ping` 与 `QueryStatus`；其余命令返回 `STATUS_NOT_SUPPORTED`
- 不注册 Ob 回调、不登记受保护进程、不修改任何进程句柄
- 新增 `scripts/build/build_driver.ps1` 与协议布局测试
- 不修改现有 C/Rust/TS 产品代码，不接入主构建

### 3.2 文件

| 文件 | 用途 |
| --- | --- |
| `kernel/include/vtg_protocol.h` | 定长协议结构、状态/原因/命令常量 |
| `kernel/include/vtg_ioctl.h` | 设备名、符号链接、SDDL、IOCTL 控制码 |
| `kernel/src/driver_main.c` | 驱动入口、控制设备、符号链接、IOCTL 队列、卸载 |
| `kernel/src/vtg_ioctl.c` | Ping/QueryStatus 请求校验与响应 |
| `kernel/VerthysGuard.inf` | 非 PnP 根枚举驱动包 |
| `kernel/VerthysGuard.vcxproj` | WDK MSBuild 工程，Desktop 目标 |
| `kernel/tests/vtg_protocol_test.c` | 协议布局与常量测试 |
| `kernel/tests/vtg_protocol_test.vcxproj` | 用户态测试工程 |
| `scripts/build/build_driver.ps1` | 64 位 MSBuild 构建、测试、产物清单 |

### 3.3 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_driver.ps1 -Configuration Debug -Clean
pwsh -NoProfile -File scripts\build\build_driver.ps1 -Configuration Release -Clean
```

结果：

- KMDF `VerthysGuard` 使用 `WindowsKernelModeDriver10.0`、`Desktop`、x64 构建成功（Debug 与 Release）
- `InfVerif`、`Inf2Cat`、catalog 生成通过；无错误、无警告
- `build_driver\driver\Debug\VerthysGuard.sys` 为 x64 Native 镜像
- `build_driver\driver\Debug\VerthysGuard\verthysguard.cat` 生成并测试签名
- `build_driver\tests\Debug\vtg_protocol_test.exe` 运行通过
- `build_driver\driver.artifacts.json` 含 `.sys/.cat/.inf` 的 SHA-256

### 3.4 回归审查

| 项 | 结果 |
| --- | --- |
| 现有产品代码改动 | 无；`git status` 只显示新增 `kernel/`、`scripts/build/build_driver.ps1`、文档 |
| 现有主构建影响 | 无；`build_production.ps1` 未修改，驱动工程不进入默认构建 |
| 产品默认路径 | 未接入服务、Rust、TS；应用行为不变 |
| 驱动运行期 | 未加载；本机没有启用 TESTSIGNING，未做 VM 攻击回归 |
| 测试签名 | WDK 自动测试签名；证书链默认不受信任，属预期 |

结论：Round 1 不构成产品断裂面；可回退为删除 `kernel/` 与 `scripts/build/build_driver.ps1`。

---

## 4. Round 2：受保护进程登记与 Ob 回调

### 4.1 实现范围

- 新增受保护进程表、ARM/DISARM、REGISTER/UNREGISTER
- 注册 `PsSetCreateProcessNotifyRoutineEx` 与 `ObRegisterCallbacks`
- 按映像路径 + 父进程对象引用识别；进程创建时自动标记，REGISTER 确认
- 父进程 bootstrap 仅允许 Job 分配所需的 `PROCESS_SET_QUOTA/PROCESS_TERMINATE`，带 5 秒截止
- 线程句柄剥离 `THREAD_SET_CONTEXT` 等危险权限
- 仍不接入服务、Rust、TS；产品默认路径不变

### 4.2 文件

| 文件 | 用途 |
| --- | --- |
| `kernel/include/vtg_state.h` | 受保护表、ARM 状态、回调 rundown 接口 |
| `kernel/src/vtg_state.c` | 进程表、身份校验、bootstrap、状态查询 |
| `kernel/include/vtg_ob.h` | Ob 回调生命周期接口 |
| `kernel/src/vtg_ob.c` | 进程/线程句柄权限剥离、altitude 注册 |
| `kernel/include/vtg_notify.h` | 进程通知生命周期接口 |
| `kernel/src/vtg_notify.c` | 进程创建/退出通知 |
| `kernel/src/vtg_ioctl.c` | ARM/DISARM/REGISTER/UNREGISTER/QUERY_STATUS |
| `kernel/src/driver_main.c` | 初始化顺序、失败清理、卸载顺序 |

### 4.3 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_driver.ps1 -Configuration Debug
pwsh -NoProfile -File scripts\build\build_driver.ps1 -Configuration Release -Clean
```

结果：

- 驱动编译、InfVerif、Inf2Cat、catalog 生成、测试签名通过；无警告（Debug 与 Release）
- 协议测试通过，新增 `VTG_ARM_IN`/`VTG_REGISTER_IN` 布局断言
- `.sys` 为 x64 Native 镜像；`.cat` 生成
- 现有产品代码零改动：`git diff --stat` 对 `core/`、`security-service/`、`verthys-tauri/`、`scripts/`、`ci/`、`tests/` 为空
- 驱动运行期未加载；未执行 VM 攻击回归、Driver Verifier、HVCI 加载

### 4.4 静态审查

| 项 | 结论 |
| --- | --- |
| 卸载竞态 | 增加 `EX_RUNDOWN_REF`；注销回调后等待在途回调归零，再释放进程引用 |
| 锁内释放对象 | 进程/父进程引用在释放锁后 `ObDereferenceObject`，避免退出通知重入死锁 |
| PID 复用 | 以进程对象引用为键；REGISTER 校验 PID + 创建时间 + 映像路径 |
| bootstrap 伪造 | 父进程以对象引用比较，不使用 PID；5 秒截止；REGISTER 后关闭 |
| 路径形式差异 | 先用文件基名预筛，命中后再用 `SeLocateProcessImageName` 校验完整路径 |
| IOCTL 混淆 | 校验结构长度、版本、保留位、命令与 IOCTL 对应关系 |
| 未实现命令 | QueryStats/QueryEvents 返回 `STATUS_NOT_SUPPORTED`，不伪装成功 |

### 4.5 未验证项

- `ObRegisterCallbacks` altitude `321000` 在目标系统是否可用
- 驱动实际加载、设备 ACL、Ping/ARM/REGISTER 端到端
- 同用户读内存、注入、终止、挂起、调试附加攻击回归
- 运行中驱动丢失、worker 重启、进程退出的实机行为
- HVCI、Secure Boot、Driver Verifier
- 服务提供的映像路径形式是否与 `SeLocateProcessImageName` 完全一致

以上未验证项必须在 VM 门禁中完成；当前不得对外宣称“内核防护已生效”。

### 4.6 退出判定

Round 2 **编译与静态审查通过**；运行期验证未完成，不满足 K1 完整门禁。

---

## 5. Round 3：服务侧内核状态查询

### 5.1 实现范围

- 新增服务侧 `kernel_guard` 模块，只读打开 `\\.\VerthysGuard`，查询固定长度状态
- 新增 IPC 命令 `VTY_SVC_CMD_KERNEL_STATUS = 5`
- 响应头 48..63 区承载内核状态、原因、能力位与协议版本；签名覆盖范围仍为前 64 字节
- 既有命令响应继续要求 48..63 全 0，新增独立 KernelStatus 解码函数，不改变旧客户端语义
- 设备 I/O 使用 250 ms 上界，超时 `CancelIoEx`，避免阻塞服务工作线程
- **不接入** worker、Rust、TS；应用不会调用该命令，产品默认路径不变

### 5.2 文件

| 文件 | 用途 |
| --- | --- |
| `security-service/src/kernel_guard.h` | 服务级内核状态、原因码与查询接口 |
| `security-service/src/kernel_guard.c` | 设备打开、IOCTL、超时、状态映射 |
| `security-service/src/pipe_server.c` | KernelStatus 分发与签名响应 |
| `security-service/src/protocol.h/.c` | KernelStatus 签名响应构造 |
| `security-service/include/vty_svc_protocol.h` | 命令 5、响应字段与编解码 |
| `security-service/tests/test_kernel_guard.c` | 不存在设备路径的 NOT_INSTALLED 映射 |
| `security-service/tests/test_protocol.c` | KernelStatus 编解码与旧解码拒绝 |
| `security-service/CMakeLists.txt` | 新源文件与 kernel/include 路径 |
| `security-service/tests/CMakeLists.txt` | 新测试源文件与 kernel/include 路径 |

### 5.3 协议

- 命令：`VTY_SVC_CMD_KERNEL_STATUS = 5`
- 响应 48..51：服务级状态
- 响应 52..55：原因码
- 响应 56..59：能力位图
- 响应 60..61：内核协议主版本
- 响应 62..63：内核协议次版本
- 普通响应解码仍拒绝 48..63 非 0，旧客户端不受影响

### 5.4 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Debug -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Release -TestHooks -RunTests -NoSign
```

结果：

- 服务、探针、fake service、测试全部构建成功（Debug/Release）
- `ctest` 1/1 通过
- 新增测试覆盖：KernelStatus 命令合法、内核字段编解码、普通解码拒绝非 0 保留区、缺失设备映射为 `NOT_INSTALLED`
- 现有 P2 命令、响应签名、状态机测试全部保持通过

### 5.5 回归审查

| 项 | 结果 |
| --- | --- |
| 既有 P2 命令 | 无行为变更；普通响应仍要求 48..63 全 0 |
| 应用默认路径 | worker/Rust/TS 未改动；应用不会发送 KernelStatus |
| 驱动依赖 | 查询只读；驱动缺失返回 `NOT_INSTALLED`，不阻塞服务 |
| 超时 | 250 ms + `CancelIoEx`，不无限等待驱动 |
| 产品断裂 | 无；新命令未被产品调用 |

### 5.6 未验证项

- 驱动真实加载后的 KernelStatus 端到端
- 客户端对 KernelStatus 响应的 ECDSA 验签
- worker/Rust/TS 接入与 `preferred` 降级 UI
- 服务在 fail-closed 状态下返回 KernelStatus 的实机行为
- 服务安装、驱动安装、卸载与回滚

### 5.7 退出判定

Round 3 **服务侧编译/单测通过**；应用侧接入未开始，K1 完整门禁仍未满足。

---

## 6. Round 4：状态透传与 UI 展示

### 6.1 实现范围

- C 核心新增可选符号 `Verthys_GetKernelStatus`，通过服务 KernelStatus 查询驱动状态
- 不提升 `VERTHYS_API_VERSION`；worker 按符号探测，旧核心缺失时返回 `None`
- worker `security_status` 报告新增可选 `kernel_status` 字段
- Tauri 主进程与 TS 类型透传；动态防护面板新增一行“内核加固”事实状态
- **未接入** `SECURE = preferred` 的自动切换逻辑；本轮只做状态透传与展示
- 不改变现有 7 路径状态、预设矩阵与解锁路径

### 6.2 文件

| 文件 | 用途 |
| --- | --- |
| `core/src/security/state/vty_machine_limiter.h/.c` | 服务 KernelStatus 客户端与状态映射 |
| `core/include/verthys.h` | 可选 `VerthysKernelStatus` 与接口声明 |
| `core/verthys.def` | 导出 `Verthys_GetKernelStatus` |
| `core/src/api/security/verthys_api_security.c` | 公共 API 映射 |
| `verthys-worker/src/runtime/ffi_types.rs` | C 结构体/符号绑定与 20 字节布局测试 |
| `verthys-worker/src/runtime/worker.rs` | 符号探测与 `kernel_status` 填充 |
| `verthys-worker/src/runtime/protocol.rs` | `KernelStatusReport` 序列化 |
| `verthys-tauri/src-tauri/src/controller/types.rs` | 主进程类型镜 |
| `verthys-tauri/src/types/verthys.ts` | 前端类型 |
| `verthys-tauri/src/composables/security-center/useDefenseStatus.ts` | `kernelStatus` 视图出口 |
| `verthys-tauri/src/components/modules/SecurityCenter.vue` | 透传 `kernel-status` |
| `verthys-tauri/src/components/views/ManagementView.vue` | 透传 `kernel-status` |
| `verthys-tauri/src/components/management/SecurityDashboard.vue` | 事实状态行与文案映射 |

### 6.3 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -NoPause
cargo test --manifest-path verthys-tauri\verthys-worker\Cargo.toml
cargo check --manifest-path verthys-tauri\src-tauri\Cargo.toml
npx vue-tsc --noEmit
npx vitest run src/components/management/SecurityDashboard.spec.ts src/composables/security-center/useDefenseStatus.spec.ts
```

结果：

- C 核心 Debug 构建通过；`verthys.dll` 生成
- worker 单元测试 128 通过、1 忽略、0 失败；新增 20 字节 C 布局测试通过
- Tauri 主进程 `cargo check` 通过
- 前端 `vue-tsc --noEmit` 通过
- 受影响 UI 测试 19 通过（SecurityDashboard 9、useDefenseStatus 10）
- C 核心 `machine_limiter` 定向回归 8 通过（未安装/默认 fail-closed/管道不可达/公钥缺失/坏签名/nonce 不匹配/状态映射/超时）
- `security_status` 新增字段为可选；旧 worker/旧核心不返回时前端不显示该行

### 6.4 回归审查

| 项 | 结果 |
| --- | --- |
| 既有 7 路径状态 | 字段与显示不变 |
| 旧核心兼容 | 符号缺失返回 `None`，前端不显示内核行 |
| ABI | 新增独立结构 20 字节；既有 `VerthysSecurityStatus` 104 字节不变 |
| 解锁/预设路径 | 未修改 |
| 产品断裂 | 类型检查、worker/UI 单测通过；未做运行期端到端 |

### 6.5 未验证项

- 驱动实际加载后的 KernelStatus 端到端
- 服务 pipe 的 ECDSA 验签在真实客户端路径的实机验证
- `SECURE = preferred` 自动切换与 UI 降级联动
- worker 可执行文件重新打包后的实际运行
- C 核心完整单元测试（按“不回归”要求未运行；已运行 machine_limiter 定向回归 8 项）
- 视觉走查（新增行复用现有 `def-stance` 样式）

### 6.6 退出判定

Round 4 **编译/类型检查/受影响单测通过**；运行期与 `preferred` 策略切换未完成。

---

## 7. Round 5：SECURE preferred 降级展示

### 7.1 实现范围

- `SECURE`（code=1）默认 `preferred`：内核状态不是 `ACTIVE` 时，UI 明确标记“高安全（用户态降级）”
- 仅做事实判定与展示；SECURE 已生效的用户态防护能力不变
- 非 SECURE 档不显示该降级标记；未安装/未运行/未知状态在普通档位继续隐藏
- **未实现**：自动审计事件、驱动安装/升级/回滚、VM 攻击回归

### 7.2 文件

| 文件 | 用途 |
| --- | --- |
| `SecurityCenter.vue` | 读取 `securityPresetRef` 与 `kernelStatus`，计算 `kernelPolicyDegraded` |
| `ManagementView.vue` | 透传降级标记 |
| `SecurityDashboard.vue` | 显示“高安全（用户态降级）· 原因” |
| `SecurityDashboard.spec.ts` | 降级标记与未安装隐藏的 UI 契约 |

### 7.3 验证

```powershell
npx vue-tsc --noEmit
npx vitest run src/components/management/SecurityDashboard.spec.ts src/composables/security-center/useDefenseStatus.spec.ts
```

结果：

- `vue-tsc` 通过
- 受影响 UI 测试 19 通过
- 既有非 SECURE 档、7 路径状态、预设矩阵未改

### 7.4 未验证 / 风险

- 内核未实际加载，降级标记仅在“状态不可用/非 ACTIVE”时出现
- 未写审计事件
- 未做安装/升级/回滚
- 未做 VM 攻击回归
- 未做视觉走查

### 7.5 退出判定

Round 5 **仅完成 preferred 降级展示**；发布门禁仍未满足。

---

## 8. Round 6：降级审计、驱动生命周期脚本与门禁取证

### 8.1 实现范围

- 新增审计事件 `KERNEL_GUARD_DEGRADED`；审计写入口提升为 `pub(crate)` 供新命令复用
- 新增 Tauri 命令 `verthys_audit_kernel_degraded`：校验 `state 0..10` / `reason 0..11`，写 `AuditResult::Failure`
- 前端在 `SECURE preferred` 降级事实出现时写一条审计，按 `(state, reason)` 去重；仅在观测到非降级事实时重置去重键，报告缺失（未采样/已锁定）不重置
- 新增 `scripts/kernel/`：公共模块、安装、升级、回滚、卸载与门禁取证
- 安装/升级/回滚均先校验 `driver.artifacts.json` 哈希与协议主版本；失败自动清理或恢复上一包
- 门禁取证只收集环境、签名、服务与包事实，不加载驱动、不伪造攻击结果；未完成用例显式列为 pending
- **未实现**：服务侧 ARM/REGISTER、安装器集成、VM 攻击回归执行

### 8.2 文件

| 文件 | 用途 |
| --- | --- |
| `verthys-tauri/src-tauri/src/util/audit_log.rs` | `KernelGuardDegraded` 事件与字符串 |
| `verthys-tauri/src-tauri/src/security_commands/audit.rs` | 审计写入入口可见性提升 |
| `verthys-tauri/src-tauri/src/security_commands/commands/kernel_guard.rs` | 降级审计命令与值域测试 |
| `security_commands/commands/mod.rs`、`security_commands/mod.rs`、`src-tauri/src/lib.rs` | 模块与命令注册 |
| `verthys-tauri/src/lib/verthys.ts` | `verthysAuditKernelDegraded` |
| `verthys-tauri/src/components/modules/SecurityCenter.vue` | 降级边沿触发与按状态去重 |
| `scripts/kernel/kernel_guard_common.ps1` | 包解析、哈希、签名、路径约束、SCM、快照与审计 |
| `scripts/kernel/install_kernel_guard.ps1` | 首次安装（拒绝覆盖既有安装） |
| `scripts/kernel/upgrade_kernel_guard.ps1` | 升级与失败自动回滚 |
| `scripts/kernel/rollback_kernel_guard.ps1` | 快照回滚与反向保护 |
| `scripts/kernel/uninstall_kernel_guard.ps1` | 服务与驱动包清理 |
| `scripts/kernel/collect_kernel_gate.ps1` | 发布门禁证据 JSON |

### 8.3 构建与验证

```powershell
cargo check --manifest-path verthys-tauri\src-tauri\Cargo.toml
cargo test --manifest-path verthys-tauri\src-tauri\Cargo.toml --lib kernel_guard
npx vue-tsc --noEmit
npx vitest run src/lib/verthys-kernel-audit.spec.ts src/components/management/SecurityDashboard.spec.ts src/composables/security-center/useDefenseStatus.spec.ts
```

结果：

- `cargo check` 通过
- `kernel_guard` 值域单测 2 通过（合法状态/原因对、超界拒绝）
- `vue-tsc --noEmit` 通过
- 受影响前端单测 23 通过（SecurityDashboard 9、useDefenseStatus 10、降级审计去重 4）
- 6 个 PowerShell 脚本语法解析通过，全部为纯 ASCII
- Release 包解析与哈希校验通过（版本 4.6.5，协议 1.0）
- 签名负向验证：未信任签名在无 `-AllowTestSigned` 时拒绝；本机未启用 TESTSIGNING 时 `-AllowTestSigned` 继续拒绝
- 安装目录约束：拒绝 Program Files 之外的路径
- 生命周期核心逻辑自测（临时目录，不触碰系统）：复制 → 写状态 → 快照 → 篡改检测 → 还原后哈希与状态一致；不一致包被拒绝
- 提权生命周期脚本未执行（本机未启用 TESTSIGNING，且需要管理员会话）

### 8.4 回归审查

| 项 | 结果 |
| --- | --- |
| 非 SECURE 档 | 不触发内核降级审计 |
| SECURE + 内核 ACTIVE | 不写降级审计 |
| SECURE + 降级 | 每次降级事实按 `(state, reason)` 去重；60s 轮询与组件重挂载均不重复写链；恢复非降级后重新记录 |
| 审计写入失败 | 不阻塞 UI；去重键重置，下轮采样重试 |
| 旧核心/旧 worker | `kernel_status` 缺失按未知降级记录；字段可选，既有链路不变 |
| 产品默认路径 | 驱动未安装时不改变解锁、预设与 7 路径状态 |
| 脚本破坏面 | 仅内核驱动类型且名为 `VerthysGuard` 的服务与 Program Files 下的驱动目录；同名非内核服务拒绝操作；不触碰容器与 P2 状态 |
| 现有构建链 | 脚本不进入主构建；驱动、服务、核心产物未改 |

### 8.5 未验证 / 风险

- 提权安装/升级/回滚/卸载未执行；SCM 内核服务镜像路径（`\??\%ProgramFiles%\...`）未实机验证
- 降级审计当前由前端观测触发；解锁/切档事务内的后端自动记录需与服务 ARM/健康检查一并落地（Round 7）
- 驱动实际加载、设备 ACL、Ping/ARM/REGISTER 端到端未验证
- A1–A14 攻击回归未执行。阻塞前置：服务侧尚未实现 ARM/REGISTER，驱动无法进入 ACTIVE，攻击用例没有受保护目标
- S1/S5/S6/S10 状态机未执行
- HVCI、Secure Boot、Driver Verifier、72 小时稳定性未执行
- 安装器集成（随 perMachine 一次 UAC）未实现；当前脚本只用于内部测试机

### 8.6 退出判定

Round 6 **审计链路与生命周期脚本完成构建、类型、负向与语法验证**；运行期与 VM 门禁未完成，不能宣称内核防护已生效或达到发布门禁。

---

## 9. Round 7：服务侧内核生命周期与 C 核心激活

### 9.1 实现范围

- 服务 IPC 新增 `KERNEL_ARM=6`、`KERNEL_REGISTER=7`、`KERNEL_DISARM=8`；请求保持 64 字节、无载荷
- 受保护对象只能是已认证的管道客户端进程：服务从进程句柄读取 PID、创建时间与映像路径，客户端不能自报
- 客户端映像基名必须为 `verthys-worker.exe` 或 `verthys-worker-x86_64-pc-windows-msvc.exe`
- 新增 DOS→NT 设备路径转换，修复用户态 `C:\...` 与 `SeLocateProcessImageName` 返回形式不一致导致的身份校验失败
- 单所有者：已有其他存活 worker 持有保护时拒绝 ARM；旧进程退出后允许接管
- C 核心新增 ARM/REGISTER/DISARM 客户端与进程级获取状态；普通/keyfile/恢复解锁前与切到 SECURE 时获取，锁定与切出 SECURE 时释放
- 失败不阻断用户态解锁（`preferred`）；状态查询如实反映驱动状态
- **未实现**：宿主在 worker 创建前 ARM（A14 无窗口）、运行中丢失自动锁定、安装器集成、VM 攻击回归

### 9.2 文件

| 文件 | 用途 |
| --- | --- |
| `security-service/include/vty_svc_protocol.h` | 命令 6/7/8 与白名单 |
| `security-service/src/kernel_guard.h/.c` | DOS→NT、worker 校验、ARM/REGISTER/DISARM、单所有者、IOCTL 上界 |
| `security-service/src/pipe_server.c` | 生命周期命令分发与签名内核状态响应 |
| `security-service/tests/test_protocol.c` | 新命令白名单与 64 字节无载荷契约 |
| `security-service/tests/test_kernel_guard.c` | DOS→NT、worker 基名、生命周期边界与拒绝路径 |
| `core/src/security/state/vty_machine_limiter.h/.c` | 生命周期命令与进程级获取/释放 |
| `core/src/api/lifecycle/verthys_api.c`、`core/src/api/security/verthys_api_security.c` | 解锁前获取、切档联动、锁定释放 |

### 9.3 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Debug -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Release -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -NoPause
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -TestHooks -NoPause
```

结果：

- 服务 Debug/Release 构建成功，`ctest` 1/1 通过
- 新增服务测试覆盖：命令白名单、DOS→NT 转换、worker 基名识别、非 worker ARM/REGISTER/DISARM 拒绝
- 新增 C 线级测试：伪服务端依次应答 ARM/REGISTER/DISARM（签名内核响应），KERNEL_STATUS 字段解码
- C 核心开发构建成功；`-TestHooks` 全量测试 **329 通过、0 失败**
- 驱动协议与驱动代码未改；本机仍未加载驱动

### 9.4 回归审查

| 项 | 结果 |
| --- | --- |
| 旧服务 + 新客户端 | 命令 6/7/8 返回 `BAD_REQUEST`，`preferred` 降级，不阻断解锁 |
| 新服务 + 旧客户端 | 旧客户端不发送新命令，行为不变 |
| BALANCED/PERFORMANCE | 不获取内核保护；锁定释放无副作用 |
| SECURE + 无驱动 | ARM 失败，解锁继续；状态 `NOT_INSTALLED` |
| SECURE + 驱动可用 | 静态推断：REGISTER 成功后驱动进入 `ACTIVE`（运行期未验证） |
| 非 worker 客户端 | 服务拒绝（`DENIED`），不触达驱动 |
| P2 既有命令 | 预算、签名、并发槽位、fail-closed 语义未改 |
| C 核心 | 全量 329 测试通过，无既有功能回归 |

### 9.5 未验证 / 风险

- 驱动未加载：ARM/REGISTER 端到端、设备 ACL、路径匹配未实机验证
- **A14 未满足**：当前由 worker 自身在解锁/切档时 ARM，worker 创建到 ARM 之间同用户仍可预开危险句柄并保留访问权
- 无窗口方案需要宿主在 `CREATE_SUSPENDED` 之前调用服务 ARM，并在 REGISTER 时提交 worker PID/创建时间；需要宿主侧服务 IPC 客户端，未实现
- 运行中驱动丢失后的自动锁定未实现；`KERNEL_STATUS` 能反映 `NOT_INSTALLED/STOPPED/LOST`，但 UI 仅在轮询时显示降级
- 安装器一次 UAC 集成未实现；当前仍使用 Round 6 的独立脚本安装驱动
- VM 攻击回归、HVCI、Secure Boot、Driver Verifier、72 小时稳定性未执行
- 服务重启会丢失所有者状态；已获取保护的 worker 在驱动仍存活时保持生效，但新服务未被驱动信任，已解锁会话的模块校验可能失败，需锁定重解锁恢复；运行中丢失自动锁定未实现
- DOS→NT 转换依赖盘符 `QueryDosDevice`；无盘符卷或特殊挂载会失败并按 `preferred` 降级

### 9.6 退出判定

Round 7 **服务侧生命周期命令与 C 核心激活链路完成，构建、单测与 C 全量回归通过**；A14、运行中锁定、安装器与 VM 门禁未完成，K1 发布门禁仍未满足。

---

## 10. Round 8：宿主预创建 ARM 与运行中丢失锁定

### 10.1 实现范围

- 服务协议新增内核载荷：ARM 携带 `mode`（0=worker self，1=宿主预 ARM）与 worker 映像选择；REGISTER 携带目标 PID + FILETIME 创建时间；DISARM 仍无载荷
- 服务 `kernel_guard` 改为 mode/owner/bound/armed_path 状态：宿主预 ARM 只从宿主映像目录 + 白名单 worker 基名派生路径，并要求文件存在
- REGISTER 宿主模式重新打开目标进程，校验创建时间、worker 基名与已 ARM 的 NT 路径；worker 自身补登记幂等
- DISARM 允许 ARM owner（宿主）或已登记 worker；驱动 `NOT_ARMED` 视为成功
- 内核生命周期命令不再要求 verthys.dll 模块校验（宿主不加载该 DLL），但连接级发布者签名认证不变
- 宿主新增服务 IPC 客户端：HKLM 公钥、固定管道、64/128 字节定长、ECDSA P-256 验签、1s I/O 超时
- `WorkerSession::spawn` 顺序改为：宿主 ARM → `CREATE_SUSPENDED` → 读取创建时间并 REGISTER → Job/DACL → resume；仅在 worker 与宿主同目录且基名白名单时启用，开发树自动跳过
- C 核心 SECURE 激活时先查内核状态：ARMED/ACTIVE 只补 REGISTER，避免清空宿主预登记；查询/登记失败回退完整 ARM+REGISTER
- worker 新增 `kernel_status` 轻量操作；宿主看门狗 2s 采样，SECURE 且曾 ACTIVE 后连续 2 次**明确**非 ACTIVE 调用 `perform_external_lock("kernel_lost")`；查询失败/超时不计数，避免长任务误锁

### 10.2 文件

| 文件 | 用途 |
| --- | --- |
| `security-service/include/vty_svc_protocol.h` | 内核载荷结构、ARM 模式/worker 选择、内核请求编解码 |
| `security-service/src/pipe_server.c` | 内核命令分支解码、载荷传递、模块校验豁免范围 |
| `security-service/src/kernel_guard.h/.c` | 宿主/worker 识别、同目录路径派生、双主体生命周期 |
| `security-service/tests/test_protocol.c` | 载荷线格式与非法输入 |
| `security-service/tests/test_kernel_guard.c` | 宿主/worker 基名、路径派生、生命周期边界 |
| `verthys-tauri/src-tauri/src/infrastructure/security_service_client.rs` | 宿主服务 IPC 与验签 |
| `verthys-tauri/src-tauri/src/worker/session.rs` | 预 ARM/REGISTER 接入与同目录判定 |
| `verthys-tauri/src-tauri/src/worker/platform.rs` | worker 创建时间读取 |
| `verthys-tauri/src-tauri/src/worker/kernel_watchdog.rs` | 运行中丢失锁定决策与线程 |
| `verthys-tauri/src-tauri/src/controller/worker_controller.rs` | 就绪后启动看门狗 |
| `core/src/security/state/vty_machine_limiter.c` | SECURE 激活顺序 |
| `core/tests/security/test_machine_limiter.c` | 预 ARM/回退/登记失败回滚序列 |
| `verthys-tauri/verthys-worker/src/runtime/{dispatch,protocol,worker}.rs` | `kernel_status` 操作与响应字段 |

### 10.3 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Debug -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Release -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -TestHooks -NoPause
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -NoPause
cargo check --manifest-path verthys-tauri\src-tauri\Cargo.toml --lib
cargo test --manifest-path verthys-tauri\src-tauri\Cargo.toml --lib security_service_client
cargo test --manifest-path verthys-tauri\src-tauri\Cargo.toml --lib kernel_watchdog
cargo test --manifest-path verthys-tauri\verthys-worker\Cargo.toml
```

结果：

- 服务 Debug/Release 构建成功，`ctest` 通过
- 服务测试新增宿主/worker 基名、路径派生、内核载荷编解码与拒绝路径
- C 核心 `-TestHooks` 全量 **332 通过、0 失败**；新增 3 个 SECURE 激活序列用例（REGISTER-only、ARM+REGISTER、登记失败回滚）
- C dev DLL 构建成功
- 宿主 `cargo check` 通过；服务客户端 5 个单测（含测试密钥对验签与篡改拒绝）、看门狗 5 个决策单测通过
- worker `cargo test` **128 通过、0 失败、1 忽略**，新增 `kernel_status` 序列化用例
- 驱动协议与驱动代码未改；本机仍未加载驱动

### 10.4 回归审查

| 项 | 结果 |
| --- | --- |
| 新服务 + 旧 worker | 旧请求载荷全 0，按 worker self 处理，行为不变 |
| 旧服务 + 新宿主 | 旧服务拒绝带载荷请求，宿主记录 warn 并降级为 worker 自 ARM |
| BALANCED/PERFORMANCE | 不预 ARM、不看门狗；看门狗读档非 SECURE 即复位 |
| SECURE + 无驱动 | 预 ARM 失败，解锁继续；看门狗从未 ACTIVE，不误锁 |
| 开发树布局 | worker 与宿主不同根，跳过预 ARM |
| 非 worker/宿主客户端 | 服务拒绝 ARM/REGISTER/DISARM，不触达驱动 |
| 长任务占用 worker | `kernel_status` 超时不累计丢失次数，避免误锁 |
| P2 既有命令 | 预算、签名、并发槽位、fail-closed 语义未改 |
| C 核心 | 全量 332 通过，既有功能无回归 |

### 10.5 未验证 / 风险

- 驱动未加载：A14 攻击回归、REGISTER 目标校验、LOST 锁定端到端未实机验证
- 宿主预 ARM 依赖 worker 与宿主同目录；生产 externalBin 布局满足，开发树跳过
- 宿主二进制被重命名（非 `verthys.exe`）时预 ARM 被服务拒绝，退回 worker 自 ARM
- 预 ARM 只校验 worker 文件存在，不额外校验其 Authenticode；安全边界依赖安装目录 ACL（Program Files 仅管理员可写）与宿主自身发布者签名
- 服务重启丢失 owner 状态：既有会话保持驱动侧保护，新 worker 回退 ARM+REGISTER 重建
- 看门狗只对「明确非 ACTIVE」计数；worker 长期繁忙时内核丢失的发现会延后
- 安装器一次 UAC、VM 攻击回归、HVCI/Secure Boot/Driver Verifier、72 小时稳定性未执行

### 10.6 退出判定

Round 8 **宿主预创建 ARM 与运行中丢失自动锁定的代码链路完成，服务/C/Rust 构建与单测通过**；受限于本机无驱动与 VM，A14 运行期门禁、安装器集成与 VM 攻击回归未满足，K1 发布门禁仍未关闭。

---

## 11. Round 9：安装器一次 UAC 驱动集成

### 11.1 实现范围

- 服务 setup 新增驱动载荷探测：`service-payload\driver` 不存在或为空视为无驱动，行为与旧安装器一致
- 驱动 `.sys`/`.cat` 使用 Authenticode 信任链校验（不钉扎发布者，兼容平台 attestation 签名）；载荷不完整或签名不受信即中止安装并回滚服务
- 驱动安装：复制到 `%ProgramFiles%\Verthys\SecurityService\driver`，注册 `SERVICE_KERNEL_DRIVER` + `SERVICE_AUTO_START`，随后启动
- 启动失败（HVCI/环境/资源）回滚本次驱动文件与服务变更，写入 `DriverInstallResult`，应用与服务继续安装
- 升级：停止旧驱动 → 备份 → 替换 → 重建/启动；失败恢复上一版文件并尝试重启旧驱动
- 卸载：仅删除确认为内核驱动的 `VerthysGuard` 服务与驱动目录；同名非内核服务不触碰
- `/repair` 重装驱动；`/status` 增加驱动结果与服务状态
- `build_production.ps1 -IncludeDriver` 显式打包：manifest 哈希 + `.sys`/`.cat` 签名双门禁，未指定时移除旧载荷
- Tauri resources 增加 `service-payload/driver/*`；仓库保留 `.keep` 占位，保证无驱动时资源 glob 仍然匹配
- 安装器钩子无需改动：POSTINSTALL/PREUNINSTALL 继续调用服务 exe，一次 UAC 内完成服务与驱动

### 11.2 文件

| 文件 | 用途 |
| --- | --- |
| `security-service/src/client_auth.h/.c` | 不钉扎发布者的可信签名校验 |
| `security-service/setup/setup_main.c` | 驱动载荷探测、签名校验、安装/升级/回滚/卸载、状态输出 |
| `security-service/tests/test_client_auth.c` | 可信签名负向路径 |
| `build_production.ps1` | `-IncludeDriver` 门禁、manifest/签名复核、载荷复制 |
| `verthys-tauri/src-tauri/tauri.conf.json` | 驱动载荷资源 |
| `verthys-tauri/src-tauri/service-payload/driver/.keep` | 无驱动时的资源占位 |

### 11.3 构建与验证

```powershell
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Debug -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Release -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Release -NoSign
cargo check --manifest-path verthys-tauri\src-tauri\Cargo.toml --lib
```

结果：

- 服务 Debug/Release 构建与 `ctest` 通过；生产（无测试钩子）Release 构建通过
- `cargo check` 在无驱动载荷、仅有 `.keep` 占位时通过，Tauri 资源 glob 不再报缺失
- `build_production.ps1` 语法解析通过，UTF-8 BOM 保持；`tauri.conf.json` JSON 校验通过
- 未执行 `-IncludeDriver` 生产打包：本机无已签名驱动产物

### 11.4 回归审查

| 项 | 结果 |
| --- | --- |
| 无驱动载荷 | 探测为 absent，服务安装/升级/卸载路径与旧版一致 |
| 载荷不完整 | 中止安装并回滚服务，不创建驱动服务 |
| 签名不受信 | 中止安装，不复制文件 |
| 驱动启动失败 | 恢复旧文件/删除新服务，写降级标记，应用继续安装 |
| 同名非内核服务 | 不停止、不删除、不回滚应用安装 |
| 升级 | 先停旧驱动再替换；失败恢复旧文件并尝试重启 |
| 卸载 | 先停服务，再确认内核驱动并删除；失败则中止卸载避免残留 |
| 既有服务安装 | `/install` 签名、根 CA、就绪与回滚语义未改 |

### 11.5 未验证 / 风险

- 本机无已签名驱动与 VM：驱动服务创建、启动、升级、卸载未实机验证
- 驱动 attestation 签名链在目标 OS 上的信任结果未验证
- `SERVICE_AUTO_START` 驱动的启动时序与 HVCI 兼容性未验证
- 安装器 `-IncludeDriver` 完整打包与 NSIS 安装/升级/卸载未执行
- 驱动启动失败时仅记录 `DriverInstallResult`，UI 修复入口仍依赖既有降级展示

### 11.6 退出判定

Round 9 **安装器驱动集成代码、打包门禁与无驱动回归完成**；受限于本机无签名驱动与 VM，驱动实机安装/启动/卸载与整包安装流程仍未验证，K1 发布门禁仍未关闭。

---

## 12. 后续门禁

| 项 | 内容 | 产品影响 |
| --- | --- | --- |
| 发布门禁 | 安装器一次 UAC、VM 攻击回归、HVCI/Secure Boot/Driver Verifier、72 小时稳定性 | 发布阻塞 |

具体范围在进入前按 [08-roadmap-adr.md](08-roadmap-adr.md) 复核，不在本文提前承诺。

---

## 13. 变更记录

| 日期 | 轮次 | 变更 | 状态 |
| --- | --- | --- | --- |
| 2026-11-21 | Round 0 | 方案复核修正 + 源码备份 | 完成 |
| 2026-11-21 | Round 1 | 内核工程骨架、最小驱动、协议测试、构建脚本 | 完成（运行期未验证） |
| 2026-11-21 | Round 2 | 受保护进程表、Ob 回调、bootstrap、rundown 卸载保护 | 完成（编译/静态审查；运行期未验证） |
| 2026-11-21 | Round 3 | 服务侧 KernelStatus 查询、签名响应、协议与单测 | 完成（服务侧；应用侧未接入） |
| 2026-11-22 | Round 4 | C 可选 API、worker 状态字段、Tauri/TS 透传、UI 事实状态行 | 完成（编译/类型/受影响单测；运行期未验证） |
| 2026-11-22 | Round 5 | SECURE preferred 用户态降级展示 | 完成（展示层；审计/安装/VM 未完成） |
| 2026-11-22 | Round 6 | 降级审计事件与边沿去重、驱动安装/升级/回滚/卸载脚本、门禁取证 | 完成（构建/类型/负向/语法；运行期与 VM 未验证） |
| 2026-11-22 | Round 7 | 服务侧 ARM/REGISTER/DISARM、DOS→NT 路径、单所有者、C 核心解锁/切档/锁定联动 | 完成（服务单测、C 全量 329；A14/运行中锁定/安装器/VM 未完成） |
| 2026-11-22 | Round 8 | 宿主预创建 ARM、REGISTER 目标校验、C 核心 REGISTER-only、运行中丢失看门狗 | 完成（服务/C/Rust 构建与单测；A14 运行期/安装器/VM 未验证） |
| 2026-11-22 | Round 9 | 安装器一次 UAC 驱动集成、签名/哈希打包门禁、驱动降级与卸载 | 完成（服务构建/单测、资源与脚本校验；驱动实机与整包安装未验证） |

---

## 14. Round 10（Phase 0）：实机接入前全链路审查

日期：2026-11-23
范围：驱动、服务、宿主、安装/打包脚本
边界：未提权、未修改 BCD、未安装/加载驱动、未替换运行中的服务与应用

### 14.1 审查发现并已修复

| 编号 | 问题 | 影响 | 修复 |
| --- | --- | --- | --- |
| P0-1 | 驱动 PE 缺少 `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` | `ObRegisterCallbacks` 与 `PsSetCreateProcessNotifyRoutineEx` 会拒绝注册，驱动无法进入保护状态 | 工程加 `/integritycheck`；重建后 PE `DllCharacteristics=0x41E0` |
| P0-2 | 宿主在 REGISTER 之后才 `OpenProcess` 做 Job/DACL/恢复 | 驱动 Confirmed 后剥离 `SET_QUOTA`/`TERMINATE`/`SUSPEND_RESUME`，worker 加固或恢复失败，生产布局无法启动 worker | 拆分为 REGISTER 前 `prepare`（Job/DACL，不恢复）与 REGISTER 后 `resume`；prepared 句柄权限不被追溯撤销 |
| P0-3 | 心跳事件在 REGISTER 后才复制，且 DACL 已收紧 | `DuplicateHandle` 需要 `PROCESS_DUP_HANDLE`，失败导致挂起看门狗降级 | prepared 句柄增加 `DUP_HANDLE`；bootstrap 对父进程保留该权限；恢复前完成心跳复制；`HeartbeatEvent` 增加 Drop |
| P0-4 | 服务 overlapped IO 把 `OVERLAPPED`/响应缓冲放在栈上 | 取消后 IRP 未完成时，内核可能写已释放栈内存，存在蓝屏风险 | 改为堆上下文；取消后 5 秒仍未完成则有意保留上下文，绝不提前释放 |
| P0-5 | 进程创建/退出通知未纳入 rundown | 卸载与在途通知回调可能并发释放状态 | 通知回调获取/释放 rundown；卸载先注销再等待 |
| P0-6 | test-signed 驱动证书进入 Root 后被当作生产签名 | 可能绕过 `-AllowTestSigned`，生产打包可能带入测试签名驱动 | 安装脚本识别 WDKTestCert，强制 `-AllowTestSigned` + TESTSIGNING，并检查 Secure Boot/HVCI；生产打包拒绝 WDKTestCert |

### 14.2 构建与静态验证

| 项 | 结果 |
| --- | --- |
| 驱动 Release 构建 | 通过；protocol tests passed |
| 驱动 PE | `ForceIntegrity=True`；sys SHA-256 `311DB0B5...CACDEED` |
| 驱动签名 | WDKTestCert 测试签名；证书未进 Root，`Get-AuthenticodeSignature=UnknownError`（预期） |
| 服务测试构建 + ctest | 1/1 passed（含 `kernel_guard` 测试） |
| 服务 Release 签名构建 | `signed=True`，`testHooks=False`，SHA-256 `5B764DD2...4C7A95` |
| 宿主 `cargo check --release` | 通过 |
| 宿主 `cargo build --release` | 通过 |
| 宿主内核相关单测 | 9 passed / 0 failed |
| 安装脚本解析与策略自检 | `PARSE OK`；无 `-AllowTestSigned` 时 test-signed 包被拒绝 |

### 14.3 本机环境实测

- Windows 11 22631，物理机，无 Hyper-V
- Secure Boot：关闭
- VBS/HVCI：未运行
- TESTSIGNING：当前非提权，`bcdedit` 拒绝访问，尚未确认
- BitLocker：当前非提权无法读取，Phase 1 必须先确认恢复密钥
- VerthysGuard：服务不存在，`\\.\VerthysGuard` 不存在
- 已安装服务：2026-11-21 旧二进制，不含 `VerthysGuard` 字符串
- 已安装应用/worker：2026-11-19 旧二进制，不含 `kernel-guard`
- WDKTestCert 私钥：`CurrentUser\My` 存在，公钥未进 `LocalMachine\Root`/`TrustedPublisher`

### 14.4 仍未解决，Phase 2/4 前必须处理

1. 生产安装器路径使用 `SERVICE_AUTO_START`；首次实机测试必须使用 `install_kernel_guard.ps1` 的按需启动路径，禁止先装 `-IncludeDriver` 整包，避免驱动启动失败形成重启循环
2. 宿主仅实现同目录预 ARM；`target/release/verthys-tauri.exe` 不在服务主机白名单，且未签名。Phase 4 必须使用打包后的 `Verthys.exe` 与签名 worker
3. 内核 ACTIVE 后宿主无法再对 worker 线程执行 `THREAD_SUSPEND_RESUME`；A18S 的挂起看门狗需要在 Phase 4 决定“跳过并声明由内核覆盖”或改造
4. `kill_orphan_workers` 对受保护 worker 的终止权限会被剥离；生命周期必须以 Job Object 为准
5. Driver Verifier、HVCI/Secure Boot 兼容、72 小时稳定性仍未验证
6. 生产打包尚未钉扎驱动发布者证书链；当前只拒绝 WDKTestCert

### 14.5 Phase 1 准入

- 必须提权确认 TESTSIGNING 与 BitLocker 状态
- 必须保存 BitLocker 恢复密钥，或先暂停保护
- 必须导出 BCD、备份服务/应用配置
- 必须导入 WDKTestCert 公钥到 `LocalMachine\Root` 与 `TrustedPublisher`
- 必须重启后复核 TESTSIGNING=Yes、签名 Valid、HVCI 仍关闭

### 14.6 Phase 2 首次加载安全序列

1. `install_kernel_guard.ps1 -AllowTestSigned -SkipStart`，先只安装不启动
2. 核对 `sc qc VerthysGuard` 为 `SERVICE_DEMAND_START`，ServiceBinary 指向 `%ProgramFiles%\Verthys\SecurityService\driver\VerthysGuard.sys`
3. 确认无 pending reboot、磁盘有足够空间写内核转储
4. 再单独 `sc start VerthysGuard`；启动失败立即停止并卸载
5. 若蓝屏：重启后驱动不会自动加载，进入系统后执行 `uninstall_kernel_guard.ps1`；必要时用安全模式删除服务与驱动文件
6. 首次加载与 Ping/Query/卸载全部通过后，才允许启用 Driver Verifier；先用 volatile 配置，避免持久化设置导致重启循环

---

## 15. Phase 1 完成与 Phase 2B 首次实机加载（2026-11-23）

### 15.1 Phase 1 环境

- TESTSIGNING：重启后 `True`
- Secure Boot：关闭
- HVCI/VBS：未运行
- WDKTestCert：已导入 `LocalMachine\Root` 与 `TrustedPublisher`
- 驱动 / catalog：`Valid`
- BitLocker：C/D/E 均 `FullyDecrypted`、保护关闭
- BCD 与旧服务/应用已备份到 `build/kernel-rollback/20261123-204004`
- System Restore 不可用（系统保护未启用），以 BCD + 文件备份替代

### 15.2 Phase 2A 安装

- `install_kernel_guard.ps1 -AllowTestSigned -SkipStart`
- 服务：`KERNEL_DRIVER`、`DEMAND_START`、`STOPPED`
- `ImagePath`：`\??\C:\Program Files\Verthys\SecurityService\driver\VerthysGuard.sys`
- 设备未创建，符合未启动状态

### 15.3 根因：P/Invoke CreateService 生成不可启动条目

隔离矩阵：

| 创建方式 | 驱动位置 | StartService |
| --- | --- | --- |
| `sc.exe create` | `System32\drivers` | 成功启动/停止 |
| P/Invoke `CreateService` | `System32\drivers` | 1243 |
| `sc.exe create` | `Program Files\...` | 成功启动/停止 |
| P/Invoke `CreateService` | `Program Files\...` | 1243 |

结论：驱动本身、test-signed 签名与 Program Files 路径均正常；问题在 `kernel_guard_common.ps1` 的 P/Invoke `CreateService`。已改为 `sc.exe create`，路径含空格时整体引用。

### 15.4 正式服务首次加载

- 卸载旧 P/Invoke 服务后，用修复脚本重新安装
- `sc start VerthysGuard`：`RUNNING`
- 停留 1 秒后 `sc stop VerthysGuard`：`STOPPED`
- 无蓝屏；`DriverEntry` 与 `DriverUnload` 实机通过
- 测试服务 `VerthysGuardTest*` 与 `System32` 临时文件已清理
- 对照驱动 `vpci` 已启动且不可停止；为 Microsoft 驱动，重启后自动清除

### 15.5 尚未执行

- SYSTEM 探针的 Ping/Query IOCTL
- ARM/REGISTER/DISARM 与 dummy worker
- A1–A14 攻击回归
- Driver Verifier、长时间稳定性、服务/应用端到端

---

## 16. Phase 2C：SYSTEM 探针 Ping/Query（2026-11-23）

### 16.1 夹具

- 新增 `tests/kernel-guard/kg_probe.c`
- 新增 `scripts/build/build_kernel_probe.ps1`
- 探针通过临时 SYSTEM 计划任务运行（设备 ACL 仅允许 SYSTEM）
- 只发送 PING 与 QUERY_STATUS，不执行 ARM/REGISTER，不接触用户进程

### 16.2 发现并修复的驱动缺陷

首次探针返回 `open_ok=true`、`ping/query call_ok=true`、`bytes=72`，但响应
`Header.Command=0`、`Header.RequestId=0`。根因是 METHOD_BUFFERED 下
输入/输出共用系统缓冲，`VtgCompleteStatus` 先 `RtlZeroMemory` 输出缓冲，
把输入 Header 的 Command/RequestId 一起清零。

修复：在 `WdfRequestRetrieveOutputBuffer` 与清零之前保存
`RequestHeader->Command` 与 `RequestHeader->RequestId`，再写入响应头。

### 16.3 修复后结果

```json
{
  "status": "PASS",
  "open_ok": true,
  "ping_ok": true,
  "query_ok": true,
  "ping_header_command": 1,
  "query_header_command": 6,
  "protocol_major": 1,
  "protocol_minor": 0,
  "state": 0,
  "reason": 0,
  "capabilities": 3,
  "protected_count": 0,
  "expected_state_unarmed": true,
  "expected_protected_zero": true
}
```

- 驱动启动、探针执行、驱动停止全部成功
- 无蓝屏
- 服务最终 `STOPPED`
- `vpci` 对照驱动仍为 RUNNING（Microsoft 驱动，不可停止；重启自动清除）

### 16.4 尚未执行

- ARM/REGISTER/DISARM 与 dummy worker
- A1–A14 攻击回归
- Driver Verifier、长时间稳定性、服务/应用端到端

---

## 17. Phase 2D：ARM/REGISTER 正控（通过）

### 17.1 阻断现象

ARM 成功后，探针 `CreateProcessW` 创建挂起态 dummy 返回 `ERROR_ACCESS_DENIED(5)`。

| 条件 | CreateProcess |
| --- | --- |
| 驱动未加载 | 成功 |
| 驱动加载但 UNARMED | 成功 |
| 驱动 ARMED | 失败 5 |

### 17.2 根因

诊断字段显示最后一次完整剥离的调用者是 `csrss.exe`（PID 964）。
CreateProcess 初始化阶段由 csrss 打开新进程/线程句柄；驱动把它当作外部
调用者完整剥离，导致初始句柄权限不足，CreateProcess 失败。

临时跳过 `VtgObInit` 后正控全流程通过，确认问题在 Ob 回调判定。

### 17.3 修复

- 目标进程处于**未确认 bootstrap** 窗口时，允许 LocalSystem 令牌的调用者
  完整访问（csrss 等创建路径）
- 父进程仍按 bootstrap 规则放行；服务、目标自身不变
- 外部同用户进程始终完整剥离
- REGISTER 后目标变为 Confirmed，不再命中 SYSTEM 例外
- 增加父 PID 回退匹配，避免父对象查找失败导致 bootstrap 失效
- 移除诊断用的响应头 Reserved 字段

### 17.4 最终验证

最终构建（无诊断字段）SYSTEM 探针结果：

```json
{
  "status": "PASS",
  "initial_state": 0,
  "arm_ok": true,
  "arm_state": 1,
  "arm_count": 0,
  "dummy_created": true,
  "register_ok": true,
  "register_state": 2,
  "register_count": 1,
  "active_ok": true,
  "active_state": 2,
  "active_count": 1,
  "disarm_ok": true,
  "final_state": 0,
  "final_count": 0
}
```

- 驱动启动/ARM/REGISTER/ACTIVE/DISARM/停止全部成功
- 无蓝屏
- 服务最终 `STOPPED`
- dummy 进程与临时目录已清理

### 17.5 尚未执行

- A1–A14 攻击回归
- Driver Verifier、长时间稳定性、服务/应用端到端

---

## 18. Phase 2E：同用户攻击集 A1–A14（通过）

### 18.1 夹具

- `kg_creator.exe`：以当前用户（非提权计划任务）创建挂起态 dummy，分配
  `KILL_ON_JOB_CLOSE` Job，并在发布身份前保留 500 ms 窗口供 A14 尝试
- `kg_arm_probe.exe --hold`：以 SYSTEM 运行，ARM 后等待 creator 身份，先提交
  伪造身份（A12/A13），再 REGISTER 真实身份并保持 ACTIVE
- `kg_attack.exe`：以当前用户（非提权计划任务）攻击，与 creator 同用户但不是父进程
- `kg_a14_probe.exe`：同用户独立进程，先写轮询标记，再按映像名发现 dummy 后立即
  尝试打开并读取；记录目标 PID 与耗时
- 编排：`build/kernel-phase2e-attack.ps1`；证据：
  `build/kernel-rollback/20261123-204004/phase2e-attack.json`

### 18.2 结果

| 用例 | 观测 | 结果 |
| --- | --- | --- |
| A1 读取 | `OpenProcess` 返回句柄，`ReadProcessMemory` 返回 5 | PASS |
| A2 写入 | `WriteProcessMemory` 返回 5 | PASS |
| A3 远程线程 | `CreateRemoteThread` 返回 5 | PASS |
| A4 APC | `QueueUserAPC` 返回 5 | PASS |
| A5 挂起 | `NtSuspendProcess` 返回 `STATUS_ACCESS_DENIED(0xC0000022)` | PASS |
| A6 终止 | `TerminateProcess` 返回 5 | PASS |
| A7 调试 | `DebugActiveProcess` 返回 5 | PASS |
| A8 Dump | `MiniDumpWriteDump` 返回 1 | PASS |
| A9 句柄复制 | `DuplicateHandle` 返回 5 | PASS |
| A10 Job 生命周期 | `AssignProcessToJobObject` 成功，dummy 存活到攻击完成 | PASS |
| A11 服务能力 | SYSTEM 服务以 `QUERY_LIMITED_INFORMATION \| TERMINATE` 打开受保护 dummy 成功 | PASS |
| A12 PID 复用 | 创建时间 +1000 的 REGISTER 被拒绝 | PASS |
| A13 伪造路径 | 末字符篡改的 REGISTER 被拒绝 | PASS |
| A14 第一刻窗口 | 轮询启动后 187 ms 发现目标（PID 与 dummy 一致），PEB 可查询；`OpenProcess(VM_READ)` 返回句柄但 `ReadProcessMemory` 返回 5 | PASS |

- 驱动：启动、ARM、REGISTER、ACTIVE、DISARM、停止全部成功
- 探针状态：`PASS`；攻击状态：`PASS`；A14 状态：`PASS`
- 无蓝屏；服务最终 `STOPPED`
- 用户任务与 SYSTEM 任务均已注销；dummy 与临时目录已清理
- A15（管理员终止/调试）不在承诺内，记录为 SKIP，不判 PASS

### 18.3 尚未执行

- S1/S6/S10、72 小时稳定性
- HVCI + 生产签名驱动、安装器一次 UAC 端到端
- 服务/应用端到端（宿主预 ARM、REGISTER、运行中丢失锁定）

---

## 19. Phase 2F：Driver Verifier 与 1000 次加载/卸载（通过）

### 19.1 配置

- `verifier /standard /driver VerthysGuard.sys`：flags `0x001209BB`，仅验证
  VerthysGuard.sys（Special pool、IRQL、Pool tracking、I/O、Deadlock、DMA、
  Security、Misc、DDI）
- `verifier /bootmode resetonunusualshutdown`：蓝屏等非正常关机后自动清除设置，
  避免重启循环
- volatile 模式不支持 standard 标志（实测 `0x10` 被拒绝），因此采用持久化配置
- 重启后 `verifier /query` 显示驱动在验证列表，初始 `load: 0 / unload: 0`

### 19.2 验证结果

| 项 | 结果 |
| --- | --- |
| A1–A14 攻击集（Verifier 下，循环前） | `probe/attack/a14` 全部 `PASS`，A14 目标 PID 一致 |
| 加载/卸载循环 | 1000/1000 通过，无失败 |
| 循环耗时 | 51.7 s；最大启动 156 ms，最大停止 69 ms |
| 循环后攻击集 | `probe/attack/a14` 全部 `PASS` |
| Verifier 计数 | `load: 1007 / unload: 1007`（1 次攻击套件 + 5 次冒烟 + 1000 次循环 + 1 次循环后复跑） |
| 系统事件 | 无 Verifier/BugCheck 事件，无蓝屏 |
| 结束状态 | 驱动 `Stopped`，无进程/任务/临时目录残留 |

证据目录：`build/kernel-rollback/20261123-2207-verifier/`

- `phase2e-attack.json`：Verifier 下攻击集
- `load-cycles-smoke.json`：5 次冒烟
- `load-cycles-1000.json`：1000 次循环
- `post-cycle/phase2e-attack.json`：循环后复跑

### 19.3 加载/卸载夹具

- `scripts/kernel/test_load_cycles.ps1`：按 `ServiceController` 启动/停止，
  记录每轮延迟，首轮失败即停止并输出 JSON
- 1000 轮参数：`-Count 1000`；默认输出 `build_driver/load-cycles.json`

### 19.4 回滚与当前状态

- 已执行 `verifier /reset`；`/querysettings` 显示 Flags=0、Verified Drivers=None
- 当前启动内已验证计数保留（`load: 1007 / unload: 1007`），下次重启后不再验证
- 驱动为 `DEMAND_START`，重启不会自动加载，不会形成启动循环

### 19.5 发布门禁取证

- `collect_kernel_gate.ps1`：`PASS`
- 证据：`build_driver/kernel-gate.json`
- 环境：TESTSIGNING=True、Secure Boot=False、HVCI 未运行；sys/cat 签名 `Valid`；
  安装状态哈希与文件一致
- 剩余 pending：S1/S5/S6/S10、72 小时稳定性、应用端到端、HVCI + 生产签名

---

## 20. Phase 4 准备：候选包与端到端夹具（2026-11-23）

### 20.1 候选包构建

- 命令：`pwsh -NoProfile -File build_production.ps1 -Profile local -AllowLocal -NoPause`
- 结果：全部构建成功
- 安装包：`verthys-tauri\src-tauri\target\release\bundle\nsis\Verthys_4.6.5_x64-setup.exe`
  - 7,325,192 字节；SHA-256 `40AC5B02...B51A64`；Authenticode `Valid`
- 组件：

| 组件 | 路径 | SHA-256 | 签名 |
| --- | --- | --- | --- |
| 应用 | `build\kernel-e2e-candidate\Verthys.exe`（构建后最终副本） | `96A1FA8F...12A292` | Valid（CN=Verthys） |
| worker | `build\kernel-e2e-candidate\verthys-worker.exe` | `8DB56392...FE1C08` | Valid |
| DLL | `build\kernel-e2e-candidate\verthys.dll` | `B2BEC912...E71812C` | Valid |
| 服务 | `build\security-service\VerthysSecuritySvc.exe` | `205532D6...0847FEF` | Valid；local profile 为 Debug |

- 构建修复：打包器生成安装包后会恢复未打补丁的原始主程序，恢复副本不带签名；
  `build_production.ps1` 在打包完成后对最终落盘副本重新签名并复核，当前副本已按同一
  签名入口补签
- 安装包内主程序由打包器在 bundle type 补丁后签名；本地端到端使用暂存目录运行

### 20.2 端到端夹具

- 脚本：`scripts/kernel/test_kernel_e2e.ps1`
- 前置：候选服务已安装且哈希匹配；驱动已安装（脚本按需启动）；应用以普通用户
  运行并由用户完成解锁
- 流程：预检 → 启动驱动 → 受限用户任务启动应用 → 等待 worker → SYSTEM 探针确认
  `ACTIVE/count=1` → 同用户 `PROCESS_VM_READ` 尝试被拒绝 → 锁定/退出后 count 归零
- 可选 `-StopDriverAfterActive`：SECURE 档下停止驱动，验证看门狗销毁 worker 并恢复驱动
- 证据：`build_driver/kernel-e2e.json`

### 20.3 预检结果

- 应用、worker、DLL 签名均为 `Valid`；暂存应用与应用哈希匹配
- 安装的服务 SHA-256 `172752B6...4FF2C56` 与候选 `205532D6...0847FEF` 不一致，
  按设计阻断，等待安装候选服务
- `-PreflightOnly -SkipServiceMatch` 自检：SYSTEM 探针 `PASS`，`state=0/count=0`，
  驱动启动与停止正常，结束后无任务与进程残留
- 夹具修复：SYSTEM 探针的工作目录必须在探针任务启动前创建，否则任务无法启动
- 尚未执行：候选安装（UAC）、交互解锁正控、S6 损失场景

---

## 21. Phase 4 正控：4.6.6 端到端与驱动修复（2026-11-23）

### 21.1 根因与修复

- 现象：应用解锁时安全核心启动失败；worker stderr：
  `DLL 加载失败 (Display): LoadLibraryExW failed`，Debug 为
  `14001 ERROR_SXS_CANT_GEN_ACTCTX`
- 根因：驱动在 REGISTER 后把 LocalSystem 调用者（csrss/lsass 等）也按完整
  掩码剥离；worker 加载 verthys.dll 的激活上下文创建依赖这些系统调用者
- 修复：`VtgProcessPreOperation` / `VtgThreadPreOperation` 对 LocalSystem
  令牌调用者始终放行；外部同用户进程仍完整剥离；移除不再使用的
  `VtgStateIsBootstrapTarget`
- 版本统一 4.6.6：VERSION、Cargo.toml、package.json/lock、config.ts、
  驱动、服务、应用、worker

### 21.2 生命周期修复

- `kernel_watchdog` 仅持有 `Weak<SessionInner>`，每轮采样临时升级；会话替换
  或销毁时旧 SessionInner 立即 Drop，Job `KILL_ON_JOB_CLOSE` 终止旧 worker
- `kill_orphan_workers` 跳过当前进程子进程，避免误杀当前受保护 worker
- `worker_init` 在 Ready 且 worker 存活时直接复用，避免重复触发替换
- 实测：两次 `worker_init` 后旧 worker 被清理，最终仅 1 个受保护 worker

### 21.3 结果

| 组件 | 版本 | SHA-256 | 签名 |
| --- | --- | --- | --- |
| 应用 | 4.6.6 | `9C97BFAF...BE7DEC` | Valid |
| worker | 4.6.6 | `26B6D697...E9524E` | Valid |
| DLL | — | `B2BEC912...E71812C` | Valid |
| 服务 | 4.6.6 | `73164E1F...929DEF4` | Valid |
| 驱动 | 4.6.6 | `ABDF9BC8...01BA1CB4` | Valid |
| 安装包 | 4.6.6 | `64A7ECCF...050F9C4E` | Valid |

- 驱动修复后 A1–A14 回归：`probe/attack/a14` 全部 `PASS`
  （`build/kernel-rollback/20261123-2310-driver-fix/phase2e-attack.json`）
- 端到端正控（候选暂存目录，人工执行）：
  - 解锁后预 ARM/REGISTER 成功，worker DLL 加载成功，驱动 `ACTIVE/count=1`
  - 同用户 `PROCESS_VM_READ` 被拒绝，错误码 5
    （`build_driver/access-final-16736.json`）
  - 关闭应用后 `state=ARMED/count=0`，无 app/worker 残留
    （`build_driver/driver-status.json`）
- 端到端脚本 `-PreflightOnly`：`PREFLIGHT_PASS`；正式脚本自动运行被取消，
  以上为人工执行与证据

### 21.4 S6 运行中丢失（通过）

- SECURE 预设（`preset.json code=1`）、解锁后驱动 `ACTIVE/count=1`，
  worker PID=16692
- 停止驱动后 **3.15 s** worker 退出；日志：
  `[kernel-watchdog] 内核保护连续 2 次非 ACTIVE，执行会话锁定`、
  `[session_guard] 外部锁定序列开始: reason=kernel_lost`、
  worker 锁库并销毁
- 驱动重启后 `UNARMED/count=0`
- 证据：`build_driver/kernel-s6-loss.json`

### 21.5 S1 preferred 降级（通过）

- 卸载驱动后驱动服务不存在，应用仍解锁成功；worker 就绪（PID 1976）
- 日志：`宿主预 ARM 未生效（preferred）: 安全服务拒绝内核命令（状态 5）`
- 安全中心显示内核不可用（人工确认）
- 证据：`build_driver/kernel-s1-degraded.json`
- 驱动已重新安装 4.6.6（`ABDF9BC8...`），服务 `Running`；按 S7 本会话
  不自动恢复保护，下次解锁启用

### 21.6 S10 worker 异常退出与重新登记（通过）

- SECURE 预设、解锁后驱动 `ACTIVE/count=1`，worker PID=5688
- SYSTEM 终止 worker 后约 2 s：
  `[kernel-watchdog] worker 异常退出，执行会话锁定`、
  `[session_guard] 外部锁定序列开始: reason=worker_exit`，
  worker 会话强制销毁，驱动回到 `ARMED/count=0`
- 重新解锁后新 worker PID=2904 完成预 ARM/REGISTER，驱动
  `ACTIVE/count=1`，同用户读取被拒绝（error 5）
- 修复：内核看门狗在 worker 非主动退出时执行 `worker_exit` 锁定；
  主动替换/销毁通过 stop 标志区分，不误锁
- 证据：`build_driver/kernel-s10-restart.json`、
  `build_driver/kernel-s10-recovery.json`、
  `build_driver/access-s10-recovery.json`

### 21.7 S5 preferred 故障注入（通过，状态标签已修复）

- 测试特性 `test_hooks` 强制 REGISTER 失败
  （`VERTHYS_TEST_KERNEL_REGISTER_FAIL=1`）：注入日志出现，宿主按
  preferred 继续并完成解锁
- 根因补充：宿主 REGISTER 失败后 worker 仍会自 ARM/REGISTER，驱动最终
  `ACTIVE/count=1`；旧 UI 把“内核状态报告缺失/滞后”当成用户态降级，
  形成“UI 已降级 vs 驱动 ACTIVE”的不一致
- 修复（2026-11-24）：
  - SECURE 下报告缺失显示“内核加固 确认中”，不判降级、不写降级审计
  - 只有拿到明确的非 ACTIVE 状态才显示“高安全 用户态降级”
  - ACTIVE + reason=5 显示“内核加固 已启用 登记降级”
  - `runtime-guards` / verthys 就绪后追加 1s、3s 两次重采样，追赶 worker 自登记
  - 前端契约测试 19 项、全量 943 项通过；`vue-tsc --noEmit` 与生产构建通过；
    S5 真机复测待执行（需 test_hooks 签名宿主 + 解锁）
- 驱动仍为 `ACTIVE/count=1`：worker 自登记使保护继续；
  关闭应用后回到 `ARMED/count=0`
- `required` 分支为 K2，不在 K1
- 证据：`build_driver/kernel-s5-preferred.json`（原始观测）、
  `build_driver/kernel-s5-preferred-final.json`（结论）

### 21.8 尚未执行

- S5 真机复测（状态标签代码与前端契约已修复，需 test_hooks 签名宿主 + 解锁确认）
- 72 小时稳定性
- 安装器整包干净机安装/卸载、HVCI + 生产签名

---

## 22. 开发签名运行时（2026-11-24）

### 22.1 问题与根因

- 开发宿主 `target/debug/verthys-tauri.exe` 未签名且基名不是 `verthys.exe`；
  服务只接受钉扎发布者签名的宿主（`pipe_server.c` → `vty_auth_client_process`）。
- 开发树 worker 位于 `verthys-worker/target/{debug,release}`，与宿主不同目录；
  服务宿主预 ARM 只接受同目录白名单 worker，`prearm_image` 返回 `None`。
- `build_dev.ps1` 使用测试钩子 DLL 并设置 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS`；
  该旁路在 `vty_machine_limiter.c` 直接返回 OK，短路 `kernel_status`，
  导致驱动 ACTIVE 时 UI 仍显示降级。
- worker `build.rs` 默认 API 版本硬编码 `0x0016`；核心已升到 `0x0017` 时
  worker 拒绝加载 DLL（`DLL API version 0017 is newer than worker-known 0016`）。

### 22.2 实施

- `scripts/build/build_core.release.ps1` 新增 `-BuildDir`；开发核心独立构建到
  `build_dev/`，使用 `-ReleaseSigning`（调用方认证 ON、测试钩子 OFF），
  契约写到 `build_dev/core/verthys.artifacts.json`，不触碰生产 `build/`。
- `scripts/dev/dev_runtime.ps1`：
  - 校验签名证书 SHA-256 与服务构建元数据 `publisherSha256` 一致；
    `VerthysSecuritySvc` 必须 Running，缺失即失败，不静默降级。
  - 核心与 worker 指纹 + 哈希戳 `build_dev/dev-runtime.json`；未变化时跳过
    重建，避免每次开发都重新链接 C 核心并刷新 DLL 哈希。
  - worker 以 `VERTHYS_DLL_PATH=<dev DLL>` 和
    `VERTHYS_WORKER_API_VERSION=<header>` 构建，签名后暂存到
    `src-tauri/verthys.dll`、`src-tauri/binaries/` 与 `target/debug/` 同级。
- `scripts/dev/dev_runner.cs`：Cargo 目标运行器。Cargo 的
  `CARGO_TARGET_*_RUNNER` 只接受单个可执行路径，因此用编译 shim 启动
  `scripts/dev/dev_app_launcher.ps1`，并以 Job Object + 父进程看门狗保证
  Tauri 监听重启时不留下孤儿进程。
- `scripts/dev/dev_app_launcher.ps1`：复制刚构建的宿主为
  `target/debug/Verthys.exe`，Authenticode 签名并复核；清除机器预算旁路后
  启动，宿主与 worker/DLL 同目录。
- `src-tauri/build.rs`：Debug 专用 `VERTHYS_DEV_DLL_PATH` 覆盖 `DLL_HASH`；
  Release 设置该变量直接 panic，防止开发 DLL 进入生产包。
- `path_resolver.rs`：Debug 构建优先宿主同级 `verthys-worker.exe` /
  `verthys.dll`；Release 顺序不变。
- `verthys-worker/build.rs`：默认 API 版本改为从
  `core/include/verthys_version.h` 读取，与 C ABI 同步；环境变量仍可覆盖。
- `build_dev.ps1`：删除测试钩子核心重建与机器预算旁路，改为
  “隔离签名核心 + 签名 worker + 签名宿主”的日常开发链路。

### 22.3 实测证据

- `build_dev.ps1` 首次：核心与 worker 构建并签名；
  `build_dev/core/Release/verthys.dll` 与 worker 签名者 SHA-256 均为
  `cbb8aac9...8d3849`；CMake 缓存
  `VERTHYS_REQUIRE_CALLER_SIG=ON`、`VERTHYS_TEST_HOOKS=OFF`。
- 第二次：日志 `Dev core up to date; skipping rebuild` 与
  `Dev worker up to date; skipping rebuild`，仅增量构建宿主并启动。
- 应用日志：
  `[resolve_worker] 开发运行时同级命中: ...\target\debug\verthys-worker.exe`；
  `[resolve_dll] 开发运行时同级命中: ...\target\debug\verthys.dll`；
  `[kernel-guard] 宿主预 ARM 已提交`、`worker 已登记为受保护进程`；
  worker `DLL 完整性校验通过: d3078036...c6416`、
  `Verthys_Init 成功（六层动态防护已就绪）`。
- 同用户 `OpenProcess(PROCESS_VM_READ)` 对 worker 返回 0，Win32 错误 5。
- 监听重启：旧 app PID 3696 / worker 18892 全部退出；新 app PID 22228 /
  worker 20912 启动，进程数各 1，VM_READ 仍为错误 5。
- 关闭应用：app / worker / dev_runner 均为 0，无残留。
- 生产产物前后哈希不变：DLL `B2BEC912...E71812C`、worker
  `26B6D697...E9524E`、服务 `73164E1F...929DEF4`、根 CA `4107A2FA...D7BE5`。
- 宿主 `cargo test --offline --lib`：614 passed / 2 ignored；
  worker `cargo test --offline`：136 passed / 1 ignored。
- Release 保护：设置 `VERTHYS_DEV_DLL_PATH` 执行 `cargo check --release`
  在 `build.rs` 直接 panic；未设置该变量时，Release 素材门禁拒绝
  `src-tauri/verthys.dll` 的开发副本（`d3078036...` ≠ `b2bec912...`），
  证明开发产物不能进入生产包。

### 22.4 风险与待办

- 开发前置条件：P2 服务已安装且 Running、签名证书与服务钉扎一致。
- 开发运行会将签名开发 DLL/worker 暂存到 `src-tauri/`；生产构建必须刷新
  这些素材，Release 门禁会在不一致时硬阻断。
- 当前工作树把核心 API 升到 `0x0017`，但既有
  `verthys-worker/target/release/verthys-worker.exe` 仍是 `0x0016` 且
  worker 源码新于该产物；生产构建必须先重新构建 worker（修复后的
  `build.rs` 会从核心头文件派生 `0x0017`）并刷新暂存素材。
- S5 状态标签一致性与 72 小时稳定性仍不在本轮范围。
