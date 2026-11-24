# 05 测试与验证

| 项目 | 内容 |
| --- | --- |
| 状态 | 评审稿 |
| 范围 | 内核加固单元、集成、攻击回归、兼容性、稳定性与验收门禁 |
| 关联 | [03-driver-design.md](03-driver-design.md)、[04-service-and-preset.md](04-service-and-preset.md)、[06-build-signing-release.md](06-build-signing-release.md) |

> Last updated: 2026-11-22

---

## 1. 测试原则

1. **默认无驱动**：常规 CI 不加载驱动，现有 C/Rust/TS 全量测试必须在无驱动环境通过
2. **驱动验证在 VM**：加载、卸载、攻击回归、蓝屏分析只在一次性 Windows VM 执行
3. **证据可复现**：每个用例输出机器可读结果，包含构建哈希、OS build、驱动版本、HVCI/Secure Boot 状态
4. **测试隔离**：不触碰真实用户目录、真实容器、真实 `%ProgramData%\Verthys\Security`
5. **测试钩子不进生产**：生产构建不包含 `--test-*`、测试证书、放宽 ACL 的分支
6. **失败必须可归因**：区分驱动缺陷、服务缺陷、应用缺陷、环境限制；不允许“重跑看看”

---

## 2. 测试分层

| 层 | 运行环境 | 内容 | 是否默认 CI |
| --- | --- | --- | --- |
| L0 静态 | 构建机 | `/W4 /WX`、SAL、CodeQL、驱动加载规则检查 | 是 |
| L1 协议/状态单元 | 用户态 | 协议编解码、路径规范化、访问掩码计算、状态机、超时 | 是 |
| L2 驱动单元（用户态替身） | 用户态 | 受保护表、身份校验、事件缓冲逻辑（抽离为可测纯函数） | 是 |
| L3 驱动集成 | VM | 真实驱动加载、IOCTL、Ob 回调、进程登记、卸载 | 否，VM 门禁 |
| L4 应用集成 | VM | 服务 + 驱动 + worker + Tauri + 解锁/切档/重启 | 否，VM 门禁 |
| L5 攻击回归 | VM | 同用户读内存、注入、终止、挂起、调试、Dump、PID 复用 | 否，VM 门禁 |
| L6 兼容/稳定性 | VM/物理机 | HVCI、Secure Boot、AV/EDR、长时间运行、升级/卸载 | 否，发布门禁 |

---

## 3. 测试矩阵

### 3.1 单元测试（L1/L2）

| 编号 | 用例 | 断言 |
| --- | --- | --- |
| U1 | 协议头长度/版本/保留字段 | 非法值全部拒绝，合法值通过 |
| U2 | 命令白名单 | 未知命令返回 `NOT_SUPPORTED` |
| U3 | 路径规范化 | 大小写、设备路径、尾随分隔符一致处理 |
| U4 | 身份匹配 | PID 同、创建时间/路径不同必须拒绝 |
| U5 | 访问掩码 | 进程/线程危险权限被剥离，查询权限保留 |
| U6 | 受保护表容量 | 超过上限返回 `CAPACITY_EXCEEDED`，不越界 |
| U7 | 事件环形缓冲 | 覆盖最旧、计数正确、无越界 |
| U8 | 状态快照 | 状态/原因/计数一致，无撕裂 |
| U9 | 超时/重试 | 版本不匹配不重试；瞬时错误只重试一次 |
| U10 | 策略语义 | `preferred/required/off` 分支符合表格 |

### 3.2 驱动集成（L3）

| 编号 | 用例 | 断言 |
| --- | --- | --- |
| D1 | 加载/卸载 | 加载成功、设备可打开、卸载无残留 |
| D2 | 设备 ACL | 普通用户无法打开设备；SYSTEM 服务可打开 |
| D3 | Ping/版本 | 版本/能力返回正确；不匹配返回明确状态 |
| D4 | ARM/REGISTER | 合法进程登记成功；非法身份拒绝 |
| D5 | 进程退出 | 登记项释放，事件生成，无悬空引用 |
| D6 | 并发登记 | 多线程登记/注销/查询无死锁、无越界 |
| D7 | 卸载竞态 | 注销回调后在途回调归零，再释放内存 |
| D8 | 事件拉取 | 环形缓冲读取、覆盖、丢弃计数正确 |
| D9 | 压力 | 1000 次加载/卸载、1000 次登记/注销无泄漏 |
| D10 | IOCTL 畸形输入 | 超长/截断/空指针/保留位非零全部拒绝 |

### 3.3 攻击回归（L5）

| 编号 | 攻击 | 期望 |
| --- | --- | --- |
| A1 | 同用户 `OpenProcess(PROCESS_VM_READ)` + `ReadProcessMemory` | 打开被剥离权限，读取失败 |
| A2 | `WriteProcessMemory` | 失败 |
| A3 | `CreateRemoteThread` | 失败 |
| A4 | `QueueUserAPC` | 失败 |
| A5 | `SuspendThread` / `NtSuspendProcess` | 失败 |
| A6 | `TerminateProcess` | 失败 |
| A7 | `DebugActiveProcess` | 失败 |
| A8 | `MiniDumpWriteDump` | 失败 |
| A9 | `DuplicateHandle` 危险权限 | 失败 |
| A10 | 父进程通过 Job Object 回收 worker | 成功（生命周期不受影响） |
| A11 | 可信服务查询/终止受保护进程 | 成功（服务保留能力） |
| A12 | PID 复用后登记 | 身份不匹配，拒绝 |
| A13 | 伪造映像路径登记 | 身份不匹配，拒绝 |
| A14 | ARM 后创建 worker，攻击进程立即尝试打开 | 外部新开句柄从第一刻起被剥离；父进程 Job 分配成功 |
| A15 | 管理员终止/调试 | 不在承诺内；记录为 SKIP，不判 PASS |

Round 8 状态：生产布局下宿主已在 `CREATE_SUSPENDED` 之前 ARM 同目录 worker，并在挂起态提交 PID/创建时间完成 REGISTER，代码链路已闭合 A14 窗口；开发树不同根时跳过预 ARM。

Phase 2E 状态：A1–A14 已在实机测试签名环境执行并全部通过。A14 用同用户独立进程在 ARM 后按映像名轮询，轮询启动后 187 ms 发现目标并立即尝试打开；`PROCESS_VM_READ` 被剥离，`ReadProcessMemory` 返回 5。A15 不在承诺内，记录 SKIP。

### 3.4 状态与失败语义（L4）

| 编号 | 场景 | 期望 |
| --- | --- | --- |
| S1 | `preferred` + 驱动未安装 | 解锁成功，状态 `DEGRADED`，UI 明示 |
| S2 | `required` + 驱动未安装 | 解锁中止，状态 `FAIL_CLOSED` |
| S3 | 驱动停止 | 已解锁会话锁定；未解锁按策略处理 |
| S4 | 版本不匹配 | 不重试，`preferred` 降级；`required` 拒绝 |
| S5 | 注册失败 | `preferred` 继续并标记；`required` 锁定 |
| S6 | 运行中丢失 | 连续 2 次健康检查失败后立即锁定 |
| S7 | 驱动恢复 | 不在已解锁会话自动挂载；下次解锁启用 |
| S8 | 运行期切到 SECURE | 成功则 ACTIVE；失败按策略回滚/降级 |
| S9 | 运行期切出 SECURE | 注销保护，驱动保持空闲 |
| S10 | worker 重启 | 重新登记；失败按策略处理 |
| S11 | 解锁前预设读取失败 | 现有 fail-closed 行为不变 |
| S12 | `required` 恢复路径 | 按 K2 定稿方案执行，审计可见 |

### 3.5 兼容性（L6）

| 编号 | 环境 | 断言 |
| --- | --- | --- |
| C1 | Windows 10 1809 x64 | 加载/保护/卸载正常 |
| C2 | Windows 10 22H2 x64 | 同上 |
| C3 | Windows 11 22H2/23H2/24H2 | 同上 |
| C4 | HVCI 开启 + 生产签名驱动 | 驱动可加载；无动态代码/W+X |
| C5 | Secure Boot 开启 + 生产签名 | 驱动可加载 |
| C6 | Secure Boot 关闭 + 测试签名 + HVCI 关闭 | 仅开发/内部；UI 提示 |
| C7 | Defender 开启 | 不拦截、不误报 |
| C8 | 第三方 AV/EDR（至少一种） | 可共存；冲突可诊断 |
| C9 | 任务管理器/Process Explorer | 受保护进程可见，危险操作失败 |
| C10 | WER | 受保护进程转储失败或按策略处理，不导致系统异常 |
| C11 | 备份/同步软件 | 不破坏正常文件读写；K3 时重点验证 |
| C12 | 升级/卸载 | 无残留；旧驱动可回滚 |

### 3.6 稳定性与性能

| 编号 | 项 | 目标 |
| --- | --- | --- |
| P1 | 驱动空闲内存 | < 5 MB |
| P2 | ACTIVE 增量解锁延迟 | p95 < 30 ms（不含现有 P2 验签） |
| P3 | CPU 占用 | 空闲 < 0.1%；健康检查无可感知抖动 |
| P4 | 文件 I/O | K1 不拦截文件，导入/导出性能不回归 |
| P5 | 连续运行 | 72 小时无蓝屏、无句柄泄漏、无内存增长 |
| P6 | 加载/卸载 | 1000 次无失败、无残留 |
| P7 | 并发 | 100 进程同时打开/终止/查询受保护进程，无死锁 |

---

## 4. VM 环境

### 4.1 测试签名 VM

- Hyper-V Gen2，Windows 11 x64（另备 Windows 10 1809/22H2）
- Secure Boot 关闭；`bcdedit /set testsigning on`
- 安装测试证书到 `LocalMachine\Root` 与 `LocalMachine\TrustedPublisher`
- 快照基线：干净系统、已装服务、已装驱动、已装应用
- WinDbg 内核调试（网络或串口）；开启 Kernel Dump
- 每个攻击用例前恢复快照，避免残留句柄/进程影响

### 4.2 生产签名 VM

- Secure Boot 开启；HVCI 开启
- 安装微软签名的驱动与正式应用
- 验证签名链、加载、升级、卸载
- 不使用测试证书、不开启 TESTSIGNING

### 4.3 测试隔离

- 测试容器放在临时目录，不使用真实用户库
- 服务测试使用测试管道/临时公钥，不触碰真实 `%ProgramData%\Verthys\Security`
- 驱动测试使用测试设备名或测试构建开关；生产设备名不被测试占用
- 测试结束清理进程、服务、驱动、证书、临时目录

---

## 5. 测试钩子

| 钩子 | 用途 | 生产构建 |
| --- | --- | --- |
| `VTG_TEST_HOOKS` | 允许测试控制台以受限身份调用 IOCTL、覆盖超时、注入错误 | 必须 OFF |
| `VTG_TEST_DEVICE_NAME` | 测试设备名，避免占用生产设备 | 必须不存在 |
| `VTG_TEST_CLOCK` | 模拟健康检查超时 | 必须不存在 |
| `VTG_TEST_ALLOW_NON_SYSTEM` | 允许测试进程打开设备 | 必须不存在 |

- 生产构建显式关闭全部测试钩子
- 发布前用字符串扫描与符号检查复核生产二进制
- 测试钩子不得改变生产路径的安全语义

---

## 6. 证据格式

每个 VM 用例输出 JSON：

```json
{
  "case": "A1",
  "result": "PASS",
  "build": "<git sha>",
  "driverVersion": "x.y.z",
  "protocol": "1.0",
  "os": "Windows 11 22631",
  "hvci": true,
  "secureBoot": true,
  "testSigning": false,
  "timestamp": "2026-11-21T12:00:00+08:00",
  "detail": "OpenProcess stripped PROCESS_VM_READ; ReadProcessMemory failed with 5"
}
```

- 驱动日志、服务事件日志、WinDbg 输出作为附件
- 失败用例必须保留复现命令、快照名、错误码
- 不允许只提交截图；截图仅作补充

环境与服务事实由 `scripts/kernel/collect_kernel_gate.ps1` 采集：

```powershell
pwsh -NoProfile -File scripts\kernel\collect_kernel_gate.ps1
```

输出 `build_driver\kernel-gate.json`，包含 OS build、HVCI、Secure Boot、TESTSIGNING、服务状态、包哈希/签名与 pending 用例清单。该脚本不加载驱动、不执行攻击用例；A1–A14、S1–S10 的结果仍须按上表格式追加。

---

## 7. 验收门禁

### 7.1 K1

- [ ] 无驱动环境：C/Rust/TS 全量测试通过
- [ ] 驱动加载/卸载/设备 ACL/版本/Ping 通过
- [x] A1–A13 通过；A14 无窗口；A15 记录 SKIP
- [ ] S1、S5、S6、S10 通过（S2/S4 的 required 分支在 K2 验证）
- [x] Driver Verifier 全项 0 问题
- [ ] HVCI 开启 + 生产签名驱动可加载；测试签名环境按 C6 关闭 HVCI
- [ ] 72 小时稳定性
- [x] 1000 次加载/卸载
- [ ] 生产构建无测试钩子
- [ ] 证据 JSON 归档

Round 8 已完成宿主预创建 ARM、REGISTER 目标校验与 S6 运行中丢失看门狗；Round 9 已完成安装器一次 UAC 驱动集成（代码、构建与静态校验）；Phase 2 已完成驱动实机安装、加载/卸载、Ping/Query、ARM/REGISTER 正控、A1–A14 攻击回归、Driver Verifier 全项与 1000 次加载/卸载；Phase 4 正控在 4.6.6 通过（解锁 → 预 ARM → REGISTER → ACTIVE/count=1 → 同用户读取拒绝 → 关闭后计数归零），并修复驱动对 LocalSystem 初始化调用的过度剥离；S6 运行中丢失通过（停止驱动后 3.15 s 自动锁定并销毁 worker，驱动重启后计数归零）；S1 preferred 降级通过（驱动缺失时仍可解锁，安全中心显示内核不可用）；S10 worker 异常退出自动锁定（reason=worker_exit）并在重新解锁后完成新 worker 登记。S5 preferred 故障注入通过：REGISTER 失败后宿主继续解锁且 UI 显示“已降级”；驱动 bootstrap 条目仍保护 worker，状态标签一致性待优化；72 小时稳定性、整包安装与 VM 门禁仍未完成。

### 7.2 K2

- [ ] K1 全部门禁
- [ ] S2/S4 的 `required` 分支通过
- [ ] S8/S9 运行期切档通过
- [ ] 主进程保护（若启用）攻击回归
- [ ] 生命周期/映像审计事件正确
- [ ] `required` 恢复路径验证（S12）
- [ ] 升级/回滚/卸载验证
- [ ] 运行中丢失锁定验证

### 7.3 K3（文件保护，条件启动）

- [ ] K2 全部门禁
- [ ] 文件写/删/改名白名单
- [ ] AV/备份/同步软件兼容
- [ ] minifilter 签名/认证路径确认
- [ ] 性能回归
- [ ] 卸载无残留

---

## 8. 不通过的判定

出现任一情况，K1/K2/K3 不得进入下一阶段：

- 有阻断级/严重级缺陷未关闭
- 受保护进程可被同用户读取、注入、终止、挂起、调试（A1–A9 任一失败）
- 驱动卸载后残留设备、回调、引用或蓝屏
- 无驱动环境出现现有功能回归
- 生产构建包含测试钩子或测试证书
- 证据不可复现或缺少关键环境字段

---

## 9. 手工验收

以下由维护人在真实环境执行，自动化只做辅助：

- 干净 VM 标准用户安装 → 一次 UAC → 服务与驱动状态正确
- 高安全档 + `preferred`：卸载驱动后解锁，UI 显示降级
- 高安全档 + `required`：卸载驱动后解锁，UI 阻止并给出修复入口
- 解锁后停止驱动：库立即锁定，worker 销毁
- 升级驱动：旧版本回滚可用
- 卸载：服务、驱动、设备、证书、注册表无残留

---

## 10. 关联文档

- [03-driver-design.md](03-driver-design.md)：IOCTL 与回调约束
- [04-service-and-preset.md](04-service-and-preset.md)：状态机与失败语义
- [06-build-signing-release.md](06-build-signing-release.md)：测试签名与生产签名
- [TESTING.md](../TESTING.md)：现有 C/Rust/TS 测试入口
