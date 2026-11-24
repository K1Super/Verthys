# Verthys 内核加固方案（Kernel Guard）

| 项目 | 内容 |
| --- | --- |
| 状态 | 执行中：Round 1/2 完成；Round 3 服务侧完成；Round 4 状态透传完成；Round 5 `preferred` 降级展示完成；Round 6 降级审计、驱动生命周期脚本与门禁取证完成；Round 7 服务侧 ARM/REGISTER/DISARM 与 C 核心激活完成；Round 8 宿主预创建 ARM、REGISTER 目标校验与运行中丢失自动锁定完成（代码/单测）；Round 9 安装器一次 UAC 驱动集成完成（代码/构建/静态校验）；Round 10 / Phase 0 全链路审查与阻断修复完成；Phase 1 测试签名环境完成；Phase 2B 实机加载/卸载通过；Phase 2C SYSTEM Ping/Query 通过；Phase 2D ARM/REGISTER 正控通过；Phase 2E 同用户攻击集 A1–A14 全部通过（A14 轮询启动后 187 ms 内发现目标并确认句柄已被剥离）；发布门禁取证 PASS（测试签名环境）；Driver Verifier 下 A1–A14 回归与 1000 次加载/卸载全部通过；Phase 4 正控在 4.6.6 通过（解锁 → 预 ARM → REGISTER → ACTIVE/count=1 → 同用户读取拒绝 → 关闭后计数归零），驱动修复 LocalSystem 初始化访问；S6 运行中丢失通过（3.15 s 自动锁定并销毁 worker）；S1 preferred 降级通过（驱动缺失仍可解锁并显示内核不可用）；S10 worker 异常退出自动锁定并重新登记通过；S5 preferred 故障注入通过（UI 已降级；bootstrap 状态标签一致性待优化）；72 小时稳定性与生产签名未验证 |
| 范围 | Windows x64，L1 内核辅助访问控制 |
| 依赖 | 现有 P2 SYSTEM 安全服务、三档安全预设、11 位特性契约 |
| 不包含 | 内核密钥托管、内核加解密、容器解析、全内核化 |
| 维护人 | K1Super |

> Last updated: 2026-11-23

---

## 0. 结论摘要

1. 内核层只做 **L1 访问控制**：用一个小驱动执行确定性拒绝，数据面继续留在用户态
2. 第一批只做 **受保护进程/线程句柄闸门**，保护 `verthys-worker.exe`；驱动不可用时 `SECURE` 降级用户态
3. 第二批加入 **生命周期与映像加载审计**，发现异常立即锁定；通知类能力不宣称阻断加载
4. 文件写/删/改名保护属于 **K3 条件项**，只有出现明确防勒索/防误删需求且 K2 稳定后才启动
5. 内核会话令牌/密钥释放 **不进入当前路线图承诺**，需要独立立项并修改 P2 非目标
6. 内核密钥托管、加解密、容器解析、反调试启发式、Hook 扫描、截屏拦截、剪贴板、USB、痕迹清理、空闲锁定、安全删除、网络过滤、性能优化 **永久不做**
7. 不新增第 12 个特性位；11 位契约保持 `0x7FF`，内核策略与运行状态独立返回
8. 生产签名走 EV + 微软 attestation；测试签名仅用于开发与内部测试机
9. 本机 SDK/WDK 已完成 KMDF 冒烟验证；K1 仍以维护人审核与 VM 门禁为前置

---

## 1. 范围与边界

### 1.1 本方案要解决的问题

| 问题 | 当前状态 | 内核加固目标 |
| --- | --- | --- |
| 同用户进程读取 worker 内存、Dump 密钥 | 用户态句柄扫描与检测，发现后处置 | 从源头剥离危险句柄权限，让读取/注入/终止直接失败 |
| 同用户进程注入 worker、远程线程、APC | 用户态反注入与 Hook 扫描 | 剥离 `PROCESS_CREATE_THREAD`、`THREAD_SET_CONTEXT` 等权限 |
| worker 被挂起、终止、调试附加 | 看门狗与检测 | 剥离 `PROCESS_SUSPEND_RESUME`、`PROCESS_TERMINATE`，生命周期走 Job Object |
| 驱动不可用时高安全档失效 | 无内核层 | `SECURE` 自动检测；`preferred` 降级用户态，`required` fail-closed |
| 文件被删改、策略文件被改写 | ACL 与用户态校验 | K3 条件项：文件写/删/改名保护 |

### 1.2 明确不做

- 不把 GMK、文件密钥、口令、明文照片放进内核
- 不在内核解析 `.verthys` 容器、不执行 AEAD、不做 KDF
- 不把 UI、worker、Rust 主进程搬进内核
- 不新增第 12 个特性位，不改变 `SECURE = 0x7FF`
- 不把内核加固做成应用运行的必要条件；只有 `required` 策略才 fail-closed
- 不覆盖管理员/内核攻击者；不承诺抵抗同机管理员
- 不承诺阻止离线复制容器后的爆破
- 不使用 SSDT/IDT Hook、PatchGuard 绕过、未文档化结构、动态代码

### 1.3 与现有 P2 服务的关系

- P2 `VerthysSecuritySvc` 是 **SYSTEM 权限的用户态 EXE 服务**，不是内核驱动
- P2 服务仍是强制依赖且 fail-closed；内核加固不改变 P2 的解锁闸门
- 内核驱动只接受 P2 服务的 IOCTL；应用不直接访问驱动
- P2 服务不可用时解锁本来就会被拒绝，内核降级不能覆盖这条规则

---

## 2. 文档索引

| 文档 | 内容 | 评审重点 |
| --- | --- | --- |
| [01-threat-model.md](01-threat-model.md) | 资产、信任边界、攻击者、攻击路径、残余风险 | 威胁模型是否覆盖真实风险；是否夸大内核能力 |
| [02-architecture.md](02-architecture.md) | 组件、信任边界、启动/解锁/切档/丢失/卸载时序 | 驱动是否越界进入数据面；生命周期是否闭合 |
| [03-driver-design.md](03-driver-design.md) | KMDF 驱动、设备对象、IOCTL、Ob 回调、受保护进程登记、并发与卸载 | 权限剥离范围、PID 复用、卸载安全、HVCI 兼容 |
| [04-service-and-preset.md](04-service-and-preset.md) | 服务托管、状态机、`preferred/required`、UI、审计、失败语义 | 降级是否显式；`required` 是否会锁死用户 |
| [05-test-and-verification.md](05-test-and-verification.md) | 测试分层、VM 矩阵、Driver Verifier、HVCI、验收门禁 | 无驱动回归是否完整；证据是否可复现 |
| [06-build-signing-release.md](06-build-signing-release.md) | WDK/SDK、构建、CI、测试签名、EV + attestation、发布与回滚 | 生产构建是否可能混入测试钩子 |
| [07-operations-maintenance.md](07-operations-maintenance.md) | 监控、事件、事故响应、升级节奏、兼容矩阵、责任 | 长期维护是否可持续 |
| [08-roadmap-adr.md](08-roadmap-adr.md) | K0–K4 路线、ADR、开放问题、决策记录 | 范围是否冻结；后续新增内核能力的判据 |
| [09-review-checklist.md](09-review-checklist.md) | 审核清单与签字门禁 | 未通过不得进入编码 |
| [10-execution-rounds.md](10-execution-rounds.md) | 分轮执行、回归证据与产品断裂防护 | 每轮范围、验证与未验证项 |

---

## 3. 冻结决策

以下决策为本方案基线，除非维护人书面批准，不得在实现阶段变更：

1. 内核范围 = L1 访问控制，不做 L2/L3
2. 驱动只由 SYSTEM 服务访问，应用不直连
3. 不新增第 12 个特性位；内核策略与状态独立
4. `SECURE` 默认 `preferred`；`required` 为高级选项
5. 运行中内核保护丢失立即锁定，不静默继续
6. 受保护进程按映像路径 + 创建时间识别，不能只按 PID
7. 驱动不碰密钥、加密、容器解析、文件内容
8. K3 文件保护条件启动；K4 内核会话令牌不在当前承诺内
9. 生产签名走 EV + attestation；测试签名仅限开发与内部测试
10. CI 默认无驱动；驱动验证在 VM 门禁中完成
11. 对外表述限定为“内核强制的进程访问保护”，不使用“内核级加密”
12. 任何新增内核能力必须同时满足：确定性拒绝、不碰数据面、无驱动可完整回归、长期可维护；缺一即留在用户态
13. 不新增第四个预设；内核策略作为 `SECURE` 的高级选项（`preferred/required`），不改变三档 + 自定义结构

---

## 4. 审核门禁

本方案为 **评审稿**。维护人审核通过前：

- 不创建驱动工程
- 不修改 `security-service/`
- 不修改 `core/`
- 不修改 `verthys-tauri/`
- 不引入 WDK 构建依赖
- 不安装测试驱动

审核通过的标志：

1. 维护人确认 [09-review-checklist.md](09-review-checklist.md) 全部通过
2. 维护人确认 K1 范围、失败语义、签名路线
3. 维护人确认无需再修改本目录文档
4. 在 [08-roadmap-adr.md](08-roadmap-adr.md) 的决策记录中登记“K0 通过”

---

## 5. 术语

| 术语 | 含义 |
| --- | --- |
| L1 | 内核辅助访问控制；数据面留在用户态 |
| L2 | 内核密钥托管/加解密/容器解析；本方案不做 |
| L3 | 全内核化；本方案不做 |
| Kernel Guard | 本方案的内核加固能力总称 |
| 受保护进程 | 被驱动剥离危险句柄权限的进程，第一版为 `verthys-worker.exe` |
| `preferred` | 优先内核；不可用时降级 `SECURE` 用户态并显式标记 |
| `required` | 内核不可用时 fail-closed，不允许降级 |
| `DEGRADED` | 策略要求内核但当前只能使用用户态防护，附具体原因 |
| P2 服务 | `VerthysSecuritySvc`，SYSTEM 用户态服务，不是驱动 |

---

## 6. 变更记录

| 日期 | 变更 | 状态 |
| --- | --- | --- |
| 2026-11-21 | 初版评审稿：L1 范围、K1/K2 范围、K3 条件项、K4 不承诺、测试/签名/运维/ADR 全套 | 待审核 |
