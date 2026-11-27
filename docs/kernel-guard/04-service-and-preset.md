# 04 服务集成与安全档位策略

| 项目 | 内容 |
| --- | --- |
| 状态 | 评审稿 |
| 范围 | P2 服务托管驱动、`SECURE` 内核策略、状态机、UI 与审计 |
| 关联 | [02-architecture.md](02-architecture.md)、[03-driver-design.md](03-driver-design.md)、[05-test-and-verification.md](05-test-and-verification.md) |

> Last updated: 2026-11-22

---

## 1. 角色与边界

| 角色 | 职责 | 不做什么 |
| --- | --- | --- |
| P2 `VerthysSecuritySvc` | 驱动安装/启动/停止、ARM/REGISTER、健康检查、状态上报、审计 | 不接触口令、密钥、明文；不执行客户端输入 |
| Tauri 主进程 | 读取预设、编排解锁、启动 worker、展示状态 | 不直接访问驱动；不决定内核真实状态 |
| Rust `kernel_guard` 模块 | 状态机、超时、重试、审计事件、UI 投影 | 不伪造 ACTIVE；不静默降级 |
| C 运行时策略层 | 三档预设矩阵与 11 位投影 | 不感知驱动细节；不持有内核状态 |
| Vue Security Center | 展示“内核加固”状态、原因、修复入口 | 不把内核能力混入 11 个防护点 |

P2 服务是 SYSTEM 用户态服务，不是内核驱动；Kernel Guard 是独立的内核组件。

### 1.1 服务 IPC 命令

| 命令 | 值 | 请求 | 行为 |
| --- | --- | --- | --- |
| `KERNEL_STATUS` | 5 | 无载荷 | 只读查询驱动状态 |
| `KERNEL_ARM` | 6 | 无载荷 | 以已认证客户端进程为对象 ARM |
| `KERNEL_REGISTER` | 7 | 无载荷 | 将已 ARM 的客户端登记为受保护进程 |
| `KERNEL_DISARM` | 8 | 无载荷 | 解除保护；已 `NOT_ARMED` 视为成功 |

- 请求保持 64 字节固定长度；PID、创建时间与映像路径全部由服务从认证句柄读取，客户端不能自报路径
- 仅接受映像基名为 `verthys-worker.exe` / `verthys-worker-x86_64-pc-windows-msvc.exe` 的已认证客户端
- ARM/DISARM 不要求 `verthys.dll` 模块校验：服务重启后新服务尚未被驱动信任，模块枚举可能因 `VM_READ` 被剥离而失败；ARM 成功后驱动登记新服务，后续 REGISTER 与常规命令恢复模块校验
- 单所有者：已有其他存活 worker 持有保护时拒绝新的 ARM；旧进程退出后允许接管
- 回显状态使用签名响应头 48..63 区，普通响应仍要求该区全 0

---

## 2. 策略模型

### 2.1 三档 + 自定义不变

| 档位 | 代号 | 内核策略 | 说明 |
| --- | --- | --- | --- |
| BALANCED | 0 | `off` | 默认推荐；不请求内核 |
| SECURE | 1 | `preferred`（默认） | 优先内核；不可用降级用户态 |
| PERFORMANCE | 2 | `off` | 只保留安全底线；不请求内核 |
| CUSTOM | 3 | `off/preferred`（K1）；`required` 在 K2 开放 | 高级配置；默认 `off` |

- 不新增第四个预设
- 不新增第 12 个特性位；`SECURE` 仍为 `0x7FF`
- 内核策略是独立字段，不进入 `security_preset_feature_bits`
- `required` 为高级选项，默认不暴露给普通用户

### 2.2 策略语义

| 策略 | 解锁前不可用 | 运行期切档不可用 | 运行中丢失 |
| --- | --- | --- | --- |
| `off` | 不检测 | 不检测 | 不处理 |
| `preferred` | 降级用户态，继续解锁，标记 `DEGRADED` | 允许切档，标记 `DEGRADED` | 立即锁定 |
| `required` | 中止解锁，显示修复入口 | 拒绝切档，保持原档 | 立即锁定 |

### 2.2.1 K1 激活路径与已知窗口

- 生产布局（worker 与宿主同目录）下由宿主在 `CreateProcess` 之前调用服务 ARM；worker 以挂起态创建后，宿主提交 PID + 创建时间完成 REGISTER，再恢复执行
- 服务只从宿主映像目录 + 白名单 worker 基名派生受保护路径，并要求文件存在；不接受客户端任意路径
- 开发树中 worker 与宿主不同根，跳过预 ARM，由 worker 在解锁/切档时自 ARM；该布局仍存在创建到 ARM 的窗口
- 因此 A14“受保护进程从创建第一刻起被剥离”在代码链路上已闭合；驱动侧 bootstrap 窗口内的剥离已由 Phase 2E 实机攻击回归验证，宿主预 ARM 的服务/应用端到端仍未验证
- 已登记保护在运行中丢失时，宿主看门狗在 SECURE 且曾 ACTIVE 后连续两次明确非 ACTIVE 即锁定会话；查询失败不计入，避免长任务误锁
- 生产安装器在 `-IncludeDriver` 打包时于同一次提权流程安装驱动；驱动启动失败按 `preferred` 回滚并记录 `DriverInstallResult`，不阻断应用安装

### 2.3 持久化

`preset.json` 增加可选字段：

```json
{
  "code": 1,
  "customFeatures": null,
  "customSessionTimeoutMinutes": null,
  "kernelPolicy": "preferred"
}
```

- `kernelPolicy` 缺省：`code=1` 时为 `preferred`，其余为 `off`
- 旧文件读取：缺省按上述规则补齐
- 新文件被旧版本读取：旧版本忽略未知字段；不改变旧版本行为
- `required` 写入前必须通过策略校验；非法值拒绝
- **K1 只启用 `preferred`**；`CUSTOM` 的 `required` 在 K1 不写入、不生效；`required` 在 K2 前必须解决策略文件可被改写的问题

### 2.4 `required` 的前置条件

当前 `preset.json` 是原子写入的普通 JSON，不是防篡改存储。若 `required` 依赖该文件，同用户可把它改成 `preferred` 或 `off`，从而绕过内核要求。K2 默认方案：

1. 把 `kernelPolicy` 的权威副本迁移到 `%ProgramData%\Verthys\Security`（SYSTEM ACL），预设文件只作展示缓存
2. HMAC 保护仅作为迁移不可行时的备选，需维护人批准

未完成上述默认方案，`required` 不得发布。

---

## 3. 状态机

### 3.1 服务状态

```text
UNARMED
  → ARMING（服务请求驱动 ARM）
  → ARMED（已登记受保护映像）
  → REGISTERING（登记 worker）
  → ACTIVE（保护生效）
  → DEGRADED（部分能力不可用）
  → LOST（运行中丢失）
  → DISARMING
  → UNARMED
```

### 3.2 失败状态

| 状态 | 触发 | 行为 |
| --- | --- | --- |
| `NOT_INSTALLED` | 驱动未安装 | `preferred` 降级；`required` 拒绝 |
| `STOPPED` | 驱动已安装未运行 | 尝试启动一次；失败按不可用处理 |
| `VERSION_MISMATCH` | 协议/版本不匹配 | 不重试；按不可用处理；提示升级/修复 |
| `UNHEALTHY` | Ping/注册超时 | 重试 1 次；仍失败按不可用处理 |
| `ACTIVE` | 登记成功 | 正常 |
| `DEGRADED` | 部分失败 | 记录原因；UI 明示 |
| `LOST` | ACTIVE 后连续 2 次健康检查失败 | 立即锁定已解锁会话 |

### 3.3 超时与重试

| 操作 | 超时 | 重试 |
| --- | --- | --- |
| Ping | 250 ms | 1 次，间隔 100 ms |
| ARM | 1 s | 1 次，仅瞬时错误 |
| REGISTER | 1 s | 1 次，仅瞬时错误 |
| QUERY_STATUS | 250 ms | 1 次 |
| QUERY_EVENTS | 500 ms | 无 |
| 健康检查周期 | 10 s | 失败退避 30 s |

- 版本不匹配、访问拒绝、身份不匹配不重试
- 所有超时必须有上界；解锁路径不得被无响应驱动无限阻塞
- 重试与失败写审计，不写敏感数据

---

## 4. 解锁流程

### 4.1 `preferred`

```text
读取 preset.json
  → code=SECURE, kernelPolicy=preferred
  → 应用 C 预设（现有 fail-closed）
  → 服务 Ping
  → 不可用：
      → 标记 DEGRADED(reason)
      → 继续用户态解锁
  → 可用：
      → ARM 受保护映像路径
      → worker 创建挂起
      → 加入 Job Object
      → REGISTER 确认进程身份
      → 恢复运行并解锁
      → 标记 ACTIVE
```

- 降级不是静默：UI 显示“高安全（用户态降级）”
- 审计记录原因、时间、驱动版本（若可得）
- 用户态 `SECURE` 的 11 位能力保持不变

### 4.2 `required`

```text
读取 preset.json
  → code=SECURE, kernelPolicy=required
  → 应用 C 预设
  → 服务 Ping
  → 不可用：
      → 中止解锁
      → UI 显示修复入口（驱动未安装/未运行/版本不匹配）
      → 审计 FAIL_CLOSED
  → 可用：
      → ARM 受保护映像路径
      → 创建挂起 → 加入 Job → REGISTER 确认 → 恢复
      → 标记 ACTIVE
```

- 不得在 `required` 下以用户态继续解锁
- 恢复路径必须在 K2 前定稿，避免驱动故障导致用户无法打开库

### 4.3 恢复路径（K2 前必须定稿）

候选方案：

| 方案 | 行为 | 风险 |
| --- | --- | --- |
| 仅修复入口 | 提示重装/启动驱动/重启，不提供用户态绕过 | 驱动长期不可用会锁死用户 |
| 恢复码临时降级 | 用户输入恢复码后，明确确认“本次以用户态解锁”，审计 | 降低 `required` 的严格性，但保留可用性 |
| 安全模式 | 管理员启用一次性安全模式，限定次数/时间，审计 | 运维复杂，普通用户不可用 |

推荐：`required` 首次发布前实现“恢复码临时降级”，明确确认 + 审计 + UI 常驻警告；不允许静默降级。最终方案在 K0 审核中确认。

---

## 5. 运行期切档

### 5.1 切到 SECURE

```text
校验会话授权
  → 校验目标策略
  → required：先 Ping/ARM，不可用则拒绝（不落盘）
  → 原子写入 preset.json
  → 切换 C 预设
  → ARM + REGISTER 当前 worker
  → 回读 C 预设与内核状态
  → 全部成功：更新 UI
  → 落盘失败 / C 层失败 / 回读不一致：DISARM + 回滚 preset.json + 保持原档
  → 内核失败：
      preferred：保留切档，标记 DEGRADED
      required：DISARM + 补偿回滚 preset.json 与 C 预设，保持原档
```

- 运行期切入只能从此刻起保护；已有危险句柄无法追溯撤销
- `required` 建议先锁定再解锁，确保从解锁第一刻起受保护
- 切档失败必须回滚，不允许“UI 显示已切档但实际未切”

### 5.2 切出 SECURE

```text
切换 C 预设
  → 服务 DISARM
  → 驱动注销受保护进程
  → 更新 UI
```

- 驱动保持加载但空闲；不反复加载/卸载
- 切出后不再剥离句柄权限；已存在的受保护登记全部释放
- 切出失败时保持原档并报错，不半切
- DISARM 失败：回滚 C 预设与 `preset.json`，保持 SECURE；回滚失败置 `preset_persist_dirty` 并阻断后续切档，直到修复

---

## 6. worker 重启

- worker 退出：驱动收到进程通知，释放登记项，事件入队
- 新 worker：ARM 仍在位 → 创建挂起（驱动创建通知即时标记）→ 加入 Job → REGISTER 确认 → 恢复
- `preferred` 注册失败：标记 `DEGRADED`，继续运行；UI 提示
- `required` 注册失败：立即锁定，拒绝继续
- REGISTER 确认失败但驱动已在创建时标记保护：保留保护，状态按 `DEGRADED` 展示并重试确认；不宣称 `ACTIVE`
- 不允许只按 PID 重新登记；必须重新校验创建时间与路径

---

## 7. 运行中丢失

- 服务每 10 s 健康检查；连续 2 次失败视为 `LOST`
- 已解锁会话：立即锁定库、销毁 worker、写审计、UI 显示“内核保护丢失，已锁定”
- 未解锁会话：`preferred` 标记 `DEGRADED` 继续；`required` 拒绝解锁
- 驱动恢复后不在已解锁会话自动挂载；下次解锁或显式重检后启用
- 不提供“忽略并继续”按钮

---

## 8. UI 与文案

### 8.1 展示位置

- 11 个防护点保持原样，不混入内核能力
- Security Center 增加独立“内核加固”区域
- 显示：策略（`preferred/required`）、实际状态、原因、驱动版本（若可得）、修复入口

### 8.2 状态文案

| 状态 | 文案 |
| --- | --- |
| `ACTIVE` | 内核加固已启用 |
| `ARMED` | 内核加固已就绪，等待受保护进程 |
| `DEGRADED` | 内核加固不可用，已使用高安全用户态防护 |
| `NOT_INSTALLED` | 内核加固不可用：驱动未安装 |
| `STOPPED` | 内核加固不可用：驱动未运行 |
| `VERSION_MISMATCH` | 内核加固不可用：版本不匹配 |
| `UNHEALTHY` | 内核加固不可用：驱动无响应 |
| `LOST` | 内核加固已丢失，库已锁定 |
| `FAIL_CLOSED` | 内核加固不可用，已阻止解锁 |

禁止文案：

- “内核态已启用”（实际只是驱动保护）
- “内核级加密”
- “受架构限制”
- 在 `DEGRADED` 时仍显示“高安全已完整启用”

### 8.3 视觉约束

- 不使用大面积阴影、渐变、发光
- 状态用文字与克制色块表达，不堆叠图标
- “内核加固”区域的标题、状态、原因层级与现有安全面板一致
- 修复入口使用现有按钮组件，不新造样式

---

## 9. 审计

| 事件 | 触发 | 字段 |
| --- | --- | --- |
| `KERNEL_GUARD_ACTIVE` | 首次 ACTIVE | 时间、策略、驱动版本、协议版本 |
| `KERNEL_GUARD_DEGRADED` | 降级 | 时间、策略、原因、驱动版本 |
| `KERNEL_GUARD_FAIL_CLOSED` | required 不可用 | 时间、原因、操作（解锁/切档） |
| `KERNEL_GUARD_LOST` | 运行中丢失 | 时间、原因、是否已锁定 |
| `KERNEL_GUARD_REGISTER_FAILED` | 登记失败 | 时间、原因、PID（可脱敏） |
| `KERNEL_GUARD_RECOVERED` | 重新可用 | 时间、驱动版本、协议版本 |
| `KERNEL_GUARD_POLICY_CHANGED` | 策略变更 | 时间、旧值、新值 |

审计不得包含：口令、密钥、明文、完整用户路径。PID 可记录，路径只记录映像名或哈希前缀。

---

## 10. 兼容与降级

| 场景 | 行为 |
| --- | --- |
| 无驱动开发环境 | `preferred` 降级；CI 全量回归通过 |
| 测试签名模式 | 可 ACTIVE；UI 显示测试模式提示；仅限开发/内部 |
| HVCI 阻止加载 | `UNHEALTHY/UNSUPPORTED`；`preferred` 降级，`required` 拒绝 |
| Secure Boot 开启 + 未签名驱动 | 加载失败；按不可用处理 |
| 服务停止 | P2 本身 fail-closed；内核状态不可用 |
| 驱动升级中 | 状态 `STOPPED/UNHEALTHY`；按失败语义处理 |
| 用户切换档位 | 见第 5 节；失败回滚 |
| KernelStatus 查询 | 只读诊断；P2 fail-closed 时仍可返回内核状态，不参与解锁授权 |

---

## 11. 与现有代码的接入点

| 层 | 文件/模块 | 改动类型 |
| --- | --- | --- |
| C 预设矩阵 | `core/src/security/preset/security_preset.c` | 不改变 11 位投影；新增独立策略查询（K1 设计阶段确定） |
| Rust 预设命令 | `verthys-tauri/src-tauri/src/security_commands/commands/preset.rs` | 切档事务加入内核检查与补偿 |
| 预设持久化 | `verthys-tauri/src-tauri/src/security_commands/preset_persistence.rs` | 增加可选 `kernelPolicy` 字段 |
| 应用侧门控 | `verthys-tauri/src-tauri/src/security/guard/app_feature_gate.rs` | 不变；内核状态独立模块 |
| UI | `verthys-tauri/src/composables/security-center/useDefenseStatus.ts`、`SecurityCenter.vue`、`SecurityDashboard.vue` | 新增内核加固状态区；11 位列表不变；KernelStatus、SECURE preferred 降级展示与降级审计已接入 |
| P2 服务 | `security-service/` | KernelStatus 查询、ARM/REGISTER/DISARM 与签名响应已落地；健康检查、安装托管未落地 |
| 驱动脚本 | `scripts/kernel/` | 安装/升级/回滚/卸载与发布门禁取证；默认不进入主构建，需显式执行 |
| 构建 | `build_production.ps1`、`scripts/build/` | 新增可选驱动阶段；默认不改变现有产物 |

具体代码改动在 K1 设计评审后确定；本方案不包含实现。

---

## 12. 待决问题

1. `required` 的恢复路径选“恢复码临时降级”还是“仅修复入口”
2. `preset.json` 的 `kernelPolicy` 权威是否迁移到 P2 服务
3. 驱动是否随 perMachine 安装包默认安装
4. `SECURE` 主进程保护是否默认开启
5. `DEGRADED` 是否允许用户手动“重试内核保护”，还是只在下一次解锁重试
6. 测试签名模式下是否允许 `required`（建议禁止）
