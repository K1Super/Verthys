# 非内核安全测试治理规格（Top-Tier）

| 项目 | 内容 |
| --- | --- |
| 目标 | 把现有非内核攻击用例治理为统一注册、统一结果模型、统一门禁的系统化测试体系 |
| 范围 | 容器/核心、P2 服务、离机 A6、vTPM 能力；**不包含内核 Guard** |
| 原则 | 不删除既有覆盖、不改变用例语义、先统一框架再逐项强化断言 |
| 状态 | 已交付（2026-11-23） |

> 最后更新：2026-11-26

---

## 1. 目标与非目标

**目标**

1. 单一权威用例注册表，消除 `A1–A20` 与内核 `A1–A14` 的命名冲突。
2. 单一入口、统一结果 schema、统一证据格式（JSON + JUnit + SARIF + Markdown）。
3. 明确 `dev/standard/release/baseline` 四种 profile 与严格退出码。
4. release 档禁止用 `SKIP/SKELETON/KNOWN_GAP` 冒充通过。
5. CI 与 `tests/gate.ps1` 统一走新入口，保留现有阶段矩阵。
6. 用例实现可保留在既有脚本中，但必须通过适配器纳入统一模型。

**非目标**

- 不修改内核 Guard、驱动、服务内核生命周期代码。
- 不删除 `tests/attack/**`、`tests/service/attack.ps1` 或既有覆盖。
- 不改写所有用例实现；先统一框架，再按任务逐项收紧断言。
- 不把桌面 `attack-forge` / `AttackTest` 纳入仓库 CI；它们保持外部工具定位。

---

## 2. 现状问题

| 问题 | 证据 |
| --- | --- |
| ID 命名冲突 | `tests/attack` 的 A14 是“设备根破坏”，内核 A14 是创建窗口 |
| 用例分散 | 内联 `run.ps1`、`vty_probe` 子命令、独立脚本、离机报告四种形态 |
| 无统一 schema | 仓库 JSON 无 schemaVersion/运行元数据；A6 单独绑定构建哈希 |
| SKIP 语义弱 | `run.ps1` 仅 FAIL 退出 1，SKIP/SKELETON 不影响退出码 |
| CI 只跑子集 | `core.yml` 只跑 `run.ps1`，不跑 `gate.ps1` 阶段矩阵 |
| 静态用例混入行为门禁 | A17/A20/A20b 为静态扫描，未标记 kind |
| 路径硬编码 | 默认 `build/core/Release`、VS 2026 CMake 路径 |
| 双框架 | 桌面 `attack-forge` 与仓库套件重叠，且绑定 4.2.8 旧安装 |

---

## 3. 目标结构

```text
tests/security/
  README.md                     # 入口、profile、退出码、证据说明
  cases.json                    # 唯一权威注册表
  schema/result.schema.json     # 运行结果 JSON Schema
  run.ps1                       # 统一入口
  lib/
    Registry.psm1               # 加载/校验注册表、ID 映射、重复检测
    Result.psm1                 # 结果模型、状态策略、JSON/JUnit/SARIF/MD 输出
    Metadata.psm1               # git/哈希/OS/PowerShell 元数据
    Isolation.psm1              # 临时目录、环境变量保存恢复、清理
    Process.psm1                # 超时执行、进程树终止、输出捕获
  suites/
    vault.ps1                   # 适配 tests/attack/run.ps1
    service.ps1                 # 适配 tests/service/attack.ps1
    tpm.ps1                     # 适配 tests/attack/vtpm/run.ps1
    offmachine.ps1              # 适配 tests/attack/offmachine/run.ps1
  self-tests/
    run-self-tests.ps1          # 注册表/schema/状态策略自检
```

既有脚本保持为**执行器**：

- `tests/attack/run.ps1`：容器/核心用例执行器
- `tests/service/attack.ps1`：服务控制台攻击执行器（需增加结构化输出）
- `tests/attack/vtpm/run.ps1`、`offmachine/run.ps1`：能力/离机证据执行器
- `tests/lib/VerthysTestHygiene.psm1`：继续复用

---

## 4. 结果模型

`result.json` 顶层字段：

```json
{
  "schemaVersion": 1,
  "runId": "20261123T120000Z-<rand>",
  "timestamp": "2026-11-23T12:00:00Z",
  "profile": "release",
  "suite": "vault",
  "mode": "postfix",
  "metadata": {
    "gitCommit": "...",
    "gitDirty": false,
    "osBuild": "22631",
    "powershell": "7.x",
    "dllSha256": "...",
    "workerSha256": "...",
    "serviceSha256": "...",
    "registrySha256": "..."
  },
  "summary": { "total": 0, "pass": 0, "fail": 0, "skip": 0, "blocked": 0, "error": 0,
               "notRun": 0, "requiredFailures": 0,
               "behavioral": 0, "static": 0, "evidence": 0, "control": 0 },
  "cases": [
    {
      "id": "VAULT-A01",
      "legacyId": "A1",
      "name": "公开默认口令解锁",
      "suite": "vault",
      "severity": "critical",
      "requirement": "P0-A",
      "kind": "behavioral",
      "status": "PASS",
      "expected": "全部拒绝",
      "observed": "...",
      "evidence": "relative/path",
      "durationMs": 123
    }
  ]
}
```

状态仅允许：

- `PASS`：断言全部满足
- `FAIL`：断言失败
- `SKIP`：显式前置不满足（仅 dev/standard 容忍）
- `BLOCKED`：外部证据/平台能力缺失（release 不容忍）
- `ERROR`：执行器异常/输出不可解析（任何 profile 都失败）
- `NOT_RUN`：profile 未选择该用例

每个 case 必须是注册表中的条目；执行器返回未知 ID 直接 `ERROR`。

---

## 5. Profile 与退出码

| Profile | 范围 | SKIP/BLOCKED 策略 | 用途 |
| --- | --- | --- | --- |
| `dev` | 全部 | 容忍，汇总告警 | 本地开发 |
| `standard` | 全部非人工证据 | 容忍，汇总告警 | PR/日常/CI |
| `release` | 全部 | 任一 required 用例非 PASS 即失败 | 发布门禁（需离机证据与非提权会话） |
| `baseline` | 仅 `CTRL-BC1` | 不允许 SKIP | harness 正控 |

CI 使用 `standard`：托管 runner 没有离机证据，服务套件的 `SVC-A09` 需要非提权进程。`release` 在发布签署主机执行，并通过 `-A6EvidenceDir` 注入离机报告。

退出码：

- `0`：成功（release 下全部 required PASS）
- `1`：存在 FAIL/ERROR
- `2`：注册表/schema/配置错误、未知 ID、缺失用例
- `3`：release 策略失败（required 用例 SKIP/BLOCKED/NOT_RUN）

---

## 6. 用例注册表

`cases.json` 字段：

```json
{
  "id": "VAULT-A01",
  "legacyId": "A1",
  "suite": "vault",
  "name": "公开默认口令解锁",
  "severity": "critical",
  "requirement": "P0-A",
  "kind": "behavioral",
  "requiredIn": ["smoke", "standard", "release"],
  "executor": "tests/attack/run.ps1",
  "evidence": "vault-result.json",
  "description": "..."
}
```

`kind`：`behavioral` / `static` / `evidence` / `control`。
静态用例不得替代行为用例；`release` 汇总单独统计 `static` 与 `behavioral`。

### 6.1 容器/核心映射

| 新 ID | legacy | 说明 |
| --- | --- | --- |
| `CTRL-PC1` | PC-1 | 正确口令正控 |
| `CTRL-SC1` | SC-1 | 明文扫描器自检 |
| `CTRL-BC1` | BC-1 | Baseline 正控（仅 baseline） |
| `VAULT-A01` | A1 | 默认/空/弱口令 |
| `VAULT-A01B` | A1b | 退避后恢复 |
| `VAULT-A02` | A2 | 调用方签名 |
| `VAULT-A03` | A3 | 未解锁枚举 |
| `VAULT-A04` | A4 | 数据明文 |
| `VAULT-A05` | A5 | 分片还原 |
| `VAULT-A06` | A6 | 离机证据（evidence） |
| `VAULT-A06B` | A6b | 同机错误模块口令 |
| `VAULT-A07` | A7 | 熔断绕过 |
| `VAULT-A08` | A8 | 内存残留（含 A8W） |
| `VAULT-A09` | A9 | 名称明文 |
| `VAULT-A10` | A10 | nonce 复用 |
| `VAULT-A11` | A11 | 槽/记录交换 |
| `VAULT-A12` | A12 | 回滚旧副本 |
| `VAULT-A13` | A13 | 明文回退注入 |
| `VAULT-A14` | A14 | 设备根破坏（非内核 A14） |
| `VAULT-A15` | A15 | 恢复码流程 |
| `VAULT-A16` | A16 | 异种格式 |
| `VAULT-A17` | A17 | 渲染进程密钥材料（static） |
| `VAULT-A18` | A18 | keyfile 因子 |
| `VAULT-A18S` | A18S | worker 挂起处置 |
| `VAULT-A20` | A20 | 导入身份键（static） |
| `VAULT-A20B` | A20b | 重试幂等（static） |

`HARNESS` 不作为用例；执行器异常映射为 `ERROR`。

### 6.2 服务映射

| 新 ID | legacy | 说明 |
| --- | --- | --- |
| `SVC-A03` | S-A3 | 伪造服务端 |
| `SVC-A04` | S-A4 | 未签名客户端 |
| `SVC-A05` | S-A5 | reset 洗预算 |
| `SVC-A06` | S-A6 | 单用户预算抽干 |
| `SVC-A08` | S-A8 | 服务停止 fail-closed |
| `SVC-A09` | S-A9 | 非管理员改 HKLM |

### 6.3 证据/能力

| 新 ID | legacy | 说明 |
| --- | --- | --- |
| `TPM-VTPM` | VTPM | vTPM 能力证据 |
| `EVID-A06` | A6 | 离机证据（由 `offmachine/run.ps1` 生成） |

A6 在 `run.ps1` 与 `offmachine` 两处出现：容器套件中的 A6 只读取合格报告；`EVID-A06` 负责 prepare/verify。注册表只保留 `VAULT-A06`，`EVID-A06` 作为证据生成工具，不重复计数。

---

## 7. 适配器规则

**vault.ps1**

- 调用 `tests/attack/run.ps1 -OutJson <temp>`（baseline 模式透传 `-Baseline`）
- 读取 `Results[]`，按 `legacyId` 映射到注册表
- 未知 ID → `ERROR`；缺失 required ID → `NOT_RUN`，release 失败
- `HARNESS` 行 → `ERROR`

**service.ps1**

- 先改造 `tests/service/attack.ps1`：
  - 新增 `-OutJson` 与 `-ResultIdPrefix`
  - `Assert-True` 改为 `Add-Check -Id <legacyId> ...`，按场景聚合
  - 场景全部断言 PASS 才 PASS；任一失败 FAIL
- 适配器映射 `S-A*` 到 `SVC-*`

**tpm.ps1**

- 调用 `vtpm/run.ps1 -OutJson`，映射 `VTPM` 状态
- `BLOCKED` 保留为 `BLOCKED`，release 失败

**offmachine.ps1**

- `prepare` 只生成包，不计入运行结果
- `verify` 生成 A6 报告，供 `VAULT-A06` 读取

---

## 8. CI 与 gate 迁移

**`.github/workflows/core.yml`**

- 移除对 `tests\attack\run.ps1` 的直接调用
- 改为：
  - `tests/security/run.ps1 -Suite vault -Profile standard -OutDir build/security-vault`
  - `tests/security/run.ps1 -Suite vault -Profile baseline -OutDir build/security-baseline`
- 上传 `result.json`、`result.junit.xml`、`result.sarif`、`summary.md`

**`.github/workflows/security-service.yml`**

- 改为 `tests/security/run.ps1 -Suite service -Profile standard -OutDir build/security-service -ServiceBuildDir build_security_service_ci`
- 上传四类证据；`SVC-A09` 在提权 runner 上记录 SKIP，不作为 release 必需项。

**`tests/gate.ps1`**

- 调用新入口，读取 `result.json`，按 `legacyId` 建立索引
- 保留 `$stageChecks` 的 `Attacks` 列表，不改变阶段语义
- 汇总计数改为使用新 summary

**release 签署主机**

- `tests/security/run.ps1 -Suite vault -Profile release -A6EvidenceDir <dir>`
- A2 需要管理员权限写入 Root 存储；非提权环境记录 `BLOCKED` 并阻止 release 通过。

---

## 9. 用例质量硬规则

1. 新增/修改用例必须先在 `cases.json` 注册，否则 runner 拒绝执行。
2. 每个 case 必须有 `expected` 与 `observed`，不得只写 PASS/FAIL。
3. 行为用例不得只断言 `rc != 0`；有明确错误码时必须断言精确值。
4. 静态用例（`kind=static`）不得计入“行为覆盖率”；release 汇总单独报告。
5. release 下 `VAULT-A06` 必须有合格离机报告；缺失即 `BLOCKED`，不得 SKIP。
6. release 下 `VAULT-A08`、`VAULT-A18S` 不得 SKIP；平台不支持时 `BLOCKED` 并失败。
7. 任何 `ERROR` 都必须保留原始输出摘要（脱敏）与执行器退出码。
8. 结果文件原子写入；失败也写 `result.json`，便于取证。
9. 不得在日志/证据中记录口令、密钥、恢复码。
10. 用例 ID 一经发布不得复用；新增使用新编号。
11. `SVC-A09` 需要非提权进程；提权环境记录 `SKIP`，不作为 release 必需项。

---

## 10. 实施阶段

| 阶段 | 内容 | 回滚 |
| --- | --- | --- |
| P1 | 注册表、schema、runner、元数据、自检 | 删除 `tests/security`，CI 未切换 |
| P2 | vault 适配 + CI/gate 切换 | CI 恢复旧 `run.ps1` 调用 |
| P3 | service 结构化输出 + 适配 | 恢复旧 `attack.ps1` |
| P4 | tpm/offmachine 适配 + release 严格策略 | profile 降为 standard |
| P5 | 断言收紧（A1/A3/A8/A6 等） | 按用例回退 |

每阶段独立验证，不一次性切换全部。

---

## 11. 验收

```powershell
pwsh -NoProfile -File tests/security/self-tests/run-self-tests.ps1
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile standard -OutDir build/security-vault
pwsh -NoProfile -File tests/security/run.ps1 -Suite service -Profile standard -OutDir build/security-service
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile baseline -OutDir build/security-baseline
```

验收判据：

- 注册表无重复/未知 suite/缺失 legacy 映射
- schema 校验通过；`result.json` 可被 JUnit/SARIF 消费者读取
- vault 用例数量与旧套件一致（不含 HARNESS），无未知 ID
- service 6 个 legacy 用例全部有结构化结果
- baseline 仅 `CTRL-BC1`，且 PASS
- release 下缺失 A6 报告或 SKIP 必失败（用负向 fixture 验证）
- CI YAML 语法通过；`gate.ps1` 阶段矩阵行为不变

---

## 12. 风险

- 旧执行器输出格式变化会导致适配器解析失败：适配器必须隔离解析并提供原始日志。
- `release` 严格化要求离机证据与提权证书存储；CI 使用 `standard` 保持绿灯，release 在签署主机执行，负向 fixture 由自检验证。
- 服务套件运行需要 Debug 构建与管理员上下文；CI 环境差异需显式 `BLOCKED`。
- 不修改内核代码；`docs/kernel-guard` 与内核用例不在本规格范围。
