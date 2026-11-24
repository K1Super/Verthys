# 非内核安全测试

统一入口、统一注册表、统一证据格式的安全测试层。范围是容器/核心、P2 安全服务、vTPM 能力与离机证据，**不包含内核 Guard**。

## 入口

```powershell
# 容器/核心：standard
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile standard -OutDir build/security-vault

# harness 正控：baseline
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile baseline -OutDir build/security-baseline

# P2 安全服务
pwsh -NoProfile -File tests/security/run.ps1 -Suite service -Profile standard `
  -OutDir build/security-service -ServiceBuildDir build_security_service

# vTPM 能力
pwsh -NoProfile -File tests/security/run.ps1 -Suite tpm -Profile standard `
  -OutDir build/security-tpm -TpmProbe build/core/tests/Release/vty_tpm_probe.exe

# 离机证据：源机 prepare，目标机 verify
pwsh -NoProfile -File tests/security/run.ps1 -Suite offmachine -OffmachineMode prepare `
  -OffmachineDir C:\A6
pwsh -NoProfile -File tests/security/run.ps1 -Suite offmachine -OffmachineMode verify `
  -OffmachineDir C:\A6 -OutDir build/security-offmachine

# 三套件合并（不含 offmachine）
pwsh -NoProfile -File tests/security/run.ps1 -Suite all -Profile standard -OutDir build/security-all
```

## Profile

| Profile | 范围 | SKIP/BLOCKED | 用途 |
| --- | --- | --- | --- |
| `dev` | 全部 | 容忍 | 本地开发 |
| `standard` | 全部非 baseline 专用 | 容忍并报告 | PR/日常/CI |
| `release` | 全部 | 任一必需项非 PASS 即失败 | 发布门禁 |
| `baseline` | 仅 `CTRL-BC1` | 不允许 | harness 正控 |

`release` 要求 `VAULT-A06` 有绑定当前构建的离机报告；`VAULT-A08`、`VAULT-A18S` 不得 SKIP；`VAULT-A02` 需要管理员权限写入 Root 存储，非提权环境为 `BLOCKED`。CI 使用 `standard`：GitHub 托管 runner 没有离机证据，且服务套件的 `SVC-A09` 需要非提权进程。发布签署在具备离机包、提权证书存储与非提权会话的主机上执行：

```powershell
pwsh -NoProfile -File tests/security/run.ps1 -Suite vault -Profile release `
  -OutDir build/security-release -A6EvidenceDir <离机报告目录>
```

## 状态与退出码

| 状态 | 含义 |
| --- | --- |
| `PASS` | 断言全部满足 |
| `FAIL` | 断言失败 |
| `SKIP` | 显式前置不满足，仅 dev/standard 容忍 |
| `BLOCKED` | 外部证据或平台能力缺失，release 不容忍 |
| `ERROR` | 执行器异常或输出不可解析，任何 profile 都失败 |
| `NOT_RUN` | 执行器未返回该用例；release 必需项视为失败 |

退出码：`0` 成功；`1` 存在 `FAIL`/`ERROR`；`2` 注册表/schema/未知 ID/重复结果；`3` release 或 baseline 必需项非 PASS。

`standard` 汇总中的 `requiredFailures` 表示“如果按 release 判定会失败”，不改变 `standard` 的退出码；它用于在 PR 阶段提前暴露发布门禁风险。

## 证据

每次运行在 `-OutDir` 写出：

- `result.json`：唯一结构化事实源，含运行元数据、汇总、逐用例 expected/observed
- `result.junit.xml`：CI 测试报告消费者
- `result.sarif`：静态分析/安全平台消费者
- `summary.md`：人工复核摘要
- `evidence/<runId>/`：执行器原始 JSON 与日志副本

元数据包含 git commit/dirty、OS build、PowerShell 版本、DLL/worker/service/注册表 SHA-256。证据只记录判定与观测，不记录口令、密钥或恢复码。

## 用例注册

`cases.json` 是唯一权威注册表。新增或修改用例必须先注册，否则 runner 拒绝执行（未知 ID → 退出码 2）。字段：

| 字段 | 说明 |
| --- | --- |
| `id` | 新命名空间：`VAULT-*` / `SVC-*` / `TPM-*` / `CTRL-*` |
| `legacyId` | 既有执行器编号，用于门禁兼容索引 |
| `suite` | `vault` / `service` / `tpm` |
| `severity` / `requirement` | 严重度与阶段归属 |
| `kind` | `behavioral` / `static` / `evidence` / `control` |
| `requiredIn` | release 等 profile 下必须 PASS 的 profile 列表；空数组表示不作为必需项 |
| `onlyIn` | 仅在这些 profile 运行（目前只有 baseline 正控） |
| `executor` | 实际执行器路径 |
| `evidence` | 证据文件类别 |

`kind=static` 的用例（当前 A17/A20/A20b）不计入行为覆盖率；`kind=evidence` 的缺失映射为 `BLOCKED`，不会被伪装成 SKIP。

## ID 映射

| 新 ID | legacy | 说明 |
| --- | --- | --- |
| `CTRL-PC1` / `CTRL-SC1` / `CTRL-BC1` | PC-1 / SC-1 / BC-1 | 正控与扫描器自检 |
| `VAULT-A01` … `VAULT-A20B` | A1 … A20b | 容器/核心攻击面；A14 与内核 A14 无映射关系 |
| `SVC-A03` … `SVC-A09` | S-A3 … S-A9 | P2 服务控制台子集 |
| `TPM-VTPM` | VTPM | vTPM 能力证据 |

`HARNESS` 不是用例：执行器返回该行即退出码 2。旧 `A8W` 行不单独计数，其结论并入 `VAULT-A08`。

## 执行器关系

`tests/attack/run.ps1`、`tests/service/attack.ps1`、`tests/attack/vtpm/run.ps1`、`tests/attack/offmachine/run.ps1` 仍是执行器，不直接作为 CI 事实源。适配器负责调用、解析、状态归一与缺口补齐：

- `tests/security/suites/vault.ps1`
- `tests/security/suites/service.ps1`
- `tests/security/suites/tpm.ps1`
- `tests/security/suites/offmachine.ps1`

桌面 `attack-forge` 与 `AttackTest` 是外部演练工具，不纳入仓库 CI，也不作为发布证据。

## 自检

```powershell
pwsh -NoProfile -File tests/security/self-tests/run-self-tests.ps1
```

覆盖注册表结构/重复 ID/未知 suite/缺失 legacy、profile 选择、状态归一、退出码策略、JSON Schema、JUnit/SARIF 生成、单用例数组保持、证据复制与 UTF-8 子进程输出。
