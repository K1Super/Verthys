# 非内核安全测试治理任务清单

> 规格见 [00-spec.md](00-spec.md)。按 P1→P5 顺序执行；每阶段验证后再进入下一阶段。
> 不包含内核 Guard。

---

## [x] P1-1 创建框架骨架

**文件**

- 新建 `tests/security/README.md`
- 新建 `tests/security/cases.json`
- 新建 `tests/security/schema/result.schema.json`
- 新建 `tests/security/lib/{Registry,Result,Metadata,Isolation,Process}.psm1`
- 新建 `tests/security/run.ps1`
- 新建 `tests/security/self-tests/run-self-tests.ps1`

**内容**

1. 注册表覆盖规格 §6 全部 legacy ID（容器/控制/服务/TPM），含 `requiredIn/kind/severity/requirement`。
2. schema 与规格 §4 一致；`additionalProperties=false`。
3. 结果库实现状态策略、profile、退出码、原子写入。
4. 元数据采集：git commit/dirty、DLL/worker/service/registry SHA-256、OS build、PowerShell 版本。
5. 自检：重复 ID、未知 suite、缺失 legacy、schema 必填、release 策略负向 fixture。

**验收**：`run-self-tests.ps1` 全绿；注册表无重复。

---

## [x] P1-2 统一 runner

**文件**

- `tests/security/run.ps1`
- `tests/security/lib/*.psm1`

**内容**

1. 参数：`-Suite vault|service|tpm|offmachine|all`、`-Profile dev|standard|release|baseline`、`-OutDir`、`-Baseline`、`-DllPath`、`-BuildDir`、`-ServiceBuildDir`、`-WorkerPath`。
2. 默认路径解析不写死 VS 版本；可用环境变量覆盖。
3. 任一异常也写 `result.json`，包含 `ERROR` 与脱敏摘要。
4. 输出 `result.json`、`result.junit.xml`、`result.sarif`、`summary.md`。

**验收**：无执行器时也能产出合法 ERROR 结果；schema 校验通过。

---

## [x] P2-1 vault 适配器

**文件**

- 新建 `tests/security/suites/vault.ps1`

**内容**

1. 调用 `tests/attack/run.ps1 -OutJson`，透传 `-Baseline`。
2. 按 `legacyId` 映射结果；未知 ID → `ERROR`；缺失 required → `NOT_RUN`。
3. `HARNESS` → `ERROR`；`A8W` 不单独计数。
4. 保留原始 executor 日志路径到证据。

**验收**：vault 用例数量与旧输出一致；baseline 仅 `CTRL-BC1`。

---

## [x] P2-2 CI 与 gate 切换

**文件**

- `.github/workflows/core.yml`
- `tests/gate.ps1`

**内容**

1. core.yml 改用 `tests/security/run.ps1`，上传四种证据。
2. gate.ps1 读取 `result.json`，按 `legacyId` 建索引；`$stageChecks` 不变。
3. 保留旧 `tests/attack/run.ps1` 作为内部执行器。

**验收**：YAML 解析通过；gate 阶段计数与旧逻辑一致；`-Profile standard` 可运行。

---

## [x] P3-1 服务套件结构化输出

**文件**

- `tests/service/attack.ps1`

**内容**

1. 新增 `-OutJson` 与 `-ResultIdPrefix`。
2. `Assert-True` 改为按场景聚合的 `Add-Check -Id`：
   - S-A3、S-A4、S-A5、S-A6、S-A8、S-A9
3. 场景全部断言 PASS 才 PASS；任一失败 FAIL；每场景输出 expected/observed。
4. 保留控制台 PASS/FAIL 行与退出码兼容。

**验收**：`-OutJson` 产出 6 个场景结果；现有控制台输出不变。

---

## [x] P3-2 服务适配器与 CI

**文件**

- 新建 `tests/security/suites/service.ps1`
- `.github/workflows/security-service.yml`

**内容**

1. 映射 `S-A*` → `SVC-*`；未知/缺失严格处理。
2. security-service.yml 改用统一 runner，上传证据。

**验收**：服务套件结果结构化；CI YAML 通过。

---

## [x] P4-1 TPM/离机适配

**文件**

- 新建 `tests/security/suites/tpm.ps1`
- 新建 `tests/security/suites/offmachine.ps1`

**内容**

1. `TPM-VTPM` 支持 PASS/BLOCKED/FAIL；BLOCKED 在 release 下失败。
2. `offmachine` 支持 prepare/verify；verify 生成 A6 报告供 `VAULT-A06` 读取。
3. 不把 prepare 计入运行结果。

**验收**：TPM 探针缺失时输出 BLOCKED 而非 ERROR；离机 prepare 不改变用例计数。

---

## [x] P4-2 release 严格策略

**文件**

- `tests/security/run.ps1`
- `tests/security/self-tests/run-self-tests.ps1`

**内容**

1. release 下 required 用例非 PASS → 退出码 3。
2. A6 缺失 → BLOCKED；A8/A18S SKIP → 失败。
3. 负向 fixture 覆盖：SKIP、BLOCKED、NOT_RUN、未知 ID、重复 ID。

**验收**：自检全绿；standard 与 release 的退出码差异有测试证明。

---

## [x] P5-1 断言收紧（逐项）

**文件**

- `tests/attack/run.ps1`
- `tests/service/attack.ps1`
- 必要时 `tests/attack/a8.ps1`、`a8-worker.ps1`

**内容**

1. A1：断言精确错误码（AUTH/RATE），不得只判非零。
2. A3：保持精确 LOCKED；补充“新句柄”。
3. A8：强制正控命中；无正控不得 PASS。
4. A6：release 必须有绑定当前构建的离机报告。
5. A17/A20/A20b：注册为 static，不参与行为覆盖率。
6. 服务 S-A5/S-A6：断言 token 精确值与 reset 前后关系。

**验收**：修改后全套 standard 通过；release 负向用例按策略失败。

---

## [x] P5-2 文档与最终审查

**文件**

- `docs/TESTING.md`
- `docs/BUILD.md`
- `docs/P2_SECURITY_SERVICE_PLAN.md`
- `tests/security/README.md`

**内容**

1. 新入口、profile、退出码、证据格式、ID 映射表。
2. 明确桌面 `attack-forge`/`AttackTest` 为外部工具，不是 CI 事实源。
3. 删除旧文档中的直接调用示例，改为新入口。
4. 最终全链路审查：注册表、schema、CI、gate、文档引用一致。

**验收**：全仓无旧入口的 CI/文档悬空引用；最终报告列出未覆盖项。

---

## 验证汇总（执行后填写）

| 项 | 命令 | 结果 |
| --- | --- | --- |
| 自检 | `tests/security/self-tests/run-self-tests.ps1` | 91 checks，0 failed |
| vault standard | `tests/security/run.ps1 -Suite vault -Profile standard` | 23 PASS / 0 FAIL / 2 BLOCKED（A2 非管理员 Root、A6 无当前构建离机报告），exit 0 |
| service standard | `tests/security/run.ps1 -Suite service -Profile standard` | 6 PASS，exit 0 |
| baseline | `tests/security/run.ps1 -Suite vault -Profile baseline` | CTRL-BC1 PASS，exit 0 |
| release 负向 | 缺失 A6 / TPM 能力 / SKIP fixture | vault 自检负向 + tpm/offmachine release 均 `BLOCKED` → exit 3 |
| CI YAML | `core.yml` / `security-service.yml` 解析 | YAML_OK |
| gate 集成 | `tests/gate.ps1 -Stage P0-C -SkipBuild` | 331 passed / 0 failed；A4/A9/A13 PASS；GATE P0-C PASS |
| 证据格式 | `Test-Json` + JUnit + SARIF 校验 | 7 个 OutDir 全部通过 |

## 未覆盖 / 风险

- 不修改内核 Guard 与驱动。
- 桌面 `attack-forge` 绑定旧版本，不作为 CI 事实源。
- release 需要提权证书存储与当前构建的离机报告；CI 使用 standard。
- 服务套件依赖 Debug 构建；缺失时显式 BLOCKED。
- A2 在非管理员环境为 BLOCKED，release 必须提权复跑。
