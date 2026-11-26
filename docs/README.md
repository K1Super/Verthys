# docs — 文档导航与治理

> 状态：现行 · 最后核验：2026-11-26 · 维护人：K1Super
>
> 本目录只索引仓库中实际存在的文档；被索引的每份文档都必须是现行契约、操作规程或仍在生效的规范。

---

## 1. 治理原则

1. **单一事实源**：版本、ABI、容器格式、依赖版本、协议常量只引用权威文件，不在文档中抄录数字。
2. **按用途分层**：现行契约 / 操作规程 / 规范附录；已完成的一次性方案、报告与验证记录直接删除，不设归档目录。
3. **每份文档可核验**：头部带 `Last updated`、状态与适用范围；结论必须指向代码、命令或可复现步骤。
4. **机检优先**：链接、索引覆盖、元数据与版本声明由 `ci/check_docs.ps1` 校验，文档变更走 `docs.yml` 工作流。

## 2. 快速导航（按角色）

### 新成员

1. 总览与定位：[../README.md](../README.md)（项目唯一入口）
2. 环境与运行：[GETTING_STARTED.md](GETTING_STARTED.md)
3. 要做什么：[REQUIREMENTS.md](REQUIREMENTS.md)
4. 术语：[GLOSSARY.md](GLOSSARY.md)
5. 系统架构：[ARCHITECTURE.md](ARCHITECTURE.md)

### 开发者

- 核心 DLL 接口契约：[CORE_API.md](CORE_API.md)
- 编码与命名规范：[CODING_STANDARDS.md](CODING_STANDARDS.md)
- 工程与注释规范附录：[references/engineering-standards.md](references/engineering-standards.md)、[references/comment-standards.md](references/comment-standards.md)
- 注释禁用语表：[references/comment-vocabulary.md](references/comment-vocabulary.md)
- 代码审查维度附录：[references/review-standards.md](references/review-standards.md)
- 版本号与命名契约：[references/versioning.md](references/versioning.md)
- 测试分层与跑法：[TESTING.md](TESTING.md)
- 密钥与解锁数据流：[DATA_FLOW.md](DATA_FLOW.md)
- 配置项与环境变量：[CONFIGURATION.md](CONFIGURATION.md)
- 架构决策索引：[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)

### 发布者

- 构建指南：[BUILD.md](BUILD.md)
- 部署与打包：[DEPLOYMENT.md](DEPLOYMENT.md)
- 发版流程：[RELEASE.md](RELEASE.md)
- 更新系统（权威）：[updater/README.md](updater/README.md)
- 升级与迁移：[MIGRATION.md](MIGRATION.md)
- 版本变更记录：[../CHANGELOG.md](../CHANGELOG.md)

### 安全审计

- 安全设计与信任模型：[SECURITY_DESIGN.md](SECURITY_DESIGN.md)
- 回退锚点生命周期与淘汰治理：[ROLLBACK_ANCHOR_LIFECYCLE.md](ROLLBACK_ANCHOR_LIFECYCLE.md)
- P2 SYSTEM 安全服务：[P2_SECURITY_SERVICE_PLAN.md](P2_SECURITY_SERVICE_PLAN.md)
- 内核加固方案（评审中）：[kernel-guard/README.md](kernel-guard/README.md)
- 依赖与供应链：[THIRD_PARTY.md](THIRD_PARTY.md)

### 问题排查

- 症状 → 原因 → 排查 → 解决：[TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 3. 全量清单

| 文档 | 解决什么问题 | 状态 |
|---|---|---|
| [../README.md](../README.md) | 项目定位、能力、构建入口 | 现行 |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | 分支、提交、评审与文档同步义务 | 现行 |
| [../CHANGELOG.md](../CHANGELOG.md) | 可发布变更记录 | 现行 |
| [REQUIREMENTS.md](REQUIREMENTS.md) | 需求规格（SRS/PRD），可验收 | 现行 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 总体设计与模块职责 | 现行 |
| [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | ADR 索引与历史决策 | 现行（含历史条目） |
| [SECURITY_DESIGN.md](SECURITY_DESIGN.md) | 信任模型、密钥链路、威胁建模 | 现行 |
| [ROLLBACK_ANCHOR_LIFECYCLE.md](ROLLBACK_ANCHOR_LIFECYCLE.md) | 回退锚点生命周期、淘汰策略、容量错误与运维规程 | 现行（已实施） |
| [P2_SECURITY_SERVICE_PLAN.md](P2_SECURITY_SERVICE_PLAN.md) | P2 机器级安全服务设计与实施状态 | 现行（干净 VM E2E 待执行） |
| [kernel-guard/README.md](kernel-guard/README.md) | 内核加固总览、范围、冻结决策与审核门禁 | 评审中 |
| [kernel-guard/01-threat-model.md](kernel-guard/01-threat-model.md) | 内核加固威胁模型、攻击路径与残余风险 | 评审中 |
| [kernel-guard/02-architecture.md](kernel-guard/02-architecture.md) | 内核加固组件、信任边界、生命周期与失败语义 | 评审中 |
| [kernel-guard/03-driver-design.md](kernel-guard/03-driver-design.md) | 驱动模型、IOCTL、受保护进程与句柄权限剥离 | 评审中 |
| [kernel-guard/04-service-and-preset.md](kernel-guard/04-service-and-preset.md) | 服务托管、预设策略、状态机、UI 与审计 | 评审中 |
| [kernel-guard/05-test-and-verification.md](kernel-guard/05-test-and-verification.md) | 测试矩阵、VM 验证、攻击回归与验收门禁 | 评审中 |
| [kernel-guard/06-build-signing-release.md](kernel-guard/06-build-signing-release.md) | WDK 构建、测试签名、EV + attestation 与发布回滚 | 评审中 |
| [kernel-guard/07-operations-maintenance.md](kernel-guard/07-operations-maintenance.md) | 监控、事故响应、兼容矩阵与长期维护 | 评审中 |
| [kernel-guard/08-roadmap-adr.md](kernel-guard/08-roadmap-adr.md) | K0–K4 路线、ADR、开放问题与代码量预算 | 评审中 |
| [kernel-guard/09-review-checklist.md](kernel-guard/09-review-checklist.md) | 维护人审核清单与编码门禁 | 评审中 |
| [kernel-guard/10-execution-rounds.md](kernel-guard/10-execution-rounds.md) | 分轮执行、回归证据与产品断裂防护 | 执行中 |
| [kernel-guard/specs/round-8/spec.md](kernel-guard/specs/round-8/spec.md) | Round 8 宿主预创建 ARM 与运行中丢失自动锁定规格 | 已批准（运行期门禁待验证） |
| [kernel-guard/specs/round-8/tasks.md](kernel-guard/specs/round-8/tasks.md) | Round 8 文件级任务、验收与证据清单 | 已批准（T1–T7 完成） |
| [security-testing/00-spec.md](security-testing/00-spec.md) | 非内核安全测试治理规格与统一门禁 | 已交付 |
| [security-testing/01-tasks.md](security-testing/01-tasks.md) | 非内核安全测试治理任务清单 | 已交付 |
| [CORE_API.md](CORE_API.md) | C core 对外接口规范 | 现行 |
| [DATA_FLOW.md](DATA_FLOW.md) | 关键数据流时序 | 现行 |
| [GETTING_STARTED.md](GETTING_STARTED.md) | 首次构建与运行 | 现行 |
| [BUILD.md](BUILD.md) | 分阶段构建、产物与构建错误 | 现行 |
| [CONFIGURATION.md](CONFIGURATION.md) | 构建/运行/更新配置项 | 现行 |
| [TESTING.md](TESTING.md) | 测试分层与执行方式 | 现行 |
| [DEPLOYMENT.md](DEPLOYMENT.md) | 打包、产物、安装与卸载 | 现行 |
| [RELEASE.md](RELEASE.md) | 发版检查清单与回滚 | 现行 |
| [MIGRATION.md](MIGRATION.md) | 升级与迁移边界 | 现行 |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | 常见问题排查 | 现行 |
| [CODING_STANDARDS.md](CODING_STANDARDS.md) | C/Rust/TS 编码规范 | 现行 |
| [GLOSSARY.md](GLOSSARY.md) | 术语表 | 现行 |
| [THIRD_PARTY.md](THIRD_PARTY.md) | 依赖、许可证与供应链 | 现行 |
| [updater/README.md](updater/README.md) | 更新系统实施入口 | 现行 |
| [updater/UPDATER_MASTER_PLAN.md](updater/UPDATER_MASTER_PLAN.md) | 本机更新实施契约 | 现行 |
| [updater/UPDATER_SERVER_DEPLOYMENT_PLAN.md](updater/UPDATER_SERVER_DEPLOYMENT_PLAN.md) | 服务器阶段部署方案 | 待启用 |
| [references/engineering-standards.md](references/engineering-standards.md) | 工程规范附录 | 规范附录 |
| [references/comment-standards.md](references/comment-standards.md) | 注释规范附录 | 规范附录 |
| [references/comment-vocabulary.md](references/comment-vocabulary.md) | 注释约束词表 | 规范附录 |
| [references/review-standards.md](references/review-standards.md) | 审查维度附录 | 规范附录 |
| [references/acceptance-cases.md](references/acceptance-cases.md) | 人格行为验收用例（仅回归用） | 规范附录 |
| [references/versioning.md](references/versioning.md) | 版本号与命名规范 | 规范附录 |

## 4. 维护约定

1. **头部元数据**：每份文档开头必须有 `Last updated: YYYY-MM-DD`；状态、适用范围与依据按需补充。`references/` 为冻结的规范附录，不强制日期，但必须被本索引收录。
2. **同 PR 更新**：接口、目录、构建、配置、安全边界变更必须同步更新对应文档。
3. **只引用不抄录**：版本号引用根 `VERSION`；ABI 与容器格式引用 `core/include/verthys_version.h`；依赖版本引用 `Cargo.toml`、`package.json`、`dep-versions.txt`。
4. **完成即删除**：一次性执行方案与报告在验收完成后直接删除；其中仍有长期约束的内容先并入现行设计文档，再删除原文件。
5. **路径冻结**：`docs/references/` 被 `.trae/rules/project_rules.md` 引用，禁止移动或重命名。
6. **机检门禁**：文档变更后运行 `powershell -ExecutionPolicy Bypass -File ci\check_docs.ps1`；CI 由 `.github/workflows/docs.yml` 执行同一检查。
7. **评审要求**：`REQUIREMENTS`、`ARCHITECTURE`、`SECURITY_DESIGN`、`CORE_API` 的实质变更需两人评审。
