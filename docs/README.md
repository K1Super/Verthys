# docs — 文档导航

> Verthys 全部工程文档的总索引，按角色（新成员/开发者/发布者/安全审计）分组导航，定位任何主题的唯一入口。
>
> Last updated: 2026-09-20 · 维护人：K1Super

本目录的组织标准由 [DOCUMENTATION_CHECKLIST.md](DOCUMENTATION_CHECKLIST.md)（文档"目录宪法"）定义；工程刚性底线见 [ENGINEERING_CONSTRAINTS.md](ENGINEERING_CONSTRAINTS.md)。历史源稿与交付报告在 [archive/](archive/README.md)，已整合进标准文档，不再直接维护。

## 快速导航（按角色）

### 新成员

1. 总览与定位：[../README.md](../README.md)（项目唯一入口）
2. 环境与运行：[GETTING_STARTED.md](GETTING_STARTED.md)
3. 要做什么：[REQUIREMENTS.md](REQUIREMENTS.md)
4. 术语：[GLOSSARY.md](GLOSSARY.md)
5. 系统怎么长的：[ARCHITECTURE.md](ARCHITECTURE.md)

### 开发者

- 核心 DLL 接口契约：[CORE_API.md](CORE_API.md)
- 前后端桥接契约：[TAURI_BRIDGE.md](TAURI_BRIDGE.md)
- 编码与命名规范：[CODING_STANDARDS.md](CODING_STANDARDS.md)
- 测试分层与跑法：[TESTING.md](TESTING.md)
- 密钥与解锁数据流：[DATA_FLOW.md](DATA_FLOW.md)
- 性能基线与优化：[PERFORMANCE.md](PERFORMANCE.md)
- 配置项与环境变量：[CONFIGURATION.md](CONFIGURATION.md)
- 架构决策索引：[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)
- 演进方向：[ROADMAP.md](ROADMAP.md)

### 发布者

- 构建指南：[BUILD.md](BUILD.md)
- 部署与打包：[DEPLOYMENT.md](DEPLOYMENT.md)
- 发版流程：[RELEASE.md](RELEASE.md)
- 升级与迁移：[MIGRATION.md](MIGRATION.md)
- 版本变更记录：[../CHANGELOG.md](../CHANGELOG.md)

### 安全审计

- 安全设计与信任模型：[SECURITY_DESIGN.md](SECURITY_DESIGN.md)
- 漏洞上报与安全策略：[../SECURITY.md](../SECURITY.md)
- 依赖与供应链：[THIRD_PARTY.md](THIRD_PARTY.md)
- 审计报告与分片发现：[audits/](audits/VERTHYS_FULL_AUDIT_REPORT.md)（全量审计 + shard-A~E 发现 + 缺陷修复工程上游输入）
- 缺陷修复工程进度：[RemediationPlan/IMPL_PROGRESS.md](RemediationPlan/IMPL_PROGRESS.md)（Wave 分批实施，中断恢复入口）

### 问题排查

- 症状→原因→排查→解决：[TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 全量清单（按优先级）

| 文档 | 解决什么问题 | 优先级 |
|---|---|---|
| ../README.md | 项目唯一入口：定位/能力/入门 | P0 |
| REQUIREMENTS.md | 需求规格（SRS/PRD），可验收 | P0 |
| ARCHITECTURE.md | 总体设计与模块职责 | P0 |
| SECURITY_DESIGN.md | 信任模型/密钥链路/威胁建模 | P0 |
| CORE_API.md | C core 对外接口规范 | P0 |
| TAURI_BRIDGE.md | 前后端桥接接口与事件 | P0 |
| GETTING_STARTED.md | 首次构建与运行 | P0 |
| CODING_STANDARDS.md | C/Rust/TS 编码规范 | P0 |
| TESTING.md | 测试分层与执行方式 | P0 |
| DEPLOYMENT.md | 打包/产物/分发 | P0 |
| TROUBLESHOOTING.md | 常见问题排查 FAQ | P0 |
| ../CHANGELOG.md | 版本变更记录 | P0 |
| ../SECURITY.md | 安全策略与上报 | P0 |
| DATA_FLOW.md | 关键数据流时序 | P1 |
| PERFORMANCE.md | 性能基线与优化 | P1 |
| CONFIGURATION.md | 配置项与环境变量 | P1 |
| THIRD_PARTY.md | 依赖与供应链 | P1 |
| BUILD.md | 构建指南与常见错误 | P1 |
| RELEASE.md | 发版流程 | P1 |
| MIGRATION.md | 升级与迁移 | P1 |
| GLOSSARY.md | 术语表 | P1 |
| ../CONTRIBUTING.md | 贡献指南 | P1 |
| ROADMAP.md | 路线图 | P2 |
| ARCHITECTURE_DECISIONS.md | ADR 索引 | P2 |
| IMPL_PEPPER_V3_KEYSET.md | pepper 持久化 V3 与密钥槽架构实施规格（含验收结果） | P2 |
| IMPL_PEPPER_V3_PROGRESS.md | pepper 改造实施进度与变更记录 | P2 |
| RemediationPlan/IMPL_PROGRESS.md | 81 项缺陷修复工程进度（Wave 分批，中断恢复入口） | P2 |

## 维护约定（摘自查单第 4 节）

1. 接口/目录/构建/配置/安全边界变更 → 同 PR 更新对应文档。
2. 每文档末尾 `Last updated` 超过两个版本未更新需复核。
3. 需求与测试条目必须可被测试或运行命令验证。
4. 版本号、依赖版本以 `CMakeLists.txt` / `Cargo.toml` / `package.json` / `dep-versions.txt` 为准，文档只引用不抄录。
5. `REQUIREMENTS`、`ARCHITECTURE`、`SECURITY_DESIGN`、`CORE_API`（API 类）变更需两人评审。