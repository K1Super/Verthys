# Documentation Checklist — ValtCore / Verthys

> 工程化文档体系清单。本文件是 `docs/` 的“目录宪法”：定义文档范围、命名规范、存放位置、
> 每个文档必须写什么、优先级与维护时机。新增/调整文档时先对照本清单，再落地内容。
>
> 适用对象：C++/CMake（core）+ Tauri（前端）桌面端项目，安全敏感（密钥守卫、解锁、恶意哈希校验）。

---

## 0. 命名与存放规范（硬约束）

- 所有文档文件名使用 **英文、大写蛇形或小写连字符**，禁止中文文件名、禁止空格。
  - 推荐：`REQUIREMENTS.md`、`ARCHITECTURE.md`、`GETTING_STARTED.md`。
- 根目录放“面向公众/全仓入口”的文件；`docs/` 放“面向开发的详细文档”。
- 图片/架构图/流程图统一放 `docs/assets/`，图床或外链禁用；复杂图优先 Mermaid 内嵌，
  位图放 `docs/assets/` 并在正文以相对路径引用。
- 每个文档头部必须有：`# 标题` + 一段 < 80 字的“本文档解决什么问题”+ 最后更新时间/维护人。
- 文档与代码同源：接口、目录结构、构建命令变更时，对应文档必须同 PR 更新，作为 DoD（完成定义）之一。

---

## 1. 根目录必备文件（Repo Root）

| 文件名 | 目的 | 必须包含的内容 | 优先级 |
|---|---|---|---|
| `README.md` | 项目唯一入口 | 一句话定位、主要能力截图、技术栈徽章、快速链接（构建/文档/贡献/安全）、最小运行示例 | P0 |
| `CHANGELOG.md` | 版本变更记录 | Keep a Changelog 格式；按版本分组（Added/Changed/Fixed/Security）；与 Git tag 对应 | P0 |
| `LICENSE` | 开源/授权声明 | 许可证全文、版权方、商业授权说明 | P0 |
| `SECURITY.md` | 安全策略（本项目必备） | 受支持版本、漏洞上报渠道与 SLA、禁止公开披露的约定、敏感数据处理边界 | P0 |
| `CONTRIBUTING.md` | 贡献指南 | 环境准备、分支策略、Commit/PR 规范、代码评审流程、跑测试/构建的命令 | P1 |
| `.gitignore` / `vcpkg.json` / `CMakeLists.txt` | 工程元数据 | 已存在，不属文档范畴，但 README 需指向 | — |

---

## 2. `docs/` 标准文档清单

### 2.1 需求与规划层

| 文件名 | 目的 | 必须包含的内容 | 优先级 | 现状 |
|---|---|---|---|---|
| `docs/README.md` | 文档导航总索引 | 本清单的精简版入口；按角色（新成员/开发者/发布者/安全审计）分组链接 | P0 | 新建 |
| `docs/REQUIREMENTS.md` | 需求规格说明（SRS/PRD） | 背景与目标、用户角色与场景、功能需求清单（可验收）、非功能需求（性能/安全/兼容）、范围外事项 | P0 | 新建 |
| `docs/ROADMAP.md` | 路线图 | 里程碑、版本目标、已完成/进行中/规划中、关键依赖与风险 | P2 | 新建 |
| `docs/GLOSSARY.md` | 术语表 | 专有名词、缩写（如核心模块名、密钥/解锁/校验相关术语）中英文对照与统一定义 | P1 | 新建 |

### 2.2 设计与架构层

| 文件名 | 目的 | 必须包含的内容 | 优先级 | 现状 |
|---|---|---|---|---|
| `docs/ARCHITECTURE.md` | 总体设计 | 系统分层图、模块职责、进程/线程模型、core 与 Tauri 前端边界、关键设计决策（ADR 摘要） | P0 | 整合 `TARGET_ARCHITECTURE_V5.md` / `DOCUMENTATION/架构.md` |
| `docs/SECURITY_DESIGN.md` | 安全设计与信任模型 | 信任边界、密钥存储/解锁流程数据流、恶意哈希校验链路、威胁建模（STRIDE 摘要）、审计点 | P0 | 新建（安全产品必备） |
| `docs/DATA_FLOW.md` | 关键数据流 | 跨模块/跨端的时序图（解锁、加解密、导出、更新校验）；可并入 ARCHITECTURE 或独立 | P1 | 新建 |
| `docs/PERFORMANCE.md` | 性能基线与优化 | 性能指标基线、测量方法、已知瓶颈与优化记录 | P1 | 整合 `PERFORMANCE_ARCHITECTURE.md` / `DOCUMENTATION/性能.md` |
| `docs/CONFIGURATION.md` | 配置项说明 | 所有配置文件、环境变量、运行时开关的含义、默认值、取值范围与影响 | P1 | 新建 |

### 2.3 接口与契约层

| 文件名 | 目的 | 必须包含的内容 | 优先级 | 现状 |
|---|---|---|---|---|
| `docs/CORE_API.md` | C core 对外接口规范 | 公开头文件/函数签名、参数与返回值语义、错误码、生命周期/内存约定、线程安全 | P0 | 新建 |
| `docs/TAURI_BRIDGE.md` | 前后端桥接接口 | Tauri command 清单、入参/出参 schema、事件定义、权限与鉴权边界、错误约定 | P0 | 新建 |
| `docs/THIRD_PARTY.md` | 依赖与供应链 | 第三方库清单、版本（对齐 `vcpkg.json` / `dep-versions.txt` / `third_party/`）、引入理由、升级策略、许可证清单 | P1 | 新建 |

### 2.4 使用与开发层

| 文件名 | 目的 | 必须包含的内容 | 优先级 | 现状 |
|---|---|---|---|---|
| `docs/GETTING_STARTED.md` | 快速开始 | 前置依赖、首次构建步骤、运行与调试、验证构建成功的最小命令/截图 | P0 | 新建（可链接根 `build_*.ps1`） |
| `docs/CODING_STANDARDS.md` | 编码规范 | C++/Rust/TS 风格、命名、注释、clang-format/clang-tidy 规则引用、提交规范 | P0 | 整合 `c_layer_coding_spec.md` |
| `docs/TESTING.md` | 测试说明 | 测试分层（单元/集成/E2E）、如何跑测试、覆盖率要求、关键场景用例说明 | P0 | 新建 |
| `docs/ARCHITECTURE_DECISIONS.md` | 架构决策记录（ADR 索引） | 每条决策：上下文、选项、结论、后果；按编号索引 | P2 | 新建 |

### 2.5 交付与运维层

| 文件名 | 目的 | 必须包含的内容 | 优先级 | 现状 |
|---|---|---|---|---|
| `docs/BUILD.md` | 构建指南 | 全量/增量/Release/Debug 构建、依赖安装、跨平台注意事项、常见构建错误 | P1 | 可并入 DEPLOYMENT |
| `docs/DEPLOYMENT.md` | 部署/打包/发布 | 打包流程、产物清单与命名、签名、安装包分发、升级机制 | P0 | 新建 |
| `docs/RELEASE.md` | 发布流程 | 版本号规则、发版检查清单、tag/发布物流程、回滚方案 | P1 | 新建 |
| `docs/MIGRATION.md` | 升级与迁移 | 版本间数据/配置迁移说明、breaking changes、旧版本处理 | P1 | 整合 `V3_UPGRADE_PLAYBOOK.md` |
| `docs/TROUBLESHOOTING.md` | 常见问题排查（FAQ） | 症状 → 可能原因 → 排查步骤 → 解决方法；按模块分类；附日志位置与诊断命令 | P0 | 新建 |

---

## 3. 资源目录约定

```
docs/
├── README.md                 # 文档导航（P0）
├── assets/                   # 图片、截图、位图
│   ├── architecture/
│   ├── flows/
│   └── ui/
├── diagrams/                  # Mermaid / SVG 源文件（可选）
└── （上述各 .md）
```

---

## 4. 维护规范（Definition of Done 中包含）

1. **代码变更同步**：接口/目录/构建/配置/安全边界变更 → 同 PR 更新对应文档。
2. **新鲜度**：每个文档末尾维护 `Last updated: YYYY-MM-DD`；超过两个版本未更新需复核。
3. **可验收**：需求与测试文档中的条目必须可被测试或运行命令验证，禁止模糊表述。
4. **单一事实来源**：版本号、依赖版本以 `vcpkg.json` / `dep-versions.txt` 为准，文档只引用不抄录。
5. **评审**：`REQUIREMENTS`、`ARCHITECTURE`、`SECURITY_DESIGN`、`API` 四类文档变更需两人评审。

---

## 5. 落地优先级（分批建设）

- **第一批（P0，最小可用集）**：根 `README.md`、`CHANGELOG.md`、`SECURITY.md`；
  `docs/README.md`、`REQUIREMENTS.md`、`ARCHITECTURE.md`、`SECURITY_DESIGN.md`、
  `CORE_API.md`、`TAURI_BRIDGE.md`、`GETTING_STARTED.md`、`CODING_STANDARDS.md`、
  `TESTING.md`、`DEPLOYMENT.md`、`TROUBLESHOOTING.md`。
- **第二批（P1）**：`CONTRIBUTING.md`、`GLOSSARY.md`、`DATA_FLOW.md`、`PERFORMANCE.md`、
  `CONFIGURATION.md`、`THIRD_PARTY.md`、`BUILD.md`、`RELEASE.md`、`MIGRATION.md`。
- **第三批（P2）**：`ROADMAP.md`、`ARCHITECTURE_DECISIONS.md`。

> 已有零散文档（`TARGET_ARCHITECTURE_V5.md`、`PERFORMANCE_ARCHITECTURE.md`、
> `V3_UPGRADE_PLAYBOOK.md`、`c_layer_coding_spec.md`、`DOCUMENTATION/*.md`、各类核验报告）
> 不要直接删除，按上表“现状”列整合/链接到对应标准文档，原始报告归入 `docs/archive/`。
