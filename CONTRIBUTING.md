# Contributing

> 说明环境准备、分支与提交规范、评审流程，以及测试构建与文档同步义务。
>
> Last updated: 2026-09-19 · 维护人：K1Super

## 环境准备

前置依赖与首次构建步骤见 [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)；Windows 环境需 MSVC 工具链（经 `scripts/env.load.ps1` 注入）、Node.js 与 Rust 工具链。

## 分支策略

- 当前为单分支开发：`v3-upgrade` 为当前工作分支，`master` 为保留基线；无多分支并行协作约定。
- 日常改动直接在 `v3-upgrade` 上提交；提交前必须本地自检（构建 + 测试 + 静态校验，见下文）。

## Commit 规范

- 格式关联 [docs/CODING_STANDARDS.md](docs/CODING_STANDARDS.md)。
- 推荐 Conventional Commits 中文格式：`type(scope): 摘要`，`type` 取 `feat / fix / refactor / docs / chore / security` 等；正文说明"为什么"。
- 现有历史风格：近期提交为中文动宾摘要（如"品牌重塑 ValtCore/vault→Verthys 全量整改"），早期存在 "updata"/"init" 等无信息消息。新提交应比现有历史更规范，避免 "updata" 类消息。

## PR 与评审流程

- 改动以 PR 提交；PR 需通过 CI（见 `.github/workflows/core.yml`）与本地自检。
- 涉及 `REQUIREMENTS`、`ARCHITECTURE`、`SECURITY_DESIGN`、`CORE_API`（API 类）文档的变更需两人评审（依据 `docs/DOCUMENTATION_CHECKLIST.md` 第 4 节）。

## 测试与构建命令

- 核心 DLL 开发构建 + 运行全部 C 测试（Debug）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_core.dev.ps1
```

等价地，构建后可用 CTest 运行核心测试：

```powershell
ctest --test-dir build_dev -C Debug --output-on-failure
```

- 核心 DLL 生产构建（Release，跳过测试）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_core.release.ps1
```

- 全量生产构建（C 核心 DLL → worker → Tauri NSIS 安装包 → 产物校验）：

```powershell
powershell -ExecutionPolicy Bypass -File build_production.ps1
```

- CI 静态校验（第一级正则过滤 + 第二级 AST 深度分析）：

```powershell
powershell -ExecutionPolicy Bypass -File ci\run_ci.ps1
```

测试分层、覆盖率要求与模糊测试用法见 [docs/TESTING.md](docs/TESTING.md)。

## 文档同步义务

改动接口 / 目录 / 构建 / 配置 / 安全边界时，必须同 PR 更新对应文档（作为完成定义 DoD 之一），依据 `docs/DOCUMENTATION_CHECKLIST.md` 第 4 节：

1. 接口、目录、构建、配置、安全边界变更 → 同 PR 更新对应文档。
2. 每文档末尾 `Last updated` 超过两个版本未更新需复核。
3. 需求与测试条目必须可被测试或运行命令验证。
4. 版本号、依赖版本以 `vcpkg.json` / `dep-versions.txt` 为准，文档只引用不抄录。