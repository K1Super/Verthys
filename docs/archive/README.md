# archive — 遗留文档归档区

> 保存历史源稿与交付报告，作为标准文档（docs/*.md）整合前的原始凭证，不参与日常导航。
>
> Last updated: 2026-09-19 · 维护人：K1Super

按 `docs/DOCUMENTATION_CHECKLIST.md` 第 5 节约定：已有零散文档不删除，按“现状”列整合进标准文档后，原稿归入本目录。

## 源稿 → 标准文档映射

| 归档文件 | 整合去向（标准文档） | 说明 |
|---|---|---|
| TARGET_ARCHITECTURE_V5.md | [ARCHITECTURE.md](../ARCHITECTURE.md)、[ARCHITECTURE_DECISIONS.md](../ARCHITECTURE_DECISIONS.md) | 目标架构 V5 全量设计 |
| DOCUMENTATION/架构.md | [ARCHITECTURE.md](../ARCHITECTURE.md) | 架构专章 |
| DOCUMENTATION/解锁.md | [SECURITY_DESIGN.md](../SECURITY_DESIGN.md)、[DATA_FLOW.md](../DATA_FLOW.md) | 解锁流程与密钥守卫设计 |
| DOCUMENTATION/性能.md | [PERFORMANCE.md](../PERFORMANCE.md) | 性能专章 |
| PERFORMANCE_ARCHITECTURE.md | [PERFORMANCE.md](../PERFORMANCE.md) | 性能架构设计（与性能.md 合并） |
| c_layer_coding_spec.md | [CODING_STANDARDS.md](../CODING_STANDARDS.md) | C 层编码规范 |
| V3_UPGRADE_PLAYBOOK.md | [MIGRATION.md](../MIGRATION.md) | V3 容器升级手册 |
| PROJECT_DOCUMENTATION.md | [REQUIREMENTS.md](../REQUIREMENTS.md)、[ROADMAP.md](../ROADMAP.md) | 项目总述与功能清单 |
| current_progress.md（原名 Current progress.md） | [ROADMAP.md](../ROADMAP.md) | 进度记录（文件名已按命名规范改为小写蛇形） |
| UNLOCK_OPTIMIZATION.md | 与 DOCUMENTATION/解锁.md 内容重复，仅存档 | 重复源稿 |
| Verthys品牌整改验证交付报告.md | 历史交付报告，仅存档 | 品牌重塑（ValtCore→Verthys）验证结论 |
| 应用功能全量核验报告.md | 历史交付报告，仅存档 | 应用功能全量核验结论 |

## 约定

- 本目录文件不再修改；如需更新内容，请修改对应标准文档。
- 交付报告类（中文文件名）为历史凭证，保留原文件名与原文。