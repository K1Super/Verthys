# Verthys 更新系统实施文档

> 状态：唯一实施文档入口（自 2026-10-22 起）
> 适用对象：Verthys Windows x64 桌面端（Tauri 2 + Rust 主进程 / verthys-worker 子进程 + C11 `verthys.dll` + Vue 3）
> 维护人：K1Super

---

## 1. 文档

| 文档 | 内容 | 何时使用 |
|---|---|---|
| [UPDATER_MASTER_PLAN.md](UPDATER_MASTER_PLAN.md) | 本机实施规范：架构决策、Manifest v2、客户端引擎、任务分解、质量门、测试矩阵、发布治理 | 现在；所有更新域代码、脚本、配置、测试与文档以本文为准 |
| [UPDATER_SERVER_DEPLOYMENT_PLAN.md](UPDATER_SERVER_DEPLOYMENT_PLAN.md) | 服务器部署：HTTPS 分发、签名清单、不可变物料、灰度、暂停 / 撤回、可观测、灾备、Runbook | 达到本机 L0 退出与客户端 readiness 后启用 |
| [UPDATER_LOCAL_VERIFICATION.md](UPDATER_LOCAL_VERIFICATION.md) | 本机验证记录：自动化门、真实物料签名 / PE、运行期检查与未执行项 | 发布前核对证据 |

---

## 2. 阅读路径

| 目标 | 阅读顺序 |
|---|---|
| 现在做本机更新 | MASTER PLAN 第 0 节 → 第 1 节现状基线 → 第 2 节架构决策 → 第 5 节本机实施 → 第 6 节质量门 |
| 以后部署服务器 | MASTER PLAN 第 2.2 节阶段资格 → 第 8 节服务器衔接 → SERVER PLAN 全文 |
| 安全 / 审计 | MASTER PLAN 第 2.5 节威胁模型 → 第 3 节清单协议 → 第 4 节客户端引擎 → 附录 A 证据锚点 |

---

## 3. 变更治理

1. **单一事实源**：更新域任何代码、配置、脚本、错误码、阈值变更，必须在同一 PR 更新 MASTER PLAN 对应章节与 [../CONFIGURATION.md](../CONFIGURATION.md)。
2. **文档可验证**：需求、阈值、测试条目必须能由命令、测试或实机步骤验证；无法验证的表述不得写成“已具备”。
3. **版本与日期**：本目录文档的 `Last updated` 随实质修改刷新；版本号只引用根 `VERSION`，不抄录具体版本。
4. **链接完整**：本目录文档之间的相对链接必须可解析；索引变更与文档变更同 PR。

---

## 4. 术语

| 术语 | 含义 |
|---|---|
| Phase L | 本机阶段：回环夹具、内部验证、不对外分发 |
| Phase S | 服务器阶段：HTTPS 分发、渠道、灰度、遥测、外部分发 |
| LKG | Last Known Good，上一次已验证可用的安装物料 |
| 清单 | `latest.json`，客户端拉取的版本 / 兼容 / 下载 / 签名元数据 |
| 安装包签名 | minisign 签名，覆盖最终安装包字节 |
| 清单签名 | 对清单规范化 JSON 的独立签名，服务器阶段强制 |
| 锁库闸门 | 安装前 `lockAll` 落盘 + 脏数据检查 + 密钥缓存清理的硬约束 |
| 更新标记 | 安装前写入、重启后消费的持久化更新状态文件 |
| 回退分级 | R0 检测与指引、R1 修复入口、R2 外部看门狗自动回退 |

---

## 5. 关联文档

- 构建与产物：[../BUILD.md](../BUILD.md)、[../DEPLOYMENT.md](../DEPLOYMENT.md)
- 发版流程：[../RELEASE.md](../RELEASE.md)
- 安全与信任模型：[../SECURITY_DESIGN.md](../SECURITY_DESIGN.md)
- 测试分层：[../TESTING.md](../TESTING.md)
- 配置登记：[../CONFIGURATION.md](../CONFIGURATION.md)
- 故障排查：[../TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
