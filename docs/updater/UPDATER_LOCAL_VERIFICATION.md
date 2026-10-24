# 本机更新系统验证记录

> 日期：2026-10-23 · 环境：Windows x64 开发机 · 版本：4.1.7 · 更新渠道：local
>
> 本记录只记录已实际执行的验证；未执行项单独列出，不替代验收结论。

## 1. 自动化门

| 项 | 命令 | 结果 |
|---|---|---|
| Rust 测试 | `cargo test`（src-tauri） | 493 通过 / 0 失败 |
| Rust 静态检查 | `cargo clippy --all-targets -- -D warnings` | 通过 |
| 前端测试 | `npx vitest run` | 599 通过 / 0 失败 |
| TypeScript | `npx vue-tsc --noEmit` | 通过 |
| 前端构建 | `npm run build` | 通过 |
| 清单脚本测试 | `node --test scripts/release/make_updater_manifest.test.mjs` | 3 通过 / 0 失败 |
| Profile 门 | production / local 配置检查 | 均通过 |
| 构建脚本语法 | PowerShell 解析 `build_production.ps1` | 通过 |

## 2. 物料与签名

| 项 | 结果 |
|---|---|
| 清单 schema_version | 2 |
| release_id | `20261022-185317-4.1.4-b5e487ad` |
| 安装包 | `Verthys_4.1.4_x64-setup.exe` |
| 安装包 SHA256 | `6551ba1a089e7e91ffcb4a648590fe4389aa604e2b38c214736535da35742efd` |
| 安装包大小 | 4,963,436 字节 |
| PE FileVersion | 4.1.4 |
| 清单规范化 SHA256 | `7da4a744f477002024e95d250a5dd241f5ba79d18ebb344df207ee87b55a9edc` |
| 安装包 minisign 复验 | 通过（真实产物） |
| 清单 minisign 复验 | 通过（真实产物） |
| release manifest | `build/updater/release-manifest.json`，安装包 / 清单 / SBOM 哈希一致 |

## 3. 正向升级：4.1.3 → 4.1.4

升级前 `E:\Verthys` 为 4.1.3 基线（`Verthys.exe` 4.1.3、17,102,336 字节，内置 `e2e_update` 钩子），注册表 `DisplayVersion=4.1.3`。回环服务返回 `latest.json` 200，清单版本 4.1.4、安装包大小 4,963,436。应用以 `VERTHYS_E2E_UPDATE=1` 启动后自动执行完整链路。

日志事件顺序：

```text
check_sent        channel=local
check_hit         toVersion=4.1.4 size=4963436 releaseId=20261022-185317-4.1.4-b5e487ad
download_start    attempt=1
sig_ok            releaseId=20261022-185317-4.1.4-b5e487ad
hash_ok           hashPrefix=6551ba1a089e
e2e_prepared      fileVersion=4.1.4
lock_ok           durationMs=0
install_handoff   releaseId=20261022-185317-4.1.4-b5e487ad
health_ok
check_sent        channel=local
check_miss
```

升级后结果：

| 项 | 结果 |
|---|---|
| `E:\Verthys\Verthys.exe` | 4.1.4，17,069,056 字节 |
| 注册表 `DisplayVersion` | 4.1.4 |
| 新进程与 worker | 均正常启动 |
| 更新历史标记 | `state=health_confirmed`，`ownerPid=16804` |
| `pending.json` | 已归档并移除 |
| 升级后静默检查 | `check_miss`，未重复提示更新 |

> 更新端子刻度样式迭代后，本机以同版本 4.1.4 重新构建并覆盖安装。新安装包位于 `verthys-tauri/src-tauri/target/release/bundle/nsis/`；本节更新链路证据对应 `build/updater` 中的 E2E 安装包，覆盖安装不改变更新链路结论。

## 4. 负向升级

| 场景 | 观察结果 |
|---|---|
| 清单签名篡改 | `check_sent` → `manifest_sig_invalid`（`E_UPDATER_MANIFEST_SIG_INVALID`） |
| 清单声明 4.1.5、安装包实际 4.1.4 | `check_hit` toVersion=4.1.5 → `download_start` → `e2e_failed`（`E_UPDATER_PE_VERSION_MISMATCH`） |

负向用例均在下载或校验阶段中止，未进入安装。

## 5. 验证中发现并修复的问题

首次正向升级时，安装文件已替换为新版，但旧进程在前端启动自检中读到刚写入的 `pending.json`，把 `to_version != current_version` 误判为安装失败并归档为 `install_failed`。

修复：`pending.json` 记录写入进程 `ownerPid`；`updater_startup_state` 对同进程标记返回 `has_pending=false`，`updater_ack_startup` 拒绝对同进程标记写入结论。只有重启后的新进程可以消费标记并执行健康自检。修复后重新构建 4.1.3 基线与 4.1.4 安装包，重复完整升级，日志与历史标记均正确。

## 6. 未执行项

| 项 | 原因 | 后续 |
|---|---|---|
| 安装中断、断电、磁盘不足 | 需要可回滚的测试环境 | 按运行时矩阵执行 |
| 锁库脏数据 / worker 未退出 | 需要可注入的会话状态 | 构造脏库场景后执行 |
| 降级、灰度、暂停、撤回 | 需要多版本物料与多安装标识 | 发布下一版本时执行 |
| 容器记录数升级前后核对 | 需要真实测试容器与凭据 | 由业务验收补充 |

## 7. 结论

4.1.4 的真实签名安装包已完成本机端到端升级：检查、下载、清单验签、安装包验签、SHA256、PE 版本、锁库闸门、安装接管、重启与健康自检全部通过，负向签名篡改与 PE 版本不符均在安装前被拒绝。其余故障注入仍需按上表补测。

## 8. 兼容字段修正后的复核

兼容区间改为编译期读取核心头文件后，`build/updater/latest.json` 已重新生成并签名；安装包字节与 SHA256 未变。

| 项 | 结果 |
|---|---|
| 核心 ABI | `0x000B ~ 0x000E` 桥接区间（`0x000B` 兼容修正前客户端，`0x000E` 为当前核心） |
| 容器版本 | `3` |
| 清单 release_id | `20261023-084324-4.1.4-b5e487ad` |
| 清单签名 | 通过，key id `C2F4D1D486662913` |
| 安装包 SHA256 / 大小 | `6551ba1a089e7e91ffcb4a648590fe4389aa604e2b38c214736535da35742efd` / 4,963,436 |
| Rust 全量单测 | 497 通过 / 0 失败 |
| 更新域单测 | 16 通过 / 0 失败 |
| 清单脚本测试 | 7 通过 / 0 失败 |
| Clippy | 零告警 |
| 前端类型检查 | 通过 |
| 更新前端单测 | 9 通过 / 0 失败 |
| 更新域边界门 | 通过 |
| 端到端升级 | 本轮未重跑 |

## 9. 会话、传输与闸门修正后的复核

本轮把检查、准备、锁库与安装纳入同一操作锁；取消改为取消令牌加代际号；安装改为挑战/一次性回执；下载由本服务自行执行并校验下载地址、重定向上限、长度与空闲超时。

| 项 | 结果 |
|---|---|
| Rust 全量单测 | 503 通过 / 0 失败 |
| 更新域单测 | 22 通过 / 0 失败 |
| 传输集成测试 | 精确字节、长度不符拒绝、在途取消三条均通过 |
| Clippy（含 e2e_update） | 零告警 |
| 前端测试 | 602 通过 / 0 失败（50 个文件） |
| 前端类型检查 | 通过 |
| 下载地址策略测试 | 本机回环、非回环、协议不符、主机白名单、插件地址不一致均覆盖 |
| 闸门测试 | 挑战绑定会话/发布/字节；挑战与回执过期判定通过 |
| 安装临界区 | 已实现：后端在锁库与安装移交期间拒绝关闭并回传提示，模块切换被拒绝（端到端未重跑） |
| 端到端升级 | 本轮未重跑 |

## 10. 标记、健康与修复修正后的复核

本轮把更新标记升级为 v2，健康结论改由 Rust 判定，并落地 LKG 晋升、修复入口与原生兜底。

| 项 | 结果 |
|---|---|
| Rust 全量单测 | 508 通过 / 0 失败 |
| 更新域单测 | 27 通过 / 0 失败 |
| Clippy（含 e2e_update） | 零告警 |
| 前端测试 | 602 通过 / 0 失败（50 个文件） |
| 前端类型检查 / 生产构建 | 均通过 |
| 标记结构 | v1 读取迁移、v2 写入；非法 release_id / 状态 / 时间戳拒绝并隔离 |
| 历史与候选保留 | 归档最近 10 份；候选物料 7 天；known-good 最近 2 份 |
| 健康自检 | DLL 哈希、worker 就绪、ABI/容器版本由 Rust 判定；只读探测如实标记为跳过 |
| LKG | 安装前复制候选，健康确认后晋升；保留最近 2 份 known-good |
| 修复 | `repair.json` 记录上一 known-good；修复前复验签名 / 哈希 / PE；启动失败保留错误状态 |
| 安装进行中窗口 | handoff 未超过 15 分钟不消费标记 |
| 原生兜底 | 前端 90 秒未接管时提供运行自检 / 打开日志 / 运行修复对话框 |
| 端到端升级与真实修复 | 本轮未重跑 |

## 11. 错误码、事件与日志导出修正后的复核

本轮建立错误码与事件的双向契约，日志改为固定基础字段、写入即脱敏、导出为 zip，并让界面只展示映射文案。

| 项 | 结果 |
|---|---|
| Rust 全量单测 | 514 通过 / 0 失败 |
| 更新域单测 | 33 通过 / 0 失败 |
| Clippy（含 e2e_update） | 零告警 |
| 前端测试 | 604 通过 / 0 失败（50 个文件） |
| 前端类型检查 / 生产构建 | 均通过 |
| 错误码契约 | Rust 29 个错误码与前端文案键完全一致 |
| 错误码源码扫描 | 未登记错误码会使测试失败 |
| 事件 schema | 固定事件清单；未登记事件会使测试失败 |
| 事件基础字段 | ts / eventId / sessionId / installId / event / phase / code / severity / os / arch / detail |
| 日志路径 | `app_data/logs/updater`；旧 `updater/logs` 首次启动迁移 |
| 脱敏 | 完整 SHA-256 截为 12 位；Windows / UNC / 用户目录路径替换为 `<path>`；含空格路径覆盖 |
| 导出 | 用户选择目标路径，Rust 生成标准 zip（含 manifest）；zip 可读性与脱敏由测试覆盖 |
| 下载进度 | 聚合为最多约 10 次/秒，不再逐块推送 |
| 界面文案 | 仅显示错误码映射的标题与指引；原始诊断只进日志 |
| 更新说明 / 强制更新 UI | 尚未实现，仍为待收口项 |
| 端到端升级与真实导出 | 本轮未重跑 |

## 12. 配置与发布链路修正后的复核

本轮把更新配置拆为基础配置与 profile 覆盖层，增加有效配置门与运行期审计；渠道改为从配置读取；发布物料改由一条命令生成，并由构建脚本自动接线。

| 项 | 结果 |
|---|---|
| Rust 全量单测 | 514 通过 / 0 失败 |
| 更新域单测 | 33 通过 / 0 失败 |
| Clippy（含 e2e_update） | 零告警 |
| Rust 格式检查 | `cargo fmt --check` 通过 |
| 前端测试 | 604 通过 / 0 失败（50 个文件） |
| 前端类型检查 / 生产构建 | 均通过 |
| 错误码契约 | Rust 与前端 30 个错误码完全一致，新增 `E_UPDATER_CONFIG_INVALID` |
| 有效配置门（local） | `tauri.local.conf.json` 通过：回环端点、`channel=local`、明文许可一致 |
| 有效配置门（production） | 注入 `https://updates.verthys.com/stable/latest.json` 后通过；占位 / 回环主机被拒绝 |
| 运行期配置审计 | 渠道缺失、协议 / 主机不合规、明文开关违规均返回 `E_UPDATER_CONFIG_INVALID`，不发起请求 |
| 渠道来源 | 前端不再传 `channel`；`updater_check` 从配置读取 |
| 发布物料 | `release_update.mjs` 实测生成 `20261023-104012-4.1.4-b5e487ad`：`latest.json`、安装包、`.sig`、`release-manifest.json`、`channel-pointer.json` 五件齐全 |
| 发布物料 ABI | `0x000B ~ 0x000E`，容器版本 `3`，清单签名通过 |
| 构建脚本 | `build_production.ps1` 文件头为 `EF BB BF`，PowerShell 解析通过；默认 `production`，端点缺失即失败 |
| 构建接线 | 构建完成后自动定位 NSIS 安装包与 `.sig`，调用 `release_update.mjs` |
| 边界门 | `ci/check_updater_boundary.ps1` 通过 |
| 版本门 | `ci/sync_version.ps1 -CheckOnly` 通过（4.1.4） |
| 依赖快照 | 重新生成 804 条目；连续两次运行哈希一致，幂等 |
| 端到端升级 | 本轮未重跑 |
| 真实发布上传 | 未执行（production 物料只生成到本地目录） |

## 13. 运行时端到端矩阵

本轮把已安装客户端升级到带 `e2e_update` 钩子的 4.1.4 基线，生成 4.1.5 真实签名物料，再以真实回环服务逐项注入故障并执行正向升级。

负向用例（全部在安装前中止）：

| 用例 | 注入 | 观察结果 |
|---|---|---|
| 清单签名篡改 | 修改 `notes` 不重签 | `manifest_sig_invalid` / `E_UPDATER_MANIFEST_SIG_INVALID` |
| 渠道不一致 | `channel=stable` 并重签 | `manifest_invalid` / `E_UPDATER_CHANNEL_MISMATCH` |
| 暂停发布 | `paused=true` 并重签 | `check_miss`，无下载 |
| 灰度排除 | `rollout.percentage=0` 并重签 | `check_miss`，无下载 |
| 桥接版本 | `min_version=9.9.9` 并重签 | `manifest_invalid` / `E_UPDATER_BRIDGE_REQUIRED` |
| ABI 不兼容 | `compatibility.abi.min=0x7FFF` 并重签 | `manifest_invalid` / `E_UPDATER_COMPAT_BLOCKED` |
| 版本撤回 | `revoked_release_ids` 命中当前发布 | `manifest_invalid` / `E_UPDATER_INSTALL_REVOKED` |
| 哈希不符 | 清单 `sha256` 置零并重签 | 下载完成 → `hash_mismatch` / `E_UPDATER_HASH_MISMATCH` |
| 大小不符 | 清单 `size` 加一字节并重签 | `size_mismatch` / `E_UPDATER_SIZE_MISMATCH` |
| PE 版本不符 | 清单声明 4.1.6，安装包实际 4.1.5 | 下载完成 → `pe_version_mismatch` / `E_UPDATER_PE_VERSION_MISMATCH` |

正向升级 4.1.4 → 4.1.5：

```text
check_sent → check_hit(4.1.5)
download_start → download_success(5,420,344)
sig_ok → hash_ok(7c4f5724a6bc) → e2e_prepared(fileVersion=4.1.5)
lock_ok → install_handoff
health_ok(dll_integrity=ok, worker_ready=ok, abi_negotiation=ok, read_only_probe=skipped)
```

| 项 | 结果 |
|---|---|
| 负向矩阵 | 10/10 通过，全部在安装前中止 |
| 正向升级 | 通过，安装后 `Verthys.exe` FileVersion = 4.1.5 |
| 标记归档 | `updater/history/20261023-110331-4.1.5-b5e487ad-*.json`，`state=health_confirmed` |
| pending 标记 | 已移除 |
| LKG | `updater/lkg/known-good-4.1.5.exe` 已生成，`current.json` 指向 4.1.5 |
| 健康子项 | DLL 完整性、worker 就绪、ABI 握手通过；只读探测按设计跳过 |
| 矩阵脚本 | `scripts/updater/updater_e2e_matrix.mjs`，可重复执行并自动恢复清单 |
| 发布物料 | `20261023-110331-4.1.5-b5e487ad`，5,420,344 字节，SHA256 `7c4f5724...`，五件齐全 |
| Rust 全量单测 | 514 通过 / 0 失败 |
| 前端测试 | 604 通过 / 0 失败（51 个文件） |
| Clippy / 格式 | 零告警 / `cargo fmt --check` 通过 |
| 版本 / 边界门 | 均通过（4.1.5） |
| 依赖快照 | 804 条目，连续两次哈希一致 |
| 发现并修复 | 构建脚本按字典序取安装包，把残留 4.1.4 包当作 4.1.5 发布；已改为按 VERSION 精确选取 |

## 14. Authenticode、更新窗口与源站缓存复核

本轮补齐系统签名验证、更新说明与强制更新窗口，并把回环夹具升级为可验证 CDN 回源契约的源站。

| 项 | 结果 |
|---|---|
| Authenticode 实现 | 准备阶段与安装前复检均调用 `WinVerifyTrustEx`；读取签名者主体与 SHA-1 指纹，支持可选钉扎 |
| 真实签名样本 | `node.exe`（OpenJS Foundation）验证通过，主体与指纹 `6153EB01...` 与系统结果一致 |
| 篡改样本 | 翻转签名字节后拒绝，返回 `E_UPDATER_AUTHENTICODE_INVALID` |
| 未签名样本 | `win.ini` 验证失败，证明未签名文件不会被放行 |
| 生产强制 | 配置门要求 `require=true`、`revocation=true`；运行期审计与构建发布前复核同一约束 |
| 更新窗口 | 手动检查展示版本跨度与说明；`force_below` 命中后不可用 Esc / 遮罩关闭 |
| 窗口测试 | 更新窗口 4 条契约测试通过；前端全量 608 通过 / 0 失败（52 个文件） |
| 前端构建 | `vue-tsc` 与 `vite build` 通过，新增窗口按视图级懒加载分包 |
| 源站缓存 | 清单 `no-store`；安装包 `immutable`、ETag、304、Range 206 / 416 全部通过 |
| Rust 全量单测 | 516 通过 / 0 失败；2 条真实签名测试按需忽略执行 |
| Clippy / 格式 | 零告警 / `cargo fmt --check` 通过 |
| 真实 CDN | 未执行：无 CDN 账号与域名；仅验证源站契约，边缘回源与 purge 未演练 |
| 真实 EV / OV 证书 | 未提供；发布侧签名与证书链核验待证书到位后执行 |
| 版本与物料 | B6 变更已随 4.1.6 构建并安装，见第 15 节 |

环境就绪后的执行入口：

```text
运行时矩阵：安装带 e2e_update 的基线 → 启动 updater_server.mjs → 运行 updater_e2e_matrix.mjs --include-positive
CDN：node scripts/updater/check_updater_origin.mjs --url https://<渠道域名>
证书：signtool 签名安装包 → build_production.ps1 -Profile production 复核系统信任链
```

## 15. 发布前置、CI 物料复现与 4.1.6 构建

本轮把发布链路从“能在本机生成”推进到“可前置检查、可在 CI 从源码复现、可安装验证”。

| 项 | 结果 |
|---|---|
| 发布前置（local） | `ci/release_preflight.ps1 -Profile local` 通过；工作区未提交仅告警 |
| 发布前置（production） | 正确阻断：缺少 Authenticode 证书指纹；未对缺失条件放行 |
| 工作流 YAML | 三个工作流均可解析；修正了 `cargo-deny` 与 clang-tidy 步骤名未加引号导致的 YAML 错误 |
| CI 物料复现 | 新增 `release-materials.yml`：手动触发，从源码构建 core / worker / Tauri，临时生成签名密钥，调用 `release_update.mjs` 并上传物料 |
| 4.1.6 构建 | `build_production.ps1 -Profile local -AllowLocal` 成功；NSIS 安装包 5,427,606 字节 |
| 4.1.6 物料 | release `20261023-121044-4.1.6-b5e487ad`，SHA256 `3d58b8fc...`，清单 / 安装包 / `.sig` / 账本 / 渠道指针五件齐全 |
| 4.1.6 安装 | 静默安装成功；`E:\Verthys\Verthys.exe` FileVersion = 4.1.6，注册表 DisplayVersion = 4.1.6 |
| 启动验证 | 安装后启动 8 秒进程保持运行，随后停止，未发现启动崩溃 |
| CI 实际运行 | 未在本机执行 GitHub Actions；工作流仅完成本地语法与逻辑校验 |
| 端到端升级 | 本轮未重跑（4.1.6 通过安装包覆盖安装，不经更新器） |

## 16. 发布撤回复检与发布报告复核

本轮在锁库挑战签发前增加在线发布复检，并补齐从事件日志生成发布报告的脚本。

| 项 | 结果 |
|---|---|
| 复检时机 | `updater_begin_lock` 在签发挑战前重新拉取并验签清单 |
| 复检判定 | 暂停、撤回、灰度排除、`release_id` / 版本 / 哈希 / 大小 / `file_version` 变化均中止 |
| 网络失败 | 返回 `E_UPDATER_NETWORK`（可重试），不放行未确认发布 |
| 并发保护 | 复检期间取消或会话变化会在重新取锁后检测并拒绝 |
| 单元测试 | 相同发布通过；版本与哈希变化均返回 `E_UPDATER_INSTALL_REVOKED` |
| Rust 全量单测 | 518 通过 / 0 失败；2 条真实签名测试按需忽略 |
| 4.1.7 构建 | release `20261023-123721-4.1.7-b5e487ad`，5,440,970 字节，SHA256 `4979473a...` |
| 真实升级 | 4.1.6 → 4.1.7 通过；日志出现 `release_recheck_ok` |
| 升级后状态 | `Verthys.exe` 4.1.7；`known-good-4.1.7.exe` 已晋升，保留 4.1.5 与 4.1.7 |
| 标记归档 | 最新历史 `20261023-123721-4.1.7-b5e487ad-*.json`，健康通过 |
| 发布报告 | `scripts/updater/updater_report.mjs` 生成 JSON / Markdown：25 会话、63 次检查、12 次命中、3 次安装移交、3 次健康通过、成功率 100% |
| 报告测试 | 聚合、Markdown 字段与空健康结论 3 条测试通过 |
| 撤回运行期用例 | 未单独构造下载后撤回的时间窗；变更检测由单元测试覆盖 |
| 真实 CDN / 真实证书 | 仍受环境限制，未执行 |

## 17. B9 外部依赖复核与可替代验证

本轮重新核查外部条件，并补齐可执行的替代验证。

| 项 | 结果 |
|---|---|
| 真实 CDN | `updates.verthys.com` 可解析，但 HTTPS 握手失败：证书链不受信任 |
| 生产端点门 | `release_preflight.ps1` 现探测 HTTPS 端点；真实端点被正确阻断 |
| 边缘回源模拟 | 新增 `check_cdn_edge.mjs`：清单两次均回源、安装包第二次命中边缘、304 / 206 由缓存应答，全部通过 |
| Authenticode 证书 | 证书库无带私钥的 Code Signing 证书；自签名根写入受信任根存储被系统 UI 阻止 |
| Authenticode 既有证据 | OpenJS 签名样本验证通过、篡改样本拒绝；生产门继续阻断无证书发布 |
| UI 收口 | 无新增改动；更新窗口 4 条契约测试与前端 608 条测试保持通过 |
| 版本与产物 | 未变更；4.1.7 已安装产物保持有效 |
