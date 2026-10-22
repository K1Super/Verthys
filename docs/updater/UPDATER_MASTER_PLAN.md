# Verthys 更新系统统一方案（MASTER PLAN）

> 文档编号：VUP-001
> 状态：**唯一实施契约**（v1.0，2026-10-22）
> 适用版本：当前 `4.1.3`，目标下一个版本（示例 `4.1.4`）
> 适用平台：Windows 10/11 x64；Tauri 2.11.5 + Rust 主进程 / verthys-worker + C11 `verthys.dll` + Vue 3.5
> 服务器阶段：[UPDATER_SERVER_DEPLOYMENT_PLAN.md](UPDATER_SERVER_DEPLOYMENT_PLAN.md)
>
> Last updated: 2026-10-22 · 维护人：K1Super

---

## 0. 执行摘要

### 0.1 方案定位

本方案是 Verthys 更新系统的唯一实施契约：定义本机阶段的架构、清单协议、客户端引擎、任务分解、质量门与验收矩阵，并给出服务器阶段的衔接边界与部署方案入口。所有更新域代码、脚本、配置、测试与文档以本文为准。

### 0.2 方案规模

- 12 项架构决策（ADR-01 ~ ADR-12）。
- 16 个 P0 任务包、9 个 P1 任务包、6 个 P2 任务包。
- 20 条核心 E2E（18 条负向 / 异常路径）+ 4 条发布回归附加。
- 1 个统一清单协议（Manifest v2），同时兼容 Tauri 插件必需字段与服务器阶段扩展字段。

### 0.3 八条关键裁决

1. **本机产物不得外发**：Phase L 构建只允许内部验证；任何对外分发的构建必须使用 `production` profile，HTTPS、清单签名、Authenticode、遥测缺一不可。
2. **安全流水线下沉到 Rust**：检查、下载、哈希、PE 版本、签名单 / 密钥集校验、安装由 Rust 更新服务负责；Vue 只负责 UI 状态与用户确认，不再直接调用插件的 `download()` / `install()` 完成安全判定。
3. **签名是信任根，哈希与 PE 版本是附加闸门**：校验顺序固定为“安装包签名验真 → SHA256 / size 完整性 → PE FileVersion 身份 → 兼容判定 → 锁库 → 安装”。
4. **NSIS 不具备事务式原子替换**：不承诺“安装器原子替换”和“自动回滚”。回退按 R0 检测与指引、R1 修复入口、R2 外部看门狗三级实现，文案必须与真实能力一致。
5. **清单 v2 向前兼容 Tauri**：保留 `version`、`notes`、`pub_date`、`platforms.<target>.{signature,url}` 必需字段；新增 `schema_version`、`channel`、`min_version`、`force_below`、`rollout`、`paused`、`revoked_release_ids`、`compatibility`、`sha256`、`size`、`file_version`、`manifest_signature`。
6. **锁库闸门必须有结构化结果**：`lockAll` 返回 `LockOutcome`，安装只接受 `clean === true`；不以布尔全局或后置 `isCacheDirty()` 作为准入凭证。
7. **更新标记与健康自检是 P0**：安装前原子写入 `pending.json`，重启后消费并执行 DLL 完整性、worker ready、ABI 协商；没有标记就不存在可靠的健康判定与回退。
8. **服务器阶段 static-first**：不做动态更新 API 依赖；清单由 CI 生成并签名，静态托管到 HTTPS/CDN；控制面只负责生成和原子切换清单，降低攻击面与运维复杂度。

### 0.4 交付边界

| 交付物 | 内容 | 本机阶段是否执行 |
|---|---|---|
| `docs/updater/UPDATER_MASTER_PLAN.md` | 实施规范、架构决策、本机实施、质量门、测试矩阵 | 是（本文） |
| `docs/updater/UPDATER_SERVER_DEPLOYMENT_PLAN.md` | 服务器部署、发布流水线、灰度、灾备、Runbook | 否（达到触发条件后执行） |
| `docs/updater/README.md` | 文档入口与阅读路径 | 是 |

---

## 1. 现状基线与设计约束

### 1.1 现状基线

当前更新链路已具备插件注册、前端三段式状态、回环夹具、安装包 minisign 签名、清单生成、版本单源、worker 副本哈希门与 SBOM。以下是代码 / 产物核验得到的事实，作为方案硬约束。

| # | 事实 | 证据 | 对方案的约束 |
|---|---|---|---|
| 1 | Rust 与前端 updater 插件均为 `2.12.0` | `verthys-tauri/src-tauri/Cargo.lock:3530-3533`；`package.json` 中 `@tauri-apps/plugin-updater: 2.12.0` | 能力判断以此版本为准 |
| 2 | JS `Update` 暴露 `rawJson: Record<string, unknown>` | `@tauri-apps/plugin-updater` 类型定义 `UpdateMetadata.rawJson` | 扩展字段必须由客户端自行解析 |
| 3 | Rust `Update::download()` 在下载过程中完成安装包签名校验，并返回 `Vec<u8>` | 插件 `updater.rs`：`download` 内调用 `verify_signature`，返回字节 | 哈希 / PE 校验在 Rust 拿到字节后执行 |
| 4 | Rust `Update::install(bytes)` 只负责写入临时文件并启动安装器，不再验签 | 插件 `updater.rs`：`install_inner` 无签名校验路径 | 签名是最终信任根；安装前必须保证字节来源 |
| 5 | 签名错误只有 `Minisign` 变体，没有独立的“公钥不匹配”变体 | 插件 `error.rs` | 公钥级错误必须由 Rust 自行识别 |
| 6 | 插件配置支持 `require_signed_version` | 插件 `config.rs` | 降级阻断有插件级方案，但依赖签名 trusted comment 含版本 |
| 7 | 当前 Tauri CLI `2.11.4` 生成的签名 trusted comment 不含版本 | 解码 `build/updater/Verthys_4.1.3_x64-setup.exe.sig`，内容为 `timestamp:... file:...` | 现状 `requireSignedVersion` 不可用；需升级 CLI 或改用 PE 版本兜底 |
| 8 | 安装包 PE `FileVersion` / `ProductVersion` 为 `4.1.3` | `Get-Item build/updater/Verthys_4.1.3_x64-setup.exe` 的 VersionInfo | PE 版本身份校验可行，可阻断“清单说新装旧” |
| 9 | JS `Update.download()` 返回 `Promise<void>`，不暴露下载字节 | `@tauri-apps/plugin-updater` 类型定义 | 前端不能完成哈希 / PE 校验；必须走 Rust 服务 |
| 10 | 当前安装闸门在 `verthysReadyRef` 为假时跳过 `lockAll` | `SecurityCenter.vue:527-533` | 禁止任何跳过锁库的分支 |
| 11 | `lockAll` 对 `waitForFlush()` 异常使用空 catch | `security-session.ts:580` | 闸门不能只依赖“调用未抛错”；需要结构化结果 |
| 12 | 发布配置为回环 HTTP + 明文许可 | `tauri.conf.json:55-65` | 必须拆 profile；production 禁止 |
| 13 | 清单生成脚本只写 `version / notes / pub_date / platforms.{signature,url}` | `scripts/make_updater_manifest.mjs:100-111` | `sha256`、`size`、`compatibility` 等字段尚未落地 |
| 14 | 当前 `latest.json` 无 `sha256`、`channel`、`compatibility`、`force_update` | `build/updater/latest.json` | 现状不能支撑哈希 / 版本身份校验 |
| 15 | 本机夹具服务不处理 HTTP Range | `scripts/updater_server.mjs:145-163` 直接整文件流式返回 | 断点续传在 Phase L 不可用；P1 需服务端与客户端同时支持 |
| 16 | 无 single-instance 插件 | `verthys-tauri/src-tauri/Cargo.toml` 无 `tauri-plugin-single-instance` | 单实例预检需新增实现 |
| 17 | `CHANGELOG.md`、`docs/MIGRATION.md` 不存在；`docs/README.md` 已引用 | 文件系统核验 | 文档漂移真实存在 |
| 18 | 仅有 `core.yml`、`rust-frontend.yml` 两个工作流 | `.github/workflows/` 目录 | 无 release 工作流 |
| 19 | worker 在初始化后主动发送 `{"ok":true,"op":"ready"}` | `verthys-worker/src/runtime/main_loop.rs:136-160`；父进程 `wait_for_ready_signal` | 健康自检可复用该协议，不需要新增握手 |
| 20 | 错误文案映射表已存在，可承载 `E_UPDATER_*` | `verthys_error.ts:266` `VERTHYS_ERROR_TEXT_MAP` | 更新错误码应复用，不另起体系 |

### 1.2 设计约束

| # | 约束 | 落地 |
|---|---|---|
| C1 | 生产构建不得包含回环端点 / 明文许可 / `dangerousInsecureTransportProtocol: true` | ADR-02、§6.1 G2 |
| C2 | 检查、下载、哈希、PE、密钥集、安装由 Rust 更新服务负责；Vue 只做 UI 状态 | ADR-04、§4.1 |
| C3 | 签名是信任根；SHA256 / size / PE 版本是附加闸门；顺序不可颠倒 | ADR-06、§3.6 |
| C4 | stock NSIS 无事务语义；不承诺自动回退；按 R0 / R1 / R2 分级 | ADR-07、§4.8 |
| C5 | 清单新增字段必须有客户端执行点、错误码与测试；不得装饰 | ADR-05、§3 |
| C6 | 安装只接受 `LockOutcome.clean === true`；禁止跳过锁库 | ADR-08、§4.6 |
| C7 | 安装前写 `pending.json`；重启后先消费标记再做健康自检 | ADR-09、§4.7 |
| C8 | Authenticode 必须先于 updater minisign；`.sig` 生成后不得改 NSIS | §2.3.1 |
| C9 | Phase L 不防同账户任意写入；Phase S 通过 HTTPS / 清单签名 / 鉴权提高门槛 | §2.5 |
| C10 | 每次发布必须有 release manifest、SBOM、哈希账本、审批与回滚物料 | ADR-11、§7 |

---
## 2. 统一方案

### 2.1 目标与质量等级

更新系统的目标不是“能更新”，而是“**在不可信网络、可中断安装、可回退数据、可审计发布的前提下，可靠地更新**”。质量等级按下列可度量口径判定：

| 目标 | 度量口径 | Phase L 合格线 | Phase S 合格线 |
|---|---|---|---:|---:|
| 可信 | 安装包签名、清单签名、Authenticode 校验全部通过才允许安装 | 安装包签名 100% | 三层签名 100% |
| 可靠 | 检查 / 下载 / 校验 / 锁库 / 安装 / 自检各阶段失败均可定位并回到可用状态 | E2E 20/20（L0 门槛 14/20） | 生产成功率 ≥ 99.5% |
| 可观测 | 每个失败事件带 `phase + code + release_id + session_id` | 100% | 100% |
| 可回退 | 健康失败后用户可在 R1 修复入口回到 LKG | R1 可用 | R2 看门狗可用 |
| 可审计 | 版本、物料哈希、签名、SBOM、发布人、发布时间可追溯 | release manifest 完整 | 发布台账 + 审批 |
| 供应链 | 安装包、DLL、worker、SBOM、依赖基线哈希一致 | 构建门全绿 | 发布门全绿 |

指标公式（Phase S 由事件聚合计算，Phase L 由 E2E 日志与脚本计算）：

| 指标 | 公式 | 告警阈值 |
|---|---|---:|
| 检查成功率 | `(check_hit + check_miss) / check_sent` | < 99.5% |
| 下载成功率 | `download_success / download_start` | < 99.0% |
| 验签失败数 | `sig_invalid + manifest_sig_invalid + pubkey_mismatch` | > 0 即告警 |
| 哈希 / 版本身份失败数 | `hash_mismatch + pe_version_mismatch` | > 0 即告警 |
| 安装成功率 | `install_confirmed / install_started` | < 99.0% |
| 回滚率 | `rolled_back / install_started` | > 2% 暂停渠道；> 0.5% 观察 |
| 数据事故 | 容器不可解锁 / 记录丢失 / 损坏 | 0，红线 |
| 可诊断性 | 带阶段与错误码的失败事件 / 全部失败事件 | < 100% |

### 2.2 阶段与发布资格

**任何构建产物必须带 profile 标签。** `local` profile 只允许内部验证，不得外发；`production` profile 才允许对外分发。该规则由构建脚本与 CI 双重强制。

| 阶段 | 名称 | 分发范围 | 入口条件 | 退出条件 |
|---|---|---|---|---|
| L0 | 本机可信基线 | 本机 / 内部测试机 | 当前 4.1.3 基线；方案批准 | 16 个 P0 任务完成；G0 ~ G7 全绿；E2E 14/20（正向 + 核心负向） |
| L1 | 本机可靠回退 | 内部测试机 | L0 退出 | R1 修复入口 + LKG + Range 续传 + 单实例；E2E 20/20 |
| S0 | 服务器预发 | 内部 / 试点 | L0 + 客户端 readiness；SERVER PLAN §2 | staging E2E、负载、回滚、密钥演练全通过 |
| S1 | 服务器生产 | 外部分发 | S0 退出；Authenticode、清单签名、遥测、审批就绪 | 灰度 1% → 10% → 50% → 100% 阶段门全通过 |
| E | 企业规模 | 企业 / 大规模 | S1 稳定 | MSI / GPO / Intune、看门狗、多区域 |

能力归属表：

| 能力 | 本方案决策 | 阶段 | 说明 |
|---|---|---|---|
| 回环 HTTP 夹具 | 仅 `local` profile | L0 | 用于本机端到端验证，不进入发布配置 |
| HTTPS 分发 | 外部分发必需 | S1 | TLS 1.2+、HSTS、证书自动续期 |
| `dangerousInsecureTransportProtocol` | 仅 `local` profile；production 硬禁 | L0 / S1 | CI 对 production 出现该键即失败 |
| 清单独立签名 | 客户端现在支持；production 强制 | L0（能力）/ S1（强制） | JCS + minisign |
| Authenticode | 外部分发必需；本机可后置 | S1 | OS 信任与 SmartScreen |
| SHA256 / size | Rust 准备阶段强制执行 | L0 | 对同一份下载字节校验 |
| PE FileVersion | 强制执行 | L0 | 阻断“清单说新装旧” |
| `min_version` | 字段现在定义；强制链 Phase S | L0（字段）/ S1（执行） | 低于该版本需桥接 |
| 渠道 / 灰度 | 服务器阶段必需；客户端现在预留 | S1 | 端点 + `rollout` bucket |
| 遥测 | Phase L 本地 JSONL；S1 聚合 | L0（本地）/ S1（聚合） | 字段白名单、可关闭 |
| 自动回退 | R0 / R1 / R2 分级；不虚假承诺 | L0 / L1 / R2 | 文案与真实能力一致 |
| Release 工作流 | L1 本地脚本，S1 CI 发布 | L1 / S1 | 物料账本、SBOM、审批 |
| 审批 / 分岗 | S1 前至少双人复核 | S1 | 构建 / 测试 / 安全 / 授权 |
| 企业 MSI / GPO | E 阶段 | E | per-machine / Intune |

### 2.3 架构决策记录（ADR）

#### ADR-01 文档单一权威

- **决策**：`docs/updater/UPDATER_MASTER_PLAN.md` 是更新域唯一实施契约。
- **理由**：更新域只能有一个事实源；并存的口径会导致实现分叉。
- **影响**：任何更新域变更必须同 PR 更新本文与 `CONFIGURATION.md`；不得引用与本文冲突的口径。

#### ADR-02 构建 profile 与端点注入

- **决策**：引入 `local` / `production` 两个构建 profile。`local` 允许回环 HTTP 与明文许可；`production` 强制 HTTPS、禁止回环 / localhost / 明文许可。端点、渠道、清单签名开关由构建期配置注入，不写死在基础 `tauri.conf.json`。
- **理由**：开发便利配置与发布配置共用一份文件，导致回环端点与明文许可可能随发布流出。
- **影响**：`build_production.ps1` 增加 `-Profile`；CI 对 production 配置做硬校验；local 产物文件名 / 元数据带 `local` 标记，禁止上传服务器。

#### ADR-03 三层信任根职责分离

- **决策**：安装包 minisign 签名负责“安装包字节来自发布者”；清单签名负责“版本 / 兼容 / 下载元数据未被篡改”；Authenticode 负责“Windows 系统信任与 SmartScreen 声誉”。三者独立存放、独立轮换、独立吊销。
- **理由**：三层签名职责不同；把清单签名当成唯一降级阻断会导致职责过载，Authenticode 缺失会让外部分发出现未知发布者。
- **影响**：Phase L 只强制安装包签名；Phase S 强制三层。密钥矩阵写入 `SECURITY_DESIGN.md`。

#### ADR-04 Rust 更新服务拥有安全流水线

- **决策**：新增 Rust `updater_service`，提供 `updater_check`、`updater_prepare`、`updater_confirm_lock`、`updater_install`、`updater_cancel`、`updater_startup_state`、`updater_export_logs`。Vue 只维护 UI 状态与用户确认，不再直接调用 `download()` / `install()` 完成安全判定。
- **理由**：哈希、PE 与密钥集校验需要下载字节；JS API 不提供字节，也不提供公钥级错误。
- **影响**：`useAppUpdater` 改为调用 IPC；现有 7 条单测迁移为 Rust 命令 + Vue 状态两层测试；`updater:default` 权限可移除（若不再使用 JS 插件命令）。

#### ADR-05 清单 v2 向前兼容 Tauri

- **决策**：保留 Tauri 必需字段，新增字段全部为附加字段；`notes` 保持字符串以兼容插件 `body`；新增 `schema_version`、`channel`、`min_version`、`force_below`、`rollout`、`compatibility`、`platforms.*.sha256/size/file_version`、`manifest_signature`。
- **理由**：扩展字段必须由客户端执行；不能为了扩展字段破坏插件解析。
- **影响**：清单生成脚本与 Rust 解析器同步升级；契约测试覆盖“旧客户端忽略新字段、新客户端校验新字段”。

#### ADR-06 校验顺序与语义

- **决策**：固定顺序为：
  1. 传输层（HTTPS / local profile）；
  2. 清单签名（production）；
  3. 清单 schema / 渠道 / 版本；
  4. 兼容区间 / `min_version` / `force_below` / rollout；
  5. 下载；
  6. 安装包签名（插件 + Rust 密钥集复验）；
  7. SHA256 / size；
  8. PE `FileVersion`；
  9. Authenticode（production）；
  10. 锁库闸门；
  11. 安装；
  12. 启动健康自检。
- **理由**：签名是信任根；哈希与 PE 版本是附加闸门；插件边界决定校验顺序。
- **影响**：I2 定义为“签名验真后再做哈希 / 版本身份校验”；`E_UPDATER_HASH_MISMATCH` 与 `E_UPDATER_PE_VERSION_MISMATCH` 分离。

#### ADR-07 回退分级

- **决策**：R0 = 检测 + 明确文案 + 日志导出；R1 = 客户端保留 LKG / 上一安装包 + “修复 / 回退”入口，需用户确认；R2 = 独立 `VerthysUpdater` 看门狗 / 修复工具，能在主程序无法启动时执行回退。Phase L 做 R0，Phase L1 做 R1，Phase S 做 R2。
- **理由**：stock NSIS 无事务语义，客户端也没有 LKG；自动回退不能凭空承诺。
- **影响**：所有 UI 文案与错误码必须对应真实层级；`RolledBack` 只表示“已检测并进入可修复状态”，不表示“已自动恢复旧二进制”。

#### ADR-08 锁库闸门结构化契约

- **决策**：`lockAll` 返回 `LockOutcome`：`{ clean: boolean, flushed: boolean, dirty: boolean, errors: string[], durationMs: number }`。安装只接受 `clean === true`。未解锁 / 未就绪时优先统一调用 `lockAll`；仅当产品确认其不可调用时，才允许受控空锁库路径，仍然要求 `clean === true`。
- **理由**：`lockAll` 吞掉落盘异常与布尔全局不足以证明数据已落盘；跳过路径必须关闭。
- **影响**：`security-session.ts` 修改返回类型；`SecurityCenter.vue` 消费结构化结果；Rust `updater_confirm_lock` 记录闸门证据。

#### ADR-09 更新标记与健康自检

- **决策**：安装前原子写入 `%APPDATA%/Verthys/updater/pending.json`（临时文件 + fsync + rename），包含 `schema_version`、`from_version`、`to_version`、`release_id`、`installer_sha256`、`lkg_path`、`lkg_sha256`、`created_at`、`nonce`。启动后读取并归档；健康自检复用 `worker_init` / `wait_for_ready_signal` / ABI 协商，不触发容器解锁。
- **理由**：没有标记就无法区分“正常启动”和“更新后启动”；健康自检与回退需要可靠入口。
- **影响**：Rust `updater_startup_state` 成为启动早期入口；健康失败写 `rolledback` 结果并进入 R1 修复提示。

#### ADR-10 事件与日志 schema

- **决策**：定义事件 schema v1，JSONL 一行一事件；字段白名单 + 关联 ID；本地日志按日 / 5 MB 滚动，保留 7 天；导出走 Rust 命令，复用 `dialog:allow-save`。
- **理由**：质量指标必须可计算；日志是 Phase L 唯一的观测面。
- **影响**：`logger.ts` 扩展或新增 `updater-log.ts`；事件集与错误码绑定；静态扫描禁止敏感字段。

#### ADR-11 发布工程与物料账本

- **决策**：每次发布生成 `release-manifest.json`，绑定安装包 SHA256、`.sig` SHA256、SBOM SHA256、Git tag、构建 profile、签名证书指纹、构建时间、发布人；SBOM 与安装包同目录归档；发布前通过质量门。
- **理由**：没有物料账本就无法证明“发布的包就是构建的包”；服务器阶段需要可审计物料。
- **影响**：`build_production.ps1` 增加物料登记；Phase L 本地归档，Phase S 上传并签审。

#### ADR-12 服务器阶段 static-first

- **决策**：服务器不承担动态更新决策；清单由 CI 生成并签名，静态托管到 HTTPS/CDN；渠道通过独立路径 / 独立清单；灰度通过清单 `rollout` 字段由客户端计算 bucket；暂停 / 撤回通过重新发布清单或 `revoked_release_ids` 实现。
- **理由**：动态 API 会增加鉴权、缓存、可用性与攻击面；本项目的发布频率与团队规模不需要。
- **影响**：SERVER PLAN 以 Nginx / 对象存储 + CDN 为主；控制面可选，且只写静态清单。

#### 签名顺序（硬约束）

签名顺序错误会直接导致更新包验签失败，必须按下列顺序：

```text
1. C 核心构建 + .vsec 完整性基准注入
2. Authenticode 签 verthys.dll / verthys-worker / Verthys.exe（打包前，签实际被打包的副本）
3. Tauri 打包 NSIS；通过 bundle.windows.signCommand / certificateThumbprint 让 bundler
   在生成安装包后立即 Authenticode 签名（或手工签名后重新生成 updater 产物）
4. updater minisign 对最终 NSIS 字节签名，生成 .sig
5. 生成 Manifest v2；对清单做 JCS + minisign 签名
6. 生成 release manifest / SBOM / 校验清单
```

铁律：

- `.sig` 覆盖最终 NSIS 字节；**任何在 `.sig` 生成后修改 NSIS 的动作都会使签名失效**。
- 禁止“先 minisign 再 Authenticode NSIS”；如果只能手工后签 NSIS，必须删除旧 `.sig`，重新用 minisign 签最终字节，并重新生成清单。
- Tauri `signCommand` 只负责它识别的二进制；DLL / worker 仍需 `beforeBundleCommand` 或构建脚本单独签名。
- 签完的 DLL / worker / 主程序不得再被替换或改写；构建脚本应在签名后计算哈希并锁定。
- **哈希时序**：worker 副本哈希漂移门在签名前执行；Authenticode 后必须重新计算最终（已签名）DLL / worker / 主程序哈希，release manifest 以最终哈希为准；不得把签名前哈希当作发布哈希。

### 2.4 总体架构

```text
┌──────────────────────────────────────────────────────────────────────┐
│ ① 构建发布面                                                         │
│  VERSION 单源 → sync_version → 质量门 → 全量构建 → Authenticode       │
│  → updater minisign 签名 → Manifest v2 → 清单签名 → release manifest  │
│  → SBOM 绑定 → 归档 / 上传                                            │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ 制品 + 清单 + 签名 + SBOM + 物料账本
┌───────────────────────────────▼──────────────────────────────────────┐
│ ② 分发面                                                             │
│  Phase L：127.0.0.1:8765 夹具（仅 local profile）                     │
│  Phase S：HTTPS 静态 / CDN，stable / beta / internal 渠道，灰度 / 暂停 │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ HTTPS 清单 + 安装包 + 签名
┌───────────────────────────────▼──────────────────────────────────────┐
│ ③ 客户端面（Rust updater_service + Vue UI）                          │
│  check → prepare（签名 / 哈希 / PE / 兼容）→ 预检 → 锁库 → install    │
│  → 重启 → pending marker → HealthCheck → Confirmed / RolledBack       │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ 脱敏事件 / 本地 JSONL
┌───────────────────────────────▼──────────────────────────────────────┐
│ ④ 观测治理面                                                         │
│  Phase L：本地日志 + 导出 + E2E 证据                                  │
│  Phase S：事件聚合 + 大盘 + 告警 + 发布审计 + 回滚演练                 │
└──────────────────────────────────────────────────────────────────────┘

信任根（纵向）：
  minisign 安装包密钥（离线 / HSM）
  清单签名密钥（离线 / HSM，Phase S 强制）
  Authenticode 证书（EV/OV + 时间戳，Phase S 强制）
  客户端内置：安装包公钥集、清单公钥集、Authenticode 系统信任链
```

组件职责：

| 组件 | 职责 | 不负责 |
|---|---|---|
| `build_production.ps1` | profile 选择、构建、签名注入、产物校验 | 发布决策 |
| `make_updater_manifest.mjs` | Manifest v2 生成、哈希计算、schema 校验 | 下载 / 安装 |
| `release_manifest` 脚本 | 物料账本、SBOM 绑定、归档 | 客户端逻辑 |
| `updater_service`（Rust） | 检查、下载、验签、哈希、PE、兼容、安装、标记、健康状态 | UI 展示、业务会话 |
| `useAppUpdater`（Vue） | 状态机、进度、用户确认、错误文案 | 安全判定 |
| `lockAll` / cache 层 | 落盘、脏数据、密钥缓存清理 | 更新网络 |
| 安装器（NSIS） | 替换程序文件、重启 | 回滚、数据迁移 |
| 日志 / 事件 | 阶段、错误码、耗时、脱敏导出 | 采集密钥 / 业务数据 |

### 2.4.1 不变量（硬约束）

| # | 不变量 | 执行点 |
|---|---|---|
| I1 | **只升不降**：目标版本必须严格高于当前版本；`allowDowngrades=false` 保持；PE 版本不得低于当前版本 | 清单版本比较 + PE 校验 + 插件配置 |
| I2 | **签名是信任根**：安装包签名必须通过插件与 Rust 密钥集双重验证；production 清单签名必须通过 | `updater_prepare` |
| I3 | **未锁库不落安装器**：只有 `LockOutcome.clean === true` 才允许安装；未就绪也不得跳过 | `lockAll` + `updater_confirm_lock` + `updater_install` |
| I4 | **私钥不进仓库**：私钥 / 口令不得出现在 Git、安装包、日志、SBOM、构建缓存 | 构建 / 签名 / 日志 |
| I5 | **夹具仅回环**：`updater_server.mjs` 只绑定 `127.0.0.1`；production 只允许 HTTPS | 配置门 + 代码审查 |
| I6 | **日志脱敏**：不记录密钥、口令、容器路径全名、记录标题 / 内容、完整设备指纹、完整哈希 | 日志模块 + 静态扫描 |
| I7 | **失败不破坏旧版与容器数据**：预检 / 下载 / 校验 / 锁库失败，旧版与已解锁会话保持可用 | 状态机 + 闸门 |
| I8 | **数据目录不在替换范围**：安装器只替换程序目录；容器与用户数据不被更新流程读写 / 移动 / 删除 | NSIS 配置 + 代码审查 |
| I9 | **未准备不安装**：只有签名、SHA256、size、PE 版本、兼容全部通过的 prepared 字节才可安装 | `updater_prepare` + `updater_install` |
| I10 | **单飞与幂等**：同一时间只有一个更新会话；同一 `release_id` 只安装一次；不并发启动安装器 | Rust 会话状态 |
| I11 | **标记先于安装**：`pending.json` 必须在安装器启动前原子落盘；重启后必须先消费标记再判定健康 | `updater_install` + 启动流程 |
| I12 | **字段必须执行**：清单新增字段必须有客户端执行点、错误码、测试；不得存在“写了没人读”的字段 | 清单解析 + 契约测试 |

### 2.5 威胁模型与边界

| 威胁 | Phase L 控制 | Phase S 控制 | 残余风险 |
|---|---|---|---|
| 网络中间人替换清单 | 仅回环；安装包签名 | HTTPS + 清单签名 + 安装包签名 | 本机同账户进程可监听回环（Phase L 接受） |
| 替换安装包 | minisign + SHA256 + PE 版本 | 同上 + Authenticode | 私钥泄露（由密钥治理覆盖） |
| 篡改清单指向旧包 | 版本比较 + PE FileVersion | 清单签名 + `requireSignedVersion` + PE | 旧 CLI 无版本签名时依赖 PE 兜底 |
| 降级 / 重放 | `allowDowngrades=false` + 版本严格比较 + PE | 同上 + 渠道清单 + `revoked_release_ids` | 用户手动安装旧包不在防护范围 |
| 安装中断 / 断电 | pending marker + R0/R1 修复 | 同上 + R2 看门狗 | stock NSIS 非事务；半安装状态需修复 |
| 磁盘空间不足 | 预检 | 预检 + 服务端提示 | 预检后空间被其他进程占用 |
| 并发实例 | 单实例 / 互斥量 | 同上 | 强制终止进程可能绕过 |
| 私钥泄露 | 仓库外、离线备份 | HSM / 双人控制 / 轮换 | 轮换过渡期旧客户端 |
| 日志泄露 | 字段白名单 + 导出脱敏 | 同 + 传输加密 + 保留期 | 用户主动导出到不安全位置 |
| 供应链投毒 | vendor 哈希 + SBOM + 锁定依赖 | 同 + 来源证明 + 审批 | 构建机被攻陷 |
| CDN / 缓存投毒 | 不适用 | 不可变路径 + 清单签名 + 短 TTL + 刷新 | 边缘节点故障 |
| 遥测隐私 | 不采集 | 白名单 + 可关闭 + 保留期 | 聚合统计的再识别风险 |

**Phase L 安全边界必须明确写出**：本机阶段防的是网络、其他账户、损坏、误替换；**不防同账户任意写入**。同账户攻击者可以改清单、替换安装包、注入进程；安装包签名只能保证“不是发布者签的包不被安装”，不能保证“本机物料目录未被同账户篡改”。Phase S 通过 HTTPS、清单签名、鉴权与审计提高门槛，但仍不防已控制用户账户的攻击者。

### 2.6 与 Tauri 插件的能力边界

| 能力 | 插件是否提供 | 本方案由谁执行 | 说明 |
|---|---|---|---|
| 拉取清单 | 是 | 插件（Rust `UpdaterExt::check`） | 支持 HTTPS、target、headers、timeout、proxy |
| 选择平台 target | 是 | 插件 | Windows NSIS 优先 `windows-x86_64-nsis` |
| 暴露原始 JSON | 是 | 插件 → Rust | `Update.raw_json` / JS `rawJson` |
| 下载安装包 | 是 | 插件 | Rust 返回字节；JS 返回 void |
| 安装包签名校验 | 是 | 插件 + Rust 复验 | 插件验主公钥；Rust 用密钥集复验并识别 key id |
| SHA256 / size | 否 | Rust | 对插件返回的字节计算 |
| PE FileVersion | 否 | Rust | 解析 PE 版本资源 |
| 清单签名 | 否 | Rust | 对 `raw_json` 去掉 `manifest_signature` 后做 JCS 规范化并验签 |
| 兼容区间 | 否 | Rust | 读清单字段并与当前 ABI / 容器 / OS 比对 |
| 渠道 / 灰度 | 否 | Rust | 端点选择 + rollout bucket |
| 锁库闸门 | 否 | Vue + Rust | `lockAll` 结果 + `updater_confirm_lock` |
| 安装 | 是 | 插件 | `install(bytes)`；Windows 启动 NSIS `/UPDATE` |
| 原子替换 | 否 | — | stock NSIS 无事务保证；R1/R2 修复 |
| 自动回退 | 否 | R1 / R2 | 客户端 LKG / 看门狗 |
| 遥测 | 否 | Rust 日志 / 服务端 | JSONL + 事件上报 |
| 失败分类 | 部分 | Rust | 插件错误面不足以区分公钥 / 哈希 / PE |

---

## 3. 清单协议（Manifest v2）

### 3.1 设计原则

1. **Tauri 兼容优先**：`version`、`notes`、`pub_date`、`platforms.<target>.{signature,url}` 必须保持 Tauri 插件可解析；新增字段全部为附加字段。
2. **语义可执行**：每个新增字段都必须有明确的客户端执行点、失败错误码与测试；不允许“写了但没人读”。
3. **签名单文件化**：清单签名内嵌在清单中，避免 `latest.json` 与 `.sig` 两个文件在发布 / 缓存时出现配对窗口。
4. **规范化可验证**：签名覆盖“去掉 `manifest_signature` 后的 JCS 规范化 JSON”，客户端可对 `raw_json` 重新规范化后验签，不依赖原始字节的空白 / 键序。
5. **向前兼容**：旧客户端忽略新字段；新客户端对未知 `schema_version` 采取 fail-closed（生产）或明确降级（本地）。

### 3.2 字段 schema

| 字段 | 类型 | 必填 | 校验规则 | 执行点 |
|---|---|---|---|---|
| `schema_version` | number | 是 | 当前为 `2`；大于客户端支持上限 → 生产拒绝 | Rust `manifest.rs` |
| `release_id` | string | 是 | `YYYYMMDD-HHMMSS-<semver>-<gitsha8>`；全局唯一 | Rust / 日志 / 发布台账 |
| `version` | string | 是 | SemVer `MAJOR.MINOR.PATCH`，无 `v` 前缀、无 `+build` | Rust / 插件 |
| `channel` | string | 是 | `local` / `internal` / `beta` / `stable`；必须与请求端点一致 | Rust |
| `pub_date` | string | 是 | RFC 3339 UTC；Tauri 必需 | Rust / 插件 |
| `notes` | string | 是 | 纯文本；Tauri 必需；禁止 HTML / 脚本 | Rust / UI |
| `notes_sections` | array | 否 | `[{ type: "security" \| "changed" \| "fixed" \| "added", items: string[] }]` | UI 展示；缺失时回退 `notes` |
| `min_version` | string | 否 | SemVer；低于该版本的客户端必须先安装桥接版本 | Rust |
| `force_below` | string | 否 | SemVer；低于该版本的客户端不得推迟安装 | Rust / UI |
| `rollout` | object | 否 | `{ percentage: 0-100, salt: string }`；缺省 100 | Rust |
| `paused` | boolean | 否 | `true` 时客户端视为“无可用更新” | Rust |
| `revoked_release_ids` | array | 否 | 已撤回的 `release_id` 列表；命中即拒绝安装 | Rust |
| `compatibility` | object | 生产必填 | `{ abi: {min,max}, container: {min,max}, os: {min}, webview2: {min} }` | Rust |
| `platforms` | object | 是 | 至少一个 target；Windows 同时写 `windows-x86_64` 与 `windows-x86_64-nsis` | Rust / 插件 |
| `platforms.<target>.url` | string | 是 | `https`（production）或 `http`（local profile）；production 必须与清单同源或白名单域名 | Rust / 插件 |
| `platforms.<target>.signature` | string | 是 | base64 minisign；安装包签名 | 插件 + Rust |
| `platforms.<target>.sha256` | string | 是 | 64 位小写十六进制 | Rust |
| `platforms.<target>.size` | number | 是 | 正整数，必须等于实际字节数 | Rust |
| `platforms.<target>.file_version` | string | 是 | 归一化 SemVer；必须等于安装包 PE `FileVersion` | Rust |
| `platforms.<target>.authenticode` | object | 生产必填 | `{ required: true, subject: string, sha256: string }` | Rust（Phase S） |
| `manifest_signature` | object | 生产必填 | `{ alg: "minisign", key_id: string, signature: base64 }` | Rust |

### 3.3 清单示例

```json
{
  "schema_version": 2,
  "release_id": "20261022-090000-4.1.4-a1b2c3d4",
  "version": "4.1.4",
  "channel": "local",
  "pub_date": "2026-10-22T09:00:00.000Z",
  "notes": "本机更新验证：修复若干问题。",
  "notes_sections": [
    { "type": "fixed", "items": ["修复 worker 就绪竞态"] },
    { "type": "security", "items": ["加强安装包版本身份校验"] }
  ],
  "min_version": "4.1.0",
  "force_below": "4.0.0",
  "rollout": { "percentage": 100, "salt": "local" },
  "paused": false,
  "revoked_release_ids": [],
  "compatibility": {
    "abi": { "min": "0x000B", "max": "0x000B" },
    "container": { "min": 3, "max": 3 },
    "os": { "min": "10.0.17763" },
    "webview2": { "min": "120.0.0" }
  },
  "platforms": {
    "windows-x86_64": {
      "url": "http://127.0.0.1:8765/Verthys_4.1.4_x64-setup.exe",
      "signature": "<base64 minisign signature>",
      "sha256": "<64 位小写十六进制>",
      "size": 4865173,
      "file_version": "4.1.4",
      "authenticode": { "required": false, "subject": "", "sha256": "" }
    },
    "windows-x86_64-nsis": {
      "url": "http://127.0.0.1:8765/Verthys_4.1.4_x64-setup.exe",
      "signature": "<base64 minisign signature>",
      "sha256": "<64 位小写十六进制>",
      "size": 4865173,
      "file_version": "4.1.4",
      "authenticode": { "required": false, "subject": "", "sha256": "" }
    }
  },
  "manifest_signature": {
    "alg": "minisign",
    "key_id": "<key id>",
    "signature": "<base64 minisign signature over JCS(manifest without manifest_signature)>"
  }
}
```

> 示例中的 URL、哈希、字节数、签名、key id 仅为格式示意；实际值必须由脚本计算 / 签名写入，禁止手工填写。Phase L 的 `manifest_signature` 允许为空；Phase S 强制。

### 3.4 版本字段语义

| 字段 | 语义 | 客户端行为 |
|---|---|---|
| `version` | 本次发布的目标版本 | 必须严格高于当前版本；相等 → 无更新；更低 → `E_UPDATER_VERSION_BLOCKED` |
| `min_version` | 安装本版本前必须达到的最低版本 | 当前版本低于此值 → `E_UPDATER_BRIDGE_REQUIRED`，提示先安装桥接版本 |
| `force_below` | 强制升级线 | 当前版本低于此值 → 更新不可推迟；UI 只提供“立即更新” |
| `rollout.percentage` | 灰度比例 | 客户端用 `SHA256(install_id + ":" + salt) mod 10000` 计算 bucket；`bucket >= percentage * 100` → 无更新 |
| `paused` | 渠道暂停 | `true` → 无更新；已下载未安装的会话在安装前重新检查时放弃 |
| `revoked_release_ids` | 撤回列表 | 命中 → `E_UPDATER_INSTALL_REVOKED`，清理已准备字节 |

**`min_version` 与 `force_below` 不得混用**：前者解决“跨不兼容版本需要桥接”，后者解决“安全修复必须尽快安装”。两者可以同时存在，但判定顺序固定为 `min_version` → `force_below`。

### 3.5 清单签名

1. **规范化**：删除 `manifest_signature` 字段，对剩余对象使用 JCS（RFC 8785）序列化为 UTF-8 字节。JCS 保证键序、数字、字符串转义的确定性。
2. **签名**：使用 minisign 私钥对规范化字节签名；`manifest_signature.signature` 存放 `.sig` 文件内容的 base64；`key_id` 存放公钥 key id。
3. **验签**：客户端从 `raw_json` 删除 `manifest_signature`，JCS 规范化，使用内置清单公钥集验签；未知 `key_id` → `E_UPDATER_MANIFEST_SIG_INVALID`。
4. **密钥集**：客户端内置 `trusted_manifest_keys: [{ key_id, public_key }]`；轮换时新旧公钥并行，至少保留一个版本周期。
5. **Phase L**：`local` profile 可以没有 `manifest_signature`；但 Rust 解析器必须实现验签路径，用测试密钥完成契约测试，确保 Phase S 打开开关即可用。
6. **禁止**：清单签名私钥不得进入仓库、安装包、日志、构建缓存；签名动作在受控构建机 / HSM 执行。
7. **重复键**：清单不得包含重复 JSON 键；生成与验签前必须拒绝重复键，避免不同解析器取不同值。

### 3.6 客户端判定顺序

严格按下列顺序执行；前序失败即终止，不进入后续阶段。

| 步 | 检查 | 失败错误码 | 备注 |
|---:|---|---|---|
| 1 | 传输协议 / 主机白名单 | `E_UPDATER_NETWORK` / `E_UPDATER_MANIFEST_INVALID` | production 仅 HTTPS；local 仅回环 |
| 2 | 清单 `manifest_signature` | `E_UPDATER_MANIFEST_SIG_INVALID` | production 必验；local 可跳过 |
| 3 | `schema_version` / 必填 / 类型 / 长度 | `E_UPDATER_MANIFEST_INVALID` | 未知高版本 fail-closed |
| 4 | `channel` 与请求渠道一致 | `E_UPDATER_CHANNEL_MISMATCH` | 防止 stable 端点返回 beta 清单 |
| 5 | `paused` / `revoked_release_ids` | 无更新 / `E_UPDATER_INSTALL_REVOKED` | 撤回优先于版本比较 |
| 6 | `version` 与当前版本 | `E_UPDATER_VERSION_BLOCKED` | 严格大于 |
| 7 | `min_version` | `E_UPDATER_BRIDGE_REQUIRED` | 需要桥接版本 |
| 8 | `compatibility`（ABI / 容器 / OS / WebView2） | `E_UPDATER_COMPAT_BLOCKED` | 不接受“未知即通过” |
| 9 | `rollout` bucket | 无更新 | 未命中不报错 |
| 10 | `platforms` target 选择 | `E_UPDATER_MANIFEST_INVALID` | NSIS 优先 |
| 11 | `url` 同源 / 白名单 | `E_UPDATER_MANIFEST_INVALID` | production 禁止跨域任意主机 |
| 12 | 预检：空间 / 单实例 / 目录可写 / 网络 | `E_UPDATER_PRECHECK_*` / `E_UPDATER_NETWORK` | 见 §4.5；在下载前拦截 |
| 13 | 下载 | `E_UPDATER_NETWORK` | 超时 / 重试 |
| 14 | 安装包签名（插件） | `E_UPDATER_SIG_INVALID` | 插件主公钥 |
| 15 | 安装包签名（Rust 密钥集复验） | `E_UPDATER_SIG_INVALID` / `E_UPDATER_SIG_PUBKEY_MISMATCH` | 识别 key id |
| 16 | `sha256` / `size` | `E_UPDATER_HASH_MISMATCH` / `E_UPDATER_SIZE_MISMATCH` | 对同一份字节 |
| 17 | `file_version` / PE `FileVersion` | `E_UPDATER_PE_VERSION_MISMATCH` | 阻断“清单说新装旧” |
| 18 | Authenticode（production） | `E_UPDATER_AUTHENTICODE_INVALID` | `WinVerifyTrust` + 证书主体 / 指纹 |
| 19 | 锁库闸门 | `E_UPDATER_LOCK_*` | 见 §4.6 |
| 20 | 安装 | `E_UPDATER_INSTALL_FAILED` | 安装器接管 |
| 21 | 启动健康自检 | `E_UPDATER_HEALTH_FAIL` | 见 §4.7 |

### 3.7 发布与缓存

1. **不可变物料路径**：`/releases/<release_id>/artifacts/Verthys_<version>_x64-setup.exe`；同一路径永不覆盖。
2. **清单路径**：`/<channel>/latest.json`；每次发布生成新文件，原子替换。
3. **缓存头**：清单 `Cache-Control: no-store` 或 `max-age=30, must-revalidate`；安装包 `public, max-age=31536000, immutable`。
4. **ETag**：清单与安装包都提供 ETag；客户端可选 `If-None-Match`，但不得依赖它做安全判定。
5. **CDN**：清单路径绕过边缘缓存或发布后 purge；安装包走边缘缓存。
6. **原子性**：单文件清单内嵌签名，避免清单 / 签名配对窗口；服务器侧用原子 rename / symlink swap。
7. **回滚**：保留最近 N 个 release 与 manifest 控制版本；回滚 = 把渠道指针指回上一份已签名清单（上一 `manifest_revision`），或重新发布上一版本；不得删除仍被清单引用的物料。

### 3.8 负向契约用例

| # | 构造 | 期望 |
|---|---|---|
| M-01 | 修改 `version` 但不重签 | 清单验签失败 |
| M-02 | 修改 `platforms.*.url` 但不重签 | 清单验签失败 |
| M-03 | 用旧版本清单回指旧包 | 版本比较 / PE 版本拒绝 |
| M-04 | 清单 `version` 调高、`url` 指向旧签名包 | PE `FileVersion` 不匹配 → 拒绝 |
| M-05 | 替换安装包但保留原 `.sig` | 安装包验签失败 |
| M-06 | 替换 `.sig` 为其他合法密钥签名 | key id 未知 → `SIG_PUBKEY_MISMATCH` |
| M-07 | 修改 `sha256` 但不重签 | 清单验签失败（production）；local 哈希失败 |
| M-08 | 清单 `schema_version = 3` | 生产 fail-closed |
| M-09 | `channel` 不匹配 | `CHANNEL_MISMATCH` |
| M-10 | `paused = true` | 无更新，不下载 |
| M-11 | `revoked_release_ids` 命中 | `INSTALL_REVOKED`，清理准备字节 |
| M-12 | `min_version` 高于当前 | `BRIDGE_REQUIRED` |
| M-13 | `compatibility` ABI 不匹配 | `COMPAT_BLOCKED` |
| M-14 | `file_version` 缺失 | `PE_VERSION_MISMATCH`（生产 fail-closed） |
| M-15 | `manifest_signature.key_id` 未知 | `MANIFEST_SIG_INVALID` |

---

## 4. 客户端更新引擎

### 4.1 Rust 更新服务

新增模块 `verthys-tauri/src-tauri/src/updater/`：

```text
updater/
├── mod.rs          # 命令注册、状态导出
├── service.rs      # UpdateSession、check / prepare / install 编排
├── manifest.rs     # Manifest v2 解析、schema 校验、JCS 验签
├── verify.rs       # minisign 密钥集复验、key id 识别
├── pe.rs           # PE FileVersion / ProductVersion 解析
├── marker.rs       # pending.json 原子写 / 读 / 归档
├── gate.rs         # LockOutcome 校验、安装授权状态
└── log.rs          # 事件 schema、JSONL、脱敏、导出
```

Tauri 命令：

| 命令 | 输入 | 输出 | 约束 |
|---|---|---|---|
| `updater_check` | `channel?: string` | `UpdateCheckResult` | 单飞；30 s 超时；返回 `release_id` / `raw_json` / 兼容判定 |
| `updater_prepare` | `update_id`, `on_event: Channel` | `PreparedUpdate` | 下载 + 插件验签 + 密钥集复验 + 哈希 + size + PE + Authenticode（S） |
| `updater_confirm_lock` | `LockOutcome` | `()` | 只接受 `clean === true`；记录闸门证据 |
| `updater_install` | `update_id` | `()` | 校验 prepared / gate / PE 复检；写 marker 后调用 `install(bytes)` |
| `updater_cancel` | `update_id` | `()` | 清理 prepared 字节、关闭句柄、记录取消 |
| `updater_startup_state` | — | `StartupState` | 启动早期调用；返回 pending / health 结果 |
| `updater_ack_startup` | `StartupAck` | `()` | 归档 marker、记录用户确认 |
| `updater_export_logs` | `target_path` | `ExportResult` | 脱敏导出；复用 `dialog:allow-save` |

安全职责：

- **Rust 是安全判定的唯一权威**：清单验签、安装包复验、哈希、PE、兼容、闸门、marker 均在 Rust。
- **Vue 是 UI 状态机**：展示、用户确认、错误文案；不得绕过 Rust 直接调用插件安装。
- **单飞**：`Mutex<Option<UpdateSession>>`；`check` / `prepare` / `install` 并发请求返回 `E_UPDATER_INTERNAL`，不排队。
- **字节生命周期**：`prepare` 成功后字节保存在 Rust 内存；`install` 消费后释放；`cancel` / 失败 / 退出时清零并清理。
- **大小上限**：安装包超过 512 MB 直接拒绝（`E_UPDATER_MANIFEST_INVALID`），避免内存耗尽。

### 4.2 用户可见状态机

| 状态 | 含义 | UI | 允许动作 |
|---|---|---|---|
| `Idle` | 空闲 | 检查更新 | 手动 / 静默检查 |
| `Checking` | 拉取并校验清单 | 检查中，禁用重复触发 | 取消 |
| `Available` | 发现可用版本 | 版本、说明、安装按钮 | 安装 / 稍后 |
| `Precheck` | 预检执行中 | 预检提示 | 等待 / 取消 |
| `Downloading` | 下载 + 插件验签 | 进度条 | 取消（P1） |
| `Verifying` | 哈希 / size / PE / Authenticode | 校验提示 | 等待 |
| `ReadyToInstall` | 已准备，待锁库 | 安装确认 | 安装 / 取消 |
| `Locking` | `lockAll` + 脏数据 + 密钥清理 | 落盘进度，禁止退出 / 切模块 | 等待 |
| `Installing` | 安装器接管 | 即将重启 | 无 |
| `Restarting` | 进程退出，等待新进程 | 过渡 | 无 |
| `HealthCheck` | 新进程自检 | 自检提示 | 等待 |
| `Confirmed` | 自检通过 | 成功提示，回 Idle | 查看日志 |
| `RolledBack` | 自检失败，进入修复 | 失败 + 修复入口 | 修复 / 导出日志 |
| `Cancelled` | 用户取消 | 已取消，回 Idle | 重试 |
| `Failed` | 任一阶段失败 | 错误标题 / 说明 / 指引 | 重试 / 导出日志 |

转移表（关键路径）：

| # | 当前 | 事件 | 守卫 | 目标 | 失败码 |
|---|---|---|---|---|---|
| M01 | Idle | 检查 | 非 Tauri 短路；单飞 | Checking | — |
| M02 | Checking | 清单有效、有更新 | schema / 签 / 渠道 / 版本 / 兼容 / rollout 通过 | Available | 对应错误码 |
| M03 | Checking | 无更新 / 已暂停 / 未命中灰度 | — | Idle | — |
| M04 | Checking | 网络 / 清单失败 | — | Failed | `NETWORK` / `MANIFEST_*` |
| M05 | Available | 用户安装 | 无并发 | Precheck | — |
| M06 | Precheck | 全部通过 | 空间 / 单实例 / 目录 / 物料 | Downloading | `PRECHECK_*` |
| M07 | Downloading | 下载 + 插件验签完成 | 字节完整 | Verifying | `NETWORK` / `SIG_INVALID` |
| M08 | Verifying | 哈希 / size / PE / Authenticode 通过 | — | ReadyToInstall | `HASH_*` / `PE_*` / `AUTHENTICODE_*` |
| M09 | ReadyToInstall | 用户确认 | 重新检查 `paused` / `revoked`（在线时） | Locking | `INSTALL_REVOKED` |
| M10 | Locking | `LockOutcome.clean === true` | 统一 `lockAll`；空锁库为受控例外 | Installing | `LOCK_*` |
| M11 | Installing | 安装器启动 | marker 已落盘 | Restarting | `INSTALL_FAILED` |
| M12 | Restarting | 新进程读取 marker | `to_version === current` | HealthCheck | `MARKER_INVALID` / `INSTALL_FAILED` |
| M13 | HealthCheck | DLL / worker / ABI 全通过 | 超时内 | Confirmed | `HEALTH_FAIL` |
| M14 | HealthCheck | 任一失败 / 超时 | — | RolledBack | `HEALTH_FAIL` |
| M15 | Failed / RolledBack / Cancelled | 用户重试 / 修复 / 关闭 | 清理句柄 | Idle | — |

越态事件必须被忽略并记录 `warn`，不得抛未捕获异常。

### 4.3 错误码契约

复用 `verthys_error.ts` 的 `VerthysErrorCode` / `VerthysUserErrorText` / `translateVerthysError`，新增 `E_UPDATER_*` 域。每个错误码必须同时有：枚举值、文案映射、单测断言、事件上报。

| 错误码 | 阶段 | 触发 | 用户文案要点 | 可重试 |
|---|---|---|---|---|
| `E_UPDATER_NETWORK` | Checking / Downloading | 超时、连接拒绝、重试耗尽 | 更新网络连接失败 | 是 |
| `E_UPDATER_MANIFEST_INVALID` | Checking | schema / 必填 / 类型 / target / URL 非法 | 更新清单无效 | 否 |
| `E_UPDATER_MANIFEST_SIG_INVALID` | Checking | 清单签名缺失 / 无效 / key id 未知 | 更新清单未受信任 | 否 |
| `E_UPDATER_CHANNEL_MISMATCH` | Checking | 端点渠道与清单渠道不一致 | 更新渠道不匹配 | 否 |
| `E_UPDATER_VERSION_BLOCKED` | Checking | 目标版本不高于当前 | 版本不可安装 | 否 |
| `E_UPDATER_BRIDGE_REQUIRED` | Checking | 当前版本低于 `min_version` | 需要先安装中间版本 | 否 |
| `E_UPDATER_COMPAT_BLOCKED` | Checking | ABI / 容器 / OS / WebView2 不匹配 | 版本与当前环境不兼容 | 否 |
| `E_UPDATER_PACKAGE_MISSING` | Precheck / Verifying | 物料缺失 / 为空 / 超过大小上限 | 更新物料缺失 | 否 |
| `E_UPDATER_PRECHECK_SPACE` | Precheck | 空间低于 `size * 2 + 100 MB` | 磁盘空间不足 | 是 |
| `E_UPDATER_PRECHECK_SINGLE_INSTANCE` | Precheck | 第二实例持有程序目录 | 程序已在运行 | 是 |
| `E_UPDATER_PRECHECK_DIR_WRITABLE` | Precheck | 探针创建 / 写入 / 删除失败 | 安装目录无写入权限 | 是 |
| `E_UPDATER_HASH_MISMATCH` | Verifying | SHA256 不一致 | 安装包校验失败 | 否 |
| `E_UPDATER_SIZE_MISMATCH` | Verifying | 字节数不一致 | 安装包大小异常 | 否 |
| `E_UPDATER_PE_VERSION_MISMATCH` | Verifying | PE 版本缺失 / 不等于清单 | 安装包版本不一致 | 否 |
| `E_UPDATER_SIG_INVALID` | Verifying | 安装包签名无效 | 安装包签名无效 | 否 |
| `E_UPDATER_SIG_PUBKEY_MISMATCH` | Verifying | key id 不在内置密钥集 | 更新签名不受信任 | 否 |
| `E_UPDATER_AUTHENTICODE_INVALID` | Verifying | 证书链 / 主体 / 时间戳失败 | 安装包未通过系统签名校验 | 否 |
| `E_UPDATER_LOCK_DIRTY` | Locking | 脏缓存未清 | 部分数据未保存，已中止 | 是 |
| `E_UPDATER_LOCK_FAILED` | Locking | `lockAll` 抛错 / 超时 | 数据锁定失败，已中止 | 是 |
| `E_UPDATER_LOCK_UNKNOWN` | Locking | 闸门结果缺失 / 不一致 | 无法确认数据已安全落盘 | 是 |
| `E_UPDATER_INSTALL_FAILED` | Installing / Restarting | 安装器未启动 / 非零退出 / 进程异常 | 更新安装未完成 | 是 |
| `E_UPDATER_INSTALL_REVOKED` | ReadyToInstall | 清单撤回 / 暂停 | 该版本已停止发布 | 否 |
| `E_UPDATER_HEALTH_FAIL` | HealthCheck | 自检子项失败 / 超时 | 新版本自检未通过 | 是 |
| `E_UPDATER_MARKER_INVALID` | Restarting | marker 缺失 / schema / nonce 非法 | 更新状态异常，请修复 | 否 |
| `E_UPDATER_ROLLBACK_MATERIAL_MISSING` | RolledBack / Repair | LKG / 旧安装包缺失或校验失败 | 回退物料不可用 | 否 |
| `E_UPDATER_CANCELLED` | 任意 | 用户取消 | 已取消更新 | 是 |
| `E_UPDATER_INTERNAL` | 任意 | 并发 / 状态不一致 / 未分类 | 更新内部错误 | 是 |

文案规则：

1. `guidance` 必须给出可执行下一步：重试、关闭其他实例、清理空间、导出日志、运行修复工具。
2. 原始技术 message / 堆栈 / URL / 完整路径只进日志，不进用户文案。
3. 静默检查失败不弹窗，只写日志；手动检查失败走统一提示。
4. `E_UPDATER_SIG_*` / `HASH_*` / `PE_*` / `AUTHENTICODE_*` 必须按安全事件记录，不得只显示“网络错误”。

### 4.4 签名复验与 PE 版本身份

1. **插件验签**：`Update::download()` 内部使用 `tauri.conf.json` 的 `pubkey` 验证安装包签名；失败直接返回错误。
2. **Rust 密钥集复验**：对返回字节再次调用 `minisign_verify`，使用 `trusted_installer_keys`（可包含新旧公钥）；读取签名 key id：
   - 签名无效 → `E_UPDATER_SIG_INVALID`；
   - key id 未知 → `E_UPDATER_SIG_PUBKEY_MISMATCH`；
   - 通过 → 继续。
3. **PE 版本**：解析安装包 PE `VS_VERSIONINFO`，读取 `FileVersion` / `ProductVersion`；归一化为 `MAJOR.MINOR.PATCH`：
   - 缺失 / 解析失败 → `E_UPDATER_PE_VERSION_MISMATCH`；
   - 不等于清单 `platforms.<target>.file_version` → `E_UPDATER_PE_VERSION_MISMATCH`；
   - 不高于当前版本 → `E_UPDATER_VERSION_BLOCKED`。
4. **为什么**：当前 CLI 的签名 trusted comment 不含版本，清单可以被篡改为“高版本号 + 旧签名包”；PE 版本在签名覆盖的字节内，是可信的版本身份。Phase S 升级 CLI 后可同时启用 `requireSignedVersion`，PE 校验保留为纵深防御。
5. **Authenticode（Phase S）**：将字节写入受控临时文件，调用 `WinVerifyTrust` 验证签名链、时间戳与证书主体 / 指纹；失败即拒绝安装；临时文件在 `finally` 中删除。
6. **密钥轮换过渡**：插件 `pubkey` 只支持一个公钥。若插件主公钥未覆盖新签名，Rust 服务可基于 `update.download_url` 自行下载（reqwest），用密钥集验签，再调用 `Update::install(bytes)`；默认路径优先使用插件下载，减少重复实现。轮换期至少保留旧公钥一个版本周期。

### 4.5 预检

| 检查项 | 规则 / 默认值 | 失败码 | 处置 |
|---|---|---|---|
| 物料存在性 | `local` profile：清单 URL 指向的本地物料存在且非空；`production`：URL 可达，最终以下载成功 + 哈希 / 签名校验为准 | `PACKAGE_MISSING` | 中止；提示维护人补齐 / 重试 |
| 磁盘空间 | 安装目录卷 + 临时目录卷剩余空间 ≥ `size * 2 + 100 MB` | `PRECHECK_SPACE` | 中止；提示清理 |
| 单实例 | 命名互斥量 / single-instance 插件；第二实例持有程序目录即失败 | `PRECHECK_SINGLE_INSTANCE` | 中止；提示关闭其他实例 |
| 目录可写 | 程序目录创建探针文件 → 写入 → 读取 → 删除 | `PRECHECK_DIR_WRITABLE` | 中止；提示权限 / 更换目录 |
| 网络可达 | 可选：HEAD 清单 / 安装包，5 s 超时 | `NETWORK` | 中止；可重试 |
| 兼容环境 | OS build / WebView2 版本 / ABI | `COMPAT_BLOCKED` | 中止；提示环境不支持 |
| 电量 / 电源 | P2 可选 | — | 仅提示，不阻断 |

所有阈值登记 `CONFIGURATION.md`，经产品确认后固化；未确认前不得写入生产配置。

### 4.6 锁库闸门

`lockAll` 目标签名改为：

```ts
export interface LockOutcome {
  clean: boolean;      // 唯一安装准入条件；clean = flushed && !dirty && errors.length === 0
  flushed: boolean;    // waitForFlush 是否成功；无会话 / 无待落盘工作时为 true
  dirty: boolean;      // isCacheDirty() 结果
  errors: string[];    // 结构化错误（不含敏感信息）
  durationMs: number;
}
```

执行顺序（不可调换、不可跳过）：

```text
Prepared + Verifying 通过
  → 复核磁盘空间 / 目录可写（下载期间可能变化）
  → 读取会话状态
  → 统一调用 lockAll()（即使当前锁定也走同一流程；无会话时应快速返回）
  → 仅当产品确认 lockAll 无法在未解锁状态调用时，才允许受控空锁库路径
  → 检查 LockOutcome.clean
  → Rust updater_confirm_lock(outcome)
  → Rust updater_install(update_id)
       → 校验 prepared / gate / PE
       → 原子写 pending.json（临时文件 + fsync + rename）
       → Update::install(bytes)
```

硬规则：

1. `clean !== true` 或结果缺失 → `E_UPDATER_LOCK_UNKNOWN`，不安装。
2. `lockAll` 抛错 / 超时 / 脏缓存 → `LOCK_FAILED` / `LOCK_DIRTY`，保持当前会话与旧版程序。
3. 锁库阶段禁止关闭窗口、禁止退出、禁止切换模块；UI 展示“正在安全落盘，不可跳过”。
4. 安装器接管前，进程内模块密钥 / GMK / 扫描缓存 / 摘要缓存必须清理；沿用既有 zeroize 口径。
5. Rust `updater_confirm_lock` 必须记录：是否有会话、`flushed`、`dirty`、`durationMs`、错误摘要；不记录密钥或容器内容。
6. **未就绪必须区分**“确定未解锁 / 无会话”与“正在解锁 / 初始化”：后者中止更新，不得走空锁库确认路径，避免会话创建竞态。
7. Rust `updater_confirm_lock` 必须复核 worker 已销毁 / 会话未就绪；不得只信任前端传入的 `clean` 布尔值。
8. **空锁库不是跳过**：若采用空锁库路径，必须验证无会话、无存活 worker、无待落盘工作、无脏缓存，并产出同样的 `LockOutcome`；禁止用 `if (ready)` 直接跳过闸门。

### 4.7 更新标记与启动健康自检

#### 4.7.1 pending.json

路径：`%APPDATA%/Verthys/updater/pending.json`（或 Tauri `app_data_dir` 下同义路径）。

```json
{
  "schema_version": 1,
  "release_id": "20261022-090000-4.1.4-a1b2c3d4",
  "from_version": "4.1.3",
  "to_version": "4.1.4",
  "installer_sha256": "<64 hex>",
  "installer_sig_key_id": "<key id>",
  "lkg_path": "%APPDATA%/Verthys/updater/lkg/Verthys_4.1.3_x64-setup.exe",
  "lkg_sha256": "<64 hex>",
  "created_at": "2026-10-22T09:00:00Z",
  "nonce": "<32 bytes base64>",
  "state": "install_handoff"
}
```

写入要求：临时文件 → `fsync` → 原子 rename；目录 ACL 仅当前用户；失败即中止安装。状态机：`prepared` → `install_handoff` → `health_confirmed` / `rolled_back` / `install_failed`。归档到 `updater/history/`，保留最近 10 次。

#### 4.7.2 启动流程

```text
应用启动
  → updater_startup_state()
  → 无 pending：正常启动，Idle
  → 有 pending 且 to_version == current：
       HealthCheck
         → DLL 加载 / 完整性自检
         → worker_init + ready 信号（不触发解锁）
         → ABI 协商
         → 可选只读探测
         → 全部通过：Confirmed，归档 marker
         → 任一失败 / 超时：RolledBack，归档 marker，显示修复入口
  → 有 pending 且 to_version != current：
       记录 INSTALL_FAILED / 版本未变更，清理 marker，进入 R1 修复提示
  → marker schema / nonce 非法：
       E_UPDATER_MARKER_INVALID，不自动执行健康检查，进入修复提示
```

健康自检子项：

| 子项 | 检查 | 复用锚点 | 默认超时 |
|---|---|---|---|
| DLL 完整性 | `verthys.dll` 加载 + `.vsec` / 运行时函数哈希 | `core/` 既有 `integrity_verify_startup` / `runtime_hash` | 10 s |
| worker 就绪 | 收到 `{"ok":true,"op":"ready"}` | `worker_controller` `wait_for_ready_signal` | 10 s |
| ABI 协商 | 主进程 / worker / DLL ABI 兼容 | `VERTHYS_API_VERSION 0x000B` | 5 s |
| 只读探测 | 模块列表 / 只读元数据可获取（可选） | 现有只读初始化路径 | 5 s |

规则：

- 自检不得触发容器解锁、密钥派生、写操作；失败不得修改用户容器。
- **仅在 marker 存在时执行健康自检**；普通启动不增加等待。自检应并行 / 早退，UI 可先渲染只读壳层，但修复入口必须在自检结果后可用。
- `RolledBack` 只表示“检测失败 + 旧版物料保留 + 修复入口可用”，**不表示新二进制已自动替换回旧版**。
- 自检结果写入事件日志，包含子项结果、耗时、超时命中、from/to 版本、release_id。
- 若 WebView 无法加载导致前端无法展示修复提示，Rust 侧必须提供原生消息 / 启动修复工具的最小路径；不得只依赖前端渲染。

### 4.8 回退分级

| 层级 | 能力 | 实现 | 阶段 | 用户动作 |
|---|---|---|---|---|
| R0 | 检测 + 指引 + 日志 | marker + 健康自检 + `RolledBack` UI | L0 | 查看说明，导出日志，手动重装 |
| R1 | LKG / 上一安装包 + 修复入口 | 客户端缓存 LKG；校验哈希 / 签名；一键运行修复 | L1 | 确认后运行修复 |
| R2 | 外部看门狗自动回退 | 独立签名的 `VerthysUpdater.exe`，主程序启动失败时执行 LKG / 历史版本 | S / E | 自动或最小确认 |

R1 的 LKG 来源：

1. 首次安装时由 NSIS 安装钩子复制安装包到 `updater/lkg/`（需要自定义 NSIS 模板 / 宏，P1 实现）；
2. 若无安装钩子，则在每次成功更新后保留“本次下载的安装包”作为下一版本的 LKG；
3. 服务器阶段由服务端保留历史版本，客户端按清单历史下载上一版本（签名 / 哈希 / PE 校验一致）；
4. LKG 在执行前必须重新校验签名、哈希、PE 版本；校验失败 → `E_UPDATER_ROLLBACK_MATERIAL_MISSING`。

**禁止**：在没有 LKG / 历史包的情况下向用户承诺“已自动回退”。文案必须写“已检测到新版本异常，旧版物料已保留，可运行修复工具 / 重新安装旧版”。

### 4.9 并发、取消与生命周期

1. **单飞**：检查 / 准备 / 安装各自互斥；`Installing` 期间拒绝新检查。
2. **取消**：`Downloading` / `Preparing` 可取消；取消后清理 prepared 字节、关闭更新会话、写 `E_UPDATER_CANCELLED`；`Locking` 开始后不可取消。
3. **关闭窗口**：下载中关闭 → 取消并清理；锁库中关闭 → 阻止关闭或等待锁库完成；安装交接后关闭 → 安装器继续。
4. **超时**：检查 30 s；下载连接 15 s、总时长 10 min；重试 3 次，间隔 2 / 5 / 10 s + 抖动；超时归 `NETWORK`。
5. **休眠 / 唤醒**：下载超时按墙钟计算；唤醒后重试；不信任本地时钟做安全判定。
6. **网络切换**：失败重试；代理 / 离线错误归 `NETWORK`；不得降级到 HTTP。
7. **幂等**：同一 `release_id` 只安装一次；重复 `updater_install` 返回 `E_UPDATER_INTERNAL`，不重复启动安装器。
8. **句柄**：`cancel` / 失败 / 退出调用 `closePending()` 语义；Rust `Update` 句柄释放；无孤儿临时文件。
9. **安装前在线复查**：stable / beta / internal 默认 `require_online_recheck_before_install = true`；安装前重新拉取清单，确认 `release_id` 未暂停、未撤回、rollout 仍命中；离线默认不安装。local profile 不复查。

### 4.10 日志与事件 schema v1

事件字段白名单：

| 字段 | 类型 | 说明 |
|---|---|---|
| `ts` | string | RFC 3339 UTC |
| `event_id` | string | UUID v4 |
| `session_id` | string | 每次应用启动随机生成，不跨会话 |
| `install_id` | string | 首次运行生成的随机 UUID，仅用于灰度 bucket 与去重，不使用设备指纹 |
| `release_id` | string | 清单发布 ID |
| `event` | string | 事件枚举 |
| `phase` | string | 状态机阶段 |
| `code` | string | `E_UPDATER_*` 或空 |
| `severity` | string | `debug` / `info` / `warn` / `error` |
| `from_version` / `to_version` | string | 版本 |
| `channel` / `profile` | string | 渠道 / `local` / `production` |
| `os` / `arch` | string | OS build / x64 |
| `duration_ms` | number | 阶段耗时 |
| `attempt` | number | 重试次数 |
| `bytes` | number | 下载 / 安装包大小 |
| `hash_prefix` | string | 仅前 12 位十六进制 |
| `bucket` | number | 灰度 bucket（0-9999） |
| `detail` | object | 白名单键值；禁止自由文本堆栈 |

事件集：

`check_sent`、`check_hit`、`check_miss`、`manifest_ok`、`manifest_sig_invalid`、`channel_mismatch`、`version_blocked`、`bridge_required`、`compat_blocked`、`rollout_excluded`、`precheck_blocked`、`download_start`、`download_progress`（聚合，不逐块）、`download_success`、`download_failed`、`sig_ok`、`sig_invalid`、`pubkey_mismatch`、`hash_ok`、`hash_mismatch`、`size_mismatch`、`pe_version_mismatch`、`authenticode_invalid`、`lock_dirty`、`lock_failed`、`lock_unknown`、`install_start`、`install_handoff`、`install_failed`、`health_ok`、`health_fail`、`rolled_back`、`repair_started`、`repair_failed`、`local_package_rejected`、`cancelled`。

日志规则：

1. 位置：`app_data_dir/logs/updater/updater-YYYYMMDD.jsonl`；按日 / 5 MB 滚动，保留 7 天。
2. 导出：Rust 命令复制并脱敏，输出 zip；用户选择目标路径；不通过前端 `fs` 插件直接写。
3. 禁止：私钥、口令、GMK、模块密钥、容器路径全名、记录标题、记录内容、完整设备指纹、完整哈希。
4. 事件必须能计算 §2.1 的指标；无法映射到指标的事件不得写入。
5. 日志写入失败不得阻断更新，但必须记录一次 `log_write_failed` 到控制台 / 系统日志。

### 4.11 UI 文案与交互

| 场景 | 文案要点 | 交互 |
|---|---|---|
| 检查中 | “正在检查更新” | 禁用重复点击 |
| 无更新 | “当前已是最新版本” | 关闭提示 |
| 有更新 | 版本号 + 说明 + 安全修复标记 | “安装更新” / “稍后” |
| 强制更新 | “此版本包含安全修复，需要立即安装” | 只保留“立即更新” |
| 预检失败 | 具体原因 + 指引（清理空间 / 关闭实例 / 权限） | 重试 / 关闭 |
| 下载失败 | “网络中断，可重试” | 重试；静默检查不弹窗 |
| 验签 / 哈希失败 | “安装包未通过安全校验，已中止” | 导出日志 / 联系维护人 |
| 锁库中 | “正在安全保存数据，请勿关闭” | 禁止关闭 / 切模块 |
| 自检失败 | “新版本自检未通过，旧版物料已保留” | 运行修复 / 导出日志 |
| 修复物料缺失 | “未找到可用的旧版安装包” | 重新安装 / 联系维护人 |

UI 不得使用“已自动回退”这类与 R0/R1 能力不符的表述；不得在验签 / 哈希 / PE 失败时显示“网络错误”。

---

## 5. 本机实施计划（Phase L）

### 5.1 实施原则

1. **先契约后代码**：T01 ~ T03 先固定文档、profile、清单 schema，再写更新服务。
2. **一个任务一个验收**：每个任务必须附带代码、测试、文档、证据四件套；没有证据不算完成。
3. **批次推进**：B0 基础 → B1 安全流水线 → B2 体验 / 健康 / 观测 → B3 验证 → B4 加固。
4. **不破坏现有行为**：现有 7 条 `useAppUpdater` 单测的行为语义必须保留；迁移后以新测试覆盖。
5. **不引入未登记依赖**：新增 Rust crate（如 `serde_jcs`、`minisign-verify`、`pelite`）必须进入 `dep-versions.txt`、vendor 哈希门与 SBOM。

### 5.2 P0 任务（L0 必须完成）

| 编号 | 任务 | 主要文件 | 依赖 | 验收 |
|---|---|---|---|---|
| T01 | 文档权威与索引：本目录 README / MASTER / SERVER；`docs/README.md` 更新入口 | `docs/updater/*`、`docs/README.md` | — | 文档存在；索引可解析；口径一致 |
| T02 | 构建 profile：`local` / `production`；端点、明文许可、渠道、清单签名开关注入；CI 静态门 | `tauri.conf.json`、`scripts/render_tauri_config.mjs`、`build_production.ps1`、`.github/workflows/*` | T01 | production 配置无回环 / 无明文许可 / HTTPS；local 产物带标记；CI 对违规硬失败 |
| T03 | Manifest v2：生成脚本扩展、JCS 规范化、清单签名、schema 校验、双 target 键 | `scripts/make_updater_manifest.mjs`、`scripts/sign_manifest.mjs`、`scripts/*.test.mjs` | T02 | 合法清单生成；15 条负向契约用例通过；Tauri 可解析 |
| T04 | Rust 更新服务骨架与 `updater_check`：会话、单飞、渠道端点、`raw_json` 解析 | `src-tauri/src/updater/*`、`lib.rs` | T03 | 检查成功 / 失败 / 无更新 / 渠道不匹配均有单测 |
| T05 | `updater_prepare`：插件下载 + 密钥集复验 + SHA256 / size + PE 版本 + 兼容 | `updater/service.rs`、`verify.rs`、`pe.rs` | T04 | 正向准备成功；签名 / key id / 哈希 / size / PE 负向全部拒绝 |
| T06 | `updater_install`：闸门校验、marker 原子写、`install(bytes)`、失败语义 | `updater/gate.rs`、`marker.rs`、`service.rs` | T05、T09 | 未授权安装拒绝；marker 落盘；安装交接日志完整 |
| T07 | Vue 状态机与错误码：显式状态、转移表、越态防护、文案映射 | `src/composables/updater/*`、`src/lib/verthys_error.ts` | T04 | 状态转移矩阵单测；27 个错误码文案齐全；现有 7 条行为保留 |
| T08 | 预检：空间、单实例（命名互斥量 + 进程路径）、目录可写、物料存在、兼容环境 | `updater/precheck.rs` / 前端预检模块 | T04 | 各检查项独立失败路径；E2E E08 ~ E10 通过 |
| T09 | 锁库闸门：`LockOutcome`、统一 `lockAll`（空锁库受控路径）、脏数据、密钥清理、`updater_confirm_lock` | `security-session.ts`、`SecurityCenter.vue`、`updater/gate.rs` | T07 | 未就绪不跳过；脏缓存中止；锁库失败保持会话；G2 关闭 |
| T10 | 更新标记与健康自检：`pending.json`、启动状态、DLL / worker / ABI、结果归档 | `updater/marker.rs`、`lib.rs`、启动初始化链路 | T06 | 正向 Confirmed；失败 RolledBack；自检不触发解锁 |
| T11 | 本地日志：事件 schema、JSONL、滚动、脱敏、导出 | `updater/log.rs`、`src/utils/logger.ts` 或 `updater-log.ts` | T07 | 事件字段白名单；导出脱敏；7 天 / 5 MB 规则 |
| T12 | 单元 / 集成测试：Rust 解析 / 验签 / PE / marker / gate；Vue 状态机；脚本契约 | 对应 `*.spec.ts` / `#[cfg(test)]` / Node test | T04 ~ T11 | 新增用例全绿；现有测试全绿 |
| T13 | CI 质量门：配置静态检查、清单契约、文档存在性、测试执行 | `.github/workflows/rust-frontend.yml`、`ci/*` | T02、T03、T12 | 违规即红；PR 可复现 |
| T14 | 干净 VM E2E：快照、基线安装、正向 + 负向 + 故障注入、证据表 | `docs/updater/TESTING.md`（或 `../TESTING.md` 章节）、脚本 | T04 ~ T11 | 14/20 用例通过并记录证据；旧版 / 容器完好 |
| T15 | 文档纠偏：`DEPLOYMENT.md` §3-4、`RELEASE.md`、`CONFIGURATION.md`、`SECURITY_DESIGN.md`、`TESTING.md`、`CHANGELOG.md`、`MIGRATION.md` | `docs/*`、根 `CHANGELOG.md` | T01 ~ T14 | 文档与代码一致；不再出现“无自动更新”漂移；参数全部登记 |
| T16 | 物料账本：release manifest、SBOM 绑定、安装包 / `.sig` / DLL / worker 哈希归档 | `build_production.ps1`、`scripts/generate_release_manifest.mjs` | T02、T03 | 归档目录含 manifest；哈希可复核；SBOM 与安装包同目录 |

### 5.3 P1 任务（L1 / 首个迭代）

| 编号 | 任务 | 要点 | 验收 |
|---|---|---|---|
| P1-01 | R1 修复入口 + LKG | 客户端 LKG 缓存、修复 UI、校验后运行；NSIS 钩子或历史包下载 | 健康失败后可一键修复；LKG 缺失有明确文案 |
| P1-02 | HTTP Range 断点续传 | 本机夹具 + 服务端支持 Range；客户端续传前重新校验 | 断网恢复续传；缓存哈希不符重下 |
| P1-03 | 单实例增强 | 用 `tauri-plugin-single-instance` 替换 P0 的命名互斥量 / 进程探测，统一行为 | 第二实例激活已有窗口；预检与启动行为一致 |
| P1-04 | 密钥轮换 / 密钥集 | 新旧安装包公钥、清单公钥并行；key id 识别 | 旧客户端验新签名包通过；泄露演练可吊销 |
| P1-05 | Authenticode 接入预演 | `beforeBundleCommand` 签 DLL / worker / 主程序；Tauri `signCommand` / 手工签 NSIS；确保 `.sig` 在 NSIS 签名后生成；时间戳 | 干净机器无未知发布者；`Get-AuthenticodeSignature` 全部 Valid；`.sig` 可验证 |
| P1-06 | Release 工作流 | tag 触发、质量门、签名、清单、物料账本、归档 | 发布可复现；不覆盖已发布清单 |
| P1-07 | E2E 自动化 | `tauri-driver` / WebDriver 或脚本化 UI 路径 | 核心用例可自动执行；人工仅做确认 |
| P1-08 | 本机指标报告 | 从 JSONL 生成成功率 / 失败 TOP / 耗时 | 每次发布附报告 |
| P1-09 | 故障排查文档 | `TROUBLESHOOTING.md` 更新问题小节，错误码 → 症状 → 处置 | 可按错误码排查 |

### 5.4 P2 任务（服务器 / 企业阶段前置）

| 编号 | 任务 | 要点 | 阶段 |
|---|---|---|---|
| P2-01 | R2 看门狗 / 修复工具 | 独立 `VerthysUpdater.exe`，主程序无法启动时回退 | S / E |
| P2-02 | MSI / GPO / Intune | per-machine 安装、企业分发 | E |
| P2-03 | 服务器 staging 客户端 | production profile、渠道、鉴权、遥测 | S0 |
| P2-04 | 更新说明向导 | 首次启动展示 notes / 安全修复，不触发解锁 | S1 |
| P2-05 | 离线包 / 内网镜像 | 离线清单、内网端点、同一信任根 | E |
| P2-06 | 多区域 / CDN 规模化 | 对象存储 + CDN + WAF + 灾备 | S1 |

### 5.5 批次顺序

| 批次 | 内容 | 退出条件 |
|---|---|---|
| B0 | T01、T02、T03、T15（文档 / profile / 清单 / 纠偏） | 文档权威；production 配置门；清单契约测试 |
| B1 | T04、T05、T06、T09（Rust 服务 / 准备 / 安装 / 闸门） | 安全流水线正向 + 负向单测；G2 关闭 |
| B2 | T07、T08、T10、T11（状态机 / 预检 / 健康 / 日志） | UI 状态机、预检、marker、健康、日志全绿 |
| B3 | T12、T13、T14、T16（测试 / CI / E2E / 物料账本） | 14/20 E2E；CI 全绿；物料可复核 |
| B4 | P1-01 ~ P1-09 | 20/20 E2E；R1 修复；Range；单实例；Authenticode 预演 |

### 5.6 文件级改动清单

| 区域 | 文件 | 动作 |
|---|---|---|
| 配置 | `verthys-tauri/src-tauri/tauri.conf.json` | 拆 profile；生产 HTTPS；移除明文许可；渠道 / 端点注入 |
| 配置生成 | `scripts/render_tauri_config.mjs`（新增） | 合并 `local` / `production` 配置；CI 校验 |
| Rust 更新服务 | `src-tauri/src/updater/*`（新增） | 清单 / 验签 / PE / marker / gate / 日志 / 命令 |
| Rust 注册 | `src-tauri/src/lib.rs` | 注册命令；启动早期读取 marker |
| 前端状态 | `src/composables/useAppUpdater.ts`、`src/composables/updater/*` | 迁移到 IPC 状态机；错误码；取消；进度 |
| 闸门 | `src/components/modules/SecurityCenter.vue` | 消费 `LockOutcome`；预检；健康 / 修复入口 |
| 会话 | `src/session/security-session.ts` | `lockAll` 返回结构化结果；不吞异常 |
| 错误 | `src/lib/verthys_error.ts` | 新增 `E_UPDATER_*` 枚举 / 文案 |
| 日志 | `src/utils/logger.ts` 或 `src/composables/updater/updater-log.ts` | 事件 schema、滚动、导出 |
| 清单脚本 | `scripts/make_updater_manifest.mjs`、`scripts/sign_manifest.mjs`（新增） | v2 字段、JCS、签名、负向校验 |
| 夹具 | `scripts/updater_server.mjs` | 保持回环；P1 增加 Range / ETag |
| 构建 | `build_production.ps1` | `-Profile`；签名时序；物料账本；产物校验 |
| CI | `.github/workflows/rust-frontend.yml`、`.github/workflows/core.yml` | 配置门、清单契约、文档检查、测试 |
| 文档 | `docs/updater/*`、`docs/*`、`CHANGELOG.md` | 权威索引、纠偏、参数登记、迁移矩阵 |

### 5.7 L0 Definition of Done

1. T01 ~ T16 全部完成；阻断项全部关闭（E2E 关闭口径为“干净 VM 矩阵 + 证据 + 14/20 核心用例”，其余 6 条在 L1 关闭）。
2. `local` profile 端到端：检查 → 准备 → 预检 → 锁库 → 安装 → 重启 → 健康自检 → Confirmed。
3. 负向：清单篡改、签名篡改、公钥不匹配、哈希不符、size 不符、PE 版本不符、降级、bridge、兼容、灰度排除、暂停、撤回、空间不足、单实例、目录不可写、锁库失败、安装中断、健康失败 —— 全部有预期拒绝 / 恢复行为。
4. 干净 VM E2E 至少 14/20，证据表完整；生产 UI 真实凭据路径与容器记录数核对完成。
5. 现有前端 / Rust / C 测试、`vue-tsc`、`vite build`、vendor 哈希门、版本漂移门全绿。
6. 私钥不在仓库 / 安装包 / 日志 / SBOM；日志脱敏测试通过。
7. `docs/README.md`、`DEPLOYMENT.md`、`RELEASE.md`、`CONFIGURATION.md`、`SECURITY_DESIGN.md`、`TESTING.md` 与本方案一致；`CHANGELOG.md`、`docs/MIGRATION.md` 存在。
8. 发布物料账本可复核：安装包、`.sig`、DLL、worker、SBOM 哈希与 release manifest 一致。

---

## 6. 质量门与测试体系

### 6.1 质量门

| 门 | 名称 | 判定内容 | 失败处置 |
|---|---|---|---|
| G0 | 文档权威 | 本目录三份文档存在；README 索引可解析；口径一致 | 阻断合入 |
| G1 | 版本单源 | `VERSION` 与 `Cargo.toml` / `package.json` / `config.ts` 一致；`sync_version.ps1 -CheckOnly` | 阻断构建 |
| G2 | Profile 配置 | `production` 配置无 `127.0.0.1` / `localhost` / `dangerousInsecureTransportProtocol: true`；端点 HTTPS；渠道合法 | 阻断构建 |
| G3 | 核心质量门 | CTest、vendor 哈希、AST 红线、clippy、`cargo test`、`vue-tsc`、Vitest、`vite build` | 阻断构建 |
| G4 | 清单契约 | 合法清单生成；15 条负向契约用例；Tauri 解析；JCS 验签 | 阻断发布 |
| G5 | 更新服务测试 | Rust `check / prepare / install / marker / gate` 单测；Vue 状态机；错误文案 | 阻断合入 |
| G6 | 干净 VM E2E | E01 ~ E20 + 回归附加；证据表完整 | 阻断发布 |
| G7 | 安全与脱敏 | 私钥 / 口令扫描；日志脱敏；配置无明文许可；依赖审计 | 阻断发布 |
| G8 | 物料账本 | 安装包 / `.sig` / DLL / worker / SBOM / release manifest 哈希一致 | 阻断发布 |
| G9 | 服务器预发 | staging E2E、负载、回滚、密钥演练 | 阻断 S1 |

质量门执行原则：

1. **可机器判定优先**：能在 CI 判定的，不靠人工勾选；不能机器判定的，必须有可复现步骤与证据。
2. **失败不降级**：任何门失败不得通过“稍后补”放行；紧急修复也必须保留事后审计记录。
3. **同一份产物**：E2E 使用的安装包必须是最终归档的同一哈希；不得用“临时构建”验收后发布另一份包。

### 6.2 单元测试

Rust（`updater/*`）：

| # | 用例 | 断言 |
|---|---|---|
| R01 | Manifest schema 正 / 负 | 缺字段、类型错误、非法 SemVer、非法 URL、未知高 `schema_version` 全部拒绝 |
| R02 | JCS 清单验签 | 键序 / 空白不同的同一 JSON 验签通过；改一字节失败 |
| R03 | 密钥集 / key id | 主公钥通过；旧公钥通过；未知 key id → `SIG_PUBKEY_MISMATCH` |
| R04 | SHA256 / size | 正确通过；篡改字节 → `HASH_MISMATCH`；长度不符 → `SIZE_MISMATCH` |
| R05 | PE 版本解析 | `4.1.4` 通过；缺失 / 非法 / 与清单不符 → `PE_VERSION_MISMATCH` |
| R06 | 兼容判定 | ABI / 容器 / OS / WebView2 边界；未知 fail-closed |
| R07 | Rollout bucket | 同一 `install_id + salt` 稳定；百分比边界；100% 全命中 |
| R08 | marker 原子性 | 写入中断不留半文件；schema / nonce 非法拒绝；归档保留 10 次 |
| R09 | Gate 状态 | 未 confirm / clean=false / 重复 install 全部拒绝 |
| R10 | 渠道端点 | stable 只请求 stable；渠道不匹配拒绝；local 只回环 |

Vue / TS：

| # | 用例 | 断言 |
|---|---|---|
| V01 | 状态转移合法路径 | Idle → Checking → Available → Precheck → Downloading → Verifying → ReadyToInstall → Locking → Installing |
| V02 | 越态事件 | `Installing` 中检查 / 重复安装被忽略；无未捕获异常 |
| V03 | 错误文案 | 27 个错误码均有 `title / message / guidance`；不含原始技术 message |
| V04 | 预检 UI | 空间 / 单实例 / 目录 / 兼容失败分别展示正确指引 |
| V05 | 锁库闸门 | `clean=false` 不进入安装；锁库失败保持会话 |
| V06 | 取消 / 关闭 | 下载取消清理；关闭窗口不误安装；恢复后状态一致 |
| V07 | 进度 | `Started / Progress` 聚合；总长未知显示“正在更新” |
| V08 | 旧行为保留 | 现有 7 条 `useAppUpdater` 行为语义迁移后仍成立 |

脚本 / Node：

| # | 用例 | 断言 |
|---|---|---|
| S01 | 清单生成 | 哈希 / size / file_version / 双 target 键正确；原子写 |
| S02 | 15 条负向契约 | 每条形如 §3.8；退出码非零；原因明确 |
| S03 | 清单签名 | 规范化字节正确；签名可被客户端公钥验证 |
| S04 | 配置渲染 | production 无回环 / 明文；local 标记正确 |
| S05 | 物料账本 | 安装包 / `.sig` / DLL / worker / SBOM 哈希齐全且可复核 |

### 6.3 集成测试（本机夹具）

| # | 场景 | 期望 |
|---|---|---|
| I01 | 正向检查 + 准备 + 安装 | Confirmed；容器可解锁；记录数一致 |
| I02 | 清单 404 / 500 / 超时 | `NETWORK`；不进入下载 |
| I03 | 下载中断 / 截断 | 重试；耗尽后 `NETWORK`；临时文件清理 |
| I04 | 安装包哈希篡改 | `HASH_MISMATCH`；不验签后继续 |
| I05 | 签名篡改 | `SIG_INVALID`；不安装 |
| I06 | 签名来自其他密钥 | `SIG_PUBKEY_MISMATCH` |
| I07 | PE 版本与清单不符 | `PE_VERSION_MISMATCH` |
| I08 | `paused` / `revoked` | 无更新 / `INSTALL_REVOKED` |
| I09 | `min_version` / `compatibility` | `BRIDGE_REQUIRED` / `COMPAT_BLOCKED` |
| I10 | 脏缓存 / 锁库失败 | `LOCK_DIRTY` / `LOCK_FAILED`；会话保持；不安装 |
| I11 | 未就绪空锁库 | `clean=true` 可安装；无脏数据；无密钥残留 |
| I12 | 健康自检失败 | `RolledBack`；marker 归档；修复入口可见 |

### 6.4 E2E 矩阵（干净 VM）

环境要求：Windows 10/11 x64 干净 VM 快照；安装基线版本；准备旧版 / 新版安装包与签名；本机夹具或 staging 服务器；真实生产 UI 凭据（受控测试容器）。每条记录：日期、VM 快照、基线 / 目标版本、操作、预期、实际、日志、哈希、执行人、结论。

| # | 场景 | 构造 / 步骤 | 预期 | 关联 |
|---|---|---|---|---|
| E01 | 正向升级 + 数据核对 | 生产 UI 检查 → 安装 → 锁库 → 重启 → 自检 | 版本升级；Confirmed；容器可解锁；记录数一致 | I1/I3/I7/I8 |
| E02 | 启动静默检查 | 启动 10 s 内检查；夹具记录请求 | 命中 / 未命中均不打断使用；无错误弹窗 | — |
| E03 | 清单篡改 | 改 `version` / `url` / `notes` 不重签 | 生产：清单验签失败；本地：schema / 一致性失败 | MANIFEST_* |
| E04 | 清单签名无效 | 用未知密钥签清单 / 改 `manifest_signature` | `MANIFEST_SIG_INVALID`；不下载 | Manifest |
| E05 | 安装包哈希篡改 | 替换 exe 保持文件名 | `HASH_MISMATCH`；临时文件清理 | I2 |
| E06 | 安装包签名篡改 | 替换 `.sig` / 改签名 | `SIG_INVALID`；旧版可启动 | I2/I7 |
| E07 | 公钥不匹配 | 用其他合法密钥签安装包 | `SIG_PUBKEY_MISMATCH` | 密钥集 |
| E08 | 清单说新装旧 | 清单 `version=4.1.9`，URL 指向 4.1.3 签名包 | `PE_VERSION_MISMATCH`；不安装 | 版本身份 |
| E09 | 降级 | 清单回指 4.1.2 | `VERSION_BLOCKED`；不下载 | I1 |
| E10 | 桥接版本 | 当前 4.0.9，`min_version=4.1.0` | `BRIDGE_REQUIRED`；提示先装桥接 | 3.4 |
| E11 | 兼容拦截 | ABI / 容器 / OS 不匹配 | `COMPAT_BLOCKED` | 3.6 |
| E12 | 暂停 / 撤回 | `paused=true` / `revoked_release_ids` 命中 | 无更新 / `INSTALL_REVOKED`；清理准备字节 | 3.4 |
| E13 | 灰度排除 | `rollout.percentage=1`，bucket 未命中 | 无更新；不报错；日志 `rollout_excluded` | 3.4 |
| E14 | 空间不足 | 受控磁盘剩余低于阈值 | `PRECHECK_SPACE`；不下载；指引清晰 | 4.5 |
| E15 | 单实例 / 目录不可写 | 第二实例持有程序目录；目录只读 | `PRECHECK_SINGLE_INSTANCE` / `PRECHECK_DIR_WRITABLE` | 4.5 |
| E16 | 脏缓存锁库 | 构造未落盘脏缓存 | `LOCK_DIRTY`；不安装；会话保持 | I3 |
| E17 | 锁库失败 | 注入 `lockAll` 抛错 / 超时 | `LOCK_FAILED`；旧版可用；无安装器 | I3 |
| E18 | 网络不可达 | 停止夹具 / 断网；手动 + 静默 | 手动提示；静默只写日志；旧版可用 | 5.3 |
| E19 | 安装中断 | 安装器启动后强制终止 / 断电 | 重启后旧版可启动或进入修复；容器数据完好；marker 可追溯 | I7 |
| E20 | 健康失败 + 修复 | 构造新进程 worker ready 超时 / DLL 不兼容 | L0：`RolledBack` + R0 提示；L1：R1 修复入口可用；旧版物料保留 | G7/4.8 |

回归附加（每次发布必跑）：

| # | 场景 | 预期 |
|---|---|---|
| RG-01 | 4.1.3 worker 图像加载策略继承 | worker 启动成功；ready 信号；无 `ERROR_ACCESS_DENIED` |
| RG-02 | SVG 命名空间 / 导航图标 | 5 个图标均可见，SVG 命名空间正确 |
| RG-03 | 模块图标宿主尺寸 | 19px 规则生效，不压穿刻度环 |
| RG-04 | 容器 V3 / ABI 0x000B 兼容 | 旧容器可解锁；记录数一致；无迁移破坏 |

### 6.5 故障注入与安全测试

| 类别 | 注入 | 期望 |
|---|---|---|
| 网络 | 500、慢响应、连接重置、截断、错误 Content-Length | 重试 / `NETWORK`；不崩溃；不误安装 |
| 存储 | 磁盘满、只读目录、探针失败 | `PRECHECK_*`；旧版可用 |
| 进程 | 下载 / 锁库 / 安装阶段杀进程、断电模拟 | marker 一致；旧版可启动或修复；无数据损坏 |
| 物料 | 替换 exe / `.sig` / 清单 / 改 PE 版本 | 对应错误码；不安装 |
| 密钥 | 未知 key id、错误公钥、旧公钥 | 通过 / 拒绝符合密钥集规则 |
| 日志 | 注入敏感字符串 | 导出日志不含密钥 / 路径 / 记录内容 |
| 配置 | production 加回环 / 明文许可 | CI 硬失败 |
| 供应链 | 篡改 vendor 哈希 / SBOM | G3 / G8 失败 |

### 6.6 证据与签字

发布签字至少包含：

1. **构建人**：产物哈希、签名、SBOM、release manifest。
2. **测试人**：E2E 证据表、回归附加、失败用例复核。
3. **安全复核**：密钥、日志脱敏、配置门、依赖审计。
4. **发布授权**：tag、清单、渠道、灰度计划、回滚包。

证据表字段：`case_id / date / vm_snapshot / baseline / target / steps / expected / actual / event_ids / hashes / operator / result / notes`。没有证据的“通过”视为未执行。

### 6.7 性能与体验基线

| 项 | 目标 |
|---|---|
| 检查更新（本机） | < 2 s；不阻塞 UI |
| 下载进度 | 首字节 < 2 s；进度更新平滑；无卡顿 |
| 安装准备（哈希 / PE） | 5 MB 安装包 < 200 ms |
| 锁库阶段 | 不超过现有 `lockAll` 预算；UI 有进度与不可关闭提示 |
| 启动健康自检 | < 20 s（DLL 10 + worker 10 + ABI 5，并行 / 早退优化后） |
| 内存 | 更新服务常驻增量 < 50 MB；prepared 字节按安装包大小 |
| 日志 | 单次更新事件 < 200 条；导出 < 5 s |

### 6.8 测试数据保护

- E2E 使用受控测试容器；不使用真实用户记录做破坏性测试。
- 测试完成后复核旧版可启动、容器可解锁、记录数一致。
- 不提交私钥、口令、测试容器、安装包到仓库；`build/updater/` 按 `.gitignore` 排除。
- 负向用例产生的日志 / 截图归档到验证记录附件，不进入公开仓库。

---

## 7. 发布与运维

### 7.1 本机发布 Runbook（Phase L）

1. **代码冻结**：目标变更合并；文档与代码同 PR。
2. **升版本**：只改根 `VERSION`；运行 `ci/sync_version.ps1`；审阅 `git diff`。
3. **全量测试**：`ctest`、`cargo test`、`npx vitest run`、`vue-tsc --noEmit`、`vite build`。
4. **构建**：`build_production.ps1 -Profile local -Clean -NoPause`；确认 worker 哈希门、签名密钥注入、PDB 清理、SBOM、产物校验全部通过。
5. **生成清单**：`make_updater_manifest.mjs`（v2）计算 SHA256 / size / file_version；写入 `channel=local`、`rollout=100`、`min_version` / `force_below` 决策值。
6. **（可选）清单签名**：用测试密钥签名，验证 Rust 验签路径；production 阶段强制。
7. **物料归档**：安装包、`.sig`、清单、release manifest、SBOM 放入 `build/updater/releases/<release_id>/`；保留上一稳定版本。
8. **启动夹具**：`node scripts/updater_server.mjs`；确认仅 `127.0.0.1:8765`。
9. **E2E**：按 §6.4 执行；先正向，再负向，再故障注入；记录证据。
10. **发布签字**：构建 / 测试 / 安全 / 授权四方签字。
11. **打 tag**：`git tag -a v<version> -m "Release <version>"`。
12. **变更记录**：`CHANGELOG.md` 按 Keep a Changelog 追加；安全条目单独列出。
13. **归档**：release manifest、证据表、日志摘要归档；旧物料按保留策略清理。

### 7.2 私钥与证书保管

| 物料 | 存放 | 权限 | 备份 | 轮换 |
|---|---|---|---|---|
| 安装包 minisign 私钥 | 仓库外受控目录 / HSM | 仅发布人 + 备份介质 | 两份离线，异地 | 预留第二公钥；泄露即吊销 |
| 安装包 minisign 公钥 | 客户端配置 | 公开 | 仓库记录 | 跟随私钥轮换 |
| 清单签名私钥 | 离线 / HSM（Phase S） | 双人控制 | 两份离线 | 新旧 key id 并行 |
| Authenticode 证书 | EV/OV 证书 / 云签名（Phase S） | 受控账号 | 证书备份 | 到期前 90 天续期 |
| 构建签名口令 | 受控密钥库 | 仅 CI / 发布机 | 离线 | 随密钥轮换 |

规则：

- 私钥、口令不得进入 Git、安装包、日志、SBOM、构建缓存、聊天记录。
- 构建脚本缺失密钥必须 `throw`，禁止生成未签名产物。
- 私钥丢失视为“已安装客户端无法验证后续更新”的全局事故；预案是重新分发完整安装包 + 新公钥桥接版本。
- 服务器阶段清单签名私钥不放在 Web 服务器；静态服务器只托管已签名清单。

### 7.3 更新事故 Runbook

| 症状 | 立即动作 | 诊断 | 恢复 |
|---|---|---|---|
| 验签失败集中出现 | 暂停渠道；保留现场日志 | 检查清单 / 安装包 / 密钥 / CDN | 恢复正确物料；重发清单；必要时撤回版本 |
| 大批安装失败 | 暂停渠道；停止灰度 | 按 `phase + code` 聚合；检查磁盘 / 权限 / 安装器 | 修复后重发；必要时回滚清单 |
| 回滚率超阈值 | 自动 / 人工暂停 | 健康自检子项、OS / WebView2 分布 | 回滚到上一清单；发布修复版 |
| 新版本无法启动 | 启用 R1 / R2 修复；暂停渠道 | marker、DLL 完整性、worker ready、ABI | 回退 LKG；发布热修 |
| 清单被篡改 | 立即暂停；吊销清单密钥（如泄露） | 清单签名、访问日志、CDN 日志 | 重签清单；轮换密钥；通知 |
| 私钥泄露 | 停止发布；启动密钥轮换 | 泄露范围、签名记录 | 新密钥 + 桥接版本 + 旧密钥吊销 |
| 证书过期 | 续期；检查 OCSP / 时间戳 | 证书链、系统时间 | 重新签名并发布 |
| CDN / 证书故障 | 切换备用源 / DNS | 可用性监控、TLS 检查 | 恢复后补发；验证缓存 |

### 7.4 指标与发布报告

每次发布附一份本机报告：

- 检查 / 下载 / 校验 / 锁库 / 安装 / 自检各阶段成功率。
- 失败原因 TOP（按错误码）。
- 平均 / P95 下载与安装耗时。
- E2E 通过率与未通过项。
- 物料哈希与 release manifest。
- 已知风险与残余项。

Phase S 由服务端事件聚合生成；Phase L 由 JSONL + 脚本生成。报告归档到发布记录，不写入用户数据。

### 7.5 保留与归档

- 构建机：保留当前版本 + 最近两个稳定版本 + 上一紧急修复版本；更早进入冷存储。
- 客户端：保留当前 LKG + 最近一次安装包（可选）；日志 7 天。
- 服务器：保留最近 10 个 release + 所有被渠道清单引用的 release；撤回版本保留至少 90 天用于审计。
- 归档物料不得被当前清单引用；删除前核对引用关系。

### 7.6 文档同步

更新域变更必须同步：

- 本文对应章节与 `Last updated`。
- `CONFIGURATION.md`：重试、超时、空间余量、健康超时、日志保留、rollout 默认值。
- `SECURITY_DESIGN.md`：信任根、密钥矩阵、威胁模型、遥测边界。
- `TESTING.md`：新增用例与执行方式。
- `TROUBLESHOOTING.md`：错误码 → 症状 → 处置。
- `CHANGELOG.md`：版本段与安全条目。
- `MIGRATION.md`：ABI / 容器 / 回退矩阵。
- `RELEASE.md` / `DEPLOYMENT.md`：流程与现状纠偏。
- `docs/README.md`：本目录入口。

---

## 8. 服务器阶段衔接

### 8.1 触发条件

只有同时满足下列条件，才允许启动 Phase S：

1. Phase L0 退出：T01 ~ T16 完成，S1 发现关闭，E2E 14/20。
2. 客户端 readiness：Rust 更新服务、清单 v2、PE 校验、marker / 健康、R1 修复、渠道 / 遥测接口可用。
3. 外部分发资格：Authenticode 证书、清单签名密钥、HTTPS 域名、发布审批、事件上报方案就绪。
4. 运维准备：告警、值班、回滚演练、密钥泄露预案。

### 8.2 客户端 readiness 清单

| # | 能力 | 必须 |
|---|---|---|
| C01 | `production` profile，HTTPS 端点，无回环 / 明文 | 是 |
| C02 | 清单签名验证 + 密钥集 | 是 |
| C03 | 安装包签名 + SHA256 + size + PE 版本 | 是 |
| C04 | Authenticode 验证（`WinVerifyTrust`） | 是 |
| C05 | 渠道选择 + `rollout` bucket | 是 |
| C06 | `paused` / `revoked_release_ids` / `force_below` | 是 |
| C07 | 安装前重新检查清单（在线） | 是 |
| C08 | `pending.json` + 健康自检 | 是 |
| C09 | R1 修复入口 / LKG | 是 |
| C10 | 事件上报（可关闭）+ 本地日志 | 是 |
| C11 | 代理 / 超时 / 重试 / Range 续传 | 是（S1） |
| C12 | beta / internal 鉴权头（DPAPI 存储） | 是 |

### 8.3 迁移路径

当前 4.1.3 的客户端内置回环端点。**不要假设它能自动切到服务器。** 迁移路径：

1. **推荐**：Phase L 只发内部 local profile；第一次外部分发直接使用 production profile 的完整安装包，不存在“旧客户端指向回环”的迁移问题。
2. **如果已有外部用户**：先发布一个“桥接版本”（production profile，HTTPS 端点），通过现有手动渠道分发；桥接版本安装后，后续更新走服务器。
3. **桥接版本要求**：包含清单签名验证、PE 校验、marker / 健康、R1 修复；不得把回环端点带入 production profile。
4. **旧客户端兼容**：服务器清单的 `min_version` 设为桥接版本；低于该版本的客户端若无法理解字段，仍会按版本比较尝试安装，服务器需确保桥接包可安装且不会破坏数据。
5. **首次服务器发布**：先 internal 100% → beta 1% → stable 1% → 10% → 50% → 100%；每阶段门见 SERVER PLAN。

### 8.4 渠道与端点约定

| 渠道 | 端点 | 访问 | 用途 |
|---|---|---|---|
| `stable` | `https://updates.<domain>/stable/latest.json` | 匿名 | 全量用户 |
| `beta` | `https://updates.<domain>/beta/latest.json` | Bearer token / 签名 URL | 试点 |
| `internal` | `https://updates.<domain>/internal/latest.json` | VPN / Cloudflare Access | 内部 |
| `local` | `http://127.0.0.1:8765/latest.json` | 本机 | Phase L 夹具，不进入 production |

### 8.5 服务器阶段不在本机实施的内容

- 域名 / 证书 / CDN / WAF。
- 对象存储 / 静态托管 / 原子发布。
- 清单签名服务 / 密钥轮换。
- 灰度 / 暂停 / 撤回运营。
- 事件聚合 / 大盘 / 告警。
- 灾备 / 多区域 / 负载测试。
- Authenticode 证书采购与时间戳服务。

以上全部由 [UPDATER_SERVER_DEPLOYMENT_PLAN.md](UPDATER_SERVER_DEPLOYMENT_PLAN.md) 定义。

---

## 9. 风险与残余项

| # | 风险 | 影响 | 缓解 | 残余接受 | 阶段 |
|---|---|---|---|---|---|
| R1 | 更新私钥丢失 | 已安装客户端无法验证后续更新 | 仓库外保管、两份离线备份、构建缺失即终止、桥接重发预案 | 依赖物理保管 | L0 |
| R2 | stock NSIS 非事务安装 | 断电 / 中断留下半安装 | marker + R0 / R1 修复；R2 看门狗 | 不能保证原子 | L0 / L1 |
| R3 | 同账户攻击者 | 可改清单 / 替换物料 / 注入进程 | 签名 + PE 版本 + 最小权限；Phase S 加 HTTPS / 清单签名 / 鉴权 | Phase L 不防同账户 | L0 |
| R4 | 当前 CLI 签名不含版本 | 清单可“说新装旧” | PE FileVersion 强制校验；评估升级 CLI + `requireSignedVersion` | 依赖 PE 解析正确 | L0 |
| R5 | PE 版本解析差异 | 误判导致拒绝更新 | 归一化 + 多版本样本测试；失败 fail-closed | 极端 PE 变形可能不识别 | L0 |
| R6 | Authenticode 证书成本 / 获取周期 | 外部分发延期 | 提前采购 EV / OV 或云签名；L1 预演 | 证书到期 / 吊销 | S1 |
| R7 | Tauri 插件升级破坏兼容 | 更新流水线中断 | 锁定版本；升级前跑契约测试；保留回退分支 | 上游行为变化 | L1 |
| R8 | CDN / 证书 / DNS 故障 | 检查失败 | 多端点 / 备用域；监控；回滚 | 区域性故障 | S1 |
| R9 | 遥测隐私 | 合规 / 信任风险 | 字段白名单、可关闭、保留期、无 PII | 聚合再识别 | S1 |
| R10 | WebView2 / OS 差异 | 健康自检误判 | 兼容矩阵；最低版本；灰度 | 老旧环境 | S1 |
| R11 | 磁盘 / 杀软拦截 | 安装失败 | 预检、签名、白名单指引、错误码 | 企业安全软件策略 | L1 / S1 |
| R12 | 方案过度工程 | 交付延期 | 按 B0 ~ B4 批次；P0 只做闭环必需；P1/P2 后置 | 功能延迟 | L0 |

---

## 10. 完成定义与治理

### 10.1 L0 完成定义

见 §5.7。补充治理要求：

1. 本文 `Last updated` 刷新；所有未关闭项在 §9 有状态与验收方式。
2. README 索引与阅读路径保持一致；文档间链接可解析，无失效引用。
3. 所有新增错误码、阈值、事件字段在 `CONFIGURATION.md` / 本文 / 代码三处一致。
4. 发布记录含四项签字与证据表；无证据不得宣称完成。

### 10.2 S0 / S1 完成定义

- S0：staging 全链路、负载、回滚、密钥演练、客户端 readiness C01 ~ C12 全通过。
- S1：灰度阶段门全通过；生产成功率 ≥ 99.5%；验签失败 0；回滚率 < 2%；数据事故 0；告警 / 值班 / 灾备就绪。

### 10.3 复盘与治理节奏

| 时点 | 动作 |
|---|---|
| 每个批次结束 | 对照 §5.5 退出条件；未达标不进入下一批 |
| 每次发布后 | 指标报告 + 失败复盘；更新 §9 风险 |
| 每个大版本前 | 回滚演练；密钥 / 证书有效期检查；E2E 回归 |
| 每季度 | 文档复核；索引与链接检查；依赖与 Tauri 插件升级评估 |

---

## 附录 A：证据锚点

| 类别 | 路径 / 事实 |
|---|---|
| 更新配置 | `verthys-tauri/src-tauri/tauri.conf.json`（回环端点、明文许可、公钥、禁止降级、passive） |
| 插件注册 | `verthys-tauri/src-tauri/src/lib.rs:322` |
| 插件依赖 | `verthys-tauri/src-tauri/Cargo.toml:184`；`Cargo.lock:3530-3533`（2.12.0） |
| 权限 | `verthys-tauri/src-tauri/capabilities/default.json:16` |
| 前端状态层 | `verthys-tauri/src/composables/useAppUpdater.ts` |
| 前端测试 | `verthys-tauri/src/composables/useAppUpdater.spec.ts`（7 条） |
| 安装闸门 | `verthys-tauri/src/components/modules/SecurityCenter.vue:471-542` |
| 锁库实现 | `verthys-tauri/src/session/security-session.ts:513`、`:580` |
| 错误契约 | `verthys-tauri/src/lib/verthys_error.ts:266` |
| 日志工具 | `verthys-tauri/src/utils/logger.ts` |
| 清单生成 | `scripts/make_updater_manifest.mjs:100-111` |
| 本机夹具 | `scripts/updater_server.mjs:145-163` |
| 构建脚本 | `build_production.ps1:427-638` |
| SBOM | `scripts/generate_sbom.mjs` |
| 版本同步 | `ci/sync_version.ps1` |
| 供应链门 | `ci/verify_vendor_hashes.ps1`、`.github/workflows/core.yml:81-85` |
| worker 就绪 | `verthys-tauri/verthys-worker/src/runtime/main_loop.rs:136-160` |
| 父进程等待 | `verthys-tauri/src-tauri/src/worker/session.rs:405`、`controller/worker_controller.rs:384-391` |
| 部署文档 | `docs/DEPLOYMENT.md:38-41`（漂移） |
| 发布文档 | `docs/RELEASE.md:7`（版本漂移） |
| 文档索引 | `docs/README.md:36-38`（引用缺失） |
| 依赖源码 | `tauri-plugin-updater 2.12.0` 的 `updater.rs` / `error.rs` / `config.rs` |
| 实际签名 | `build/updater/Verthys_4.1.3_x64-setup.exe.sig`（trusted comment 无版本） |
| 实际 PE 版本 | `Verthys_4.1.3_x64-setup.exe` FileVersion / ProductVersion = 4.1.3 |

## 附录 B：服务器 readiness 清单

见 [UPDATER_SERVER_DEPLOYMENT_PLAN.md](UPDATER_SERVER_DEPLOYMENT_PLAN.md) 第 2 节与第 14 节；本机阶段只需完成 C01 ~ C12 中与 L0 相关的项，其余在 S0 前完成。

## 附录 C：修订记录

| 版本 | 日期 | 变更 | 作者 |
|---|---|---|---|
| v1.0 | 2026-10-22 | 首次发布：12 项 ADR、Manifest v2、Rust 更新服务、本机 P0/P1/P2 任务、质量门、E2E 矩阵、服务器衔接 | K1Super |


