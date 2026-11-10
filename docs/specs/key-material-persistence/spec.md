# 加密库机器密钥材料持久化与解锁 fail-closed Spec

## 1. 结论（已验证）

2026-11-11 00:56 的“打开加密库失败”不是口令、keyfile 或容器损坏，而是
`%LOCALAPPDATA%\com.verthys.app\container.secret` 被整目录删除后重新生成：

| 证据 | 来源 | 结论 |
| --- | --- | --- |
| `container.secret` CreationTime=2026-11-11 00:56:33 | `%LOCALAPPDATA%\com.verthys.app` | 文件在 00:56:33 才被创建，旧文件已不存在 |
| `%LOCALAPPDATA%\com.verthys.app`、`%APPDATA%\com.verthys.app` 创建时间均为 00:56:05/06 | 文件系统 | 两处应用数据根目录被整体删除重建 |
| 审计 HMAC 链首条为 00:56:06 | `%APPDATA%\com.verthys.app\audit.log` | 旧审计链随目录一并消失，证明确实发生整目录删除 |
| 58 条解锁审计零成功，均为先 `ERR_0000001A`（需 keyfile）后 `ERR_00000002`（AUTH） | 同上 | 库启用 keyfile，且设备槽认证失败 |
| `Vault.verthys` 头 `VRTY` v4 完整、59,185,489 字节；keyfile `VKFL` v1 完整 | `Desktop\.Verthys.V4` | 容器与 keyfile 未损坏 |
| 库文件最后写入 00:55:30；00:55:54 服务停止、00:56:04 服务重装 | 文件 mtime + Windows 事件日志 | 00:55:30–00:56:05 之间执行了卸载/安装 |
| 卸载器 `Delete the application data` 分支删除 `$APPDATA\com.verthys.app` 与 `$LOCALAPPDATA\com.verthys.app` | Tauri NSIS 模板生成脚本 | 机器密钥材料位于被删目录内，随卸载丢失 |

根因：

> v4 容器的设备槽由“本机 32 字节随机密钥（DPAPI 密封保存）+ OS 胡椒”派生。
> 该密钥材料原先存放在应用数据目录内。卸载时勾选“Delete the application data”
> 会整目录删除应用数据，密钥材料随之丢失；重新安装后应用生成新的随机密钥，
> 旧库设备槽永远无法解封，普通解锁固定返回 AUTH。恢复码通道不依赖该密钥材料，
> 是唯一的数据恢复路径；恢复后必须重绑本机设备槽才能恢复普通解锁。

## 2. 目标

1. 正常卸载（含勾选“Delete the application data”）后安装新版本，已有加密库仍可普通解锁。
2. 机器密钥材料与“可删除的应用数据”解耦；卸载、重装、应用数据清理不再破坏既有库。
3. 密钥材料缺失时解锁 fail-closed 并给出可执行指引（恢复码 + 重绑），不再静默生成新密钥、
   不再误报“打开加密库失败”，且不计入口令失败次数。
4. 不削弱安全边界：密钥仍为 DPAPI 绑定当前用户，复制到其他用户/机器仍不可解封。

## 3. 非目标

- 不改变 v4 容器格式、设备槽/恢复槽的密码学语义。
- 不改变恢复码、keyfile 的生成与验证规则。
- 不引入云备份、密钥托管或跨机迁移能力。
- 不处理 `background_patrol` 对第三方签名 DLL 的误报（已知风险，另行立项）。

## 4. 设计

### 4.1 密钥材料目录规则（`AppPaths`）

| 数据目录来源 | 主密钥材料目录 | 旧位置（仅迁移读取） |
| --- | --- | --- |
| `KnownFolder`（安装版默认） | `%LOCALAPPDATA%\Verthys\KeyMaterial` | `data_dir` |
| `CliArg` / `PortableFeature` / `ExeDirFallback` | `data_dir` | 无 |

理由：

- `%LOCALAPPDATA%\Verthys` 已承载锁存/回滚状态，属于机器安全状态目录，
  不在 `com.verthys.app` 应用数据目录内，卸载器不会删除。
- 便携/自定义数据目录模式必须自包含，密钥材料继续跟随 `data_dir`。
- 目录名与 `%APPDATA%\Verthys\pepper.bin` 的既有密钥材料布局一致。

### 4.2 读取与迁移（`container_secret`）

- `load_existing(dir)`：只读探测；文件不存在返回 `None`，绝不生成。
- `migrate_legacy(legacy, primary)`：校验旧位置可解封 → 以临时文件 + 原子 rename
  写入主位置 → 回读解封校验；**不删除旧文件**，保留为只读兜底。
- `restore_legacy(legacy, primary)`：主位置存在但不可解封时，用旧位置有效副本
  原子替换主位置（仅在主位置不可用时使用）。
- `load_or_create(dir)`：保持原有语义，仅创建新库时使用。

### 4.3 解锁策略（宿主）

- 普通解锁与会话内操作：只接受既有密钥材料。
  - 主位置可用 → 使用。
  - 主位置缺失、旧位置存在 → 迁移后使用。
  - 两者都不存在 → 返回稳定错误码 `E_KEY_MATERIAL_MISSING`，审计记为
    `Denied`，**不**调用 `record_auth_failure`，不触发口令熔断。
  - 主位置损坏、旧位置有效 → 恢复主位置后使用；两者都不可用 → fail-closed。
- 创建新库：允许生成新密钥材料（含旧位置迁移优先）。
- 恢复码通道：不读取密钥材料，行为不变。

### 4.4 卸载器（`installer-hooks.nsh`）

`NSIS_HOOK_PREUNINSTALL` 在服务卸载与文件删除之前：

1. 若主目录不存在密钥材料、旧位置存在 → 复制到
   `%LOCALAPPDATA%\Verthys\KeyMaterial\container.secret`。
2. 复制后校验目标存在；失败立即中止卸载并提示，避免“库保留但永久打不开”。
3. 勾选“Delete the application data”时显示一次明确提示：应用数据会删除，
   但机器密钥材料会保留在 `%LOCALAPPDATA%\Verthys\KeyMaterial`。

说明：旧版本（本次修复前安装的版本）的卸载器没有该钩子，无法追溯修复；
从旧版本升级到本版本时必须保证升级安装不勾选“Delete the application data”，
或在升级前完成一次密钥材料迁移（见 4.5）。

### 4.5 过渡保护

发布本版本后首次启动时，应用会自动把旧位置密钥材料迁移到主位置；
迁移为复制 + 校验，不删除旧副本。对已经丢失密钥材料的库，只能使用恢复码解锁，
随后在管理页“重绑本机设备槽”重新绑定当前密钥材料。

### 4.6 错误契约

- 新增稳定错误码 `E_KEY_MATERIAL_MISSING`。
- 前端文案：本机密钥材料已丢失，无法用普通方式打开该库；请使用恢复码解锁，
  并在恢复会话中重绑本机设备槽。
- 该错误不进入 `E_VERTHYS_UNLOCK_FAILED` 通用分支，避免被折叠为
  “打开加密库失败”。

## 5. 备选方案与否决理由

| 备选 | 结论 | 理由 |
| --- | --- | --- |
| 只改卸载器备份/恢复，不迁移目录 | 否决 | 用户手动清理应用数据、其他清理工具仍会破坏密钥材料；且备份/恢复窗口内崩溃会留下缺口 |
| 只迁移目录，不改卸载器 | 否决 | 从旧版本卸载时旧卸载器仍会删除旧位置密钥材料，升级路径无法覆盖 |
| 将密钥材料写入库文件同目录 | 否决 | 改变容器信任边界与便携语义；复制库到其他机器时密钥材料随行仍受 DPAPI 限制，收益低、迁移风险高 |
| 密钥材料缺失时自动生成并继续解锁 | 否决 | 掩盖数据丢失根因，制造“空库/失败”误判，且会让后续恢复更困难 |
| 密钥材料缺失时自动走恢复码 | 否决 | 恢复码不在应用内保存，无法自动完成；必须由用户提供 |

## 6. 风险与回滚

- 风险：首次迁移写主位置失败 → 拒绝解锁并保留旧副本，不产生新密钥。
- 风险：主位置损坏 → 尝试旧位置恢复；均失败则 fail-closed，不静默生成。
- 风险：卸载器复制失败 → 中止卸载（宁可保留安装，也不破坏库可达性）。
- 回滚：还原 `app_paths.rs`、`container_secret.rs`、`verthys_controller.rs`、
  `global-verthys.ts`、`verthys-error-i18n.ts`、`verthys_error.ts`、
  `installer-hooks.nsh` 与文档即可；已迁移的密钥材料无需回迁（新位置为超集副本）。

## 7. 验证计划

| 项 | 命令 / 操作 | 期望 |
| --- | --- | --- |
| Rust 单元测试 | `cargo test`（`verthys-tauri/src-tauri`） | 新增目录规则、只读探测、迁移、恢复用例通过 |
| 类型检查 | `npx vue-tsc --noEmit`（`verthys-tauri`） | 无新增错误 |
| 前端单元测试 | `npx vitest run`（`verthys-tauri`） | 全部通过 |
| Worker 链路 | `tests/e2e/worker-smoke.ps1` | 创建→锁定→恢复码→解锁全部 PASS |
| 迁移实测 | 删除主位置、保留旧位置后解锁 | 自动迁移并成功解锁，旧文件仍在 |
| 缺失实测 | 主位置与旧位置均不存在时解锁 | 返回 `E_KEY_MATERIAL_MISSING`，不生成新密钥，不计入熔断 |
| 卸载实测 | 安装后创建库→卸载勾选删除应用数据→重装→解锁 | 库可普通解锁；`KeyMaterial\container.secret` 保留 |
