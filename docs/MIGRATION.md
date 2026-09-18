# 升级与迁移（MIGRATION）

> 说明 V1/V2→V3 与 2.5.x→2.6.x 品牌整改的升级迁移、breaking changes 与旧数据处置方式。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档整合 `archive/V3_UPGRADE_PLAYBOOK.md`、`archive/应用功能全量核验报告.md`、`archive/Verthys品牌整改验证交付报告.md` 并对照当前代码（2.6.1）修正。结论以代码现状为准。

---

## 1. V1/V2 → V3 迁移总览

**旧版本不再支持，无迁移路径。** 声明如下：

- V3 是唯一容器格式；V1/V2 旧容器（B+ 树 + 槽位池 + Merkle 迁移链）已按「彻底抛弃旧容器、只认 V3」方针整链删除（删除清单见 `archive/V3_UPGRADE_PLAYBOOK.md` §1.4）。
- V1/V2 迁移相关 API（`Verthys_MigrateV1ToV2`/`verthys_detect_format`/`verthys_rebuild_merkle` 等）已从导出面与四层链路移除，无任何应用内迁移或降级读写路径（`archive/应用功能全量核验报告.md` §7 P1-1/P2-2）。
- 旧数据如需保全，只能通过**导出/导入交换信封**（`Verthys_Export`/`Verthys_Import`）在旧版本仍可运行时导出、再导入新容器；代码库内无独立转换工具（核验报告 §8 边界声明 3）。

---

## 2. 2.5.x → 2.6.x 品牌迁移（Breaking Changes）

品牌重塑（`git 610bf4c`）引入下列不兼容变更，每条附迁移动作：

| 变更项 | 旧值 | 新值 | 迁移动作 |
|---|---|---|---|
| 容器扩展名 | `.vault` | `.verthys` | 旧 `.vault` 无法识别；新建容器使用 `.verthys`；旧文件按 §4 处置 |
| 事件 scheme | `valt://` | `verthys://` | 外部深链/监听器改用 `verthys://`，`valt://` 不再触发 |
| 环境变量前缀 | `VALTCORE_*`/`VAULT_*` | `VERTHYS_*`（`VERTHYS_VS_ROOT`/`VERTHYS_CMAKE_EXE`/`VERTHYS_CL_EXE`/`VERTHYS_VS_GENERATOR`） | 清理旧 `VALTCORE_*`/`VAULT_*`，改设 `VERTHYS_*` |
| 公开导出符号 | `Vault_*` | `Verthys_*`（29 个） | 集成方按名解析/声明改为 `Verthys_*`（见 `CORE_API.md`） |
| DLL 产物 | `valtcore.dll` | `verthys.dll` | 部署/引用改 `verthys.dll`；`build.rs` 哈希固化对象随之更新 |
| crate 命名 | `valt-tauri` / `vault-worker` | `verthys-tauri` / `verthys-worker` | 依赖路径、二进制名（`binaries/verthys-worker-*`）更新 |
| CMake target | `vault_core`/`vault_tests` 等 | `verthys_core`/`verthys_tests` | 构建脚本/CI 引用更新 |
| 容器魔数 | `VALT`（0x54 4C 41 56） | `VERT`（0x56 45 52 54） | 旧魔数文件视同不可读，需新建 |
| 域密钥前缀 | `valtcore/…`（.vsec/机器绑定/胡椒/CNG AAD/GMK 验证器） | `verthys/…` | 旧域密钥/旧 pepper 失效，首次启动重建 |

---

## 3. 数据兼容性声明（2.6.1 现状）

- **旧容器文件不可打开**：磁盘上旧 `.vault`、旧魔数（VALT）的 `.verthys`、以及品牌改名前的 `.verthys` 一律无法打开（`archive/Verthys品牌整改验证交付报告.md` §五.2），需新建容器。
- **旧 pepper 已删除**：按「抛弃旧密钥域」方针删除 `%APPDATA%\Verthys\pepper.bin` 旧域文件，首次启动自动重建（OS 托管 + 恢复卡 + 编译内嵌三级来源）。
- **全局密钥库/恢复卡需重新初始化**：GMK 验证器常量已更新（`VERTHYS_GLOBAL_KEY_VERIFIER_v2__`，32B，`gmk.rs`）。
- **旧状态文件失效**：`STATE_LEGACY_MAGIC_V1`（dead_code 只读回退）不再匹配旧磁盘状态，旧状态文件视为无效并重新初始化（`src-tauri/src/constants.rs`）。
- **结论**：2.6.1 对 2.5.x 及更早版本**不提供数据自动迁移**；数据迁移只能经旧版导出 → 新版导入完成。

---

## 4. 升级步骤

1. **导出旧数据（若旧版本仍可运行）**：在旧版中通过导出功能将需保留的数据导出为独立加密包。
2. **备份**：备份旧 `.vault`/`.verthys`、旧 `pepper.bin`、旧状态目录（`%APPDATA%\…`），供误删恢复。
3. **卸载旧版**：经 NSIS 卸载器卸载旧客户端（ValtCore/旧 2.5.x）。
4. **清理旧环境**：清除 `VALTCORE_*`/`VAULT_*` 环境变量与旧状态文件（避免残留旧域文件与新域冲突）。
5. **安装新版**：安装 Verthys 2.6.1（NSIS 包，含 `verthys.dll` 与 `verthys-worker`）。
6. **新建容器并重新初始化**：新建 `.verthys` 容器（旧容器不识别）；重新初始化全局密钥、设备绑定、安全预设。
7. **导入数据**：将步骤 1 导出的加密包导入新容器。
8. **验证**：解锁 → 记录可见 → `Verthys_VerifyIntegrity` 通过 → SecurityDashboard 防御闭环 7 路径展示。

---

## 5. 常见迁移问题

症状、原因、排查步骤与解决方法见 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)。常见项包括：打开旧 `.vault` 提示格式错误（属预期，无迁移）、pepper 来源错误（`VERTHYS_ERR_PEPPER_SOURCE`）、旧环境变量仍被脚本引用导致构建/运行异常等。

> 品牌整改与 V3 升级的完整变更清单见 `archive/Verthys品牌整改验证交付报告.md`（§二）与 `archive/V3_UPGRADE_PLAYBOOK.md`（§1.4、E-8）。