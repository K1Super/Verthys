# 版本号与命名规范

## 目的

约束“版本”在代码中的存在形式：版本号只描述**契约**，不描述**代码代际**。
文件名、目录名、模块名、内部符号不得承载 `v2/v3/v4` 之类的时间线信息。

## 三类版本

| 类别 | 示例 | 处置 |
| --- | --- | --- |
| 磁盘/协议格式契约 | 容器格式版本、ABI 版本、协议版本 | 保留为常量或数据字段，单点定义 |
| 冻结外部契约 | `Verthys_V4Unlock`、worker op `v4_module_status` | 保留原值，集中登记，不随内部改名变动 |
| 产品版本 | `VERSION`、安装包版本、用户可见文案 | 保留，按发布流程同步 |

## 唯一事实源

- C：`core/include/verthys_version.h`
  - `VERTHYS_API_VERSION`：C ABI 接口集版本
  - `VERTHYS_CONTAINER_FORMAT_VERSION`：容器磁盘格式版本
- Rust 主进程：`src-tauri/build.rs` 解析同一头文件，生成 `CORE_API_VERSION` /
  `CORE_CONTAINER_VERSION`。
- worker：构建脚本解析同一头文件，生成期望格式版本；禁止硬编码。
- 前端：只消费后端返回值，不复制版本数值。
- 发布脚本：`scripts/release/make_updater_manifest.mjs` 解析同一头文件。

版本常量只能在上表定义的唯一来源中出现 `#define`；其它文件只能引用。
`ci/check_version_naming.ps1` 在 CI 与发布预检中强制该规则。

## 命名规则

禁止：

- 文件名/目录名含 `_v2`/`_v3`/`_v4` 或 `v2_`/`v3_`/`v4_` 前缀。
- 目录段 `/v2/`、`/v3/`、`/v4/`。
- 内部函数、类型、宏、测试名含代际后缀（`*_v4`、`vty_v4_*`、`VTY_V4_*`）。
- 用版本号区分“当前实现”和“旧实现”。当前实现只有一份，直接使用能力名。

允许：

- 格式字段/常量名中的版本语义（`VERTHYS_CONTAINER_FORMAT_VERSION`）。
- 冻结 ABI 名（`Verthys_V4*`）与协议 op 字符串（`"v4_*"`）。
- 磁盘 magic 值、KDF 域分离字符串（如 `verthys/v4/...`）。
- 产品版本号与用户可见文案。

命名应以能力为准：`container/`、`crypto/`、`index/`、`api/`、`vty_module.c`、
`vty_keymanager.c`、`test_rollback.c`。

## 旧代策略

- 项目处于开发期，无历史用户；旧容器格式（V3/V2）已整体删除。
- 磁盘上遇到非当前格式文件一律 `fail-closed`，不迁移、不回退、不兼容。
- 禁止重新引入 `VERTHYS_V3_SUPPORT`、`verthys_core_legacy`、V3 schema 或
  legacy DLL；CI 守卫会拦截。
- 历史攻击样本如需保留，只能以二进制夹具形式存在，不得附带完整旧实现。

## 新增格式版本的流程

1. 在 `verthys_version.h` 更新 `VERTHYS_CONTAINER_FORMAT_VERSION`。
2. 在格式头/结构体中新增版本字段或使用既有字段，不新增代际文件名。
3. 旧格式按损坏拒绝；如确需迁移，单独评审并限定在明确的迁移模块内，
   迁移完成后删除迁移代码。
4. 同步更新发布兼容区间与测试基线。

## 冻结契约清单

- C ABI：`core/verthys.def` 中全部 `Verthys_*`（含 `Verthys_V4*`）。
- worker 协议 op：`verthys-worker/src/runtime/protocol.rs` 与 dispatch 中的
  字符串常量。
- 磁盘格式：`VTY_MAGIC`、版本字段、A/B 元数据布局、恢复码/模块槽布局。
- 以上契约改名必须单独评审并同步全部消费方（含独立 P2 服务与发布清单）。

## 历史文档

历史审计/整改快照已随旧代清理整体删除，不作为当前架构依据。当前架构以
`docs/ARCHITECTURE.md`、`docs/GLOSSARY.md`、`docs/REQUIREMENTS.md` 为准。
