# Verthys 品牌整改验证交付报告

| 项目 | 内容 |
|---|---|
| 报告日期 | 2026-09-19 |
| 报告版本 | v1.0（零出错复验版） |
| 整改主题 | 品牌名 ValtCore/vault → Verthys 全量整改 |
| 验证范围 | C 核心（core）、Rust 主进程（verthys-tauri/src-tauri）、Worker 子进程（verthys-worker）、前端（Vue3+TS）、构建脚本、CI 基线 |
| 验证结论 | **零出错** —— 16 项验证维度全部通过 |
| 整体状态 | 可交付 |

---

## 一、执行摘要

本项目分两阶段完成品牌名整改（ValtCore → Verthys、vault → verthys），并在整改完成后执行了代码级、运行级、二进制级三层深度验证。全部验证通过：

- **core 全量测试：250 passed / 0 failed**（含容器全生命周期、LSM、事务崩溃恢复、属性测试）
- **端到端 FFI 冒烟**：worker 进程真实加载 verthys.dll，六层防御闭环初始化成功，协议响应正常
- **全仓残留归零**：git 跟踪源码 `(?i)vault` 零命中，VALT 魔数全变体零命中
- **部署二进制零残留**：DLL 与 Worker EXE 的 ASCII/UTF-16 全形态扫描 CLEAN

---

## 二、整改范围与变更清单

### 2.1 内容替换（第二阶段，9101 处）

| 替换轮次 | 形态 | 处数 |
|---|---|---|
| 1 | vault → verthys | 5945 |
| 2 | Vault → Verthys | 2898 |
| 3 | VAULT → VERTHYS | 243 |
| 4 | VALT → VERT | 16 |
| 定点规则 | 魔数/域密钥/CNG 标签等 | 22 条规则 |

### 2.2 定点修复的关键常量（22 条规则核心项）

| 常量 | 位置 | 新值 |
|---|---|---|
| 容器魔数 | verthys_format.c（写入+校验双侧） | `0x56 0x45 0x52 0x54`（"VERT"） |
| .vsec 域密钥 | integrity.c ↔ build_core.release.ps1 | `verthys/vsec-v1/` + 固定尾 16 字节（逐字节双侧一致） |
| 机器绑定域密钥 | hardware_binding.c | `verthys/machine-bind-v2` + 零填充 32B |
| 胡椒域密钥 | verthys_pepper.c | `verthys/pepper-fp-v1` + 零填充 32B |
| CNG 包装 AAD 前缀 | keymanager_cng.c ↔ test_cng_kernel.c | `verthys/wrap-v3`（15 字符 + NUL） |
| CNG 角色密钥 ID | keymanager_cng.c（4 行） | `verthys:{mek,keya,keyb,keyc}:v3` |
| LSM Bloom 种子 | verthys_lsm_sstable.c | `0x5645525433564C31`（"VERT3VL1"） |
| SHM/状态魔数 | constants.rs / shm 共享定义 | `VERTHYS_STATE` |
| GMK 验证器 | gmk.rs | `VERTHYS_GLOBAL_KEY_VERIFIER_v2__`（恰好 32 字节） |

### 2.3 命名整改

- **文件/目录**：152 个含 vault 命名的跟踪文件全部改名归零（vault-ui → verthys-ui、vault_controller.rs → verthys_controller.rs、vault_pepper.c → verthys_pepper.c 等）
- **CMake target**：vault_core / vault_core_obj / vault_tests → verthys_core / verthys_core_obj / verthys_tests
- **产物**：valtcore.dll → verthys.dll；crate valt-tauri → verthys-tauri、vault-worker → verthys-worker
- **协议**：容器扩展名 `.vault` → `.verthys`；事件 scheme `valt://` → `verthys://`；环境变量 `VALTCORE_*` / `VAULT_*` → `VERTHYS_*`
- **导出符号**：29 个 `Vault_*` → `Verthys_*`（verthys.def 唯一白名单）

---

## 三、验证方法与验证矩阵

### 3.1 代码级静态审计（逐字节比对，10 项全过）

| # | 验证项 | 方法 | 结果 |
|---|---|---|---|
| 1 | .vsec 域密钥双侧一致性 | 拆字符重建为字节序列与 PS1 hex 对照 | **逐字节一致** |
| 2 | 机器绑定/胡椒域密钥内容语义 | 解析 C 数组初始化项，重建字符串比对 + 零填充位置校验 | PASS |
| 3 | CNG 角色密钥 4 行内容 | 逐行重建字符串比对 | PASS |
| 4 | impl 与测试镜像一致性 | test_cng_kernel.c prefix 与 keymanager_cng.c WRAP_AAD_PREFIX 逐字节对照 | **字节相同** |
| 5 | 数组定长审计 | 全 core 扫描数字维度静态数组，项数 vs 声明 | overflow = 0 |
| 6 | 魔数矩阵全端一致 | C 写入端 / C 校验端 / Rust 校验端（controller.rs:415、state.rs:277,339）/ 测试端四方对照 | 全部 `56 45 52 54` |
| 7 | FFI 符号三向一致 | verthys.def（29）vs ci/export_baseline.txt（29）vs worker 实际加载（26） | def = 基线 ⊇ worker 加载 |
| 8 | 错误码镜像 | verthys.h 与 worker（protocol.rs/dispatch.rs/worker.rs）16 组 `VERTHYS_ERR_*` 数值对照 | **数值全部相同** |
| 9 | SHM/状态魔数 | constants.rs STATE_MAGIC + include! 共享单一事实源确认 | PASS |
| 10 | gmk.rs 定长常量 | `b"VERTHYS_GLOBAL_KEY_VERIFIER_v2__"` 字符计数 + `[u8;32]` 编译器强制 | 恰好 32 字节 |

> 说明：`VERTHYS_ERR_FORMAT` / `VERTHYS_ERR_INTERNAL` 在 worker 侧未镜像是原有 fallback 设计（未识别码统一回落 AUTH），本次整改仅改宏名前缀、数值未动，无影响。

### 3.2 运行级验证（真实执行，4 项全过）

| # | 验证项 | 结果 |
|---|---|---|
| 11 | core dev 全量重建 + ctest | **250 passed / 0 failed**（覆盖容器全生命周期、LSM 压缩/墓碑/影子、事务 commit/rollback/崩溃恢复、属性测试 2000 步不变式、六层防御闭环） |
| 12 | 端到端 FFI 冒烟 | worker EXE 真实加载 verthys.dll → 进程沙盒 mitigation（attrs=0x06）→ `Verthys_NotifySandboxAttrs` → `Verthys_Init`（六层防御闭环就绪）→ `{"ok":true,"op":"ping"}` |
| 13 | src-tauri build.rs 素材哈希门禁 | 强制重跑（touch build.rs）后**零警告**——verthys.dll 与 worker EXE 暂存哈希均与最新构建产物一致 |
| 14 | 前端构建 | vue-tsc --noEmit **0 errors** + vite build 成功（264 modules，产物全部 Verthys 命名） |

### 3.3 二进制级验证（字节扫描，3 项全过）

| # | 验证项 | 扫描模式 | 结果 |
|---|---|---|---|
| 15 | 部署二进制残留 | verthys.dll（407,040 B）与 worker EXE（354,304 B）：ASCII 全形态（vault/Vault/VAULT/VaUlT）+ UTF-16LE | **CLEAN** |
| 16 | 二进制品牌旧名 | ValtCore / valt-tauri / vault-worker（含 PDB 路径嵌入检查） | **CLEAN** |
| 17 | 全仓源码残留 | git grep 跟踪文件：`(?i)vault`、VALT hex 序列（`0x41,0x4C,0x54`）、`0x544C4156`、拆字符 `'V','A','L','T'`、VALT3VL1 | **零命中** |

**唯一允许的例外**：`verthys-worker/src/runtime/gmk.rs:28` 保留品牌重塑历史注释（`/// v2：品牌重塑（ValtCore→Verthys，8→7 字符）后…`），为有意保留的变更记录。

---

## 四、整改过程中发现并根治的缺陷

| 缺陷 | 根因 | 根治措施 |
|---|---|---|
| 双重 BOM（5 个文件） | 替换脚本 `UTF8.GetString` 保留 BOM 为 U+FEFF，写回时 `UTF8Encoding($true)` 再加 BOM | 全仓扫描修复，删除多余 3 字节 |
| C2078 编译错误 ×2 | 域密钥拆字符补零数多写一个（33 项超 [32]） | 精确修正零数，重跑构建通过 |
| 94/250 测试失败 | 域密钥变更后磁盘旧 pepper.bin 无法解包（来源错误 -2） | 按抛弃旧密钥域方针删除，250 全绿 |
| git 脏记录 | 生成物（target/appdata/build_dev/idx_cache，2300+ 文件）被跟踪 | 解除跟踪 + .gitignore 根治 |
| third_party 注释残留 ×3 | Flatcc.cmake/Libsodium.cmake 注释引用旧 target 名 | 定点修复为 verthys 命名 |

---

## 五、功能影响声明（域密钥与魔数变更的直接后果）

1. **旧 pepper 已按"抛弃旧密钥域"方针删除**，首次启动自动重建（OS 托管 + 恢复卡 + 编译内嵌三级来源）
2. **磁盘旧容器文件（VALT 魔数）无法打开**——含旧 `.vault` 与改名前的 `.verthys`，需新建容器；符合既定"彻底抛弃旧容器（V1/V2）、不做迁移"方针
3. **全局密钥库/恢复卡需重新初始化**（GMK 验证器常量已更新）
4. `STATE_LEGACY_MAGIC_V1`（dead_code 只读回退）不再匹配旧磁盘状态文件，旧状态文件视为无效并重新初始化——与上述方针一致，非缺陷

---

## 六、遗留事项（需人工处理）

| # | 事项 | 说明 |
|---|---|---|
| 1 | 根目录改名 | `Desktop\Project\ValtCore` → `Verthys`（改名后如遇构建脚本路径引用报错需同步修正） |
| 2 | git commit | 全部变更已暂存（1,691 条：rename 487 / add-modify 135 / delete 1068），待确认后提交 |
| 3 | 旧容器文件清理 | 磁盘上旧 `.vault` / 旧魔数 `.verthys` 文件已不可用，可手动删除 |

---

## 七、最终结论

品牌整改（ValtCore/vault → Verthys）已全量完成并通过三层 17 项深度验证：

- **代码级**：域密钥、魔数、FFI 符号、错误码等关键常量双侧/多侧逐字节一致
- **运行级**：250 项全量测试通过，端到端 FFI 链路真实可用
- **二进制级**：部署产物字节扫描零残留

**项目质量确认：品牌整改零出错，达到交付标准。**