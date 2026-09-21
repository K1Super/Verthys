# 需求规格说明（SRS/PRD）

> 定义 Verthys 私密数据管理器的功能需求（可验收）、非功能需求与范围外事项，作为验收与测试的唯一依据。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档依据 `DOCUMENTATION_CHECKLIST.md` 的 P0 需求层要求整合，素材来自 `archive/PROJECT_DOCUMENTATION.md` 与 `archive/应用功能全量核验报告.md`；每条功能需求均以代码实现位置佐证，可被命令或可观察现象验收。约定：版本 2.6.1；品牌仅 Verthys；容器扩展名 `.verthys`；公开符号前缀 `Verthys_`；环境变量前缀 `VERTHYS_`。

---

## 1. 背景与目标

Verthys 是一款 **Windows 首发、可跨平台的本地高安全桌面私密数据管理器**，采用 Tauri + Vue3 轻量化架构，基于 Argon2id、XChaCha20-Poly1305、AES-256-GCM 等商用级加密体系，加密存储账号密码、私密照片、证书、文件等敏感数据。数据仅以密文落地，无明文缓存残留；密钥由 CNG 内核托管，容器采用 V3 格式（分区认证 + 内容寻址 Extent + LSM 索引 + 超级块法定人数提交）。

**目标**：抵御同机非特权用户态攻击者（恶意软件、浏览器漏洞落地 payload），达到"民用最高安全水位"；核心安全逻辑收敛在 `verthys.dll`（C11），密钥明文只在受限栈帧瞬态存在。

| 维度 | 边界 |
|---|---|
| 技术栈 | 核心 C11 DLL（MSVC）+ Tauri(Rust) + Vue3/TypeScript |
| 容器格式 | V3（FlatBuffers schema 驱动），`.verthys` |
| 版本 | 2.6.1 |
| 威胁模型 | 同机非特权用户态攻击者（严于普通桌面应用） |

---

## 2. 用户角色与场景

| 角色 | 说明 |
|---|---|
| **普通用户（终端使用者）** | 用 Verthys 存储日常账号/照片/文件，创建与解锁保险库，执行增删改查 |
| **安全管理员（高安全诉求）** | 配置安全预设、设备绑定、USB 安全影子、隐私模式，关注防御闭环状态 |
| **开发者/集成者** | 通过 C ABI 与 Tauri 桥接集成或审计，关注接口契约与测试 |

典型场景（角色 × 场景）：

1. **普通用户**：首次新建保险库（`verthys_create`）→ 录入账号/照片 → 锁定/解锁 → 导出备份。
2. **安全管理员**：配置 SECURE 预设 + 设备绑定 → 观察 SecurityDashboard 防御闭环 7 路径 → 启用剪贴板隔离与 USB 影子。
3. **开发者**：本地构建 `scripts/build_core.dev.ps1` → 跑 `verthys_tests.exe` 全量 → 对照 `CORE_API.md` 调用 29 个导出符号。

---## 3. 功能需求清单

> 每条含「描述 / 验收标准（可执行命令或可观察现象）/ 实现佐证路径」。实现佐证统一以 `core/`、`verthys-tauri/` 为相对根。

### FR-01 新建保险库

- **描述**：通过安全预设创建新 `.verthys` 容器，路径不存在才允许，创建即完成解锁，Argon2id 参数按预设/校准写入超级块。
- **验收标准**：前端 SecurityCenter 新建成功后进入 management 态；C 层对已存在路径返回 `VERTHYS_ERR_EXISTS`（0x4）。命令级：`verthys_tests.exe v3life` 全绿。
- **实现佐证**：前端 `src-tauri/src/controller/verthys_controller.rs`(verthys_create) → worker `verthys-tauri/verthys-worker/src/runtime/dispatch.rs`(`create_with_preset`) → C `core/src/api/lifecycle/verthys_v3_lifecycle.c`。

### FR-02 打开/解锁保险库

- **描述**：解锁已有容器，pepper 快速失败 → `.vsec` 验签 → 解锁流水线 S0-S6；非 V3 文件在 C 层 open 即拒绝（`VERTHYS_ERR_FORMAT`）。
- **验收标准**：解锁成功进入 management 态并可读记录；非 V3 容器返回 `VERTHYS_ERR_FORMAT`（0x5）。
- **实现佐证**：`core/src/api/unlock/verthys_unlock_pipeline.c` + `core/src/api/lifecycle/verthys_v3_lifecycle.c` + `core/src/api/lifecycle/verthys_api.c`。

### FR-03 渐进式解锁

- **描述**：`VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST`（0x04）下，超块+密钥+分区表完成后即返回 `VERTHYS_ERR_PARTIAL_UNLOCK`，索引预热转后台。
- **验收标准**：解锁中途态返回 `0x11`（PARTIAL_UNLOCK），worker/前端按成功分支处理，后台完成预热。
- **实现佐证**：`core/include/verthys.h`(flags bit2) + `dispatch.rs`(PARTIAL_UNLOCK 按成功处理) + `verthys.ts`(has_global_key 三字段内联探测)。

### FR-04 解锁进度回传

- **描述**：解锁各阶段经进度回调异步推送，防止前端"卡死"错觉。
- **验收标准**：解锁过程前端可见 8 阶段进度回调推进至 100%；注册 `NULL` 回调可取消通知。
- **实现佐证**：`core/src/api/progress/verthys_progress.c/.h` + `Verthys_RegisterUnlockProgressCallback`（verthys.h）。

### FR-05 预热加速

- **描述**：支持解锁前预热索引与持久化温缓存加载，加速二次解锁。
- **验收标准**：预热后解锁走内存映射零拷贝路径；`Verthys_GetDiagnostics` 上报 `preheat_status` 与 `page_cache_hit_ratio`。
- **实现佐证**：`core/src/index/warmcache/verthys_warmcache_v3.c` + `verthys_api.c`(预热位透传)。

### FR-06 全局密钥初始化/验证/修改

- **描述**：全局主密钥（GMK）生命周期——首次派生、验证、修改；GMK 永不出 worker 子进程。
- **验收标准**：`verthys_derive_global_key`/`verthys_verify_global_key`/`verthys_change_password` 命令真实实现；验证器常量 `VERTHYS_GLOBAL_KEY_VERIFIER_v2__`（32B）。
- **实现佐证**：`verthys-tauri/verthys-worker/src/runtime/gmk.rs` + `verthys-tauri/src-tauri/src/controller/key_controller.rs` + `core/src/api/transfer/verthys_export_import.c`(ChangePassword)。

### FR-07 模块子密钥派发

- **描述**：按模块域派生独立子密钥（HKDF `verthys/module/`），经 GMK 隔离，模块级增删改开关。
- **验收标准**：`verthys_derive_subkey` 命令返回模块独立密钥；登出走 `verthys_clear_global_key`。
- **实现佐证**：`key_controller.rs`(derive_module_subkey) + `gmk.rs`(MODULE_INFO_PREFIX) + `core/src/crypto/keymanager/keymanager.c`。

### FR-08 设备绑定

- **描述**：容器与机器绑定，指纹 = SHA-256(CPU+主板+磁盘 组合)，支持 partial_match 权重语义。
- **验收标准**：换机打开返回设备不匹配状态；`check_device_binding` 按权重判定。
- **实现佐证**：`verthys-tauri/src-tauri/src/infrastructure/device_fingerprint.rs` + `device_controller.rs` + `core/src/security/layer3_hw_binding/hardware_binding.c`(MachineGuid)。

### FR-09 会话倒计时与立即锁定

- **描述**：会话超时自动锁定；立即锁定清空敏感内存并刷盘，进程可恢复。
- **验收标准**：倒计时归零触发锁定；lockAll 期间防 UI 重入；`verthys_lock_persist` 完成刷盘。
- **实现佐证**：前端 `SecurityCenter.vue`(startSessionTick/lockAll) + `core/src/api/lifecycle/verthys_api.c`(Lock)。

### FR-10 磁盘级持久化验证

- **描述**：持久化落盘后经独立只读句柄回读验证，防"写入成功但盘面损坏"假象。
- **验收标准**：`verthys_verify_disk_persist` 命令回读校验通过才返回成功。
- **实现佐证**：前端 `verthys.ts`(verthys_verify_disk_persist) + Rust `verthys_controller.rs`。

### FR-11 安全预设（三档+自定义）

- **描述**：BALANCED/SECURE/PERFORMANCE/CUSTOM 三档预设+自定义，双缓冲原子切换，防重复守卫。
- **验收标准**：`VerthysPreset` 枚举 4 值；`applyPreset` 重复应用被守卫拒绝；预设持久写入超级块。
- **实现佐证**：`core/src/security/preset/security_preset.c` + 前端 `usePreset.ts`。

### FR-12 隐私模式与剪贴板隔离

- **描述**：隐私模式加密剪贴板（partial_protection 语义），锁定/超时清空剪贴板。
- **验收标准**：`set_privacy_mode`/`clear_clipboard`/`restore_privacy_mode` 命令真实实现。
- **实现佐证**：`verthys-tauri/src-tauri/src/controller/clipboard_controller.rs` + `verthys-tauri/src-tauri/src/security/clipboard_guard.rs`。

### FR-13 USB 安全影子

- **描述**：USB 设备读序列号、注册、克隆检测、影子休眠/恢复/清除/状态，7 命令全链路。
- **验收标准**：`security_usb_*` 7 命令（read_serial/register_device/check_clone/shadow_sleep/try_recover/purge/shadow_status）全部实现。
- **实现佐证**：`verthys-tauri/src-tauri/src/security_commands/commands/usb.rs` + 前端 `verthys.ts`(1460-1505)。

### FR-14 防御闭环状态查询（安全中心）

- **描述**：`Verthys_GetSecurityStatus` 每次调用 RUNTIME 级实时复检 7 条攻击路径，前端 SecurityDashboard 60s 轮询展示。
- **验收标准**：worker `security_status` op → Rust `verthys_security_status` 命令 → 前端 `verthysGetSecurityStatus()` 四层接通；7 路径 × 4 态展示。
- **实现佐证**：`core/src/security/layer6_closure/defense_closure.c` + `verthys_api.c`(GetSecurityStatus) + 前端 `useDefenseStatus.ts`。

### FR-15 记录增删改（账号/证书/文件/照片）

- **描述**：四类业务记录的增删改与上传，统一 AddRecord + persistVerthys 一致性模式。
- **验收标准**：AccountVerthys/CertManager 增删改均立即落盘；FileVerthys 上传磁盘级验证；PhotoAlbum 解析后导入。
- **实现佐证**：前端 `AccountVerthys.vue`、`CertManager.vue`、`FileVerthys.vue`、`PhotoAlbum.vue` → `verthys_add_record` → `core/src/api/lifecycle/verthys_api.c`(AddRecord)。

### FR-16 导出/导入

- **描述**：导出为独立加密交换信封（可设独立密码，不继承应用胡椒）；导入合并为一个事务。
- **验收标准**：`verthys_export`/`verthys_import` 命令实现；导出 >65535 条返回 `VERTHYS_ERR_EXPORT_TOO_MANY`（0xD）。
- **实现佐证**：`core/src/api/transfer/verthys_export_import.c` + `core/src/container/format/verthys_format.c`(交换信封)。

### FR-17 修改主密码

- **描述**：仅重加密数据密钥（不重加密业务数据），改密经 VsbTxnV3 法定人数保护。
- **验收标准**：`verthys_change_password` 命令实现（command 2013、worker op 474）；改密后旧密码解锁失败、新密码成功。
- **实现佐证**：`core/src/api/transfer/verthys_export_import.c`(Verthys_ChangePassword) + `core/src/container/superblock/verthys_superblock_v3.c`。

### FR-18 完整性校验

- **描述**：全量遍历 AEAD 标签 + 哈希校验，输出损坏 lid 列表，禁止与写并发。
- **验收标准**：`Verthys_VerifyIntegrity` 输出损坏计数；篡改容器后校验能识别。
- **实现佐证**：`core/src/api/lifecycle/verthys_api.c`(VerifyIntegrity) + `core/src/container/extent/verthys_extent.c`(读路径三重校验)。

### FR-19 全量/摘要扫描

- **描述**：全量（解密）与摘要（仅元数据）双扫描游标，绑定事务快照，快照过期重建。
- **验收标准**：`verthys_scan_*`/`verthys_scan_summary_*` 前端封装齐全；游标关闭释放全部资源。
- **实现佐证**：`core/src/api/scan/verthys_scan.c` + `verthys_controller.rs`/`scan_controller.rs`。

### FR-20 worker 生命周期与启动预检

- **描述**：worker 子进程 init、健康检查、自动恢复、残留清理；启动时解析 worker/DLL、校验架构与依赖完整性。
- **验收标准**：worker 异常退出后自动恢复；启动预检失败给出明确错误；陈旧 worker 被清理。
- **实现佐证**：`verthys-tauri/src-tauri/src/controller/worker_controller.rs` + `verthys-tauri/src-tauri/src/state/worker_lifecycle.rs`。

### FR-21 密码工具

- **描述**：密码生成器（默认 16 位无符号）、安全评估（Argon2id 凭证串）、随机令牌、密钥生成 + 导出 .bin。
- **验收标准**：前端 PasswordTools 生成/评估/导出可用；导出 .bin 走 `write_user_file` raw IPC。
- **实现佐证**：前端 `PasswordTools.vue` + `file_controller.rs`(write_user_file)。---

## 4. 非功能需求清单（NFR）

> 由 `docs/ENGINEERING_CONSTRAINTS.md` 转化而来，括号内标注对应条款号。

### NFR-01 密码学算法安全（刚性条款 2.1）

- **要求**：禁止 MD5（作为密码哈希）、SHA-1（签名）、明文存储密码等已废弃算法。
- **现状佐证**：口令派生 Argon2id；AEAD XChaCha20-Poly1305 / CNG AES-256-GCM；完整性 HMAC-SHA256 + BLAKE2b-256；设备指纹 SHA-256（`device_fingerprint.rs:79-84`）。全库无 MD5/SHA-1 密码学用途。
- **验收**：`grep -ri "md5\|sha1" core/src` 无密码学调用点（仅注释/第三方宏名）。

### NFR-02 敏感信息禁止硬编码（刚性条款 2.1）

- **要求**：密钥、口令、令牌不硬编码于代码/配置；域分离标签唯一、校验。
- **现状佐证**：CNG 内核托管密钥（用户态仅句柄）；GMK 以 `Zeroizing` 持有；`verthys_secure_zero` 全库贯彻。
- **验收**：审计代码无明文密钥常量（pepper 内嵌为已声明兜底取舍，见 `archive/PROJECT_DOCUMENTATION.md` §17.3）。

### NFR-03 全链路入参校验（刚性条款 2.1 / 3.4）

- **要求**：外部输入（文件、参数、网络）校验净化，防范注入/路径遍历/越界。
- **现状佐证**：解析纪律 HMAC→AEAD→flatcc verifier 三层纵深 + 回绕安全分解（`verthys_container_v3.h`、`verthys_extent.c`）。
- **验收**：fuzz 5 目标（superblock/partition/extent/sstable/import）冒烟零崩溃。

### NFR-04 核心逻辑单元测试覆盖率 ≥ 80%（刚性条款 1.4）

- **要求**：核心逻辑单元测试覆盖率不低于 80%。
- **现状佐证**：`core/tests/` 六子域镜像 + `test_v3_property.c` 属性测试；全量 250/250 通过。
- **验收**：`powershell -ExecutionPolicy Bypass -File scripts/build_core.dev.ps1 -NoPause` 全绿；`verthys_tests.exe` 出口码 0。

### NFR-05 关键接口常规负载 P95 ≤ 200ms（刚性条款 1.4）

- **要求**：关键接口常规负载 P95 延迟 ≤ 200ms（允许显式定义阈值）。
- **现状佐证**：持久化缓存/预取/扫描摘要路径；`Verthys_GetDiagnostics` 暴露耗时指标。
- **验收**：`core/tests/perf/test_perf_baseline.c` 通过；解锁整体 ≤ 2.5s（M2 基准）。

### NFR-06 无 OWASP Top 10 高危 / 并发无竞争（刚性条款 1.4）

- **要求**：无 OWASP Top 10 高危；并发场景无数据竞争与死锁。
- **现状佐证**：FFI 单线程语义 + SRWLOCK 单写者；ASAN/UBSAN CI 门；`/sdl`/`/guard:cf`/`/CETCOMPAT` 加固。
- **验收**：ASAN 全量通过（`-DVERTHYS_ENABLE_ASAN=ON`）。

### NFR-07 关键路径结构化日志与调用记录（刚性条款 1.4 / 3.6）

- **要求**：关键节点异常记录结构化日志；外部依赖调用记录耗时/结果状态。
- **现状佐证**：应急三级（TELEMETRY/DEGRADE/KILL）信号模型 + 审计日志（AEAD 保护）。
- **验收**：`Verthys_GetDiagnostics`/`Verthys_GetSecurityStatus` 可观测出口存在。

### NFR-08 平台与工具链兼容

- **要求**：Windows x64 首发，架构预留跨平台；工具链 VS 2026 / MSVC 14.51。
- **现状佐证**：`CMakeLists.txt`（C11，MSVC）+ Tauri NSIS 打包；`cmake/VerthysHardening.cmake`。
- **验收**：Release 构建产出 `build/core/Release/verthys.dll` 且 `dumpbin -exports` 与 `ci/export_baseline.txt` 29 符号逐一相等。

### NFR-09 导出面最小化

- **要求**：导出面唯一由 `.def` 白名单管控，无全量导出。
- **现状佐证**：`core/verthys.def` 29 符号 = `ci/export_baseline.txt`；`VERTHYS_API` 为空宏。
- **验收**：`dumpbin -exports build/core/Release/verthys.dll` 数出 29 个导出。

---

## 5. 范围外事项（本项目不做什么）

| 项 | 说明 |
|---|---|
| V1/V2 旧容器迁移 | 彻底抛弃旧容器，只认 V3，不提供 `.vault`/旧魔数迁移路径（方针见 `archive/应用功能全量核验报告.md` §7） |
| 内核态/硬件攻击防护 | 威胁模型止于"内核之下"；驱动级恶意软件、DMA/冷启动不在防护范围 |
| 云同步/多端协作 | 本地单机私密数据管理器，不提供云存储、多设备实时同步 |
| 密码找回 | 忘记主密码无法恢复（零知识设计，无后门） |
| 移动端/Web 版 | 当前仅 Windows 桌面（Tauri + NSIS） |
| 旧版 `.vault`/`valt://`/`VALTCORE_*`/`Vault_*` 兼容 | 上述旧标识一律不识别，仅允许出现在历史/迁移语境 |

> 更多版本间迁移与 breaking changes 见 [MIGRATION.md](MIGRATION.md)。