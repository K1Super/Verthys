# Tauri 前后端桥接（Tauri Command / 事件 / 鉴权）
> Tauri 命令全量清单（76 个）、入出参、事件定义与权限边界，命令名以源码为准。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档列出 `verthys-tauri/src-tauri` 下全部 `#[tauri::command]`（共 **76** 个，与
`src/lib.rs` 的 `generate_handler!` 注册清单一致，`Select-String` 全量枚举结果为 76），
按控制器分组的入参/返回类型与职责、事件定义、权限与鉴权边界、前端调用封装位置。

## 1. 架构概述

- 主进程（Tauri UI）不加载 DLL、不持有 `VerthysHandle`；所有加解密/密钥/容器操作由
  **verthys-worker 子进程**执行，主进程经 `AppState::send()` 以 JSON 指令下发，响应内联返回。
  见 `CORE_API.md` 与 `ARCHITECTURE.md`。
- 命令注册：`src-tauri/src/lib.rs` 的 `.invoke_handler(generate_handler![...])`。
- 类型绑定：控制器层类型以 `ts-rs`（`#[derive(TS)] #[ts(export, export_to = "bindings/")]`）
  自动生成前端 TypeScript 绑定。
- 命令名即 Rust 函数名（snake_case，未设置 `rename_all`）；前端 `invoke` 入参键写 camelCase，
  Tauri 自动转 snake_case（见 `invoke_wrapper.ts` 注释）。

## 2. 错误约定（返回值结构）

控制器共存在三类返回约定：

1. **遗留统一信封 `VerthysResponse`**（`controller/types.rs`，已标记 deprecated）：
   `{ ok, op, id?, rtype?, name?, data?, error?, records?, summary_records?, exhausted?,
   shm_name?, shm_size?, record_count?, has_global_key?, global_key_id?, global_key_record?,
   security_status?, ids?, batch_id?, failed_indices?, hashes?, import_id?, processed_count?,
   total_count?, skipped_count? }`。
   失败时 `ok=false`、`error` 承载脱敏消息；成功时按 `op` 填充对应字段。
2. **结构化响应类型**（新代码，取代 `VerthysResponse`）：如 `PreflightResult`、
   `InitStatusResult`、`DeviceBindingResult`、`ClipboardResult`、`PrivacyModeResult`、
   `SecurityResult`、`AuthTokenResult`、`PresetConfig`、`BruteForceStatus`、
   `BruteForceCheckResponse`、`ShadowSleepStatus`、`CloneCheckResult` 等，均 `#[derive(TS)]`。
3. **统一错误信封 `ApiResponse<T>` / `ApiError` / `ErrorCode`**（`controller/api_error.rs`）：
   - `ApiResponse<T>`：`{ api_version: "2.0", ok, data?, error? }`。
   - `ApiError`：`{ code: ErrorCode, message: String, details? }`；`details` 标 `#[serde(skip)]`，
     仅日志用、**不**序列化到前端；`message` 为脱敏文案（不含路径/密码/密钥）。
   - `ErrorCode`（`SCREAMING_SNAKE_CASE` 序列化）：`DLL_NOT_FOUND / INTEGRITY_FAILED /
     DEPENDENCY_MISSING / SPAWN_TIMEOUT / READY_TIMEOUT / STILL_INITIALIZING / SHM_CORRUPTED /
     BINARY_ARCH_MISMATCH / BINARY_LOAD_FAILED / INVALID_PATH / PERMISSION_DENIED / FILE_TOO_LARGE /
     DISK_SPACE_INSUFFICIENT / DISK_SPACE_UNKNOWN / RATE_LIMITED / CLIPBOARD_MONITOR_FAILED /
     DEVICE_MISMATCH / DEVICE_UNBOUND / DEVICE_PARTIAL_MATCH / VERTHYS_LOCKED / VERTHYS_NOT_INITIALIZED /
     STATE_CORRUPTED / INVALID_PASSWORD / PASSWORD_COMPLEXITY_INSUFFICIENT / KEY_STATE_MISMATCH /
     TEMPORARY_FAILURE / INTERNAL`。

Rust 层命令的 `Result<T, String>` 中，`Err(String)` 即脱敏后的错误描述（直接作为 Tauri
`CommandError` 抛给前端）；不含内部细节（路径经 `sanitize_path` 处理，细节走日志）。

## 3. 事件定义（以源码真实字符串为准）

| 事件名 | 方向 | 载荷 | 触发位置 |
|---|---|---|---|
| `verthys://cleanup-and-exit` | 后端 → 前端 | `()`（无载荷） | `src/lib.rs`（`on_window_event` CloseRequested：隐藏窗口后通知前端 `lockAll` 异步清理） |
| `verthys://security-emergency` | 后端 → 前端 | `EmergencyPayload { signal, signal_name, fault_code, module_path, module_name, consecutive_count, ... }` | `src/security/background_patrol.rs`（常量 `EMERGENCY_EVENT_NAME`） |

- 前端监听：`src/composables/useWindowControls.ts` 中 `listen("verthys://cleanup-and-exit", ...)`（`@tauri-apps/api/event`）。
- `verthys://security-emergency` 由后端 `BackgroundPatrol` 检测到应急信号（如未知 DLL 注入）时 `app.emit` 推送；
  前端 listen 后执行辅助通知（熔断由后端直接执行），当前 `src/` 内未检索到对该事件名的显式 `listen` 调用。
- 进度类推流不经过全局事件，而是用 Tauri Channel（如 `verthys_unlock` 的 `on_progress: Channel<UnlockProgress>`、
  `verthys_add_records_batch` 的 `on_progress: Channel<ImportBatchProgress>`、
  `verthys_enumerate_records_stream` 的 `on_batch: Channel<EnumerateBatch>`）。---

## 4. 核心控制器命令（`src/controller/`，共 52）

所有 `app: tauri::AppHandle` / `state: State<'_, AppState>` 均为 Tauri 注入参数，表格省略。

### 4.1 `verthys_controller.rs`（20）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `verthys_init_status` | — | `Result<InitStatusResult, String>` | 查询初始化状态（none/initializing/ready/broken/maintenance + verthys_path） |
| `verthys_preheat` | `verthys_path: String` | `Result<VerthysResponse, String>` | 启动解锁前预热（索引/缓存预热） |
| `verthys_unlock` | `verthys_path: String, password: String, preheat_token: Option<String>, on_progress: Channel<UnlockProgress>` | `Result<VerthysResponse, String>` | 解锁容器；响应内联 `has_global_key/global_key_id/global_key_record`（消除 probe IPC） |
| `verthys_create` | `verthys_path: String, password: String, preset: Option<u32>` | `Result<VerthysResponse, String>` | 创建容器并解锁 |
| `verthys_lock_persist` | — | `Result<VerthysResponse, String>` | 锁定并持久化（v1 原子落盘 + 文件锁释放） |
| `verthys_lock` | — | `Result<VerthysResponse, String>` | 锁定容器（销毁会话守卫/释放文件锁） |
| `verthys_flush` | `_verthys_path: String, _password: String`（未使用） | `Result<VerthysResponse, String>` | 显式刷盘 |
| `verthys_verify_disk_persist` | `verthys_path: String, expected_record_count: Option<u64>` | `Result<VerthysResponse, String>` | 磁盘持久化完整性校验（预期记录数） |
| `verthys_add_record` | `rtype: u32, name: String, data_b64: String` | `Result<VerthysResponse, String>` | 新增单条记录 |
| `verthys_get_record` | `id: u64` | `Result<VerthysResponse, String>` | 按 ID 读完整记录 |
| `verthys_enumerate_records` | `start_id: u64` | `Result<VerthysResponse, String>` | 一次性枚举（自 start_id，超时 60s） |
| `verthys_enumerate_records_stream` | `start_id: u64, batch_size: u64, on_batch: Channel<EnumerateBatch>` | `Result<VerthysResponse, String>` | 流式分页枚举（Channel 推送，单批 ≤500） |
| `verthys_delete_record` | `id: u64` | `Result<VerthysResponse, String>` | 删除单条记录 |
| `verthys_delete_records` | `ids: Vec<u64>` | `Result<VerthysResponse, String>` | 批量删除（单事务） |
| `verthys_get_summary_count` | — | `Result<VerthysResponse, String>` | 摘要索引记录总数 |
| `verthys_has_record_by_type` | `rtype: u32` | `Result<VerthysResponse, String>` | 是否存在指定类型记录 |
| `verthys_export` | `export_path: String, password: String` | `Result<VerthysResponse, String>` | 导出加密包 |
| `verthys_import` | `import_path: String, password: String` | `Result<VerthysResponse, String>` | 导入外部容器 |
| `verthys_change_password` | `old_password: String, new_password: String` | `Result<VerthysResponse, String>` | 修改主密码 |
| `verthys_security_status` | — | `Result<VerthysResponse, String>` | 查询防御闭环 7 路径状态（`security_status` 字段） |

### 4.2 `scan_controller.rs`（8）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `verthys_scan_open` | `start_id: u64, batch_size: u64` | `Result<VerthysResponse, String>` | 打开全量扫描游标 |
| `verthys_scan_next` | `batch_size: u64` | `Result<VerthysResponse, String>` | 拉取下一批完整解密记录 |
| `verthys_scan_close` | — | `Result<VerthysResponse, String>` | 关闭游标 |
| `verthys_scan_abort` | — | `Result<VerthysResponse, String>` | 中止扫描 |
| `verthys_scan_summary_open` | `start_id: u64, batch_size: u64` | `Result<VerthysResponse, String>` | 打开摘要游标 |
| `verthys_scan_summary_next` | `batch_size: u64` | `Result<VerthysResponse, String>` | 拉取下一批摘要 |
| `verthys_scan_summary_close` | — | `Result<VerthysResponse, String>` | 关闭摘要游标 |
| `verthys_scan_summary_abort` | — | `Result<VerthysResponse, String>` | 中止摘要扫描 |

### 4.3 `verthys_batch_controller.rs`（5）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `verthys_import_begin` | `verthys_path: Option<String>` | `Result<VerthysResponse, String>` | 开启批量导入会话（WAL + 去重哈希基线） |
| `verthys_add_records_batch` | `records: Vec<BatchRecordInput>, on_progress: Channel<ImportBatchProgress>` | `Result<VerthysResponse, String>` | 单 IPC 批量写入 N 条（返回 ids/failed_indices/批处理统计） |
| `verthys_import_end` | `success: bool` | `Result<VerthysResponse, String>` | 结束导入会话并提交 |
| `verthys_import_checkpoint` | — | `Result<VerthysResponse, String>` | 查询当前导入检查点 |
| `verthys_wal_recover` | `verthys_path: Option<String>` | `Result<VerthysResponse, String>` | WAL 断点续传恢复 |

### 4.4 `key_controller.rs`（5）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `verthys_derive_global_key` | `password: String, bin_data_b64: String, bin_password: String` | `Result<VerthysResponse, String>` | 派生全局主密钥 |
| `verthys_verify_global_key` | `password: String, bin_data_b64: String, bin_password: String, record_b64: String` | `Result<VerthysResponse, String>` | 验证全局主密钥 |
| `verthys_derive_subkey` | `module_id: String` | `Result<VerthysResponse, String>` | 派生模块子密钥 |
| `verthys_clear_global_key` | — | `Result<VerthysResponse, String>` | 清除全局密钥（零化） |
| `verthys_reconcile_key_presence` | `has_global_key: bool` | `Result<VerthysResponse, String>` | 校正密钥存在状态（前后端一致） |

### 4.5 `file_controller.rs`（4）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `read_file_bytes` | `path: String` | `Result<tauri::ipc::Response, String>` | 白名单内读取文件，返回原始二进制（raw IPC，去 base64；≤50MB） |
| `write_file_bytes` | `request: tauri::ipc::Request<'_>` | `Result<(), String>` | 白名单内原子写入（raw body + `x-path` 头；≤50MB） |
| `read_user_file` | `path: String` | `Result<tauri::ipc::Response, String>` | 用户授权读取（对话框选文件，≤2GB） |
| `write_user_file` | `request: tauri::ipc::Request<'_>` | `Result<(), String>` | 用户授权写入（≤2GB，超时 120s） |

### 4.6 `clipboard_controller.rs`（3）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `set_privacy_mode` | `enabled: bool, auth_token: Option<String>` | `Result<PrivacyModeResult, String>` | 启用/关闭隐私模式（防截屏 + 剪贴板监听，启用返回 `session_token`） |
| `clear_clipboard` | — | `Result<ClipboardResult, String>` | 安全清空剪贴板 |
| `restore_privacy_mode` | — | `Result<PrivacyModeResult, String>` | 恢复隐私模式（退出后重设） |

### 4.7 `device_controller.rs`（3）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `get_device_fingerprint` | — | `Result<String, String>` | 采集设备指纹 |
| `set_device_binding` | — | `Result<(), String>` | 绑定当前设备 |
| `check_device_binding` | — | `Result<DeviceBindingResult, String>` | 校验设备绑定（match/mismatch/unbound/partial_match/error） |

### 4.8 `preflight_controller.rs`（1）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `verthys_preflight` | `verthys_path: String` | `Result<PreflightResult, String>` | 路径预检（白名单/写权限租约/磁盘空间/系统保护目录；错误脱敏） |

### 4.9 `diag_controller.rs`（1）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `diag_info` | — | `Result<DiagInfo, String>` | 诊断信息（worker/DLL 存在性、DLL SHA-256 前 16 字符、worker PID） |

### 4.10 `worker_controller.rs`（2）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `worker_init` | `_dll_path: String`（忽略，强制后端解析） | `Result<VerthysResponse, String>` | 启动 worker 子进程（DLL 完整性/加载校验） |
| `worker_destroy` | — | `Result<VerthysResponse, String>` | 销毁 worker 会话 |---

## 5. 安全防护命令（`src/security_commands/commands/`，共 24）

所有 `app: tauri::AppHandle` / `state: State<SecurityState>` 均为 Tauri 注入参数，表格省略。

### 5.1 `brute_force.rs`（6）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_brute_check` | — | `Result<BruteForceCheckResponse, String>` | 检查是否允许解锁（Allow/Locked{remaining_secs}/PurgeRequired） |
| `security_brute_record_failure` | — | `Result<BruteForceCheckResponse, String>` | 记录一次解锁失败 |
| `security_generate_auth_token` | `app_state: State<AppState>` | `Result<AuthTokenResult, String>` | 生成一次性权限令牌（32 字节 hex，抗重放） |
| `security_brute_record_success` | `app_state: State<AppState>, auth_token: Option<String>` | `Result<SecurityResult, String>` | 记录解锁成功（需 auth_token） |
| `security_brute_clear_purge` | `auth_token: Option<String>` | `Result<SecurityResult, String>` | 清空/校验（敏感，需 auth_token） |
| `security_brute_status` | — | `Result<BruteForceStatus, String>` | 暴力拦截状态快照（失败计数/剩余锁定时长） |

### 5.2 `session.rs`（3）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_session_start` | — | `Result<(), String>` | 启动会话守卫（监听系统锁屏，需真实 HWND） |
| `security_session_stop` | — | `Result<(), String>` | 停止会话守卫 |
| `security_session_set_high_security` | `enabled: bool, auth_token: Option<String>` | `Result<SecurityResult, String>` | 设置高安全会话（敏感，需 auth_token） |

### 5.3 `module_whitelist.rs`（3）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_module_patrol` | — | `Result<Vec<UnknownModuleInfo>, String>` | 模块巡检（返回未知模块列表） |
| `security_add_trusted_path` | `path: String, auth_token: Option<String>` | `Result<SecurityResult, String>` | 添加受信任路径（需 auth_token） |
| `security_clear_trusted_paths` | `auth_token: Option<String>` | `Result<SecurityResult, String>` | 清空受信任路径（需 auth_token） |

### 5.4 `cleanup.rs`（3）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_cleanup_recent` | — | `Result<(), String>` | 清理最近使用痕迹 |
| `security_secure_delete` | `logical_id: String, file_name: String, mode: String` | `Result<(), String>` | 安全删除（按逻辑标识 + 文件名 + 模式） |
| `security_cleanup_crash_residue` | — | `Result<usize, String>` | 清理崩溃残留，返回清理数量 |

### 5.5 `file_lock.rs`（1）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_harden_private_dir` | `logical_id: String` | `Result<(), String>` | ACL 加固私有目录（按逻辑标识） |

### 5.6 `usb.rs`（7）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_usb_read_serial` | `drive_letter: String` | `Result<String, String>` | 读取 USB 卷序列号 |
| `security_usb_register_device` | `volume_label: String, serial_hash: String, auth_token: Option<String>` | `Result<SecurityResult, String>` | 注册受信 USB（需 auth_token） |
| `security_usb_check_clone` | `volume_label: String, serial_hash: String` | `Result<CloneCheckResult, String>` | 检测 USB 克隆（卷标 + 序列号哈希比对） |
| `security_usb_shadow_sleep` | `encrypted_index_b64: String, txid: u64, timeout_min: u64` | `Result<(), String>` | 影子休眠（加密索引驻留 + 超时） |
| `security_usb_try_recover` | `txid: u64` | `Result<Option<String>, String>` | 尝试从影子休眠恢复（返回加密索引或 None） |
| `security_usb_purge` | — | `Result<(), String>` | 清除 USB 影子数据 |
| `security_usb_shadow_status` | — | `Result<ShadowSleepStatus, String>` | 影子休眠状态（in_shadow_sleep + 真实 txid） |

### 5.7 `preset.rs`（1）
| 命令名 | 入参（核心） | 返回 | 职责 |
|---|---|---|---|
| `security_get_preset_config` | `preset: u32` | `Result<PresetConfig, String>` | 查询三档预设配置（BALANCED/SECURE/PERFORMANCE + 特性开关） |

---

## 6. 权限与鉴权边界

### 6.1 一次性权限令牌（抗重放）
- 敏感命令 `security_brute_record_success` / `security_brute_clear_purge` /
  `security_session_set_high_security` / `security_add_trusted_path` / `security_clear_trusted_paths` /
  `security_usb_register_device` 接受 `auth_token: Option<String>`。
- 令牌由 `security_generate_auth_token` 生成（BCryptGenRandom，回退 SHA-256），`store_auth_token` 存储（上限 16 个防泄漏），
  `verify_and_consume_auth_token` 一次性验证后立即消费，防重放。
- 关闭隐私模式（`set_privacy_mode enabled=false`）要求匹配启用时下发的 `session_token`，防无凭据关闭。
- 部分命令（`set_privacy_mode`/`restore_privacy_mode`/`security_add_trusted_path` 等）开头校验
  `KeyLifecycle` 状态（见 `security_commands/state.rs` 与各命令开头校验逻辑）。

### 6.2 解锁态门禁（worker 侧）
- `verthys_*` 数据命令（add/get/delete/enumerate/export/import/change_password/scan/summary/flush 等）
  经 `AppState::send()` 下发给 worker；“未解锁不可操作”由 worker 内持有的 `VerthysHandle` 状态强制
  （对应 `CORE_API.md` 的 `VERTHYS_ERR_LOCKED`），主进程侧不重复代理校验。
- `verthys_init_status` 只读、可在解锁前查询；`verthys_preflight` 只做路径预检、无需解锁；
  `verthys_security_status` 对应 C 层锁定态可查询的进程级防御状态。

### 6.3 路径白名单与输入校验
- `preflight_controller`（第 3.1-3.9 项）：白名单基目录（用户目录/EXE 目录/非系统盘根）canonicalize 前缀校验；
  先校验后操作；原子租约（独占锁文件）消除 TOCTOU；写权限测试用 CSPRNG 随机文件名 + 重试；
  错误脱敏仅返回错误码（`INVALID_PATH/PERMISSION_DENIED/DISK_SPACE_INSUFFICIENT/DISK_SPACE_UNKNOWN/TEMPORARY_FAILURE`）；
  并发信号量（≤4）+ 5s 超时。
- `file_controller`：白名单内 canonicalize 校验 + 目录遍历/符号链接阻断；50MB/2GB 分档大小上限；
  原子写入（临时文件 + fsync + rename）；写操作全局互斥；错误脱敏走日志。
- `security_commands`（13.2.1）：文件系统命令不接收前端路径，改用逻辑标识
  （`verthys_dir/temp_dir/data_dir` 等），由后端 `path_resolver` 从受信上下文解析。

### 6.4 进程资源/完整性
- `worker_init`：强制后端解析 DLL 路径（忽略前端传入），先做 DLL 完整性（SHA-256）/加载校验；
  worker 进程启动后做“不可继承句柄”自检（`handle_factory::validate_no_inherited_handles`）。
- 启动期资源完整性：`resource_guard::verify_resource_hashes()`（release 阻断、dev 警告）。
- 平台沙盒属性经 `Verthys_NotifySandboxAttrs` 传递给 DLL。

---

## 7. 前端调用封装位置

| 文件 | 作用 |
|---|---|
| `verthys-tauri/src/utils/invoke_wrapper.ts` | 统一带超时的 `invoke` 包装 `invokeWithTimeout<T>(cmd, args?, timeoutMs?, options?)`；支持 raw body 直传与 `InvokeOptions.headers`（`x-path`） |
| `verthys-tauri/src/lib/verthys.ts` | 主业务 API 封装（IPC 接口统一入口，复用 `invokeWithTimeout`） |
| `verthys-tauri/src/lib/verthys_error.ts` | 前端错误类型/文案映射（`VerthysError`） |
| `verthys-tauri/src/lib/crypto.ts` / `keyManager.ts` | 前端侧加密/密钥管理（Web 侧派生，与后端 key_controller 对应） |
| `verthys-tauri/src/session/security-session.ts` | 安全会话客户端 |
| `verthys-tauri/src/composables/useWindowControls.ts` | `listen("verthys://cleanup-and-exit")` 与窗口控制 |
| `src-tauri/bindings/` | ts-rs 自动生成的前端类型绑定目录 |

前端 `invoke` 命令名 = Rust 函数名（snake_case）；入参对象键用 camelCase（Tauri 自动转 snake_case）。

---

## 8. 交叉引用

- C 层接口与错误码：`CORE_API.md`。
- 构建/配置（DLL 路径解析、worker 二进制、bundling）：`CONFIGURATION.md`。
- 依赖与供应链（ts-rs、Tauri 版本）：`THIRD_PARTY.md`。
- 安全设计与威胁模型：`SECURITY_DESIGN.md`。