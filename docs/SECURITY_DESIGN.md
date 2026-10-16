# SECURITY_DESIGN — Verthys 安全设计与信任模型

> 定义四层信任边界、密钥派生链路、哈希校验机制与威胁建模，供安全审计与应急处置参考。
>
> Last updated: 2026-09-28 · 维护人：K1Super

---

## 1. 信任边界

自底向上四条边界，密钥与明文只能单向向下沉降，任何一层不得向下层反授权。

```mermaid
flowchart TB
    subgraph T4["边界 4：持久化层（不可信磁盘/外设）"]
        V[" .verthys 容器 · pepper.bin · 附属数据目录 .d（idx_cache 等）"]
    end
    subgraph T3["边界 3：核心 DLL 层（信任根，进程内）"]
        C["verthys.dll<br/>api/crypto/container/index/transaction/security<br/>CNG 内核密钥托管"]
    end
    subgraph T2["边界 2：verthys-worker 子进程"]
        W["单线程 FFI · mitigation policy · 进程级沙盒"]
    end
    subgraph T1["边界 1：verthys-tauri 主进程 + 前端"]
        M["Rust 控制器 · Vue3 渲染"]
    end
    M -->|"JSON-lines（口令跨边界单向传递）"| W
    W -->|"C ABI（verthys.dll）"| C
    C -->|"AEAD 密文 / 原子写"| V
    V -->|"HMAC/AEAD 校验失败 → 应急熔断"| C
```

- 边界 1↔2：跨此边界的唯一敏感数据是**口令**（调用后即清零）；传输走子进程管道。
- 边界 2↔3：只有 `verthys.h` 白名单 ABI 可进入 DLL；worker 加载 DLL 前完成进程级 mitigation 与 DLL SHA-256 预检。
- 边界 3↔4：落盘一律密文（分区 AEAD + 超级块 HMAC + Merkle）；只读回验，篡改即报应急。
- 密钥与明文只存在于边界 3 内（且密钥主体在 CNG 内核态），上两层为“零密钥接触”。

## 2. 密钥存储与派生链路

### 2.1 V3 密钥层级（以 `keymanager.h`/`keymanager_cng.h`/`verthys_v3_lifecycle.c` 为准）

```mermaid
flowchart TB
    PW["L1 口令 password（用户输入，不落盘）"]
    DKM["L2 DKM = Argon2id(password ‖ pepper, salt, 超级块参数)<br/>32B 瞬时，派生后立即清零"]
    MEK["L3 MEK = HKDF-Expand(DKM, verthys/master-key-v3)<br/>32B，导入 CNG 内核后清零"]
    IK["integrity_key = HKDF-Expand(MEK, verthys/integrity-key-v3)<br/>32B，超级块/温缓存 HMAC 用"]
    ABC["L4 子密钥 A/B/C：各 32B 随机（OS CSPRNG）<br/>由 MEK 内核态 AEAD 包裹为 60B，存超级块"]
    PW --> DKM --> MEK
    MEK --> IK
    MEK -->|"内核态 wrap（12B nonce‖32B ct‖16B tag）"| ABC
```

- DKM 与 MEK 仅在解锁流水线 S2→S3 栈帧瞬态存在；`verthys_cng_aead_import_key` 是唯一允许密钥明文进入用户态栈帧的点，导入后 `SecureZeroMemory`。
- A/B/C 包装密钥经 CNG 内核态解包，解包输出为栈上瞬态，立即导入对应角色句柄并清零；进程终止时 CNG 自动回收内核态密钥，与“锁库即杀进程”语义一致。
- 记录级隔离：V3 数据经分区 B 密钥 AEAD 加密；v1/v2 遗留方案另派生 `record_key = HKDF(key_b, record_id)` 实现逐条隔离。

### 2.2 胡椒（pepper）三层来源

> `core/src/crypto/pepper/verthys_pepper.h` 定义；**编译内嵌胡椒为内部常量，本文档不抄录明文**，仅描述机制。

按优先级降序：

1. **注入胡椒**：调度层经 `verthys_pepper_inject` 从 OS 密钥存储（TPM/CNG/Keychain）注入，部署首选。
2. **OS 托管胡椒**：`verthys_pepper_load_from_os` 从 CNG 持久化机器密钥读取（TPM 绑定）；首次自动生成并持久化到 `%APPDATA%\Verthys\pepper.bin`（v2 布局 304B，含 `source_type` + `source_fingerprint`，机器密钥 RSA-OAEP 包裹，OAEP label = 硬件指纹）。解包失败 → 置来源错误，**禁止静默兜底**，解锁返回 `VERTHYS_ERR_PEPPER_SOURCE`（0x0C），提示“保险库安全源已变更”。
3. **编译内嵌胡椒**：确定性兜底常量，保证零配置可开箱（来源随容器记录于超级块 flags，解锁时校验一致性防漂移）。

胡椒恢复：`verthys_pepper_export_shamir / reconstruct_shamir`（GF(2^8) Shamir 秘密共享，threshold k-of-n）生成恢复卡分片。

### 2.3 机器绑定

`layer3_hw_binding` 三件套：`cng_machine_key`（CNG 持久化 RSA 机器密钥，wrap/unwrap 胡椒）、`hardware_binding`（system_instance 硬件指纹，作为 OAEP label 与跨设备校验依据）、`system32_loader`（系统目录优先加载）。跨设备迁移时胡椒解包认证失败 → 直接拒绝，对应防御路径 `CROSS_DEVICE`（见 §5）。

### 2.4 关于 “.vsec / .rhat”

澄清：`.vsec`（DLL 只读节，构建期签名基线）与 `.rhat`（DLL 只读节，运行时函数哈希表）是**完整性校验数据**，不是密钥存储；密钥的“拆分存储”体现为 V3 超级块内 `wrapped_key_a/b/c` 三份包装密钥与 3 副本超级块，而非文件级拆分。详见 §4 与 [ARCHITECTURE.md](ARCHITECTURE.md) §2.5。

### 2.5 文件记录口令派生（文件级 KDF，2026-09-28 收口）

文件（清藏）记录可设独立访问密码，采用**文件级派生**，与容器级密钥体系相互独立、不混胡椒：

- **派生**：`文件密钥 = PBKDF2(口令, 文件盐, 150000 次)`；文件盐 16B 随机、每文件派生一次
  （历史逐块盐形态的写入路径已删除，旧记录读取保持兼容）。
- **块布局**：`iv(12B) ‖ 密文+标签`（AES-256-GCM）；每块唯一 IV、同一文件密钥。
- **口令判定唯一化**：记录携带 `passwordCheck`（固定明文的一次 AEAD）。导出时先解密
  校验 `passwordCheck` 判定口令（错误即 `E_PWD_WRONG`，发生在选择保存位置之前）；
  数据块解密失败一律按数据损坏归类，不再以“全部块解密失败”推断口令错误。
- **oracle 边界**：`passwordCheck` 与数据块 AEAD 属同类认证界面，不新增可离线攻击的
  新界面；口令强度由 PBKDF2 迭代数与用户口令共同承担。历史记录（无校验块）导出时
  显示“密码错误或数据已损坏”合并提示并给出可执行引导。
- **去重键不含口令材料**：文件级去重键 = `BLAKE3(明文 ‖ 格式版本 ‖ 形态标志)`；
  会话日志为明文落盘，任何口令派生量入键即构成可离线爆破的验证器，故同内容不同
  口令共用一键（换口令需先删除原记录）。
- **内存上界**：导入分片读取上界 4MiB/次，块载荷在进程间层为 base64 但受批量预算
  约束（≤11.19MiB/批）；导入与导出内存占用与文件大小无关。

台账与回收的完整性语义（会话结算、GC 前置守卫、删除事务化）见 [DATA_FLOW.md](DATA_FLOW.md) §5
与 [ARCHITECTURE.md](ARCHITECTURE.md) §3.1。

## 3. 解锁流程数据流

以 `verthys_unlock_pipeline.h` 的 S0–S6 为准（与《解锁.md》一致）。

```mermaid
sequenceDiagram
    participant FE as 前端控制器
    participant MAIN as 主进程 worker_controller/verthys_controller
    participant WK as verthys-worker
    participant DLL as verthys.dll（unlock pipeline）
    participant OS as OS/CNG
    FE->>MAIN: invoke unlock(path, password)
    MAIN->>WK: {op:unlock}（stdin JSON）
    WK->>DLL: Verthys_Unlock(handle, path, pw, flags)
    DLL->>DLL: S0 前置检查（状态机/emergency 门控/pepper 快速失败）
    par S1 与 S2 并行
        DLL->>DLL: S1 读 3 副本超级块 + 无校验结构解析（50ms 预算）
        DLL->>DLL: S2 DKM=Argon2id(pw‖pepper,salt) → MEK=HKDF(DKM)
    end
    DLL->>OS: S3 CNG 批量导入 MEK/A/B/C（内核态句柄）
    DLL->>DLL: S3 3 副本 HMAC 验证 + 法定人数裁决
    DLL->>DLL: S4 分区表加载
    DLL->>DLL: S5 索引预热（温缓存优先，否则冷启动+WAL恢复）
    DLL->>DLL: S6 最终校验 + 状态切换
    DLL-->>WK: VERTHYS_OK（或 PARTIAL_UNLOCK）
    WK-->>MAIN: {op:unlock, ok:true}（stdout JSON）
    MAIN-->>FE: 解锁成功
```

## 4. 恶意软件哈希校验链路

两层互补（读 `security/integrity/integrity.c` 与 `runtime_hash.c/h`、`core/tools/rhash_gen.c`）：

```mermaid
flowchart TB
    subgraph A["A. 分发篡改校验（启动时，一次）"]
        A1["integrity_verify_startup()<br/>Verthys_Init 内调用"]
        A2["从磁盘重读自身 PE，重算 .text/.rdata 文件内容 HMAC"]
        A3["与 .vsec 只读节基准常量时间比对（v2 追加 .rhat 第三槽）"]
        A4["失配 → EMERG_SIG_INTEGRITY_FAIL → KILL"]
    end
    subgraph B["B. 运行时内存补丁校验（解锁后 + 周期性）"]
        B1["runtime_hash_verify()：解锁成功后立即一次"]
        B2["runtime_hash_verify_periodic()：每 30 分钟，写路径 API 入口"]
        B3["解析自身 .reloc，掩码重定位槽位后重算 32 关键函数 BLAKE2b"]
        B4["与 .rhat 节（VRHT 表，构建期 rhash_gen 补丁）比对"]
        B5["失配 → EMERG_SIG_PROCESS_TAMPER → KILL"]
    end
    A1 --> A2 --> A3 --> A4
    B1 --> B3 --> B4 --> B5
    B2 --> B3
```

- **校验什么**：A 校验 DLL 文件 `.text`/`.rdata`（含 `.rhat`）未能被替换/篡改；B 校验 32 个关键函数（加解密主路径、密钥组生命周期、轮换、超块事务、分区表、WAL、六 Phase 事务、LSM、解锁流水线、应急、完整性、`runtime_hash_scan` 自身）的**内存映像**未被 hotpatch。
- **何时执行**：A 在 `Verthys_Init`（`integrity_verify_startup`）；B 在解锁成功后一次 + 之后每次写路径 API（Add/Delete/Import/ChangePassword/Flush）经 `runtime_hash_verify_periodic` 时间门控重算（30 分钟间隔）。
- **惩罚**：失配即 `emergency_report(KILL, ...)` → 内存绝育 + 终止进程；`.rhat` 表自身纳入 `.vsec` HMAC（防文件级改表）。
- 构建闭环：`core/tools/rhash_gen.c --patch <dll|exe>` 解析 map 文件（符号 RVA）+ `.pdata`（函数边界）+ `.reloc`（重定位表），对 X 清单函数计算 BLAKE2b 补丁 `.rhat`；清单以 X-macro 单源定义，删改任一符号即构建失败（禁静默降级）。

## 5. 威胁建模（STRIDE 摘要）

| 威胁类别 | 攻击示例 | 防线模块 | 说明 |
|---|---|---|---|
| Spoofing 欺骗 | 伪冒合法进程/调用方 | brute_force（限流 + 一次性 auth_token）、session 守卫 | 解锁尝试限流，敏感命令需令牌 |
| Tampering 篡改 | 改 DLL/改 .verthys/内存补丁 | integrity（.vsec+.rhat）、superblock HMAC、Merkle、partition AEAD | 三类篡改各有信号（INTEGRITY_FAIL / PROCESS_TAMPER / SUPERBLOCK_HMAC） |
| Repudiation 抵赖 | 操作无痕 | util/audit_log.rs + security_commands/audit.rs | 安全命令写入审计日志（AEAD 保护） |
| Information Disclosure 泄露 | 读内存/转储/冷启动 | CNG 内核托管 + memory_guard + secure_allocator + key_separation | 密钥内核态不可读；明文缓冲用后清零 |
| Denial of Service 拒绝服务 | 资源耗尽/暴力爆破 | emergency（分级响应）+ 资源上限（512MB/句柄/线程）+ brute_force | 达到预算拒绝新操作、熔断 |
| Elevation of Privilege 提权 | 注入/Hook/进程镂空 | layer1 job_isolation、layer4 tls_loader+syscall_direct、layer5 process_sandbox、anti_inject | 进程级 mitigation + Job ACL 等效 PPL |

7 攻击路径闭环（`verthys.h VerthysDefensePath` = 内部 `DefensePath`）：挂起绕过 / 内存 Dump / 休眠取证 / IAT-Inline Hook / DLL 劫持·反射注入 / 进程读取 / 跨设备迁移，分别由 `layer1_process_guard`、`memory`、`layer4_hook_defense`、`layer5_sandbox + anti_analysis`、`layer3_hw_binding` 承接，`layer6_closure` 统一 BOOT/RUNTIME 校验（`Verthys_GetSecurityStatus` 反映 7 路径实时状态）。

## 6. 审计点清单

| 关键路径 | 审计点（函数/位置） |
|---|---|
| 解锁 | `Verthys_Unlock` → `verthys_unlock_pipeline_run`（S0–S6）；`keymanager_derive_master_v3`（DKM/MEK 派生即清零）；`verthys_cng_km_import_batch`（MEK 导入后清零） |
| 密钥注入/解包 | `verthys_cng_aead_import_key`、`verthys_cng_km_wrap_key`、`verthys_cng_km_rotate_abc` |
| pepper 来源 | `verthys_pepper_init / load_from_os`（来源错误置 `PEPPER_SOURCE`）、`pepper_source_error` |
| 改密/轮换 | `verthys_cng_km_verify_mek / rekey / rotate_mek`、`vsb_txn_v3_commit` |
| 导出 | `Verthys_Export`（流式、明文经用户态缓冲，用后清零）；导出密码不混胡椒 |
| 完整性校验 | `integrity_verify_startup`、`runtime_hash_verify(_periodic)`、`Verthys_VerifyIntegrity` |
| 应急自毁 | `emergency_report / emergency_trigger`（TELEMETRY/DEGRADE/KILL 三级） |
| 事务提交 | `vsb_v3_commit_quorum`（3 副本 2/3 成功）、WAL 回放 |
| 预设切档 | `security_apply_preset`（授权 → 原子落盘 → worker 切档 → C 投影回读，不一致回滚并报 `E_PRESET_VERIFY`）；落盘失败回滚置 `preset_persist_dirty` 阻断后续切档 |
| 自完整性核验 | `integrity_check::verify_self_image_async`（启动主镜像 WinVerifyTrust）+ 后台巡检抽样复核；结果写 `INTEGRITY_CHECK` 审计事件 |
| 痕迹清理 | `trace_cleanup::run_locked_cleanup_async`（锁定/退出触发）；仅删除指向应用自身痕迹域（`.verthys`/`.venc` 扩展名 + 应用自有目录前缀）的最近记录条目，写 `TRACE_CLEANUP` 审计事件 |
| 介质绑定 | `pre_unlock_guard`（解锁前卷序列号哈希比对，克隆嫌疑 fail-closed 拒绝）+ `post_unlock_commit`（DPAPI 持久化登记/重绑定） |

## 7. 安全防护档位与特性契约

三档预设（BALANCED / SECURE / PERFORMANCE）与自定义档的策略唯一权威在 C 运行时策略层（`security_preset.c` 三档填充矩阵），Rust/TS/UI 仅只读消费，禁止本地可写副本与缓存回写权威。

### 7.1 特性位契约（11 位，位序跨层禁止重排）

位序：0=anti_debug，1=anti_inject，2=integrity_check，3=memory_guard，4=key_separation，5=emergency_response，6=session_lock_on_idle，7=module_patrol，8=clipboard_guard，9=usb_clone_detect，10=trace_cleanup；有效掩码 `0x7FF`。

档位值：BALANCED `0x6FF`、SECURE `0x7FF`、PERFORMANCE `0x073`。C 层投影接口 `security_preset_feature_bits` / `security_active_preset` 为唯一口径；应用侧镜像 `app_feature_gate`（AtomicU32）按回读结果更新，未应用预设时按保守全开处理——任何异常路径朝"防护更严"方向失败。

### 7.2 红线能力（全档恒定，不随档位或用户开关关闭）

调试检测（anti_debug 全档恒开，性能档不减负）、注入拦截、密钥三权分立（CNG）、应急熔断（`emergency.c` 无条件 KILL 级）、锁定清空剪贴板、系统锁屏/注销/断连即锁定（WTS 事件）、全局密钥导出二次验证。`key_separation` / `emergency_response` 两位由红线常量提供。

### 7.3 特性执行路径（能力真实性）

| 特性 | 执行路径 |
|---|---|
| module_patrol | 后台巡检线程按动态周期扫描，门控关闭时仅维持线程与心跳 |
| integrity_check | 启动期主镜像签名核验（WinVerifyTrust，后台线程）+ 巡检轮次随机抽样已加载受信位置模块复核；失败不阻断启动/解锁（离线吊销检查可能误报），审计 + 日志可见 |
| usb_clone_detect | 解锁前置守卫：可移动卷序列号哈希与 DPAPI 登记比对，不匹配拒绝解锁并提供重绑定流程（全局密钥二次验证） |
| trace_cleanup | 锁定/退出时精确清理系统最近记录中指向应用自身文件的条目（COM 专用线程解析 .lnk，绝不触碰无关记录） |
| session_lock_on_idle | 前端会话计时器按档位超时应用；自定义档可显式关闭 |
| clipboard_guard | 语义 = 剪贴板监听（外部写入即清空）；锁定清空为恒定底线，不受该位影响 |

### 7.4 档位生效时机与信任链

解锁流程在凭据验证前按受信文件（`<verthys_path>.preset.json`，按本次容器路径派生）应用档位并回读校验，失败中止解锁（fail-closed）；本地 localStorage 仅作迁移来源与只读缓存，任何路径不得以其覆盖受信文件；运行期唯一写路径是用户显式切换（落盘 → 切档 → 回读 → 成功才更新 UI，并递增竞态版本号）。

显示器关闭锁定（display-off）：会话守卫注册 `GUID_CONSOLE_DISPLAY_STATE` 电源设置通知，仅高安全（SECURE）模式下显示器关闭执行锁定；通知注册失败退化为既有挂起监听。