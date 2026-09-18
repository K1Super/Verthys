# Verthys 项目完整技术文档

> **文档版本**: 5.0（2026-09-15 全面更新）
> **对应代码状态**: master 工作区（V3 全系升级 WP-0..14 落地 + V2 代码退役 + core 模块化重构后）
> **本版变更**: V3 加密容器全面转正（FlatBuffers/flatcc schema 驱动：superblock\_v3/partition/extent/sstable）、CNG 内核密钥全量托管、LSM 索引 + 内容寻址 Extent、VsbTxnV3 六 Phase 事务、密钥自动轮换（rekey\_auto）、`.vsec` + `.rhat` 双重完整性（构建期签名 + 32 函数运行时哈希）、直接系统调用（SSN 排序法）、防御闭环 7/7 BLOCKED（`Verthys_GetSecurityStatus`）、属性测试 harness（250 测试）、导出面收敛 29 符号（V2 API 退役）、core 源码模块化重构（六域 31 组件目录，ADR 见 V3\_UPGRADE\_PLAYBOOK.md §1.6）。
> **姊妹文档**: [V3\_UPGRADE\_PLAYBOOK.md](./V3_UPGRADE_PLAYBOOK.md)（V3 升级执行手册，工作包级留痕）
> **相关文档**: [VERTHYS\_INIT\_TO\_AUTH\_FLOW.md](./VERTHYS_INIT_TO_AUTH_FLOW.md) — 初始化窗口到身份认证窗口流程分析

---

## 目录

1. [项目概述](#1-项目概述)
2. [系统架构](#2-系统架构)
3. [目录结构](#3-目录结构)
4. [构建系统](#4-构建系统)
5. [密码学设计](#5-密码学设计)
6. [密钥管理体系](#6-密钥管理体系)
7. [.verthys 加密容器格式](#7-verthys-加密容器格式)
8. [核心 C DLL 模块详解](#8-核心-c-dll-模块详解)
9. [安全防护模块](#9-安全防护模块)
10. [运行时保护模块](#10-运行时保护模块)
11. [事务与一致性](#11-事务与一致性)
12. [公共 C ABI 接口](#12-公共-c-abi-接口)
13. [错误码体系](#13-错误码体系)
14. [测试体系](#14-测试体系)
15. [编译加固](#15-编译加固)
16. [环境变量与部署](#16-环境变量与部署)
17. [安全边界声明](#17-安全边界声明)
18. [已知问题与待办](#18-已知问题与待办)
19. [附录：常量速查表](#19-附录常量速查表)

---

## 1. 项目概述

### 1.1 定位

Verthys 是一款 **Windows 首发、可跨平台的本地高安全桌面私密数据管理器**，采用 Tauri + Vue3 轻量化架构，依托 XChaCha20-Poly1305、Argon2id 商用级加密体系，加密存储账号密码、私密照片等敏感数据。

### 1.2 核心特性

| 特性 | 说明 |
|------|------|
| **加密存储** | 所有敏感数据仅密文落地，无明文缓存残留 |
| **四层架构** | UI 交互层 / 应用调度层 / 核心安全 DLL / 持久化存储层 |
| **防逆向** | 编译剥离符号表、内置反调试（本进程内高置信度信号，检测器经直接系统调用防 Hook）、mitigation policy 沙盒、`.vsec` 构建期签名 + `.rhat` 32 函数运行时哈希双重完整性 |
| **原子化事务** | WAL 先行重放 + 六 Phase 提交（VsbTxnV3 法定人数）+ Extent 内容寻址（BLAKE2b 指纹去重）+ 崩溃恢复矩阵 |
| **三密钥分立** | 索引密钥（A）/ 数据密钥（B）/ 超级块密钥（C）独立隔离；★ **CNG 内核全量托管**（用户态仅瞬态栈帧）+ 自动轮换（rekey\_auto） |
| **CNG 机器绑定** | pepper 经 CNG 持久化机器密钥（RSA-OAEP）包装，跨设备不可解；来源指纹化、可诊断 |
| **应急分级响应** | TELEMETRY / DEGRADE / KILL 三级信号模型，检测与响应解耦，杜绝误报自毁 |
| **民用顶级安全** | 抵御普通本地、远程非特权攻击（威胁模型详见 §17）；防御闭环 7/7 BLOCKED（`Verthys_GetSecurityStatus`） |

### 1.3 技术栈

- **核心 DLL**：C11，CMake 构建，MSVC 工具链（VS 18 2026 / MSVC 14.51）
- **加密库**：libsodium 1.0.20（vendored 静态链接）
- **应用层**：Tauri (Rust) + Vue3 + TypeScript
- **构建工具**：CMake 3.20+、PowerShell 脚本
- **目标平台**：Windows x64（架构预留跨平台）

---

## 2. 系统架构

### 2.1 四层安全架构（自下而上）

```
┌─────────────────────────────────────────────────────────┐
│  L4  UI 交互层（Vue3 + Three.js）                          │
│      仅界面渲染/用户交互，无权限/无加密能力，操作抽象句柄       │
│      运行在 Tauri 沙箱内                                    │
└────────────────────────────┬────────────────────────────┘
                             │ Tauri IPC (invoke)
┌────────────────────────────┴────────────────────────────┐
│  L3  应用调度层（Tauri-Rust 主进程）                        │
│      系统权限唯一入口，管控 DLL 子进程生命周期                │
│      参数校验/指令白名单/防截屏/剪贴板清空/闲置锁屏            │
│      全程不接触密钥与明文；build.rs 固化 verthys.dll SHA-256│
└────────────────────────────┬────────────────────────────┘
                             │ stdin/stdout JSON-lines（Actor 模型）
┌────────────────────────────┴────────────────────────────┐
│  L2  verthys-worker 子进程（Rust，BELOW_NORMAL 优先级）        │
│      ① 加载 DLL 前应用进程级 mitigation policy              │
│      ② libloading 按名解析导出函数（白名单符号）              │
│      ③ 单线程 FFI 语义（一请求一调用）；GMK 仅存 worker       │
│      ④ 锁库即杀进程：密钥最终归宿是"进程死亡"                 │
└────────────────────────────┬────────────────────────────┘
                             │ C ABI（29 个白名单导出）
┌────────────────────────────┴────────────────────────────┐
│  L1  核心安全层（C 加固 DLL → verthys.dll）                │
│      封装全部密码运算/文件解析/内存安全逻辑                   │
│      内部分层 L0→L5 单向依赖 + L6 横向防御（见 §2.2）         │
└────────────────────────────┬────────────────────────────┘
                             │ 原子写 / RoW / 双指针 / 日志
┌────────────────────────────┴────────────────────────────┐
│  L0  持久化存储层：.verthys（V3 容器，schema 驱动）            │
│             + 分区/Extent 内容寻址存储                      │
└─────────────────────────────────────────────────────────┘
```

### 2.2 核心 DLL 内部分层（依赖方向 L5→L0 单向，无循环；V3 收口 + 模块化重构后）

```
L5  api/           公共 C ABI 门面（lifecycle/unlock/scan/transfer/progress/shared 六组件）
L4  transaction/   事务一致（wal + txn：VsbTxnV3 六 Phase 法定人数提交）
L3  index/         索引数据（lsm：MemTable + 分层 SSTable + Bloom（xxHash64）+ warmcache）
L2  container/     V3 容器（format/superblock/partition/extent/io/shared，schema 驱动）
L1  crypto/        密码学原语（cipher/keymanager/pepper/rekey_auto）
L0  （存储即 V3 容器文件本身，分区认证 + Extent 内容寻址）
L6  security/      纵深防御（横向，12 个组件目录）：
      preset/               三档安全预设（双缓冲原子切换）
      integrity/            .vsec 构建期签名验签 + ★ WP-8 runtime_hash（.rhat 32 函数运行时哈希）
      anti_analysis/        反调试 v2（KILL 级）+ 防注入巡检 + ★ WP-9 syscall_direct（直接系统调用）
      memory/               内存防护（防转储巡逻）+ 三权分立 CNG 密钥（WP-1 全量接线）+ 安全分配器
      emergency/            应急分级响应（TELEMETRY/DEGRADE/KILL）
      layer1_process_guard/ 双层 Job Object + 白名单 DACL
      layer3_hw_binding/    CNG 机器密钥 + MachineGuid 指纹 + System32 优先
      layer4_hook_defense/  TLS 标志验证 + 联动销毁（CNG purge + emergency）
      layer5_sandbox/       进程 mitigation policy 位掩码登记
      layer6_closure/       ★ WP-11 闭环防御验证（7 项攻击路径状态机，7/7 BLOCKED）
```

**V2 退役删除**（2026-09-15，详见 V3\_UPGRADE\_PLAYBOOK.md §1.4）：`verthys_btree`/`verthys_datablock`/`verthys_migration`/`verthys_v2_lifecycle`/V2 超级块/`verthys_warmcache`(v2)/watcher/mountwatch/runtime 层整体——B+ 树与槽位池由 LSM + Extent 承接，运行时监视由 worker 侧（Rust）承接。
**历史上已删除的表演性防御**（最终修复方案 §6.4）：`key_drift`、`working_set`、`mem_reset`、`entropy_pool`、`obfuscation`、`syscall_whitelist`、`stack_guard`、`inline_crc`、`timer_queue_guard`。

### 2.3 三层职责分离（安全防护链路）

| 层 | 职责 | 密钥/明文接触 |
|---|---|---|
| 主进程（Tauri-Rust） | 进程编排、会话策略、Rust 侧安全模块（session_guard/clipboard_guard/usb_guard/file_lock/module_whitelist/brute_force） | 从不 |
| worker 子进程 | mitigation policy 应用 → DLL 加载 → 单线程 FFI 转发；GMK 派生/持有/清零 | GMK（Rust 侧 Zeroizing） |
| verthys.dll | 全部密码运算与容器解析；A/B/C 密钥 CNG 内核托管（用户态仅瞬态栈帧，E-5 界定） | 派生密钥瞬态 |

---

## 3. 目录结构（模块化重构后，ADR-2026-09-15）

```
core/
├── CMakeLists.txt              # 源清单（VERTHYS_SRC_SUBDIRS 31 组件目录）+ ASAN 开关
├── verthys.def                # ★ 导出符号唯一白名单（29 个函数）
├── include/                    # ── 公共接口区（与私有实现物理隔离）──
│   ├── verthys.h              # 对外 C ABI 契约（API_VERSION 0x000B）
│   └── error_codes.h           # C/Rust FFI 错误码对齐
├── src/                        # ── 实现区（六域 → 组件两级，小写蛇形）──
│   ├── api/                    # L5 公共门面
│   │   ├── lifecycle/          # verthys_api.c + verthys_v3_lifecycle.c/.h + dllmain.c
│   │   ├── unlock/            # verthys_unlock_pipeline.c/.h（解锁 S0-S6 流水线）
│   │   ├── scan/              # verthys_scan.c（全量/摘要扫描游标）
│   │   ├── transfer/          # verthys_export_import.c（导出/导入/改密）
│   │   ├── progress/          # verthys_progress.c/.h（进度环形缓冲）
│   │   └── shared/            # verthys_api_utils.c/.h
│   ├── container/              # L2 V3 容器（schema 驱动）
│   │   ├── format/            # verthys_format.c/.h（V3 交换信封）
│   │   ├── superblock/        # verthys_superblock_v3.c（VsbTxnV3 + 法定人数）
│   │   ├── partition/         # verthys_partition.c/.h（分区表 + nonce 计数器）
│   │   ├── extent/            # verthys_extent.c/.h（内容寻址 + BLAKE2b + 去重）
│   │   ├── io/                # verthys_io.c/.h（统一 64 位 I/O）
│   │   └── shared/            # verthys_container_v3.h + verthys_internal.h
│   ├── crypto/                 # L1 密码学
│   │   ├── cipher/            # verthys_crypto.c/.h + verthys_crypto_cng.c/.h + secure_mem.c
│   │   ├── keymanager/        # keymanager.c/.h + keymanager_cng.c/.h（CNG rotate_abc）
│   │   ├── pepper/            # verthys_pepper.c/.h（v2 来源指纹/Shamir）
│   │   └── rekey/             # verthys_rekey_auto.c/.h（★ 自动轮换）
│   ├── index/                  # L3 索引
│   │   ├── lsm/               # verthys_lsm.c/.h + _internal.h + _memtable/_sstable/_compaction.c
│   │   └── warmcache/         # verthys_warmcache_v3.c/.h（独占句柄 + 原子替换）
│   ├── transaction/            # L4 事务
│   │   ├── wal/               # verthys_wal.c/.h（WAL 先行 + 重放）
│   │   └── txn/               # verthys_transaction_v3.c/.h（六 Phase）
│   └── security/               # L6 纵深防御（10 组件目录，12 个含根）
│       ├── preset/            # security_preset.c/.h（双缓冲原子切换）
│       ├── integrity/         # integrity.c/.h + runtime_hash.c/.h（★ .vsec + .rhat）
│       ├── anti_analysis/     # anti_debug_v2 + anti_inject + syscall_direct（★ WP-9）
│       ├── memory/            # memory_guard + key_separation + secure_allocator
│       ├── emergency/         # emergency.c/.h（分级响应）
│       ├── layer1_process_guard/  # job_isolation.c/.h
│       ├── layer3_hw_binding/     # cng_machine_key + hardware_binding + system32_loader
│       ├── layer4_hook_defense/    # tls_loader + tls_callbacks + tamper_destroy
│       ├── layer5_sandbox/         # process_sandbox.c/.h
│       └── layer6_closure/         # defense_closure.c/.h（★ WP-11）
├── schema/                     # ── FlatBuffers 契约区 ──
│   ├── superblock_v3.fbs / partition.fbs / extent.fbs / sstable.fbs / demo.fbs
│   └── generated/             # flatc -a 产物（reader/builder/verifier，构建期再生成）
├── tools/                      # ── 构建工具区 ──
│   └── rhash_gen.c            # ★ .rhat 节生成（/MAP + .pdata + .reloc 解析）
├── examples/                   # ── 示例区 ──
│   └── ffi/cng_example.c      # CNG 密钥托管 FFI 示例
└── tests/                      # ── 测试区（镜像 src 子域，35 文件 250 项）──
    ├── test_runner.c          # 入口 + argv 过滤器（子串 + OR 多组）
    ├── api/ container/ crypto/ index/ transaction/
    ├── property/              # ★ test_v3_property.c（不变式 harness）
    ├── regression/ schema/ security/ perf/
    └── fuzz/                  # 5 目标 + gen_seeds（语料生成）
```

---

## 4. 构建系统

### 4.1 构建策略

- `verthys_core_obj`：OBJECT 库，源码编译一次，DLL 与测试共用
- `verthys_core`：SHARED DLL，`/DEF:verthys.def` 白名单导出（**唯一导出机制**）
- `verthys_tests`：测试 exe，直接链接对象库（不走 DLL 边界），`/STACK:16777216`
- `VERTHYS_ENABLE_ASAN=ON`：AddressSanitizer 构建（§6.2/§14）

### 4.2 构建脚本

| 脚本 | 用途 | 产物 |
|---|---|---|
| `scripts/build_core.dev.ps1` | 开发构建（Debug）+ 强制全量测试 | `build_dev/core/Debug/` |
| `scripts/build_core.release.ps1` | 生产构建（Release 加固）+ **`.vsec` 完整性基准注入** + **`.rhat` 运行时哈希表注入** | `build/core/Release/verthys.dll` |
| `scripts/build_core.fuzz.ps1` | fuzz 5 目标构建 + `gen_seeds` 语料生成（WP-10） | `build_ninja/core/fuzz/` |

**`.vsec` + `.rhat` 注入流程**（§9.3 机制，Release 专属）：
1. 链接完成后，脚本解析 PE 节表，定位 `.text` / `.rdata` / `.vsec` / `.rhat`；
2. `tools/rhash_gen`（`/MAP` + `.pdata` + `.reloc` 解析）对 X-macro 32 关键函数计算 BLAKE2b-256，构建后补丁写入 `.rhat`（表项 48B，全命中强制）；
3. 以域密钥（与 `integrity.c` 的 `K_VSEC_DOMAIN_KEY` 逐字节一致）计算两节的**文件内容** HMAC-SHA256（`.rhat` 纳入 v2 校验第三槽）；
4. 写入 `.vsec`（128B：magic `'VESC'` + version + 双 HMAC）；
5. **Authenticode 签名（若有）必须在此步骤之后**。

### 4.3 导出面治理（方案 §7 / P0-A）

- `verthys.h` 的 `VERTHYS_API` 为**空宏**（不携带 dllexport/dllimport）；
- 导出唯一由 `verthys.def` 决定，实测 `dumpbin -exports` = 29 符号与白名单逐一相等；
- 基线文件 `ci/export_baseline.txt` + CI 比对门（`.github/workflows/core.yml`）。

---

## 5. 密码学设计

### 5.1 加密算法体系

| 用途 | 算法 | 参数 |
|---|---|---|
| 记录/索引/超级块/缓存 AEAD | ★ V3 主路径：CNG AES-256-GCM（内核托管，12B 单调 nonce，E-7）；交换信封/兼容路径：XChaCha20-Poly1305 (libsodium，24B nonce) | 密文布局 `[ct‖tag]` |
| 口令派生 | Argon2id | BALANCED 32MiB / iters 校准（1..3，目标 ~1.2s）；SECURE 64MiB/3/1（固定） |
| 子密钥派生 | HKDF-SHA256-Expand | 域分离标签 `verthys/…-v1/v2` |
| 完整性 | HMAC-SHA256 + BLAKE2b-256（Extent 内容指纹） | integrity_key = HKDF(MEK, "integrity-key") |
| 随机数 | randombytes_buf | OS CSPRNG |
| pepper 机器包装 | CNG RSA-2048 OAEP-SHA256 | label = MachineGuid 指纹（自携带于 pepper 文件） |
| 密钥托管（★ WP-1 已接线） | CNG AES-256-GCM | 12B nonce，`[ct‖tag]` 与 libsodium 布局兼容 |

### 5.2 Argon2id 动态校准与自适应再封装（方案 §4.5）

- **创建期**：`verthys_argon2_calibrate`（两段式探测：初始测量 + 换算确认）在 `[1,3]` 迭代区间选择本机参数（目标 1.2s）；选参写入超级块 `argon2_iters`，基准耗时写入 `flags[0..3]`。
- **解锁期**：漂移监控判据由 `verthys_rekey_auto`（WP-7）承接——连续 3 次超基准 30% → 降 1 档；连续 3 次达标且 < 基准 70% → 升 1 档；90 天 / 10,000 ops / 24h 最小间隔 / DEGRADE 信号强制触发：新 MEK 派生 → A/B 密钥 CNG 内核态重包裹（`rotate_abc` 原子句柄切换）→ 新 key_c → 超级块 VsbTxnV3 法定人数持久化 → 基准线性换算防震荡（原 V2 `verthys_argon2_rewrap` 已随 V2 退役，语义由本路径等价承接）。
- **SECURE 预设不参与**（偏差 D-5：合规确定性优先）。

### 5.3 密码学原语接口（verthys_crypto.h）

`verthys_aead_encrypt/decrypt`（XChaCha20）、`verthys_argon2id_derive_ex`（全参数化 + DoS 边界校验 8KiB..4GiB）、`verthys_argon2_calibrate`、`verthys_hkdf_expand`、`verthys_hmac_sha256`、`verthys_derive_integrity_key`、`verthys_random_bytes`。

---

## 6. 密钥管理体系

### 6.1 四级密钥层次

```
L1 口令：password（用户输入，不落盘）
L2 派生：DKM = Argon2id(password ‖ pepper, salt, mem/iters/parallel)   [瞬时]
L3 主密钥：MEK = HKDF-Expand(DKM, "verthys/master-key-v1")            [瞬时]
L4 记录密钥：record_key = HKDF-Expand(DEK, "verthys/record-v1" ‖ record_id)
    A/B/C 密钥：随机生成（key_c 从 MEK 派生），MEK 包裹存于超级块
```

### 6.2 胡椒（Pepper）机制 — v2 托管框架

**三层来源**（优先级降序）：注入 > OS 托管（CNG/TPM）> 编译内嵌兜底。

**★ v2 文件格式（304B）**：`magic(4) + version(2) + source_type(2) + fingerprint(8) + label(32) + cipher(256)`。
- `source_fingerprint = HMAC-SHA256(domain_key, label‖cipher)[:8]`，与机器密钥解包交叉验证；
- v1 文件（296B）解包成功后自动升级为 v2（方案 §9 迁移）。

**★ 来源错误禁兜底（P0-B 根治）**：文件存在但解包失败/指纹不符 → 置 `g_pepper_source_error`，**禁止静默回退编译常量**；解锁路径返回 `VERTHYS_ERR_PEPPER_SOURCE`（区别于"密码错误"）。容器超级块 `flags[5]` 记录创建时来源，解锁时校验一致性。

**恢复卡**：Shamir GF(2⁸) k-of-n 分片（`verthys_pepper_export/reconstruct_shamir`）。

### 6.3 三密钥分立（V3 容器）

- **key_a（索引）**：随机生成，MEK 包裹；解密 LSM SSTable/温缓存/摘要。
- **key_b（数据）**：随机生成，MEK 包裹；解密 Extent 数据；记录级密钥 = HKDF(key_b, name)。
- **key_c（超级块）**：从 MEK 派生（解决"先有鸡"问题）；改密随 MEK 轮换。
- 三密钥 CNG 内核托管（§6.4）；所有失败路径 `verthys_secure_zero`（回归测试覆盖）。

### 6.4 CNG 内核托管（key_separation）— ★ 已全量接线（WP-1）

`key_separation.c` 提供 AES-256-GCM 内核态 AEAD（`BCryptGenerateSymmetricKey` 导入内核，用户态仅持句柄；C 角色激活/休眠逻辑隔离；`any_installed` 查询供防御闭环 MEM\_DUMP 判据）。V3 全路径采用 12B 单调 nonce 计数器（E-7，分区表持久化）。`keymanager_cng` 的 `rotate_abc` 支撑 rekey\_auto 内核态新旧切换。用户态明文瞬态窗口见 E-5 诚实界定（§17.3）。

---

## 7. .verthys 加密容器格式（V3，现役）

### 7.1 V3 格式（FlatBuffers schema 驱动，`core/schema/*.fbs`）

```
superblock_v3.fbs     超级块：magic/feature_flags/container_id/salt/Argon2id 参数/
                      wrapped_key_a/b/c（CNG 内核包装）/分区布局/txid/state_chain/
                      法定人数（quorum）提交状态机 + 全局 HMAC
partition.fbs         分区表：每分区元数据含 nonce_counter（12B 单调计数器，
                      E-7：解锁恢复继续递增，杜绝 GCM nonce 重用）+ 分区级认证
extent.fbs           内容寻址数据区：BLAKE2b-256 内容指纹（E-3）→ 去重（同内容
                      零重写）+ per-block nonce/offset/size 三重校验（flatcc
                      verifier + 索引 HMAC + AEAD tag）
sstable.fbs          LSM 分层 SSTable：Bloom 过滤器（xxHash64 双重哈希，E-4）+
                      墓碑 + 分层元数据
```

- 序列化运行时：vendored **flatcc**（纯 C11，E-2 决策），构建期 `flatc -a` 生成 reader/builder/verifier 到 `schema/generated/`。
- 解析纪律：HMAC → AEAD → flatcc verifier 边界检查三层纵深；`a+b>c` 全部回绕安全分解（P2-2 加固）。
- **V1/V2 容器不再可读**（V2 退役，无向后兼容）；旧数据迁移走导出/导入交换信封（`verthys_format.c` V3 信封专用）。

### 7.2 槽位池（V2 历史机制，已随 V2 退役）

SMALL/MEDIUM/LARGE 池与 `pool_extend` 上界修复（P0-1）为 V2 时代机制，随 V2 容器删除；V3 数据布局 = 分区 + Extent 内容寻址（§7.1），容量上界由分区表认证约束。

### 7.3 温启动缓存（V3 重写）

V3 温缓存（`index/warmcache/verthys_warmcache_v3.c`）：独占句柄（共享模式 0）写 `.tmp` → `FlushFileBuffers` → `MoveFileExW(REPLACE|WRITE_THROUGH)` 原子替换，读者只见完整旧/新文件（P2-4 竞态结构性消除）；container\_id + txid 前置校验 + HMAC 完整性。

---

## 8. 核心 C DLL 模块详解（V3 + 模块化重构后）

### 8.1 L1 crypto/
- `cipher/verthys_crypto.c`：AEAD 往返、参数化 Argon2id（越界拒绝防 DoS）、`verthys_argon2_calibrate`、HKDF/HMAC；`verthys_crypto_cng.c`：CNG 内核 AEAD（BCrypt AES-GCM，12B 单调 nonce）。
- `keymanager/keymanager.c`：四级派生 + DEK 包裹（AD 域分离）+ 记录密钥；`keymanager_cng.c`：CNG 密钥导入/导出/rotate\_abc（rekey\_auto 轮换执行体）。pepper 来源错误 → `VERTHYS_ERR_PEPPER_SOURCE`。
- `pepper/verthys_pepper.c`：v2 托管框架（§6.2，来源指纹/禁兜底/Shamir/CNG 机器包装）。
- `cipher/secure_mem.c`：`verthys_secure_zero` / `verthys_lock_memory`。
- `rekey/verthys_rekey_auto.c`：★ 密钥自动轮换（WP-7）——90 天 / 10,000 ops / 24h 最小间隔 / DEGRADE 信号强制触发；轮换在 CNG 内核态新旧切换（原子指针切换句柄）+ vsb\_txn 法定人数保护。

### 8.2 L2 container/
- `superblock/verthys_superblock_v3.c`：V3 超级块（schema 驱动）+ **VsbTxnV3** 事务原语（begin 备份 → commit 丢弃 → rollback 整块恢复 + HMAC，幂等）+ 法定人数（quorum）提交状态机。
- `partition/verthys_partition.c`：分区表读写 + **nonce\_counter 持久化与恢复**（E-7：恢复取 max(盘面值, WAL 重放值) + 安全裕量，R-5）。
- `extent/verthys_extent.c`：内容寻址存储——BLAKE2b-256 指纹去重（同内容零重写）、读路径三重校验（verifier + 索引 HMAC + AEAD）、回绕安全边界分解；`verthys_extent_gc_eligible` 判定接口（GC 执行未来必走 vsb\_txn）。
- `format/verthys_format.c`：V3 交换信封（导出/导入），迁移接口已随 V2 退役删除。
- `io/verthys_io.c`：统一 64 位 I/O 层（`vio_fseek64/ftell64/pread64/pwrite64`）。
- `shared/verthys_container_v3.h` + `verthys_internal.h`：域内共享契约。

### 8.3 L3 index/
- `lsm/verthys_lsm.c`（+ `_memtable` / `_sstable` / `_compaction`）：LSM 引擎（WP-4）——MemTable → 分层 SSTable 刷新与压实、Bloom（xxHash64 双重哈希）加速查找、**墓碑感知查询**（NULL 探测统一走墓碑路径，缺陷①修复）、WAL 重放式回滚重建（`memtable_rebuild_locked` / `verthys_lsm_rebuild_excluding`，缺陷②/②b 修复）。
- `warmcache/verthys_warmcache_v3.c`：V3 温缓存（§7.3）。

### 8.4 L4 transaction/
- `txn/verthys_transaction_v3.c`：**六 Phase 提交**（BEGIN→WRITE→PREPARE→COMMIT→CONFIRM→CLEANUP）；WAL 先行 + MemTable ≡ 重放 [0, wal\_cursor) 不变式；回滚走 WAL 重放（保被墓碑遮蔽的原始条目）；提交/回滚后 WAL 帧清零（防同 txid 合并废弃帧复活）。
- `wal/verthys_wal.c`：预写日志（帧追加 + cursor + `verthys_wal_reset`）。

### 8.5 L5 api/
- `lifecycle/verthys_api.c`：`Verthys_Init`（防御闭环 BOOT 门 + 降级处理器 + 活动句柄注册表）、`Verthys_Unlock`（pepper 快速失败 → `.vsec` 验签 → 解锁流水线 → 成功钩子：`emergency_clear_signals` + 模块巡检 + 防转储巡逻 + **runtime\_hash\_scan**）、`Verthys_Lock`/`Verthys_Deinit`、`Verthys_GetSecurityStatus`（★ WP-11）。
- `lifecycle/verthys_v3_lifecycle.c`：V3 创建/解锁（maybe\_rotate 接线 rekey\_auto）、`Verthys_CreateWithPreset`。
- `unlock/verthys_unlock_pipeline.c`：解锁 S0-S6 流水线（渐进式，回调 8 阶段异步推送）。
- `transfer/verthys_export_import.c`：`Verthys_ChangePassword`（vsb\_txn 保护）、`Verthys_Export`（>65535 条 `VERTHYS_ERR_EXPORT_TOO_MANY`）、`Verthys_Import`。
- `scan/verthys_scan.c`：全量/摘要扫描游标（`v3_owner` 实例身份锚点 + `scan_v3_alive` 校验 + 熔断作废，P2-5 修复）。
- `progress/verthys_progress.c`：无锁环形缓冲 + 独立消费线程（P1-7 销毁无限等待语义）。

---

## 9. 安全防护模块（V3 收口后：含 WP-8/9/11）

### 9.1 emergency — 应急分级响应（★ P0-3 根治）

**三级模型**（检测与响应解耦）：

| 级别 | 行为 | 使用者 |
|---|---|---|
| `EMERG_LEVEL_TELEMETRY` | 仅记入信号窗口，无处置 | 模块巡检（未知 DLL）、注入痕迹、syscall 降级 |
| `EMERG_LEVEL_DEGRADE` | 窗口内**同一信号 ≥2 次**（10 分钟滑动窗口，8 槽环形历史）→ 置熔断闩锁 → 调用降级处理器（清密钥 + 锁库，进程存活可恢复）+ **rekey\_auto 强制轮换触发**（WP-7） | 远程内存读取巡逻 |
| `EMERG_LEVEL_KILL` | 立即内存绝育 + 匿名故障码上报看门狗 + TerminateProcess | 调试器确认、完整性验签失败、**runtime\_hash 失配（WP-8）**、TLS 标志异常 |

- 降级处理器由 API 层注入（`emergency_set_degrade_handler` → `verthys_emergency_lock_all`：遍历活动句柄注册表，清零密钥并置 LOCKED，不做磁盘写入，恢复 = 正常解锁）。
- `emergency_clear_signals` 接入解锁成功与降级恢复。
- KILL 路径保留原有序：熔断闩锁 → `memory_guard_emergency_purge` → `key_separation_purge_all` → `select_fault_code`（匿名类别码 0xE0001..0xE0006）→ `TerminateProcess`（不留 dump）。

### 9.2 检测器（★ WP-9：检测器查询经直接系统调用，绕过用户态 Hook）

| 检测器 | 修复 | 接线点 | 级别 |
|---|---|---|---|
| `anti_debug_v2_check` | 删进程名黑名单、删 0.5% 比特反转；仅本进程内高置信度信号（IsDebuggerPresent / **NtQuery 三重探测经 syscall\_direct stub** / DR0-DR3） | Verthys\_Init、ChangePassword、Export | KILL |
| `anti_inject_check_modules` | 签名优先信任模型 + 分隔符边界前缀匹配（P1-N） | 解锁成功一次 | TELEMETRY |
| `memory_guard_check_remote_read` | 父进程/系统/自身排除（P0-5）+ 注册表临界区；**句柄表扫描经 syscall\_direct NtQuerySystemInformation** | 解锁启动 60s 一次性定时器链巡逻，锁定/销毁停止 | DEGRADE |

**syscall\_direct**（`anti_analysis/syscall_direct.c`，WP-9）：SSN 排序法提取（`4C 8B D1` + `B8 imm32` 特征 + 仿射一致性 + 双侧锚点插值互证）→ W^X stub 页（RW 写入 → 收紧 X，全程无可写可执行页）→ CFG `SetProcessValidCallTargets` 登记；任一环节失败优雅降级回 `GetProcAddress`（TELEMETRY）。覆盖 NtQueryInformationProcess / NtQuerySystemInformation 两入口，表驱动扩展。

### 9.3 integrity — 双重完整性：.vsec 构建期签名 + .rhat 运行时哈希（★ WP-8）

- `.vsec` 只读节（128B）由 Release 构建脚本注入 `.text`/`.rdata` 文件内容 HMAC；`integrity_verify_startup()`（Verthys\_Unlock 入口）从磁盘重算比对——以文件内容为校验对象，免疫 ASLR 重定位；全零节（开发构建）= 跳过；失配 = KILL + `VERTHYS_ERR_CORRUPT`。
- **`.rhat` 节（WP-8 运行时哈希）**：构建期 `tools/rhash_gen` 解析 `/MAP` + `.pdata` + `.reloc`，对 X-macro 32 关键函数计算 BLAKE2b-256 补丁写入；运行期 `runtime_hash_scan()`（解锁后 + 每 30 分钟）重算比对——**重定位槽位双侧掩码归一**防 ASLR 误报；失配 = KILL；`.rhat` 自身纳入 `.vsec` v2 校验第三槽（防改表）。
- 旧锚点轮换/EXE 校验/timer\_queue\_guard 周期任务已删除。

### 9.4 其余防御模块

| 模块 | 现状 |
|---|---|
| `key_separation` | ★ **CNG 内核托管 AEAD 全量接线**（WP-1）：三密钥驻留内核句柄，用户态仅瞬态栈帧（E-5）；`any_installed` 判据支撑 MEM\_DUMP BLOCKED |
| `job_isolation` | 双层 Job（内层 BREAKAWAY\_OK / 外层 KILL\_ON\_JOB\_CLOSE）+ 无 Deny-ACE 白名单 DACL |
| `process_sandbox` | Rust worker 加载 DLL 前应用四项 mitigation policy，位掩码经 `Verthys_NotifySandboxAttrs` 注入 |
| `tls_loader` | 仅验证 TLS 回调标志（未置位 = KILL；**不再自愈**）；IAT 基准与种子定时器已删除 |
| `tamper_destroy` | 两步真实链：`key_separation_purge_all` → `emergency_trigger` |
| `hardware_binding` | **MachineGuid 指纹**（HMAC-SHA256 域分离）；CPUID/SMBIOS/UEFI 已弃用 |
| `cng_machine_key` | 仅 `NTE_BAD_KEYSET` 才创建（P0-C）；无 OVERWRITE flag；NTE\_EXISTS 竞态重试打开 |
| `defense_closure` | ★ **7/7 BLOCKED（运行时验证，WP-11）**：SUSPEND\_BYPASS / MEM\_DUMP / HIBERNATION / IAT\_INLINE\_HOOK / DLL\_HIJACK / PROCESS\_READ / CROSS\_DEVICE 状态机，BLOCKED/DEGRADED/FAILED 语义诚实化；`Verthys_GetSecurityStatus` 导出供 worker/前端查询 |
| `security_preset` | **双缓冲 + 原子指针切换**（P1-L 治理，无全零窗口） |
| `memory_guard` | 注册区锁页 + 单轮覆写 + 巡逻定时器（性能模式零启动） |
| `secure_allocator` | 安全分配器（CNG 密钥路径专用，WP-1 配套） |

---

## 10. 运行时保护模块（V3 后仅存 progress；V2 组件退役）

### 10.1 verthys_progress（api/progress/）
无锁环形缓冲 + 独立消费线程（解锁进度 8 阶段异步推送，O(1) 入队）；**销毁无限等待消费者退出**（P1-7）。

### 10.2 已退役（V2 删除清单，2026-09-15）
- `verthys_watcher`（ReadDirectoryChangesW 文件监听）、`verthys_mountwatch`（挂载/锁屏监视）：随 V2 退役删除——文件与挂载监视职责移交流水线侧/前端会话策略；mountwatch 的 INFINITE 等待缺陷（P2-10）随之消失。
- `verthys_warmcache`(v2)（三级缓存链）：由 `verthys_warmcache_v3.c` 重写承接（§7.3）。
- runtime/ 层整体（含 anti\_debug v1）：反调试由 `anti_debug_v2` 承接（§9.2）。

---

## 11. 事务与一致性

### 11.1 写时重定向（V3 语义）
修改不覆盖原内容：新内容写入 Extent（内容寻址，同内容去重零重写）→ LSM MemTable 更新（墓碑表删除）→ 压实成 SSTable；WAL 先行保证崩溃可重放。

### 11.2 原子提交与崩溃恢复（V3 六 Phase）
WAL 帧追加 + fsync（BEGIN→WRITE→PREPARE）→ 超级块 VsbTxnV3 法定人数提交（COMMIT，幂等）→ CONFIRM 后 WAL 帧清零。**MemTable ≡ 重放 [0, wal\_cursor) 不变式**保证任一崩溃点重开后语义完整：PREPARED 崩溃 → 丢弃组按排除重建（`verthys_lsm_rebuild_excluding`，保被墓碑遮蔽的已提交条目）；COMMITTED 后 CONFIRM 前 → 记录必须可见。崩溃注入矩阵测试覆盖（`test_txn_recovery_inject` + 属性测试 4/5/6）。

### 11.3 超级块事务原语（★ VsbTxnV3，法定人数提交）

```c
VsbTxnV3 txn;
vsb_txn_v3_begin(&txn, sb);      /* 整块备份 */
/* ... 任意字段修改 + schema 序列化 + 落盘 ... */
成功 → vsb_txn_v3_commit(&txn);   /* 法定人数（quorum）确认，清零备份 */
失败 → vsb_txn_v3_rollback(&txn); /* 整块恢复 + HMAC（幂等） */
```
使用者：`verthys_transaction_v3`（六 Phase 全程）、`Verthys_ChangePassword`、`verthys_rekey_auto`（轮换落盘）、lifecycle（创建/恢复）。原 V2 `vsb_txn` 使用链（vtxn\_commit/vsb\_atomic\_commit/vsb\_rekey）已随 V2 退役由 V3 等价承接。

### 11.4 校验体系（V3）
AEAD tag（逐块认证解密时即时）→ Extent 索引 HMAC + BLAKE2b-256 内容指纹（读路径三重校验）→ flatcc verifier 边界检查（schema 驱动）→ 全量扫描（CPU 让步 + 断点续扫 + `scan_v3_alive` 校验）。

### 11.5 偏差 D-9：tail log / bitmap 刷写失败处置
提交点（超级块）已原子持久后，尾部日志确认写失败**不再返回错误**（返回错误将使调用方重试 → 重复记录，比日志缺失更危险），改为诊断告警；一致性由超级块单点真值保障，位图由下次解锁从盘头重建。

---

## 12. 公共 C ABI 接口

### 12.1 接口设计原则
不透明句柄 / 统一 32 位状态码 / `__cdecl` / **导出面唯一由 `.def` 白名单管控**（29 个符号，`ci/export_baseline.txt` 基线 + CI 比对门）。

### 12.2 API 版本

`VERTHYS_API_VERSION 0x000B`（V3 收口）：
- 新增 V3 功能码：`VERTHYS_ERR_CNG_UNAVAILABLE`（0x0E）、`VERTHYS_ERR_RESOURCE_LIMIT`（0x0F）、`VERTHYS_ERR_QUORUM_FAILED`（0x10）、`VERTHYS_ERR_PARTIAL_UNLOCK`（0x11）、`VERTHYS_ERR_TIMEOUT`（0x12）、`VERTHYS_ERR_UNSUPPORTED`（0x13）；
- 新增导出 `Verthys_GetSecurityStatus`（WP-11）；
- **V2 API 退役**：`Verthys_RebuildMerkle` / `Verthys_RebuildMerkleChunked` / `Verthys_MigrateV1ToV2` 移出导出面（LSM 无 Merkle 重建语义、V2 迁移引擎删除）；
- 导出面治理（§4.3）。

### 12.3 接口清单（29 个，与 verthys.def 一致）

生命周期：`Verthys_Init` / `Verthys_NotifySandboxAttrs` / `Verthys_Deinit` / `Verthys_Unlock` / `Verthys_CreateWithPreset` / `Verthys_RegisterUnlockProgressCallback` / `Verthys_Lock` / `Verthys_Flush`
记录：`Verthys_AddRecord`（name\_len ≤ 4096）/ `Verthys_GetRecord` / `Verthys_DeleteRecord` / `Verthys_DeleteRecords` / `Verthys_HasRecordByType` / `Verthys_FindFirstLidByType`
扫描：`Verthys_ScanOpen/Fetch/RecordFree/Close` / `Verthys_ScanSummaryOpen/Fetch/RecordFree/Close` / `Verthys_GetSummaryCount`
完整性与诊断：`Verthys_VerifyIntegrity` / `Verthys_GetContainerInfo` / `Verthys_GetDiagnostics` / **`Verthys_GetSecurityStatus`**（★ WP-11）
导入导出：`Verthys_Export` / `Verthys_Import` / `Verthys_ChangePassword`

### 12.4 关键契约
- `Verthys_GetRecord` 返回**借用指针**：任何写操作/再次 Get 后立即失效（UAF 回归测试 8 项钉死）。
- `Verthys_Unlock` flags：bit0 = 索引已预热（mmap 零拷贝路径），bit1 = 允许加载持久化缓存。

---

## 13. 错误码体系

### 13.1 公共错误码（verthys.h，VerthysResult）

| 码 | 名称 | 含义 |
|---|---|---|
| 0x0 | VERTHYS_OK | 成功 |
| 0x1 | VERTHYS_ERR_INVALID | 入参非法（含 name_len > 4096） |
| 0x2 | VERTHYS_ERR_AUTH | 认证失败/解密校验未通过 |
| 0x3 | VERTHYS_ERR_NOTFOUND | 记录不存在 |
| 0x4 | VERTHYS_ERR_EXISTS | 已存在 |
| 0x5 | VERTHYS_ERR_FORMAT | 格式不符 |
| 0x7 | VERTHYS_ERR_LOCKED | 锁定态/应急熔断 |
| 0x8 | VERTHYS_ERR_IO | 磁盘 IO 异常 |
| 0x9 | VERTHYS_ERR_CORRUPT | 完整性校验失败（含 `.vsec`/`.rhat` 验签失败） |
| 0xA | VERTHYS_ERR_RATE | 访问限流 |
| 0xB | VERTHYS_ERR_SNAPSHOT | 扫描快照过期（WP-5） |
| **0xC** | **VERTHYS_ERR_PEPPER_SOURCE** | ★ 胡椒来源不可用（提示"安全源已变更"，非密码错误） |
| **0xD** | **VERTHYS_ERR_EXPORT_TOO_MANY** | ★ 导出超出交换信封 65535 条容量（P1-8） |
| **0xE** | **VERTHYS_ERR_CNG_UNAVAILABLE** | ★ CNG 内核托管不可用（WP-1：导入失败/内核句柄缺失） |
| **0xF** | **VERTHYS_ERR_RESOURCE_LIMIT** | ★ 资源上限触顶（WP-7：内存 512MB / 后台线程等） |
| **0x10** | **VERTHYS_ERR_QUORUM_FAILED** | ★ 超级块法定人数提交失败（WP-2：VsbTxnV3 quorum 未达成） |
| **0x11** | **VERTHYS_ERR_PARTIAL_UNLOCK** | ★ 部分解锁成功（WP-5：渐进式解锁中途态，按成功分支处理） |
| **0x12** | **VERTHYS_ERR_TIMEOUT** | ★ 操作超时（WP-5：解锁流水线阶段超时） |
| **0x13** | **VERTHYS_ERR_UNSUPPORTED** | ★ 不支持的操作（WP-5 接线收口：V2 退役 op 统一语义化拒绝） |
| 0xFFFFFFFF | VERTHYS_ERR_INTERNAL | 未归类内部异常 |

**worker 侧反 Oracle 统一化（E-8）**：功能码（INVALID/NOTFOUND/EXISTS/LOCKED/RATE/SNAPSHOT/PEPPER\_SOURCE/EXPORT\_TOO\_MANY/CNG\_UNAVAILABLE/RESOURCE\_LIMIT/QUORUM\_FAILED/PARTIAL\_UNLOCK/TIMEOUT/UNSUPPORTED）透传前端；AUTH/FORMAT/IO/CORRUPT/INTERNAL 及未知码统一为 AUTH（防"密码错误 vs 文件篡改"区分泄露）。

### 13.2 应急故障码（emergency.h，进程退出码）
`0xE0001` 索引损坏 / `0xE0002` 注入阻断 / `0xE0003` 调试阻断 / `0xE0004` 内存篡改 / `0xE0005` 完整性失败 / `0xE0006` 多威胁（匿名类别码，不含隐私）。

---

## 14. 测试体系

### 14.1 测试框架
极简自研（`verthys_test.h`：TEST/CHECK/CHECK_EQ/RUN_TEST 宏）；**argv 过滤器**：`verthys_tests.exe <子串> [子串…]`（OR 语义，故障定位用）；无参数全量运行。

### 14.2 测试构建
- `build_dev`（VS 生成器 Debug）：`scripts/build_core.dev.ps1`（构建 + 强制全量测试）
- `build_asan`（`-DVERTHYS_ENABLE_ASAN=ON`）：AddressSanitizer 构建（CI 门）

### 14.3 测试清单（35 文件，250 项注册；镜像 src 子域）

| 子域 | 文件 | 覆盖 |
|---|---|---|
| api/ | test\_init / test\_verthys\_api / test\_v3\_lifecycle / test\_verthys\_export | 生命周期、公共 API 全链路、V3 创建/解锁/扫描家族（v3life\_scan\_family\_v3）、导入导出/改密 |
| container/ | test\_verthys\_format / test\_format\_fuzz / test\_v3\_container / test\_v3\_partition / test\_v3\_extent | 交换信封往返 + 篡改、V3 容器/分区/Extent 全链路（去重/引用守恒/回绕边界） |
| crypto/ | test\_crypto / test\_keymanager / test\_cng\_kernel / test\_auto\_rekey | AEAD、四级密钥、★ CNG 内核托管（WP-1）、★ 自动轮换三触发 + 防震荡（WP-7） |
| index/ | test\_v3\_lsm | LSM 插入/删除/查找/压实/close→reopen |
| transaction/ | test\_txn\_recovery\_inject | 六 Phase 崩溃注入矩阵（CONFIRM 前后/回滚后/同 txid 复活） |
| property/ | ★ test\_v3\_property | 不变式 harness（WP-12：LSM 影子模型 2000 步 / Extent 引用守恒 1200 步 / 事务一致性 48 混合 + 定向回归，揪出缺陷①②②b） |
| regression/ | test\_final\_repair | 最终修复方案 §6.1 回归（P0/P1 全覆盖） |
| schema/ | test\_flatcc\_demo | flatcc codegen 冒烟（WP-0） |
| security/ | test\_memory\_safety / test\_key\_separation / test\_emergency / test\_integrity\_verify / test\_secure\_allocator / ★ test\_runtime\_hash / ★ test\_syscall\_direct / ★ test\_defense\_closure | Lock 清零/UAF、CNG 三权分立、应急分级、`.vsec` 验签、安全分配器、★ .rhat 哈希 + 补丁注入检出（WP-8）、★ SSN stub 一致性（WP-9）、★ 7/7 BLOCKED（WP-11） |
| perf/ | test\_perf\_prefetch / test\_perf\_baseline | 温缓存回归、性能基准（解锁/吞吐） |
| fuzz/ | fuzz\_superblock / fuzz\_partition / fuzz\_extent / fuzz\_sstable / fuzz\_import + gen\_seeds | ★ WP-10：5 目标 `/fsanitize=fuzzer`，语料 = 测试生成合法容器 |

### 14.4 当前测试状态（如实记录，2026-09-15）

- **全量连跑**：**250/250 通过（0 failed）**——模块化重构后全新配置全量编译验证（历史：K-1 修复后 132/132 × 3 连绿 → V2 退役后 229 → 属性测试 254 → 删除 4 个 ad\_\* 死测试后 250）。
- fuzz 5 目标冒烟 + 属性测试期间持续模糊零崩溃；每目标 10 分钟全程验收待重装系统后补跑（本机恶意软件事件，构建产物已清除）。
- 复验命令：`scripts/build_core.dev.ps1 -NoPause`（强制全量测试）。

### 14.5 CI（.github/workflows/core.yml）
构建 Debug → 全量测试 → Release（含 `.vsec` 注入）→ **dumpbin 导出面与基线比对门** → 产物上传；ASAN job 复用 `VERTHYS_ENABLE_ASAN`。

---

## 15. 编译加固

### 15.1 当前配置（cmake/VerthysHardening.cmake）

| 类别 | 旗标 |
|---|---|
| 编译基线 | `/GS` `/guard:cf` `/guard:ehcont` **`/sdl`** `/wd4996`（偏差 D-2）`/utf-8` `/Zc:inline` |
| Release | `/O2 /Oi /Oy /GL /Gy /Gw` |
| 链接基线 | `/INCREMENTAL:NO /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` + x64 **`/CETCOMPAT`** |
| Release 链接 | `/LTCG /OPT:REF /OPT:ICF /DEBUG:NONE /RELEASE` |

### 15.2 偏差留痕（详见 [UPGRADE_EXECUTION_STATUS.md](./UPGRADE_EXECUTION_STATUS.md) §3）
- **D-1**：`/guard:longjmp` 未落地——工具链缺 `guardcfw.h`（C1083 实测）且与 /guard:cf 互斥（D9025）；CET 影子栈覆盖其意图。
- **D-2**：`/wd4996` 抑制 MSVC 对 ISO C 标准函数（fopen 等 43 处关键 IO）的劝告升级；/sdl 其余检查全生效。

---

## 16. 环境变量与部署

- 生产产物：`build/core/Release/verthys.dll`（含 `.vsec`）→ Tauri `resources`；`build.rs` 编译期固化 SHA-256，加载前校验（**DLL 补丁必须先于 Rust 构建**）。
- pepper 文件：`%APPDATA%\Verthys\pepper.bin`（v2，304B）。
- 环境变量注入：`scripts/env.load.ps1`（VERTHYS_VS_ROOT / VERTHYS_CMAKE_EXE / VERTHYS_CL_EXE / VERTHYS_VS_GENERATOR）。
- CI：GitHub Actions `core.yml`（windows-latest + msvc-dev-cmd）。

---

## 17. 安全边界声明

### 17.1 威胁模型
抵御**同机非特权用户态攻击者**（恶意软件、浏览器漏洞落地 payload）：可读自身进程内存、注入本会话进程、读取磁盘全部文件。

### 17.2 有效防线（按成本收益）
1. **进程即边界**：mitigation policy（内核强制）+ 双 Job + 主进程固化 DLL 哈希 + 锁库杀进程；
2. **密钥纪律**：verthys_secure_zero 全库贯彻 + 失败路径清零（测试覆盖）+ pepper CNG 机器绑定（跨设备不可解）；
3. **密码学本体**：Argon2id（防离线爆破）+ AEAD 全量密文落地 + 域分离。

### 17.3 明示的残余风险（诚实声明）
- 密钥明文**瞬态**经过用户态栈帧（E-5 诚实界定：BCrypt 无法内核句柄→内核句柄导入，解包输出必然短暂落地；规范 = 栈上即清、禁堆分配、禁传递）；CNG 内核托管已全量接线（WP-1），防 Dump 依赖 MEM\_DUMP 判据（`key_separation_any_installed`）。
- 编译内嵌兜底 pepper 为二进制可提取常量（零配置兜底的既定取舍；企业部署应使用 `verthys_pepper_inject` 注入强 pepper）。
- 用户态启发式检测（反调试/巡检）对特权攻击者无效——设计上仅作遥测与威慑。
- MachineGuid 指纹随重装系统改变（绑定语义使然；恢复走授权迁移/pepper 恢复卡）。

---

## 18. 已知问题与待办

### K-1（已解决，2026-09-01）：全量测试顺序依赖段错误
- **现象（历史）**：全量连跑在 `perf_diagnostics_metrics_complete` 处段错误；所有分组隔离与组合运行（含 58 项跨组、ASAN perf 组）均通过；崩溃点位于测试边界，ASAN 全量无报告，二进制布局敏感。
- **根因（ASAN 实锤）**：`verthys_btree.c` `leaf_split` 对父节点**双重插入**——手工插入 `(split_key, new_leaf)` 后又经 `internal_insert_propagate` 二次插入 → `key_count` 越界 → `keys[64]`/`children[65]` 越界写（`keys[64]` 覆写 union 起始处 `children[0]`，lid 整数误入子指针槽，ASAN 崩溃地址 0x421 = lid 1057 吻合；`children[65]` 覆写 parent/next 并溢出结构体尾部）→ 堆损坏 → 布局敏感跨模块野指针崩溃。修复：删除手工插入，完全委托 `internal_insert_propagate`。
- **连带修复**：`verthys_datablock.c` `pool_extend` 池类型判断误将 `VerthysV2PoolDesc*` 指针与枚举整数比较（恒为假）→ SMALL/MEDIUM 池落入 LARGE 分支（上界=尾部区域）→ SMALL 池扩展越界零写毁坏 MEDIUM 池（`repair_pool_extend_boundary` 失败根因）。修复：与 `&mgr->pools[...]` 地址比较。
- **验证**：全量 3 连绿（132/132 × 3，Debug build_dev）；CI `core.yml` 全量测试门经复核本就完好（无分组降级策略实际生效），无需恢复。
- **沉淀资产**：RUN_TEST 宏测试间状态快照断言（线程/句柄/GDI/emergency 差异打印 `[LEAK?]`）+ 组间 `[ CHECKPOINT ]` 基线增量 + 每测试后强制 `emergency_clear_signals()` + `scripts/k1_asan_run.ps1` ASAN 诊断脚本。

### K-2（已解决，2026-09-15）：V3 工作包全量落地
FlatBuffers schema 工具链（WP-0）→ V3 超级块分区认证（WP-2）→ LSM 索引（WP-4）→ 内容寻址 Extent（WP-3）→ CNG 密钥全量接线（WP-1）→ 解锁流水线/渐进式解锁（WP-5）→ 密钥自动轮换（WP-7）→ 运行时哈希（WP-8）→ 直接系统调用（WP-9）→ 防御闭环 7/7（WP-11）→ 属性测试（WP-12）→ fuzz 基建（WP-10）→ P2 清零（WP-14）→ **V2 退役 + worker 适配（E-8）+ core 模块化重构**。执行留痕逐包见 [V3\_UPGRADE\_PLAYBOOK.md](./V3_UPGRADE_PLAYBOOK.md) §5；验收状态见其 §9 里程碑矩阵（M0-M3 ✅，M4/M5 待重装后复验收口——本机恶意软件事件产物清除）。

### K-3（已解决，2026-09-15，WP-14 六项全部闭环）
GC 超级块裸写（P2-2，结构性吸收）、读块 data\_size 无钳制（P2-4，V3 三重校验 + 回绕安全分解）、vtxn\_rollback 空壳（P2-5，VsbTxnV3 完整恢复）、温缓存 .tmp 竞态（P2-7，V3 原子替换）、扫描游标生命周期（P2-8，v3\_owner 身份锚点）、mountwatch INFINITE（P2-10，随 V2 删除）。逐项留痕见 [V3\_UPGRADE\_PLAYBOOK.md](./V3_UPGRADE_PLAYBOOK.md) §5 WP-14 表。

---

## 19. 附录：常量速查表

| 常量 | 值 | 出处 |
|---|---|---|
| VERTHYS_KEY_BYTES | 32 | verthys_crypto.h |
| VERTHYS_SALT_BYTES | 16 | verthys_crypto.h |
| VERTHYS_AEAD_NONCE_BYTES | 24 | verthys_crypto.h |
| VERTHYS_AEAD_MAC_BYTES | 16 | verthys_crypto.h |
| VERTHYS_HMAC_BYTES | 32 | verthys_crypto.h |
| VERTHYS_ARGON2_MEM_KIB / ITERS / PARALLEL | 65536 / 3 / 1（SECURE） | verthys_crypto.h |
| VERTHYS_ARGON2_BALANCED_MEM_KIB / ITERS / PARALLEL | 32768 / 2 / 1（校准默认） | verthys_crypto.h |
| VERTHYS_ARGON2_CALIBRATE_TARGET_MS / BALANCED_ITERS_MAX | 1200 / 3 | verthys_crypto.h |
| VERTHYS_NAME_MAX_BYTES | 4096 | verthys_internal.h（P1-9） |
| VERTHYS_RECORDS_MAX | 1,000,000 | verthys_api_utils.c（P1-3） |
| KEYSEP_AEAD_NONCE_BYTES（CNG） | 12 | key_separation.h |
| EMERG_WINDOW_MS / EMERG_DEGRADE_THRESHOLD | 600,000 / 2 | emergency.h |
| EMERG_HISTORY_SLOTS | 8 | emergency.h |
| VSEC 节大小 / magic | 128B / 'VESC'（0x43534556 LE） | integrity.c |
| RHAT 表项 / 上限 / magic | 48B（RVA+size+BLAKE2b-256）/ 40 / 'VRHT' | runtime_hash.h |
| 运行时哈希重扫间隔 | 30 分钟 | runtime_hash.h（WP-8） |
| VERTHYS_PEPPER_FILE_BYTES（v2）/ FP_BYTES | 304 / 8 | verthys_pepper.c |
| .def 导出数 | 29 | verthys.def / ci/export_baseline.txt |
| VERTHYS_API_VERSION | 0x000B | verthys.h |

---
