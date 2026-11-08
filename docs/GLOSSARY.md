# 术语表（GLOSSARY）

> 统一 Verthys 全项目专有名词与标识符的中英文对照与定义，术语均来自真实代码标识符并附出处。
>
> Last updated: 2026-09-19 · 维护人：K1Super

约定：本表术语以代码真实命名为准；「主要出处」以 `core/`、`verthys-tauri/` 为相对根。已废弃旧名（`.vault`、`valt://`、`VALTCORE_*`、`Vault_*`、valtcore.dll）仅允许出现在历史/迁移语境，见 [MIGRATION.md](MIGRATION.md)。

---

## 1. 容器与存储

| 中文术语 | 英文/标识符 | 定义（一句话，可验收/可定位） | 主要出处 |
|---|---|---|---|
| Verthys 容器 | .verthys / 当前容器格式（`VTY_MAGIC` `'VRTY'`） | 唯一现役的加密容器文件，A/B 元数据 + 追加数据区 + 双包裹密钥 + 模块槽 | `core/src/container/vty_format.c`、`core/include/verthys_version.h` |
| 容器格式版本 | `VERTHYS_CONTAINER_FORMAT_VERSION` | 落盘格式身份，当前为 4；只作为常量/版本字段存在，不进入文件名 | `core/include/verthys_version.h` |
| 元数据副本 | metadata A/B | 双副本原子提交的容器根元数据，单副本损坏不阻断打开 | `core/src/container/vty_format.c` |
| 密钥槽 | key slot | 口令/恢复码/keyfile 等因子的包裹槽位 | `core/src/container/vty_keyslot.c` |
| 模块槽 | module slot | 相册/账号/清藏模块的独立密钥与启用状态 | `core/src/container/vty_module.c` |
| 内容分片 | chunk | 大对象切分后的加密数据块，经 Rust 单写者通道落盘 | `core/src/container/vty_chunk.c` |
| 记录 | record | 容器内的类型化条目（账号、照片元数据等） | `core/src/index/vty_record.c` |
| 仓库 | repo / store | 记录读写、类型盲索引与数据区存储 | `core/src/index/vty_repo.c`、`vty_store.c` |
| 交换信封 | exchange envelope | 导出/导入用的独立加密文件包（不继承应用胡椒） | `core/src/container/format/verthys_format.c` |
| 导入 WAL | import.wal | 导入断点续传日志（Rust 仓储层，附属目录内） | `verthys-tauri/src-tauri/src/repository/verthys_wal.rs` |

## 2. 密码与密钥

| 中文术语 | 英文/标识符 | 定义 | 主要出处 |
|---|---|---|---|
| 密钥守卫 / CNG 内核托管 | key_separation / CNG | A/B/C 密钥导 CNG 内核句柄，用户态仅瞬态栈帧 | `core/src/security/memory/key_separation.c` |
| 胡椒 | pepper（`verthys_pepper` / `VERTHYS_ERR_PEPPER_SOURCE`） | Argon2id 混入的应用级胡椒，三层来源 + 来源指纹 + 禁兜底 | `core/src/crypto/pepper/verthys_pepper.c` |
| 域密钥 | domain key（`K_VSEC_DOMAIN_KEY`） | 构建期 `.vsec` 签名域密钥，双侧逐字节一致 | `core/src/security/integrity/integrity.c` |
| 机器绑定 | machine binding / `MachineGuid` | 容器跨设备不可解，CNG RSA-OAEP 包装 + MachineGuid 指纹 | `core/src/security/layer3_hw_binding/hardware_binding.c` |
| 全局主密钥 | GMK（`VERTHYS_GLOBAL_KEY_VERIFIER_v2__`） | 全局主密钥，worker 子进程内 `Zeroizing` 持有，永不出 worker | `verthys-tauri/verthys-worker/src/runtime/gmk.rs` |
| 域分离 | domain separation / HKDF info | 用唯一标签隔离各派生用途，如 `verthys/master-key-v1`、`verthys/module/` | `core/src/crypto/cipher/verthys_crypto.h` |
| Argon2id | Argon2id（校准 `argon2_calibrate`） | 内存硬口令派生，创建期两段式校准选参（目标 ~1.2s） | `core/src/crypto/cipher/verthys_crypto.c` |
| XChaCha20-Poly1305 | XChaCha20-Poly1305（24B nonce） | libsodium AEAD，用于交换信封/兼容路径 | `verthys_crypto.c` |
| CNG | Cryptography Next Generation | Windows 内核态密码服务 API（BCrypt AES-GCM，12B nonce） | `core/src/crypto/cipher/verthys_crypto_cng.c` |
| 恢复卡 | Shamir 分片 | pepper 恢复的 k-of-n 分片方案 | `verthys_pepper.c` |

## 3. 安全防御

| 中文术语 | 英文/标识符 | 定义 | 主要出处 |
|---|---|---|---|
| .vsec | 构建期签名节（magic `'VESC'`） | `.text`/`.rdata` 文件内容 HMAC-SHA256 构建期签名（128B），启动验签 | `core/src/security/integrity/integrity.c` |
| .rhat 运行时哈希 | runtime hash（magic `'VRHT'`） | 关键函数 BLAKE2b-256 运行时哈希（产品 15 项 / 全量 40 项），失配 = KILL | `core/src/security/integrity/runtime_hash.c` + `core/tools/rhash_gen.c` |
| 容器解锁 | vty_vault_open | 单阶段原子解锁：口令 + 设备根双槽解封 `K_c` → 元数据与 DataRoot 挂载；全部成功才进入 UNLOCKED | `core/src/crypto/vty_keymanager.c` |
| 层 1-6 防御 | layer1..6 | 进程守卫/硬件绑定/钩子防御/沙箱/闭环的分层纵深防御 | `core/src/security/layer*_*` |
| 防御闭环 | defense closure / 7 路径 | 7 条攻击路径状态机（BLOCKED/DEGRADED/FAILED） | `core/src/security/layer6_closure/defense_closure.c` |
| 应急分级响应 | emergency / TELEMETRY·DEGRADE·KILL | 三级信号模型，检测与响应解耦 | `core/src/security/emergency/emergency.c` |
| 直接系统调用 | syscall_direct / SSN | SSN 排序法提取 + W^X stub 页，失败优雅降级 | `core/src/security/anti_analysis/syscall_direct.c` |
| 安全分配器 | secure_allocator | 密钥专用 VirtualAlloc 隔离堆 + 全局内存预算记账 | `core/src/security/memory/secure_allocator.c` |
| 部分解锁返回码（保留） | `VERTHYS_ERR_PARTIAL_UNLOCK`(0x11) | 冻结 ABI 保留码；当前解锁为单阶段原子完成，不产生该返回 | `core/include/verthys.h` |

## 4. 进程与工程

| 中文术语 | 英文/标识符 | 定义 | 主要出处 |
|---|---|---|---|
| worker 子进程 | verthys-worker | 加载 DLL + 单线程 FFI 转发，BELOW_NORMAL 优先级 | `verthys-tauri/verthys-worker/src/main.rs` |
| FFI | C ABI / libloading | C DLL 与 Rust 的边界，libloading 按名解析 29 白名单符号 | `verthys-tauri/verthys-worker/Cargo.toml` |
| NSIS | nsis | Tauri Windows 安装包目标 | `verthys-tauri/src-tauri/tauri.conf.json` |
| keyboard-types | keyboard-types（本地补丁） | Rust 键盘事件类型 crate，项目以本地补丁修复 serde 兼容 | `verthys-tauri/src-tauri/Cargo.toml`（[patch.crates-io]） |
| 状态魔法数 | `STATE_MAGIC`（`VERTHYS_STATE`） | 状态文件 magic 前缀（与版本号分离） | `verthys-tauri/src-tauri/src/constants.rs` |
| 进程隔离（双层 Job） | job_isolation | 双层 Job Object + 白名单 DACL（进程守卫） | `core/src/security/layer1_process_guard/job_isolation.c` |