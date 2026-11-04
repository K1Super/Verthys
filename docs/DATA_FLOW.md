# DATA_FLOW — Verthys 关键数据流

> 用时序图说明解锁、加解密、导出、更新/完整性校验、导入域与全库 DEK 轮换六类跨层数据流，标注各方参与模块。
>
> Last updated: 2026-09-28 · 维护人：K1Super

---

> 调用链约定：前端控制器 → Tauri command → worker actor（stdin JSON）→ core API（C ABI）→ 容器/密钥模块 → OS/存储。核心 API 契约见 [CORE_API.md](CORE_API.md)，桥接命令以 `verthys-tauri` 的 command 注册为准。

## 1. 解锁流程

```mermaid
sequenceDiagram
    participant FE as 前端控制器（Vue3）
    participant TC as Tauri command（verthys_controller.rs）
    participant WK as verthys-worker（dispatch→FFI）
    participant API as core API（Verthys_Unlock）
    participant KM as 密钥模块（keymanager/pepper/CNG）
    participant CT as 容器模块（superblock/partition/lsm/wal）
    participant OS as OS/CNG 内核
    FE->>TC: invoke unlock
    TC->>WK: {op:unlock}（stdin JSON，含 password）
    WK->>API: Verthys_Unlock(handle, path, pw, flags)
    API->>API: S0 前置检查 + pepper 快速失败
    par 并行
        API->>CT: S1 读 3 副本超级块
        API->>KM: S2 DKM=Argon2id(pw‖pepper)→MEK=HKDF
    end
    API->>KM: S3 pepper/CNG 机器密钥 + MEK 导入内核
    API->>OS: BCryptGenerateSymmetricKey（MEK/A/B/C 句柄）
    API->>CT: S3 副本 HMAC 法定人数裁决
    API->>CT: S4 分区表加载
    API->>CT: S5 LSM 温缓存/冷启动 + WAL 恢复
    API->>API: S6 最终校验
    API-->>WK: VERTHYS_OK / PARTIAL_UNLOCK
    WK-->>TC: {op:unlock, ok}
    TC-->>FE: 解锁结果
```

## 2. 加解密流程（单条记录写入 + 读取）

```mermaid
sequenceDiagram
    participant FE as 前端控制器
    participant TC as Tauri command（verthys_batch_controller.rs）
    participant WK as verthys-worker
    participant API as core API（Verthys_AddRecord/GetRecord）
    participant TX as 事务模块（txn/wal）
    participant IDX as 索引模块（LSM）
    participant EXT as Extent/分区模块
    participant KM as 密钥模块（CNG 内核）
    participant OS as OS/磁盘
    FE->>TC: invoke add_record
    TC->>WK: {op:add_record, name, data(base64)}
    WK->>API: Verthys_AddRecord
    API->>TX: txn begin（txid+1，WAL BEGIN）
    API->>EXT: 明文→BLAKE2b（内容寻址哈希/查重）
    API->>KM: CNG 内核态 AEAD 加密（分区 B 密钥）
    API->>EXT: 追加写入 Extent 分区
    API->>IDX: MemTable 插入（key→extent 引用）
    API->>TX: PREPARE → COMMIT（超级块法定人数）
    TX->>OS: WAL + 超级块副本落盘（fsync）
    API-->>WK: VERTHYS_OK + lid
    WK-->>TC: {op:add_record, ok, id}
    TC-->>FE: 新记录 lid
    Note over FE,OS: 读取：GetRecord → LSM 查引用 → Extent 定位 → CNG 内核解密 → 校验 BLAKE2b
```

## 3. 数据导出流程

```mermaid
sequenceDiagram
    participant FE as 前端控制器
    participant TC as Tauri command（file_controller.rs）
    participant WK as verthys-worker
    participant API as core API（Verthys_Export）
    participant SC as 扫描游标（Verthys_Scan*）
    participant KM as 密钥模块（导出密钥，不混胡椒）
    participant OS as OS/导出文件
    FE->>TC: invoke export（导出路径 + 独立口令）
    TC->>WK: {op:export, path, password}
    WK->>API: Verthys_Export(handle, path, pw)
    API->>KM: 导出口令派生（keymanager_derive_master_export，无胡椒）
    loop 游标分批
        API->>SC: ScanFetch 逐条取得记录
        API->>KM: 逐条解密（明文经用户态缓冲）
        API->>OS: 流式分片写入导出文件
        API->>API: 明文缓冲用后清零
    end
    API-->>WK: VERTHYS_OK（或 EXPORT_TOO_MANY）
    WK-->>TC: {op:export, ok}
    TC-->>FE: 导出完成
```

## 4. 更新/完整性校验流程

```mermaid
sequenceDiagram
    participant API as core API
    participant INT as 完整性模块（integrity/runtime_hash）
    participant CT as 容器模块（superblock/extent/merkle）
    participant KM as 密钥模块（CNG 内核）
    participant OS as OS/磁盘
    Note over API,OS: 更新 = 写入事务（同 §2 的 BEGIN→…→COMMIT）；更新后防回滚：
    API->>CT: 超级块 txid 单调递增 + state_chain 防回滚
    API->>CT: partition nonce 计数器防重用/防回退
    API->>INT: runtime_hash_verify_periodic（写路径入口，30 分钟门控）
    INT->>INT: 关键函数内存映像 BLAKE2b 与 .rhat 比对
    Note over API,OS: 完整性校验 = Verthys_VerifyIntegrity：
    API->>CT: 遍历全部数据块
    CT->>KM: 逐块 CNG AEAD 标签校验
    CT->>CT: Merkle 树哈希校验（merkle_leaf）
    CT-->>API: 输出损坏 lid 列表 + 损坏数
    API->>INT: 启动期 integrity_verify_startup（.text/.rdata/.rhat HMAC）
```

## 5. 导入域数据流（会话 · 台账 · 去重跳过与结算）

图片（拾光）与文件（清藏）两条导入链路共用同一写入通道：全部写入经单写者
串行，块归属由台账记账，孤儿块回收前先与会话日志结算。

### 5.1 导入会话与台账结算（含 GC 守卫）

```mermaid
sequenceDiagram
    participant FE as 前端管道（useFileImport / importPipeline）
    participant TC as Tauri command（verthys_batch_controller.rs）
    participant IW as 单写者通道（state/import_writer.rs）
    participant LG as 块台账（repository/verthys_chunks.rs）
    participant WL as 会话日志（repository/verthys_wal.rs）
    FE->>TC: import_begin
    TC->>WL: 载入快照 → 结算（committed chunk_ids → 台账 owner）并落盘
    Note over TC: 结算落盘失败即拒绝创建会话（防未结算引用被回收）
    FE->>TC: add_chunk_batch（块上传）
    IW->>LG: 块入账 owner=0（上传中）
    IW->>WL: 追加 pending
    FE->>TC: add_records_batch（元数据）
    IW->>LG: owner 改写为元数据 ID
    IW->>WL: 追加 committed（含 verthys_id + chunk_ids）
    FE->>TC: import_end（success=true）
    IW->>LG: 台账落盘（失败即拒绝结束、保留日志供续传）
    IW->>WL: 压缩日志
    FE->>TC: gc_orphan_chunks
    TC->>WL: 先结算（无法证明归属的历史条目冻结为不可回收值）
    TC->>LG: 回收 owner 为空且已结算的块
```

### 5.2 续传幂等与删除释放

- **条目键**：`entry_key = SHA-256(source_path | size | mtime)`（解析导入为展示名/大小/序号）；
  非内容哈希，只用于断点续传幂等，不做内容寻址或存在性判定。键集合持久于会话日志。
- **块键**：`chunk_key = SHA-256("chunk" | entry_key | seq)`；记录名为 `chunk_<chunk_key>`，
  同一条目重试复用 ID，不同路径同内容各自落块。
- **导入**：条目键命中即"续传跳过"（不计失败、不入列表、显式报告）；
  不做内容级去重，同内容不同路径会分别导入。
- **删除**：记录批量删除并落盘成功后执行 `verthys_forget_import_keys`（日志追加删除墓碑）
  释放条目键，同一来源文件即可重新导入；释放失败转入待重试队列，由下次导入开始前补释放。
- **清藏删除**：块引用与元数据合并单次批量事务删除；删除提交后立即失效三层缓存
  并落盘。失败语义：删除失败保持原状可重试（零副作用）；落盘失败保持条目并提供
  "仅重放落盘"的重试入口（批量删除对缺失条目整体拒绝，删除步骤不可重放）；
  去重释放失败不改变删除结论。
- **内存口径**：分片读取上界 4MiB/次（越界即报错），块载荷在进程间层为 base64
  但受批量预算约束（≤11.19MiB/批）；导入/导出内存占用与文件大小无关。

## 6. 全库 DEK 轮换数据流（v4 D9，API 版本 0x0010）

仅恢复码会话可发起；源库作业期间只读。轮换在新文件中全量重建后原子替换，
旧恢复码继续有效。

```mermaid
sequenceDiagram
    participant FE as VaultRotateDialog
    participant TC as vault_rotate_controller / service
    participant WK as verthys-worker
    participant DLL as verthys.dll（vty_rotate_v4）
    participant FS as 文件系统
    FE->>TC: attach_keyfile(path)（容器启用 KEYFILE 且会话无摘要时）
    TC->>WK: {op:v4_rotate_attach_keyfile}
    WK->>DLL: 读取 VKFL + 口令验证 user 槽，缓存摘要
    FE->>TC: begin(new_path, flags)（容器口令由宿主注入）
    TC->>WK: {op:v4_rotate_begin}
    WK->>DLL: Verthys_V4RotateBegin
    DLL->>FS: 创建临时新库（新 K_c / epoch+1 / 恢复槽重封）
    DLL-->>FE: 统计( stage=BEGUN, modules_ready, records… )
    FE->>TC: unlock_module(module_id, 模块口令)
    TC->>WK: {op:v4_rotate_unlock_module}
    WK->>DLL: 校验模块口令并解锁源 MDEK
    FE->>TC: run(onProgress, cancel_event)
    TC->>WK: {op:v4_rotate_run}
    WK->>DLL: Verthys_V4RotateRun(cb)
    loop 逐模块/逐记录/逐分片/逐文件
        DLL->>FS: 复制并以新 K_c 重新加密
        DLL-->>WK: 进度回调（统计；取消事件置位时返回 1）
        WK-->>FE: 签名进度行（200ms 节流）
    end
    DLL->>DLL: 记录数/文件数/分片数完整性复核
    DLL-->>FE: stage=COPIED
    FE->>TC: commit(keep_old) 或 abort()
    TC->>WK: {op:v4_rotate_commit | v4_rotate_abort}
    WK->>DLL: Verthys_V4RotateCommit / Abort
    DLL->>FS: （提交·PCR）覆盖前落盘 <库路径>.vtyrotj 恢复日志
    DLL->>FS: （提交）ReplaceFileW 单次原子替换（旧库→备份）+ 回退锚点推进
    DLL->>FS: （提交·PCR）删除恢复日志
    DLL->>DLL: （中止）删除临时库；删除失败返回 IO，源库不变
```

关键约束：

- **只读窗口**：Begin 成功后源库 `rotate_pending=1`，记录/文件/模块/口令/PCR/keyfile
  写入口统一返回 `ROTATE_PENDING`；宿主 UI 不得在此期间放行写操作。
- **已删除文件模块**：源库 fileverthys `deleted` 时跳过文件/分片复制，仅允许
  墓碑；记录复制与提交照常，`next_id` 水位保留，已删除高位 ID 不复用。
- **复制自检**：记录/文件/分片写入新库后逐条回读比对，任何偏差返回 `VERIFY`，
  提交前不会把“计数相同但内容漂移”当成成功。
- **锁定/退出**：lockAll 先调用 `verthys_prepare_lock` 请求取消并等待全部轮换
  操作（Begin/解锁模块/Run/补录/Commit/Abort）在途计数归零（30s 上限），
  失败整体放弃锁定并保留会话；`verthys_lock`/`worker_destroy`
  内部保留同一闸门，并以会话代际（`session_epoch`）原子校验，代际已变返回
  `E_LOCK_SUPERSEDED`，延迟命令不得清空新会话；代际已变且无任何会话时
  补全释放无归属的哨兵锁与旧文件锁。空闲锁定仅在轮换命令在途时
  抑制（ready/failed 解除），安全边界在 Rust。进程级硬退出路径不可拦截，
  其崩溃窗口由 PCR 恢复日志兜底。
- **PCR 崩溃恢复**：Commit 在覆盖 PCR 密钥前落盘恢复日志；若进程在重封后、
  替换前退出，下次口令解锁仅当“日志与当前文件代/位图/策略摘要一致且平台
  PCR 未变”时用当前 `K_c` 重封并重新验证，否则 fail-closed（恢复码仍可打开）。
- **IPC 超时**：流式或普通请求超时后强制回收 worker（kill + 标记死亡），
  下一次请求从新进程开始，不读取旧序号残留行。
- **口令边界**：容器口令由主进程保管模块读取；模块口令只经本次 IPC 透传，worker
  不缓存、不写日志；恢复码不进入普通轮换请求。
- **失败态**：复制/复核失败进入 `FAILED`，只能 `Abort`；`Abort` 删除临时库并释放作业，
  源库保持原状。
- **提交后状态**：C 句柄指向新会话、恢复标记清零；宿主重建会话哨兵锁，前端同步
  收起恢复会话提示。