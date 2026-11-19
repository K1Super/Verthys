# 02 — 数据模型与兼容

> 状态：评审中 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 本文定义照片数据面的记录类型、元数据扩展、预览记录、分块口径、VENC 边界与旧数据兼容策略。

---

## 1. 记录类型

现有照片相关类型（`src/constants/record_types.ts` 与 `src-tauri/src/constants.rs`）：

| 类型 | 值 | 用途 |
|---|---|---|
| `TYPE_PHOTO_META` | `0x01` | 照片索引/元数据 |
| `TYPE_PHOTO_CHUNK` | `0x05` | 照片数据块 |
| `TYPE_PHOTO_THUMB` | `0x07` | 缩略图记录（索引瘦身布局） |
| `TYPE_PHOTO_CHUNK_SET` | `0x09` | 块集记录（逐块 ID/哈希） |
| `TYPE_PHOTO_PREVIEW`（新增） | `0x0B` | 2048px 预览记录 |

约束：

- `0x0B` 取扩展域空闲值；不得复用 `0x08`（文件保险箱元数据）或 `0x0A`（自定义类型定义）。
- C 层把 `rtype` 当标签，不按值做业务校验；新增类型只需 TS/Rust 常量同步，不改 `VerthysRecordType` 枚举。
- 新类型必须加入 Rust `is_supported_chunk_rtype` 白名单（若预览记录走外置记录写入通道），并补单元测试。
- 记录名规则：
  - 缩略图：`thumb_<chunk_key>`（沿用现有规则）
  - 块集：`cset_<chunk_key>`（沿用）
  - 预览：`preview_<entryKey>`（无 `entryKey` 时退回 `preview_<metaId>`，见第 4 节）
- 内容种类：新增 `kind = "preview"`，种类码 `9`。必须同时加入：
  - worker `module_keys.rs` 的 `kind_code` 与 `open_inner` 白名单；
  - `src-tauri/src/controller/module_crypto_controller.rs` 的 `CRYPT_KINDS`；
  - 种类错配（preview ↔ thumb/meta/chunk）必须认证失败。

## 2. `PhotoMeta` 扩展

保持 JSON、加密后存 `TYPE_PHOTO_META` 记录。新增字段全部可选，旧读取器忽略未知字段。

```json
{
  "name": "IMG_0001.jpg",
  "mime": "image/jpeg",
  "size": 10485760,
  "thumbB64": "<400px JPEG base64>",
  "chunkIds": [101, 102, 103],
  "chunkHashes": ["...", "...", "..."],
  "fileHash": "<BLAKE3 hex>",
  "createdAt": 1763500000000,
  "animated": false,
  "chunkSize": 4194304,
  "width": 6000,
  "height": 4000,
  "orientation": 1
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `chunkSize` | `number?` | 新导入块大小（4MiB）；缺省按 1MiB 历史口径理解；读取侧不得用固定块长校验 |
| `width` / `height` | `number?` | 原始像素尺寸（应用 EXIF 方向后） |
| `orientation` | `number?` | EXIF 方向值（1–8），无则缺省 |
| `animated` | `boolean?` | 动图三态：true/false/缺省（历史未探测） |

不新增 `previewId` 字段：预览用确定性名称定位，避免旧记录迁移与 meta 重写。

### 2.1 缩略图

- 新导入仍把 400px JPEG 缩略图内联在 `thumbB64`，保持旧读取路径与列表缓存行为不变。
- 预留在 Phase 4 将缩略图拆为独立记录并通过二进制批量下发；该阶段需扩展 `thumbId` 的读取分流（不再依赖 `fmt=2`）。
- 单张缩略图目标 ≤45,000 base64 字符（现有预算），避免索引越过扫描缓存阈值。

### 2.2 预览

- 长边 2048px，编码档位 2048/0.82 → 2048/0.70 → 1600/0.75 → 1280/0.70，512KB 预算内取首个符合档位；目标 150–450KB（噪声类极端样本允许接近 512KB）。
- 独立记录、独立加密（模块 MDEK，内容种类 `preview`）、独立完整性哈希。
- 预览只服务首屏；不替代原图、不参与编辑、不进入 VENC 备份清单。

## 3. 分块口径

### 3.1 新导入

- 明文块大小：**4MiB**（4,194,304 字节）。
- 块数 = `ceil(字节数 / 4MiB)`。例如 10MiB=3 块、17.73MiB=5 块、
  24.43MiB=7 块、50MiB=13 块、100MiB=25 块；旧 1MiB 分块对应
  10/18/25/50/100 块。10MiB 只是样本，不是产品上限。
- 块密文通过 `Verthys_V4ChunkSeal` 裸字节接口产生；`file_uuid`、`seq`、`total` 语义不变。
- 块记录通过 `Verthys_AddRecords` 批量写入，单批 128–512 条。

### 3.2 兼容

- 旧 1MiB 块继续可读；读取侧只依赖 `chunkIds` 顺序与总字节数，不依赖固定块长。
- 需要审计并移除/放宽的固定 1MiB 假设：
  - `container-import.worker.ts` 的 `chunk.length > CHUNK_SIZE` 校验；
  - 任何以 `CHUNK_SIZE` 推导块数的路径；
  - VENC 解析单帧上限保持 `PARSE_MAX_FRAME_BYTES`（64MiB），4MiB 安全。
- 新块大小在 Gate G0 验证 C 层最大 `plain_len` 与记录长度上限后生效。

### 3.3 索引体积

4MiB 分块下，100MiB 照片的 `chunkIds` + `chunkHashes` 约 25 项，JSON 体积约 2KB；24.43MiB 照片约 7 项，远低于扫描缓存 64KB 阈值。无需为照片启用索引瘦身布局。

## 4. 预览记录的确定性命名

### 4.1 命名

```text
preview_<entryKey>      // meta 携带 entryKey（新导入与绝大多数历史记录）
preview_<metaId>        // meta 无 entryKey：历史记录缺省
```

- `entryKey` 由导入条目确定（`sha256("file|" + name + "|" + size + "|" + mtime_ms)`），跨重启稳定，且在 meta 记录 ID 分配前即已知。
- 新导入在同一批次内写入 meta 与预览，此时 metaId 尚不存在，只能使用 `entryKey`。
- 记录类型 `TYPE_PHOTO_PREVIEW`，载荷为加密 JPEG。
- 同一照片至多一条预览记录；重复生成按记录名幂等覆盖/复用。

### 4.2 为什么不用 meta 字段

- 旧照片的 meta 已加密落盘；新增字段需要重写 meta，改变记录内容与 WAL/去重语义。
- 确定性名称让旧照片可以**懒生成预览**：首次查看时生成 `preview_<entryKey>`（无 entryKey 则 `preview_<metaId>`），后续直接命中，无需迁移。
- 新旧照片走同一读取逻辑：先查预览记录，缺失则回退原图/懒生成。

### 4.3 预览索引（名称 → 记录 ID）

记录名不能直接作为读取键（C API 按记录 ID 读取），需要一层名称索引：

- 容器已有名称盲索引（`vty_name_index` / repo leaf `name_index`）。新增 C API
  `Verthys_FindLidByName(handle, name, name_len, &found, &lid)`，按精确名称查 ID，自动跳过墓碑。
- `photo_preview_get(metaId)`：先按 meta 选择命名规则（`entryKey` 优先）→ `FindLidByName`
  → 命中则按 ID 读取；未命中则懒生成。
- 新导入/懒生成成功后无需额外登记（名称索引本身持久化）；worker 不做跨请求缓存。
- 删除：按同一命名规则查 previewId 后级联删除；找不到视为无预览。
- 索引不是安全边界：预览记录本身的 AEAD 与记录类型仍是权威校验。

### 4.4 生命周期

| 事件 | 行为 |
|---|---|
| 新导入完成 | 导入任务生成预览密文，与 meta 同一批次写入（失败不阻断导入） |
| 旧照片首次查看 | 预览缺失 → 原图解密 → 原生生成 → 宿主写回预览记录 → 返回 |
| 删除照片 | 删除对应预览记录（删除事务前解析预览 ID 并入同一批） |
| 密钥轮换 | 预览记录随模块记录一起换封；不额外迁移 |
| 备份还原 | 不携带预览；还原后首次查看懒生成 |
| 预览损坏 | 视为缺失，重生成；不阻断原图 |

### 4.5 完整性

- 预览记录使用现有模块记录 AEAD；记录名绑定照片条目。
- 预览明文头部为 32 字节 BLAKE3 原始 `fileHash`（无 metaId）：读取侧解密后必须与当前
  meta 的 `fileHash` 一致；不一致视为缺失并重新生成，防止记录 ID 复用/孤儿预览错配。
- 写入前若索引命中同一照片的旧预览，名称幂等由写者保证；预览头校验是第二道防线。
- 若解密失败：按“预览缺失”处理，尝试原图；原图也失败才报照片损坏。
- 预览记录不参与原图 `fileHash` 校验的权威判定；它只是派生缓存。

## 5. VENC 容器边界

- `LightMeta` 字段集合保持不变：`name / mime / size / thumbB64 / fileHash / createdAt / chunkCount`。
- 不新增预览帧、不改格式版本；旧 `.venc` 继续可导入。
- 新导入的 4MiB 块在导出时按现有块序列打包，`chunkCount` 相应减少；解析侧按清单块数读取，不依赖固定块长。
- 备份还原后预览按第 4.4 节懒生成；备份本身不承诺秒开。

## 6. 缓存与派生数据

### 6.1 前端

- 缩略图：现有 Blob URL + 释放点不变。
- 预览/原图：新增有界 Blob URL LRU：
  - 键：`preview:<metaId>` 与 `full:<metaId>`（预览/原图独立键空间，互不误命中）；
  - 上限：按字节（默认 64MB）或最近 5 项，先到者淘汰；
  - 释放：模块卸载、密钥锁定、登出、照片删除、LRU 淘汰。
- 不在 `localStorage`/`IndexedDB` 持久化任何明文或 Blob。

### 6.2 Worker/主进程

- 不长期缓存照片明文；SHM 为 job 级，job 结束即零化销毁。
- 预览记录是加密落盘缓存；解密后的预览只存在于 SHM 与前端 Blob URL。
- 如需二级解密缓存，必须先通过安全评审；默认不做。

## 7. 旧数据兼容矩阵

| 数据形态 | 新读取 | 新写入 | 说明 |
|---|---|---|---|
| 1MiB 块 + 内联缩略图 + 内联 chunkIds | 支持 | 不再新建 | 现有照片 |
| 1MiB 块 + 瘦身布局（thumb/cset 独立） | 支持 | 不再新建 | 历史布局二 |
| 4MiB 块 + 内联缩略图 + 内联 chunkIds | 支持 | 新导入 | 本方案 |
| 预览记录存在 | 优先 | 新导入/懒生成 | `preview_<entryKey>`；无 entryKey 用 `preview_<metaId>` |
| 预览记录缺失/损坏 | 回退原图/重生成 | 懒生成 | 不阻断 |
| 旧 `.venc`（1MiB 块） | 支持 | — | 备份还原 |
| 新 `.venc`（4MiB 块） | 支持 | 支持 | 清单字段不变 |

## 8. 数据模型验收

1. 新导入记录同时被新原生读链路与旧 JS 读链路读取（查看/导出）。
2. 旧 1MiB 照片在未生成预览时可正常查看，生成预览后二次打开 ≤50ms。
3. 4MiB 块通过 VENC 导出/还原后字节完全一致，BLAKE3 校验通过。
4. 删除照片级联删除预览记录，块台账与 GC 不残留。
5. 预览生成失败不改变照片可用性；错误只影响预览路径。
6. 新增记录类型不与其他类型冲突，TS/Rust 常量与测试同步。
