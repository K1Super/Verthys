# 04 — 查看、导出与备份还原

> 状态：评审中 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 本文定义预览优先查看、原图按需、缩略图/缓存、原始/`.venc`/PNG 导出、备份还原与对应安全约束。

---

## 1. 查看目标

- 首屏只读 2048px 预览；高像素照片不再等待全图解密与全分辨率解码。
- 10MiB/24MP 样本预览 P95 ≤120ms；重复打开命中缓存 ≤50ms。
- 原图只在放大、导出或动画播放时读取；按 Range/分片流式，避免一次性大载荷。
- 查看期间密钥不离开 worker；明文不落盘。

## 2. 预览优先查看

### 2.1 流程

```text
前端：photo_preview_get(metaId)
主进程：会话/密钥检查 → worker photo_read_job_begin(mode=preview, meta_id)
worker：
  1. GetRecord(metaId) → 解密 meta → entryKey / fileHash / chunkIds；
  2. 按 `preview_<entryKey>`（无 entryKey 用 `preview_<metaId>`）调
     Verthys_FindLidByName → GetRecord → 解密（kind=preview）→ 预览头
     fileHash 校验 → 命中则返回 JPEG；
  3. 缺失/损坏/头不匹配 → 按既有布局解析块引用（内联 chunkDataB64 /
     chunkIds）→ 逐块 ChunkOpen → 原生解码 → 2048px JPEG
     → 返回 JPEG 与该预览的待写回密文。
主进程：AppendDerived 写回预览记录（失败只告警）→ 返回 JPEG
前端：Blob URL → <img> → 立即显示
```

- 预览记录是加密派生缓存；生成失败不影响原图。
- 旧照片首次查看触发懒生成；生成期间先显示已有 400px 缩略图（放大、轻度模糊），预览到达后交叉淡入。
- 预览为一次性请求：worker 不保留预览 job；快速切换照片时前端丢弃过期响应，并在原图路径取消在途 job。

### 2.2 预览尺寸与格式

- 长边 2048px；编码档位 2048/0.82 → 2048/0.70 → 1600/0.75 → 1280/0.70，512KB 预算内取首个符合档位；目标 150–450KB。
- EXIF 方向在生成时应用；预览不携带方向元数据。
- 动图（GIF/动态 WebP/APNG）预览取首帧静态图；动画播放走原图路径。

### 2.3 缓存

前端 Blob URL LRU：

- 键：`preview:<metaId>` 与 `full:<metaId>`（预览/原图独立键空间）；
- 容量：默认 64MB 或最近 5 项，先到者淘汰；
- 释放：LRU 淘汰、照片删除、模块卸载、密钥锁定、登出；
- 不持久化到磁盘/IndexedDB/localStorage。

worker 不长期缓存预览明文；请求结束即释放，前端只保留 Blob URL。

## 3. 原图查看

### 3.1 读取

```text
photo_full_begin(metaId) -> { jobId, chunkTotal, size, mime }
worker：注册读取 job；每次 next 逐块 GetRecord + ChunkOpen → 明文块
主进程：photo_full_next(jobId) 返回单块 base64 与 done 标志
前端：逐块拼 Blob → LRU
```

- 分块口径与导入一致（4MiB）；单块 base64 约 5.59MB，低于 12MiB IPC 预算。
- 读取按块产出，内存峰值与文件大小解耦；末块返回前 worker 以整图 BLAKE3 校验完整性，不符即报错。
- 查看器在预览已显示后再请求原图；原图到达后替换，不出现空白等待。
- 原图 Blob URL 进入同一 LRU；关闭查看器不立即释放（由 LRU 管理），锁定时统一释放。
- 自动加载策略：动图必拉；静态图 ≤32MiB 自动拉取；>32MiB 置为待定，用户放大（`scale > 1.01`）时再拉取；关闭/切换照片时取消在途 job。
- Phase 2 不实现 `verthys-photo://` 自定义协议与 HTTP Range；大图仍按块 IPC 流式返回。
  Phase 4 评估结论：维持分块 IPC，不注册自定义协议；100MiB 读取已由 E2E 覆盖。

### 3.2 自定义协议（已评估，不实现）

Phase 2 采用 4MiB 分块 IPC，不注册自定义协议；下列设计保留为 Phase 4 的大图优化候选。

- 协议：`verthys-photo://<metaId>?token=<session-token>&v=<fileHash>`。
- 主进程 protocol handler 校验 token、metaId、Range、会话状态；向 worker 请求对应密文块的解密范围。
- 响应：
  - `200` 全量（仅小图）；
  - `206 Partial Content` + `Content-Range`；
  - `416` 越界；`403` 未授权/锁定；`404` 记录缺失。
- 明文只在主进程内存/SHM 与 WebView 渲染缓冲中存在，不落临时文件。
- CSP 同步加入 `img-src`/`media-src` 对应 scheme；token 一次性/短 TTL，绑定会话与 metaId。

### 3.3 动图

- 预览为静态首帧；用户打开查看器后按原图路径读取完整文件，交给 `<img>` 播放动画。
- 大动图走原图分块路径；不生成动画预览（避免转码成本与体积）。
- 动图标记沿用 `PhotoMeta.animated` 三态；历史记录首次查看补判。

### 3.4 Phase 2 实施结果（与原计划的差异）

| 计划项 | 实际落点 | 说明 |
|---|---|---|
| SHM / 二进制响应 / Range | 4MiB 分块 JSON/base64 IPC | 单块 base64 约 5.59MB，低于 12MiB 预算；不引入第二套数据面 |
| `photo_full_get` + `photo_preview_cancel` | `photo_full_begin/next/cancel`；预览为一次性请求 | 原图 job 保留在 worker，支持取消与 120s 空闲回收 |
| 预览缓存键 `metaId + fileHash` | `preview:<metaId>` / `full:<metaId>` | 预览与原图独立键空间；密钥失效与删除时清理 |
| 旧照片懒预览 | 已实现 | 生成后经 `AppendDerived` 按名称幂等写回；写回失败不影响本次显示 |
| 删除级联 | `photo_preview_ids` 在删除事务前解析预览 ID | 预览不在块台账，必须单独定位；解析失败只告警 |
| 自定义协议 | 不实现 | Phase 4 评估后维持 4MiB 分块 IPC；100MiB 读取已由 E2E 覆盖 |
| 瘦身布局原生读取 | Phase 4 已实现 | `meta`/`slim_meta`、`chunkSetId`、`chunk`/`slim_chunk`、独立 `thumb`；不再回退 JS |

## 4. 网格缩略图

- 现状：400px JPEG 内联 meta；Phase 4 由 `photo_meta_get` 在 worker 内解密并按需返回展示字段。
- Phase 4 决策：不拆分 `thumb_<metaId>`；以 `photo_meta_get` 原生返回展示字段与
  内联缩略图，宿主 32 条/批。下列拆分方案保留为未来优化候选：
  - `photo_thumbs_get(metaIds[])` → 多个二进制缩略图（SHM 批量）；
  - `photo_meta_get(metaIds[])` → 解密后的展示字段 + 缩略图字节（SHM 批量），
    消除列表路径的逐记录 base64；
  - 前端 Blob URL 缓存与现有 LRU 一致；
  - 旧照片内联 fallback。
- 网格滚动期间不做字节级大载荷；缩略图/meta 批量大小受 SHM 单批上限约束。

## 5. 导出

### 5.1 统一入口

```text
photo_export_start(
  ids: number[],
  format: "original" | "venc-single" | "venc-multiple" | "png",
  dest: string,           // 单文件模式为目标文件，其余为目标目录
  token?: string,         // venc 必填
  onProgress: Channel
) -> PhotoExportResult
```

- 命令阻塞至整批结束或取消；worker 逐张解密/打包/编码，主进程负责原子写盘与进度转发。
- 前端只发参数、收进度与失败明细，不接触照片字节。
- `original` 为明文原始文件导出；仅原生链路提供。

### 5.2 原始文件导出

- worker 逐块 `ChunkOpen`，按文件顺序产出 ≤4MiB 的 `segment` 事件；主进程追加到暂存文件。
- 文件名净化/唯一化沿用现有规则；失败按张记账。
- 完整性：整图 BLAKE3 在 worker 内增量校验；不一致拒绝写出。

### 5.3 `.venc` 导出

- 在 Rust worker 内实现 VENC 打包：
  - 外层头（magic/version/flags/KDF/iterations/salt/iv）；
  - 内容密钥封装；
  - 轻量清单帧（`LightMeta`，字段集合不变）；
  - 逐块加密帧；
  - 尾部校验帧。
- 令牌 KDF 在 worker 内完成；不在 JS 派生。
- 逐张流式产出帧段，经 `segment` 事件交给主进程原子写盘；单文件上限沿用 `MAX_EXPORT_SINGLE_BYTES`。
- 多文件模式逐张独立 `.venc`；单文件模式打包全部选中照片。
- 4MiB 块按清单 `chunkCount` 打包；旧 `.venc` 解析不受影响。

### 5.4 PNG 导出

- 仅静态图片；动图跳过并明确提示（沿用现有失败原因 `animated-unsupported`）。
- worker 原生解码（EXIF 方向）→ `image` 编码器输出 PNG；不使用 Canvas/JS。
- 大图按目标尺寸？默认保留原尺寸 PNG；高像素 PNG 体积大，进度按张显示。
- 文件名扩展名、净化、唯一化沿用现有规则。

### 5.5 进度与取消

- 进度：按张 `done/total`，阶段 `scanning / exporting / finishing / done / cancelled`。
- 取消：在块/张边界停止；已写出的临时文件由主进程 abort 清理；不产生半截目标文件。
- 失败：按张收集原因（数据缺失/解密失败/打包失败/编码失败/写盘失败/动图不支持 PNG），沿用现有结果契约。

### 5.6 Phase 3 实施结果（与原计划的差异）

| 计划项 | 实际落点 | 说明 |
|---|---|---|
| SHM 分片导出 | 4MiB 分块 JSON/base64 事件 | 单段解码后 ≤4MiB；响应约 ≤5.59MB，低于 12MiB IPC 预算 |
| worker 直接写盘 | 宿主暂存写盘 | worker 只产出字节；宿主 `create_new` 暂存 → fsync → rename，失败 abort |
| 导出目标 grant | 未启用 | 宿主写盘无需 worker 权限；目标路径仍做字符校验、canonicalize 与系统目录拒绝 |
| 单文件上限 | `E_EXPORT_TOO_LARGE` | worker 逐段累计；宿主中止暂存，不留超限产物 |
| 原始文件格式 | 已实现 | 新增“原始文件”导出；明文、不要求令牌 |
| PNG 转码 | worker `image` 编码 | 应用 EXIF 方向；动图 `animated-unsupported` |
| 还原 | worker 流式解析 + 逐块重封装 | 宿主经现有单写者写入 chunks/meta；预览懒生成 |
| 去重 | 条目键 committed 集合 | worker 侧跳过只校验不落库；后端幂等跳过同样计 skipped |
| 容器替换检测 | 预览 fileHash 列表 | 清单哈希不一致立即失败 |
| 瘦身布局 | 整批拒绝 | `E_PHOTO_LAYOUT_UNSUPPORTED`，前端回退旧 JS 导出；原始文件格式直接报错 |

## 6. 备份还原

```text
photo_restore_start(
  vencPath: string,
  token: string,
  expectedHashes: string[],   // 预览扫描结果，用于容器替换检测
  onProgress: Channel
) -> PhotoImportResult
worker：
  1. 原生解析 VENC 外层/清单/帧，校验帧序、AEAD、块数、字节数、整图 BLAKE3；
  2. 逐块重新封装为本地模块密文；
  3. 走同一导入写入链（chunks → meta → preview 懒生成）。
```

- 不经过 JS、不 base64、不生成中间明文文件。
- 令牌错误/容器损坏：终止，不产生部分记录；已提交项由台账结算。
- 预览不入备份；还原后首次查看懒生成。
- 旧 `.venc` 与新 `.venc` 均可还原；4MiB 块按清单读取。

## 7. 安全约束

1. 查看/导出明文只在 worker、SHM、主进程写盘/协议缓冲、WebView 渲染缓冲中存在；不落临时明文文件。
2. 自定义协议必须：
   - token 绑定会话、metaId、fileHash 与短 TTL；
   - 严格 Range 解析与上限；
   - 拒绝跨会话/跨照片 IDOR；
   - 锁定/登出立即失效。
3. SHM 认证、`VirtualLock`、job 级销毁、零化沿用扫描 SHM 规则。
4. 日志不记录路径、文件名、明文、令牌；错误只返回分类与 job_id。
5. 前端 LRU/Blob URL 在锁定、登出、卸载、删除时释放；不持久化。
6. PNG/解码路径限制像素总量、边长、内存与超时；不可信图片不得 OOM。
7. 导出目标路径必须由 `photo_export` 批量 grant 授权；备份源路径必须由 `photo_restore` grant 授权。

## 8. 验收

1. 10MiB/24MP 样本预览 P95 ≤120ms；重复打开 ≤50ms；17.73/24.43MiB 大图预览按同口径复测。
2. 原图 10MiB 样本 P95 ≤350ms；17.73/24.43/50MiB 走 Range 流式，首段可交互；10MiB 不是产品上限。
3. 100 张预览快速切换不阻塞主线程；过期预览请求被取消。
4. 原始/`.venc`/PNG 导出字节正确，BLAKE3/容器校验通过；失败不产生半截文件。
5. 旧 `.venc` 可还原；新 4MiB `.venc` 可还原并与原图一致。
6. 动图 PNG 导出被明确跳过；加密导出保留动画。
7. 自定义协议 token/越权/Range 滥用全部 fail-closed；锁定后旧 token 失效。
8. 查看/导出过程无明文临时文件；日志无路径/明文/令牌。
