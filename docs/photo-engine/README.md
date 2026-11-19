# 拾光照片数据面重构 — 生产方案

> 状态：评审中 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 适用范围：Windows 桌面应用（Tauri + Vue3 + verthys-worker + core C DLL），仅本地文件路径导入，不包含手机、MTP、移动端与跨设备传输。
>
> 本目录是编码前的唯一设计依据。方案评审通过并完成 Gate G0 后，才允许进入实现阶段。

---

## 1. 为什么必须重构

当前拾光模块的照片数据面位于 JS/WebView 层：

- 导入：整文件读入 JS → Web Worker → 逐 1MiB 串行 `seal` RPC → base64/JSON 多层搬运 → 主线程批量写入。
- 查看：一次性取全部块密文 → 逐块串行 `open` RPC → 拼接 Blob → 全分辨率 `<img>` 解码。
- 缩略图：Worker 内 `createImageBitmap` 全分辨率解码后再缩放。

这条链路把本应属于 Rust/C 的字节流放到了 JS，导致大照片的耗时随“块数 × 进程往返 × base64 膨胀”增长，而不是随磁盘与 CPU 的物理吞吐增长。

本次不是补丁式优化，而是**把照片数据面整体下沉到 Rust/C**：

- JS 只传路径、ID、格式，收进度与最终展示/导出字节。
- 原生层完成流式读盘、哈希、缩略图/预览、分块加解密、批量记录写入编排、导出打包。
- 密钥仍只在 worker/C 会话内，容器格式与 C 加密核心不改。

## 2. 目标与验收摘要

| 目标 | 验收摘要 |
|---|---|
| 极速导入 | 目标待 G0-A 确认：当前 C 单次记录提交固定约 450ms（TPM 回退见证），必须先完成批量提交/锚点摊销；主线程无 >50ms 长任务 |
| 极速查看 | 预览 P95 ≤ 120ms；10MiB 样本原图 P95 ≤ 350ms；17.73/24.43/50MiB 大图走 Range 首段；重复查看命中缓存 ≤50ms |
| 极速导出 | 原始/`.venc`/PNG 全部原生流式，吞吐接近磁盘写入上限 |
| 零 JS 字节面 | 桌面端照片路径不再出现 base64 照片载荷、Web Worker 加密、逐块 Promise 链路 |
| 数据安全 | 密钥只在 worker/C；明文不落盘；路径授权、SHM 认证、零化与锁会话语义保持 |
| 数据兼容 | 旧 1MiB 块、旧缩略图、旧 `.venc` 全部可读；新导入可被新读链路完整读取 |
| 可回滚 | 原生管线有功能开关；旧链路在验收前保留，可一键回退 |

完整指标与测量方法见 [06-verification.md](06-verification.md)。

G0 实测已确认：4MiB seal/open 约 800MB/s、24MP WIC 热解码约 34ms；但 `AddRecords/Flush` 每次固定约 450ms，根因是每次保存轮换 TPM 回退见证密钥（CNG 建键+持久化约 427ms），不是磁盘或 base64。原“单一 10MiB 样本导入 ≤250ms”在现有实现下不可达；必须先完成 G0-A：首选 TPM 见证密钥预置 + 批量提交，备选延迟锚点。10MiB 只是样本，产品单文件上限为 100MiB；大图矩阵见 [G0-A2-PROTOTYPE-REPORT.md](G0-A2-PROTOTYPE-REPORT.md)。

## 3. 核心决策

| 编号 | 决策 | 理由 |
|---|---|---|
| ADR-01 | 照片数据面下沉 Rust，JS 只做 UI 与调度 | 消除 JS/Worker/base64/逐块 Promise 的根本瓶颈 |
| ADR-02 | 文件 I/O、解码、加密在 worker 媒体任务内完成；记录写入经主进程单写者/WAL/台账执行 | 原图明文与密钥留在 worker（展示/导出输出除外）；不破坏现有断点续传与单写者一致性 |
| ADR-03 | 控制面走 JSON 行，数据面走共享内存（SHM） | 控制消息小且可审计；照片字节不进入 JSON/base64 |
| ADR-04 | 新导入使用 4MiB 分块；旧 1MiB 块继续可读 | 10MiB 样本从 10 条降为 3 条，24.43MiB 从约 25 条降为 7 条；减少记录、IPC 与元数据体积 |
| ADR-05 | 预览优先查看：2048px JPEG 预览独立加密记录，原图按需加载 | 高像素照片首屏不再等待全图解密与全分辨率解码 |
| ADR-06 | 预览记录使用确定性名称 `preview_<entryKey>`（无 entryKey 时 `preview_<metaId>`），不重写旧 meta | 旧照片可懒生成预览，避免迁移与记录哈希/WAL 语义变化 |
| ADR-07 | 原生解码/编码优先 WIC + libjpeg-turbo 缩放解码；WebP/GIF 走兼容解码器 | 避免 JS 全图解码；JPEG 可用 DCT 缩放显著降 CPU 与内存 |
| ADR-08 | 保留 VENC 容器清单字段不变；预览不入备份，还原后按需/懒生成 | 不引入容器版本迁移，旧备份继续可导入 |
| ADR-09 | 保留现有去重与续传语义：entry_key 只做续传幂等，不改成内容去重 | 不改变已承诺的数据语义与删除释放逻辑 |
| ADR-10 | 长任务采用 job 协议：立即返回 job_id、异步进度、可取消、无固定 15s 超时 | 大文件导入/导出不能受普通 IPC 超时约束 |
| ADR-11 | 路径授权扩展为批量/作业级 grant | 现有单路径 grant 上限 32 条、TTL 30s，无法承载批量导入 |
| ADR-12 | 旧 JS 管线仅保留为浏览器开发模式回退，桌面端验收后删除 | 桌面端不再有第二条照片数据面 |

决策的完整上下文与替代方案见 [01-architecture.md](01-architecture.md)。

## 4. 文档结构

| 文档 | 内容 |
|---|---|
| [01-architecture.md](01-architecture.md) | 现状瓶颈、目标进程/线程模型、数据流、模块边界、SHM 与 job 协议、安全不变量、失败模型 |
| [02-data-model.md](02-data-model.md) | 记录类型、`PhotoMeta` 扩展、预览命名、分块尺寸、兼容与懒迁移、VENC 边界 |
| [03-import.md](03-import.md) | 原生批量导入、并发与背压、WAL/台账、缩略图/预览、取消/崩溃/移动语义 |
| [04-view-export.md](04-view-export.md) | 预览优先查看、原图按需、LRU、网格缩略图、原始/`.venc`/PNG 导出、备份还原 |
| [05-implementation.md](05-implementation.md) | 阶段划分、文件级改动、删除清单、功能开关、回滚、测试与风险登记 |
| [06-verification.md](06-verification.md) | 性能基线/目标、测试矩阵、安全验收、Gate 与证据要求 |
| [PHASE4-5-REPORT.md](PHASE4-5-REPORT.md) | Phase 4/5 改动、验证证据、未验证项、依赖审计与回滚边界 |

## 5. 评审与执行纪律

1. 本目录所有文档评审通过前，不修改生产代码。
2. Gate G0（可行性验证）完成前，不进入 Phase 1 编码。G0 必须回答：
   - `Verthys_V4ChunkSeal/Open` 的线程安全与最大块长；
   - worker 媒体任务线程模型是否可行；
   - WIC/解码器对 JPEG/PNG/WebP/GIF/APNG 的覆盖与性能；
   - 批量路径授权、SHM 数据面、长任务协议的最小可行原型。
3. 每阶段有独立验收门禁与回滚开关；未过门禁不得进入下一阶段。
4. 方案落地后，长期约束并入 `ARCHITECTURE.md`、`DATA_FLOW.md`、`SECURITY_DESIGN.md`、`CORE_API.md`，本目录按文档治理规则移除或收敛为长期契约。
