# 缺陷修复工程进度记录（Remediation IMPL_PROGRESS）

> 本文件为 Verthys 修复工作唯一变更台账（Wave 0~58）；历史方案/审查清单文档已归档删除，批次契约锚点以各 Wave『关键约束』小节为准。
> 编号（FIX-x-y、P1-x 等）仅存在于工程文档，按项目硬约束不得进入代码注释。最新交接见文末 **Wave 58**（安全防护面板修复计划终结）。

#### Wave 26 收尾交接清单（残段）
1. 无 FFI/API 面变更，worker 与 src-tauri 无需重编绑定；release DLL 已重编，Tauri 打包素材哈希需在生产构建流程刷新（构建脚本自动比对）。
2. 全部改动未提交 git，与 Wave 0~25 同批待用户评审验收。

### 2026-09-25 Wave 27：Batch C 收尾（P3-1~P3-17 全闭环 + CI 防回退锚点门）

#### 变更点概览
- Batch C 十七项（P3-1~P3-17）逐项闭环：fmt_version 全经 VERTHYS_FMT_V3 枚举、导出面 .def 直读比对、诊断宏可变参数化、shm 头部注释对齐、业务源码零路径输出、set_privacy_mode 移出异步执行器线程、protocol 拆 max_count、core.yml 测试命令与导出白名单直读、error_codes.h 删除并尾收 util/ffi.rs 整文件删除（负数错误码体系同源清除）、容量上限双重校验、main_loop 生产路径 unwrap 清零、.clang-tidy 摘除 C++ 专用子集、BUILD/TROUBLESHOOTING 文档同步。
- 实测深化：rustc 1.98 对无引号 `--cfg=fast_arithmetic=64` 直接报 invalid --cfg argument——config.toml 必须为带引号字符串字面量（rustflags 数组逐项透传无 shell 分词风险）。
- 承接声明：P3-2 一致性由 .def 直读比对门承接；P3-5 no-console 以「业务源码零路径输出」承接（项目无 ESLint 生态）；P3-6 专项扫描由 regex_scan + clippy 承接；generate-icon.cjs 为一次性工具不受 P3-5 约束。

#### 关键约束（改动时勿破坏）
- CI 防回退锚点门（run_ci.ps1）：①`VERTHYS_C_ERR_` 负数错误码体系禁入（单一定义源为 verthys.h 正数枚举，扫描 core + src-tauri + worker 全源码）；②worker main_loop.rs 生产路径 `.unwrap()` 清零（仅排除 #[cfg(test)] 测试模块）；③`fmt_version` 禁止字面量赋值（必须经 VERTHYS_FMT_* 枚举）。
- 纪律：编辑含中文的 .ps1 后必须复验 UTF-8 BOM（首三字节 EF BB BF），否则 PowerShell 5.1 按 ANSI 解析中文注释直接 ParseError。

门禁：C Debug/Release 各 300/300；worker clippy 0 警 + 测试 22/22；src-tauri check/clippy 0 警 + 测试 336/336；vue-tsc 0 错；vitest 71/71；build 通过；run_ci 全绿（基线豁免 44→38）；全仓版本 3.3.0 一致；打包素材已刷新（与 release 产物哈希一致）。
遗留：锚点门反向验证（core/src 临时写入 `fmt_version = 3;` 应触发锚点 3 变红、撤回转绿）待用户实测。

### 2026-09-25 Wave 28：容器创建/会话守卫锁时序冲突根治（生产级 P0）

#### 变更点概览
- 症状：无法创建容器初始化、无法创建子模块密钥。根因：C 层单写者句柄（FILE_SHARE_READ）存活期间，主进程 GENERIC_WRITE 独占文件锁必被 SHARING_VIOLATION 拒绝——创建必败（回滚 remove_file 亦失败致 .verthys 残留）、SessionGuard 必败致数据域全拒。
- 修复：创建时序重排 create_with_preset → lock op → 主进程独占哨兵锁（偏移 2GB，与 C 层超级块锁 [0,64KB) 零重叠）→ unlock 重开会话；VerthysSessionGuard 改共享读哨兵锁（lock_shared），跨实例单写者互斥职责显式移交 C 层容器锁。

#### 关键约束（改动时勿破坏）
- 锁时序契约由回归测试 test_lock_timing_contract_with_single_writer_handle 锁死：共享哨兵锁必须成功 / 独占锁必须被拒 / 句柄关闭后独占锁必须可取——任何一侧改动共享模式/锁类型立即变红。

门禁：端到端探针 build/probe_worker.ps1（create→lock→unlock→add_record→enumerate→flush→lock）全通；src-tauri 337/337；clippy/check 0 警；run_ci 全绿。
遗留：仅改主进程 Rust；用户实测项（建容器/模块密钥/重启解锁/锁定）待验收。

### 2026-09-26 Wave 29：拾光/密钥生成工具用户体验整改（五项全落地）

#### 变更点概览
- 导出窗口选中项去阴影（仅 accent 边框）；导出 .venc 默认名统一 `verthys_<时间戳>`；密钥工具导出默认名 `verthys_` + 12 位小写随机串；拾光选中态删圆形勾标、红描边改缩略图内嵌 inset 环（根治 masonry overflow 裁剪）；批量删除接入全局 ConfirmDelete 二次确认（onDeleteBtn 仅切选择模式）。

门禁：vue-tsc 0 错 / vitest 71/71 / build 通过。仅改前端。

### 2026-09-26 Wave 30：拾光/密钥工具视觉整改 + 导入全链路审计修复（六项全落地）

#### 变更点概览
- 视觉五项：密钥导出按钮复用全局 `.gen-btn`；复制提示呼吸圆点改原创立标（插旗入场后静止，success/error 变体、reduced-motion 终态）；密码/密钥工具选中态去阴影；拾光选中红环补圆角闭合；右上删除按钮仅切换选择模式、删除执行移交底部操作栏二次确认。
- 导入链路审计闭环：列表 ID 碰撞（复用后端记录 ID + 内存模式单调计数器）；流水线 AbortSignal 取消 + running 实例互斥（保证 WAL begin/end 配对）；persist 先落盘校验后写列表；进度等权计数为明示取舍；解析导入同毫秒重名改模块级单调时间戳。
- 能力边界：大图 metaB64 IPC 瞬时内存峰值与图片尺寸线性相关，不改造 IPC 架构无法根治（临时措施：背压队列 + 批次 50 + WAL 检查点；转生产补齐：meta 分块流式 IPC），实测需 >100MB 原图样本。

门禁：vue-tsc 0 错 / vitest 71/71 / build 通过。仅改前端拾光模块。

### 2026-09-26 Wave 31：导出按钮 a11y 收尾 + 晶碑立标整体重设计

#### 变更点概览
- 导出按钮补 aria-label；`.gen-btn` 补 :focus-visible 细描边（全站按钮零阴影约束下的键盘可达性）。
- 复制提示立标终版「引力视界」3D 立标（18×18 黑洞三层：影子/光子环/吸积盘弧；多普勒亮肢错相、三段因果时序入场；--mark-c 单源换色、影形恒深色；prefers-reduced-motion 静态终态）。
- 空闲治理伪元素豁免补齐：`:is()` 不接受伪元素，须独立选择器并列——否则空闲期立标冻结在 0% 帧（透明）不可见。

门禁：vue-tsc 0 错 / vitest 78/78 / build 5.09s（终版构建被并行 worker 池改动引用未导出常量阻塞，非本波引入）。

### 2026-09-26 Wave 32：拾光导出/解析修复方案批次 1~4（数据安全 + 容器 + 流式写出原子性）

> 权威方案《拾光照片导出与解析修复方案》与配套审查报告已归档删除，本条为台账记录。批次 1~3 为前置会话交付补记，批次 4 为本波交付。

#### 变更点概览
- 批次 1（P0 数据安全）：导入 fatal 错误传播至会话结束决策；verthysImportEnd(true) 仅零失败路径（部分失败保留断点续传）；批次消费逐条状态推导 + 失败子集重试；不可解密独立第四分类不计入失败集。
- 批次 2（容器端到端）：.venc 自描述信封 + 内容密钥封装 + 逐帧 AEAD（XChaCha20-Poly1305）+ 尾部校验帧；解包七步全链路校验；旧版打包/解包函数全量删除（无兼容承诺）。
- 批次 3（解析/导出一致性）：先落盘后入列、四分类计数、令牌 trim + hex 长度预检；导出三处数据判定收敛唯一入口、ExportOutcome 契约、文件名净化 + 批次内唯一、令牌生命周期（二次确认 + 冻结）。
- 批次 4（流式写出）：export_stream 常量表（4MiB 分块 / 512MiB 单文件上限 / 24h 残留清理，与前端对齐）；FileStreamState 流式会话表 + 锁中毒恢复；write/append/finalize/abort_user_file_stream 四命令（.venc.tmp create_new 独占创建 + 逐块直写 + finalize fsync→rename 原子替换 + abort 幂等清理）；前端 packVencV2Streamed 逐帧 emit + 背压。
- 不变量：任何时刻目标文件要么旧完整版、要么新完整版，不存在部分写入的最终文件。
- 纪律：注释遵守「无外部文档引用与编号」硬约束。

门禁：src-tauri cargo test 346/0（+8 流式用例）；vue-tsc 0 错；vitest 130/130；build 通过。
遗留（串行项后续承接）：P1-3 单写者通道 → P1-6 外置 chunk → P1-2 WAL 墓碑 → R-06 预览下沉（均已在 Wave 33~36 落地）。

### 2026-09-26 Wave 33：导入单写者通道（P1-3：三层超时 + 心跳看门狗 + fsync 批化）

#### 变更点概览
- 新增 state/import_writer.rs：crossbeam bounded(1) 背压通道 + 每命令 oneshot 应答；专用写者线程（import-writer，生命周期 = 应用生命周期）串行消费 AppendPending/End，worker IPC 与 WAL fsync 移出 Tauri 异步运行时。
- 三层超时：命令发送 5s（spawn_blocking 兜底背压）/ 应答等待 60s / 心跳看门狗 15s 阈值 5s 巡检（常量取自 constants::import_writer 权威表）；失效写者置死原地孵化，旧队列一律回「写者已被重建」（WAL 哈希去重兜底幂等）；调用方与看门狗共享同一重建入口。
- fsync 批化：WalWriter 增 append_deferred + flush_sync，pending 条目随批次 committed/checkpoint 一并持久（单批 fsync 2N+1 → N+1 级）；控制器改「闸门 + 投递 + 应答组装」，结束与批量命令同走 FIFO（杜绝「结束先于最后一批」）；协议类型上移控制器层 + 输入校验。
- 不变量：单容器同一时刻仅一个活跃导入会话；WAL 写顺序与批次 ID 单调由写者线程串行保证；崩溃恢复/断点续传语义与旧实现逐条等价。

门禁：src-tauri cargo test 354/0（+8）；check 0 警；vue-tsc 0 错；vitest 130/130；build 通过。

### 2026-09-26 Wave 34：大文件外置 chunk（P1-6：块上传命令 + 前端分片 + 引用校验）

#### 变更点概览
- Rust：BatchRecordInput 增 chunk_ids/chunk_hashes（serde default 向后兼容）；TYPE_PHOTO_CHUNK 权威值；WriterCommand::AppendChunks（空批/越 MAX_CHUNKS_PER_IPC/越 MAX_IPC_PAYLOAD_BYTES/畸形校验 + 会话内哈希幂等去重）；AppendPending 外置引用校验——chunk_ids ⊆ 本会话已发放块 ID 集合，未上传引用按条拒绝（杜绝悬空引用入库）；verthys_add_chunk_batch 命令。
- 前端：worker 块密文超内联阈值产出外置形态（chunkB64List + chunkHashes + metaTemplate）；uploadExternalChunks 贪心分片（每批 ≤8 块且 ≤ 载荷 80% 预算）+ ChunkUploadError 失败分类；读取/导出/删除链路零改动即兼容。

门禁：src-tauri cargo test 358/0（+4）；vue-tsc 0 错；vitest 133/133；build 通过。
遗留（明示，Wave 37 补齐）：崩溃窗口孤儿块（meta 未 committed 而块已落库）当时无回收机制；跨会话重传产生同哈希新块记录（原孤儿不可达）。

### 2026-09-26 Wave 35：删除后可重导入（P1-2：WAL 删除墓碑 + 快照基线）

#### 变更点概览
- WAL 新增 Removed 删除墓碑（恢复重放时从 committed 集合/ID 映射移除哈希）；快照文件（.snapshot，tmp+rename 原子写）承载 compacted committed 集合，恢复 = 快照 O(1) 基线 + WAL 增量重放（WAL 缺失时快照独立承载去重集合）；append_removed / remove_all / forget_committed。
- 命令：verthys_forget_hashes（闸门 + spawn_blocking 落墓碑 + 活跃会话内存即时移除）与 dev_reset_wal（仅无活跃会话可用）；前端批量删除成功后 best-effort verthysForgetHashes（失败仅影响再导入去重、不影响删除结果）。

#### 能力边界（必须明示）
- 原方案「store 持久化 alive_hashes 索引」无法落地：内容哈希位于客户端加密 meta 密文内部，store 侧（worker/C 层）不具备任何哈希语义，且删除是唯一变更存活集的路径、必经前端——以「前端删除成功后写 Removed 墓碑」等价闭环；若未来引入后端可解析哈希的存储形态再补 store 侧索引。

门禁：src-tauri cargo test 362/0（+4）；check 0 警；vue-tsc 0 错；vitest 133/133；build 通过。

### 2026-09-26 Wave 36：解析预览移出主线程 + 批次 5 收口（P2-1/P2-4/P2-6）

#### 变更点概览
- 新增 parse-crypto.worker.ts：容器解包（令牌派生 + 逐帧 AEAD）、逐张首块密钥预检、块 base64 转换全部移入 Worker（progress/success/failure 三态可辨识联合）；doParse Worker 委托（transferList 零拷贝移交 + rAF 去重进度 + 完成后 terminate；parseWorkerFactory 依赖注入）；主线程不再执行任何解密计算。
- 批次 5：进度结束语义（end(ok) 成功才落 100%「已导入 N 张」，失败/中止保持真实进度）；展示名结构化 displayName（真实文件名优先，仅缺失回退记录名剥离 meta_ 前缀）；取消提示补记已导入数量。
- 已核验无需再改（前置已落地）：P1-4 定时器纳管、P1-5 导入状态机（epoch 代次仲裁）、P2-5 内存模式 ID 统一、P2-7 skipped 以后端为权威、P2-2 并发互斥双重覆盖。

#### 能力边界（明示未达）
- 照片网格虚拟滚动未落地：现为 CSS 瀑布流全量渲染；虚拟化需绝对定位/占位高度重构，且必须先建立万级大照片库滚动性能基线才可验证收益（临时措施：按需解密 + 扫描分页已覆盖首屏；转生产需专项：基线测量 → content-visibility/窗口化选型 → 回归）。

门禁：vue-tsc 0 错；vitest 134/134；build 通过（本轮无 Rust 变更）。

### 2026-09-26 Wave 37：导入链路全量深检收口（WAL 快照基线保真 + 墓碑写者化 + 孤儿块台账 GC + 删除级联闭环）

#### 变更点概览（深检根治 4 缺陷 + 补齐）
- WAL 重放遇 Begin 不再无条件清空快照基线（否则新会话截断 WAL 后 compact 把全集收敛为仅本会话增量，重启后同一批照片全量重复入库）；compact 改最小骨架（begin+checkpoint+end），哈希全集只落快照文件（O(1) 恢复；含墓碑跨 compact 生效回归测试）。
- 墓碑并发写竞态：活跃会话期间经写者 FIFO 落墓碑（WriterCommand::AppendRemoved），无活跃会话保留直接追加快速路径——杜绝双句柄并发写 JSON 行交错。
- verthys_import_begin / wal_recover 的 WAL 载入改 spawn_blocking；取消「WAL 缺失即空返回」早退（快照独立承载基线场景不被静默丢弃）。
- 孤儿块回收：新增 verthys_chunks.rs 外置块台账（chunk 记录 ID → owner meta ID，0 = 已上传未引用；只存数字 ID 映射不含密钥/明文/哈希；tmp+fsync+rename 原子写）；单写者双向记账（落账失败不影响已入库数据，GC 退化为保守）；verthys_gc_orphan_chunks 命令（闸门 + 活跃会话拒绝 + spawn_blocking）；前端零失败收敛后 + 批删后 best-effort 触发。
- 删除级联闭环：单张删除补记去重锁释放（此前仅批量路径）；占位项删除经 resolveMeta 强制解密（并发 4）补齐外置 chunk 级联与 fileHash，杜绝「删 meta 不删块」存储泄漏。
- 门禁加固：run_ci.ps1 锚点 4 扩至 8 命令——begin / add_records / add_chunk / forget_hashes / dev_reset_wal / import_end / import_checkpoint / gc_orphan_chunks 各挂接解锁闸门（防回退红线）。
- 纪律：注释遵守「无外部文档引用与编号」硬约束。

#### 关键约束（改动时勿破坏）
- store 侧无哈希语义边界维持：alive_hashes 索引以「前端删除墓碑 + 台账 GC」等价闭环。

门禁：src-tauri cargo test 371/0；worker 22/0；vue-tsc 0 错；vitest 134/134；build 通过；run_ci 全绿（锚点 8 命令，基线豁免 42 条重生成）。

### 2026-09-27 Wave 38：拾光照片加载链路修复（批次一~三 + 索引瘦身布局）

> 依据《拾光模块照片加载链路修复方案》（修订版，已归档）执行。

#### 变更点概览
- 前端读取链路：摘要首屏、缓存回灌只认已解密、扫描失败显式可见、密钥失效联动、查看器一致性（请求序号 + 逐块哈希校验）、方向感知预取去抖。
- 后端容量：扫描投影（INDEX/FULL）+ 取批字节预算 + 失败条目透传；worker 写侧响应行收敛与读取侧兜底上限的跨层不变式。
- 元数据瘦身（压缩块恒定外置）+ 每文件一次密钥派生（按盐缓存、口令参与键控）；解密下沉 Worker（decrypt_meta / decrypt_chunks / decrypt_thumb、encrypt_slim_thumb；派生缓存按「口令指纹 + 盐」有界驻留容量 8；模块密钥失效由池 clearCache 标记下一任务入口清空）。
- 扫描进度与取消：ScanProgress（cached/scanned/failed 真实计数）+ 协作式可续扫取消；前端信号层（阶段区间 + 真实计数插值 + 单调闸门）。
- 缩略图 Blob URL：解密产物与回灌重建均产出，五处释放点与生成点成对（覆盖前/单删/批删/卸载/密钥失效）。
- 跨层预算常量单源：photo_budget.schema.json + generate.mjs 产出前端 TS 与 Rust 同源常量（不变式 + 编译期断言），run_ci 新增常量门（生成物与来源漂移即红）。
- 索引瘦身布局：缩略图独立记录（类型 0x07，经外置载荷通道上传并入台账认领）、随机文件密钥包裹于索引、块密文仅 nonce|密文；写入开关 PHOTO_WRITE_FMT 默认关（既有布局）；读取按索引内布局标记分流（缺引用回落既有布局）。

#### 关键约束（改动时勿破坏）
- 索引密文盐必须与包裹密钥同盐（读取侧一次派生覆盖索引与缩略图）；
- 缩略图与块的 AD 绑定（文件哈希 / 序号与总数）不得放宽；
- 索引明文受 PHOTO_INDEX_MAX_BYTES 预算约束（超预算前置拒绝）；
- 布局二与布局一必须并存可读，禁止只写新布局而不读旧布局。

门禁：C 307/307（Debug/Release 各一次）；src-tauri 377/0；worker 33/0；vue-tsc 0 错；vitest 215/215；build 通过；run_ci 全绿（新增常量门）；生产构建部署哈希一致、DLL 导出 31 符号与基线逐一相等。
遗留：后台重打包与「索引瘦身至 1KiB」当时未实施（Wave 39 落地：降至 2656 字节）；导出链路解密当时未下沉（Wave 40）。

### 2026-09-27 Wave 39：索引瘦身目标收口（块集记录）与后台重打包落地

> 依据《拾光模块照片加载链路修复方案》（修订版，已归档）执行。

#### 变更点概览
- 块集记录（类型 0x09）：逐块引用与逐块哈希移出索引，索引体积与照片大小解耦；加密规格与缩略图一致（包裹密钥 + 文件盐 + 文件哈希 AD）；Worker 新增 encrypt_slim_set / decrypt_slim_set；写入经 verthys_add_chunk_batch 外置载荷通道（Rust 角色白名单 {5,7,9}，按角色命名 chunk_/thumb_/cset_）。
- 索引字段收口：新写入索引只含 thumbId / chunkSetId / chunkCount；缩略图缺失时 thumbId=0；布局判定（isSlimLayout）与缩略图判定（isSlimPhotoMeta）分离；逐块引用分流收敛于 photo-album/chunk-refs.ts（块集优先 → 索引内联回落 → 索引内联块密文；块集解析校验 chunkCount === ids.length）。
- 后台重打包（存量布局一 → 布局二）：repack.ts 引擎（依赖注入、幂等单元=单张、整图 BLAKE3 前置校验、取消在张边界生效、DUPLICATE_SKIPPED 计跳过）+ usePhotoRepack 编排（列表原位替换 + 缩略图 URL 吊销 + 三层缓存失效）；入口由 PHOTO_WRITE_FMT 控制（默认关 → 入口不出现）。
- 预算单源更新：生成器派生 photo_index_plain_max=2656、chunk_set_plain_max=7964（最大 100 块）；11 条不变式；Rust 同源常量 4 个 PB_* + 编译期断言。

#### 关键约束（改动时勿破坏）
- 块集与缩略图共用包裹密钥与文件盐：读取侧一次派生必须覆盖索引/缩略图/块集/密钥解封；
- 块集 AD 必须绑定文件哈希（跨照片换用即解密失败）；块集项数必须与索引 chunkCount 相等；
- 重打包必须「新索引落库成功后才删除旧记录集」，任一步失败保留源记录；
- 索引超预算必须前置拒绝（不静默写入使列表缓存失效）；
- 无缩略图照片必须仍可写入：索引以 thumbId=0 明确「无缩略图」，但台账认领列表不得含占位 0（否则写者按「引用未上传」拒绝整条记录）；
- 早期布局二（索引内联逐块项）读取分支不得删除。

门禁：常量生成物一致（11 条不变式）；src-tauri 377/0；worker 33/0；C ctest 通过；vue-tsc 0 错；vitest 230/230；build 通过；run_ci 全绿；生产构建部署哈希一致。
遗留：默认关时重打包入口不出现（存量数据零改动）；导出链路解密当时未下沉（Wave 40 落地）；真机手工用例延续 Wave 38 清单。

### 2026-09-28 Wave 40：导出路径解密下沉 Worker 池（导出一致性收口）

> 依据《拾光模块照片加载链路修复方案》（修订版，已归档）执行。

#### 变更点概览
- 导出层三处解密点全部改经解密桥（Worker 优先 + 主线程兜底）：占位项索引解密（decryptMetaPreferWorker）、瘦身缩略图记录解密（decryptThumbPreferWorker）、明文导出整图逐块解密（decryptChunksPreferWorker）；主线程不再执行 PBKDF2-150k 与 AEAD。
- 顺序校验统一下沉：既有布局「块自描述位置（seq/total）与列表位置一致」判定由共享解密路径统一执行——导出/查看器/重打包口径一致，截断/乱序列表拼接前拒绝并标注块序号。
- 失败归因修正：PhotoDecryptError 区分解密失败（decrypt-failed）与画布转换失败（convert-failed）。

#### 关键约束（改动时勿破坏）
- 导出解密必须经桥（photo-decrypt-bridge），禁止在导出层直接调用 decryptMeta / decryptChunk / decryptSlimThumb 等主线程原语；
- 既有布局块列表必须校验 seq/total 自描述位置（Worker 与回退两条路径同一判定）；
- 明文导出解密失败必须归因 decrypt-failed，不得与 convert-failed 混记；
- 导出结果文案仍只由成功/失败计数派生（三态契约不变）。

门禁：vue-tsc 0 错；vitest 235/235；build 通过；run_ci 全绿；Rust/C 沿用 Wave 39（377 / 33 / 全量通过）。
遗留：导出依旧无取消入口（既有语义）；浏览器模式导出为内存内加密，不在下沉范围。

### 2026-09-28 Wave 41：多方案冲突统一（导入链路 × 加载链路）+ 落盘门禁结构性修复

#### 冲突裁定（统一冲突源）
1. 响应行预算双机制收敛单一权威来源：读侧语义截批（超预算截批 + 游标续批零丢失）与写侧兜底收敛保留为纵深防御；读侧预算改生成常量 PB_ENUM_RESPONSE_DATA_BUDGET_BYTES（= ipc_max_payload），新增生成器断言「预算 + JSON 头 ≤ 写侧行上限」。
2. 导入预算禁止新建第二份 schema：并入 photo_budget.schema.json（同生成器、同 --check 门）；新增 max_file_chunk_size / flush_* / session_*_timeout_ms 常量；派生量由生成器计算（禁手填）。
3. 落盘校验下沉宿主修正：C 层运行在 verthys-worker 子进程、主进程拿不到句柄——统一为 worker op verify_persist（进程内持锁句柄自查，同进程同句柄锁语义无关），主机命令仅转发结构化结果。
4. 记录模型兼容确认：MAX_INLINE_META_BYTES=0（分块一律外置）使导入/解析两路 inline/external 判定自动收敛恒外置。

#### 本波落地概览
- P0-1/P0-2 落盘门禁（结构性）：C 新增 Verthys_VerifyPersist（持锁句柄自查 + .def 导出；C 测试覆盖解锁态/锁库/空参）；worker op verify_persist；主机 verthys_verify_disk_persist 删外部读旧实现改转发；前端 flushWithVerify 三态（ok / partial_persisted / not_persisted），partial 时提交列表与缓存（消除「已落盘却宣称未生效」撕裂）。
- P1-1 会话状态机：begin ok 校验 + 按后端错误分流；endSessionSafely（失败重试一次 → verthys_force_close_import_session 自愈清理，保留 WAL 续传状态）；全部会话结束点（含重打包）统一走该封装。
- P1-4 边界前置：FileVerthys 导入前按 MAX_INLINE_FILE_BYTES（9MiB）拦截；P2-1 预热 V3 化（删 v1/v2 索引区预读，改 V3 帧头 + 固定布局区预读 + .verthys.idx_cache）；P2-2/P2-3 读侧吞错收敛（verthysGetRecord 失败留痕；ForgetHashes 检查返回值 + 重试上抛）；P2-4 四分类不变量改所有环境记录。

门禁：常量门一致（14 项不变式）；C 308/0；worker 33/0；src-tauri 372/0；vue-tsc 0 错；vitest 236；生产构建两次成功（本波引入的 9 处 printf 红线清零后重部署）；run_ci 除外部在途 1 项分层违规（verthys_controller.rs:636，Wave 44 根治）外全绿。
遗留待办：P1-2 缓冲区所有权（BufferRef）、P1-3 统一忙碌信号（AppBusy）、P1-4 FileVerthys 外置块迁移、P2-6 0 块照片归因、session_*_timeout_ms 接入调用点——均 Wave 42 承接。

### 2026-09-28 Wave 42：导入链路遗留项收口（P1-2 / P1-3 / P1-4 / P2-6 + 会话超时接入）

#### 变更点概览
- P1-2 缓冲区所有权：parseFilePath 记录完整路径，已转移缓冲区（byteLength===0）按原路径重读续跑，浏览器模式要求重选——消除「解析失败后直接重试发送 0 字节缓冲报文件已损坏」。
- P1-3 统一忙碌信号：albumBusy（导入∨解析∨解析导入∨导出∨重打包）统一禁用顶栏四处入口（not-allowed + 禁用态样式含 :hover 覆盖）；互斥第一道防线回到 UI，后端拒绝仅兜底。
- P1-4 FileVerthys 外置块迁移：逐块独立 chunk 记录 + meta 仅存引用与展示字段；删除加载侧 chunkIds→内联迁移分支（读取对两形态原生兼容：chunkDataB64 优先、chunkIds 回退）；移除 9MiB 拦截（单文件体量只受容器容量约束）；无消费者的 max_inline_file_bytes / PB_MAX_INLINE_FILE_BYTES 及断言整体退役（禁止无消费者常量沉淀）。
- P2-6 空数据记录归因：解析 Worker 预检把 chunkCount===0 单列（emptyCount 不再混入 undecryptable，响应必填字段）；对话框独立提示「N 张为空数据记录」。
- 会话超时接入：verthysImportBegin / End / ForceCloseImportSession 改 invokeWithTimeout + 生成常量（3s / 30s / 5s），超时按可重试失败返回（不抛出）。
- 并发协作说明：importPipeline.ts 被另一会话重构期间未介入其飞行中代码；收敛后复核本波会话状态机改动已被整合进 runSession。

门禁：常量门一致（13 项不变式）；vue-tsc 0 错；vitest 236；worker 33/0；src-tauri 372/0；C 沿用 308/0；生产构建成功；run_ci 本波 0 新增违规。

#### 遗留待办（2026-09-28 复核后口径）
- P2-8 解析预览常驻块密文：PARSE_PREVIEW_CHUNK_INMEM=false 未实现（预览仍携 chunkB64List 避免二次读盘）；收口需二选一设计（导入期按路径重读 / 预览只留缩略图元信息），独立立项；
- P3-1 超长记录名前置校验：Windows MAX_PATH 260 下不可达后端 1024 字节上限，理论风险记录；
- P3-2 verthys_import_checkpoint 无调用方：删除或明确用途需产品/接口裁定；
- P3-3 记录 ID >2^53 精度：当前容器规模无实害，达到量级需跨层切 BigInt/字符串 ID；
- P3-4 成功反馈双通道（Toast + 对话框）：体验细节随 UI 批次；
- FileVerthys.vue 头部「0x05 元数据」为既有失效描述（现为 0x08），待清理批次统一处理。

### 2026-09-28 Wave 43：导入流水线同构编排去重（runImpl / runParsedImpl → runSession + 生产策略）

#### 变更点概览
- 共享编排骨架 runSession(config)：会话建立（beginResult.ok 分流 + classifyBeginFailure）、并发生产者调度、在途提交收尾、消费者缓冲刷新、会话结束四分支（取消/致命/部分失败/成功）、异常兜底与四分类不变量兜底唯一定义；ProduceContext 契约（会话状态只由编排层持有，生产策略仅经 ctx 投喂记账）；差异收敛为 produceFileImportItem / produceParsedItem 两策略方法；runExclusive 互斥包装；run()/runParsed() 薄包装。
- 有意收敛的行为差异：日志带会话标签；解析导入 undecryptable 参与取消分支不变量断言（文件导入恒 0）；undecryptable=0 时不打印该字段。

#### 关键约束（改动时勿破坏）
- 会话状态只能由 runSession 持有；生产策略不得直接触碰 imported / failedRecords / consumerItems / aborted（只经 ProduceContext）；
- 新增会话语义修复只改 runSession 一处；新增条目来源只新增一个策略实现；
- 生产策略不得吞异常后不记账：拒绝态经 ctx.recordProduceError 入账，同步抛错由编排层 allSettled 分支兜底（两条通道都必须留下条目级失败记录）；
- 既有语义等价不得回归：四分类不变量、成功语义守卫（零致命 + 零失败才压缩 WAL）、取消保留检查点、逐条状态重试与背压阈值、endSessionSafely 自愈清理。

门禁：vue-tsc 0 错；vitest 240（+4 共享编排回归）；build 通过；run_ci 锚点/常量/一级正则通过（二级 AST 报外部在途 1 项，Wave 44 根治）。
遗留边界：runSession 约 440 行；如需拆分按「会话生命周期 / 生产者调度」抽方法，不得引入第二份会话状态或第二处结束分支。

### 2026-09-28 Wave 44：CI 分层违规根治（service 层依赖反转）+ AST 基线语义对齐

#### 变更点概览
- 新建 service/unlock_gate.rs：UnlockGate 枚举（Allowed / Locked(u64) / PurgeRequired / Unavailable）+ 错误码 AUTH_DOMAIN_ERROR + 三个 OnceLock<fn> 注册位（闸门检查 / 认证失败记账 / 认证成功记账）；未注册时 gate_check fail-closed 返回 Unavailable（实现缺失时禁止放行）；security_commands 新增 install_unlock_gate()（三个适配器，经 app.state 托管实例），lib.rs 唯一 .setup 闭包顶部注册（先于任何命令可被调用）；controller 全部闸门/记账调用点改经 service 契约，controller → security_commands 反向依赖归零。
- AST 基线对齐：删除 3 条迁移后自然消亡的豁免、保留 38 条；重要认知——CI 行号语义为 content[..pos].lines().count()+1（对行内缩进 use 报真实行号 +1），基线键必须按 CI 实际报键维护，不得以自建脚本「真实行号」比对。

#### 关键约束（改动时勿破坏）
- 控制器禁止直接 use crate::security_commands::...（口令闸门唯一入口为 service::unlock_gate 契约）；
- install_unlock_gate() 必须在 .setup 期调用：遗漏使闸门 fail-closed（Unavailable），全部口令类操作被拒（安全方向正确但功能不可用）；
- 基线仅用于存量豁免：新增违规不得入基线；维护行号按 CI 语义（缩进行 +1）核对。

门禁：cargo check exit 0；cargo test 372/0；run_ci 全绿（AST 二级 0 错 0 警，基线 38 条）。
遗留：原 CI 唯一红项清零；解锁流程行为与修复前完全一致（架构迁移无功能变更）。

### 2026-09-28 Wave 45：解析导入 meta-only 加密全量失败根治（Vue 响应式代理穿越 Worker 边界）

#### 变更点概览
- 根因：解析产物 meta 恒含 chunkHashes 数组，存入 Vue ref 后为深层响应式 Proxy；importPipeline `{...meta}` 浅展开不消除嵌套 Proxy——postMessage 结构化克隆抛 DataCloneError → 归类 encrypt-failed → 全部失败（structuredClone 实验实证；既有单测 mock 了 Worker 池，未覆盖「真实 Worker 边界 + 响应式载荷」组合）。
- 双道防线：① 源头——importPipeline 导出纯函数 toPlainPayload（JSON 往返脱代理），produceParsedItem 入口对 meta 一次性净化（覆盖该条目全部派生）；② 边界兜底——photoWorkerPool.dispatch 对 DataCloneError 原地净化重投一次（不消耗槽位崩溃计数与毒丸预算，属同一次投递的修复；零正常路径成本）。
- 测试盲区补齐：FakeWorker cloneStrict 模式（投递前执行真实结构化克隆）+ 2 例（Proxy 载荷自动净化重投成功，崩溃/毒丸指标 0；reactive 污染 meta 净化后可克隆，前置断言锁定污染载荷不可克隆）。

#### 关键约束（改动时勿破坏）
- 进入 Worker（postMessage）的载荷必须为纯数据：新增提交入口时，来自响应式状态（ref/reactive）的载荷须先经 toPlainPayload 净化；
- 池层 DataCloneError 自愈是纵深防御而非主路径：不得以「已有兜底」为由跳过源头净化（净化应发生在知道数据来源的领域层）；
- cloneStrict 为测试专用（模拟浏览器 postMessage 语义），生产代码不得依赖其行为。

门禁：vitest 242（+2）；vue-tsc 0 错；build_production 产出 NSIS 安装包。
遗留：无（根因闭环 + 双道防线落地）。

### 2026-09-28 Wave 46：拾光加载进度卡移除（按用户决策：默认加载动画 + 通用错误提示即可）

#### 变更点概览
- 移除「读取加密索引」进度悬浮卡（QuantumProgressFlow 进度条 + 取消/暂停按钮）及全部展示派生与 CSS；CosmicLoading 改为无条件加载反馈；loadError → toast 接线 + 顶部细横幅保留（承载错误文案与重试/继续入口，避免失败静默）；死代码清理（cancelActionLabel 及其用例、相关 ref 解构）。
- 有意保留：usePhotoData 数据层能力（cancelLoad/resumeLoad/retryLoad/loadStage）完整保留——数据层能力不随 UI 决策删除，当前 UI 不再暴露取消入口。
- 惯例确立：此后构建与打包由项目方执行，助手不代跑构建。

#### 关键约束（改动时勿破坏）
- 加载失败不得静默：loadError → toast 接线与顶部横幅重试入口是失败可见性唯一通道，二者必须保持；
- CosmicLoading 是列表装载期间唯一进度反馈，不得再引入居中悬浮进度卡（用户已明确否决该交互形态）。

门禁：vitest 241（删 1 例随死代码）；vue-tsc 0 错。

### 2026-09-28 Wave 47：导出加密照片窗口全面整改（两栏工作台 + 编辑式排版）

#### 变更点概览
- 四段垂直堆叠 → 两栏工作台：左栏（弹性）选片工具条 + 自适应网格（栏内滚动；蓝色描边选中态、名称单行 + hover 浮签）；右栏（296px 固定）格式/令牌/保存位置三组；底栏单行摘要 + 动作按钮，导出进度改底栏顶缘 2px 细线。
- 信息去重三处合并（已选计数常驻头部；格式说明并入分段控件下方单行提示；加密方式并入底栏摘要与令牌提示行）。
- 控件语言：格式分段控件（原生 radio 承载可访问性）；令牌假强度条删除、单行输入可编辑、导出前置校验令牌下限；令牌长度口径统一——解析导入原「64 位 hex 写死校验」放宽为最小 8 位字符集不限（DEFAULT_TOKEN_LENGTH(64) → MIN_TOKEN_LENGTH(8)，isValidHex 前置校验移除；底层 PBKDF2 任意字符串可用）；保存位置整行可点；分组改「微标签 + 渐变延伸细线」；窗口固定 min(860px,100vw−48px) × min(560px,100vh−96px)，窄窗（≤760px）单列兜底；旧 .ed-* 样式全删；「取消」更名「清空」。

#### 关键约束（改动时勿破坏）
- 功能面等价：多选/全选/清空、令牌显示/复制/重新生成/复制对勾态、三格式切换（PNG 隐藏令牌组）、保存位置选择、产出摘要、导出进度与禁用条件不得变更；
- 格式选择必须保留原生 radio（label 承载），不得改为纯 div 点击；
- 「微标签 + 延伸细线」分组与底栏单行摘要为模块排版语言：同类窗口（如解析对话框）后续整改应复用该语言而非另造样式。

门禁：vue-tsc 0 错；vitest 241（导出逻辑未改，语义等价）。
遗留：解析对话框排版仍为旧语言，可后续按同一工作台语言整改（顺带已调整其占位文案与打开文件图标钮）。

### 2026-09-28 Wave 48：总修复方案落地（回灌契约 / 常量唯一化 / 完整性下沉 / 门禁机械化）

> 依据《总修复方案》（已归档删除）执行；承接 Wave 38-47 主体修复，无数据模型变更、无数据迁移。

#### 变更点概览
- 回灌契约与瘦身布局接缝闭合：rehydrateEntries「已加载」绑定「具备可渲染缩略图来源」——瘦身布局且带缩略图引用（isSlimPhotoMeta）项回到待解密态由可视区回填；重建器存在且内联缩略图为空时置空（不留上一会话已释放的陈旧地址）。
- 跨层常量唯一化：flush 服务重试/退避/落盘自查超时改消费生成常量（自查超时按可重试失败）；schema 新增 write_file_chunk_bytes / max_export_single_bytes；Rust 移除无消费者发射（PB_FLUSH_*/PB_SESSION_*）；调用点接线（记录名/导出分片/导出上限 + 单文件导出按预估总量前置拦截）；生成器不变式 13→15 条。
- 完整性校验下沉：decrypt_chunks 协议新增可选 expectedHashes / expectedFileHash——Worker 解密前逐块校验密文哈希、解密后按序增量比对整图明文哈希，不符确定性拒绝（不回退重算）；桥接透传、主线程回退同等标准；块集解析补哈希项数等式；导出 PNG 整图哈希校验随任务下沉。
- 读侧错误语义判别化：verthysGetRecordDetailed（判别式 + 归因分类），原函数保留兼容包装；导出链路元数据读取迁移到判别式版本。
- 机械化门禁：run_ci 新增「常量消费门」（TS/Rust 清单逐名检查真实消费点）与「导出契约门」（.def 与 export_baseline.txt 集合比对，32 符号）；部署一致性按解析路径枚举哈希比对（清理陈旧 worker 副本）。

门禁：常量生成器一致（15 条不变式）；vue-tsc 0 错；vitest 250（+10）；src-tauri 372/0；CI 新门禁本地预演通过；C 沿用 308/0。
遗留：无未闭环项；真机验收由用户执行。

### 2026-09-28 Wave 49：防截屏隐私保护总修复（上传方案评审校正 + 全链路重写）

#### 核心裁定（对上传方案的校正）
对账一律全窗口重扫（按卡死清单对账会漏「还原成功但从未被保护」窗口）；过渡被取代时必须释放未决租约；不做统一窗口工厂（唯一主窗口，visible:false + 启动序列即可）；审计改可选扩展块而非格式号迁移（历史条目序列化字节不变、HMAC 链逐字节兼容）；剪贴板监听剥离回安全档位（与捕获排除解耦）；隐私模式默认开启。

#### 变更点概览
- security/window_affinity.rs：WDA 三常量 + RtlGetVersion 版本检测（Win10 19041+ 排除捕获、旧系统降级监视器亲和性）+ 原始读/写回读校验。
- controller/privacy_controller.rs 重写：令牌槽位三态（Empty/PendingAdoption/Active，只存 SHA-256 摘要；校验占位为租约——可重试、世代单调、单租约；提交即消费；采纳即轮换；跨世代拒绝陈旧租约）；状态机单飞（Transitioning 自带身份号，被取代的过渡不得覆盖状态且必须释放未决租约）；卡死看门狗 30s 内联收尸转隔离；应用原子性（逐窗施加 + 回读校验 + 逆序回滚至快照，回滚失败窗口整体隔离）；对账一律全窗口重扫；意图持久化 PersistedIntent DPAPI 加密 + 临时文件原子替换 + 旧格式一次性重写；启动序列（visible:false → 保护就绪 + 回读成功才显示；还原失败原生 MessageBoxW RETRYCANCEL 驱动对账，拒绝或窗口缺失 exit(0) 不留无界面进程）；四命令（set_privacy_mode 开启默认无凭证、关闭/再开启需租约 / get_privacy_status / adopt_privacy_session / reconcile_privacy）+ 29 单测。
- util/rate_limiter.rs：SlidingWindowLimiter const fn（支持 static 初始化）、拒绝不占额度、按用途分离实例（开启 10/分、关闭 60/分、采纳 10/分、对账 5/分、状态查询不限）。
- 审计扩展块：PrivacyModeChange / PrivacyQuarantine / PrivacyReconcile 事件（ClipboardModeChange 标注历史事件不再产生）；AuditExtensions 挂 AuditEvent.extensions + skip_serializing_if——历史条目序列化字节不变、HMAC 链逐字节兼容。
- 剪贴板剥离：clipboard_controller 仅保留 clear_clipboard（限流 10/分）；外部写入即清空随安全档位启停（失败不回滚会话高安全并返回 CLIPBOARD_MONITOR_FAILED），与防截屏完全解耦。
- 前端：privacy-session.ts 应用级模块单例（状态 ref / 令牌 / 两个单飞 Promise，失败不伪造为关闭）；PhotoAlbum 按钮 + 恢复对话框（稍后处理/立即修复）+ MainView 最早挂载点采纳；privacy-session.spec 7 例。
- 清理：WindowPrivacyGuard / set_window_privacy / panic 清零器 / usePhotoPrivacy / restore_privacy_mode 全删；REQUIREMENTS FR-12 重写（默认开启、全或无语义、命令集、剪贴板解耦）。

复审增补（全链路复核）：2 缺陷整改 + 1 加固 + 1 记录不改——会话层「不抛异常」契约（runGuarded 把 IPC 异常转 PRIVACY_IPC_FAILED，消除 unhandled rejection）；adopt 显式拒绝过渡态与隔离态（任何状态不签发无主凭证）；rate_limiter::max_calls 死 API 删除；状态机锁内写审计为低风险设计偏差记录不改。其余链路（取代释放租约、看门狗收尸、全窗口重扫、逆序回滚、意图原子替换、审计字节级兼容、剪贴板解耦、注册对应、清理残留）全部确认无缺陷。

门禁：常量生成器一致；vue-tsc 0 错；vitest 259；src-tauri 406/0（基线 372+34）；worker 33/0；run_ci -SkipBuild 全通过（基线 37 条）。
遗留：无未闭环项；「统一窗口工厂」经核实为过度设计不予采纳，若引入多窗口需重评启动序列窗口枚举。

### 2026-09-28 Wave 50：拾光交互整改与防截屏操作延迟根治（用户决策驱动）

#### 变更点概览
- 拾光加载提示栏系统化移除：顶部加载横幅（密钥失效/扫描失败/解密暂停/失败计数聚合）及展示派生全删；「模块密钥不可用」不再产生用户提示（保留 console 告警便于排查）；解密失败计数首次非零 → toast 一次性边沿触发（0→>0，重试清零后可再提示）；重打包进度横幅保留（后台任务进度 + 取消入口，非提示条）。
- 约束：数据层能力（retryLoad / resumeLoad / cancelLoad / decryptPaused）保留不删——UI 决策不删数据层能力。
- 防截屏按钮重构：会话层乐观显示态（点击同帧切换图标）+ 在途标志 + statusEpoch 序号（在途旧查询结果按序号丢弃，防旧查询晚到覆盖新状态）；成功后按后端契约本地收敛（启用=槽位生效 / 关闭=槽位清空），移除串行状态查询 IPC（原 3~5 次 → 1 次命令 IPC）；图标开启=划斜线眼 / 关闭=睁眼（双图标交叉淡入无布局抖动），移除高亮圆点与 blink 动画；在途极短不做视觉降级；凭证丢失/非桌面端保留完整降级样式。
- 操作延迟根治（后端审计路径全项目受益）：审计 HMAC 密钥进程级 OnceLock 缓存（仅缓存成功；此前每次审计写入重新做设备指纹采集 + PBKDF2 十万次迭代，单次数百毫秒，为可感延迟主因）；剪贴板控制器审计委托共享写入器 write_audit_with_extensions；audit.log 尾窗口读取（64KB 窗口 + 无法解析全量回退）——消除随日志增长的全量读取成本。

门禁：vitest 261（+2）；vue-tsc 0 错；src-tauri 407/0；check 0 警；run_ci -SkipBuild 全通过。
遗留：无未闭环项；审计密钥首次派生为一次性成本（既有阻塞路径承担）；构建与 git 提交由项目方执行。

### 2026-09-28 Wave 51：拾光卡片悬浮文字模糊根治（文字层与图像层解耦）

#### 变更点概览
- 根因（四条件叠加）：文字画进 filter 表面（ClearType 被禁、灰度抗锯齿）+ 常驻合成层（will-change:transform + preserve-3d）+ 栅格锁定（JS 逐帧直写 transform 与 CSS transition 双写 → 浏览器视为持续动画，栅格锁 1×，非整数放大 + 透视重采样模糊）——hover 是文字 opacity 出现 + transform 激活 + filter 过渡三者同帧的唯一时刻。
- 修复：文字层（.photo-overlay / .enc-mark）移出 .photo-thumb 与图像层平级（滤镜只包裹图片）；删 .photo-card 常驻 will-change:transform 与 preserve-3d（禁令以注释固化）；卡片抬升改 CSS :hover 整数 translateY(-6px)（合成器整数设备像素吸附）；图像层悬浮期按需 will-change（离悬浮即撤销——常驻合成锁栅格比例且占显存）；3D 倾斜只写 .photo-thumb（1.06 过扫保覆盖，平移量从 JS 变换移除与 CSS 抬升单写不冲突）；观感等价（倾斜由整卡变为框内照片）。

#### 关键约束（改动时勿破坏）
- 文字层祖先链禁止出现 filter / 3D 变换 / 非整数缩放；3D 倾斜与非整数缩放只能作用于 .photo-thumb；
- 禁止恢复 .photo-card 的常驻 will-change:transform 与 transform-style:preserve-3d；
- .photo-thumb 的 transform 由 JS 逐帧直写，不得声明 transform 过渡（双写锁死栅格比例）；卡片抬升只能经 CSS 整数平移；
- 缩略图滤镜不得重新包裹文字节点。

门禁：vue-tsc 0 错；vitest 261（表现层改动语义等价）。
遗留：.masonry-item 虚滚动分数像素 translate3d 为同类隐患（整数吸附已缓解）；若实测列表文字发虚按同一铁律整数量化。

### 2026-09-28 Wave 52：拾光死样式清零 + 照片倾斜移除 + 入场动画遮蔽缺陷修复

#### 变更点概览
- 死样式清零 10 条（.empty 系 / .plus / .import-progress 系 / .progress 系 / .viewer-hint；复扫口径：样式块类名 × 模板/脚本引用比对，仅余 Vue transition 运行时类名）。
- 照片 3D 倾斜整体移除（perspective + ±8° rotate + 1.06 过扫逐帧写入删除；composable 只承载光晕跟随；图像层不再有任何 transform）；保留效果：光晕跟随、抬升 + 阴影、文字浮层淡入、滤镜提亮、加密锁标、选中红环、入场动画。
- 入场动画遮蔽缺陷：photo-reveal 填充模式 both → backwards——CSS 级联中动画声明优先级高于普通/内联声明，前向填充在动画结束后继续以终态 transform 压住 hover 抬升（终态关键帧与基础样式一致，改后视觉零变化）；禁令注释固化「不得改回 both/forwards」。

#### 关键约束（改动时勿破坏）
- 卡片悬浮位移只能经 CSS 整数平移（translateY(-6px)）；图像层不得声明 transform；
- 文字/浮层节点不得移回 .photo-thumb（filter 子树禁用亚像素抗锯齿并逐帧重绘）；
- .photo-card 禁止恢复常驻 will-change:transform / transform-style:preserve-3d；
- photo-reveal 填充模式必须为 backwards（前向填充会压住 hover 变换）。

门禁：vue-tsc 0 错；vitest 261；死样式复扫 0 条。
遗留：同类倾斜实现（FileVerthys 内联视差、CertManager/AccountVerthys 经 useCardTilt）待决策——Wave 53 承接移除。

### 2026-09-28 Wave 53：同类卡片倾斜批量移除（存签/枢钥/钥域）+ 共享光泽追踪收敛

#### 变更点概览
- 根因补充：三处卡片入场动画 card-in 前向填充永久以终态 transform 覆盖 JS 倾斜与 -3px 抬升——倾斜/抬升从未真正渲染（与 Wave 51 同缺陷类；这三处无 no-anim 摘除机制，恒被覆盖）。
- 新增 composables/useCardShine.ts（仅光泽追踪，保留排帧节流与 currentTarget 同步捕获）；删除 useCardTilt.ts；FileVerthys 内联倾斜移除（保留本地光晕）；.acct-card 与 verthys-common.css .verthys-card 同口径清理（去 preserve-3d / transform 过渡，填充模式 both → backwards）；FileVerthys 死样式 5 条清零。全仓已无卡片倾斜实现（useCardTilt / perspective(800px) 零命中）。

#### 关键约束（改动时勿破坏）
- 卡片悬浮效果仅阴影 + 光泽追踪；如需恢复倾斜必须同时满足：入场动画不得前向填充 transform、3D/非整数缩放不得作用于文字层、不得与 CSS 过渡或逐帧写入双写；
- .verthys-card / .acct-card 入场动画填充模式必须为 backwards；
- 新增卡片的指针光泽追踪统一复用 composables/useCardShine.ts。

门禁：vue-tsc 0 错；vitest 261；残留检索 0 命中；死样式扫描通过（CertManager expiry-* 系动态类非死样式）。
遗留：FileVerthys 本地光晕（0.1）与 useCardShine（0.18）口径不一——Wave 54 收口；verthys-common.css 未做全量死样式扫描（跨文件动态类名易误报，另开批次）。

### 2026-09-28 Wave 54：卡片指针光晕强度统一 + 实现收口（单令牌 / 单 composable / 单渐变定义）

#### 变更点概览
- 强度单源：tokens.css 新增 --shine-alpha: 0.14 / --shine-reach: 60%（色相沿用 --accent-rgb）——三套 rgba 字面量（0.1/0.12/0.18）与两种范围收敛，0.14 为中位折衷。
- 实现单源：useCardShine 只写卡片元素 --shine-x / --shine-y（不组建渐变串、不查节点）+ cancel()（卸载丢弃未触发排帧写入）；拾光 usePhotoInteraction 光晕件与存签内联实现删除，四模块（存签/枢钥/钥域/拾光）共用。
- 渲染单源：渐变由 CSS 统一定义（radial-gradient circle at var(--shine-x,50%) var(--shine-y,50%)）；存签删除重复 scoped 几何声明（仅保留悬浮显隐规则）。
- 表面差异有意保留：卡片表面 screen 混合 + z-index 1，拾光照片面常规混合（不把屏幕混合叠加在照片与文字上）；顺带修「悬浮未移动指针无光斑」（渐变 CSS 常驻定义）。

#### 关键约束（改动时勿破坏）
- 光晕强度只能改 tokens.css 的 --shine-alpha / --shine-reach；禁止各模块重新硬编码 rgba 字面量或第二份渐变定义；
- 指针光晕统一入口为 composables/useCardShine.ts，禁止再复制内联实现；新模块接入 = 卡片挂 .card-shine 层 + @mousemove/@mouseleave 绑定；
- composable 只写 --shine-* 变量（不写 background），渲染口径归 CSS。

门禁：vue-tsc 0 错；vitest 261；字面量残留检索 0 命中；死样式扫描通过。

### Wave 0（2026-09-28）：清藏导入链路预研与基线实测

#### 产出概览
- BLAKE3 吞吐实测：纯 JS（@noble/hashes）28~29 MB/s 主线程不可接受；hash-wasm 流式 512 MB/s、逐块 4MiB 489 MB/s；两者摘要逐字节一致。裁定：批量哈希改 hash-wasm 流式实例（零新增依赖、无需 Worker）。
- 去重生效范围实测：去重键是写入 extent 的字节——无密码分支写明文跨文件同内容共享 extent；有密码分支每块唯一随机盐/IV 密文互异去重不生效。
- IPC 基线：逐块单条写 1GiB ≈ 259 次 IPC；2 块/批（12MiB 与 8 条双预算）≈ 133 次。
- 内存口径：现路径峰值 ≥ 文件体积；目标 ≈ 单块 + base64 + 批预算 ≤ ~16MiB。端到端峰值/耗时为用户实测项。

### Wave 1（2026-09-28）：导出完整性热修（P1-2 / P2-4 / D5 / P1-1 语义守卫）

#### 变更点概览
- 新增组合式导出管道 useFileExport.ts：单遍流式（逐块取回 → 布局/长度校验 → 可选解密 → 追加写流 → 最终一次 finalize），失败即中止流（目标位置不产生文件）；加密条目在选取保存位置之前先解密首块；依赖注入便于单测。
- 布局校验口径：块数 == 分块总数 == ceil(声明长度 / 分块口径)；空文件与零块严格对应；meta 分块口径必须与跨层常量一致；历史内联形态同样校验。
- 组件接线：保存改管道（流式落盘）；导入侧 meta 写入失败即抛错（不计数、不入列表、不提示成功）；meta 不再写 completedChunks 伪字段。
- 未完成项（随 Wave 2 迁移同批交付）：导入侧组合式抽层与「导入三态」单测。

门禁：vue-tsc 0 错；vitest 275（+14 导出矩阵）；cargo test 411。

### Wave H（2026-09-28，施工顺序先于下列 Wave 0/1）：共享写者 GC 误删窗口 hotfix（清藏链路施工前置）

#### 变更点概览
- 收起在线数据损坏窗口：块台账归属改写只存在于导入写者内存、批末落盘且失败静默降级，WAL committed 条目不携带块引用 → 崩溃恢复无法重建归属；窗口内孤儿回收会删除仍被已提交记录引用的块（数据「看得见却打不开」且去重键仍在、重导被跳过）。
- 四件套闭环：WAL committed 条目携带 chunk_ids（字段缺省即历史条目）；会话创建先结算（归属改写 + 冻结）再截断 WAL，结算落盘失败拒绝创建；批末台账落盘失败置脏标记，成功结束前必须落盘台账，失败拒绝结束并保留会话与 WAL；孤儿回收前先结算——可证明归属改写为拥有者、不可证明归属的孤儿候选冻结为不可回收值。
- 冻结语义：历史条目（无引用集合）无法结算时宁可永久保留也不误删；冻结值不进回收候选，回收面绝不扩大。

门禁：src-tauri 411；新增 8 单测（台账结算 5 / 写者 2 / 台账冻结 1）；clippy 0 警（含 5 条基线遗留机械修复）；worker 33。

### 2026-09-28 Wave 55：拾光滚动丝滑度根治（七层方案评审落地 · 三铁律）

> 七层方案（行窗口模型 / 零重绘 hover / 滚动静默态 / 优先级调度 / 滚轮平滑器 / 设备分档 / 验证标准）评审落地；方案缺陷已直接修正（评审裁定与验收清单原见专项文档，已归档）。

#### 变更点概览（三轮迭代终态）
- 铁律一「滚动期主线程不做 O(可见项) 工作」：visible-window.ts 行窗口模型（像素 → 行窗口量化；跨行重建按「源引用 + 布局键」复用对象，内容未变返回旧数组）；usePhotoData computed 惰性接入；条目 style 预算为字符串；坐标整数量化；no-anim 迁移容器级。
- 铁律二「禁止重绘型属性参与过渡」：卡片过渡只剩 transform；阴影改固定阴影层 masonry-item::before（opacity/transform 过渡、visibility 门控）；hover 提亮改 photo-card::before 白层（仅 opacity）；钉死 .glass:hover 边框/阴影漂移；contain:layout style + 条目/卡片双 isolation 固化层序（图像 1＜提亮 2＜文字遮罩 3＜光晕 4）。
- 铁律三「滚动期冻结非必要动画与解码」：scrollQuiet 静默态（容器 data-scrolling + 根 app-scrolling）——解密项边界暂停取新项、hover 视觉压平过渡/动画关停、背景氛围动画暂停；停稳 120ms 统一追帧（补齐可视区解密 + 运动方向下一行 Image.decode 预热，有界去重）。
- 滚轮平滑三轮终态：主线程逐帧写 scrollTop（preventDefault 把合成器滚动降级为主线程滚动，主线程忙碌即卡）→ scrollBy behavior:"smooth"（高频滚轮下平滑动画反复取消/重启致爬行顿挫）→ **滚轮平滑整体移除**（含 spec/配置开关/挂载点），滚动回归原生合成器路径；静默态 `html.app-scrolling` 通配改枚举动画元素（约 200 节点含伪元素单列——html 类切换触发全文档样式失效根治）；useCardShine 布局读延迟到排帧回调 + 静默期跳过。
- 审查轮修复：静默态入场动画冻结 animation:none → animation-play-state:paused（none 解冻瞬间从 0% 重播致整屏闪烁）；首批解密被静默暂停时收尾三分支（保持在途与进度位置，不得虚假宣告完成/置位 firstFillDone）；清理 8 个无消费者死导出；retryLoad/cancelLoad/resumeLoad 悬空能力面登记保留待产品决策。

#### 关键约束（改动时勿破坏）
- 滚动期主线程不做 O(可见项) 工作（行窗口复用、像素级滚动零状态写入）；
- 禁止重绘型属性（box-shadow / filter）参与过渡——卡片过渡只剩 transform；
- 任何 JS 接管滚动都是降级（固化于配置头注与代码注释）；滚动行为单点回退 config/scroll-perf.ts；
- 静默态动画暂停用 animation-play-state:paused（不得用 animation:none——解冻重播闪烁）；
- 静默态选择器为枚举动画元素（不得恢复 html 类通配——全文档样式失效）；
- 观感差异有意为之：hover 提亮不升饱和度（白层近似）、滚动期 hover 冻结停稳恢复、背景氛围滚动期静止、滚轮「1 行」设置（deltaY≈33）不接管（保护触控板）。

门禁：vue-tsc 0 错；vitest 308（27 文件）；run_ci 两级全通过（存量 37 条基线豁免）。
遗留：干扰变量记录——用户实测时间窗与后端 92.3s 系统模块哈希基线构建重叠（最低优先级单线程，对照实验项，未判定主因）。

### 2026-09-29 Wave 55A（补录）：容器附属数据目录收口（`<容器>.d` 旁路目录单一契约）

> 方案文档已归档删除，本条为台账补录。

- 契约：容器附属数据统一收口至 `<容器路径>.d/`（状态 / 预设 / WAL / 台账 /
  warmcache / 容器锁旁路），单一事实源 `repository/container_layout.rs`
  （新/旧布局派生、ensure_sidecar_dir、懒迁移、旧布局回收、双清），
  Rust⇄C 双端防漂移；`.gitignore` 增 `*.verthys.d/`。
- 执行时门禁：Rust 464 / worker 33 / C 313（含 sidecar 契约用例）/
  vitest 382 / vue-tsc 0 / build 0 / run_ci 通过 / npm audit 0 漏洞
  （修复前 4 high）/ 生产构建哈希一致。
- 未覆盖项（环境边界）：真机 GUI 手工链路、clang-tidy 门、云端流水线；
  发版前需按该方案验收清单执行一遍真机手工验收。

### Wave 2（2026-09-28）：清藏架构收敛（P2-1 / P2-2 / P2-4 读取侧 / P1-2 消费侧补齐）

#### 变更点概览
- 块角色白名单收敛：TYPE_FILEVERTHYS_CHUNK=4 单源常量 + 角色白名单函数 + 名称派生（chunk_{hash}，不承载来源文件名与分块序号）。
- 分片读取与元数据快照：read_user_file 增 offset/length（越界/超尾/超单次上界/空片报错不静默截断；独立分片超时 15s，整文件 120s）；user_file_stat 同授权链。
- 导入管线迁移 useFileImport.ts：单遍优先 / 续传两遍（只读轮哈希判定 → 上传轮重算比对）；块批 2 块/批（载荷与块数双预算推导，无字面量）；来源身份稳定（文件开始 + 每块批边界 + 结束三处复查长度与修改时间）；明文与密文缓冲用后清零；元数据仅在块引用全部确认后写入；失败文件块留台账由孤儿回收处理；会话成功语义 = 全部文件成功且正常结束。
- 导出侧完整性消费：携带 chunkHashes 时逐块 BLAKE3 比对（不符 E_CHUNK_CORRUPTED；条数块数不一致 E_LAYOUT_INVALID）。
- 取消导入与并发互斥：覆盖层取消（每文件与每块批边界检查，保留断点）；会话冲突确认框（结束并继续 / 取消），强制清理残留会话兜底。
- 支撑性性能修复：bytesToBase64 改 32KiB 分块 String.fromCharCode（4MiB ~480ms → ~74ms，输出逐字节一致）。

能力边界：有密码分支去重键为「内容 + 形态标志」（同内容不同口令共用键，Wave 3 文件级密钥落地区分能力）；加密分支每块一次 PBKDF2（Wave 3 收口）；GUI 端到端为桌面实测项。
锚点注入即红：A1 / A2 / B 三条锚点逐条注入均 [RED] + exit 1 后撤回复原。

门禁：src-tauri 421（+10）；clippy 0 警；worker 33；vitest 315；vue-tsc 0 错；run_ci 全绿。
遗留：Wave 3 文件级密钥与密码前置、D1 常量收编、磁盘空间预检；Wave 4 删除事务化、密码空禁用、注释文档同步。

### Wave 2 增补（2026-09-28 同批）：全链路深度审查与整改

#### 发现与整改（5 项）
1. 审计 HMAC 密钥逐次派生（高）：五个控制器统一加进程内单次派生缓存（仅缓存成功结果，失败下次自愈重试）——1GiB 导入原被放大为约 128 次派生（秒级 CPU）。
2. 删除未释放文件级去重键（高）：条目携带 fileHash（导入产物 + 读取侧解析）、删除落盘成功后释放、失败进待重试队列（下次导入开始前自动重试）——修复「删除后重导被静默跳过」；属 P2-5 子项提前落地。
3. 块批/元数据写入传输层异常未分类（中）：分类为 E_CHUNK_FAILED / E_META_FAILED。
4. 后端按会话日志跳过元数据被误判失败（中）：按结构化 skipped_count 判定「跳过」入账。
5. 死导入清理（卫生）。
- 确认保留：删除链路事务化归 Wave 4；每分片一条审计（整改后微秒级，保留逐片可追溯）；去重集合容器级共享（有照片导入时清藏导入固定两遍形态，续传正确性优先）；PBKDF2 逐块口径归 Wave 3。
- ast_baseline.txt 存量违规行号随插入位移同步（语义未变）。

门禁：src-tauri 422（+1）；clippy 0 警；vitest 318（+3）；vue-tsc 0 错；run_ci 全绿。
实测项（追加）：删除已导入文件 → 重新导入必须正常导入；导入 1GiB 过程无秒级停顿。

### Wave 3（2026-09-28）：加密与体量（文件级 KDF / D1 常量收编 / 磁盘空间预检）

#### 施工裁定（实现前冻结）
1. 无密码条目不写 kdf/passwordCheck；加密条目两者必写。
2. 去重键维持「内容 + 形态标志」——D4「指纹取文件密钥 BLAKE3」不采纳：文件盐逐次随机致密钥摘要不稳定（续传重试会重复导入已提交文件）；改稳定值必然是口令派生量，而会话日志（.import.wal 与快照）为明文 JSON，落盘即公开口令验证器。用户裁定采纳；「同内容不同密码可并存」回写为「删除后重导可换口令」。
3. 2GiB 边界：size > limit 拒绝（恰好 2GiB 允许）；读数文案按 GB。
4. 磁盘预检时机：导入 = user_file_stat 后读块前（容器卷，阈值 size × 1.05）；导出 = 选定路径后开流前（目标卷，阈值 size）；读数不可得不阻断（尽力而为），确定不足即拒绝且零副作用。

#### 变更点概览
- crypto 层：FileKdfV2 / FileKeyV2、createFileKeyV2（随机盐一次派生、导入句柄后即刻清零）、unlockFileKeyV2、encrypt/decryptChunkV2（iv(12)‖ct+tag）、build/verifyPasswordCheckV2（固定明文，唯一口令判定点）；历史逐块盐写入路径删除（不留死代码）。
- 导入/导出管线：FileKeySuite 为有密码导入唯一加密路径（文件密钥每文件一次、两轮共用句柄）；meta 携 kdf/passwordCheck；体量预检（E_FILE_TOO_LARGE）与容器/目标卷空间预检（E_DISK_FULL）；openV2Decryptor 选路径前完成解锁与口令判定（E_PWD_WRONG）；块解密失败一律 E_CHUNK_CORRUPTED（删「全部失败=密码错」启发式）。
- D1 常量收编：user_file_size_limit=2147483648 入 schema（移除手填 max_export_single_bytes）；生成器派生 USER_FILE_SIZE_LIMIT 与 MAX_EXPORT_SINGLE_BYTES（同源赋值 + Rust 编译期断言相等）；照片导出上限 512MiB → 2GiB。
- 磁盘预检：check_disk_space(path?) 独立命令（预检超时、系统关键目录拒绝、未创建目标回退最近已存在祖先）；util::disk 增字节口径。
- 留证：1GiB 流式 BLAKE3 实测 581 MB/s（1762ms），无需 Worker。

能力边界：同内容不同口令共用去重键（换口令导入须先删除原条目，用户裁定）；1GiB 端到端 KDF 占比 ≤5% 为桌面实测项；v1 存量（旧 meta/内联块/逐块盐）读取与导出保持，v1 写入路径已删除。

门禁：src-tauri 426（+4）；clippy 0 警；vitest 326；vue-tsc 0 错；run_ci 全绿；常量门一致。
遗留（Wave 4）：删除事务化（P2-5）、密码空按钮禁用（P3-3 余项）、注释文档全量同步、组合式抽层。

### Wave 4（2026-09-28）：清藏收口（删除事务化 / 交互余项 / 组合式抽层 / 文档全量同步）

#### 变更点概览
- 删除链路事务化（P2-5）：新增 useFileDelete.ts——块引用（外置形态）与元数据 ID 收敛单次批量事务删除；删除提交后立即失效摘要/全量/扫描三层缓存并强制立即落盘（取消防抖）；落盘成功后释放文件级去重键（内含一次即时重试，历史条目无键跳过留日志）；收尾 best-effort 孤儿块回收。失败语义：删除失败 → 条目与缓存零变化可重试；落盘失败 → 保持「删除已提交待落盘」态（重试仅重放落盘与收尾，删除步骤不可重放，批量删除对缺失条目整体拒绝零副作用）；释放失败 → 删除结论不变，键入待重试队列。
- 组件接线：删除期间卡片保持可见（删除中…禁用态），成功才移除；删除路径不再携带「格式升级」死字符串分支（核心与进程间层均无生产者）。
- 待重试队列迁移：pendingDedupeReleases 迁入 createDedupeReleaseQueue（组合式导出），startImport 建会话前补释放。
- 交互余项（P3-3）：勾选独立密码口令为空禁用「开始加密导入」；口令为空禁用「解密保存」。
- 回归防线：useFileDelete.spec 4 例；文档全量同步（DATA_FLOW / ARCHITECTURE / SECURITY_DESIGN 等）。

能力边界：去重键释放待重试队列为进程内（跨重启极端窗口需再执行一次删除补释放，实际概率极低）；删除交互为桌面实测项。

门禁：src-tauri 426（无 Rust 改动）；clippy 0 警；vitest 330（+4）；vue-tsc 0 错；run_ci 全绿。
遗留：T-1 错误码契约收口（独立任务）；交互式桌面实测场景。

### T-1（2026-09-28）：错误码契约收口（P2-6 · 独立任务）

#### 事实核实与裁定
核心 V3-only：格式枚举仅 NONE/V3、解锁格式门禁对非 V3 头一律 VERTHYS_ERR_FORMAT 拒绝、全部 V3 分发 API 对非 V3 返回 VERTHYS_ERR_INTERNAL、worker DLL 预检要求 fmt=3 → 不存在「已解锁但格式需升级」状态，VERTHYS_WRITE_BLOCKED 无生产者，其「格式升级」分支与文案（「重新打开应用重试升级」）为死代码且误导 → 裁定 B 分支（删除死分支）；A 分支为不可达状态发明后端接口，不采纳。

#### 变更点概览
- 消费点删除 16 处 + 注释 2 处（证书/账户/照片删除/解析/导入/管线/flush 注释），死分支原不可达、可达行为不变。
- 照片链路「致命错误」机制保留：唯一可达类别为后端容量告罄（ERR_0000000F → storage-full），2 例改写并新增映射断言。
- 锚点 8 启用：run_ci.ps1 全前端整串禁入 VERTHYS_WRITE_BLOCKED（原冻结等式正则有覆盖盲区，按整串禁入收紧）；注入 [RED] + exit 1 验证后撤回。

能力边界：旧容器解锁被格式门禁拒绝的用户提示链路不在核查范围（如需面向旧容器的显式指引另行立项）。

门禁：src-tauri 426；clippy 0 警；vitest 340；vue-tsc 0 错；run_ci 全绿；字符串零残留。
遗留：无（P2-6 闭合，T-1 结项）。

### 复审（2026-09-29）：修复后全链路复核与整改（第四次全链路审查）

#### 结论概要
- 假说验证 10 项全部防线确认或证伪（无窗口）：GC×活跃会话（活跃会话直接拒绝）、删除×导入并发（worker actor 串行 + forget_hashes 经单写者 FIFO）、同会话同哈希块重传（幂等复用）、结算不失证明（先结算再截断 + 墓碑基线固化回快照）、结束义务（台账落盘失败拒绝结束保留 WAL）、读取预检（分片越界报错 + 预检回退最近祖先）、容量告罄属码匹配（ERR_0000000F 结构化单一格式器，非文案判定）、导入 UI 遮挡（覆盖层全遮蔽）、模块切换中导入（后台继续 + 会话冲突确认收敛）、去重键域隔离（清藏与照片构造域不同）。
- 发现与整改 3 项：①导入确认键同步重入窗口（首个 await 前未置位 importing，连击可双开导入互杀）→ 同步重入闸门前置；②落盘失败重试态幽灵条目（E_PERSIST_FAILED 保留组件态而模块缓存仍含条目，切模块重挂载后复活成「看得见打不开删不掉」）→ 模块缓存按数据层视图写入（syncModuleCache，persist-retry 条目不入缓存，4 处写点统一）；③会话冲突判定文案耦合（按后端文案子串驱动控制流）→ VerthysResponse 增结构化 error_code 字段与 err_code() 构造器，import_begin 三拒绝分支携带 E_IMPORT_SESSION_BUSY / E_VERTHYS_NOT_READY（busy 出口收敛单一构造函数），TS 导出同源码常量按码分支，照片引导文案改如实。

边界：组件级防护与冲突引导文案为桌面实测项；落盘失败重试态跨重启窗口为既有声明边界（重启后复活记录可正常再删）。

门禁：src-tauri 427（+1 契约测试）；clippy 0 警；vitest 343；vue-tsc 0 错；run_ci 全绿（AST 基线 37 条未动）。

### 2026-09-29 Wave 56：全局 Toast 层收口（唯一渲染层 + 最高层级令牌 · 四套并存实现归一）

#### 变更点概览
- 根因：toast DOM 渲染在模块组件内部被困 #app 栈上下文——Teleport 到 body 的弹窗（模块密钥窗 z 1000 / 确认 3000 / 导出 4000）必然盖过提示；useErrorToast 非单例致跨 composable 提示丢失（拾光曾二次封装 usePhotoToast 补救，同源问题两套实现）。
- 收口：新增 ToastLayer.vue（App 根单点挂载 + Teleport to body，pointer-events:none，idle-* 类按唯一权威源 useGlobalIdleScheduler 透传）与 useToastCenter.ts（模块级单例 + 5 通道 error/status/copied/exportDone/clip，自动消失计时收敛中心，重复触发重置）；tokens.css 新增分层序令牌 --z-toast: 100000（全序：Dock 50 → 弹窗 1000 → 查看器 2000 → 确认 3000 → 导出 4000 → 扫描线 9998 → 遮罩/加载 9999 → Toast 100000）；样式收口 components.css（.toast-* / .err-toast-* !important 压过 .glass transition:all；中枢 .sc-toast 归一 .clip-toast）；7 模块 + 2 composable 调用方迁移，旧实现（useErrorToast / usePhotoToast / ToastOverlay / ClipToast）删除；useClipToast 保留剪贴板生命周期（写入 → 倒计时 → 到期覆写清零），渲染改经中心通道。

#### 关键约束（改动时勿破坏）
- 全部瞬时提示必须且只能经 useToastCenter 写入、由 ToastLayer 渲染；禁止任何模块再自行渲染 toast DOM（层级/状态分裂均由此而来）；
- 层级唯一来源 = tokens.css 的 --z-toast（.toast-layer 持有）；提示本体不得声明 z-index；
- 新增提示通道时：useToastCenter 扩展状态 + ToastLayer 扩展渲染，保持一一对应；
- .toast-* / .err-toast-* 过渡的 !important 为压过 .glass { transition: all } 所必需（同特异性位序靠后），不得移除。

复审增补（两轮，同日）结论：第一轮全链路审查——修正分层序注释绘制序倒置（9999 遮罩与 9998 扫描线写反）；修复 useClipToast 卸载清理跨模块竞态（对象身份归属判定精确收回）；idle-governance §3 补维护契约（.toast-layer 经 Teleport 挂 body，idle-* 透传对立标同样生效）；新增 useToastCenter.spec 7 例。第二轮独立对抗式审查——唯一 P1：深响应式代理使对象身份比较失效致剪贴板倒计时第 1 秒自停（安全清空失效），整改 exportDone/clip 改 shallowRef（状态定义处注明「禁止改回 deep ref」不变式）+ 到期清理 try/catch + useClipToast.spec 6 例（常量无关断言）；其余轴（渲染单点/层级锚定/治理透传/单写者/删除残留/死导入/星野场演进态复核）无发现。
- 有意行为差异（标准化结果，非缺陷）：中枢「已复制」并入标准 copied 通道；提示不随模块卸载被强杀（全局层语义，消息不被模块切换中断）；deep-idle 下立标入场动画随治理暂停；顶部 error/exportDone 与底部 status/copied/clip 同位并存完全重叠为既有特征（需两条独立失败路径 ≤2.6s 并发才出现）。

门禁：vue-tsc 0 错；vitest 356（30 文件，含新增 13 例）；4 个编辑 CSS postcss 解析通过。

---

### 2026-09-29 Wave 57：安全防护面板全链路修复（B1~B5B-2b 完成，B5B-2c 待办）

> 对应《安全防护面板全链路修复方案》与《安全防护面板全链路审查清单》（23 项缺陷：P0×5 / P1×7 / P2×7 / P3×4），两文档已归档删除，本 Wave 为其交付记录。

#### 已交付批次总览

| 批次 | 主题 | 状态 |
|---|---|---|
| B1 | 前端交互正确性（视觉状态同步契约：挂载期播种 + 三态闭环） | 完成 |
| B2 | 信任链与恢复链（解锁前置位回读 + 回滚可见） | 完成 |
| B3 | 持久化加固（写互斥 / 唯一临时名 / 重命名标记） | 完成 |
| B4 | C 层一致性根治（单一矩阵事实源 + 快照读取 + 世代校验） | 完成 |
| B5A | 特性模型与语义（矩阵投影、bit 位序契约、特性语义重定义） | 完成 |
| B5B-1 | 门控基础设施（app_feature_gate + 巡检门控接线） | 完成 |
| B5B-2a | 介质绑定后端（检测/登记/重绑定 + 解锁期守卫 + DPAPI 持久化） | 完成 |
| B5B-2b | 介质绑定前端（克隆阻断确认对话框 + 枚举对齐 + 消息透传） | 完成 |
| B5B-2c | 其余能力接线（integrity_check / trace_cleanup / display-off） | 完成 |
| B6 | 全量回归与收口（门禁复跑 + 文档同步 + 验收脚本） | 完成 |

#### 关键约束（契约锚点，改动时勿破坏）

1. **视觉状态同步契约**（SecurityDashboard.vue）：`syncVisualState` 为
   `--pos/--posw` 唯一写入入口；三态闭环 = 挂载播种（onMounted）+ 变更同步
   （watch，拖拽期跳过）+ 吸附/键盘落位。禁止恢复 `immediate: true`
   （Vue 3.5.39 immediate 回调恒先于挂载执行，`flush:'post'` 无法修复）。
2. **单一矩阵事实源（C 权威）**：档位矩阵唯一载体 = core 层
   core/src/security/preset/security_preset.c 的 fill_balanced / fill_secure /
   fill_performance；投影 `security_preset_feature_bits()` + 活跃档位
   `security_active_preset()` + 快照读取 `security_config_snapshot()`
   （世代 + 8 次重试 + 保守回填）。Rust/TS/UI 只读消费，禁止本地可写副本、
   禁止缓存回写权威文件。
3. **11 位特性位契约（跨层位序不可变）**：ANTI_DEBUG 0 / ANTI_INJECT 1 /
   INTEGRITY_CHECK 2 / MEMORY_GUARD 3 / KEY_SEPARATION 4 / EMERGENCY_RESPONSE 5 /
   SESSION_LOCK_IDLE 6 / MODULE_PATROL 7 / CLIPBOARD_GUARD 8 / USB_CLONE_DETECT 9 /
   TRACE_CLEANUP 10；VALID_MASK 0x7FF。档位值：BALANCED 0x6FF / SECURE 0x7FF /
   PERFORMANCE 0x073（shadow_sleep 已从矩阵移除）。
4. **C 幂等加固**：快照基于 `InterlockedExchangePointer` 发布 +
   `InterlockedCompareExchange` 一次性初始化；anti_debug / anti_inject /
   memory_guard / emergency 全部改为消费快照（安全检查不经缓存指针）。
5. **API 面扩展**：VERTHYS_API_VERSION 0x000C→0x000D，新增
   `Verthys_GetSecurityPreset` / `Verthys_GetPresetFeatureBits`（.def + 导出
   白名单 + worker FFI 同步，导出契约 34 symbols）。
6. **解锁前置位回读**：verthys_unlock 前经 service/preset_source.rs 的
   `apply_persisted_preset_before_unlock` 读取 `<verthys_path>.preset.json`
   档位并回读校验（失败回滚 + E_PRESET_VERIFY 可见）；与 C 运行时档位一致后
   才放行。持久化一致性由 `preset_persist_dirty` 脏标记守护（B3：写互斥 /
   唯一临时名 / 重命名标记；回滚失败置真，前端经 security_load_preset_state
   读取并提示）。

#### B5B 批次要点（压缩）
- B5B-1 门控基础设施：app_feature_gate.rs AtomicU32 应用侧镜像（store 按 VALID_MASK 归约、snapshot/enabled 读取；保守默认 FEAT_CONSERVATIVE——门未开按最保守子集）；background_patrol 在 FEAT_MODULE_PATROL 关闭时跳过扫描、只维持线程存活与心跳（能力开关由矩阵控制，禁止复用停扫死循环）。
- B5B-2a 介质绑定后端：usb_guard.rs 卷信息解析（GetVolumePathNameW → GetDriveTypeW（本地常量 DRIVE_TYPE_REMOVABLE=2）→ GetVolumeInformationW；固定盘/空盘符 None）+ UsbRegistry::known_hash；usb_binding.rs service 层依赖反转契约（UsbBindAction{None,Register,Rebind} + pre/post 注册点，未注册 fail-open）；decide_bind_action 判定介质 hash ≠ 登记且未确认 → Err(E_USB_CLONE_SUSPECTED)；security_usb_volume_status（只检测不阻断 + 审计）/ security_usb_register_current / security_usb_rebind_device 三命令；解锁守卫接线——拦截前 pre_unlock_guard（克隆嫌疑 Err 阻断），密码验证成功后按动作 Register/Rebind + DPAPI 持久化（post_unlock_commit）。
- B5B-2b 介质绑定前端：useUnlockFlow 增 usbRebindConfirmed（E_USB_CLONE_SUSPECTED 时不直接报错，置 usbRebindPrompt 弹确认；confirmUsbRebind 重试 / cancelUsbRebind 可见提示「已取消介质更换确认，解锁保持阻止状态」）；SecurityCenter 新增「介质标识变化」对话框（零阴影样式）；枚举对齐——VerthysErrorCode 增 E_USB_CLONE_SUSPECTED，verthys_error.ts 文案表 + verthys-error-i18n.ts 消息表（Record 穷举完整性），global-verthys.ts 先于通用 E_VERTHYS_UNLOCK_FAILED 识别克隆嫌疑码；spec 4 例（触发 prompt / 确认重试 / 取消可见 / 他错保持 showError）。

门禁（B1~B5B-2b 累计）：vue-tsc 0 错 / vitest 34 文件 386 例 / build 通过 / src-tauri cargo test 470 例 / check 0 警 / run_ci 全通过（基线 37 条同步行号偏移，controller 无新违规）/ C ctest 全绿。

遗留小项：P2-16 create-with-preset 合法值 0/1 归一（C 层已收 0/1/2 判定不一致，前端可能需传用户预设档而非默认 BALANCED——待确认）；已知 flaky：repository::container_layout::tests::test_migrate_legacy_superseded_copy_removed（isolated 复跑恒绿，不影响门禁）。

执行纪律（红线重申）：①代码注释仅自包含中文、可验证，禁止外部引用词（.md / docs / 版本号 / issue / 来源 / 依据 / 详见 / 参见等）；②编辑含中文的 .ps1 后必须复验 UTF-8 BOM（首三字节 EF BB BF），中文注释按 ANSI 解析会直接 ParseError；③前端交互按既有用户红线：零阴影按钮、可点击 pointer / 禁用 not-allowed、操作即时反馈不卡顿、无白色幕布升起效果；④全部改动未提交 git，待用户评审验收。

### 2026-09-29 Wave 58：B5B-2c 能力接线 + P3-23 + B6 全量收口（安全防护面板修复计划终结）

> 承接 Wave 57 交接点（B5B-2c 三项能力接线、B6 全量回归收口、P3-23），本 Wave 完成后安全防护面板修复计划全部批次终结。

#### B5B-2c-1：integrity_check 接线（FEAT_INTEGRITY_CHECK = 1<<2）
- 启动期核验：security/integrity_check.rs 新增——lib.rs setup 阶段派发独立后台线程（不阻塞启动）对 current_exe 真实路径做 WinVerifyTrust 签名核验（复用 module_whitelist 既有 FFI 与 1h 结果缓存）。失败语义（按 Wave 57 裁定）：不阻断启动与解锁（离线吊销检查可能误报防自锁）——Release 写 INTEGRITY_CHECK 审计 + 错误日志，Debug 仅日志；特性位关闭时跳过（未应用预设按保守全开执行）。
- 运行期抽样复核：module_whitelist 新增 trusted_signable_module_paths()（受信位置非系统目录的已加载模块清单，口径与 scan_modules 签名验证集合一致）；background_patrol 每轮随机抽样 ≤ INTEGRITY_SAMPLE_PER_ROUND=3（部分 Fisher-Yates，抽样期推进心跳防看门狗误判）→ verify_signature 复核，签名失效以「签名失效（完整校验抽样）」进入既有威胁管线（去重 + 连续阈值后升级，单轮失败仅记录）；审计复用 PATROL_THREAT。
- 审计基建：AuditEventType 新增 IntegrityCheck / TraceCleanup 变体（serde 向后兼容：仅新增变体，历史日志链验证不受影响）；get_audit_hmac_key 提升 pub(crate) 供 security 层复用（免重复 PBKDF2 派生）。

#### B5B-2c-2：trace_cleanup 接线（FEAT_TRACE_CLEANUP = 1<<10）
- security/trace_cleanup.rs 新增：锁定/退出时精确清理 %APPDATA%\Microsoft\Windows\Recent 中指向本应用文件的 .lnk 条目。触发点 = verthys_lock（手动锁定与退出 lockAll 均经此）fire-and-forget 不阻塞锁定响应；spawn_blocking 专用线程内 CoInitializeEx(APARTMENTTHREADED)（RPC_E_CHANGED_MODE 沿用既有 apartment 且不配对 CoUninitialize），经 IShellLink/IPersistFile + SLGP_RAWPATH 解析链接目标（不要求目标存在、不触发网络解析）。
- 应用自身痕迹域收口（is_app_owned_target 纯函数 + 单测）：.verthys / .venc 专属扩展名 + 应用自有目录前缀（config/local_data/data 三目录，按路径边界匹配——verthys 前缀不得命中 verthys2）；通用扩展名（.bin 等）与未知目标一律不删，绝不触碰无关系统记录；删除对象仅为 .lnk 本身。审计：删除数 > 0 → TRACE_CLEANUP Success；失败 → Failure + 告警；0 条仅 debug 日志（不制造审计噪音）。
- COM 契约：CLSID_ShellLink 为系统级稳定 GUID（crate 未导出，本地常量定义）；ComScope RAII 管理 COM 初始化归属。

#### B5B-2c-3：display-off 锁定（session_guard）
- 窗口创建时 RegisterPowerSettingNotification(GUID_CONSOLE_DISPLAY_STATE)（成功返回 HPOWERNOTIFY，失败仅告警降级为既有挂起监听，不视为致命）；
- window_proc 的 WM_POWERBROADCAST 分支扩展：PBT_POWERSETTINGCHANGE 时解析 POWERBROADCAST_SETTING（GUID 匹配 + DataLength≥1 + Data[0]=0）且高安全模式 → 发送 SessionEvent::DisplayOff（新增变体）；
- 工作线程 DisplayOff 与 PowerSuspend 同臂处理：仅高安全执行 on_lock（与挂起锁定同门控同语义）；
- 句柄生命周期：MessageLoopState.power_notify 槽位随 stop() / restart() 统一注销（新增 unregister_notifications，WTS 与电源两路独立注销、互不牵连）。

#### 遗留小项：P3-23（自定义模板双写收口）
- 根治：applySecurityPreset 增可选 customOverride 参数（恢复链缺省读缓存的既有行为不变），onApplyCustom 显式传入当前编辑值并不再预写——本地缓存由会话层在应用成功后单点落盘，失败路径缓存与前端状态保持一致；防回退：usePreset.spec 新增 2 例（显式传参 + 成功提示 / 失败可见报错且不提示成功），mock 面移除 saveCustomFeatures（再引入即失败）。

门禁（B6 全量复跑）：vue-tsc 0 错 / vitest 34 文件 388 例（+2 应用链）/ src-tauri cargo test --lib 476 例（+6：integrity 1 / trace_cleanup 4 / 抽样 1）/ check 0 警 / worker 33 例（本批零 worker 改动）/ C 沿用 Wave 57 基线全绿（零 C 改动）/ run_ci 全绿 exit 0（版本门 + 锚点门 + 常量门 + 导出契约门 34 符号 + AST 两级 0 错 0 警）。

文档同步：审查清单与修复方案各增第十节（基线勘误 + 23 项闭环打标 + 能力接线终态 / 批次实施终态表 B1~B6 全部完成 + B5B-2c 实施要点 + 收口门禁表）；SECURITY_DESIGN 第 6 节审计点清单扩充（预设切档 / 自完整性核验 / 痕迹清理 / 介质绑定）+ 新增第 7 节（安全防护档位与特性契约：11 位契约、红线能力、执行路径、生效时机与信任链、display-off）。（前两文档现均已归档删除，本 Wave 与 Wave 57 为其终态台账。）

收尾交接（改动域）：Rust 新增 security/{integrity_check,trace_cleanup}.rs；修改 security/{module_whitelist,background_patrol,session_guard,mod}.rs、util/audit_log.rs、security_commands/audit.rs、lib.rs、controller/verthys_controller.rs；前端 security-session.ts（customOverride 参数）、usePreset.ts（onApplyCustom 收口 + spec 2 例）；文档 SECURITY_DESIGN / IMPL_PROGRESS。未提交 git，与既有工作树同批待用户评审验收。

用户实测项（开发模式，完整保留）：
- display-off：SECURE 档 + 已解锁会话 → 关闭显示器 → 会话应锁定；BALANCED/PERFORMANCE 档关闭显示器不触发锁定；
- 痕迹清理：打开某 .verthys 容器或导出 .venc 后（Recent 出现条目）→ 手动锁定 → Recent 中该条目消失、无关条目保留；
- 启动核验（Release 构建）：正常启动日志出现「主程序镜像签名核验通过」；
- 自定义模板：编辑特性 → 应用 → 失败场景（断开后端）下缓存不变。

终审增补（同日全量对抗式复核 + 整改）：独立全量核验（逐文件深读终态 + 跨层契约比对 + 对抗假说推演 + 门禁升级复跑）检出 8 项全部整改——clippy 严格档 2 项（session_guard PBT_POWERSETTINGCHANGE 分支嵌套 if 折叠为 match guard；trace_cleanup spawn_blocking 句柄 let _ = 改显式 drop，fire-and-forget 意图显式化）；注释红线 6 项（integrity_check 补平台分发 cfg 兑现——模块头「非 Windows 空操作」声明此前无兑现，非 Windows 会误报失败；trace_cleanup 目录范围文档对齐实现——不含临时目录；normalize_lower 兑现「统一反斜杠」契约——补 / → \ 归一；security/mod.rs 文件头模块清单补全；session_guard 与 background_patrol 文件头能力摘要同步；run_one_patrol 块注释补第 3 步）。对抗假说核验全部证伪或防线确认：FEAT 位序跨层逐位一致（C 投影 ↔ Rust 镜像 ↔ 双向保守回填同向）；POWERBROADCAST_SETTING x64 布局偏移正确、Data[0] 对 DWORD 0/1 语义正确；COM 归属三态处置与 Drop 顺序正确；HPOWERNOTIFY 注册/注销配对覆盖 stop/restart 双路径；applySecurityPreset 三参变更全调用方无回归（恢复链 2 参行为不变，唯一 3 参 = onApplyCustom）；P3-23 失败路径先于任何状态突变抛出（localStorage 零写入）；audit 枚举新增变体 serde/HMAC 链向后兼容；抽样子集与 scan_modules 签名验证集合口径一致；sample_random 边界（k≥len 全量 / 空集 / 索引界内）。终审后门禁全量复跑全绿（clippy -D warnings 0 告警 / cargo test --lib 476 / check 0 错 0 警 / run_ci exit 0 / vue-tsc 0 错 / vitest 388）。

观察项（非缺陷，如实声明）：Release 未签名构建每次启动产生 INTEGRITY_CHECK Failure 审计（按「不阻断」裁定语义执行，建议发布流程接入 Authenticode 签名）；sample_random 存在模偏差（非安全随机用途，仅影响抽样均匀性）；启动核验线程无 catch_unwind（单次执行，panic 仅损失本轮核验；常驻巡检线程已有防护）；抽样威胁审计升级需连续阈值，单轮失败仅告警日志（统一威胁模型设计决策）。

遗留：无代码遗留项；已知 flaky 用例（repository::container_layout::tests::test_migrate_legacy_superseded_copy_removed）isolated 复跑恒绿，不影响门禁。
