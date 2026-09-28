# 缺陷修复工程进度记录（Remediation IMPL_PROGRESS）

> 本文件为缺陷修复工程的分批实施变更记录，随时更新，供中断后快速接手。
> 编号（FIX-x-y、P1-x 等）仅存在于工程文档，按项目硬约束不得进入代码注释。

## 恢复指引（接手时先读这里）

#### Wave 26 收尾交接清单
1. 无 FFI/API 面变更（新增均为 core 内部函数与结构字段），worker
   与 src-tauri 无需重编绑定；但由于 release DLL 已重编，Tauri
   打包素材哈希需在生产构建流程中刷新（构建脚本自动比对）。
2. 全部改动未提交 git，与 Wave 0~25 同批待用户评审验收。

### 2026-09-25 Wave 27：Batch C 收尾（P3-1~P3-17 全闭环 + CI 防回退锚点门）

#### 变更点
1. Batch C 十七项逐项闭环（依据验证清单验收标准定点取证）：

| 编号 | 结果 | 证据要点 |
|---|---|---|
| P3-1 | 完成 | verthys_api.c 全部 fmt_version 赋值经 VERTHYS_FMT_V3 枚举；CI 锚点门 3 禁字面量 |
| P3-2 | 完成 | ffi_types.rs 注释改为"该符号仍在导出白名单且在役"；.def/注释/调用三处一致 |
| P3-3 | 完成 | VERTHYS_DIAG_LOG 可变参数，Release 空操作 sizeof(逗号表达式) 引用实参消除未用警告 |
| P3-4 | 完成 | shm_schema.rs 头部注释 80 字节 + [40..72]/[72..80] 区间；shared_memory.rs 注释同步 80 |
| P3-5 | 完成 | 业务源码零路径输出（SecurityCenter.vue 不再打印 verthys_path；usePhotoViewer.ts 无 chunkIds 输出） |
| P3-6 | 完成 | set_privacy_mode 命令体经 spawn_blocking 移出 async 执行器线程并 await 保持落盘契约 |
| P3-7 | 完成 | protocol.rs 拆出 max_count 字段并注释语义分离；rtype 仅承载记录类型 |
| P3-8 | 完成 | core.yml 主测试套件改 ctest --test-dir build_ci --output-on-failure --no-tests=error |
| P3-9 | 完成 | regex_scan.py 扫描根列表化（主进程 + worker + shm_schema.rs + build.rs） |
| P3-10 | 完成 | rust-frontend.yml 接入 Swatinem/rust-cache@v2，workspaces 分键 |
| P3-11 | 完成 | error_codes.h 已删（cng_example.c 改引 verthys.h）；本 Wave 尾收 Rust 侧负数体系镜像（见变更点 3d） |
| P3-12 | 完成 | VERTHYS_RECORD_DATA_MAX_BYTES 于 API 入口（verthys_api.c）与下沉层（v3_lifecycle.c）双重校验 |
| P3-13 | 完成 | main_loop.rs 生产路径 unwrap 清零（测试模块作用于确定性 Cursor 输入并标注理由）；CI 锚点门 2 只查生产区 |
| P3-14 | 完成 | .clang-tidy 摘除 C++ 专用子集，保留 bugprone/clang-analyzer/readability 对 C 有效项 |
| P3-15 | 完成 | core.yml 删除 MigrateV 死映射，导出白名单直接读 .def 的 EXPORTS 节 |
| P3-16 | 完成 | config.toml 统一为 --cfg=fast_arithmetic="64"（带引号），注释与 rustflags 一致（本 Wave 深化，见变更点 3a） |
| P3-17 | 完成 | BUILD.md 清理名单与 TROUBLESHOOTING.md 进程名同步 Verthys，目录路径 verthys-tauri 保留 |

2. CI 防回退锚点门（[run_ci.ps1](../ci/run_ci.ps1) 版本门之后新增，
   零成本毫秒级、精确文本锚点、命中即红，兑现"注入即变红"）：
   ——锚点 1：`VERTHYS_C_ERR_` 负数错误码体系禁止复活（单一定义源为
   verthys.h 正数枚举，扫描 core + src-tauri + worker 全源码）；
   ——锚点 2：worker main_loop.rs 生产路径 `.unwrap()` 清零（排除
   #[cfg(test)] 测试模块，其 unwrap 作用于确定性输入且已标注理由）；
   ——锚点 3：`fmt_version` 禁止字面量赋值（必须经 VERTHYS_FMT_* 枚举）。
3. 本 Wave 修复实施中的连带发现与根治：
   a. P3-16 深化——cargo 实测暴露注释与事实矛盾：rustc 1.98 对无引号
      `--cfg=fast_arithmetic=64` 直接报 invalid --cfg argument（必须带
      引号字符串字面量）。rustflags 改回 `--cfg=fast_arithmetic="64"`
      （与 serde_json build.rs 输出形式一致），注释按实测结论重写；
      config.toml rustflags 为数组逐项透传、无 shell 分词双引号风险，
      "嵌入双引号引发解析问题"的历史论断随实测推翻并删除；
   b. 素材门禁正确性实证——C Release 重编后 build.rs 打包素材门禁
      （P1-1/Batch A 成果）如实拦截过期 src-tauri/verthys.dll 与
      worker 素材（cargo 缓存输出重放所致误报经 cargo clean -p 证伪，
      刷新素材后门禁转绿，门禁本身工作正常）；
   c. P3-6 调用点补齐——spawn_blocking join 结果显式 `let _ =` 吸收
      （must_use 警告清零，闭包内已记录持久化成败，join 结果无附加信息）；
   d. P3-11 尾收——删除 [util/ffi.rs](../verthys-tauri/src-tauri/src/util/ffi.rs)
      整文件（"FFI 桥接层模板"零调用者 + VERTHYS_C_ERR_* 负数常量
      与已删 error_codes.h 同源同值，违背"全仓无引用"验收），
      [util/mod.rs](../verthys-tauri/src-tauri/src/util/mod.rs) 移除挂载与
      模块清单条目。删除前交叉验证：全仓 grep 零使用、pub 项无
      dead_code 标记风险由 clippy 门守；
   e. P3-7 拆分遗漏同步——gmk.rs 测试 Request 构造补 max_count 字段
      （worker cargo test 编译期抓出，E0063）；
   f. 新版 clippy lint 清零——ipc_secure.rs hex 解码改
      `is_multiple_of(2)` + `as_chunks::<2>()`（manual_is_multiple_of /
      chunks_exact_to_as_chunks）；dispatch.rs parse_shm_auth_key 错误
      变体改 Box<Response>（result_large_err，Response≥288B，错误冷
      路径一次堆分配，调用点 `return *resp` 四处同步）；
   g. ast_analyze 分层模型根治——constants 为 crate 根纯常量叶模块
      （STATE_MAGIC/SHM/超时配置等，实际被 controller/repository/
      infrastructure/state 六处引用），原模型未列为共享叶层导致
      同类引用反复登记基线豁免。LAYER_HIERARCHY 各层允许表统一
      加入 "constants"，基线豁免 44→38 条存量条目不再命中（scan_
      controller 新超时一致性测试首现即放行，不产生新豁免债务）；
   h. run_ci.ps1 中文编码纪律——本 Wave 修复时发现 Edit 改写会丢失
      UTF-8 BOM，PowerShell 5.1 按 ANSI 解析中文注释直接 ParseError。
      已在脚本尾部操作后重写 BOM 并复验（首三字节 EF BB BF），
      今后凡编辑含中文的 .ps1 均须执行 BOM 复验步骤（构建脚本
      build_dev/build_production 因纯 ASCII 化不受此影响）。
4. 子项承接声明（计划工作表的 CI 内建子项，未单独落地者按既有
   门禁承接，不新造机构）：
   ——P3-2"注释与 .def 一致性脚本"：由 core.yml 导出面 .def 直读
   比对门承接（dumpbin 实测导出 vs .def 白名单，比文本注释校验更强）；
   ——P3-5"ESLint no-console"：项目无 ESLint 生态（lint 栈为 vue-tsc +
   vitest，构建期 vite disableConsoleOutput 剥离），未引入 ESLint；
   以"业务源码零路径输出"验收达成承接；
   ——P3-6"CI 扫描命令体内 std::fs::"：命令体级 AST 区分成本高且
   regex_scan 已覆盖入口文件危险关键词（含 std::fs::），clippy 门
   覆盖其余；未新增专项扫描。
5. 前端生成脚本 console.log 保留说明（generate-icon.cjs 为一次性
   图标生成工具，不在业务源码与打包链内；ESLint/resource 白名单
   均不适用，不由 P3-5 验收约束）。

#### Wave 27 批次验证门（w27gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| C Debug 全量 | build_core.dev.ps1 -NoPause | 300/300 通过 |
| C Release 构建 | build_core.release.ps1 -NoPause | 成功 + vsec 注入（405.5KB） |
| C Release 全量 | build/core/tests/Release/verthys_tests.exe | 300/300 通过 |
| worker clippy | cargo clippy --all-targets -- -D warnings | 0 警告 |
| worker 测试 | cargo test（verthys-worker） | 22/22 全绿 |
| worker release | cargo build --release | 成功（5.26s） |
| src-tauri check | cargo check --all-targets | 0 警告 |
| src-tauri clippy | cargo clippy --all-targets -- -D warnings | 0 警告（素材门禁同步转绿） |
| src-tauri 测试 | cargo test | 336/336 全绿 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 全绿 |
| 前端构建 | npm run build | 通过（4.12s） |
| 体系静态 | ci/run_ci.ps1 | 全通过（版本门 + 锚点门 + 二级 0 错误 0 警告，基线豁免 44→38） |
| 版本一致性 | ci/sync_version.ps1 -CheckOnly（run_ci 首步） | GATE PASS，全仓 3.3.0 |

#### Wave 27 收尾交接清单
1. 打包素材已刷新（verthys.dll 2FD04CD…、verthys-worker-x86_64-
   pc-windows-msvc.exe 50CF26…，与各自 release 产物哈希一致），
   生产打包链路可直接进入 tauri build；
2. 用户实测项：run_ci.ps1 锚点门反向验证——在 core/src 任意 .c
   临时写入 `fmt_version = 3;`（字面量）应触发锚点门 3 变红退出，
   恢复后转绿（"注入即变红"闭环）；
3. 全部改动未提交 git，与 Wave 0~26 同批待用户评审验收。

### 2026-09-25 Wave 28：容器创建/会话守卫锁时序冲突根治（生产级 P0）

#### 症状
用户实测：无法创建容器初始化、无法创建子模块密钥。

#### 根因（全链路取证，两条并存，同一病根）
C 层容器锁（P1-3 单写者语义）引出的强互斥与主进程文件锁体系
抢同一文件的写访问权——worker 容器句柄以 `FILE_SHARE_READ` 共享
模式存活期间，任何进程（含主进程自身）再以 `GENERIC_WRITE` 打开
同一文件都被内核以 `ERROR_SHARING_VIOLATION` 拒绝：

1. **创建必败**：verthys_controller.rs 的 verthys_create 在
   create_with_preset 成功（worker C 层句柄存活）后立即执行
   VerthysFileLock::lock_exclusive（GENERIC_READ|GENERIC_WRITE
   打开）→ SHARING_VIOLATION → "创建加密库失败（文件锁失败）"；
   回滚 remove_file 亦因句柄无 FILE_SHARE_DELETE 共享而删不掉，
   .verthys 残留 + 重试永远撞"文件已存在"。
2. **会话守卫必败 → 数据域全拒**：VerthysSessionGuard::new 同样
   用 lock_exclusive，在 unlock 成功后（worker 句柄存活）必然失败；
   Err 被调用处吞掉（仅审计），has_verthys_session() 恒 false →
   state_allows_data_access 拒绝所有数据域命令（add_record 等）→
   子模块密钥无法创建。unlock 命令看似成功（错误被吞），下游全断。

#### 修复
1. [verthys_controller.rs](../verthys-tauri/src-tauri/src/controller/verthys_controller.rs)
   创建时序重排（锁序红线注释化）：create_with_preset → lock op
   （worker 落盘并释放容器句柄）→ 主进程独占哨兵锁（偏移 2GB，
   与 C 层超级块锁 [0,64KB) 零重叠）→ unlock 重开会话。
2. [verthys_session.rs](../verthys-tauri/src-tauri/src/state/verthys_session.rs)
   VerthysSessionGuard 由独占锁改为**共享读哨兵锁**（lock_shared，
   GENERIC_READ 句柄与 C 层 FILE_SHARE_READ 兼容）；跨实例单写者
   互斥职责显式移交 C 层容器锁（本为上策冗余），guard 仅作进程内
   会话哨兵。
3. 防回退回归测试（[file_lock.rs](../verthys-tauri/src-tauri/src/security/file_lock.rs)
   新 TEST `test_lock_timing_contract_with_single_writer_handle`）：
   模拟 C 层单写者句柄（GENERIC_RW + FILE_SHARE_READ）——
   共享哨兵锁必须成功；独占锁必须被拒；句柄关闭后独占锁必须可取。
   三条断言锁死两套锁体系的时序契约，任何一侧改动共享模式/锁类型
   立即变红。
4. 其余写访问点审计排除：preheat 只读 SEQUENTIAL 打开、导入 WAL
   为旁路文件（.import.wal）、preflight 租约为临时文件，均不触碰
   容器本体，无需改动。

#### 端到端实证（worker 协议级探针）
[build/probe_worker.ps1](../build/probe_worker.ps1)（纯 ASCII）
驱动真实 worker + Release DLL（含 vsec 注入版）：
create_with_preset → lock → unlock（8 段进度）→ add_record（id=1）
→ enumerate_records（record_count=1）→ flush → lock——全绿，
证明 C 核心/worker/IPC 全链健康，断裂点仅在主进程锁时序（已修）。

#### Wave 28 批次验证门（w28gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 端到端探针 | build/probe_worker.ps1 | create→lock→unlock→add_record→enumerate→flush→lock 全通 |
| 锁时序回归 | test_lock_timing_contract_with_single_writer_handle | 通过（共享兼容/独占拒绝/关闭可锁三断言） |
| src-tauri 测试 | cargo test | 337/337 全绿 |
| src-tauri clippy | cargo clippy --all-targets -- -D warnings | 0 警告 |
| src-tauri check | cargo check --all-targets | 0 警告 |
| 体系静态 | ci/run_ci.ps1 | 全通过（版本门 + 锚点门 + 二级 0 错误 0 警告） |

#### Wave 28 收尾交接清单
1. 用户实测项：新建容器（密码 ≥8 位）正常完成且立即进入可写状态；
   新建后设置任意模块密钥成功；重启应用后打开容器仍可完成解锁，
   模块密钥状态正常读取；关闭容器（锁定）流程正常；
2. 本次仅改主进程 Rust（无 C 核心/worker/前端变更），素材与产物
   无需重编；全部改动未提交 git，与 Wave 0~27 同批待用户评审验收。

### 2026-09-26 Wave 29：拾光/密钥生成工具用户体验整改（五项全落地）

#### 变更点
1. 导出加密照片窗口选中项去除阴影（[PhotoAlbum.vue](../verthys-tauri/src/components/modules/PhotoAlbum.vue)
   `.ed-photo-item.selected` 仅保留 accent 边框，删除 box-shadow 光晕）。
2. 导出文件名前缀规范（[usePhotoExport.ts](../verthys-tauri/src/composables/photo-album/usePhotoExport.ts)）：
   单文件模式 save defaultPath 与浏览器模式 downloadBlob 两处默认名
   `photos_<时间戳>.venc` 统一改为 `verthys_<时间戳>.venc`。
3. 密钥生成工具导出默认文件名（[PasswordTools.vue](../verthys-tauri/src/components/modules/PasswordTools.vue)
   `randomKeyFileName`）：原 14 位大小写字母混排随机串改为
   `verthys_` 前缀 + 12 位小写字母数字随机串（无大写），返回
   `verthys_xxxxxxxxxxxx.bin`。
4. 拾光选择删除选中态精简与描边裁剪根治（[PhotoAlbum.vue](../verthys-tauri/src/components/modules/PhotoAlbum.vue)）：
   ——删除圆形勾选标记（模板 photo-select-mark 块 + 三条样式规则）；
   ——红色选中描边由外扩 box-shadow 环（超出元素边界，首行顶部与
   首列两侧被 masonry-scroll 的 overflow 裁剪）改为缩略图内嵌
   inset 环（`.masonry-item.selected .photo-thumb`），四边描边在
   滚动容器边缘处完整可见，且不引入任何布局位移。
5. 拾光批量删除接入二次确认（[usePhotoDelete.ts](../verthys-tauri/src/composables/photo-album/usePhotoDelete.ts)
   + [PhotoAlbum.vue](../verthys-tauri/src/components/modules/PhotoAlbum.vue)）：
   原 onDeleteBtn 一拆三——onDeleteBtn 仅切换选择模式 / 拉起
   ConfirmDelete 确认窗口（保持选择与已选状态），cancelDeleteConfirm
   仅关窗，confirmDelete 关窗后调 executeBatchDelete（原批量删除
   逻辑原样下沉，含 deleteAndPersistBatch 单次 flush + 强制落盘 +
   缓存失效）；PhotoAlbum.vue 复用全局 ConfirmDelete 组件（与存签/
   枢钥/清藏的删除确认同款），弹窗清理守卫同步关闭确认窗杜绝残留
   遮挡。

#### Wave 29 批次验证门（w29gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 全绿 |
| 前端构建 | npm run build | 通过（5.74s） |

#### Wave 29 收尾交接清单
1. 用户实测项：导出窗口选中照片仅边框高亮无阴影；导出的 .venc
   默认名为 verthys_<时间戳>；密钥生成工具导出的 .bin 默认名为
   verthys_<12 位小写随机串>；拾光选择删除仅红色边框且四边完整
   （含第一行顶部与最左列），无圆形勾选等附加效果；点击"删除选中"
   弹出确认窗口（取消保持选择态可继续调整，确认后执行删除）；
2. 本次仅改前端（Vue/TS），无 Rust/C/worker 变更；全部改动未提交
   git，与 Wave 0~28 同批待用户评审验收。

### 2026-09-26 Wave 30：拾光/密钥工具视觉整改 + 导入全链路审计修复（六项全落地）

#### 变更点（用户六项需求）
1. 密钥生成工具导出密钥按钮复用全局 `.gen-btn` 样式
   （[PasswordTools.vue](../verthys-tauri/src/components/modules/PasswordTools.vue)）：
   删除 `.keygen-export-icon` 全部专属样式（26px 紫色渐变 + glow），
   导出按钮改用与重新生成/复制一致的 `.gen-btn`。
2. 全局复制提示呼吸圆点改为品牌原创立标
   （[components.css](../verthys-tauri/src/styles/components.css) +
   [animations.css](../verthys-tauri/src/styles/animations.css)）：
   删除 `dot-blink` 无限呼吸动画；`.toast-dot` 重写为「插旗立标」——
   不规则 clip-path 旗面（斜切 8 段多边形）+ 双渐变叠层明暗 + 中缝
   折痕，`toast-mark-plant` 入场采用三段内联 animation-timing-function
   复合曲线（下坠→回弹→落定）+ skewY 偏斜过冲，落定即静止（非呼吸）；
   零发光/模糊/色散，`--mark-c` 主题色注入兼容 success/error 变体；
   prefers-reduced-motion 下直接呈现终态；保留 `.toast-dot` 类名避免
   全局 15+ 处模板与 idle-governance 选择器连锁改动。
3. 删除密码生成器/密钥生成工具选中阴影
   （[PasswordTools.vue](../verthys-tauri/src/components/modules/PasswordTools.vue)）：
   `.preset-btn.active` 与 `.gen-display:hover`、`.keygen-display:hover`
   的 box-shadow 全部删除。
4. 拾光选中红框圆角修复
   （[PhotoAlbum.vue](../verthys-tauri/src/components/modules/PhotoAlbum.vue)）：
   `.masonry-item.selected .photo-thumb` 内嵌 inset 2px 红环并补
   `border-radius: var(--radius)`，四边描边随圆角完整闭合。
5. 右上角删除按钮职责拆分
   （[usePhotoDelete.ts](../verthys-tauri/src/composables/photo-album/usePhotoDelete.ts)）：
   onDeleteBtn 仅切换选择模式（调出/收起下方删除操作栏，不执行删除）；
   删除执行权移交选择栏「删除选中」onDeleteSelected（拉起全局
   ConfirmDelete 二次确认，确认后执行原批量删除逻辑）。

6. 导入照片全链路审计与修复（6 条缺陷逐条闭环）：
   - P1-1 列表 ID 碰撞：`importedToPhotoEntries` 由 `Date.now()+偏移`
     构造改为直接复用后端记录 ID（metaId）；[usePhotoData.ts](../verthys-tauri/src/composables/photo-album/usePhotoData.ts)
     加载路径占位项 id 同步改为记录 ID（删除 listId 计数器），两路
     同源后列表 id 全局唯一、跨重启稳定；内存模式条目（浏览器导入/
     解析导入无 meta 项）改用 `nextMemoryPhotoId` 模块级单调计数器
     （[utils.ts](../verthys-tauri/src/composables/photo-album/utils.ts)），
     消除 Date.now()+i 同毫秒批量构造碰撞。
   - P1-2 流水线无取消机制：[importPipeline.ts](../verthys-tauri/src/composables/photo-album/importPipeline.ts)
     `run()` 新增可选 AbortSignal——信号中止后生产者停止投喂新文件，
     已提交批次照常落库（哈希去重保证幂等），以 `verthysImportEnd(false)`
     保留 WAL 检查点供下次续传；`running` 实例级互斥保证普通导入与
     解析导入（共用实例）不会并发破坏 WAL begin/end 配对；
     [usePhotoImport.ts](../verthys-tauri/src/composables/photo-album/usePhotoImport.ts)
     新增重入守卫 + abortImport 导出；PhotoAlbum.vue 卸载清理调用
     abortImport 消除卸载后继续写库的孤儿会话。
   - P1-3 persist 失败无回滚：[usePhotoImport.ts](../verthys-tauri/src/composables/photo-album/usePhotoImport.ts)
     onImport 调整为「先落盘校验、后写列表」，失败时后端内存记录仍受
     WAL 保护，提示文案与真实状态一致，消除旧顺序「先显示成功、后
     提示失败」的前后矛盾。
   - P3-1 进度逐文件固定权重：等权计数为明示取舍——流式读取无前置
     总字节统计（Tauri 无 stat 前置），按文件数等权是最小失真方案，
     进度文本本就含 n/M 真值不虚报，代码注释同步说明原因。
   - P3-2 解析导入同毫秒重名：`importTimestamp = Date.now()` 改为模块级
     单调递增批次时间戳，createdAt 与 recordName 跨批次必然唯一。
   - P2 大图 metaB64 IPC 内存峰值：能力边界声明——单条记录 data_b64
     经批量 IPC 入队时的瞬时内存峰值与图片尺寸线性相关，在不改造
     IPC 架构（分块/流式传输）的前提下无法根治；按项目规则明示为
     声明项：原因（IPC 负载即 metaB64 字符串）、影响（大尺寸照片
     批量导入内存峰值升高）、临时措施（背压队列 + 消费者批次 50 +
     WAL 检查点保障正确性）、转生产补齐方案（meta 分块流式 IPC +
     增量组装）、风险期限（下次导入链路专项整改时闭环）。实测压测
     需大图样本（>100MB 原图）验证阈值。

#### Wave 30 批次验证门（w30gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 全绿 |
| 前端构建 | npm run build | 通过（4.67s） |

#### Wave 30 收尾交接清单
1. 用户实测项：密钥生成工具导出按钮与重新生成/复制按钮外观一致；
   复制成功 toast 前为原创立标（插旗入场后静止，无呼吸光点），
   success/error 变体颜色正确；密码/密钥工具各选中态无阴影；拾光
   选中红框四边含圆角完整闭合；右上角删除按钮点击仅进入/退出选择
   模式，底部操作栏「删除选中」弹出确认窗口后才执行删除；
2. 导入链路实测项：正常批量导入照片成功；导入中点连击不重入；导入
   进程中切换模块后返回，照片列表与加密库记录一致（WAL 续传幂等）；
   导入后重启应用照片完整、无重复；.venc 解析导入记录名不再同毫秒
   重名；
3. 本次仅改前端（Vue/TS 拾光模块），无 Rust/C/worker 变更；全部
   改动未提交 git，与 Wave 0~29 同批待用户评审验收。

### 2026-09-26 Wave 31：导出按钮 a11y 收尾 + 晶碑立标整体重设计
#### 变更点
1. 密钥工具导出按钮收尾：
   - [PasswordTools.vue](../verthys-tauri/src/components/modules/PasswordTools.vue)
     导出按钮补 aria-label（图标按钮无文本，屏幕阅读器语义补全）；
   - 两处过期/错位注释修正：全局类引用注释改自包含描述，删除悬于
     .keygen-hint 之上的错位注释；
   - [components.css](../verthys-tauri/src/styles/components.css)
     .gen-btn 补 :focus-visible 细描边焦点指示（全站按钮任意状态
     零阴影约束下的键盘可达性）。
2. 复制提示立标整体重设计（替换 Wave 30 版燕尾旗，非迭代；同波内
   曾先后产出「量子晶碑」「事件视界」两版，经用户反馈迭代为终版）——
   「引力视界」3D 立标（18×18），[components.css](../verthys-tauri/src/styles/components.css)
   .toast-dot / [animations.css](../verthys-tauri/src/styles/animations.css)：
   - 构图：以黑洞真实天体结构为基准的三层纵深 — 影子（视界黑洞，
     硬边切割零羽化）→ 光子环（爱因斯坦环发丝亮圈）→ 吸积盘近掠弧
     （盘面自影子正前方横切）；终版删除初版的三颗深空尘点（用户反馈）。
   - 多普勒：三层亮部同偏左下约 220° 单肢增亮，盘弧热核与光子环
     亮肢错相 8°（相对论束流模拟 + 可控不规则偏差）；
   - 盘弧：横切弧 92°→311°，左右收口硬边分阶步宽错落（5/7/8 与
     6/7/6 度），热核（196°-248°）近白沿弧向两端密度渐弱，拒绝
     镜像对称；光子环 8 段连续压暗偏亮，无均匀同心圆；
   - 入场：影子凝聚 → 光子环旋转锁定（76° 坍缩过冲回弹至 8°）→
     盘弧反向掠切（-64° 反角动量切入回正至 -14°），三段因果时序
     ·每段独立复合缓动；全程仅动 opacity/transform，环形遮罩与
     锥形渐变静态一次栅格化，末帧与落态 transform 一致零跳变；
   - 换色单源：--mark-c 一处注入，光子环混冷白冰色派生
     （error 红 / success 绿 / 默认青），影形恒为虚空深色不随主题；
     prefers-reduced-motion 静态呈现完整形态。
3. 空闲治理伪元素豁免缺口修复，[idle-governance.css](../verthys-tauri/src/styles/idle-governance.css)：
   idle 与降级两处「工作进行中指示器」豁免原先仅覆盖 .toast-dot 本体，
   其承载入场动画的 ::before/::after 仍被通配暂停 — 空闲期出现提示时
   立标冻结在 0% 帧（透明）不可见；补齐伪元素豁免选择器（:is() 不接受
   伪元素，须独立选择器并列）。

#### Wave 31 批次验证门（w31gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 78/78 全绿 |
| 前端构建 | npm run build | 终版星尘删除后：vite 打包被并发中的 worker 池改动阻塞（photoWorkerPool.ts 导入 MAX_TASK_ATTEMPTS / MAX_CONSECUTIVE_SLOT_CRASHES，crypto_const.ts 尚未导出——非本波引入，按其约束不代为修复）；本波 CSS 改动前的构建 5.09s 通过 |

#### Wave 31 收尾交接清单
1. 用户实测项：复制成功 toast 前呈现「影子凝聚 + 光子环旋转锁定 +
   盘弧反向掠切」单次入场后静止（18×18px 黑洞三层结构，无呼吸/
   发光，无星尘背景）；光子环为贴影发丝亮圈、盘弧自影子前横切、
   左下亮肢偏亮；
   error 红与拾光 success 绿变体明暗正确、影形恒为虚空深色；键盘
   Tab 聚焦导出按钮有细描边无阴影；空闲 >60s 后程序性 toast（如
   导出完成）立标入场动画正常播放不冻结；
2. 本次仅改前端样式三文件 + PasswordTools.vue 一处属性与注释，
   无 Rust/C/worker 变更；全部改动未提交 git，与 Wave 0~30 同批
   待用户评审验收。

### 2026-09-26 Wave 32：拾光导出/解析修复方案批次 1~4（数据安全 + 容器 + 流式写出原子性）

> 权威方案：[拾光照片导出与解析修复方案](../audits/拾光照片导出与解析修复方案.md)
> 配套审查：[拾光照片导出与解析全链路代码审查报告](../audits/拾光照片导出与解析全链路代码审查报告.md)
> 批次 1~3 由前一工作会话交付并已门禁全绿（该会话记录未落本文件，此处补记概要）；
> 批次 4 为本波交付。注释遵守「无外部文档引用与编号」硬约束。

#### 批次 1（P0 数据安全，前置会话交付）
- 导入流水线 fatal 错误经共享数组传播至会话结束决策；
  `verthysImportEnd(true)` 仅在零失败路径调用，部分失败保留断点续传状态；
- 批次消费改逐条状态推导（ids/failed_indices）+ 失败子集重试
  （consumerMaxRetries=2、退避 200ms）；不可解密记录独立第四分类，
  不再计入失败集；返回值契约 ok 仅在零失败路径为 true。

#### 批次 2（容器端到端，前置会话交付）
- .venc 自描述信封 + 内容密钥封装 + 逐帧 AEAD（XChaCha20-Poly1305）
  + 尾部校验帧；解包七步全链路校验（头部自描述 → 解封 → 帧序 →
  负载上限 → 尾部交叉校验 → 逐块 BLAKE3 → 无残留）；
- 旧版打包/解包函数全量删除（无兼容承诺）；块数 + 顺序 + BLAKE3
  三重校验收敛于解密入口。

#### 批次 3（解析/导出一致性，前置会话交付）
- 解析：先落盘后入列、四分类计数（importable/undecryptable/skipped/
  failed）、令牌 trim + hex 长度预检、不可解密项不入失败集；
- 导出：三处数据判定收敛唯一入口、ExportOutcome 结果契约、文件名
  净化 + 批次内唯一化、令牌生命周期（二次确认 + 冻结 + 局部变量）、
  onExportSingle 死代码删除。

#### 批次 4（性能与内存：流式打包 + 写出原子性，本波交付）
Rust 侧（[src-tauri](../verthys-tauri/src-tauri/src)）：
- [constants.rs](../verthys-tauri/src-tauri/src/constants.rs) 新增
  export_stream 常量表：WRITE_FILE_CHUNK_BYTES（4MiB）/
  MAX_EXPORT_SINGLE_BYTES（512MiB）/ STALE_TEMP_MAX_AGE（24h），
  与前端常量表对齐（另补 WRITE_FILE_CHUNK_BYTES 至前端表）；
- [state/file_streams.rs](../verthys-tauri/src-tauri/src/state/file_streams.rs)
  新增 FileStreamState + 流式会话表（每会话 Arc<Mutex>，表锁仅覆盖
  指针增删查）；AppState 接入 + 锁中毒恢复（逐会话清暂存后重置空表）；
- [file_controller.rs](../verthys-tauri/src-tauri/src/controller/file_controller.rs)
  新增 write_user_file_stream / append_user_file_chunk /
  finalize_user_file_stream / abort_user_file_stream 四命令：数据域
  解锁闸门 + 暂存（.venc.tmp）create_new 独占创建（同目标并发必拒）
  + 逐块原始字节直写（x-stream-id 头 + raw body，与 writeUserFile
  同机制）+ finalize fsync→关句柄→rename 原子替换（全局写互斥保护）
  + abort 幂等清理；单块/累计双重上限；暂时残留按龄惰性清理
  （24h 阈值，等价启动清理）；用户授权目标解析抽取
  resolve_user_file_target 供原子写入与流式写入同链复用；
- [api_error.rs](../verthys-tauri/src-tauri/src/controller/api_error.rs)
  新增 STREAM_NOT_FOUND 错误码；security/command_names.rs 补齐四命令
  常量；lib.rs 注册四命令。
前端侧（[src](../verthys-tauri/src)）：
- [verthys.ts](../verthys-tauri/src/lib/verthys.ts) 新增四命令包装
  （writeUserFileStream / appendUserFileChunk / finalizeUserFileStream
  / abortUserFileStream）；
- [crypto.ts](../verthys-tauri/src/lib/crypto.ts) 抽取 packVencV2Internal
  共享核心，新增 packVencV2Streamed（逐帧 emit + 背压）与
  estimateVencTotalBytes（与真实产出逐字节一致），packVencV2 语义不变；
- [usePhotoExport.ts](../verthys-tauri/src/composables/photo-album/usePhotoExport.ts)
  单文件模式改流式写出（建会话 → 逐帧追加 → finalize；失败路径 abort
  清暂存、清理失败仅记日志、原始错误原样上抛）；进度按累计已写/
  预估总量换算。
不变量：任何时刻目标文件要么是旧完整版、要么是新完整版，
不存在部分写入的最终文件。

#### Wave 32 批次验证门（w32gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 全量单测 | cargo test --lib（src-tauri） | 346/0 全绿（+8 流式用例） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 130/130 全绿（crypto-v2 +8、usePhotoExport +3） |
| 前端构建 | npm run build | 通过（4.49s） |

#### Wave 32 收尾交接清单
1. 用户实测项：拾光单文件导出 .venc 到用户对话框选择位置成功且内容
   完整；导出过程中目标目录可见 .venc.tmp 暂存文件，完成后消失；
   导出失败/取消后无暂存残留；超过 24h 的崩溃残留于下次导出同目录时
   自动清理；
2. 剩余串行项（前置依赖已逐一验证均未实现，按序推进）：P1-3 单写者
   通道（ImportWriter + 三层超时 + 心跳看门狗，constants 已就位）→
   P1-6 大文件外置 chunk（verthys_add_chunk_batch + 前端分片）→
   P1-2 WAL tombstone + alive_hashes（涉及 worker/C 侧 store 索引，
   需跨进程协议扩展）→ R-06 预览移出主线程；随后批次 5/6 收口
   （进度字节粒度、结果摘要、虚拟滚动、定时器纳管、死代码清理）；
3. 本次改动涉及 Rust（src-tauri）与前端拾光链路文件，未提交 git，
   与 Wave 0~31 同批待用户评审验收。

### 2026-09-26 Wave 33：导入单写者通道（P1-3：三层超时 + 心跳看门狗 + fsync 批化）

#### 变更点
新模块 [state/import_writer.rs](../verthys-tauri/src-tauri/src/state/import_writer.rs)
（单写者通道全量实现）：
- 通道模型：crossbeam bounded(1) 天然背压 + 每命令独立 oneshot 应答；
  写者线程串行消费 `AppendPending` / `End` 两类命令，阻塞的 worker
  IPC 与 WAL fsync 从 Tauri 异步运行时线程移入专用线程
  （线程名 import-writer，生命周期 = 应用生命周期）；
- 三层超时：命令层发送（5s，spawn_blocking 兜底背压）、应答层等待
  （60s）、写者心跳看门狗（15s 阈值 / 5s 巡检，常量取自
  constants::import_writer 权威表）；心跳在每命令与每条记录处理处
  刷新，长批次不误判；
- 重建语义：失效写者置死（alive=false）→ 原地孵化新写者；旧写者
  不再执行任何已排队命令（一律回「写者已被重建」），仍在执行的单条
  命令完成后由 WAL 哈希去重兜底幂等；调用方与看门狗共享同一重建
  入口（ensure），无第二套状态；
- fsync 批化：[verthys_wal.rs](../verthys-tauri/src-tauri/src/repository/verthys_wal.rs)
  WalWriter 新增 `append_deferred` + `flush_sync` 公开——pending 类
  条目不再逐条落盘，改随批次内 committed / checkpoint 的 fsync 一并
  持久（pending 恢复时本就被忽略，语义零损失），单批 fsync 次数由
  2N+1 级降为 N+1 级；原控制器内逐条流程整体迁入写者线程，语义等价；
- 控制器瘦身：[verthys_batch_controller.rs](../verthys-tauri/src-tauri/src/controller/verthys_batch_controller.rs)
  verthys_add_records_batch / verthys_import_end 改为「闸门 + 投递 +
  应答组装」，新增 submit_writer_cmd 通用投递（两层超时 + 错误分类）；
  结束命令与批量命令同走 FIFO，杜绝「结束先于最后一批」的交错；
  无活跃会话快速失败保留（写者线程内持会话锁二次复核为权威判定）；
  命令名响应统一改用 cmd::* 常量（消除散落字面量）；
- 协议类型上移：[types.rs](../verthys-tauri/src-tauri/src/controller/types.rs)
  BatchRecordInput / ImportBatchProgress 迁入控制器层共享类型，
  消除跨分层重复定义；新增输入校验（空批/超 MAX_BATCH_RECORDS 拒绝）；
- AppState 接入：writer 句柄 + lock_writer 中毒恢复（置死旧写者 →
  重置）；[lib.rs](../verthys-tauri/src-tauri/src/lib.rs) setup 启动
  看门狗（随 shutdown 令牌退出）；
- 常量表收敛：MAX_IPC_PAYLOAD_BYTES / MAX_CHUNKS_PER_IPC /
  MAX_RECORD_NAME_LEN / MAX_RECORD_HASH_LEN 标注权威表先行
  （消费点随后续分块批量路径落地），Rust 侧编译警告归零。

不变量保持：单 verthys 同一时刻仅一个活跃导入会话；WAL 写顺序与
批次 ID 单调由写者线程串行保证；崩溃恢复/断点续传语义与旧实现逐条
等价（pending 重放忽略、committed 幂等跳过、检查点粒度重做）。

#### Wave 33 批次验证门（w33gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 全量单测 | cargo test --lib（src-tauri） | 354/0 全绿（+8：写者 7 + WAL deferred 1） |
| Rust 编译告警 | cargo check --lib | 0 警告 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 130/130 全绿 |
| 前端构建 | npm run build | 通过（4.47s） |

#### Wave 33 收尾交接清单
1. 用户实测项：正常批量导入照片功能与先前一致（进度逐条推送、
   去重跳过、失败计数）；导入完成后断点续传语义不变；重启后续传
   （未 end 的 WAL）仍正确恢复 committed 集合；导入结束响应字段
   （total_count/import_id）不变；
2. 本轮仅改 Rust（src-tauri 三文件 + 新模块），前端契约零变更；
   未提交 git，与 Wave 0~32 同批待用户评审验收；
3. 后续串行项顺序不变：P1-6 大文件外置 chunk（依赖本波 WriteCmd
   通道与写者顺序保证）→ P1-2 WAL tombstone + alive_hashes → R-06
   预览移出主线程 → 批次 5/6 收口。

### 2026-09-26 Wave 34：大文件外置 chunk（P1-6：块上传命令 + 前端分片 + 引用校验）

#### 变更点
Rust 侧：
- [types.rs](../verthys-tauri/src-tauri/src/controller/types.rs)
  BatchRecordInput 新增 chunk_ids / chunk_hashes 可选字段（serde
  default，向后兼容）；新增 ChunkBlob 块载荷类型；
- [constants.rs](../verthys-tauri/src-tauri/src/constants.rs) 新增
  record_types::TYPE_PHOTO_CHUNK（外置块记录类型权威值，主进程写入）；
- [import_writer.rs](../verthys-tauri/src-tauri/src/state/import_writer.rs)
  新增 WriterCommand::AppendChunks（与 AppendPending/End 同 FIFO）；
  process_append_chunks：空批/越 MAX_CHUNKS_PER_IPC/越
  MAX_IPC_PAYLOAD_BYTES/哈希与载荷畸形校验，会话内哈希幂等去重
  （lookup_chunk 复用既有 ID），worker add_record 以块类型落库；
  AppendPending 新增外置引用校验（chunk_ids ⊆ 本会话已发放块 ID
  集合，未上传引用按条拒绝，杜绝悬空引用入库）；worker_add_record
  公共化（meta/块同链错误分类）；
- [verthys_wal.rs](../verthys-tauri/src-tauri/src/repository/verthys_wal.rs)
  ImportSession 新增 chunk_ids_by_hash / issued_chunk_ids 索引与
  lookup/remember/chunk_refs_known 方法；新增 WAL deferred 追加测试；
- [verthys_batch_controller.rs](../verthys-tauri/src-tauri/src/controller/verthys_batch_controller.rs)
  新增 verthys_add_chunk_batch 命令（闸门 + 会话快速失败 + 写者投递 +
  应答组装）；cmd::ADD_CHUNK_BATCH 常量；lib.rs 注册。
前端侧：
- [types/verthys.ts](../verthys-tauri/src/types/verthys.ts) +
  [verthys.ts](../verthys-tauri/src/lib/verthys.ts)：
  ChunkBlobInput / AddChunkBatchResult 类型 + verthysAddChunkBatch 包装；
- [photo-crypto.worker.ts](../verthys-tauri/src/workers/photo-crypto.worker.ts)
  块密文总量超过内联阈值（MAX_INLINE_META_BYTES）时产出外置形态
  （chunkB64List + chunkHashes + metaTemplate，不再整包内联 metaB64）；
- [importPipeline.ts](../verthys-tauri/src/composables/photo-album/importPipeline.ts)
  uploadExternalChunks 贪心分片（每批 ≤8 块且 ≤ 载荷 80% 预算）+
  ChunkUploadError 失败分类（可重试）；finalizeExternalRecord：
  块上传 → 回填 chunkIds → meta-only 加密 → 带引用记录；run() 与
  runParsed() 两路接入，解析路径外置时前置去重避免无效上传；
  FailedRecord 新增 chunk-upload-failed 分类。
读取/导出/删除链路零改动即兼容：外置形态与既有「chunkIds 旧格式
迁移」读取路径（usePhotoData / usePhotoExport / usePhotoDelete）同
形状，直接复用批量按 ID 读取与删除。

#### Wave 34 批次验证门（w34gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 全量单测 | cargo test --lib（src-tauri） | 358/0 全绿（+4 块路径用例） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 133/133 全绿（+3 外置路径用例） |
| 前端构建 | npm run build | 通过（4.57s） |

#### Wave 34 收尾交接清单
1. 用户实测项：导入 >6MiB 块密文总量的大图成功（块记独立记录、
   meta 引用）；同大图断点续传幂等（块同哈希复用）；导入后列表/
   删除/导出与内联照片行为一致；删除大图照片时块记录一并清理
   （meta.chunkIds 驱动）；
2. 已知残留（明示）：崩溃窗口孤儿块——meta 未 committed 而块已
   落库时（≤ 一个未完成批次）产生的孤儿块记录无回收机制，等待
   后续健全化；跨会话重传产生同哈希新块记录（原孤儿不可达）；
3. 本轮改 Rust（5 文件）+ 前端（5 文件），未提交 git，与
   Wave 0~33 同批待用户评审验收。

### 2026-09-26 Wave 35：删除后可重导入（P1-2：WAL 删除墓碑 + 快照基线）

#### 变更点
[verthys_wal.rs](../verthys-tauri/src-tauri/src/repository/verthys_wal.rs)：
- WalEntry 新增 `Removed` 删除墓碑（hashes + at，独立于导入会话）；
  恢复重放时从 committed 集合/ID 映射移除哈希；
- 快照文件（WAL 同目录 .snapshot，tmp+rename 原子写）：compacted
  committed 集合镜像，恢复 = 快照 O(1) 基线 + WAL 增量重放；
  WAL 文件缺失时快照仍独立承载去重集合（新增回归测试验证）；
- 新增 `append_removed`（append 模式写墓碑 + fsync；WAL 不存在时
  无操作且不创建文件）与 `remove_all`（开发重置：删除 WAL + 快照）；
- ImportSession 新增 `forget_committed`（内存集合即时移除 + 计数递减）。
命令层：
- 新增 `verthys_forget_hashes`（闸门 + 输入校验 + spawn_blocking 落
  墓碑 + 活跃会话内存即时移除）与 `dev_reset_wal`（仅无活跃会话时
  可用）；cmd 常量 FORGET_HASHES / DEV_RESET_WAL；lib.rs 注册。
前端：
- [verthys.ts](../verthys-tauri/src/lib/verthys.ts) 新增
  verthysForgetHashes 包装；
- [usePhotoDelete.ts](../verthys-tauri/src/composables/photo-album/usePhotoDelete.ts)
  批量删除成功后收集已加载 meta 的 fileHash 调 verthysForgetHashes
  （best-effort，失败仅影响再导入去重、不影响删除结果）。

#### 与原方案的能力边界声明（必须明示）
原方案「store 持久化 alive_hashes 索引 + 求交」无法原样落地：
内容哈希位于客户端加密的 meta 密文内部，store 侧（worker/C 层）
不具备任何哈希语义，且删除是唯一变更存活集的路径、必经前端。
故以「前端删除成功后写 Removed 墓碑（删除时点的真实存活差集）」
作为等价闭环，产品语义（删除后可重新导入）一致；若未来引入后端
可解析哈希的存储形态，再补 store 侧索引。

#### Wave 35 批次验证门（w35gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 全量单测 | cargo test --lib（src-tauri） | 362/0 全绿（+4 墓碑/快照用例） |
| Rust 编译告警 | cargo check --lib | 0 警告 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 133/133 全绿 |
| 前端构建 | npm run build | 通过（4.51s） |

#### Wave 35 收尾交接清单
1. 用户实测项：导入照片 → 删除该照片 → 重新导入同一文件成功
   （去重锁已释放）；未删除的照片重复导入仍被跳过（去重仍有效）；
   重启应用后再导入已删照片成功（墓碑持久化）；
2. 剩余项：R-06 解析预览移出主线程 + 批次 5/6 收口（P1-4/P1-5
   导入状态机与定时器纳管、P2 进度细化、P3 网格虚拟滚动/关闭反馈/
   死代码清理）；
3. 本轮改 Rust（4 文件）+ 前端（2 文件），未提交 git，与
   Wave 0~34 同批待用户评审验收。

### 2026-09-26 Wave 36：解析预览移出主线程 + 批次 5 收口（P2-1/P2-4/P2-6）

#### 变更点
R-06 解析预览移出主线程：
- 新增 [parse-crypto.worker.ts](../verthys-tauri/src/workers/parse-crypto.worker.ts)：
  容器解包（令牌派生 + 逐帧 AEAD）、逐张首块密钥预检、块 base64
  转换全部移入 Web Worker；协议含 progress / success / failure 三态
  可辨识联合（type 判别字段，主线程窄化安全）；
- [usePhotoParse.ts](../verthys-tauri/src/composables/photo-album/usePhotoParse.ts)
  doParse 改为 Worker 委托：容器字节 transferList 零拷贝移交（视图
  与底层缓冲不重合时先复制精确片段）、进度消息经既有 rAF 去重渲染、
  完成后装载预览并 terminate；parseWorkerFactory 依赖注入（测试以
  伪 Worker 驱动响应）；主线程不再执行任何解密计算；
- [usePhotoParse.spec.ts](../verthys-tauri/src/composables/photo-album/usePhotoParse.spec.ts)
  伪 Worker 驱动模式重写（请求捕获 + 响应注入），新增 worker 失败
  分类文案用例（7 用例全绿）。
批次 5 收口：
- P2-1 进度结束语义：[importProgress.ts](../verthys-tauri/src/composables/photo-album/importProgress.ts)
  end(ok) 成功才落 100%「已导入 N 张照片」；失败/中止保持真实进度，
  文案「导入未完成（已导入 N 张）」；[importPipeline.ts](../verthys-tauri/src/composables/photo-album/importPipeline.ts)
  八个收尾路径按成败语义区分调用（成功 true，中止/致命/部分失败/
  异常 false）；
- P2-4 展示名结构化：ImportedPhotoResult / ConsumerItem 新增
  displayName（run 取真实文件名、runParsed 取 meta.name），
  importedToPhotoEntries 以 displayName 为权威、仅缺失时回退
  「记录名剥离 meta_ 前缀」；
- P2-6 取消提示如实化：[usePhotoImport.ts](../verthys-tauri/src/composables/photo-album/usePhotoImport.ts)
  取消状态文案补记已导入数量（已提交批次已落库）。
已核验无需再改（前置会话已落地）：
- P1-4 定时器纳管（useSingleTimer 双句柄 + 阶段守卫）与 P1-5 导入
  状态机（idle/acquiring/running/finishing + epoch 代次仲裁）已在
  usePhotoImport 完整实现；
- P2-5 浏览器/内存模式 ID 统一（nextMemoryPhotoId）已实现；
- P2-7 skipped 以后端响应为权威已在消费层落实；P2-2 并发互斥由
  pipeline running 实例锁 + 状态机 epoch 双重覆盖。

#### 能力边界声明（P3 网格虚拟滚动，明示未达）
照片网格虚拟滚动未在本轮落地：现为 CSS 瀑布流（如 masonry 布局）
渲染全量条目，虚拟化需要绝对定位/占位高度重构，且必须先建立大
照片库（万级）的滚动性能基线才可验证收益，盲目改造有回退风险。
临时措施：现有加载按需解密 + 扫描分页已覆盖首屏性能；转生产补齐
需一次专项（基线测量 → content-visibility / 窗口化方案选型 → 回归）。

#### Wave 36 批次验证门（w36gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 全量单测 | cargo test --lib（src-tauri） | 362/0（本轮无 Rust 变更） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 134/134 全绿（parse +1） |
| 前端构建 | npm run build | 通过（4.77s） |

#### Wave 36 收尾交接清单
1. 用户实测项：解析大 .venc 时主线程不卡（选择/滚动对话框即时
   响应），进度逐张推进；模块密钥不匹配照片计入不可解密；导入
   完成后进度条 100%「已导入 N 张」；取消/失败导入进度不虚假冲刺
   且文案含已导入数量；导入列表文件名显示真实文件名（无 meta_ 前缀）；
2. 收口后剩余：P3 网格虚拟滚动（声明见上）+ 全量门禁（run_ci +
   worker 测试 + 回滚说明）；其余修复方案条目全部落地（批次 1~5、
   P1-2/P1-3/P1-6、R-06）；
3. 本轮改前端（5 文件 + 1 新 Worker），未提交 git，与 Wave 0~35
   同批待用户评审验收。

### 2026-09-26 Wave 37：导入链路全量深检收口（WAL 快照基线保真 + 墓碑写者化 + 孤儿块台账 GC + 删除级联闭环）

> 背景：Wave 33~36 已交付单写者/外置 chunk/删除墓碑/快照与批次 5 收口。
> 本波对导入全链路做深入验证，发现并根治 4 处真实缺陷，补齐孤儿块
> 回收机制，并完成全量门禁。注释遵守「无外部文档引用与编号」硬约束。

#### 缺陷根治（深检发现，均为生产级数据正确性/性能缺陷）
1. 跨会话去重键永久丢失：WAL 重放遇 Begin 无条件清空快照基线，
   新会话截断 WAL 后 compact 即把全集收敛为「仅本会话增量」，重启
   后同一批照片全部重复入库（去重失效）。根治：[verthys_wal.rs](../verthys-tauri/src-tauri/src/repository/verthys_wal.rs)
   Begin 仅标记活跃会话不再清空集合（WAL 每会话创建前必截断，
   Begin 必为当前历史起点）；新增回归测试
   test_snapshot_baseline_survives_new_session。
2. compact 未达 O(1) 载入目标：compact 将全量哈希重复写入 WAL，
   快照基线仅作冗余，百万级存活下 begin 仍全量重放。根治：compact
   改最小骨架（begin + checkpoint + end），哈希全集只落快照文件；
   恢复 = 快照 O(1) 基线 + WAL 增量重放；新增回归测试
   test_compact_wal_is_minimal_skeleton 与
   test_tombstone_after_compact_releases_snapshot_hash（墓碑跨
   compact 生效）。
3. 墓碑并发写竞态：活跃会话期间命令层直开第二句柄追加 WAL，与
   写者线程并发写同一文件存在 JSON 行交错损坏风险。根治：
   [import_writer.rs](../verthys-tauri/src-tauri/src/state/import_writer.rs)
   新增 WriterCommand::AppendRemoved，[verthys_batch_controller.rs](../verthys-tauri/src-tauri/src/controller/verthys_batch_controller.rs)
   verthys_forget_hashes 活跃会话时经写者 FIFO 落墓碑 + 会话内存即时
   释放；无活跃会话保留直接追加快速路径（无并发写者）。
4. INV-6 异步线程阻塞残留：verthys_import_begin / verthys_wal_recover
   的 WAL 载入改 spawn_blocking；wal_recover 取消「WAL 缺失即空返回」
   早退（快照独立承载基线场景不被静默丢弃）。修复后的 wal_recover
   对旧 caller 语义零变化（无遗留时 load 自然返回空集）。

#### 孤儿块回收（补齐 Wave 34 声明的残留）
- 新增 [verthys_chunks.rs](../verthys-tauri/src-tauri/src/repository/verthys_chunks.rs)：
  外置块台账（chunk 记录 ID → owner meta ID，0 = 已上传未引用）。
  只存纯数字 ID 映射，不含密钥/明文/哈希；原子写（tmp+fsync+rename）。
- 单写者双向记账：块上传成功 set_owner(id,0)（随命令落账）；
  meta 成功 committed 且带 chunk_ids 时 set_owner(cid, meta_id)
  （随批次 checkpoint 落账）；落账失败不影响已入库数据（GC 语义
  退化为保守）。
- 新增 verthys_gc_orphan_chunks 命令（闸门 + 活跃会话拒绝 +
  spawn_blocking 超时包裹）：台账 owner=0 的块经 worker
  delete_records 批量回收，成功才收敛台账（收敛失败仅影响后续
  GC 时点，块已删无害）；cmd 常量 GC_ORPHAN_CHUNKS；lib.rs 注册。
- 前端触发点：导入会话零失败收敛后 + 批量删除成功后 best-effort
  触发（verthysGcOrphanChunks 包装，失败仅推迟到下次时机）。

#### 删除级联闭环（前端）
- [usePhotoDelete.ts](../verthys-tauri/src/composables/photo-album/usePhotoDelete.ts)
  单张删除补记去重锁释放（此前仅批量路径释放，单删后再导入会被
  误判已导入跳过）；占位项（重启后 meta 未解密）删除经 resolveMeta
  注入强制解密（并发 4）补齐外置 chunk 级联与 fileHash，杜绝
  「删 meta 不删块」的存储泄漏；[PhotoAlbum.vue](../verthys-tauri/src/components/modules/PhotoAlbum.vue)
  注入 decryptPhotoMeta 兜底回调。

#### 门禁加固
- [run_ci.ps1](../ci/run_ci.ps1) 锚点 4 由 4 命令扩至 8 命令
  （begin / add_records / add_chunk / forget_hashes / dev_reset_wal /
  import_end / import_checkpoint / gc_orphan_chunks 各一挂接解锁闸门，
  防回退红线）。

#### Wave 37 批次验证门（w37gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 全量单测 | cargo test --lib（src-tauri） | 371/0 全绿（+3 WAL 回归 + 6 台账/GC） |
| Rust 编译检查 | cargo check --lib | 0 错误 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 134/134 全绿 |
| 前端构建 | npm run build | 通过 |
| Worker 单测 | cargo test（verthys-worker） | 22/0 全绿 |
| 全量 CI | .\ci\run_ci.ps1 | 全部通过（锚点 8 命令 + AST 0 错误，42 条存量基线豁免重生成） |

#### Wave 37 收尾交接清单
1. 用户实测项：重启后再次导入历史照片仍被去重跳过（快照基线保真）；
   删除照片（含重启后未浏览的占位项）后重新导入成功且无块残留；
   导入成功结束后 / 批量删除后孤儿块被 GC 回收；
2. 声明边界维持不变：store 侧无哈希语义（哈希在客户端加密 meta 内），
   alive_hashes 索引以「前端删除墓碑 + 台账 GC」等价闭环；网格虚拟
   滚动仍暂缓（Wave 36 声明）；
3. 本轮改 Rust（6 文件 + 1 新模块）+ 前端（5 文件）+ run_ci，未提交
   git，与 Wave 0~36 同批待用户评审验收。
### 2026-09-27 Wave 38：拾光照片加载链路修复（批次一~三 + 索引瘦身布局）

依据 `docs/RemediationPlan/拾光模块照片加载链路修复方案.md`（修订版）执行，
方案内 §3.8~§3.20.1 为逐批结果记录，此处仅列运维要点与门禁。

#### 变更点
1. 前端读取链路：摘要首屏、缓存回灌语义（只认已解密）、扫描失败显式可见、
   密钥失效联动、查看器一致性（请求序号 + 逐块哈希校验）、方向感知预取 + 去抖。
2. 后端容量：扫描投影（INDEX/FULL）+ 取批字节预算 + 失败条目透传；
   worker 写侧响应行收敛与读取侧兜底上限的跨层不变式。
3. 元数据瘦身（压缩块恒定外置）与每文件一次密钥派生（按盐缓存、口令参与键控）。
4. 解密下沉 Worker：`decrypt_meta` / `decrypt_chunks` / `decrypt_thumb` 与
   `encrypt_slim_thumb`，Worker 优先 + 主线程兜底桥接；派生缓存按
   "口令指纹 + 盐"有界驻留（容量 8、淘汰零填充），模块密钥失效由池
   `clearCache` 标记于各 Worker 下一任务入口清空（`invalidateDerivedKeys`）。
5. 扫描进度与取消（S5）：域层 `ScanProgress`（cached/scanned/failed 真实计数）
   + `cancelRecordScan` / `cancelSummaryScan`（协作式、可续扫）；前端
   `photo-album/load-progress.ts` 信号层（阶段区间 + 真实计数插值 + 单调闸门），
   进度卡接入统一进度条组件并带取消/继续入口。
6. 缩略图 Blob URL（S9）：解密产物与回灌重建均产出 Blob URL，五处释放点与
   生成点成对（覆盖前 / 单删 / 批删 / 卸载 / 密钥失效）。
7. 跨层预算常量单源：`verthys-tauri/constants/photo_budget.schema.json` +
   `generate.mjs` 产出前端 TS 与 Rust 同源常量（9 条不变式 + 编译期断言），
   `run_ci.ps1` 新增常量门（生成物与来源漂移即红）。
8. 索引瘦身布局（§5.2 / §5.3）：缩略图独立记录（类型 0x07，经外置载荷通道
   上传并入台账认领）、随机文件密钥包裹于索引、块密文仅 nonce|密文；
   写入开关 `PHOTO_WRITE_FMT` 默认关（既有布局），容器导入按来源布局保留；
   读取侧按索引内布局标记分流（缺引用即回落既有布局）。

#### 关键约束（改动时勿破坏）
- 索引密文盐必须与包裹密钥同盐（读取侧一次派生覆盖索引与缩略图）；
- 缩略图与块的 AD 绑定（文件哈希 / 序号与总数）不得放宽；
- 索引明文受 `PHOTO_INDEX_MAX_BYTES` 预算约束（超预算前置拒绝）；
- 布局二与布局一必须并存可读，禁止只写新布局而不读旧布局。

#### Wave 38 批次验证门
| 门禁 | 命令 | 结果 |
|---|---|---|
| C 全量测试 | build_dev / build Release 测试可执行 | 307/307 全绿（Debug 与 Release 各一次） |
| Rust 全量单测 | cargo test --lib（src-tauri） | 377/0 全绿 |
| Worker 单测 | cargo test（verthys-worker） | 33/0 全绿 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 215/215 全绿（20 文件） |
| 前端构建 | npx vite build | 通过 |
| 全量 CI | .\ci\run_ci.ps1 | 全部通过（锚点门 + 新增常量门 + 一级正则 + 二级 AST，41 条存量基线豁免） |
| 生产构建部署 | .\build_production.ps1 -SkipTauri -NoPause | DLL 与 worker 重建并部署，哈希校验一致；DLL 导出集 31 符号与基线逐一相等 |

#### Wave 38 收尾交接清单
1. 用户实测项（开发模式）：含 5 MB 照片相册的列表首屏与滚动、进度卡取消/继续、
   缩略图 Blob URL 释放（切模块多次往返不增长对象 URL）、布局二仅在开启
   写入开关后由新导入产生（默认关时新导入仍为既有布局）。
2. 明确未实施项：后台重打包（§5.5 可选，已在 Wave 39 落地）、导出链路解密下沉 Worker、
   记录模型演进的"索引瘦身至 1 KiB"目标值（当时为上界 10460 字节；已在 Wave 39 以块集记录降至 2656 字节）。
3. 本轮改 C（1 文件：全量扫描告警去 printf 族）、Rust（8 文件）、前端（约 30 文件）、
   新增常量生成物与 CI 常量门，未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-27 Wave 39：索引瘦身目标收口（块集记录）与后台重打包落地

依据 `docs/RemediationPlan/拾光模块照片加载链路修复方案.md`（修订版）执行，
方案内 §3.21~§3.21.3 为规格与结果记录，此处仅列运维要点与门禁。

#### 变更点
1. 块集记录（类型 0x09）：逐块引用与逐块哈希移出索引，索引体积与照片大小解耦。
   加密规格与缩略图一致（包裹密钥 + 文件盐 + 文件哈希 AD），双向结构校验；
   Worker 新增 `encrypt_slim_set` / `decrypt_slim_set` 两个 op；池与解密桥
   （主线程兜底）接线；写入经 `verthys_add_chunk_batch` 外置载荷通道
   （Rust 角色类型白名单扩至 {5,7,9}，按角色命名 `chunk_/thumb_/cset_`）。
2. 索引字段收口：新写入索引只含 `thumbId / chunkSetId / chunkCount` 聚合引用；
   `chunk_ids` 台账认领覆盖缩略图与块集记录；缩略图缺失时 `thumbId=0`，
   布局判定（`isSlimLayout`）与缩略图判定（`isSlimPhotoMeta`）分离。
3. 逐块引用分流收敛于单一模块 `photo-album/chunk-refs.ts`：块集优先 →
   索引内联回落 → 索引内联块密文；查看器 / 导出 / 删除 / 重打包共用；
   块集解析校验 `chunkCount === ids.length`，缺块按缺失计数上报。
4. 后台重打包（存量布局一 → 布局二）：引擎（`repack.ts`，依赖注入、
   幂等单元=单张、整图 BLAKE3 前置校验、"新索引落库成功后才删除旧记录集"、
   取消在张边界生效、`DUPLICATE_SKIPPED` 计跳过）+ 编排层
   （`usePhotoRepack.ts`，摘要索引/扫描缓存/解密桥/Worker 池/写入会话装配，
   列表项原位替换 + 缩略图 URL 吊销 + 三层缓存失效）；入口由写入开关
   常量控制显隐（默认关 → 入口不出现），运行横幅显示真实计数与取消。
5. 预算单源更新：`photo_budget.schema.json` 新增索引固定字段/引用字节数
   与块集预算参数；生成器派生 `photo_index_plain_max=2656`、
   `chunk_set_plain_max=7964`（最大 100 块场景），新增 2 条不变式（共 11 条）；
   Rust 同源常量新增 4 个 `PB_*` 并纳入编译期 const 断言。

#### 关键约束（改动时勿破坏）
- 块集与缩略图共用包裹密钥与文件盐：读取侧一次派生必须覆盖索引/缩略图/块集/密钥解封；
- 块集 AD 必须绑定文件哈希（跨照片换用即解密失败）；块集项数必须与索引 `chunkCount` 相等；
- 重打包必须"新索引落库成功后才删除旧记录集"，任一步失败保留源记录；
- 索引超预算必须前置拒绝（不静默写入使列表缓存失效）；
- 无缩略图照片必须仍可写入：索引以 `thumbId=0` 明确"无缩略图"，
  但台账认领列表不得含占位 0（否则写者按"引用未上传"拒绝整条记录）；
- 早期布局二（索引内联逐块项）读取分支不得删除。

#### Wave 39 批次验证门
| 门禁 | 命令 | 结果 |
|---|---|---|
| 常量生成物 | node constants/generate.mjs --check | 一致（11 条不变式全过） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 230/230 全绿（21 文件，新增引擎 10 + 块集 4 + 瘦身写入回归 1） |
| 前端构建 | npx vite build | 通过 |
| Rust 全量单测 | cargo test --lib（src-tauri） | 377/0 全绿 |
| Worker 单测 | cargo test（verthys-worker） | 33/0 全绿 |
| C 全量测试 | ctest --test-dir build -C Release | 通过（1 个聚合测试项） |
| 全量 CI | .\ci\run_ci.ps1 | 全部通过（锚点门 + 常量门 + 一级正则 + 二级 AST） |
| 生产构建部署 | .\build_production.ps1 -SkipTauri -NoPause | DLL 与 worker 重建并部署，哈希校验一致 |

#### Wave 39 收尾交接清单
1. 用户实测项（开发模式）：开启写入开关后顶栏出现迁移入口；迁移单张照片后
   重启仍可正常浏览/查看/导出/删除；迁移中途取消后再次点击可续跑；
   块集与缩略图记录随照片删除无残留（孤儿台账 GC 兜底）。
2. 遗留边界：默认关时重打包入口不出现（存量数据零改动）；导出链路解密
   当时仍未下沉 Worker（已在 Wave 40 落地）；真机手工用例仍待实测（延续 Wave 38 清单）。
3. 本轮改 Rust（4 文件：类型、角色白名单、常量与生成物）、前端（约 20 文件，
   含 repack / usePhotoRepack / chunk-refs 三个新模块与 repack.spec 一个新测试文件，
   另扩展 crypto-slim.spec 与 importPipeline.spec）、常量 schema 与生成器，
   未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 40：导出路径解密下沉 Worker 池（导出一致性收口）

依据 `docs/RemediationPlan/拾光模块照片加载链路修复方案.md`（修订版）执行，
方案内 §3.22 为规格与结果记录，此处仅列运维要点与门禁。

#### 变更点
1. 导出层三处解密点全部改经解密桥（Worker 池优先 + 主线程兜底）：
   占位项（重启后未解密）的索引解密 → `decryptMetaPreferWorker`；索引瘦身布局的
   缩略图记录解密 → `decryptThumbPreferWorker`；明文导出的整图逐块解密 →
   `decryptChunksPreferWorker`（瘦身布局携带包裹密钥与块总数）。
   主线程不再执行 PBKDF2-150k 与 AEAD，导出期间不阻塞渲染主线程。
2. 顺序校验统一下沉：既有布局"块自描述位置（seq/total）与列表位置一致"的判定
   由共享解密路径（Worker 任务与主线程回退）统一执行——此前仅明文导出侧单独校验；
   现导出/查看器/重打包口径一致，截断/乱序列表在拼接前拒绝并标注块序号。
3. 失败归因修正：明文导出（PNG）此前把解密/完整性校验失败与画布转换失败
   混记为 `convert-failed`；现以专用错误类型 `PhotoDecryptError` 区分，
   解密失败归因 `decrypt-failed`，结果文案与失败明细准确。
4. 进度与取消语义不变：解密为单张一次任务，逐张状态与百分比照旧；
   导出期间对话框不可关闭、无取消入口的既有语义未改变。

#### 关键约束（改动时勿破坏）
- 导出解密必须经桥（`photo-decrypt-bridge`），禁止在导出层直接调用
  `decryptMeta` / `decryptChunk` / `decryptSlimThumb` 等主线程原语；
- 既有布局块列表必须校验 seq/total 自描述位置（Worker 与回退两条路径同一判定）；
- 明文导出的解密失败必须归因 `decrypt-failed`，不得与 `convert-failed` 混记；
- 导出结果文案仍只由成功/失败计数派生（三态契约不变）。

#### Wave 40 批次验证门
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 235/235 全绿（21 文件，导出 +3 / Worker +1 / 桥 +1） |
| 前端构建 | npx vite build | 通过 |
| 全量 CI | .\ci\run_ci.ps1 | 全部通过（锚点门 + 常量门 + 一级正则 + 二级 AST） |
| Rust / C 门禁 | 本轮未改 Rust/C | 沿用 Wave 39 结果（宿主 377 / worker 33 / C 全量通过） |

#### Wave 40 收尾交接清单
1. 用户实测项（开发模式）：重启后未浏览即导出（占位项）仍成功且期间交互流畅；
   PNG 明文导出大批量照片不卡界面；对损坏照片导出时失败文案为
   "照片解密或完整性校验失败"（而非"图片转换失败"）。
2. 遗留边界：导出依旧无取消入口（既有语义）；浏览器模式导出为内存内加密
   （无解密环节），不在本次下沉范围。
3. 本轮改前端（2 文件：usePhotoExport.ts 与其 spec；另 worker/bridge 各 1 处
   校验与 2 个 spec 用例），未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 41：多方案冲突统一（导入链路 × 加载链路）+ 落盘门禁结构性修复

依据：导入链路生产级根治方案 v1.0（终稿）与《拾光模块照片加载链路修复方案》
（修订版）并行推进下的冲突裁定；承接 Wave 39/40 已落地的记录模型与导出下沉。

#### 冲突裁定（统一冲突源，逐条给结论）

1. **响应行预算双机制 → 收敛到单一权威来源。**
   加载链路已建 `verthys-tauri/constants/photo_budget.schema.json` + `generate.mjs`
   （请求行 16MiB / worker 写侧响应 24MiB / 主进程读取 32MiB，含生成器静态断言）；
   导入链路的 `ENUM_RESPONSE_DATA_BUDGET_BYTES` 原为字面量 12MiB。
   裁定：读侧**语义截批**（超预算即截批并由调用方以游标续批，零记录丢失）与写侧
   **兜底收敛**（超限响应转受控错误行）保留为纵深防御；读侧预算改为生成常量
   `PB_ENUM_RESPONSE_DATA_BUDGET_BYTES`（= `ipc_max_payload`），并新增生成器断言
   「预算 + JSON 头 ≤ 写侧行上限」，保证合法批次永不触发写侧兜底。
2. **导入预算拟新建第二份 schema → 并入第一份（禁止第二来源）。**
   导入方案原拟新建 `constants/schemas/photo-import-budget.schema.json`；裁定并入
   现有 `photo_budget.schema.json`（同生成器、同 `--check` CI 门禁）。新增常量：
   `max_file_chunk_size` / `flush_max_retries`(2→3) / `flush_retry_backoff_ms` /
   `flush_verify_timeout_ms` / `session_begin|end|force_close_timeout_ms`；
   派生量 `enum_response_data_budget` / `max_inline_file_bytes` 由生成器计算（禁手填）。
3. **落盘校验下沉的宿主架构修正（方案 §3.4 假设与实现不符）。**
   方案假设主进程可直接持有 C 会话句柄；实际 **C 层运行在 verthys-worker 子进程**，
   主进程拿不到句柄。裁定统一为 **worker op `verify_persist`**：worker 进程内用
   `ctx->v3->f` 持锁句柄自查（同进程同句柄，锁语义无关），主机命令仅转发结构化
   结果，前端按判别式消费。
4. **照片记录模型变更的兼容确认（无冲突）。**
   加载链路已将 `MAX_INLINE_META_BYTES` 定为 0（分块一律外置，meta 仅缩略图+引用）；
   导入/解析两条路径的 inline/external 判定经同一常量自动收敛为「恒外置」，
   两侧口径一致；导入侧内联分支仅剩 0 块边界（见遗留待办）。

#### 本波次落地（代码）

1. **常量单一来源**：`photo_budget.schema.json`（+7 常量）与 `generate.mjs`
   （+2 派生量、+4 断言）重新生成 TS/Rust 常量；worker `dispatch.rs` 的响应预算
   改用生成常量；`FileVerthys.vue` 分块口径改用 `MAX_FILE_CHUNK_SIZE_BYTES`。
2. **P0-1/P0-2 落盘门禁修复（结构性）**：
   C 层新增 `Verthys_VerifyPersist`（`core/include/verthys.h` 声明、
   `verthys_api.c` 用持锁句柄实现、`verthys.def` 导出；C 测试
   `v3life_verify_persist_selfcheck` 覆盖解锁态 OK / 锁库后 INTERNAL / 空参不崩溃）；
   worker 新增 op `verify_persist`（`worker.rs` 绑定 + `dispatch.rs` 分支 +
   `protocol.rs` 结构化字段）；主机 `verthys_verify_disk_persist` 删除外部读旧实现
   （含其 3 个旧单测，改由 C 测试承载）改为转发 worker 自查；前端
   `flushWithVerify()` + `persistVerthysDetailed()` 三态（ok / partial_persisted /
   not_persisted），`persistVerthys()` 保留 boolean 签名（partial 视为已落盘并告警）；
   三个消费点（usePhotoParse / usePhotoImport / usePhotoDelete）按三态分流，
   **partial 时提交列表与缓存**（消除「已落盘却宣称未生效」撕裂）。
3. **P1-1 会话状态机**：`importPipeline.ts` 两处 begin 增加 `ok` 校验并按后端错误
   分流文案（残留会话 / 未解锁 / 其他）；新增 `endSessionSafely()`（失败重试一次
   → 仍失败调用新命令 `verthys_force_close_import_session` 自愈清理，保留 WAL
   续传状态）；全部会话结束点（含重打包）统一走该封装。
4. **P1-4 边界前置**：`FileVerthys` 导入前按 `MAX_INLINE_FILE_BYTES`（9MiB）拦截
   超限文件并给出可理解文案（内联模型下的诚实边界，外置块迁移见遗留待办）。
5. **P2-1 预热 V3 化**：`verthys_preheat_blocking` 删除 v1/v2 布局的索引区预读
   （旧 header[54..70] 解析），改为 V3 帧头判定 + 预读固定布局区（超块三副本 64KB
   + WAL 960KB + 分区表 3MB）与温缓存文件 `.verthys.idx_cache`。
6. **P2-2/P2-3 读侧吞错收敛**：`verthysGetRecord` 失败留痕（记录过大/通道异常不再
   退化为静默空数据）；`verthysForgetHashes` 检查返回值 + 重试一次 + 仍失败上抛
   （去重锁释放失败不再静默）。
7. **P2-4 不变量常驻**：导入结果四分类不变量改为所有环境记录（原仅 DEV）。

#### Wave 41 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 常量门 | node constants/generate.mjs --check | 一致（14 项不变式通过） |
| C 核心全量 | build_dev/core/tests/Debug/verthys_tests.exe | 308 passed / 0 failed |
| Worker 单测 | cargo test（verthys-worker） | 33 passed / 0 failed |
| 主机单测 | cargo test（src-tauri） | 372 passed / 0 failed（较上轮 -3：旧落盘校验单测被 C 测试取代） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 236 passed（21 文件） |
| 生产构建 | build_production.ps1 -SkipTauri -NoPause | 成功（两次：初版 + printf 红线修复后重部署）：DLL（含 Verthys_VerifyPersist，无 printf 族）与 worker 重建并部署到 binaries/ + src-tauri/，哈希一致 |
| 全量 CI | .\ci\run_ci.ps1 | **本波次引入的 9 处 printf 红线已清零**；剩余 1 项为外部在途（见下方交叉发现第 2 条，`verthys_controller.rs:636` 分层违规），非本波次范围 |

#### Wave 41 CI 交叉发现（复核记录）

1. **已修（本波次引入）**：新落盘自查 C 代码使用 `snprintf` 写入 `last_error`，
   触发「C 文件包含 printf/fprintf 输出函数」红线（9 处，均超出基线豁免）。
   已改为静态文案拷贝（`ver_persist_set_error`：`strlen` + `memcpy`），数值细节由
   结构体字段（`header_magic` / `header_version` / `file_size` / `wal_offset`）承载；
   复核后该文件已无任何 `snprintf`，C 套件仍 308/0。
2. **外部在途（非本波次，勿在本任务内改动）**：`controller/verthys_controller.rs:636`
   `use crate::security_commands::brute_force_bridge::{gate_check, UnlockGate};`
   触发「反向导入 controller → security_commands」红线（暴力熔断闸门，另一会话
   在途改动）。建议由该会话按分层规则收敛（经 service/state 层暴露该闸门），
   或经架构评审后加入基线；本波次不动他人飞行中代码。

#### Wave 41 收尾交接清单

1. **用户实测项（开发模式）**：解锁态导入 1 张照片 → 不得再出现「持久化失败」提示；
   解析导入成功 → 对话框完成且相册即时出现照片；删除 1 张 → 不得出现「删除操作
   持久化失败」；日志不再出现 `读取头部失败: 另一个程序已锁定文件的一部分`。
2. **遗留待办（按优先级，均在方案内、未在本波次执行）**：
   - P1-2 缓冲区所有权契约（`BufferRef`：解析失败后重试不得复用已转移缓冲区）；
   - P1-3 统一忙碌信号（`AppBusy`：解析导入期间顶部动作仍可点击，现由管线重入守卫兜底）；
   - P1-4 `FileVerthys` 迁移外置块模型（当前仅体量前置拦截，>9MiB 文件不可导入）；
   - P2-6 0 块照片归因（现被归为「无法用当前密钥解密」，实为空数据记录）；
   - 加载链路批次二/三（扫描投影、回退枚举分页、记录模型演进收尾）；
   - 会话 begin/end 超时常量（`session_*_timeout_ms`）已入 schema 但未接入调用点。
3. **本波次改动文件**：C（verthys.h / verthys_api.c / verthys.def / test_v3_lifecycle.c /
   test_runner.c）、worker（dispatch.rs / protocol.rs / worker.rs / ffi_types.rs）、
   主机（verthys_controller.rs / types.rs / lib.rs）、前端（verthys.ts / types/verthys.ts /
   verthys-flush-service.ts / verthys-flush.ts / verthys-cache.ts / keyManager.ts /
   usePhotoParse.ts / usePhotoImport.ts / usePhotoDelete.ts / PhotoAlbum.vue /
   importPipeline.ts / FileVerthys.vue）、常量（photo_budget.schema.json / generate.mjs +
   两侧生成物）；未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 42：导入链路遗留项收口（P1-2 / P1-3 / P1-4 / P2-6 + 会话超时接入）

承接 Wave 41 收尾交接清单的遗留待办，逐项落地并复跑门禁。

#### 变更点

1. **P1-2 缓冲区所有权契约（解析重试可重读）**：`usePhotoParse.ts` 新增
   `parseFilePath`（Tauri 选择时记录完整路径）；`doParse` 发送前检测已转移
   （detached，`buffer.byteLength === 0`）缓冲区——按原路径重读后续跑；
   浏览器模式无路径则明确要求重新选择。消除「解析失败后未重选文件直接重试
   发送 0 字节缓冲 → 报『文件已损坏』」的误导性失败。
2. **P1-3 统一忙碌信号**：`PhotoAlbum.vue` 新增 `albumBusy`（importing ∨ parsing
   ∨ importingParsed ∨ exporting ∨ repackRunning），顶栏导出/解析/导入/删除四处
   入口统一 `:disabled`（删除态保留"退出选择模式"）；禁用态样式含 `:hover` 覆盖
   （不再悬浮提亮），光标 not-allowed。互斥第一道防线回到 UI，后端拒绝仅兜底。
3. **P1-4 FileVerthys 外置块模型迁移**：`startImport` 改为逐块写入独立 chunk 记录
   （`chunk_<文件名>_<序号>`，任一块失败即计入失败并留痕），meta 仅存 `chunkIds`
   与展示字段；**删除加载侧「chunkIds → 内联」迁移分支**（迁移方向已反转，读取
   路径对两种形态原生兼容：`chunkDataB64` 优先、`chunkIds` 回退；删除级联仍收集
   `chunkIds`）；随之移除 9MiB 体量前置拦截——单文件体量只受容器容量约束。
   配套：`photo_budget` 中已无消费者的派生量 `max_inline_file_bytes` 与
   `PB_MAX_INLINE_FILE_BYTES` 及其断言整体退役（禁止无消费者常量沉淀）。
4. **P2-6 空数据记录归因**：解析 Worker 预检把 `chunkCount === 0` 单列
   （`emptyCount`，不再混入 `undecryptable`）；完成响应新增必填字段
   `emptyCount`；`usePhotoParse` 新增 `parsedEmpty`；对话框新增
   「N 张为空数据记录（无图像块），将不会被导入」提示（与密钥不匹配分列）。
5. **会话超时常量接入调用点**：`verthysImportBegin` / `verthysImportEnd` /
   `verthysForceCloseImportSession` 改用 `invokeWithTimeout` + 生成常量
   `SESSION_BEGIN/END/FORCE_CLOSE_TIMEOUT_MS`（3s / 30s / 5s）；超时按可重试
   失败返回（不抛出），由 `endSessionSafely` 重试与自愈清理承接；worker 挂死
   不再无限等待。

#### 并发协作说明（重要）

- `importPipeline.ts` 在 Wave 41 后被另一会话重构为「`runSession` 编排骨架 +
  `ProduceContext` + 两条链路生产策略」；本波次核验时其重构曾处于不可编译的
  中间态（`files`/`ctx` 未接线的语法错误 + 17 项 spec 失败）。**未介入其飞行中
  代码**；等待其收敛后复核：本波次的会话状态机改动（`classifyBeginFailure` /
  `beginResult.ok` 校验 / `endSessionSafely` + 强制清理）已被其保留并整合进
  `runSession`，`vue-tsc` 0 错误、vitest 236 全绿。
- 本波次自身引入的门禁问题（`ParseCryptoSuccess.emptyCount` 必填导致 spec 类型
  错误）已同步修复（两处 mock 补字段 + 新增 `parsedEmpty` 断言）。

#### Wave 42 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 常量门 | node constants/generate.mjs --check | 一致（13 项不变式通过；max_inline_file_bytes 退役） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 236 passed（21 文件） |
| Worker 单测 | cargo test（verthys-worker） | 33 passed / 0 failed |
| 主机单测 | cargo test（src-tauri） | 372 passed / 0 failed |
| C 核心全量 | build_dev/core/tests/Debug/verthys_tests.exe | 308 passed / 0 failed（本轮无 C 改动，沿用 Wave 41 复核） |
| 生产构建 | build_production.ps1 -SkipTauri -NoPause | 成功：DLL 与 worker 重建并部署，哈希一致 |
| 全量 CI | .\ci\run_ci.ps1 | 本波次 0 新增违规；仍剩 Wave 41 记录的外部在途 1 项 |

#### Wave 42 收尾交接清单

1. **用户实测项（开发模式）**：文件库可导入 >9MB 文件（分块外置，导出/删除正常）；
   解析失败后不重选文件直接重试 → 自动重读原文件（不再报"文件已损坏"）；
   解析导入进行中顶栏四处动作均禁用（not-allowed 光标）；含空数据记录的容器
   解析后提示"空数据记录"而非"密钥不匹配"。
2. **遗留待办（更新，2026-09-28 复核后口径）**：
   - **P2-8 解析预览常驻块密文**：`PARSE_PREVIEW_CHUNK_INMEM`（方案常量表要求 false）
     未实现——预览对象仍携带 `chunkB64List`（导入阶段直接复用，避免二次读盘）。
     收口需二选一：导入阶段按路径重读容器取块，或预览只留缩略图/元信息、块密文另行
     装载；属独立设计改动，未纳入 Wave 42。
   - **P3-1 超长记录名前置校验**：Windows 路径上限（MAX_PATH 260）下记录名不可能
     达到后端 1024 字节上限，判定为**理论风险、实际不可达**；如未来支持超长路径
     再补前置护栏。
   - **P3-2 `verthys_import_checkpoint` 无调用方**：属暴露面/维护面决策（删除或
     明确用途），需产品/接口裁定，未擅自删除。
   - **P3-3 记录 ID 精度（>2^53）**：当前容器规模无实害，作为已知约束记录；如达到
     该量级需统一切换 BigInt/字符串 ID（跨层改造）。
   - **P3-4 成功反馈双通道（Toast + 对话框文案）**：体验细节，随 UI 批次合并。
   - 加载链路批次二/三（扫描投影、回退枚举分页、记录模型演进收尾，属另一会话方案）；
     外部在途分层违规 1 项（`verthys_controller.rs:636`，属安全/暴力熔断会话）；
     `FileVerthys.vue` 头部注释"0x05 元数据"为既有失效描述（meta 现为 0x08），
     待清理批次统一处理。
3. **本波次改动文件**：`usePhotoParse.ts`（+其 spec）/ `PhotoAlbum.vue` /
   `FileVerthys.vue` / `parse-crypto.worker.ts`（协议字段）/ `verthys.ts`
   （会话超时接入）/ `photo_budget.schema.json` + `generate.mjs` + 两侧生成物；
   未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 43：导入流水线同构编排去重（runImpl / runParsedImpl → runSession + 生产策略）

承接代码质量评审：`runImpl` 与 `runParsedImpl` 重复率约 70%（会话初始化、进度启动、
消费者缓冲与 flushConsumer、背压信号量、生产者异常收尾、allSettled 处理、会话结束
四分支、异常兜底、不变量校验几乎同构），会话语义修复必须两处同步、极易漏改。

#### 变更点

1. **共享编排骨架 `runSession(config)`**：会话建立（含 `beginResult.ok` 分流与
   `classifyBeginFailure`）、并发生产者调度（取消检查 / 让出节奏）、在途提交收尾、
   消费者缓冲刷新、会话结束四分支（取消 / 致命 / 部分失败 / 成功）、异常兜底与
   四分类不变量兜底全部唯一定义；`label`（「导入」/「解析导入」）注入日志与文案。
2. **`ProduceContext` 契约**：会话状态（imported / failedRecords / skipped /
   undecryptable / fatalErrors / firstErrorName / consumerItems / aborted）只由编排层
   持有，生产策略仅经 ctx 投喂与记账：`addSubmit` / `enqueue` / `isCommitted` /
   `recordSkipped` / `recordProgress` / `recordUndecryptable` / `recordProduceError` /
   `recordLocalFailure` / `abort`。
3. **差异收敛为两个策略方法**：`produceFileImportItem`（读取闸门 + 读文件 +
   单文件上限 + 完整加密 submit + 外置/内联记录构造）与 `produceParsedItem`
   （外置判定 + 前置去重 + 块上传 / 内联 + meta-only 加密 + 不可解密分类）。
4. **互斥包装 `runExclusive`**：空集早返回、进行中拒绝（失败明细按条目展开）、
   `running` 标记成对；`run()` / `runParsed()` 变为薄包装（只提供差异配置）。
5. **有意收敛的行为差异**：日志带会话标签（`生产者异常（解析导入）…`、
   `<label>流水线完成/异常`、`<label>记录写入失败`）；解析导入的 `undecryptable`
   参与取消分支的不变量断言（文件导入恒 0，语义不变）；`undecryptable=0` 时不打印
   该字段（文件导入完成日志保持原样）。

#### 关键约束（改动时勿破坏）

- 会话状态只能由 `runSession` 持有；生产策略不得直接触碰 `imported` /
  `failedRecords` / `consumerItems` / `aborted` 等变量（只经 `ProduceContext`）；
- 新增会话语义修复只改 `runSession` 一处；新增条目来源只新增一个策略实现；
- 生产策略不得吞异常后不记账：拒绝态经 `ctx.recordProduceError` 入账，
  同步抛错由编排层 allSettled 分支兜底（两条通道都必须留下条目级失败记录）；
- 既有语义等价不得回归：四分类不变量、成功语义守卫（零致命 + 零失败才压缩 WAL）、
  取消保留检查点、逐条状态重试与背压阈值、`endSessionSafely` 自愈清理。

#### Wave 43 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 240 passed（21 文件；新增共享编排回归 4 例：策略异常入账 ×2 / 互斥拒绝 / 取消不投喂） |
| 前端构建 | npx vite build | 通过 |
| 全量 CI | .\ci\run_ci.ps1 | 锚点门 / 常量门 / 一级正则通过；二级 AST 报 1 条 Rust 分层违规（`verthys_controller.rs:636`，属安全/暴力熔断会话在途改动，非本波次范围，见 Wave 41 交叉发现第 2 条） |

#### Wave 43 收尾交接清单

1. **用户实测项（开发模式）**：文件导入与 .venc 解析导入的批量行为、进度、
   取消、部分失败文案应与此前完全一致（本波次为重构，无功能变更）。
2. **遗留边界**：`runSession` 含背压/分支/兜底，体量较大（约 440 行）；
   后续如需拆分可按「会话生命周期」与「生产者调度」两段抽方法，但不得引入
   第二份会话状态或第二处结束分支。
3. **本波次改动文件**：`importPipeline.ts` + `importPipeline.spec.ts`；
   未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 44：CI 分层违规根治（service 层依赖反转）+ AST 基线语义对齐

承接 Wave 43 验证门遗留的唯一 CI 红项：`controller/verthys_controller.rs:636`
（controller → security_commands 反向依赖）。该违规为解锁闸门
（`require_unlocked` / `gate_check`）在控制器层直接引用 security_commands
实现所致；本波次按分层单向依赖规则（controller 仅允许引用 service /
repository / util / constants）以依赖反转根治，消除架构性反向引用。

#### 变更点

1. **服务层契约（依赖反转落点）**：新建 `service/unlock_gate.rs`——
   `UnlockGate` 枚举（`Allowed` / `Locked(u64)` / `PurgeRequired` / `Unavailable`）、
   错误码常量 `AUTH_DOMAIN_ERROR`、三个 `OnceLock<fn>` 注册位
   （闸门检查 / 认证失败记账 / 认证成功记账）与对应调用入口；
   未注册时 `gate_check` fail-closed 返回 `Unavailable`（实现缺失时禁止放行）。
2. **实现侧注册（security_commands）**：`brute_force_bridge.rs` 新增
   `install_unlock_gate()` 与三个适配器（经 `app.state::<SecurityState>()`
   获取与命令注入同一托管实例），保留原实现仅供适配器与单测调用；
   `lib.rs` 在唯一 `.setup` 闭包顶部完成注册（先于任何命令可被调用）。
3. **控制器迁移**：`verthys_controller.rs` / `key_controller.rs` 全部闸门与
   记账调用点改经 `crate::service::unlock_gate::*`；随之删除 4 个命令与
   1 个 helper 的 `security_state: State<'_, SecurityState>` 形参及
   `DerivePrecheckCtx.security_state` 字段（全部构造/解构点同步清理）。
   controller → security_commands 反向依赖归零。
4. **AST 基线语义对齐**：删除 3 条已真实消失的豁免
   （`key_controller.rs|306` / `|535`、`verthys_controller.rs|695`——
   均为迁移前的 security_commands 引用键，迁移后自然消亡）；
   保留 38 条（26 反向导入 + 12 C 输出函数）。**重要认知（勿再踩）**：
   CI 行号语义为 `content[..pos].lines().count() + 1`，对「行内缩进 use」
   报真实行号 + 1（把匹配行内前导空白计为一行），基线键必须按 CI 语义
   维护；核对基线时以 CI 实际报键为准，不得以自建脚本的「真实行号」比对。

#### 关键约束（改动时勿破坏）

- 控制器禁止直接 `use crate::security_commands::...`（口令闸门唯一入口为
  `service::unlock_gate` 契约）；
- `security_commands::brute_force_bridge::install_unlock_gate()` 必须在
  `.setup` 期调用：遗漏会使闸门 fail-closed（`Unavailable`），全部口令
  类操作被拒（安全方向正确，但功能不可用）；
- 基线仅用于存量豁免：新增违规不得入基线；维护行号时按上文第 4 条
  CI 语义（缩进行 +1）核对。

#### Wave 44 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 类型检查 | cargo check（src-tauri） | exit 0（无 error/warning） |
| src-tauri 全量测试 | cargo test（src-tauri） | 372 passed / 0 failed（lib 主套件；+3 ignored 长时用例） |
| 全量 CI | .\ci\run_ci.ps1 | 全绿：版本门禁 / 锚点门 / 常量门 / 一级正则通过；二级 AST 0 错误 0 警告（基线豁免 38 条） |

#### Wave 44 收尾交接清单

1. **本波次改动文件**：`service/unlock_gate.rs`（新增）、`service/mod.rs`、
   `security_commands/brute_force_bridge.rs`、`lib.rs`、
   `controller/verthys_controller.rs`、`controller/key_controller.rs`、
   `ci/ast_baseline.txt`；未提交 git，与既有工作树同批待用户评审验收。
2. **用户实测项**：解锁流程（正确/错误口令、连续失败熔断冷却、清空态
   拒绝）行为应与修复前完全一致（本波次为架构迁移，无功能变更）。
3. **遗留**：原 CI 唯一红项已清零。

### 2026-09-28 Wave 45：解析导入 meta-only 加密全量失败根治（Vue 响应式代理穿越 Worker 边界）

用户实测报告：解析导入 15 张照片全部失败，UI 文案「导入失败: 部分记录写入失败，
已保留断点续传状态（失败15张: 加密任务失败×15）」；直接导入同一批照片成功。

#### 根因（全链路铁证）

1. 日志（`%LOCALAPPDATA%\com.verthys.app\logs\main_ui.log`）取证：解析导入会话
   （imp-1790531966687-c1c008e6）块上传逐批成功（22/22 块，与直接导入会话数量
   一致），但**全程无 verthys_add_records_batch 请求**，会话以
   success=false / committed=0 结束——失败发生在「块上传之后、写入之前」。
2. 失败归因全部为 encrypt-failed（非 chunk-upload-failed）→ 排除块上传路径
   （ChunkUploadError 语义），锁定 meta-only 加密提交（submitMetaOnly）。
3. 代码链路闭环：解析产物 meta 恒含 chunkHashes 数组（完整加密产物的
   metaTemplate 由 worker processPhoto 生成时必带，经导出 → .venc → 解析
   原样保留）；`parsedPhotos` 存入 Vue ref（usePhotoParse），`ph.meta` 为深层
   响应式 Proxy；importPipeline 的 `{...meta}` 浅展开**不消除嵌套 Proxy**
   （chunkHashes 等数组），提交 `photoWorkerPool.submitMetaOnly` 后，
   dispatch 的 postMessage 对含 Proxy 载荷抛 DataCloneError
   （"[object Array] could not be cloned"）→ 池转成「Worker 通信失败」普通
   Error → recordProduceError 归类 encrypt-failed → 每张照片同一位置失败
   → 15/15 全失败。
4. 实验实证：structuredClone（与 postMessage 同算法）对 Proxy 的嵌套数组抛
   DataCloneError，且浅展开后仍保留代理身份（Node 复现，与浏览器一致）。
5. 测试盲区说明：importPipeline.spec 将 photoWorkerPool 整体 mock
   （submitMetaOnly 为 vi.fn），postMessage 不执行真实结构化克隆，故既有单测
   与 E2E 均未覆盖「真实 Worker 边界 + 响应式载荷」组合。

#### 修复（双道防线）

1. **源头修复（领域层）**：`importPipeline.ts` 新增导出纯函数
   `toPlainPayload`（JSON 往返脱代理），在 `produceParsedItem` 入口对
   `ph.meta` 一次性净化——覆盖该条目后续全部派生（metaTemplate / 外置提交 /
   内联提交）与模块引用，Proxy 不可能再进入 Worker 载荷。
   语义：与 JSON 一致（undefined 字段净化后消失；跨线程结构化克隆与后端
   JSON 解析后，缺失与 undefined 本就不可区分）。
2. **边界兜底（基础设施层）**：`photoWorkerPool.dispatch` 在 postMessage
   同步失败时识别 DataCloneError → 原地净化为纯数据（JSON 往返）并重投一次：
   不消耗槽位崩溃计数（槽位健康无涉）与毒丸预算（属同一次投递的修复而非
   重试，attempts 不自增）；净化后仍失败才按既有路径 settle。零正常路径
   成本（仅失败路径付费），自动覆盖全部 Worker 载荷链路（含未来新增链路）。

#### 测试（盲区补齐）

- `photoWorkerPool.spec.ts`：FakeWorker 增加 cloneStrict 模式（投递前执行
  真实结构化克隆，与浏览器 postMessage 同语义）；新增用例「载荷含响应式
  代理（DataCloneError）：池自动脱代理净化并重投成功」——真 Proxy 触发真
  DataCloneError，断言净化后载荷可真实克隆、任务成功、崩溃/毒丸指标为 0。
- `importPipeline.spec.ts`：新增用例「Vue 响应式污染的解析产物：meta 脱代理
  净化后提交」——reactive 污染 meta（含 chunkHashes），前置断言锁定污染载荷
  不可克隆（防用例漂移失效），断言进入 Worker 的 meta 与整个请求体均可
  结构化克隆。

#### 关键约束（改动时勿破坏）

- 进入 Worker（postMessage）的载荷必须为纯数据：新增任何提交入口时，来自
  响应式状态（ref / reactive）的载荷须先经 toPlainPayload 净化（解析导入
  路径已在 produceParsedItem 入口收敛）；
- 池层的 DataCloneError 自愈是纵深防御而非主路径：不得以「已有兜底」为由
  跳过源头净化（净化应发生在知道数据来源的领域层）；
- cloneStrict 模式为测试专用（模拟浏览器 postMessage 语义），生产代码不得
  依赖其行为。

#### Wave 45 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端单测 | npx vitest run | 242 passed（21 文件；新增 2 例覆盖本波次根因） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端构建 + 打包 | build_production.ps1 -SkipCore -SkipWorker | 成功：NSIS 安装包 Verthys_3.3.0_x64-setup.exe（3.57 MB） |

#### Wave 45 收尾交接清单

1. **用户实测项**：解析导入应全部成功（表现与直接导入一致）；若仍有失败，
   请提供 UI 失败明细与 `%LOCALAPPDATA%\com.verthys.app\logs\main_ui.log`。
2. **本波次改动文件**：`importPipeline.ts`、`photoWorkerPool.ts`、
   `importPipeline.spec.ts`、`photoWorkerPool.spec.ts`；未提交 git，
   与既有工作树同批待用户评审验收。
3. **遗留**：无（根因闭环 + 双道防线落地）。

### 2026-09-28 Wave 46：拾光加载进度卡移除（按用户决策：默认加载动画 + 通用错误提示即可）

用户决策：进入拾光时不需要「读取加密索引」进度卡（含进度条与「取消扫描」/
「暂停解密」按钮）——加载有默认动画（CosmicLoading）承载，失败经通用错误
提示（toast）呈现即可（该机制已存在）。

#### 变更点

1. **移除进度卡（表现层）**：`PhotoAlbum.vue` 删除 `photo-load-progress`
   悬浮卡片（QuantumProgressFlow 进度条 + 阶段取消/暂停按钮）及其全部
   展示派生：`showLoadProgress`、280ms 延迟显示窗口（`progressVisible` +
   `progressShowTimer` + watch）、`loadActionVisible` / `loadActionText`，
   以及对应 CSS（`.photo-load-progress(-card)` / `.photo-load-action` /
   `photo-progress-in` 动画）与卸载清理分支。
2. **默认加载动画承接**：`CosmicLoading`（非阻塞、自动消失）改为无条件的
   加载反馈（移除 `v-if="!progressVisible"`）。
3. **错误改走通用提示**：新增 `watch(loadError)` → `showError()`（toast），
   覆盖加载失败与降级提示；顶部状态横幅保留（承载错误文案与重试/继续
   入口，避免失败静默——仅细横幅，非弹窗）。
4. **死代码清理**：`load-progress.ts` 删除 `cancelActionLabel`（唯一消费者
   为已移除的卡片按钮），同步删除其单测用例；`PhotoAlbum.vue` 清理
   `ref` import 与相关解构项（loadStage/loadPercent/loadMessage/
   loadElapsedMs/firstFillInFlight/cancelLoad）。
5. **保留（有意）**：`usePhotoData` 的加载生命周期 API 面完整保留
   （`cancelLoad`/`resumeLoad`/`retryLoad` 与 `loadStage` 等内部状态机——
   数据层能力不随 UI 决策删除；当前 UI 不再暴露取消入口）。

#### 关键约束（改动时勿破坏）

- 加载失败不得静默：`loadError` → toast 的接线与顶部横幅重试入口是
  失败可见性的唯一通道，二者必须保持；
- `CosmicLoading` 是列表装载期间唯一的进度反馈，不得再引入居中悬浮
  进度卡（用户已明确否决该交互形态）。

#### Wave 46 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端单测 | npx vitest run | 241 passed（21 文件；删除 1 例随死代码清理） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端构建 + 打包 | build_production.ps1 -SkipCore -SkipWorker | 成功（NSIS 安装包已产出；此后构建由用户自行执行，助手不代跑构建） |

#### Wave 46 收尾交接清单

1. **用户实测项**：进入拾光不再出现「读取加密索引」弹窗与取消扫描按钮；
   列表加载以居中加载动画呈现；加载失败/降级时弹出通用错误提示且顶部
   横幅提供重试。
2. **本波次改动文件**：`PhotoAlbum.vue`、`load-progress.ts`、
   `load-progress.spec.ts`；未提交 git，与既有工作树同批待用户评审验收。
3. **遗留**：无。

### 2026-09-28 Wave 47：导出加密照片窗口全面整改（两栏工作台 + 编辑式排版）

用户决策：现有导出窗口「冗余且杂乱」——以顶级排版全面整改，合并/精简
冗余信息，原创非模板化布局；功能面保持完全等价。

#### 设计（两栏工作台 + 编辑式分组语言）

1. **结构重构：四段垂直堆叠 → 两栏工作台**
   - 左栏（弹性）：选片工具条 + 自适应网格（滚动收敛在栏内，替换原固定
     224px 定高铺开）；选中态为蓝色描边（勾标角标经用户决策移除，仅保留
     描边），原「名称 + 大小」双行噪声收敛为名称单行 + hover 浮签
     （名称 · 大小）。
   - 右栏（296px 固定栏 + 细分隔线）：格式 / 令牌 / 保存位置三组配置。
   - 底栏：单行摘要（并入原「照片数 / 格式 / 加密」三列汇总）+ 动作按钮；
     导出进度改为底栏顶缘 2px 细线（取消原独立进度条区块）。
2. **信息去重（三处合并）**：已选计数上移常驻头部（`已选 N / M`，数字
   强调）；格式说明并入分段控件下方单行提示（原 3 张 radio 卡片 + 重复
   描述）；加密方式并入底栏摘要与令牌提示行（原汇总「AES-256-GCM」与
   密钥区信息重复）。
3. **控件语言**
   - 格式：三张 radio 卡片 → 分段控件（原生 radio 承载可访问性，选中段
     为内描边提升块）；与令牌 / 保存位置行同宽同高（40px 整行）；
   - 令牌：恒 100% 的假强度条删除（零信息量装饰），信息收敛为提示行
     「256-bit · 无此令牌无法解密导出文件」；令牌文本改为单行输入框
     （超长省略，不再折行多行）并支持直接编辑自定义令牌；令牌行与
     保存位置行同宽同高（40px 整行）；导出入口前置校验令牌下限（加密
     模式下不足最小长度即 toast 提示，避免读完照片数据才在打包层失败）；
   - 令牌长度口径统一：解析导入原有「64 位 hex 写死校验」放宽为「最小
     长度 8 位、字符集不限」（底层为 PBKDF2 派生，任意字符串可用），与
     导出自定义令牌口径闭环；常量由 DEFAULT_TOKEN_LENGTH(64) 收敛为
     MIN_TOKEN_LENGTH(8)，`isValidHex` 前置校验随之移除；
   - 保存位置：只读输入框 + 独立「浏览」按钮 → 整行可点按钮（路径 +
     文件夹图标，hover 点亮；未选择时为空文本框——不显示占位文案，
     选择后按原路径文本样式呈现）；
   - 分组标题：大写小标题 → 微标签 + 渐变延伸细线（编辑式分组，替代
     模板化标题堆叠）。
4. **冗余清理**：删除 `.ed-section*` / `.ed-radio*` / `.ed-summary*` /
   `.ed-strength*` / `.ed-token-info` / `.ed-progress` / `.ed-path-*` /
   `.ed-browse-btn` / `.ed-photo-size` 等全部旧样式；选择操作「取消」
   更名「清空」（原与窗口关闭语义混淆）。
5. **尺寸**：窗口 640px → 固定尺寸 min(860px, 100vw − 48px) ×
   min(560px, 100vh − 96px)（不随内容变化；body 单行 1fr 撑满，选片网格
   填满左栏并在栏内滚动）；窄窗（≤760px）单列堆叠兜底。

#### 关键约束（改动时勿破坏）

- 功能面等价：多选 / 全选 / 清空、令牌显示 / 复制 / 重新生成 / 复制对勾态、
  三格式切换（PNG 隐藏令牌组）、保存位置选择、产出摘要、导出进度与禁用
  条件（exporting / 0 张 / 无路径）不得变更；
- 可访问性：格式选择必须保留原生 radio（label 承载），不得改为纯 div 点击；
- 「微标签 + 延伸细线」分组与底栏单行摘要为模块排版语言：同类窗口
  （如解析对话框）后续整改应复用该语言而非另造样式。

#### Wave 47 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 241 passed（21 文件；导出逻辑未改动，语义等价） |
| 前端构建 + 打包 | build_production.ps1 -SkipCore -SkipWorker | 成功（NSIS 安装包已产出；此后构建由用户自行执行，助手不代跑构建） |

#### Wave 47 收尾交接清单

1. **用户实测项**：打开导出窗口核对两栏布局、分段格式选择、整行路径选择、
   底栏摘要与进度线；确认选择 / 令牌 / 导出全流程行为与旧版一致。
2. **本波次改动文件**：`PhotoAlbum.vue`（模板 + 样式）；未提交 git。
3. **遗留**：解析对话框（parse）排版仍为旧语言，可后续按同一工作台语言
   整改（用户未提出，暂不动）；本轮已顺带调整其文案与入口——占位文案
   精简为「请选择 .venc 文件」「请输入密钥」，文字「浏览」改为打开文件
   图标钮（正方形居中，悬浮提示「打开文件」）。

### 2026-09-28 Wave 48：总修复方案落地（回灌契约 / 常量唯一化 / 完整性下沉 / 门禁机械化）

依据：《总修复方案》（审查产出的统一执行文档）。承接 Wave 38-47 的主体修复，
只收敛残余缺陷、接缝缺口与纪律破口；无数据模型变更、无数据迁移。

#### 变更点

1. **回灌契约与瘦身布局接缝闭合**：`rehydrateEntries` 的「已加载」与「具备可渲染的缩略图来源」
   绑定——瘦身布局且带缩略图引用（`isSlimPhotoMeta`）的项回到待解密态，由可视区按引用回填；
   重建器存在且内联缩略图为空时置空（不保留上一会话已释放的陈旧地址）。
2. **跨层常量唯一化**：
   - flush 服务的重试次数 / 退避 / 落盘自查超时改为消费生成常量；自查加超时包裹
     （超时按可重试失败处理，与 IO 失败的恢复动作一致）；
   - schema 新增 `write_file_chunk_bytes` / `max_export_single_bytes`；生成器发射
     TS `PHOTO_MAX_BYTES` / `MAX_EXPORT_SINGLE_BYTES` 与 Rust `PB_MAX_RECORD_NAME_BYTES` /
     `PB_WRITE_FILE_CHUNK_BYTES` / `PB_MAX_EXPORT_SINGLE_BYTES`；
   - Rust 侧移除无消费者的前端语义发射（`PB_FLUSH_*` / `PB_SESSION_*`）；
   - 调用点接线：Rust `constants.rs`（记录名 / 导出分片 / 导出上限）、前端 `crypto_const`
     再导出、单文件导出入口按预估总量前置拦截；
   - 生成器不变式 13 → 15 条（新增导出分片上限与单文件上限关系两条）。
3. **完整性校验下沉**：`decrypt_chunks` 协议新增可选 `expectedHashes` / `expectedFileHash`；
   Worker 解密前逐块校验密文哈希、解密后按序增量比对整图明文哈希，不符即确定性拒绝（不回退重算）；
   桥接层透传、主线程回退路径保持同等校验标准；查看器主线程只做块数与哈希项数判定；
   块集解析补齐哈希项数等式；导出 PNG 路径的整图哈希校验随任务下沉（主线程不再做兆字节级同步哈希）。
4. **读侧错误语义判别化**：新增 `verthysGetRecordDetailed`（判别式 + 归因分类），
   原函数保留为兼容包装；导出链路的元数据读取迁移到判别式版本。
5. **机械化门禁**：`run_ci.ps1` 新增「常量消费门」（TS/Rust 清单逐名检查生成物之外的真实消费点）
   与「导出契约门」（`verthys.def` 与 `export_baseline.txt` 集合比对）；导出基线补齐至 32 符号。
6. **部署一致性**：清理不在解析路径内的陈旧 worker 副本；声明改为按解析路径枚举校验
   （构建脚本对打包源与 Tauri target 副本逐一哈希比对）。
7. **文档同步**：加载方案文档加「状态说明」并按现行实现修订（部署口径、导出契约、进度展示、
   S2 适用范围、常量表、不变式条数）；需求与架构决策文档的导出符号计数更新为 32。

#### Wave 48 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 常量生成器 | node constants/generate.mjs --check | 一致（15 条不变式） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 250 passed（23 文件；新增 10 例：回灌契约 2、flush 行为 2、判别式 3、Worker 校验 2、桥回退校验 1） |
| 宿主单测 | cargo test --lib（src-tauri） | 372 passed / 0 failed |
| CI 新门禁 | run_ci.ps1（常量消费门 / 导出契约门） | 本地预演通过（消费清单全命中；32 符号一致） |
| C 全量套件 | — | 本轮未改 C，沿用上一阶段 308/0 |

#### Wave 48 收尾交接清单

1. **用户实测项（开发模式）**：布局切为瘦身后导入 → 进入拾光 → 切走 → 切回，缩略图自动补齐；
   大图（10 MB / 100 MB）点击查看无秒级无响应；落盘失败注入后重试与自查超时符合权威值。
2. **构建与部署**：无 Rust 侧协议改动（解密校验扩展在前端 Worker）；常量接线涉及 Rust 源码
   （`constants.rs` 与生成物 `photo_budget.rs`），生产打包需重建宿主与 worker，由项目方
   执行构建脚本（含哈希校验）；`run_ci.ps1` 全流程由项目方执行。
3. **本波次改动文件**：`photo-album/utils.ts`（+其 spec）/ `cache/domain/verthys-flush-service.ts`
   （+新增 spec）/ `constants/photo_budget.schema.json` + `constants/generate.mjs` + 两侧生成物 /
   `constants/crypto_const.ts` / `src-tauri/src/constants.rs` / `usePhotoExport.ts`（+其 spec）/
   `usePhotoViewer.ts` / `chunk-refs.ts` / `photo-crypto-protocol.ts` / `photo-crypto.worker.ts`
   （+其 spec）/ `photo-decrypt-bridge.ts`（+其 spec）/ `lib/verthys.ts`（+新增 spec）/
   `ci/run_ci.ps1` / `ci/export_baseline.txt` / `build_production.ps1`（未改动，核对确认不刷新陈旧副本）；
   `docs/REQUIREMENTS.md` / `docs/ARCHITECTURE_DECISIONS.md` / 加载方案文档（状态说明与漂移修订）。
4. **遗留**：无未闭环项；真机验收项由用户执行。

### 2026-09-28 Wave 49：防截屏隐私保护总修复（上传方案评审校正 + 全链路重写）

依据：用户上传的《拾光·防截屏生产方案》。逐条评审后产出唯一执行文档
[防截屏隐私保护总修复方案.md](./防截屏隐私保护总修复方案.md)（含逐条裁定与
校正理由），并按其完成施工。核心校正：对账一律全窗口重扫（上传方案按卡死清单
对账会漏掉「还原成功但从未被保护」的窗口）；过渡被取代时必须释放未决租约
（上传方案未覆盖）；不做统一窗口工厂（本项目唯一主窗口，配置 `visible:false` +
启动序列即可，工厂为无消费者的过度设计）；审计改可选扩展块而非格式号迁移
（保持历史条目序列化字节不变、HMAC 链逐字节兼容）；剪贴板监听剥离回安全档位
（与捕获排除解耦，故障互不误报）；隐私模式默认开启（上传方案未涉及）。

#### 变更点

1. **底层原语**：新增 `security/window_affinity.rs`——WDA 三常量
   （NONE/MONITOR/EXCLUDEFROMCAPTURE）、`RtlGetVersion` 版本检测
   （Win10 19041+ 用排除捕获、旧系统降级监视器亲和性）、原始读
   （`get_raw_affinity` 回读校验）/写 `set_raw_affinity`、4 单测。
2. **协调器重写**（`controller/privacy_controller.rs`，约 2390 行含测试）：
   - 令牌槽位三态（Empty / PendingAdoption / Active）：只存 SHA-256 摘要；
     校验占位为租约（可重试、世代单调、单租约），提交即消费，释放可重试；
     采纳即轮换；跨世代校验拒绝陈旧租约；
   - 状态机单飞：`Transitioning` 变体自带身份号，过渡身份校验兜底——
     被新变更取代的过渡不得覆盖状态且必须释放未决租约；
   - 卡死看门狗（30s 阈值）：内联收尸转隔离，不轮询、不阻塞执行器；
   - 应用原子性：逐窗施加 + 回读校验，任一失败逆序回滚至快照；
     回滚失败窗口整体隔离（无「部分保护」假象，失败错误码明确）；
   - 隔离与对账：隔离为纯运行时状态（不持久化）；对账一律全窗口重扫，
     收敛到目标态后按需轮换令牌；
   - 意图持久化：`PersistedIntent{schema,enabled,written_at}`，DPAPI 加密 +
     临时文件原子替换，旧格式一次性重写；解析为纯函数便于单测；
   - 启动序列：`visible:false` 窗口在保护就绪+回读成功后才显示；还原失败弹
     原生 `MessageBoxW`（MB_RETRYCANCEL）驱动对账，拒绝则退出不留无界面进程；
     还原目标缺失（窗口不存在）时如实 log + `exit(0)`；
   - 四命令：`set_privacy_mode`（开启默认无凭证；关闭/再开启需租约）/
     `get_privacy_status` / `adopt_privacy_session` / `reconcile_privacy`；
   - 29 单测（FakeOps / Fake Gate / RecordingSink；覆盖取代路径、看门狗、
     全窗口重扫断言、意图兼容、回滚失败隔离）。
3. **限流组件**（`util/rate_limiter.rs`）：`SlidingWindowLimiter::new` 为
   `const fn`（支持 static 初始化）；拒绝不占额度；按用途分离实例——
   开启 10/分、关闭 60/分、采纳 10/分、对账 5/分、状态查询不限；4 单测。
4. **审计扩展块**（`util/audit_log.rs`）：新增 `PrivacyModeChange` /
   `PrivacyQuarantine` / `PrivacyReconcile` 事件类型（`ClipboardModeChange`
   标注为历史事件不再产生）；`AuditExtensions`（`is_empty` + 链式 builder）
   挂为 `AuditEvent.extensions: Option<...>` 且 `skip_serializing_if`——
   历史条目序列化字节不变、HMAC 链验证逐字节兼容；扩展块篡改检测单测。
   `security_commands/audit.rs` 提供 `write_audit_with_extensions`（空块不写）。
5. **剪贴板剥离**：`clipboard_controller.rs` 仅保留 `clear_clipboard`
   （静态限流 10/分）；外部写入即清空随安全档位启停
   （`SecurityState::set_clipboard_guard`，启停失败不回滚会话高安全并返回
   `CLIPBOARD_MONITOR_FAILED`），与防截屏完全解耦。
6. **启动装配**（`lib.rs`）：setup 最先装配协调器（`app.manage(Arc)`）并执行
   `startup_engage`；主窗口缺失时 log + `exit(0)`；删除 panic 清零器注册
   （槽位只存摘要，无敏感驻留可清零）；`tauri.conf.json` 主窗口
   `"visible": false`。
7. **前端**：新增 `session/privacy-session.ts` 应用级模块单例（状态 ref /
   令牌 / 两个单飞 Promise；失败不伪造为关闭）；`PhotoAlbum.vue` 按钮
   （禁用态 `cursor-not-allowed` + 悬浮提示）、恢复对话框（CosmicOverlay，
   「稍后处理 / 立即修复」）、错误码→界面映射、`MainView.vue` 最早挂载点
   采纳；`lib/verthys.ts` 增三命令、删 `restorePrivacyMode`；新增
   `privacy-session.spec.ts` 7 例（连击单飞、并发采纳、不重复签发、凭证丢失
   不发 IPC、关闭回传凭证、对账后再采纳）。
8. **清理**：删除 `security::WindowPrivacyGuard` / `set_window_privacy` /
   panic 清零器 / `usePhotoPrivacy.ts` / `restore_privacy_mode` 命令与前端
   包装 / 陈旧注释；AST 基线删除已消除的豁免行。
9. **文档同步**：`docs/REQUIREMENTS.md` FR-12 按现行实现重写（默认开启、
   全或无语义、命令集、剪贴板解耦）。

#### Wave 49 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 常量生成器 | node verthys-tauri/constants/generate.mjs --check | 一致 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 257 passed（24 文件；新增 7 例 privacy-session） |
| 宿主单测 | cargo test --lib（src-tauri） | 405 passed / 0 failed（基线 372，+33） |
| Worker 单测 | cargo test（worker） | 33 passed / 0 failed |
| CI 全量 | run_ci.ps1 -SkipBuild | 全通过（AST 第二级 0 错误 0 警告） |

#### Wave 49 收尾交接清单

1. **用户实测项（真机验收，开发模式）**：
   - 首次启动：主窗口出现即受保护——系统截图 / 录屏（Win10 19041+）
     中窗口区域被排除；旧系统为空白矩形；
   - 应用内关闭防截屏 → 重启应用 → 不再自动开启（意图持久化）；
   - 关闭后凭证丢失（重启后直接尝试关闭）→ 界面提示需先修复，不发 IPC；
   - 关闭失败注入（他人抢改亲和性）→ 按钮可立即重试（租约可重试不消费）；
   - 还原失败注入 → 启动时出现原生对话框（重试 / 取消），取消则进程退出
     不显示窗口；重试成功后窗口才显示；
   - 隔离注入 → 界面出现恢复对话框，「立即修复」触发对账并收敛；
   - 连击开关十次 → 仅一次 IPC（单飞），计数与状态最终一致。
2. **构建与部署**：Rust 侧有改动（新模块与命令契约），生产打包需重建宿主；
   构建脚本与 git 提交由项目方执行（`run_ci.ps1` 全流程亦由项目方复跑），
   后端已本地预演全绿。
3. **本波次改动文件**：Rust——`src-tauri/src/security/window_affinity.rs`（新）/
   `controller/privacy_controller.rs`（新）/ `controller/clipboard_controller.rs`
   （重写）/ `controller/types.rs` / `util/rate_limiter.rs`（新）/
   `util/audit_log.rs` / `security/mod.rs` / `security_commands/audit.rs` /
   `security_commands/state.rs` / `security_commands/commands/session.rs` /
   `middleware/panic_hook.rs` / `lib.rs` / `tauri.conf.json` / `util/mod.rs` /
   `controller/mod.rs` / `ci/ast_baseline.txt`；前端——`session/privacy-session.ts`
   （+ 其 spec）/ `lib/verthys.ts` / `types/verthys.ts` / `bindings/*`（再生成）/
   `components/modules/PhotoAlbum.vue` / `components/MainView.vue` /
   `composables/photo-album/usePhotoViewer.ts`（注释）/ 删除 `usePhotoPrivacy.ts`；
   文档——`docs/RemediationPlan/防截屏隐私保护总修复方案.md`（新）/
   `docs/REQUIREMENTS.md`。
4. **遗留**：无未闭环项；上传方案中的「统一窗口工厂」经核实为过度设计不予采纳
   （本项目配置声明唯一主窗口），若后续引入多窗口需重评启动序列的窗口枚举。

#### Wave 49 增补：全链路复核（核验轮）

在 Wave 49 落地后再次逐链路复核（Rust 启动序列/命令注册、协调器状态机与并发、
安全原语、审计与剪贴板、前端会话层与集成、契约与 bindings、清理残留、门禁），
逐行核对实现；复核发现的缺陷与裁决如下：

| 发现 | 性质 | 裁定 |
|---|---|---|
| 前端会话层 IPC 异常外泄：`ipc()` 对 invoke 失败抛异常，而 privacy-session 三个入口未防护——切换/对账路径异常会外泄为 unhandled rejection（按钮无反馈、界面无提示） | 真实缺陷 | **已修复**：会话层新增"不抛异常"契约（`runGuarded` 把 IPC 异常转为 `PRIVACY_IPC_FAILED` 失败结果）；界面层补该错误码的提示映射；新增 2 例（切换异常后单飞可重试、对账异常不外泄） |
| `adopt()` 未显式拒绝过渡态与隔离态：当前所有可达路径下"隔离+待采纳"组合不可达（隐含兜底成立），但契约声明"隔离态仅对账可达"未在状态层显式化 | 防御缺口 | **已加固**：稳定态显式校验（过渡→Busy、隔离→Quarantined），任何状态下不签发无主凭证；新增 1 例 |
| `rate_limiter::max_calls()` 无生产消费者（仅测试引用） | 死 API | **已删除**（测试断言改为行为断言） |
| 状态机锁内写审计（append_audit 读文件尾 + HMAC + 追加） | 设计偏差（低风险） | **记录不改**：审计写为操作级低频（模式变更/隔离/对账），并发调用方仅有单飞下的状态查询；锁持有窗口毫秒级，无卡顿实测面。改动面大（十余处尾段）收益低，维持现状 |

其余复核项全部确认无缺陷：取代路径释放未决租约、看门狗收尸转隔离、对账全窗口
重扫、原子应用逆序回滚、意图 DPAPI 原子替换与旧格式迁移、审计扩展块字节级兼容
（混合链验签单测）、剪贴板剥离与安全档位启停、命令注册与前端调用一一对应、
bindings 与 Rust 结构一致、`visible:false` 启动序列与窗口缺失退出分支、
清理无残留（全仓 grep 陈旧符号零命中）。

##### 复核轮验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端单测 | npx vitest run | 259 passed（24 文件；+2 异常防护用例） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 宿主单测 | cargo test --lib（src-tauri） | 406 passed / 0 failed（+1 采纳拒绝用例） |
| CI 全量 | run_ci.ps1 -SkipBuild | 全通过（第二级 0 错误 0 警告；基线豁免 37 条不变，新增代码零违规） |

### 2026-09-28 Wave 50：拾光交互整改与防截屏操作延迟根治（用户决策驱动）

用户两项决策：① 系统化移除拾光加载提示栏（含"模块密钥已失效"提示与栏内其它提示），
必要提示改走通用 toast；② 防截屏按钮点击延迟高、高亮圆点效果低级——需即时响应、
图标随状态变化。根因诊断与整改如下。

#### 变更点

1. **加载提示栏系统化移除**（表现层）：
   - 删除拾光顶部加载状态横幅（聚合"密钥失效 / 扫描失败 / 解密暂停 / 解密失败计数"
     四类文案与"重试 / 继续解密"动作）及其全部展示派生（`bannerText` /
     `bannerAction` / `bannerActionText`）与解构项（`decryptPaused` /
     `retryLoad` / `resumeLoad`）；
   - "模块密钥不可用"不再产生任何用户提示（进入拾光本应经安全管理验证），
     保留 console 告警便于排查；`loadError` → toast 既有接线保留；
   - 解密失败计数首次非零 → toast 一次性告知（`0 → >0` 边沿触发，
     重试清零后可再次提示）；
   - 重打包进度横幅保留（后台任务进度 + 取消入口，非提示条）；
   - 数据层能力（`retryLoad` / `resumeLoad` / `cancelLoad` / `decryptPaused`）
     保留不删：UI 决策不删数据层能力（延续既有约束）。
2. **防截屏按钮重构（即时响应 + 状态图标）**：
   - 会话层新增乐观显示态（点击同帧切换图标）与在途标志；成功后按后端契约
     本地收敛（启用=槽位生效 / 关闭=槽位清空），**移除串行的状态查询 IPC**
     （原路径固定 3 次 IPC 往返 + 采纳路径 5 次，现为 1 次命令 IPC）；
   - 新增状态写序号（`statusEpoch`）：在途旧查询结果按序号丢弃，防止
     "旧查询晚到覆盖新状态"的竞态；失败/异常回退真实态并经错误码映射提示；
   - 图标随状态切换：开启=捕获被阻止（划斜线的眼），关闭=画面可被捕获（睁眼）；
     双图标绝对定位交叉淡入（无布局抖动）；**移除高亮圆点与 blink 动画**；
   - 在途窗口极短，禁用态不做视觉降级（仅 not-allowed 光标 + 悬浮提示），
     避免快速开关时按钮闪烁；凭证丢失/非桌面端仍用完整降级样式。
3. **操作延迟根治（后端审计路径，全项目受益）**：
   - **审计 HMAC 密钥进程级缓存**（`OnceLock`，仅缓存成功）：密钥派生为
     设备指纹采集 + PBKDF2 十万次迭代，此前**每次审计写入都重新派生**
     （调试构建单次数百毫秒），是防截屏开关可感延迟的主因；密钥材料
     （设备指纹 + 固定盐）进程内不变，缓存不改变任何审计字节序；
   - **剪贴板控制器审计委托共享写入器**：删除第二套派生/落盘逻辑
     （复用安全命令层 `write_audit_with_extensions`，分层约束用全限定路径），
     剪贴板清空同样受益于密钥缓存；
   - **audit.log 尾窗口读取**（64KB 窗口 + 无法解析时全量回退）：审计日志
     只追加不清空，全量读取让每次追加成本随日志大小恶化（当前已 3MB 且
     持续增长）；尾窗口只可能截断首行，末行终点即文件末尾天然完整。

#### Wave 50 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端单测 | npx vitest run | 261 passed（24 文件；+2：点击即刻反馈、失败回退真实态） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 宿主单测 | cargo test --lib（src-tauri） | 407 passed / 0 failed（+1 尾窗口边界用例） |
| 编译警告 | cargo check --lib | 0 警告 |
| CI 全量 | run_ci.ps1 -SkipBuild | 全通过（第二级 0 错误 0 警告） |

#### Wave 50 收尾交接清单

1. **用户实测项（开发模式）**：拾光顶部无加载提示栏（密钥失效/解密暂停/失败计数
   不再常驻）；解密失败时一次性 toast；防截屏按钮点击后图标同帧切换（无迟滞感），
   开启=划斜线眼、关闭=睁眼，无圆点闪烁；连点行为由单飞兜底。
2. **性能说明**：审计密钥首次派生仍发生在进程内首次审计写入（一次性成本，
   由既有阻塞路径承担）；后续全部审计写入走缓存密钥 + 尾窗口读取。
3. **本波次改动文件**：`verthys-tauri/src/components/modules/PhotoAlbum.vue` /
   `src/session/privacy-session.ts`（+ 其 spec）/ `src-tauri/src/security_commands/audit.rs` /
   `src-tauri/src/controller/clipboard_controller.rs` / `src-tauri/src/util/audit_log.rs`。
4. **遗留**：无未闭环项；构建与 git 提交由项目方执行。

### 2026-09-28 Wave 51：拾光卡片悬浮文字模糊根治（文字层与图像层解耦）

用户报告：拾光照片卡悬浮时，浮出的文字突然变模糊，要求系统化/工程化定位根因。

#### 根因（渲染管线路径切换，四条件叠加）

1. **文字被画进滤镜表面**：`.photo-overlay`（11px/9px 小字）原为 `.photo-thumb`
   子元素，而 `.photo-thumb` 带 `filter: saturate() brightness()`——filter 为强制
   分组属性，子树须先画进离屏表面再整体过滤：表面内亚像素抗锯齿（ClearType）
   被禁用，文字回退灰度抗锯齿；hover 时 filter 值还在 0.4s 过渡，该表面逐帧重绘。
2. **文字被拉进 3D 渲染上下文 + 常驻合成层**：`.photo-card` 常驻
   `will-change: transform` + `transform-style: preserve-3d`——常驻合成令合成器
   优先复用既有纹理、不按新比例重新栅格化；preserve-3d 让文字参与 3D 投影，
   不再是独立清晰层。违反项目在 `App.vue` 已确立的「文字不进 3D 渲染上下文，
   ClearType 渲染路径恒定」规范。
3. **核心根因（栅格锁定 + 非整数放大）**：悬浮 transform 为
   `perspective(800px) + rotateY/rotateX + translateY(-6px) + scale(1.03)`，
   由 `usePhotoInteraction` 每帧直写，同时 `.photo-card` 又保留
   `transition: transform 0.3s`——双写下变换目标每帧变化，浏览器视为持续动画，
   栅格比例被锁在 1×，交互期间不按 1.03 重新栅格化：合成器只能把 1× 纹理做
   非整数放大 + 透视重采样，字形全程模糊。
4. **「突然」的时序**：hover 是「文字 opacity 0→1 出现 + transform 激活 +
   filter 值过渡」三者同帧发生的唯一时刻。

排除项（已逐一核验）：祖先链（main-view / workspace / module-switch / stage）
无常驻 filter/opacity/transform；`.glass { transition: all }` 与 `.glass:hover`
box-shadow 被 scoped `.photo-card[data-v]` 覆盖；无 `blur` / `backdrop-filter`
作用于卡片；`.viewer.blurred` 与入场动画无关；`.masonry-item` 虚滚动定位的
分数像素 `translate3d` 由合成器整数设备像素吸附（列为同类隐患，见遗留）。

#### 变更点（文字清晰度铁律落地）

1. **结构解耦**（`PhotoAlbum.vue` 模板）：`.photo-overlay` 与 `.enc-mark` 移出
   `.photo-thumb`，与图像层平级成为 `.photo-card` 直接子元素——文字不再进入
   filter 子树，缩略图滤镜只包裹图片；overlay 与锁标相对卡片几何位置不变。
2. **样式**（同文件）：
   - 删除 `.photo-card` 的 `will-change: transform` 与
     `transform-style: preserve-3d`（禁令以注释固化在样式位）；
   - 卡片悬浮抬升改为 CSS `:hover { transform: translateY(-6px) }`——纯整数
     平移，合成器整数设备像素吸附，字形不重采样；
   - 图像层 `.photo-card:hover .photo-thumb` 增 `will-change: transform`：
     仅悬浮期按需提升合成层（逐帧 transform 走合成器变换，避免逐帧重绘），
     离悬浮即撤销——常驻合成会锁定栅格比例并占用每卡显存。
3. **交互层**（`usePhotoInteraction.ts`）：3D 倾斜
   （`perspective(800px)` + 8° rotate + scale）改为只写 `.photo-thumb`，
   平移量从 JS 变换中移除（与 CSS 抬升单写不冲突）；1.06 过扫保证倾斜/透视
   收缩时画面始终覆盖卡片圆角框不露底；文件头补齐铁律与「逐帧直写不得叠加
   CSS transform 过渡」约束。
4. **视觉等价**：抬升量、阴影、光晕跟随、滤镜提亮、选中红环、入场动画行为不变；
   倾斜由「整卡倾斜」变为「框内照片倾斜」（滤镜/缩放只作用于位图，观感一致）。

#### 关键约束（改动时勿破坏）

- 文字层（`.photo-overlay` / `.enc-mark`）祖先链禁止出现 filter / 3D 变换 /
  非整数缩放；3D 倾斜与非整数缩放只能作用于 `.photo-thumb`；
- 禁止恢复 `.photo-card` 的常驻 `will-change: transform` 与
  `transform-style: preserve-3d`；
- `.photo-thumb` 的 transform 由 JS 逐帧直写，不得声明 transform 过渡
  （双写会锁死栅格比例）；卡片抬升只能经 CSS 整数平移（`translateY(-6px)`）；
- 缩略图滤镜（`.photo-thumb` filter）不得重新包裹文字节点。

#### Wave 51 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 261 passed（24 文件；本次为表现层改动，语义等价） |
| 前端构建 + 打包 | — | 由项目方执行（延续 Wave 46 起惯例，助手不代跑构建） |

#### Wave 51 收尾交接清单

1. **用户实测项（开发模式）**：悬停照片卡，浮出的文件名/大小文字应与界面其余
   文字同等锐利（不再突然发虚）；快速移动指针时倾斜跟随流畅，指针静止后文字
   依旧清晰；卡片抬升、阴影、光晕、加密锁标、图片提亮观感与旧版一致。
   DevTools 核验口径：Rendering → Paint flashing / Layers——悬停时文字层不得被
   缩放或重新栅格化，文字祖先链无 filter / 3D transform。
2. **本波次改动文件**：`verthys-tauri/src/components/modules/PhotoAlbum.vue`
   （模板 + 样式）、`verthys-tauri/src/composables/photo-album/usePhotoInteraction.ts`；
   未提交 git，与既有工作树同批待用户评审验收。
3. **遗留**：`.masonry-item` 虚滚动定位的分数像素 `translate3d` 为同类隐患
   （合成器整数吸附已缓解，非本次症状来源）；若后续实测出现列表文字发虚，
   按同一铁律对定位坐标做整数量化。

### 2026-09-28 Wave 52：拾光死样式清零 + 照片倾斜移除 + 入场动画遮蔽缺陷修复

用户决策：① 清理验证轮发现的全部死样式；② 照片 3D 倾斜功能整体移除；
③ 修复此前验证发现的「入场动画前向填充压住卡片悬浮抬升」缺陷。

#### 变更点

1. **死样式清零**（`PhotoAlbum.vue` scoped 样式，共 10 条无消费者规则）：
   - `.empty` / `.empty-icon` / `.empty-text` / `.empty-hint`（空态已由 `CosmicEmpty`
     组件承载）；
   - `.plus`（旧「+ 导入照片」文案节点已不存在）；
   - `.import-progress` / `.progress-bar` / `.progress-fill` / `.progress-text`
     （导入进度已由 `ImportProgressOverlay` 组件承载）；
   - `.viewer-hint`（查看器提示行已移除，仅保留 `.viewer-status`）。
   复扫口径：样式块类选择器 × 模板/脚本引用比对 → 清零（仅余 Vue `<transition>`
   运行时类名 `privacy-ico-*` / `toast-*`，非死代码）。
2. **照片 3D 倾斜整体移除**：
   - `usePhotoInteraction.ts` 删除 `.photo-thumb` 逐帧 3D 写入
     （`perspective(800px)` + ±8° rotate + 1.06 过扫缩放）；该 composable 现只承载
     光晕跟随（职责注释同步收敛；恢复倾斜的约束写入文件头：3D/非整数缩放只能作用
     于图像层、不得与 CSS 过渡或逐帧写入双写）；
   - `.photo-card:hover .photo-thumb` 移除 `will-change: transform`（图像层不再做
     任何 transform，仅保留滤镜提亮）；卡片层注释收敛为三条：卡片只做整数像素平移、
     图像层无 transform、禁令（不得恢复 will-change / preserve-3d；不得把文字浮层
     移回 filter 子树）。
   - **保留效果（未受影响）**：光晕跟随、卡片抬升 + 阴影、文字浮层淡入、图片滤镜
     提亮、加密锁标、选中红环、入场动画。
3. **入场动画遮蔽缺陷修复**（验证轮发现的真实缺陷）：
   `photo-reveal` 填充模式 `both` → `backwards`。CSS 级联中动画声明优先级高于
   普通/内联声明，前向填充会在动画结束后继续以终态 `transform` 覆盖卡片悬浮抬升，
   表现为「进入拾光后一段时间内（首批 `no-anim` 生效前）悬停无抬升」。终态关键帧
   与基础样式一致，改后视觉零变化，入场结束后立即释放 hover 变换；注释固化
   「不得改回 both/forwards」。

#### 关键约束（改动时勿破坏）

- 卡片悬浮位移只能经 CSS 整数平移（`translateY(-6px)`）；图像层不得声明 transform；
- 文字/浮层节点不得移回 `.photo-thumb`（filter 子树禁用亚像素抗锯齿并逐帧重绘）；
- `.photo-card` 禁止恢复常驻 `will-change: transform` / `transform-style: preserve-3d`；
- `photo-reveal` 填充模式必须为 `backwards`（前向填充会压住 hover 变换）。

#### Wave 52 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 261 passed（24 文件） |
| 死样式复扫 | 样式块类名 × 模板/脚本引用比对 | 0 条（仅余 Vue transition 运行时类名） |
| 前端构建 + 打包 | — | 由项目方执行（延续 Wave 46 起惯例，助手不代跑构建） |

#### Wave 52 收尾交接清单

1. **用户实测项（开发模式）**：悬停照片卡不再倾斜/缩放，仅剩抬升 + 阴影 + 光晕跟随 +
   图片提亮 + 文字浮层；进入拾光后立刻悬停即应有抬升（1.5s 遮蔽窗口消失）。
2. **同类倾斜实现（本次未动，待决策是否一并移除）**：`FileVerthys.vue` 内联卡片视差
   （6° + `translateY(-3px)`）、`CertManager.vue` / `AccountVerthys.vue` 经共享
   `useCardTilt`（6° + `translateY(-3px)`）——若同样要求移除，须按同一铁律批量治理。
3. **本波次改动文件**：`verthys-tauri/src/components/modules/PhotoAlbum.vue`、
   `verthys-tauri/src/composables/photo-album/usePhotoInteraction.ts`；
   未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 53：同类卡片倾斜批量移除（存签/枢钥/钥域）+ 共享光泽追踪收敛

用户决策：承接 Wave 52 遗留，按同一口径移除其余三处卡片 3D 视差倾斜——
`FileVerthys.vue`（存签，内联实现）与 `CertManager.vue`（枢钥）/
`AccountVerthys.vue`（钥域）（经共享 `useCardTilt`）。

#### 根因补充（这三处倾斜实际从未渲染）

三个模块的卡片均带入场动画 `card-in`（`animation: ... both` + `--i` 交错延迟）。
CSS 级联中动画声明优先级高于普通/内联声明 → 前向填充**永久**以动画终态
（`transform: translateY(0)`）覆盖 JS 逐帧写入的倾斜与 -3px 抬升。即这三处
倾斜/抬升从未真正生效（与 Wave 51 拾光卡片属同一缺陷类；拾光因 1.5s 后
`no-anim` 摘除动画而部分可见，这三处无摘除机制，恒被覆盖）。

#### 变更点

1. **共享 composable 收敛**：新增 `composables/useCardShine.ts`（仅光泽追踪：
   删除 transform/抬升写入，保留主循环排帧节流与 currentTarget 同步捕获的关键
   修复）；删除 `useCardTilt.ts`；`CertManager.vue` / `AccountVerthys.vue`
   的 import、调用点、文件头注释与段注释同步更名。
2. **FileVerthys.vue**：内联倾斜移除（保留本地光晕跟随，强度口径不变）；
   `.acct-card` 删除 `transform-style: preserve-3d` 与失效的 transform 过渡，
   入场动画填充模式 `both` → `backwards`（禁令写入注释）。
3. **`styles/verthys-common.css`（共享卡片皮肤）**：`.verthys-card` 同口径清理
   （去 `preserve-3d`、transform 过渡；填充模式 `both` → `backwards`），
   消除「前向填充静默压住未来 hover transform」的陷阱。
4. **FileVerthys 死样式清零**（同 Wave 52 口径，5 条无消费者规则）：
   `.plus` / `.empty` / `.empty-icon` / `.empty-text` / `.empty-hint`
   （空态已由 `CosmicEmpty` 组件承载）。
5. **视觉效果**：三处倾斜/抬升本就未渲染，移除后无可见变化；光晕跟随、阴影、
   彩条、入场动画、卡片其余交互全部保留。全仓已无卡片倾斜实现
   （`useCardTilt` / `perspective(800px)` 零命中）。

#### 关键约束（改动时勿破坏）

- 卡片悬浮效果仅阴影 + 光泽追踪；如需恢复倾斜，必须同时满足：入场动画不得前向
  填充 transform、3D/非整数缩放不得作用于文字层、不得与 CSS 过渡或逐帧写入双写；
- `.verthys-card` / `.acct-card` 入场动画填充模式必须为 `backwards`；
- 新增卡片的指针光泽追踪统一复用 `composables/useCardShine.ts`。

#### Wave 53 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 261 passed（24 文件） |
| 残留检索 | src 内 `useCardTilt` / `perspective(800px)` | 0 命中 |
| 死样式扫描 | FileVerthys / CertManager / AccountVerthys 类名 × 引用比对 | FileVerthys 5 条已清；AccountVerthys 0；CertManager `expiry-*` 系模板字面量动态类（`expiry-${status}`），非死样式 |
| 前端构建 + 打包 | — | 由项目方执行（延续 Wave 46 起惯例，助手不代跑构建） |

#### Wave 53 收尾交接清单

1. **用户实测项（开发模式）**：存签 / 枢钥 / 钥域卡片悬停不再有倾斜（此前亦不可见），
   光晕、阴影、彩条、入场动画与旧版一致；拾光不受影响。
2. **遗留**：FileVerthys 本地光晕实现（强度 0.1）与 `useCardShine`（0.18）口径不一，
   待产品确认强度后合并为单一实现；`verthys-common.css` 未做全量死样式扫描
   （跨文件动态类名易误报），如需清扫另开批次。
3. **本波次改动文件**：`composables/useCardShine.ts`（新）、`composables/useCardTilt.ts`
   （删）、`components/modules/FileVerthys.vue`、`CertManager.vue`、
   `AccountVerthys.vue`、`styles/verthys-common.css`；未提交 git，
   与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 54：卡片指针光晕强度统一 + 实现收口（单令牌 / 单 composable / 单渐变定义）

用户决策：统一四处光晕强度并收口实现（此前为三套 rgba 字面量 0.1 / 0.12 / 0.18、
两种范围 50% / 60%、四种写法）。

#### 变更点

1. **强度单源（设计令牌）**：`styles/tokens.css` 新增 `--shine-alpha: 0.14` /
   `--shine-reach: 60%`（色相沿用 `--accent-rgb`）。三套字面量与两种范围收敛为
   单一取值，后续调整只改令牌一处。取值说明：0.14 为中位折衷——卡片表面
   （screen 混合）由此前 0.18 略降、拾光照片面（常规混合）由此前 0.12 略升，
   四处观感趋同。
2. **实现单源（一个 composable）**：`useCardShine` 不再组建渐变字符串、不再查询
   光晕节点——只把指针位置写成卡片元素上的 `--shine-x` / `--shine-y`
   （自定义属性继承到光晕层），并新增 `cancel()`（卸载时丢弃未触发的排帧写入）。
   拾光 `usePhotoInteraction`（光晕专用件）与存签内联实现全部删除；四个模块
   （存签 / 枢钥 / 钥域 / 拾光）共用同一 composable。
3. **渲染单源（一处渐变定义）**：渐变由 CSS 渲染——共享 `verthys-common.css`
   的 `.card-shine` 与拾光 `.photo-shine` 统一为
   `radial-gradient(circle at var(--shine-x, 50%) var(--shine-y, 50%),
   rgba(var(--accent-rgb), var(--shine-alpha)), transparent var(--shine-reach))`；
   存签删除与共享定义重复的 scoped `.card-shine` 几何声明（仅保留其悬浮显隐规则）。
4. **表面差异（有意保留）**：卡片表面保持 `mix-blend-mode: screen` + `z-index: 1`
   （光晕与玻璃底/彩条融合），拾光照片面为常规混合（不把屏幕混合叠加在照片与
   文字上）——几何与混合模式属表面属性；强度、色相、范围已统一。
5. 顺带：光晕在「悬浮但未移动指针」时也有默认居中光斑（渐变由 CSS 常驻定义），
   此前该场景无光晕（JS 未写入即无背景）。

#### 关键约束（改动时勿破坏）

- 光晕强度只能改 `tokens.css` 的 `--shine-alpha` / `--shine-reach`；
  禁止在各模块重新硬编码 rgba 字面量或第二份渐变定义；
- 指针光晕统一入口为 `composables/useCardShine.ts`（存签/枢钥/钥域/拾光），
  禁止再复制内联实现；新模块接入 = 卡片上挂 `.card-shine` 层 +
  `@mousemove/@mouseleave` 绑定；
- 该 composable 只写 `--shine-*` 变量（不写 background），渲染口径归 CSS。

#### Wave 54 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 261 passed（24 文件） |
| 字面量残留 | src 内 `usePhotoInteraction` / `shine.style.background` / 光晕 rgba 字面量检索 | 0 命中（仅剩无关的悬浮阴影 rgba 与 SVG stroke） |
| 死样式扫描 | 四模块类名 × 引用比对 | FileVerthys 0 / AccountVerthys 0；CertManager `expiry-*`、PhotoAlbum `card-shine` 均为动态类/注释文本（非死样式） |
| 前端构建 + 打包 | — | 由项目方执行（延续 Wave 46 起惯例，助手不代跑构建） |

#### Wave 54 收尾交接清单

1. **用户实测项（开发模式）**：存签 / 枢钥 / 钥域 / 拾光四处卡片光晕强度应一致
   （此前 0.1 / 0.12 / 0.18 差异消失）；指针移动时光斑跟随；如需更强/更弱，
   只调 `tokens.css` 的 `--shine-alpha` 一处即全站生效。
2. **本波次改动文件**：`styles/tokens.css`、`styles/verthys-common.css`、
   `composables/useCardShine.ts`、`composables/photo-album/usePhotoInteraction.ts`
   （删）、`components/modules/PhotoAlbum.vue`、`FileVerthys.vue`；
   `CertManager.vue` / `AccountVerthys.vue` 无需改动（自动继承新口径）；
   未提交 git，与既有工作树同批待用户评审验收。

### Wave 0（2026-09-28）：清藏导入链路预研与基线实测

#### 产出

1. **BLAKE3 哈希吞吐实测（决定实现后端）**
   - 纯 JS 实现（`@noble/hashes`，照片链路现用）：512MiB 实测 **28~29 MB/s**（1GiB ≈ 36s），
     主线程不可接受，移入 Worker 也降低不了总耗时；
   - `hash-wasm`（WASM，项目既有依赖）：流式 **512 MB/s**、逐块 4MiB **489 MB/s**（每块约 8ms）；
   - 两者摘要逐字节一致（同一输入 hex 完全相同），可互换。
   - 裁定：清藏批量哈希改用 hash-wasm 流式实例；零新增依赖，无需 Worker。
2. **内容寻址去重生效范围（实测 + 分层结论）**
   - 实跑：`build/core/tests/Release/verthys_tests.exe v3ext_dedup` → `[OK] v3ext_dedup_no_rewrite`；
   - 结论：去重键是写入 extent 的字节。无密码分支写明文 → 跨文件同内容块共享 extent；
     有密码分支每块唯一随机盐/IV → 密文互异 → 去重不生效。
3. **IPC 次数基线（按跨层常量推导）**
   - 现路径（逐块单条写）：1GiB ≈ **259 次 IPC**（256 块 + meta + 落盘校验）；
   - 迁移后（2 块/批，受 12MiB 与 8 条双预算约束）：≈ **133 次**。
4. **内存口径**：现路径峰值 ≥ 文件体积（整文件驻留）；目标路径峰值 ≈ 单块 + base64 + 批预算
   ≤ ~16MiB。端到端峰值/耗时需交互式桌面实测（用户实测项）。

### Wave 1（2026-09-28）：导出完整性热修（P1-2 / P2-4 / D5 / P1-1 语义守卫）

#### 变更点

1. 新增组合式导出管道 `composables/file-verthys/useFileExport.ts`：单遍流式
   （逐块取回 → 布局/长度校验 → 可选解密 → 追加写流 → 最终一次 finalize），
   失败即中止流（目标位置不产生文件）；加密条目在选取保存位置**之前**先解密首块；
   依赖注入设计便于单测。
2. 布局校验口径：块数 == 分块总数 == ceil(声明长度 / 分块口径)；空文件与零块严格对应；
   meta 声明的分块口径必须与跨层常量一致；历史内联形态同样校验。
3. 组件接线：保存改用管道（流式落盘替代整文件内存拼装）；导入侧 meta 写入失败即抛错
   （不计数、不入列表、不提示成功）；meta 不再写入 `completedChunks`（伪字段），
   列表条目携带 meta 声明的分块口径。

#### Wave 1 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 275 passed（25 文件，新增导出矩阵 14 例） |
| 后端回归 | cargo test --lib | 411 passed（未受影响） |

#### Wave 1 收尾交接清单

1. 未完成项（随 Wave 2 迁移一并交付）：导入侧组合式抽层与"导入三态"单测
   （meta 失败/块失败/正常）——导入管线在 Wave 2 整体迁移到批量会话路径，
   现在抽层会造成测试断言二次返工，故与迁移同批交付。
2. 用户实测项（开发模式）：导入含加密与非加密条目 → 保存到本地逐字节比对；
   删除一条块记录后保存应报"第 N 块数据缺失"且目标位置不产生文件；
   0 字节文件导入后可导出为 0 字节文件。
3. 未提交 git，与既有工作树同批待用户评审验收。

### Wave H（2026-09-28，施工顺序先于下列 Wave 0/1）：共享写者 GC 误删窗口 hotfix（清藏链路施工前置）

#### 变更点

1. 收起一个在线数据损坏窗口：块台账的归属改写只存在于导入写者内存，落盘
   发生在批末且失败被静默降级；WAL 的 committed 条目不携带块引用，崩溃恢复
   无法重建归属。窗口内若触发孤儿回收，会删除仍被已提交记录引用的块，表现为
   数据"看得见却打不开"，且去重键仍在、重新导入被跳过。
2. 四件套闭环：
   - WAL `committed` 条目携带 `chunk_ids`（显式声明引用集合；字段缺省即历史条目）；
   - 会话创建先结算（归属改写 + 冻结）再截断 WAL，结算落盘失败即拒绝创建会话；
   - 批末台账落盘失败置脏标记；成功结束前必须落盘台账，失败即拒绝结束并保留
     会话与 WAL（可排除障碍后重试）；
   - 孤儿回收前先结算：可证明归属的块改写为拥有者，无法证明归属的孤儿候选冻结
     为不可回收值，结算落盘失败则放弃本次回收。
3. 冻结语义：历史条目（无引用集合）无法结算时，宁可永久保留也不误删；冻结值
   不进入回收候选，回收面绝不扩大。

#### Wave H 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量单测 | cargo test --lib（src-tauri） | 411 passed |
| 新增单测 | 台账结算 5 / 写者 2 / 台账冻结 1 | 8 passed |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警（含 5 条基线遗留告警的机械修复） |
| worker 单测 | cargo test --manifest-path verthys-worker/Cargo.toml | 33 passed |

#### Wave H 收尾交接清单

1. 本波次改动文件：`src-tauri/src/repository/verthys_wal.rs`、`verthys_chunks.rs`、
   `src-tauri/src/state/import_writer.rs`、`src-tauri/src/controller/verthys_batch_controller.rs`；
   基线告警机械修复：`src-tauri/src/controller/privacy_controller.rs`（2 处改写）。
2. 用户实测项（开发模式）：导入照片 → 中途结束进程 → 重启后再次导入 → 删除若干
   照片 → 观察容器内数据可正常打开、回收不误删；若磁盘异常导致台账落盘失败，
   导入结束应给出明确失败提示并可重试。
3. 未提交 git，与既有工作树同批待用户评审验收。

### 2026-09-28 Wave 55：拾光滚动丝滑度根治（七层方案评审落地 · 三铁律）

用户报告拾光网格上下滚动"不流畅丝滑"，经七层方案（行窗口模型 / 零重绘 hover /
滚动静默态 / 优先级调度 / 滚轮平滑器 / 设备分档 / 验证标准）评审后实施根治；
方案缺陷与项目不符处已直接修正（完整评审裁定表与验收清单见专项文档
`拾光滚动丝滑度根治修复方案.md`）。

#### 根因（五因素叠加，按影响排序）

1. 滚轮滚动时卡片从指针下掠过，连续触发 hover 过渡链——box-shadow 与 filter
   是重绘型属性，过渡期逐帧重绘（滚动掉帧主因）；
2. 每个滚动帧全量重建可视区列表（48 项对象 + style/class 对象）并全量 diff；
3. 每项独立合成层（translate3d），新进屏行首次栅格化（大模糊阴影最贵）排队；
4. 滚动停顿 80ms 即启动 4 路并发解密，与再度滚动竞争主线程；
5. 滚轮离散步进（约 100px/格）无平滑——"丝滑感"行为层底座。

#### 变更点（三铁律落地）

1. **滚动期主线程不做 O(可见项) 工作**：新增 `photo-album/visible-window.ts`
   行窗口模型（像素 → 行窗口量化；跨行重建按"源引用 + 布局键"复用对象，
   内容未变时返回旧数组）；`usePhotoData` 以 computed 惰性重算接入，滚动像素级
   移动零状态写入；条目 style 预算为字符串（`_style`）；坐标整数量化
   （合成器整数吸附）；no-anim 迁移至容器级（1.5s 切换只 patch 一个节点）。
2. **禁止重绘型属性参与过渡**：卡片过渡只剩 transform；阴影加深改为固定阴影层
   `masonry-item::before`（opacity/transform 过渡、visibility 门控不参与静态
   栅格化）；hover 提亮改为 `photo-card::before` 白层（仅 opacity）；钉死
   `.glass:hover` 的边框/阴影漂移（零重绘）；`contain: layout style` +
   条目/卡片双 isolation 固化层序（图像 1＜提亮 2＜文字遮罩 3＜光晕 4）。
3. **滚动期冻结非必要动画与解码**：`scrollQuiet` 静默态状态机（容器
   `data-scrolling` + 根节点 `app-scrolling`）：解密在项边界暂停取新项、
   hover 视觉压平且过渡/动画关停、背景氛围动画暂停（idle-governance.css
   第 7 节通配暂停，与 idle/reduce-motion 同款实现）；停稳 120ms 后统一追帧：
   立即补齐可视区解密 + 预热运动方向下一行缩略图（Image.decode，有界去重）。
4. **滚轮平滑器**：新增 `utils/wheel-smoothing.ts`——只接管鼠标离散步进
   （整数 deltaY ≥ 40px、无横向/缩放/行页模式），指数插值写原生 scrollTop
   （合成器滚动/键盘/拖条/无障碍全保留）；外部打断让位（键盘/拖滚动条）；
   触控板高频熔断（<25ms 连发 3 次让位原生，保护系统惯性）；开关与手感系数
   集中于 `config/scroll-perf.ts`（一键回退原生滚动）。
5. **方案修正**（评审直接改方案处，详见专项文档 §二）：光晕跟随不改 transform
   （非滚动路径 + 已排帧节流）；阴影层落 masonry-item（photo-card 的
   overflow:hidden 会裁阴影）；背景降频走根类 CSS（背景为合成器 CSS 动画，
   不走 useFrameGate）；postTask 分片与 Blob 延迟创建裁剪（复杂度/生命周期
   权衡）；设备分档与运行期自动降级裁剪（项目已有 FrameBudgetMonitor +
   reduce-motion 治理，避免双监控与观感突变）；平滑器补齐方案未覆盖的
   4 个接缝（动态 maxScroll / 打断让位 / 触控板熔断 / 整数性判定）。
6. **实施后审查轮（同批次）修复 2 缺陷**：① 静默态入场动画冻结由
   `animation: none` 改为 `animation-play-state: paused`（前者解冻瞬间会从 0%
   重播 → 停稳后整屏卡片重新淡入闪烁）；② 首批解密被静默暂停时的收尾三分支
   （静默保持"在途与进度位置，停稳追帧续跑"，不得虚假宣告完成/置位
   firstFillDone 使剩余项永不续跑）。另清理 8 个无消费者死导出
   （loadStage/loadPercent/loadMessage/loadElapsedMs/firstFillInFlight/
   decryptPaused/decryptingMetaIds/ensureVisiblePhotosDecrypted）；
   `retryLoad/cancelLoad/resumeLoad` 悬空能力面登记（Wave 50 移除横幅后
   失去 UI 入口，保留实现并注释标注，待产品决策）。
7. **第二轮根因重判与根治（用户实测"仍卡顿"后）**：取证排除软渲染（RTX 3050
   + 本地 console 会话 + WebView2 GrShaderCache 活跃）；定位架构级根因为
   第一轮平滑器在主线程逐帧写 scrollTop（preventDefault 取消原生滚动 =
   把合成器滚动降级为主线程滚动，主线程任何忙碌直接卡住滚动）→ 重写为
   合成器驱动平滑滚动（scrollBy behavior:"smooth"，插值在合成器线程完成；
   删除手写插值/打断/让位状态机）；同轮加固 ParticleBackground 滚动静默期
   跳过渲染帧（渡越相位冻结，GPU/主线程让位滚动合成）；干扰变量记录：
   用户实测时间窗与后端 92.3s 系统模块哈希基线构建重叠（最低优先级单线程，
   对照实验项，不判定为主因）。
8. **第二轮验证门**：vue-tsc 0 错误；vitest 315 passed（28 文件）；
   CI 两级全通过（第二级 0 错误，0 警告）。平滑单测重写为"判定 + 合成器
   发起 + 熔断 + 脱钩"四面对齐新架构。
9. **第三轮红线处置（生产级事故回退：快速滚轮顿挫）**：用户实测"快速滚轮
   顿挫极其严重、劣于修复前"→ 定位两处自引入缺陷：① `scrollBy smooth`
   每格调用在高频滚轮下平滑动画被反复取消/重启（短目标反复重启 → 爬行 +
   顿挫，频率越高越严重）→ **滚轮平滑整体移除**（含 spec / 配置开关 /
   挂载点，不留悬空），滚动回归原生合成器路径——"任何 JS 接管都是降级"
   固化进配置头注与代码注释；② 静默态 `html.app-scrolling .ambient-bg *`
   通配最右端：html 类切换触发全文档样式失效（慢速逐格滚动每格两次全文档
   重算）→ 改为枚举动画元素（约 200 节点，含伪元素单列，CSS 内固化维护
   契约）。另修复既有缺陷：`useCardShine` 在 mousemove 同步阶段
   `getBoundingClientRect()`（滚动期强制 reflow）→ 布局读延迟到排帧回调 +
   静默期跳过采集。第三轮验证门：vue-tsc 0 错误；vitest 308 passed
   （27 文件，平滑用例随实现删除）；CI 两级全通过。

#### Wave 55 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 308 passed（27 文件；第三轮随平滑实现删除相关用例） |
| CI 第一级 | pwsh ci/run_ci.ps1 -Level1Only | 通过（存量基线警告，本轮零新增） |
| CI 第二级 | pwsh ci/run_ci.ps1 | 0 错误（存量 37 条含并行施工登记，项目方已纳入基线豁免） |

#### Wave 55 收尾交接清单

1. **用户实测项（开发模式）**：滚轮 / 触控板 / 拖滚动条 / 键盘四输入源对照——
   滚动全程由合成器线程保障（平滑滚动经 scrollBy smooth 合成器插值）；
   滚动中卡片掠过指针不闪烁；停稳后 hover 经过渡自然呈现；快速下滚新行无
   "空白等待"。DevTools Performance 判据：滚动期 Scripting 近空、无大面积
   Paint、无棋盘格补白。详见专项文档 §五 验收清单。
2. **观感差异（有意为之）**：hover 提亮不再提升饱和度（合成器约束，白层近似
   亮度差）；滚动期间 hover 视觉冻结（静止态，停稳后过渡恢复）；背景氛围
   （.ambient-bg CSS 动画 + ParticleBackground WebGL）滚动期静止、停稳恢复；
   滚轮"1 行"设置（deltaY≈33）不接管（保护触控板，安全退化）；滚轮平滑曲线
   为浏览器合成器内置（不自定义 easing）。
3. **回退**：`config/scroll-perf.ts` 单点开关（wheelSmoothing / wheelStepGain /
   静默态延时）；ParticleBackground 让位检查单点可去。
4. 本波次改动文件：`src/config/scroll-perf.ts`（新）、
   `src/composables/photo-album/visible-window.ts`（新 + spec）、
   `src/utils/wheel-smoothing.ts`（新 + spec）、
   `src/composables/photo-album/usePhotoData.ts`、
   `src/composables/photo-album/types.ts`、
   `src/components/modules/PhotoAlbum.vue`、`src/styles/idle-governance.css`、
   `src/components/ParticleBackground.vue`（滚动静默让位）；
   未提交 git，与既有工作树同批待用户评审验收。

### Wave 2（2026-09-28）：清藏架构收敛（P2-1 / P2-2 / P2-4 读取侧 / P1-2 消费侧补齐）

#### 变更点

1. 块角色白名单收敛：新增记录类型单源常量 `TYPE_FILEVERTHYS_CHUNK = 4`；写者块上传
   校验由三分支判断改为角色白名单函数 + 名称派生函数（记录名 `chunk_{hash}`，不承载
   来源文件名与分块序号）；新增 2 例（白名单含 4 / 名称派生）。
2. 分片读取与元数据快照：`read_user_file` 增 `offset/length`（成对缺省 = 整文件读取，
   行为不变；成对给出 = 分片），越界/超尾/超单次分片上界/空分片一律报错、不静默截断；
   新增独立分片超时 15s（整文件保持 120s）；新增 `user_file_stat(path) → {size, mtime_ms}`
   （与读取同一授权链）；新增 8 例（0/末块/越界/超尾/超上限与空片/参数不配对/缺省不变/
   stat 契约，另含超时关系断言）。
3. 导入管线迁移：新增 `composables/file-verthys/useFileImport.ts`——单遍优先（无遗留
   去重集合）/ 续传两遍（只读轮哈希判定 → 上传轮，上传轮重算哈希与只读轮比对）；
   块批 2 块/批（由载荷上限与块数上限双预算推导，无字面量）；来源身份稳定（文件开始 +
   每个块批边界 + 文件结束三处复查长度与修改时间，收尾断言已读总字节等于初始长度）；
   明文与密文缓冲用后清零；元数据仅在块引用全部确认后写入（写入形态字段：schema /
   chunkIds / chunkHashes / chunkSize / fileHash / encrypted）；失败文件的块留台账由
   孤儿回收处理（前端不做补偿删除）；会话成功语义 = 全部文件成功且会话正常结束。
4. 组件接线：FileVerthys.vue 旧逐块单条写入路径整体删除（锚点 A1）；导入改走管道；
   列表接纳条件改为 `Array.isArray(chunkIds)`（0 字节文件可入列表，P2-4 读取侧）；
   条目携带 chunkHashes。
5. 导出侧完整性消费（补齐 P1-2 的哈希校验，避免 chunkHashes 成为无消费方字段）：
   `useFileExport.ts` 增逐块密文哈希校验（携带 chunkHashes 时逐块 BLAKE3 比对，不符即
   E_CHUNK_CORRUPTED；条数与块数不一致 → E_LAYOUT_INVALID）；新增 3 例（不符中止 /
   一致通过 / 条数不一致）。
6. 取消导入与并发互斥：进度覆盖层增"取消导入"（管道在每个文件与每个块批边界检查；
   取消保留断点、会话按未成功语义结束）；会话冲突（已有活跃会话）时弹确认框
   （结束并继续 / 取消导入），允许则 `import_end(false)` → 重建会话，仍失败则强制清理
   残留会话后再建。
7. 支撑性性能修复（方案外声明）：`utils/binary_codec.bytesToBase64` 由逐字节字符串拼接
   改为 32 KiB 分块 `String.fromCharCode`（4 MiB 实测 ~480ms → ~74ms，输出逐字节一致），
   消除 4 MiB 块 base64 在导入热路径上的放大。
8. 注释与文档对齐：FileVerthys.vue 模块头（记录类型 0x08/0x04、去重与重传语义）；
   `read_user_file` 文档 50MB/10s → 2GB/120s（分片 15s）——P3-1 中与本次改动同函数的
   部分，其余留 Wave 4。

#### 能力边界（本波次声明）

- 去重指纹：当前写入形态的块密钥逐块派生（无稳定文件级密钥），有密码分支的同内容
  不同口令共用同一去重键；区分能力随 Wave 3 文件级密钥落地（指纹改为文件密钥摘要，
  历史条目按形态标记天然分流）。
- 加密分支每块一次 PBKDF2（150k，历史逐块盐口径）：1GiB 加密导入的 KDF 占比目标由
  Wave 3 文件级密钥达成，本波次不度量该指标。
- GUI 端到端（真实大文件导入/导出、杀进程续传、取消交互）为交互式桌面实测项，
  本环境无交互桌面，未实测。

#### Wave 2 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量 Rust 单测 | cargo test --lib（src-tauri） | 421 passed（新增 10：写者 2 / 分片与 stat 8） |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| worker 单测 | cargo test --manifest-path verthys-worker/Cargo.toml | 33 passed |
| 前端单测 | npx vitest run | 315 passed（28 文件；清藏新增导入 14 例 + 导出 3 例） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| CI 全量 | ci/run_ci.ps1（含 AST 第二级） | 全绿（exit 0） |
| 锚点注入即红 | A1 / A2 / B 逐条注入 | 三条均 [RED] 且 exit 1，随后撤回、文件复原 |

#### Wave 2 收尾交接清单

1. 本波次改动文件（未提交 git，与既有工作树同批）：
   Rust：`src-tauri/src/constants.rs`、`src-tauri/src/state/import_writer.rs`、
   `src-tauri/src/controller/file_controller.rs`、`src-tauri/src/lib.rs`；
   前端：`src/composables/file-verthys/useFileImport.ts`（新）、
   `useFileImport.spec.ts`（新）、`useFileExport.ts`、`useFileExport.spec.ts`、
   `src/lib/verthys.ts`、`src/utils/binary_codec.ts`、
   `src/components/modules/FileVerthys.vue`、
   `src/components/common/cosmic/ImportProgressOverlay.vue`；
   CI：`ci/run_ci.ps1`（锚点 5/6/7）、`ci/ast_baseline.txt`（存量违规行号随插入位移
   同步 103 → 110，语义未变）。
2. 用户实测项（开发模式）：导入单文件/多文件（含加密与非加密）→ 列表出现、保存到本地
   逐字节一致；同文件重复导入 → 显式"已跳过"；导入中点击取消 → 覆盖层消失、断点保留；
   导入中修改源文件 → 该文件报"源文件被修改"且不入列表；0 字节文件导入 → 入列表且
   可导出为空文件；删除一条块记录后保存 → 报"第 N 块数据校验失败"且目标位置不产生文件。
3. 遗留（后续波次）：Wave 3 文件级密钥与密码前置、D1 常量收编、磁盘空间预检；
   Wave 4 删除失败可回滚、密码为空按钮禁用（P3-3 余项）、注释与文档全量同步。

### Wave 2 增补（2026-09-28 同批）：全链路深度审查与整改

#### 审查范围

Wave 2 改动全链（导入管线 / 导出管线 / 删除链路 / 列表加载 / 后端分片读取与单写者
块角色白名单 / CI 锚点），并覆盖其上下游交互面（照片链路共享的会话日志与去重集合、
审计日志、二进制编解码）。

#### 发现与整改（5 项）

1. **审计 HMAC 密钥逐次派生（性能放大，高）**：每个审计调用点各自执行 10 万次
   PBKDF2 派生密钥；分片读取按片追加审计，单次 1GiB 导入被放大为约 128 次派生
   （秒级 CPU）。六个调用点中仅 `security_commands/audit.rs` 已做进程内缓存。
   整改：五个控制器统一加进程内单次派生缓存（仅缓存成功结果：采集/派生瞬时失败
   不占缓存，下次写入自愈重试）；新增 1 例（两次取键一致 + 成功结果入缓存）。
2. **删除未释放文件级去重键（功能缺陷，高）**：本轮导入让 `fileHash` 成为会话日志
   中的去重键，但删除链路从未调用 `verthysForgetHashes`，且列表条目不携带
   `fileHash` → 删除后的文件重新导入被静默跳过（"删除后可重导"不成立）。
   整改：条目携带 `fileHash`（导入产物 + 读取侧解析）；删除落盘成功后释放；
   释放失败进进程内待重试队列（下次导入开始前自动重试）并给出精确提示；
   历史条目无键则跳过并留日志。属 P2-5"成功后释放去重锁"子项的提前落地。
3. **块批/元数据写入的传输层异常未分类（契约缺陷，中）**：`chunkBatch` /
   `recordsBatch` 抛出的通道异常会退化为未分类错误（默认归为读取失败），归因误导。
   整改：两处包裹并分类为 `E_CHUNK_FAILED` / `E_META_FAILED`；新增 2 例。
4. **后端按会话日志跳过元数据被误判为失败（边界缺陷，中）**：该路径返回
   `ids[0]=0`（失败集为空），原实现按 `E_META_FAILED` 处理。整改：按结构化字段
   `skipped_count` 判定为"跳过"入账，不计成功、不产生条目；新增 1 例。
5. **死导入清理（卫生）**：`FileVerthys.vue` 移除两个无消费者的 shallow 工具导入。

#### 同步的机械化项

- `ci/ast_baseline.txt`：本次插入导致 5 处控制器存量违规行号位移，按分析器实际
  行号同步（device 66→73 / file 110→118 / key 59→67 / scan 78→85 / verthys
  130→136），违规语义未变。
- 复核分块 base64 与旧实现逐字节一致（边界含 0/1/2/3/255/32767/32768/32769/
  65536/65537/123456/4MiB+1）。

#### 确认保留（不在本批改动，逐项说明）

- **删除链路事务化（P2-5，Wave 4）**：逐条删除失败仅 `VERTHYS_WRITE_BLOCKED`
  上抛，无回滚与重试态，存在"元数据删除失败而块删除成功"的复活窗口与"块删除
  失败"的空间泄漏；按方案归 Wave 4，统一改 `verthysDeleteRecords` 单事务 +
  可见可重试。
- **每分片一条审计（容量）**：约 128 条/GiB；成本在整改 1 后降至微秒级，保留
  逐片可追溯。
- **去重集合为容器级共享**：容器内有过照片导入时清藏导入固定走两遍形态（多一轮
  读取）；两侧去重键构造域不同、无互误跳过；已在代码注释声明，属"续传正确性
  优先"的设计取舍。
- 加密分支每块一次 PBKDF2 仍为历史逐块盐口径（Wave 3 文件级密钥收口）。

#### 批次验证门（增补）

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量 Rust 单测 | cargo test --lib（src-tauri） | 422 passed（+1） |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| 前端单测 | npx vitest run | 318 passed（+3） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| CI 全量 | ci/run_ci.ps1（含 AST 第二级） | 全绿（exit 0） |

#### 交接

1. 本批追加改动文件：Rust `src-tauri/src/controller/{file,device,key,scan,
   verthys}_controller.rs`；前端 `src/components/modules/FileVerthys.vue`、
   `src/composables/file-verthys/useFileImport.ts`、`useFileImport.spec.ts`；
   CI `ci/ast_baseline.txt`。未提交 git，与既有工作树同批。
2. 用户实测项（追加）：删除一个已导入文件 → 重新导入同一文件 → 必须正常导入
   （不得被跳过）；导入 1GiB 文件过程中不出现秒级停顿（审计派生不再重复）。

### Wave 3（2026-09-28）：加密与体量（文件级 KDF / D1 常量收编 / 磁盘空间预检）

#### 施工裁定（实现前冻结，已回写方案文档）

1. **无密码条目**不写 `kdf`/`passwordCheck`；加密条目两者必写。
2. **去重键维持"内容 + 形态标志"**（D4 的"指纹取文件密钥 BLAKE3"**不采纳**）：
   文件盐逐次随机 → 密钥摘要不稳定（续传重试会重复导入已提交文件，破坏
   已验收的中断续传跳过）；若改为稳定值则必然是口令派生量，而会话日志
   （`<容器>.import.wal` 与快照）为明文 JSON，落盘即公开口令验证器。
   用户裁定采纳本口径；§9.1"同内容不同密码可并存"回写为"删除后重导可换口令"。
3. **2GiB 边界**：`size > limit` 拒绝（恰好 2GiB 允许）；读数文案按 GB。
4. **磁盘预检时机**：导入 = `user_file_stat` 后、读块前（容器卷，阈值
   `size × 1.05`）；导出 = 选定路径后、开流前（目标卷，阈值 `size`）；
   读数不可得不阻断（前置预检为尽力而为），确定不足即拒绝且零副作用。
5. **`check_disk_space(path?)`** 独立命令：缺省 = 会话容器路径；复用
   `util::disk`（新增字节口径，MB 口径改为其派生）。
6. **crypto 层原语**落 `lib/crypto.ts`；导入/导出管线接口见变更点 2、3。

#### 变更点

1. crypto 层（`lib/crypto.ts`）：`FileKdfV2` / `FileKeyV2`、
   `createFileKeyV2`（随机盐一次派生，原始密钥导入句柄后即刻清零）、
   `unlockFileKeyV2`、`encryptChunkV2`（`iv(12)‖ct+tag`）、`decryptChunkV2`、
   `buildPasswordCheckV2` / `verifyPasswordCheckV2`（固定明文，唯一口令判定点）。
2. 导入管线：deps 增 `FileKeySuite`（有密码导入的唯一加密路径；**历史逐块盐
   写入路径删除**——无未来用途，不留死代码）；文件密钥每文件派生一次、只读轮与
   上传轮共用句柄；meta 携 `kdf`/`passwordCheck`；`user_file_stat` 后新增体量预检
   （超限 `E_FILE_TOO_LARGE`，读块前拒绝）与容器卷空间预检（`E_DISK_FULL`）。
3. 导出管线：条目携 `kdf`/`passwordCheck`；`openV2Decryptor` 在选路径之前完成解锁
   与口令判定（不匹配 → `E_PWD_WRONG`）；块解密失败一律 `E_CHUNK_CORRUPTED`
   （删除"全部失败=密码错"启发式）；v1 合并文案补可执行引导；目标卷空间预检。
4. D1 常量收编：`photo_budget.schema.json` 新增 `user_file_size_limit = 2147483648`
   （移除手填 `max_export_single_bytes`）；生成器派生 `USER_FILE_SIZE_LIMIT` 与
   `MAX_EXPORT_SINGLE_BYTES`（同源赋值 + Rust 编译期断言相等）；
   `file_controller.rs` 删除本地字面量改用生成常量；前端按该常量做超限预检；
   照片导出上限 512MiB → 2GiB（放宽回归 2 例，文案改 GB 读数）。
5. 磁盘空间预检：Rust `check_disk_space(path?) → {free_bytes}`（预检超时、
   系统关键目录拒绝、未创建目标回退最近已存在祖先）；`util::disk` 增字节口径；
   两个管线与组件接线完成。
6. **3.3 裁定留证**：1GiB 流式 BLAKE3 实测 **581 MB/s（1762ms/1GiB）**，
   无需移入 Worker（与 Wave 0 的 512MB/s 结论一致）。
7. AST 基线：`file_controller.rs` 存量违规行号随本地常量删除位移同步
   （118 → 110）；`state` 层引用并入既有导入行（同类既有豁免，不新增违规）。

#### 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量 Rust 单测 | cargo test --lib（src-tauri） | 426 passed（+4：D1 统一断言 + 磁盘预检 3） |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| 前端单测 | npx vitest run | 326 passed（27 文件；新增 crypto 5 / 导入 5 / 导出 6 / 照片 2） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| CI 全量 | ci/run_ci.ps1（含 AST 第二级） | 全绿（exit 0） |
| 常量门 | node constants/generate.mjs --check | 生成物与权威来源一致 |
| 哈希位置复核 | node 基准（1GiB 流式 BLAKE3） | 581 MB/s（1762ms），无需 Worker |

#### 能力边界

- 同内容不同口令共用同一去重键（换口令导入须先删除原条目）——用户裁定口径。
- 加密导入的 PBKDF2 由"每块一次"降为"每文件一次"；1GiB 端到端 KDF 占比 ≤ 5%
  属交互式桌面实测项（本环境无交互桌面，未实测）。
- v1 存量（旧 meta / 内联块 / 逐块盐）读取与导出路径保持；v1 写入路径已删除。

#### 收尾交接清单

1. 改动文件（未提交 git，与既有工作树同批）：
   Rust：`src-tauri/src/constants.rs`、`src-tauri/src/util/disk.rs`、
   `src-tauri/src/controller/file_controller.rs`、`src-tauri/src/lib.rs`、
   `photo_budget.rs`（生成物）；
   前端：`src/lib/crypto.ts`、`src/composables/file-verthys/{useFileImport,useFileExport}.ts`
   及两个 spec、`src/lib/verthys.ts`、`src/components/modules/FileVerthys.vue`、
   `src/composables/photo-album/usePhotoExport.ts` 及其 spec、
   `src/constants/{photo_budget.schema.json,generate.mjs,photo_budget.generated.ts}`；
   CI：`ci/ast_baseline.txt`。
2. 用户实测项：加密导入 → 导出逐字节一致；错误口令即时报"密码错误"且不弹保存框；
   历史 v1 条目仍可导出（合并文案含可执行引导）；`>512MiB` 照片单文件导出不再被拒；
   容器/目标磁盘不足时前置拒绝。
3. 遗留（Wave 4）：删除链路事务化（P2-5）、密码为空按钮禁用（P3-3 余项）、
   注释与文档全量同步、组合式抽层与 spec 全量。

### Wave 4（2026-09-28）：清藏收口（删除事务化 / 交互余项 / 组合式抽层 / 文档全量同步）

#### 变更点

1. **删除链路事务化（P2-5）**：新增 `composables/file-verthys/useFileDelete.ts`——
   块引用（外置形态）与元数据 ID 收敛为单次批量事务删除（`deleteAndPersistBatch`
   → 单事务 `verthysDeleteRecords`）；删除提交后立即失效摘要/全量/扫描三层缓存
   并强制立即落盘（`persistVerthys` 取消防抖）；落盘成功后释放文件级去重键
   （`verthysForgetHashes`，释放实现内含一次即时重试），历史条目无键跳过并留
   日志；收尾 best-effort 触发一次孤儿块回收。失败语义：
   - 删除失败（返回 false 或抛异常）→ 条目与缓存零变化，按钮恢复，重新执行即重试；
   - 落盘失败 → 条目保持"删除已提交待落盘"态（保存禁用、删除按钮变"重试"），
     重试经 `retryFileDeletePersist` 仅重放落盘与收尾——批量删除对缺失条目整体
     拒绝并零副作用返回，删除步骤不可重放；
   - 释放失败 → 删除结论不变，键入待重试队列并给出精确提示。
2. **组件接线**：FileVerthys.vue 删除段整体改用该管道；删除期间卡片保持可见
   （按钮禁用、`cursor: not-allowed`、标签"删除中…"），成功才移除条目并提示；
   删除路径不再携带"格式升级"字符串分支（该串在核心与进程间层均无生产者，
   属死代码；清藏消费点按 B 分支对齐，其余模块消费点由 T-1 独立跟踪）。
3. **待重试队列迁移（Wave 2 深审子项）**：进程内 `pendingDedupeReleases` 由组件
   迁入 `createDedupeReleaseQueue`（组合式导出），`startImport` 建会话前补释放，
   语义不变（避免"删除后重导被静默跳过"残留为永久状态）。
4. **交互余项（P3-3）**：导入对话框"开始加密导入"在勾选独立密码且口令为空时
   禁用；密钥对话框"解密保存"在口令为空时禁用；禁用态 `cursor: not-allowed`
   由全局主按钮样式承载。
5. **回归防线**：新增 `useFileDelete.spec.ts` 4 例——批量失败回滚（零副作用 +
   恢复后重试）/ 落盘失败（不重删、仅收尾重放）/ 去重键释放（成功释放、
   失败入队与补释放、历史条目跳过）/ 成功路径（单次合并调用、缓存失效、
   孤儿回收、删除后可重导；含历史内联形态与无后端记录边界）。
6. **文档与注释全量同步**：方案实施记录与 §9.3 勾选、本进度、审查清单状态
   回填（新增第十节）、`DATA_FLOW.md`（导入域会话/台账结算/去重跳过与删除
   释放）、`ARCHITECTURE.md`（导入域单写者/台账/GC 守卫/分片读取）、
   `SECURITY_DESIGN.md`（文件级 KDF v2、口令判定唯一化、去重键不含口令材料）、
   `FileVerthys.vue` 模块头（删除语义）。

#### 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量 Rust 单测 | cargo test --lib（src-tauri） | 426 passed（本波无 Rust 改动，与 Wave 3 一致） |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| 前端单测 | npx vitest run | 330 passed（28 文件；新增 useFileDelete 4 例） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| CI 全量 | ci/run_ci.ps1（含 AST 第二级） | 全绿（exit 0；AST 基线 37 条存量豁免未动） |

#### 能力边界

- 去重键释放待重试队列为进程内：跨重启的极端窗口（释放失败且随后重启再导入
  同一文件）仍会命中跳过并有提示，需再执行一次删除以补释放；释放失败本身
  已含一次即时重试，实际触发概率极低。
- 删除交互（删除中禁用态、"重试"入口、落盘失败文案）为交互式桌面实测项
  （本环境无交互桌面，未实测）。

#### 收尾交接清单

1. 改动文件（未提交 git，与既有工作树同批）：
   前端：`src/composables/file-verthys/useFileDelete.ts`（新）、
   `useFileDelete.spec.ts`（新）、`src/components/modules/FileVerthys.vue`；
   文档：`docs/RemediationPlan/{清藏模块导入文件链路修复方案,清藏模块导入文件链路审查清单,IMPL_PROGRESS}.md`、
   `docs/{DATA_FLOW,ARCHITECTURE,SECURITY_DESIGN}.md`。
2. 用户实测项（开发模式）：删除一个已导入文件 → 卡片短暂显示"删除中…"后消失
   并提示"已删除"；重启后不复活；删除后重新导入同一文件 → 正常导入（不被
   跳过）；勾选"独立加密"但不输入密码 → "开始加密导入"为禁用态；密钥对话框
   口令为空 → "解密保存"为禁用态。
3. 遗留：T-1 错误码契约收口（独立任务，不占本波出口门）；§9.1 中需交互式
   桌面实测的大文件/杀进程/磁盘不足场景（本环境无交互桌面）。

### T-1（2026-09-28）：错误码契约收口（P2-6 · 独立任务）

#### 事实核实（A/B 分支前提，证据闭合）

1. 核心为 V3-only：格式枚举仅保留 `VERTHYS_FMT_NONE/V3`
   （`core/src/container/shared/verthys_internal.h:28-33`）；解锁格式门禁对
   非 V3 头一律 `VERTHYS_ERR_FORMAT` 拒绝（`core/src/api/lifecycle/verthys_api.c:952-959`，
   注释语义"V3 不读 V2 文件"，无应用内迁移路径，数据保全经由旧版本导出 /
   新版导入）。
2. 全部 V3 分发 API 对非 V3 返回 `VERTHYS_ERR_INTERNAL`
   （`verthys_api.c:1160/1193/1228/1280/1478`）；扫描与导入导出返回
   `VERTHYS_ERR_FORMAT`（`verthys_scan.c:513/683/796/856`、
   `verthys_export_import.c:249/555/663`）；worker DLL 预检要求 fmt=3
   （`verthys-worker/src/runtime/worker.rs:262-288`）。
3. 结论：**不存在"已解锁但格式需升级"的状态**；`VERTHYS_WRITE_BLOCKED`
   无生产者，其"格式升级"分支与文案（"重新打开应用重试升级"）为死代码且
   误导（无应用内升级路径）。原两分支假设均不成立 → **裁定 B 分支（删除死分支）**；
   A 分支为不可达状态发明后端接口，不采纳。

#### 变更点（全仓收口）

1. 消费点删除（16 处 + 注释 2 处）：`CertManager.vue` ×3、`AccountVerthys.vue` ×3、
   `usePhotoDelete.ts` ×4、`usePhotoParse.ts` ×2、`usePhotoImport.ts` ×2、
   `importPipeline.ts` ×2（另 1 处方法注释）、`verthys-flush-service.ts` 注释；
   `FileVerthys.vue` 已于 Wave 4 对齐。删除后各路径按既有通用失败分支收口
   （或直接抛错传播），死分支原不可达，可达行为不变。
2. 照片链路"致命错误"机制保留：唯一可达类别为后端容量告罄（`ERR_0000000F`
   → `storage-full`）；`importPipeline.spec.ts` 2 例由注入该字符串改写为容量
   告罄类别，并新增映射断言（`failedRecords.reason === "storage-full"`、
   错误文案含"存储空间不足"）。
3. **锚点 C 启用**：`ci/run_ci.ps1` 新增锚点 8——全前端
   （`verthys-tauri/src/**/*.{ts,vue}`）整串禁入 `VERTHYS_WRITE_BLOCKED`；
   注入验证 [RED] + exit 1 后撤回复原。原冻结等式正则在实测中存在覆盖盲区
   （`.includes(...)` 与 `msg ===` 形态），按整串禁入收紧并回写方案 §8.2。

#### 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量 Rust 单测 | cargo test --lib（src-tauri） | 426 passed（本任务无 Rust 改动，沿用本树结果） |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警（同上） |
| 前端单测 | npx vitest run | 340 passed（28 文件；T-1 改写 2 例断言口径，未增减用例数） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| CI 全量 | ci/run_ci.ps1（含锚点 8 与 AST） | 全绿（exit 0） |
| 锚点 C 注入即红 | 注入字符串 → CI | [RED] + exit 1，随后撤回复原 |
| 字符串零残留 | src 全目录检索 | 零命中 |

#### 能力边界

- 旧容器在解锁阶段被格式门禁拒绝的用户提示链路不在本任务核查范围
  （观察项：如需面向旧容器的显式指引"请用旧版本导出后重新导入"，另行立项）。
- vitest 全量 340 例含并行工作流对 `useTransitionEngine.spec.ts` 的扩充
  （该文件非本任务改动），与本链路无关。

#### 收尾交接清单

1. 改动文件（未提交 git，与既有工作树同批）：
   前端：`src/components/modules/{CertManager,AccountVerthys}.vue`、
   `src/composables/photo-album/{usePhotoDelete,usePhotoParse,usePhotoImport}.ts`、
   `src/composables/photo-album/importPipeline.ts` 及 `importPipeline.spec.ts`、
   `src/cache/domain/verthys-flush-service.ts`（注释）；
   CI：`ci/run_ci.ps1`（锚点 8）；
   文档：`docs/RemediationPlan/{清藏模块导入文件链路修复方案,清藏模块导入文件链路审查清单,IMPL_PROGRESS}.md`。
2. 用户实测项（开发模式）：证书新增/编辑/删除、账户新增/编辑/删除、照片删除、
   加密文件解析导入、照片导入 —— 正常路径不回归（死分支删除不影响可达行为）。
3. 遗留：无（P2-6 闭合，T-1 结项）。

### 复审（2026-09-29）：修复后全链路复核与整改（第四次全链路审查）

#### 复审范围与方法

范围：清藏导入文件全链路（导入/列表/导出/删除）+ 其共享底座（会话 / 单写者 /
台账 / WAL 结算 / GC 守卫 / 分片读取 / 磁盘预检）+ T-1 波及面（照片导入与
致命机制、证书 / 账户消费点）。方法：前后端全量读码 + 跨层契约比对 +
并发假说构造与验证（先证伪防线、再定位缺口）+ 全量门禁复跑。

#### 假说验证（防线确认 / 高危假说证伪）

1. **GC × 活跃会话**：`verthys_gc_orphan_chunks` 对活跃会话直接拒绝
   （`verthys_batch_controller.rs:610-617`），前端 best-effort 吞错 →
   不存在"GC 误删在途块"窗口（证伪）。
2. **删除 × 导入并发**：`delete_records` 经 worker actor 串行
   （`verthys_controller.rs:1876-1880`）；`forget_hashes` 活跃会话时经单写者
   FIFO 落盘（`:440-475`）；删除不触碰 WAL/台账 → 无交错损坏（证伪）。
3. **同会话同哈希块重传**：会话内幂等复用返回既有 ID（`import_writer.rs:688-692`），
   前端 `id<=0` 失败判定不会误伤（证伪）。
4. **结算不失证明**：会话创建先结算（committed chunk_ids → 台账 owner，
   失败拒绝建会话）再截断 WAL，且墓碑基线固化回快照
   （`verthys_wal.rs:616-663`）→ 删除后重导不复活（防线确认）。
5. **结束义务**：成功结束前台账落盘失败即拒绝结束并保留 WAL
   （`import_writer.rs:789-801`）；批末落盘失败置脏（防线确认）。
6. **读取与预检**：分片越界即报错（`file_controller.rs:890-897`，含测试）、
   磁盘预检回退最近已存在祖先（`:1361/:1381`）（防线确认）。
7. **容量告罄判定属码匹配**：`ERR_0000000F` 为 worker 结构化错误码单一格式器
   输出（`verthys-worker/src/runtime/protocol.rs:266`，格式由 `gmk.rs:540`
   测试钉住）→ 非文案判定，保留（防线确认）。
8. **导入中 UI 遮挡**：覆盖层 `inset:0` 全遮蔽（`ImportProgressOverlay.vue:93-101`）
   → 同模块"删除 × 导入"不可达；跨模块删除按第 2 条收敛（证伪）。
9. **模块切换（无 keep-alive）中的导入**：后台继续、缓存与落盘仍提交，
   重入由会话冲突确认收敛，无重复入库 / 数据丢失（已评估收敛）。
10. **去重键域隔离**：清藏 `BLAKE3(明文‖格式版本‖形态标志)`
    （`useFileImport.ts:72-77`）与照片 `BLAKE3(明文)`（`crypto.ts:232`）
    构造域不同，无互误跳过（证伪）。

#### 发现与整改（3 项，全部根治）

1. **导入确认键同步重入窗口（P2，并发）**：`startImport` 在首个 `await` 之前
   未置位 `importing`，确认键连击 / 重复触发可双开导入（两轮会话并发互杀 +
   重复入库窗口）。整改：同步重入闸门置位于首个 `await` 之前
   （`FileVerthys.vue:501-507`）；待重试去重键补释放异常兜底不阻断。
2. **落盘失败重试态的幽灵条目（P2，状态一致性）**：`E_PERSIST_FAILED` 保留
   卡片与"重试"态（仅组件内存），而模块缓存仍含条目；组件无 keep-alive，
   切模块重挂载后条目以常规卡片复活——数据层已删除：保存必失败、删除因
   条目缺失被批量命令整体拒绝，形成"看得见却打不开、删不掉"的幽灵条目
   （直至重启）。整改：模块缓存按"数据层视图"写入（`syncModuleCache`，
   persist-retry 条目不入缓存，4 处写点统一：导入提交 / 删除收口 / 扫描回填 /
   演示条目）。
3. **会话冲突判定文案耦合（P3，违反"结果式契约"纪律）**：两处按后端文案
   子串驱动控制流（`useFileImport.ts` 旧 `.includes("已有导入会话")` 与
   `importPipeline.ts` 旧 `classifyBeginFailure` 三文案分支；且"正在自动清理"
   引导与事实不符）。整改：`VerthysResponse` 增结构化 `error_code` 字段与
   `err_code()` 构造器（`controller/types.rs:474-476/:612-617`）；`import_begin`
   三个拒绝分支携带稳定错误码（`E_IMPORT_SESSION_BUSY` / `E_VERTHYS_NOT_READY`，
   busy 出口收敛为单一构造函数 `import_session_busy_response`）；TS 侧导出
   同源码常量（`lib/verthys.ts:525-529`），两消费点按码分支；照片引导文案改为
   如实（等待重试 / 持续存在时重启清理会话）；新增 Rust 契约测试
   （码值 + 序列化形态）与前端"无码不做冲突确认"用例。

#### 复审批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 全量 Rust 单测 | cargo test --lib（src-tauri） | 427 passed（+1：会话冲突码契约） |
| 静态检查 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| 前端单测 | npx vitest run | 343 passed（28 文件；本波 +1 冲突码用例，另含并行工作流扩充） |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| CI 全量 | ci/run_ci.ps1（含锚点门与 AST） | 全绿（exit 0；AST 0 错误 0 警告，基线 37 条未动） |

#### 边界（复审结束语）

- 组件级防护（重入闸门、缓存视图一致性）与冲突引导文案为交互式桌面实测项
  （本环境无交互桌面）；仓库无 SFC 组件测试基建，与既有测试口径一致。
- 落盘失败重试态的跨重启窗口（未重试即退出）为既有声明边界：重启后记录复活
  可正常再次删除，不产生不可恢复状态。

### 2026-09-29 Wave 56：全局 Toast 层收口（唯一渲染层 + 最高层级令牌 · 四套并存实现归一）

用户要求：toast 不被其它界面覆盖、必须在最高层，系统化工程化标准化修改。

#### 问题定位（审查实测）

1. **层级失控（根因）**：toast DOM 渲染在模块组件内部（拾光导出/复制/状态提示、
   钥域/清藏底部提示等均未 Teleport），被困在 `#app`（z 1）→ 模块栈上下文内 ——
   凡 Teleport 到 body 的弹窗（模块密钥窗 z 1000 / 二次确认 z 3000 / 导出对话框
   z 4000）在根栈上下文绘制，必然整体盖过提示；既有逐处补丁各自为政
   （z 999 / 4500 / 5000 / 100000 四套口径），拾光甚至需要 `.clip-toast--over-dialog`
   手工抬层覆盖自家导出对话框。
2. **状态分裂**：`useErrorToast` 非单例（每次调用各持一份 errorMsg），跨 composable
   共享时提示丢失；拾光曾因此二次封装 `usePhotoToast` 补救 —— 同源问题两套实现。

#### 变更点

1. **唯一渲染层（新增）**：`components/common/feedback/ToastLayer.vue` ——
   App 根节点单点挂载 + `<Teleport to="body">`，脱离 `#app` 栈上下文；
   层容器 `pointer-events: none`（提示永不拦截交互）；空闲治理类（`idle-*`）
   由层根节点按唯一权威源（useGlobalIdleScheduler）透传承载，Teleport 出栈后
   `.toast-dot` 的暂停/豁免语义与主界面一致。
2. **唯一状态中心（新增）**：`composables/useToastCenter.ts` —— 模块级单例状态 +
   5 通道方法（error / status / copied / exportDone / clip），自动消失计时收敛
   到中心（重复触发重置计时）；任何模块任意 composable 调用都写入同一份 ref。
3. **层级唯一权威（标准化）**：`tokens.css` 新增分层序令牌 `--z-toast: 100000`
   （注释载明全序：Dock 50 → 弹窗 1000 → 查看器 2000 → 确认 3000 → 导出 4000 →
   遮罩/加载 9999 → 扫描线 9998 → Toast 100000）；`.toast-layer` 唯一持有，
   提示本体不再声明 z-index，调整层级只改令牌一处。
4. **样式收口**：`.toast-layer` / `.clip-toast`（含 `--top` / `--success` / `--error`
   变体，自拾光 scoped 收编）/ 全局 `.toast-*` 过渡（模块 scoped 四份删除；
   `!important` 压过 `.glass` 的 `transition: all`，与 `.err-toast-*` 同款处置）
   全部归 `components.css`；`dashboard.css` 删除 `.sc-toast` + `toast-in` +
   重复过渡（`.sc-toast` 系中枢私有实现，同批归一为 `.clip-toast`）。
5. **调用方迁移（7 模块 + 2 composable）**：MainView/useModuleNavigation、中枢、
   存签、枢钥、钥域、拾光、清藏 —— 模块内 toast DOM / 本地计时器 / 本地样式
   全部清零，仅保留中心方法调用；`useClipToast(text)` 保留剪贴板生命周期
   （写入 → 逐秒倒计时 → 到期覆写清零），渲染改经中心倒计时通道，
   卸载时同步收起提示（防全局状态残留）。
6. **拾光依赖注入口径保留**：子 composable 注入口径不变
   （showError/showToast/showExportDone/showCopied），由 PhotoAlbum 绑定中心
   方法（showToast 保留模块既有 2s 口径）；中枢子系统沿用 `showToast` 参数名
   绑定标准状态通道，四个安全 composable 注入点零改动。
7. **旧实现删除**：`useErrorToast.ts`、`photo-album/usePhotoToast.ts`、
   `common/feedback/ToastOverlay.vue`、`common/verthys-ui/ClipToast.vue`
   及 `ExportDoneToast` 类型；9 处 composable 注释口径同步
   （「来自 useErrorToast/usePhotoToast」→「来自全局 Toast 中心」）。

#### 关键约束（改动时勿破坏）

- 全部瞬时提示必须且只能经 `useToastCenter` 写入、由 `ToastLayer` 渲染；
  禁止任何模块再自行渲染 toast DOM（层级/状态分裂均由此而来）；
- 层级唯一来源 = `tokens.css` 的 `--z-toast`（`.toast-layer` 持有）；
  提示本体不得声明 z-index；
- 新增提示通道时：`useToastCenter` 扩展状态 + `ToastLayer` 扩展渲染，保持一一对应；
- `.toast-*` / `.err-toast-*` 过渡的 `!important` 为压过 `.glass { transition: all }`
  所必需（同特异性、位序靠后），不得移除。

#### 批次验证门

| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 343 passed（28 文件） |
| 残留检索 | src 内 toast 渲染点 / `class="(error-toast\|clip-toast)"` | 仅 ToastLayer.vue（+ components.css 定义） |
| 旧实现残留 | `useErrorToast\|usePhotoToast\|ToastOverlay\|ClipToast` 引用 | 0 命中（中心文件历史沿革注释除外） |
| z-index 口径 | `z-index: 4500/5000/999`（toast 相关）| 0 命中 |
| 前端构建 + 打包 | — | 由项目方执行（延续 Wave 46 起惯例，助手不代跑构建） |

#### 收尾交接清单

1. **用户实测项（开发模式）**：各模块触发提示（清藏导入/删除、钥域复制/导出、
   存签/枢钥复制倒计时、拾光导入/导出/防截屏开关、中枢锁存与模块密钥操作）——
   提示均在最高层，弹出导出对话框 / 查看器 / 二次确认时仍不被覆盖；
   提示不再拦截底部区域点击（pointer-events: none）。
2. **本波次改动文件**：新增 `composables/useToastCenter.ts`、
   `components/common/feedback/ToastLayer.vue`；修改 `App.vue`、`MainView.vue`、
   7 个模块组件、`useModuleNavigation.ts`、`useClipToast.ts`、
   `styles/{tokens,components,security/dashboard}.css`、
   照片链路 5 个 composable 与安全链路 4 个 composable（注释口径）；删除
   4 个旧实现文件；未提交 git，与既有工作树同批待用户评审验收。

#### 复审增补（同日 · 全链路全量审查）

复审范围：状态中心 / 渲染层 / 层级令牌 / 治理契约 / 全量调用点 / 样式残留 /
测试与文档，共七轴。结论：0 残留、0 未迁移调用点；发现 2 项缺陷与 1 项契约
缺口，已整改；补 1 组防回退测试。

1. **缺陷 1（已修）**：`tokens.css` 分层序注释绘制序倒置（9999 遮罩/加载
   与 9998 扫描线次序写反）→ 按真实绘制序修正为
   `… 4000 → 扫描线 9998 → 遮罩/加载 9999 → Toast 100000`。
2. **缺陷 2（已修）**：`useClipToast` 卸载清理跨模块竞态 —— 模块切换为
   交叉淡出（新旧短暂并存），旧实例卸载会误清新模块已接管的倒计时提示。
   整改：以「对象身份归属判定」精确收回（`toastState.clip.value ===
   本实例最后写入` 时才清除），中心侧只读不写第二来源。
3. **契约补注（已加）**：`idle-governance.css` §3 增补维护契约 ——
   `.toast-layer` 经 Teleport 挂 body、不在 `.app-root` 之下，其根节点按
   唯一权威源透传 `idle-*` 类，豁免/暂停语义对立标同样生效。
4. **新增防回退测试（已加）**：`composables/useToastCenter.spec.ts` 7 例 ——
   单例语义（方法同一引用 / 后写覆盖先写）、error 2.5s + 重复触发重置、
   status 默认 2.5s + 显式时长覆写（拾光 2s）、copied 1.5s、exportDone 2.6s
   + 载荷保真、clip 长驻无计时、通道互不干扰。
5. **全量核查结果（零残留证据）**：
   - 写者纪律：`toastState.*.value` 直写仅存在于中心实现（模块/composable 零直写）；
   - 渲染单点：toast 渲染 DOM 仅 `ToastLayer.vue`；`transition name="toast"/"err-toast"`
     仅 Layer；`.clip-toast`/`.error-toast` 定义仅 `components.css`；
   - 层级：全仓 `z-index` 数值扫描最大值 9999（遮罩/加载）< Toast 100000；
     toast 相关 999/4500/5000 口径零命中；
   - 调用点：7 模块 + 2 composable 逐点清点，与改前调用数一致
     （清藏 20 / 拾光 12 / 钥域 6 / 枢钥 6 / 存签 5 / 中枢 4 / 导航 1）；
   - 依赖面：无 barrel/index 引用删除物；无 spec 引用删除物；
     `common/feedback/` 仅存 ToastLayer；所有编辑 CSS 经 postcss 解析通过。
6. **有意行为差异（标准化结果，非缺陷；交接说明）**：
   - 中枢私有 `.sc-toast`（bottom 30 / text-primary / 无立标）归一为标准
     `.clip-toast`（bottom 24 / accent / 立标）—— 与清藏/钥域口径一致；
   - 中枢「已复制到剪贴板」并入标准 copied 通道（1.5s / accent / 立标）；
   - 提示不再随模块卸载被强杀：错误/状态/导出完成按自身时长自然消失，
     倒计时按归属收回（全局层语义：消息不被模块切换中断）；
   - deep-idle 下错误提示立标入场动画随治理暂停（与既有 inline 提示口径
     统一；deep-idle 语义为用户远离 / 窗口失焦，可接受）。
7. **复审后验证门**：`npx vue-tsc --noEmit` 0 错误；`npx vitest run`
   350 passed（29 文件，含新增 7 例）；4 个编辑 CSS postcss 解析通过；
   前端构建 + 打包仍由项目方执行（惯例不变）。

#### 第二轮复审增补（同日 · 独立对抗式审查 + 演进态复核）

复审方式：① 独立审查员对当前冻结态做对抗式审查（渲染单点 / 层级锚定 /
治理透传 / 单写者 / 身份不变式 / CSS 收敛 / 删除物残留 / 死导入，共八轴）；
② 对「提示底板 · 星野场」视觉演进态逐项复核引用完整性与治理覆盖。

1. **P1 缺陷（本次唯一实质缺陷，已修）**：深响应式代理使对象身份比较失效
   —— `ref` 包装对象时 `.value` 返回 Proxy，与写入方持有的原始对象恒不等，
   引入「单写者自守」后倒计时会在第 1 秒自停（提示冻结在起始值、到期覆写
   与剪贴板清空不再执行 —— 安全清空功能失效）。整改：载荷状态
   （`exportDone` / `clip`）改用 `shallowRef`（恒定整体替换、身份稳定），
   并在状态定义处注明不变式「禁止改回 deep ref」。
2. **P2 补强（已加）**：到期清理路径加 try/catch（无 clipboard API 环境
   不得以未捕获异常逃逸出计时回调）；新增 `useClipToast.spec.ts` 6 例
   （倒计时递减 / 到期覆写与清空 / 无 API 健壮性 / 自守让出 / 卸载归属与
   精确收回 / 重复复制重置）—— 该链路此前零覆盖，是本轮唯一 P1 的检出者。
3. **P3（已修·注释口径）**：提示底板性能说明「存续 1.5~2.6s」与倒计时
   通道现口径不符 → 补注「剪贴板倒计时最长 = COUNTDOWN_SECONDS 30s，
   仍为单件小面积」。
4. **P3（归入有意差异）**：剪贴板倒计时口径 15s → 30s（外部调整，非本次
   引入）；相关测试改为**常量无关断言**（动态读取起步值，验证逐秒递减与
   到期收束），口径再调整不再破测。
5. **独立审查结论**：A 渲染单点 / B 层级与 containing block / C 治理透传 /
   D 单写者纪律 / G 删除物残留 / H 死导入 = 全部无发现；E 身份不变式在
   shallowRef 后成立（其提出的 15→30 表述问题已按第 4 条处置）；F 两处 P3
   均非缺陷（PhotoAlbum 横幅为既有非 toast 元素复用立标；`.error-toast`
   `position: fixed !important` 冗余但无害、保留以守约束）。
6. **演进态复核（星野场底板）**：`--toast-surface`（tokens）与
   `toast-field-drift-far/near`（animations，仅 transform、平铺宽单源）
   定义齐备；reduced-motion 媒体查询已覆盖星野伪元素；提示脱离 `.glass`
   后 `.toast-*` / `.err-toast-*` 去 `!important` 成立（无 `transition: all`
   竞逐）；`isolation` + 星野 `z-index:-1` 的图层秩序正确（文字不被星点
   覆盖）；idle-* 透传使漂移动画随空闲治理暂停。
7. **已知既有特征（非本次引入；如需消除另立项）**：顶部
   error 与 exportDone、底部 status/copied/clip 同位并存时完全重叠
   （同一 24px 锚点）—— 需两条独立失败路径在 ≤2.6s 窗口内并发才可出现，
   属原实现既有行为。
8. **第二轮验证门**：`npx vue-tsc --noEmit` 0 错误；`npx vitest run`
   356 passed（30 文件，含新增 useClipToast 6 例）；4 个 CSS
   （components / tokens / animations / idle-governance）postcss 解析通过。
