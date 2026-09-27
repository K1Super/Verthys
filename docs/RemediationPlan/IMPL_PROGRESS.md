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
