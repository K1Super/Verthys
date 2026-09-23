# 缺陷修复工程进度记录（Remediation IMPL_PROGRESS）

> 本文件为 81 项缺陷修复工程的分批实施变更记录，随时更新，供中断后快速接手。
> 总纲与批次细则见本目录 `00_MASTER_PLAN.md` ~ `06_TEST_GATE_MATRIX.md`。
> 时间均为本机本地时间（Asia/Shanghai）。
> 编号（FIX-x-y、P1-x 等）仅存在于工程文档，按项目硬约束不得进入代码注释。

## 恢复指引（接手时先读这里）

- 当前进度：Wave 0 已由用户确认。Wave 1 存储完整性批、Wave 2 密钥卫生批
  **全部完成并已用户确认验收**。Wave 3 纵深防御批**全部完成**（用户已
  确认开工并裁决两项产品级决策：FIX-3-16 选 A 禁止空口令、FIX-3-7 选严格
  删除 5 个零调用命令）。已交付：A 片（FIX-3-1~3-4）、B 片（FIX-3-5）、
  C 片（FIX-3-6/3-7）、D 片（FIX-3-8~3-16）、E 片（FIX-3-17~3-21）、
  F 片 P3 卫生 8 项，w3gate 批次验证门全过（详见下文 Wave 3 节）。
  Wave 4 平台工程批**全部完成**：FIX-4-1~4-11（依赖快照门禁/CI 环境收敛/
  AST 双引擎红线门/clang-tidy/工具链钉版/文档与配置一致）+ C 核心 P3 卫生
  A 片 9 项 + B 片 4 项（partition grow 区域上限截断、format name 业务
  上限、WAL reset 半区序次收口等）+ w4gate 批次验证门全过 + 现行文档
  vcpkg 悬空引用与过期测试数清理（详见下文 Wave 4 节）。
  Wave 5 存储/事务子域修复批**全部完成**：存储引擎事务子域修复方案
  十项（Manifest 影子事务、nonce 追赶协议化、持久化写侧口径守卫、
  内部不变量断言、锁访问收敛、注释体积修正、三项权衡 ADR 化）
  + 三条红线不变量入 CONTRIBUTING 评审 Checklist + 5 个回归测试
  （w5gate 全绿：C 双配置 296/0）。代码注释零编号、零外部引用
  （详见下文 Wave 5 节）。
  Wave 6 V1/V2 残留系统化清理批**全部完成**：死代码删除 3 组（C 1 +
  Rust 2）、悬空注释改写约 20 处、活路径保留 5 类均附裁决证据，
  w6gate 全绿（C 双配置 296/0、src-tauri 314/0、worker 18/0、
  run_ci 45 基线 0 错误）（详见下文 Wave 6 节）。
  Wave 7 开发体验修复批**全部完成**：build_dev.ps1/build_production.ps1
  闪退修复（BOM 丢失致 PowerShell 5.1 乱码 ParseError，UTF-8 BOM 重写）；
  build_dev 构建树 1.27GB 测试沙箱残留清理（7 个死 pid 沙箱）；
  test_runner.c 死 pid 残留启动清扫（防复发）。w7gate 全绿（C 双配置
  296/0、清扫实测生效、run_ci 45 基线 0 错误 0 警告）（详见下文 Wave 7 节）。
  Wave 8（全局密钥落盘链路根治）+ Wave 8.1（评审收口）+ Wave 8.2
  （阀-闸门冲突根治）**全部完成**：状态推进后置到落盘确认、mtime
  启发式判据退役、changeGlobalKey 先新后旧收敛、评审五条收口；8.2
  起用户实测报错取证发现"数据域解锁态闸门"（仅 Unlocked 放行）拦截
  初始化全程（NoKey）的 add_record/get_record——存储动作下沉 worker
  新操作 derive_and_store_global_key（派生→收敛→写入→读回验证原子
  完成），derive 命令 gate 放宽 NoKey|Unlocked 修复 change 路径；
  回归测试前端 11 条 init/change + src-tauri 5 条，AST 基线
  key_controller 202→302、426→510 对齐（45 条总数不变，
  详见下文 Wave 8 / 8.1 / 8.2 节）。
  Wave 9 安全中枢防护全链路修复批**全部完成**：授权模型统一（废除无
  发放端的一次性令牌，改按密钥生命周期会话授权）、运行时切档贯通链路
  （security_apply_preset → worker switch_preset op → C 导出
  Verthys_SwitchSecurityPreset 双缓冲原子切档）、卡死防护（前端 IPC
  统一超时 + pending 复位兜底）、持久化加固（后端受信文件
  <verthys_path>.preset.json 单一事实源 + localStorage 迁移）、竞态
  仲裁（presetEpoch 版本号）与显示层单一事实源（档位标签按后端权威
  code 渲染、特性文案如实化、静态表与 C 层对齐）。w9gate 全过：
  C Debug 全量单测、src-tauri 321/0、worker 20/0、前端 61/61、
  run_ci 45 基线 0 错误 0 警告（详见下文 Wave 9 节）。
  Wave 10 卡死根源渲染层根治批**全部完成**：用户实测"一滑动/点击立刻
  全应用卡死"证据链收敛至 WebView2 渲染线程重绘风暴（非后端近因，
  卡死时段后端无新命令、噪声为 rAF 逐帧驱动 + filter/clip-path 重绘
  属性）。修复：mgmt-hub 六处 drop-shadow 半径随 --boost 逐帧变化 +
  will-change: filter 强制提升采样 → 全部静态化（能量增稠改由
  opacity/stroke-width 承接）；SecurityDashboard 拖拽从 pointermove
  同步 getBoundingClientRect + 直写 --posw 驱动 clip-path 改为
  pointerdown 一次性缓存布局 + tiltLoop 帧内合并写入；ManagementHub
  onPointerMove 布局缓存；dashboard.css 移除 clip-path/stroke-dashoffset
  will-change 强制提升；预设恢复链去双触发（onMounted 恢复移除，统一
  watch(globalKeyReadyRef, { immediate }) 单通道）。w10gate 全过：
  vue-tsc 0 错误、vitest 61/61、npm run build 通过（详见下文 Wave 10 节）。
  Wave 11 安全防护三档切换卡死根治批**全部完成**：按修复方案四批次
  落地——Batch 1 摘除 additionalBrowserArgs 三项 GPU 强制参数（保透明
  窗口，WebView2 回归自适应合成决策）；Batch 2 指针/触碰类唤醒分级
  （先 settling、持续活动 400ms 升温 active，keydown 维持即时满帧）+
  氛围类阈值迟滞（进入 25/75、退出 31/69）+ 拖拽期间氛围过渡冻结；
  Batch 3 --posw 亮层 2% 量化 + 30Hz 抽帧（α scaleX 路径留待设计
  评审）；Batch 4 移除 --js-flags 整段（1GB 堆上限与 --expose-gc 面
  移除）+ gc.ts 头注释事实校准。w11gate 四批次全过：vue-tsc 0 错误、
  vitest 61/61、npm run build 通过、src-tauri 321/0、worker 20/0、
  run_ci 45 基线 0 错误 0 警告（详见下文 Wave 11 节）。待用户实测
  验收矩阵后判定。
  Wave 12 点击/滑动全卡死同帧自旋根治批**全部完成**：根因分析报告六节
  方向四批次全量落地——Batch 1 契约层（MasterFrameLoop once 排空改帧快照
  splice(0) 截断 + once 任务 WeakMap 跨帧错误熔断（10 次 / 1000ms 冷却，
  冷却后自动恢复）+ 注释事实校准 + spec 3 用例）；Batch 2 调用层审计
  （全仓 once 自重排点有界性逐一核实，pointercancel 幂等与卸载断泵
  齐全，零改动）；Batch 3 次根因（删除 lib.rs WEBVIEW2_ADDITIONAL_
  BROWSER_ARGUMENTS 三项 GPU 强制参数注入 + CONFIGURATION.md 事实同步 +
  全仓注入点复查）；Batch 4 文档同步。w12gate 全过：vue-tsc 0 错误、
  vitest 64/64、npm run build 通过、src-tauri 321/0、worker 20/0、
  run_ci 45 基线 0 错误 0 警告（详见下文 Wave 12 节）。待用户实测
  验收后判定。
  Wave 13 安全防护面板体验与数据真实性整改批**全部完成**：五项核验
  全部落地——导航坞三态统一 hover 显示（不再自动弹出）；拖拽轨迹
  三项性能热点根治（扫掠弧过渡冻结/轨道渐变冻结/clip 过渡收敛）；
  三个百分比假数据全系替换为真实数据源（CPU 为 Rust GetSystemTimes
  差分采样命令 verthys_system_snapshot 2s 轮询，安全覆盖与综合评分
  为真实信号双权重纯函数合成）；切档进度道锚定目标档位位置
  （后端分阶段事件 security://preset-apply-progress + 切换路径废除
  乐观位移、失败回撤）；安全防护栏接入后端权威配置快照
  （CORE ACTIVE/DEGRADED 如实呈现）。w13gate 全过：vue-tsc 0 错误、
  vitest 71/71、npm run build 通过、src-tauri 325/0、clippy 0 告警、
  worker 20/0、run_ci 45 基线 0 错误 0 警告（详见下文 Wave 13 节）。
  Wave 14 安全防护细节体验整改批**全部完成**（按用户实测反馈三项）：
  ①音符条端点对齐 — 删除与端点锚重复的端桩双立杆，端点锚兼作左高
  右低终点桩（固定 22/11 高度，邻近仅亮色不拔高，端点与静态几何
  同一）；②切档进度能量条系统化删除 — 前端进度道模板/样式/状态/
  事件订阅/链路透传与 Rust 分阶段进度事件全量移除，切档改为友好
  toast 提示（开始"正在切换至…"/完成"已切换至…"），磁性吸附失败
  回撤语义保留；③呼吸效果系统化删除 — 安全防护与防御闭环
  圆点呼吸动画、错相延迟规则与 def-breath 关键帧全量移除，圆点
  改静态实心（cap-breath 关键帧仅保留给数据流转轨道运行状态位）。
  w14gate 全过：vue-tsc 0 错误、vitest 71/71、npm run build 通过、
  src-tauri 325/0、clippy 0 告警、worker 20/0、run_ci 45 基线
  0 错误 0 警告（详见下文 Wave 14 节）。
  Wave 15 切档落位交互时序整改批**全部完成**：松手越过相邻档中位后，
  游标先即时磁性落位到相邻档位（视觉先行，过渡动画即刻启动），
  随后延迟 220ms 且切换仍在进行中时才出"正在切换至…"toast，
  快速成功仅出完成提示；切档失败回撤语义保留（游标回齐后端权威
  档位，即时落位全程可逆）。w15gate 全过：vue-tsc 0 错误、
  vitest 71/71、npm run build 通过、run_ci 45 基线 0 错误 0 警告
  （详见下文 Wave 15 节）。
  Wave 16 进度链路文案与表现层防御整改批**全部完成**（P1→P2→P3）：
  P1 初始化链路 70% 文案时序校准（"校验密钥记录"→"确认密钥落盘"，
  读回校验实际已含于 20% 原子动作内）；P2 QuantumProgressFlow
  表现层 percent 钳制防御（0..100 收束 + NaN/Infinity 归零，宽度
  与 Meta 显示共用同一安全值）；P3 解锁链路双信号源核验收敛——
  核实经单调递增闸门 + 通道区间映射（8%~85%）+ 完成位守卫已收敛
  为单一输出，无需结构改动；另校准通道文案映射两处语义偏差
  （5% "读取索引"→"读取加密头"、50% "校验完整性"→"映射索引"）
  与表现层注释中 v1/v2 时期过时文案清单。w16gate 全过：vue-tsc
  0 错误、vitest 71/71、npm run build 通过、run_ci 45 基线
  0 错误 0 警告（详见下文 Wave 16 节）。
  Wave 17 提交按钮悬浮伸展收敛调参批**完成**：CosmicSubmit
  （解锁/初始化/验证视图提交按钮）悬浮伸展终点
  --cs-reach-hover 由 0.86 收敛至 0.74（两侧呼吸位 7%→13%），
  悬浮/焦点/按下三态由单一权威源联动派生，一处即全局；文件头
  与交互注释数值同步校准。w17gate 全过：npm run build 通过、
  run_ci 45 基线 0 错误 0 警告（详见下文 Wave 17 节）。
  Wave 18 面板头部英文小标题移除批**完成**：安全防护头部
  "CORE ACTIVE/DEGRADED" 与防御闭环头部 "RUNTIME" 两个英文小
  标题按用户裁定移除（模板 span 与对应 .cap-sub/.def-sub 样式、
  capSubText 计算属性全量清理，能力计数与圆点真实状态保留）。
  w18gate 全过：vue-tsc 0 错误、npm run build 通过、run_ci 45
  基线 0 错误 0 警告（详见下文 Wave 18 节）。
  Wave 19 运行状态行文字可读性整改批**完成**：数据流转轨道的
  运行状态行（"运行状态 · 直读装载 — …"）由等宽字体（无完整
  中文字形，中文落入回退字体造成中英混排双字体跳变）改为界面
  主字体、字号 9→10px、字距 0.22em→0.08em、对比度提升一档，
  消除"糊成一坨"观感。w19gate 全过：npm run build 通过、
  run_ci 45 基线 0 错误 0 警告（详见下文 Wave 19 节）。
  Wave 20 密钥弹窗待启用提示移除批**完成**：按用户裁定删除
  KeyEditDialog 内"保存密钥后将自动开启该模块的密钥保护；中途
  退出则保护保持关闭"提示条、未使用的 pendingEnable 属性与透传
  绑定，以及 .kv-info /.kv-info svg 专用样式；自动开启保护的后端
  行为链保持不动（仅移除提示展示）。w20gate 全过：vue-tsc
  0 错误、npm run build 通过、run_ci 45 基线 0 错误 0 警告
  （详见下文 Wave 20 节）。
  Wave 21 弹窗确认/取消按钮样式重构批**完成**：btn-primary 重构为
  「潮汐注能」（底部偏左势隙线待机呼吸 + 悬浮时势隙线先铺展、
  90ms 迟滞后不规则锯齿潮面升起、三段复合缓动 + 退落单一下潜的
  非对称往返、按下位移下沉顶替旧通用缩放），kv-cancel 重写为
  「静谧退潮风」（偏左疏引线弱能量退让侧），kv-confirm 保留紧凑
  体位修饰；VerthysDialog 与 FileVerthys 补挂统一 class（零行为
  变更）。反 AI 大众化约束全数落实：无粒子/波纹/辉光堆叠、非对称
  原点与留白、复合函数曲线组合、按压交互差异化；后经用户裁定
  叠加：按钮家族全域零阴影（悬浮/按压/激活均无投影，含 .btn
  通配、危险钮、确认删除钮、相册删除系列、窗口关闭钮）+ 禁用
  态 not-allowed 光标区分。w21gate 全过：
  vue-tsc 0 错误、vitest 71/71、npm run build 通过、run_ci 45
  基线 0 错误 0 警告（详见下文 Wave 21 节）。
  全部改动未提交 git，待用户评审（Wave 0~21 同批）。
- 验证命令：
  - C 层（项目根执行）：`powershell -ExecutionPolicy Bypass -File scripts\build_core.dev.ps1 -NoPause`
    ——构建 + verthys_tests.exe 全量测试一体；注意**红测试同样使脚本 exit 1**，
    判读须 grep 日志 `Summary`（勿把预期红误判为构建失败）；增量构建须用
    VS 自带 cmake 全路径（PATH 前置的 D:\Deps\CMake 4.4 会与缓存配置混载，
    详见"已失败且勿重试"）；跑测试前核对产物 mtime 晚于 core 源码 mtime
    （防过期产物假绿）；
  - 前端类型：`npx vue-tsc --noEmit`（0 错）
  - 前端单测：`npx vitest run`（71 用例全绿）
  - 前端构建：`npm run build`
  - Rust 测试：`cargo test`（src-tauri：325 通过；verthys-worker：20 通过，
    纯 bin crate 的测试位于 `#[cfg(test)] mod tests`）
  - Rust 静态：`cargo clippy --all-targets -- -D warnings`（两 crate 均 0 告警）
- 关键架构事实（Wave 0 后成立）：
  - 口令类命令（`verthys_unlock` / `verthys_verify_global_key` / `verthys_derive_global_key`）的服务端入口均接入暴力熔断闸门（fail-closed）；
  - 失败计数唯一权威在服务端（`security_commands/brute_force_bridge.rs`），前端所有计数调用已移除；
  - 认证域错误码常量 `AUTH_DOMAIN_ERROR = "ERR_00000002"` 定义于 bridge，两处控制器共用；
  - 前端 `securityBruteRecordFailure/Success` 封装已删除，仅保留 `securityBruteCheck` 纯查询。
- 关键架构事实（Wave 1 后成立）：
  - T0 结论：L3 worker 为单线程 stdin loop + `&mut worker` 独占借用（编译期不可重入），
    全仓无 FFI 并发线程访问 C 层——C API 已串行化，FIX-1-4 按纵深防御实施；
  - SSTable 写前预算：五写点（数据块 ×2 / Bloom / Index / Footer / Trailer）先预算后
    落盘，事后总量检查保留为第二道防线（`verthys_lsm_sstable.c`）；
  - 事务 DELETE 顺序纪律：墓碑先行（失败零副作用）→ 账本先于引用释放（回滚
    "多归还一次引用"只多不少，方向安全）；
  - WAL 双半区换区纪律：清零新半区数据区 → fsync → 写头，失败不切换 active_half；
    被换出半区数据保留（旧区转备份语义）；
  - 扫描读路径锁纪律：六游标接口（ScanOpen/ScanFetch/ScanSummaryOpen/
    ScanSummaryFetch/HasRecordByType/FindFirstLidByType）核心读全程持
    `api_mutex` 共享锁（锁内单出口），锁序恒为 `api_mutex → lsm 内部锁` 单向；
  - 暴力破解退避记账为进程级模块全局（`verthys_api_utils.c` 原子维护，三函数
    无参），跨句柄聚合、独立句柄不可绕过；容器创建成功不再清零退避计数。
- 关键架构事实（Wave 2 后成立）：
  - 敏感请求构造为类型化借用结构体（`&'a str` 字段 + `serde_json::to_string`
    直写 `Zeroizing<String>`），`json!` 宏弃用——宏对 `&str` 也产生 owned
    Value 拷贝且 Drop 不清零；unlock step3 无 flags 线格式经
    `Option<u32>` + `skip_serializing_if` 精确保持；
  - worker `Request` 六敏感字段（password/data/old_password/new_password/
    bin_data/bin_password）为 `Zeroizing<String>`，`#[serde(default)]` 依赖
    zeroize 1.9 derived Default；main_loop 行缓冲同 Zeroizing；
  - GMK 派生链中间量（binKey PRK / GMK PRK / okm）拷入 Zeroizing 后对
    extract 输出缓冲 volatile 清零；GMK 持有为 thread_local
    `Zeroizing<[u8;32]>`；
  - worker 批量扫描明文/摘要缓冲为 RAII 守卫（Drop 三轮覆写
    0x00→0xFF→0x00，提前 return 自动覆盖）；`SecuredString` 手动 Debug
    只暴露 len 与 `<REDACTED>`；
  - COMPILED 胡椒为编译期门控（CMake option 默认 OFF）；旧
    key_separation AEAD 实现与导出已删除，空明文语义统一。
- 已失败且勿重试的方案：
  - bridge 测试在默认配置下紧密循环 `record_failure`（速率限制 1000ms 会吞掉计数，测试必须 `rate_limit_ms: 0`）；
  - 测试名含大写英文（如 JSON）会触发 clippy `non-snake-case`（`-D warnings` 下必红）；
  - C 测试 CHECK 为"失败立即 return 1"：中途断言会跳过清理，泄漏的 FILE*/句柄将
    连坐后续测试（Windows 打开文件不可删除）——新测试一律"先完成操作与清理，
    再统一断言"模式，红态下也零残留；
  - 直接对 WAL 区域新建空文件跑 `verthys_wal_open` 会因读半区头越界失败
    （`vio_pread64` 对空文件 fread 0 字节判错）——测试须先 `vio_pwrite64`
    预扩展文件至 `VERTHYS_WAL_REGION_BYTES` 满幅；
  - FIX-1-3 红测试构造若用"cursor 预判循环"填充活动半区，触发换区的帧会误入
    下一圈打乱对齐——A 圈填充须用"active_half 翻转检测"（触发帧计入 B），
    只在 B 圈末尾用 cursor 预判（保证触发帧恰为第三圈同长首帧）；
  - 无锁扫描的红态表现为**病态挂起**（读写定位竞争下 90s+ 不完成，绿态数秒
    完成），而非错误计数——红态判据须含 watchdog 超时维度；
  - `git stash push -- <file>` 回退修复验证红态时，若仓库启用 autocrlf，pop 会
    因行尾假差异冲突——先 `git diff HEAD --stat -- <file>` 确认无实质差异，
    `git checkout -- <file>` 清行尾噪音后再 pop；
  - 本机无独立 ninja 安装，fuzz 构建须先把 VS 自带 Ninja 目录前置 PATH
    （`Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja`）；
  - 多线程测试内禁止 CHECK（立即 return 跳过 join/句柄清理，残留句柄连坐
    后续测试）——线程内只原子累计错误码，join 后统一断言（test_scan_concurrent
    为样板）；
  - PATH 前置的 D:\Deps\CMake（4.4）与 build 缓存配置用的 VS 自带 cmake-4.3
    混载：CMakeLists 变更触发再配置时报 "No preprocessor test for PellesC"
    且 configure incomplete——增量构建必须显式调用 VS 自带 cmake.exe 全路径；
  - 构建产物可能落后源码（Wave 2 门禁实证：产物 09/19 22:18 vs 源码
    09/21 14:10，旧产物跑出 257/0 假绿）——跑 C 测试前必须核对
    build 产物 mtime 晚于 core/src 与 core/tests 最新 mtime；
  - PowerShell 5.1 对无 BOM .ps1 按 ANSI/GBK 解码，中文注释乱码会直接
    ParseError（发生在任何代码执行前，try/catch 无效）——新建与 Edit
    工具改动过的 .ps1 必须用 Shell 重写 UTF-8 with BOM 头（EF BB BF）；
    Edit 后须复查首字节，本批 ci/refresh_dep_versions.ps1、ci/run_ci.ps1、
    根目录 build_dev.ps1/build_production.ps1（Wave 7 闪退事故）均因丢 BOM
    翻车过——项目内全部 6 个 .ps1 现均为 UTF-8 with BOM；
  - PowerShell EAP=Stop 下 cargo 的 stderr 进度行会包装为
    NativeCommandError 中途终止脚本——build/扫描桥段须临时
    EAP=Continue 包裹并按 $LASTEXITCODE 判定；
  - package-lock.json v3 的 entries 无 name 字段，解析依赖名须从 key
    提取 `k.split("node_modules/").pop()`；node -e 传参引号会被 PS
    再解析破坏，改用临时 .js 文件方案；
  - cargo metadata 会改写 Cargo.lock，构建脚本内禁止调用——[patch]
    生效性验证改用 Cargo.lock 文本断言（keyboard-types 条目无 source）；
  - ast_analyze（syn 2.0.119 + rustc 1.98.1）注意：
    `Span::start()/end()` 需 proc-macro2 显式开 `span-locations` feature；
    `Pat::span()` 需 `use syn::spanned::Spanned`；arm body 为 Box<Expr>；
    分隔行写 `"=".repeat(60)`（不可拆空格）。
  - C 测试断言不得用 CHECK_EQ 比较指针：该宏按 long 强转比较参数，
    x64 下触发 C4311 指针截断警告——指针断言一律 CHECK(p == NULL)；

## 进度条目

### 2026-09-20 Wave 0：止血批（代码与自动化门完成，待手工验收）

**范围**：FIX-0-1 ~ FIX-0-5 + 范围外同模式缺陷处置 + 5 处既有类型错误修复。

#### FIX-0-1 照片导出 IPC 协议错配（P0-1）

- 文件：`src/composables/photo-album/usePhotoExport.ts`
- 变更：`writeVencFile` 原以 JSON+`dataB64` 载荷调用 `write_user_file`，与命令签名
  （Raw body + `x-path` 头 + `encodeURIComponent`）不符，导出必现失败。改为
  `writeUserFile(path, bytes)`（`lib/verthys.ts` 既有正确封装），移除对
  `@tauri-apps/api/core` invoke 的直接依赖；`bytesToBase64` 保留供缩略图路径使用。
- 测试：新增 `usePhotoExport.spec.ts`（3 用例：路径/字节引用直传、无 base64 编码调用、异常上抛），全绿。

#### FIX-0-2 日志脱敏设施（P1-6 + P2-23 同模式）

- 新增 `src-tauri/src/util/log_sanitizer.rs`：`json_log_summary(json, keep_fields)`
  纯函数——合法 JSON 输出结构等价摘要（白名单仅限标量，嵌套递归脱敏），
  非 JSON 输出长度占位，绝不回显原文。util 层零日志权限（纯函数红线）。
- 接入 6 处日志点：`controller/actor.rs` 两处超时日志（原 `json: &str` 明文入日志）；
  `controller/key_controller.rs` 与 `controller/verthys_controller.rs` 各两处
  响应解析失败日志（原 `raw={}` 明文入日志）。
- 测试：5 个单测（敏感字段脱敏/非 JSON 长度占位/嵌套递归/结构化白名单/数组顶层）。

#### FIX-0-3 服务端强制暴力熔断（P1-7，含范围扩展）

- 新增 `src-tauri/src/security_commands/brute_force_bridge.rs`：
  `gate_check`（入口闸门，四态 Allowed/Locked/PurgeRequired/Unavailable，fail-closed）、
  `record_auth_failure`（认证域失败计数+持久化+审计）、
  `record_auth_success`（成功重置+持久化+审计）、
  `AUTH_DOMAIN_ERROR` 常量。桥接与命令版共享同一守卫与 DPAPI 持久化层。
- **范围扩展（执行中工程决策）**：原方案仅接 `verthys_unlock`；核验发现
  `verthys_verify_global_key` / `verthys_derive_global_key` 同为口令入口且仅前端计数
  （或无闸门），按"咽喉点强制"原则同批接入：
  - `verthys_unlock`（verthys_controller.rs）：入口闸门 + 认证域失败计数 + 成功重置；
  - `verthys_verify_global_key`（key_controller.rs）：入口闸门 + 认证域失败计数 + 成功重置
    （与既有进程内冷却并行：内存级快速反馈与持久化权威互补）；
  - `verthys_derive_global_key`（key_controller.rs）：仅入口闸门不计数——NoKey 态是
    首次设置新秘密，无既有秘密可暴破，派生失败若计数会误锁首次设置用户。
- **前端去计数（防双重计数）**：`key/global-verthys.ts` 的
  `verifyGlobalKeyWithBruteForce` 移除 `securityBruteRecordSuccess/Failure` 调用，
  失败态改用 `securityBruteCheck()` 纯查询映射锁定/清空；`initUnlock` 在
  verthys_unlock 前新增门禁预检（纯查询，避免锁定态进入 Argon2id 长运算）；
  `lib/verthys.ts` 删除两个计数封装（防未来误用恢复双重计数）；
  `session/security-session.ts` 清理失效 import 与过时注释。
- 计数判定纪律：仅 `ERR_00000002`（worker 统一化 AUTH 域）计失败；通信层失败、
  功能性状态码（CNG 不可用、超时等）不计数，防止非口令因素误锁正常用户。
- 测试：bridge 单测 1 项（禁用速率限制下连续失败必入锁定/清空态、成功重置恢复 Allow）。

#### FIX-0-4 log_fatal 命令注册（P1-10）

- 文件：`src-tauri/src/controller/diag_controller.rs`（命令已存在：16KB 上限 +
  UTF-8 边界截断 + `log::error!` 落盘）、`src-tauri/src/lib.rs`
  （generate_handler! 列表补登记）。
- 效果：前端致命错误上报通道恢复（原命令未注册，调用必现"未知命令"）。

#### FIX-0-5 README 合并冲突标记

- 文件：`README.md`。移除 `<<<<<<< HEAD` / `=======` / `>>>>>>>` 三段标记，
  修复过程误删的尾部闭合结构已补齐。

#### 附加修复：5 处既有类型错误（阻塞交付门）

- `ManagementHub.vue`：`gateDt` 未定义 → 改用同作用域 `wStep`（未钳制墙钟增量，
  与注释语义一致）；
- `ParticleBackground.vue`：`applyDprNow` 补 `scene` 空值守卫（`Scene | null` 收窄）；
- `useQuantumField.ts`：补 `lastWallClock` 声明（首帧守卫），并在 `start()`
  与 `applySize` 尺寸有效跃迁两处重置——循环重启/冻结恢复首帧 wStep=0，
  杜绝暂停期间累积的墙钟跳变。

#### 验证结果（自动化门全过）

| 门 | 命令 | 结果 |
|---|---|---|
| 前端类型 | `npx vue-tsc --noEmit` | 0 错误 |
| 前端单测 | `npx vitest run` | 26 通过（23 既有 + 3 新增） |
| 前端构建 | `npm run build` | 4.83s 成功 |
| Rust 测试 | `cargo test`（src-tauri） | 302 通过 / 0 失败 |
| Rust 测试 | `cargo test`（verthys-worker） | 0 测试（纯 bin crate，既有状态） |
| Rust 静态 | `cargo clippy --all-targets -- -D warnings`（两 crate） | 0 告警 |

#### 遗留项（不阻塞代码交付，需明示）

1. **三项手工验收待执行**（自动化无法覆盖，需 Tauri 运行时）：
   - Tauri 模式导出一张照片落盘成功；
   - 模拟 worker 不响应后，日志文件 grep 无口令明文；
   - 连续错误口令第 10 次后端返回 Locked（熔断闸门端到端实证）。
2. `cargo test` 构建期存在 1 条工具链级 `linker_messages` 警告（链接期产生，
   clippy check 阶段不出现，与本次改动无关，未治理）。
3. `npm audit` 5 条传递依赖告警（既有，与本次改动无关，Wave 4 依赖治理范围）。
4. 全部改动未提交 git，待用户评审。

### 2026-09-20 Wave 1：存储完整性批（FIX-1-1 ~ 1-3 完成，FIX-1-4 进行中）

**范围**：FIX-1-1 SSTable 写前预算、FIX-1-2 DELETE 先墓碑后账本+释放、
FIX-1-3 WAL 换区清零、FIX-1-4 扫描游标 SRW 共享锁、FIX-1-5 退避计数进程级聚合。
批次细则见 `02_WAVE1_STORAGE_INTEGRITY.md`。

#### T0 前置核查：L3 worker 调度是否串行化（结论：已串行化）

- 事实：`verthys-worker/src/runtime/main_loop.rs` 为单线程 `stdin.lock().lines()`
  循环 + `handle_request(&mut worker, &req)` 同步调用；`&mut` 独占借用为编译期
  不可重入保证；全仓无其他 FFI 并发线程（唯一额外线程是 C 层进度消费线程，
  只写 stdout）；src-tauri 无直接加载 verthys.dll 的并发路径。
- 结论：C API 单写者纪律在 L3 已成立，FIX-1-4 定位为纵深防御（C 层自保，
  直接使用 A API 的用户也安全），维持批次顺序实施。

#### FIX-1-1 SSTable 写前预算（越界字节不落盘）

- 文件：`core/src/index/lsm/verthys_lsm_sstable.c`
- 变更：新增静态函数 `sstable_budget_check(abs_cursor, write_len, data_end_abs)`
  ——写前预算（帧头+载荷+tag+帧尾 ≤ 数据区剩余），越界返回 RESOURCE_LIMIT；
  `blockbuilder_flush` 签名新增 `data_end_abs` 参数，函数体开头先预算再
  `verthys_lsm_frame_write`；`verthys_lsm_sstable_write` 五写点（两处数据块
  flush、Bloom、Index、Footer、Trailer）全部接入预算；原事后总量检查保留并
  注释更新为"容量复核（最终防线）"——双防线分工明确。
- 测试：新增 `core/tests/index/test_sstable_budget.c`（2 用例）：
  `sstb_budget_rejects_before_physical_write`（SSTB_TIGHT_LIMIT=64 逼迫首块越界，
  断言 RESOURCE_LIMIT、游标不回退、meta 不登记、边界后 512B 0xA5 哨兵完好）、
  `sstb_budget_normal_write_unaffected`（64KB 容量正常写 + find 读回 + 哨兵完好）。
  两用例均"先完成操作与清理、再统一断言"。已登记 `core/tests/CMakeLists.txt`
  与 `test_runner.c`（checkpoint "sstable_budget"）。
- 红绿证据：红 = 哨兵被覆写（越界写已物理发生），1 failed / 258 passed；
  绿 = 哨兵完好 + 全量 259 passed / 0 failed。

#### FIX-1-2 DELETE 先墓碑后 ledger+release

- 文件：`core/src/transaction/txn/verthys_transaction_v3.c`（`verthys_txn_v3_delete`）
- 变更：重排为 `lsm_get`（记 had_value）→ `lsm_delete` 墓碑先行（失败即零副作用
  返回）→ had_value 时 `txn_ledger_record(-1)` → `verthys_extent_release` → WAL
  append（与旧序"ledger→release→delete"相逆）。函数注释写明顺序纪律与安全方向
  论证：引用先于墓碑释放会在失败与回滚之间留"索引存活但引用已清零"的悬挂窗口
  （GC 误回收）；账本先于释放使 release 失败时回滚"多归还一次引用"——计数只多
  不少，空间泄漏换数据安全。
- 调用方核查：`verthys_api.c` 的 v3 delete / delete_many 均已"失败即 abort"，
  0 处重试语义，无需改动；回滚路径（`txn_ledger_apply_rollback` 净额反向 +
  `verthys_lsm_rollback_txid` 的 `memtable_rebuild_locked` 重建解冻）与重排兼容。
- 测试：新增 `core/tests/transaction/test_txn_delete_retry.c`（1 用例）：
  冻结活跃 memtable 注入（`verthys_lsm_memtable_freeze`，墓碑 WAL 帧已落盘、
  跳表插入被拒 = 确定性"删除半程"）→ 断言失败瞬间 refcount==1、账本 0 记账、
  lsm_get 仍存活 → 回滚复原（回滚后 rebuild 的 memtable 天然解冻，一次性注入）→
  新事务全链提交后 refcount==0、GetRecord NOTFOUND、账本弃置。登记 CMakeLists
  与 test_runner（checkpoint "txn_delete_retry"）。
- 红绿证据：红 = `ref_fail=0 ledger_fail=1 alive=1`（旧序损坏窗口），
  [txn-del-retry] obs 行留档，259 passed / 1 failed；绿 = `ref_fail=1
  ledger_fail=0` + 全量 260 passed / 0 failed。

#### FIX-1-3 WAL 换区先清零新区数据区

- 文件：`core/src/transaction/wal/verthys_wal.c`
- 变更：新增静态函数 `wal_clear_half_data(w, half)`——calloc 零缓冲单次
  `vio_pwrite64` 清目标半区数据区（半区尾前 480KB-24B）+ `wal_fsync`；
  `verthys_wal_append` 换区分支改为"清零+fsync → 写头 → 切换"序列，
  清零或写头失败直接返回、**不切换 active_half**（旧区保持活动可重试）。
  被换出半区数据保留（"旧区转备份"语义），`wal_foreach_frame` 扫描逻辑不动。
- 测试：扩展 `core/tests/transaction/test_txn_recovery_inject.c` 注入 4
  `inject_wal_third_round_residual_not_replayed`——三圈构造：A 圈首帧 53B BEGIN +
  4219B INDEX 大帧填充（active_half 翻转检测，触发帧计入 B）→ B 圈大帧 + 53B
  BEGIN 填至极限（cursor 预判）→ 第三圈 BEGIN（新 txid）触发换回 A，与第一圈
  首帧同长完整覆盖。close 模拟崩溃（只清内存态）→ 重开扫描 + replay 断言
  `frames_open == 1 + kb`（残留旧帧不得续链）、`torn == 0`、`discarded == kb + 1`。
  登记 test_runner（checkpoint "txn_inject" 内）。
- 红绿证据：红 = `ka=117 kb=155 frames_open=272 discarded=272`（旧帧链被完整
  续上回放），260 passed / 1 failed；绿 = `frames_open=156=1+kb torn=0` + 全量
  261 passed / 0 failed。

#### FIX-1-4 扫描游标接口加 SRW 共享锁（已完成）

- 文件：`core/src/api/scan/verthys_scan.c`
- 变更：六游标读接口全部接入 `api_mutex` 共享锁，每函数锁内单出口、
  Acquire/Release 严格对称、零嵌套（每函数最多一层锁）：
  1. `Verthys_ScanOpen`——锁覆盖 diag 原子计数（`InterlockedIncrement64`，
     共享锁下多 ScanOpen 并发计数不丢）+ 警告日志 + `scan_v3_open`
     （其内部解引用 `ctx->v3`，Lock 换实例 TOCTOU 消除）；
  2. `Verthys_ScanFetch`——前置校验/熔断检测在锁外，锁覆盖 `scan_v3_fetch`
     （Extent 解密 `verthys_extent_get` 的共享 FILE* 读取 + LSM 推进 +
     实例存活性检测），ctx 经 `cursor->v3_ctx` 防御性判空取锁；
  3. `Verthys_ScanSummaryOpen`——同 ScanOpen 模式（`scan_v3_open` 共用骨架）；
  4. `Verthys_ScanSummaryFetch`——同 ScanFetch 模式（锁覆盖元数据直读 +
     Extent 索引内存回查）；
  5. `Verthys_HasRecordByType` / 6. `Verthys_FindFirstLidByType`——独立加锁
     覆盖 `scan_v3_find_by_type`（两者不经 ScanFetch 复用实现，各持一层锁）。
- 锁层级核查（代码事实）：extent/lsm 层无反向获取 api_mutex 的路径；
  `verthys_lsm_scan_next` 内部持 `lsm->lock` 独占锁与外层 api_mutex 共享锁
  同向（写路径 api_mutex 独占 → lsm lock 同序），无死锁环；文件头辅助段
  注明 `api_mutex 共享锁纪律`（锁序单向 + 持锁区间禁获取 api_mutex）。
- 测试：新增 `core/tests/api/test_scan_concurrent.c`（1 用例，三线程拓扑：
  writer 循环 AddRecord 唯一记录 ×256 + reader 交替摘要/全量游标周期 +
  prober 循环按类型探测；线程内原子累计错误，join 后统一断言——写侧零失败、
  读侧零未预期错误码、零解密失败条目、计数一致 seed+writes、末条内容完整
  往返）。登记 CMakeLists 与 test_runner（checkpoint "scan_concurrent"）。
- 红绿证据：红 = 回退修复（git stash）后测试**病态挂起**——90s watchdog
  超时不结束，三次观测一致（最长一次 CPU 340s+ 未完成）；绿 = 修复在位
  `[ OK ] scan_concurrent_readers_vs_writer`，数秒完成。红态行为证明无锁
  竞争真实暴露（读写定位交错致病态交互），而非概率性偶发。

#### FIX-1-5 退避计数进程级聚合（已完成）

- 文件与变更：
  - `core/src/api/shared/verthys_api_utils.c/.h`——计数自 `VerthysContext`
    字段迁至模块级原子全局 `g_brute_failures` / `g_brute_last_fail_ms`
    （InterlockedIncrement64 / Exchange64 / CompareExchange64 维护，饱和
    封顶 32 防移位溢出）；三函数（`verthys_backoff_record_failure` /
    `verthys_backoff_reset` / `verthys_backoff_remaining_ms`）改无参一次改净；
  - `core/src/container/shared/verthys_internal.h`——`VerthysContext` 的
    `failed_attempts` / `last_failed_tick` 字段删除（Init 为 calloc 零初始化，
    无需改动）；
  - `core/src/api/lifecycle/verthys_api.c`——Unlock 成功 reset（L571）、AUTH
    失败记账（L587）、Unlock 入口门禁（L939，位于 Argon2id 之前快速拒绝）
    三处改无参调用；**CreateWithPreset 成功路径的 reset（原 L680）整体删除**
    ——安全决策：创建新容器不构成对既有容器口令知识的证明，保留该调用
    会让攻击者以"新建容器"无限重置进程级计数完全绕过指数退避（方向保守
    即更严格）；已核实无测试依赖创建重置语义；
  - `ctx_zero_sensitive` 注释同步更新（退避记账为进程级全局，与上下文
    生命周期无关）。
- 测试污染全量审计结论：verthys_tests.exe 单进程跑全部测试，进程级计数
  跨句柄持久——盘点全部 Unlock 调用点后确认仅 3 处既有测试会因 AUTH 残留
  计数被退避窗口破坏，均已加 `verthys_backoff_reset()` 修补：
  1. `test_verthys_export.c` `cp_then_unlock_new`（AUTH 后 Deinit → 下个
     `cp_wrong_old` 的 OK 解锁会被 RATE 拦截）；
  2. `test_txn_recovery_inject.c` `inject_sb_ciphertext_bitflip_rejected`
     （Unlock 结果接受 AUTH → 下个 `inject_taillog` 的 OK 解锁会被拦截）；
  3. `test_v3_lifecycle.c` `v3life_cp_old_password_rejected`（原注释
     "独立句柄规避退避冷却跨句柄污染"依赖旧 per-ctx 语义，进程级聚合后
     必破——同测试内 AUTH 断言后主动清零，函数头注释同步改写）。
  其余测试自含（以成功解锁收尾触发 571 行 reset）或失败路径不产生 AUTH
  记账，无需改动。
- 新测试：`core/tests/security/test_backoff_process_wide.c`（1 用例：
  句柄 A 错误口令 AUTH → 独立句柄 B 正确口令必须 RATE → 记账清零后 B
  正常解锁 OK；断言后置模式，开头防御性清零保证时序确定性）。登记
  CMakeLists 与 test_runner（checkpoint "backoff_process_wide"）。
- 红绿证据：红（per-ctx 旧实现）= `[FAIL] independent handle bypasses
  backoff: expect RATE, got 0`（got 0 = VERTHYS_OK，独立句柄成功绕过
  退避）；绿（进程级聚合）= backoff + 三组修补测试 6 passed / 0 failed。

#### 验证结果（Wave 1 最终）

| 门 | 命令 | 结果 |
|---|---|---|
| C 层构建+全量测试 | `build_core.dev.ps1` 构建 + `verthys_tests.exe` 全量 | **263 passed / 0 failed**（原 261 + scan_concurrent + backoff 两新增） |
| FIX-1-4 红证据 | 回退修复后跑 scan_concurrent | 90s watchdog 超时病态挂起 ×3 次观测（最长 CPU 340s+） |
| FIX-1-5 红证据 | per-ctx 实现下跑 backoff_process_wide | `expect RATE, got 0`（独立句柄绕过），0 passed / 1 failed |
| fuzz 构建 | `cmake -S . -B build_fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug -DVERTHYS_ENABLE_FUZZ=ON` | 构建通过（ASAN + fuzzer 全量插桩） |
| 5 fuzz 目标 smoke（含 fuzz_sstable 回归） | `ctest --test-dir build_fuzz -C Debug -R "fuzz_.*_smoke"` | **5/5 Passed**（superblock/partition/extent/sstable/import 各 -runs=2000） |

#### Wave 1 收尾交接清单

1. FIX-1-1 ~ FIX-1-5 全部完成，红→绿证据与验证表已补全（上文）；
2. 全部改动未提交 git，待用户评审（Wave 0/1 同批）；
3. 下一步：Wave 2 密钥卫生批（FIX-2-1 ~ FIX-2-10，T1 密钥流盘点先行），
   细则见 `02` 批次文档同目录 Wave 2 部分。

### 2026-09-21 Wave 2：密钥卫生批（FIX-2-1 ~ 2-10 全部完成，批次验证门通过）

**范围**：FIX-2-1 敏感请求零中间副本、FIX-2-2 扫描批量缓冲 RAII 擦除、
FIX-2-3 COMPILED 胡椒编译期门控、FIX-2-4 CNG key 失败清零 + 栈缓冲补零、
FIX-2-5 AES-GCM provider 生命周期锁化、FIX-2-6 rotate_mek 原子切换、
FIX-2-7 ULONG 溢出守卫、FIX-2-8 SecuredString Debug 脱敏、FIX-2-9 worker
敏感链全量 Zeroizing、FIX-2-10 旧 AEAD 下线。批次细则见 `03_WAVE2_SECRET_HYGIENE.md`。

#### T1 前置盘点（密钥流清单）

- COMPILED 胡椒存量判定 + `key_separation_aead_` 调用点清单，产出 FIX-2-3
  门控范围与 FIX-2-10 下线清单。

#### C 层（FIX-2-3 / 2-4 / 2-5 / 2-6 / 2-7 / 2-10）

- `core/src/crypto/cipher/verthys_crypto_cng.c/.h`——FIX-2-4（import_key
  失败清零调用方 key、三处 P3 栈缓冲补零）、FIX-2-5（provider open 路径
  SRWLOCK + state 化，refs 只做计数，deinit 互斥序列化）、FIX-2-7
  （size_t→ULONG 溢出守卫 + pt_len+TAG 减法形式判定，只修新 AEAD 路径）；
- `core/src/crypto/keymanager/keymanager_cng.c/.h`——FIX-2-6（rotate_mek
  先写临时槽验证后原子切换，失败旧槽不动）；
- FIX-2-3——COMPILED 胡椒编译期门控（CMake option，默认 OFF）；
  红→绿：门控路径 1 failed（证明拦截真实）→ 8/8 通过；
- FIX-2-10——旧 AEAD 实现与导出删除、测试重构、空明文语义统一；
- P3 栈缓冲补零另覆盖 `verthys_export_import.c` / `verthys_v3_lifecycle.c` /
  `verthys_unlock_pipeline.c`；
- 测试：`core/tests/crypto/test_cng_kernel.c` 新增 4 测试；C 全量
  **267 passed / 0 failed**（Wave 1 后 263 + 净增 4）。

#### Rust 层（FIX-2-1 / 2-2 / 2-8 / 2-9）

- FIX-2-1（`src-tauri/src/controller/key_controller.rs` +
  `verthys_controller.rs`）：
  - 弃用 `json!` 宏——宏对 `&str` 也经 `From<&str> for Value` 产生 owned
    拷贝且 Drop 不清零；新增类型化借用结构体（`DeriveGlobalKeyReq` /
    `VerifyGlobalKeyReq` / `UnlockReq` / `CreateWithPresetReq` /
    `PathPasswordReq` / `ChangePasswordReq` / `AddRecordReq`，`&'a str`
    字段），`serde_json::to_string` 直写 `Zeroizing<String>`，全程零中间
    副本；
  - `UnlockReq.flags: Option<u32>` + `skip_serializing_if`——unlock step3
    传 None 精确复现无 flags 线格式（worker 端 serde default=0 兼容）；
  - 发送后按各路径敏感集合显式 drop（req_str / password / bin_password /
    bin_data_b64 / record_b64）；`send_with_timeout` /
    `send_with_unlock_progress` 均为 `&str` 借用签名；
  - 行为等价性由既有测试覆盖（key_controller 15 项 + verthys_controller
    套件全绿）。
- FIX-2-2（`verthys-worker/src/runtime/worker.rs`）：`PlainBatchGuard` /
  `SummaryBatchGuard` RAII 守卫——Drop 三轮覆写（0x00→0xFF→0x00），`?`
  提前返回自动覆盖；`scrub()` 公开幂等 + `rows()` 只读切片视图；替换
  `fetch_into_shm` / `fetch_summary_into_shm` 两处手工零化循环。
  新增 3 测试（plain scrub 覆写 + 幂等 / summary scrub 覆写 name+merkle /
  rows 契约）；Drop 后内存已释放不可观测，改为直测 scrub() 效果，
  Drop→scrub 单行委托由审查保证（测试模块注释记录该决策）。
- FIX-2-8（`src-tauri/src/util/secured_string.rs`）：derive 行移除
  Debug，手动实现只暴露 `len` 与 `<REDACTED>`；全仓 `{:?}` 排查无敏感
  泄露点。新增 2 测试（明文不出现且含 REDACTED+len / 派生结构体场景
  同样脱敏）——红态可推演（derive Debug 时 `{:?}` 会输出明文内容）。
- FIX-2-9（`verthys-worker`：`runtime/protocol.rs` / `runtime/main_loop.rs` /
  `runtime/gmk.rs` + `Cargo.toml`）：
  - `Request` 六敏感字段（password/data/old_password/new_password/
    bin_data/bin_password）改 `Zeroizing<String>`，`#[serde(default)]`
    依赖 zeroize 1.9 derived Default（Cargo.toml 补 serde feature）；
  - main_loop 行缓冲 `Zeroizing::new(l)`（BOM strip 分支同构）；
  - GMK 派生链：binKey/GMK 的 PRK 经 `Hkdf::extract` 返回后拷入
    `Zeroizing<[u8;32]>` 并对原缓冲 `prk[..].zeroize()` volatile 清零；
    okm 同构；gmk_arr move 进 thread_local `Zeroizing` 无残留副本；
  - 新增 5 测试（make_request 辅助构造：roundtrip 124B record + 32B
    subkey / 错误口令拒绝 / 跨派生 record 拒绝 / 无 GMK LOCKED
    `ERR_00000007` / 子密钥确定性）——行为回归维度，等价性全绿。

#### 验证结果（Wave 2 最终）

| 门 | 命令 | 结果 |
|---|---|---|
| C 层全量 | VS 自带 cmake 重建 + `verthys_tests.exe` | **267 passed / 0 failed**（过期产物 257 不可信，见下文教训） |
| worker 测试 | `cargo test`（verthys-worker） | **8 passed / 0 failed**（3 守卫 + 5 gmk） |
| worker 静态 | `cargo clippy --all-targets` | 0 告警 |
| worker release | `cargo build --release` + exe 同步 `src-tauri/binaries/` | 完成（build.rs 三规则门禁全过） |
| src-tauri 测试 | `cargo test`（src-tauri） | **304 passed / 0 failed**（含 2 新 Debug 脱敏测试） |
| src-tauri 静态 | `cargo clippy --all-targets` | 0 告警（DLL 素材同步后复跑确认） |
| 前端类型+构建 | `npm run build`（vue-tsc --noEmit && vite build） | 0 错误，4.10s 成功 |
| 前端单测 | `npm run test`（vitest run） | **50 passed / 0 failed** |
| 打包素材 | DLL / worker exe 哈希 vs 最新构建产物 | 一致（DLL 082AC27E…） |

#### Wave 2 门禁重大教训（已固化到"恢复指引"）

1. **构建产物过期假绿**：门禁复跑时发现 build/core 产物（09/19 22:18）落后
   源码（09/21 14:10）两天——此前旧产物跑出的 257/0 为旧代码结果，非当前
   状态。重新构建后 267/0。判据：产物 mtime 必须晚于 core/src 与
   core/tests 最新 mtime，再跑测试。
2. **cmake 混载失败**：PATH 前置 D:\Deps\CMake 4.4 与缓存配置的 VS 自带
   cmake-4.3 在 CMakeLists 变更触发再配置时模块混载（"No preprocessor
   test for PellesC"）——增量构建必须显式用 VS 自带 cmake.exe 全路径。
3. **素材级联同步**：C 重建 → verthys.dll 变化 → 必须同步
   `src-tauri/verthys.dll` 并复跑 src-tauri clippy（dll_hash.rs 重新生成
   触发重编译），本批已按序完成且门禁干净。

#### Wave 2 收尾交接清单

1. FIX-2-1 ~ FIX-2-10 全部完成，批次验证门通过（上表）；
2. 全部改动未提交 git，待用户评审（Wave 0/1/2 同批）；
3. 下一步：Wave 3（进入前需用户确认验收），细则见批次文档。

### 2026-09-21 Wave 3：纵深防御批（已完成，全部改动待用户评审）

**范围**：FIX-3-1 ~ 3-21 + F 片 P3 卫生。细则见 `04_WAVE3_DEFENSE_DEPTH.md`。
用户已裁决：FIX-3-16 选 A（禁止空口令，旧数据无需兼容，可直接清除）；
FIX-3-7 选严格删除（命令与实现一并删除，仅保留有内部调用方的实现）。

**已完成分片（代码 + 测试 + clippy 门禁均绿）**：

- A 片 L3/IPC 输入边界：
  - FIX-3-1 枚举 max_count 双端 clamp（`MAX_ENUM_COUNT=5000`，dispatch 与
    worker fetch/open 全部经 clamp_enum_count，预分配与 FFI 传参同值）；
  - FIX-3-2 四处 CString::new unwrap → match 返回失败码 + 日志只记字节长度；
  - FIX-3-3 带限行读取 16MB：worker main_loop 与 src-tauri actor×3 + stderr
    全经 bounded_read_line（超限丢弃至行尾 + 协议错误断开；60 字节窗口
    stream 测试证明内存平稳）；
  - FIX-3-4 SHM 随机名/擦除改 getrandom CSPRNG，xorshift 删除。
  - 验证：worker 18 passed；src-tauri（当时）308 passed；双 clippy 0。
- B 片 FIX-3-5 FFI 边界三层：progress_cb 回调体 catch_unwind（panic 置
  进程级标记，绝不展开进 C）；worker 27 处 C 符号调用统一经 ffi_call 收口；
  panic hook 置位进程级标记 + 主循环每轮检测安全退出（log.rs PANIC_FLAG）。
  验证：worker 18 passed（含 ffi_call panic 注入测试）；clippy 0。
- C 片服务端授权闸门与死命令：
  - FIX-3-6 `require_unlocked` 统一闸门（KeyStateMismatch + 审计 Denied），
    接入 18 个数据域命令（verthys_controller 12 项：add/get/enumerate×2/
    delete×2/get_summary_count/has_record_by_type/export/import/
    change_password/flush；scan_controller 6 项：scan_open/next/close/
    summary_open/summary_next/summary_close）；状态策略纯函数拆分单测
    （NoKey/Locked 拒、Unlocked 放行、Lock 后再拒）；
  - FIX-3-7 严格删除：diag_info、verthys_scan_abort、verthys_scan_summary_abort、
    verthys_derive_subkey（含 validate_module_id helper 与 4 测试）、
    security_generate_auth_token（含 auth.rs generate/store、AuthTokenResult
    与 binding 文件）；worker 端 scan_abort/scan_summary_abort op 保留——
    scan_controller open 流程内部发该 op 回滚旧游标，属内部调用方；
    verify_and_consume_auth_token 保留（6 个已注册命令消费）。
  - 验证：src-tauri 311 passed / clippy 0。

- D 片第一组（FIX-3-8~3-10，已由子代理实施并按验收复核）：
  - FIX-3-8 export/import 路径纵深防御：`verthys_export_import.c` 新增
    `verthys_validate_transfer_path`（Windows），Export/Import 入口调用；
    拒绝字面 `.`/`..` 段、GetFullPathNameA 失败、落于 Windows/System32
    前缀（delimiter 边界比较）、FILE_FLAG_OPEN_REPARSE_POINT 重解析点；
    新增 `core/tests/api/test_export_path_guard.c` 4 用例（含临时目录不误拒），
    登记 CMakeLists + test_runner（checkpoint `export_path_guard`）；
  - FIX-3-9 defense_closure 全阻断语义：三条件齐备（failed==0 &&
    degraded==0 && blocked==DEFENSE_PATH_COUNT）；`has_degraded` 口径
    自洽未改；test_defense_closure.c 扩展两用例 + 修正旧用例断言（未解锁
    态含 DEGRADED → acb=0）；
  - FIX-3-10 anti_inject 线程基线白名单：`count_process_threads` →
    `count_external_threads`（逐线程查起始地址，本库模块内不计入），
    基线字段同步改名；`test_anti_inject.c` 3 用例（内部模块地址→不计入、
    ntdll 导出→计入、VirtualAlloc 未落模块→计入）。
  - 验证（已复核）：Release 重建 + 全量 **276 passed / 0 failed**（267+9）。
- D 片第二组（FIX-3-11~3-13）：
  - FIX-3-11 Deinit/Lock 有限等待：verthys_v3_lifecycle.c 与 progress 线程
    汇合改 `VERTHYS_JOIN_TIMEOUT_MS` 有界等待（超时/失败仅记诊断并继续
    收口，残存线程由进程退出回收；阻塞读取消点评估结论一并注释固化）；
    新增 `core/tests/api/test_join_bounded.c`（注入阻塞线程断言超时返回）。
  - FIX-3-12 integrity fail-open 改可观测：三类路径（通过/不匹配/基础
    设施异常未完成）显式区分，异常不得当通过；与 FIX-3-21 缓存重构合并
    实施（重算计数 `integrity_verify_recompute_count` 为测试白盒钩子）。
  - FIX-3-13 runtime_hash s_hbuf 并发保护：`runtime_hash_test_install`
    进入 `s_scanning` 单飞区（与 verify/overlay 写入路径同锁串行化），
    共享缓冲全部写入路径持同一临界区；并发 install+verify 测试绿。

- D 片第三组（FIX-3-14~3-16）：
  - FIX-3-14 system32_loader 分隔符边界：前缀比较改 `dir_prefix_matches`
    同款带边界比较（后随 `\0`/`\`/`/`），新增 `core/tests/security/
    test_system32_loader.c`（伪前缀 `System32Malware` 路径断言被拒）。
  - FIX-3-15 自动 rekey in-progress 互斥（含关键缺陷修复）：`km_get` 状态
    守卫放开 REKEYING（新旧句柄共存、旧句柄可读语义），`rotate_abc` 接受
    KERNEL_RESIDENT/REKEYING 双态入区并在成功路径收尾回 KERNEL_RESIDENT，
    `fail_committed` 恢复在途 `km->state`；删除 2 处临时 `[rekey-diag]`
    fprintf 与 rotate 前预恢复。修复前重包装在 REKEYING 态取不到
    old_key_a → CNG_UNAVAILABLE 连坐 6 个 arekey 用例（自锁缺陷），
    修复后全绿。
  - FIX-3-16 空口令显式拒绝（方案 A）：建库与解锁 `password_len==0`
    返 INVALID（api 守卫 + export/import 同款守卫），新增
    `api_empty_password` 测试。
- E 片存储边角（FIX-3-17~3-21）：
  - FIX-3-17 flush 后 memtable 重建失败 → 置只读（拒绝再写已持久化旧表），
    `v3lsm_flush_rebuild_fail_readonly` 绿；
  - FIX-3-18 close 失败 dirty 语义显式化：返回错误码 + 函数注释固化
    "返回错误必须 reopen-replay，不得当干净关闭"，WAL 完整重建测试绿；
  - FIX-3-19 superblock 读法定内容比对：agree 判定 = txid 一致 + 整结构
    `memcmp` 双条件，`v3sb_quorum_same_txid_divergent_content` 三场景
    （A/A/B、A/B/C、A/B+空槽）绿；
  - FIX-3-20 warmcache 段矩形完整校验：空段规范形 {0, ≠0} 拒绝、
    sst 下界无条件校验、两段不重叠；`v3ic_roundtrip_and_layout_fuzz`
    8 组非法布局判 miss 绿；
  - FIX-3-21 解锁自身验签缓存：卷序列号+文件索引+大小+mtime 指纹 +
    SRW 单飞锁（快路径共享锁回放 / 冷路径独占重算双检）+ `_open_osfhandle`
    +`_fdopen` 同句柄验签（无路径替换竞态）；测试用重算计数证据与
    SetFileTime 失效触发（确定性计数证据替代计时对比，防 CI 抖动）。
- F 片 P3 卫生 8 项：
  - crypto.rs hmac_sign 改 `Result<[u8;32],String>`，调用链
    audit_log/usb_guard/ipc_secure/background_patrol（同款 expect 一并
    清除）全收敛，零 expect；
  - shared_memory reader 区域矩形校验（name/data offset 必须完整落在
    各自区域），坏 offset 跳过不熔断；新增 3 测试（坏 name offset 跳过
    良记录接受 / data 越区跳过 / summary 同款）；
  - 句柄清理失败观测：`note_cleanup_failure`（debug 记录失败码，release
    与原 `let _=` 行为一致）；
  - enumerate 上界常量化：dispatch `MAX_ENUM_RECORDS=100_000` 与 C 端
    VERTHYS_V3IC_MEMTABLE_MAX_ENTRIES 对齐（全量枚举兜底终止）；
  - anti_inject TEB 偏移注释固化版本基线（Win10/11 x64/x86 快照）与
    失效降级语义（读取失败/漂移静默跳过、不报威胁，由其他闭环兜底）；
  - emergency 事件名加 CSPRNG 8 字节随机后缀（用毕 verthys_secure_zero），
    防预占/监听；全仓核验无 OpenEventW 等待方，随机后缀安全；
  - anti_debug_v2 硬件断点注释固化"入口点瞬时快照"语义边界（非持续
    监控，窗口风险由锚点校验与运行时哈希纵深兜底）；
  - dllmain DLL_PROCESS_DETACH 核查结论注释固化：调用链 =
    tls_loader_shutdown（空实现）+ verthys_pepper_deinit（VirtualUnlock +
    内存清零 + 标志赋值，无锁/无堆/无 CRT 依赖）→ 无需推迟到后台线程。

#### Wave 3 批次验证门（w3gate，全过）

| 门项 | 命令/证据 | 结果 |
|---|---|---|
| C 层全量 | Debug + Release 双配置 `verthys_tests.exe` | **291 passed / 0 failed** ×2 |
| worker 测试 | `cargo test`（verthys-worker） | **18 passed / 0 failed** |
| worker 静态 | `cargo clippy --all-targets -- -D warnings` | 0 告警 |
| src-tauri 测试 | `cargo test`（src-tauri） | **314 passed / 0 failed**（素材同步后复跑 2 次） |
| src-tauri 静态 | `cargo clippy --all-targets -- -D warnings` | 0 告警 |
| 前端类型+构建 | `npm run build`（vue-tsc --noEmit && vite build） | 0 错误，4.44s |
| 前端单测 | `npm run test`（vitest run） | **50 passed / 0 failed** |
| 恶意输入注入 | NUL 路径 / 超大 id / 100MB 超长行 / 符号链接 / 伪前缀用例 | 全在对应 FIX 测试内通过 |
| 命令契约 | generate_handler 与前端 invoke 双向 diff | 无孤儿（record_failure/success 为服务端权威计数保留面，Wave 1 已验收） |
| 打包素材 | build.rs 三规则（DLL 哈希 / worker exe 哈希 / 源码 mtime） | 全过（Release 重建 + .vsec 注入 + 素材同步后） |
| git 状态 | `git status` | 无构建产物泄漏；全部改动待评审 |

**w3gate 门禁教训（已固化到"恢复指引"）**：
1. **clippy redundant_pattern_matching**：`if let Err(_) = result` 在
   `-D warnings` 下必红（提示改 `is_err()`）——错误路径可观测代码必须
   写成 clippy 认可的形态；教训：任何新代码都要过双 clippy 门。
2. **素材级联同步（Wave 2 教训再验证）**：F 片 C 侧改动 → Release 重建
   （build_core.release.ps1 含 .vsec 与 .rhat 注入）→ 同步
   `src-tauri/verthys.dll`；F 片 worker 侧改动 → `cargo build --release`
   → 同步 `src-tauri/binaries/`。顺序颠倒会导致 build.rs 红。
3. **Release 配置测试**：Release（/O2）与 Debug 双配置同跑全量 291/0，
   避免"只在优化下暴露的未定义行为"漏检。

**Wave 3 关键交接事实**：
- 最终测试基线：C 层 **291 passed / 0 failed**（Debug 与 Release 双配置
  同验）；src-tauri **314 passed / 0 failed**；worker **18 passed /
  0 failed**；前端 vitest **50 passed / 0 failed**；双 clippy 0 告警。
- C 层增量构建必须用 VS 自带 cmake 全路径（见恢复指引"已失败且勿重试"），
  跑测试前核对产物 mtime 晚于 core/src 最新 mtime。
- 外部环境事实：worker.rs 的 call_delete_records 注释被外部修改为
  "C 层单事务逐条删除……整体回滚为 NOTFOUND"（保留，勿回退）；
  IMPL_PROGRESS.md 被外部追加"Rust 状态层 v2 死代码删除"段落（保留）。
- F 片 enumerate 上界项完成：dispatch `MAX_ENUM_RECORDS=100_000` 与
  C 端 VERTHYS_V3IC_MEMTABLE_MAX_ENTRIES 对齐常量化。

**Wave 3 收尾交接清单**：
1. FIX-3-1 ~ FIX-3-21 + F 片 P3 卫生 8 项全部完成，w3gate 批次验证门
   全过（上表），文档批次要求全部满足；
2. 打包素材已同步：`src-tauri/verthys.dll`（Release 重建 + .vsec 注入，
   哈希一致）与 `src-tauri/binaries/verthys-worker-*.exe`（release 重编译
   后同步），build.rs 三规则门禁全过；
3. 全部改动未提交 git，待用户评审（Wave 0/1/2/3 同批，257 个变更文件
   + 5 个新测试文件 + 1 个 FIX-3-7 删除的绑定文件）；
4. 命令行契约检查已手工通过（门禁第 4 条），Wave 4 引入脚本后可自动
   复验。

### 2026-09-21 附加清理：Rust 状态层 v2 死代码删除（container_id 绑定链）

**触发**：核查发现 verthys_state.rs 中 v2 超级块明文头布局注释及下方实现疑似
失效。经严格验证后确认整条 container_id 绑定链为 v2 残留、V3 格式下恒失效，
且其中 "VERT" magic 校验静默废掉主动修复路径。用户裁决：彻底删除。

**删除前证据链（核验）**：
- V3 主容器文件偏移 0 为副本帧头 'V3RP'（superblock_v3.c vsb_v3_write_replica
  put_u32le 帧头实证）；"VERT" 魔数现仅属于交换格式（verthys_format.c，
  Export/Import 契约），与主容器无关；
- read_container_id_from_header 对 V3 文件前 4 字节校验即失败，恒 None →
  状态文件 container_id 字段恒空；
- verify_container_id_match 恒 true → 比对分支永不触发；
- validate_verthys_magic（"VERT"）对 V3 恒 false，且为 try_repair_state_file
  第一步前置 → 主动修复全废。

**变更**：
- verthys_state.rs：删除 container_id 字段、read_container_id_from_header、
  verify_container_id_match、v2 布局注释与两常量；validate_verthys_magic
  替换为 validate_verthys_file（V3 帧头探测：'V3RP' + payload_len 边界，
  与 C 层副本读取前置校验同源）；状态提交日志移除 container_id 输出。
- verthys_controller.rs：移除 init_status 中 container_id 比对/重建分支，
  文档注释与 import 同步。
- audit_log.rs：ContainerIdMismatch 枚举变体**保留为历史审计数据反序列化
  兼容位**（注明不得写入新事件）——审计日志逐行 HMAC 链验证需字节级复原
  事件文本，删除变体会使含该事件的历史行反序列化失败、链验证误报篡改；
  产生路径已在 controller 移除。
- 新增 6 个单测：V3 帧接受 / "VERT" 拒绝 / 零载荷拒绝 / 超界载荷拒绝 /
  短文件拒绝 / 文件缺失拒绝。

**兼容性**：状态文件 JSON 无 deny_unknown_fields，旧状态文件残留
container_id 键被 serde 忽略；设备级绑定由 DPAPI device_binding_blob
继续保障。

**验证**：src-tauri `cargo test` 314 passed / 0 failed；`cargo clippy
--all-targets -- -D warnings` 通过（于本次改动后、Wave 3 并发编辑开始前实测）。
C 层未改动，不需重建。

**遗留待确认**：验证末段发现工作区存在并发 Wave 3 编辑（FIX-3-7 命令删除，
diag_controller/scan_controller 新近被改、lib.rs 注册表窗口期不同步），
该中间态与本次清理无关；批内门禁复跑须待 Wave 3 活动收敛后执行。

**追加（同日）**：worker 侧 v2 过时注释修正（纯注释/日志文案，未跑构建）：
- worker.rs `call_delete_records` 注释：删除 v2/vtxn_commit/重加密/全局 HMAC
  表述，改写为 V3 单事务收口语义（依据 verthys_api_v3_delete_many 实证）——
  函数本身调用链完整活跃，非死代码；
- ffi_types.rs `VerthysFindFirstLidByTypeFn` 绑定注释：原"v1/v2 遍历、绝不
  返回 FORMAT"与 worker.rs 既有注释矛盾，经 C 层 verthys_scan.c 实证
  （fmt!=V3 → FORMAT；V3 内未找到 → OK+found=0），按实证改写；
- dispatch.rs `probe_global_key` 日志文案去除"v1/v2 全遍历"过时表述。

### 2026-09-22 Wave 4：平台工程批（FIX-4-1 ~ 4-11 + C 核心 P3 卫生，全部完成）

#### FIX-4-1 依赖快照单源门禁
- 新建 `ci/refresh_dep_versions.ps1`（UTF-8 BOM）：解析两根 Cargo.lock 的
  `[[package]]`（正则）+ package-lock.json v3（node 临时文件解析），幂等生成
  `dep-versions.txt`（796 条目）；`rust-frontend.yml` 新增 "Dependency snapshot
  drift gate" step（refresh + `git diff --exit-code`），手动改版本不刷快照即门红。
- 重新生成 `dep-versions.txt`：serde_json 1.0.151 修正、valt-tauri→verthys-tauri、
  新增 npm 段。

#### FIX-4-2 MSVC 环境探测收敛
- `build_production.ps1` 0.5 阶段与 `build_dev.ps1` Step 0 注入环境探测：
  注入环境（VCToolsInstallDir+INCLUDE+LIB+cl.exe）优先 + Ninja 单配置；
  fallback env.load.ps1 + VS 多配置（-A x64 + --config Release）。
- CONTRIBUTING.md 环境准备补充探测顺序说明。

#### FIX-4-3 AST 双引擎红线门接入 CI
- `core.yml` 新增 ast-redline job；`ci/run_ci.ps1` Level2 传
  `--baseline ci/ast_baseline.txt`（存量豁免：key=`category|file|line`，
  `--write-baseline` 生成，新违规仍阻断）；ast_analyze 修 syn 2.0.119 编译错、
  加基线参数、锁 Cargo.lock；ci/ast_baseline.txt 45 条存量 ERROR 基线。
- 自举验证：探针 printf 变红 exit 1 → 删除恢复绿。
- w4gate 复查补修：Level1 python 探测原为 `python3 优先`——本机 python3
  命中 Windows Store 存根（Get-Command 命中但执行失败），全量 run_ci
  在第一级即崩。改为候选 `python/python3` 逐一实测 `--version` 退出码，
  不可用则显式跳过；另因 A 片在 pepper.c 插入注释块致 6 条基线行号漂移
  失配，按 `--write-baseline` 机制重写基线对齐（45 条数不变）。

#### FIX-4-4 clang-tidy 接入
- `core.yml` 新增 clang-tidy job；CMakeLists.txt 加
  `VERTHYS_ENABLE_CLANG_TIDY` option（find_program + CMAKE_C_CLANG_TIDY 注入，
  未找到时 WARNING 跳过）；.clang-tidy 注释路径 build_ninja→build_ci、
  补存量豁免表说明（ci/clang_tidy_baseline.txt）。

#### FIX-4-5/4-6 依赖安装与锁文件纪律
- build_production/build_dev 前端切换 `npm ci`；构建期 `cargo update` 移除，
  改为 Cargo.lock 只读文本断言（[patch] keyboard-types 无 source 条目）。
  全批次 NiWA 无写锁纪律：构建脚本零 cargo update/metadata。

#### FIX-4-7/4-8 工具链钉版与 CI 对齐
- 新建 rust-toolchain.toml（1.98.1、clippy+rustfmt、minimal）；两 workflow
  Setup Rust 改 `dtolnay/rust-toolchain@master`（读 rust-toolchain.toml）；
  CI Node 22→20；本地 @types/node ^26.0.1→^20.0.0（lock 到 20.19.43）；
  rust-frontend.yml 新增 local-script-smoke job（build_production.ps1 -SkipTauri）。

#### FIX-4-9/4-10/4-11 文档与配置一致性
- CONTRIBUTING.md 删除悬空 vcpkg.json 引用（改 Cargo.toml/package.json/
  dep-versions.txt 三真实来源）、PR 门补 rust-frontend.yml；
- tauri.conf.json CSP connect-src 删除 7778 两条目（全仓核验零连接代码）；
- error-handler.ts FATAL-IPC-FAIL console.error 用
  `/* javascript-obfuscator:disable */` 粒度豁免（产物验证该表达式完整保留）。

#### C 核心 P3 卫生 A 片（9 项）
- verthys_crypto.c argon2id pepper 分支长度加法溢出守卫；crypto.h
  verthys_random_bytes 熵失败 abort 语义注释；secure_allocator magic 语义
  注释 + region_release 改 void + VirtualFree 失败仅诊断 + destroy 无条件
  unaccount；rekey_auto 三收口路径栈缓冲 verthys_secure_zero 全清零；
  pepper 模块状态区 MT 纪律注释块 + save 路径 hardware_binding_get_hash
  失败直返（删除零 label 降级）；memory_guard s_regions_cs 改 INIT_ONCE
  一次性初始化 + patrol_callback 前置 DeleteTimerQueueTimer。

#### C 核心 P3 卫生 B 片（4 项）
- verthys_wal.c `verthys_wal_reset` 重写：删除全量 960KB calloc+pwrite 清零，
  改"清半区 0 数据区（复用 wal_clear_half_data）→ 写半区 0 新头
  （nseq=half_seq+1）→ 半区 1 头失活 pwrite → fsync"（注释固化崩溃序次
  安全语义：任一中间点重开的数据视图为 reset 前或后语义，无凭空丢失）；
- verthys_partition grow 加 `region_limit` 参数（区域终点绝对偏移）：
  最小需求越界 → VERTHYS_ERR_RESOURCE_LIMIT 且内存态不变；2x 目标越界 →
  截断于上限。头文件签名/注释、调用方
  `verthys_txn_v3_commit`（audit_partition_offset）、test_v3_partition
  三处既有调用 + 新增拒绝/截断用例同步；
- verthys_lsm.c scan_next 死变量 best_is_mem/best_sst 严格确认（只写不读，
  胜者选择直接维护 w/lid）后删除；tie-break 注释（同 lid 首见源胜出）保留；
- verthys_format name 业务上限：头文件加 VERTHYS_FMT_NAME_MAX_BYTES 4096，
  写两侧（vfmt_write/vfmt_write_streaming 布局计算前）与解析侧
  （vfmt_decrypt_records 索引条目解析）三处对称校验。

#### Wave 4 批次验证门（w4gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| C 层 Debug | scripts/build_core.dev.ps1 | **291 passed / 0 failed** |
| C 层 Release | VS cmake --build build_dev --config Release + verthys_tests.exe | **291 passed / 0 failed** |
| 生产 DLL | scripts/build_core.release.ps1（/O2 + .vsec/.rhat 注入） | 400.5KB，同步 src-tauri/verthys.dll 哈希一致 |
| src-tauri | cargo test / clippy --all-targets -- -D warnings | **314 passed / 0 failed** / 0 告警 |
| worker | cargo test | **18 passed / 0 failed** |
| 前端 | npm run build / npx vitest run | 3.98s / **50 passed** |
| 文档 | Grep vcpkg.json / 7778 / 冲突标记 | 现行文档全清（计划/审计档案按裁决保留） |

#### Wave 4 收尾交接清单
1. FIX-4-1~4-11 与 C 核心 A/B 片 P3 卫生全部完成，w4gate 全绿（见上表）；
2. 现行文档 vcpkg 悬空引用清理：README、docs/README、CODING_STANDARDS、
   THIRD_PARTY、GETTING_STARTED、DOCUMENTATION_CHECKLIST、RELEASE（历史
   审计 reports/audits/、ADR、RemediationPlan 计划文档按裁决保留）；
   过期测试数 250→291 修正（TESTING/RELEASE/GETTING_STARTED）；
3. 门禁教训已固化到"恢复指引"（BOM 编码、EAP=Continue、package-lock v3
   key 提取、cargo metadata 禁写锁、ast_analyze syn 2.0.119 注意点）；
4. 全部改动未提交 git，与 Wave 0/1/2/3 同批待用户评审验收。

### 2026-09-22 Wave 5：存储/事务子域修复批（S-001 ~ S-010 全部完成）

**范围**：docs/design/存储引擎事务子域修复方案.md 十项问题修复
（S-001~S-010）+ 三条红线不变量入评审 Checklist + 三项权衡 ADR 化。
问题编号仅存在于本工程文档，代码注释零编号、零外部引用（含标准
编号），修复描述一律改写为自包含的"行为/约束/设计意图"表述。

#### W5-1 Manifest 影子事务（S-001：严重）
- `verthys_lsm_compaction.c`：新增 ManifestShadowTxn（数组浅拷贝 +
  元数据 + removed_idx/removed_n）。compact 流程重排：先备份中间态
  → manifest_remove_inputs / 插入新表（仅动数组与元数据）→
  `verthys_lsm_manifest_save` 成功才释放被摘除表惰性缓存（经备份副本
  指针）；save 失败 goto fail_rollback 只恢复数组与元数据，零 release。
  修复根因：原实现 release/remove 先于备份，save 失败回滚丢失输入表。
- 本容器 SSTable 无独立数据文件（写在共享数据区），方案中
  "sstable_drop 拆删磁盘文件"不适用——孤儿表回收 = next_data_offset
  游标回退（失败轮落盘区沦为脏区，被下一轮覆写），注释已固化此语义。

#### W5-2 nonce 追赶协议化（S-002：严重）
- `verthys_crypto_cng.c/h`：新增公共解码函数
  `verthys_cng_nonce_decode_counter`（读 nonce[4..11] 大端，与
  encode_nonce 对偶）；文件头补"nonce 字节布局（公共契约，全仓
  一致）"段：12B nonce = counter 96 位大端编码、counter 位于
  nonce[4..11]、提取统一经公共函数、禁止各点自行解码。
- `verthys_wal.c`：帧 nonce 提取改用公共解码（修既有缺陷：旧实现
  读 nonce 前 8 字节 = counter>>32，丢失低 32 位 → restore 目标低估
  → nonce 重用）；open 路径 target 加 UINT64_MAX-MARGIN 溢出钳制。
- `verthys_transaction_v3.c`：recover 收尾新增追赶块——重放组与丢弃
  组的 EXTENT 帧均提取计数器（密文已落盘即 nonce 已消耗，孤儿块
  后续亦不得复用 nonce）；floor = max(盘面计数器, 重放最大帧计数器
  + VERTHYS_WAL_NONCE_RESTORE_MARGIN)，restore 防降序，一旦推进立即
  verthys_extent_index_save 固化（防收敛点与持久化点之间再崩溃回退）。
- `verthys_wal.h`：VERTHYS_WAL_NONCE_RESTORE_MARGIN 64→256，注释
  记录推导理由（覆盖崩溃点前后在途加密推进的保守上界）。
- 崩溃窗口语义在 wal.h 文件头规则 1-6 自包含（"规则 5"注释引用为
  代码内定义，非外部编号）。

#### W5-3/W5-4 持久化写侧口径守卫（S-003/S-004）
- 新建 `verthys_persist_guard.h`：VERTHYS_GUARD_U32 /
  VERTHYS_GUARD_U32_PLUS 宏（写路径禁止截断，失败统一返回
  VERTHYS_ERR_INVALID）。
- `verthys_extent.c` put：明文 + tag 之和守卫（补既有"只挡明文"的
  pt_len==UINT32_MAX 密文长溢出洞）。
- `verthys_format.c` vfmt_write / vfmt_write_streaming：data_size >
  UINT32_MAX 拒绝（手写 goto fail/stream_fail 分支，宏直返会跳过
  block_nonces 清理）。

#### W5-5 内部不变量断言（S-005）
- `verthys_internal.h` 新增 VERTHYS_INTERNAL_ASSERT 宏（Debug 打印
  出错点 + 按错误码中止；Release 静默同样中止，防御一致）；
- `verthys_lsm.c` flush 保存失败回滚：found 标志 + memmove 摘除 +
  INTERNAL_ASSERT(found) + 元数据回滚（next_seq/txid/
  next_data_offset），替代无条件 count--。

#### W5-6 锁访问收敛（S-006）
- `verthys_lsm_internal.h`：lsm_lock_shared/lsm_unlock_shared 内联
  入口 + #pragma warning(push/disable:4090/pop) 收敛 const 强转；
  verthys_lsm.c 三处只读 API（wal_cursor/max_lid/estimate_records）
  改经内联入口，锁配对所有无早退路径。

#### W5-7 注释体积修正（S-007）
- `verthys_wal.c` wal_group_deliver 栈记录注释改为"name 指向内联
  缓冲，占用随结构体声明而定"（sizeof 表达式语义，删原固定字节数
  表述——结构体布局变更时不再漂移）。

#### W5-8/9/10 三项权衡 ADR 化（S-008/S-009/S-010）
- 新建 docs/adr/ADR-001-wal-commit-append-failure.md（WAL COMMIT
  追加失败不收尾、引用计数只多不少 GC 收敛）、
  ADR-002-memtable-fail-readonly.md（MemTable 重建失败降级只读、
  WAL 帧重开幂等重放）、ADR-003-quorum-uncertainty-wal.md（法定
  人数不确定窗口由 WAL 恢复兜底、法定人数后即置 COMMITTED）。
- 按注释规范，ADR 链接不进代码注释；代码相应位置的权衡语义为
  自包含注释（如 commit 的"状态先行 COMMITTED——回滚通道永久
  关闭"），ADR 文档自身亦不引用外部方案编号。

#### W5-不变量 评审 Checklist 三条红线
- `CONTRIBUTING.md` 评审 Checklist 新增存储/事务子域红线：①破坏性
  操作前内存态 Manifest 必须持有完整可回滚快照、释放推迟到持久化
  成功之后；②nonce 恢复 floor = max(盘面值, 重放最大帧计数器 +
  裕量)，禁止回退；③持久化字段写侧携带与盘面类型一致上界校验、
  写路径禁止截断。

#### W5 回归测试（5 个新测试，291 → 296）
- test_v3_lsm.c：v3lsm_flush_manifest_save_fail_rollback /
  v3lsm_compact_manifest_save_fail_rollback（经新增非静态注入钩子
  verthys_lsm_test_fail_manifest_save，对象直链非导出面；覆盖
  flush/compact 提交失败回滚 + 复位重试 + 脏区覆写回收）；
- test_cng_kernel.c：cng_aead_nonce_decode_layout（手工矢量 +
  encrypt 输出 nonce 逐次精确对偶）；
- test_v3_extent.c：v3ext_put_size_guard_rejects（上限与截断临界两侧
  代表值 + 状态/出参不变）；
- test_verthys_format.c：format_data_size_guard_rejects（写侧拒绝，
  出参置空）。
- test_runner.c 声明 + RUN_TEST 注册 5 处。

#### Wave 5 批次验证门（w5gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| C 层 Debug | scripts/build_core.dev.ps1 | **296 passed / 0 failed** |
| C 层 Release | VS cmake --build build_dev --config Release + verthys_tests.exe | **296 passed / 0 failed** |
| 生产 DLL | scripts/build_core.release.ps1（/O2 + .vsec/.rhat 注入） | 400.5KB，同步 src-tauri/verthys.dll 哈希一致 |
| src-tauri | cargo test / clippy --all-targets -- -D warnings | **314 passed / 0 failed** / 0 告警 |
| worker | cargo test | **18 passed / 0 failed** |
| 前端 | npm run build / npx vitest run | 6.77s / **50 passed** |
| run_ci | AST 双引擎（45 条存量基线豁免） | 0 错误 0 警告，无新增违规 |
| 注释审计 | 本批变更文件黑名单词扫描（S-0x/方案/见/参考/依据/详见/来源/标准编号） | 全清（既有"S3/S4 阶段"为代码内枚举定义、合法） |

#### Wave 5 门禁教训（已固化到"恢复指引"）
- CHECK_EQ 宏对指针参数做 long 强转比较：x64 下触发 C4311 指针
  截断警告（`-W4` 可视）——指针相等断言一律用 CHECK(p == NULL)
  形式，禁用 CHECK_EQ(ptr, (type*)NULL)；
- 测试文件多处重复的收尾块（teardown+return 0）不能作 Edit 锚点，
  用文件尾唯一段落（如 load NULL 检查）做锚；
- TEST 声明区与 RUN_TEST 注册区含同名子串（`TEST(x);` 与
  `RUN_TEST(x)`），Edit 锚必须带相邻行唯一上下文。

#### Wave 5 收尾交接清单
1. S-001~S-010 十项修复 + 三 ADR + 三条不变量 + 5 回归测试全部
   完成，w5gate 全绿（见上表）；
2. 代码注释已按规范审计：本批变更文件零编号、零外部文档/标准
   引用；verthys_crypto_cng.h 既有"NIST SP 800-38D"标准编号按
   规范已删除引用片段（语义未变）；
3. 现行文档测试数 291→296 同步（TESTING/RELEASE/GETTING_STARTED）；
   TESTING.md 过时引用一并校正（CMakeLists 源文件数 37→39 与
   ":7-37/:80" 行号、test_runner argv 过滤行 333-355→400-428、
   CI 运行 C 测试引用 42-45→93-97、worker 段"未定义单元测试"→
   "18 个测试用例"）；rust-frontend.yml 头注释同步（src-tauri
   296→314、worker 编译验证→18 项；job 定义经核对确含 worker
   cargo test + 双 crate clippy 门禁）；
4. 全部改动未提交 git，与 Wave 0/1/2/3/4 同批待用户评审验收。

### 2026-09-22 Wave 6：V1/V2 残留系统性清理（死代码删除 + 悬空注释改写）

**范围**：全仓（core + src-tauri + worker）V1/V2/legacy 残留盘点 → 死代码
再三确认后删除 → 悬空引用注释按注释规范改写 → 全量门禁复验。

#### W6-1 删除死代码（3 组，均零引用且经交叉验证）
1. C：verthys_derive_integrity_key + VERTHYS_INTEGRITY_KEY_INFO 宏
   （verthys_crypto.c/h，V2 完整性密钥派生）。证据：全仓零调用方，
   现行路径为 keymanager_derive_integrity_key_v3（unlock pipeline /
   v3_lifecycle 3 处调用）；不在 .def 导出与 rhat 监控表。
2. Rust：STATE_LEGACY_MAGIC_V1 / STATE_LEGACY_VERSION_V1
   （src-tauri/constants.rs，含 re-export）。证据：编译器自带
   #[allow(dead_code)]（历史压制实锤）；迁移函数实际只校验
   STATE_MAGIC；MIGRATION.md 已裁决 v1 状态文件失效不迁移。
3. Rust：parse_config_legacy（src-tauri/middleware/context.rs，
   含"后续删除此方法"自注释）。证据：全仓零调用方、无测试引用。

#### W6-2 确认保留（非残留，防止误删）
- try_migrate_from_legacy_state：2.6.x 状态文件布局过渡（config 目录
  → 跟随 .verthys）活迁移路径，read_state_file 调用，仅接受新 magic
  且校验 V3 容器帧头，保留；
- device_fingerprint/binding_blob 二态判断：现行版本字段演进兼容，保留；
- anti_debug_v2 模块名：现行模块代际命名，活代码，保留；
- keymanager/keymanager_cng/wal 域分离注释（"与 V2/V1 标签严格隔离"）：
  安全设计活约束，保留；
- repair_v1_mac_offset_overflow：V3 拒绝 V1 风格头部正向回归，活测试，
  保留；flatcc 生成产物、WINTRUST_ACTION_GENERIC_VERIFY_V2（Windows
  API 常量）不动。

#### W6-3 悬空引用注释改写（约 20 处，全为引用已删符号/文件/行号）
- "删除清单"引用：verthys_api.c 头注释与 create/unlock 门禁注释、
  verthys_scan.c、warmcache_v3.h；
- "迁移自 v2/v2 lifecycle/vwarm_*"：v3_lifecycle.c/h、unlock_pipeline.c/h、
  export_import.c、warmcache 头；
- 已删符号/行号引用：verthys_api.c "v2_lifecycle L1249"、
  worker progress_cb.rs "verthys_v2_open_existing"→v3、
  "Verthys_MigrateV1ToV2 移出白名单"句删除；
- 测试注释历史对照：test_final_repair.c 验收墓碑块删除 + "原 V2
  vsb_txn"/"原 V2 单超块语义"对照改写为现状描述；
  test_format_fuzz.c "V2 版本号位于文件头 +4"对照句删除；
  test_runner.c 反调试测试墓碑行删除；
- "迁移自 key_separation.c"改为"与 key_separation.c 实现语义一致"
  （该文件现存 security/memory/）。

#### W6-4 顺带修复（验证门暴露）
- test_runtime_hash.c 3 处 `(HANDLE)_beginthreadex(...)` 强转在 x64
  触发 C4312 → 补 `<stdint.h>` + `(HANDLE)(uintptr_t)` 中间强转，
  零警告达标。

#### W6-5 文档同步
- MIGRATION.md 数据兼容声明：删除"STATE_LEGACY_MAGIC_V1（dead_code
  只读回退）"悬空表述，改为"新版不再识别旧版（v1）状态文件 magic，
  迁移校验 magic 不匹配即按全新用户处理"。
- ci/ast_baseline.txt：本批删除 verthys_scan.c 一行注释致基线
  verthys_scan.c|463 → |462 行号漂移，已核验为同一条 snprintf 诊断
  日志违规后手工对齐（45 条总数不变）。

#### Wave 6 批次验证门（w6gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| C 层 Debug / Release | dev 脚本 + VS cmake Release + verthys_tests.exe | **296 passed / 0 failed**，零警告 |
| 生产 DLL | build_core.release.ps1（.vsec/.rhat 注入） | 400.5KB，同步 src-tauri/verthys.dll 哈希一致 |
| src-tauri | cargo test / clippy -D warnings | **314 passed** / 0 告警 |
| worker | cargo test / clippy -D warnings；release 重建 + 素材同步 | **18 passed** / 0 告警 / 哈希一致 |
| run_ci | AST 双引擎（45 条存量基线） | 0 错误 0 警告 |

#### Wave 6 收尾交接清单
1. 死代码删除 3 组（C 1 + Rust 2）、悬空注释改写约 20 处、保留项
   均为附证据裁决，w6gate 全绿；
2. 全部改动未提交 git，与 Wave 0~5 同批待用户评审验收。

### 2026-09-22 Wave 7：开发体验修复批（dev 脚本闪退 + 构建树 1.27GB 残留治理）

起因：用户报告 build_dev.ps1 双击/运行闪退；随后发现 build_dev
构建目录 1.3GB+ 体积异常。

#### W7-1 dev 脚本闪退根因与修复（BOM 丢失）
- 现象：build_dev.ps1 运行窗口一闪而过，零输出。
- 根因：两个根目录脚本均无 UTF-8 BOM（首字节实测 `23 20 56` /
  `23 20 62`），PowerShell 5.1 对无 BOM .ps1 按 ANSI/GBK 解码，脚本内
  中文注释/字符串字节错位成乱码，破坏双引号/大括号配对——Parser 实测
  build_dev.ps1 报 line 41 MissingEndCurlyBrace、build_production.ps1
  报 20+ 处结构错误。ParseError 发生在任何代码执行前，try/catch
  与 Read-Host 全部失效，故无任何输出即退出（闪退）。
  build_production.ps1 文件头注释本就声明"必须保存为 UTF-8 with BOM
  编码（确认文件头 3 字节为 EF BB BF）"——BOM 系此前编辑丢失。
- 修复：两脚本以 UTF-8 with BOM 重写（内容零改动，仅补 EF BB BF），
  Parser 复验 PARSE OK；build_dev.ps1 实测运行至 Tauri dev 启动
  全部步骤输出正常（cl.exe/MSVC 环境、进程与端口检查、依赖校验、
  pre-flight 均绿）。
- 教训固化（恢复指引既有条目扩展）：项目根 .ps1 与 scripts/ 下脚本
  同等受 BOM 硬约束；改动 .ps1 后必须复验首 3 字节 EF BB BF +
  Parser 语法，两者任一失败即闪退。

#### W7-2 build_dev 测试沙箱残留清理（1.27 GB）
- 现场：build_dev 1,339 MB，大头 tests/Debug 下 7 个
  test_scratch_<pid> 目录，各含 1 个 181 MB 的 .verthys 容器文件
  （扫描/重密钥类用例的大容器预分配），合计 1,267 MB。
- 根因链：test_runner.c 沙箱清理挂 atexit（正常 exit 才执行），
  测试被中断/硬崩溃时跳过；且启动仅清"同 pid"目录，历史死 pid
  残留永不回收。原设计注释寄望"-Clean/构建目录删除"兜底，但
  build_dev 长期存续时残留无限累积，违背空间管控红线。
- 处置：逐一核验 7 个 pid（11536/13784/13820/4340/6552/6948/992）
  进程均已不存在后整目录删除——纯测试临时文件，无用户数据可能。
  清理后 build_dev 计 72.7 MB（回落 94.6%）。

#### W7-3 test_runner.c 死 pid 残留启动清扫（防复发）
- 新增 scratch_sweep_stale(exe_dir)：建沙箱前枚举 exe 目录下
  test_scratch_<pid> 前缀目录，解析 pid 后缀后 OpenProcess(SYNCHRONIZE)
  判活：
  - 可打开 = 进程存活（含并发运行的另一测试进程）→ 跳过不碰；
  - 失败且 GetLastError()==ERROR_INVALID_PARAMETER = 进程已死 → 整删；
  - 其余失败 = 存活状态无法判定 → 保守跳过（宁残留不误删活跃沙箱）；
  - 名字非纯 pid 后缀格式 → 一律跳过（非本机制产物不碰）。
- 沙箱设计段注释同步：崩溃残留由下次运行启动清扫回收，残留最多暂留
  到下一次测试运行，不随运行次数无限累积。
- 实测（Debug）：构造假死 pid 沙箱 test_scratch_999999 后运行 →
  `swept stale scratch` 回收成功；并发双实例（前后台各一）→ 前台的
  清扫未触碰后台活跃沙箱；正常退出仍 `test scratch dir cleaned`。

#### Wave 7 批次验证门（w7gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| C 层 Debug | build_core.dev.ps1 + verthys_tests.exe（含并发双实例） | **296 passed / 0 failed** |
| C 层 Release | VS cmake Release + verthys_tests.exe（连跑 x3） | **296 passed / 0 failed** |
| 清扫实测 | 假死 pid 沙箱回收 / 并发活跃沙箱不误删 | swept 生效 / 零误删 |
| run_ci | AST 双引擎（45 条存量基线） | 0 错误 0 警告 |

#### Wave 7 收尾交接清单
1. 双脚本 BOM 修复 + 构建树 1.27GB 残留清理 + 沙箱防复发启动清扫，
   w7gate 全绿；Release 构建后首次直跑出现一次无输出 exit 1（exe 刚
   补丁完毕的瞬态，复跑 x3 均 296/0），未复现，不阻断；
2. 全部改动未提交 git，与 Wave 0~6 同批待用户评审验收。

### 2026-09-22 Wave 8：全局密钥落盘链路根治（状态死锁 + 判据误报 + 修改中间态）

起因：用户报告"全局密钥落地失败，无法新建密钥和验证"。全链路
取证（前端 → Rust controller → worker → C V3 单调用事务）后定位
三处缺陷：① 派生成功即转 Locked 与记录落盘解耦，落盘失败不回滚
状态 → 同会话死锁（derive 要求 NoKey 被拒、verify 磁盘无记录）；
② 磁盘校验以"文件 mtime 在 15s 内"为核心判据，flush 队列积压或
时钟回拨即恒失败且重试不可自愈（V3 的 AddRecord 已 WAL 逐帧
_commit + 超块法定人数即时落盘，flush 常为 no-op 不推进 mtime）；
③ changeGlobalKey 先删旧后 flush，失败时旧记录已删、新记录未落盘。

#### W8-1 状态机与磁盘事实强一致（根治①）
- key_controller.rs：derive 成功的 resp.ok 分支不再立即
  transition_to_locked——状态推进改由前端"记录写入 + 读回验证"成功
  后经 verthys_reconcile_key_presence(true) 驱动；注释同步写明
  时序契约。
- initGlobalKey 重写：派生 → AddRecord → **内容级读回验证**
  （GetRecord 读回 == 写入值，V3 事务即时落盘下等价于落盘证据）→
  reconcile(true) 推进 Locked。任一环节失败统一补偿：删半成品记录
  + verthysClearGlobalKey + reconcile(false) 复位 NoKey，用户可
  立即重试。
- 兜底 flush 降级为 LSM 归并优化：失败仅 warn 不判错（记录落盘已由
  读回验证确认），根除 flush 误报导致的假"落盘失败"。

#### W8-2 磁盘校验判据重构（根治②）
- verthys_controller.rs verify_disk_persist_blocking：删除"mtime
  15s 时效"与"mtime 在未来即失败"两处硬判定；保留结构校验
  （存在/大小/V3RP 帧头/payload_len/64KB 边界/记录数弱告警），
  定位统一为 doFlush 的磁盘侧结构兜底而非落盘新鲜度证明；
  doc 注释附判据退役注记（不引外部编号）。

#### W8-3 修改全局密钥确定性收敛（根治③）
- changeGlobalKey 重写：验证旧密钥 → **记录收敛**（枚举清除任一
  残留 global-key 记录，恒单条）→ 派生 + 写新记录 + 读回验证 →
  删旧记录 + 读回验证删除 → 兜底 flush（失败不阻断）。
- 任一步骤失败统一补偿：回收新记录 + 清 GMK（Unlocked→Locked），
  磁盘收敛回"仅旧记录"，用户以旧密钥重新验证即可重试；未预期
  异常外层统一补偿。派生失败也走补偿（GMK 不确定即清零，保证
  重试路径可用）。

#### Wave 8 批次验证门（w8gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | **50/50 通过** |
| 前端构建 | npm run build | 成功 |
| src-tauri | cargo test / cargo clippy --all-targets -- -D warnings | **314 passed** / 0 告警 |
| run_ci | AST 双引擎 | 0 错误 0 警告（45 条存量豁免，key_controller.rs:431→426 行号对齐） |

#### Wave 8 收尾交接清单
1. 三缺陷根治落地（状态死锁/判据误报/修改中间态），重要语义收敛：
   init 流程的状态推进后置到落盘确认之后、change 失败统一补偿回
   旧记录态、磁盘校验不再以 mtime 判落盘；C 核心/worker 零改动；
2. 全部改动未提交 git，与 Wave 0~7 同批待用户评审验收。

### 2026-09-22 Wave 8.1：Wave 8 评审收口（五条收口 + 三观察 + 初始化进度条）

起因：用户对 Wave 8 给出评审意见——方向正确、根因抓准，但存在一个
回归风险（重入互斥丢失）、一个未验证核心假设（读回编码契约）、三个
质量项（补偿失败无兜底、回归测试缺口、R3 影响面未评估），并要求密钥
初始化复用现有进度条（页面怪异现象）。本节逐条落定。

#### W81-1 重入互斥丢失（评审阻塞项，回归修复）
- 背景：状态推进后置使 derive 成功到 reconcile(true) 之间后端恒为
  NoKey，重复 derive 不再被状态机天然拦截；并发 initGlobalKey 会
  两次派生（GMK 后写覆盖）+ 两次 AddRecord（磁盘两条记录）→
  findGlobalKeyRecord 取 lid 最小条而其 verifier 对应第一次 GMK，
  与 worker 内存不符，verify 必然失败。
- 修复：global-verthys.ts 模块级 `keyOpInFlight` 互斥（initGlobalKey
  与 changeGlobalKey 共享，外层锁 + inner 编排主体），in-flight 时
  以 E_VERTHYS_NOT_READY 拒绝。UI 层 useGlobalKey.onInitKey 已有
  processing 守卫，双层防护。
- 验证：spec 覆盖派生 in-flight 期间二次调用被拒且首调用正常完成。

#### W81-2 读回比较编码契约（评审阻塞项，证据固化）
- 契约内容：`readBack.dataB64 === recordB64` 成立的前提是 C 层
  GetRecord 与 AddRecord 写入值逐字节等价（不重编码/补位/截断）。
- 证据组合（三层）：
  1. worker 侧 protocol.rs 新增 2 条测试——base64 编解码幂等
     （空/1/2/3/4/7/10/124 字节样本：无换行、decode(encode(x))==x、
     encode(decode(enc))==enc）与 CR/LF 容错；
  2. C 层既有测试（test_v3_lifecycle / test_v3_property）已覆盖
     AddRecord→GetRecord 字节 roundtrip（V3 单调用事务写读一致）；
  3. 前端 spec 读回一致/不一致两分支断言，锁死"不一致即补偿"行为。
- 结论：契约成立，init 不会恒走补偿分支。

#### W81-3 补偿动作失败兜底（评审质量项）
- 前端 ipcRetry：补偿链内删除/清零/复位动作 2 次重试；
- 后端新增 `verthys_reset_global_key_state` 命令（key_controller.rs +
  key_lifecycle.rs `force_reset_no_key` + lib.rs 注册）：best-effort
  清 GMK + 状态机任何状态幂等强制回 NoKey、失败计数与冷却清零。
  补偿动作连续失败时由前端调用，杜绝"删旧成功、clear 失败"残留
  Unlocked+磁盘旧记录的不可达状态；任何状态下调用均幂等成功。
- 验证：src-tauri 全量测试无回归（新命令注册通过 compile + clippy）。

#### W81-4 三条修复路径回归测试（评审质量项）
- Rust（verthys_controller.rs tests 模块新增 5 条）：
  verify_disk_persist_blocking 的 mtime 无关性回归——合法 64KB V3
  容器（V3RP 帧头）mtime 改陈旧 1h / 未来 1h 仍 Ok；结构破坏
  （魔数错/payload_len 越界/超级块区截断）仍 Err。
- 前端（src/key/global-verthys.spec.ts 新增 12 条）：init 成功推进、
  AddRecord 失败、读回不一致、reconcile 失败、补偿自身失败强制复位、
  重入锁；change 先新后旧成功、旧密钥验证失败拦截、删旧失败回滚、
  derive 失败补偿、残留记录收敛、未预期异常兜底。
- 既有 worker 测试 18→20（base64 两条）。

#### W81-5 R3 影响面评估（评审质量项，显式记录）
- 退役后 verify_disk_persist 仅剩结构校验，`doFlush` 路径的"确实
  写盘"信号一并消失。可接受性依赖以下 C 层契约，必须持续成立：
  1. V3 AddRecord/DeleteRecord 为单调用事务：WAL 逐帧 `_commit`(fsync)
     + 超块法定人数即时落盘（flushed 即持久）；
  2. 重启/异常后 WAL 可重放（下次 open 重放未提交帧），MemTable
     数据不唯一驻留；
  3. flush 的 LSM 归并失败由 WAL 副本兜底，恢复可重放。
- 边界声明：将来若新增"仅写 MemTable 且无 WAL 帧"的路径，本结构
  校验将静默漏判该路径的落盘失败——新增此类路径时必须同时补齐
  其持久化确认手段，否则不得通过评审。

#### W81-次要 1 GMK re-wrap 查证（评审观察项）
- 查证结论：`derive_module_subkey` 当前零前端/主进程调用方（模块
  密钥经独立 record 存储），GMK 不包裹持久数据，changeGlobalKey
  换 GMK 无需 re-wrap，无数据风险缺口。
- 边界声明：未来接入 module_subkey 派生链时，changeGlobalKey 必须
  补充子密钥/数据的 re-wrap 步骤，现有实现不覆盖该场景。

#### W81-次要 2 收敛扫描读取面（评审观察项）
- changeGlobalKey 收敛由 enumerate 全量解密改为 verthysScanSummary
  游标（仅取索引元数据不解密数据块，512/批），收敛不扩大敏感
  数据读取面、库大时不卡顿；游标异常降级为跳过收敛（不影响主路径）。

#### W81-次要 3 密钥初始化进度条（用户要求，复用三层解耦）
- 信号层：initGlobalKey 新增 onProgress 回调，五阶段 emit
  （8/20/50/70/88：准备派生/派生/写记录/校验记录/推进状态）；
- 感知层：useGlobalKey.onInitKey 改用既有 verifyRhythm
  （start/pushRealProgress/seal/halt/waitForComplete/waitForHaltMin），
  与验证视图同一节奏引擎；成功 seal 收束后清表单，失败 halt 降级；
- 呈现层：InitKeyView.vue 的 QuantumCoreLoader 替换为
  QuantumProgressFlow（与 VerifyView 同款组件），SecurityCenter.vue
  补 progress/msg/dimmed 三绑定。视觉与交互同验证流，消除"无进度条
  怪异现象"。

#### Wave 8.1 批次验证门（w81gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | **62/62 通过**（原 50 + 12 新增） |
| 前端构建 | npm run build | 成功 |
| src-tauri | cargo test / cargo clippy --all-targets -- -D warnings | **319 passed**（原 314 + 5 新增）/ 0 告警 |
| worker | cargo test | **20 passed**（原 18 + 2 新增） |
| run_ci | AST 双引擎 + C 双配置 296/0 | 0 错误 0 警告（45 条存量豁免，key_controller.rs:426 对齐维持） |

#### Wave 8.1 收尾交接清单
1. 评审五条收口全部落地：两个阻塞项（重入互斥/读回契约）修复并
   测试固化，三个质量项（补偿兜底/回归测试/R3 影响面记录）完成；
2. 密钥初始化进度条复用验证节奏三层解耦，InitKeyView 与 VerifyView
   呈现同款；
3. 全部改动未提交 git，与 Wave 0~8 同批待用户评审验收。

### 2026-09-22 Wave 8.2：数据域闸门冲突根治（用户实测"全局密钥落盘失败"取证）

起因：用户实测运行报"全局密钥落盘失败，请重试"。日志取证定位
关键时序：derive 成功（NoKey）→ `add_record 被解锁态闸门拒绝：当前
NoKey`。`verthys_add_record` / `get_record` / `delete_record` /
`flush` 命令均受"数据域统一解锁态闸门"（仅 Unlocked 放行）保护——
全局密钥初始化全程状态机为 NoKey（Wave 8 后派生不再抢先转 Locked），
写密钥记录恒被拒绝：旧代码（derive 即 Locked）被 Locked 拒、新代码
被 NoKey 拒，**无论时序怎么排都写不进**。同时确认 derive 命令 gate
"仅 NoKey 允许派生"，changeGlobalKey 在 Unlocked 态派生新密钥同被拒
（第二潜伏断点）。本次按"敏感操作下沉"架构根治。

#### W82-1 worker 新增 derive_and_store_global_key 操作（敏感操作下沉）
- gmk.rs：提取 `derive_gmk_core` 公共派生链（资源 Box<Response>
  错误变体），新增 `handle_derive_and_store_global_key`——worker
  进程内原子完成「派生 → 收敛残留 global-key 记录（find+delete
  循环）→ 写入新记录 → GetRecord 读回逐字节比对」。成功响应内联
  lid + recordB64；失败统一补偿：清 GMK + 尽力回收半成品记录。
  全程不经过主进程数据命令，绕开解锁态闸门（闸门语义保持不破）。
- 读回验证在 worker 内以字节数组直接比较（不经 base64 转换），
  编码契约风险一并消除。
- dispatch.rs 注册新操作分支。

#### W82-2 前端 initGlobalKey 改用原子操作
- global-verthys.ts：initGlobalKeyInner 改为单次
  verthysDeriveAndStoreGlobalKey 调用（不再前端 AddRecord/读回/
  删除——删除命令 NoKey 下同受闸门拒绝）；失败补偿仅 clear +
  reconcile(false)，连续失败经 verthys_reset_global_key_state
  强制复位兜底；reconcile(true) 失败时不删记录，靠重试时 worker
  收敛保证单条（磁盘恒收敛）。
- 进度四节点 8/20/70/88（存储与读回验证在 worker 内合流为 70）。

#### W82-3 后端命令改造
- key_controller.rs：提取 `DerivePrecheckCtx` 参数结构 +
  `precheck_derive_request` 公共前置（熔断闸门 fail-closed + 状态
  允许集合 + 输入校验 + 序列化，审计一致）；derive 命令 gate 放宽
  为 NoKey|Unlocked（Unlocked=身份验证通过后的密钥更换，重派生
  授权成立；Locked 仍拒）；新增 verthys_derive_and_store_global_key
  命令（仅 NoKey，透传 worker 响应，审计同款）；lib.rs 注册。
- verthys.ts 新增 verthysDeriveAndStoreGlobalKey 包装
  （{ id, recordB64 }）。

#### W82-4 回归测试与基线
- 前端 spec 重写 init 组（5 用例）：成功推进（断言不再调用
  add_record/get_record）、worker 失败补偿、reconcile 失败重试
  收敛（断言不前端删除）、补偿失败 reset 兜底、重入互斥锁；
  change 组 6 用例不变。
- AST 基线：key_controller.rs 202→302、426→510 行号对齐
  （45 条豁免总数不变，位置随重构漂移，无新增豁免项）。

#### Wave 8.2 批次验证门（w82gate，全过）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | **61/61 通过**（init 5 + change 6，其余模块 50） |
| 前端构建 | npm run build | 成功 |
| src-tauri | cargo test / cargo clippy --all-targets -- -D warnings | **319 passed** / 0 告警 |
| worker | cargo test / cargo clippy --all-targets -- -D warnings | **20 passed** / 0 告警 |
| run_ci | AST 双引擎 + C 双配置 296/0 | 0 错误 0 警告（45 条豁免全匹配） |

#### Wave 8.2 收尾交接清单
1. 根因闭环：数据域解锁态闸门与初始化时序的冲突经"存储下沉 worker
   原子操作"破解，闸门不破坏、初始化可达、change 路径同步修复；
2. 用户实测验证仍待执行（最终构建后初始化一次全局密钥）；
3. 全部改动未提交 git，与 Wave 0~8.1 同批待用户评审验收。

### 2026-09-23 Wave 9：安全中枢防护全链路修复（排查报告 12 项 + 修复方案 7 分项落地）

起因：用户报告安全中枢三项严重症状——切换三档模式卡死应用、切换
假生效（未真实调用/关闭对应内容，含自定义）、模式选择无法落盘重启
还原。先输出《安全中枢防护全链路深度排查报告》（12 项：A1-A4 假生效、
B1-B2 卡死/竞态、C1-C3 持久化、D1-D3 架构契约），再经 Decision Gate
四条实读裁定（DG-1/2/3 分支 B：温缓存锁阻断不成立、C 层无并发首读、
WebView 数据目录不随 data_dir 漂移；DG-4 系统性缺陷成立），随后按
《安全中枢防护修复方案》三不变式（生效性/可见性/单一事实源）分四批实施。

#### W9-1 授权模型统一（A2/DG-4，批次 1）
- 删除无发放端的一次性令牌机制：auth.rs 的 verify_and_consume_auth_token、
  state.rs 的 auth_tokens 字段、tests.rs 两条 token 测试全部移除；
- 新增 require_session_authorized：以密钥生命周期（Locked/Unlocked 放行、
  NoKey 拒绝）为统一授权信号——两种状态仅在解锁完成且存在主密钥记录后
  出现，等价"本次会话已完成至少一次秘密证明"；
- 六个调用点改造：set_high_security / add_trusted_path / clear_trusted_paths /
  usb_register_device / brute_record_success / clear_purge（后两者保留
  Unlocked 严格检查防"清熔断→无限暴破"安全退化），审计文案改
  PERMISSION_DENIED + 明确错误详情；
- 注释清理：security_commands/commands 两级 mod.rs 的"generate_auth_token"
  不实声明等 10 处死注释改写为会话授权语义（clipboard_controller 隐私
  模式令牌为独立机制保留）。

#### W9-2 可见性契约（A2 前端侧，批次 1）
- securitySessionSetHighSecurity 由 ipc<void>（静默吞 SecurityResult）
  改为返回 Promise<boolean> 并检查 r.ok；
- applySecurityPreset 内高安全设置/配置查询全部 withTimeout(3s)，
  拒绝可见 log.warn；usePreset onApplyPreset/onApplyCustom 以
  withTimeout(8s) 兜底，超时/异常走既有 showError（pending 复位不卡死）。

#### W9-3 运行时切档贯通链路（A1/D1，批次 2）
- C 层：security_preset_switch 零调用方死实现接通——verthys.h 声明 +
  verthys.def 白名单导出 Verthys_SwitchSecurityPreset（显式枚举映射不依赖
  数值巧合、复用双缓冲 InterlockedExchangePointer 原子发布）；
- worker：ffi_types 新函数指针类型 + call_switch_security_preset +
  dispatch "switch_preset" op（幂等：切当前档返回 OK）；
- Rust：新命令 security_apply_preset——require_session_authorized →
  code 合法域（E_INVALID_PRESET）→ send_with_timeout(5s) → 透传
  worker 错误码（E_WORKER_COMM/E_WORKER_ERROR），审计记录旧档→新档，
  返回新档真实配置（后端权威副本替代前端静态查表结果）；
- 前端：applySecurityPreset 顺序反转为"先调后端、成功后改前端状态"，
  失败抛错保持原状态；SecurityCenter 恢复链改调 restoreSecurityPreset。

#### W9-4 持久化加固（C1/C2，批次 3）
- 新 preset_persistence.rs：受信配置文件 <verthys_path>.preset.json
  （与 .state 同域，随容器文件迁移），tmp+rename 原子写，读校验
  code 合法域，失败一律上抛明确错误不静默；
- security_apply_preset 合并"切档+落盘"事务语义：先写受信文件成功再切
  C 层档；C 层切档失败补偿回滚落盘至旧内容（无旧文件则删除，磁盘恒收敛）；
- CUSTOM(3) 同命令落盘（code+自定义特性），自定义配置任意变更即时落盘，
  废除"保存并应用"延迟落盘语义；
- 新命令 security_load_preset_state：恢复链权威读取；
- 前端 restoreSecurityPreset 三段恢复：后端有值→真实应用；后端无值
  localStorage 有值→迁移（应用+落盘+清 localStorage）；两端无值→应用
  默认 BALANCED 建立权威副本。

#### W9-5 竞态仲裁与显示层单一事实源（B2/C3/D2，批次 4）
- presetEpoch 单调版本号：onApplyPreset/onApplyCustom 用户显式切换递增，
  restoreSecurityPreset 每次 await 后校验 epoch 未变，变化即丢弃恢复
  结果（用户最新选择为最终状态，根治恢复链覆盖用户切换竞态）;
- currentModeLabel 由 activeAnchorIdx 档位判定改为按 securityPresetRef
  （后端权威 code）映射（顺带修正原 labels 数组索引与锚点错位 bug）;
- 特性列表 6 项"C 层固定启用"不实文案改为可验证的如实描述（反调试加固/
  DLL 注入防御等）；
- 静态表与 C 层对齐：PERFORMANCE 档 anti_debug true→false（C
  fill_performance 为 0）、key_separation false→true（架构层固定能力，
  不随档位关闭）。

#### W9-不实施 撤销项（Decision Gate 裁定）
- A4（C 层并发首读竞态）：DG-2 分支 B——worker 单线程 &mut 串行 FFI，
  安全配置无并发首读方，不修改；
- B1 锁阻断卡死链：DG-1 分支 B——set_high_security 先校验后锁且
  set_high_security_mode 仅 AtomicBool store，session_guard start 为独立
  消息线程，锁阻断不成立；透传链超时防护仍按通用规则落地（W9-2）；
- C1"数据目录漂移"：DG-3 分支 B——无 dataDirectory 配置，WebView2 固定
  LocalAppData，持久化加固理由收敛为单点脆弱+静默吞失败+无权威源。

#### Wave 9 批次验证门（w9gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| C 核心 | scripts\build_core.dev.ps1（Debug + verthys_tests.exe）+ build_production.ps1 -SkipWorker -SkipTauri（Release） | 构建通过 + 全量单测通过 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 61/61 通过 |
| src-tauri | cargo test / cargo clippy --all-targets -- -D warnings | **321 passed**（319 + preset_persistence 4，token 2 删）/ 0 告警 |
| worker | cargo test / cargo clippy --all-targets -- -D warnings | **20 passed** / 0 告警 |
| 素材同步 | worker release 重建 + binaries 哈希一致 | 通过 |
| run_ci | AST 双引擎 + 45 条基线 | 0 错误 0 警告（无新增豁免） |

#### Wave 9 收尾交接清单
1. 三不变式落地验收点：生效性（切档贯通 C 层双缓冲，security_preset_switch
   有可达调用路径）、可见性（SecurityResult 不再被 Promise<void> 静默吞、
   全链路超时兜底）、单一事实源（后端受信文件权威，localStorage 降级缓存
   并迁移清除）；
2. 用户实测项：切换三档不再卡死、重启保持档位、自定义即时落盘、权限拒绝
   可见提示；
3. 全部改动未提交 git，与 Wave 0~8.2 同批待用户评审验收。

### 2026-09-23 Wave 10：卡死根源渲染层根治（用户实测"一滑动/点击立刻全应用卡死"）

#### 取证（证据链收敛，全部实读代码/日志）
- 后端无罪：卡死时段 `main_ui.log` 无任何新命令进入（verify/切档/落盘/
  高安全模式全部快速成功返回），冻结发生在 WebView2 前端主线程而非后端
  锁/命令阻塞；
- 主证据一（mgmt-hub）：ManagementHub.frame() 每帧（active 档 60fps）
  对 3 单元写 `el.style.transform/opacity` 与 `--boost/--prox/--lift`
  CSS 变量；mgmt-hub.css 中 6 处 `filter: drop-shadow(0 0 calc(… + var(--boost)…))`
  + `will-change: filter`。`filter` 为重绘属性（非合成器属性）——
  每帧半径变化强制 WebView2 每帧整层重栅格化 3 个 SVG 单元；
  `will-change: filter` 进一步常驻强制提升采样层。idle-governance 只
  暂停 CSS animation，管不住 rAF 直写 + filter 重绘（卡死的核心机制）；
- 主证据二（drag）：SecurityDashboard pointermove 每事件（可达 250Hz）
  同步 `getBoundingClientRect()`（与每帧 CSS 变量写入叠加触发强制同步
  样式重算）+ 直写 `--posw` 驱动 `clip-path: inset(…)` + `will-change:
  clip-path` → 逐事件整层重栅格化；
- 主证据三（will-change 滥用）：dashboard.css 另有 `will-change:
  stroke-dashoffset`（flow-run 动画）常驻强制提升；全表仅 mgmt-hub 的
  filter 是变量驱动逐帧变化（其余 drop-shadow 均为静态值，安全保留）。

#### 修复（四个文件，全部根治性改动）
1. [mgmt-hub.css](../verthys-tauri/src/styles/security/mgmt-hub.css)
   ——6 处 `filter: drop-shadow(calc(…var(--boost)…))` 全部改为静态
   fixed 半径（1~1.5px 常驻弱光晕），移除全部 `will-change: filter`；
   能量增稠质感交由 opacity / stroke-width（合成器友好属性）承接，
   视觉语义不变（见 `.mh-fa` 注释）；
2. [SecurityDashboard.vue](../verthys-tauri/src/components/management/SecurityDashboard.vue)
   ——拖拽路径去同步布局与直写：
   - `updateFromPointer` 改为仅更新数值 + 摆锤冲量 + 120ms 节流 model，
     DOM 写入推迟到 `tiltLoop` 帧内合并执行（`if (dragging.value)
     writePosToDom(latestPos)`）；
   - `onTrackPointerDown` 一次性缓存 `downLeft/downWidth`（pointermove
     期间零 getBoundingClientRect），按下即启动帧内写入门控；
3. [ManagementHub.vue](../verthys-tauri/src/components/management/ManagementHub.vue)
   ——`onPointerMove` 不再逐事件 getBoundingClientRect，左缘/顶缘在
   `layout()`（ResizeObserver 驱动的唯一布局入口）统一缓存；
4. [dashboard.css](../verthys-tauri/src/styles/security/dashboard.css)
   ——移除 `.bs-survey--lit` 的 `will-change: clip-path` 与
   `.flow-packets` 的 `will-change: stroke-dashoffset`（重绘属性
   will-change 无合成器收益，仅制造常驻强制提升）；
5. [SecurityCenter.vue](../verthys-tauri/src/components/modules/SecurityCenter.vue)
   ——预设恢复链去双触发：onMounted 中恢复分支删除，统一收敛到
   `watch(globalKeyReadyRef, …, { immediate: true })` 单通道
   （presetEpoch 竞态仲裁兜底在途恢复链自弃，语义不退化）。

#### Wave 10 批次验证门（w10gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 61/61 通过 |
| 前端构建 | npm run build | 通过（产物正常生成） |

#### Wave 10 收尾交接清单
1. 用户实测项：滑动/点击不再立即卡死、窗口可正常关闭、三档切换/拖拽
   滑块丝滑（修复仅涉渲染层，后端无改动，无需重跑 C/worker/Rust 门禁）；
2. 视觉回归注意点：hover 时弧流辉光半径不再随 boost 呼吸（改为
   opacity/stroke-width 增稠），属有意取舍（重绘代价换静态光晕）；
3. 全部改动未提交 git，与 Wave 0~9 同批待用户评审验收。

### 2026-09-23 Wave 11：安全防护三档切换卡死根治（修复方案四批次全量落地）

#### 背景
三档锚点/滑块一操作即全局卡死。排查清单已收敛：H1 主根因（透明分层
窗口 + 强制 GPU 光栅化在双显卡机型把 WebView2 GPU 进程推入不稳定域）
+ S1~S5 放大因素（交互唤醒满帧尖峰、拖拽逐帧整层重栅格化、氛围类
切换风暴、GC/堆策略失当）。修复方案按风险阶梯四批次实施，每批次
单一因果归因 + 独立全门禁。

#### 变更点（四批次）
1. [tauri.conf.json](../verthys-tauri/src-tauri/tauri.conf.json)
   ——`additionalBrowserArgs` 移除三项 GPU 强制参数
   `--enable-gpu-rasterization --enable-zero-copy --ignore-gpu-blocklist`
   （Batch 1）与 `--js-flags="--max-old-space-size=1024 --expose-gc"`
   整段（Batch 4）。`transparent: true` / `decorations: false` 保留，
   视觉零变化；WebView2 回归自适应合成决策与 V8 默认动态堆策略；
2. [useGlobalIdleScheduler.ts](../verthys-tauri/src/composables/useGlobalIdleScheduler.ts)
   ——事件分级装配：指针/触碰类（pointerdown/pointermove/wheel/
   touchstart）两段唤醒——先落 settling（30fps、DPR 1.5），一次性
   定时器满 400ms 后升 active；keydown 维持即时 active；forceResetIdle
   直通豁免不变；升温定时器随页面隐藏/窗口失焦/卸载清理；
3. [usePreset.ts](../verthys-tauri/src/composables/security-center/usePreset.ts)
   ——presetAmbienceMode 增加 ±6 迟滞带：进入 25/75、退出 31/69，
   滞后档位锁存 + 单次推算跨带收敛（最多 3 步），消除滑块在阈值
   附近往复引发的类切换风暴；
4. [dashboard.css](../verthys-tauri/src/styles/security/dashboard.css)
   ——新增 `.is-dragging .ambience-glow { transition: none }`：拖拽期间
   氛围背景过渡冻结（类切换退化为瞬时静态，松手吸附后恢复 0.8s 渐变，
   与既有 `.is-dragging .bs-survey--lit` 同手法）；架构头注释同步校准；
5. [SecurityDashboard.vue](../verthys-tauri/src/components/management/SecurityDashboard.vue)
   ——γ 方案：--posw 亮层写入 2% 量化（≤50 档）+ 拖拽期 30Hz 抽帧
   （tiltLoop 帧循环内半步抽帧，无新增渲染管线）；--pos 游标逐帧
   全精度直跟不变；非拖拽路径即时写入（吸附/锚点/键盘/预设同步）；
   α（scaleX 合成器路径）留待设计评审，未实施；
6. [gc.ts](../verthys-tauri/src/utils/gc.ts)
   ——文件头注释事实校准：删除与实际窗口配置不符的 flag 清单描述
   （--gc-interval 等），改写为可验证行为描述（缺失原生 gc 时安全
   no-op、显式启用时桥接生效）；函数逻辑与调用链零改动。

#### Wave 11 批次验证门（w11gate，四批次全绿）
| 门禁 | 命令 | 结果（Batch 1/2/3/4 一致） |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 61/61 通过 |
| 前端构建 | npm run build | 通过（产物正常生成） |
| src-tauri 测试 | cargo test | 321 passed / 0 failed |
| worker 测试 | cargo test | 20 passed / 0 failed |
| 体系静态 | ci/run_ci.ps1 | 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 11 收尾交接清单
1. 用户实测验收矩阵（Batch 1 验收项 1~6 为全批次基线）：三档锚点各
   点击 5 次不卡不冻、滑块 0→100 来回 10 次（含快速甩动）无 100ms
   停帧、切档瞬间点"立即锁定"与窗口关闭按钮立即响应、10 分钟静置
   GPU 子进程存活、Crashpad/系统事件日志无新增、松手氛围色 0.8s
   渐变完整；拖拽悬停 25/75 阈值附近往复 20 次类切换次数显著下降；
2. GPU 健康观测四件套：任务管理器 msedgewebview2.exe GPU 子进程、
   EBWebView\Crashpad\reports 无新增、事件日志无 Display 4101/4102、
   main_ui.log 冻结时段命令时序正常；
3. 待决项：Batch 3 的 α（scaleX 合成器路径）需视觉评审后再决定是否
   升级替代 γ；修复方案 4.2 节书面"退出带 19/81"与"±6 迟滞"数理
   不自洽，实施采用进入 25/75、退出 31/69 的对称迟滞，以本条目为
   书面裁定；
4. 全部改动未提交 git，与 Wave 0~10 同批待用户评审验收。

### 2026-09-23 Wave 12：点击/滑动全卡死同帧自旋根治（根因分析报告六节方向全量落地）

#### 背景
根因分析报告定位两个根因：A 渲染主线程同帧自旋死循环（MasterFrameLoop
once 队列同帧排空语义 × tiltLoop 拖拽态无条件自重排——点击/滑动必现、
永不恢复、45s 硬退出兜底因 CloseRequested 未发生而失效）；B WebView2
GPU 强制参数经环境变量第二注入点绕过最近批次摘除（整画面定格形态
隐患）。既往底层 C 升级经证据排除（主进程不加载 verthys.dll、worker
行协议全链路超时隔离）。修复按四批次实施，每批次独立全门禁。

#### 变更点（四批次）
1. [master-frame-loop.ts](../verthys-tauri/src/core/master-frame-loop.ts)
   ——契约层根治：once 队列排空由 while 同帧循环改为帧快照
   （splice(0) 截断本帧批次，排空期间新排入者顺延下一帧），从契约上
   禁止 once 任务同帧自我延续；新增 once 任务独立错误熔断（WeakMap
   跨帧计数，连续抛错 10 次进入 1000ms 冷却期跳过执行，冷却结束自动
   恢复执行资格，不永久失效）；文件头/字段/方法注释事实校准；
   [master-frame-loop.spec.ts](../verthys-tauri/src/core/master-frame-loop.spec.ts)
   ——新增 3 用例：同帧自重排仅每帧执行一次、排空期间新排入顺延下一帧、
   once 熔断冷却停止执行与冷却后恢复；
2. 调用层审计（零改动）：tiltLoop 拖拽期自重排在新语义下为每帧至多
   一次（60fps 直跟保留），松手后欠阻尼弹簧有界收敛；pointercancel
   已与 pointerup 共幂等处理器（dragging 置位守卫）；组件卸载断泵
   （tiltActive/parallaxActive/auraActive）齐全；tickParallax（0.001）、
   auraFrame（0.5px）指数阻尼有界；useCardTilt 单发去重无自重排——
   全仓无第二处无界同帧重排；
3. [lib.rs](../verthys-tauri/src-tauri/src/lib.rs)
   ——删除 run_main_ui 内 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS 三项
   强制 GPU 参数注入块（次根因 B 的最后一处运行期注入点）与对应头注释；
   tauri.conf.json 无 additionalBrowserArgs/js-flags 残留，全仓复查
   代码域零注入点；
4. [CONFIGURATION.md](../docs/CONFIGURATION.md)
   ——运行时环境变量节事实校准：删除运行期写出条目，结论改为不读取
   VERTHYS_ 变量且不对 WebView2 / GPU 参数做运行时写出。

#### 行为语义校准（帧快照的连带效应）
- 视差/光环类 once 泵（tickParallax 0.08、auraFrame 0.12）原设计为
  "逐帧缓动"，但旧同帧排空语义使链在同一帧收敛完毕，缓动从未显形；
  帧快照后改为每帧一步，缓动如实表达（收敛尾迹约 0.5~1.4s），属注释
  声明的既定设计语义回归，非视觉缺陷。

#### Wave 12 批次验证门（w12gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | **64/64 通过**（61 + 3 新增） |
| 前端构建 | npm run build | 通过（10.9s） |
| src-tauri 测试 | cargo test | 321 passed / 0 failed |
| src-tauri 静态 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| worker 测试 | cargo test | 20 passed / 0 failed |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免；一级警告与本次改动文件交叉核对零命中） |

#### Wave 12 收尾交接清单
1. 用户实测验收矩阵：安全中枢按下/滑动持续拖拽 30s 无卡死、连续点击
   三档锚点各 10 次、拖拽中按关闭按钮即时响应；渲染进程 CPU 不再单核
   打满（帧快照后拖拽期 tiltLoop 每帧至多一次）；
2. 行为观察项：鼠标视差与解锁光环改为逐帧缓动跟随（旧语义为同帧收敛
   瞬跳），缓动节奏如需调整可在泵常量（0.08 / 0.12）处单点调参；
3. 全部改动未提交 git，与 Wave 0~11 同批待用户评审验收。

### 2026-09-23 Wave 13：安全防护面板体验与数据真实性整改（五项核验全落地）

#### 用户五项要求与核验结论（先核验后整改）

| # | 要求 | 核验结论 | 处置 |
|---|---|---|---|
| 1 | 仪表界面导航栏不应自动弹出，应同首屏一样 hover 才显示 | 属实。ManagementView 仅 dashboard 态 emit panel-active=true 收起 Dock，hub/detail 态放宽 → Dock 常驻弹出 | 三态统一 panel-active=true，悬浮 Dock 区域（clientX<80）展开，与首屏一致 |
| 2 | 安全防护界面交互明显卡顿 | 属实，三处热点：①拖拽期 .bs-sweep stroke-dashoffset 0.6s 过渡叠加 drop-shadow 滤镜，模型同步 120ms 节拍重触发致连续重绘带；②轨道背景渐变每 120ms 随之重绘；③松手后 clip-path 0.5s 全层过渡重栅格化 | ①拖拽期冻结扫掠弧/能量点过渡；②渐变位置拖拽期冻结、松手吸附后一次性写；③clip 过渡 0.5s→0.4s |
| 3 | 三个百分比是否真实数据 | 伪造。cpuOverhead=15+斜率×位置、securityCoverage=42+斜率×位置、overallScore=两者平均 —— 纯滑块线性公式，零后端信号 | 全系整改：CPU 改后端 GetSystemTimes 差分真实采样（2s 轮询）；覆盖度=已启用特性占比×防御闭环已防御占比双权重合成；综合评分=覆盖度×负载双权重合成（纯函数层 + 7 单测） |
| 4 | 切档进度应显示在模式所在处而非恢复原位 | 属实：切换路径预先写入游标位置（乐观位移，失败/重载即回弹）且无锚定进度 | 后端分阶段真实进度事件 + 进度道锚定目标档位位置；切换路径废除乐观位移（成功后落位/失败回撤，始终与后端权威档位同位）；初始游标对齐后端档位（重挂载不闪回中性位） |
| 5 | 安全防护与防御闭环是否真实调用 | 防御闭环：真实四层链路（verthys_security_status→worker→C RUNTIME 复检，60s 轮询）。能力状态栏原为恒等伪装计数（n/n 恒满） | 能力状态栏接入后端权威配置快照：核心能力按档位降档关闭时如实灰态（CORE ACTIVE/DEGRADED），防御闭环保持原真实链路不动 |

#### 变更点（四批次）
1. [ManagementView.vue](../verthys-tauri/src/components/views/ManagementView.vue)
   ——panel-active 三态统一 emit true（导航坞 hover 才展开）；
2. [usePreset.ts](../verthys-tauri/src/composables/security-center/usePreset.ts)
   ——轨道渐变拖拽期冻结（gradientPos 锁存）；假数据公式全删，三指标
   改真实信号合成（options 注入 cpuUsage/defenseMeta）；切档进度状态
   presetApplyProgress + 事件订阅 + 完成驻留/失败回撤 + syncOrbitFromPresetRef
   收敛同源；初始游标对齐后端权威档位；snapToAnchor/onOrbitSliderRelease
   废除乐观位移；
3. [dashboard.css](../verthys-tauri/src/styles/security/dashboard.css)
   ——拖拽期冻结扫掠弧/能量点过渡；clip 过渡收敛 0.4s；新增 .bs-apply-rail
   锚定进度道（scaleX 合成器填充，零重排零重绘）与降档灰态 cap-item.off；
4. [SecurityDashboard.vue](../verthys-tauri/src/components/management/SecurityDashboard.vue)
   ——切档进度道模板（锚定 targetPos）+ 能力状态栏真实状态（capFeatOn/
   capActiveCount/capSubText）；
5. Rust：[system_metrics.rs](../verthys-tauri/src-tauri/src/security_commands/commands/system_metrics.rs)
   新增 —— GetSystemTimes 差分采样命令 verthys_system_snapshot（进程内
   基线跨调用保留，首采 None，非 Windows 恒 None，4 单测）；
   [preset.rs](../verthys-tauri/src-tauri/src/security_commands/commands/preset.rs)
   ——切档分阶段进度事件（8/25~60/40/88/100，best-effort 不阻断主流程）；
   lib.rs 白名单注册新命令；
6. 前端新件：[useSystemMetrics.ts](../verthys-tauri/src/composables/security-center/useSystemMetrics.ts)
   （2s 轮询）、[presetMetrics.ts](../verthys-tauri/src/composables/security-center/presetMetrics.ts)
   （合成纯函数）+ spec（7 单测）；[verthys.ts](../verthys-tauri/src/lib/verthys.ts)
   新增 verthysGetSystemSnapshot 封装；
7. [SecurityCenter.vue](../verthys-tauri/src/components/modules/SecurityCenter.vue)
   ——装配 useSystemMetrics/useDefenseStatus 前置注入 usePreset，透传
   presetFeatures/applyProgress。

#### Wave 13 批次验证门（w13gate，四批次全绿）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | **71/71 通过**（64 + 7 新增） |
| 前端构建 | npm run build | 通过 |
| src-tauri 测试 | cargo test | **325 passed**（321 + 4 新增）/ 0 failed |
| src-tauri 静态 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| worker 测试 | cargo test | 20 passed / 0 failed |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 13 收尾交接清单
1. 用户实测项：进入三个仪表界面后导航坞不再自动弹出（悬浮左侧才出现）；
   拖拽/点击锚点全程无卡顿（扫掠弧不再逐节拍重绘）；三档切换时进度道
   在目标档位锚点处推进并在完成处停驻；切换失败时游标回齐原档位（不
   再出现"进度恢复原位"错位）；
2. 数据语义说明：CPU/IO 开销为系统级占用率真实采样（2s 窗口差分），
   与预设档位无直接因果（档位只影响覆盖度与综合评分）；首次进入面板
   约 2s 内出现首个真实采样值；
3. 全部改动未提交 git，与 Wave 0~12 同批待用户评审验收。

### 2026-09-23 Wave 14：安全防护细节体验整改（用户实测反馈三项全落地）

#### 背景
Wave 13 焦点在数据真实性与锚定进度，用户实测后反馈三项细节/交互问题：
端点视觉突兀、拖拽越过相邻档中位时出现的切档进度能量条体验不佳、
能力/防御面板呼吸动效多余。三项均按用户裁定系统化整改。

#### 变更点（三项）
1. **音符条端点对齐**（[SecurityDashboard.vue](../verthys-tauri/src/components/management/SecurityDashboard.vue)
   + [dashboard.css](../verthys-tauri/src/styles/security/dashboard.css)）
   —— 删除与端点锚重复的端桩双立杆（.bs-post 模板与样式全量移除）；
   端点锚（性能 0% / 安全 100%）兼作左高右低终点桩：固定高度 22/11px
   与静态端点几何同一（.bs-anchor-0/2 高度改写 + 终点色沿用），邻近
   态仅亮色、不参与拔高（.bs-anchor-0/2.near 高度锁定）——端点与
   测线基准同一几何，无双杆错位突兀；
2. **切档进度能量条系统化删除**（[usePreset.ts](../verthys-tauri/src/composables/security-center/usePreset.ts)
   / SecurityDashboard.vue / ManagementView.vue / SecurityCenter.vue /
   [preset.rs](../verthys-tauri/src-tauri/src/security_commands/commands/preset.rs) /
   dashboard.css）—— 前端进度道模板、样式、状态 presetApplyProgress、
   ensureProgressListener 事件订阅、三组件透传，及 Rust 端
   ApplyProgressPayload / emit_apply_progress 分阶段事件全部移除
   （全仓残留引用 grep 复核零命中）；切档改为友好 toast 提示：
   开始"正在切换至「X」模式…"+ 完成"已切换至「X」模式"；切档
   期间游标停在释放位、完成后落位、失败回撤的收敛语义保留不变
   （Wave 13 进度道相关条目以本 Wave 为书面裁定撤销）；
3. **呼吸效果系统化删除**（dashboard.css）—— 安全防护圆点
   （cap-breath 动画 + 质数序列延迟规则）与防御闭环阻断态圆点
   （def-breath 动画 + 延迟规则 + 关键帧）全量移除，圆点改静态
   实心；cap-breath 关键帧仅保留给数据流转轨道"运行状态行"状态位
   （该元素不在用户裁定范围）；面板头部与技术注释同步校准。

#### Wave 14 批次验证门（w14gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 通过 |
| 前端构建 | npm run build | 通过 |
| src-tauri 测试 | cargo test | 325 passed / 0 failed |
| src-tauri 静态 | cargo clippy --all-targets -- -D warnings | 0 告警 |
| worker 测试 | cargo test | 20 passed / 0 failed |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 14 收尾交接清单
1. 用户实测项：音符条两端点与中间锚点、测线刻度基准同一几何无突兀；
   拖拽越过相邻档中位松手后不再出现能量条，仅 toast 提示并落位
   （失败回撤仍保持）；能力/防御面板圆点静止；
2. 全部改动未提交 git，与 Wave 0~13 同批待用户评审验收。

### 2026-09-23 Wave 15：切档落位交互时序整改（先落位后提示）

#### 背景
Wave 14 删除进度能量条后，松手切换路径不再即时落位（游标停在释放
位置直到后端返回），用户实测反馈"拖拽越过 25 后松手当场卡住"。要求：
松手先即时落位到相邻档位，随后才是 toast 提示。

#### 变更点（[usePreset.ts](../verthys-tauri/src/composables/security-center/usePreset.ts)）
1. 释放/点击处理器改为**先即时落位**：orbitSliderPos 与 activeAnchorIdx
   在调用 onApplyPreset 之前同步写入相邻锚点（视觉先行，游标
   0.5s 弹簧过渡即刻启动），随后再异步切档 —— 不再等待后端返回才动；
2. **toast 时序后置**：开始提示改为延迟 220ms 且仅当切换仍在进行中
   才显示（快速成功只出完成提示）；在成功/失败收口与组件卸载时
   清理计时器，杜绝残留提示；
3. 失败回撤语义保留：切档失败时游标回齐后端权威档位（即时落位
   全程可逆，界面与后端状态恒收敛）。

#### Wave 15 批次验证门（w15gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 通过 |
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 15 收尾交接清单
1. 用户实测项：拖拽越过 25 松手后游标立即滑向平衡档位（无停顿），
   随后约 0.2s 出现"正在切换至 平衡 模式…"提示，完成后再出完成提示；
   失败时游标回撤到原档位；
2. 全部改动未提交 git，与 Wave 0~14 同批待用户评审验收。

### 2026-09-23 Wave 16：进度链路文案与表现层防御整改（P1→P2→P3）

#### 背景
对五条进度链路（初始化/验证/解锁/模块密钥验证/照片导入）核验后
结论为工程化达标（评级高），并列出三项改进项：P1 初始化文案时序
偏差、P2 表现层钳制弱防御、P3 解锁链路双源待复核。本 Wave 按
P1→P2→P3 顺序全量落地。

#### 变更点
1. P1（[global-verthys.ts](../verthys-tauri/src/key/global-verthys.ts)）
   ——初始化链路 70% 文案"校验密钥记录"→"确认密钥落盘"：读回逐字节
   校验实际已包含于 20% 的 derive_and_store 原子动作（worker 进程内
   派生→写入→读回一体），70% 时点的真实动作是兜底 flush 与状态
   推进前哨，文案与时序对齐；
2. P2（[QuantumProgressFlow.vue](../verthys-tauri/src/components/common/cosmic/QuantumProgressFlow.vue)）
   ——表现层钳制防御：新增 safePercent（Number 归一则、NaN/Infinity/
   负值归零、0..100 收束），进度宽度与 Meta 百分比共用同一安全值，
   上游异常输入不再可能造成宽度溢出（上游各源此前已各自钳制，
   此层为契约兜底）；
3. P3（[global-verthys.ts](../verthys-tauri/src/key/global-verthys.ts)
   + [QuantumProgressFlow.vue](../verthys-tauri/src/components/common/cosmic/QuantumProgressFlow.vue)）
   ——解锁链路双信号源核验收敛：经核实，前端阶段 emit 与 C 层通道
   emit 已由「单调递增闸门（lastEmittedPercent）+ 通道区间映射
   （8 + p×0.77，≤85%）+ 完成位守卫（unlockProgressDone 与
   verthys.ts completed 阻断残留）」收敛为单一输出，互斥成立，
   无需结构改动。另校准两处通道文案语义偏差：5% "读取索引"→
   "读取加密头"（C 节点为读取超级块）、50% "校验完整性"→"映射索引"
   （C 节点为索引映射，完整性校验属 100% Merkle 阶段）；同步校准
   表现层注释中 v1/v2 时期的过时 initUnlock 文案清单（删除已不存在的
   "检测格式/升级加密库"等）。

#### Wave 16 批次验证门（w16gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 通过 |
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 16 收尾交接清单
1. 用户实测项：初始化全局密钥时 70% 显示"确认密钥落盘"、解锁过程
   通道文案围绕"读取加密头→派生密钥→映射索引→解密数据→重建索引→
   生成摘要→校验完成"推进；导入进度条百分比异常值不再出现视觉溢出；
2. 全部改动未提交 git，与 Wave 0~15 同批待用户评审验收。

### 2026-09-23 Wave 17：提交按钮悬浮伸展收敛调参

#### 变更点（[cosmic-submit.css](../verthys-tauri/src/styles/security/cosmic-submit.css)）
按用户实测反馈调短解锁/初始化/验证视图提交按钮（CosmicSubmit）
悬浮时下方势能线/充能轨的向两端扩展程度：
`--cs-reach-hover` 0.86 → 0.74（自中心对称收敛至 74%，两侧呼吸位
7% → 13%）；悬浮/焦点/按下三态与按下压陷量均由该单一权威源
calc 派生，一处即全局联动；文件头与交互注释数值同步校准。

#### Wave 17 批次验证门（w17gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 17 收尾交接清单
1. 用户实测项：悬浮提交按钮时下划线向两端扩展幅度收敛（不再
   接近铺满整钮），按下收缩与 loading 全轨行为不变；
2. 全部改动未提交 git，与 Wave 0~16 同批待用户评审验收。

### 2026-09-23 Wave 18：面板头部英文小标题移除

#### 变更点
按用户裁定移除安全防护面板两个面板头部的英文小标题：
1. [SecurityDashboard.vue](../verthys-tauri/src/components/management/SecurityDashboard.vue)
   ——删除"安全防护"头部 cap-sub span（CORE ACTIVE/DEGRADED）
   与"防御闭环"头部 def-sub span（RUNTIME）；capSubText 计算属性
   随载具一并删除（能力启动计数 capActiveCount 与圆点真实状态保留，
   真实状态呈现不受影响）；
2. [dashboard.css](../verthys-tauri/src/styles/security/dashboard.css)
   ——删除仅服务于两个小标题的 .cap-sub / .def-sub 样式块。

#### Wave 18 批次验证门（w18gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 18 收尾交接清单
1. 用户实测项：安全防护头部仅剩"标题 + 计数"，防御闭环头部
   仅剩"标题 + 姿态计数"，无英文小标题；
2. 全部改动未提交 git，与 Wave 0~17 同批待用户评审验收。

### 2026-09-23 Wave 19：运行状态行文字可读性整改

#### 背景与根因
数据流转轨道"运行状态 · 直读装载 — 按需载入，绕过预热"等文字
观感"糊成一坨"。根因：等宽字体栈（Cascadia Code/Consolas）无
完整中文字形，中文落入回退字体，中英混排出现双字体跳变；叠加
9px 小字号、0.22em 宽字距与低对比色，文字粘连不清。

#### 变更点（[dashboard.css](../verthys-tauri/src/styles/security/dashboard.css)）
1. `.flow-status-text`：字体 `--font-mono` → `--font`（与界面主体
   同源，中文统一走微软雅黑）；字号 9px → 10px；字距 0.22em →
   0.08em；颜色 `--text-muted` → `--text-secondary`（对比度提升
   一档）。状态位呼吸方点保持不动；
2. `.flow-label`（磁盘/读取/解密/校验/装载/内存车站标签）同源整改：
   字体 → `--font`、10px、字距 0.08em，基础色提升一档；端点标签
   （磁盘/内存）进一步升至 `--text-primary` 保持端位强调层级。

#### Wave 19 批次验证门（w19gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 19 收尾交接清单
1. 用户实测项：运行状态行与车站标签文字清晰可辨、与面板整体字体
   风格统一；
2. 全部改动未提交 git，与 Wave 0~18 同批待用户评审验收。

### 2026-09-24 Wave 20：密钥弹窗待启用提示移除

#### 变更点
按用户裁定删除密钥编辑弹窗中"保存密钥后将自动开启该模块的密钥
保护；中途退出则保护保持关闭"提示及其专用样式：
1. [KeyEditDialog.vue](../verthys-tauri/src/components/dialogs/KeyEditDialog.vue)
   ——删除 kv-info 提示块（含盾形图标与文案）、未再使用的
   pendingEnable 属性定义；
2. [SecurityCenter.vue](../verthys-tauri/src/components/modules/SecurityCenter.vue)
   ——删除 :pending-enable 透传绑定；
3. [components.css](../verthys-tauri/src/styles/components.css)
   ——删除仅服务于该提示的 .kv-info 与 .kv-info svg 样式块。
   自动开启保护的行为链（useModuleKeys pendingEnableModuleId
   待启用流程）保持不动 —— 本次仅移除提示展示层。

#### Wave 20 批次验证门（w20gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 20 收尾交接清单
1. 用户实测项：开启保护触发密钥设置时弹窗不再显示该提示条，
   保存后仍自动开启保护（行为不变）；
2. 全部改动未提交 git，与 Wave 0~19 同批待用户评审验收。

### 2026-09-24 Wave 21：弹窗确认/取消按钮样式重构

#### 变更点
弹窗复用按钮家族（确认保存/确认修改/验证/解密保存/取消）由旧的
低透明渐变 + 通用缩放按压升级为宇宙主题定制视觉：
1. [components.css](../verthys-tauri/src/styles/components.css)
   ——btn-primary 重构为「潮汐注能」：深舱斜向低饱和底色、底部
   偏左侧势隙线（原点 22% 非中心对称、5.3s 非对称相位呼吸仅走
   opacity 通道）、悬浮时势隙线先铺展 + 90ms 相位迟滞后不规则
   锯齿潮面自舱底升起（clip-path 非均匀齿距、三段复合缓动：
   快爬升→粘滞高抬→缓泊定；退落为单一快速下潜曲线，两向不对
   称）；按下位移下沉 1px + 潮面降明 + 势隙收缩（快压 0.12s /
   慢回 0.22s，顶替旧通用缩放）；键盘焦点 = 注能等价；禁用
   沉降调暗 + 呼吸冻结；reduced-motion 静态等价。kv-cancel 重写
   为「静谧退潮风」（无主色倾注，底部偏左疏引线一脉弱线索）；
   kv-confirm 仅作紧凑体位修饰。
2. 模板接入统一（零行为变更，仅 class 对齐）：
   [VerthysDialog.vue](../verthys-tauri/src/components/common/verthys-ui/VerthysDialog.vue)、
   [FileVerthys.vue](../verthys-tauri/src/components/modules/FileVerthys.vue)
   ——取消/确认按钮补挂 kv-cancel / kv-confirm，全弹窗家族一致。
3. 反 AI 大众化约束落实：无粒子/波纹圆环/辉光堆叠；势隙线原点
   22% + 右侧 24% 留白、疏引线原点 16% + 右侧 30% 留白、锯齿
   齿距非均匀；涨潮三段复合缓动 vs 退落单一下潜曲线；按压为
   下沉 + 降明而非缩放胶囊，交互响应非样板实现。
4. 用户零阴影裁定叠加：按钮家族全域无投影 —— .btn 通配悬浮投影、
   btn-danger、btn-primary、kv-cancel（components.css）与
   ActionButton（danger 变体）、ConfirmDelete（确认删除钮）、
   PhotoAlbum（删除选中/删除工具栏钮）、WindowControls（窗口
   关闭钮）的悬浮/激活投影逐一清除，任何态均不叠加阴影；
   确认/取消禁用态光标统一 not-allowed，与可点击态明确区分。

#### Wave 21 批次验证门（w21gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 全绿 |
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | 二级 0 错误 0 警告（45 条存量基线豁免） |

#### Wave 21 收尾交接清单
1. 用户实测项：密钥类弹窗（生成/修改/验证/导出/关闭验证）与
   通用表单弹窗（账户/证书/文档导入）的确认/取消按钮呈现潮汐
   注能与静谧退潮风格，悬浮铺展、按压下沉、禁用休眠三态正常；
2. 全部改动未提交 git，与 Wave 0~20 同批待用户评审验收。

### 2026-09-24 Wave 22：数据域会话闸门语义根治（密钥全链路失效）

#### 变更点
1. 场景：生产级严重错误——模块密钥设置无法落盘保存、退出应用
   重启后已设密钥清空、模块绕过保护直接进入，全局密钥初始化/
   验证链路同步受影响。
2. 根因（全链路溯源结论）：
   ——数据域命令家族（add_record/get_record/delete_record/
   delete_records/enumerate_records/enumerate_records_stream/
   flush/export/import/change_password/has_record_by_type/
   get_summary_count 与 scan_/scan_summary_ 全族）此前接入统一
   闸门，判定为「全局密钥生命周期 == Unlocked 才放行」。但容器
   解锁成功仅进入 Locked（存在全局密钥记录）或 NoKey（无全局
   密钥记录），Unlocked 仅在 GMK 验证成功后才可达；
   ——记录数据由容器密钥加密保护，读写仅依赖容器解锁（模块密钥
   由各模块密钥自身加密，与 GMK 无关）。前端关键路径
   （ensureSummaryScan / 类型迁移 / loadModuleKeyStatus）运行在
   verify 之前的 Locked/NoKey 窗口，全部被闸门拒绝 → 摘要缓存
   为空、模块密钥状态全 false → 模块放行进入，并呈现「重启后
   密钥被清空」；setModuleKey 在 NoKey/Locked 窗口同样被拒 →
   「无法设置落盘保存」；全局密钥链为绕开该闸门曾引入专用
   派生存储命令（补丁式绕过，进一步证实谓词语义错位）。
3. 修复：数据域闸门判定由全局密钥生命周期状态改为容器会话存在
   性。[verthys_controller.rs](../verthys-tauri/src-tauri/src/controller/verthys_controller.rs)
   的 state_allows_data_access 谓词改用 AppState::has_verthys_session
   （VerthysSessionGuard 存在 = 容器已解锁），require_unlocked 注释、
   日志与审计文案同步校准为容器会话语义。会话由 unlock/create 建立、
   lock 销毁，与数据域可用性精确一致；GMK 授权仍由密钥命令自身
   状态机与 require_session_authorized 独立裁决，两层不掺混。
4. 配套校准：闸门单测由三态断言改写为会话断言（无会话拒绝 /
   会话存在放行 / 会话销毁拒绝）；派生存储专用命令相关注释
   （key_controller / worker gmk / dispatch / verthys.ts /
   global-verthys.ts / global-verthys.spec.ts）由「绕开闸门拒绝
   NoKey」改写为「派生、落盘与读回验证同一调用原子完成」的可
   验证描述；体系静态基线条目随行号漂移同步（651→664）。

#### Wave 22 批次验证门（w22gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| Rust 主进程单测 | cargo test --lib（src-tauri） | 325/325 全绿 |
| Rust worker 单测 | cargo test（verthys-worker） | 20/20 全绿 |
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 全绿 |
| 前端构建 | npm run build | 通过 |
| 体系静态 | ci/run_ci.ps1 | AST 0 违规（45 条存量基线豁免） |

#### Wave 22 收尾交接清单
1. 用户实测项：设置任一模块密钥 → 重启应用 → 密钥仍在且模块
   受保护拦截；无全局密钥场景下模块密钥设置/修改/关闭全程可用；
   全局密钥初始化/验证/修改回归正常；
2. 全部改动未提交 git，与 Wave 0~21 同批待用户评审验收。

### 2026-09-24 Wave 23：确认按钮潮面升起层移除

#### 变更点
1. 用户裁定：确认保存/确认修改等通用按钮的悬浮「从下往上幕布
   效果」（白色罩层升起、像屏障般盖住按钮面）不可接受，予以
   移除。
2. 实施（[components.css](../verthys-tauri/src/styles/components.css)）：
   btn-primary 的 ::after 潮面层（浅白渐变罩层 + clip-path 锯齿
   顶缘 + kv-tide-rise 升起动画）整体删除，含 hover/focus-visible/
   active 的 ::after 规则与 reduced-motion 对应分支；保留势隙线
   呼吸/悬停铺展、底色增浓边框提亮、按压下沉 1px+势隙收缩、
   禁用休眠与零阴影、光标语义等其余全部既定视觉，按钮面不再
   被任何罩层遮挡，文字恒为最上层。注释同步校准（移除潮面
   描述，潮面相关描述不再出现在样式注释中）。
3. 零行为变更：仅样式层，模板与逻辑未动。

#### Wave 23 批次验证门（w23gate）
| 门禁 | 命令 | 结果 |
|---|---|---|
| 前端类型 | npx vue-tsc --noEmit | 0 错误 |
| 前端单测 | npx vitest run | 71/71 全绿 |
| 前端构建 | npm run build | 通过 |

#### Wave 23 收尾交接清单
1. 用户实测项：确认保存/确认修改/验证/解密保存按钮悬浮时仅
   势隙线铺展 + 底色增浓 + 边框提亮，无白色幕布升起；按压
   下沉 1px + 势隙收缩；禁用态休眠；全程零阴影、光标区分；
2. 全部改动未提交 git，与 Wave 0~22 同批待用户评审验收。
