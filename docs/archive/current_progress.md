继续 WP-14 P2 项核对。先在各代码路径逐项验证 6 个 P2 项的当前状态。

已搜索 3 次文件
mountwatch 零活代码（仅退役注释）——P2-6 已随 V2 退役删除清单闭环。继续核对其余项。

已搜索 3 次文件
所有超块写入路径均经 vsb_txn（3 处调用点，零裸写）——P2-1 结构性吸收。继续核对温缓存与 VsbTxn 回滚。

已读取 2 个文件，搜索 4 次文件
P2-4 已被 V3 重写吸收（独占句柄 + fsync + MoveFileExW 原子替换）。P2-3 已实现完整回滚。继续核对 P2-2（读块尺寸钳制）与 P2-5（扫描游标生命周期）。

已读取 2 个文件，搜索 2 次文件
发现一处需要加固的点：offset + size > next_offset 存在 uint64 回绕理论窗口（HMAC 在前不可达，但按纵深防御纪律应显式防回绕）。先记录，继续核对 P2-5 扫描游标，随后统一修复。

已读取 2 个文件，搜索 2 次文件
P2-5 已由 V3 身份锚点方案完整修复。现在修复 P2-2 核对中发现的 extent 索引解析回绕窗口，并检查其它解析路径是否有同类模式。

已读取 2 个文件，搜索 1 次文件
三处同类模式需逐一确认类型与可达性。先看 sstable 结构与 format 函数签名。

已搜索 3 次文件
三处均为"认证数据解析中的理论回绕窗口"（纵深防御层级）。逐一加固：拆分比较杜绝 uint64 回绕。

已编辑 3 个文件，读取 1 个文件
三处加固完成。查看后台验证任务进展。

已执行 1 条命令
后台仍在 fuzz 冒烟阶段（会自动通知）。趁等待期间，将 WP-14 P2 核对结果写入 PLAYBOOK 留痕。先读 WP-14 章节。

已编辑 1 个文件，读取 1 个文件
同步更新 §1.2 已知缺陷表的 P2 行状态。

已编辑 1 个文件
WP-14 留痕完成。检查后台验证任务状态。

已执行 1 条命令
partition 冒烟耗时偏长。查看冒烟测试定义确认超时参数。

已读取 1 个文件，搜索 1 次文件
冒烟测试有界（-runs=2000/-timeout=25），等待即可。趁间隙核对 PLAYBOOK 的 WP 状态总表，确认除验证/重建/文档外无遗漏工作包。

已读取 2 个文件
M4 里程碑就差后台验证收口，M5 剩重建+终验+文档。检查后台任务是否推进。

已执行 1 条命令
fuzz_partition 进程 CPU 几乎为零——疑似挂起。查当前时间与挂起时长，并看 fuzz_partition 的输入处理。

已执行 1 条命令
进程挂在一个 "Microsoft Visual C++ Runtime Library" 运行时错误对话框上（19:33 起挂起 1 小时+，CPU≈0）——fuzz_partition 触发了 CRT 报错弹窗而非干净退出。先读取对话框文本定位原因。

已执行 1 条命令
真实堆损坏缺陷被抓到了：fuzz_partition 在分区解析路径写越堆块尾部（CRT 调试堆先于 ASAN 检出）。这正是 fuzz 门的价值。先终止挂起进程，然后定位越界写。

已读取 1 个文件，执行 1 条命令
后台任务因我终止进程而失败（预期内）。堆损坏 victim 是 CRT 内部 locale 块——需要读分区表解析函数找出越界写。

已读取 1 个文件，搜索 1 次文件
解析函数本体纪律良好（verifier 先行 + count 上限 + 定长向量）。堆写的来源需实证定位。先给 fuzz 目标加 CRT 无对话框初始化（否则任何 CRT 报错都会挂死 CI），再重建复现拿崩溃输入。

已创建 1 个文件，编辑 1 个文件
给其余 4 个目标加同样防护，并给 ctest 加 TIMEOUT。先读各目标头部。

已编辑 4 个文件，读取 4 个文件
现在给 ctest 加 TIMEOUT 防挂死。

已编辑 1 个文件
重建 fuzz_partition 复现堆损坏，拿到崩溃输入。

已执行 1 条命令
我的 shell 环境与构建脚本环境不一致导致重配置失败（PATH 里混入了 pgrep\bin 的编译器）。查看构建脚本的环境设置方式。

已读取 1 个文件
构建脚本通过 env.load.ps1 隔离环境。读取它以在当前会话正确构建。

已读取 1 个文件
env.load.ps1 用 cl.exe 强制覆盖编译器。在正确环境下重建。

已执行 1 条命令
复现堆损坏（无对话框后应保存崩溃工件并退出）。

已执行 1 条命令
输出被 PowerShell 吞了。重定向到文件完整捕获。

已执行 1 条命令
env.load.ps1 的 $ErrorActionPreference=Stop 把 stderr 当异常。用 cmd /c 隔离重定向。

已执行 2 条命令
2000 次未复现（随机种子不同）。但注意到更严重的问题：Failed to find function "__sanitizer_*" 警告说明 ASAN 运行时未生效（只有 libFuzzer 计数器在跑）——这解释了为什么堆损坏由 CRT 调试堆而非 ASAN 检出。先验证 ASAN 链接状态。

已执行 2 条命令
关键发现：ASAN 根本没有链接进去——exe 导入表无 clang_rt.asan_dynamic-x86_64.dll。MSVC 的 /fsanitize=fuzzer 不隐含 ASAN，必须显式 /fsanitize=address,fuzzer。当前 5 个目标只有覆盖率引导、零内存安全插桩——这正是堆损坏落到 CRT 调试堆上的原因。读完整 CMakeLists 修正。

已读取 1 个文件
修正前先看主构建的 ASAN 开关如何处理 MSVC 标志（尤其 /RTC1 与 ASAN 互斥问题）。

已读取 2 个文件，搜索 6 次文件
查 build_asan 的既有配置，确认 Debug 配置下 /fsanitize=address 与 /RTC1 的实际处理。

已执行 2 条命令
build_asan 的 Debug 对象证明本工具链（VS 2026 / 14.51）接受 /RTC1+/fsanitize=address 共存。按既有工作模式修正 fuzz 构建标志。

已编辑 3 个文件
重新配置并全量重建 fuzz 目标（含插桩核心重编译，后台运行）。

已执行 1 条命令
重建进行中。趁间隙清理刚才读代码时注意到的 verthys_partition.c 遗留调试输出（[PTDBG] fprintf）。

已搜索 1 次文件
后台重建失败了，先查原因。（另发现 26 处遗留调试 fprintf——生产代码信息泄露面，稍后统一清理。）

已执行 3 条命令
我的管道过滤截断了错误输出。重跑构建并全量落盘。

已执行 1 条命令
LNK2019 缺 main —— 疑似 cl 不识别逗号组合形式而整项忽略了。查 D9002 警告与实际传入的编译选项。

已执行 2 条命令
确认：此 cl 不接受逗号组合（D9002 整项忽略）。改用两个独立开关并验证。

已执行 1 条命令
独立开关被接受（无 D9002）。修正 CMakeLists 为两个独立选项。

已编辑 4 个文件，执行 1 条命令
重建后台进行。现在清理 26 处生产代码遗留调试输出（[PTDBG]/[V3DBG]/[UPLDBG] —— 信息泄露面 + 服务进程无控制台语义）。先处理 verthys_partition.c。

已编辑 2 个文件，读取 1 个文件
重建成功。验证 ASAN 是否真正链接进 fuzz 目标。

已执行 1 条命令
ASAN 已正确链接。跑 5 目标冒烟门。

已执行 1 条命令
5/5 冒烟全绿（ASAN 生效）。现在完成全部代码修改（清理 V3DBG/UPLDBG 调试输出），再统一重建并跑 10 分钟/目标的完整验证。

已编辑 15 个文件，读取 5 个文件，搜索 2 次文件
全部调试输出清理完成（余下 [CNG-DBG] 是带开关的正规诊断宏，保留）。现在统一验证。先看 dev 构建脚本是否含测试执行。

已搜索 1 次文件
两个构建验证并行启动：fuzz 全程（10 分钟/目标）+ dev 全量测试。

已执行 2 条命令
验证并行跑。趁此推进任务 8（文档同步）。先看 PLAYBOOK 的 WP-10/WP-12 小节现状。

已读取 1 个文件
历史对话已被压缩
已读取 2 个文件
Fuzz 构建作业已完成 — 构建成功（5 个目标 + ASAN DLL + 种子，冒烟测试 5/5 通过），但 10 分钟的运行全部因参数格式错误而立即退出：No such file or directory: 600; exiting。这是经典的 libFuzzer 参数问题 — -max_total_time 600（空格分隔）被解析为位置参数 "600"（被视作语料库路径）。让我检查一下脚本。

已读取 1 个文件
Found it. Line 79 of the fuzz script:


PowerShell

& $exe $dir -max_total_time=($Minutes * 60) ...
PowerShell splits -max_total_time= and ($Minutes * 60) into two arguments — libFuzzer receives positional 600, treats it as a corpus path, and exits immediately ("No such file or directory: 600"). Let me check the CI workflow for the same pattern.

已搜索 1 次文件
CI workflow uses literal -max_total_time=600 so it's fine — only the local script has the bug. Also, the dev test job just completed — let me check its result.

已执行 1 条命令
Dev test suite: 249 passed, 3 failed — all 3 failures in the new property tests (prop_lsm_insert_find_delete, prop_txn_commit_rollback_consistency, and prop_txn_crash_no_resurrection which is likely cascading from the second test's early-return without cleanup leaving the verthys file locked). Let me examine the test code.

已读取 1 个文件
Both failures are shadow-model mismatches in the new property tests (extent property passed). Failure 3 is cascading — failure 2's early return 1 skipped Verthys_Deinit, leaving the verthys file locked, so the next test's p3_cleanup() couldn't delete it and Verthys_CreateWithPreset failed. Let me examine the actual API semantics to find the real mismatches.

已读取 1 个文件，搜索 2 次文件
Found a real production bug. At verthys_lsm.c:1225: if (out != NULL && out->tombstone) — when out == NULL (the probe form), a tombstone found in an SSTable returns VERTHYS_OK instead of NOTFOUND. The MemTable branch checks me->tombstone before touching out, but the SSTable branch only checks out->tombstone when out != NULL. Let me verify the SSTable find tolerates NULL out, and check how production code uses this probe form.

已读取 1 个文件
Production verthys_api_v3_delete/delete_many use this exact NULL-probe form as an existence check — so the property test caught a genuine core-index defect. Let me see the full picture: the rest of verthys_lsm_get, verthys_lsm_sstable_find's NULL-out handling, and verthys_txn_v3_delete's tombstone tolerance.

已读取 2 个文件
Now let me examine verthys_v3_add_record_in_txn, Verthys_GetRecord's V3 path, and verthys_txn_v3_rollback to understand the visibility semantics for failure 2.

已读取 2 个文件
verthys_api_v3_get itself is clean. The record must be getting lost in the LSM. Key suspicion: interaction between rollback's MemTable purge, txid reuse, and auto-flush. Let me read the transaction implementation.

已读取 2 个文件
Let me read verthys_lsm_rollback_txid and the LSM WAL/flush internals — the visibility loss must originate there.

已读取 3 个文件，搜索 1 次文件
The MemTable purge on rollback rebuilds by dropping entries with created_txid == txid. Critical question: when a delete writes a tombstone, does it replace the original entry in the MemTable (newest-wins)? If so, rollback purges the tombstone but the original is already gone — a real data-loss bug. Let me verify the MemTable semantics.

已搜索 1 次文件
Root cause of failure 2 confirmed — a genuine production data-loss bug: the MemTable uses newest-wins in-place replacement (RoW), so verthys_txn_v3_delete's tombstone overwrites the original entry. Rollback's purge then drops the tombstone (created_txid == txid), but the original is already destroyed — the deleted record vanishes. Same destructive pattern likely exists in the crash-recovery discard path. Let me read the recovery code to confirm.

已读取 1 个文件
Confirmed — the recovery discard path (line 717, verthys_lsm_purge_txid per discarded txid) has the same data-loss pattern: a discarded group's tombstone overwrote a MemTable-resident original during WAL replay, and purging the tombstone destroys the record.

Let me check remaining details: verthys_lsm_purge_txid callers, verthys_lsm_sstable_find's NULL-out handling, and the recovery flow around the flush.

已读取 1 个文件，搜索 3 次文件
scan_block tolerates out == NULL but the tombstone flag is then lost — confirming bug 1's fix needs a local probe entry + name scratch. Now let me read lsm_open_internal (for the max_lid derivation and the verthys_lsm_purge_txid comment reference) before writing the fixes.

已读取 1 个文件
Let me check the background thread's behavior (does it ever flush, which would interact with the rollback precondition?) and the memtable max_lid helper.

已读取 1 个文件
Background thread only compacts SSTables — never flushes — so the rollback precondition is safe. I now have the complete picture. Two production bugs found by the property tests:

verthys_lsm_get NULL-probe: SSTable tombstone returns VERTHYS_OK instead of NOTFOUND (tombstone only checked when out != NULL) — breaks Verthys_DeleteRecord's existence-check contract.

Rollback/recovery data loss: MemTable is newest-wins (RoW), so a delete's tombstone overwrites the original entry; rollback/recovery purge drops the tombstone and the original is destroyed. Runtime rollback (delete-then-rollback loses the record) and crash recovery (discard of an uncommitted delete loses the record) are both affected.

思考过程
现在启动 dev 全量重建 + 测试（木马清除后 EXE 被删，需重新构建）。先确认脚本参数。

已读取 1 个文件，搜索 1 次文件
启动 dev 构建 + 全量测试（增量重建，后台运行）。

已执行 1 条命令
构建进行中。趁此时间更新 PLAYBOOK WP-12 执行痕迹，先查看当前 WP-12 章节。

已读取 3 个文件，搜索 1 次文件
趁构建进行，检查构建进度。

已读取 1 个文件
构建成功，测试正在运行。等待测试完成并检查结果。

已执行 4 条命令
dev 全量测试 254/254 全绿（含 6 项属性测试与缺陷②/②b 定向回归）。现在启动 fuzz 全程（5 目标 × 10 分钟，后台），并行推进其余任务。

已执行 1 条命令
fuzz 已在后台运行。同时进行 3 连绿的第 2 次运行，并查阅 E-8 闭环要求。

已读取 4 个文件，搜索 9 次文件，执行 1 条命令
命令执行中
.\build_dev\core\tests\Debug\verthys_tests.exe

.\build_dev\core\tests\Debug\verthys_tests.exe
[Background Job] command_id=job-f7dfb9e394b54cf5a257464197b15645, log_path=C:\Users\Administrator\AppData\Local\Temp\trae-agent-toolhost\jobs\job-f7dfb9e394b54cf5a257464197b15645\output.log
Use CheckCommandStatus with this command_id to get output updates.
Use StopCommand to terminate if needed.
找到 3 行
E-8|verthys-worker|verthys-tauri
未找到结果
已读取
V3_UPGRADE_PLAYBOOK.md
思考
已搜索
verthys-worker/*
未找到结果
搜索了 10 个文件
verthys-tauri/*
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\__blur_lab.html
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\vite.config.ts
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\package.json
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\shm_schema.rs
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\package-lock.json
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\tsconfig.node.json
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\generate-icon.cjs
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\index.html
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\tsconfig.json
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\.gitignore
搜索了 1 个文件
src-tauri/**/Cargo.toml
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\src-tauri\Cargo.toml
已读取
Cargo.toml
思考
搜索了 1 个文件
**/verthys-worker*/**/Cargo.toml
c:\Users\Administrator\Desktop\Project\Verthys\verthys-tauri\verthys-worker\Cargo.toml
已搜索
*/Cargo.toml
未找到结果
已读取
Cargo.toml
思考
找到 15 行
verthys\.dll|Library\(|binaries
未找到结果
找到 23 行
dll_path|canonicalize|parent|VerthysWorker::new
未找到结果
思考
已读取
package.json
思考
找到 40 行
verthys-worker|verthys
未找到结果
思考
Now I understand the E-8 production artifact chain:

build_core.release.ps1 → build/core/Release/verthys.dll (with .vsec injection)
cd verthys-tauri/verthys-worker && cargo build --release → verthys-tauri/verthys-worker/target/release/verthys-worker.exe
Stage:
Copy-Item build/core/Release/verthys.dll verthys-tauri/src-tauri/verthys.dll
Copy-Item verthys-tauri/verthys-worker/target/release/verthys-worker.exe verthys-tauri/src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe
build.rs verifies hash consistency between staged and fresh artifacts.
Plan (task 2 + task 9 Release chain):

Run build_core.release.ps1 -NoPause (Release build + .vsec injection). ~5-10 min.
cargo build --release in verthys-worker.
Stage both artifacts.
Verify .vsec + .rhat present in Release DLL, export baseline check (dumpbin vs ci/export_baseline.txt).
But CPU contention: fuzz is running in background (1 worker core), test run 2 is running (1 core). Release build can use multiple cores. Machine likely has enough. But wait — the release build script may also run tests? Let me check build_core.release.ps1 quickly. Also, an important caution: build_core.release.ps1 writes to build/ directory — separate from build_dev/build_fuzz. No conflicts.

Also — one concern: running Release build concurrently with fuzz might slow both, but no correctness risk. However, to be careful about system stability and clean timing, maybe sequence: wait for test run 2 → start test run 3 → then release build + worker build → stage → verify. Meanwhile fuzz runs throughout.

Actually, let me check the release script content first to see what it does (tests? .vsec injection? export check?).


E-8 闭环链路已明确：Release DLL → worker 构建 → 双暂存（build.rs 哈希校验）。先看 release 脚本内容。

已读取 1 个文件
release 脚本流程明确（Release 构建 + .vsec v2 注入，无测试）。检查第 2 轮测试进度。

已执行 1 条命令
两项后台任务正常推进（测试第 2 轮进行中；fuzz 第一目标 45k exec/s 无崩溃）。现在启动 Release 生产构建（独立 build/ 目录，互不干扰）。

已执行 1 条命令
三个后台任务并行推进中。现在撰写 PLAYBOOK WP-12 执行留痕。先查看 WP 状态总表当前标记。

已读取 1 个文件
Release 构建失败，查看原因。

已执行 1 条命令
Release 脚本解析失败——典型的 BOM 丢失问题（UTF-8 中文被 PowerShell 5.1 按 GBK 解码破坏字符串配对）。检查所有脚本的 BOM 状态。

已执行 1 条命令
三个脚本丢失 BOM（release/k1_asan_run/run_test_diag——应为早前编辑或恶意软件清理时被剥离）。按项目规范恢复 UTF-8 with BOM。

已执行 1 条命令
BOM 已恢复。重新启动 Release 构建。

已执行 1 条命令
趁构建运行，撰写 WP-12 执行留痕。先看 §9 里程碑矩阵格式。

已读取 1 个文件
Release 构建再次失败，查看日志。

已执行 1 条命令
build/ 目录存在陈旧 CMake 缓存（生成器/平台不匹配）。使用 -Clean 全新构建。

已执行 1 条命令
Release 干净构建已启动。现在写入 WP-12 执行留痕到 PLAYBOOK。