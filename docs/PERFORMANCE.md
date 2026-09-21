# PERFORMANCE — Verthys 性能基线与优化

> 汇总性能基线指标、测量方法与已知瓶颈，并对照工程刚性底线说明达标情况，不夸大未验证数字。
>
> Last updated: 2026-09-19 · 维护人：K1Super

---

> 源稿：《archive/PERFORMANCE_ARCHITECTURE.md》与《archive/DOCUMENTATION/性能.md》内容基本一致（目标态性能数字）；《archive/DOCUMENTATION/解锁.md》给出解锁分阶段耗时建模。本节以代码 `core/tests/perf` 为唯一可复现证据，源稿数字标注复现状态。

## 1. 性能基线指标表

| 指标 | 源稿目标值（典型硬件 4C/16G/SSD） | 代码/测试可复现性 | 备注 |
|---|---|---|---|
| 解锁时间（BALANCED） | ≤ 2.5 s；温启动 ≤ 1.2 s | 未复现（见下） | `test_perf_baseline` 仅断言 `unlock < 5s`（上界健全性） |
| 单条 Add 记录 | P95 < 20 ms | 源稿数据，未在测试中复现 | 无 P95 断言 |
| 单条 Get 记录 | P95 < 10 ms | 源稿数据，未在测试中复现 | 无 P95 断言 |
| 单条 Delete 记录 | P95 < 15 ms | 源稿数据，未在测试中复现 | 无 P95 断言 |
| 全量扫描 | ≥ 50,000 条/秒（不含明文）；≥ 20,000 条/秒（明文） | 源稿数据，未在测试中复现 | SHM 零拷贝传输已落地，但无量化基准 |
| 内存占用 | 空闲 < 50MB；空库 < 100MB；10 万条 < 300MB；峰值 ≤ 512MB | 部分可复现 | 512MB 预算在 `secure_allocator` 记账存在，量化断言缺失 |
| 后台 CPU | 单核 ≤ 25%，BELOW_NORMAL | 已落地 | worker 以 `BELOW_NORMAL_PRIORITY_CLASS` 启动（代码核实） |
| IO | 顺序写 ≥ 100MB/s；随机读 ≤ 5ms | 源稿数据，未在测试中复现 | 无吞吐基准 |

## 2. 测量方法

`core/tests/perf/` 实际存在两个基准文件：

- `test_perf_baseline.c` — `perf_baseline_unlock_write_read`：二次解锁耗时（温缓存热路径）、50 条写入吞吐、批量读取吞吐；断言仅健全性（解锁 < 5s、吞吐 > 0），输出 stdout 供 CI 采集。
- `test_perf_prefetch.c` — 8 项 `perf_*`：BALANCED 开启/ SECURE 关闭温缓存、二次解锁命中、缓存损坏回退磁盘、损坏头跳过缓存、`Verthys_GetDiagnostics` 指标完整、无缓存冷启动、Argon2id 漂移指标采集、写入/读取吞吐。

运行命令（读 `tests/CMakeLists.txt` + `test_runner.c` 核实）：

- 测试合并为单一可执行 `verthys_tests`，CMake 注册的测试名只有 `verthys_tests`（`add_test(NAME verthys_tests COMMAND verthys_tests)`）。
- 按子串过滤：`verthys_tests.exe perf`（argv[1] 子串，匹配所有 `perf_*`）。
- `ctest -C Release -R perf` **无法定位性能测试**——注册测试名不含 “perf”，`-R perf` 匹配 0 项；正确姿势是构建后直接跑 `verthys_tests.exe perf`（或 `ctest -R verthys_tests` 跑全部）。

## 3. 已知瓶颈与优化记录（按时间倒序）

| 优化项 | 措施 | 来源 |
|---|---|---|
| 后台任务降级 | worker 以 `BELOW_NORMAL_PRIORITY_CLASS` 启动，消除解锁后后台任务抢占 UI | `worker/session.rs`（代码核实） |
| 索引预读无条件启动 | 修复“缓存假阳性→串行磁盘 IO”退化，预读 IO 被 Argon2id CPU 时间掩盖 | `test_perf_prefetch.c` |
| 温启动缓存（.idx_cache） | LSM/MemTable 快照 + SSTable 元数据缓存，冷 150ms → 温 30ms（10 万条） | 源稿 |
| 解锁流水线 S0–S6 | Argon2id（S2）与超级块读取（S1）并行；CNG 批量导入 | `verthys_unlock_pipeline.h`（代码核实） |
| Argon2id 校准 | 目标 1200ms → 1000ms；三阶段精确校准；漂移自调档 | 源稿《解锁.md》 |
| 超级块副本并行读 | 3 副本并行 + 取最快 2 个有效 + 副本内存缓存 | 源稿 |
| LSM/Extent 架构 | 写入 O(1) 追加、内容寻址去重、后台 compaction/GC 限速 | 源稿 |

## 4. 与刚性底线（关键接口 P95 ≤ 200ms）对照

工程底线《ENGINEERING_CONSTRAINTS.md》规定“关键接口常规负载 P95 ≤ 200ms（允许按业务场景调整阈值，但需显式定义）”。对照结论：

1. **CRUD 类关键接口**：源稿目标（Add/Get/Delete P95 < 20/10/15ms）处于 200ms 红线内，但**当前无对应自动化基准确认**，不能声称已达标——仅有 `perf_baseline` 的宽松健全性断言（>0 吞吐、<5s 解锁）。
2. **解锁接口**：属一次性高强度密钥派生（Argon2id 主导，>1s），非“常规负载 CRUD”，按业务场景显式定义阈值为 **BALANCED ≤ 2.5s / 温启动 ≤ 1.2s**（源稿），仍显著高于 200ms —— 该阈值为显式业务豁免，非性能回归项。
3. **诚实声明**：在补齐可量化的 P50/P95/P99 基准与其 CI 阈值门（源稿 §8.2 所述）之前，本文件对“是否已达标”不给出肯定结论；达标需以测试证据为准（见 [TESTING.md](TESTING.md)）。