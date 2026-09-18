# 路线图（ROADMAP）

> 按"已完成/进行中/候选方向"三态记录 Verthys 演进路线与里程碑，已完成项以 git log 与报告为据。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档遵循 "属性归属性" 纪律：已完成项必须有提交 hash 或报告佐证；进行中项必须有工作树证据；候选方向仅为 `archive/current_progress.md` 已提及、未排期的提案，不做未来计划承诺。

---

## 1. 一页速览（三栏）

| 已完成（有提交/报告佐证） | 进行中（有工作树证据） | 候选方向（未排期提案） |
|---|---|---|
| 代码基线 init（`5cabc99`） | 文档工程化整合（docs 归整入 archive/，`DOCUMENTATION_CHECKLIST.md`/`README.md` 新建，工作树 18 处改动待提交） | fuzz 5 目标 × 10 分钟全程 CI 验收（`current_progress.md` 提及，待补跑） |
| V3 升级 WP-0 基线固化 + K-1 修复（`be23497`） | M4/M5 复验收口（重装后补跑 Release 链路与 3 连绿） | worker 正式构建 + DLL/EXE 双暂存（E-8 留痕"待重装后执行"） |
| V3 全系升级 WP-1..14（`99e2225` 代码落盘；WP 级留痕见报告） | | Release `.vsec`+`.rhat` 链路 + `dumpbin` 导出面比对复验 |
| 品牌重塑 ValtCore→Verthys（`610bf4c`） | | Authenticode 签名（尚未落地） |
| 清理旧容器（`2da2821`） | | |

---

## 2. 已完成（详表，按时间倒序）

| 条目 | 佐证提交（hash） | 佐证报告 | 日期 |
|---|---|---|---|
| 清理旧容器：删除 VALT 旧魔数测试遗留容器 | `2da2821` | `archive/Verthys品牌整改验证交付报告.md` §五 | 2026-09-19 |
| 品牌重塑 ValtCore/vault→Verthys 全量整改（导出符号/类型/容器魔数 VALT→VERT/域密钥双侧/扩展名 .verthys/事件 scheme/环境变量/文件与 CMake 命名） | `610bf4c` | `archive/Verthys品牌整改验证交付报告.md` | 2026-09-19 |
| V3 全系升级代码基线落盘（WP-1..14 工作包；注：git 无 WP 级独立提交，代码以一次 init 落盘） | `99e2225` | `archive/V3_UPGRADE_PLAYBOOK.md` §5/§9、`archive/PROJECT_DOCUMENTATION.md` v5.0 | 2026-09-14 |
| WP-0 基线固化与依赖 vendoring（flatcc/xxhash）+ K-1 测试顺序依赖修复 | `be23497` | `archive/V3_UPGRADE_PLAYBOOK.md` §5 WP-0/WP-13 | 2026-09-01 |
| 迭代开发（updata） | `86b4081`、`ed095d5` 等 | — | 2026-08-25 ~ 08-30 |
| 代码基线 init | `5cabc99` | — | 2026-07-01 |

> WP-1..14 的逐包完成日期（2026-09-01 ~ 09-15）以 `archive/V3_UPGRADE_PLAYBOOK.md` §9 里程碑矩阵为准，git log 中无逐包提交——已完成的实现以报告留痕为据、代码落盘以 `99e2225` 为据。

---

## 3. 里程碑表（M0 至今，按日期）

| 里程碑 | 工作包 | 验收门 | git log 日期/状态 |
|---|---|---|---|
| **M0 基线恢复** | WP-13, WP-0 | 全量 3 连绿；flatcc/xxhash vendored + codegen 跑通 | `be23497`（2026-09-01）✅ |
| **M1 内核密钥安全** | WP-1, WP-7 | test_cng_kernel + test_secure_allocator 全绿；MEM_DUMP 判据可 BLOCKED | 2026-09-01（报告）✅ |
| **M2 V3 容器就绪** | WP-2..5 | V3 全链路绿；解锁 ≤2.5s；WAL 崩溃注入矩阵；删除清单构建绿 | 2026-09-02~15（报告）✅ |
| **M3 纵深防御闭环** | WP-6, WP-8, WP-9, WP-11 | defense_closure 7/7 BLOCKED；runtime_hash 补丁检测通过 | 2026-09-15（报告）✅ |
| **M4 测试体系完备** | WP-10, WP-12, WP-14 | 属性测试 + P2 清零完成；fuzz 5 目标全程待复验 | 🔶 部分完成 |
| **M5 生产就绪** | 全部 | 品牌整改完成；3 连绿 + 全链路复验收口待重装后执行 | `610bf4c`（2026-09-19）🔶 |

---

## 4. 关键依赖与风险

| 类别 | 项 | 说明 / 缓解 |
|---|---|---|
| 技术风险 | Release 产物未 Authenticode 签名 | `.vsec`/`.rhat` 注入后签名流程尚为"若有"；发布前需补齐签名，否则触发杀软告警 |
| 技术风险 | `/guard:longjmp` 不可用 | 工具链缺 `guardcfw.h` 且与 `/guard:cf` 互斥（偏差 D-1），由 `/CETCOMPAT` 影子栈覆盖意图（见 `cmake/VerthysHardening.cmake` 留痕） |
| 运维依赖 | 工具链与安全环境正常 | 依赖 VS 2026 / MSVC 14.51 / SDK 10.0.26100 工具链可用、构建与测试产物运行环境正常 |
| 复验依赖 | M4/M5 全程验收待执行 | fuzz 5 目标 × 10 分钟、Release `.vsec`+`.rhat` 链路、3 连绿、`dumpbin` 导出面比对为生产就绪的前置（见 `archive/current_progress.md`） |