/*
 * runtime_hash.h — 运行时函数级哈希校验（内部模块，不导出）
 *
 * V3 升级：防运行时代码补丁（hotpatching）攻击。
 *   与 .vsec 全节校验互补（函数粒度 vs 节粒度）：
 *   - .vsec：启动时从磁盘重算 .text/.rdata 文件内容 HMAC —— 防分发篡改；
 *   - .rhat：解锁成功后 + 每 30 分钟重算关键函数【内存映像】哈希
 *     —— 防运行时内存补丁（VirtualProtect + 改字节注入跳转）。
 *
 * 机制（构建期 → 运行期闭环）：
 *   1. 构建期（rhash_gen 工具，core/tools/rhash_gen.c）：链接完成后解析
 *      map 文件（符号名 → RVA）与 .pdata（精确函数边界）与 .reloc（重定位
 *      表），对 X 清单每个关键函数计算 BLAKE2b-256（libsodium
 *      crypto_generichash；域标签前缀做域分离），直接补丁 DLL/EXE 的
 *      .rhat 只读节（复用 .vsec 的"构建后补丁"模式——避免两遍链接）。
 *   2. 运行期（本文件 scan）：解析自身内存映像的 .reloc，对每条表项
 *      复制函数字节并掩码重定位槽位（与构建期归一化方式逐字节一致，
 *      杜绝 ASLR 重定位导致的跨启动误报——.vsec 同类教训，见
 *      integrity.h 完整性设计注记），重算 BLAKE2b 与表内基准比对。
 *   3. 失配 = 进程内存被篡改（高置信度）→ KILL 级应急响应
 *      （EMERG_SIG_PROCESS_TAMPER；.vsec 文件篡改走 INTEGRITY_FAIL，
 *      两者信号语义区分）。
 *
 * 重定位掩码（跨启动稳定性的关键）：
 *   x64 映像 .text 内少量指令含绝对地址（mov rax, imm64 等），加载器
 *   重定位后内存字节 ≠ 文件字节。双侧（构建期文件 / 运行期内存）将
 *   .reloc 覆盖的槽位清零后再哈希 → 同一函数两视角归一。已掩码槽位
 *   内的补丁不可检出（已知取舍：该槽位本身是绝对地址操作数，攻击者
 *   改写等价于指针重定向，其余全部字节仍受保护）。
 *
 * .rhat 节布局（构建后补丁，全零 = 未配置 = 跳过，开发构建语义）：
 *   [0..3]   magic  = "VRHT"
 *   [4..5]   version= 0x0001
 *   [6..7]   count  = 有效表项数（0 = 未配置）
 *   [8..11]  flags  = 0（预留）
 *   [12..15] 保留
 *   [16 + i*48 .. +48) 表项 i：
 *     u64 rva        函数 RVA（映像基相对）
 *     u32 size       函数字节数（.pdata 精确边界）
 *     u32 x_index    X 清单序号（诊断用）
 *     u8  hash[32]  BLAKE2b-256(标签 ‖ 掩码后函数字节)
 *
 * 表自身防篡改：.rhat 节纳入 .vsec v2 校验范围（HMAC 第三槽，
 * integrity 完整性模块扩展）——攻击者文件级改表 = 分发篡改 = 启动拒绝。
 */
#ifndef VERTHYS_RUNTIME_HASH_H
#define VERTHYS_RUNTIME_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */

/* 域分离标签（前缀进哈希输入；非秘密，仅防跨用途碰撞） */
#define VERTHYS_RHASH_LABEL "verthys/runtime-hash-v1"

/* 表容量上限（X 清单 ≤ 此值；节大小 = 头 16B + 48B × 此值） */
#define VERTHYS_RUNTIME_HASH_MAX 40u

/* 周期重算间隔（每 30 分钟） */
#define VERTHYS_RUNTIME_HASH_INTERVAL_MS (30u * 60u * 1000u)

/* 单函数字节数上限（超限 = 构建期工具报错，防静态缓冲溢出） */
#define VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES 65536u

/* .rhat 魔数与版本 */
#define VERTHYS_RHAT_MAGIC0 'V'
#define VERTHYS_RHAT_MAGIC1 'R'
#define VERTHYS_RHAT_MAGIC2 'H'
#define VERTHYS_RHAT_MAGIC3 'T'
#define VERTHYS_RHAT_VERSION 1u

/*
 * 关键函数清单（X-macro，~30 个）
 * 约束：
 *   - 仅限非 static 外部符号（map "Publics by Value" 可见）；
 *   - 增删条目 = 构建期 rhash_gen 与运行期两侧同步（同一宏展开）；
 *   - 清单必须全命中：任一符号构建期缺失 → 构建失败（禁静默降级）；
 *   - 清单函数声明处必须标注 __declspec(noinline)（Release /GL+/LTCG
 *     下小函数会被跨模块内联进调用方，本体随后被 /OPT:REF 丢弃——
 *     map 缺符号即 rhash_gen 报错暴露；且内联副本不受 .rhat 保护，
 *     noinline 是"被哈希代码体 = 实际执行代码体"的语义前提）。
 * 覆盖面：加解密主路径 / 密钥组生命周期 / 轮换 / 超块事务 / 分区表 /
 * WAL / 六阶段事务 / LSM / 解锁流水线 / 应急 / 完整性 / 本模块自身。
 */
#define VERTHYS_RUNTIME_HASH_FUNCS(X) \
    X(verthys_cng_aead_encrypt) \
    X(verthys_cng_aead_decrypt) \
    X(verthys_cng_aead_import_key) \
    X(verthys_cng_km_import_batch) \
    X(verthys_cng_km_wrap_key) \
    X(verthys_cng_km_rotate_abc) \
    X(verthys_rekey_auto_rotate) \
    X(verthys_random_bytes) \
    X(verthys_generichash) \
    X(verthys_hmac_sha256) \
    X(vsb_txn_v3_begin) \
    X(vsb_txn_v3_commit) \
    X(vsb_txn_v3_rollback) \
    X(verthys_partition_table_save) \
    X(verthys_partition_table_load) \
    X(verthys_wal_append) \
    X(verthys_wal_replay_ex) \
    X(verthys_txn_v3_begin) \
    X(verthys_txn_v3_commit) \
    X(verthys_txn_v3_confirm) \
    X(verthys_txn_v3_rollback) \
    X(verthys_txn_v3_recover) \
    X(verthys_lsm_put) \
    X(verthys_lsm_get) \
    X(verthys_lsm_flush) \
    X(verthys_lsm_compact) \
    X(verthys_unlock_pipeline_run) \
    X(verthys_v3_open_existing) \
    X(integrity_verify_startup) \
    X(emergency_report) \
    X(emergency_trigger) \
    X(runtime_hash_scan)

/* ---------- .rhat 节二进制布局（构建工具 rhash_gen 与运行期共享） ----------
 * 单一事实源：两侧必须逐字节一致（pack(1)；修改任意字段 = 两侧同步）。
 */
#pragma pack(push, 1)

typedef struct VerthysRhatEntry {
    uint64_t rva;          /* 函数 RVA（映像基相对，文件/内存同值） */
    uint32_t size;         /* 函数字节数（.pdata 精确边界） */
    uint32_t x_index;      /* X 清单序号（诊断用） */
    uint8_t  hash[32];     /* BLAKE2b-256(标签 ‖ 掩码后函数字节) */
} VerthysRhatEntry;         /* 48 字节 */

typedef struct VerthysRhatBlob {
    uint8_t  magic[4];     /* "VRHT" */
    uint16_t version;     /* VERTHYS_RHAT_VERSION */
    uint16_t count;       /* 有效表项数（0 = 未配置） */
    uint32_t flags;       /* 预留 0 */
    uint32_t reserved;
    VerthysRhatEntry entry[VERTHYS_RUNTIME_HASH_MAX];
} VerthysRhatBlob;          /* 16 + 48×40 = 1936 字节 */

#pragma pack(pop)

/* ---------- 查询 / 编排 ---------- */

/*
 * 全量扫描（纯检查，无应急副作用——测试与诊断用）。
 *   校验对象：.rhat 表（若已配置）+ 测试白盒 overlay（若已安装）。
 * 返回失配条数（0 = 全通过或未配置）。
 * 基础设施异常（PE 解析失败 / 哈希计算失败 / 超限）按"不阻断不误报"
 * 惯例返回 0（与 integrity.c anti_debug 一致）。
 */
__declspec(noinline) int runtime_hash_scan(void);

/*
 * 表是否已配置（count > 0 且魔数/版本合法）。
 * 开发构建（.rhat 全零）返回 0——校验跳过。
 */
int runtime_hash_configured(void);

/*
 * 生产校验入口：scan + 失配 → KILL 级应急响应
 * （emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_PROCESS_TAMPER)，
 *  进程终止由应急模块执行，本函数不返回错误——进程不再继续运行）。
 * 接线：Verthys_Unlock 成功后。
 */
void runtime_hash_verify(void);

/*
 * 周期重算（时间门控，每 30 分钟）：
 *   距上次全量扫描 < 30 分钟 → 直接返回（单次 GetTickCount64 开销）；
 *   到期 → 全量 verify。接线于写路径 API 入口（Add/Delete/Import/
 *   ChangePassword/Flush——均持 api_mutex 串行化）。
 * 首次调用（进程启动后）立即执行一次全量校验（last=0 → 已过期）。
 */
void runtime_hash_verify_periodic(void);

/* ---------- 测试白盒（仅 tests 链接使用，生产代码禁调） ---------- */

/*
 * 安装一条 overlay 测试基准：对 [addr, addr+len) 以当前内存内容计算
 * 掩码哈希作为基准（自基线——测试校验的是检测机制而非构建期签名）。
 * overlay 与 .rhat 表叠加参与 scan。最多 VERTHYS_RUNTIME_HASH_MAX 条，
 * 满载/参数非法返回非 0。
 */
int runtime_hash_test_install(const void *addr, size_t len);

/*
 * 查询函数是否被任何已配置表项（.rhat 或 overlay）覆盖。
 * 命中返回 1 并输出表内记录的覆盖区间（func 所在条目的基址与长度，
 * 供测试 VirtualProtect 后改字节定位）；未命中返回 0。
 */
int runtime_hash_lookup(const void *func,
                        const void **out_base, size_t *out_len);

/* 清空全部 overlay 测试基准（测试 teardown 用） */
void runtime_hash_test_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_RUNTIME_HASH_H */
