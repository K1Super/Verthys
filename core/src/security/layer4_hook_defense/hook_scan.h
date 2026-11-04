/*
 * hook_scan.h — ntdll 导出基线扫描与 IAT 校验（内部模块，不导出）
 *
 * 职责：
 *   1. 从磁盘 System32\ntdll.dll 解析安全模块实际使用的 Nt 导出 RVA，
 *      缓存函数入口字节作为基线；
 *   2. 与内存中 ntdll 的 syscall stub 比较，识别 Inline Hook；
 *   3. 校验自身 PE 导入表里指向 ntdll 目标函数的 IAT 槽值。
 *
 * 分级处置（禁止首次异常直接终止）：
 *   - 内存字节仍为可识别的标准 stub，仅与磁盘基线不一致（Windows 更新/
 *     热补丁未重启）→ 证据过期（STALE）+ 遥测，不终止；
 *   - 内存首字节呈 Hook 特征（E9/EB/FF25/68..C3/48 B8..FF E0）→ 首次遥测，
 *     连续两次终止；
 *   - 基线解析失败/目标缺失 → 不可用（UNAVAILABLE），不终止。
 *
 * 线程契约：
 *   - hook_scan_init 幂等（InitOnce）；可在 BOOT 闭包之前调用。
 *   - run_once 持内部 SRWLOCK 串行化，可与定时器/解锁路径并发调用。
 *   - 周期定时器 60s；stop 使用 DeleteTimerQueueEx 等待在途回调退出。
 */
#ifndef VERTHYS_HOOK_SCAN_H
#define VERTHYS_HOOK_SCAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HOOK_SCAN_UNAVAILABLE 0u
#define HOOK_SCAN_CLEAN       1u
#define HOOK_SCAN_ANOMALY     2u
#define HOOK_SCAN_STALE       3u

/* 周期与证据有效期（毫秒） */
#define HOOK_SCAN_PERIOD_MS       60000u
#define HOOK_SCAN_EVIDENCE_TTL_MS 120000u

/*
 * 初始化：解析磁盘 ntdll 基线与目标 RVA，并立即执行一次扫描。
 * 解析失败不拒绝启动——状态为 UNAVAILABLE，由 defense_closure 如实降级。
 * 返回 0（初始化流程完成；扫描结论经 hook_scan_get_state 查询）。
 */
int hook_scan_init(void);

/* 立即扫描一次（解锁后/测试驱动）。返回 0=扫描完成，-1=未初始化。 */
int hook_scan_run_once(void);

/*
 * 启动/停止 60s 周期扫描（TimerQueue）。
 * 启动幂等；停止等待在途回调退出。初始化未完成时启动为空操作。
 */
int hook_scan_start_periodic(void);
void hook_scan_stop_periodic(void);

/*
 * 最近一次扫描结论；CLEAN 证据超过有效期（默认 120s）按 STALE 返回；
 * 从未扫描或基线不可用返回 UNAVAILABLE。
 */
uint32_t hook_scan_get_state(void);

/* 最近一次扫描的单调毫秒时间戳（0=从未扫描；诊断/测试） */
uint64_t hook_scan_get_last_scan_ms(void);

/*
 * 纯判定（测试注入与生产共用）：
 *   obs[i].baseline_ok  该目标基线可用
 *   obs[i].mem_matches  内存 stub 与磁盘基线一致
 *   obs[i].mem_hook_shaped 不一致时内存首字节呈 Hook 特征
 *   obs[i].iat_matches  IAT 槽值与磁盘导出 RVA 一致
 * 连续两次 Hook 特征 → *kill=1（仅高置信度终止）；其余异常只遥测。
 * mem_streak/iat_streak 为调用方持有的连续异常计数（长度 >= count），
 * 函数会就地更新；命中正常时清零。返回 HOOK_SCAN_* 状态。
 */
typedef struct {
    int baseline_ok;
    int mem_matches;
    int mem_hook_shaped;
    int iat_matches;
} HookScanTargetObs;

uint32_t hook_scan_evaluate(const HookScanTargetObs *obs, uint32_t count,
                            uint32_t *mem_streak, uint32_t *iat_streak,
                            int *kill);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_HOOK_SCAN_H */
