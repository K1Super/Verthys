/*
 * machine_state.h — 机器级令牌桶、每用户配额与原子持久化
 *
 * 并发语义：
 *   - 所有状态访问在同一 SRWLOCK 独占区内完成；
 *   - 持久化失败时必须回滚本次请求的所有内存变更；
 *   - 每用户配额只驻留内存，使用 GetTickCount64 单调时钟，服务重启清零。
 *
 * 公共包装函数读取真实时钟；*_at 变体接受注入时钟，供单元测试复现
 * 令牌恢复、时钟回拨与配额窗口边界。
 */
#ifndef VTY_MACHINE_STATE_H
#define VTY_MACHINE_STATE_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#include "vty_svc_protocol.h"
#include "service_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_MS_CAPACITY 10u
#define VTY_MS_REFILL_INTERVAL_100NS 600000000ULL /* 60 秒 */
#define VTY_MS_USER_MINUTE_LIMIT 6u
#define VTY_MS_USER_MINUTE_WINDOW_MS 60000ULL
#define VTY_MS_USER_GLOBAL_LIMIT 6u
#define VTY_MS_USER_GLOBAL_WINDOW_MS 600000ULL /* 10 分钟 */
#define VTY_MS_QUOTA_SLOTS 64u
#define VTY_MS_PAYLOAD_BYTES 64u
#define VTY_MS_STATE_BYTES 96u
#define VTY_MS_MAGIC 0x534D5456u /* 'VTMS' */
#define VTY_MS_VERSION 1u
#define VTY_MS_SUCCESS_FLUSH_INTERVAL_100NS 600000000ULL /* 60 秒 */
#define VTY_MS_STATE_FILE_NAME L"machine_rate.bin"
#define VTY_MS_TEMP_FILE_NAME L"machine_rate.tmp"
#define VTY_MS_KEY_FILE_NAME L"machine_state.key"

typedef struct VtyMachineStateFields {
    uint32_t capacity;
    uint32_t tokens;
    uint64_t last_refill_100ns;
    uint64_t total_failures;
    uint64_t total_denied;
    uint64_t total_success;
    uint64_t created_100ns;
    uint64_t last_write_100ns;
} VtyMachineStateFields;

typedef struct VtyUserQuota {
    int used;
    uint8_t sid_hash[32];
    uint64_t minute_start_ms;
    uint32_t minute_count;
    uint64_t global_start_ms;
    uint32_t global_count;
    uint64_t last_seen_ms;
} VtyUserQuota;

typedef struct VtyMachineDecision {
    uint16_t status; /* VTY_SVC_STATUS_* */
    uint32_t retry_after_sec;
    uint32_t remaining_tokens;
} VtyMachineDecision;

typedef struct VtyMachineState {
    SRWLOCK lock;
    wchar_t dir[VTY_PATH_MAX];
    uint8_t hmac_key[32];
    VtyMachineStateFields fields;
    VtyUserQuota quota[VTY_MS_QUOTA_SLOTS];
    int success_dirty;
    int initialized;
    int emit_events;
    int ignore_user_quota;
    volatile LONG fail_closed;
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    int64_t test_utc_offset_100ns;
    int64_t test_ms_offset;
#endif
} VtyMachineState;

/*
 * 初始化内存结构，不读写磁盘。dir 为状态目录；key 为 32 字节 HMAC 密钥。
 * emit_events 控制是否写事件日志（单元测试传 0）。
 * 返回 0 成功。
 */
int vty_machine_state_init(VtyMachineState *st, const wchar_t *dir,
                           const uint8_t key[32], int emit_events);

/* 首次运行：建立默认预算并持久化。失败返回非 0，不留下半初始化状态。 */
int vty_machine_state_create_new(VtyMachineState *st);

/* 从磁盘加载并校验 HMAC/schema。失败置 fail_closed 并返回非 0。 */
int vty_machine_state_load(VtyMachineState *st);

/* 停止前刷写累计的成功审计计数。 */
int vty_machine_state_flush(VtyMachineState *st);

int vty_machine_state_is_fail_closed(VtyMachineState *st);

int vty_machine_state_check(VtyMachineState *st, const uint8_t sid_hash[32],
                            VtyMachineDecision *out);
int vty_machine_state_record_failure(VtyMachineState *st,
                                     const uint8_t sid_hash[32],
                                     VtyMachineDecision *out);
int vty_machine_state_reset(VtyMachineState *st, const uint8_t sid_hash[32],
                            VtyMachineDecision *out);

int vty_machine_state_check_at(VtyMachineState *st,
                               const uint8_t sid_hash[32], uint64_t now_utc,
                               uint64_t now_ms, VtyMachineDecision *out);
int vty_machine_state_record_failure_at(VtyMachineState *st,
                                        const uint8_t sid_hash[32],
                                        uint64_t now_utc, uint64_t now_ms,
                                        VtyMachineDecision *out);
int vty_machine_state_reset_at(VtyMachineState *st,
                               const uint8_t sid_hash[32], uint64_t now_utc,
                               uint64_t now_ms, VtyMachineDecision *out);

/* 只用于测试断言；拷贝持久字段。 */
void vty_machine_state_snapshot(VtyMachineState *st, VtyMachineStateFields *out);

/* 清零内存中的 HMAC 密钥与配额。 */
void vty_machine_state_destroy(VtyMachineState *st);

#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
/* 测试时钟偏移：只影响公共包装函数，不改变 *_at 的注入语义。 */
void vty_machine_state_set_test_offsets(VtyMachineState *st,
                                        int64_t utc_offset_100ns,
                                        int64_t ms_offset);
/* 集成测试忽略每用户配额，用于验证全局令牌桶；生产构建不暴露。 */
void vty_machine_state_set_test_ignore_user_quota(VtyMachineState *st,
                                                  int ignore);
#endif

#ifdef __cplusplus
}
#endif

#endif /* VTY_MACHINE_STATE_H */
