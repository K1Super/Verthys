/*
 * machine_state.c — 令牌桶 / 每用户配额 / 原子持久化
 *
 * 关键不变量：
 *   1. 全局令牌只随时间恢复，reset 不恢复预算。
 *   2. 内存变更只在持久化成功后提交；失败返回 INTERNAL，不产生
 *      “内存已扣减、磁盘仍旧值”的不一致窗口。
 *   3. 每用户配额表只驻留内存；仅在过期条目中回收槽位，避免通过
 *      SID 洪水把活跃用户的配额洗掉。
 */
#include "machine_state.h"
#include "service_util.h"
#include "state_crypto.h"

#include <string.h>

#define VTY_MS_COUNTER_MAX UINT64_MAX

static uint64_t counter_increment(uint64_t value)
{
    return value == VTY_MS_COUNTER_MAX ? value : value + 1u;
}

static int key_is_nonzero(const uint8_t key[32])
{
    size_t i;
    uint8_t acc = 0;

    for (i = 0; i < 32u; i++) {
        acc |= key[i];
    }
    return acc != 0;
}

static void encode_payload(const VtyMachineStateFields *f,
                           uint8_t payload[VTY_MS_PAYLOAD_BYTES])
{
    memset(payload, 0, VTY_MS_PAYLOAD_BYTES);
    vty_svc_put_u32le(payload + 0, VTY_MS_MAGIC);
    vty_svc_put_u16le(payload + 4, (uint16_t)VTY_MS_VERSION);
    vty_svc_put_u16le(payload + 6, 0);
    vty_svc_put_u32le(payload + 8, f->capacity);
    vty_svc_put_u32le(payload + 12, f->tokens);
    vty_svc_put_u64le(payload + 16, f->last_refill_100ns);
    vty_svc_put_u64le(payload + 24, f->total_failures);
    vty_svc_put_u64le(payload + 32, f->total_denied);
    vty_svc_put_u64le(payload + 40, f->total_success);
    vty_svc_put_u64le(payload + 48, f->created_100ns);
    vty_svc_put_u64le(payload + 56, f->last_write_100ns);
}

static int decode_payload(const uint8_t payload[VTY_MS_PAYLOAD_BYTES],
                          VtyMachineStateFields *f)
{
    if (payload == NULL || f == NULL) return -1;
    if (vty_svc_get_u32le(payload + 0) != VTY_MS_MAGIC) return -1;
    if (vty_svc_get_u16le(payload + 4) != (uint16_t)VTY_MS_VERSION) return -1;
    if (vty_svc_get_u16le(payload + 6) != 0) return -1;
    f->capacity = vty_svc_get_u32le(payload + 8);
    f->tokens = vty_svc_get_u32le(payload + 12);
    f->last_refill_100ns = vty_svc_get_u64le(payload + 16);
    f->total_failures = vty_svc_get_u64le(payload + 24);
    f->total_denied = vty_svc_get_u64le(payload + 32);
    f->total_success = vty_svc_get_u64le(payload + 40);
    f->created_100ns = vty_svc_get_u64le(payload + 48);
    f->last_write_100ns = vty_svc_get_u64le(payload + 56);
    if (f->capacity != VTY_MS_CAPACITY || f->tokens > f->capacity) return -1;
    if (f->created_100ns == 0 || f->last_write_100ns == 0) return -1;
    return 0;
}

static int persist_fields(VtyMachineState *st, VtyMachineStateFields *candidate,
                          uint64_t now)
{
    uint8_t payload[VTY_MS_PAYLOAD_BYTES];
    uint8_t mac[VTY_HASH_BYTES];
    uint8_t blob[VTY_MS_STATE_BYTES];
    int rc;

    if (st == NULL || candidate == NULL) return -1;
    candidate->last_write_100ns = now;
    encode_payload(candidate, payload);
    if (vty_hmac_sha256(st->hmac_key, payload, VTY_MS_PAYLOAD_BYTES, mac) != 0) {
        vty_secure_zero(payload, sizeof(payload));
        return -1;
    }
    memcpy(blob, payload, VTY_MS_PAYLOAD_BYTES);
    memcpy(blob + VTY_MS_PAYLOAD_BYTES, mac, VTY_HASH_BYTES);
    rc = vty_write_file_atomic_named(st->dir, VTY_MS_STATE_FILE_NAME,
                                     VTY_MS_TEMP_FILE_NAME, blob,
                                     VTY_MS_STATE_BYTES);
    vty_secure_zero(payload, sizeof(payload));
    vty_secure_zero(mac, sizeof(mac));
    vty_secure_zero(blob, sizeof(blob));
    if (rc != 0) return -1;
    st->fields = *candidate;
    st->success_dirty = 0;
    st->initialized = 1;
    return 0;
}

static int refill_candidate(VtyMachineStateFields *f, uint64_t now,
                            int emit_events)
{
    uint64_t elapsed;
    uint64_t units;
    uint64_t added;

    if (now < f->last_refill_100ns) {
        /* 系统时间回拨：不补充预算，记录事件；last_refill 不回退。 */
        if (emit_events) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3004,
                          L"clock rollback detected; token refill skipped");
        }
        return 0;
    }
    elapsed = now - f->last_refill_100ns;
    units = elapsed / VTY_MS_REFILL_INTERVAL_100NS;
    if (units == 0) return 0;

    added = units * VTY_MS_REFILL_INTERVAL_100NS;
    if ((uint64_t)f->tokens + units >= (uint64_t)f->capacity) {
        f->tokens = f->capacity;
        /* 丢弃超出容量的时间信用，避免“先攒满再瞬间恢复”。 */
        f->last_refill_100ns = now;
    } else {
        f->tokens += (uint32_t)units;
        f->last_refill_100ns += added;
    }
    return 1;
}

static uint32_t seconds_ceil_100ns(uint64_t ticks)
{
    uint64_t sec = (ticks + 9999999ULL) / 10000000ULL;

    if (sec == 0) return 1;
    if (sec > 0xFFFFFFFFULL) return 0xFFFFFFFFu;
    return (uint32_t)sec;
}

static uint32_t refill_retry_seconds(uint64_t now, uint64_t last_refill)
{
    if (now < last_refill) {
        return (uint32_t)(VTY_MS_REFILL_INTERVAL_100NS / 10000000ULL);
    }
    if (now - last_refill >= VTY_MS_REFILL_INTERVAL_100NS) return 1;
    return seconds_ceil_100ns(VTY_MS_REFILL_INTERVAL_100NS -
                              (now - last_refill));
}

static uint32_t window_retry_seconds(uint64_t start_ms, uint64_t window_ms,
                                     uint64_t now_ms)
{
    uint64_t remaining_ms;
    uint64_t sec;

    if (now_ms <= start_ms || now_ms - start_ms >= window_ms) return 1;
    remaining_ms = window_ms - (now_ms - start_ms);
    sec = (remaining_ms + 999ULL) / 1000ULL;
    if (sec == 0) return 1;
    if (sec > 0xFFFFFFFFULL) return 0xFFFFFFFFu;
    return (uint32_t)sec;
}

static void quota_normalize(VtyUserQuota *q, uint64_t now_ms)
{
    if (now_ms < q->minute_start_ms) {
        q->minute_start_ms = now_ms;
        q->minute_count = 0;
    } else if (now_ms - q->minute_start_ms >= VTY_MS_USER_MINUTE_WINDOW_MS) {
        q->minute_start_ms = now_ms;
        q->minute_count = 0;
    }
    if (now_ms < q->global_start_ms) {
        q->global_start_ms = now_ms;
        q->global_count = 0;
    } else if (now_ms - q->global_start_ms >= VTY_MS_USER_GLOBAL_WINDOW_MS) {
        q->global_start_ms = now_ms;
        q->global_count = 0;
    }
}

static VtyUserQuota *quota_find(VtyMachineState *st, const uint8_t sid_hash[32],
                                int create, uint64_t now_ms, int *created)
{
    size_t i;
    size_t free_slot = VTY_MS_QUOTA_SLOTS;
    size_t oldest_slot = VTY_MS_QUOTA_SLOTS;
    uint64_t oldest_seen = 0;
    VtyUserQuota *q;

    if (created != NULL) *created = 0;
    for (i = 0; i < VTY_MS_QUOTA_SLOTS; i++) {
        q = &st->quota[i];
        if (q->used &&
            vty_const_time_equal(q->sid_hash, sid_hash, 32u)) {
            return q;
        }
        if (!q->used && free_slot == VTY_MS_QUOTA_SLOTS) {
            free_slot = i;
        }
    }
    if (!create) return NULL;

    if (free_slot != VTY_MS_QUOTA_SLOTS) {
        q = &st->quota[free_slot];
        memset(q, 0, sizeof(*q));
        q->used = 1;
        memcpy(q->sid_hash, sid_hash, 32u);
        q->minute_start_ms = now_ms;
        q->global_start_ms = now_ms;
        q->last_seen_ms = now_ms;
        if (created != NULL) *created = 1;
        return q;
    }

    /* 只在两个窗口都已过期的条目上回收，避免通过 SID 洪水重置活跃配额。 */
    for (i = 0; i < VTY_MS_QUOTA_SLOTS; i++) {
        q = &st->quota[i];
        if (!q->used) continue;
        if (now_ms >= q->global_start_ms &&
            now_ms - q->global_start_ms >= VTY_MS_USER_GLOBAL_WINDOW_MS) {
            if (oldest_slot == VTY_MS_QUOTA_SLOTS ||
                q->last_seen_ms < oldest_seen) {
                oldest_slot = i;
                oldest_seen = q->last_seen_ms;
            }
        }
    }
    if (oldest_slot == VTY_MS_QUOTA_SLOTS) {
        return NULL;
    }
    q = &st->quota[oldest_slot];
    memset(q, 0, sizeof(*q));
    q->used = 1;
    memcpy(q->sid_hash, sid_hash, 32u);
    q->minute_start_ms = now_ms;
    q->global_start_ms = now_ms;
    q->last_seen_ms = now_ms;
    if (created != NULL) *created = 1;
    return q;
}

int vty_machine_state_init(VtyMachineState *st, const wchar_t *dir,
                           const uint8_t key[32], int emit_events)
{
    if (st == NULL || dir == NULL || key == NULL) return -1;
    if (!key_is_nonzero(key)) return -1;
    memset(st, 0, sizeof(*st));
    InitializeSRWLock(&st->lock);
    if (vty_wide_copy(st->dir, VTY_PATH_MAX, dir) != 0) return -1;
    memcpy(st->hmac_key, key, 32u);
    st->emit_events = emit_events ? 1 : 0;
    st->initialized = 0;
    st->fail_closed = 0;
    return 0;
}

int vty_machine_state_create_new(VtyMachineState *st)
{
    VtyMachineStateFields candidate;
    uint64_t now;
    int rc;

    if (st == NULL) return -1;
    now = vty_utc_now_100ns();
    memset(&candidate, 0, sizeof(candidate));
    candidate.capacity = VTY_MS_CAPACITY;
    candidate.tokens = VTY_MS_CAPACITY;
    candidate.last_refill_100ns = now;
    candidate.created_100ns = now;
    candidate.last_write_100ns = now;

    AcquireSRWLockExclusive(&st->lock);
    memset(st->quota, 0, sizeof(st->quota));
    st->success_dirty = 0;
    rc = persist_fields(st, &candidate, now);
    if (rc != 0) {
        InterlockedExchange(&st->fail_closed, 1);
    }
    ReleaseSRWLockExclusive(&st->lock);
    return rc;
}

int vty_machine_state_load(VtyMachineState *st)
{
    wchar_t path[VTY_PATH_MAX];
    uint8_t blob[VTY_MS_STATE_BYTES];
    uint8_t mac[VTY_HASH_BYTES];
    VtyMachineStateFields f;
    int rc = -1;

    if (st == NULL) return -1;
    if (vty_path_join(path, VTY_PATH_MAX, st->dir,
                      VTY_MS_STATE_FILE_NAME) != 0) {
        return -1;
    }
    if (vty_read_file_exact(path, blob, VTY_MS_STATE_BYTES,
                            VTY_MS_STATE_BYTES) != 0) {
        goto done;
    }
    if (decode_payload(blob, &f) != 0) goto done;
    if (vty_hmac_sha256(st->hmac_key, blob, VTY_MS_PAYLOAD_BYTES, mac) != 0) {
        goto done;
    }
    if (!vty_const_time_equal(mac, blob + VTY_MS_PAYLOAD_BYTES,
                              VTY_HASH_BYTES)) {
        goto done;
    }

    AcquireSRWLockExclusive(&st->lock);
    st->fields = f;
    memset(st->quota, 0, sizeof(st->quota));
    st->success_dirty = 0;
    st->initialized = 1;
    InterlockedExchange(&st->fail_closed, 0);
    ReleaseSRWLockExclusive(&st->lock);
    rc = 0;

done:
    vty_secure_zero(blob, sizeof(blob));
    vty_secure_zero(mac, sizeof(mac));
    if (rc != 0) {
        InterlockedExchange(&st->fail_closed, 1);
        if (st->emit_events) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                          L"machine state missing or corrupted; fail-closed");
        }
    }
    return rc;
}

int vty_machine_state_flush(VtyMachineState *st)
{
    VtyMachineStateFields candidate;
    uint64_t now;
    int rc = 0;

    if (st == NULL) return -1;
    AcquireSRWLockExclusive(&st->lock);
    if (st->initialized && st->success_dirty) {
        candidate = st->fields;
        now = vty_utc_now_100ns();
        rc = persist_fields(st, &candidate, now);
    }
    ReleaseSRWLockExclusive(&st->lock);
    return rc;
}

int vty_machine_state_is_fail_closed(VtyMachineState *st)
{
    if (st == NULL) return 1;
    return InterlockedCompareExchange(&st->fail_closed, 0, 0) != 0 ? 1 : 0;
}

static int decision_fail_closed(VtyMachineDecision *out)
{
    if (out == NULL) return -1;
    out->status = (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    out->retry_after_sec = 0;
    out->remaining_tokens = 0;
    return 0;
}

int vty_machine_state_check_at(VtyMachineState *st,
                               const uint8_t sid_hash[32], uint64_t now_utc,
                               uint64_t now_ms, VtyMachineDecision *out)
{
    VtyMachineStateFields candidate;
    VtyUserQuota *q;
    int changed;
    int rc = 0;

    if (st == NULL || sid_hash == NULL || out == NULL) return -1;
    AcquireSRWLockExclusive(&st->lock);
    if (InterlockedCompareExchange(&st->fail_closed, 0, 0) != 0 ||
        !st->initialized) {
        ReleaseSRWLockExclusive(&st->lock);
        return decision_fail_closed(out);
    }

    candidate = st->fields;
    changed = refill_candidate(&candidate, now_utc, st->emit_events);

    out->remaining_tokens = candidate.tokens;
    out->status = (uint16_t)VTY_SVC_STATUS_OK;
    out->retry_after_sec = 0;

    q = NULL;
    if (!st->ignore_user_quota) {
        q = quota_find(st, sid_hash, 0, now_ms, NULL);
    }
    if (q != NULL) {
        quota_normalize(q, now_ms);
        q->last_seen_ms = now_ms;
        if (q->global_count >= VTY_MS_USER_GLOBAL_LIMIT) {
            out->status = (uint16_t)VTY_SVC_STATUS_LOCKED;
            out->retry_after_sec = window_retry_seconds(
                q->global_start_ms, VTY_MS_USER_GLOBAL_WINDOW_MS, now_ms);
        }
    }
    if (out->status == (uint16_t)VTY_SVC_STATUS_OK && candidate.tokens == 0) {
        out->status = (uint16_t)VTY_SVC_STATUS_LOCKED;
        out->retry_after_sec =
            refill_retry_seconds(now_utc, candidate.last_refill_100ns);
    }

    if (changed) {
        if (persist_fields(st, &candidate, now_utc) != 0) {
            out->status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            out->retry_after_sec = 0;
            out->remaining_tokens = 0;
            rc = 0;
        }
    }
    ReleaseSRWLockExclusive(&st->lock);
    return rc;
}

int vty_machine_state_record_failure_at(VtyMachineState *st,
                                        const uint8_t sid_hash[32],
                                        uint64_t now_utc, uint64_t now_ms,
                                        VtyMachineDecision *out)
{
    VtyMachineStateFields candidate;
    VtyUserQuota qcand;
    VtyUserQuota *q;
    int created = 0;
    int changed;
    int rc = 0;

    if (st == NULL || sid_hash == NULL || out == NULL) return -1;
    AcquireSRWLockExclusive(&st->lock);
    if (InterlockedCompareExchange(&st->fail_closed, 0, 0) != 0 ||
        !st->initialized) {
        ReleaseSRWLockExclusive(&st->lock);
        return decision_fail_closed(out);
    }

    candidate = st->fields;
    changed = refill_candidate(&candidate, now_utc, st->emit_events);
    out->remaining_tokens = candidate.tokens;
    out->status = (uint16_t)VTY_SVC_STATUS_OK;
    out->retry_after_sec = 0;

    memset(&qcand, 0, sizeof(qcand));
    if (st->ignore_user_quota) {
        q = NULL;
    } else {
        q = quota_find(st, sid_hash, 1, now_ms, &created);
        if (q == NULL) {
            out->status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            out->remaining_tokens = 0;
            ReleaseSRWLockExclusive(&st->lock);
            return 0;
        }
        qcand = *q;
        quota_normalize(&qcand, now_ms);
        qcand.last_seen_ms = now_ms;

        if (qcand.minute_count >= VTY_MS_USER_MINUTE_LIMIT) {
            *q = qcand;
            out->status = (uint16_t)VTY_SVC_STATUS_LOCKED;
            out->retry_after_sec = window_retry_seconds(
                qcand.minute_start_ms, VTY_MS_USER_MINUTE_WINDOW_MS, now_ms);
            if (st->emit_events) {
                vty_event_log(EVENTLOG_WARNING_TYPE, 2001,
                              L"per-user failure quota reached");
            }
            ReleaseSRWLockExclusive(&st->lock);
            return 0;
        }
        if (qcand.global_count >= VTY_MS_USER_GLOBAL_LIMIT) {
            *q = qcand;
            out->status = (uint16_t)VTY_SVC_STATUS_LOCKED;
            out->retry_after_sec = window_retry_seconds(
                qcand.global_start_ms, VTY_MS_USER_GLOBAL_WINDOW_MS, now_ms);
            if (st->emit_events) {
                vty_event_log(EVENTLOG_WARNING_TYPE, 2001,
                              L"per-user global token quota reached");
            }
            ReleaseSRWLockExclusive(&st->lock);
            return 0;
        }
    }

    if (candidate.tokens == 0) {
        candidate.total_denied = counter_increment(candidate.total_denied);
        if (persist_fields(st, &candidate, now_utc) != 0) {
            if (created && q != NULL) {
                memset(q, 0, sizeof(*q));
            }
            out->status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            out->remaining_tokens = 0;
            ReleaseSRWLockExclusive(&st->lock);
            return 0;
        }
        if (q != NULL) *q = qcand;
        out->status = (uint16_t)VTY_SVC_STATUS_LOCKED;
        out->retry_after_sec =
            refill_retry_seconds(now_utc, candidate.last_refill_100ns);
        out->remaining_tokens = 0;
        if (st->emit_events) {
            vty_event_log(EVENTLOG_WARNING_TYPE, 2002,
                          L"machine token budget exhausted");
        }
        ReleaseSRWLockExclusive(&st->lock);
        return 0;
    }

    {
        uint32_t previous_tokens = candidate.tokens;
        candidate.tokens--;
        candidate.total_failures = counter_increment(candidate.total_failures);
        if (q != NULL) {
            qcand.minute_count++;
            qcand.global_count++;
        }
        if (persist_fields(st, &candidate, now_utc) != 0) {
            if (created && q != NULL) {
                memset(q, 0, sizeof(*q));
            }
            out->status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            out->remaining_tokens = 0;
            ReleaseSRWLockExclusive(&st->lock);
            return 0;
        }
        if (q != NULL) *q = qcand;
        out->remaining_tokens = candidate.tokens;
        if (previous_tokens != 0 && candidate.tokens == 0 && st->emit_events) {
            vty_event_log(EVENTLOG_WARNING_TYPE, 2002,
                          L"machine token budget exhausted");
        }
    }
    (void)changed;
    ReleaseSRWLockExclusive(&st->lock);
    return rc;
}

int vty_machine_state_reset_at(VtyMachineState *st,
                               const uint8_t sid_hash[32], uint64_t now_utc,
                               uint64_t now_ms, VtyMachineDecision *out)
{
    VtyMachineStateFields candidate;
    int rc = 0;

    (void)sid_hash;
    (void)now_ms;
    if (st == NULL || out == NULL) return -1;
    AcquireSRWLockExclusive(&st->lock);
    if (InterlockedCompareExchange(&st->fail_closed, 0, 0) != 0 ||
        !st->initialized) {
        ReleaseSRWLockExclusive(&st->lock);
        return decision_fail_closed(out);
    }
    candidate = st->fields;
    candidate.total_success = counter_increment(candidate.total_success);
    out->status = (uint16_t)VTY_SVC_STATUS_OK;
    out->retry_after_sec = 0;
    out->remaining_tokens = candidate.tokens;

    if (candidate.last_write_100ns <= now_utc &&
        now_utc - candidate.last_write_100ns >=
            VTY_MS_SUCCESS_FLUSH_INTERVAL_100NS) {
        if (persist_fields(st, &candidate, now_utc) != 0) {
            out->status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            out->remaining_tokens = 0;
            ReleaseSRWLockExclusive(&st->lock);
            return 0;
        }
    } else {
        st->fields = candidate;
        st->success_dirty = 1;
    }
    ReleaseSRWLockExclusive(&st->lock);
    return rc;
}

void vty_machine_state_snapshot(VtyMachineState *st, VtyMachineStateFields *out)
{
    if (st == NULL || out == NULL) return;
    AcquireSRWLockExclusive(&st->lock);
    *out = st->fields;
    ReleaseSRWLockExclusive(&st->lock);
}

void vty_machine_state_destroy(VtyMachineState *st)
{
    if (st == NULL) return;
    AcquireSRWLockExclusive(&st->lock);
    vty_secure_zero(st->hmac_key, sizeof(st->hmac_key));
    vty_secure_zero(st->quota, sizeof(st->quota));
    st->initialized = 0;
    ReleaseSRWLockExclusive(&st->lock);
}

static uint64_t adjusted_now_utc(VtyMachineState *st)
{
    uint64_t now = vty_utc_now_100ns();
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    now = (uint64_t)((int64_t)now + st->test_utc_offset_100ns);
#endif
    return now;
}

static uint64_t adjusted_now_ms(VtyMachineState *st)
{
    uint64_t now = GetTickCount64();
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    now = (uint64_t)((int64_t)now + st->test_ms_offset);
#endif
    return now;
}

int vty_machine_state_check(VtyMachineState *st, const uint8_t sid_hash[32],
                            VtyMachineDecision *out)
{
    if (st == NULL) return -1;
    return vty_machine_state_check_at(st, sid_hash, adjusted_now_utc(st),
                                      adjusted_now_ms(st), out);
}

int vty_machine_state_record_failure(VtyMachineState *st,
                                     const uint8_t sid_hash[32],
                                     VtyMachineDecision *out)
{
    if (st == NULL) return -1;
    return vty_machine_state_record_failure_at(
        st, sid_hash, adjusted_now_utc(st), adjusted_now_ms(st), out);
}

int vty_machine_state_reset(VtyMachineState *st, const uint8_t sid_hash[32],
                            VtyMachineDecision *out)
{
    if (st == NULL) return -1;
    return vty_machine_state_reset_at(st, sid_hash, adjusted_now_utc(st),
                                      adjusted_now_ms(st), out);
}

#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
void vty_machine_state_set_test_offsets(VtyMachineState *st,
                                        int64_t utc_offset_100ns,
                                        int64_t ms_offset)
{
    if (st == NULL) return;
    st->test_utc_offset_100ns = utc_offset_100ns;
    st->test_ms_offset = ms_offset;
}

void vty_machine_state_set_test_ignore_user_quota(VtyMachineState *st,
                                                  int ignore)
{
    if (st == NULL) return;
    st->ignore_user_quota = ignore ? 1 : 0;
}
#endif
