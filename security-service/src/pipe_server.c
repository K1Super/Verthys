/*
 * pipe_server.c — 8 实例消息模式管道、并发上限、认证与请求处理
 *
 * 每个实例一个工作线程；连接、读、写全部使用 overlapped I/O + 超时，
 * 防止未认证客户端长期占用实例。停止时主线程置位 stop_event，工作线程
 * 取消挂起连接并在 10 秒内退出。
 */
#include "pipe_server.h"
#include "client_auth.h"
#include "protocol.h"
#include "service_util.h"
#include "state_crypto.h"

#include <process.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#define VTY_PIPE_SDDL L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
#define VTY_ACTIVE_USER_SLOTS 64u
#define VTY_ACCEPT_RATE_LIMIT 50u
#define VTY_ACCEPT_RATE_WINDOW_MS 1000ull

#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
#define VTY_PIPE_TEST_LOG(...)                 \
    do {                                       \
        fprintf(stderr, __VA_ARGS__);          \
        fflush(stderr);                        \
    } while (0)
#else
#define VTY_PIPE_TEST_LOG(...) ((void)0)
#endif

typedef struct ActiveUserSlot {
    int used;
    uint8_t sid_hash[32];
    DWORD count;
} ActiveUserSlot;

typedef struct ActiveUsers {
    SRWLOCK lock;
    ActiveUserSlot slots[VTY_ACTIVE_USER_SLOTS];
} ActiveUsers;

typedef struct AcceptRate {
    SRWLOCK lock;
    ULONGLONG window_start;
    DWORD count;
} AcceptRate;

typedef struct PipeWorker {
    VtyServiceContext *ctx;
    ActiveUsers *active;
    AcceptRate *rate;
    HANDLE initial_pipe;
    HANDLE thread;
} PipeWorker;

static int active_user_add(ActiveUsers *users, const uint8_t sid_hash[32])
{
    size_t i;
    size_t free_slot = VTY_ACTIVE_USER_SLOTS;
    int ok = 0;

    if (users == NULL || sid_hash == NULL) return 0;
    AcquireSRWLockExclusive(&users->lock);
    for (i = 0; i < VTY_ACTIVE_USER_SLOTS; i++) {
        if (users->slots[i].used &&
            vty_const_time_equal(users->slots[i].sid_hash, sid_hash, 32u)) {
            if (users->slots[i].count < 2u) {
                users->slots[i].count++;
                ok = 1;
            }
            ReleaseSRWLockExclusive(&users->lock);
            return ok;
        }
        if (!users->slots[i].used && free_slot == VTY_ACTIVE_USER_SLOTS) {
            free_slot = i;
        }
    }
    if (free_slot != VTY_ACTIVE_USER_SLOTS) {
        users->slots[free_slot].used = 1;
        memcpy(users->slots[free_slot].sid_hash, sid_hash, 32u);
        users->slots[free_slot].count = 1;
        ok = 1;
    }
    ReleaseSRWLockExclusive(&users->lock);
    return ok;
}

static void active_user_remove(ActiveUsers *users, const uint8_t sid_hash[32])
{
    size_t i;

    if (users == NULL || sid_hash == NULL) return;
    AcquireSRWLockExclusive(&users->lock);
    for (i = 0; i < VTY_ACTIVE_USER_SLOTS; i++) {
        if (users->slots[i].used &&
            vty_const_time_equal(users->slots[i].sid_hash, sid_hash, 32u)) {
            if (users->slots[i].count > 0) {
                users->slots[i].count--;
            }
            if (users->slots[i].count == 0) {
                users->slots[i].used = 0;
                vty_secure_zero(users->slots[i].sid_hash, 32u);
            }
            break;
        }
    }
    ReleaseSRWLockExclusive(&users->lock);
}

static void accept_rate_delay(AcceptRate *rate)
{
    ULONGLONG now;
    DWORD count;

    if (rate == NULL) return;
    AcquireSRWLockExclusive(&rate->lock);
    now = GetTickCount64();
    if (rate->window_start == 0 ||
        now - rate->window_start >= VTY_ACCEPT_RATE_WINDOW_MS) {
        rate->window_start = now;
        rate->count = 0;
    }
    rate->count++;
    count = rate->count;
    ReleaseSRWLockExclusive(&rate->lock);
    if (count > VTY_ACCEPT_RATE_LIMIT) {
        Sleep(20);
    }
}

static HANDLE create_pipe_instance(VtyServiceContext *ctx, int first,
                                   DWORD *error_out)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    DWORD flags;
    HANDLE pipe;
    DWORD err = 0;
    BOOL sddl_ok;

    if (error_out != NULL) *error_out = 0;
    sddl_ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        VTY_PIPE_SDDL, SDDL_REVISION_1, &sd, NULL);
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    if (sddl_ok) {
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = FALSE;
    } else if (ctx->cfg.test_mode) {
        VTY_PIPE_TEST_LOG("pipe SDDL conversion failed: %lu\n",
                          (unsigned long)GetLastError());
    }

    flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
            PIPE_REJECT_REMOTE_CLIENTS;
    if (first) flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    pipe = CreateNamedPipeW(
        ctx->cfg.pipe_name, flags,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        VTY_SVC_MAX_PIPE_INSTANCES, VTY_SVC_MAX_MESSAGE_BYTES,
        VTY_SVC_MAX_MESSAGE_BYTES, 0, &sa);
    err = (pipe == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (pipe == INVALID_HANDLE_VALUE && err == ERROR_INVALID_PARAMETER &&
        (flags & PIPE_REJECT_REMOTE_CLIENTS) != 0) {
        /*
         * 部分 Windows 构建拒绝 PIPE_REJECT_REMOTE_CLIENTS（ERROR_INVALID_PARAMETER）。
         * 回退时仍由 GetNamedPipeClientProcessId 拒绝远程客户端：
         * 远程连接没有本地 PID，认证必然失败。
         */
        static volatile LONG warned = 0;
        if (InterlockedCompareExchange(&warned, 1, 0) == 0) {
            if (ctx->cfg.test_mode) {
                VTY_PIPE_TEST_LOG(
                    "PIPE_REJECT_REMOTE_CLIENTS unsupported; "
                    "remote denial via PID check\n");
            }
            vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                          L"PIPE_REJECT_REMOTE_CLIENTS unsupported; "
                          L"remote clients denied by PID check");
        }
        flags &= ~PIPE_REJECT_REMOTE_CLIENTS;
        pipe = CreateNamedPipeW(
            ctx->cfg.pipe_name, flags,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            VTY_SVC_MAX_PIPE_INSTANCES, VTY_SVC_MAX_MESSAGE_BYTES,
            VTY_SVC_MAX_MESSAGE_BYTES, 0, &sa);
        err = (pipe == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    }
    if (sd != NULL) LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (error_out != NULL) *error_out = err;
        if (first) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3003,
                          L"pipe name already owned; refuse start");
        }
        return INVALID_HANDLE_VALUE;
    }
    return pipe;
}

static int connect_pipe(HANDLE pipe, HANDLE stop_event)
{
    OVERLAPPED ov;
    HANDLE event;
    BOOL connected;
    DWORD err;
    int rc = -1;

    memset(&ov, 0, sizeof(ov));
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) return -1;
    ov.hEvent = event;

    connected = ConnectNamedPipe(pipe, &ov);
    if (connected) {
        rc = 0;
        goto done;
    }
    err = GetLastError();
    if (err == ERROR_PIPE_CONNECTED) {
        rc = 0;
        goto done;
    }
    if (err == ERROR_IO_PENDING) {
        HANDLE waits[2];
        DWORD wait;
        waits[0] = stop_event;
        waits[1] = event;
        wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0 + 1u) {
            DWORD transferred = 0;
            if (GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
                rc = 0;
            }
        } else {
            CancelIoEx(pipe, &ov);
            (void)WaitForSingleObject(event, 1000u);
        }
    }

done:
    CloseHandle(event);
    return rc;
}

static int read_message(HANDLE pipe, uint8_t *buf, DWORD cap, DWORD *len,
                        DWORD timeout_ms)
{
    OVERLAPPED ov;
    HANDLE event;
    BOOL ok;
    DWORD err;
    DWORD transferred = 0;
    int rc = -1;

    if (buf == NULL || len == NULL) return -1;
    *len = 0;
    memset(&ov, 0, sizeof(ov));
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) return -1;
    ov.hEvent = event;

    ok = ReadFile(pipe, buf, cap, &transferred, &ov);
    if (ok) {
        *len = transferred;
        rc = 0;
        goto done;
    }
    err = GetLastError();
    if (err == ERROR_MORE_DATA) {
        rc = -2;
        goto done;
    }
    if (err != ERROR_IO_PENDING) goto done;
    if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        (void)WaitForSingleObject(event, 1000u);
        goto done;
    }
    if (GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
        *len = transferred;
        rc = 0;
    } else if (GetLastError() == ERROR_MORE_DATA) {
        rc = -2;
    }

done:
    CloseHandle(event);
    return rc;
}

static int write_message(HANDLE pipe, const uint8_t *buf, DWORD len,
                         DWORD timeout_ms)
{
    OVERLAPPED ov;
    HANDLE event;
    BOOL ok;
    DWORD err;
    DWORD transferred = 0;
    int rc = -1;

    memset(&ov, 0, sizeof(ov));
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) return -1;
    ov.hEvent = event;

    ok = WriteFile(pipe, buf, len, &transferred, &ov);
    if (ok) {
        rc = (transferred == len) ? 0 : -1;
        goto done;
    }
    err = GetLastError();
    if (err != ERROR_IO_PENDING) goto done;
    if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        (void)WaitForSingleObject(event, 1000u);
        goto done;
    }
    if (GetOverlappedResult(pipe, &ov, &transferred, FALSE) &&
        transferred == len) {
        rc = 0;
    }

done:
    CloseHandle(event);
    return rc;
}

static int send_status(VtyServiceContext *ctx, HANDLE pipe,
                       const VtySvcRequestFields *request, uint16_t status,
                       uint32_t retry_after_sec, uint32_t remaining_tokens)
{
    uint8_t response[VTY_SVC_RESPONSE_BYTES];

    if (ctx == NULL || ctx->signing_key == NULL) return -1;
    memset(response, 0, sizeof(response));
    if (vty_svc_build_signed_response(ctx->signing_key, request, status,
                                      retry_after_sec, remaining_tokens,
                                      vty_unix_seconds_now(), response) != 0) {
        VTY_PIPE_TEST_LOG("build response failed status=%u\n",
                          (unsigned)status);
        return -1;
    }
    {
        int wr = write_message(pipe, response, VTY_SVC_RESPONSE_BYTES,
                               VTY_SVC_SERVER_WRITE_TIMEOUT_MS);
        if (wr != 0) {
            VTY_PIPE_TEST_LOG("write response failed status=%u\n",
                              (unsigned)status);
        }
        return wr;
    }
}

static void handle_connection(VtyServiceContext *ctx, HANDLE pipe,
                              ActiveUsers *active)
{
    VtyClientIdentity identity;
    HANDLE process = NULL;
    uint8_t raw[VTY_SVC_MAX_MESSAGE_BYTES];
    DWORD raw_len = 0;
    VtySvcRequestFields request;
    VtySvcRequestFields empty_request;
    VtyMachineDecision decision;
    VtyMachineStateFields fields;
    int auth_ok;
    int active_ok = 0;
    int read_rc;
    uint16_t decode_status;
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    int ignore_auth = ctx->cfg.test_ignore_client_auth;
    int ignore_quota = ctx->cfg.test_ignore_user_quota;
#else
    int ignore_auth = 0;
    int ignore_quota = 0;
#endif
    int verify_image = ignore_auth ? 0 : 1;

    memset(&identity, 0, sizeof(identity));
    memset(&request, 0, sizeof(request));
    memset(&empty_request, 0, sizeof(empty_request));
    memset(&decision, 0, sizeof(decision));

    auth_ok = vty_auth_client_process(pipe, ctx->cfg.publisher_sha256,
                                      verify_image, &identity, &process) == 0;
    if (!auth_ok) {
        VTY_PIPE_TEST_LOG("auth failed pid=%lu\n",
                          (unsigned long)identity.pid);
        vty_auth_log_denied(&identity,
                            verify_image ? L"image-auth" : L"process-sid");
    } else if (!ignore_quota) {
        /*
         * 每用户并发连接上限 2 对所有命令（含 Ping）生效，
         * 防止单个用户用慢连接占满 8 个实例。
         */
        if (!active_user_add(active, identity.sid_hash)) {
            vty_auth_log_denied(&identity, L"user-concurrency");
            goto done;
        }
        active_ok = 1;
    }

    read_rc = read_message(pipe, raw, sizeof(raw), &raw_len,
                           VTY_SVC_SERVER_READ_TIMEOUT_MS);
    if (read_rc == -2) {
        (void)send_status(ctx, pipe, &empty_request,
                          (uint16_t)VTY_SVC_STATUS_BAD_REQUEST, 0u, 0u);
        goto done;
    }
    if (read_rc != 0) {
        VTY_PIPE_TEST_LOG("read failed rc=%d\n", read_rc);
        goto done;
    }

    decode_status = vty_svc_request_decode(raw, raw_len, &request);
    if (decode_status != (uint16_t)VTY_SVC_STATUS_OK) {
        VTY_PIPE_TEST_LOG("decode failed len=%lu\n",
                          (unsigned long)raw_len);
        (void)send_status(ctx, pipe, &empty_request,
                          (uint16_t)VTY_SVC_STATUS_BAD_REQUEST, 0u, 0u);
        goto done;
    }
    if (!auth_ok) {
        (void)send_status(ctx, pipe, &request,
                          (uint16_t)VTY_SVC_STATUS_DENIED, 0u, 0u);
        goto done;
    }

    if (request.command != (uint16_t)VTY_SVC_CMD_PING) {
        if (!ignore_auth &&
            vty_auth_check_module(process, ctx->cfg.publisher_sha256) != 0) {
            vty_auth_log_denied(&identity, L"module-auth");
            (void)send_status(ctx, pipe, &request,
                              (uint16_t)VTY_SVC_STATUS_DENIED, 0u, 0u);
            goto done;
        }
    }

    if (vty_service_context_is_fail_closed(ctx)) {
        (void)send_status(ctx, pipe, &request,
                          (uint16_t)VTY_SVC_STATUS_UNAVAILABLE, 0u, 0u);
        goto done;
    }

    if (request.command == (uint16_t)VTY_SVC_CMD_PING) {
        vty_machine_state_snapshot(&ctx->state, &fields);
        (void)send_status(ctx, pipe, &request,
                          (uint16_t)VTY_SVC_STATUS_OK, 0u, fields.tokens);
        goto done;
    }

    if (request.command == (uint16_t)VTY_SVC_CMD_CHECK) {
        if (vty_machine_state_check(&ctx->state, identity.sid_hash, &decision) !=
            0) {
            decision.status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            decision.retry_after_sec = 0;
            decision.remaining_tokens = 0;
        }
    } else if (request.command == (uint16_t)VTY_SVC_CMD_RECORD_FAILURE) {
        if (vty_machine_state_record_failure(&ctx->state, identity.sid_hash,
                                             &decision) != 0) {
            decision.status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            decision.retry_after_sec = 0;
            decision.remaining_tokens = 0;
        }
    } else if (request.command == (uint16_t)VTY_SVC_CMD_RESET) {
        if (vty_machine_state_reset(&ctx->state, identity.sid_hash,
                                    &decision) != 0) {
            decision.status = (uint16_t)VTY_SVC_STATUS_INTERNAL;
            decision.retry_after_sec = 0;
            decision.remaining_tokens = 0;
        }
    } else {
        decision.status = (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    (void)send_status(ctx, pipe, &request, decision.status,
                      decision.retry_after_sec, decision.remaining_tokens);

done:
    if (active_ok) {
        active_user_remove(active, identity.sid_hash);
    }
    if (process != NULL) CloseHandle(process);
    memset(raw, 0, sizeof(raw));
}

static unsigned __stdcall pipe_worker_main(void *arg)
{
    PipeWorker *worker = (PipeWorker *)arg;
    HANDLE pipe = NULL;

    if (worker == NULL) return 0;
    pipe = worker->initial_pipe;
    worker->initial_pipe = NULL;

    for (;;) {
        if (WaitForSingleObject(worker->ctx->stop_event, 0) ==
            WAIT_OBJECT_0) {
            if (pipe != NULL) CloseHandle(pipe);
            break;
        }
        if (pipe == NULL) {
            DWORD create_error = 0;
            pipe = create_pipe_instance(worker->ctx, 0, &create_error);
            if (pipe == INVALID_HANDLE_VALUE) {
                if (WaitForSingleObject(worker->ctx->stop_event, 0) ==
                    WAIT_OBJECT_0) {
                    break;
                }
                Sleep(10);
                continue;
            }
        }
        if (connect_pipe(pipe, worker->ctx->stop_event) != 0) {
            (void)DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            pipe = NULL;
            if (WaitForSingleObject(worker->ctx->stop_event, 0) ==
                WAIT_OBJECT_0) {
                break;
            }
            continue;
        }
        if (WaitForSingleObject(worker->ctx->stop_event, 0) ==
            WAIT_OBJECT_0) {
            (void)DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            break;
        }
        accept_rate_delay(worker->rate);
        handle_connection(worker->ctx, pipe, worker->active);
        /*
         * 响应已写入后才断开实例；Sleep 给客户端一个极短的读取窗口，
         * DisconnectNamedPipe 会丢弃尚未读取的数据。此处在 handle_connection
         * 已释放每用户连接槽位，不会阻塞后续请求。
         */
        Sleep(10);
        (void)DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        pipe = NULL;
    }
    return 0;
}

int vty_pipe_server_run(VtyServiceContext *ctx)
{
    ActiveUsers active;
    AcceptRate rate;
    PipeWorker workers[VTY_SVC_MAX_PIPE_INSTANCES];
    HANDLE threads[VTY_SVC_MAX_PIPE_INSTANCES];
    HANDLE initial[VTY_SVC_MAX_PIPE_INSTANCES];
    size_t i;
    size_t created = 0;
    DWORD wait_result;
    DWORD join_result;
    DWORD timeout;
    int rc = -1;

    if (ctx == NULL) return -1;
    memset(&active, 0, sizeof(active));
    memset(&rate, 0, sizeof(rate));
    memset(workers, 0, sizeof(workers));
    memset(threads, 0, sizeof(threads));
    memset(initial, 0, sizeof(initial));
    InitializeSRWLock(&active.lock);
    InitializeSRWLock(&rate.lock);

    for (i = 0; i < VTY_SVC_MAX_PIPE_INSTANCES; i++) {
        DWORD create_error = 0;
        initial[i] = create_pipe_instance(ctx, i == 0, &create_error);
        if (initial[i] == INVALID_HANDLE_VALUE) {
            if (ctx->cfg.test_mode) {
                VTY_PIPE_TEST_LOG(
                    "pipe instance %lu creation failed: %lu\n",
                    (unsigned long)i, (unsigned long)create_error);
            }
            for (size_t j = 0; j < created; j++) {
                CloseHandle(initial[j]);
            }
            return -1;
        }
        created++;
    }

    for (i = 0; i < VTY_SVC_MAX_PIPE_INSTANCES; i++) {
        workers[i].ctx = ctx;
        workers[i].active = &active;
        workers[i].rate = &rate;
        workers[i].initial_pipe = initial[i];
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, pipe_worker_main,
                                           &workers[i], 0, NULL);
        if (threads[i] == NULL) {
            for (size_t j = i; j < VTY_SVC_MAX_PIPE_INSTANCES; j++) {
                CloseHandle(initial[j]);
            }
            SetEvent(ctx->stop_event);
            for (size_t j = 0; j < i; j++) {
                if (threads[j] != NULL) {
                    WaitForSingleObject(threads[j], 10000u);
                    CloseHandle(threads[j]);
                }
            }
            return -1;
        }
    }

    if (ctx->cfg.test_mode) {
        VTY_PIPE_TEST_LOG("READY\n");
    }

    timeout = INFINITE;
    if (ctx->cfg.test_mode && ctx->cfg.test_run_seconds > 0) {
        timeout = (DWORD)ctx->cfg.test_run_seconds * 1000u;
    }
    wait_result = WaitForSingleObject(ctx->stop_event, timeout);
    if (wait_result == WAIT_TIMEOUT) {
        SetEvent(ctx->stop_event);
    }

    join_result = WaitForMultipleObjects((DWORD)VTY_SVC_MAX_PIPE_INSTANCES,
                                          threads, TRUE, 10000u);
    if (join_result == WAIT_OBJECT_0) {
        rc = 0;
    } else {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3005,
                      L"pipe worker shutdown timeout");
        rc = -1;
    }

    for (i = 0; i < VTY_SVC_MAX_PIPE_INSTANCES; i++) {
        if (threads[i] != NULL) CloseHandle(threads[i]);
    }
    return rc;
}
