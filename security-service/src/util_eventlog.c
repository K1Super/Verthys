/*
 * util_eventlog.c — 事件日志写入与重复抑制
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

typedef struct VtyEventGate {
    DWORD id;
    ULONGLONG last_ms;
    DWORD suppressed;
} VtyEventGate;

#define VTY_EVENT_GATE_COUNT 8u
#define VTY_EVENT_GATE_WINDOW_MS 10000ULL

static SRWLOCK g_event_gate_lock = SRWLOCK_INIT;
static VtyEventGate g_event_gates[VTY_EVENT_GATE_COUNT];

static int event_gate_should_log(DWORD id, DWORD *suppressed)
{
    ULONGLONG now = GetTickCount64();
    size_t i;
    size_t free_slot = VTY_EVENT_GATE_COUNT;

    *suppressed = 0;
    AcquireSRWLockExclusive(&g_event_gate_lock);
    for (i = 0; i < VTY_EVENT_GATE_COUNT; i++) {
        if (g_event_gates[i].id == id &&
            g_event_gates[i].last_ms != 0) {
            if (now - g_event_gates[i].last_ms < VTY_EVENT_GATE_WINDOW_MS) {
                g_event_gates[i].suppressed++;
                ReleaseSRWLockExclusive(&g_event_gate_lock);
                return 0;
            }
            *suppressed = g_event_gates[i].suppressed;
            g_event_gates[i].suppressed = 0;
            g_event_gates[i].last_ms = now;
            ReleaseSRWLockExclusive(&g_event_gate_lock);
            return 1;
        }
        if (g_event_gates[i].id == 0 && free_slot == VTY_EVENT_GATE_COUNT) {
            free_slot = i;
        }
    }
    if (free_slot == VTY_EVENT_GATE_COUNT) {
        free_slot = (size_t)(id % VTY_EVENT_GATE_COUNT);
        *suppressed = g_event_gates[free_slot].suppressed;
    }
    g_event_gates[free_slot].id = id;
    g_event_gates[free_slot].last_ms = now;
    g_event_gates[free_slot].suppressed = 0;
    ReleaseSRWLockExclusive(&g_event_gate_lock);
    return 1;
}

void vty_event_log(WORD type, DWORD id, const wchar_t *detail)
{
    HANDLE source;
    const wchar_t *strings[1];
    wchar_t buffer[256];
    DWORD suppressed = 0;
    DWORD count = 0;

    if (!event_gate_should_log(id, &suppressed)) return;

    if (detail != NULL && suppressed > 0) {
        if (swprintf_s(buffer, 256, L"[suppressed %lu] %s",
                       (unsigned long)suppressed, detail) > 0) {
            detail = buffer;
        }
    } else if (detail == NULL && suppressed > 0) {
        if (swprintf_s(buffer, 256, L"[suppressed %lu]",
                       (unsigned long)suppressed) > 0) {
            detail = buffer;
        }
    }

    source = RegisterEventSourceW(NULL, VTY_SVC_EVENT_SOURCE);
    if (source == NULL) return;
    if (detail != NULL) {
        strings[0] = detail;
        count = 1;
    }
    ReportEventW(source, type, 0, id, NULL, (WORD)count, 0,
                 count > 0 ? strings : NULL, NULL);
    DeregisterEventSource(source);
}
