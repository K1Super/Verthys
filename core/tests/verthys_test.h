/*
 * verthys_test.h — 极简测试框架（无外部依赖）
 *
 * TDD 原则：测试通过公共接口验证行为，不耦合实现细节。
 * 测试函数返回 0=通过，非 0=失败。test_runner.c 汇总。
 */
#ifndef VERTHYS_TEST_H
#define VERTHYS_TEST_H

#include <stdio.h>

extern int g_tests_passed;
extern int g_tests_failed;

/* 定义测试函数（非 static，供 runner 链接调用） */
#define TEST(name) int name(void)

/* 断言：失败立即返回 1 */
#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("  [CHECK FAIL] %s @ %s:%d\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define CHECK_EQ(actual, expected) do { \
    long _a = (long)(actual); long _e = (long)(expected); \
    if (_a != _e) { \
        printf("  [CHECK_EQ FAIL] %s=%ld != %s=%ld @ %s:%d\n", \
               #actual, _a, #expected, _e, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

/* ------------------------------------------------------------------ *
 * ★ WP-13（K-1）：测试间状态快照 — 测试前后对比线程数/句柄数/
 * emergency 信号，差异非零即打印，用于定位测试间累积状态泄漏源
 * （K-1 怀疑：后台线程/句柄/紧急信号窗口跨测试残留 + 布局敏感野指针）。
 * 实现位于 test_runner.c（Windows API 不侵入各测试翻译单元）。
 * ------------------------------------------------------------------ */
typedef struct TestStateSnapshot {
    long threads;                   /* 本进程线程数（TH32CS_SNAPTHREAD 枚举） */
    long handles;                   /* 内核句柄数（GetProcessHandleCount） */
    long gdi_handles;               /* GDI 对象数（GetGuiResources） */
    unsigned long emergency_signals; /* emergency 信号窗口并集（位掩码） */
    int emergency_triggered;        /* 应急熔断状态（0=未触发） */
} TestStateSnapshot;

/* 采集当前进程状态快照（失败字段置 -1，不中断测试） */
void test_state_capture(TestStateSnapshot *snap);

/* 对比测试前后快照，差异非零打印 [LEAK?] 行（定位泄漏源，不判失败） */
void test_state_report_diff(const char *test_name,
                            const TestStateSnapshot *before,
                            const TestStateSnapshot *after);

/* 组间检查点：打印当前线程/句柄数及相对进程启动基线的增量（累积趋势） */
void test_state_checkpoint(const char *group_label);

/* emergency.h 清零入口前置声明（隔离测试翻译单元，不引入内部头） */
void emergency_clear_signals(void);

/* 运行测试并计数 */
int test_filter_match(const char *test_name);
#define RUN_TEST(name) do { \
    if (g_filter_active && !(test_filter_match(#name) || test_filter_match_extra(#name))) break; \
    printf("[ RUN      ] %s\n", #name); \
    fflush(stdout); \
    TestStateSnapshot _snap_before, _snap_after; \
    test_state_capture(&_snap_before); \
    if (name() == 0) { \
        printf("[       OK ] %s\n", #name); \
        fflush(stdout); \
        g_tests_passed++; \
    } else { \
        printf("[     FAIL ] %s\n", #name); \
        fflush(stdout); \
        g_tests_failed++; \
    } \
    /* ★ WP-13 步骤2：每测试后强制清零 emergency 信号窗口，阻断跨测试累积 */ \
    emergency_clear_signals(); \
    /* ★ WP-13 步骤1：测试间状态快照断言（差异非零打印） */ \
    test_state_capture(&_snap_after); \
    test_state_report_diff(#name, &_snap_before, &_snap_after); \
} while (0)

/* ------------------------------------------------------------------ *
 * 测试框架输出封装（入口文件零直接 printf）                            *
 *                                                                    *
 * 规范引用（ 第 1 节）：                                       *
 *   入口文件禁止出现 printf/fprintf/OutputDebugString 等直接输出      *
 *   test_runner.c（入口）通过以下宏调用测试框架输出，实现分层解耦     *
 * ------------------------------------------------------------------ */

/* 常规日志输出（替代入口中的 printf） */
#define TEST_LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)

/* 致命错误：输出后立即退出（替代入口中的 printf + return） */
#define TEST_FATAL(fmt, ...) do { \
    printf("[FATAL] " fmt, ##__VA_ARGS__); \
    return 2; \
} while (0)

/* 汇总报告输出 */
#define TEST_SUMMARY() printf("\n=== Summary: %d passed, %d failed ===\n", \
                               g_tests_passed, g_tests_failed)

#endif /* VERTHYS_TEST_H */
