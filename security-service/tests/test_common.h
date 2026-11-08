/*
 * test_common.h — 独立测试框架与临时目录工具
 *
 * 不使用第三方框架，避免引入额外依赖与测试钩子泄漏面。
 */
#ifndef VTY_TEST_COMMON_H
#define VTY_TEST_COMMON_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int g_test_failures;
extern int g_test_checks;
extern int g_test_skipped;

#define CHECK(cond)                                                        \
    do {                                                                   \
        g_test_checks++;                                                   \
        if (!(cond)) {                                                     \
            g_test_failures++;                                             \
            printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
        }                                                                  \
    } while (0)

#define CHECK_EQ_U64(actual, expected)                                     \
    do {                                                                   \
        uint64_t a_ = (uint64_t)(actual);                                  \
        uint64_t e_ = (uint64_t)(expected);                                \
        g_test_checks++;                                                   \
        if (a_ != e_) {                                                    \
            g_test_failures++;                                             \
            printf("  [FAIL] %s:%d: %s = %llu, expected %llu\n", __FILE__, \
                   __LINE__, #actual, (unsigned long long)a_,              \
                   (unsigned long long)e_);                                \
        }                                                                  \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                     \
    do {                                                                   \
        int a_ = (int)(actual);                                            \
        int e_ = (int)(expected);                                          \
        g_test_checks++;                                                   \
        if (a_ != e_) {                                                    \
            g_test_failures++;                                             \
            printf("  [FAIL] %s:%d: %s = %d, expected %d\n", __FILE__,     \
                   __LINE__, #actual, a_, e_);                             \
        }                                                                  \
    } while (0)

#define SKIP(msg)                                                          \
    do {                                                                   \
        g_test_skipped++;                                                  \
        printf("  [SKIP] %s: %s\n", __FILE__, msg);                        \
    } while (0)

/* 创建唯一临时目录；失败返回非 0。 */
int test_make_temp_dir(wchar_t *out, size_t cap);

/* 递归删除目录；先解除可能存在的加固 ACL。 */
int test_remove_tree(const wchar_t *path);

/* 读取整个文件到缓冲区；返回实际字节数，失败返回 -1。 */
long test_read_file(const wchar_t *path, uint8_t *buf, DWORD cap);

#ifdef __cplusplus
}
#endif

#endif /* VTY_TEST_COMMON_H */
