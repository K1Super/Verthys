/*
 * test_export_path_guard.c — Export/Import 路径纵深防御（C 层）测试
 *
 * 覆盖：
 *   - 含 '.'/'..' 目录穿越段的路径被拒（VERTHYS_ERR_INVALID）
 *   - 位于系统关键目录（Windows / System32）内的路径被拒
 *   - 正常临时目录路径不被误拒（导出往返成功）
 *
 * 边界契约（与修复实现对齐）：
 *   - 路径校验在参数判空之后、状态机检查之前执行——坏路径即使锁定态也
 *     返回 INVALID，与"入参非法"同级；
 *   - 校验项：字面 '.'/'..' 段 → 无法规范化 → 系统目录前缀 → 重解析点。
 */
#include "verthys_test.h"
#include "verthys.h"

#include <string.h>
#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define PG_VERTHYS  "test_pg.verthys"
#define PG_PW       "pg-pass-2026"
#define PG_PW_LEN   (sizeof(PG_PW) - 1)
#define PG_PRESET   VERTHYS_PRESET_PERFORMANCE

/* 返回系统目录（System32，如 C:\Windows\System32），失败返回空串 */
static void pg_get_system32(char *buf, size_t cap)
{
    if (GetSystemDirectoryA(buf, (UINT)cap) == 0) buf[0] = '\0';
}

/* 返回 Windows 目录（如 C:\Windows），失败返回空串 */
static void pg_get_windows_dir(char *buf, size_t cap)
{
    if (GetWindowsDirectoryA(buf, (UINT)cap) == 0) buf[0] = '\0';
}

/*
 * 场景 1：目录穿越段（ .. ）路径被拒。
 * 构造 "System32\..\evil.bin"，规范化后会落到 Windows 目录内的穿越路径。
 */
TEST(pg_export_rejects_dotdot_path)
{
    VerthysHandle h;
    char          sys[MAX_PATH];
    char          evil_path[MAX_PATH];

    evil_path[0] = '\0';
    pg_get_system32(sys, sizeof(sys));
    if (sys[0] != '\0') {
        snprintf(evil_path, sizeof(evil_path), "%s\\..\\evil.bin", sys);
    }

    remove(PG_VERTHYS);
    VerthysResult rc_init   = Verthys_Init(&h);
    VerthysResult rc_create = (rc_init == VERTHYS_OK)
        ? Verthys_CreateWithPreset(h, PG_VERTHYS, PG_PW, PG_PW_LEN, PG_PRESET)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_export = (rc_create == VERTHYS_OK && evil_path[0] != '\0')
        ? Verthys_Export(h, evil_path, "epw", 3)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_deinit = Verthys_Deinit(h);
    remove(PG_VERTHYS);

    CHECK_EQ(rc_init, VERTHYS_OK);
    CHECK_EQ(rc_create, VERTHYS_OK);
    CHECK_EQ(rc_export, VERTHYS_ERR_INVALID);
    CHECK_EQ(rc_deinit, VERTHYS_OK);
    return 0;
}

/*
 * 场景 2：系统目录内目标路径被拒（导出侧）。
 */
TEST(pg_export_rejects_system_dir_path)
{
    VerthysHandle h;
    char          sys[MAX_PATH];
    char          evil_path[MAX_PATH];

    evil_path[0] = '\0';
    pg_get_system32(sys, sizeof(sys));
    if (sys[0] != '\0') {
        snprintf(evil_path, sizeof(evil_path), "%s\\verthys_evil.bin", sys);
    }

    remove(PG_VERTHYS);
    VerthysResult rc_init   = Verthys_Init(&h);
    VerthysResult rc_create = (rc_init == VERTHYS_OK)
        ? Verthys_CreateWithPreset(h, PG_VERTHYS, PG_PW, PG_PW_LEN, PG_PRESET)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_export = (rc_create == VERTHYS_OK && evil_path[0] != '\0')
        ? Verthys_Export(h, evil_path, "epw", 3)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_deinit = Verthys_Deinit(h);
    remove(PG_VERTHYS);

    CHECK_EQ(rc_init, VERTHYS_OK);
    CHECK_EQ(rc_create, VERTHYS_OK);
    CHECK_EQ(rc_export, VERTHYS_ERR_INVALID);
    CHECK_EQ(rc_deinit, VERTHYS_OK);
    return 0;
}

/*
 * 场景 3：系统目录内文件路径被拒（导入侧）。使用 System32 内真实文件
 * kernel32.dll——命中黑名单时在读取前返回 INVALID。
 */
TEST(pg_import_rejects_system_dir_path)
{
    VerthysHandle h;
    char          sys[MAX_PATH];
    char          sys_path[MAX_PATH];

    sys_path[0] = '\0';
    pg_get_system32(sys, sizeof(sys));
    if (sys[0] != '\0') {
        snprintf(sys_path, sizeof(sys_path), "%s\\kernel32.dll", sys);
    }

    remove(PG_VERTHYS);
    VerthysResult rc_init   = Verthys_Init(&h);
    VerthysResult rc_create = (rc_init == VERTHYS_OK)
        ? Verthys_CreateWithPreset(h, PG_VERTHYS, PG_PW, PG_PW_LEN, PG_PRESET)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_import = (rc_create == VERTHYS_OK && sys_path[0] != '\0')
        ? Verthys_Import(h, sys_path, PG_PW, PG_PW_LEN)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_deinit = Verthys_Deinit(h);
    remove(PG_VERTHYS);

    CHECK_EQ(rc_init, VERTHYS_OK);
    CHECK_EQ(rc_create, VERTHYS_OK);
    CHECK_EQ(rc_import, VERTHYS_ERR_INVALID);
    CHECK_EQ(rc_deinit, VERTHYS_OK);
    return 0;
}

/*
 * 场景 4：正常临时目录路径不被误拒（导出成功落盘）。
 */
TEST(pg_export_accepts_temp_path)
{
    VerthysHandle h;
    char          tmp_path[MAX_PATH];

    tmp_path[0] = '\0';
    if (GetTempPathA(MAX_PATH, tmp_path) == 0) tmp_path[0] = '\0';
    if (tmp_path[0] != '\0') {
        size_t base = strlen(tmp_path);
        if (base + 32 < MAX_PATH) {
            snprintf(tmp_path + base, MAX_PATH - base,
                     "verthys_pg_%lu.verthys", (unsigned long)GetCurrentProcessId());
        }
    }

    remove(PG_VERTHYS);
    VerthysResult rc_init   = Verthys_Init(&h);
    VerthysResult rc_create = (rc_init == VERTHYS_OK)
        ? Verthys_CreateWithPreset(h, PG_VERTHYS, PG_PW, PG_PW_LEN, PG_PRESET)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_export = (rc_create == VERTHYS_OK && tmp_path[0] != '\0')
        ? Verthys_Export(h, tmp_path, "epw", 3)
        : VERTHYS_ERR_INTERNAL;
    VerthysResult rc_deinit = Verthys_Deinit(h);
    if (tmp_path[0] != '\0') remove(tmp_path);
    remove(PG_VERTHYS);

    CHECK_EQ(rc_init, VERTHYS_OK);
    CHECK_EQ(rc_create, VERTHYS_OK);
    CHECK_EQ(rc_export, VERTHYS_OK);
    CHECK_EQ(rc_deinit, VERTHYS_OK);
    return 0;
}