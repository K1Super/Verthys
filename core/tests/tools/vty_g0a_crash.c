/*
 * vty_g0a_crash.c — G0-A 崩溃注入宿主（仅隔离原型 + 测试钩子构建）
 *
 * 用途：在独立进程中推进回滚锚点，并在指定提交阶段直接 TerminateProcess，
 * 由父测试进程验证崩溃后的状态/TPM 键组合与恢复行为。命令行不含口令等秘密。
 *
 * 用法：
 *   vty_g0a_crash <state_path> <uuid_hex32> <generation> <crash_point> [preset]
 *
 * 退出码：
 *   0xC0DE0000|point  崩溃点已触发（进程被杀）
 *   10  参数非法
 *   11  状态路径注入失败
 *   12  回滚模块初始化失败
 *   13  preset 模式下 check 失败
 *   14  见证 ID 派生失败
 *   15  preset 模式下预置键未就绪
 *   20+rc 提交失败且未触发崩溃
 */
#include "vty_rollback.h"
#include "vty_tpm_witness.h"
#include "vty_witness_pool.h"
#include "vty_secure_state.h"
#include "vty_types.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_uuid(const char *hex, uint8_t uuid[VTY_UUID_BYTES])
{
    int i;

    if (strlen(hex) != VTY_UUID_BYTES * 2u) return 1;
    for (i = 0; i < (int)VTY_UUID_BYTES; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0) return 1;
        uuid[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    unsigned long generation;
    int crash_point;
    int preset;
    int rc;

    if (argc < 5 || argc > 6) return 10;
    if (parse_uuid(argv[2], uuid) != 0) return 10;
    generation = strtoul(argv[3], NULL, 10);
    crash_point = (int)strtol(argv[4], NULL, 10);
    preset = (argc == 6) ? (int)strtol(argv[5], NULL, 10) : 0;

    if (vty_rollback_set_path_for_test(argv[1]) != VTY_OK) return 11;
    vty_rollback_set_enabled(1);
    if (vty_rollback_init() != VTY_OK) return 12;

    if (preset) {
        /* 先加载状态并预热下一把密钥，使随后的提交走预置快路径。 */
        if (vty_rollback_check(uuid, generation - 1u) != VTY_OK) return 13;
        if (vty_secure_state_identity_rollback(uuid, wid) != VTY_OK) return 14;
        if (!vty_witness_pool_test_wait_ready(wid, 5000)) return 15;
    }

    if (crash_point == 1000) {
        /* 半完成键：在 NCryptCreatePersistedKey 成功后、FinalizeKey 前崩溃。 */
        vty_tpm_witness_set_crash_after_create_for_test(1);
    } else {
        vty_rollback_set_crash_point_for_test(crash_point);
    }
    rc = vty_rollback_commit(uuid, (uint64_t)generation);
    vty_rollback_shutdown();
    return 20 + (rc & 0xFF);
}
