/*
 * fuzz_import.c — v1 交换格式（导入信封）头部模糊测试目标（WP-10 目标 5/5）
 *
 * 设计依据：docs/V3_UPGRADE_PLAYBOOK.md WP-10
 *
 * 测试面：vfmt_parse_header —— Verthys_Import 消费跨设备迁移文件的第一道
 * 解析边界（魔数/版本/算法 ID → meta_offset/mac_offset 边界校验（P1-1
 * 无回绕形式）→ salt 提取）。该函数直接消费攻击者完全可控的文件字节
 * （导入文件可来自不可信来源），是全部 5 个目标中唯一"未经加密认证
 * 前置"的明文解析面——内存安全完全依赖自身边界纪律。
 *
 * 语料：corpus/import/（gen_seeds 经 vfmt_write 生成的合法 v1 信封，
 * 含 1 条记录的完整 blob——头部字段偏移即合法基线）。
 *
 * 判定：任何崩溃 / ASAN 报告 / 挂起 = 失败。
 */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "verthys.h"
#include "verthys_format.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    VerthysFmtMeta meta;

    fuzz_msvc_prepare();

    int rc = vfmt_parse_header(data, size, &meta);
    (void)rc; /* -1/0 均合法：崩溃/ASAN 是唯一失败信号 */

    return 0;
}
