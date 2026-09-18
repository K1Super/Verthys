/*
 * fuzz_partition.c — V3 分区表明文帧模糊测试目标（WP-10 目标 2/5）
 *
 * 设计依据：docs/V3_UPGRADE_PLAYBOOK.md WP-10
 *
 * 测试面：verthys_partition_table_parse_unverified —— 分区表帧 AEAD 解密
 * 后的明文解析（flatcc verifier → magic/version/txid → 条目数上限 →
 * 逐条目 key_id 16B / wrapped 48B / wrap_nonce 12B 向量长度严格校验）。
 * 生产路径随后逐条目 CNG 解包完成认证；本目标独立验证解析器在任意
 * 输入下的边界纪律。
 *
 * 语料：corpus/partition/（gen_seeds 生成的合法 PartitionTableV3）。
 *
 * 判定：任何崩溃 / ASAN 报告 / 挂起 = 失败。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_common.h"
#include "verthys.h"
#include "verthys_partition.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t txid = 0;
    VerthysPartitionEntryRaw entries[VERTHYS_PARTITION_MAX];
    size_t count = 0;
    uint8_t *buf;
    VerthysResult r;

    fuzz_msvc_prepare();

    buf = (uint8_t *)malloc(size ? size : 1);
    if (buf == NULL) return 0;
    if (size != 0) memcpy(buf, data, size);

    r = verthys_partition_table_parse_unverified(buf, size, &txid,
                                               entries, &count);
    (void)r;

    free(buf);
    return 0;
}
