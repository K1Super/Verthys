/*
 * fuzz_superblock.c — V3 超级块明文帧模糊测试目标（WP-10 目标 1/5）
 *
 * 设计依据：docs/V3_UPGRADE_PLAYBOOK.md WP-10
 *
 * 测试面：vsb_v3_parse_unverified —— S1 解锁流水线在 integrity_key 派生
 * 之前消费的唯一样本输入面（flatcc verifier → 字段读取 → 向量长度严格
 * 校验）。生产路径中该输入在 AEAD/HMAC 认证闭环内，但解析器自身的
 * 内存安全必须独立于认证成立（纵深防御：解析层缺陷不得依赖加密层兜底）。
 *
 * 语料：gen_seeds 生成的合法 SuperBlockV3 FlatBuffer 明文（种子根目录
 * corpus/superblock/）。libFuzzer 变异覆盖：截断/扩展/位翻转/结构破坏。
 *
 * 判定：任何崩溃 / ASAN 报告 / 挂起 = 失败（发现即转 bug 清单）；
 * 返回 FORMAT/OK 均为合法结果（harness 不断言返回值——harness 越薄，
 * 信号越可信）。
 *
 * 构建：/fsanitize=fuzzer（MSVC 内置 libFuzzer + ASAN，隐含内存安全检查）。
 * 运行：fuzz_superblock.exe <corpus_dir> [-max_total_time=600]
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_common.h"
#include "verthys.h"
#include "verthys_container_v3.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    VerthysSuperBlockV3 out;
    uint8_t *buf;
    VerthysResult r;

    fuzz_msvc_prepare();

    /* flatcc 读取器约定可写缓冲（parse 签名 uint8_t*）→ 精确长度堆拷贝 */
    buf = (uint8_t *)malloc(size ? size : 1);
    if (buf == NULL) return 0;
    if (size != 0) memcpy(buf, data, size);

    r = vsb_v3_parse_unverified(buf, size, &out);
    (void)r; /* 结果码不断言：崩溃/ASAN 是唯一失败信号 */

    free(buf);
    return 0;
}
