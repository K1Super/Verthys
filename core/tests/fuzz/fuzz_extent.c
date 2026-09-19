/*
 * fuzz_extent.c — V3 Extent 索引明文帧模糊测试目标
 *
 * 测试面：verthys_extent_index_parse_unverified —— Extent 索引帧 AEAD
 * 解密后的明文解析（flatcc verifier → magic/version → 条目数上限 →
 * 逐条目 hash 32B / nonce 12B 向量长度校验 → 字段一致性校验：
 * size ≥ tag、plaintext_size 自洽、offset+size ≤ next_offset 追加游标
 * ——防越界读放大与 uint64 回绕）。
 *
 * 语料：corpus/extent/（gen_seeds 生成的合法 ExtentIndexV3）。
 *
 * 判定：任何崩溃 / ASAN 报告 / 挂起 = 失败。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_common.h"
#include "verthys.h"
#include "verthys_extent.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    VerthysExtentIndex idx;
    uint64_t nonce_counter = 0;
    uint8_t *buf;
    VerthysResult r;

    fuzz_msvc_prepare();

    buf = (uint8_t *)malloc(size ? size : 1);
    if (buf == NULL) return 0;
    if (size != 0) memcpy(buf, data, size);

    r = verthys_extent_index_parse_unverified(buf, size, &idx, &nonce_counter);
    (void)r;

    free(buf);
    return 0;
}
