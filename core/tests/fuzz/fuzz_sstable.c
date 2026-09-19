/*
 * fuzz_sstable.c — V3 LSM SSTable/Manifest 明文帧模糊测试目标
 *
 * 测试面（SSTable 子系统的两个明文输入面，单目标全覆盖）：
 *   1. verthys_lsm_manifest_parse_unverified —— Manifest 帧 AEAD 解密后的
 *      明文解析（flatcc verifier → magic/version → 逐表元数据边界校验：
 *      level < MAX_LEVELS、size 非零、min_key ≤ max_key → 有序重建）。
 *      成功路径须逐表释放惰性缓存指针（对齐生产失败清理纪律）。
 *   2. verthys_lsm_entry_decode —— 数据块明文的条目边界解码（定长头 78B
 *      + 变长 name，name_len ≤ 4096）。逐条推进直至失败/耗尽——
 *      该编解码器直接消费任意长度的块明文，是 SSTable 读路径中
 *      距原始字节最近的解析边界。
 *
 * 语料：corpus/sstable/（gen_seeds 生成的合法 LSMManifestV3 + 合法
 * 条目编码序列，两类种子同目录投喂）。
 *
 * 判定：任何崩溃 / ASAN 报告 / 挂起 = 失败。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_common.h"
#include "verthys.h"
#include "verthys_lsm_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_msvc_prepare();

    /* ---- 面 1：Manifest 明文帧 ---- */
    {
        VerthysLsmManifest m;
        VerthysResult r = verthys_lsm_manifest_parse_unverified(data, size, &m);
        if (r == VERTHYS_OK) {
            /* 成功路径同样走生产清理纪律（惰性缓存指针在此恒为 NULL，
             * release 幂等；保持与 manifest_load 失败路径对称） */
            for (size_t i = 0; i < m.count; i++) {
                verthys_lsm_sstable_meta_release(&m.tables[i]);
            }
            memset(&m, 0, sizeof(m));
        }
    }

    /* ---- 面 2：数据块明文条目序列 ---- */
    {
        size_t off = 0;
        while (off < size) {
            VerthysLsmEntry e;
            size_t consumed = verthys_lsm_entry_decode(data + off,
                                                     size - off, &e);
            if (consumed == 0) break; /* 边界失败即终止（生产 scan_block 同语义） */
            off += consumed;
        }
    }
    return 0;
}
