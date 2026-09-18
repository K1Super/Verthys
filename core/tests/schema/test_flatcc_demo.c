/*
 * test_flatcc_demo.c — WP-0 验收：vendored flatcc 工具链全链路验证
 *
 * 链路：core/schema/demo.fbs
 *   → flatcc_cli（vendored 编译器，构建期 -a 生成 reader/builder/verifier）
 *   → core/schema/generated/*.h
 *   → flatccrt（vendored 运行时，静态链入测试 exe）
 *   → builder 编码 / verifier 结构校验 / reader 解码 闭环
 */
#include "verthys_test.h"
#include "demo_builder.h"
#include "demo_verifier.h"
#include <string.h>

#define DEMO_MAGIC   UINT32_C(0x56455254)   /* "VERT" */
#define DEMO_COUNTER UINT64_C(0x123456789ABCDEF0)
#define DEMO_PAYLOAD_LEN 16

/*
 * 构建一个 ToolchainDemo buffer。
 * 返回 flatcc_builder_aligned_free 归属的对齐缓冲，失败返回 NULL。
 * size_out 可为 NULL。
 */
static void *demo_build(size_t *size_out)
{
    flatcc_builder_t builder;
    flatbuffers_uint8_vec_ref_t payload_ref;
    uint8_t payload[DEMO_PAYLOAD_LEN];
    void *buf = NULL;
    size_t size = 0;
    unsigned i;

    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(i * 7 + 1);
    }

    if (flatcc_builder_init(&builder) != 0) {
        goto done;
    }
    payload_ref = flatbuffers_uint8_vec_create(&builder, payload, sizeof(payload));
    if (payload_ref == 0) {
        goto clear;
    }
    if (ToolchainDemo_create_as_root(&builder, DEMO_MAGIC, DEMO_COUNTER,
                                     payload_ref) == 0) {
        goto clear;
    }
    buf = flatcc_builder_finalize_aligned_buffer(&builder, &size);
clear:
    flatcc_builder_clear(&builder);
done:
    if (size_out != NULL) {
        *size_out = size;
    }
    return buf;
}

/* 编码 → 结构校验 → 解码 全链路闭环 */
TEST(flatcc_demo_roundtrip)
{
    void *buf;
    size_t size = 0;
    ToolchainDemo_table_t table;
    unsigned i;

    buf = demo_build(&size);
    CHECK(buf != NULL);
    CHECK(size > 0);

    /* verifier：结构校验通过（合法 buffer 必须放行） */
    CHECK(ToolchainDemo_verify_as_root(buf, size) == flatcc_verify_ok);

    /* reader：字段解码值与编码值逐项一致 */
    table = ToolchainDemo_as_root(buf);
    CHECK(table != NULL);
    CHECK_EQ(ToolchainDemo_magic(table), (long)DEMO_MAGIC);
    CHECK(ToolchainDemo_counter(table) == DEMO_COUNTER);
    {
        flatbuffers_uint8_vec_t payload_vec = ToolchainDemo_payload(table);
        CHECK(payload_vec != NULL);
        CHECK_EQ(flatbuffers_uint8_vec_len(payload_vec),
                 (long)DEMO_PAYLOAD_LEN);
        for (i = 0; i < DEMO_PAYLOAD_LEN; i++) {
            CHECK_EQ(flatbuffers_uint8_vec_at(payload_vec, i),
                     (long)(uint8_t)(i * 7 + 1));
        }
    }

    flatcc_builder_aligned_free(buf);
    return 0;
}

/* 损坏 buffer（根偏移越界/截断/垃圾）必须被 verifier 拒绝 */
TEST(flatcc_demo_tamper_rejected)
{
    void *buf;
    size_t size = 0;
    uint8_t *bytes;
    uint8_t saved;

    buf = demo_build(&size);
    CHECK(buf != NULL);
    CHECK(size > 8);
    bytes = (uint8_t *)buf;

    /* 1) 根偏移改写为越界值 → 拒绝 */
    saved = bytes[0];
    bytes[0] = 0xFF;
    CHECK(ToolchainDemo_verify_as_root(buf, size) != flatcc_verify_ok);
    bytes[0] = saved;
    CHECK(ToolchainDemo_verify_as_root(buf, size) == flatcc_verify_ok);

    /* 2) 截断（size 不足表结构）→ 拒绝 */
    CHECK(ToolchainDemo_verify_as_root(buf, size - 8) != flatcc_verify_ok);

    /* 3) 全零垃圾缓冲 → 拒绝 */
    {
        uint8_t garbage[16];
        memset(garbage, 0, sizeof(garbage));
        CHECK(ToolchainDemo_verify_as_root(garbage, sizeof(garbage))
              != flatcc_verify_ok);
    }

    flatcc_builder_aligned_free(buf);
    return 0;
}
