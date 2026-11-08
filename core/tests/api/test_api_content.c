/*
 * test_api_content.c — 分片公共 API 验收
 *
 * 覆盖：模块解锁前置、分片往返、篡改拒绝、缓冲不足返回所需长度、
 * 模块锁定后的 POLICY 拒绝。全部走公共 C API，不访问内部仓库。
 */
#include "verthys_test.h"
#include "verthys.h"

#include <string.h>

#define CONTENT_PATH "api_content.vty"
#define CONTENT_PW   "content-pw"
#define CONTENT_MOD  "content-mod-pw"

TEST(api_content_chunk)
{
    VerthysHandle h = NULL;
    char code[80];
    uint8_t file_uuid[16];
    uint8_t pt[64];
    uint8_t ct[512];
    uint8_t opened[512];
    size_t ct_len = 0;
    size_t pt_len = 0;
    size_t seal_len = 0;
    size_t i;

    remove(CONTENT_PATH);
    for (i = 0; i < sizeof(file_uuid); i++) file_uuid[i] = (uint8_t)(0x10u + i);
    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(0xA0u + i);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, CONTENT_PATH, CONTENT_PW, strlen(CONTENT_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_PHOTO,
                                    CONTENT_MOD, strlen(CONTENT_MOD), NULL),
             VERTHYS_OK);

    CHECK_EQ(Verthys_V4ChunkSeal(h, VERTHYS_MODULE_PHOTO, file_uuid, 0, 2,
                                 pt, sizeof(pt), ct, sizeof(ct), &ct_len),
             VERTHYS_OK);
    CHECK(ct_len > sizeof(pt));
    CHECK_EQ(Verthys_V4ChunkOpen(h, VERTHYS_MODULE_PHOTO, file_uuid, 0, 2,
                                 ct, ct_len, opened, sizeof(opened), &pt_len),
             VERTHYS_OK);
    CHECK_EQ(pt_len, sizeof(pt));
    CHECK(memcmp(pt, opened, sizeof(pt)) == 0);

    /* 错误 seq/total 与篡改都必须拒绝 */
    CHECK_EQ(Verthys_V4ChunkOpen(h, VERTHYS_MODULE_PHOTO, file_uuid, 1, 2,
                                 ct, ct_len, opened, sizeof(opened), &pt_len),
             VERTHYS_ERR_AUTH);
    ct[ct_len - 1u] ^= 0x01u;
    CHECK_EQ(Verthys_V4ChunkOpen(h, VERTHYS_MODULE_PHOTO, file_uuid, 0, 2,
                                 ct, ct_len, opened, sizeof(opened), &pt_len),
             VERTHYS_ERR_AUTH);
    ct[ct_len - 1u] ^= 0x01u;

    /* 缓冲不足：返回所需长度，不写越界 */
    pt_len = 0;
    CHECK_EQ(Verthys_V4ChunkOpen(h, VERTHYS_MODULE_PHOTO, file_uuid, 0, 2,
                                 ct, ct_len, opened, 8, &pt_len),
             VERTHYS_ERR_RESOURCE_LIMIT);
    CHECK_EQ(pt_len, sizeof(pt));

    /* 模块锁定后内容入口必须 POLICY，不能退回 Keyring。
     * Seal 入口会先把 out_len 置 0，故用独立变量避免破坏 Open 的输入长度。 */
    CHECK_EQ(Verthys_V4ModuleLock(h, VERTHYS_MODULE_PHOTO), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ChunkSeal(h, VERTHYS_MODULE_PHOTO, file_uuid, 0, 2,
                                 pt, sizeof(pt), ct, sizeof(ct), &seal_len),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_V4ChunkOpen(h, VERTHYS_MODULE_PHOTO, file_uuid, 0, 2,
                                 ct, ct_len, opened, sizeof(opened), &pt_len),
             VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(CONTENT_PATH);
    return 0;
}
