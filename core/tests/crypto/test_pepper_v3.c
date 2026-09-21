/*
 * test_pepper_v3.c — 胡椒持久化格式与密钥槽闭环验收
 *
 * 覆盖：
 *   - 首建闭环：生成 → 封装 → 落盘 308B → 重载一致
 *   - 密文篡改 / 指纹篡改 → 来源错误（禁止兜底）
 *   - 封装级伪造（头部级别字节改为与实际封装相反的级别）→ 不跨级回退
 *   - 外来尺寸 / 坏 magic → 结构门拒绝
 *   - 注入优先级：注入胡椒时不触碰 OS 存储
 *
 * 隔离：全部用例经 verthys_pepper_set_storage_path_override 落盘到
 * 测试沙箱（CWD），绝不触碰 %APPDATA% 真实胡椒。
 *
 * 布局常量在测试侧独立定义：实现侧偏移一旦漂移，本文件即失配报警。
 */
#include "verthys_test.h"
#include "verthys_pepper.h"
#include "cng_machine_key.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define V3_FILE_BYTES     308u
#define V3_OFF_MAGIC      0
#define V3_OFF_VERSION    4
#define V3_OFF_KEY_LEVEL  8
#define V3_OFF_KEY_PROV   9
#define V3_OFF_FP         12
#define V3_OFF_LABEL      20
#define V3_OFF_CIPHER     52
#define V3_FP_BYTES       8u
#define V3_MAGIC          0x50505656u
#define V3_VERSION        3

static const char *K_PP_PATH = "pepper_v3_test.bin";

/* 恢复模块与沙箱干净态（路径覆盖复位 + 删除测试文件） */
static void pp_reset(void)
{
    verthys_pepper_deinit();
    verthys_pepper_set_storage_path_override(NULL);
    remove(K_PP_PATH);
}

/* 通过首建路径生成一份合法持久化文件，随后重置模块（文件保留） */
static int pp_make_valid_file(void)
{
    pp_reset();
    if (cng_machine_key_init() != 0) return 1;
    verthys_pepper_set_storage_path_override(K_PP_PATH);
    if (verthys_pepper_init() != 0) return 1;
    verthys_pepper_deinit();
    return 0;
}

/* 读测试文件全部 308B（调用方保证文件存在） */
static int pp_read_file(uint8_t *buf)
{
    FILE *f = fopen(K_PP_PATH, "rb");
    if (f == NULL) return 1;
    size_t rd = fread(buf, 1, V3_FILE_BYTES, f);
    fclose(f);
    return (rd == V3_FILE_BYTES) ? 0 : 1;
}

static int pp_write_file(const uint8_t *buf, size_t len)
{
    FILE *f = fopen(K_PP_PATH, "wb");
    if (f == NULL) return 1;
    size_t wr = fwrite(buf, 1, len, f);
    fclose(f);
    return (wr == len) ? 0 : 1;
}

TEST(pepper_v3_first_seal_roundtrip)
{
    pp_reset();
    CHECK(cng_machine_key_init() == 0);
    verthys_pepper_set_storage_path_override(K_PP_PATH);

    CHECK(verthys_pepper_init() == 0);
    const uint8_t *p1 = verthys_pepper_get();
    CHECK(p1 != NULL);
    uint8_t saved[VERTHYS_KEY_BYTES];
    memcpy(saved, p1, sizeof(saved));

    /* 文件结构断言 */
    uint8_t buf[V3_FILE_BYTES];
    CHECK(pp_read_file(buf) == 0);
    uint32_t magic = (uint32_t)buf[V3_OFF_MAGIC] |
                     ((uint32_t)buf[V3_OFF_MAGIC + 1] << 8) |
                     ((uint32_t)buf[V3_OFF_MAGIC + 2] << 16) |
                     ((uint32_t)buf[V3_OFF_MAGIC + 3] << 24);
    CHECK_EQ(magic, (uint32_t)V3_MAGIC);
    uint16_t ver = (uint16_t)buf[V3_OFF_VERSION] |
                   ((uint16_t)buf[V3_OFF_VERSION + 1] << 8);
    CHECK_EQ(ver, (uint16_t)V3_VERSION);
    CHECK(buf[V3_OFF_KEY_LEVEL] == CMK_KEY_LEVEL_USER ||
          buf[V3_OFF_KEY_LEVEL] == CMK_KEY_LEVEL_MACHINE);
    CHECK(buf[V3_OFF_KEY_PROV] == CMK_PROVIDER_PLATFORM_KSP ||
          buf[V3_OFF_KEY_PROV] == CMK_PROVIDER_SOFTWARE_KSP);

    /* 重载一致性 */
    verthys_pepper_deinit();
    CHECK(verthys_pepper_init() == 0);
    const uint8_t *p2 = verthys_pepper_get();
    CHECK(p2 != NULL);
    CHECK(memcmp(p2, saved, VERTHYS_KEY_BYTES) == 0);

    pp_reset();
    return 0;
}

TEST(pepper_v3_cipher_tamper_rejected)
{
    CHECK(pp_make_valid_file() == 0);

    uint8_t buf[V3_FILE_BYTES];
    CHECK(pp_read_file(buf) == 0);
    buf[V3_OFF_CIPHER] ^= 0x01;
    CHECK(pp_write_file(buf, V3_FILE_BYTES) == 0);

    verthys_pepper_set_storage_path_override(K_PP_PATH);
    CHECK(verthys_pepper_init() == -1);
    CHECK(verthys_pepper_source_error() == 1);
    CHECK(verthys_pepper_get() == NULL);

    pp_reset();
    return 0;
}

TEST(pepper_v3_fingerprint_tamper_rejected)
{
    CHECK(pp_make_valid_file() == 0);

    uint8_t buf[V3_FILE_BYTES];
    CHECK(pp_read_file(buf) == 0);
    buf[V3_OFF_FP] ^= 0x01;
    CHECK(pp_write_file(buf, V3_FILE_BYTES) == 0);

    verthys_pepper_set_storage_path_override(K_PP_PATH);
    CHECK(verthys_pepper_init() == -1);
    CHECK(verthys_pepper_source_error() == 1);
    CHECK(verthys_pepper_get() == NULL);

    pp_reset();
    return 0;
}

TEST(pepper_v3_level_forgery_rejected)
{
    CHECK(pp_make_valid_file() == 0);

    /* 头部级别字节伪造为相反级别，指纹同步重算：
     * 指纹通过、解包按伪造级别定位密钥 → 必然失败且不得跨级回退 */
    uint8_t buf[V3_FILE_BYTES];
    CHECK(pp_read_file(buf) == 0);
    buf[V3_OFF_KEY_LEVEL] = (buf[V3_OFF_KEY_LEVEL] == CMK_KEY_LEVEL_USER)
                                ? (uint8_t)CMK_KEY_LEVEL_MACHINE
                                : (uint8_t)CMK_KEY_LEVEL_USER;
    uint8_t fp_new[V3_FP_BYTES];
    CHECK(pepper_file_fingerprint(buf + V3_OFF_VERSION,
                                  buf + V3_OFF_LABEL,
                                  buf + V3_OFF_CIPHER,
                                  fp_new) == 0);
    memcpy(buf + V3_OFF_FP, fp_new, V3_FP_BYTES);
    CHECK(pp_write_file(buf, V3_FILE_BYTES) == 0);

    verthys_pepper_set_storage_path_override(K_PP_PATH);
    CHECK(verthys_pepper_init() == -1);
    CHECK(verthys_pepper_source_error() == 1);
    CHECK(verthys_pepper_get() == NULL);

    pp_reset();
    return 0;
}

TEST(pepper_v3_foreign_size_rejected)
{
    pp_reset();
    CHECK(cng_machine_key_init() == 0);
    verthys_pepper_set_storage_path_override(K_PP_PATH);

    /* 写入 304B 历史尺寸文件：尺寸门必须拒绝 */
    uint8_t foreign[304];
    memset(foreign, 0, sizeof(foreign));
    foreign[0] = (uint8_t)(V3_MAGIC & 0xFF);
    foreign[1] = (uint8_t)((V3_MAGIC >> 8) & 0xFF);
    foreign[2] = (uint8_t)((V3_MAGIC >> 16) & 0xFF);
    foreign[3] = (uint8_t)((V3_MAGIC >> 24) & 0xFF);
    CHECK(pp_write_file(foreign, sizeof(foreign)) == 0);

    CHECK(verthys_pepper_init() == -1);
    CHECK(verthys_pepper_source_error() == 1);
    CHECK(verthys_pepper_get() == NULL);

    pp_reset();
    return 0;
}

TEST(pepper_v3_bad_magic_rejected)
{
    pp_reset();
    CHECK(cng_machine_key_init() == 0);
    verthys_pepper_set_storage_path_override(K_PP_PATH);

    /* 308B 但 magic 非法：magic 门必须拒绝 */
    uint8_t buf[V3_FILE_BYTES];
    memset(buf, 0, sizeof(buf));
    buf[V3_OFF_VERSION]     = (uint8_t)(V3_VERSION & 0xFF);
    buf[V3_OFF_VERSION + 1] = (uint8_t)((V3_VERSION >> 8) & 0xFF);
    CHECK(pp_write_file(buf, sizeof(buf)) == 0);

    CHECK(verthys_pepper_init() == -1);
    CHECK(verthys_pepper_source_error() == 1);
    CHECK(verthys_pepper_get() == NULL);

    pp_reset();
    return 0;
}

/* OS 托管来源不可用 + 无注入：默认构建必须显式失败，
 * 不得以零熵编译内嵌常量静默开箱（该常量随源码公开，走此来源的
 * 容器离线爆破退化为纯口令熵）。构造方式：超长存储路径覆盖迫使
 * 路径解析失败，等价 OS 托管持久化层不可达。 */
TEST(pepper_v3_no_compiled_fallback)
{
    pp_reset();
    CHECK(cng_machine_key_init() == 0);

    char long_path[600];
    memset(long_path, 'A', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    verthys_pepper_set_storage_path_override(long_path);

    CHECK_EQ(verthys_pepper_init(), -1);
    CHECK(verthys_pepper_get() == NULL);
    CHECK_EQ(verthys_pepper_get_source(), VERTHYS_PEPPER_SOURCE_NONE);
    CHECK(verthys_pepper_source_error() == 1);

    pp_reset();
    return 0;
}

TEST(pepper_v3_inject_bypasses_os)
{
    pp_reset();
    CHECK(cng_machine_key_init() == 0);
    verthys_pepper_set_storage_path_override(K_PP_PATH);

    uint8_t inj[VERTHYS_KEY_BYTES];
    memset(inj, 0xA5, sizeof(inj));
    CHECK(verthys_pepper_inject(inj) == 0);
    CHECK(verthys_pepper_init() == 0);
    CHECK_EQ(verthys_pepper_get_source(), VERTHYS_PEPPER_SOURCE_INJECTED);
    CHECK(memcmp(verthys_pepper_get(), inj, VERTHYS_KEY_BYTES) == 0);

    /* 注入路径不得触碰 OS 存储：测试路径下不应产生任何文件 */
    FILE *f = fopen(K_PP_PATH, "rb");
    CHECK(f == NULL);

    pp_reset();
    return 0;
}