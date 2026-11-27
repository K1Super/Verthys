/*
 * vty_blake3_avx2.c — BLAKE3 8 路并行 chunk 压缩
 *
 * 8 个 chunk 的数据按 lane 排布：每个 __m256i 承载同一状态字在 8 个
 * 独立 chunk 上的值。chunk 之间没有链式依赖，因此可以整块并行；
 * chunk 内部的 16 个 block 仍按顺序推进。
 *
 * 本文件必须由构建系统以 AVX2 指令集单独编译；调用方负责运行时
 * CPU 特性检测，未启用 AVX2 的平台只使用标量路径。
 */
#include "vty_blake3_avx2.h"

#include <immintrin.h>
#include <stdint.h>
#include <string.h>

#define B3_CHUNK_LEN 1024u
#define B3_BLOCK_LEN 64u
#define B3_CHUNK_START 0x01u
#define B3_CHUNK_END   0x02u

static const uint32_t B3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const uint8_t B3_PERM[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static uint32_t load_u32(const uint8_t *p)
{
    uint32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static void put_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value & 0xFFu);
    p[1] = (uint8_t)((value >> 8) & 0xFFu);
    p[2] = (uint8_t)((value >> 16) & 0xFFu);
    p[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static __m256i rotr32(__m256i x, int n)
{
    return _mm256_or_si256(_mm256_srli_epi32(x, n),
                           _mm256_slli_epi32(x, 32 - n));
}

static void g(__m256i *a, __m256i *b, __m256i *c, __m256i *d,
              __m256i mx, __m256i my)
{
    *a = _mm256_add_epi32(_mm256_add_epi32(*a, *b), mx);
    *d = rotr32(_mm256_xor_si256(*d, *a), 16);
    *c = _mm256_add_epi32(*c, *d);
    *b = rotr32(_mm256_xor_si256(*b, *c), 12);
    *a = _mm256_add_epi32(_mm256_add_epi32(*a, *b), my);
    *d = rotr32(_mm256_xor_si256(*d, *a), 8);
    *c = _mm256_add_epi32(*c, *d);
    *b = rotr32(_mm256_xor_si256(*b, *c), 7);
}

static void round8(__m256i s[16], const __m256i m[16])
{
    g(&s[0], &s[4], &s[8], &s[12], m[0], m[1]);
    g(&s[1], &s[5], &s[9], &s[13], m[2], m[3]);
    g(&s[2], &s[6], &s[10], &s[14], m[4], m[5]);
    g(&s[3], &s[7], &s[11], &s[15], m[6], m[7]);
    g(&s[0], &s[5], &s[10], &s[15], m[8], m[9]);
    g(&s[1], &s[6], &s[11], &s[12], m[10], m[11]);
    g(&s[2], &s[7], &s[8], &s[13], m[12], m[13]);
    g(&s[3], &s[4], &s[9], &s[14], m[14], m[15]);
}

int vty_blake3_chunk_cv8_avx2(const uint8_t *data8, uint32_t first_chunk,
                              uint8_t out_cvs[8][32])
{
    __m256i s[16];
    __m256i m[16];
    __m256i msg_tmp[16];
    uint32_t words[8][8];
    unsigned block;
    unsigned word;
    unsigned lane;
    int r;
    int i;

    if (data8 == NULL || out_cvs == NULL) return 1;

    for (i = 0; i < 8; i++) {
        s[i] = _mm256_set1_epi32((int)B3_IV[i]);
    }
    {
        __m256i counter_vec = _mm256_setr_epi32(
            (int)first_chunk, (int)(first_chunk + 1u), (int)(first_chunk + 2u),
            (int)(first_chunk + 3u), (int)(first_chunk + 4u),
            (int)(first_chunk + 5u), (int)(first_chunk + 6u),
            (int)(first_chunk + 7u));
        s[12] = counter_vec;

        for (block = 0; block < 16u; block++) {
            uint32_t flags = 0;
            if (block == 0u) flags |= B3_CHUNK_START;
            if (block == 15u) flags |= B3_CHUNK_END;

            /* 每个 block 都从当前 CV + IV/计数器/长度/标志重新初始化
             * 后半状态；只有前 8 个字承接上一 block 的 CV。 */
            for (i = 0; i < 4; i++) {
                s[8 + i] = _mm256_set1_epi32((int)B3_IV[i]);
            }
            s[12] = counter_vec;
            s[13] = _mm256_setzero_si256();
            s[14] = _mm256_set1_epi32((int)B3_BLOCK_LEN);
            s[15] = _mm256_set1_epi32((int)flags);

        for (word = 0; word < 16u; word++) {
            const size_t word_off = (size_t)block * B3_BLOCK_LEN + (size_t)word * 4u;
            m[word] = _mm256_setr_epi32(
                (int)load_u32(data8 + 0u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 1u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 2u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 3u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 4u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 5u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 6u * B3_CHUNK_LEN + word_off),
                (int)load_u32(data8 + 7u * B3_CHUNK_LEN + word_off));
        }

        for (r = 0; r < 7; r++) {
            round8(s, m);
            if (r != 6) {
                for (word = 0; word < 16u; word++) {
                    msg_tmp[word] = m[B3_PERM[word]];
                }
                for (word = 0; word < 16u; word++) {
                    m[word] = msg_tmp[word];
                }
            }
        }

        for (i = 0; i < 8; i++) {
            s[i] = _mm256_xor_si256(s[i], s[i + 8]);
        }
        }
    }

    for (word = 0; word < 8u; word++) {
        _mm256_storeu_si256((__m256i *)&words[word][0], s[word]);
    }
    for (lane = 0; lane < 8u; lane++) {
        for (word = 0; word < 8u; word++) {
            put_u32(out_cvs[lane] + word * 4u, words[word][lane]);
        }
    }

    memset(s, 0, sizeof(s));
    memset(m, 0, sizeof(m));
    memset(msg_tmp, 0, sizeof(msg_tmp));
    return 0;
}
