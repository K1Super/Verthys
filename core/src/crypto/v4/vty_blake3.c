/*
 * vty_blake3.c — BLAKE3 一次性 32B 摘要（便携实现）
 *
 * 结构：1024 字节为一个 chunk；chunk 内 64 字节为一个 block；
 * 每个 chunk 产出 8 个 32 位字的 CV，再按二叉 Merkle 树两两合并。
 * 只有根节点的最终压缩带 ROOT 标志，因此单 chunk 消息直接在
 * chunk 的末块上带 ROOT，多 chunk 消息在最后一次合并时带 ROOT。
 */
#include "vty_blake3.h"
#include "vty_util.h"

#include <stdlib.h>
#include <string.h>

#define B3_BLOCK_LEN 64u
#define B3_CHUNK_LEN 1024u

#define B3_CHUNK_START 0x01u
#define B3_CHUNK_END   0x02u
#define B3_PARENT      0x04u
#define B3_ROOT        0x08u

static const uint32_t B3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

/* 每轮消息字置换；轮数固定 7 */
static const uint8_t B3_PERM[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static uint32_t rot32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32u - n));
}

static void g(uint32_t s[16], int a, int b, int c, int d,
              uint32_t mx, uint32_t my)
{
    s[a] = s[a] + s[b] + mx;
    s[d] = rot32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = rot32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rot32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = rot32(s[b] ^ s[c], 7);
}

static void b3_round(uint32_t s[16], const uint32_t m[16])
{
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

/* 压缩函数：只输出前 8 个字（32 字节摘要所需的全部） */
static void b3_compress(const uint32_t cv[8], const uint32_t block[16],
                        uint64_t counter, uint32_t block_len, uint32_t flags,
                        uint8_t out[32])
{
    uint32_t s[16];
    uint32_t m[16];
    uint32_t tmp[16];
    int r, i;

    memcpy(s, cv, sizeof(uint32_t) * 8);
    s[8] = B3_IV[0];
    s[9] = B3_IV[1];
    s[10] = B3_IV[2];
    s[11] = B3_IV[3];
    s[12] = (uint32_t)(counter & 0xFFFFFFFFu);
    s[13] = (uint32_t)(counter >> 32);
    s[14] = block_len;
    s[15] = flags;

    memcpy(m, block, sizeof(uint32_t) * 16);

    for (r = 0; r < 7; r++) {
        b3_round(s, m);
        if (r != 6) {
            for (i = 0; i < 16; i++) {
                tmp[i] = m[B3_PERM[i]];
            }
            memcpy(m, tmp, sizeof(m));
        }
    }

    for (i = 0; i < 8; i++) {
        uint32_t w = s[i] ^ s[i + 8];
        out[i * 4 + 0] = (uint8_t)(w & 0xFFu);
        out[i * 4 + 1] = (uint8_t)((w >> 8) & 0xFFu);
        out[i * 4 + 2] = (uint8_t)((w >> 16) & 0xFFu);
        out[i * 4 + 3] = (uint8_t)((w >> 24) & 0xFFu);
    }
    vty_secure_zero(s, sizeof(s));
    vty_secure_zero(m, sizeof(m));
    vty_secure_zero(tmp, sizeof(tmp));
}

/* 单 chunk 的 CV；root=1 表示该 chunk 即整条消息 */
static void b3_chunk_cv(const uint8_t *data, size_t len, uint32_t chunk_index,
                        int root, uint8_t out[32])
{
    uint32_t cv[8];
    uint32_t block[16];
    size_t nblocks, i;

    memcpy(cv, B3_IV, sizeof(cv));
    nblocks = (len == 0) ? 1u : (len + B3_BLOCK_LEN - 1u) / B3_BLOCK_LEN;

    for (i = 0; i < nblocks; i++) {
        size_t off = i * B3_BLOCK_LEN;
        size_t remain = len - off;
        size_t blen = remain > B3_BLOCK_LEN ? B3_BLOCK_LEN : remain;
        uint32_t flags = 0;

        memset(block, 0, sizeof(block));
        if (blen != 0) {
            memcpy(block, data + off, blen);
        }
        if (i == 0) flags |= B3_CHUNK_START;
        if (i == nblocks - 1) flags |= B3_CHUNK_END;
        if (root && nblocks == 1) flags |= B3_ROOT;

        b3_compress(cv, block, (uint64_t)chunk_index, (uint32_t)blen, flags, out);
        /* 中间块输出的是 CV，可直接作为下一块的链值；末块输出即该 chunk 的 CV */
        if (i + 1 < nblocks) {
            uint32_t next_cv[8];
            memcpy(next_cv, out, sizeof(next_cv));
            memcpy(cv, next_cv, sizeof(cv));
            vty_secure_zero(next_cv, sizeof(next_cv));
        }
    }
    vty_secure_zero(cv, sizeof(cv));
    vty_secure_zero(block, sizeof(block));
}

static void b3_parent_cv(const uint8_t left[32], const uint8_t right[32],
                         int root, uint8_t out[32])
{
    uint32_t block[16];
    uint32_t cv[8];
    uint32_t flags = B3_PARENT | (root ? B3_ROOT : 0u);

    memcpy(block, left, 32);
    memcpy(block + 8, right, 32);
    memcpy(cv, B3_IV, sizeof(cv));
    b3_compress(cv, block, 0, B3_BLOCK_LEN, flags, out);
    vty_secure_zero(cv, sizeof(cv));
    vty_secure_zero(block, sizeof(block));
}

int vty_blake3_32(const uint8_t *data, size_t len, uint8_t out[VTY_HASH_BYTES])
{
    size_t nchunks, i, n, w;
    uint8_t *cvs;
    uint8_t tmp[32];

    if (out == NULL) return VTY_E_INVALID;
    if (data == NULL && len != 0) return VTY_E_INVALID;

    if (len <= B3_CHUNK_LEN) {
        b3_chunk_cv(data != NULL ? data : (const uint8_t *)"", len, 0, 1, out);
        return VTY_OK;
    }

    nchunks = (len + B3_CHUNK_LEN - 1u) / B3_CHUNK_LEN;
    if (nchunks > SIZE_MAX / 32u) return VTY_E_RESOURCE;
    cvs = (uint8_t *)malloc(nchunks * 32u);
    if (cvs == NULL) return VTY_E_RESOURCE;

    for (i = 0; i < nchunks; i++) {
        size_t off = i * B3_CHUNK_LEN;
        size_t remain = len - off;
        size_t clen = remain > B3_CHUNK_LEN ? B3_CHUNK_LEN : remain;
        b3_chunk_cv(data + off, clen, (uint32_t)i, 0, cvs + i * 32u);
    }

    n = nchunks;
    while (n > 1) {
        if (n == 2) {
            b3_parent_cv(cvs, cvs + 32u, 1, out);
            break;
        }
        w = 0;
        for (i = 0; i + 1 < n; i += 2) {
            b3_parent_cv(cvs + i * 32u, cvs + (i + 1) * 32u, 0, tmp);
            memcpy(cvs + w * 32u, tmp, 32);
            w++;
        }
        if (i < n) {
            memcpy(cvs + w * 32u, cvs + i * 32u, 32);
            w++;
        }
        n = w;
    }

    vty_secure_zero(cvs, nchunks * 32u);
    free(cvs);
    vty_secure_zero(tmp, sizeof(tmp));
    return VTY_OK;
}
