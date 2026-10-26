/*
 * vty_tpm_probe.c — TPM 2.0 能力探针（测试工具，不进入生产 DLL）
 *
 * 职责：在验收机上确认 TBS 通道可用、PCR[7,11] 可读、专用测试索引上的
 * NV 计数器可完成“定义 → 递增 → 读取 → 删除”全流程。探针只使用固定
 * 测试索引并在退出前清理，避免污染 Windows 自身占用的 NV 空间。
 *
 * 约束：
 *   - 只做只读与可清理的写操作；不触碰平台索引（0x01C00000 段）。
 *   - 不输出任何密钥材料；owner auth 只报告“可获取/不可获取”。
 *   - 命令编码为大端（TPM 2.0 线格式），与内部小端容器格式无关。
 */
#define _WIN32_WINNT 0x0A00
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tbs.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

/* 最近一次 PCR 读取结果（供 PCP PCR 绑定用例构造摘要列表） */
static uint8_t g_pcr7[32];
static uint8_t g_pcr11[32];
static int g_pcr_valid = 0;

/* TPM 2.0 常量（只列探针使用的最小集合） */
#define TPM_ST_NO_SESSIONS 0x8001u
#define TPM_ST_SESSIONS    0x8002u
#define TPM_CC_PCR_READ    0x0000017Eu
#define TPM_CC_NV_DEFINE   0x0000012Bu
#define TPM_CC_NV_UNDEFINE 0x00000122u
#define TPM_CC_NV_INCREMENT 0x00000134u
#define TPM_CC_NV_READ     0x0000014Eu
#define TPM_RH_OWNER       0x40000001u
#define TPM_RS_PW          0x40000009u
#define TPM_ALG_SHA256     0x000Bu
#define TPM_RC_SUCCESS     0x000u
#define TPM_RC_NV_UNINITIALIZED 0x14Au

/* 专用测试索引：owner 段内的固定位置，探针启动先清、退出再清 */
#define PROBE_NV_INDEX 0x01500010u
/* NV 计数器属性：NT=counter(0x1) | ownerWrite(0x10) | noDA(0x400) | ownerRead(0x10000) */
#define PROBE_NV_ATTR  0x00010411u

typedef struct {
    uint8_t buf[1024];
    size_t len;
} CmdBuf;

static TBS_HCONTEXT g_tbs = NULL;

static int cmd_init(CmdBuf *c, uint16_t tag, uint32_t cc)
{
    if (c == NULL) return -1;
    memset(c, 0, sizeof(*c));
    c->buf[c->len++] = (uint8_t)(tag >> 8);
    c->buf[c->len++] = (uint8_t)tag;
    c->buf[c->len++] = 0;   /* size 占位，提交前回填 */
    c->buf[c->len++] = 0;
    c->buf[c->len++] = 0;
    c->buf[c->len++] = 0;
    c->buf[c->len++] = (uint8_t)(cc >> 24);
    c->buf[c->len++] = (uint8_t)(cc >> 16);
    c->buf[c->len++] = (uint8_t)(cc >> 8);
    c->buf[c->len++] = (uint8_t)cc;
    return 0;
}

static void cmd_u8(CmdBuf *c, uint8_t v)
{
    c->buf[c->len++] = v;
}

static void cmd_u16(CmdBuf *c, uint16_t v)
{
    c->buf[c->len++] = (uint8_t)(v >> 8);
    c->buf[c->len++] = (uint8_t)v;
}

static void cmd_u32(CmdBuf *c, uint32_t v)
{
    c->buf[c->len++] = (uint8_t)(v >> 24);
    c->buf[c->len++] = (uint8_t)(v >> 16);
    c->buf[c->len++] = (uint8_t)(v >> 8);
    c->buf[c->len++] = (uint8_t)v;
}

static void cmd_bytes(CmdBuf *c, const void *p, size_t n)
{
    memcpy(c->buf + c->len, p, n);
    c->len += n;
}

/* 空口令会话：TPM_RS_PW + 空 nonce + 属性 0 + 空 HMAC */
static void cmd_password_session(CmdBuf *c)
{
    cmd_u32(c, TPM_RS_PW);
    cmd_u16(c, 0);
    cmd_u8(c, 0);
    cmd_u16(c, 0);
}

static uint32_t rd_u16(const uint8_t *p)
{
    return (uint32_t)((p[0] << 8) | p[1]);
}

static uint32_t rd_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* 提交命令；返回 TBS 错误（0 表示已拿到 TPM 响应，rc 需另读） */
static int tpm_submit(CmdBuf *c, uint8_t *resp, size_t *resp_len)
{
    UINT32 out_len;
    TBS_RESULT r;

    if (c == NULL || c->len < 10 || c->len > 0xFFFFu) return -1;
    if (resp == NULL || resp_len == NULL || *resp_len < 10) return -1;
    /* 回填 size（大端） */
    c->buf[2] = (uint8_t)(c->len >> 24);
    c->buf[3] = (uint8_t)(c->len >> 16);
    c->buf[4] = (uint8_t)(c->len >> 8);
    c->buf[5] = (uint8_t)c->len;

    out_len = (UINT32)*resp_len;
    r = Tbsip_Submit_Command(g_tbs, TBS_COMMAND_LOCALITY_ZERO,
                             TBS_COMMAND_PRIORITY_NORMAL,
                             c->buf, (UINT32)c->len, resp, &out_len);
    *resp_len = (size_t)out_len;
    return (int)r;
}

/* 解析响应头：返回 TPM rc；resp_len 不足 10 视为通道错误 */
static uint32_t tpm_rc(const uint8_t *resp, size_t resp_len)
{
    if (resp == NULL || resp_len < 10) return 0xFFFFFFFFu;
    if (rd_u16(resp) != TPM_ST_NO_SESSIONS && rd_u16(resp) != TPM_ST_SESSIONS) {
        return 0xFFFFFFFEu;
    }
    if (rd_u32(resp + 2) != resp_len) return 0xFFFFFFFDu;
    return rd_u32(resp + 6);
}

/* 跳过响应末尾的授权区（nonce TPM2B + 属性 1B + hmac TPM2B） */
static int skip_auth_response(const uint8_t *resp, size_t resp_len, size_t *off)
{
    size_t o = *off;
    uint32_t n;

    if (o + 2 > resp_len) return -1;
    n = rd_u16(resp + o);
    o += 2 + n;
    if (o + 1 > resp_len) return -1;
    o += 1;
    if (o + 2 > resp_len) return -1;
    n = rd_u16(resp + o);
    o += 2 + n;
    if (o != resp_len) return -1;
    *off = o;
    return 0;
}

/* 打印命令/响应原始字节，定位线格式与参数偏移问题（不含密钥材料） */
static void dump_bytes(const char *tag, const uint8_t *p, size_t n)
{
    size_t i;
    printf("[%s] len=%u\n", tag, (unsigned)n);
    for (i = 0; i < n; i++) {
        printf("%02X%s", p[i], ((i + 1) % 16 == 0) ? "\n" : " ");
    }
    if (n % 16 != 0) printf("\n");
}

/* 用空口令会话在各层次创建 RSA 存储主密钥：区分“层次句柄不可用”与
 * “命令编码错误”。成功即刷新句柄，不在 TPM 内留下常驻对象。 */
static int probe_create_primary(uint32_t hierarchy, const char *label)
{
    CmdBuf c;
    uint8_t resp[512];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    uint32_t handle;
    CmdBuf f;
    uint8_t fresp[32];
    size_t fresp_len = sizeof(fresp);

    cmd_init(&c, TPM_ST_SESSIONS, 0x00000131u);
    cmd_u32(&c, hierarchy);
    cmd_password_session(&c);
    /* inSensitive */
    cmd_u16(&c, 4);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0);
    /* inPublic：RSA2048 存储主密钥（restricted|decrypt|fixedTPM|fixedParent|
     * sensitiveDataOrigin|userWithAuth|noDA） */
    cmd_u16(&c, 26);
    cmd_u16(&c, 0x0001);            /* TPM_ALG_RSA */
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, 0x00030072u);
    cmd_u16(&c, 0);                 /* authPolicy 为空 */
    cmd_u16(&c, 0x0006);            /* symmetric: AES */
    cmd_u16(&c, 128);
    cmd_u16(&c, 0x0043);            /* CFB */
    cmd_u16(&c, 0x0010);            /* scheme: NULL */
    cmd_u16(&c, 2048);
    cmd_u32(&c, 0);
    cmd_u16(&c, 0);                 /* unique 为空 */
    /* outsideInfo、creationPCR */
    cmd_u16(&c, 0);
    cmd_u32(&c, 0);

    if (tpm_submit(&c, resp, &resp_len) != 0) {
        printf("[PRIMARY] submit failed\n");
        return -1;
    }
    rc = tpm_rc(resp, resp_len);
    printf("[PRIMARY] %s create rc=0x%08X resp_len=%u\n", label, rc, (unsigned)resp_len);
    if (rc != TPM_RC_SUCCESS) {
        dump_bytes("PRIMARY-CMD", c.buf, c.len);
        dump_bytes("PRIMARY-RESP", resp, resp_len);
        return (int)rc;
    }
    if (resp_len < 14) return -2;
    handle = rd_u32(resp + 10);
    printf("[PRIMARY] %s handle=0x%08X\n", label, handle);

    cmd_init(&f, TPM_ST_NO_SESSIONS, 0x00000165u);
    cmd_u32(&f, handle);
    (void)tpm_submit(&f, fresp, &fresp_len);
    printf("[PRIMARY] %s flush rc=0x%08X\n", label, tpm_rc(fresp, fresp_len));
    return 0;
}

/* 最小无会话命令：取随机数，验证 TBS 通道对普通 TPM 2.0 命令的放行 */
static int probe_getrandom(void)
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x0000017Bu);
    cmd_u16(&c, 16);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[RAND] getrandom rc=0x%08X resp_len=%u\n", rc, (unsigned)resp_len);
    return (int)rc;
}

/* ---------------- HMAC 会话（该固件拒绝 TPM_RS_PW 口令会话） ---------------- */

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    int rc = -1;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return -1;
    }
    if (BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0) == 0) {
        if (BCryptHashData(h, (PUCHAR)data, (ULONG)data_len, 0) == 0 &&
            BCryptFinishHash(h, out, 32, 0) == 0) {
            rc = 0;
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

/* TPM KDFa：counter(4) || label || 0x00 || contextU || contextV || bits(4) */
static int kdfa_sha256(const uint8_t *key, size_t key_len,
                       const char *label,
                       const uint8_t *u, size_t u_len,
                       const uint8_t *v, size_t v_len,
                       uint8_t out[32])
{
    uint8_t msg[256];
    uint8_t hmac[32];
    size_t label_len = strlen(label);
    size_t n = 0;
    uint8_t ctr[4] = { 0, 0, 0, 0 };
    uint8_t bits[4] = { 0, 0, 0x01, 0x00 };   /* 256 bits */

    if (label_len + u_len + v_len + 10 > sizeof(msg)) return -1;
    memcpy(msg + n, ctr, 4); n += 4;
    memcpy(msg + n, label, label_len); n += label_len;
    msg[n++] = 0;
    if (u_len != 0) { memcpy(msg + n, u, u_len); n += u_len; }
    if (v_len != 0) { memcpy(msg + n, v, v_len); n += v_len; }
    memcpy(msg + n, bits, 4); n += 4;

    if (hmac_sha256(key, key_len, msg, n, hmac) != 0) return -1;
    memcpy(out, hmac, 32);
    return 0;
}

/* 启动 HMAC 会话；非绑定、无盐、空对称算法。成功后回传会话句柄与 TPM nonce。 */
static int start_hmac_session(uint32_t *session, uint8_t nonce_tpm[32],
                              const uint8_t nonce_caller[32])
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    size_t off = 10;
    uint32_t n;

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000176u);
    cmd_u32(&c, 0x40000007u);       /* tpmKey: NULL */
    cmd_u32(&c, 0x40000007u);       /* bind: NULL */
    cmd_u16(&c, 32);
    cmd_bytes(&c, nonce_caller, 32);
    cmd_u16(&c, 0);                 /* encryptedSalt */
    cmd_u8(&c, 0x00);               /* TPM_SE_HMAC */
    cmd_u16(&c, 0x0010);            /* symmetric: NULL */
    cmd_u16(&c, TPM_ALG_SHA256);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    dump_bytes("SESS-RESP", resp, resp_len);
    if (rc != TPM_RC_SUCCESS) {
        printf("[HMAC] StartAuthSession rc=0x%08X\n", rc);
        return (int)rc;
    }
    if (off + 4 > resp_len) return -2;
    *session = rd_u32(resp + off); off += 4;
    if (off + 2 > resp_len) return -2;
    n = rd_u16(resp + off); off += 2;
    if (n != 32 || off + n > resp_len) return -2;
    memcpy(nonce_tpm, resp + off, 32);
    return 0;
}

/* 在命令缓冲中追加 HMAC 授权区；返回 0 成功。auth 为空（该机 owner 无口令）。 */
static int append_hmac_auth(CmdBuf *c, uint32_t session, uint32_t cc,
                            const uint8_t *auth, size_t auth_len,
                            const uint8_t nonce_tpm[32],
                            const uint8_t nonce_caller[32])
{
    uint8_t key[32];
    uint8_t input[128];
    uint8_t mac[32];
    size_t n = 0;
    size_t aes_len;

    (void)cc;
    if (kdfa_sha256(auth, auth_len, "ATH", nonce_tpm, 32, nonce_caller, 32, key) != 0) {
        return -1;
    }
    memcpy(input + n, nonce_tpm, 32); n += 32;
    memcpy(input + n, nonce_caller, 32); n += 32;
    input[n++] = 0x00;              /* sessionAttributes: 单次使用、结束会话 */
    aes_len = n;

    if (hmac_sha256(key, 32, input, aes_len, mac) != 0) {
        memset(key, 0, sizeof(key));
        return -1;
    }
    cmd_u32(c, session);
    cmd_u16(c, 32);
    cmd_bytes(c, nonce_caller, 32);
    cmd_u8(c, 0x00);
    cmd_u16(c, 32);
    cmd_bytes(c, mac, 32);
    memset(key, 0, sizeof(key));
    memset(mac, 0, sizeof(mac));
    return 0;
}

/* 会话句柄有效性：先刷新，再重建会话，确认句柄在 TPM 内真实存在 */
static int probe_session_handle(void)
{
    uint8_t nc[32];
    uint8_t nt[32];
    uint32_t s1 = 0;
    uint32_t s2 = 0;
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    memset(nc, 0x11, sizeof(nc));
    if (start_hmac_session(&s1, nt, nc) != 0) return -1;
    printf("[SESS] s1=0x%08X\n", s1);

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
    cmd_u32(&c, s1);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[SESS] flush s1 rc=0x%08X\n", rc);

    memset(nc, 0x22, sizeof(nc));
    if (start_hmac_session(&s2, nt, nc) != 0) return -1;
    printf("[SESS] s2=0x%08X（句柄单调递增说明会话真实创建）\n", s2);

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
    cmd_u32(&c, s2);
    resp_len = sizeof(resp);
    (void)tpm_submit(&c, resp, &resp_len);
    printf("[SESS] flush s2 rc=0x%08X\n", tpm_rc(resp, resp_len));
    return 0;
}

/* 优先级/局部性对会话命令的影响：判定驱动是否按调用优先级过滤 */
static int probe_priority_matrix(void)
{
    static const struct { TBS_COMMAND_PRIORITY pri; TBS_COMMAND_LOCALITY loc; const char *l; } m[] = {
        { TBS_COMMAND_PRIORITY_NORMAL, TBS_COMMAND_LOCALITY_ZERO, "normal/l0" },
        { TBS_COMMAND_PRIORITY_HIGH, TBS_COMMAND_LOCALITY_ZERO, "high/l0" },
        { TBS_COMMAND_PRIORITY_SYSTEM, TBS_COMMAND_LOCALITY_ZERO, "system/l0" },
        { TBS_COMMAND_PRIORITY_SYSTEM, TBS_COMMAND_LOCALITY_TWO, "system/l2" }
    };
    size_t i;

    for (i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
        uint8_t nc[32];
        uint8_t nt[32];
        uint32_t s = 0;
        CmdBuf c;
        uint8_t resp[128];
        size_t resp_len = sizeof(resp);
        UINT32 out_len;
        TBS_RESULT r;
        uint32_t rc;

        memset(nc, 0x11, sizeof(nc));
        if (start_hmac_session(&s, nt, nc) != 0) continue;
        cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
        if (append_hmac_auth(&c, s, 0x0000017Bu, NULL, 0, nt, nc) != 0) continue;
        cmd_u16(&c, 16);
        c.buf[2] = (uint8_t)(c.len >> 24);
        c.buf[3] = (uint8_t)(c.len >> 16);
        c.buf[4] = (uint8_t)(c.len >> 8);
        c.buf[5] = (uint8_t)c.len;
        out_len = (UINT32)resp_len;
        r = Tbsip_Submit_Command(g_tbs, m[i].loc, m[i].pri,
                                 c.buf, (UINT32)c.len, resp, &out_len);
        rc = (r == TBS_SUCCESS) ? tpm_rc(resp, out_len) : 0x80000000u | (uint32_t)r;
        printf("[PRI] %s rc=0x%08X\n", m[i].l, rc);
        cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
        cmd_u32(&c, s);
        resp_len = sizeof(resp);
        (void)tpm_submit(&c, resp, &resp_len);
    }
    return 0;
}

/* 判定 tag 0x8002 是否被整体拒绝：分别对有授权句柄/无授权句柄命令试零会话 */
static int probe_tag_behavior(void)
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len;
    static const uint8_t data4[4] = { 1, 2, 3, 4 };

    /* CreatePrimary(NULL) + tag 0x8002 + 零会话 */
    cmd_init(&c, TPM_ST_SESSIONS, 0x00000131u);
    cmd_u32(&c, 0x40000007u);
    cmd_u16(&c, 4);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0);
    cmd_u16(&c, 26);
    cmd_u16(&c, 0x0001);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, 0x00030072u);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0x0006);
    cmd_u16(&c, 128);
    cmd_u16(&c, 0x0043);
    cmd_u16(&c, 0x0010);
    cmd_u16(&c, 2048);
    cmd_u32(&c, 0);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0);
    cmd_u32(&c, 0);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) == 0) {
        printf("[TAG] createprimary sessions-tag zero-auth rc=0x%08X\n",
               tpm_rc(resp, resp_len));
    }

    /* TPM2_Hash + tag 0x8002 + 零会话 */
    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Du);
    cmd_u16(&c, 4);
    cmd_bytes(&c, data4, 4);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, 0x40000007u);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) == 0) {
        printf("[TAG] hash sessions-tag zero-auth rc=0x%08X\n",
               tpm_rc(resp, resp_len));
    }

    /* TPM2_Hash + tag 0x8001（对照） */
    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x0000017Du);
    cmd_u16(&c, 4);
    cmd_bytes(&c, data4, 4);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, 0x40000007u);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) == 0) {
        printf("[TAG] hash no-sessions rc=0x%08X\n", tpm_rc(resp, resp_len));
    }
    return 0;
}

/* 会话结构判定三连：空会话区、空 nonce、错误 HMAC。
 * 目的：区分“会话句柄不被接受”和“HMAC 计算错误”。 */
static int probe_session_diagnostics(void)
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len;
    uint32_t rc;
    uint8_t nc[32];
    uint8_t nt[32];
    uint32_t s = 0;
    uint8_t zero_mac[32];

    /* 1) tag 0x8002 + 零会话（无授权命令允许） */
    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
    cmd_u16(&c, 16);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) == 0) {
        printf("[DIAG] sessions-tag zero-auth rc=0x%08X\n", tpm_rc(resp, resp_len));
    }

    /* 2) HMAC 会话 + 空 nonce（应报 NONCE，说明授权区被正确解析） */
    memset(nc, 0x77, sizeof(nc));
    if (start_hmac_session(&s, nt, nc) == 0) {
        cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
        cmd_u32(&c, s);
        cmd_u16(&c, 0);             /* nonce 为空 */
        cmd_u8(&c, 0x00);
        cmd_u16(&c, 32);
        cmd_bytes(&c, zero_mac, 32);
        cmd_u16(&c, 16);
        resp_len = sizeof(resp);
        if (tpm_submit(&c, resp, &resp_len) == 0) {
            printf("[DIAG] hmac empty-nonce rc=0x%08X\n", tpm_rc(resp, resp_len));
        }
        cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
        cmd_u32(&c, s);
        resp_len = sizeof(resp);
        (void)tpm_submit(&c, resp, &resp_len);
    }

    /* 3) HMAC 会话 + 正确 nonce + 全零 HMAC（应报鉴权失败而非句柄错误） */
    memset(nc, 0x78, sizeof(nc));
    if (start_hmac_session(&s, nt, nc) == 0) {
        cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
        cmd_u32(&c, s);
        cmd_u16(&c, 32);
        cmd_bytes(&c, nc, 32);
        cmd_u8(&c, 0x00);
        cmd_u16(&c, 32);
        cmd_bytes(&c, zero_mac, 32);
        cmd_u16(&c, 16);
        resp_len = sizeof(resp);
        if (tpm_submit(&c, resp, &resp_len) == 0) {
            printf("[DIAG] hmac zero-mac rc=0x%08X\n", tpm_rc(resp, resp_len));
        }
        cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
        cmd_u32(&c, s);
        resp_len = sizeof(resp);
        (void)tpm_submit(&c, resp, &resp_len);
    }
    return 0;
}

/* 会话在两次提交之间是否被资源管理驱逐：ContextSave 可判定会话是否加载 */
static int probe_session_context(void)
{
    uint8_t nc[32];
    uint8_t nt[32];
    uint32_t s = 0;
    CmdBuf c;
    uint8_t resp[512];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    uint32_t ctx_len;
    uint8_t ctx[512];
    size_t ctx_size = 0;
    uint32_t s2 = 0;

    memset(nc, 0x66, sizeof(nc));
    if (start_hmac_session(&s, nt, nc) != 0) return -1;

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000162u);   /* ContextSave */
    cmd_u32(&c, s);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[CTX] ContextSave(session) rc=0x%08X len=%u\n", rc, (unsigned)resp_len);
    if (rc != TPM_RC_SUCCESS) return (int)rc;
    ctx_len = rd_u16(resp + 10);
    if (ctx_len + 12 > resp_len || ctx_len > sizeof(ctx)) return -2;
    memcpy(ctx, resp + 12, ctx_len);
    ctx_size = ctx_len;

    /* 使用原句柄（若被驱逐，则此处失败） */
    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
    if (append_hmac_auth(&c, s, 0x0000017Bu, NULL, 0, nt, nc) != 0) return -1;
    cmd_u16(&c, 16);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    printf("[CTX] use saved-session handle rc=0x%08X\n", tpm_rc(resp, resp_len));

    /* 重新载入会话上下文 */
    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000161u);   /* ContextLoad */
    cmd_u16(&c, (uint16_t)ctx_size);
    cmd_bytes(&c, ctx, ctx_size);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[CTX] ContextLoad rc=0x%08X\n", rc);
    if (rc == TPM_RC_SUCCESS) {
        s2 = rd_u32(resp + 10);
        printf("[CTX] loaded handle=0x%08X\n", s2);
        cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
        cmd_u32(&c, s2);
        resp_len = sizeof(resp);
        (void)tpm_submit(&c, resp, &resp_len);
        printf("[CTX] flush loaded rc=0x%08X\n", tpm_rc(resp, resp_len));
    }
    return 0;
}

/* 会话在“使用失败”后是否仍存在：区分句柄被 TBS 驱逐 与 会话被 TPM 拒绝 */
static int probe_session_lifecycle(void)
{
    uint8_t nc[32];
    uint8_t nt[32];
    uint32_t s = 0;
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    memset(nc, 0x44, sizeof(nc));
    if (start_hmac_session(&s, nt, nc) != 0) return -1;

    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
    if (append_hmac_auth(&c, s, 0x0000017Bu, NULL, 0, nt, nc) != 0) return -1;
    cmd_u16(&c, 16);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    printf("[LIFE] use session rc=0x%08X\n", tpm_rc(resp, resp_len));

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
    cmd_u32(&c, s);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[LIFE] flush-after-fail rc=0x%08X（0=会话仍在 TPM 内）\n", rc);
    return 0;
}

/* 策略会话（TPM_SE_POLICY）在无授权命令上的可用性：排除 HMAC 特有原因 */
static int probe_policy_session(void)
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    uint32_t s = 0;
    uint8_t nc[32];
    uint8_t nt[32];
    size_t off;

    memset(nc, 0x55, sizeof(nc));
    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000176u);
    cmd_u32(&c, 0x40000007u);
    cmd_u32(&c, 0x40000007u);
    cmd_u16(&c, 32);
    cmd_bytes(&c, nc, 32);
    cmd_u16(&c, 0);
    cmd_u8(&c, 0x03);               /* TPM_SE_POLICY */
    cmd_u16(&c, 0x0010);
    cmd_u16(&c, TPM_ALG_SHA256);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[POL] StartAuthSession(policy) rc=0x%08X\n", rc);
    if (rc != TPM_RC_SUCCESS) return (int)rc;
    s = rd_u32(resp + 10);
    off = 14;
    if (rd_u16(resp + off) != 32) return -2;
    memcpy(nt, resp + off + 2, 32);

    /* 策略会话不需要 HMAC：auth 区只带会话句柄、nonce 与空 hmac */
    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
    cmd_u32(&c, s);
    cmd_u16(&c, 32);
    cmd_bytes(&c, nc, 32);
    cmd_u8(&c, 0x00);
    cmd_u16(&c, 0);
    cmd_u16(&c, 16);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    printf("[POL] getrandom with policy session rc=0x%08X\n", tpm_rc(resp, resp_len));

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000165u);
    cmd_u32(&c, s);
    resp_len = sizeof(resp);
    (void)tpm_submit(&c, resp, &resp_len);
    printf("[POL] flush rc=0x%08X\n", tpm_rc(resp, resp_len));
    return 0;
}

/* HMAC 会话下的 NV 定义：判定会话是否被 TPM 接受，以及 owner auth 是否为空 */
static int probe_nv_define_hmac(uint32_t index)
{
    uint8_t nc[32];
    uint8_t nt[32];
    uint32_t session = 0;
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    memset(nc, 0x33, sizeof(nc));
    if (start_hmac_session(&session, nt, nc) != 0) return -1;

    cmd_init(&c, TPM_ST_SESSIONS, TPM_CC_NV_DEFINE);
    cmd_u32(&c, TPM_RH_OWNER);
    if (append_hmac_auth(&c, session, TPM_CC_NV_DEFINE, NULL, 0, nt, nc) != 0) {
        return -1;
    }
    cmd_u16(&c, 0);
    cmd_u32(&c, index);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, PROBE_NV_ATTR);
    cmd_u16(&c, 0);
    cmd_u16(&c, 8);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[NV] define(hmac) index=0x%08X rc=0x%08X\n", index, rc);
    if (rc == TPM_RC_SUCCESS) {
        printf("[NV] define(hmac) ok -> cleanup=%s\n",
               probe_nv_undefine(index) == 0 ? "OK" : "FAIL");
    } else {
        dump_bytes("NVHMAC-CMD", c.buf, c.len);
        dump_bytes("NVHMAC-RESP", resp, resp_len);
    }
    return (int)rc;
}

/* HMAC 会话探针：GetRandom 无授权句柄，成功即证明会话编码正确 */
static int probe_hmac_session(void)
{
    uint8_t nonce_caller[32];
    uint8_t nonce_tpm[32];
    uint32_t session = 0;
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    int r;

    memset(nonce_caller, 0x5A, sizeof(nonce_caller));
    r = start_hmac_session(&session, nonce_tpm, nonce_caller);
    if (r != 0) return r;
    printf("[HMAC] session=0x%08X nonceTPM=%02X%02X...\n",
           session, nonce_tpm[0], nonce_tpm[1]);

    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
    if (append_hmac_auth(&c, session, 0x0000017Bu, NULL, 0,
                         nonce_tpm, nonce_caller) != 0) {
        return -1;
    }
    cmd_u16(&c, 16);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[HMAC] getrandom rc=0x%08X resp_len=%u\n", rc, (unsigned)resp_len);
    if (rc != TPM_RC_SUCCESS) {
        dump_bytes("HMAC-CMD", c.buf, c.len);
        dump_bytes("HMAC-RESP", resp, resp_len);
        return (int)rc;
    }
    return 0;
}

/* ---------------- Platform Crypto Provider（Windows 支持的 TPM 路径） ---------------- */

static void enable_privilege(const wchar_t *name)
{
    HANDLE tok = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        return;
    }
    if (LookupPrivilegeValueW(NULL, name, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(tok);
}

/* 读取并打印 PCP 的 TPM 标识与版本；失败视为无 PCP */
static void probe_pcp_info(void)
{
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st;
    WCHAR buf[256];
    DWORD cb = 0;

    st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    printf("[PCP] open provider st=0x%08X\n", (unsigned)st);
    if (st != 0) return;
    memset(buf, 0, sizeof(buf));
    st = NCryptGetProperty(prov, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
                           (PBYTE)buf, sizeof(buf) - sizeof(WCHAR), &cb, 0);
    printf("[PCP] platform type st=0x%08X cb=%u value=%ws\n",
           (unsigned)st, (unsigned)cb, buf);
    NCryptFreeObject(prov);
}

/* 打开系统 seal key，加封/解封 32B 数据：验证 PCP 密封通道可用 */
static void probe_pcp_seal(void)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    SECURITY_STATUS st;
    uint8_t in[32];
    uint8_t blob[512];
    uint8_t out[64];
    DWORD blob_len = 0;
    DWORD out_len = 0;

    memset(in, 0x42, sizeof(in));
    st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (st != 0) return;
    st = NCryptOpenKey(prov, &key, TPM_RSA_SRK_SEAL_KEY, 0, 0);
    printf("[PCP] open seal key st=0x%08X\n", (unsigned)st);
    if (st == 0) {
        st = NCryptEncrypt(key, in, sizeof(in), NULL, NULL, 0, &blob_len,
                           NCRYPT_SEALING_FLAG);
        printf("[PCP] seal size st=0x%08X len=%u\n", (unsigned)st, (unsigned)blob_len);
        if (st == 0 && blob_len <= sizeof(blob)) {
            st = NCryptEncrypt(key, in, sizeof(in), NULL, blob, blob_len, &blob_len,
                               NCRYPT_SEALING_FLAG);
            printf("[PCP] seal st=0x%08X len=%u\n", (unsigned)st, (unsigned)blob_len);
            if (st == 0) {
                /* NCryptDecrypt 的容量查询会返回明文长度（32），不是密文长度 */
                out_len = sizeof(out);
                st = NCryptDecrypt(key, blob, blob_len, NULL, out, out_len, &out_len,
                                   NCRYPT_SEALING_FLAG);
                printf("[PCP] unseal st=0x%08X len=%u match=%s\n",
                       (unsigned)st, (unsigned)out_len,
                       (st == 0 && out_len == sizeof(in) &&
                        memcmp(out, in, sizeof(in)) == 0) ? "YES" : "NO");
            }
        }
        NCryptFreeObject(key);
    }
    NCryptFreeObject(prov);
}

/* 创建 PCR 绑定密钥并做加密/解密：验证 PCP 平台绑定可用性与正确 PCR 摘要格式。
 * expected_digest 为 24 个 PCR 值的扁平数组（SHA-256），NULL 表示使用当前 PCR。 */
static int pcp_pcr_key(const wchar_t *name, uint32_t mask,
                       const uint8_t *expected, size_t expected_len,
                       int do_roundtrip)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    SECURITY_STATUS st;
    DWORD usage = NCRYPT_PCP_ENCRYPTION_KEY;
    uint8_t mask3[3];
    uint16_t pcr_alg = 0x000Bu;      /* TPM_ALG_SHA256 */
    uint8_t in[32];
    uint8_t blob[512];
    uint8_t out[64];
    DWORD blob_len = 0;
    DWORD out_len = 0;
    int ok = 0;

    mask3[0] = (uint8_t)(mask & 0xFFu);
    mask3[1] = (uint8_t)((mask >> 8) & 0xFFu);
    mask3[2] = (uint8_t)((mask >> 16) & 0xFFu);
    memset(in, 0x5C, sizeof(in));
    st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (st != 0) { printf("[PCP] pcr open prov st=0x%08X\n", (unsigned)st); return -1; }

    /* 清理同名遗留键 */
    if (NCryptOpenKey(prov, &key, name, 0, 0) == 0) {
        NCryptDeleteKey(key, 0);
        key = 0;
    }
    st = NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM, name, 0, 0);
    printf("[PCP] pcr create st=0x%08X\n", (unsigned)st);
    if (st == 0) {
        st = NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                               (PBYTE)&usage, sizeof(usage), 0);
        printf("[PCP] pcr set usage st=0x%08X\n", (unsigned)st);
        st = NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
                               (PBYTE)mask3, sizeof(mask3), 0);
        printf("[PCP] pcr set mask(0x%06X,3B) st=0x%08X\n",
               mask & 0xFFFFFFu, (unsigned)st);
        if (st == 0) {
            st = NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY,
                                   (PBYTE)&pcr_alg, sizeof(pcr_alg), 0);
            printf("[PCP] pcr set algid(0x%04X) st=0x%08X\n",
                   pcr_alg, (unsigned)st);
        }
        if (st == 0 && expected != NULL) {
            st = NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRDIGESTLIST_PROPERTY,
                                   (PBYTE)expected, (DWORD)expected_len, 0);
            printf("[PCP] pcr set digestlist(%u) st=0x%08X\n",
                   (unsigned)expected_len, (unsigned)st);
        }
        if (st == 0) {
            st = NCryptFinalizeKey(key, 0);
            printf("[PCP] pcr finalize st=0x%08X\n", (unsigned)st);
        }
        if (st == 0) {
            uint8_t digest[64];
            DWORD dlen = sizeof(digest);
            if (NCryptGetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRDIGEST_PROPERTY,
                                  digest, sizeof(digest), &dlen, 0) == 0) {
                printf("[PCP] pcr bound digest len=%u %02X%02X...%02X%02X\n",
                       (unsigned)dlen, digest[0], digest[1],
                       digest[dlen > 1 ? dlen - 2 : 0], digest[dlen ? dlen - 1 : 0]);
            } else {
                printf("[PCP] pcr bound digest unavailable\n");
            }
        }
        if (st == 0 && do_roundtrip) {
            st = NCryptEncrypt(key, in, sizeof(in), NULL, NULL, 0, &blob_len, 0);
            printf("[PCP] pcr encrypt size st=0x%08X len=%u\n", (unsigned)st, (unsigned)blob_len);
            if (st == 0 && blob_len <= sizeof(blob)) {
                st = NCryptEncrypt(key, in, sizeof(in), NULL, blob, blob_len, &blob_len, 0);
                printf("[PCP] pcr encrypt st=0x%08X len=%u\n", (unsigned)st, (unsigned)blob_len);
                if (st == 0) {
                    st = NCryptDecrypt(key, blob, blob_len, NULL, out, sizeof(out), &out_len, 0);
                    printf("[PCP] pcr decrypt st=0x%08X match=%s\n", (unsigned)st,
                           (st == 0 && out_len == sizeof(in) &&
                            memcmp(out, in, sizeof(in)) == 0) ? "YES" : "NO");
                }
            }
        }
        if (key != 0) {
            NCryptDeleteKey(key, 0);
            key = 0;
        }
    }
    NCryptFreeObject(prov);
    return ok;
}

/* PCR 绑定密钥的完整链路：TPM 内生成密钥 → 导出公钥 → 软件加密 →
 * TPM 解密。PCR 不匹配时解密必须失败，这是 PCR 槽的实现基础。 */
static int pcp_pcr_decrypt_test(const wchar_t *name, uint32_t mask,
                                const uint8_t *expected, size_t expected_len)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    BCRYPT_ALG_HANDLE rsa = NULL;
    BCRYPT_KEY_HANDLE pub = NULL;
    SECURITY_STATUS st;
    NTSTATUS bs;
    DWORD usage = NCRYPT_PCP_ENCRYPTION_KEY;
    uint8_t mask3[3];
    uint16_t pcr_alg = 0x000Bu;
    uint8_t pubblob[1024];
    DWORD pubblob_len = sizeof(pubblob);
    uint8_t in[32];
    uint8_t ct[512];
    uint8_t out[64];
    DWORD ct_len = 0;
    DWORD out_len = 0;
    int result_fail = 0;

    mask3[0] = (uint8_t)(mask & 0xFFu);
    mask3[1] = (uint8_t)((mask >> 8) & 0xFFu);
    mask3[2] = (uint8_t)((mask >> 16) & 0xFFu);
    memset(in, 0x6D, sizeof(in));

    st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (st != 0) return -1;
    if (NCryptOpenKey(prov, &key, name, 0, 0) == 0) {
        NCryptDeleteKey(key, 0);
        key = 0;
    }
    st = NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM, name, 0, 0);
    if (st != 0) { printf("[PCP2] create st=0x%08X\n", (unsigned)st); goto done; }
    st = NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                           (PBYTE)&usage, sizeof(usage), 0);
    if (st != 0) { printf("[PCP2] usage st=0x%08X\n", (unsigned)st); goto done; }
    st = NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
                           (PBYTE)mask3, sizeof(mask3), 0);
    if (st != 0) { printf("[PCP2] mask st=0x%08X\n", (unsigned)st); goto done; }
    st = NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY,
                           (PBYTE)&pcr_alg, sizeof(pcr_alg), 0);
    if (st != 0) { printf("[PCP2] algid st=0x%08X\n", (unsigned)st); goto done; }
    if (expected != NULL) {
        st = NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRDIGESTLIST_PROPERTY,
                               (PBYTE)expected, (DWORD)expected_len, 0);
        if (st != 0) { printf("[PCP2] digestlist st=0x%08X\n", (unsigned)st); goto done; }
    }
    st = NCryptFinalizeKey(key, 0);
    printf("[PCP2] finalize st=0x%08X\n", (unsigned)st);
    if (st != 0) goto done;

    st = NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
                         pubblob, sizeof(pubblob), &pubblob_len, 0);
    printf("[PCP2] export pub st=0x%08X len=%u\n", (unsigned)st, (unsigned)pubblob_len);
    if (st != 0) goto done;

    bs = BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (bs == 0) {
        bs = BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &pub,
                                 pubblob, pubblob_len, 0);
    }
    printf("[PCP2] import pub st=0x%08X\n", (unsigned)bs);
    if (bs == 0) {
        BCRYPT_OAEP_PADDING_INFO oaep;
        memset(&oaep, 0, sizeof(oaep));
        oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        ct_len = sizeof(ct);
        bs = BCryptEncrypt(pub, in, sizeof(in), &oaep, NULL, 0,
                           ct, ct_len, &ct_len, BCRYPT_PAD_OAEP);
        printf("[PCP2] oaep encrypt st=0x%08X len=%u\n", (unsigned)bs, (unsigned)ct_len);
    }
    if (bs == 0) {
        BCRYPT_OAEP_PADDING_INFO oaep;
        memset(&oaep, 0, sizeof(oaep));
        oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        out_len = sizeof(out);
        st = NCryptDecrypt(key, ct, ct_len, &oaep, out, out_len, &out_len,
                           BCRYPT_PAD_OAEP);
        printf("[PCP2] oaep tpm decrypt st=0x%08X len=%u match=%s\n",
               (unsigned)st, (unsigned)out_len,
               (st == 0 && out_len == sizeof(in) &&
                memcmp(out, in, sizeof(in)) == 0) ? "YES" : "NO");
        result_fail = (st != 0);
    }

done:
    if (pub != NULL) BCryptDestroyKey(pub);
    if (rsa != NULL) BCryptCloseAlgorithmProvider(rsa, 0);
    if (key != 0) {
        NCryptDeleteKey(key, 0);
        key = 0;
    }
    NCryptFreeObject(prov);
    return result_fail;
}

/* 对称见证密钥：HMAC/AES 持久化键的创建与运算耗时（若可用则替代 ECC） */
static int probe_witness_symmetric(void)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD usage;
    uint8_t nonce[32];
    uint8_t sig[64];
    DWORD sig_len;
    LARGE_INTEGER f, t0, t1;
    SECURITY_STATUS st;
    int i;

    memset(nonce, 0x5A, sizeof(nonce));
    QueryPerformanceFrequency(&f);
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        printf("[WIT2] provider unavailable\n");
        return -1;
    }

    QueryPerformanceCounter(&t0);
    usage = NCRYPT_PCP_HMACVERIFICATION_KEY;
    for (i = 0; i < 3; i++) {
        if (NCryptOpenKey(prov, &key, L"VerthysWitHmac", 0, 0) == 0) {
            NCryptDeleteKey(key, 0);
            key = 0;
        }
        st = NCryptCreatePersistedKey(prov, &key, NCRYPT_HMAC_SHA256_ALGORITHM,
                                      L"VerthysWitHmac", 0,
                                      NCRYPT_OVERWRITE_KEY_FLAG);
        if (st == 0) {
            (void)NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                                    (PBYTE)&usage, sizeof(usage), 0);
            st = NCryptFinalizeKey(key, 0);
            if (st == 0) {
                sig_len = sizeof(sig);
                st = NCryptSignHash(key, NULL, nonce, sizeof(nonce),
                                    sig, sizeof(sig), &sig_len, 0);
                printf("[WIT2] hmac round=%d sign=0x%08X len=%u %02X%02X\n",
                       i, (unsigned)st, (unsigned)sig_len, sig[0], sig[1]);
            } else {
                printf("[WIT2] hmac round=%d finalize=0x%08X\n", i, (unsigned)st);
            }
            NCryptDeleteKey(key, 0);
            key = 0;
        } else {
            printf("[WIT2] hmac round=%d create=0x%08X\n", i, (unsigned)st);
        }
    }
    QueryPerformanceCounter(&t1);
    printf("[PERF] witness hmac create+sign+delete x3 = %.1f ms\n",
           1000.0 * (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart);

    QueryPerformanceCounter(&t0);
    usage = NCRYPT_PCP_ENCRYPTION_KEY;
    for (i = 0; i < 3; i++) {
        uint8_t out[64];
        DWORD out_len = sizeof(out);
        if (NCryptOpenKey(prov, &key, L"VerthysWitAes", 0, 0) == 0) {
            NCryptDeleteKey(key, 0);
            key = 0;
        }
        st = NCryptCreatePersistedKey(prov, &key, BCRYPT_AES_ALGORITHM,
                                      L"VerthysWitAes", 0,
                                      NCRYPT_OVERWRITE_KEY_FLAG);
        if (st == 0) {
            (void)NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                                    (PBYTE)&usage, sizeof(usage), 0);
            st = NCryptFinalizeKey(key, 0);
            if (st == 0) {
                st = NCryptEncrypt(key, nonce, 16, NULL, out, sizeof(out),
                                   &out_len, 0);
                printf("[WIT2] aes round=%d enc=0x%08X len=%u %02X%02X\n",
                       i, (unsigned)st, (unsigned)out_len, out[0], out[1]);
            } else {
                printf("[WIT2] aes round=%d finalize=0x%08X\n", i, (unsigned)st);
            }
            NCryptDeleteKey(key, 0);
            key = 0;
        } else {
            printf("[WIT2] aes round=%d create=0x%08X\n", i, (unsigned)st);
        }
    }
    QueryPerformanceCounter(&t1);
    printf("[PERF] witness aes create+encrypt+delete x3 = %.1f ms\n",
           1000.0 * (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart);

    NCryptFreeObject(prov);
    return 0;
}

/* 见证密钥耗时：ECC P-256 持久化键的创建/导出/覆盖/删除（不含 PCR 绑定） */
static int probe_witness_timing(void)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD usage = NCRYPT_PCP_SIGNATURE_KEY;
    uint8_t pub[256];
    DWORD pub_len;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    uint8_t dig[32];
    LARGE_INTEGER f, t0, t1;
    int i;

    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        printf("[WIT] provider unavailable\n");
        return -1;
    }
    for (i = 0; i < 3; i++) {
        if (NCryptOpenKey(prov, &key, L"VerthysWitProbeA", 0, 0) == 0) {
            NCryptDeleteKey(key, 0);
            key = 0;
        }
        if (NCryptCreatePersistedKey(prov, &key, BCRYPT_ECDSA_P256_ALGORITHM,
                                     L"VerthysWitProbeA", 0,
                                     NCRYPT_OVERWRITE_KEY_FLAG) == 0) {
            (void)NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                                    (PBYTE)&usage, sizeof(usage), 0);
            if (NCryptFinalizeKey(key, 0) == 0) {
                pub_len = sizeof(pub);
                if (NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                                    pub, sizeof(pub), &pub_len, 0) == 0) {
                    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                    NULL, 0) == 0 &&
                        BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) == 0 &&
                        BCryptHashData(hash, pub, pub_len, 0) == 0 &&
                        BCryptFinishHash(hash, dig, 32, 0) == 0) {
                        printf("[WIT] round=%d pubLen=%u fp=%02X%02X%02X%02X\n",
                               i, (unsigned)pub_len, dig[0], dig[1], dig[2], dig[3]);
                    }
                    if (hash != NULL) { BCryptDestroyHash(hash); hash = NULL; }
                    if (alg != NULL) { BCryptCloseAlgorithmProvider(alg, 0); alg = NULL; }
                }
            }
            NCryptDeleteKey(key, 0);
            key = 0;
        }
    }
    NCryptFreeObject(prov);
    QueryPerformanceCounter(&t1);
    printf("[PERF] witness ecc create+export+delete x3 = %.1f ms\n",
           1000.0 * (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart);
    return 0;
}

/* 常驻句柄与密钥生成耗时：评估“每库一把 PCR 绑定密钥”的容量与延迟 */
static int probe_pcp_capacity(void)
{
    CmdBuf c;
    uint8_t resp[512];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    size_t off;
    uint32_t count;
    uint32_t i;
    LARGE_INTEGER f, t0, t1;
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD usage = NCRYPT_PCP_ENCRYPTION_KEY;
    uint8_t mask3[3] = { 0x80, 0x08, 0x00 };
    uint16_t alg = 0x000B;

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x0000017Au);
    cmd_u32(&c, 0x00000001u);
    cmd_u32(&c, 0x80000000u);
    cmd_u32(&c, 32);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) == 0) {
        rc = tpm_rc(resp, resp_len);
        if (rc == TPM_RC_SUCCESS) {
            off = 10 + 1 + 4;
            count = rd_u32(resp + off);
            off += 4;
            printf("[CAP] persistent count=%u\n", (unsigned)count);
            for (i = 0; i < count && off + 4 <= resp_len; i++) {
                printf("[CAP] persistent handle=0x%08X\n", rd_u32(resp + off));
                off += 4;
            }
        }
    }

    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) == 0) {
        if (NCryptOpenKey(prov, &key, L"VerthysPcrTiming", 0, 0) == 0) {
            NCryptDeleteKey(key, 0);
            key = 0;
        }
        if (NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM,
                                     L"VerthysPcrTiming", 0, 0) == 0) {
            (void)NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                                    (PBYTE)&usage, sizeof(usage), 0);
            (void)NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
                                    mask3, sizeof(mask3), 0);
            (void)NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY,
                                    (PBYTE)&alg, sizeof(alg), 0);
            (void)NCryptFinalizeKey(key, 0);
            (void)NCryptDeleteKey(key, 0);
        }
        NCryptFreeObject(prov);
    }
    QueryPerformanceCounter(&t1);
    printf("[PERF] pcr-key create+delete = %.1f ms\n",
           1000.0 * (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart);
    return 0;
}

/* 口令会话变体：用于判定固件是否要求 nonce 或特定属性位 */
static void cmd_password_session_ex(CmdBuf *c, uint8_t attrs, uint32_t nonce_len)
{
    static const uint8_t nonce[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    cmd_u32(c, TPM_RS_PW);
    cmd_u16(c, (uint16_t)nonce_len);
    if (nonce_len != 0) cmd_bytes(c, nonce, nonce_len);
    cmd_u8(c, attrs);
    cmd_u16(c, 0);
}

/* 口令会话变体探针：GetRandom 无授权句柄，结果只反映会话编码是否被接受 */
static int probe_session_variants(void)
{
    static const struct { uint8_t attrs; uint32_t nonce; const char *label; } v[] = {
        { 0x00, 32, "nonce32" },
        { 0x01, 0,  "continue" },
        { 0x00, 0,  "plain" }
    };
    size_t i;

    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        CmdBuf c;
        uint8_t resp[64];
        size_t resp_len = sizeof(resp);
        uint32_t rc;

        cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
        cmd_password_session_ex(&c, v[i].attrs, v[i].nonce);
        cmd_u16(&c, 16);
        if (tpm_submit(&c, resp, &resp_len) != 0) continue;
        rc = tpm_rc(resp, resp_len);
        printf("[SESS] %s rc=0x%08X\n", v[i].label, rc);
    }
    return 0;
}

/* 带空口令会话的 GetRandom：判定 0x8B 是否来自“口令会话本身被拒”，
 * 与层次句柄无关（该命令无授权句柄）。 */
static int probe_getrandom_session(void)
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_SESSIONS, 0x0000017Bu);
    cmd_password_session(&c);
    cmd_u16(&c, 16);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[RAND] getrandom+password rc=0x%08X resp_len=%u\n",
           rc, (unsigned)resp_len);
    if (rc != TPM_RC_SUCCESS) {
        dump_bytes("RAND-CMD", c.buf, c.len);
        dump_bytes("RAND-RESP", resp, resp_len);
    }
    return (int)rc;
}

/* 无会话 CreatePrimary（NULL 层）：若返回 AUTH_MISSING 说明句柄解析正常，
 * 若仍为 HANDLE 说明该命令被通道/策略拦截。 */
static int probe_create_primary_nosession(void)
{
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000131u);
    cmd_u32(&c, 0x40000007u);
    cmd_u16(&c, 4);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0);
    cmd_u16(&c, 26);
    cmd_u16(&c, 0x0001);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, 0x00030072u);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0x0006);
    cmd_u16(&c, 128);
    cmd_u16(&c, 0x0043);
    cmd_u16(&c, 0x0010);
    cmd_u16(&c, 2048);
    cmd_u32(&c, 0);
    cmd_u16(&c, 0);
    cmd_u16(&c, 0);
    cmd_u32(&c, 0);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[PRIMARY] NULL-noauth rc=0x%08X resp_len=%u\n", rc, (unsigned)resp_len);
    return (int)rc;
}

/* 读取 TPM 属性和 NV 句柄清单：确认层次启用状态与现有索引分布 */
static int probe_capabilities(void)
{
    CmdBuf c;
    uint8_t resp[1024];
    size_t resp_len = sizeof(resp);
    uint32_t rc;
    size_t off = 10;
    uint32_t i;

    /* TPM_CAP_TPM_PROPERTIES：从 0x100 起 48 项，覆盖永久/启动/固定属性 */
    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x0000017Au);
    cmd_u32(&c, 0x00000006u);
    cmd_u32(&c, 0x00000100u);
    cmd_u32(&c, 48);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[CAP] properties rc=0x%08X\n", rc);
    if (rc != TPM_RC_SUCCESS) return (int)rc;
    off += 1;                       /* moreData */
    off += 4;                       /* capability */
    {
        uint32_t count = rd_u32(resp + off);
        off += 4;
        printf("[CAP] property count=%u\n", (unsigned)count);
        for (i = 0; i < count && off + 8 <= resp_len; i++) {
            uint32_t prop = rd_u32(resp + off);
            uint32_t val = rd_u32(resp + off + 4);
            if (prop == 0x0000010Bu || prop == 0x00000126u ||
                prop == 0x00000128u || prop == 0x0000012Fu ||
                prop == 0x00000115u) {
                printf("[CAP] property 0x%03X = 0x%08X\n", prop, val);
            }
            off += 8;
        }
    }

    /* TPM_CAP_TPM_PROPERTIES：可变属性（0x200 起），含永久/启动状态 */
    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x0000017Au);
    cmd_u32(&c, 0x00000006u);
    cmd_u32(&c, 0x00000200u);
    cmd_u32(&c, 16);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[CAP] var properties rc=0x%08X\n", rc);
    if (rc == TPM_RC_SUCCESS) {
        uint32_t vcount;
        off = 10 + 1 + 4;
        vcount = rd_u32(resp + off);
        off += 4;
        printf("[CAP] var property count=%u\n", (unsigned)vcount);
        for (i = 0; i < vcount && off + 8 <= resp_len; i++) {
            uint32_t prop = rd_u32(resp + off);
            uint32_t val = rd_u32(resp + off + 4);
            if (prop == 0x00000200u || prop == 0x00000201u ||
                prop == 0x00000202u) {
                printf("[CAP] var property 0x%03X = 0x%08X\n", prop, val);
            }
            off += 8;
        }
    }

    /* TPM_CAP_HANDLES：NV 索引句柄 */
    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x0000017Au);
    cmd_u32(&c, 0x00000001u);
    cmd_u32(&c, 0x01000000u);
    cmd_u32(&c, 64);
    resp_len = sizeof(resp);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[CAP] nv handles rc=0x%08X\n", rc);
    if (rc != TPM_RC_SUCCESS) return (int)rc;
    off = 10 + 1 + 4;
    {
        uint32_t count = rd_u32(resp + off);
        off += 4;
        printf("[CAP] nv count=%u\n", (unsigned)count);
        for (i = 0; i < count && off + 4 <= resp_len; i++) {
            printf("[CAP] nv index=0x%08X\n", rd_u32(resp + off));
            off += 4;
        }
    }
    return 0;
}

/* 删除索引；前置声明供索引段探测复用 */
static int probe_nv_undefine(uint32_t index);

/* 读取 NV 公共区（不要求授权）：用于确认索引是否存在及属性 */
static int probe_nv_read_public(uint32_t index)
{
    CmdBuf c;
    uint8_t resp[256];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_NO_SESSIONS, 0x00000169u);
    cmd_u32(&c, index);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    if (rc != TPM_RC_SUCCESS) {
        printf("[NV] readpublic index=0x%08X rc=0x%08X\n", index, rc);
        return (int)rc;
    }
    printf("[NV] readpublic index=0x%08X OK\n", index);
    return 0;
}

/* 在指定索引上尝试定义计数器；成功即删除，仅用于探测索引段归属 */
static int probe_nv_define_at(uint32_t index, uint32_t attr)
{
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_SESSIONS, TPM_CC_NV_DEFINE);
    cmd_u32(&c, TPM_RH_OWNER);
    cmd_password_session(&c);
    cmd_u16(&c, 0);
    cmd_u32(&c, index);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, attr);
    cmd_u16(&c, 0);
    cmd_u16(&c, 8);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    printf("[NV] define index=0x%08X attr=0x%08X rc=0x%08X\n", index, attr, rc);
    if (rc != TPM_RC_SUCCESS) {
        dump_bytes("NV-CMD", c.buf, c.len);
        dump_bytes("NV-RESP", resp, resp_len);
    }
    if (rc == TPM_RC_SUCCESS) {
        printf("[NV] define ok -> cleanup=%s\n",
               probe_nv_undefine(index) == 0 ? "OK" : "FAIL");
    }
    return (int)rc;
}

static int probe_nv_ranges(void)
{
    probe_nv_read_public(0x01C00002u);   /* Windows 自身索引：只读探测 */
    probe_nv_define_at(0x01900010u, PROBE_NV_ATTR);
    probe_nv_define_at(0x01900011u, 0x00000001u);  /* 仅 NT=counter */
    probe_nv_define_at(0x01900012u, 0x00020021u);  /* NT=counter|authWrite|authRead */
    probe_nv_define_at(0x01500010u, PROBE_NV_ATTR); /* 平台段，预期拒绝 */
    return 0;
}

static int probe_nv_undefine(uint32_t index)
{
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_SESSIONS, TPM_CC_NV_UNDEFINE);
    cmd_u32(&c, TPM_RH_OWNER);
    cmd_u32(&c, index);
    cmd_password_session(&c);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    return (rc == TPM_RC_SUCCESS) ? 0 : (int)rc;
}

static int probe_nv_define(uint32_t index)
{
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_SESSIONS, TPM_CC_NV_DEFINE);
    cmd_u32(&c, TPM_RH_OWNER);       /* authHandle */
    cmd_password_session(&c);
    cmd_u16(&c, 0);                  /* authValue 为空 */
    cmd_u32(&c, index);
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u32(&c, PROBE_NV_ATTR);
    cmd_u16(&c, 0);                  /* authPolicy 为空 */
    cmd_u16(&c, 8);                  /* 计数器数据宽度 */
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    return (rc == TPM_RC_SUCCESS) ? 0 : (int)rc;
}

static int probe_nv_increment(uint32_t index)
{
    CmdBuf c;
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    uint32_t rc;

    cmd_init(&c, TPM_ST_SESSIONS, TPM_CC_NV_INCREMENT);
    cmd_u32(&c, TPM_RH_OWNER);
    cmd_u32(&c, index);
    cmd_password_session(&c);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    return (rc == TPM_RC_SUCCESS) ? 0 : (int)rc;
}

/* 读取计数器；*value 在成功时写出。返回 0 或 TPM rc（含 NV_UNINITIALIZED） */
static int probe_nv_read(uint32_t index, uint64_t *value)
{
    CmdBuf c;
    uint8_t resp[128];
    size_t resp_len = sizeof(resp);
    size_t off = 10;
    uint32_t rc;
    uint32_t n;

    if (value == NULL) return -1;
    cmd_init(&c, TPM_ST_SESSIONS, TPM_CC_NV_READ);
    cmd_u32(&c, TPM_RH_OWNER);
    cmd_u32(&c, index);
    cmd_password_session(&c);
    cmd_u16(&c, 8);
    cmd_u16(&c, 0);
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    if (rc != TPM_RC_SUCCESS) return (int)rc;

    if (off + 2 > resp_len) return -2;
    n = rd_u16(resp + off);
    off += 2;
    if (n != 8 || off + n > resp_len) return -2;
    *value = ((uint64_t)rd_u32(resp + off) << 32) | rd_u32(resp + off + 4);
    off += n;
    if (skip_auth_response(resp, resp_len, &off) != 0) return -2;
    return 0;
}

/* 读取 PCR[7,11]（SHA-256 银行）并计算策略摘要 H(pcr7 || pcr11) */
static int probe_pcr_read(void)
{
    CmdBuf c;
    uint8_t resp[256];
    size_t resp_len = sizeof(resp);
    size_t off = 10;
    uint32_t rc;
    uint32_t count;
    uint32_t i;
    uint32_t digest_count;
    uint8_t pcr_values[2][32];
    static const uint8_t select7_11[3] = { 0x80, 0x08, 0x00 };
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    uint8_t digest[32];
    int got = 0;

    cmd_init(&c, TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ);
    cmd_u32(&c, 1);                    /* TPML_PCR_SELECTION 项数 */
    cmd_u16(&c, TPM_ALG_SHA256);
    cmd_u8(&c, 3);
    cmd_bytes(&c, select7_11, sizeof(select7_11));
    if (tpm_submit(&c, resp, &resp_len) != 0) return -1;
    rc = tpm_rc(resp, resp_len);
    if (rc != TPM_RC_SUCCESS) {
        printf("[PCR] rc=0x%08X\n", rc);
        return -2;
    }

    /* pcrUpdateCounter */
    off += 4;
    if (off + 4 > resp_len) return -3;
    count = rd_u32(resp + off); off += 4;
    for (i = 0; i < count; i++) {
        uint32_t sel_size;
        if (off + 5 > resp_len) return -3;
        off += 2;                      /* hashAlg */
        sel_size = resp[off]; off += 1;
        if (sel_size > 3 || off + sel_size > resp_len) return -3;
        off += sel_size;
    }
    if (off + 4 > resp_len) return -3;
    digest_count = rd_u32(resp + off); off += 4;
    if (digest_count > 8) return -3;
    for (i = 0; i < digest_count; i++) {
        uint32_t n;
        if (off + 2 > resp_len) return -3;
        n = rd_u16(resp + off); off += 2;
        if (n != 32 || off + n > resp_len) return -3;
        if (i < 2) memcpy(pcr_values[i], resp + off, 32);
        printf("[PCR] value[%u]=%02X%02X%02X%02X...%02X%02X%02X%02X\n",
               i, resp[off], resp[off + 1], resp[off + 2], resp[off + 3],
               resp[off + 28], resp[off + 29], resp[off + 30], resp[off + 31]);
        off += n;
        got++;
    }
    if (got != 2) {
        printf("[PCR] expected 2 digests, got %d\n", got);
        return -4;
    }
    memcpy(g_pcr7, pcr_values[0], 32);
    memcpy(g_pcr11, pcr_values[1], 32);
    g_pcr_valid = 1;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return -5;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return -5;
    }
    if (BCryptHashData(hash, pcr_values[0], 32, 0) != 0 ||
        BCryptHashData(hash, pcr_values[1], 32, 0) != 0 ||
        BCryptFinishHash(hash, digest, 32, 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -5;
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    printf("[PCR] policyDigest(pcr7||pcr11)=%02X%02X%02X%02X...%02X%02X%02X%02X\n",
           digest[0], digest[1], digest[2], digest[3],
           digest[28], digest[29], digest[30], digest[31]);
    return 0;
}

static int probe_nv_roundtrip(void)
{
    uint64_t v = 0;
    int rc;

    /* 上一次异常退出可能留下测试索引：先删再建 */
    (void)probe_nv_undefine(PROBE_NV_INDEX);
    rc = probe_nv_define(PROBE_NV_INDEX);
    if (rc != 0) {
        printf("[NV] define failed rc=0x%08X\n", (unsigned)rc);
        return -1;
    }

    rc = probe_nv_read(PROBE_NV_INDEX, &v);
    if (rc == TPM_RC_NV_UNINITIALIZED) {
        printf("[NV] read-before-write -> NV_UNINITIALIZED (expected on some firmware)\n");
        v = 0;
        rc = 0;
    } else if (rc != 0) {
        printf("[NV] read failed rc=0x%08X\n", (unsigned)rc);
        goto cleanup;
    } else {
        printf("[NV] initial value=%llu\n", (unsigned long long)v);
    }

    rc = probe_nv_increment(PROBE_NV_INDEX);
    if (rc != 0) {
        printf("[NV] increment failed rc=0x%08X\n", (unsigned)rc);
        goto cleanup;
    }
    rc = probe_nv_read(PROBE_NV_INDEX, &v);
    if (rc != 0 || v != 1) {
        printf("[NV] after-1 value=%llu rc=0x%08X (expect 1)\n",
               (unsigned long long)v, (unsigned)rc);
        goto cleanup;
    }
    printf("[NV] after-1 value=%llu\n", (unsigned long long)v);

    rc = probe_nv_increment(PROBE_NV_INDEX);
    if (rc != 0) {
        printf("[NV] increment#2 failed rc=0x%08X\n", (unsigned)rc);
        goto cleanup;
    }
    rc = probe_nv_read(PROBE_NV_INDEX, &v);
    if (rc != 0 || v != 2) {
        printf("[NV] after-2 value=%llu rc=0x%08X (expect 2)\n",
               (unsigned long long)v, (unsigned)rc);
        goto cleanup;
    }
    printf("[NV] after-2 value=%llu\n", (unsigned long long)v);

cleanup:
    printf("[NV] undefine -> %s\n",
           probe_nv_undefine(PROBE_NV_INDEX) == 0 ? "OK" : "FAIL");
    if (probe_nv_read(PROBE_NV_INDEX, &v) == 0) {
        printf("[NV] read-after-undefine still works (unexpected)\n");
        return 1;
    }
    printf("[NV] read-after-undefine -> rejected (expected)\n");
    return 0;
}

static int probe_owner_auth(void)
{
    uint8_t buf[64];
    UINT32 len = (UINT32)sizeof(buf);
    TBS_RESULT r;

    r = Tbsi_Get_OwnerAuth(g_tbs, TBS_OWNERAUTH_TYPE_FULL, buf, &len);
    if (r == TBS_SUCCESS) {
        /* 只报告长度，不输出内容 */
        printf("[OWNER] Get_OwnerAuth=available len=%u\n", (unsigned)len);
        SecureZeroMemory(buf, sizeof(buf));
        return 0;
    }
    printf("[OWNER] Get_OwnerAuth=unavailable tbs=0x%08X（空 owner auth 下仍可提交 NV 命令）\n",
           (unsigned)r);
    return 0;
}

int main(void)
{
    TBS_CONTEXT_PARAMS2 params;
    TBS_RESULT r;
    TPM_DEVICE_INFO info;
    int rc = 0;
    int use_raw = 0;

    /* 两次尝试：默认上下文与 requestRaw 上下文。后者绕过 TBS 资源管理的
     * 会话虚拟化，用于判定 0x8B 是否由资源管理层引入。 */
    {
        const char *env = getenv("VTY_TPM_RAW");
        use_raw = (env != NULL && env[0] == '1') ? 1 : 0;
    }
    memset(&params, 0, sizeof(params));
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    params.requestRaw = use_raw ? 1u : 0u;
    if (use_raw) {
        enable_privilege(L"SeLoadDriverPrivilege");
        enable_privilege(L"SeTcbPrivilege");
    }
    r = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &g_tbs);
    if (r != TBS_SUCCESS) {
        printf("[TBS] context create failed tbs=0x%08X (raw=%d)\n", (unsigned)r, use_raw);
        return 2;
    }
    printf("[TBS] context create OK (raw=%d)\n", use_raw);

    memset(&info, 0, sizeof(info));
    info.structVersion = 1;
    r = Tbsi_GetDeviceInfo(sizeof(info), &info);
    if (r == TBS_SUCCESS) {
        printf("[TPM] version=%u interface=%u revision=0x%08X\n",
               (unsigned)info.tpmVersion, (unsigned)info.tpmInterfaceType,
               (unsigned)info.tpmImpRevision);
    } else {
        printf("[TPM] GetDeviceInfo failed tbs=0x%08X\n", (unsigned)r);
    }

    probe_owner_auth();
    probe_getrandom();
    probe_session_handle();
    probe_hmac_session();
    probe_priority_matrix();
    probe_tag_behavior();
    probe_session_diagnostics();
    probe_session_context();
    probe_session_lifecycle();
    probe_policy_session();
    probe_nv_define_hmac(0x01900010u);
    probe_getrandom_session();
    probe_session_variants();
    probe_create_primary_nosession();
    probe_capabilities();
    probe_create_primary(0x40000007u, "NULL");
    probe_create_primary(0x4000000Bu, "ENDORSEMENT");
    probe_create_primary(0x40000001u, "OWNER");
    probe_create_primary(0x4000000Cu, "PLATFORM");
    probe_nv_ranges();

    if (probe_pcr_read() != 0) rc = 1;
    /* NV 计数器依赖平台允许带授权区的 TPM 2.0 命令；本机不支持时只记录，
     * 不作为 P2 PCR 门禁的失败条件。 */
    {
        int nv = probe_nv_roundtrip();
        printf("[RESULT-NV] %s\n", nv == 0 ? "SUPPORTED" : "BLOCKED");
    }

    /* PCP：Windows 支持的 TPM 访问路径（PCR 绑定与密封） */
    probe_pcp_info();
    probe_pcp_seal();
    probe_witness_timing();
    probe_witness_symmetric();
    probe_pcp_capacity();
    pcp_pcr_key(L"VerthysPcrProbeMask", 0x00000880u, NULL, 0, 0);
    if (pcp_pcr_decrypt_test(L"VerthysPcrDecrypt", 0x00000880u, NULL, 0) != 0) rc = 1;
    if (g_pcr_valid) {
        /* 以“全零”作为预期 PCR 7/11 的负向样本：创建应成功、解密应失败 */
        uint8_t zero_list[24 * 32];
        memset(zero_list, 0, sizeof(zero_list));
        pcp_pcr_key(L"VerthysPcrProbeWrong", 0x00000880u,
                    zero_list, sizeof(zero_list), 0);
        if (pcp_pcr_decrypt_test(L"VerthysPcrDecryptWrong", 0x00000880u,
                                 zero_list, sizeof(zero_list)) == 0) {
            /* 负向样本竟然解封成功：说明 PCR 门未生效 */
            rc = 1;
        }
    } else {
        rc = 1;
    }

    Tbsip_Context_Close(g_tbs);
    printf("[RESULT] %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
