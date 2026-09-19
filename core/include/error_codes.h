/*
 * error_codes.h — C 层标准化错误码定义
 * 
 *
 * 设计原则：
 *   - 所有 C 函数必须返回本文件定义的标准化错误码（整型枚举）
 *   - VERTHYS_C_SUCCESS 表示成功，其他为各类失败原因
 *   - C 源码内部严格禁止向 stdout/stderr 输出任何调试信息
 *   - 错误反馈仅通过返回值传递
 *   - 头文件中定义所有公开函数原型及错误码常量，供 Rust FFI 绑定使用
 *
 * CI 红线：
 *   - C 源文件不得直接调用 printf / fprintf / OutputDebugString*
 *     （诊断一律经 verthys_diag.h 的 VERTHYS_DIAG_LOG 编译门）
 *   - C 函数返回值必须为本文件定义的错误码常量
 */
#ifndef VERTHYS_ERROR_CODES_H
#define VERTHYS_ERROR_CODES_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * 标准化错误码                                                        *
 *                                                                    *
 * 与 Rust 侧 util/ffi.rs 中 c_error_codes 模块完全对齐。              *
 * Rust FFI 桥接层依据此错误码转换为 VerthysError 变体。                 *
 * ------------------------------------------------------------------ */

#define VERTHYS_C_SUCCESS           0     /* 成功 */
#define VERTHYS_C_ERR_INVALID      (-1)   /* 无效参数 */
#define VERTHYS_C_ERR_LOCKED       (-2)   /* 加密库已锁定 */
#define VERTHYS_C_ERR_AUTH         (-3)   /* 认证失败（密码错误） */
#define VERTHYS_C_ERR_IO           (-4)   /* I/O 错误 */
#define VERTHYS_C_ERR_CORRUPT      (-5)   /* 数据损坏 */
#define VERTHYS_C_ERR_FULL         (-6)   /* 容器已满 */
#define VERTHYS_C_ERR_NOTFOUND     (-7)   /* 记录不存在 */
#define VERTHYS_C_ERR_NOMEM        (-8)   /* 内存不足 */
#define VERTHYS_C_ERR_STATE        (-9)   /* 状态错误 */
#define VERTHYS_C_ERR_INTERNAL     (-10)  /* 通用内部错误 */
#define VERTHYS_C_ERR_ROLLBACK     (-11)  /* 检测到回滚攻击 */

/* ------------------------------------------------------------------ *
 * 示例 C 函数原型                                                    *
 *                                                                    *
 * 所有 C 函数遵循以下签名模式：                                       *
 *   - 接收输入缓冲区、输出缓冲区指针及长度                            *
 *   - 执行具体的系统 API 调用                                         *
 *   - 返回标准化错误码（int）                                         *
 *   - 严禁任何输出操作                                                *
 * ------------------------------------------------------------------ */

/*
 * 示例：CNG 加密函数
 *
 * 参数：
 *   plaintext       - 输入明文缓冲区
 *   plaintext_len   - 明文长度
 *   ciphertext      - 输出密文缓冲区（调用方分配，长度 >= plaintext_len + 28）
 *   ciphertext_len  - 输入：缓冲区容量；输出：实际写入字节数
 *   key             - 对称密钥（32 字节）
 *   nonce           - Nonce（24 字节）
 *
 * 返回值：VERTHYS_C_SUCCESS 或错误码
 */
int verthys_cng_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    size_t *ciphertext_len,
    const unsigned char *key,
    const unsigned char *nonce
);

/*
 * 示例：CNG 解密函数
 */
int verthys_cng_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext,
    size_t *plaintext_len,
    const unsigned char *key,
    const unsigned char *nonce
);

/*
 * 示例：创建不可继承的文件句柄
 *
 *    "不可继承强制"
 * bInheritHandle 设为 FALSE
 */
int verthys_create_non_inheritable_file(
    const char *path,
    void **out_handle
);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_ERROR_CODES_H */
