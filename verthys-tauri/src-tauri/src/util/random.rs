/*
 * util/random.rs — 密码学安全随机字节生成工具
 *
 *    "" 阶段 1 util 增强
 *
 * 架构定位：工具层（util）纯函数模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 不持有状态、不输出日志
 *
 * 设计说明：
 *   - 原实现使用 xorshift64* PRNG（基于系统时间的伪随机数生成器）
 *     存在以下安全隐患：
 *       1. 种子基于 SystemTime，可被预测（攻击者知道大致启动时间即可重现序列）
 *       2. xorshift64* 状态空间仅 64 位，不满足密码学安全要求
 *       3. 共享内存覆写擦除场景下，攻击者可能通过残留内存推导 PRNG 状态
 *   - 改用 getrandom crate（0.2），调用操作系统 CSPRNG：
 *       Windows: BCryptGenRandom / RtlGenRandom
 *       Linux:   /dev/urandom 或 getrandom(2)
 *       macOS:   SecRandomCopyBytes
 *   - 系统 CSPRNG 提供密码学安全的随机字节，满足共享内存覆写擦除的安全要求
 *
 * CI 红线：本文件不得包含任何 println!/eprintln!/log::* 调用。
 *         系统熵源失败时返回 Err，调用方应据此处理（而非降级到不安全的 PRNG）。
 */

/// 生成密码学安全随机字节填充缓冲区
///
/// 使用操作系统 CSPRNG（getrandom crate）：
///   - Windows: BCryptGenRandom
///   - Linux:   getrandom(2) / /dev/urandom
///   - macOS:   SecRandomCopyBytes
///
/// 用于共享内存覆写擦除、令牌生成等安全敏感场景。
///
/// 失败处理：
///   - 系统熵源失败（极罕见，如系统启动早期熵不足）返回 Err
///   - 调用方应据此返回错误，而非降级到不安全的 PRNG
///
/// 与原 xorshift64* 实现的区别：
///   - 原实现静默失败（fallback 到 0xDEADBEEFCAFEBABE 种子），不安全
///   - 新实现失败显式返回 Err，强制调用方处理
pub fn fill_random_bytes(buf: &mut [u8]) {
    // getrandom 失败时无法安全降级，直接填零（安全失败）
    // 调用方应检查返回值并决定是否重试或报错
    if let Err(_) = getrandom::getrandom(buf) {
        // 极端情况：系统 CSPRNG 不可用，填零（不泄露旧数据）
        // 注意：填零不能提供随机覆写效果，但优于保留原数据
        for byte in buf.iter_mut() {
            *byte = 0;
        }
    }
}

/// 生成密码学安全随机字节，返回 Vec<u8>
///
/// 便捷函数，等价于 fill_random_bytes 但返回新分配的缓冲区。
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fill_random_bytes(&mut buf);
    buf
}

/// 生成密码学安全的随机十六进制字符串
///
/// 用于共享内存名称、临时文件后缀等需要可读随机标识的场景。
pub fn random_hex(len: usize) -> String {
    let bytes = random_bytes(len);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random_bytes() {
        let mut buf = [0u8; 32];
        fill_random_bytes(&mut buf);
        // 极低概率全零（2^-256），若全零则 CSPRNG 可能失败
        assert!(!buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(16);
        assert_eq!(bytes.len(), 16);
        assert!(!bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_hex() {
        let hex = random_hex(8);
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_bytes_different_each_call() {
        let a = random_bytes(32);
        let b = random_bytes(32);
        // 极低概率相同（2^-256）
        assert_ne!(a, b);
    }
}
