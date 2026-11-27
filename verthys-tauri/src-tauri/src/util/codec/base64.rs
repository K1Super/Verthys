/*
 * util/base64.rs — Base64 编解码工具
 *
 *
 *
 * 架构定位：工具层（util）纯函数模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 不持有状态、不执行 I/O、不输出日志
 *   - 仅对外暴露确定性的编解码接口
 *
 * 实现选型：使用标准 base64 crate（0.22）：
 *   - 支持多种字母表与配置，覆盖流式与一次性编解码
 *   - 错误信息精细，社区维护并经广泛审计
 *   - 不自行实现编码表：自编实现易缺 URL-safe 字母表与流式接口，
 *     且实现 bug 可能导致数据损坏
 *
 * 接口：base64_encode / base64_decode 保持现有签名，内部委托至 base64 crate。
 *
 * CI 红线：本文件不得包含任何 println!/eprintln!/log::* 调用。
 */

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// base64 编码（标准字母表 + padding）
///
/// 内部委托至 base64 crate STANDARD engine。
/// 标准字母表 + padding，跨进程可达同一编码结果。
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// base64 解码（标准字母表，支持 padding 与空白字符过滤）
///
/// 内部委托至 base64 crate STANDARD engine。
/// 行为约定：
///   - 过滤 \n \r 空白字符
///   - 非法字符返回 Err
///   - padding 处理由 base64 crate 内部完成
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // 过滤空白字符
    let filtered: String = input
        .chars()
        .filter(|&c| c != '\n' && c != '\r' && c != ' ')
        .collect();
    STANDARD
        .decode(filtered)
        .map_err(|e| format!("invalid base64: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn test_decode_basic() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
    }

    #[test]
    fn test_decode_with_whitespace() {
        assert_eq!(base64_decode("aGVs\nbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVs bG8=").unwrap(), b"hello");
    }

    #[test]
    fn test_decode_invalid() {
        assert!(base64_decode("!!!invalid!!!").is_err());
    }

    #[test]
    fn test_roundtrip() {
        let data = b"\x00\x01\x02\x03\xff\xfe\xfd";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
    }
}
