/* base64.rs — base64 编解码
 *
 * 职责：标准字母表（无换行）编解码，宽容 CR/LF/空格输入。
 */

const B64_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64_TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let cleaned: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    if !cleaned.len().is_multiple_of(4) {
        return Err("invalid base64 length");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let lookup = |c: u8| -> i32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i32,
            b'a'..=b'z' => (c - b'a' + 26) as i32,
            b'0'..=b'9' => (c - b'0' + 52) as i32,
            b'+' => 62,
            b'/' => 63,
            b'=' => -1,
            _ => -2,
        }
    };
    let mut i = 0;
    while i < cleaned.len() {
        let a = lookup(cleaned[i]);
        let b = lookup(cleaned[i + 1]);
        let c = lookup(cleaned[i + 2]);
        let d = lookup(cleaned[i + 3]);
        if a < 0 || b < 0 || c == -2 || d == -2 {
            return Err("invalid base64 char");
        }
        let n = ((a as u32) << 18)
            | ((b as u32) << 12)
            | (if c >= 0 { (c as u32) << 6 } else { 0 })
            | (if d >= 0 { d as u32 } else { 0 });
        out.push((n >> 16) as u8);
        if c >= 0 {
            out.push((n >> 8) as u8);
        }
        if d >= 0 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}
