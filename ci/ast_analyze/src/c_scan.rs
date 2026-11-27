/*
 * c_scan.rs — C 源码扫描辅助
 *
 * strip_c_comments_and_literals 去掉注释与字符串/字符字面量并保留换行，
 * 使注释或字符串里的 printf 不构成输出调用，行号仍可对齐。
 */
use std::path::Path;

pub(crate) fn normalized_rel(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// 去掉 C 注释与字符串/字符字面量，保留换行以维持行号。
///
/// 注释里提到 printf/OutputDebugString 不构成输出调用；仅扫描真实代码。
pub(crate) fn strip_c_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    let mut state = 0u8; // 0=normal 1=line comment 2=block comment 3=string 4=char

    while index < bytes.len() {
        let current = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            0 => {
                if current == b'/' && next == Some(b'/') {
                    out.extend_from_slice(b"  ");
                    state = 1;
                    index += 2;
                } else if current == b'/' && next == Some(b'*') {
                    out.extend_from_slice(b"  ");
                    state = 2;
                    index += 2;
                } else if current == b'"' {
                    out.push(b' ');
                    state = 3;
                    index += 1;
                } else if current == b'\'' {
                    out.push(b' ');
                    state = 4;
                    index += 1;
                } else {
                    out.push(current);
                    index += 1;
                }
            }
            1 => {
                if current == b'\n' {
                    out.push(b'\n');
                    state = 0;
                } else {
                    out.push(b' ');
                }
                index += 1;
            }
            2 => {
                if current == b'*' && next == Some(b'/') {
                    out.extend_from_slice(b"  ");
                    state = 0;
                    index += 2;
                } else {
                    out.push(if current == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
            3 => {
                if current == b'\\' && next.is_some() {
                    out.extend_from_slice(b"  ");
                    index += 2;
                } else if current == b'"' {
                    out.push(b' ');
                    state = 0;
                    index += 1;
                } else {
                    out.push(if current == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
            _ => {
                if current == b'\\' && next.is_some() {
                    out.extend_from_slice(b"  ");
                    index += 2;
                } else if current == b'\'' {
                    out.push(b' ');
                    state = 0;
                    index += 1;
                } else {
                    out.push(if current == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}
