/*
 * media/mime.rs — 照片格式判定
 *
 * 只看文件头，不信任扩展名：用户可以把任意文件改成 .jpg，解码器必须在
 * 打开前就按内容拒绝。扩展名仅用于在文件头无法识别时给出明确诊断。
 */

use std::fs::File;
use std::io::Read;
use std::path::Path;

const HEAD_BYTES: usize = 16;

/// 识别受支持的照片 MIME；不支持或无法读取返回 Err。
pub(crate) fn detect_mime(path: &Path) -> Result<&'static str, String> {
    let mut file = File::open(path).map_err(|e| format!("打开文件失败: {}", e))?;
    let mut head = [0u8; HEAD_BYTES];
    let n = file
        .read(&mut head)
        .map_err(|e| format!("读取文件头失败: {}", e))?;
    let head = &head[..n];

    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Ok("image/jpeg");
    }
    if head.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Ok("image/png");
    }
    if head.len() >= 6 && (&head[..6] == b"GIF87a" || &head[..6] == b"GIF89a") {
        return Ok("image/gif");
    }
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Ok("image/webp");
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    Err(format!(
        "不支持的图片格式（扩展名 {}，文件头未识别）",
        if ext.is_empty() { "无" } else { &ext }
    ))
}

/// 是否为需要动图探测的容器类型。
pub(crate) fn is_animated_candidate(mime: &str) -> bool {
    matches!(mime, "image/gif" | "image/webp" | "image/png")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vty-mime-{}-{}", std::process::id(), name))
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = File::create(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn detects_supported_formats_by_magic_not_extension() {
        let jpeg = temp("a.bin");
        write(&jpeg, &[0xFF, 0xD8, 0xFF, 0xE0]);
        assert_eq!(detect_mime(&jpeg).unwrap(), "image/jpeg");

        let png = temp("b.bin");
        write(&png, &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(detect_mime(&png).unwrap(), "image/png");

        let gif = temp("c.bin");
        write(&gif, b"GIF89a....");
        assert_eq!(detect_mime(&gif).unwrap(), "image/gif");

        let webp = temp("d.bin");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(b"WEBP");
        write(&webp, &bytes);
        assert_eq!(detect_mime(&webp).unwrap(), "image/webp");

        for path in [jpeg, png, gif, webp] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn rejects_unknown_content_even_with_image_extension() {
        let path = temp("fake.jpg");
        write(&path, b"not an image");
        assert!(detect_mime(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
