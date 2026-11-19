/*
 * media/animated.rs — 动图三态检测
 *
 * GIF 交给解码器数帧；WebP/PNG 只解析容器块，不解码像素。输入来自用户
 * 文件，任何结构异常都收敛为 false，不影响照片本身导入。
 */

use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;

use image::codecs::gif::GifDecoder;
use image::{AnimationDecoder, ImageDecoder};

use super::mime;

/// 头部扫描上限：ANIM/acTL 必须出现在像素数据之前，1MiB 足够覆盖元数据。
const HEAD_SCAN_BYTES: u64 = 1024 * 1024;

/// 返回 Some(true/false) 表示已确认；None 表示该格式不需要/无法判定。
pub(crate) fn detect(path: &Path, mime_type: &str) -> Result<Option<bool>, String> {
    if !mime::is_animated_candidate(mime_type) {
        return Ok(None);
    }
    match mime_type {
        "image/gif" => gif_animated(path).map(Some),
        "image/webp" => webp_animated(&read_head(path)?).map(Some),
        "image/png" => png_animated(&read_head(path)?).map(Some),
        _ => Ok(None),
    }
}

/// 按已解密字节探测动图（备份还原与 PNG 导出没有源文件路径）。
pub(crate) fn detect_bytes(bytes: &[u8], mime_type: &str) -> Result<Option<bool>, String> {
    if !mime::is_animated_candidate(mime_type) {
        return Ok(None);
    }
    match mime_type {
        "image/gif" => gif_animated_bytes(bytes).map(Some),
        "image/webp" => webp_animated(bytes).map(Some),
        "image/png" => png_animated(bytes).map(Some),
        _ => Ok(None),
    }
}

fn gif_animated(path: &Path) -> Result<bool, String> {
    let file = File::open(path).map_err(|e| format!("打开 GIF 失败: {}", e))?;
    let decoder = gif_decoder(BufReader::new(file))?;
    count_gif_frames(decoder)
}

fn gif_animated_bytes(bytes: &[u8]) -> Result<bool, String> {
    let decoder = gif_decoder(Cursor::new(bytes))?;
    count_gif_frames(decoder)
}

/// GIF 解码限额：动图探测只需前两帧，但恶意/异常文件可能声明超大画布。
/// 在解码前限制尺寸与分配，避免帧解码把 worker 内存打爆。
fn gif_decoder<R: std::io::BufRead + std::io::Seek>(
    reader: R,
) -> Result<GifDecoder<R>, String> {
    let mut decoder =
        GifDecoder::new(reader).map_err(|e| format!("解析 GIF 失败: {}", e))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    decoder
        .set_limits(limits)
        .map_err(|e| format!("GIF 尺寸超出上限: {}", e))?;
    Ok(decoder)
}

fn count_gif_frames<R: std::io::BufRead + std::io::Seek>(
    decoder: GifDecoder<R>,
) -> Result<bool, String> {
    let mut frames = decoder.into_frames();
    let mut count = 0usize;
    while count < 2 {
        match frames.next() {
            Some(Ok(_)) => count += 1,
            Some(Err(e)) => return Err(format!("解码 GIF 帧失败: {}", e)),
            None => break,
        }
    }
    Ok(count >= 2)
}

fn webp_animated(data: &[u8]) -> Result<bool, String> {
    if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return Ok(false);
    }
    let mut off = 12usize;
    while off + 8 <= data.len() {
        let fourcc = &data[off..off + 4];
        let size = u32::from_le_bytes([
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ]) as usize;
        if fourcc == b"ANIM" || fourcc == b"ANMF" {
            return Ok(true);
        }
        if fourcc == b"VP8 " || fourcc == b"VP8L" {
            return Ok(false);
        }
        let next = off
            .saturating_add(8)
            .saturating_add(size)
            .saturating_add(size & 1);
        if next <= off || next > data.len() {
            break;
        }
        off = next;
    }
    Ok(false)
}

fn png_animated(data: &[u8]) -> Result<bool, String> {
    if data.len() < 8 || &data[..8] != &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Ok(false);
    }
    let mut off = 8usize;
    while off + 8 <= data.len() {
        let len = u32::from_be_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
        ]) as usize;
        let typ = &data[off + 4..off + 8];
        if typ == b"acTL" {
            if len >= 8 && off + 16 <= data.len() {
                let frames = u32::from_be_bytes([
                    data[off + 8],
                    data[off + 9],
                    data[off + 10],
                    data[off + 11],
                ]);
                return Ok(frames >= 2);
            }
            return Ok(false);
        }
        if typ == b"IDAT" || typ == b"IEND" {
            return Ok(false);
        }
        let next = off.saturating_add(12).saturating_add(len);
        if next <= off || next > data.len() {
            break;
        }
        off = next;
    }
    Ok(false)
}

fn read_head(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("打开文件失败: {}", e))?;
    let mut data = Vec::new();
    file.take(HEAD_SCAN_BYTES)
        .read_to_end(&mut data)
        .map_err(|e| format!("读取文件头失败: {}", e))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vty-anim-{}-{}", std::process::id(), name))
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = File::create(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn apng_actl_before_idat_is_animated() {
        let path = temp("anim.png");
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(b"acTL");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        write(&path, &bytes);
        assert_eq!(detect(&path, "image/png").unwrap(), Some(true));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn png_without_actl_is_static() {
        let path = temp("static.png");
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"IDAT");
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        write(&path, &bytes);
        assert_eq!(detect(&path, "image/png").unwrap(), Some(false));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn webp_anim_chunk_is_animated() {
        let path = temp("anim.webp");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&14u32.to_le_bytes());
        bytes.extend_from_slice(b"WEBP");
        bytes.extend_from_slice(b"ANIM");
        bytes.extend_from_slice(&6u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 6]);
        write(&path, &bytes);
        assert_eq!(detect(&path, "image/webp").unwrap(), Some(true));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn webp_static_vp8_chunk_is_static() {
        let path = temp("static.webp");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&12u32.to_le_bytes());
        bytes.extend_from_slice(b"WEBP");
        bytes.extend_from_slice(b"VP8 ");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        write(&path, &bytes);
        assert_eq!(detect(&path, "image/webp").unwrap(), Some(false));
        let _ = std::fs::remove_file(path);
    }
}
