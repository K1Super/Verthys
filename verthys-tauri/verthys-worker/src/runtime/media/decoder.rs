/*
 * media/decoder.rs — 原生缩略图与尺寸探测
 *
 * 只解码一次原图，按预算逐档降级编码 JPEG 缩略图；解码前设置尺寸与
 * 内存上限，避免畸形图片以极小文件触发超大分配。
 */

use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;

use image::codecs::jpeg::JpegEncoder;
use image::{
    DynamicImage, GrayImage, ImageEncoder, ImageFormat, ImageReader, Limits, RgbImage,
};

use crate::runtime::budget::PB_PHOTO_THUMB_MAX_CHARS;
use crate::runtime::protocol::base64_encode;

/// 缩略图最长边上限（与原前端 400px 档位一致）。
const THUMB_MAX_SIDE: u32 = 400;
/// 预览最长边上限（首屏只读预览，不替代原图）。
const PREVIEW_MAX_SIDE: u32 = 2048;
/// 预览编码体积上限（字节）：超过即降档，避免预览记录随原图线性膨胀。
const PREVIEW_MAX_BYTES: usize = 512 * 1024;
/// 解码尺寸上限：超过即拒绝，避免解压炸弹。
const MAX_DECODE_SIDE: u32 = 20_000;
/// 解码内存上限（image 默认为 512MiB，显式写出以固定预算）。
const MAX_DECODE_ALLOC: u64 = 512 * 1024 * 1024;
/// 缩略图编码档位：质量优先，逐档降级到字符预算内。
const THUMB_QUALITIES: &[(u32, u8)] = &[(400, 85), (400, 70), (320, 75), (256, 70), (192, 60)];
/// 预览编码档位：长边 2048、质量 0.82 起，逐档降级到字节预算内。
const PREVIEW_QUALITIES: &[(u32, u8)] = &[(2048, 82), (2048, 70), (1600, 75), (1280, 70)];

#[cfg(test)]
pub(crate) struct ThumbResult {
    pub(crate) thumb_b64: String,
}

/// 读取缩略图；失败返回可读原因，由调用方跳过该文件（仅测试使用）。
#[cfg(test)]
pub(crate) fn generate_thumb(path: &Path) -> Result<ThumbResult, String> {
    Ok(ThumbResult {
        thumb_b64: generate_thumb_b64(path)?,
    })
}

/// 导入期只生成 400px 缩略图。
///
/// 2048px 预览属派生缓存，首次查看时由 `generate_preview_from_bytes`
/// 从解密字节懒生成；导入关键路径不再为大图做二次整图编码，避免每张
/// 照片多付一次全尺寸解码 + 2048 编码的 CPU 与驻留成本。
pub(crate) fn generate_thumb_b64(path: &Path) -> Result<String, String> {
    let orientation = read_jpeg_orientation(path);
    if is_jpeg_file(path) {
        if let Some(img) = decode_jpeg_scaled_path(path, THUMB_MAX_SIDE) {
            return encode_thumb_b64(&apply_orientation(img, orientation));
        }
    }
    let img = read_image(path)?;
    encode_thumb_b64(&apply_orientation(img, orientation))
}

fn encode_thumb_b64(img: &DynamicImage) -> Result<String, String> {
    let mut smallest: Option<String> = None;
    for &(max_side, quality) in THUMB_QUALITIES {
        let side = max_side.min(THUMB_MAX_SIDE);
        let thumb = img.thumbnail(side, side);
        let encoded = encode_jpeg(&thumb, quality)?;
        let b64 = base64_encode(&encoded);
        if b64.len() <= PB_PHOTO_THUMB_MAX_CHARS as usize {
            return Ok(b64);
        }
        smallest = Some(b64);
    }

    /* 全部档位仍超预算：返回最小产物，不阻塞导入。读取侧会以占位图兜底，
     * 但照片本身可用，优于把整张照片判失败。 */
    Ok(smallest.unwrap_or_default())
}

/// 从已解密原图字节生成 2048px 预览（历史照片懒生成路径）。
///
/// 解码/编码与导入路径共用同一套限制与档位；失败只影响预览，不改变
/// 原图可用性。
pub(crate) fn generate_preview_from_bytes(bytes: &[u8], mime_type: &str) -> Result<Vec<u8>, String> {
    let is_jpeg = mime_type == "image/jpeg";
    let (img, orientation) = if is_jpeg {
        let orientation = parse_jpeg_orientation(bytes);
        match decode_jpeg_scaled_bytes(bytes, PREVIEW_MAX_SIDE) {
            Some(img) => (img, orientation),
            None => (decode_bytes(bytes)?, orientation),
        }
    } else {
        (decode_bytes(bytes)?, 1)
    };
    encode_preview(&apply_orientation(img, orientation))
}

/// 是否为 JPEG（按 SOI 魔数判断，不依赖扩展名）。
fn is_jpeg_file(path: &Path) -> bool {
    let mut head = [0u8; 2];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok()
        && head == [0xFF, 0xD8]
}

/// 按路径缩放解码 JPEG；无法缩放/格式不支持/解码失败返回 None。
fn decode_jpeg_scaled_path(path: &Path, target_side: u32) -> Option<DynamicImage> {
    let file = File::open(path).ok()?;
    let mut decoder = jpeg_decoder::Decoder::new(BufReader::new(file));
    decode_jpeg_scaled(&mut decoder, target_side)
}

/// 按字节缩放解码 JPEG；无法缩放/格式不支持/解码失败返回 None。
fn decode_jpeg_scaled_bytes(bytes: &[u8], target_side: u32) -> Option<DynamicImage> {
    let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(bytes));
    decode_jpeg_scaled(&mut decoder, target_side)
}

/// JPEG 缩放解码核心：只启用 1/2–1/8 降采样，输出不低于目标长边。
///
/// `scale` 选择「输出至少在一个轴向上不小于请求尺寸」的最小缩放因子；
/// 若 1/2 仍会低于目标，说明缩放在本图上无收益，交回既有整图解码路径。
fn decode_jpeg_scaled<R: Read>(
    decoder: &mut jpeg_decoder::Decoder<R>,
    target_side: u32,
) -> Option<DynamicImage> {
    decoder.read_info().ok()?;
    let info = decoder.info()?;
    let width = info.width as u32;
    let height = info.height as u32;
    if width > MAX_DECODE_SIDE || height > MAX_DECODE_SIDE {
        return None;
    }
    let longest = width.max(height);
    if longest.div_ceil(2) < target_side {
        return None;
    }
    let target = target_side.min(u16::MAX as u32) as u16;
    let (out_w, out_h) = decoder.scale(target, target).ok()?;
    let pixels = decoder.decode().ok()?;
    jpeg_pixels_to_image(info.pixel_format, out_w, out_h, pixels)
}

/// jpeg-decoder 像素布局转 `DynamicImage`；CMYK/L16 等不安全格式返回 None
/// 由调用方回退到 `image` 整图解码（不自写色彩转换）。
fn jpeg_pixels_to_image(
    format: jpeg_decoder::PixelFormat,
    width: u16,
    height: u16,
    pixels: Vec<u8>,
) -> Option<DynamicImage> {
    let width = width as u32;
    let height = height as u32;
    match format {
        jpeg_decoder::PixelFormat::L8 => {
            GrayImage::from_raw(width, height, pixels).map(DynamicImage::ImageLuma8)
        }
        jpeg_decoder::PixelFormat::RGB24 => {
            RgbImage::from_raw(width, height, pixels).map(DynamicImage::ImageRgb8)
        }
        _ => None,
    }
}

/// 解码已解密字节并应用 EXIF 方向（JPEG）。
pub(crate) fn decode_bytes(bytes: &[u8]) -> Result<DynamicImage, String> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| format!("识别图片格式失败: {}", e))?;
    reader.limits(decode_limits());
    reader
        .decode()
        .map_err(|e| format!("解码图片失败: {}", e))
}

/// 原生转码为 PNG（保留原尺寸，应用 EXIF 方向）。
pub(crate) fn encode_png_bytes(bytes: &[u8], mime_type: &str) -> Result<Vec<u8>, String> {
    let img = decode_bytes(bytes)?;
    let orientation = if mime_type == "image/jpeg" {
        parse_jpeg_orientation(bytes)
    } else {
        1
    };
    let img = apply_orientation(img, orientation);
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|e| format!("编码 PNG 失败: {}", e))?;
    Ok(out)
}

fn encode_preview(img: &DynamicImage) -> Result<Vec<u8>, String> {
    let mut smallest: Option<Vec<u8>> = None;
    for &(max_side, quality) in PREVIEW_QUALITIES {
        let side = max_side.min(PREVIEW_MAX_SIDE);
        let preview = img.thumbnail(side, side);
        let encoded = encode_jpeg(&preview, quality)?;
        if encoded.len() <= PREVIEW_MAX_BYTES {
            return Ok(encoded);
        }
        if smallest
            .as_ref()
            .map(|s| encoded.len() < s.len())
            .unwrap_or(true)
        {
            smallest = Some(encoded);
        }
    }
    /* 仍超预算时返回最小档位：预览仍可显示，只是体积偏大。 */
    smallest.ok_or_else(|| "预览编码为空".to_string())
}

fn decode_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DECODE_SIDE);
    limits.max_image_height = Some(MAX_DECODE_SIDE);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    limits
}

fn read_image(path: &Path) -> Result<DynamicImage, String> {
    let mut reader = ImageReader::open(path)
        .map_err(|e| format!("打开图片失败: {}", e))?
        .with_guessed_format()
        .map_err(|e| format!("识别图片格式失败: {}", e))?;
    reader.limits(decode_limits());
    reader
        .decode()
        .map_err(|e| format!("解码图片失败: {}", e))
}

fn encode_jpeg(img: &DynamicImage, quality: u8) -> Result<Vec<u8>, String> {
    /* JPEG 不支持 alpha：GIF/PNG 解码得到的 RGBA8 若不转 RGB8，编码器会直接
     * 拒绝，整张照片被跳过。缩略图丢弃 alpha 可接受。 */
    let rgb = img.to_rgb8();
    let mut out = Vec::new();
    let encoder = JpegEncoder::new_with_quality(&mut out, quality);
    encoder
        .write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(|e| format!("编码缩略图失败: {}", e))?;
    Ok(out)
}

/// EXIF 方向：仅 JPEG 需要；解析失败按正常方向处理。
fn read_jpeg_orientation(path: &Path) -> u8 {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 1,
    };
    let mut head = Vec::new();
    if file.take(256 * 1024).read_to_end(&mut head).is_err() {
        return 1;
    }
    parse_jpeg_orientation(&head)
}

fn parse_jpeg_orientation(head: &[u8]) -> u8 {
    if head.len() < 4 || head[0] != 0xFF || head[1] != 0xD8 {
        return 1;
    }

    let mut i = 2usize;
    while i + 4 <= head.len() {
        if head[i] != 0xFF {
            break;
        }
        let marker = head[i + 1];
        if marker == 0xDA || marker == 0xD9 {
            break;
        }
        let len = u16::from_be_bytes([head[i + 2], head[i + 3]]) as usize;
        if len < 2 || i + 2 + len > head.len() {
            break;
        }
        let payload = &head[i + 4..i + 2 + len];
        if marker == 0xE1 && payload.starts_with(b"Exif\0\0") {
            return parse_tiff_orientation(&payload[6..]);
        }
        i += 2 + len;
    }
    1
}

fn parse_tiff_orientation(tiff: &[u8]) -> u8 {
    if tiff.len() < 8 {
        return 1;
    }
    let little = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return 1,
    };
    let u16_at = |off: usize| -> Option<u16> {
        let bytes = tiff.get(off..off + 2)?;
        Some(if little {
            u16::from_le_bytes([bytes[0], bytes[1]])
        } else {
            u16::from_be_bytes([bytes[0], bytes[1]])
        })
    };
    let u32_at = |off: usize| -> Option<u32> {
        let bytes = tiff.get(off..off + 4)?;
        Some(if little {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        })
    };

    if u16_at(2) != Some(42) {
        return 1;
    }
    let Some(ifd) = u32_at(4).map(|v| v as usize) else {
        return 1;
    };
    let Some(count) = u16_at(ifd).map(|v| v as usize) else {
        return 1;
    };
    for idx in 0..count {
        let entry = ifd + 2 + idx * 12;
        if entry + 12 > tiff.len() {
            break;
        }
        if u16_at(entry) != Some(0x0112) {
            continue;
        }
        let typ = u16_at(entry + 2);
        let n = u32_at(entry + 4);
        if typ == Some(3) && n == Some(1) {
            let value = u16_at(entry + 8).unwrap_or(1);
            if (1..=8).contains(&value) {
                return value as u8;
            }
        }
        break;
    }
    1
}

fn apply_orientation(img: DynamicImage, orientation: u8) -> DynamicImage {
    match orientation {
        2 => img.fliph(),
        3 => img.rotate180(),
        4 => img.flipv(),
        5 => img.rotate90().fliph(),
        6 => img.rotate90(),
        7 => img.rotate270().fliph(),
        8 => img.rotate270(),
        _ => img,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_png_produces_jpeg_thumbnail() {
        let path = std::env::temp_dir().join(format!("vty-thumb-{}.png", std::process::id()));
        let img = image::RgbImage::from_fn(8, 8, |x, y| {
            image::Rgb([(x * 20) as u8, (y * 20) as u8, 128])
        });
        img.save(&path).unwrap();

        let result = generate_thumb(&path).unwrap();
        let bytes = crate::runtime::protocol::base64_decode(&result.thumb_b64).unwrap();
        assert_eq!(&bytes[..3], &[0xFF, 0xD8, 0xFF]);
        assert!(bytes.len() > 32);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rgba_png_produces_jpeg_thumbnail() {
        /* GIF 解码结果同为 RGBA8：编码器必须先把 alpha 丢弃为 RGB8 才能成功 */
        let path = std::env::temp_dir().join(format!("vty-thumb-rgba-{}.png", std::process::id()));
        let img = image::RgbaImage::from_fn(8, 8, |x, y| {
            image::Rgba([(x * 20) as u8, (y * 20) as u8, 128, (x * 30) as u8])
        });
        img.save(&path).unwrap();

        let result = generate_thumb(&path).unwrap();
        let bytes = crate::runtime::protocol::base64_decode(&result.thumb_b64).unwrap();
        assert_eq!(&bytes[..3], &[0xFF, 0xD8, 0xFF]);
        assert!(bytes.len() > 32);

        let _ = std::fs::remove_file(path);
    }

    fn write_jpeg(name: &str, width: u32, height: u32) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vty-jpeg-{}-{}-{}",
            std::process::id(),
            width,
            name
        ));
        let img = image::RgbImage::from_fn(width, height, |x, y| {
            image::Rgb([
                (x % 251) as u8,
                (y % 241) as u8,
                ((x * 3 + y * 5) % 239) as u8,
            ])
        });
        img.save(&path).unwrap();
        path
    }

    #[test]
    fn scaled_jpeg_decode_uses_reduced_resolution() {
        let path = write_jpeg("2000x1500.jpg", 2000, 1500);
        let scaled = decode_jpeg_scaled_path(&path, THUMB_MAX_SIDE).expect("应启用缩放解码");
        assert_eq!((scaled.width(), scaled.height()), (500, 375));

        let b64 = generate_thumb_b64(&path).unwrap();
        let bytes = crate::runtime::protocol::base64_decode(&b64).unwrap();
        let thumb = image::load_from_memory(&bytes).unwrap();
        assert!(thumb.width().max(thumb.height()) <= THUMB_MAX_SIDE);

        let medium = write_jpeg("800x600.jpg", 800, 600);
        let bytes = std::fs::read(&medium).unwrap();
        let half = decode_jpeg_scaled_bytes(&bytes, THUMB_MAX_SIDE).expect("800px 应走 1/2");
        assert_eq!((half.width(), half.height()), (400, 300));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(medium);
    }

    #[test]
    fn small_jpeg_skips_scaled_decode() {
        let path = write_jpeg("400x300.jpg", 400, 300);
        assert!(decode_jpeg_scaled_path(&path, THUMB_MAX_SIDE).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn jpeg_pixel_formats_fall_back_without_color_conversion() {
        assert!(jpeg_pixels_to_image(
            jpeg_decoder::PixelFormat::RGB24,
            1,
            1,
            vec![1, 2, 3]
        )
        .is_some());
        assert!(jpeg_pixels_to_image(
            jpeg_decoder::PixelFormat::L8,
            1,
            1,
            vec![7]
        )
        .is_some());
        assert!(jpeg_pixels_to_image(
            jpeg_decoder::PixelFormat::CMYK32,
            1,
            1,
            vec![0; 4]
        )
        .is_none());
        assert!(jpeg_pixels_to_image(
            jpeg_decoder::PixelFormat::L16,
            1,
            1,
            vec![0; 2]
        )
        .is_none());
    }

    fn exif_orientation_header(orientation: u16) -> Vec<u8> {
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"II");
        tiff.extend_from_slice(&42u16.to_le_bytes());
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x0112u16.to_le_bytes());
        tiff.extend_from_slice(&3u16.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&orientation.to_le_bytes());
        tiff.extend_from_slice(&0u16.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());

        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
        jpeg.extend_from_slice(&((2 + 6 + tiff.len()) as u16).to_be_bytes());
        jpeg.extend_from_slice(b"Exif\0\0");
        jpeg.extend_from_slice(&tiff);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        jpeg
    }

    #[test]
    fn exif_orientation_is_parsed_and_applied() {
        let head = exif_orientation_header(6);
        assert_eq!(parse_jpeg_orientation(&head), 6);

        let img = DynamicImage::ImageRgb8(RgbImage::from_fn(4, 2, |_, _| {
            image::Rgb([1, 2, 3])
        }));
        let rotated = apply_orientation(img, 6);
        assert_eq!((rotated.width(), rotated.height()), (2, 4));
    }

    /// 25MP 缩略图耗时对照；默认忽略，按需执行：
    /// `cargo test --offline bench_25mp_thumb -- --ignored --nocapture`
    #[test]
    #[ignore = "手动性能测量"]
    fn bench_25mp_thumb() {
        let path = std::env::temp_dir().join(format!(
            "vty-bench-25mp-{}.jpg",
            std::process::id()
        ));
        let img = image::RgbImage::from_fn(6000, 4000, |x, y| {
            image::Rgb([
                (x % 251) as u8,
                (y % 241) as u8,
                ((x * 7 + y * 13) % 239) as u8,
            ])
        });
        img.save(&path).unwrap();
        let file_bytes = std::fs::metadata(&path).unwrap().len();

        let started = std::time::Instant::now();
        let scaled_b64 = generate_thumb_b64(&path).unwrap();
        let scaled_ms = started.elapsed().as_millis();

        let started = std::time::Instant::now();
        let full = read_image(&path).unwrap();
        let full_b64 = encode_thumb_b64(&full).unwrap();
        let full_ms = started.elapsed().as_millis();

        println!(
            "[thumb-bench] file={} scaled_ms={} full_ms={} scaled_b64={} full_b64={}",
            file_bytes,
            scaled_ms,
            full_ms,
            scaled_b64.len(),
            full_b64.len()
        );
        assert!(!scaled_b64.is_empty());
        assert!(!full_b64.is_empty());
        let _ = std::fs::remove_file(path);
    }
}
