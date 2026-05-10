//! Unified image handler. Recognises PNG, JPEG, GIF, WEBP, BMP, and
//! HEIC by magic bytes and passes raw encoded bytes through tagged
//! with the right MIME — UI layers hand them straight to a platform
//! image decoder (`BitmapFactory` on Android, `<img>` on the web,
//! `image` crate via `infer` everywhere else).
//!
//! HEIC sits inside an ISO BMFF container (the same family as MP4),
//! so this handler must register **before** the video handler — both
//! formats answer "yes" to the leading `ftyp` magic; the brand at
//! bytes 8-11 disambiguates.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::Result;

/// Recognises PNG / JPEG / GIF / WEBP / BMP / HEIC by magic bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImageHandler;

const KIND: &str = "image/*";

const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
const GIF_MAGIC_87A: &[u8] = b"GIF87a";
const GIF_MAGIC_89A: &[u8] = b"GIF89a";
const BMP_MAGIC: &[u8] = b"BM";

/// Detect a recognised image MIME from the leading bytes. Returns
/// `None` when no signature matches.
fn detect_mime(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(PNG_MAGIC) {
        return Some("image/png");
    }
    if head.starts_with(JPEG_MAGIC) {
        return Some("image/jpeg");
    }
    if head.starts_with(GIF_MAGIC_87A) || head.starts_with(GIF_MAGIC_89A) {
        return Some("image/gif");
    }
    if head.len() >= 12 && head.starts_with(b"RIFF") && &head[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if head.starts_with(BMP_MAGIC) {
        return Some("image/bmp");
    }
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        // ISO BMFF brand — the four bytes after `ftyp` decide whether
        // this is an HEIF/HEIC image or a video container. We claim
        // only the image-shaped brands; everything else falls through
        // to VideoHandler.
        let brand = &head[8..12];
        if matches!(brand, b"heic" | b"heix" | b"hevc" | b"hevx" | b"mif1" | b"msf1") {
            return Some("image/heic");
        }
    }
    None
}

impl ContentHandler for ImageHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        if detect_mime(head).is_some() {
            Confidence::Definite
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let mime = detect_mime(&bytes[..bytes.len().min(64)])
            .unwrap_or("application/octet-stream")
            .to_owned();
        Ok(Rendition::Image { mime, data: bytes })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(bytes: &[u8]) -> Confidence {
        ImageHandler.can_handle(bytes, &Hint::default())
    }

    fn render(bytes: &[u8]) -> Rendition {
        ImageHandler
            .render(Bytes::copy_from_slice(bytes), &RenderContext::default())
            .expect("image handler should not error")
    }

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0u8, 0, 0, 0x18];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0u8; 12]);
        data
    }

    #[test]
    fn claims_png() {
        let mut data = PNG_MAGIC.to_vec();
        data.extend_from_slice(b"...payload...");
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Image { mime, .. } => assert_eq!(mime, "image/png"),
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn claims_jpeg() {
        let data = [0xFFu8, 0xD8, 0xFF, 0xE0, b'p', b'a', b'd'];
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Image { mime, .. } => assert_eq!(mime, "image/jpeg"),
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn claims_gif87a() {
        let mut data = b"GIF87a".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Image { mime, .. } => assert_eq!(mime, "image/gif"),
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn claims_gif89a() {
        let mut data = b"GIF89a".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
    }

    #[test]
    fn claims_webp() {
        let mut data = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Image { mime, .. } => assert_eq!(mime, "image/webp"),
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn claims_bmp() {
        let mut data = b"BM".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
    }

    #[test]
    fn claims_heic() {
        let data = ftyp(b"heic");
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Image { mime, .. } => assert_eq!(mime, "image/heic"),
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn claims_mif1_heif() {
        let data = ftyp(b"mif1");
        assert_eq!(confidence(&data), Confidence::Definite);
    }

    #[test]
    fn rejects_mp4_ftyp() {
        // Plain MP4 brand must NOT be claimed — VideoHandler runs after.
        let data = ftyp(b"isom");
        assert_eq!(confidence(&data), Confidence::None);
    }

    #[test]
    fn rejects_riff_wave() {
        let mut data = b"RIFF\x00\x00\x00\x00WAVE".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::None);
    }

    #[test]
    fn rejects_text() {
        assert_eq!(confidence(b"hello world"), Confidence::None);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(b""), Confidence::None);
    }

    #[test]
    fn rejects_partial_png_magic() {
        assert_eq!(confidence(&PNG_MAGIC[..6]), Confidence::None);
    }
}
