//! Video handler. Detects ISO BMFF containers (MP4 / MOV / M4V),
//! EBML (`WebM` / MKV), and RIFF/AVI by their magic bytes. Emits
//! [`Rendition::Video`] tagged with a MIME so UI shells can hand the
//! bytes straight to a platform decoder (Android `MediaPlayer` /
//! `Media3` `ExoPlayer`, browser `<video>` element, desktop player, etc.).
//!
//! Decoding is intentionally not done here — the platform players
//! handle raw container bytes natively.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::Result;

/// Recognises common video container formats.
#[derive(Debug, Default, Clone, Copy)]
pub struct VideoHandler;

const KIND: &str = "video/*";

const EBML_MAGIC: &[u8] = &[0x1A, 0x45, 0xDF, 0xA3];

/// Sniff the leading bytes for a video container signature. Returns a
/// concrete IANA MIME on match, `None` otherwise.
fn detect_mime(head: &[u8]) -> Option<&'static str> {
    // ISO Base Media File Format: 4-byte size, then `ftyp` at offset
    // 4. Covers MP4, MOV, M4V, M4A — same container, different brands.
    // We hand all of them off to the platform player; if there's no
    // video track it gracefully plays as audio-only.
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        return Some("video/mp4");
    }
    // EBML — WebM and MKV share this header. Don't bother distinguishing;
    // platform players accept either via the same MIME.
    if head.starts_with(EBML_MAGIC) {
        return Some("video/webm");
    }
    // RIFF/AVI: `RIFF<size>AVI `.
    if head.len() >= 12 && head.starts_with(b"RIFF") && &head[8..12] == b"AVI " {
        return Some("video/x-msvideo");
    }
    None
}

impl ContentHandler for VideoHandler {
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
        Ok(Rendition::Video { mime, data: bytes })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(bytes: &[u8]) -> Confidence {
        VideoHandler.can_handle(bytes, &Hint::default())
    }

    fn render(bytes: &[u8]) -> Rendition {
        VideoHandler
            .render(Bytes::copy_from_slice(bytes), &RenderContext::default())
            .expect("video handler should not error")
    }

    fn ftyp(brand: [u8; 4]) -> Vec<u8> {
        let mut data = vec![0u8, 0, 0, 0x18]; // 24-byte ftyp box
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(&brand);
        data.extend_from_slice(&[0u8; 12]);
        data
    }

    #[test]
    fn claims_mp4_isom() {
        let data = ftyp(*b"isom");
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Video { mime, .. } => assert_eq!(mime, "video/mp4"),
            other => panic!("expected Video, got {other:?}"),
        }
    }

    #[test]
    fn claims_mp4_mp42() {
        let data = ftyp(*b"mp42");
        assert_eq!(confidence(&data), Confidence::Definite);
    }

    #[test]
    fn claims_mov() {
        let data = ftyp(*b"qt  ");
        assert_eq!(confidence(&data), Confidence::Definite);
    }

    #[test]
    fn claims_m4v() {
        let data = ftyp(*b"M4V ");
        assert_eq!(confidence(&data), Confidence::Definite);
    }

    #[test]
    fn claims_webm() {
        let mut data = EBML_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Video { mime, .. } => assert_eq!(mime, "video/webm"),
            other => panic!("expected Video, got {other:?}"),
        }
    }

    #[test]
    fn claims_avi() {
        let mut data = b"RIFF\x00\x00\x00\x00AVI ".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Video { mime, .. } => assert_eq!(mime, "video/x-msvideo"),
            other => panic!("expected Video, got {other:?}"),
        }
    }

    #[test]
    fn rejects_riff_wave() {
        // RIFF/WAVE is audio, not video — must not be claimed here.
        let mut data = b"RIFF\x00\x00\x00\x00WAVE".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::None);
    }

    #[test]
    fn rejects_partial_ftyp() {
        assert_eq!(confidence(b"\x00\x00\x00\x18ftyp"), Confidence::None);
    }

    #[test]
    fn rejects_png() {
        assert_eq!(
            confidence(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Confidence::None,
        );
    }

    #[test]
    fn rejects_text() {
        assert_eq!(confidence(b"hello world hello world"), Confidence::None);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(b""), Confidence::None);
    }
}
