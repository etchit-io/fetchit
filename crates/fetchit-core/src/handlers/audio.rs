//! Audio handler. Detects MP3, WAV, FLAC, and OGG by magic bytes and
//! emits [`Rendition::Audio`] tagged with the right MIME so UI shells
//! can hand bytes straight to a platform decoder.
//!
//! Decoding to PCM is intentionally not done here — the platform's
//! audio pipeline (Media3 / ExoPlayer on the Android app, the browser
//! `<audio>` element for HTML renditions, whatever the `fetchit` CLI
//! plays through) accepts the encoded bytes directly.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::Result;

/// Recognises common encoded audio formats.
#[derive(Debug, Default, Clone, Copy)]
pub struct AudioHandler;

const KIND: &str = "audio/*";

const ID3V2_MAGIC: &[u8] = b"ID3";
const FLAC_MAGIC: &[u8] = b"fLaC";
const OGG_MAGIC: &[u8] = b"OggS";
const RIFF_MAGIC: &[u8] = b"RIFF";
const WAVE_MARKER: &[u8] = b"WAVE";

/// Detect a raw MP3 frame sync word: 11 set bits at the start of a
/// frame (`0xFF`, then upper three bits of byte 1 set). Covers MPEG
/// 1/2/2.5 layer I/II/III headers.
fn looks_like_mp3_frame(head: &[u8]) -> bool {
    head.len() >= 2 && head[0] == 0xFF && (head[1] & 0xE0) == 0xE0
}

fn detect_mime(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(ID3V2_MAGIC) || looks_like_mp3_frame(head) {
        return Some("audio/mpeg");
    }
    if head.starts_with(FLAC_MAGIC) {
        return Some("audio/flac");
    }
    if head.starts_with(OGG_MAGIC) {
        return Some("audio/ogg");
    }
    if head.starts_with(RIFF_MAGIC) && head.len() >= 12 && &head[8..12] == WAVE_MARKER {
        return Some("audio/wav");
    }
    None
}

impl ContentHandler for AudioHandler {
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
        Ok(Rendition::Audio { mime, data: bytes })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(bytes: &[u8]) -> Confidence {
        AudioHandler.can_handle(bytes, &Hint::default())
    }

    fn render(bytes: &[u8]) -> Rendition {
        AudioHandler
            .render(Bytes::copy_from_slice(bytes), &RenderContext::default())
            .expect("audio handler should not error")
    }

    #[test]
    fn claims_id3v2_mp3() {
        let mut data = b"ID3\x03\x00\x00\x00\x00\x00\x0A".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Audio { mime, .. } => assert_eq!(mime, "audio/mpeg"),
            other => panic!("expected Audio, got {other:?}"),
        }
    }

    #[test]
    fn claims_raw_mp3_frame_sync() {
        let data = [0xFFu8, 0xFB, 0x90, 0x40, 0x00, 0x00];
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Audio { mime, .. } => assert_eq!(mime, "audio/mpeg"),
            other => panic!("expected Audio, got {other:?}"),
        }
    }

    #[test]
    fn claims_flac() {
        let mut data = b"fLaC".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Audio { mime, .. } => assert_eq!(mime, "audio/flac"),
            other => panic!("expected Audio, got {other:?}"),
        }
    }

    #[test]
    fn claims_ogg() {
        let mut data = b"OggS".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Audio { mime, .. } => assert_eq!(mime, "audio/ogg"),
            other => panic!("expected Audio, got {other:?}"),
        }
    }

    #[test]
    fn claims_wav() {
        let mut data = b"RIFF\x00\x00\x00\x00WAVE".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::Definite);
        match render(&data) {
            Rendition::Audio { mime, .. } => assert_eq!(mime, "audio/wav"),
            other => panic!("expected Audio, got {other:?}"),
        }
    }

    #[test]
    fn rejects_riff_without_wave() {
        // RIFF with non-WAVE form (e.g. AVI). Should not claim.
        let mut data = b"RIFF\x00\x00\x00\x00AVI ".to_vec();
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(confidence(&data), Confidence::None);
    }

    #[test]
    fn rejects_partial_id3() {
        assert_eq!(confidence(b"ID"), Confidence::None);
    }

    #[test]
    fn rejects_image_magic() {
        assert_eq!(
            confidence(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Confidence::None
        );
    }

    #[test]
    fn rejects_text() {
        assert_eq!(confidence(b"hello world"), Confidence::None);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(b""), Confidence::None);
    }
}
