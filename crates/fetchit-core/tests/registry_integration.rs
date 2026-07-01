//! End-to-end checks that the default 0.1.0 handler set classifies and
//! renders representative inputs in the priority order documented in
//! `handlers/mod.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use fetchit_core::{Hint, RenderContext, RenderingContext, Rendition};

fn render(bytes: &[u8]) -> Rendition {
    default_registry()
        .render(
            Bytes::copy_from_slice(bytes),
            &Hint::default(),
            &RenderContext::default(),
        )
        .expect("default registry should always render something")
}

#[test]
fn envelope_beats_plain_json() {
    let env = br#"{"v":1,"meta":{"title":"t","lang":""},"content":"c"}"#;
    match render(env) {
        Rendition::EtchitEnvelope { title, content, .. } => {
            assert_eq!(title, "t");
            assert_eq!(content, "c");
        }
        other => panic!("envelope should win, got {other:?}"),
    }
}

#[test]
fn plain_json_renders_as_json_not_text() {
    let raw = br#"{"foo":"bar","n":42}"#;
    match render(raw) {
        Rendition::Json { value } => assert_eq!(value["n"], 42),
        other => panic!("plain JSON should be Rendition::Json, got {other:?}"),
    }
}

#[test]
fn png_magic_renders_as_image() {
    let mut data: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    data.extend_from_slice(b"...payload...");
    match render(&data) {
        Rendition::Image { mime, .. } => assert_eq!(mime, "image/png"),
        other => panic!("PNG should be Rendition::Image, got {other:?}"),
    }
}

#[test]
fn jpeg_magic_renders_as_image() {
    let data = [0xFFu8, 0xD8, 0xFF, 0xE0, b'p', b'a', b'd'];
    match render(&data) {
        Rendition::Image { mime, .. } => assert_eq!(mime, "image/jpeg"),
        other => panic!("JPEG should be Rendition::Image, got {other:?}"),
    }
}

#[test]
fn plain_text_renders_as_text() {
    let raw = b"hello, world\nthis is a paragraph\n";
    match render(raw) {
        Rendition::Text { body, .. } => assert!(body.starts_with("hello")),
        other => panic!("plain text should be Rendition::Text, got {other:?}"),
    }
}

#[test]
fn binary_falls_back_to_opaque() {
    let raw = [0x00u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
    match render(&raw) {
        Rendition::OpaqueBinary { mime, .. } => assert!(!mime.is_empty()),
        other => panic!("binary should fall back to OpaqueBinary, got {other:?}"),
    }
}

#[test]
fn pdf_falls_through_to_binary_handler_with_correct_mime() {
    // PDF is not a dedicated 0.1.0 handler — it falls through to
    // BinaryHandler, which uses `infer` to label it. Real PDFs are not
    // pure text (they contain compressed streams), so the text handler
    // is excluded by the embedded NUL.
    let mut pdf: Vec<u8> = b"%PDF-1.4\n".to_vec();
    pdf.extend_from_slice(b"1 0 obj\n<< /Length 5 >>\nstream\n");
    pdf.extend_from_slice(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    match render(&pdf) {
        Rendition::OpaqueBinary { mime, .. } => assert_eq!(mime, "application/pdf"),
        other => panic!("expected OpaqueBinary with PDF MIME, got {other:?}"),
    }
}

#[test]
fn mp3_magic_renders_as_audio() {
    let mut data = b"ID3\x03\x00\x00\x00\x00\x00\x0A".to_vec();
    data.extend_from_slice(&[0u8; 16]);
    match render(&data) {
        Rendition::Audio { mime, .. } => assert_eq!(mime, "audio/mpeg"),
        other => panic!("ID3 audio should be Rendition::Audio, got {other:?}"),
    }
}

#[test]
fn mp4_ftyp_renders_as_video() {
    // 24-byte ftyp box, brand `isom` — a plain MP4. Also confirms the
    // image handler (registered first) doesn't claim a video ftyp brand.
    let mut data = vec![0u8, 0, 0, 0x18];
    data.extend_from_slice(b"ftypisom");
    data.extend_from_slice(&[0u8; 12]);
    match render(&data) {
        Rendition::Video { mime, .. } => assert_eq!(mime, "video/mp4"),
        other => panic!("MP4 ftyp should be Rendition::Video, got {other:?}"),
    }
}

#[test]
fn html_document_renders_as_html_not_text() {
    let raw = b"<!DOCTYPE html>\n<html><body>hi</body></html>";
    match render(raw) {
        Rendition::Html { body } => assert!(body.contains("<body>")),
        other => panic!("an HTML document should win over text, got {other:?}"),
    }
}

#[test]
fn csv_renders_as_tabular_not_text() {
    let raw = b"name,age,city\nalice,30,nyc\nbob,25,la\ncarol,40,sf\n";
    match render(raw) {
        Rendition::Tabular { columns, rows } => {
            assert_eq!(columns.len(), 3);
            assert_eq!(rows.len(), 3);
        }
        other => panic!("CSV should win over text, got {other:?}"),
    }
}

#[test]
fn markdown_renders_as_text_tagged_markdown() {
    let raw = b"# heading\n\nsome body text under it.\n";
    match render(raw) {
        Rendition::Text { language, .. } => {
            assert_eq!(language, Some("markdown".to_owned()));
        }
        other => panic!("markdown should be Text tagged markdown, got {other:?}"),
    }
}

#[test]
fn zip_renders_as_archive() {
    // A 22-byte end-of-central-directory record — a valid, empty ZIP.
    let empty_zip: [u8; 22] = [
        0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    match render(&empty_zip) {
        Rendition::Archive { entries } => assert!(entries.is_empty()),
        other => panic!("a ZIP should be Rendition::Archive, got {other:?}"),
    }
}

/// M3 F3 — `render_with_context` short-circuits to `Rendition::Blocked`
/// when the denylist matches the address, otherwise passes through to
/// the existing renderer set.
#[test]
fn render_with_context_blocked_xorname_short_circuits_default_registry() {
    struct Block(&'static str);
    impl fetchit_trust_types::DenylistQuery for Block {
        fn is_blocked(&self, kind: fetchit_trust_types::EntryKind, value: &str) -> bool {
            kind == fetchit_trust_types::EntryKind::XorName && value == self.0
        }
    }
    let reg = default_registry();
    let blocked_hex = "abcd".repeat(16);
    let rctx = RenderingContext {
        denylist: Some(Arc::new(Block(Box::leak(
            blocked_hex.clone().into_boxed_str(),
        )))),
        addr_hex: Some(blocked_hex.clone()),
    };
    // A payload that WOULD render as text/json/etc. on the bare render
    // path. The blocked short-circuit must beat the handler dispatch.
    let payload = br#"{"foo":"bar"}"#;
    let r = reg
        .render_with_context(
            Bytes::copy_from_slice(payload),
            &Hint::default(),
            &RenderContext::default(),
            &rctx,
        )
        .expect("blocked short-circuit returns Ok(Blocked)");
    match r {
        Rendition::Blocked { reason } => {
            assert!(reason.starts_with("xor_name:"), "reason = {reason}");
            assert!(reason.contains(&blocked_hex), "reason = {reason}");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

/// M3 F3 — when no denylist is supplied, the default registry behaves
/// exactly as `render` did before M3. This pins the back-compat
/// contract for offline / test callers that never wire a consumer.
#[test]
fn render_with_context_without_denylist_renders_as_before() {
    let reg = default_registry();
    let payload = br#"{"foo":"bar"}"#;
    let rctx = RenderingContext::default();
    let r = reg
        .render_with_context(
            Bytes::copy_from_slice(payload),
            &Hint::default(),
            &RenderContext::default(),
            &rctx,
        )
        .expect("no-denylist path must match render() behaviour");
    match r {
        Rendition::Json { value } => assert_eq!(value["foo"], "bar"),
        other => panic!("default-context JSON should be Rendition::Json, got {other:?}"),
    }
}
