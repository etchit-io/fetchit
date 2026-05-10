//! End-to-end checks that the default 0.1.0 handler set classifies and
//! renders representative inputs in the priority order documented in
//! `handlers/mod.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use fetchit_core::{Hint, RenderContext, Rendition};

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
