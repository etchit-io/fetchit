//! Registry-level integration: `saorsa-mls/v1` envelopes route to the
//! MLS-envelope handler ahead of the text-family handlers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use fetchit_core::{Hint, RenderContext, Rendition};

#[test]
fn registry_routes_mls_envelope_to_encrypted_envelope() {
    let fixture = b"saorsa-mls/v1\ngroup=reading-club\n\n\x01\x02\x03";
    let rendition = default_registry()
        .render(
            Bytes::copy_from_slice(fixture),
            &Hint::default(),
            &RenderContext::default(),
        )
        .unwrap();
    match rendition {
        Rendition::EncryptedEnvelope {
            group_hint,
            ciphertext_len,
        } => {
            assert_eq!(group_hint.as_deref(), Some("reading-club"));
            assert_eq!(ciphertext_len, 3);
        }
        other => panic!("expected EncryptedEnvelope, got {other:?}"),
    }
}

#[test]
fn plain_text_mentioning_the_magic_mid_body_stays_text() {
    let fixture = b"notes about the saorsa-mls/v1 format follow below";
    let rendition = default_registry()
        .render(
            Bytes::copy_from_slice(fixture),
            &Hint::default(),
            &RenderContext::default(),
        )
        .unwrap();
    assert!(matches!(rendition, Rendition::Text { .. }));
}
