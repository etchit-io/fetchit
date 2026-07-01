//! End-to-end mock-network integration. Exercises the two halves of
//! `fetchit-core` the way a UI shell composes them: an [`Address`] is
//! resolved to bytes through a [`NetworkClient`], then those bytes are
//! classified by the default [`HandlerRegistry`](fetchit_core::HandlerRegistry).
//!
//! The fetch side uses [`MockClient`] — no real Autonomi connection —
//! so the test is free and instant. The classification side is the
//! production `default_registry()`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use fetchit_core::network::MockClient;
use fetchit_core::{Address, Error, Hint, NetworkClient, RenderContext, Rendition};

/// A 64-hex-char [`Address`] built by repeating one hex digit.
fn addr(digit: char) -> Address {
    digit
        .to_string()
        .repeat(64)
        .parse()
        .expect("64 hex chars is a valid address")
}

/// Fetch `a` through `client`, then classify the bytes — the full
/// fetch path a surface layer runs once connected.
async fn fetch_and_render(
    client: &dyn NetworkClient,
    a: &Address,
) -> fetchit_core::Result<Rendition> {
    let bytes = client.fetch(a).await?;
    default_registry().render(bytes, &Hint::default(), &RenderContext::default())
}

#[tokio::test]
async fn fetches_and_classifies_json() {
    let client = MockClient::new();
    let a = addr('a');
    client.insert(a, Bytes::from_static(br#"{"n":42}"#));
    match fetch_and_render(&client, &a).await.expect("pipeline") {
        Rendition::Json { value } => assert_eq!(value["n"], 42),
        other => panic!("expected Json, got {other:?}"),
    }
}

#[tokio::test]
async fn fetches_and_classifies_image() {
    let client = MockClient::new();
    let a = addr('b');
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend_from_slice(b"payload");
    client.insert(a, Bytes::from(png));
    match fetch_and_render(&client, &a).await.expect("pipeline") {
        Rendition::Image { mime, .. } => assert_eq!(mime, "image/png"),
        other => panic!("expected Image, got {other:?}"),
    }
}

#[tokio::test]
async fn fetches_and_classifies_text() {
    let client = MockClient::new();
    let a = addr('c');
    client.insert(a, Bytes::from_static(b"just some plain prose.\n"));
    match fetch_and_render(&client, &a).await.expect("pipeline") {
        Rendition::Text { .. } => {}
        other => panic!("expected Text, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_address_surfaces_a_network_error() {
    let client = MockClient::new();
    // Nothing inserted — the fetch half must fail, and the error must
    // reach the caller rather than being swallowed by the render half.
    let err = fetch_and_render(&client, &addr('d'))
        .await
        .expect_err("an un-inserted address should fail");
    assert!(matches!(err, Error::Network(_)));
}

#[tokio::test]
async fn distinct_addresses_resolve_independently() {
    let client = MockClient::new();
    let (json_at, text_at) = (addr('e'), addr('f'));
    client.insert(json_at, Bytes::from_static(br#"{"k":1}"#));
    client.insert(text_at, Bytes::from_static(b"plain words here.\n"));
    assert!(matches!(
        fetch_and_render(&client, &json_at).await.expect("json"),
        Rendition::Json { .. }
    ));
    assert!(matches!(
        fetch_and_render(&client, &text_at).await.expect("text"),
        Rendition::Text { .. }
    ));
}
