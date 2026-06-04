//! M2.5 bridge **hermetic shadow** — pins the bridge wrap/unseal
//! contract against a real x0xd-produced `MemberJoined` event
//! captured from the wyse21 close-gate run.
//!
//! # What this exercises
//!
//! The fixture at `tests/fixtures/m2_5_member_joined_wyse21.bin` is the
//! exact JSON-event bytes x0xd 0.21.0 publishes on a `/groups/join`
//! flow — captured live on wyse21 against group
//! `5ffbb3c93daea2e6…` and shipped end-to-end to wyse37 in the M2.5
//! close-gate PASS. This file pins:
//!
//! - [`build_bridge_outbox`] produces a `TransitEnvelope` with
//!   `kind == EnvelopeKind::X0xdGroupMetadataEvent`.
//! - The sealed wrapper round-trips byte-for-byte through
//!   [`unseal_bridge_wrapper`] — the captured x0xd bytes survive the
//!   PQ seal (`ML-KEM-768` encapsulation + AEAD seal) intact.
//! - The recipient field on the envelope matches what the relay's
//!   `sender_agent_id` predicate will route on.
//! - The wrapper's `topic` round-trips identically.
//!
//! # What it does NOT exercise
//!
//! The peer-side **apply** (`apply_named_group_metadata_event` on the
//! receiver's x0xd) runs inside x0xd itself; the M2.5 live test
//! (`tests/m2_5_bridge.rs::m2_5_bridge_live_member_joined_applies_on_peer`)
//! is the empirical proof that these exact bytes apply cleanly on a
//! real peer — captured in the close-gate PASS that produced this
//! fixture. The shadow test guards regressions in the **send wire
//! path** without needing the live wyse rig every time.
//!
//! # Regenerating the fixture
//!
//! Run `tests/m2_5_bridge.rs::m2_5_bridge_live_member_joined_applies_on_peer`
//! with `M2_5_BRIDGE_DUMP_BYTES=<path>` set (see the live test's
//! docstring for the full env-var contract). A single live capture
//! produces one fixture; re-running this hermetic test against the
//! checked-in fixture is the standing regression guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use fetchit_chat::chat_crypto::kem_keygen;
use fetchit_chat::groups::bridge::{
    build_bridge_outbox, unseal_bridge_wrapper, X0xdGroupMetadataEventWrapper,
};
use fetchit_relay_client::StaticKeySigner;
use fetchit_relay_proto::EnvelopeKind;
use std::sync::Arc;

/// Read the captured signed `MemberJoined` JSON event bytes. The path
/// is resolved against `CARGO_MANIFEST_DIR` so the test stays correct
/// regardless of where cargo is invoked from.
fn read_fixture() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/m2_5_member_joined_wyse21.bin");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

/// Pin the M2.5 bridge wrap → unseal roundtrip against the wyse21
/// fixture. The signed event bytes go through the production
/// [`build_bridge_outbox`] (ML-KEM-768 + AEAD seal + ML-DSA-65 sign)
/// and come back out via [`unseal_bridge_wrapper`] byte-identical to
/// what we put in.
///
/// Regression surface this guards:
/// - `EnvelopeKind::X0xdGroupMetadataEvent` discriminator stays stable
///   on the wire (the relay's forward-compat shim relies on this).
/// - The bridge wrapper's `(topic, payload_b64)` postcard layout.
/// - The PQ KEM/AEAD path correctly seals + opens the captured bytes.
/// - Recipient + topic fields survive the round-trip identically.
#[tokio::test]
async fn shadow_wyse21_member_joined_round_trips_through_bridge() {
    let signed_event_bytes = read_fixture();
    assert!(
        signed_event_bytes.len() > 1000,
        "fixture should be a real x0xd event (~23 KiB); got {} bytes",
        signed_event_bytes.len(),
    );

    // Parse to pull the real group_id out so the test stays pinned to
    // whatever's actually in the fixture (no drift if the fixture is
    // regenerated against a different group).
    let parsed: serde_json::Value =
        serde_json::from_slice(&signed_event_bytes).expect("fixture is JSON");
    let group_id_str = parsed
        .get("group_id")
        .and_then(|v| v.as_str())
        .expect("fixture has group_id");
    let member_agent_hex = parsed
        .get("member_agent_id")
        .and_then(|v| v.as_str())
        .expect("fixture has member_agent_id");
    assert_eq!(group_id_str.len(), 64, "group_id is 64-hex");
    assert_eq!(member_agent_hex.len(), 64, "member_agent_id is 64-hex");

    // Generate an ephemeral recipient KEM keypair. The fixture is
    // public test data; there's no privacy concern about whose key it
    // gets sealed to. We just need a valid keypair so the round-trip
    // is exercised against real ML-KEM-768.
    let (recipient_kem_pub, recipient_kem_sec) = kem_keygen().expect("ML-KEM-768 keypair");

    let recipient_agent_id = [0x42u8; 32];
    let local_agent_id = [0x11u8; 32];
    let local_machine_id = [0x22u8; 32];

    // Static signer (no x0xd / no daemon) — its sign() returns a
    // deterministic test signature. The envelope shape is what we
    // pin; ML-DSA-65 verification is exercised by the live test.
    let signer = Arc::new(StaticKeySigner::from_public_key(
        b"shadow-test-signer".to_vec(),
    ));

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&signed_event_bytes);

    // Use a representative topic shape — matches what x0xd's
    // `metadata_topic` returns for this group.
    let short_gid = &group_id_str[..16];
    let topic = format!("x0x.group.{short_gid}.meta");

    let outbound = build_bridge_outbox(
        &recipient_agent_id,
        &recipient_kem_pub,
        topic.clone(),
        payload_b64.clone(),
        &local_agent_id,
        &local_machine_id,
        signer.as_ref(),
    )
    .await
    .expect("build_bridge_outbox against fixture must succeed");

    // ── Envelope shape pins ──────────────────────────────────────────
    assert_eq!(
        outbound.envelope.kind,
        EnvelopeKind::X0xdGroupMetadataEvent,
        "bridge envelope kind must be X0xdGroupMetadataEvent (the \
         forward-compat shim at dcc4d53 relies on this discriminator)",
    );
    assert_eq!(
        outbound.recipient_agent_id.as_bytes(),
        &recipient_agent_id,
        "recipient field must propagate verbatim — the relay routes \
         on this",
    );
    assert_eq!(
        outbound.envelope.sender_agent_id.as_bytes(),
        &local_agent_id,
        "sender field must match the bound identity — the relay \
         bearer-token check enforces this",
    );
    assert!(
        !outbound.envelope.ciphertext.is_empty(),
        "AEAD ciphertext must be populated",
    );
    assert!(
        !outbound.envelope.kem_ciphertext.is_empty(),
        "ML-KEM-768 ciphertext must be populated",
    );
    assert!(
        !outbound.envelope.nonce.is_empty(),
        "AEAD nonce must be populated",
    );
    assert!(
        !outbound.envelope.sender_signature.is_empty(),
        "sender signature must be populated",
    );

    // ── Round-trip pin: bytes survive the seal ───────────────────────
    let wrapper = unseal_bridge_wrapper(
        &recipient_kem_sec,
        &outbound.envelope.kem_ciphertext,
        &outbound.envelope.nonce,
        &outbound.envelope.ciphertext,
    )
    .expect("unseal_bridge_wrapper against our own seal must succeed");

    assert_eq!(wrapper.topic, topic, "topic round-trips unchanged");
    assert_eq!(
        wrapper.payload_b64, payload_b64,
        "base64 payload round-trips unchanged",
    );

    // Final byte-equality on the actual signed-event bytes — the
    // canonical proof that what x0xd published survives the bridge
    // intact.
    let recovered = base64::engine::general_purpose::STANDARD
        .decode(&wrapper.payload_b64)
        .expect("payload decodes from base64");
    assert_eq!(
        recovered, signed_event_bytes,
        "captured x0xd bytes survive the bridge byte-identical",
    );
}

/// Tampering with the AEAD ciphertext must fail the unseal — pins
/// that the seal is integrity-protected end-to-end, not just
/// confidential.
#[tokio::test]
async fn shadow_tampered_ciphertext_fails_unseal() {
    let signed_event_bytes = read_fixture();
    let (recipient_kem_pub, recipient_kem_sec) = kem_keygen().expect("ML-KEM-768 keypair");
    let signer = Arc::new(StaticKeySigner::from_public_key(
        b"shadow-test-signer".to_vec(),
    ));

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&signed_event_bytes);

    let mut outbound = build_bridge_outbox(
        &[0x42; 32],
        &recipient_kem_pub,
        "x0x.group.shadow.meta".to_owned(),
        payload_b64,
        &[0x11; 32],
        &[0x22; 32],
        signer.as_ref(),
    )
    .await
    .expect("build_bridge_outbox");

    // Flip one byte deep inside the AEAD ciphertext. The seal must
    // detect it.
    let mid = outbound.envelope.ciphertext.len() / 2;
    outbound.envelope.ciphertext[mid] ^= 0x01;

    let err = unseal_bridge_wrapper(
        &recipient_kem_sec,
        &outbound.envelope.kem_ciphertext,
        &outbound.envelope.nonce,
        &outbound.envelope.ciphertext,
    )
    .expect_err("tampered ciphertext must fail aead-open");
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("aead") || msg.to_lowercase().contains("open"),
        "tampered-unseal error should mention AEAD/open: {msg}",
    );
}

/// Postcard-roundtripping the inner wrapper is the existing unit-test
/// surface in `groups::bridge`; here we additionally pin that a real
/// `X0xdGroupMetadataEventWrapper` carrying the fixture bytes
/// postcard-encodes to a stable shape that decodes back identically.
/// The wrapper format is the apply-side contract — if it changes,
/// receivers crash on `/publish` decoding.
#[test]
fn shadow_fixture_wrapper_postcard_roundtrip() {
    let signed_event_bytes = read_fixture();
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&signed_event_bytes);

    let wrapper = X0xdGroupMetadataEventWrapper {
        topic: "x0x.group.5ffbb3c93daea2e6.meta".to_owned(),
        payload_b64: payload_b64.clone(),
    };
    let bytes = wrapper.to_postcard().expect("postcard encode");
    let decoded = X0xdGroupMetadataEventWrapper::from_postcard(&bytes).expect("postcard decode");
    assert_eq!(decoded.topic, wrapper.topic);
    assert_eq!(decoded.payload_b64, payload_b64);
}
