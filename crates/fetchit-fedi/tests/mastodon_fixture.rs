//! Integration tests for `Actor::from_json_ld` against a vendored
//! Mastodon-shape fixture.
//!
//! The fixture under `tests/fixtures/gargron_actor.json` mirrors what
//! a real `application/activity+json` Mastodon Actor looks like —
//! full `@context` array (`activitystreams` + `security/v1` + a custom
//! prefix block), real-world publication metadata, plus a `publicKey`
//! with a synthetic SPKI PEM. It also carries the FROZEN
//! [`fetchit_fedi::actor::PQ_ATTESTATION_PROPERTY_URI`] key so the
//! decoder picks our PQ attestation up.
//!
//! Many Mastodon-evolution keys (`manuallyApprovesFollowers`,
//! `summary`, `attachment`, `endpoints`, etc.) are present and MUST
//! be ignored by the decoder without error — that is the forward-
//! compat-with-Mastodon-evolution discipline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_fedi::actor::{Actor, PQ_ATTESTATION_PROPERTY_URI};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/gargron_actor.json");

#[test]
fn fixture_parses_to_actor() {
    let raw: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let actor = Actor::from_json_ld(&raw).expect("Actor decode");

    assert_eq!(actor.id.as_str(), "https://mastodon.example/users/gargron");
    assert_eq!(actor.preferred_username, "gargron");
    assert_eq!(
        actor.inbox.as_str(),
        "https://mastodon.example/users/gargron/inbox"
    );
    assert_eq!(
        actor.outbox.as_str(),
        "https://mastodon.example/users/gargron/outbox"
    );
    assert!(actor
        .rsa_public_key_pem
        .starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(actor
        .rsa_public_key_pem
        .ends_with("-----END PUBLIC KEY-----\n"));
    assert!(!actor.ml_dsa_attestation.ml_dsa_pubkey.is_empty());
    assert!(!actor.ml_dsa_attestation.signature.is_empty());
}

#[test]
fn fixture_round_trips_parse_emit_parse() {
    // The discipline Alice asked for: parse the fixture, re-emit the
    // canonical shape, parse again, assert the two decoded `Actor`s
    // are equal. Catches lossy round-trips (e.g. decoder ignores a
    // key but emitter produces it, or vice versa).
    let raw: Value = serde_json::from_str(FIXTURE).unwrap();
    let first = Actor::from_json_ld(&raw).unwrap();
    let reemitted = first.to_json_ld();
    let second = Actor::from_json_ld(&reemitted).unwrap();
    assert_eq!(first, second);
}

#[test]
fn fixture_decoder_ignores_mastodon_evolution_keys() {
    // The fixture carries plenty of keys the decoder doesn't care
    // about — `summary`, `attachment`, `featured`, `endpoints`,
    // `discoverable`, etc. Verify the decode succeeds and the parsed
    // Actor doesn't accidentally surface them as missing-field
    // errors.
    let raw: Value = serde_json::from_str(FIXTURE).unwrap();
    assert!(raw.get("summary").is_some(), "fixture sanity: summary key");
    assert!(
        raw.get("manuallyApprovesFollowers").is_some(),
        "fixture sanity: manuallyApprovesFollowers"
    );
    assert!(
        raw.get("attachment").is_some(),
        "fixture sanity: attachment"
    );
    Actor::from_json_ld(&raw).expect("decode tolerates Mastodon-evolution keys");
}

#[test]
fn missing_required_field_surfaces_error() {
    // Strip the `inbox` field and confirm the decoder rejects the
    // document with the right error variant.
    let mut raw: Value = serde_json::from_str(FIXTURE).unwrap();
    raw.as_object_mut().unwrap().remove("inbox");
    let err = Actor::from_json_ld(&raw).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("inbox"), "expected inbox in error; got: {msg}");
}

#[test]
fn missing_pq_attestation_surfaces_error() {
    // Strip the FROZEN PQ URI key and confirm the decoder rejects the
    // document with a missing-field error naming that URI.
    let mut raw: Value = serde_json::from_str(FIXTURE).unwrap();
    raw.as_object_mut()
        .unwrap()
        .remove(PQ_ATTESTATION_PROPERTY_URI);
    let err = Actor::from_json_ld(&raw).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("mlDsaAttestation-v1"),
        "expected PQ URI in error; got: {msg}"
    );
}

#[test]
fn malformed_attestation_value_surfaces_error() {
    // Replace the attestation object with garbage and confirm decode
    // surfaces ActorError::Attestation.
    let mut raw: Value = serde_json::from_str(FIXTURE).unwrap();
    raw.as_object_mut().unwrap().insert(
        PQ_ATTESTATION_PROPERTY_URI.into(),
        serde_json::json!("not an object"),
    );
    let err = Actor::from_json_ld(&raw).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("PQ attestation"),
        "expected PQ attestation context in error; got: {msg}"
    );
}
