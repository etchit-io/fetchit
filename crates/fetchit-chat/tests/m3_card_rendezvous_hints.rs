//! M3 Phase E4 — extended share-card round-trip for the
//! `fetchit_rendezvous_hints` slot.
//!
//! Alice mints a v2 card carrying two `wss://` relays; the parsing
//! peer (the role the Bob side plays in production) reads the same
//! list back via the public [`fetchit_chat::card::RendezvousHintsV1`]
//! decoder. Pins the wire shape that Phase E1's `ClientBuilder.
//! advertised_relays(...)` and E2's `chat_regenerate_card_with_relays`
//! Tauri command both write through.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::card::{extend_with_fetchit_fields, verify_card_extension, RendezvousHintsV1};
use fetchit_relay_client::{MlDsaSigner, Signer};
use serde_json::json;

fn fake_x0x_card(agent_id_hex: &str) -> serde_json::Value {
    json!({
        "agent_id": agent_id_hex,
        "display_name": "Alice",
        "addresses": [],
    })
}

#[tokio::test]
async fn alice_mints_card_with_two_relays_and_bob_parses_same_list() {
    // Alice's signing + KEM materials. The KEM bytes are stand-ins for
    // ML-KEM-768 public material; the card's signature only covers the
    // x0x_card + KEM + agent-pub triple, never the hints slot — hints
    // are forward-compat opaque payload.
    let alice = MlDsaSigner::generate().unwrap();
    let kem_pub = b"alice-kem-768-pub-stand-in";
    let agent_id_hex = hex::encode(alice.agent_id());

    let relays = vec![
        "wss://nyc.etchit.io/v1/ws".to_owned(),
        "wss://fra.etchit.io/v1/ws".to_owned(),
    ];

    // Alice mints the card with the advertised relays in the v2 slot.
    let card = extend_with_fetchit_fields(
        &fake_x0x_card(&agent_id_hex),
        kem_pub,
        &alice,
        Some(RendezvousHintsV1 {
            relays: relays.clone(),
        }),
    )
    .await
    .expect("card mint with hints must succeed");

    // Bob (any parsing peer) reads the wire-shape field. The hints land
    // under `fetchit_rendezvous_hints` as `{ v: 1, data: {relays: [...]} }`
    // — that exact envelope is what the v1 decoder consumes.
    let hints_field = card
        .get("fetchit_rendezvous_hints")
        .expect("v2 slot must be present when hints are set");
    let v = hints_field
        .get("v")
        .and_then(serde_json::Value::as_u64)
        .expect("wire version field must be present");
    assert_eq!(v, 1, "v=1 is the only shape this round-trip pins");

    let data = hints_field
        .get("data")
        .expect("v1 envelope must carry data");
    let parsed = RendezvousHintsV1::from_value(data).expect("data must validate as v1");
    assert_eq!(parsed.relays, relays);
}

#[tokio::test]
async fn card_signature_verifies_independently_of_the_hints_slot() {
    // Hints are NOT part of the signed body (per `extend_with_fetchit_fields`
    // docstring + verify_card_extension implementation). Mint two cards
    // with the same identity + KEM but different hints; both must verify
    // against Alice's public key, and the verified `CardExtension` must
    // surface `v2_rendezvous_hints = None` either way (the verify path
    // deliberately omits the unsigned slot).
    let alice = MlDsaSigner::generate().unwrap();
    let kem_pub = b"alice-kem-768-pub-stand-in";
    let agent_id_hex = hex::encode(alice.agent_id());
    let pubkey = alice.public_key();

    let card_a = extend_with_fetchit_fields(
        &fake_x0x_card(&agent_id_hex),
        kem_pub,
        &alice,
        Some(RendezvousHintsV1 {
            relays: vec!["wss://nyc.etchit.io/v1/ws".to_owned()],
        }),
    )
    .await
    .unwrap();
    let card_b = extend_with_fetchit_fields(
        &fake_x0x_card(&agent_id_hex),
        kem_pub,
        &alice,
        Some(RendezvousHintsV1 {
            relays: vec![
                "wss://nyc.etchit.io/v1/ws".to_owned(),
                "wss://fra.etchit.io/v1/ws".to_owned(),
            ],
        }),
    )
    .await
    .unwrap();

    let verified_a = verify_card_extension(&card_a, &pubkey).expect("card A must verify");
    let verified_b = verify_card_extension(&card_b, &pubkey).expect("card B must verify");
    assert!(verified_a.v2_rendezvous_hints.is_none());
    assert!(verified_b.v2_rendezvous_hints.is_none());
}

#[tokio::test]
async fn card_with_no_hints_omits_the_v2_field_byte_for_byte() {
    // The wire-shape contract that lets v1 readers stay v1: when no
    // hints are supplied at mint time, the card carries no
    // `fetchit_rendezvous_hints` field at all (instead of `null` or an
    // empty envelope). This is what
    // `current_card_value_without_regenerate_omits_hints` already pins
    // at the unit level; the integration test confirms the public
    // helper preserves the contract.
    let alice = MlDsaSigner::generate().unwrap();
    let kem_pub = b"alice-kem-768-pub-stand-in";
    let agent_id_hex = hex::encode(alice.agent_id());

    let card = extend_with_fetchit_fields(&fake_x0x_card(&agent_id_hex), kem_pub, &alice, None)
        .await
        .unwrap();
    assert!(
        card.get("fetchit_rendezvous_hints").is_none(),
        "v1 readers must see a card byte-identical to a pre-M3 mint",
    );
}
